"""Build and prepare Firecracker VM root filesystem images.

Uses podman export + mkfs.ext4 -d to create rootfs without root privileges.
Container images, config, and startup scripts are populated into a staging
directory before building the ext4 image.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import click

from agentcage.config import Config
from agentcage.podman import Podman

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_BASE_ROOTFS_NAME = "agentcage-vmbase"


def _state_dir(deploy_name: str) -> Path:
    """Return the VM state directory for a deployment."""
    config_dir = Path(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    ) / "agentcage" / "deployments" / deploy_name / "vm"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def build_base_rootfs(podman: Podman, force: bool = False) -> str:
    """Build the base VM rootfs container image if not already cached.

    Returns the image name.
    """
    if not force and podman.image_exists(_BASE_ROOTFS_NAME):
        click.echo(f"Base VM image '{_BASE_ROOTFS_NAME}' already exists (use force=True to rebuild)")
        return _BASE_ROOTFS_NAME

    click.echo("Building base VM rootfs image...")
    containerfile = str(_DATA_DIR / "firecracker" / "Containerfile.vmbase")
    podman.build_image(
        _BASE_ROOTFS_NAME,
        containerfile,
        str(_DATA_DIR),
        cap_add=["ALL"],
    )
    return _BASE_ROOTFS_NAME


def _export_base_to_dir(podman: Podman, staging_dir: str) -> None:
    """Export the base VM image to a staging directory."""
    container_name = f"agentcage-export-{os.getpid()}"
    subprocess.run(
        ["podman", "create", "--name", container_name, _BASE_ROOTFS_NAME, "/bin/true"],
        capture_output=True, check=True,
    )
    try:
        tar_path = os.path.join(staging_dir, "base.tar")
        subprocess.run(
            ["podman", "export", "-o", tar_path, container_name],
            check=True,
        )
        # Untar into the staging directory
        subprocess.run(
            ["tar", "xf", tar_path, "-C", staging_dir],
            check=True,
        )
        os.unlink(tar_path)
    finally:
        subprocess.run(
            ["podman", "rm", "-f", container_name],
            capture_output=True,
        )


def _export_container_images(
    staging_dir: str,
    images: list[str],
) -> None:
    """Export container images as gzipped, split tarballs into the staging dir.

    mkfs.ext4 -d has a 2GB per-file limit (signed 32-bit in __populate_fs).
    Images are gzip-compressed and split into <1.9GB chunks.
    Chunks are named <image>.tar.gz.00, .01, etc.
    vm-init.sh reassembles them with cat before podman load.
    """
    images_dir = os.path.join(staging_dir, "var/lib/agentcage/images")
    os.makedirs(images_dir, exist_ok=True)

    for image in images:
        safe_name = image.replace("/", "_").replace(":", "_")
        chunk_prefix = os.path.join(images_dir, f"{safe_name}.tar.gz.")
        click.echo(f"  Exporting image: {image}")
        save_proc = subprocess.Popen(
            ["podman", "save", "--format", "docker-archive", image],
            stdout=subprocess.PIPE,
        )
        gzip_proc = subprocess.Popen(
            ["gzip", "-1"],
            stdin=save_proc.stdout,
            stdout=subprocess.PIPE,
        )
        split_proc = subprocess.Popen(
            ["split", "-b", "1900m", "-d", "--suffix-length=2", "-", chunk_prefix],
            stdin=gzip_proc.stdout,
        )
        save_proc.stdout.close()
        gzip_proc.stdout.close()
        split_proc.wait()
        gzip_proc.wait()
        save_proc.wait()
        if save_proc.returncode != 0:
            raise subprocess.CalledProcessError(save_proc.returncode, "podman save")
        if gzip_proc.returncode != 0:
            raise subprocess.CalledProcessError(gzip_proc.returncode, "gzip")
        if split_proc.returncode != 0:
            raise subprocess.CalledProcessError(split_proc.returncode, "split")


def _generate_startup_script(config: Config, deploy_name: str) -> str:
    """Generate a shell script that starts the cage containers via podman."""
    name = config.name
    cc = config.container

    # DNS server config — use configured servers, fallback to public DNS
    dns_servers = config.dns_servers if config.dns_servers else ["1.1.1.1", "8.8.8.8"]

    # Build dnsmasq args
    dns_args = ["dnsmasq", "--no-daemon", "--log-queries", "--no-resolv"]
    for srv in dns_servers:
        dns_args += ["--server", srv]
    if config.domains.mode == "allowlist" and config.domains.list:
        dns_args += ["--address=/#/198.51.100.1"]
        for domain in config.domains.list:
            for srv in dns_servers:
                dns_args += [f"--server=/{domain}/{srv}"]

    dns_cmd = " ".join(_shell_quote(a) for a in dns_args)

    # Build proxy command — use multi-mode when ports are configured
    if cc.ports:
        proxy_cmd = (
            "mitmdump -s /app/addon.py --mode regular@10.89.0.11:8080"
        )
        for port_spec in cc.ports:
            parts = port_spec.split(":")
            if len(parts) == 3:
                container_port = parts[2]
            elif len(parts) == 2:
                container_port = parts[1]
            else:
                continue
            proxy_cmd += f" --mode reverse:http://10.89.0.2:{container_port}@0.0.0.0:{container_port}"
        proxy_cmd += " --set connection_strategy=lazy"
    else:
        proxy_cmd = (
            "mitmdump -s /app/addon.py --listen-port 8080"
            " --set connection_strategy=lazy --listen-host 10.89.0.11"
        )
    if not config.logging.allowed_requests:
        proxy_cmd += " --quiet"

    # Proxy secrets (for secret injection)
    proxy_secret_args = ""
    for rule in config.secret_injection:
        env_q = _shell_quote(f"{rule.env},type=env,target={rule.env}")
        proxy_secret_args += f"    --secret {env_q} \\\n"

    # Agent container config
    agent_image = _shell_quote(cc.image)
    agent_cmd = ""
    if cc.command:
        agent_cmd = " ".join(_shell_quote(c) for c in cc.command)

    # Warn about host volume mounts (not supported in Firecracker mode)
    volume_warnings = ""
    if cc.volumes:
        for vol in cc.volumes:
            vol_q = _shell_quote(vol)
            volume_warnings += f'echo "start-cage: WARNING: host volume mount not supported in Firecracker mode, skipping:" {vol_q}\n'

    # Build cage container extra args
    cage_extra_args = ""

    # Environment variables from config
    for key, val in cc.env.items():
        cage_extra_args += f"    -e {_shell_quote(f'{key}={val}')} \\\n"

    # Tmpfs mounts
    for tmpfs_spec in cc.tmpfs:
        cage_extra_args += f"    --tmpfs {_shell_quote(tmpfs_spec)} \\\n"

    # Named volumes — backed by data drive if available
    named_volume_setup = ""
    for vol_name, mount_spec in cc.named_volumes.items():
        vn_q = _shell_quote(vol_name)
        vn_path_q = _shell_quote(f"/mnt/data/{vol_name}")
        named_volume_setup += f"""# Create named volume backed by data drive
if [[ -d /mnt/data ]]; then
    mkdir -p {vn_path_q}
    # Fix ownership: data migrated from rootless podman has UIDs shifted by
    # subuid offset (e.g. 100000). In the VM, rootful podman uses real UIDs.
    if [[ -d {vn_path_q} ]]; then
        # Find files owned by shifted UIDs (>=100000) and remap to real UIDs
        find {vn_path_q} -uid +99999 -exec chown 1000:1000 {{}} + 2>/dev/null || true
    fi
    podman volume create --opt type=none --opt o=bind --opt device={vn_path_q} {vn_q} 2>/dev/null || true
else
    podman volume create {vn_q} 2>/dev/null || true
fi
"""
        cage_extra_args += f"    -v {_shell_quote(f'{vol_name}:{mount_spec}')} \\\n"

    # Ports — use socat to forward traffic from the VM's eth0 to the proxy
    # container.  iptables DNAT is unreliable here because firewall_driver=none
    # means Podman doesn't set up bridge forwarding rules, and manual DNAT
    # across the Podman bridge is fragile.  socat is simple and reliable.
    port_forwards_script = ""
    for port_spec in cc.ports:
        parts = port_spec.split(":")
        if len(parts) == 3:
            host_port, container_port = parts[1], parts[2]
        elif len(parts) == 2:
            host_port, container_port = parts[0], parts[1]
        else:
            host_port = container_port = parts[0]
        port_forwards_script += (
            f'echo "start-cage: port-forward 0.0.0.0:{host_port} -> 10.89.0.11:{container_port}"\n'
            f'socat TCP-LISTEN:{host_port},bind=0.0.0.0,fork,reuseaddr'
            f' TCP:10.89.0.11:{container_port} &\n'
        )

    # Capabilities
    for cap in cc.drop_capabilities:
        cage_extra_args += f"    --cap-drop {_shell_quote(cap)} \\\n"
    for cap in cc.add_capabilities:
        cage_extra_args += f"    --cap-add {_shell_quote(cap)} \\\n"

    # Resource limits
    if cc.memory:
        cage_extra_args += f"    --memory {_shell_quote(cc.memory)} \\\n"
    if cc.cpus:
        cage_extra_args += f"    --cpus {_shell_quote(cc.cpus)} \\\n"

    # User
    if cc.user:
        cage_extra_args += f"    -u {_shell_quote(cc.user)} \\\n"

    # Security settings
    if cc.read_only:
        cage_extra_args += "    --read-only \\\n"
    if cc.no_new_privileges:
        cage_extra_args += "    --security-opt no-new-privileges \\\n"
    if cc.security_label_disable:
        cage_extra_args += "    --security-opt label=disable \\\n"

    # Podman secrets (direct secrets, not injection)
    for secret_name in cc.podman_secrets:
        sn_q = _shell_quote(f"{secret_name},type=env,target={secret_name}")
        cage_extra_args += f"    --secret {sn_q} \\\n"

    # Secret injection placeholders — cage sees only the placeholder value
    for rule in config.secret_injection:
        cage_extra_args += f"    -e {_shell_quote(f'{rule.env}={rule.placeholder}')} \\\n"

    # Build the script
    name_q = _shell_quote(name)
    script = f"""#!/bin/bash
# Auto-generated cage startup script for {name}
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

CAGE_NAME={name_q}

{volume_warnings}echo "start-cage: creating networks"
# Internal network — agent container only (no internet gateway)
podman network create --internal --subnet=10.89.0.0/24 "${{CAGE_NAME}}-net" 2>/dev/null || true
# External network — for DNS and proxy outbound connectivity
podman network create --subnet=10.90.0.0/24 "${{CAGE_NAME}}-ext" 2>/dev/null || true

# Enable IP forwarding and set up NAT for the external network manually
# (firewall_driver=none in containers.conf means netavark skips nftables,
# so we do it here with iptables-legacy which the microvm kernel supports)
echo 1 > /proc/sys/net/ipv4/ip_forward
EXT_BRIDGE=$(podman network inspect "${{CAGE_NAME}}-ext" --format '{{{{.NetworkInterface}}}}' 2>/dev/null || echo "")
if [ -n "$EXT_BRIDGE" ]; then
    echo "start-cage: setting up NAT for $EXT_BRIDGE"
    iptables-legacy -P FORWARD ACCEPT || echo "start-cage: WARNING: cannot set FORWARD policy"
    iptables-legacy -t nat -A POSTROUTING -s 10.90.0.0/24 ! -o "$EXT_BRIDGE" -j MASQUERADE || echo "start-cage: WARNING: MASQUERADE rule failed"
fi

{named_volume_setup}echo "start-cage: starting DNS container (dual-homed)"
podman run -d --replace --name "${{CAGE_NAME}}-dns" \\
    --log-driver k8s-file \\
    --network "${{CAGE_NAME}}-net:ip=10.89.0.10" \\
    --network "${{CAGE_NAME}}-ext" \\
    --cap-add NET_BIND_SERVICE \\
    localhost/agentcage-dns \\
    {dns_cmd}

echo "start-cage: starting proxy container (dual-homed)"
podman run -d --replace --name "${{CAGE_NAME}}-proxy" \\
    --log-driver k8s-file \\
    --network "${{CAGE_NAME}}-net:ip=10.89.0.11" \\
    --network "${{CAGE_NAME}}-ext" \\
    -v /etc/agentcage/config.yaml:/etc/agentcage/config.yaml:ro \\
    --dns 10.89.0.10 \\
{proxy_secret_args}    localhost/agentcage-proxy \\
    {proxy_cmd}

# Wait for proxy CA cert to be generated
echo "start-cage: waiting for proxy CA cert..."
for i in $(seq 1 30); do
    if podman exec "${{CAGE_NAME}}-proxy" test -f /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem 2>/dev/null; then
        break
    fi
    sleep 1
done

# Copy CA cert from proxy for the cage container
CERT_DIR="/tmp/agentcage-certs"
mkdir -p "$CERT_DIR"
podman cp "${{CAGE_NAME}}-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem" "$CERT_DIR/" 2>/dev/null || true

echo "start-cage: starting cage container (internal network only)"
podman run -d --replace --name "${{CAGE_NAME}}-cage" \\
    --log-driver k8s-file \\
    --network "${{CAGE_NAME}}-net:ip=10.89.0.2" \\
    -e "HTTP_PROXY=http://10.89.0.11:8080" \\
    -e "HTTPS_PROXY=http://10.89.0.11:8080" \\
    -e "http_proxy=http://10.89.0.11:8080" \\
    -e "https_proxy=http://10.89.0.11:8080" \\
    -e "NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem" \\
    -e "SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem" \\
    -e "NODE_OPTIONS=--import /agentcage/proxy-fetch.mjs" \\
    -v "$CERT_DIR:/certs:ro" \\
    -v /var/lib/agentcage/patches:/agentcage:ro \\
    --dns 10.89.0.10 \\
{cage_extra_args}    {agent_image} \\
    {agent_cmd}

echo "start-cage: all containers started"
{port_forwards_script}podman ps

# Follow all container logs so they appear on the VM console
podman logs -f "${{CAGE_NAME}}-dns" 2>&1 | while IFS= read -r line; do echo "[dns] $line"; done &
podman logs -f "${{CAGE_NAME}}-proxy" 2>&1 | while IFS= read -r line; do echo "[proxy] $line"; done &
podman logs -f "${{CAGE_NAME}}-cage" 2>&1 | while IFS= read -r line; do echo "[cage] $line"; done &
"""
    return script


def _shell_quote(s: str) -> str:
    """Quote a string for safe inclusion in a shell script."""
    if not s:
        return "''"
    # If the string is simple (no special chars), return as-is
    if all(c.isalnum() or c in "-_=./:,+" for c in s):
        return s
    # Otherwise, single-quote it (escaping any embedded single quotes)
    return "'" + s.replace("'", "'\\''") + "'"


def _populate_staging(
    staging_dir: str,
    config: Config,
    deploy_name: str,
    quadlet_files: dict[str, str],
    proxy_config_path: str,
    container_images: list[str],
) -> None:
    """Add cage-specific files to the staging directory."""
    # Ensure directories exist
    for d in [
        "var/lib/agentcage/quadlets",
        "var/lib/agentcage/images",
        "var/lib/agentcage/patches",
        "etc/agentcage",
    ]:
        os.makedirs(os.path.join(staging_dir, d), exist_ok=True)

    # Copy Node.js proxy-fetch patches into rootfs
    patches_src = _DATA_DIR / "patches"
    patches_dest = os.path.join(staging_dir, "var/lib/agentcage/patches")
    if patches_src.is_dir():
        shutil.copytree(str(patches_src), patches_dest, dirs_exist_ok=True)

    # Write quadlet files
    for filename, content in quadlet_files.items():
        path = os.path.join(staging_dir, "var/lib/agentcage/quadlets", filename)
        with open(path, "w") as f:
            f.write(content)

    # Copy proxy config
    dest_config = os.path.join(staging_dir, "etc/agentcage/config.yaml")
    shutil.copy2(proxy_config_path, dest_config)

    # Export container images
    click.echo("Exporting container images into VM rootfs...")
    _export_container_images(staging_dir, container_images)

    # Generate and write startup script
    script = _generate_startup_script(config, deploy_name)
    script_path = os.path.join(staging_dir, "var/lib/agentcage/start-cage.sh")
    with open(script_path, "w") as f:
        f.write(script)
    os.chmod(script_path, 0o755)


def prepare_vm_rootfs(
    podman: Podman,
    deploy_name: str,
    config: Config,
    quadlet_files: dict[str, str],
    proxy_config_path: str,
    container_images: list[str] | None = None,
) -> str:
    """Prepare a cage-specific VM rootfs with config, images, and startup script.

    Returns the path to the rootfs ext4 image.
    """
    if container_images is None:
        container_images = ["agentcage-proxy", "agentcage-dns"]

    vm_dir = _state_dir(deploy_name)
    rootfs_path = str(vm_dir / "rootfs.ext4")

    # Ensure base image exists
    build_base_rootfs(podman)

    with tempfile.TemporaryDirectory(prefix="agentcage-rootfs-") as staging:
        click.echo("Exporting base VM image to staging directory...")
        _export_base_to_dir(podman, staging)

        click.echo("Populating rootfs with cage files...")
        _populate_staging(
            staging, config, deploy_name,
            quadlet_files, proxy_config_path, container_images,
        )

        # Ensure all files are readable (Fedora ships /etc/gshadow etc.
        # with mode 000 which mkfs.ext4 -d cannot read as non-root)
        subprocess.run(
            ["chmod", "-R", "u+r", staging],
            check=True,
        )

        # Determine rootfs size from actual staging content + headroom
        # Image tarballs are kept on disk (not deleted) so the VM can
        # reload them after a restart.  Peak usage: decompressed tarballs
        # + overlay layer storage + podman temp files + base OS.
        result = subprocess.run(
            ["du", "-sm", staging],
            capture_output=True, text=True, check=True,
        )
        staging_mb = int(result.stdout.split()[0])
        # 10x headroom: during podman load in the VM, the decompressed
        # tar and extracted container layers coexist on the rootfs.
        # Peak usage: gzip tarballs + decompressed tar (~2.5x gzip)
        # + overlay layer storage (~2.5x gzip) + podman temp files + base OS.
        # The rootfs is a sparse file so host disk only uses actual content.
        size_mb = max(staging_mb * 10, 4096)

        # Create ext4 image from populated directory
        click.echo(f"Building ext4 rootfs: {rootfs_path} ({size_mb}MB, staging: {staging_mb}MB)")
        subprocess.run(
            ["truncate", "-s", f"{size_mb}M", rootfs_path],
            check=True,
        )
        subprocess.run(
            ["mkfs.ext4", "-F", "-q", "-d", staging, rootfs_path],
            check=True,
        )

    click.echo(f"Prepared VM rootfs: {rootfs_path}")
    return rootfs_path


def ensure_data_drive(deploy_name: str, size_mb: int = 4096) -> str:
    """Create a persistent data drive for named volumes if it doesn't exist.

    The data drive survives rootfs rebuilds (cage update) so named volume
    data persists across updates. Only created on first call.

    Returns the path to the data drive image.
    """
    vm_dir = _state_dir(deploy_name)
    data_path = vm_dir / "data.ext4"

    if data_path.exists():
        click.echo(f"Data drive already exists: {data_path}")
        return str(data_path)

    click.echo(f"Creating persistent data drive: {data_path} ({size_mb}MB)")
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={data_path}",
         "bs=1M", f"count={size_mb}"],
        capture_output=True, check=True,
    )
    subprocess.run(
        ["mkfs.ext4", "-F", "-q", "-L", "cage-data", str(data_path)],
        capture_output=True, check=True,
    )

    return str(data_path)


def data_drive_path(deploy_name: str) -> str:
    """Return the expected data drive path for a deployment."""
    return str(_state_dir(deploy_name) / "data.ext4")


def rootfs_path(deploy_name: str) -> str:
    """Return the expected rootfs path for a deployment."""
    return str(_state_dir(deploy_name) / "rootfs.ext4")


def cleanup_rootfs(deploy_name: str) -> bool:
    """Remove the VM rootfs for a deployment. Returns True if removed."""
    path = _state_dir(deploy_name) / "rootfs.ext4"
    if path.exists():
        path.unlink()
        return True
    return False
