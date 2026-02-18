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
    """Export container images as OCI tarballs into the staging dir."""
    images_dir = os.path.join(staging_dir, "var/lib/agentcage/images")
    os.makedirs(images_dir, exist_ok=True)

    for image in images:
        safe_name = image.replace("/", "_").replace(":", "_")
        tar_path = os.path.join(images_dir, f"{safe_name}.tar")
        click.echo(f"  Exporting image: {image}")
        subprocess.run(
            ["podman", "save", "--format", "docker-archive", "-o", tar_path, image],
            check=True,
        )


def _generate_startup_script(config: Config, deploy_name: str) -> str:
    """Generate a shell script that starts the cage containers via podman."""
    name = config.name

    # DNS server config
    dns_servers = ["1.1.1.1", "8.8.8.8"]

    # Build dnsmasq args
    dns_args = ["dnsmasq", "--no-daemon", "--log-queries", "--no-resolv"]
    for srv in dns_servers:
        dns_args += ["--server", srv]
    if config.domains.mode == "allowlist" and config.domains.list:
        dns_args += ["--address=/#/198.51.100.1"]
        for domain in config.domains.list:
            for srv in dns_servers:
                dns_args += [f"--server=/{domain}/{srv}"]

    dns_cmd = " ".join(f"'{a}'" if " " in a else a for a in dns_args)

    # Build proxy command
    proxy_cmd = (
        "mitmdump -s /app/addon.py --listen-port 8080"
        " --set connection_strategy=lazy --listen-host 10.89.0.11"
    )
    if not config.logging.allowed_requests:
        proxy_cmd += " --quiet"

    # Agent container config
    agent_image = config.container.image
    agent_cmd = ""
    if config.container.command:
        agent_cmd = " ".join(config.container.command)

    # Build the script
    script = f"""#!/bin/bash
# Auto-generated cage startup script for {name}
set -euo pipefail

CAGE_NAME="{name}"

echo "start-cage: creating network"
podman network create --internal --subnet=10.89.0.0/24 "${{CAGE_NAME}}-net" 2>/dev/null || true

echo "start-cage: starting DNS container"
podman run -d --name "${{CAGE_NAME}}-dns" \\
    --network "${{CAGE_NAME}}-net:ip=10.89.0.10" \\
    --cap-add NET_BIND_SERVICE \\
    localhost/agentcage-dns \\
    {dns_cmd}

echo "start-cage: starting proxy container"
podman run -d --name "${{CAGE_NAME}}-proxy" \\
    --network "${{CAGE_NAME}}-net:ip=10.89.0.11" \\
    -v /etc/agentcage/config.yaml:/etc/agentcage/config.yaml:ro \\
    --dns 10.89.0.10 \\
    localhost/agentcage-proxy \\
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

echo "start-cage: starting cage container"
podman run -d --name "${{CAGE_NAME}}-cage" \\
    --network "${{CAGE_NAME}}-net" \\
    -e "HTTP_PROXY=http://10.89.0.11:8080" \\
    -e "HTTPS_PROXY=http://10.89.0.11:8080" \\
    -e "http_proxy=http://10.89.0.11:8080" \\
    -e "https_proxy=http://10.89.0.11:8080" \\
    -e "NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem" \\
    -e "SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem" \\
    -v "$CERT_DIR:/certs:ro" \\
    --dns 10.89.0.10 \\
    {agent_image} \\
    {agent_cmd}

echo "start-cage: all containers started"
podman ps
"""
    return script


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
        "etc/agentcage",
    ]:
        os.makedirs(os.path.join(staging_dir, d), exist_ok=True)

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

    # Determine rootfs size (enough for base + container images + headroom)
    # Base Fedora image ~300MB, images need space both as tarballs and extracted
    size_mb = max(config.firecracker.mem_mb, 4096)

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

        # Create ext4 image from populated directory
        click.echo(f"Building ext4 rootfs: {rootfs_path} ({size_mb}MB)")
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={rootfs_path}",
             "bs=1M", f"count={size_mb}"],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["mkfs.ext4", "-F", "-q", "-d", staging, rootfs_path],
            check=True,
        )

    click.echo(f"Prepared VM rootfs: {rootfs_path}")
    return rootfs_path


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
