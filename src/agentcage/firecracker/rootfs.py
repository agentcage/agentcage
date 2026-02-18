"""Build and prepare Firecracker VM root filesystem images."""

from __future__ import annotations

import os
import subprocess
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
    )
    return _BASE_ROOTFS_NAME


def _export_image_to_ext4(podman: Podman, image: str, output_path: str, size_mb: int) -> None:
    """Export a container image to an ext4 filesystem image."""
    click.echo(f"Exporting image to ext4: {output_path} ({size_mb}MB)")

    # Create a container from the image (don't start it)
    container_name = f"agentcage-export-{os.getpid()}"
    subprocess.run(
        ["podman", "create", "--name", container_name, image, "/bin/true"],
        capture_output=True, check=True,
    )

    try:
        # Create empty ext4 image
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={output_path}",
             "bs=1M", f"count={size_mb}"],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["mkfs.ext4", "-F", "-q", output_path],
            capture_output=True, check=True,
        )

        # Mount and copy container filesystem into ext4 image
        mount_dir = f"/tmp/agentcage-rootfs-{os.getpid()}"
        os.makedirs(mount_dir, exist_ok=True)

        # Export container filesystem as tar and extract into image
        export_proc = subprocess.run(
            ["podman", "export", container_name],
            capture_output=True, check=True,
        )

        # Use e2tools or mount to inject (podman unshare for fuse mount)
        tar_path = f"/tmp/agentcage-rootfs-{os.getpid()}.tar"
        with open(tar_path, "wb") as f:
            f.write(export_proc.stdout)

        # Use podman unshare to mount ext4 and extract
        subprocess.run(
            ["podman", "unshare", "bash", "-c",
             f"mkdir -p {mount_dir} && "
             f"mount -o loop {output_path} {mount_dir} && "
             f"tar xf {tar_path} -C {mount_dir} && "
             f"umount {mount_dir}"],
            check=True,
        )

        os.unlink(tar_path)
        os.rmdir(mount_dir)
    finally:
        subprocess.run(
            ["podman", "rm", "-f", container_name],
            capture_output=True,
        )


def prepare_vm_rootfs(
    podman: Podman,
    deploy_name: str,
    config: Config,
    quadlet_files: dict[str, str],
    proxy_config_path: str,
) -> str:
    """Prepare a cage-specific VM rootfs with config and quadlets baked in.

    Returns the path to the rootfs ext4 image.
    """
    vm_dir = _state_dir(deploy_name)
    rootfs_path = str(vm_dir / "rootfs.ext4")

    # Ensure base image exists
    build_base_rootfs(podman)

    # Determine rootfs size (base + headroom for container images)
    size_mb = max(config.firecracker.mem_mb // 2, 1024)

    # Export base image to ext4
    _export_image_to_ext4(podman, _BASE_ROOTFS_NAME, rootfs_path, size_mb)

    # Overlay cage-specific files into the rootfs
    _inject_cage_files(rootfs_path, deploy_name, quadlet_files, proxy_config_path)

    click.echo(f"Prepared VM rootfs: {rootfs_path}")
    return rootfs_path


def _inject_cage_files(
    rootfs_path: str,
    deploy_name: str,
    quadlet_files: dict[str, str],
    proxy_config_path: str,
) -> None:
    """Inject quadlet files and config into the rootfs image."""
    inject_script = _build_inject_script(deploy_name, quadlet_files, proxy_config_path)

    subprocess.run(
        ["podman", "unshare", "bash", "-c", inject_script.format(rootfs=rootfs_path)],
        check=True,
    )


def _build_inject_script(
    deploy_name: str,
    quadlet_files: dict[str, str],
    proxy_config_path: str,
) -> str:
    """Build a shell script that injects cage files into the rootfs."""
    mount_dir = f"/tmp/agentcage-inject-{os.getpid()}"

    lines = [
        f"set -e",
        f"mkdir -p {mount_dir}",
        f"mount -o loop {{rootfs}} {mount_dir}",
        f"mkdir -p {mount_dir}/var/lib/agentcage/quadlets",
        f"mkdir -p {mount_dir}/var/lib/agentcage/images",
        f"mkdir -p {mount_dir}/etc/agentcage",
    ]

    # Write quadlet files
    for filename, content in quadlet_files.items():
        escaped = content.replace("'", "'\\''")
        lines.append(
            f"printf '%s' '{escaped}' > {mount_dir}/var/lib/agentcage/quadlets/{filename}"
        )

    # Copy proxy config
    lines.append(f"cp {proxy_config_path} {mount_dir}/etc/agentcage/config.yaml")

    lines.extend([
        f"umount {mount_dir}",
        f"rmdir {mount_dir}",
    ])

    return "\n".join(lines)


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
