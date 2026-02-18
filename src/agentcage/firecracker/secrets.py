"""File-based secret store and secrets drive for Firecracker VMs.

In container mode, secrets are managed by Podman's secret store.
In Firecracker mode, secrets are stored as files on the host and
injected into the VM via a small ext4 "secrets drive" (virtio-block).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _secrets_dir(deploy_name: str) -> Path:
    """Return the host directory for a cage's secrets."""
    config_dir = Path(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    ) / "agentcage" / "deployments" / deploy_name / "secrets"
    config_dir.mkdir(parents=True, exist_ok=True)
    # Restrict permissions to owner only
    config_dir.chmod(0o700)
    return config_dir


def save_secret(deploy_name: str, key: str, value: str) -> None:
    """Store a secret value for a cage."""
    secrets_dir = _secrets_dir(deploy_name)
    secret_path = secrets_dir / key
    secret_path.write_text(value)
    secret_path.chmod(0o600)


def load_secret(deploy_name: str, key: str) -> str:
    """Load a secret value for a cage."""
    secret_path = _secrets_dir(deploy_name) / key
    if not secret_path.is_file():
        raise FileNotFoundError(f"Secret '{key}' not found for '{deploy_name}'")
    return secret_path.read_text()


def secret_exists(deploy_name: str, key: str) -> bool:
    """Check if a secret exists for a cage."""
    return (_secrets_dir(deploy_name) / key).is_file()


def list_secrets(deploy_name: str) -> list[str]:
    """List all secret names for a cage."""
    secrets_dir = _secrets_dir(deploy_name)
    if not secrets_dir.is_dir():
        return []
    return sorted(f.name for f in secrets_dir.iterdir() if f.is_file())


def remove_secret(deploy_name: str, key: str) -> bool:
    """Remove a secret. Returns True if removed."""
    secret_path = _secrets_dir(deploy_name) / key
    if secret_path.is_file():
        secret_path.unlink()
        return True
    return False


def remove_all_secrets(deploy_name: str) -> list[str]:
    """Remove all secrets for a cage. Returns list of removed keys."""
    removed = []
    for key in list_secrets(deploy_name):
        if remove_secret(deploy_name, key):
            removed.append(key)
    return removed


def create_secrets_drive(deploy_name: str, output_path: str) -> bool:
    """Build a small ext4 image containing secrets as files.

    The VM init script mounts this as /dev/vdb and creates Podman
    secrets from each file.

    Returns True if a secrets drive was created (False if no secrets).
    """
    secrets = list_secrets(deploy_name)
    if not secrets:
        return False

    secrets_dir = _secrets_dir(deploy_name)

    # Create a small ext4 image (4MB is plenty for secrets)
    size_mb = 4
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={output_path}",
         "bs=1M", f"count={size_mb}"],
        capture_output=True, check=True,
    )
    subprocess.run(
        ["mkfs.ext4", "-F", "-q", output_path],
        capture_output=True, check=True,
    )

    # Mount and copy secrets in
    mount_dir = f"/tmp/agentcage-secrets-{os.getpid()}"
    inject_lines = [
        f"set -e",
        f"mkdir -p {mount_dir}",
        f"mount -o loop {output_path} {mount_dir}",
    ]
    for key in secrets:
        src = str(secrets_dir / key)
        inject_lines.append(f"cp {src} {mount_dir}/{key}")
    inject_lines.extend([
        f"umount {mount_dir}",
        f"rmdir {mount_dir}",
    ])

    subprocess.run(
        ["podman", "unshare", "bash", "-c", "\n".join(inject_lines)],
        check=True,
    )

    return True


def secrets_drive_path(deploy_name: str) -> str:
    """Return the expected secrets drive path for a deployment."""
    config_dir = Path(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    ) / "agentcage" / "deployments" / deploy_name / "vm"
    config_dir.mkdir(parents=True, exist_ok=True)
    return str(config_dir / "secrets.ext4")
