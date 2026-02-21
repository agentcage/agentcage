"""Generate Firecracker VM JSON configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentcage.config import Config
from agentcage.firecracker.network import cage_ip, tap_name, BRIDGE_IP, BRIDGE_NETMASK


def generate_vm_config(
    config: Config,
    deploy_name: str,
    rootfs_path: str,
    secrets_drive_path: str | None = None,
    data_drive_path: str | None = None,
) -> dict:
    """Generate the Firecracker JSON config for a cage VM."""
    fc = config.firecracker
    vm_ip = cage_ip(deploy_name)

    boot_args = (
        f"console=ttyS0 reboot=k panic=1 pci=off "
        f"ip={vm_ip}::{BRIDGE_IP}:{BRIDGE_NETMASK}::eth0:off "
        f"agentcage.name={deploy_name} "
        f"init=/usr/local/bin/vm-init.sh"
    )

    cfg: dict = {
        "boot-source": {
            "kernel_image_path": fc.kernel,
            "boot_args": boot_args,
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": rootfs_path,
                "is_root_device": True,
                "is_read_only": False,
            },
        ],
        "network-interfaces": [
            {
                "iface_id": "eth0",
                "host_dev_name": tap_name(deploy_name),
            },
        ],
        "machine-config": {
            "vcpu_count": fc.vcpus,
            "mem_size_mib": fc.mem_mb,
        },
    }

    # Add secrets drive if present
    if secrets_drive_path and os.path.isfile(secrets_drive_path):
        cfg["drives"].append({
            "drive_id": "secrets",
            "path_on_host": secrets_drive_path,
            "is_root_device": False,
            "is_read_only": True,
        })

    # Add persistent data drive if present
    if data_drive_path and os.path.isfile(data_drive_path):
        cfg["drives"].append({
            "drive_id": "data",
            "path_on_host": data_drive_path,
            "is_root_device": False,
            "is_read_only": False,
        })

    return cfg


def write_vm_config(config_dict: dict, output_path: str) -> None:
    """Write the VM config to a JSON file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(config_dict, f, indent=2)


def vm_config_path(deploy_name: str) -> str:
    """Return the expected VM config path for a deployment."""
    config_dir = Path(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    ) / "agentcage" / "cages" / deploy_name / "vm"
    config_dir.mkdir(parents=True, exist_ok=True)
    return str(config_dir / "vm-config.json")
