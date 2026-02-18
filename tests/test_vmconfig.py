"""Tests for Firecracker VM config generation."""

from __future__ import annotations

import json
import os

import pytest

from agentcage.config import Config, ContainerConfig, FirecrackerConfig
from agentcage.firecracker.vmconfig import generate_vm_config, vm_config_path, write_vm_config


def _make_config(**fc_overrides) -> Config:
    fc_kwargs = {
        "kernel": "/opt/firecracker/vmlinux",
        "vcpus": 2,
        "mem_mb": 2048,
    }
    fc_kwargs.update(fc_overrides)
    return Config(
        name="myagent",
        isolation="firecracker",
        container=ContainerConfig(image="test:latest"),
        firecracker=FirecrackerConfig(**fc_kwargs),
    )


class TestGenerateVmConfig:
    def test_basic_structure(self):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "myagent", "/path/to/rootfs.ext4")

        assert "boot-source" in vm_cfg
        assert "drives" in vm_cfg
        assert "network-interfaces" in vm_cfg
        assert "machine-config" in vm_cfg

    def test_kernel_path(self):
        cfg = _make_config(kernel="/boot/vmlinux")
        vm_cfg = generate_vm_config(cfg, "myagent", "/path/to/rootfs.ext4")
        assert vm_cfg["boot-source"]["kernel_image_path"] == "/boot/vmlinux"

    def test_boot_args_contain_cage_name(self):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "myagent", "/path/to/rootfs.ext4")
        assert "agentcage.name=myagent" in vm_cfg["boot-source"]["boot_args"]

    def test_boot_args_contain_ip(self):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "myagent", "/path/to/rootfs.ext4")
        assert "ip=" in vm_cfg["boot-source"]["boot_args"]
        assert "10.88.0." in vm_cfg["boot-source"]["boot_args"]

    def test_rootfs_drive(self):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "myagent", "/data/rootfs.ext4")
        drives = vm_cfg["drives"]
        rootfs = next(d for d in drives if d["drive_id"] == "rootfs")
        assert rootfs["path_on_host"] == "/data/rootfs.ext4"
        assert rootfs["is_root_device"] is True
        assert rootfs["is_read_only"] is False

    def test_no_secrets_drive_by_default(self):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "myagent", "/rootfs.ext4")
        assert len(vm_cfg["drives"]) == 1

    def test_secrets_drive_when_provided(self, tmp_path):
        secrets_path = tmp_path / "secrets.ext4"
        secrets_path.write_text("fake")
        cfg = _make_config()
        vm_cfg = generate_vm_config(
            cfg, "myagent", "/rootfs.ext4",
            secrets_drive_path=str(secrets_path),
        )
        assert len(vm_cfg["drives"]) == 2
        secrets = next(d for d in vm_cfg["drives"] if d["drive_id"] == "secrets")
        assert secrets["is_read_only"] is True

    def test_data_drive_when_provided(self, tmp_path):
        data_path = tmp_path / "data.ext4"
        data_path.write_text("fake")
        cfg = _make_config()
        vm_cfg = generate_vm_config(
            cfg, "myagent", "/rootfs.ext4",
            data_drive_path=str(data_path),
        )
        assert len(vm_cfg["drives"]) == 2
        data = next(d for d in vm_cfg["drives"] if d["drive_id"] == "data")
        assert data["is_read_only"] is False

    def test_all_drives(self, tmp_path):
        secrets_path = tmp_path / "secrets.ext4"
        secrets_path.write_text("fake")
        data_path = tmp_path / "data.ext4"
        data_path.write_text("fake")
        cfg = _make_config()
        vm_cfg = generate_vm_config(
            cfg, "myagent", "/rootfs.ext4",
            secrets_drive_path=str(secrets_path),
            data_drive_path=str(data_path),
        )
        assert len(vm_cfg["drives"]) == 3
        drive_ids = {d["drive_id"] for d in vm_cfg["drives"]}
        assert drive_ids == {"rootfs", "secrets", "data"}

    def test_network_interface(self):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "myagent", "/rootfs.ext4")
        iface = vm_cfg["network-interfaces"][0]
        assert iface["iface_id"] == "eth0"
        assert iface["host_dev_name"] == "tap-myagent"

    def test_machine_config(self):
        cfg = _make_config(vcpus=4, mem_mb=4096)
        vm_cfg = generate_vm_config(cfg, "myagent", "/rootfs.ext4")
        mc = vm_cfg["machine-config"]
        assert mc["vcpu_count"] == 4
        assert mc["mem_size_mib"] == 4096

    def test_init_in_boot_args(self):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "myagent", "/rootfs.ext4")
        assert "init=/usr/local/bin/vm-init.sh" in vm_cfg["boot-source"]["boot_args"]


class TestWriteVmConfig:
    def test_writes_valid_json(self, tmp_path):
        cfg = _make_config()
        vm_cfg = generate_vm_config(cfg, "test", "/rootfs.ext4")
        out = str(tmp_path / "vm-config.json")
        write_vm_config(vm_cfg, out)

        with open(out) as f:
            loaded = json.load(f)
        assert loaded == vm_cfg

    def test_creates_parent_dirs(self, tmp_path):
        out = str(tmp_path / "deep" / "path" / "vm-config.json")
        write_vm_config({"test": True}, out)
        assert os.path.isfile(out)


class TestVmConfigPath:
    def test_returns_path_in_deployments(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        path = vm_config_path("myagent")
        assert "myagent" in path
        assert path.endswith("vm-config.json")
