"""Tests for Firecracker prerequisites checker."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agentcage.config import Config, ContainerConfig, FirecrackerConfig
from agentcage.firecracker.prerequisites import check_prerequisites


def _make_fc_config(**overrides) -> Config:
    fc_kwargs = {
        "kernel": "/boot/vmlinux",
        "vcpus": 2,
        "mem_mb": 2048,
        "firecracker_bin": "firecracker",
    }
    fc_kwargs.update(overrides)
    return Config(
        name="test",
        isolation="firecracker",
        container=ContainerConfig(image="test:latest"),
        firecracker=FirecrackerConfig(**fc_kwargs),
    )


class TestCheckPrerequisites:
    @patch("agentcage.firecracker.prerequisites.shutil.which")
    @patch("agentcage.firecracker.prerequisites.os.access", return_value=True)
    @patch("agentcage.firecracker.prerequisites.os.path.exists", return_value=True)
    @patch("agentcage.firecracker.prerequisites.os.path.isfile", return_value=True)
    @patch("agentcage.firecracker.prerequisites._is_setuid_root", return_value=True)
    def test_all_ok(self, mock_setuid, mock_isfile, mock_exists, mock_access, mock_which):
        mock_which.return_value = "/usr/bin/fake"
        cfg = _make_fc_config()
        issues = check_prerequisites(cfg)
        assert issues == []

    @patch("agentcage.firecracker.prerequisites.os.path.exists", return_value=False)
    def test_no_kvm(self, mock_exists):
        cfg = _make_fc_config()
        issues = check_prerequisites(cfg)
        assert any("/dev/kvm" in i for i in issues)

    @patch("agentcage.firecracker.prerequisites.shutil.which", return_value=None)
    @patch("agentcage.firecracker.prerequisites.os.access", return_value=True)
    @patch("agentcage.firecracker.prerequisites.os.path.exists", return_value=True)
    @patch("agentcage.firecracker.prerequisites.os.path.isfile", return_value=True)
    def test_missing_firecracker_binary(self, mock_isfile, mock_exists, mock_access, mock_which):
        cfg = _make_fc_config()
        issues = check_prerequisites(cfg)
        assert any("firecracker" in i and "not found" in i for i in issues)

    @patch("agentcage.firecracker.prerequisites.shutil.which")
    @patch("agentcage.firecracker.prerequisites.os.access", return_value=True)
    @patch("agentcage.firecracker.prerequisites.os.path.exists", return_value=True)
    @patch("agentcage.firecracker.prerequisites.os.path.isfile", return_value=False)
    @patch("agentcage.firecracker.prerequisites._is_setuid_root", return_value=True)
    def test_missing_kernel(self, mock_setuid, mock_isfile, mock_exists, mock_access, mock_which):
        mock_which.return_value = "/usr/bin/fake"
        cfg = _make_fc_config()
        issues = check_prerequisites(cfg)
        assert any("kernel" in i for i in issues)

    def test_empty_kernel_path(self):
        cfg = _make_fc_config(kernel="")
        issues = check_prerequisites(cfg)
        assert any("kernel" in i and "not set" in i for i in issues)
