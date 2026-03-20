"""Tests for Lima provisioning config generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
import yaml

from agentcage.lima.provisioning import _parse_port_forwards, generate_lima_config


# ---------------------------------------------------------------------------
# Mock config objects (Config module not yet updated for VmConfig)
# ---------------------------------------------------------------------------


@dataclass
class VmConfig:
    vcpus: int = 2
    mem_mb: int = 2048


@dataclass
class ContainerConfig:
    image: str = ""
    ports: list = field(default_factory=list)


@dataclass
class MockConfig:
    name: str = ""
    isolation: str = "vm"
    container: ContainerConfig = field(default_factory=ContainerConfig)
    vm: VmConfig = field(default_factory=VmConfig)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**kwargs) -> MockConfig:
    cfg = MockConfig()
    for k, v in kwargs.items():
        setattr(cfg, k, v)
    return cfg


# ---------------------------------------------------------------------------
# Tests for _parse_port_forwards
# ---------------------------------------------------------------------------


class TestParsePortForwards:
    def test_two_part_spec(self):
        result = _parse_port_forwards(["8080:80"])
        assert result == [{"host_bind": "127.0.0.1", "host_port": 8080, "guest_port": 80}]

    def test_three_part_spec(self):
        result = _parse_port_forwards(["127.0.0.1:9000:9000"])
        assert result == [{"host_bind": "127.0.0.1", "host_port": 9000, "guest_port": 9000}]

    def test_multiple_specs(self):
        result = _parse_port_forwards(["8080:80", "0.0.0.0:443:443"])
        assert len(result) == 2
        assert result[0] == {"host_bind": "127.0.0.1", "host_port": 8080, "guest_port": 80}
        assert result[1] == {"host_bind": "0.0.0.0", "host_port": 443, "guest_port": 443}

    def test_empty_list(self):
        assert _parse_port_forwards([]) == []

    def test_invalid_spec_raises(self):
        with pytest.raises(ValueError, match="Invalid port spec"):
            _parse_port_forwards(["80"])

    def test_ports_are_integers(self):
        result = _parse_port_forwards(["8080:80"])
        assert isinstance(result[0]["host_port"], int)
        assert isinstance(result[0]["guest_port"], int)


# ---------------------------------------------------------------------------
# Tests for generate_lima_config
# ---------------------------------------------------------------------------


class TestGenerateLimaConfig:
    def test_returns_valid_yaml(self):
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        # Should parse without error
        docs = list(yaml.safe_load_all(output))
        assert len(docs) >= 1

    def test_vmtype_qemu_on_linux(self):
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        assert "vmType: qemu" in output

    def test_vmtype_vz_on_darwin(self):
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Darwin"):
            output = generate_lima_config(cfg)
        assert "vmType: vz" in output

    def test_vz_includes_rosetta_and_virtiofs(self):
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Darwin"):
            output = generate_lima_config(cfg)
        assert "rosetta:" in output
        assert "mountType: virtiofs" in output

    def test_qemu_excludes_rosetta(self):
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        assert "rosetta" not in output

    def test_cpus_set_correctly(self):
        cfg = MockConfig(name="test-cage", vm=VmConfig(vcpus=4, mem_mb=2048))
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        assert parsed["cpus"] == 4

    def test_memory_set_correctly(self):
        cfg = MockConfig(name="test-cage", vm=VmConfig(vcpus=2, mem_mb=4096))
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        assert parsed["memory"] == "4GiB"

    def test_memory_rounded_up(self):
        # 1500 MB -> ceil(1500/1024) = 2 GiB
        cfg = MockConfig(name="test-cage", vm=VmConfig(vcpus=2, mem_mb=1500))
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        assert parsed["memory"] == "2GiB"

    def test_provision_script_included(self):
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        assert "agentcage provisioning complete" in output
        assert "apt-get install" in output

    def test_provision_script_contains_podman(self):
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        assert "podman" in output

    def test_name_in_comment(self):
        cfg = MockConfig(name="my-agent")
        output = generate_lima_config(cfg)
        assert "my-agent" in output

    def test_no_port_forwards_when_empty(self):
        cfg = MockConfig(name="test-cage", container=ContainerConfig(ports=[]))
        output = generate_lima_config(cfg)
        assert "portForwards" not in output

    def test_port_forwards_rendered(self):
        cfg = MockConfig(
            name="test-cage",
            container=ContainerConfig(ports=["8080:80", "127.0.0.1:9000:9000"]),
        )
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        assert "portForwards" in output
        parsed = yaml.safe_load(output)
        pf = parsed["portForwards"]
        assert len(pf) == 2
        # First: 8080:80 -> host_bind=127.0.0.1
        assert pf[0]["guestPort"] == 80
        assert pf[0]["hostPort"] == 8080
        assert pf[0]["hostIP"] == "127.0.0.1"
        # Second: 127.0.0.1:9000:9000
        assert pf[1]["guestPort"] == 9000
        assert pf[1]["hostPort"] == 9000
        assert pf[1]["hostIP"] == "127.0.0.1"

    def test_images_have_digest(self):
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        for img in parsed["images"]:
            assert "digest" in img, f"Image entry missing digest: {img}"
            assert img["digest"].startswith("sha256:"), f"Digest not sha256: {img['digest']}"
            # SHA-256 hex digest is 64 characters
            assert len(img["digest"]) == len("sha256:") + 64, f"Invalid digest length: {img['digest']}"

    def test_containerd_disabled(self):
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        assert parsed["containerd"]["system"] is False
        assert parsed["containerd"]["user"] is False
