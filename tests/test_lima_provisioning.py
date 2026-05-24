"""Tests for Lima provisioning config generation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
import yaml

from agentcage.lima.provisioning import (
    _extra_mounts_for_volumes,
    _parse_port_forwards,
    generate_lima_config,
)


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
    volumes: list = field(default_factory=list)


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

    def test_provision_install_skips_recommends_and_socat(self):
        """The apt-get install line must use --no-install-recommends (cuts
        ~50 MB of unused dependencies on a fresh Ubuntu cloud image) and
        must not pull in socat (no caller references it in the repo).
        """
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        # Locate the install line.
        install_lines = [
            ln for ln in output.splitlines()
            if "apt-get install" in ln or ("podman" in ln and "uidmap" in ln)
        ]
        joined = "\n".join(install_lines)
        assert "--no-install-recommends" in joined
        assert "socat" not in joined

    def test_provision_targets_host_username(self):
        """The provision script targets the real guest user (the host user
        Lima mirrors, resolved from the passwd database), not a hardcoded
        'lima' account, and does not rely on Lima's discouraged
        $LIMA_CIDATA_* variables."""
        import pwd
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        expected_user = pwd.getpwuid(os.getuid()).pw_name
        assert f'lima_user="{expected_user}"' in output
        # Linger is enabled by touching the sentinel file directly (the
        # loginctl/dbus path was observed to deadlock during cloud-init).
        assert '/var/lib/systemd/linger/$lima_user' in output
        assert "LIMA_CIDATA" not in output

    def test_provision_does_not_call_loginctl_enable_linger(self):
        """`loginctl enable-linger` goes through systemd-logind over D-Bus.
        During cloud-init that call has been observed to deadlock for the
        rest of the boot (the preceding `usermod -aG` on a user with an
        active SSH session can leave logind unresponsive). The provision
        script must instead write logind's own linger sentinel file."""
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        # An actual command invocation always sits at the start of a line
        # (possibly after whitespace). Ignore matches inside comments.
        code_lines = [
            ln for ln in output.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        assert not any("loginctl" in ln for ln in code_lines)
        assert "/var/lib/systemd/linger" in output

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

    def test_no_home_mount(self):
        """The blanket ~ mount must not appear — only targeted directories."""
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        locations = [m["location"] for m in parsed["mounts"]]
        assert "~" not in locations
        # Ensure the targeted mounts are present
        assert "~/.config/agentcage" in locations
        assert "~/.local/share/agentcage" in locations

    def test_config_dir_read_only(self):
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        for m in parsed["mounts"]:
            if m["location"] == "~/.config/agentcage":
                assert m["writable"] is False
                break
        else:
            pytest.fail("~/.config/agentcage mount not found")

    def test_data_dir_writable(self):
        cfg = MockConfig(name="test-cage")
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        for m in parsed["mounts"]:
            if m["location"] == "~/.local/share/agentcage":
                assert m["writable"] is True
                break
        else:
            pytest.fail("~/.local/share/agentcage mount not found")

    def test_user_volume_adds_extra_mount(self, tmp_path):
        vol_dir = tmp_path / "project"
        vol_dir.mkdir()
        cfg = MockConfig(
            name="test-cage",
            container=ContainerConfig(volumes=[f"{vol_dir}:/workspace:ro"]),
        )
        with patch("agentcage.lima.provisioning.platform.system", return_value="Linux"):
            output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        locations = [m["location"] for m in parsed["mounts"]]
        assert str(vol_dir) in locations

    def test_no_tmp_lima_mount(self):
        """The hardcoded /tmp/lima mount is gone — it does not exist on a
        fresh host and a missing mount source wedges VM startup."""
        cfg = MockConfig(name="test-cage")
        output = generate_lima_config(cfg)
        parsed = yaml.safe_load(output)
        locations = [m["location"] for m in parsed["mounts"]]
        assert "/tmp/lima" not in locations


# ---------------------------------------------------------------------------
# Tests for _extra_mounts_for_volumes
# ---------------------------------------------------------------------------


class TestExtraMountsForVolumes:
    def test_empty_volumes(self):
        assert _extra_mounts_for_volumes([]) == []

    def test_blocked_ssh_dir(self):
        with pytest.raises(ValueError, match="~/.ssh"):
            _extra_mounts_for_volumes(["~/.ssh:/keys:ro"])

    def test_blocked_gnupg_dir(self):
        with pytest.raises(ValueError, match="~/.gnupg"):
            _extra_mounts_for_volumes(["~/.gnupg:/gpg:ro"])

    def test_blocked_aws_dir(self):
        with pytest.raises(ValueError, match="~/.aws"):
            _extra_mounts_for_volumes(["~/.aws:/aws:ro"])

    def test_rw_volume_yields_writable_mount(self, tmp_path):
        d = tmp_path / "data"
        d.mkdir()
        mounts = _extra_mounts_for_volumes([f"{d}:/data:rw"])
        assert len(mounts) == 1
        assert mounts[0]["writable"] is True

    def test_ro_volume_yields_readonly_mount(self, tmp_path):
        d = tmp_path / "data"
        d.mkdir()
        mounts = _extra_mounts_for_volumes([f"{d}:/data:ro"])
        assert len(mounts) == 1
        assert mounts[0]["writable"] is False

    def test_no_opts_defaults_readonly(self, tmp_path):
        d = tmp_path / "data"
        d.mkdir()
        mounts = _extra_mounts_for_volumes([f"{d}:/data"])
        assert len(mounts) == 1
        assert mounts[0]["writable"] is False

    def test_deduplicates_same_host_path(self, tmp_path):
        d = tmp_path / "data"
        d.mkdir()
        mounts = _extra_mounts_for_volumes([f"{d}:/a:ro", f"{d}:/b:ro"])
        assert len(mounts) == 1

    def test_skips_nonexistent_host_path(self, tmp_path):
        """A volume whose host path does not exist must not become a Lima
        mount — Lima would only warn, then the VM hangs on startup."""
        missing = tmp_path / "does-not-exist"
        assert _extra_mounts_for_volumes([f"{missing}:/x:rw"]) == []

    def test_skips_file_host_path(self, tmp_path):
        """A volume whose host source is a single file must not become a
        Lima mount — `limactl create` fatals with "refers to a
        non-directory path" because virtiofs only shares directories.
        This is the claude-code scaffold's ~/.claude.json case."""
        f = tmp_path / "config.json"
        f.write_text("{}")
        assert _extra_mounts_for_volumes([f"{f}:/home/node/.claude.json:rw"]) == []

    def test_expands_env_var_in_host_path(self, tmp_path, monkeypatch):
        """${PROJECT_DIR} (and friends) must be expanded, not passed
        through to Lima as a literal path."""
        proj = tmp_path / "proj"
        proj.mkdir()
        monkeypatch.setenv("PROJECT_DIR", str(proj))
        mounts = _extra_mounts_for_volumes(["${PROJECT_DIR}:/workspace:rw"])
        assert len(mounts) == 1
        assert mounts[0]["location"] == os.path.realpath(str(proj))
        assert mounts[0]["writable"] is True

    def test_skips_unexpanded_env_var(self, monkeypatch):
        """If a variable cannot be expanded, the literal ${VAR} path must
        be skipped rather than handed to Lima."""
        monkeypatch.delenv("PROJECT_DIR", raising=False)
        assert _extra_mounts_for_volumes(["${PROJECT_DIR}:/workspace:rw"]) == []
