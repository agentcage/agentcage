"""Tests for VM/isolation config parsing and validation."""

import platform
import textwrap
from unittest.mock import patch

import pytest

from agentcage.config import VmConfig, load_config, validate_config

# These assert the *Linux* default isolation (``container``). On macOS the
# default is apple-container/vm (container is rejected), so the Linux-default
# assertions only hold on the Linux CI.
LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="asserts the Linux default isolation (container); macOS defaults differ",
)


class TestVmConfigDefaults:
    @LINUX_ONLY
    def test_default_isolation_is_container(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.isolation == "container"

    def test_default_vm_config(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        vm = cfg.vm
        assert vm.vcpus == 4
        assert vm.mem_mb == 4096


class TestVmConfigParsing:
    def test_isolation_vm_field(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
            vm:
              vcpus: 4
              mem_mb: 4096
        """))
        cfg = load_config(str(p))
        assert cfg.isolation == "vm"
        assert cfg.vm.vcpus == 4
        assert cfg.vm.mem_mb == 4096

    def test_firecracker_isolation_migrated_to_vm(self, tmp_path):
        """isolation: firecracker in YAML is silently mapped to 'vm'."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
            firecracker:
              vcpus: 2
              mem_mb: 2048
        """))
        cfg = load_config(str(p))
        assert cfg.isolation == "vm"

    def test_firecracker_section_used_as_vm_fallback(self, tmp_path):
        """vcpus/mem_mb from firecracker: section are read into vm config."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
            firecracker:
              vcpus: 8
              mem_mb: 8192
        """))
        cfg = load_config(str(p))
        assert cfg.vm.vcpus == 8
        assert cfg.vm.mem_mb == 8192

    def test_vm_section_preferred_over_firecracker(self, tmp_path):
        """Explicit vm: section takes priority over firecracker: fallback."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
            vm:
              vcpus: 3
              mem_mb: 3072
            firecracker:
              vcpus: 8
              mem_mb: 8192
        """))
        cfg = load_config(str(p))
        assert cfg.vm.vcpus == 3
        assert cfg.vm.mem_mb == 3072

    def test_container_mode_ignores_vm_section(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: container
            container:
              image: test:latest
            vm:
              vcpus: 4
        """))
        cfg = load_config(str(p))
        assert cfg.isolation == "container"
        # vm section is parsed but not validated in container mode
        assert cfg.vm.vcpus == 4


class TestVmValidation:
    def test_invalid_isolation_mode(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: invalid
            container:
              image: test:latest
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="isolation"):
            validate_config(cfg)

    def test_vm_vcpus_minimum(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
            vm:
              vcpus: 0
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="vcpus"):
            validate_config(cfg)

    def test_vm_mem_minimum(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
            vm:
              mem_mb: 64
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="mem_mb"):
            validate_config(cfg)

    def test_valid_vm_config(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
            vm:
              vcpus: 2
              mem_mb: 2048
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert warnings == []

    @LINUX_ONLY
    def test_container_mode_no_vm_required(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        warnings = validate_config(cfg)
        assert warnings == []

    def test_container_isolation_rejected_on_macos(self, minimal_yaml):
        # Pin the load to Linux so the default isolation is `container`
        # regardless of the host OS (on a macOS host the default would be
        # apple-container, making the first assertion misfire). The point of
        # this test is the *validation* rejection under Darwin, below.
        with patch("agentcage.config.platform.system", return_value="Linux"):
            cfg = load_config(minimal_yaml)
        assert cfg.isolation == "container"
        with patch("agentcage.config.platform.system", return_value="Darwin"):
            with pytest.raises(ValueError, match="macOS"):
                validate_config(cfg)

    def test_vm_isolation_accepted_on_macos(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
        """))
        cfg = load_config(str(p))
        with patch("agentcage.config.platform.system", return_value="Darwin"):
            warnings = validate_config(cfg)
        assert warnings == []
