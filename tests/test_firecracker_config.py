"""Tests for Firecracker-related config parsing and validation."""

import textwrap

import pytest

from agentcage.config import FirecrackerConfig, load_config, validate_config


class TestFirecrackerConfigDefaults:
    def test_default_isolation_is_container(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.isolation == "container"

    def test_default_firecracker_config(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        fc = cfg.firecracker
        assert fc.kernel == ""
        assert fc.vcpus == 2
        assert fc.mem_mb == 2048
        assert fc.firecracker_bin == "firecracker"


class TestFirecrackerConfigParsing:
    def test_isolation_field(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
            firecracker:
              kernel: /opt/firecracker/vmlinux
        """))
        cfg = load_config(str(p))
        assert cfg.isolation == "firecracker"

    def test_all_firecracker_fields(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
            firecracker:
              kernel: /boot/vmlinux
              vcpus: 4
              mem_mb: 4096
              firecracker_bin: /usr/bin/firecracker
        """))
        cfg = load_config(str(p))
        fc = cfg.firecracker
        assert fc.kernel == "/boot/vmlinux"
        assert fc.vcpus == 4
        assert fc.mem_mb == 4096
        assert fc.firecracker_bin == "/usr/bin/firecracker"

    def test_container_mode_ignores_firecracker_section(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: container
            container:
              image: test:latest
            firecracker:
              kernel: /boot/vmlinux
        """))
        cfg = load_config(str(p))
        assert cfg.isolation == "container"
        # Firecracker section is parsed but not validated in container mode
        assert cfg.firecracker.kernel == "/boot/vmlinux"


class TestFirecrackerValidation:
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

    def test_firecracker_defaults_kernel_when_empty(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.firecracker.kernel == ""
        validate_config(cfg)
        assert "vmlinux" in cfg.firecracker.kernel
        assert cfg.firecracker.kernel != ""

    def test_firecracker_vcpus_minimum(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
            firecracker:
              kernel: /boot/vmlinux
              vcpus: 0
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="vcpus"):
            validate_config(cfg)

    def test_firecracker_mem_minimum(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
            firecracker:
              kernel: /boot/vmlinux
              mem_mb: 64
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="mem_mb"):
            validate_config(cfg)

    def test_valid_firecracker_config(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: firecracker
            container:
              image: test:latest
            firecracker:
              kernel: /boot/vmlinux
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert warnings == []

    def test_container_mode_no_kernel_required(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        warnings = validate_config(cfg)
        assert warnings == []
