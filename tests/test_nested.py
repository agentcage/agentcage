"""Tests for nested container support (podman-in-podman)."""

import textwrap

import pytest

from agentcage.config import load_config, validate_config
from agentcage.quadlets import generate_quadlets


# ── Config parsing ──────────────────────────────────────


class TestNestedConfigParsing:
    def test_default_false(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.container.nested_containers is False

    def test_explicit_true(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              nested_containers: true
        """))
        cfg = load_config(str(p))
        assert cfg.container.nested_containers is True

    def test_explicit_false(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              nested_containers: false
        """))
        cfg = load_config(str(p))
        assert cfg.container.nested_containers is False


# ── Config validation ───────────────────────────────────


class TestNestedConfigValidation:
    def test_warning_emitted(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              nested_containers: true
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert any("nested_containers" in w for w in warnings)
        assert any("elevated capabilities" in w for w in warnings)

    def test_vm_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
              nested_containers: true
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="nested_containers.*not supported.*vm"):
            validate_config(cfg)

    def test_no_warning_when_disabled(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        warnings = validate_config(cfg)
        assert not any("nested_containers" in w for w in warnings)


# ── Quadlet generation ──────────────────────────────────


class TestNestedQuadletGeneration:
    @pytest.fixture
    def nested_yaml(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/agentcage-nested
              nested_containers: true
        """))
        return str(p)

    def test_generates_storage_volume(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        assert "test-podman-storage.volume" in files
        content = files["test-podman-storage.volume"]
        assert "VolumeName=agentcage-podman-test" in content

    def test_five_files_generated_with_nested(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        # v0.22: net + certs + cage + egress + podman-storage = 5
        # (was 6 with the legacy proxy + dns pair, now collapsed to
        # a single egress quadlet).
        assert len(files) == 5

    def test_capabilities_overridden(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        # Should NOT drop ALL capabilities
        assert "DropCapability=ALL" not in content
        # Should add nested-required capabilities
        for cap in ("SYS_ADMIN", "SYS_CHROOT", "MKNOD", "SETUID", "SETGID",
                     "CHOWN", "DAC_OVERRIDE", "FOWNER"):
            assert f"AddCapability={cap}" in content

    def test_no_new_privileges_false(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "NoNewPrivileges=true" not in content

    def test_runs_as_root(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "User=0" in content

    def test_fuse_device(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "AddDevice=/dev/fuse" in content

    def test_storage_volume_mount(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Volume=test-podman-storage.volume:/var/lib/containers:rw" in content

    def test_docker_shim_mount(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Volume=/patches/nested/docker:/usr/local/bin/docker:ro,Z" in content

    def test_config_file_mounts(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Volume=/patches/nested/storage.conf:/etc/containers/storage.conf:ro,Z" in content
        assert "Volume=/patches/nested/containers.conf:/etc/containers/containers.conf:ro,Z" in content
        assert "Volume=/patches/nested/registries.conf:/etc/containers/registries.conf:ro,Z" in content

    def test_run_tmpfs(self, nested_yaml):
        cfg = load_config(nested_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Tmpfs=/run:rw,exec,size=256M" in content


# ── Default behavior unchanged ──────────────────────────


class TestNestedDisabledDefault:
    def test_four_files_when_disabled(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        # v0.22: net + certs + cage + egress = 4 (was 5; proxy + dns
        # merged into the single egress quadlet).
        assert len(files) == 4
        assert "test-podman-storage.volume" not in files

    def test_no_fuse_device_when_disabled(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "AddDevice=/dev/fuse" not in content

    def test_drop_all_caps_when_disabled(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "DropCapability=ALL" in content

    def test_no_new_privileges_when_disabled(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "NoNewPrivileges=true" in content

    def test_no_nested_volumes_when_disabled(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "/var/lib/containers" not in content
        assert "/usr/local/bin/docker" not in content


# ── User-specified capabilities preserved ───────────────


class TestNestedWithUserCapabilities:
    def test_user_caps_merged(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              nested_containers: true
              add_capabilities:
                - NET_BIND_SERVICE
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        # User capability preserved
        assert "AddCapability=NET_BIND_SERVICE" in content
        # Nested capabilities added
        assert "AddCapability=SYS_ADMIN" in content
        assert "AddCapability=MKNOD" in content

    def test_no_duplicate_caps(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              nested_containers: true
              add_capabilities:
                - SYS_ADMIN
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        # SYS_ADMIN should appear exactly once
        assert content.count("AddCapability=SYS_ADMIN") == 1
