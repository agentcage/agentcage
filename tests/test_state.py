"""Unit tests for agentcage.state — deployment state management."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import yaml

from agentcage.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_minimal_config(path: Path) -> Path:
    """Write a minimal cage.yaml and return the file path."""
    cfg = path / "config.yaml"
    cfg.write_text(textwrap.dedent("""\
        name: test
        container:
          image: localhost/test:latest
    """))
    return cfg


def _write_full_config(path: Path) -> Path:
    """Write a config that contains proxy and non-proxy keys."""
    cfg = path / "config.yaml"
    cfg.write_text(textwrap.dedent("""\
        name: myapp
        container:
          image: node:22-slim
        domains:
          allow:
            - example.com
        secrets:
          MY_KEY: secret123
        max_request_body: 4096
        entropy: true
        content_type: application/json
        inspectors:
          - type: keyword
        rate_limit:
          rpm: 60
        logging:
          level: info
        secret_injection:
          - env: MY_KEY
        capture: true
        dns_servers:
          - 1.1.1.1
    """))
    return cfg


@pytest.fixture
def _patch_state_dirs(tmp_path, monkeypatch):
    """Patch agentcage.state module-level dirs to use tmp_path, auto-reverted."""
    import agentcage.state as state
    config_dir = tmp_path / "config" / "agentcage"
    monkeypatch.setattr(state, "_CONFIG_DIR", config_dir)
    monkeypatch.setattr(state, "_DEPLOYMENTS_DIR", config_dir / "cages")
    return state


@pytest.fixture
def _patch_state_data_dir(tmp_path, monkeypatch):
    """Patch agentcage.state _DATA_DIR to use tmp_path, auto-reverted."""
    import agentcage.state as state
    monkeypatch.setattr(state, "_DATA_DIR", tmp_path / "data" / "agentcage")
    return state


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSaveAndLoadDeployment:
    """save_deployment / load_deployment_config round-trip."""

    def test_round_trip(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("demo", str(cfg_file))

        loaded = state.load_deployment_config("demo")
        assert isinstance(loaded, Config)
        assert loaded.name == "test"
        assert loaded.container.image == "localhost/test:latest"

    def test_load_missing_raises(self, _patch_state_dirs):
        state = _patch_state_dirs
        with pytest.raises(FileNotFoundError):
            state.load_deployment_config("nonexistent")


class TestSaveProxyConfig:
    """save_proxy_config should only keep _PROXY_KEYS."""

    def test_filters_keys(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_full_config(tmp_path)
        state.save_deployment("myapp", str(cfg_file))
        proxy_path = state.save_proxy_config("myapp")

        with open(proxy_path) as f:
            proxy_cfg = yaml.safe_load(f)

        # Proxy keys should be present
        assert "domains" in proxy_cfg
        assert "secrets" in proxy_cfg
        assert "max_request_body" in proxy_cfg

        # Non-proxy keys should be absent
        assert "container" not in proxy_cfg
        assert "dns_servers" not in proxy_cfg
        assert "name" not in proxy_cfg

    def test_protocol_relays_passes_through(self, tmp_path, _patch_state_dirs):
        """The proxy needs `protocol_relays` to start its IMAP/SMTP/etc.
        listeners — without this key in the filter, the relay never boots."""
        state = _patch_state_dirs
        cfg = tmp_path / "config.yaml"
        cfg.write_text(textwrap.dedent("""\
            name: myapp
            container:
              image: node:22-slim
            domains:
              allow:
                - example.com
            protocol_relays:
              - name: migadu-imap
                type: imap
                listen: "127.0.0.1:1143"
                upstream:
                  host: imap.migadu.com
                  port: 993
                auth:
                  type: imap-login
                  user_source: "podman:MIGADU_USER"
                  password_source: "podman:MIGADU_PASSWORD"
        """))
        state.save_deployment("myapp", str(cfg))
        proxy_path = state.save_proxy_config("myapp")
        with open(proxy_path) as f:
            proxy_cfg = yaml.safe_load(f)
        assert "protocol_relays" in proxy_cfg
        assert proxy_cfg["protocol_relays"][0]["name"] == "migadu-imap"


class TestResolveRelayCaFiles:
    """`upstream.ca_file` is a host path; the relay runs in the proxy
    container. The CLI reads it at deploy time and hands the proxy the
    contents, so a rotated certificate is picked up by `cage restart`
    with no config edit and no per-backend bind-mount plumbing."""

    PEM = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBfakeexamplecertificatebody\n"
        "-----END CERTIFICATE-----\n"
    )

    def _cfg(self, ca_file) -> dict:
        return {
            "protocol_relays": [{
                "name": "bridge-imap",
                "type": "imap",
                "upstream": {"host": "10.88.0.5", "port": 1143,
                             "tls": True, "ca_file": str(ca_file)},
            }]
        }

    def test_reads_the_file_into_ca_pem(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cert = tmp_path / "bridge.pem"
        cert.write_text(self.PEM)

        out = state.resolve_relay_ca_files(self._cfg(cert))
        upstream = out["protocol_relays"][0]["upstream"]

        assert upstream["ca_pem"] == self.PEM
        # The path is consumed, not forwarded: it would be meaningless
        # inside the proxy container and invites a stale second source.
        assert "ca_file" not in upstream

    def test_expands_user_and_vars(self, tmp_path, _patch_state_dirs, monkeypatch):
        state = _patch_state_dirs
        cert = tmp_path / "bridge.pem"
        cert.write_text(self.PEM)
        monkeypatch.setenv("CERT_HOME", str(tmp_path))

        out = state.resolve_relay_ca_files(self._cfg("$CERT_HOME/bridge.pem"))
        assert out["protocol_relays"][0]["upstream"]["ca_pem"] == self.PEM

    def test_missing_file_fails_at_deploy(self, tmp_path, _patch_state_dirs):
        """Better a refused deploy than a relay that can't verify its
        upstream at 3am and says only 'certificate verify failed'."""
        state = _patch_state_dirs
        with pytest.raises(ValueError, match="cannot read"):
            state.resolve_relay_ca_files(self._cfg(tmp_path / "absent.pem"))

    def test_non_pem_file_fails_at_deploy(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        junk = tmp_path / "notacert.pem"
        junk.write_text("this is not a certificate\n")
        with pytest.raises(ValueError, match="no PEM certificate"):
            state.resolve_relay_ca_files(self._cfg(junk))

    def test_relays_without_ca_file_are_untouched(self, _patch_state_dirs):
        state = _patch_state_dirs
        cfg = {"protocol_relays": [
            {"name": "migadu-imap",
             "upstream": {"host": "imap.migadu.com", "port": 993}},
        ]}
        assert state.resolve_relay_ca_files(cfg) == cfg

    def test_does_not_mutate_the_stored_cage_config(
        self, tmp_path, _patch_state_dirs
    ):
        """The rewrite must not leak back into cage.yaml — the operator
        wrote a path and should keep seeing a path, not a wall of PEM."""
        state = _patch_state_dirs
        cert = tmp_path / "bridge.pem"
        cert.write_text(self.PEM)
        cfg = tmp_path / "config.yaml"
        cfg.write_text(textwrap.dedent(f"""\
            name: myapp
            container:
              image: node:22-slim
            domains:
              allow:
                - example.com
            protocol_relays:
              - name: bridge-imap
                type: imap
                listen: "0.0.0.0:1243"
                upstream:
                  host: 10.88.0.5
                  port: 1143
                  tls: true
                  ca_file: "{cert}"
                auth:
                  type: imap-login
                  user_source: "podman:BRIDGE_USER"
                  password_source: "podman:BRIDGE_PASSWORD"
        """))
        state.save_deployment("myapp", str(cfg))
        proxy_path = state.save_proxy_config("myapp")

        with open(proxy_path) as f:
            proxy_cfg = yaml.safe_load(f)
        relay_upstream = proxy_cfg["protocol_relays"][0]["upstream"]
        assert relay_upstream["ca_pem"] == self.PEM
        assert "ca_file" not in relay_upstream

        stored = state.load_raw_config("myapp")
        stored_upstream = stored["protocol_relays"][0]["upstream"]
        assert stored_upstream["ca_file"] == str(cert)
        assert "ca_pem" not in stored_upstream


class TestSaveDnsAllowlist:
    """save_dns_allowlist writes dnsmasq's --servers-file format from cage.yaml."""

    def test_writes_one_line_per_domain_upstream_pair(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg = tmp_path / "config.yaml"
        cfg.write_text(textwrap.dedent("""\
            name: app
            container:
              image: localhost/app:latest
            domains:
              allow:
                - api.example.com
                - github.com
            dns_servers:
              - 1.1.1.1
              - 8.8.8.8
        """))
        state.save_deployment("app", str(cfg))
        path = state.save_dns_allowlist("app")
        body = Path(path).read_text().splitlines()
        # 2 domains × 2 upstreams = 4 lines, deterministic order
        assert body == [
            "server=/api.example.com/1.1.1.1",
            "server=/api.example.com/8.8.8.8",
            "server=/github.com/1.1.1.1",
            "server=/github.com/8.8.8.8",
        ]

    def test_empty_when_not_in_allowlist_mode(self, tmp_path, _patch_state_dirs):
        """Block-mode and the implicit no-domains case must produce an empty
        file — dnsmasq tolerates an empty --servers-file fine, and the
        sinkhole flag is gated separately on allowlist mode."""
        state = _patch_state_dirs
        cfg = tmp_path / "config.yaml"
        cfg.write_text(textwrap.dedent("""\
            name: app
            container:
              image: localhost/app:latest
            domains:
              block:
                - bad.example
            dns_servers:
              - 1.1.1.1
        """))
        state.save_deployment("app", str(cfg))
        path = state.save_dns_allowlist("app")
        assert Path(path).read_text() == ""

    def test_passthrough_merged_into_dns_lines(self, tmp_path, _patch_state_dirs):
        """Passthrough domains must resolve via real DNS too, so they belong
        in the allowlist file alongside regular allow entries."""
        state = _patch_state_dirs
        cfg = tmp_path / "config.yaml"
        cfg.write_text(textwrap.dedent("""\
            name: app
            container:
              image: localhost/app:latest
            domains:
              allow:
                - allowed.example
              passthrough:
                - passthrough.example
            dns_servers:
              - 1.1.1.1
        """))
        state.save_deployment("app", str(cfg))
        body = Path(state.save_dns_allowlist("app")).read_text()
        assert "server=/allowed.example/1.1.1.1" in body
        assert "server=/passthrough.example/1.1.1.1" in body


class TestSaveAndLoadMetadata:
    """save_metadata / load_metadata round-trip."""

    def test_round_trip(self, _patch_state_dirs):
        state = _patch_state_dirs
        meta = {"backend": "container", "created": "2025-01-01"}
        state.save_metadata("demo", meta)

        loaded = state.load_metadata("demo")
        assert loaded == meta

    def test_load_missing_returns_empty(self, _patch_state_dirs):
        state = _patch_state_dirs
        assert state.load_metadata("nonexistent") == {}


class TestListDeployments:
    def test_empty(self, _patch_state_dirs):
        state = _patch_state_dirs
        assert state.list_deployments() == []

    def test_multiple(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("alpha", str(cfg_file))
        state.save_deployment("beta", str(cfg_file))

        result = state.list_deployments()
        assert result == ["alpha", "beta"]

    def test_ignores_dirs_without_cage_yaml(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        # Create a directory without cage.yaml
        (state._DEPLOYMENTS_DIR / "orphan").mkdir(parents=True)

        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("valid", str(cfg_file))

        assert state.list_deployments() == ["valid"]


class TestDeploymentExistsAndDir:
    def test_exists_true(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("demo", str(cfg_file))

        assert state.deployment_exists("demo") is True

    def test_exists_false(self, _patch_state_dirs):
        state = _patch_state_dirs
        assert state.deployment_exists("nope") is False

    def test_deployment_dir_path(self, _patch_state_dirs):
        state = _patch_state_dirs
        d = state.deployment_dir("demo")
        assert d == state._DEPLOYMENTS_DIR / "demo"


class TestCapturePaths:
    def test_capture_dir_created(self, _patch_state_data_dir):
        state = _patch_state_data_dir
        d = state.capture_dir("myapp")
        assert d.is_dir()
        assert d == state._DATA_DIR / "myapp" / "capture"

    def test_capture_file_path(self, _patch_state_data_dir):
        state = _patch_state_data_dir
        f = state.capture_file("myapp")
        assert f == state._DATA_DIR / "myapp" / "capture" / "capture.jsonl"


class TestEdgeCases:
    def test_corrupted_yaml(self, _patch_state_dirs):
        state = _patch_state_dirs
        # Manually write corrupted YAML
        d = state._DEPLOYMENTS_DIR / "bad"
        d.mkdir(parents=True)
        (d / "cage.yaml").write_text(": : : not valid yaml [[[")

        # load_raw_config should either raise or return something
        # The yaml parser may raise an exception
        with pytest.raises(Exception):
            state.load_raw_config("bad")

    def test_empty_config_file(self, _patch_state_dirs):
        state = _patch_state_dirs
        d = state._DEPLOYMENTS_DIR / "empty"
        d.mkdir(parents=True)
        (d / "cage.yaml").write_text("")

        raw = state.load_raw_config("empty")
        assert raw == {}

    def test_remove_deployment(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("todelete", str(cfg_file))
        assert state.deployment_exists("todelete")

        state.remove_deployment("todelete")
        assert not state.deployment_exists("todelete")
