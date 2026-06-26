"""Shared fixtures for agentcage tests."""

import sys
import textwrap
import types
from unittest.mock import MagicMock

import pytest


# ── Stub mitmproxy at collection time ────────────────────────
# The proxy modules (addon, secret_injector) import mitmproxy at
# top-level. Stub it before any test module imports them so the
# tests can run on the host without the proxy container's deps.
_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []
_mitmproxy.ctx = MagicMock()
_mitmproxy.http = MagicMock()
_proxy = types.ModuleType("mitmproxy.proxy")
_proxy.__path__ = []
_mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
_mode_specs.ReverseMode = MagicMock()
_mitmproxy.proxy = _proxy
_proxy.mode_specs = _mode_specs
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)
sys.modules.setdefault("mitmproxy.proxy", _proxy)
sys.modules.setdefault("mitmproxy.proxy.mode_specs", _mode_specs)


@pytest.fixture(autouse=True)
def _isolate_host_dns(monkeypatch):
    """Stub host DNS auto-detection for the whole unit suite.

    ``load_config()`` calls ``_host_dns_servers()`` whenever a config omits
    ``dns_servers``. On a host whose ``/etc/resolv.conf`` only lists loopback
    resolvers (systemd-resolved stubs, a local DNS proxy, a sandbox, etc.)
    and which has no ``/run/systemd/resolve/resolv.conf``, that raises — so
    every test that loads a config without pinning ``dns_servers`` would fail
    for reasons unrelated to what it asserts. Pin a deterministic upstream
    here so the unit suite never depends on the host resolver.

    Tests that specifically exercise detection (``test_*dns*`` /
    ``TestHostDnsServers``) re-``monkeypatch`` ``_host_dns_servers`` or the
    lower-level ``_read_nameservers`` / ``_scutil_dns_servers`` in their own
    body; those later setattrs override this one and are restored normally.
    """
    monkeypatch.setattr(
        "agentcage.config._host_dns_servers", lambda: ["1.1.1.1"]
    )


@pytest.fixture
def patch_state_dirs(tmp_path, monkeypatch):
    """Redirect agentcage.state's filesystem roots into tmp_path. Prevents
    tests that exercise save_proxy_config / save_dns_allowlist / etc. from
    writing into the developer's real ~/.config/agentcage."""
    import agentcage.state as state
    config_dir = tmp_path / "config" / "agentcage"
    monkeypatch.setattr(state, "_CONFIG_DIR", config_dir)
    monkeypatch.setattr(state, "_DEPLOYMENTS_DIR", config_dir / "cages")
    monkeypatch.setattr(state, "_DATA_DIR", tmp_path / "data" / "agentcage")
    return state


@pytest.fixture
def minimal_yaml(tmp_path):
    """Write a minimal valid config and return its path."""
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent("""\
        name: test
        container:
          image: localhost/test:latest
    """))
    return str(p)


@pytest.fixture
def full_yaml(tmp_path):
    """Write a config with all fields populated and return its path."""
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent("""\
        name: myapp
        container:
          image: "node:22-slim"
          command: ["node", "/app/agent.js"]
          volumes:
            - "./agent:/app:ro"
          env:
            ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"
            STATIC_VAR: "hello"
          named_volumes:
            myapp-data: "/data:rw"
          tmpfs:
            - "/tmp:rw,noexec,nosuid,size=64M"
          ports:
            - "127.0.0.1:3000:3000"
          podman_secrets:
            - MY_API_KEY
            - INJECTED_KEY
          user: ""
          memory: "4g"
          cpus: "2.0"
          read_only: false
          drop_capabilities: []
          add_capabilities:
            - NET_BIND_SERVICE
          no_new_privileges: false
          security_label_disable: false
          restart: "no"
          restart_sec: 0
          timeout_start_sec: 300
          timeout_stop_sec: 60
        secret_injection:
          - env: INJECTED_KEY
            placeholder: "{{INJECTED_KEY}}"
            inject_to:
              - api.example.com
        dns_servers:
          - 100.100.100.100
          - 1.1.1.1
    """))
    return str(p)


@pytest.fixture
def openclaw_yaml(tmp_path):
    """Write an openclaw-style config and return its path."""
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent("""\
        name: openclaw
        container:
          image: "ghcr.io/openclaw/openclaw:latest"
          command:
            - "/usr/local/bin/entrypoint.sh"
          volumes:
            - "${HOME}/openclaw-workspace:/workspace:rw"
          named_volumes:
            openclaw-state: "/home/node/.openclaw:rw"
          tmpfs:
            - "/tmp:rw,noexec,nosuid,size=64M"
            - "/home/node/.npm:rw,size=128M"
            - "/scratch:rw,exec,nosuid,size=256M"
          ports:
            - "127.0.0.1:18789:18789"
          env:
            OPENCLAW_DISABLE_BONJOUR: "1"
          podman_secrets:
            - OPENCLAW_GATEWAY_PASSWORD
          memory: "4g"
          cpus: "2.0"
          timeout_start_sec: 120
        secret_injection:
          - env: ANTHROPIC_API_KEY
            placeholder: "{{ANTHROPIC_API_KEY}}"
            inject_to:
              - anthropic.com
        domains:
          allow:
            - anthropic.com
            - npmjs.org
            - github.com
        exec_aliases:
          openclaw: ["node", "openclaw.mjs"]
        help: |
          Open http://localhost:18789 in your browser.
    """))
    return str(p)
