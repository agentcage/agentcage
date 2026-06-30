"""Tests for the live egress addon's inspector-chain orchestration.

Exercises ``addon.request()`` (the shared ``data/proxy/addon.py`` run by
both the container and apple-container egress) to assert how it handles
inspector verdicts:

  * a ``block`` result → 403 response + ``agentcage_blocked`` metadata,
  * a ``flag`` result  → request proceeds, recorded as ``flagged``,
  * no inspectors / all abstain → ``allowed`` passthrough.

These ported from the (now-deleted) apple ``allowlist_addon`` chain tests,
retargeted at the live addon so the orchestration stays covered on the
code that actually ships.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

# ── Stub mitmproxy before importing the addon ────────────
_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []
_mitmproxy.ctx = MagicMock()
_mitmproxy.http = MagicMock()
_proxy = types.ModuleType("mitmproxy.proxy")
_proxy.__path__ = []
_mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
_mitmproxy.proxy = _proxy
_proxy.mode_specs = _mode_specs
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)
sys.modules.setdefault("mitmproxy.proxy", _proxy)
sys.modules.setdefault("mitmproxy.proxy.mode_specs", _mode_specs)


class _StubReverseMode:
    pass


sys.modules["mitmproxy.proxy.mode_specs"].ReverseMode = _StubReverseMode

_PROXY_DIR = (
    Path(__file__).resolve().parent.parent
    / "src" / "agentcage" / "data" / "proxy"
)
if str(_PROXY_DIR) not in sys.path:
    sys.path.insert(0, str(_PROXY_DIR))

for _mod in ("addon", "secret_injector"):
    sys.modules.pop(_mod, None)

from addon import Agentcage  # noqa: E402
from inspectors.base import InspectionResult  # noqa: E402
from secret_injector import SecretInjector  # noqa: E402


class _Headers(dict):
    def items(self, multi=False):  # noqa: ARG002
        return list(super().items())

    def get(self, key, default=None):  # type: ignore[override]
        kl = key.lower()
        for k, v in super().items():
            if k.lower() == kl:
                return v
        return default

    def keys(self):  # type: ignore[override]
        return list(super().keys())


class _FakeInspector:
    """Returns a fixed verdict for every request; abstains on responses."""

    def __init__(self, result):
        self._result = result

    def inspect_request(self, ctx):  # noqa: ARG002
        return self._result

    def inspect_response(self, ctx):  # noqa: ARG002
        return None


def _build_addon(tmp_path, inspectors):
    addon = Agentcage()
    addon.cfg = {}
    addon.log_allowed = True
    addon.inspectors = inspectors
    addon._rl_rate = 0.0
    addon._rl_burst = 0
    addon._rl_buckets = {}
    addon._audit_file = (tmp_path / "audit.jsonl").open("a")
    addon._cap_pending = {}
    addon.injector = SecretInjector()
    addon.injector.rules = []
    addon.injector.redact_to = []
    addon._capture = None

    def _make_response(status, body, headers):
        resp = MagicMock()
        resp.status_code = status
        resp.content = body
        resp.headers = headers
        return resp

    from mitmproxy import http as _http
    _http.Response.make.side_effect = _make_response
    return addon


def _make_flow():
    """A clean outbound HTTPS flow whose SNI == Host so it passes the
    SNI/Host gate and reaches the inspector chain."""
    flow = MagicMock()
    flow.id = "test-flow-inspector-chain"
    flow.metadata = {}
    flow.request.url = "https://api.example.com/v1/do"
    flow.request.host = "api.example.com"
    flow.request.pretty_host = "api.example.com"
    flow.request.host_header = "api.example.com"
    flow.request.pretty_url = flow.request.url
    flow.request.path = "/v1/do"
    flow.request.port = 443
    flow.request.method = "POST"
    flow.request.http_version = "HTTP/1.1"
    flow.request.headers = _Headers({"Content-Type": "application/json",
                                     "Host": "api.example.com"})
    flow.request.content = b"{}"
    flow.request.get_text.side_effect = (
        lambda strict=False: flow.request.content.decode("utf-8", "replace")
    )
    flow.client_conn.sni = "api.example.com"
    flow.client_conn.tls_established = True
    flow.client_conn.address = ("127.0.0.1", 12345)
    flow.client_conn.proxy_mode = MagicMock()
    flow.response = None
    return flow


def _was_blocked(flow):
    return (
        flow.response is not None
        and getattr(flow.response, "status_code", None) == 403
    )


def _audit_decisions(tmp_path):
    text = (tmp_path / "audit.jsonl").read_text()
    return [json.loads(line)["decision"] for line in text.splitlines() if line]


def test_inspector_block_returns_403(tmp_path):
    """A ``block`` verdict makes the addon synthesize a 403 and mark the
    flow blocked — the request never reaches the upstream."""
    insp = _FakeInspector(InspectionResult(
        inspector="test-block", action="block", reason="nope", severity="error",
    ))
    addon = _build_addon(tmp_path, [insp])
    flow = _make_flow()

    addon.request(flow)

    assert _was_blocked(flow)
    assert flow.metadata.get("agentcage_blocked") is True
    assert "nope" in flow.response.content.decode()
    assert "blocked" in _audit_decisions(tmp_path)


def test_inspector_flag_does_not_block(tmp_path):
    """A ``flag`` verdict records the hit but lets the request through."""
    insp = _FakeInspector(InspectionResult(
        inspector="test-flag", action="flag", reason="suspicious", severity="warning",
    ))
    addon = _build_addon(tmp_path, [insp])
    flow = _make_flow()

    addon.request(flow)

    assert not _was_blocked(flow)
    assert flow.metadata.get("agentcage_blocked") is not True
    assert _audit_decisions(tmp_path) == ["flagged"]


def test_no_inspectors_is_passthrough(tmp_path):
    """An empty inspector chain (the common legacy-cage case) allows the
    request — recorded as ``allowed``, never blocked."""
    addon = _build_addon(tmp_path, [])
    flow = _make_flow()

    addon.request(flow)

    assert not _was_blocked(flow)
    assert _audit_decisions(tmp_path) == ["allowed"]


# ── Relay inspector chain ────────────────────────────────


def _addon_with_inspectors(cfg, inspectors):
    addon = Agentcage()
    addon.cfg = cfg
    addon.inspectors = inspectors
    return addon


def _secret_ctx():
    """An InspectionContext carrying a leaked AWS key in the body."""
    from inspectors.base import InspectionContext

    return InspectionContext(
        url="https://relay.local/",
        host="relay.local",
        method="POST",
        headers=[],
        content_type="text/plain",
        body_bytes=b"access_key=AKIAIOSFODNN7EXAMPLE",
        body_text="access_key=AKIAIOSFODNN7EXAMPLE",
        body_size=31,
    )


def _relay_secrets(addon):
    """The secrets entry in the relay chain (a wrapper, name == 'secrets')."""
    return next(i for i in addon._build_relay_inspectors() if i.name == "secrets")


def test_relay_chain_strips_domain_inspector():
    """DomainInspector is HTTP-host shaped and must not run on relay
    (SMTP) traffic."""
    from inspectors.domain import DomainInspector
    from inspectors.secrets import SecretsInspector

    dom = DomainInspector()
    dom.configure({})
    sec = SecretsInspector()
    sec.configure({"enabled": True})
    addon = _addon_with_inspectors({"secrets": {}}, [dom, sec])

    chain = addon._build_relay_inspectors()

    assert not any(isinstance(i, DomainInspector) for i in chain)
    assert any(i.name == "secrets" for i in chain)


def test_relay_secrets_defaults_to_block_when_http_flags():
    """HTTP egress defaults the secrets inspector to flag; the relay view
    must still hard-block by default (email body is a deliberate exfil
    channel)."""
    from inspectors.secrets import SecretsInspector

    sec = SecretsInspector()
    sec.configure({"enabled": True})  # -> action "flag" (new HTTP default)
    assert sec.inspect_request(_secret_ctx()).action == "flag"
    addon = _addon_with_inspectors({"secrets": {}}, [sec])

    relay_sec = _relay_secrets(addon)
    assert relay_sec.inspect_request(_secret_ctx()).action == "block"
    # The shared HTTP instance still flags (verdict unchanged for HTTP).
    assert sec.inspect_request(_secret_ctx()).action == "flag"


def test_relay_secrets_honors_explicit_flag_action():
    """An explicit secrets.action: flag wins everywhere — the relay does
    not override it back to block."""
    from inspectors.secrets import SecretsInspector

    sec = SecretsInspector()
    sec.configure({"enabled": True, "action": "flag"})
    addon = _addon_with_inspectors({"secrets": {"action": "flag"}}, [sec])

    assert _relay_secrets(addon).inspect_request(_secret_ctx()).action == "flag"


def test_relay_secrets_tracks_hot_reload_of_shared_instance():
    """The relay wrapper delegates to the live shared instance, so an
    allow_to_domains exemption added on hot-reload (reconfigure in place)
    is honoured on the relay path too — no stale clone."""
    from inspectors.secrets import SecretsInspector

    sec = SecretsInspector()
    sec.configure({"enabled": True})
    addon = _addon_with_inspectors({"secrets": {}}, [sec])
    relay_sec = _relay_secrets(addon)

    # Before reload: a leaked AWS key to relay.local is caught (blocked).
    assert relay_sec.inspect_request(_secret_ctx()).action == "block"

    # Operator edits config and the addon reconfigures in place.
    sec.configure({"enabled": True, "allow_to_domains": {"aws_access_key": ["relay.local"]}})

    # The same wrapper now reflects the new exemption (abstains).
    assert relay_sec.inspect_request(_secret_ctx()) is None


def test_relay_secrets_honors_action_from_inspectors_list():
    """action set via the `inspectors:` list (not the top-level `secrets:`
    block) is still honoured by the relay — explicitness is read from the
    configured instance, not re-parsed from one config path."""
    from inspectors.secrets import SecretsInspector

    sec = SecretsInspector()
    # Simulates _load_custom_inspectors reconfiguring the built-in with the
    # inspectors-list `config:` section.
    sec.configure({"enabled": True, "action": "flag"})
    addon = _addon_with_inspectors(
        {"inspectors": [{"name": "secrets", "config": {"action": "flag"}}]},
        [sec],
    )

    assert _relay_secrets(addon).inspect_request(_secret_ctx()).action == "flag"
