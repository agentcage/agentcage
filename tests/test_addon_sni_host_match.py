"""Tests for the addon's SNI ↔ Host header match guard (CTF F3, 0.22.6).

A cage that opens TLS with ``SNI=A`` and then sends an HTTP ``Host: B``
inside that TLS gets *different* audit identities, allowlist decisions,
and secret-injection rule selections — the attacker chooses which one
fires at each decision point. mitmproxy's transparent mode happily
follows the Host header for the upstream connection, so on the wire the
request lands on B while audit logs and inspector context (keyed on the
pre-rewrite ``flow.request.host``) reference A. The 0.22.6 CTF
demonstrated this by reaching api.anthropic.com over TLS with
``SNI=evil.example`` — Cloudflare's ``set-cookie: Domain=
api.anthropic.com`` in the response confirmed the upstream was real
api.anthropic.com, no 403 from the addon.

The fix in ``addon.request()`` enforces strict equality between SNI and
the Host header (case-insensitive, port-stripped) BEFORE the
``flow.request.host = pretty_host`` rewrite. HTTP requests (no SNI)
fall through to the Host header as before.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock


# ── Stub mitmproxy before importing addon ────────────────


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
    """Real class so ``isinstance(..., ReverseMode)`` works.

    Outbound-flow tests construct a ``client_conn.proxy_mode`` MagicMock
    that is NOT an instance of this class — the addon treats those as
    transparent outbound. The reverse-mode test passes an instance.
    """


sys.modules["mitmproxy.proxy.mode_specs"].ReverseMode = _StubReverseMode

# Stage the proxy/ dir so ``from addon import Agentcage`` etc. resolve.
_PROXY_DIR = (
    Path(__file__).resolve().parent.parent
    / "src" / "agentcage" / "data" / "proxy"
)
if str(_PROXY_DIR) not in sys.path:
    sys.path.insert(0, str(_PROXY_DIR))

# Drop any previously-imported addon module so it re-imports with the
# patched ReverseMode binding.
for _mod in ("addon", "secret_injector"):
    sys.modules.pop(_mod, None)

from addon import Agentcage  # noqa: E402
from secret_injector import SecretInjector  # noqa: E402


# ── Shared helpers ──────────────────────────────────────


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


def _build_addon(tmp_path):
    """Minimal Agentcage. No inspectors; rate-limit disabled; injector
    has no rules; audit file open. Just enough to reach the SNI/Host
    check in ``request()`` and observe its block-or-not behavior."""
    addon = Agentcage()
    addon.cfg = {}
    addon.log_allowed = False
    addon.inspectors = []
    addon._rl_rate = 0.0
    addon._rl_burst = 0
    addon._rl_buckets = {}
    addon._audit_file = (tmp_path / "audit.jsonl").open("a")
    addon._cap_pending = {}
    addon.injector = SecretInjector()
    addon.injector.rules = []
    addon.injector.redact_to = []
    addon._capture = None

    # mitmproxy.http.Response.make is a MagicMock — make it record the
    # status/body/headers on a sentinel object the tests can introspect.
    def _make_response(status, body, headers):
        resp = MagicMock()
        resp.status_code = status
        resp.content = body
        resp.headers = headers
        return resp

    from mitmproxy import http as _http
    _http.Response.make.side_effect = _make_response
    return addon


def _make_flow(*, sni, host_header, reverse_mode=False,
               url="https://api.anthropic.com/v1/messages",
               method="POST"):
    """Mock an outbound HTTPS HTTPFlow for the addon's ``request`` hook.

    ``sni`` is the TLS SNI the cage committed to (or None for plain HTTP).
    ``host_header`` is the Host header inside the HTTP request (or None
    for HTTP/1.0 with no Host).
    """
    flow = MagicMock()
    flow.id = "test-flow-sni-host"
    flow.metadata = {}
    flow.request.url = url
    # Pre-rewrite, flow.request.host is the SO_ORIGINAL_DST hostname
    # mitmproxy resolved from the Host header in transparent mode.
    flow.request.host = host_header or "1.2.3.4"
    flow.request.pretty_host = host_header or "1.2.3.4"
    flow.request.host_header = host_header
    flow.request.pretty_url = url
    flow.request.path = "/v1/messages"
    flow.request.port = 443
    flow.request.method = method
    flow.request.http_version = "HTTP/1.1"
    h = {"Content-Type": "application/json"}
    if host_header:
        h["Host"] = host_header
    flow.request.headers = _Headers(h)
    flow.request.content = b"{}"
    flow.request.get_text.side_effect = (
        lambda strict=False: flow.request.content.decode("utf-8", "replace")
    )

    flow.client_conn.sni = sni
    flow.client_conn.tls_established = sni is not None
    flow.client_conn.address = ("127.0.0.1", 12345)
    if reverse_mode:
        flow.client_conn.proxy_mode = _StubReverseMode()
    else:
        flow.client_conn.proxy_mode = MagicMock()
    flow.response = None
    return flow


def _was_blocked(flow):
    return (
        flow.response is not None
        and getattr(flow.response, "status_code", None) == 403
    )


def _block_reason(flow):
    return json.loads(flow.response.content.decode())["reason"]


# ── Tests ────────────────────────────────────────────────


def test_matching_sni_and_host_passes(tmp_path):
    """SNI == Host (case-insensitive, no port) → no 403."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="api.anthropic.com",
                      host_header="api.anthropic.com")
    asyncio.run(addon.request(flow))
    assert not _was_blocked(flow)


def test_mismatched_sni_and_host_is_blocked(tmp_path):
    """The exact CTF F3 case: SNI=evil.example, Host=api.anthropic.com
    → 403 with reason naming both values."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="evil.example",
                      host_header="api.anthropic.com")
    asyncio.run(addon.request(flow))
    assert _was_blocked(flow)
    reason = _block_reason(flow)
    assert "SNI/Host header mismatch" in reason
    assert "evil.example" in reason
    assert "api.anthropic.com" in reason


def test_mismatched_sni_and_host_reversed_is_blocked(tmp_path):
    """Same mismatch with the values swapped: SNI=api.anthropic.com,
    Host=evil.example → 403. Symmetry matters — an attacker could
    pick either direction depending on which inspector they want to
    confuse."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="api.anthropic.com",
                      host_header="evil.example")
    asyncio.run(addon.request(flow))
    assert _was_blocked(flow)


def test_http_without_sni_falls_through(tmp_path):
    """Plain HTTP requests have no SNI — the Host header is the only
    authority available. Don't block; the downstream domain inspector
    still gets to enforce the allowlist on the Host header."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni=None,
                      host_header="api.anthropic.com",
                      url="http://api.anthropic.com/v1/messages")
    asyncio.run(addon.request(flow))
    assert not _was_blocked(flow)


def test_case_insensitive_match(tmp_path):
    """Hostname comparison is case-insensitive (DNS spec). A SNI of
    `Api.Anthropic.COM` must match Host `api.anthropic.com`."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="Api.Anthropic.COM",
                      host_header="api.anthropic.com")
    asyncio.run(addon.request(flow))
    assert not _was_blocked(flow)


def test_port_in_host_header_is_stripped(tmp_path):
    """Host headers can carry an explicit port (`Host: x.example:443`).
    SNI is host-only by spec, so the comparison strips the port from
    the Host header before matching."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="api.anthropic.com",
                      host_header="api.anthropic.com:443")
    asyncio.run(addon.request(flow))
    assert not _was_blocked(flow)


def test_trailing_dot_tolerated(tmp_path):
    """The FQDN trailing-dot is semantically equivalent (RFC 1035 §3.1)
    and must not cause a false-positive mismatch."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="api.anthropic.com.",
                      host_header="api.anthropic.com")
    asyncio.run(addon.request(flow))
    assert not _was_blocked(flow)


def test_bytes_sni_is_decoded(tmp_path):
    """Some mitmproxy versions surface the SNI as bytes (IDN-encoded).
    The check must decode to str before comparing."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni=b"api.anthropic.com",
                      host_header="api.anthropic.com")
    asyncio.run(addon.request(flow))
    assert not _was_blocked(flow)


def test_bytes_sni_mismatch_is_decoded_and_blocked(tmp_path):
    """Bytes SNI that doesn't match Host should still trigger the block
    — decoding must happen BEFORE the comparison, not just for the
    passing path."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni=b"evil.example",
                      host_header="api.anthropic.com")
    asyncio.run(addon.request(flow))
    assert _was_blocked(flow)


def test_subdomain_is_not_treated_as_match(tmp_path):
    """SNI is for a specific hostname; the cert mitmproxy minted is
    keyed on it. Allowing `SNI=anthropic.com` to talk to
    `Host: api.anthropic.com` (or vice versa) would re-introduce the
    F3 ambiguity for wildcard-cert deployments. Strict equality only."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="anthropic.com",
                      host_header="api.anthropic.com")
    asyncio.run(addon.request(flow))
    assert _was_blocked(flow)


def test_reverse_proxy_flow_skips_the_check(tmp_path):
    """Reverse-proxy flows are inbound (host → cage via proxy); the
    SNI/Host relationship is between an external client and the
    proxy's configured upstream, not a cage-controlled mismatch. The
    existing rewrite logic already exempts reverse-mode flows; the
    SNI/Host check must do the same."""
    addon = _build_addon(tmp_path)
    flow = _make_flow(sni="evil.example",
                      host_header="api.anthropic.com",
                      reverse_mode=True)
    asyncio.run(addon.request(flow))
    assert not _was_blocked(flow)
