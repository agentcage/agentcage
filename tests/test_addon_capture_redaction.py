"""End-to-end tests for the container-backend addon's request-side
secret redaction in the capture pipeline.

CTF-derived fix (apple-container 0.21.10):

``SecretInjector.inject_request`` substitutes the real secret value
into the outbound request URL, headers, and body so the upstream
receives a working key. The capture writer then snapshots the flow
into ``capture.jsonl`` — a file bind-mounted into the cage rootfs at
mode 0644. Without a symmetric ``redact_request`` running between the
upstream send and the capture write, raw ``ANTHROPIC_API_KEY`` bytes
land on disk where the cage workload can recover them via
``grep sk- /var/log/agentcage/capture.jsonl``. That defeats the
placeholder-injection trust model: the proxy held the raw key
precisely so the cage wouldn't see it; capture brought it right back.

These tests instantiate the addon (``Agentcage()`` from
``data/proxy/addon.py``), run the full request → inject →
upstream-sent → response → redact_request → capture pipeline, and
grep the on-disk ``capture.jsonl`` line for the real value. The
assertion is binary: real value present in capture file = leak.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


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
    """Standin so ``isinstance(x, ReverseMode)`` evaluates cleanly.

    conftest.py stubbed ``ReverseMode`` as a MagicMock at collection
    time, which makes the ``isinstance(proxy_mode, ReverseMode)`` call
    in addon.request() / addon.response() crash with TypeError. We
    overwrite it with a real class BEFORE importing the addon module
    so the import binds ``ReverseMode`` to a proper type. No test flow
    sets ``proxy_mode`` to an instance of this class, so the addon
    correctly treats every flow as outbound transparent-mode traffic.
    """


# Important: replace the stub BEFORE the addon module is imported
# below (the addon does ``from mitmproxy.proxy.mode_specs import
# ReverseMode`` at module load and caches the binding).
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
for _mod in ("addon", "capture", "secret_injector"):
    sys.modules.pop(_mod, None)

from addon import Agentcage  # noqa: E402
from capture import CaptureWriter  # noqa: E402
from secret_injector import InjectionRule, SecretInjector  # noqa: E402


# ── Shared test helpers ─────────────────────────────────


class _Headers(dict):
    """dict subclass with mitmproxy.Headers-like methods.

    - ``items(multi=True)`` — CaptureWriter walks this for snapshot
      serialization.
    - ``get(key, default)`` — case-insensitive lookup; CaptureWriter
      calls ``headers.get("content-type", "")``.
    - ``keys()`` returns a list copy so iter+mutate doesn't blow up.
    """

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


def _build_addon_with_capture(tmp_path, *, rules, capture_domains=None):
    """Construct an Agentcage with the secret_injector + capture wired up.

    Skips the full ``load()`` config-parsing path (it expects a YAML
    file on disk and a baked-in inspector chain we don't need for this
    test). Instead we set the attributes load() would set, in the
    same order, and point the capture writer at tmp_path.
    """
    addon = Agentcage()
    addon.cfg = {}
    addon.log_allowed = False
    addon.inspectors = []
    addon._rl_rate = 0.0  # disable rate limiter
    addon._rl_burst = 0
    addon._rl_buckets = {}
    addon._audit_file = (tmp_path / "audit.jsonl").open("a")
    addon._cap_pending = {}

    addon.injector = SecretInjector()
    addon.injector.rules = list(rules)
    addon.injector.redact_to = []

    cap_cfg: dict = {
        "max_body_size": 10485760,
        "domains": list(capture_domains) if capture_domains else [],
    }
    addon._capture = CaptureWriter(cap_cfg, str(tmp_path / "capture.jsonl"))
    return addon


def _make_flow(
    *,
    url="https://api.anthropic.com/v1/messages",
    host="api.anthropic.com",
    method="POST",
    headers=None,
    body=b"",
    content_type="application/json",
):
    """Mock HTTPFlow shaped for the addon's request/response hooks."""
    flow = MagicMock()
    flow.id = "test-flow-leak"
    flow.metadata = {}
    flow.request.url = url
    flow.request.host = host
    flow.request.pretty_host = host
    flow.request.pretty_url = url
    flow.request.path = "/v1/messages"
    flow.request.port = 443
    flow.request.method = method
    flow.request.http_version = "HTTP/1.1"
    h = dict(headers or {})
    h.setdefault("Content-Type", content_type)
    flow.request.headers = _Headers(h)
    flow.request.content = body if isinstance(body, bytes) else body.encode()
    flow.request.get_text.side_effect = (
        lambda strict=False: flow.request.content.decode(
            "utf-8", errors="replace",
        )
    )
    # client_conn — not a ReverseMode → addon treats as outbound.
    flow.client_conn.proxy_mode = MagicMock()
    flow.client_conn.tls_established = True
    flow.client_conn.address = ("127.0.0.1", 12345)

    # Response stub the test will populate as needed.
    flow.response = None
    return flow


def _attach_response(flow, *, body=b'{"ok": true}', status=200,
                     content_type="application/json"):
    flow.response = MagicMock()
    flow.response.status_code = status
    flow.response.reason = "OK"
    flow.response.http_version = "HTTP/1.1"
    flow.response.headers = _Headers({"Content-Type": content_type})
    flow.response.content = body if isinstance(body, bytes) else body.encode()
    flow.response.get_text.side_effect = (
        lambda strict=False: flow.response.content.decode(
            "utf-8", errors="replace",
        )
    )


# ── End-to-end: capture.jsonl must never carry the real value ──


_FAKE_REAL = "sk-ant-api03-FAKE-TEST-VALUE-FOR-REDACTION-CONTAINER-1234567890"


def test_capture_jsonl_does_not_contain_real_secret_after_inject(tmp_path):
    """The exact CTF F4 regression: cage sends a request with the
    placeholder in the body, addon injects the real value upstream,
    response comes back, addon writes the capture entry. The on-disk
    ``capture.jsonl`` must NOT contain the raw ``sk-ant-api03-...``
    bytes — only the placeholder."""
    rule = InjectionRule(
        name="ANTHROPIC_API_KEY",
        placeholder="{{ANTHROPIC_API_KEY}}",
        real_value=_FAKE_REAL,
        inject_to=["anthropic.com"],
        # Placeholder is in the body, so the inject step needs the opt-in
        # body-injection path; strict (default) mode would leave it alone.
        inject_body=True,
    )
    addon = _build_addon_with_capture(tmp_path, rules=[rule])

    req_body = (
        '{"model": "claude", "x-api-key": "{{ANTHROPIC_API_KEY}}"}'
    )
    flow = _make_flow(body=req_body)
    addon.request(flow)
    # Sanity: the upstream got the real value (inject worked).
    assert _FAKE_REAL.encode() in flow.request.content

    _attach_response(flow)
    addon.response(flow)

    cap_text = (tmp_path / "capture.jsonl").read_text()
    assert _FAKE_REAL not in cap_text, (
        "real-key bytes leaked into capture.jsonl: "
        f"{cap_text[:500]!r}..."
    )
    # Both perspectives should now show the placeholder, not the real
    # bytes. inbound is what the cage sent; outbound was "what went on
    # the wire" — post-fix that view also serializes the redacted form.
    entry = json.loads(cap_text.splitlines()[0])
    assert "{{ANTHROPIC_API_KEY}}" in entry["inbound"]["request"]["body"]
    assert "{{ANTHROPIC_API_KEY}}" in entry["outbound"]["request"]["body"]
    assert _FAKE_REAL not in entry["inbound"]["request"]["body"]
    assert _FAKE_REAL not in entry["outbound"]["request"]["body"]


def test_strict_default_leaves_body_placeholder_uninjected(tmp_path):
    """Strict mode (the default): a placeholder that lives only in the
    request body is never swapped for the real value — it never reaches
    the wire, so it cannot leak into capture.jsonl either. Opting into
    body injection is what test_capture_jsonl_does_not_contain_real_secret
    _after_inject covers."""
    rule = InjectionRule(
        name="ANTHROPIC_API_KEY",
        placeholder="{{ANTHROPIC_API_KEY}}",
        real_value=_FAKE_REAL,
        inject_to=["anthropic.com"],
        # inject_body defaults to False — strict mode.
    )
    addon = _build_addon_with_capture(tmp_path, rules=[rule])

    flow = _make_flow(
        body='{"model": "claude", "x-api-key": "{{ANTHROPIC_API_KEY}}"}',
    )
    addon.request(flow)
    # The real value never went on the wire: body still holds the placeholder.
    assert _FAKE_REAL.encode() not in flow.request.content
    assert b"{{ANTHROPIC_API_KEY}}" in flow.request.content

    _attach_response(flow)
    addon.response(flow)

    cap_text = (tmp_path / "capture.jsonl").read_text()
    assert _FAKE_REAL not in cap_text
    entry = json.loads(cap_text.splitlines()[0])
    assert "{{ANTHROPIC_API_KEY}}" in entry["outbound"]["request"]["body"]


def test_capture_jsonl_does_not_contain_real_secret_in_headers(tmp_path):
    """Same as above but the placeholder lives in an Authorization
    header (the common case for API key auth). Header-only requests
    are the leak shape the live-Mac e2e-vm proof captured."""
    rule = InjectionRule(
        name="ANTHROPIC_API_KEY",
        placeholder="{{ANTHROPIC_API_KEY}}",
        real_value=_FAKE_REAL,
        inject_to=["anthropic.com"],
    )
    addon = _build_addon_with_capture(tmp_path, rules=[rule])

    flow = _make_flow(
        headers={"Authorization": "Bearer {{ANTHROPIC_API_KEY}}"},
        body=b"",
    )
    addon.request(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {_FAKE_REAL}"

    _attach_response(flow)
    addon.response(flow)

    cap_text = (tmp_path / "capture.jsonl").read_text()
    assert _FAKE_REAL not in cap_text, (
        f"real-key bytes leaked via header into capture.jsonl: "
        f"{cap_text[:500]!r}..."
    )
    entry = json.loads(cap_text.splitlines()[0])
    inbound_auth = next(
        v for k, v in entry["inbound"]["request"]["headers"]
        if k.lower() == "authorization"
    )
    outbound_auth = next(
        v for k, v in entry["outbound"]["request"]["headers"]
        if k.lower() == "authorization"
    )
    assert inbound_auth == "Bearer {{ANTHROPIC_API_KEY}}"
    assert outbound_auth == "Bearer {{ANTHROPIC_API_KEY}}"


def test_redact_request_round_trip_through_addon_response(tmp_path):
    """Full pipeline cross-check: after addon.request() the flow has
    the real value (inject was meant to put it on the wire), and after
    addon.response() the flow is restored to placeholder form. This is
    the key invariant that makes the capture-time snapshot safe.
    """
    rule = InjectionRule(
        name="ANTHROPIC_API_KEY",
        placeholder="{{ANTHROPIC_API_KEY}}",
        real_value=_FAKE_REAL,
        inject_to=["anthropic.com"],
        # Exercises injection into BOTH the Authorization header and the
        # body, so the rule opts into body injection.
        inject_body=True,
    )
    addon = _build_addon_with_capture(tmp_path, rules=[rule])

    flow = _make_flow(
        headers={"Authorization": "Bearer {{ANTHROPIC_API_KEY}}"},
        body='{"k": "{{ANTHROPIC_API_KEY}}"}',
    )
    addon.request(flow)
    # On the wire upstream: real value present in BOTH places.
    assert flow.request.headers["Authorization"] == f"Bearer {_FAKE_REAL}"
    assert _FAKE_REAL.encode() in flow.request.content

    _attach_response(flow)
    addon.response(flow)

    # In memory after response(): placeholder restored everywhere.
    assert flow.request.headers["Authorization"] == (
        "Bearer {{ANTHROPIC_API_KEY}}"
    )
    assert _FAKE_REAL.encode() not in flow.request.content
    assert b"{{ANTHROPIC_API_KEY}}" in flow.request.content
