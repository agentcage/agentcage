"""No audit record carries a real secret value (Phase 0a fix 0a.31).

The audit entry for an allowed or flagged request was built from the
request after secret injection. A rule with ``inject_body: true`` whose
placeholder sits in the URL (query string or path) therefore wrote the
real value into the entry's ``url`` and ``path``, and so into
``audit.jsonl`` and onto stderr, which the host keeps in its journal.
A literal secret the cage sent itself (allowed to an ``inject_to`` host,
or blocked elsewhere) landed there too, as did a secret echoed by a
server into a response inspector's reason, and the copy of an allowed
entry handed to the traffic watcher.

The contract these tests pin: every audit record, whoever produces it
(HTTP and WebSocket decisions, relays, the Policy API, the watcher), is
written with each secret (a rule's real value or a token its transform
minted) swapped for the rule's placeholder, the form ``redact_request``
gives the capture, on both sinks and in the watcher's ring.
"""

from __future__ import annotations

import asyncio
import collections
import json
import sys
from urllib.parse import urlsplit
from unittest.mock import MagicMock

import pytest


_REAL = "sk-FAKE-AUDIT-SECRET-0123456789abcdefghijklmnopqrstuv"
_PH = "{{API_KEY}}"
_HOST = "api.example.com"


class _StubReverseMode:
    """Real class so ``isinstance(..., ReverseMode)`` works (conftest
    stubs it as a MagicMock instance). No flow here is reverse-mode."""


class _Headers(dict):
    """dict with the Headers methods the addon and the writer use."""

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


class _Request:
    """The request fields the addon reads. As on a real request, host
    and path follow the URL (assigning ``url`` re-parses it), so a value
    injected into the URL reaches them too."""

    def __init__(self, url: str, *, headers=None, body: bytes = b"",
                 method: str = "GET") -> None:
        self.url = url
        self.method = method
        self.http_version = "HTTP/1.1"
        self.port = 443
        self.headers = _Headers(dict(headers or {}))
        self.content = body

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def pretty_host(self) -> str:
        return self.host

    @property
    def host_header(self) -> str:
        return self.host

    @property
    def path(self) -> str:
        parts = urlsplit(self.url)
        return parts.path + (f"?{parts.query}" if parts.query else "")

    def get_text(self, strict: bool = False) -> str:  # noqa: ARG002
        return self.content.decode("utf-8", "replace")


class _Inspector:
    """Returns *action* with *reason(ctx)* for the given hook."""

    def __init__(self, action: str, reason, *, on: str = "request") -> None:
        self.name = f"test-{action}"
        self._action = action
        self._reason = reason
        self._on = on

    def _result(self, ctx):
        from inspectors.base import InspectionResult
        return InspectionResult(
            inspector=self.name, action=self._action,
            reason=self._reason(ctx), severity="warning")

    def inspect_request(self, ctx):
        return self._result(ctx) if self._on == "request" else None

    def inspect_response(self, ctx):
        return self._result(ctx) if self._on == "response" else None


@pytest.fixture
def addon_mod(monkeypatch):
    from agentcage.data.proxy import addon as mod
    monkeypatch.setattr(mod, "ReverseMode", _StubReverseMode)
    return mod


def _rule(addon_mod, **kw):
    rule_cls = sys.modules[addon_mod.SecretInjector.__module__].InjectionRule
    kw.setdefault("name", "API_KEY")
    kw.setdefault("placeholder", _PH)
    kw.setdefault("real_value", _REAL)
    kw.setdefault("inject_to", [_HOST])
    return rule_cls(**kw)


def _addon(addon_mod, tmp_path, *, rules=(), inspectors=(),
           log_allowed=False, capture=False):
    addon = addon_mod.Agentcage()
    addon.cfg = {}
    addon.log_allowed = log_allowed
    addon.inspectors = list(inspectors)
    addon._rl_rate = 0.0
    addon._rl_burst = 0
    addon._rl_buckets = {}
    addon._audit_file = (tmp_path / "audit.jsonl").open("a")
    addon._cap_pending = {}
    addon.injector = addon_mod.SecretInjector()
    addon.injector.rules = list(rules)
    addon.injector.redact_to = []
    addon._capture = None
    if capture:
        from capture import CaptureWriter
        addon._capture = CaptureWriter(
            {"max_body_size": 10485760}, str(tmp_path / "capture.jsonl"))
    return addon


def _flow(url: str, *, headers=None, body: bytes = b"", flow_id="flow-1"):
    flow = MagicMock()
    flow.id = flow_id
    flow.metadata = {}
    flow.request = _Request(url, headers=headers, body=body)
    flow.client_conn.proxy_mode = MagicMock()
    flow.client_conn.sni = None
    flow.client_conn.tls_established = True
    flow.client_conn.address = ("127.0.0.1", 12345)
    flow.response = None
    flow.websocket = None
    return flow


def _respond(flow, *, body: bytes = b'{"ok": true}', status: int = 200,
             headers=None):
    flow.response = MagicMock()
    flow.response.status_code = status
    flow.response.reason = "OK"
    flow.response.http_version = "HTTP/1.1"
    flow.response.headers = _Headers(
        dict(headers or {"Content-Type": "application/json"}))
    flow.response.content = body
    flow.response.get_text.side_effect = (
        lambda strict=False: flow.response.content.decode("utf-8", "replace"))


def _audit(addon, tmp_path, capsys, secret: str = _REAL) -> list[dict]:
    """The entries written to both sinks, after checking that neither
    holds *secret*. They must agree: stderr is what the journal keeps."""
    addon._audit_file.flush()
    file_text = (tmp_path / "audit.jsonl").read_text()
    stderr = capsys.readouterr().err
    assert secret not in file_text, f"secret in audit.jsonl: {file_text}"
    assert secret not in stderr, f"secret on stderr: {stderr}"
    entries = [json.loads(line) for line in file_text.splitlines()]
    printed = [json.loads(line) for line in stderr.splitlines()
               if line.startswith("{")]
    assert printed == entries
    return entries


def _run(coro):
    return asyncio.run(coro)


# ── Injection into the URL (inject_body) ─────────────────


class TestUrlInjection:
    def test_query_string_injection_not_in_audit(
            self, addon_mod, tmp_path, capsys):
        addon = _addon(addon_mod, tmp_path,
                       rules=[_rule(addon_mod, inject_body=True)])
        flow = _flow(f"https://{_HOST}/v1/data?key={_PH}&q=1")
        _run(addon.request(flow))
        # On the wire: the real value, in the query string.
        assert flow.request.path == f"/v1/data?key={_REAL}&q=1"

        [entry] = _audit(addon, tmp_path, capsys)
        assert entry["decision"] == "allowed"
        assert entry["secrets_injected"] == ["API_KEY"]
        assert entry["path"] == f"/v1/data?key={_PH}&q=1"
        assert entry["url"] == f"https://{_HOST}/v1/data?key={_PH}&q=1"

    def test_path_injection_not_in_audit(self, addon_mod, tmp_path, capsys):
        addon = _addon(addon_mod, tmp_path, log_allowed=True,
                       rules=[_rule(addon_mod, inject_body=True)])
        flow = _flow(f"https://{_HOST}/v1/keys/{_PH}/usage")
        _run(addon.request(flow))
        assert flow.request.path == f"/v1/keys/{_REAL}/usage"

        [entry] = _audit(addon, tmp_path, capsys)
        assert entry["path"] == f"/v1/keys/{_PH}/usage"
        assert entry["url"] == f"https://{_HOST}/v1/keys/{_PH}/usage"

    def test_flagged_request_url_injection_not_in_audit(
            self, addon_mod, tmp_path, capsys):
        addon = _addon(
            addon_mod, tmp_path,
            rules=[_rule(addon_mod, inject_body=True)],
            inspectors=[_Inspector("flag", lambda ctx: "looks odd")],
        )
        flow = _flow(f"https://{_HOST}/v1/data?key={_PH}")
        _run(addon.request(flow))
        assert _REAL in flow.request.url

        [entry] = _audit(addon, tmp_path, capsys)
        assert entry["decision"] == "flagged"
        assert entry["reason"] == "looks odd"
        assert entry["path"] == f"/v1/data?key={_PH}"
        assert entry["url"] == f"https://{_HOST}/v1/data?key={_PH}"

    def test_response_blocked_request_not_in_audit(
            self, addon_mod, tmp_path, capsys):
        """Both entries of a request blocked at the response stage: the
        request's (written after injection) and the block's."""
        addon = _addon(
            addon_mod, tmp_path,
            rules=[_rule(addon_mod, inject_body=True)],
            inspectors=[_Inspector("block", lambda ctx: "bad response",
                                   on="response")],
        )
        flow = _flow(f"https://{_HOST}/v1/data?key={_PH}")
        _run(addon.request(flow))
        _respond(flow)
        _run(addon.response(flow))

        allowed, blocked = _audit(addon, tmp_path, capsys)
        assert allowed["decision"] == "allowed"
        assert blocked["decision"] == "blocked"
        assert blocked["reason"] == "bad response"
        for entry in (allowed, blocked):
            assert entry["path"] == f"/v1/data?key={_PH}"
            assert entry["url"] == f"https://{_HOST}/v1/data?key={_PH}"

    def test_injected_host_not_in_audit_or_capture(
            self, addon_mod, tmp_path, capsys):
        """A placeholder in the host name is injected there too (the URL is
        re-parsed), so the host field is redacted like the rest."""
        real = "tenant-0a1b2c3d4e5f6a7b8c9d0e1f2a3b"
        addon = _addon(
            addon_mod, tmp_path, capture=True,
            rules=[_rule(addon_mod, name="TENANT", placeholder="{{tenant}}",
                         real_value=real, inject_to=["example.com"],
                         inject_body=True)],
        )
        flow = _flow("https://{{tenant}}.example.com/v1/data")
        _run(addon.request(flow))
        assert flow.request.host == f"{real}.example.com"
        _respond(flow)
        _run(addon.response(flow))

        [entry] = _audit(addon, tmp_path, capsys, secret=real)
        assert entry["host"] == "{{tenant}}.example.com"
        capture_text = (tmp_path / "capture.jsonl").read_text()
        assert real not in capture_text
        assert json.loads(capture_text)["host"] == "{{tenant}}.example.com"


# ── Injection into a header (strict default) ─────────────


class TestHeaderInjection:
    def test_header_injected_secret_not_in_audit(
            self, addon_mod, tmp_path, capsys):
        addon = _addon(addon_mod, tmp_path, log_allowed=True,
                       rules=[_rule(addon_mod)])
        flow = _flow(f"https://{_HOST}/v1/data",
                     headers={"Authorization": f"Bearer {_PH}"})
        _run(addon.request(flow))
        assert flow.request.headers["Authorization"] == f"Bearer {_REAL}"
        _respond(flow)
        _run(addon.response(flow))

        [entry] = _audit(addon, tmp_path, capsys)
        assert entry["decision"] == "allowed"
        assert entry["secrets_injected"] == ["API_KEY"]


# ── A literal secret the cage sent ───────────────────────


class TestLiteralSecret:
    def test_literal_secret_in_url_to_inject_to_host(
            self, addon_mod, tmp_path, capsys):
        """Allowed through (it is the credential the egress would inject
        there anyway), but recorded as the placeholder."""
        addon = _addon(addon_mod, tmp_path, log_allowed=True,
                       rules=[_rule(addon_mod)])
        flow = _flow(f"https://{_HOST}/v1/data?key={_REAL}")
        _run(addon.request(flow))
        assert not flow.metadata.get("agentcage_blocked")

        [entry] = _audit(addon, tmp_path, capsys)
        assert entry["decision"] == "allowed"
        assert entry["url"] == f"https://{_HOST}/v1/data?key={_PH}"

    def test_blocked_literal_secret_in_url(self, addon_mod, tmp_path, capsys):
        addon = _addon(addon_mod, tmp_path, rules=[_rule(addon_mod)])
        flow = _flow(f"https://collector.example/upload/{_REAL}")
        _run(addon.request(flow))
        assert flow.metadata.get("agentcage_blocked") is True

        [entry] = _audit(addon, tmp_path, capsys)
        assert entry["decision"] == "blocked"
        assert entry["reason"] == (
            "literal secret value API_KEY found in outbound request to "
            "collector.example"
        )
        assert entry["path"] == f"/upload/{_PH}"
        assert entry["url"] == f"https://collector.example/upload/{_PH}"

    def test_watcher_ring_copy_is_redacted(self, addon_mod, tmp_path, capsys):
        """An allowed entry kept out of the durable log (allowed_requests
        off, no secret injected) still goes to the traffic watcher, whose
        scans send it to an LLM: it is redacted too."""
        addon = _addon(addon_mod, tmp_path, rules=[_rule(addon_mod)])
        addon._watcher_ring = collections.deque()
        flow = _flow(f"https://{_HOST}/v1/data?key={_REAL}")
        _run(addon.request(flow))

        assert _audit(addon, tmp_path, capsys) == []
        [entry] = addon._watcher_ring
        assert _REAL not in json.dumps(entry)
        assert entry["url"] == f"https://{_HOST}/v1/data?key={_PH}"


# ── Inspector reasons ────────────────────────────────────


class TestInspectorReasons:
    def test_response_inspector_quoting_an_echoed_secret(
            self, addon_mod, tmp_path, capsys):
        """Response inspectors see the response before it is redacted for
        the cage, so a reason quoting the body can hold a secret the
        server echoed."""
        addon = _addon(
            addon_mod, tmp_path,
            rules=[_rule(addon_mod)],
            inspectors=[_Inspector(
                "block", lambda ctx: f"suspicious body: {ctx.body_text}",
                on="response")],
        )
        flow = _flow(f"https://{_HOST}/v1/data",
                     headers={"Authorization": f"Bearer {_PH}"})
        _run(addon.request(flow))
        _respond(flow, body=f"you sent {_REAL}".encode())
        _run(addon.response(flow))

        allowed, blocked = _audit(addon, tmp_path, capsys)
        assert blocked["decision"] == "blocked"
        assert blocked["reason"] == f"suspicious body: you sent {_PH}"
        assert blocked["inspectors"][0]["reason"] == (
            f"suspicious body: you sent {_PH}")


# ── WebSocket ────────────────────────────────────────────


class TestWebSocket:
    def test_upgrade_and_frames_not_in_audit(
            self, addon_mod, tmp_path, capsys):
        addon = _addon(addon_mod, tmp_path, log_allowed=True,
                       rules=[_rule(addon_mod, inject_body=True)])
        flow = _flow(f"https://{_HOST}/socket?token={_PH}",
                     headers={"Upgrade": "websocket"})
        _run(addon.request(flow))
        assert _REAL in flow.request.url
        _respond(flow, body=b"", status=101, headers={"Upgrade": "websocket"})
        flow.websocket = MagicMock()
        flow.websocket.messages = []
        _run(addon.response(flow))

        for content, from_client in ((f"auth {_PH}".encode(), True),
                                     (f"echo {_REAL}".encode(), False)):
            msg = MagicMock()
            msg.content = content
            msg.from_client = from_client
            msg.is_text = True
            flow.websocket.messages.append(msg)
            _run(addon.websocket_message(flow))
        # The cage → remote frame went out with the real value.
        assert flow.websocket.messages[0].content == f"auth {_REAL}".encode()

        upgrade, sent, received = _audit(addon, tmp_path, capsys)
        assert upgrade["secrets_injected"] == ["API_KEY"]
        assert sent["reason"] == received["reason"] == "websocket"
        for entry in (upgrade, sent, received):
            assert entry["path"] == f"/socket?token={_PH}"
            assert entry["url"] == f"https://{_HOST}/socket?token={_PH}"


# ── Every other producer: relays, Policy API, watcher ────


class TestAuditFunnel:
    def test_every_string_field_is_redacted(self, addon_mod, tmp_path, capsys):
        """Records written straight to the funnel (``_audit_write``): any
        string, at any depth, holding a secret is redacted; other values
        and keys are left alone."""
        addon = _addon(addon_mod, tmp_path, rules=[_rule(addon_mod)])
        addon._watcher_ring = collections.deque()
        addon._audit_write({
            "kind": "smtp_data",
            "decision": "upstream_error",
            "error": f"upstream said: 535 bad token {_REAL}",
            "recipients": [f"{_REAL}@example.com", "b@example.com"],
            "nested": {"detail": [f"x{_REAL}x"], "size": 12, "ok": True},
        })

        [entry] = _audit(addon, tmp_path, capsys)
        assert entry["error"] == f"upstream said: 535 bad token {_PH}"
        assert entry["recipients"] == [f"{_PH}@example.com", "b@example.com"]
        assert entry["nested"] == {"detail": [f"x{_PH}x"], "size": 12,
                                   "ok": True}
        [ring] = addon._watcher_ring
        assert _REAL not in json.dumps(ring)

    def test_record_without_secrets_is_unchanged(
            self, addon_mod, tmp_path, capsys):
        addon = _addon(addon_mod, tmp_path)
        record = {"kind": "tcp_bypass_blocked", "host": "1.1.1.1:443"}
        addon._audit_write(dict(record))
        [entry] = _audit(addon, tmp_path, capsys)
        assert {k: entry[k] for k in record} == record
