"""WebSocket frames reach ``capture.jsonl`` (Phase 0a fix 0a.13).

``request()`` stages a capture entry and ``response()`` completes and
writes it. For a WebSocket upgrade the proxy fires ``response`` on the 101
before any frame arrives, so the entry used to be written there with no
frames, and ``websocket_message`` only buffered frames while the entry was
still staged: ``ws_messages`` never reached the file. The recorded opcode
was also always 2, because message content is always bytes.

The contract these tests pin:

* the 101 keeps the entry open; the frames of both directions are added
  in order with their real type, and the entry is written when the socket
  ends (``websocket_end``) or the flow errors (``error``), exactly once;
* captured frames are redacted like the forwarded ones: no real secret
  value in the file, whether injected, echoed back, or blocked;
* per-frame data is capped at ``max_body_size`` and each flow at
  ``_WS_MAX_MESSAGES`` frames / ``max_body_size`` bytes, with the rest
  counted in ``ws_messages_omitted``;
* ``min_action`` is checked when the entry is written, against the
  decision its frames escalated; domain filters are applied at the 101;
* a writer swapped by a reload while the socket is open writes the entry;
* non-WebSocket flows are written at ``response()`` as before.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from unittest.mock import MagicMock

import pytest


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


class _FlagWord:
    """Inspector that flags (or blocks) any body containing ``word``."""

    def __init__(self, word: bytes, action: str = "flag") -> None:
        self.name = f"word-{action}"
        self._word = word
        self._action = action

    def _check(self, ctx):
        if ctx.body_bytes and self._word in ctx.body_bytes:
            from inspectors.base import InspectionResult
            return InspectionResult(
                inspector=self.name, action=self._action,
                reason=f"saw {self._word!r}", severity="warning")
        return None

    inspect_request = _check
    inspect_response = _check


_REAL = "sk-ws-FAKE-TEST-VALUE-FOR-WEBSOCKET-CAPTURE-0123456789"
_PH = "{{WS_API_KEY}}"


@pytest.fixture
def addon_mod(monkeypatch):
    # Imported lazily, like the other addon suites (see
    # test_addon_bounded_state), and with ReverseMode made a real class.
    from agentcage.data.proxy import addon as mod
    monkeypatch.setattr(mod, "ReverseMode", _StubReverseMode)
    return mod


def _injection_rule(addon_mod, **kw):
    rule_cls = sys.modules[addon_mod.SecretInjector.__module__].InjectionRule
    kw.setdefault("name", "WS_API_KEY")
    kw.setdefault("placeholder", _PH)
    kw.setdefault("real_value", _REAL)
    kw.setdefault("inject_to", ["ws.example.com"])
    return rule_cls(**kw)


def _addon(addon_mod, tmp_path, *, rules=(), inspectors=(), **cap_cfg):
    from capture import CaptureWriter
    addon = addon_mod.Agentcage()
    addon.cfg = {}
    addon.log_allowed = False
    addon.inspectors = list(inspectors)
    addon._rl_rate = 0.0
    addon._rl_burst = 0
    addon._rl_buckets = {}
    addon._audit_file = None
    addon._cap_pending = {}
    addon.injector = addon_mod.SecretInjector()
    addon.injector.rules = list(rules)
    addon.injector.redact_to = []
    addon._capture = CaptureWriter(cap_cfg, str(tmp_path / "capture.jsonl"))
    return addon


def _flow(flow_id="ws-1", host="ws.example.com"):
    flow = MagicMock()
    flow.id = flow_id
    flow.metadata = {}
    flow.request.url = f"https://{host}/socket"
    flow.request.host = host
    flow.request.pretty_host = host
    flow.request.host_header = host
    flow.request.path = "/socket"
    flow.request.port = 443
    flow.request.method = "GET"
    flow.request.http_version = "HTTP/1.1"
    flow.request.headers = _Headers({
        "Upgrade": "websocket", "Connection": "Upgrade",
        "Sec-WebSocket-Version": "13"})
    flow.request.content = b""
    flow.request.get_text.side_effect = lambda strict=False: ""
    flow.client_conn.proxy_mode = MagicMock()
    flow.client_conn.sni = host
    flow.client_conn.tls_established = True
    flow.client_conn.address = ("127.0.0.1", 12345)
    flow.response = None
    flow.websocket = None
    return flow


def _respond(flow, status=101, websocket=True):
    flow.response = MagicMock()
    flow.response.status_code = status
    flow.response.reason = "Switching Protocols" if status == 101 else "OK"
    flow.response.http_version = "HTTP/1.1"
    flow.response.headers = _Headers(
        {"Upgrade": "websocket"} if status == 101
        else {"Content-Type": "application/json"})
    flow.response.content = b"" if status == 101 else b'{"ok": true}'
    flow.response.get_text.side_effect = (
        lambda strict=False: flow.response.content.decode())
    if websocket:
        flow.websocket = MagicMock()
        flow.websocket.messages = []


def _upgrade(addon, flow):
    asyncio.run(addon.request(flow))
    _respond(flow)
    asyncio.run(addon.response(flow))


def _frame(addon, flow, content: bytes, *, from_client: bool, text: bool):
    msg = MagicMock()
    msg.content = content
    msg.from_client = from_client
    msg.is_text = text
    flow.websocket.messages.append(msg)
    asyncio.run(addon.websocket_message(flow))
    return msg


def _lines(tmp_path):
    path = tmp_path / "capture.jsonl"
    text = path.read_text() if path.exists() else ""
    return [json.loads(line) for line in text.splitlines()]


class TestFramesAreRecorded:
    def test_entry_stays_open_at_the_101(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path)
        flow = _flow()
        _upgrade(addon, flow)
        assert _lines(tmp_path) == []
        assert addon._cap_pending["ws-1"]["websocket"] is True

    def test_both_directions_in_order_with_their_type(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path)
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b'{"op":"hello"}', from_client=True, text=True)
        _frame(addon, flow, b"\x00\xffbin", from_client=False, text=False)
        _frame(addon, flow, b"ascii-bin", from_client=True, text=False)
        _frame(addon, flow, "café".encode(), from_client=False, text=True)
        addon.websocket_end(flow)

        [entry] = _lines(tmp_path)
        assert entry["flow_id"] == "ws-1"
        assert entry["decision"] == "allowed"
        assert entry["inbound"]["response"]["status"] == 101
        assert entry["outbound"]["response"]["status"] == 101
        assert "ws_messages_omitted" not in entry
        msgs = entry["ws_messages"]
        assert [(m["type"], m["opcode"]) for m in msgs] == [
            ("send", 1), ("receive", 2), ("send", 2), ("receive", 1)]
        assert msgs[0]["data"] == '{"op":"hello"}'
        assert msgs[1]["dataEncoding"] == "base64"
        assert base64.b64decode(msgs[1]["data"]) == b"\x00\xffbin"
        # Binary that is valid UTF-8 is stored as text, like bodies.
        assert msgs[2]["data"] == "ascii-bin" and "dataEncoding" not in msgs[2]
        assert msgs[3]["data"] == "café"
        assert all("decision" not in m and m["ts"] for m in msgs)

    def test_written_on_error_exactly_once(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path)
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"one", from_client=True, text=True)
        addon.error(flow)
        [entry] = _lines(tmp_path)
        assert [m["data"] for m in entry["ws_messages"]] == ["one"]
        # The state is released, and a later end finds nothing to write.
        assert addon._cap_pending == {} and addon._capture._ws_buffers == {}
        addon.websocket_end(flow)
        assert len(_lines(tmp_path)) == 1

    def test_end_releases_state(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path)
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"x", from_client=True, text=True)
        addon.websocket_end(flow)
        assert addon._cap_pending == {}
        assert addon._capture._ws_buffers == {}
        addon.error(flow)
        assert len(_lines(tmp_path)) == 1

    def test_socket_without_frames_is_still_written(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path)
        flow = _flow()
        _upgrade(addon, flow)
        addon.websocket_end(flow)
        [entry] = _lines(tmp_path)
        assert "ws_messages" not in entry
        assert entry["inbound"]["response"]["status"] == 101


class TestRedaction:
    def test_injected_secret_is_captured_as_placeholder(self, addon_mod, tmp_path):
        rule = _injection_rule(addon_mod, inject_body=True)
        addon = _addon(addon_mod, tmp_path, rules=[rule])
        flow = _flow()
        _upgrade(addon, flow)
        sent = _frame(addon, flow, f'{{"key":"{_PH}"}}'.encode(),
                      from_client=True, text=True)
        # The upstream got the real value...
        assert _REAL.encode() in sent.content
        addon.websocket_end(flow)
        text = (tmp_path / "capture.jsonl").read_text()
        # ...the capture only the placeholder.
        assert _REAL not in text
        [entry] = _lines(tmp_path)
        assert entry["ws_messages"][0]["data"] == f'{{"key":"{_PH}"}}'

    def test_echoed_secret_is_redacted_like_the_forwarded_frame(
            self, addon_mod, tmp_path):
        rule = _injection_rule(addon_mod, inject_body=True)
        addon = _addon(addon_mod, tmp_path, rules=[rule])
        flow = _flow()
        _upgrade(addon, flow)
        got = _frame(addon, flow, f"echo {_REAL}".encode(),
                     from_client=False, text=True)
        assert got.content == f"echo {_PH}".encode()
        addon.websocket_end(flow)
        assert _REAL not in (tmp_path / "capture.jsonl").read_text()
        [entry] = _lines(tmp_path)
        assert entry["ws_messages"][0]["data"] == f"echo {_PH}"

    def test_blocked_frame_carrying_a_secret_is_redacted(
            self, addon_mod, tmp_path):
        # A literal real value heading to a host outside inject_to is
        # blocked and dropped; the capture still never holds it.
        rule = _injection_rule(addon_mod, inject_to=["api.example.org"])
        addon = _addon(addon_mod, tmp_path, rules=[rule])
        flow = _flow()
        _upgrade(addon, flow)
        sent = _frame(addon, flow, f"leak {_REAL}".encode(),
                      from_client=True, text=True)
        assert sent.drop.called
        addon.websocket_end(flow)
        assert _REAL not in (tmp_path / "capture.jsonl").read_text()
        [entry] = _lines(tmp_path)
        assert entry["decision"] == "blocked"
        assert entry["ws_messages"][0]["data"] == f"leak {_PH}"
        assert entry["ws_messages"][0]["decision"] == "blocked"


class TestBounds:
    def test_frame_data_capped_at_max_body_size(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path, max_body_size=8)
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"0123456789AB", from_client=True, text=True)
        addon.websocket_end(flow)
        [entry] = _lines(tmp_path)
        [msg] = entry["ws_messages"]
        assert msg["data"] == "01234567"
        assert msg["dataTruncated"] is True
        assert msg["dataOriginalSize"] == 12

    def test_flow_total_bounded_rest_counted(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path, max_body_size=10)
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"aaaaaa", from_client=True, text=True)
        _frame(addon, flow, b"bbbbbb", from_client=False, text=True)
        _frame(addon, flow, b"cc", from_client=True, text=True)
        addon.websocket_end(flow)
        [entry] = _lines(tmp_path)
        # 6 + 4 (cut to what was left of the 10-byte total), then full.
        assert [m["data"] for m in entry["ws_messages"]] == ["aaaaaa", "bbbb"]
        assert entry["ws_messages"][1]["dataTruncated"] is True
        assert entry["ws_messages_omitted"] == 1

    def test_message_count_bounded_rest_counted(
            self, addon_mod, tmp_path, monkeypatch):
        import capture
        monkeypatch.setattr(capture, "_WS_MAX_MESSAGES", 3)
        addon = _addon(addon_mod, tmp_path)
        flow = _flow()
        _upgrade(addon, flow)
        for i in range(5):
            _frame(addon, flow, f"m{i}".encode(), from_client=True, text=True)
        assert len(addon._capture._ws_buffers["ws-1"].messages) == 3
        addon.websocket_end(flow)
        [entry] = _lines(tmp_path)
        assert [m["data"] for m in entry["ws_messages"]] == ["m0", "m1", "m2"]
        assert entry["ws_messages_omitted"] == 2

    def test_rotation_still_applies(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path, max_file_size=64)
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"x" * 100, from_client=True, text=True)
        addon.websocket_end(flow)
        rotated = tmp_path / "capture.jsonl.1"
        assert rotated.exists()
        assert json.loads(rotated.read_text())["flow_id"] == "ws-1"
        assert (tmp_path / "capture.jsonl").read_text() == ""


class TestFilters:
    def test_min_action_skips_a_socket_with_only_allowed_frames(
            self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path, min_action="flag",
                       inspectors=[_FlagWord(b"FLAGME")])
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"fine", from_client=True, text=True)
        addon.websocket_end(flow)
        assert _lines(tmp_path) == []
        assert addon._cap_pending == {} and addon._capture._ws_buffers == {}

    def test_min_action_keeps_a_socket_whose_frame_was_flagged(
            self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path, min_action="flag",
                       inspectors=[_FlagWord(b"FLAGME")])
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"fine", from_client=True, text=True)
        _frame(addon, flow, b"FLAGME please", from_client=False, text=True)
        addon.websocket_end(flow)
        [entry] = _lines(tmp_path)
        assert entry["decision"] == "flagged"
        assert [m.get("decision") for m in entry["ws_messages"]] == [
            None, "flagged"]

    def test_min_action_block_needs_a_blocked_frame(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path, min_action="block",
                       inspectors=[_FlagWord(b"FLAGME"),
                                   _FlagWord(b"BLOCKME", action="block")])
        flagged, blocked = _flow("ws-f"), _flow("ws-b")
        for flow in (flagged, blocked):
            _upgrade(addon, flow)
        _frame(addon, flagged, b"FLAGME", from_client=True, text=True)
        _frame(addon, blocked, b"BLOCKME", from_client=True, text=True)
        _frame(addon, blocked, b"FLAGME", from_client=True, text=True)
        addon.websocket_end(flagged)
        addon.websocket_end(blocked)
        [entry] = _lines(tmp_path)
        assert entry["flow_id"] == "ws-b"
        # A later flagged frame does not lower the escalated decision.
        assert entry["decision"] == "blocked"

    def test_excluded_domain_buffers_nothing(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path, exclude_domains=["example.com"])
        flow = _flow()
        _upgrade(addon, flow)
        assert addon._cap_pending == {}
        _frame(addon, flow, b"x", from_client=True, text=True)
        assert addon._capture._ws_buffers == {}
        addon.websocket_end(flow)
        assert _lines(tmp_path) == []


class TestHotReload:
    def test_writer_swapped_mid_socket_writes_the_entry(
            self, addon_mod, tmp_path, monkeypatch):
        cap_path = tmp_path / "capture.jsonl"
        monkeypatch.setattr(addon_mod, "CAPTURE_PATH", str(cap_path))
        addon = _addon(addon_mod, tmp_path)
        addon.cfg = {"capture": {"enable_har": True}}
        addon._capture_cfg = None
        addon._init_capture()
        old = addon._capture
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"before", from_client=True, text=True)

        addon.cfg = {"capture": {"enable_har": True,
                                 "exclude_domains": ["other.test"]}}
        addon._init_capture()
        assert addon._capture is not old and old._file is None
        _frame(addon, flow, b"after-swap", from_client=False, text=True)
        addon.websocket_end(flow)

        [entry] = _lines(tmp_path)
        assert [m["data"] for m in entry["ws_messages"]] == [
            "before", "after-swap"]

    def test_capture_disabled_mid_socket_drops_it(
            self, addon_mod, tmp_path, monkeypatch):
        monkeypatch.setattr(
            addon_mod, "CAPTURE_PATH", str(tmp_path / "capture.jsonl"))
        addon = _addon(addon_mod, tmp_path)
        addon.cfg = {"capture": {"enable_har": True}}
        addon._capture_cfg = None
        addon._init_capture()
        flow = _flow()
        _upgrade(addon, flow)
        _frame(addon, flow, b"before", from_client=True, text=True)
        addon.cfg = {"capture": {"enable_har": False}}
        addon._init_capture()
        _frame(addon, flow, b"after", from_client=True, text=True)
        addon.websocket_end(flow)
        assert _lines(tmp_path) == []
        assert addon._cap_pending == {}


class TestNonWebSocketUnchanged:
    def test_http_flow_written_at_response(self, addon_mod, tmp_path):
        addon = _addon(addon_mod, tmp_path)
        flow = _flow("http-1")
        asyncio.run(addon.request(flow))
        _respond(flow, status=200, websocket=False)
        asyncio.run(addon.response(flow))
        [entry] = _lines(tmp_path)
        assert entry["flow_id"] == "http-1"
        assert entry["inbound"]["response"]["status"] == 200
        assert "ws_messages" not in entry
        assert addon._cap_pending == {}

    def test_101_without_a_websocket_written_at_response(
            self, addon_mod, tmp_path):
        # A 101 the proxy does not follow with a WebSocket (another
        # Upgrade protocol, or WebSocket support off) has no frames to
        # wait for.
        addon = _addon(addon_mod, tmp_path)
        flow = _flow("up-1")
        asyncio.run(addon.request(flow))
        _respond(flow, status=101, websocket=False)
        asyncio.run(addon.response(flow))
        [entry] = _lines(tmp_path)
        assert entry["flow_id"] == "up-1"
        assert addon._cap_pending == {}
