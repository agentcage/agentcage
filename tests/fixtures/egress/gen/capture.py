"""Record ``tests/fixtures/egress/capture.json`` from the Python egress.

Runs the live ``CaptureWriter`` (``src/agentcage/data/proxy/capture.py``)
with the clock pinned and records:

* ``settings``: a ``capture`` section → whether the writer accepts it,
  and its filter answers (``should_capture`` / ``captures_host``);
* ``request`` / ``response``: a message → its snapshot (compact JSON);
* ``entry``: ``write_entry`` arguments → the exact line written;
* ``ws``: a sequence of WebSocket frames → the buffered messages and the
  omitted count.

    uv run python tests/fixtures/egress/gen/capture.py

``tests/test_egress_corpus_capture.py`` re-runs every case through
:func:`run`; the Rust port (``agentcage-egress``, ``src/capture.rs``)
asserts the same file.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

_ROOT = Path(__file__).resolve().parents[4]
OUT = _ROOT / "tests" / "fixtures" / "egress" / "capture.json"

_PROXY = _ROOT / "src" / "agentcage" / "data" / "proxy"
if str(_PROXY) not in sys.path:
    sys.path.insert(0, str(_PROXY))

import capture as capture_mod  # noqa: E402
from capture import CaptureWriter  # noqa: E402


def enc(data: bytes):
    """A byte string in the corpus convention (README)."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(data).decode("ascii")}


def dec(value) -> bytes:
    if isinstance(value, dict):
        return base64.b64decode(value["b64"])
    return value.encode("utf-8")


class _Headers:
    """The two Headers methods the writer uses: multi-valued items in
    wire order, and ``get`` folding duplicates with ``", "``."""

    def __init__(self, pairs):
        self._pairs = [(k, v) for k, v in pairs]

    def items(self, multi=False):  # noqa: ARG002
        return list(self._pairs)

    def get(self, key, default=None):
        values = [v for k, v in self._pairs if k.lower() == key.lower()]
        return ", ".join(values) if values else default


def url_of(req: dict) -> str:
    """The URL the egress reports for a request: default port omitted,
    an IPv6 literal bracketed."""
    host = req["host"]
    if ":" in host:
        host = f"[{host}]"
    default = (req["scheme"], req["port"]) in (("http", 80), ("https", 443))
    port = "" if default else f":{req['port']}"
    return f"{req['scheme']}://{host}{port}{req['path']}"


def _writer(tmp: str, cfg: dict) -> CaptureWriter:
    return CaptureWriter(cfg, os.path.join(tmp, "capture.jsonl"))


def _fixed_clock(parts):
    moment = datetime(*parts, tzinfo=timezone.utc)

    class _Fixed(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ARG003
            return moment

    return _Fixed


def run(case: dict) -> dict:
    kind, inp = case["kind"], case["input"]
    with tempfile.TemporaryDirectory() as tmp:
        if kind == "settings":
            try:
                w = _writer(tmp, inp["section"])
            except (TypeError, ValueError) as e:
                return {"accepted": False, "error": type(e).__name__}
            return {
                "accepted": True,
                "should_capture": [w.should_capture(d, h)
                                   for d, h in inp["should_capture"]],
                "captures_host": [w.captures_host(h)
                                  for h in inp["captures_host"]],
            }
        if kind == "request":
            r = inp["request"]
            req = SimpleNamespace(
                method=r["method"], url=url_of(r),
                http_version=r["http_version"],
                headers=_Headers(r["headers"]), content=dec(r["body"]))
            snap = _writer(tmp, inp["section"]).snapshot_request(
                SimpleNamespace(request=req))
            return {"url": url_of(r),
                    "snapshot": json.dumps(snap, separators=(",", ":"))}
        if kind == "response":
            r = inp["response"]
            resp = None if r is None else SimpleNamespace(
                status_code=r["status"], reason=r["reason"],
                http_version=r["http_version"],
                headers=_Headers(r["headers"]), content=dec(r["body"]))
            snap = _writer(tmp, inp["section"]).snapshot_response(
                SimpleNamespace(response=resp))
            return {"snapshot": json.dumps(snap, separators=(",", ":"))}
        if kind == "entry":
            w = _writer(tmp, {})
            saved = capture_mod.datetime
            capture_mod.datetime = _fixed_clock(inp["ts"])
            try:
                w.write_entry(**inp["args"])
            finally:
                capture_mod.datetime = saved
            w.close()
            with open(os.path.join(tmp, "capture.jsonl"), "rb") as f:
                return {"line": f.read().decode("ascii")}
        if kind == "ws":
            w = _writer(tmp, inp["section"])
            for fr in inp["frames"]:
                w.add_ws_frame(
                    fr.get("flow", "f"), from_client=fr["from_client"],
                    is_text=fr["is_text"], content=dec(fr["content"]),
                    ts=fr["ts"], decision=fr.get("decision", "allowed"))
            msgs, omitted = w.pop_ws_buffer("f")
            return {"messages": json.dumps(msgs, separators=(",", ":")),
                    "omitted": omitted}
    raise AssertionError(f"unknown kind {kind!r}")


# ── The cases ────────────────────────────────────────────

_ALL = [[d, h] for d in ("allowed", "flagged", "blocked", "weird")
        for h in ("example.com",)]
_HOSTS = ["api.anthropic.com", "anthropic.com", "xanthropic.com",
          "openai.com", "internal.local", "sub.internal.local", "",
          "ANTHROPIC.COM"]


def _settings(cid, section, should=None):
    return {"id": f"settings-{cid}", "kind": "settings", "input": {
        "section": section,
        "should_capture": should or _ALL + [["allowed", h] for h in _HOSTS],
        "captures_host": _HOSTS}}


def _req(cid, section=None, **over):
    r = {"method": "POST", "scheme": "https", "host": "api.example.com",
         "port": 443, "path": "/v1/messages?beta=true",
         "http_version": "HTTP/1.1",
         "headers": [["Host", "api.example.com"],
                     ["Content-Type", "application/json"],
                     ["X-Dup", "a"], ["x-dup", "b"]],
         "body": '{"model":"m"}'}
    r.update(over)
    return {"id": f"request-{cid}", "kind": "request",
            "input": {"section": section or {}, "request": r}}


def _resp(cid, section=None, **over):
    r = {"status": 200, "reason": "OK", "http_version": "HTTP/1.1",
         "headers": [["Content-Type", "application/json"],
                     ["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]],
         "body": '{"ok":true}'}
    r.update(over)
    return {"id": f"response-{cid}", "kind": "response",
            "input": {"section": section or {}, "response": r}}


def cases() -> list[dict]:
    out = [
        _settings("defaults", {}),
        _settings("min-action-flag", {"min_action": "flag"}),
        _settings("min-action-block", {"min_action": "block"}),
        _settings("min-action-alias-flagged", {"min_action": "flagged"}),
        _settings("min-action-alias-blocked", {"min_action": "blocked"}),
        _settings("min-action-alias-allowed", {"min_action": "allowed"}),
        _settings("min-action-unknown-records-all", {"min_action": "bogus"}),
        _settings("min-action-null", {"min_action": None}),
        _settings("min-action-empty", {"min_action": ""}),
        _settings("min-action-non-string", {"min_action": 2}),
        _settings("domains", {"domains": ["anthropic.com"]}),
        _settings("exclude", {"exclude_domains": ["internal.local"]}),
        _settings("both", {"domains": ["anthropic.com", "internal.local"],
                           "exclude_domains": ["sub.internal.local"],
                           "min_action": "flag"}),
        _settings("domains-null", {"domains": None,
                                   "exclude_domains": None}),
        _settings("numeric-strings", {"max_body_size": "12",
                                      "max_file_size": " 99 "}),
        _settings("float-and-bool", {"max_body_size": 1.9,
                                     "max_file_size": True}),
        _settings("negative-file-size", {"max_file_size": -5}),
        _settings("bad-max-body", {"max_body_size": "abc"}),
        _settings("null-max-body", {"max_body_size": None}),
        _settings("bad-max-file", {"max_file_size": "1.5"}),
        _settings("list-max-file", {"max_file_size": [1]}),
    ]
    out += [
        _req("utf8"),
        _req("empty-body", method="GET", body="", headers=[]),
        _req("binary-body", body={"b64": base64.b64encode(
            bytes(range(256))).decode()}),
        _req("non-ascii-text", body="café ☃ \U0001f600",
             headers=[["X-Name", "café"]]),
        _req("truncated-text", section={"max_body_size": 10},
             body="x" * 100),
        _req("truncation-splits-a-codepoint", section={"max_body_size": 3},
             body="abéé"),
        _req("unlimited", section={"max_body_size": 0}, body="y" * 50),
        _req("negative-max-body-cuts-from-the-end",
             section={"max_body_size": -2}, body="hello"),
        _req("negative-max-body-longer-than-the-body",
             section={"max_body_size": -9}, body="hello"),
        _req("exactly-at-limit", section={"max_body_size": 5}, body="12345"),
        _req("http-non-default-port", scheme="http", port=8080,
             host="10.89.0.2", path="/"),
        _req("http2", http_version="HTTP/2.0", scheme="https", port=8443,
             host="2001:db8::1", path="/x"),
        _resp("utf8"),
        _resp("empty", status=204, reason="No Content", headers=[],
              body=""),
        _resp("no-content-type", headers=[["X", "1"]], body="hi"),
        _resp("folded-content-type",
              headers=[["content-type", "text/plain"],
                       ["Content-Type", "charset=utf-8"]]),
        _resp("binary-truncated", section={"max_body_size": 3},
              body={"b64": base64.b64encode(b"\x89PNG\r\n").decode()}),
        _resp("empty-reason", reason="", http_version="HTTP/2.0"),
        _resp("switching-protocols", status=101,
              reason="Switching Protocols",
              headers=[["Upgrade", "websocket"]], body=""),
        {"id": "response-none", "kind": "response",
         "input": {"section": {}, "response": None}},
    ]

    req = {"method": "POST", "url": "https://api.example.com/v1",
           "httpVersion": "HTTP/1.1",
           "headers": [["authorization", "Bearer {{KEY}}"]],
           "body": "{}", "bodyEncoding": None, "bodySize": 2}
    resp = {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": [], "body": "café", "bodyEncoding": None,
            "bodySize": 5, "mimeType": "text/plain"}
    base = {"flow_id": "f-1", "direction": "outbound", "decision": "allowed",
            "host": "api.example.com", "method": "POST", "path": "/v1",
            "inspectors": [], "inbound_req": req, "inbound_resp": resp,
            "outbound_req": req, "outbound_resp": resp}
    out += [
        {"id": "entry-plain", "kind": "entry",
         "input": {"ts": [2026, 10, 10, 1, 2, 3, 0], "args": base}},
        {"id": "entry-with-inspectors", "kind": "entry",
         "input": {"ts": [2026, 10, 10, 1, 2, 3, 456], "args": {
             **base, "decision": "flagged", "inspectors": [
                 {"name": "secrets", "action": "flag",
                  "reason": "possible secret ☃", "severity": "warning"}]}}},
        {"id": "entry-blocked-empty-response", "kind": "entry",
         "input": {"ts": [2026, 10, 10, 1, 2, 3, 0], "args": {
             **base, "decision": "blocked", "direction": "inbound",
             "inbound_resp": {}, "outbound_resp": {}}}},
        {"id": "entry-ws", "kind": "entry",
         "input": {"ts": [2026, 10, 10, 1, 2, 3, 0], "args": {
             **base, "method": "GET", "ws_messages": [
                 {"type": "send", "ts": "2026-10-10T01:02:03+00:00",
                  "opcode": 1, "data": "hi"}],
             "ws_messages_omitted": 3}}},
        {"id": "entry-ws-empty-list-and-zero-omitted", "kind": "entry",
         "input": {"ts": [2026, 10, 10, 1, 2, 3, 0], "args": {
             **base, "ws_messages": [], "ws_messages_omitted": 0}}},
    ]

    ts = "2026-10-10T01:02:03.000004+00:00"
    out += [
        {"id": "ws-shapes", "kind": "ws", "input": {"section": {}, "frames": [
            {"from_client": True, "is_text": True, "content": "hi", "ts": ts},
            {"from_client": False, "is_text": False,
             "content": {"b64": base64.b64encode(b"\xff\x00").decode()},
             "ts": ts},
            {"from_client": False, "is_text": False, "content": "ascii-bin",
             "ts": ts},
            {"from_client": True, "is_text": True, "content": "x", "ts": ts,
             "decision": "flagged"},
            {"from_client": True, "is_text": True, "content": "y", "ts": ts,
             "decision": "blocked"},
            {"from_client": True, "is_text": True,
             "content": "café", "ts": ts},
            {"from_client": True, "is_text": True, "content": "other flow",
             "ts": ts, "flow": "g"},
        ]}},
        {"id": "ws-per-frame-and-total-bound", "kind": "ws", "input": {
            "section": {"max_body_size": 5}, "frames": [
                {"from_client": True, "is_text": True,
                 "content": "abcdefgh", "ts": ts},
                {"from_client": True, "is_text": True, "content": "z",
                 "ts": ts},
                {"from_client": True, "is_text": True, "content": "z",
                 "ts": ts}]}},
        {"id": "ws-total-cut-mid-frame", "kind": "ws", "input": {
            "section": {"max_body_size": 6}, "frames": [
                {"from_client": True, "is_text": True, "content": "abcd",
                 "ts": ts},
                {"from_client": False, "is_text": True,
                 "content": "ééé", "ts": ts},
                {"from_client": False, "is_text": False,
                 "content": {"b64": base64.b64encode(b"\xff").decode()},
                 "ts": ts}]}},
        {"id": "ws-text-cut-mid-codepoint", "kind": "ws", "input": {
            "section": {"max_body_size": 5}, "frames": [
                {"from_client": True, "is_text": True, "content": "abcd",
                 "ts": ts},
                {"from_client": False, "is_text": True,
                 "content": "\u00e9\u00e9", "ts": ts}]}},
        {"id": "ws-negative-max-body-omits-everything", "kind": "ws",
         "input": {"section": {"max_body_size": -3}, "frames": [
             {"from_client": True, "is_text": True, "content": "abc",
              "ts": ts}]}},
        {"id": "ws-binary-cut-into-invalid-utf8", "kind": "ws", "input": {
            "section": {"max_body_size": 3}, "frames": [
                {"from_client": True, "is_text": False,
                 "content": "aéé", "ts": ts}]}},
    ]
    return out


def main() -> None:
    recorded = [{**c, "expected": run(c)} for c in cases()]
    doc = {
        "_comment": (
            "capture.jsonl writer behaviour as the Python egress had it: "
            "settings and filters, request/response snapshots, exact entry "
            "lines, and WebSocket frame buffering. Generated by "
            "tests/fixtures/egress/gen/capture.py; asserted by "
            "tests/test_egress_corpus_capture.py and by "
            "rust/agentcage-egress/src/capture.rs (corpus test)."
        ),
        "cases": recorded,
    }
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {OUT} ({len(recorded)} cases)")


if __name__ == "__main__":
    main()
