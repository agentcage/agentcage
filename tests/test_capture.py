"""Unit tests for capture JSONL writer and HAR builder."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── CaptureWriter tests (proxy-side) ────────────────────

# The CaptureWriter lives in data/proxy/ with mitmproxy-style imports,
# so we test via import path manipulation or by testing the logic directly.

# We import CaptureWriter by adding its parent to sys.path.
_PROXY_DIR = str(Path(__file__).resolve().parent.parent / "src" / "agentcage" / "data" / "proxy")
if _PROXY_DIR not in sys.path:
    sys.path.insert(0, _PROXY_DIR)

from capture import CaptureWriter


class TestCaptureWriterFiltering:
    def _writer(self, tmp_path, **cfg_overrides):
        cfg = {
            "enabled": True,
            "max_body_size": 10485760,
            "min_action": "all",
            "domains": [],
            "exclude_domains": [],
        }
        cfg.update(cfg_overrides)
        path = str(tmp_path / "capture.jsonl")
        return CaptureWriter(cfg, path)

    def test_should_capture_all_by_default(self, tmp_path):
        w = self._writer(tmp_path)
        assert w.should_capture("allowed", "example.com")
        assert w.should_capture("flagged", "example.com")
        assert w.should_capture("blocked", "example.com")

    def test_min_action_flag(self, tmp_path):
        w = self._writer(tmp_path, min_action="flag")
        assert not w.should_capture("allowed", "example.com")
        assert w.should_capture("flagged", "example.com")
        assert w.should_capture("blocked", "example.com")

    def test_min_action_block(self, tmp_path):
        w = self._writer(tmp_path, min_action="block")
        assert not w.should_capture("allowed", "example.com")
        assert not w.should_capture("flagged", "example.com")
        assert w.should_capture("blocked", "example.com")

    def test_domain_allowlist(self, tmp_path):
        w = self._writer(tmp_path, domains=["anthropic.com"])
        assert w.should_capture("allowed", "api.anthropic.com")
        assert w.should_capture("allowed", "anthropic.com")
        assert not w.should_capture("allowed", "openai.com")

    def test_domain_blocklist(self, tmp_path):
        w = self._writer(tmp_path, exclude_domains=["internal.local"])
        assert w.should_capture("allowed", "api.anthropic.com")
        assert not w.should_capture("allowed", "internal.local")
        assert not w.should_capture("allowed", "sub.internal.local")


class TestCaptureWriterEncoding:
    def _writer(self, tmp_path, max_body_size=10485760):
        cfg = {"enabled": True, "max_body_size": max_body_size,
               "min_action": "all", "domains": [], "exclude_domains": []}
        path = str(tmp_path / "capture.jsonl")
        return CaptureWriter(cfg, path)

    def test_encode_utf8_body(self, tmp_path):
        w = self._writer(tmp_path)
        body, encoding, truncated, orig = w._encode_body(b'{"key": "value"}')
        assert body == '{"key": "value"}'
        assert encoding is None
        assert not truncated

    def test_encode_binary_body_base64(self, tmp_path):
        w = self._writer(tmp_path)
        data = bytes(range(256))
        body, encoding, truncated, orig = w._encode_body(data)
        assert encoding == "base64"
        import base64
        assert base64.b64decode(body) == data

    def test_encode_none_body(self, tmp_path):
        w = self._writer(tmp_path)
        body, encoding, truncated, orig = w._encode_body(None)
        assert body == ""
        assert encoding is None
        assert not truncated
        assert orig == 0

    def test_truncation(self, tmp_path):
        w = self._writer(tmp_path, max_body_size=10)
        data = b"x" * 100
        body, encoding, truncated, orig = w._encode_body(data)
        assert truncated
        assert orig == 100
        assert len(body) == 10

    def test_no_truncation_when_under_limit(self, tmp_path):
        w = self._writer(tmp_path, max_body_size=1000)
        data = b"hello"
        body, encoding, truncated, orig = w._encode_body(data)
        assert not truncated
        assert body == "hello"


class TestCaptureWriterEntry:
    def test_write_entry_produces_valid_jsonl(self, tmp_path):
        cfg = {"enabled": True, "max_body_size": 10485760,
               "min_action": "all", "domains": [], "exclude_domains": []}
        path = str(tmp_path / "capture.jsonl")
        w = CaptureWriter(cfg, path)

        w.write_entry(
            flow_id="abc123",
            direction="outbound",
            decision="allowed",
            host="api.anthropic.com",
            method="POST",
            path="/v1/messages",
            inspectors=[{"name": "domain", "action": "allow", "reason": "ok"}],
            inbound_req={"method": "POST", "url": "https://api.anthropic.com/v1/messages",
                         "headers": [["authorization", "Bearer {{KEY}}"]], "body": "{}",
                         "bodyEncoding": None, "bodySize": 2},
            inbound_resp={"status": 200, "statusText": "OK", "headers": [],
                          "body": '{"ok":true}', "bodyEncoding": None, "bodySize": 11,
                          "mimeType": "application/json"},
            outbound_req={"method": "POST", "url": "https://api.anthropic.com/v1/messages",
                          "headers": [["authorization", "Bearer sk-ant-real"]], "body": "{}",
                          "bodyEncoding": None, "bodySize": 2},
            outbound_resp={"status": 200, "statusText": "OK", "headers": [],
                           "body": '{"ok":true}', "bodyEncoding": None, "bodySize": 11,
                           "mimeType": "application/json"},
        )
        w.close()

        lines = Path(path).read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["flow_id"] == "abc123"
        assert entry["decision"] == "allowed"
        assert entry["inbound"]["request"]["headers"][0][1] == "Bearer {{KEY}}"
        assert entry["outbound"]["request"]["headers"][0][1] == "Bearer sk-ant-real"

    def test_write_entry_with_ws_messages(self, tmp_path):
        cfg = {"enabled": True, "max_body_size": 10485760,
               "min_action": "all", "domains": [], "exclude_domains": []}
        path = str(tmp_path / "capture.jsonl")
        w = CaptureWriter(cfg, path)

        w.write_entry(
            flow_id="ws1",
            direction="outbound",
            decision="allowed",
            host="ws.example.com",
            method="GET",
            path="/ws",
            inspectors=[],
            inbound_req={}, inbound_resp={},
            outbound_req={}, outbound_resp={},
            ws_messages=[{"type": "send", "ts": "2024-01-01T00:00:00Z",
                          "opcode": 1, "data": "hello"}],
        )
        w.close()

        entry = json.loads(Path(path).read_text().strip())
        assert len(entry["ws_messages"]) == 1
        assert entry["ws_messages"][0]["data"] == "hello"


class TestCaptureWriterWsBuffer:
    def test_buffer_and_pop(self, tmp_path):
        cfg = {"enabled": True, "max_body_size": 10485760,
               "min_action": "all", "domains": [], "exclude_domains": []}
        path = str(tmp_path / "capture.jsonl")
        w = CaptureWriter(cfg, path)

        w.add_ws_message("flow1", {"type": "send", "data": "a"})
        w.add_ws_message("flow1", {"type": "receive", "data": "b"})
        msgs = w.pop_ws_messages("flow1")
        assert len(msgs) == 2
        # Second pop returns empty
        assert w.pop_ws_messages("flow1") == []

    def test_pop_nonexistent_flow(self, tmp_path):
        cfg = {"enabled": True, "max_body_size": 10485760,
               "min_action": "all", "domains": [], "exclude_domains": []}
        path = str(tmp_path / "capture.jsonl")
        w = CaptureWriter(cfg, path)
        assert w.pop_ws_messages("nonexistent") == []


# ── HAR builder tests (host-side) ────────────────────────

from agentcage.har import CaptureFilter, capture_to_har, parse_since


_SAMPLE_ENTRY = {
    "ts": "2026-02-20T10:00:00+00:00",
    "flow_id": "abc123",
    "direction": "outbound",
    "decision": "allowed",
    "host": "api.anthropic.com",
    "method": "POST",
    "path": "/v1/messages",
    "inspectors": [{"name": "domain", "action": "allow", "reason": "ok"}],
    "inbound": {
        "request": {
            "method": "POST",
            "url": "https://api.anthropic.com/v1/messages",
            "httpVersion": "HTTP/1.1",
            "headers": [["authorization", "Bearer {{KEY}}"],
                        ["content-type", "application/json"]],
            "body": '{"prompt": "hello"}',
            "bodyEncoding": None,
            "bodySize": 19,
        },
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [["content-type", "application/json"]],
            "body": '{"reply": "world"}',
            "bodyEncoding": None,
            "bodySize": 18,
            "mimeType": "application/json",
        },
    },
    "outbound": {
        "request": {
            "method": "POST",
            "url": "https://api.anthropic.com/v1/messages",
            "httpVersion": "HTTP/1.1",
            "headers": [["authorization", "Bearer sk-ant-real-key"],
                        ["content-type", "application/json"]],
            "body": '{"prompt": "hello"}',
            "bodyEncoding": None,
            "bodySize": 19,
        },
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [["content-type", "application/json"]],
            "body": '{"reply": "world"}',
            "bodyEncoding": None,
            "bodySize": 18,
            "mimeType": "application/json",
        },
    },
}

_BLOCKED_ENTRY = {
    "ts": "2026-02-20T10:01:00+00:00",
    "flow_id": "def456",
    "direction": "outbound",
    "decision": "blocked",
    "host": "evil.com",
    "method": "POST",
    "path": "/exfil",
    "inspectors": [{"name": "domain", "action": "block", "reason": "not allowed"}],
    "inbound": {
        "request": {"method": "POST", "url": "https://evil.com/exfil",
                     "headers": [], "body": "secret", "bodySize": 6},
        "response": {"status": 403, "statusText": "Forbidden", "headers": [],
                      "body": '{"blocked":true}', "bodySize": 16,
                      "mimeType": "application/json"},
    },
    "outbound": {
        "request": {"method": "POST", "url": "https://evil.com/exfil",
                     "headers": [], "body": "secret", "bodySize": 6},
        "response": {"status": 403, "statusText": "Forbidden", "headers": [],
                      "body": '{"blocked":true}', "bodySize": 16,
                      "mimeType": "application/json"},
    },
}


class TestCaptureFilter:
    def test_empty_filter_matches_all(self):
        filt = CaptureFilter()
        assert filt.matches(_SAMPLE_ENTRY)
        assert filt.matches(_BLOCKED_ENTRY)

    def test_decision_filter(self):
        filt = CaptureFilter(decisions=["blocked"])
        assert filt.matches(_BLOCKED_ENTRY)
        assert not filt.matches(_SAMPLE_ENTRY)

    def test_decision_filter_multiple(self):
        filt = CaptureFilter(decisions=["blocked", "allowed"])
        assert filt.matches(_BLOCKED_ENTRY)
        assert filt.matches(_SAMPLE_ENTRY)

    def test_host_filter(self):
        filt = CaptureFilter(hosts=["anthropic"])
        assert filt.matches(_SAMPLE_ENTRY)
        assert not filt.matches(_BLOCKED_ENTRY)

    def test_method_filter(self):
        filt = CaptureFilter(methods=["GET"])
        assert not filt.matches(_SAMPLE_ENTRY)  # POST

    def test_method_filter_case_insensitive(self):
        filt = CaptureFilter(methods=["post"])
        assert filt.matches(_SAMPLE_ENTRY)

    def test_direction_filter(self):
        filt = CaptureFilter(directions=["inbound"])
        assert not filt.matches(_SAMPLE_ENTRY)  # outbound

    def test_since_filter(self):
        cutoff = datetime(2026, 2, 20, 10, 0, 30, tzinfo=timezone.utc)
        filt = CaptureFilter(since=cutoff)
        assert not filt.matches(_SAMPLE_ENTRY)  # before cutoff
        assert filt.matches(_BLOCKED_ENTRY)  # after cutoff

    def test_combined_filters(self):
        filt = CaptureFilter(decisions=["blocked"], hosts=["evil"])
        assert filt.matches(_BLOCKED_ENTRY)
        assert not filt.matches(_SAMPLE_ENTRY)


class TestCaptureToHar:
    def test_produces_valid_har_structure(self):
        har = capture_to_har([_SAMPLE_ENTRY], view="inbound")
        assert har["log"]["version"] == "1.2"
        assert har["log"]["creator"]["name"] == "agentcage"
        assert len(har["log"]["entries"]) == 1

    def test_inbound_view_has_placeholder(self):
        har = capture_to_har([_SAMPLE_ENTRY], view="inbound")
        entry = har["log"]["entries"][0]
        auth_header = [h for h in entry["request"]["headers"]
                       if h["name"] == "authorization"]
        assert auth_header[0]["value"] == "Bearer {{KEY}}"

    def test_outbound_view_has_real_secret(self):
        har = capture_to_har([_SAMPLE_ENTRY], view="outbound")
        entry = har["log"]["entries"][0]
        auth_header = [h for h in entry["request"]["headers"]
                       if h["name"] == "authorization"]
        assert auth_header[0]["value"] == "Bearer sk-ant-real-key"

    def test_response_fields(self):
        har = capture_to_har([_SAMPLE_ENTRY], view="inbound")
        resp = har["log"]["entries"][0]["response"]
        assert resp["status"] == 200
        assert resp["statusText"] == "OK"
        assert resp["content"]["mimeType"] == "application/json"
        assert resp["content"]["text"] == '{"reply": "world"}'

    def test_empty_entries(self):
        har = capture_to_har([], view="inbound")
        assert har["log"]["entries"] == []

    def test_multiple_entries(self):
        har = capture_to_har([_SAMPLE_ENTRY, _BLOCKED_ENTRY], view="inbound")
        assert len(har["log"]["entries"]) == 2

    def test_comment_contains_metadata(self):
        har = capture_to_har([_SAMPLE_ENTRY], view="inbound")
        comment = json.loads(har["log"]["entries"][0]["comment"])
        assert comment["flow_id"] == "abc123"
        assert comment["decision"] == "allowed"
        assert comment["view"] == "inbound"

    def test_query_string_extraction(self):
        entry = {**_SAMPLE_ENTRY}
        entry = json.loads(json.dumps(entry))  # deep copy
        entry["inbound"]["request"]["url"] = "https://example.com/api?q=hello&n=10"
        har = capture_to_har([entry], view="inbound")
        qs = har["log"]["entries"][0]["request"]["queryString"]
        names = {p["name"] for p in qs}
        assert "q" in names
        assert "n" in names

    def test_post_data_included(self):
        har = capture_to_har([_SAMPLE_ENTRY], view="inbound")
        req = har["log"]["entries"][0]["request"]
        assert "postData" in req
        assert req["postData"]["text"] == '{"prompt": "hello"}'
        assert req["postData"]["mimeType"] == "application/json"


class TestParseSince:
    def test_hours(self):
        dt = parse_since("1h")
        assert dt is not None
        assert (datetime.now(timezone.utc) - dt).total_seconds() < 3700

    def test_minutes(self):
        dt = parse_since("30m")
        assert dt is not None
        assert (datetime.now(timezone.utc) - dt).total_seconds() < 1900

    def test_days(self):
        dt = parse_since("7d")
        assert dt is not None
        diff = (datetime.now(timezone.utc) - dt).total_seconds()
        assert 6 * 86400 < diff < 8 * 86400

    def test_iso_date(self):
        dt = parse_since("2026-02-20T10:00:00+00:00")
        assert dt is not None
        assert dt.year == 2026

    def test_invalid(self):
        dt = parse_since("not-a-date")
        assert dt is None
