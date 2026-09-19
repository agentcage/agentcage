"""Unit tests for the HAR builder — host side.

Split out of ``tests/test_capture.py`` (RUST-PORT-PLAN.md §2.4): the capture
JSONL *writer* is in ``data/proxy/`` and stays Python, while ``agentcage.har``
reads that file back on the host and becomes Rust. Test names are unchanged so
failures stay greppable against history.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock


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


class TestHarExportReadsRotatedGeneration:
    """`cage har` must read `capture.jsonl.1` too.

    The writer rotates at `capture.max_file_size`, keeping one previous
    generation. An exporter that only opened the live file would silently
    shorten every export taken after a rollover — the older half would
    vanish with no error, which is the worst failure mode for a forensic
    tool.
    """

    def _entry(self, host, ts="2026-01-01T00:00:00+00:00"):
        return json.dumps({
            "ts": ts, "flow_id": host, "direction": "outbound",
            "decision": "allowed", "host": host, "method": "GET",
            "path": "/", "inspectors": [],
            "inbound": {"request": {"method": "GET", "url": f"https://{host}/",
                                    "headers": [], "body": "",
                                    "bodyEncoding": None, "bodySize": 0},
                        "response": {"status": 200, "headers": [], "body": "",
                                     "bodyEncoding": None, "bodySize": 0,
                                     "mimeType": "application/json"}},
            "outbound": {"request": {}, "response": {}},
        })

    def test_rotated_entries_are_exported(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from agentcage.cli import main
        from unittest.mock import patch

        cap = tmp_path / "capture.jsonl"
        (tmp_path / "capture.jsonl.1").write_text(
            self._entry("old.example") + "\n")
        cap.write_text(self._entry("new.example") + "\n")

        with patch("agentcage.cli.state") as st, \
                patch("agentcage.cli._is_apple_container", return_value=False):
            st.deployment_exists.return_value = True
            st.load_deployment_config.return_value = MagicMock()
            st.capture_file.return_value = cap
            res = CliRunner().invoke(main, ["cage", "har", "test"])

        assert res.exit_code == 0, res.output
        # Both generations present, oldest first.
        assert "old.example" in res.output, "rotated generation was dropped"
        assert "new.example" in res.output
        assert res.output.index("old.example") < res.output.index("new.example")
