"""Unit tests for agentcage.har — HAR builder and capture filtering."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from agentcage.har import CaptureFilter, capture_to_har, parse_since


# ---------------------------------------------------------------------------
# Sample JSONL entries
# ---------------------------------------------------------------------------

def _sample_entry(
    *,
    direction: str = "outbound",
    decision: str = "allowed",
    method: str = "GET",
    host: str = "api.example.com",
    url: str = "https://api.example.com/v1/data?key=val",
    status: int = 200,
    req_body: str = "",
    req_body_encoding: str | None = None,
    resp_body: str = "",
    resp_body_encoding: str | None = None,
    ts: str | None = None,
) -> dict:
    if ts is None:
        ts = datetime.now(timezone.utc).isoformat()

    req: dict = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": [["Host", host], ["Content-Type", "application/json"]],
        "body": req_body,
        "bodySize": len(req_body),
    }
    if req_body_encoding:
        req["bodyEncoding"] = req_body_encoding

    resp: dict = {
        "status": status,
        "statusText": "OK",
        "httpVersion": "HTTP/1.1",
        "headers": [["Content-Type", "application/json"]],
        "body": resp_body,
        "bodySize": len(resp_body),
        "mimeType": "application/json",
    }
    if resp_body_encoding:
        resp["bodyEncoding"] = resp_body_encoding

    return {
        "ts": ts,
        "direction": direction,
        "decision": decision,
        "host": host,
        "method": method,
        "flow_id": "abc123",
        "inspectors": [],
        "inbound": {"request": req, "response": resp},
        "outbound": {"request": req, "response": resp},
    }


# ---------------------------------------------------------------------------
# capture_to_har
# ---------------------------------------------------------------------------

class TestCaptureToHar:
    def test_basic_conversion(self):
        entries = [_sample_entry()]
        har = capture_to_har(entries)

        assert har["log"]["version"] == "1.2"
        assert har["log"]["creator"]["name"] == "agentcage"
        assert len(har["log"]["entries"]) == 1

        har_entry = har["log"]["entries"][0]
        assert har_entry["request"]["method"] == "GET"
        assert har_entry["response"]["status"] == 200

    def test_query_string_parsed(self):
        entries = [_sample_entry(url="https://example.com/path?a=1&b=2")]
        har = capture_to_har(entries)

        qs = har["log"]["entries"][0]["request"]["queryString"]
        names = {p["name"] for p in qs}
        assert "a" in names
        assert "b" in names

    def test_empty_entries(self):
        har = capture_to_har([])
        assert har["log"]["entries"] == []

    def test_inbound_view(self):
        entries = [_sample_entry()]
        har = capture_to_har(entries, view="inbound")
        assert len(har["log"]["entries"]) == 1

    def test_comment_metadata(self):
        entries = [_sample_entry(decision="blocked")]
        har = capture_to_har(entries)
        comment = json.loads(har["log"]["entries"][0]["comment"])
        assert comment["decision"] == "blocked"
        assert comment["flow_id"] == "abc123"

    def test_missing_response(self):
        """Entry with no response data should produce an empty HAR response."""
        entry = _sample_entry()
        entry["outbound"]["response"] = {}
        har = capture_to_har([entry], view="outbound")
        resp = har["log"]["entries"][0]["response"]
        assert resp["status"] == 0

    def test_post_data_included(self):
        entries = [_sample_entry(method="POST", req_body='{"key": "value"}')]
        har = capture_to_har(entries)
        post_data = har["log"]["entries"][0]["request"]["postData"]
        assert post_data["text"] == '{"key": "value"}'
        assert post_data["mimeType"] == "application/json"


# ---------------------------------------------------------------------------
# Body encoding
# ---------------------------------------------------------------------------

class TestBodyEncoding:
    def test_utf8_text_body(self):
        entries = [_sample_entry(resp_body="hello world")]
        har = capture_to_har(entries)
        content = har["log"]["entries"][0]["response"]["content"]
        assert content["text"] == "hello world"
        assert "encoding" not in content

    def test_base64_body(self):
        import base64
        raw = base64.b64encode(b"\x00\x01\x02binary").decode()
        entries = [_sample_entry(resp_body=raw, resp_body_encoding="base64")]
        har = capture_to_har(entries)
        content = har["log"]["entries"][0]["response"]["content"]
        assert content["encoding"] == "base64"
        assert content["text"] == raw

    def test_base64_request_body(self):
        import base64
        raw = base64.b64encode(b"binary-req").decode()
        entries = [_sample_entry(
            method="POST",
            req_body=raw,
            req_body_encoding="base64",
        )]
        har = capture_to_har(entries)
        post_data = har["log"]["entries"][0]["request"]["postData"]
        assert post_data["encoding"] == "base64"


# ---------------------------------------------------------------------------
# parse_since
# ---------------------------------------------------------------------------

class TestParseSince:
    def test_hours(self):
        result = parse_since("2h")
        assert result is not None
        expected = datetime.now(timezone.utc) - timedelta(hours=2)
        assert abs((result - expected).total_seconds()) < 2

    def test_minutes(self):
        result = parse_since("30m")
        assert result is not None
        expected = datetime.now(timezone.utc) - timedelta(minutes=30)
        assert abs((result - expected).total_seconds()) < 2

    def test_days(self):
        result = parse_since("7d")
        assert result is not None
        expected = datetime.now(timezone.utc) - timedelta(days=7)
        assert abs((result - expected).total_seconds()) < 2

    def test_uppercase_unit(self):
        result = parse_since("1H")
        assert result is not None

    def test_iso_date(self):
        result = parse_since("2025-01-15T10:00:00+00:00")
        assert result is not None
        assert result.year == 2025
        assert result.month == 1
        assert result.day == 15

    def test_iso_date_naive_gets_utc(self):
        result = parse_since("2025-06-01T00:00:00")
        assert result is not None
        assert result.tzinfo == timezone.utc

    def test_invalid_returns_none(self):
        assert parse_since("foobar") is None
        assert parse_since("") is None

    def test_zero_value(self):
        result = parse_since("0h")
        assert result is not None


# ---------------------------------------------------------------------------
# CaptureFilter
# ---------------------------------------------------------------------------

class TestCaptureFilter:
    def test_matches_all_by_default(self):
        f = CaptureFilter()
        assert f.matches(_sample_entry()) is True

    def test_filter_by_decision(self):
        f = CaptureFilter(decisions=["blocked"])
        assert f.matches(_sample_entry(decision="allowed")) is False
        assert f.matches(_sample_entry(decision="blocked")) is True

    def test_filter_by_direction(self):
        f = CaptureFilter(directions=["inbound"])
        assert f.matches(_sample_entry(direction="outbound")) is False
        assert f.matches(_sample_entry(direction="inbound")) is True

    def test_filter_by_host(self):
        f = CaptureFilter(hosts=["example.com"])
        assert f.matches(_sample_entry(host="api.example.com")) is True
        assert f.matches(_sample_entry(host="other.io")) is False

    def test_filter_by_method(self):
        f = CaptureFilter(methods=["POST"])
        assert f.matches(_sample_entry(method="GET")) is False
        assert f.matches(_sample_entry(method="POST")) is True

    def test_filter_by_min_action(self):
        f = CaptureFilter(min_action="flag")
        assert f.matches(_sample_entry(decision="allowed")) is False
        assert f.matches(_sample_entry(decision="flagged")) is True
        assert f.matches(_sample_entry(decision="blocked")) is True

    def test_filter_by_since(self):
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        recent_ts = datetime.now(timezone.utc).isoformat()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

        f = CaptureFilter(since=cutoff)
        assert f.matches(_sample_entry(ts=old_ts)) is False
        assert f.matches(_sample_entry(ts=recent_ts)) is True


# ---------------------------------------------------------------------------
# Malformed JSONL entries
# ---------------------------------------------------------------------------

class TestMalformedEntries:
    def test_missing_view_key_produces_empty_request(self):
        """Entry missing the requested view should still produce HAR output."""
        entry = {"ts": datetime.now(timezone.utc).isoformat()}
        har = capture_to_har([entry], view="outbound")
        assert len(har["log"]["entries"]) == 1
        # Request built from empty dict
        assert har["log"]["entries"][0]["request"]["method"] == ""

    def test_filter_handles_missing_fields(self):
        f = CaptureFilter(decisions=["allowed"])
        # Entry with no decision field
        assert f.matches({}) is False
