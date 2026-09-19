"""Unit tests for the capture JSONL writer (egress side).

Boundary note (RUST-PORT-PLAN.md §2.4): ``capture.py`` lives in
``src/agentcage/data/proxy/`` and stays Python. The HAR builder that reads the
file back is host-side and moved to ``tests/test_capture_har.py``; the one
assertion that the writer's default size cap matches the host's
``config.MAX_CAPTURE_FILE_BYTES`` belongs to neither side and moved to
``tests/cross_language/test_capture_format_conformance.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


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


class TestCaptureWriterRotation:
    """The capture file used to grow without bound.

    A body-heavy cage writes far faster than anything downstream reads it
    (measured: 222 MB in 20 minutes of apt traffic), which fills the
    volume and leaves the watcher's byte-offset tail permanently behind.
    ``max_file_size`` rolls the file over, keeping one generation.
    """

    def _write(self, w, host="api.example.com", body="x" * 2048):
        w.write_entry(
            flow_id="f", direction="outbound", decision="allowed",
            host=host, method="POST", path="/p", inspectors=[],
            inbound_req={"method": "POST", "url": f"https://{host}/p",
                         "headers": [], "body": body, "bodyEncoding": None,
                         "bodySize": len(body)},
            inbound_resp={"status": 200, "headers": [], "body": "",
                          "bodyEncoding": None, "bodySize": 0},
            outbound_req={"method": "POST", "url": f"https://{host}/p",
                          "headers": [], "body": body, "bodyEncoding": None,
                          "bodySize": len(body)},
            outbound_resp={"status": 200, "headers": [], "body": "",
                           "bodyEncoding": None, "bodySize": 0},
        )

    def _cfg(self, **over):
        cfg = {"enable_har": True, "max_body_size": 10485760,
               "min_action": "all", "domains": [], "exclude_domains": []}
        cfg.update(over)
        return cfg

    def test_first_rollover_loses_nothing(self, tmp_path):
        # Across a single rollover the two generations together still hold
        # every entry — the rotation itself does not drop data.
        path = tmp_path / "capture.jsonl"
        w = CaptureWriter(self._cfg(max_file_size=20000), str(path))
        n = 8
        for _ in range(n):
            self._write(w)
        rotated = tmp_path / "capture.jsonl.1"
        assert rotated.is_file(), "expected a rotated generation"
        assert path.stat().st_size < 20000
        total = sum(1 for f in (rotated, path)
                    for line in f.read_text().splitlines() if line.strip())
        assert total == n

    def test_retention_is_bounded_to_two_generations(self, tmp_path):
        # Deliberate: past the second rollover the oldest generation is
        # discarded. That is the trade — bounded disk, bounded history.
        path = tmp_path / "capture.jsonl"
        w = CaptureWriter(self._cfg(max_file_size=20000), str(path))
        for i in range(40):
            self._write(w, host=f"h{i:03d}.example")
        kept = [json.loads(line)["host"]
                for f in (tmp_path / "capture.jsonl.1", path)
                for line in f.read_text().splitlines() if line.strip()]
        assert kept, "expected retained entries"
        # What survives is the RECENT tail, not the beginning.
        assert kept[-1] == "h039.example"
        assert "h000.example" not in kept

    def test_ceiling_is_two_generations(self, tmp_path):
        path = tmp_path / "capture.jsonl"
        w = CaptureWriter(self._cfg(max_file_size=20000), str(path))
        for _ in range(200):
            self._write(w)
        on_disk = sum(p.stat().st_size for p in tmp_path.iterdir())
        assert on_disk < 3 * 20000, f"unbounded growth: {on_disk} bytes"

    def test_zero_disables_rotation(self, tmp_path):
        path = tmp_path / "capture.jsonl"
        w = CaptureWriter(self._cfg(max_file_size=0), str(path))
        for _ in range(20):
            self._write(w)
        assert not (tmp_path / "capture.jsonl.1").exists()
        assert path.stat().st_size > 20000


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
