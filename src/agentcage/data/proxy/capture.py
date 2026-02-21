"""Capture JSONL writer — records full request/response bodies for HAR export.

Runs inside the proxy container.  Writes one JSON line per completed flow
with both INBOUND (cage-visible, placeholders) and OUTBOUND (wire, real
secrets) perspectives.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mitmproxy import http


_ACTION_ORDER = {"all": 0, "flag": 1, "block": 2}


class CaptureWriter:
    """Append capture entries to a JSONL file."""

    def __init__(self, cfg: dict, path: str) -> None:
        self._cfg = cfg
        self._max_body = int(cfg.get("max_body_size", 10485760))
        self._min_action = cfg.get("min_action", "all")
        self._domains: list[str] = cfg.get("domains") or []
        self._exclude_domains: list[str] = cfg.get("exclude_domains") or []
        self._ws_buffers: dict[str, list[dict]] = {}

        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._file = open(path, "a")

    # ── Snapshot helpers ─────────────────────────────────

    def snapshot_request(self, flow: http.HTTPFlow) -> dict:
        """Serialize the current state of a flow's request."""
        req = flow.request
        headers = [[k, v] for k, v in req.headers.items(multi=True)]
        body, encoding, truncated, orig_size = self._encode_body(req.content)
        d: dict = {
            "method": req.method,
            "url": req.url,
            "httpVersion": req.http_version,
            "headers": headers,
            "body": body,
            "bodyEncoding": encoding,
            "bodySize": len(req.content) if req.content else 0,
        }
        if truncated:
            d["bodyTruncated"] = True
            d["bodyOriginalSize"] = orig_size
        return d

    def snapshot_response(self, flow: http.HTTPFlow) -> dict:
        """Serialize the current state of a flow's response."""
        resp = flow.response
        if resp is None:
            return {}
        headers = [[k, v] for k, v in resp.headers.items(multi=True)]
        body, encoding, truncated, orig_size = self._encode_body(resp.content)
        mime = resp.headers.get("content-type", "")
        d: dict = {
            "status": resp.status_code,
            "statusText": resp.reason or "",
            "httpVersion": resp.http_version,
            "headers": headers,
            "body": body,
            "bodyEncoding": encoding,
            "bodySize": len(resp.content) if resp.content else 0,
            "mimeType": mime,
        }
        if truncated:
            d["bodyTruncated"] = True
            d["bodyOriginalSize"] = orig_size
        return d

    def _encode_body(
        self, content: bytes | None
    ) -> tuple[str, str | None, bool, int]:
        """Encode body bytes for JSON serialization.

        Returns (body_str, encoding, truncated, original_size).
        """
        if content is None:
            return "", None, False, 0

        original_size = len(content)
        truncated = False
        if self._max_body and original_size > self._max_body:
            content = content[: self._max_body]
            truncated = True

        # Try UTF-8 first; fall back to base64 for binary
        try:
            text = content.decode("utf-8")
            return text, None, truncated, original_size
        except UnicodeDecodeError:
            return base64.b64encode(content).decode("ascii"), "base64", truncated, original_size

    # ── Filtering ────────────────────────────────────────

    def should_capture(self, decision: str, host: str) -> bool:
        """Check capture-time filters (domain + min_action)."""
        # Action filter
        decision_level = _ACTION_ORDER.get(
            {"allowed": "all", "flagged": "flag", "blocked": "block"}.get(decision, "all"),
            0,
        )
        min_level = _ACTION_ORDER.get(self._min_action, 0)
        if decision_level < min_level:
            return False

        # Domain allowlist
        if self._domains:
            if not any(self._domain_matches(d, host) for d in self._domains):
                return False

        # Domain blocklist
        if self._exclude_domains:
            if any(self._domain_matches(d, host) for d in self._exclude_domains):
                return False

        return True

    @staticmethod
    def _domain_matches(pattern: str, host: str) -> bool:
        """Check if host matches pattern (exact or subdomain)."""
        return host == pattern or host.endswith("." + pattern)

    # ── Entry writing ────────────────────────────────────

    def write_entry(
        self,
        flow_id: str,
        direction: str,
        decision: str,
        host: str,
        method: str,
        path: str,
        inspectors: list[dict],
        inbound_req: dict,
        inbound_resp: dict,
        outbound_req: dict,
        outbound_resp: dict,
        ws_messages: list[dict] | None = None,
    ) -> None:
        """Write a complete capture entry as one JSONL line."""
        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "flow_id": flow_id,
            "direction": direction,
            "decision": decision,
            "host": host,
            "method": method,
            "path": path,
            "inspectors": inspectors,
            "inbound": {
                "request": inbound_req,
                "response": inbound_resp,
            },
            "outbound": {
                "request": outbound_req,
                "response": outbound_resp,
            },
        }
        if ws_messages:
            entry["ws_messages"] = ws_messages

        line = json.dumps(entry, separators=(",", ":"))
        self._file.write(line + "\n")
        self._file.flush()

    # ── WebSocket buffering ──────────────────────────────

    def add_ws_message(self, flow_id: str, msg: dict) -> None:
        """Buffer a WebSocket message for a flow."""
        self._ws_buffers.setdefault(flow_id, []).append(msg)

    def pop_ws_messages(self, flow_id: str) -> list[dict]:
        """Pop and return buffered WS messages for a flow."""
        return self._ws_buffers.pop(flow_id, [])

    # ── Lifecycle ────────────────────────────────────────

    def flush(self) -> None:
        if self._file:
            self._file.flush()

    def close(self) -> None:
        if self._file:
            self._file.flush()
            self._file.close()
            self._file = None  # type: ignore[assignment]
