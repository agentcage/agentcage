"""Capture JSONL writer — records full request/response bodies for HAR export.

Runs inside the proxy container.  Writes one JSON line per completed flow
with both INBOUND (cage-visible, placeholders) and OUTBOUND (wire, real
secrets) perspectives.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mitmproxy import http


_ACTION_ORDER = {"all": 0, "flag": 1, "block": 2}

# ``min_action`` spellings the configuration reference used to show,
# mapped to the values they mean. Before this they fell through to
# "record everything"; the host accepts them with a warning, and rejects
# any other unknown value.
_MIN_ACTION_ALIASES = {"allowed": "all", "flagged": "flag", "blocked": "block"}

# Per-flow bound on buffered WebSocket frames. A WebSocket's entry is
# written when the socket ends, so every frame it records sits in memory
# until then, and a socket can stay open for hours. Each frame's data is
# capped at ``max_body_size`` like a body; on top of that one flow keeps
# at most _WS_MAX_MESSAGES frames and at most ``max_body_size`` bytes of
# frame data in total (_WS_DEFAULT_TOTAL when ``max_body_size`` is 0: an
# unlimited body still ends, a socket need not). Frames past either bound
# are counted, not kept, and the entry reports them as
# ``ws_messages_omitted``. The sizes keep a WebSocket entry inside the
# watcher's single-line cap (four body slots plus 1 MiB of slack): the
# frame data fills at most one body slot, and 4096 records of roughly
# 120 bytes of JSON framing each fit in the slack.
_WS_MAX_MESSAGES = 4096
_WS_DEFAULT_TOTAL = 10485760


class _WsBuffer:
    """One flow's recorded WebSocket frames and what the bound dropped."""

    __slots__ = ("messages", "data_bytes", "omitted")

    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.data_bytes = 0
        self.omitted = 0


class CaptureWriter:
    """Append capture entries to a JSONL file."""

    def __init__(self, cfg: dict, path: str) -> None:
        self._cfg = cfg
        self._max_body = int(cfg.get("max_body_size", 10485760))
        min_action = str(cfg.get("min_action") or "all")
        self._min_action = _MIN_ACTION_ALIASES.get(min_action, min_action)
        self._domains: list[str] = cfg.get("domains") or []
        self._exclude_domains: list[str] = cfg.get("exclude_domains") or []
        self._ws_buffers: dict[str, _WsBuffer] = {}
        self._ws_total = self._max_body or _WS_DEFAULT_TOTAL

        # Size cap + single-generation rotation. Without this the capture
        # file grows without bound: a body-heavy cage writes far faster
        # than anything downstream reads (a measured 222 MB in 20 minutes
        # of apt traffic), filling the volume and leaving the watcher's
        # tail permanently behind. ``audit.jsonl`` has had a cap since its
        # own disk-fill review; this is the same posture for the much
        # larger stream. 0 disables the cap.
        self._max_file = max(0, int(cfg.get("max_file_size", 134217728)))
        self._path = path
        self._rotated = f"{path}.1"

        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._file = open(path, "a")
        try:
            self._size = self._file.tell()
        except OSError:  # pragma: no cover — defensive
            self._size = 0

    def _maybe_rotate(self) -> None:
        """Roll the capture file over once it passes ``max_file_size``.

        One generation is kept (``capture.jsonl.1``), so the on-disk
        ceiling is twice the cap. Rotation is rename + reopen: the
        watcher's tail tracks ``(st_dev, st_ino)`` and treats the new
        inode as a reset, and ``cage har`` reads the rotated generation
        before the live one — so neither silently loses the older half.
        """
        if not self._max_file or self._size < self._max_file:
            return
        try:
            self._file.flush()
            self._file.close()
        except OSError:  # pragma: no cover — defensive
            pass
        try:
            os.replace(self._path, self._rotated)
        except OSError as e:  # pragma: no cover — defensive
            # Rotation failed; reopen and keep appending rather than
            # dropping capture entirely.
            print(f"agentcage: capture rotation failed: {e}",
                  file=sys.stderr, flush=True)
        self._file = open(self._path, "a")
        self._size = 0

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
        return self.captures_host(host)

    def captures_host(self, host: str) -> bool:
        """Check the domain filters alone (``domains``/``exclude_domains``).

        A WebSocket's decision can still escalate after its upgrade (a
        later frame may be flagged or blocked), so at the upgrade only
        the domain half of ``should_capture`` is final.
        """
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
        ws_messages_omitted: int = 0,
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
        if ws_messages_omitted:
            entry["ws_messages_omitted"] = ws_messages_omitted

        line = json.dumps(entry, separators=(",", ":"))
        self._file.write(line + "\n")
        self._file.flush()
        # Track the size we wrote rather than stat()ing per entry, then
        # roll over past the cap.
        self._size += len(line.encode("utf-8", "replace")) + 1
        self._maybe_rotate()

    # ── WebSocket buffering ──────────────────────────────

    def add_ws_frame(
        self,
        flow_id: str,
        *,
        from_client: bool,
        is_text: bool,
        content: bytes,
        ts: str,
        decision: str = "allowed",
    ) -> None:
        """Record one WebSocket message for a flow, within the flow's bound.

        ``content`` must already be in its capture form (redacted by the
        caller). Text messages are stored as text (opcode 1); binary ones
        (opcode 2) as text when they decode as UTF-8, else base64 with
        ``dataEncoding``. Data past ``max_body_size``, or past what is
        left of the flow's total, is cut and marked ``dataTruncated``; a
        message arriving with nothing left, or past _WS_MAX_MESSAGES, is
        only counted (see the module constants).
        """
        buf = self._ws_buffers.setdefault(flow_id, _WsBuffer())
        room = self._ws_total - buf.data_bytes
        if len(buf.messages) >= _WS_MAX_MESSAGES or room <= 0:
            buf.omitted += 1
            return
        limit = min(self._max_body, room) if self._max_body else room
        original_size = len(content)
        kept = content[:limit]
        msg: dict = {
            "type": "send" if from_client else "receive",
            "ts": ts,
            "opcode": 1 if is_text else 2,
        }
        if is_text:
            # Text messages are UTF-8 by definition; "replace" only ever
            # touches a character the truncation cut in half.
            msg["data"] = kept.decode("utf-8", errors="replace")
        else:
            try:
                msg["data"] = kept.decode("utf-8")
            except UnicodeDecodeError:
                msg["data"] = base64.b64encode(kept).decode("ascii")
                msg["dataEncoding"] = "base64"
        if len(kept) < original_size:
            msg["dataTruncated"] = True
            msg["dataOriginalSize"] = original_size
        if decision != "allowed":
            msg["decision"] = decision
        buf.data_bytes += len(kept)
        buf.messages.append(msg)

    def add_ws_message(self, flow_id: str, msg: dict) -> None:
        """Buffer an already-serialized WebSocket message for a flow.

        Counts against the flow's message bound but not its data total
        (``msg`` is opaque here); the proxy records through add_ws_frame.
        """
        buf = self._ws_buffers.setdefault(flow_id, _WsBuffer())
        if len(buf.messages) >= _WS_MAX_MESSAGES:
            buf.omitted += 1
            return
        buf.messages.append(msg)

    def pop_ws_buffer(self, flow_id: str) -> tuple[list[dict], int]:
        """Pop a flow's buffered WS messages and how many were omitted."""
        buf = self._ws_buffers.pop(flow_id, None)
        if buf is None:
            return [], 0
        return buf.messages, buf.omitted

    def pop_ws_messages(self, flow_id: str) -> list[dict]:
        """Pop and return buffered WS messages for a flow."""
        return self.pop_ws_buffer(flow_id)[0]

    def adopt_ws_buffers(self, other: "CaptureWriter") -> None:
        """Take over ``other``'s buffered WebSocket frames.

        Used when a config reload replaces the writer: flows still open
        across the swap are completed by the new writer, which must hand
        back the frames buffered before it existed. Each buffer keeps
        what it already used of its bound; frames from here on are
        measured against this writer's limits.
        """
        self._ws_buffers.update(other._ws_buffers)
        other._ws_buffers = {}

    # ── Lifecycle ────────────────────────────────────────

    def flush(self) -> None:
        if self._file:
            self._file.flush()

    def close(self) -> None:
        if self._file:
            self._file.flush()
            self._file.close()
            self._file = None  # type: ignore[assignment]
