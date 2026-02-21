"""HAR 1.2 builder and capture JSONL filtering.

Runs on the host — reads capture JSONL entries and produces standard
HAR JSON loadable in Chrome DevTools.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import version as pkg_version


_ACTION_ORDER = {"all": 0, "flag": 1, "block": 2}


@dataclass
class CaptureFilter:
    """Filter capture entries (mirrors AuditFilter pattern)."""

    decisions: list[str] = field(default_factory=list)
    directions: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    min_action: str | None = None
    since: datetime | None = None

    def matches(self, entry: dict) -> bool:
        if self.decisions and entry.get("decision") not in self.decisions:
            return False
        if self.directions and entry.get("direction") not in self.directions:
            return False
        if self.hosts and not any(h in entry.get("host", "") for h in self.hosts):
            return False
        if self.methods:
            entry_method = entry.get("method", "").upper()
            if entry_method not in [m.upper() for m in self.methods]:
                return False
        if self.min_action:
            decision = entry.get("decision", "allowed")
            decision_level = _ACTION_ORDER.get(
                {"allowed": "all", "flagged": "flag", "blocked": "block"}.get(decision, "all"),
                0,
            )
            min_level = _ACTION_ORDER.get(self.min_action, 0)
            if decision_level < min_level:
                return False
        if self.since:
            ts = entry.get("ts", "")
            if ts:
                try:
                    entry_dt = datetime.fromisoformat(ts)
                    if entry_dt < self.since:
                        return False
                except (ValueError, TypeError):
                    pass
        return True


def _build_headers(headers: list) -> list[dict]:
    """Convert [[name, value], ...] to HAR headers format."""
    return [{"name": h[0], "value": h[1]} for h in headers if len(h) >= 2]


def _build_query_string(url: str) -> list[dict]:
    """Extract query parameters from URL."""
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    params = []
    if parsed.query:
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            for val in values:
                params.append({"name": key, "value": val})
    return params


def _build_request_entry(req: dict) -> dict:
    """Convert a capture request snapshot to a HAR request object."""
    headers = _build_headers(req.get("headers", []))
    url = req.get("url", "")
    body = req.get("body", "")
    body_size = req.get("bodySize", 0)

    har_req: dict = {
        "method": req.get("method", ""),
        "url": url,
        "httpVersion": req.get("httpVersion", "HTTP/1.1"),
        "cookies": [],
        "headers": headers,
        "queryString": _build_query_string(url),
        "headersSize": -1,
        "bodySize": body_size,
    }

    if body:
        # Determine MIME type from headers
        mime = ""
        for h in req.get("headers", []):
            if len(h) >= 2 and h[0].lower() == "content-type":
                mime = h[1]
                break
        post_data: dict = {"mimeType": mime, "text": body}
        if req.get("bodyEncoding") == "base64":
            post_data["encoding"] = "base64"
        har_req["postData"] = post_data

    return har_req


def _build_response_entry(resp: dict) -> dict:
    """Convert a capture response snapshot to a HAR response object."""
    if not resp:
        return {
            "status": 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": [],
            "content": {"size": 0, "mimeType": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        }

    headers = _build_headers(resp.get("headers", []))
    body = resp.get("body", "")
    mime = resp.get("mimeType", "")

    content: dict = {
        "size": resp.get("bodySize", 0),
        "mimeType": mime,
    }
    if body:
        content["text"] = body
        if resp.get("bodyEncoding") == "base64":
            content["encoding"] = "base64"

    return {
        "status": resp.get("status", 0),
        "statusText": resp.get("statusText", ""),
        "httpVersion": resp.get("httpVersion", "HTTP/1.1"),
        "cookies": [],
        "headers": headers,
        "content": content,
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": resp.get("bodySize", -1),
    }


def capture_to_har(entries: list[dict], view: str = "inbound") -> dict:
    """Convert capture JSONL entries to HAR 1.2 JSON.

    Args:
        entries: parsed capture JSONL entries
        view: "inbound" or "outbound" — which perspective to render
    Returns:
        Complete HAR 1.2 dict ready for json.dumps()
    """
    har_entries = []
    for entry in entries:
        perspective = entry.get(view, {})
        req_data = perspective.get("request", {})
        resp_data = perspective.get("response", {})

        ts = entry.get("ts", datetime.now(timezone.utc).isoformat())

        har_entry = {
            "startedDateTime": ts,
            "time": 0,
            "request": _build_request_entry(req_data),
            "response": _build_response_entry(resp_data),
            "cache": {},
            "timings": {"send": -1, "wait": -1, "receive": -1},
        }

        # Add agentcage metadata as a comment
        har_entry["comment"] = json.dumps({
            "flow_id": entry.get("flow_id", ""),
            "direction": entry.get("direction", ""),
            "decision": entry.get("decision", ""),
            "inspectors": entry.get("inspectors", []),
            "view": view,
        })

        har_entries.append(har_entry)

    try:
        creator_version = pkg_version("agentcage")
    except Exception:
        creator_version = "0.0.0"

    return {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "agentcage",
                "version": creator_version,
            },
            "entries": har_entries,
        }
    }


def parse_since(since: str) -> datetime | None:
    """Parse a --since value into a datetime.

    Accepts: 1h, 30m, 7d, or ISO date strings.
    Returns None if parsing fails.
    """
    from datetime import timedelta

    m = re.match(r"^(\d+)([hHmMdD])$", since)
    if m:
        val, unit = int(m.group(1)), m.group(2).lower()
        now = datetime.now(timezone.utc)
        if unit == "h":
            return now - timedelta(hours=val)
        elif unit == "m":
            return now - timedelta(minutes=val)
        elif unit == "d":
            return now - timedelta(days=val)

    # Try ISO date
    try:
        dt = datetime.fromisoformat(since)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
