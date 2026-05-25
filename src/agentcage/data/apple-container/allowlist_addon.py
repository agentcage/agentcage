"""agentcage apple-container egress allowlist + audit addon for mitmproxy.

The mitmproxy `--allow-hosts` flag controls *interception scope* (which
hosts get MITMed) but does NOT block non-listed hosts. It just passes
them through unintercepted, which is the opposite of what we want.

This addon enforces a real allowlist: every request's host is checked
against /etc/agentcage/allowlist.txt (one entry per line, subdomains
auto-allowed). Non-matching requests are replied to with a 403 from
mitmproxy itself — the upstream connection is never opened.

For every decision we emit a structured JSON line to
``/var/log/agentcage/audit.jsonl`` (or ``$AGENTCAGE_AUDIT_LOG``), in the
format ``agentcage.audit.AuditEntry.from_dict`` expects — that's what
``agentcage cage audit`` consumes on the host side once the file is
bind-mounted out of the microVM. For successful 2xx responses we also
emit a basic capture record to ``/var/log/agentcage/capture.jsonl`` so
``agentcage cage har`` can produce HAR 1.2 JSON.

This is a leaner audit format than the container backend's
``addon.py`` (no inspector chain, no body capture, no secret-injection
metadata yet — those are tracked as separate items in #120's parity
plan). The fields here are the minimum subset ``AuditEntry`` /
``CaptureFilter`` need to filter and summarize.

The allowlist file is read once at startup; restart the cage to pick up
changes. Empty allowlist means "block everything".
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from mitmproxy import ctx, http


ALLOWLIST_PATH = "/etc/agentcage/allowlist.txt"
AUDIT_LOG_PATH = os.environ.get(
    "AGENTCAGE_AUDIT_LOG", "/var/log/agentcage/audit.jsonl"
)
CAPTURE_PATH = os.environ.get(
    "AGENTCAGE_CAPTURE", "/var/log/agentcage/capture.jsonl"
)


def _load_allowlist() -> set[str]:
    try:
        with open(ALLOWLIST_PATH) as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def _host_allowed(host: str, allowed: set[str]) -> bool:
    """Subdomains of allowed hosts are also allowed (matches Lima behaviour).

    e.g. allowlist {"github.com"} accepts host "api.github.com" but not
    "evil-github.com" or "githubcom.example.com".
    """
    h = host.lower()
    for d in allowed:
        d = d.lower()
        if h == d or h.endswith("." + d):
            return True
    return False


class AllowlistAddon:
    def __init__(self) -> None:
        self.allowed = _load_allowlist()
        ctx.log.info(
            f"[agentcage] allowlist loaded: {sorted(self.allowed) or '(empty — block all)'}"
        )
        self._audit_fh = self._open_log(AUDIT_LOG_PATH)
        self._capture_fh = self._open_log(CAPTURE_PATH)

    @staticmethod
    def _open_log(path: str):
        """Append-open ``path``; return None and log a warning on failure.

        ``/var/log/agentcage`` is bind-mounted from the host (mode 1777)
        on apple-container, so the open should succeed even though the
        mitmproxy process runs as uid 200. Tests can point both paths
        at /dev/null via the env vars.
        """
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            return open(path, "a", buffering=1)  # line-buffered
        except OSError as exc:  # pragma: no cover — virtiofs surprise
            ctx.log.warn(f"[agentcage] cannot open {path}: {exc}")
            return None

    def _write(self, fh, entry: dict) -> None:
        if fh is None:
            return
        try:
            fh.write(json.dumps(entry) + "\n")
        except OSError as exc:  # pragma: no cover
            ctx.log.warn(f"[agentcage] write failed: {exc}")

    def _audit(self, entry: dict) -> None:
        # Mirror entries to stderr so they also surface in `container logs`
        # (same pattern container's addon.py uses for the journalctl path).
        print(json.dumps(entry), file=sys.stderr, flush=True)
        self._write(self._audit_fh, entry)

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        now = datetime.now(timezone.utc).isoformat()

        entry: dict = {
            "ts": now,
            "direction": "outbound",
            "method": flow.request.method,
            "host": host,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "port": flow.request.port,
            "source": "apple-container",
            "inspectors": [],
            "secrets_injected": [],
            "secrets_redacted": [],
        }

        if _host_allowed(host, self.allowed):
            entry["decision"] = "allowed"
            entry["reason"] = "domain-allowlist"
            self._audit(entry)
            return

        ctx.log.info(f"[agentcage] BLOCK {flow.request.method} {host}")
        entry["decision"] = "blocked"
        entry["reason"] = "domain-allowlist: host not in cage allowlist"
        self._audit(entry)
        flow.response = http.Response.make(
            403,
            (
                f"agentcage: host '{host}' is not on the cage allowlist.\n"
                "Add the domain to cage.yaml under `domains.allow` and "
                "rebuild the cage.\n"
            ).encode(),
            {"Content-Type": "text/plain"},
        )

    def response(self, flow: http.HTTPFlow) -> None:
        """Emit a capture record for successful round-trips.

        Capture only includes responses we actually proxied (i.e. the
        request hook did NOT short-circuit with a 403). The format is a
        subset of the container backend's capture.jsonl, enough for
        ``agentcage.har.capture_to_har`` to render a HAR file: ts,
        request fields, response status/headers. Bodies are omitted in
        v1 because the apple-container addon doesn't have the streaming
        capture machinery; HAR will show response.content.size=0.
        """
        if self._capture_fh is None or flow.response is None:
            return
        # If we already 403ed in `request`, the response is one we
        # constructed locally — no point re-capturing it.
        if (
            flow.response.status_code == 403
            and flow.response.headers.get("Content-Type", "").startswith(
                "text/plain"
            )
            and flow.response.content
            and flow.response.content.startswith(b"agentcage: host '")
        ):
            return
        host = flow.request.pretty_host
        capture: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "direction": "outbound",
            "decision": "allowed",
            "host": host,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": [
                    {"name": k, "value": v}
                    for k, v in flow.request.headers.items()
                ],
            },
            "response": {
                "status": flow.response.status_code,
                "statusText": flow.response.reason or "",
                "headers": [
                    {"name": k, "value": v}
                    for k, v in flow.response.headers.items()
                ],
            },
        }
        self._write(self._capture_fh, capture)


addons = [AllowlistAddon()]
