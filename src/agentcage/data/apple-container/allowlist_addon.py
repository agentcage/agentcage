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
SECRET_INJECTION_PATH = "/etc/agentcage/secret_injection.json"
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


def _load_secret_injection_rules() -> list[dict]:
    """Load the cage's secret_injection rule list, baked in at build time.

    Each rule is ``{"env": str, "placeholder": str, "inject_to": [str]}``.
    The actual secret VALUE is read from ``os.environ[env]`` at request
    time (forwarded by ``AppleContainerBackend.start()`` via ``-e``).
    """
    try:
        with open(SECRET_INJECTION_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


class AllowlistAddon:
    def __init__(self) -> None:
        self.allowed = _load_allowlist()
        ctx.log.info(
            f"[agentcage] allowlist loaded: {sorted(self.allowed) or '(empty — block all)'}"
        )
        self.injection_rules = _load_secret_injection_rules()
        # Resolve secret values from the environment ONCE at startup —
        # later os.environ changes won't propagate. Skip rules whose
        # env var isn't set (the backend logs a warning at start, and
        # the placeholder simply doesn't get substituted).
        self._resolved_secrets: list[dict] = []
        for rule in self.injection_rules:
            value = os.environ.get(rule.get("env", ""))
            if not value:
                continue
            self._resolved_secrets.append({
                "env": rule["env"],
                "placeholder": rule["placeholder"],
                "value": value,
                "inject_to": [d.lower() for d in (rule.get("inject_to") or [])],
            })
        if self._resolved_secrets:
            ctx.log.info(
                f"[agentcage] secret injection: "
                f"{[r['env'] for r in self._resolved_secrets]}"
            )
        self._audit_fh = self._open_log(AUDIT_LOG_PATH)
        self._capture_fh = self._open_log(CAPTURE_PATH)

    def _maybe_inject(self, flow: http.HTTPFlow) -> list[str]:
        """Substitute placeholders in request headers/body for matching hosts.

        Returns the list of env names that had at least one substitution
        performed; the audit entry surfaces this as `secrets_injected`.
        """
        host = flow.request.pretty_host.lower()
        injected: list[str] = []
        for rule in self._resolved_secrets:
            inject_to = rule["inject_to"]
            if inject_to and not any(
                host == d or host.endswith("." + d) for d in inject_to
            ):
                continue
            placeholder = rule["placeholder"]
            value = rule["value"]
            replaced_any = False
            # Headers
            for name, val in list(flow.request.headers.items()):
                if placeholder in val:
                    flow.request.headers[name] = val.replace(placeholder, value)
                    replaced_any = True
            # Body — only attempt if it's text-ish; binary bodies passed
            # through unchanged. Skip if the placeholder isn't there to
            # avoid round-tripping the body through .text.
            try:
                body_text = flow.request.get_text(strict=False)
            except (UnicodeDecodeError, ValueError):
                body_text = None
            if body_text and placeholder in body_text:
                flow.request.set_text(body_text.replace(placeholder, value))
                replaced_any = True
            if replaced_any:
                injected.append(rule["env"])
        return injected

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
            # Apply secret injection BEFORE the upstream request goes out.
            # Substitutions happen in place; we record the env names in
            # the audit entry so the operator can see what was swapped.
            injected = self._maybe_inject(flow)
            entry["decision"] = "allowed"
            entry["reason"] = "domain-allowlist"
            entry["secrets_injected"] = injected
            self._audit(entry)
            return

        ctx.log.info(f"[agentcage] BLOCK {flow.request.method} {host}")
        reason = "domain-allowlist: host not in cage allowlist"
        entry["decision"] = "blocked"
        entry["reason"] = reason
        self._audit(entry)
        # JSON body to match the container backend's 403 shape exactly
        # (src/agentcage/data/proxy/addon.py — `{"blocked": true, "reason":
        # ..., "host": ..., "by": "agentcage"}`). Same Content-Type
        # (application/json) so CLI tools that switch on it work the same
        # way across backends.
        flow.response = http.Response.make(
            403,
            json.dumps(
                {
                    "blocked": True,
                    "reason": reason,
                    "host": host,
                    "by": "agentcage",
                }
            ).encode(),
            {"Content-Type": "application/json"},
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
        # constructed locally — no point re-capturing it. Match on the
        # unique `"by": "agentcage"` marker in our JSON body so the
        # check stays robust against accidental Content-Type changes.
        if (
            flow.response.status_code == 403
            and flow.response.content
            and b'"by": "agentcage"' in flow.response.content
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
