"""Audit log parsing, filtering, and formatting.

Pure-function module — no subprocess/IO, independently testable.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AuditEntry:
    """Parsed audit log entry."""

    ts: str
    direction: str
    method: str
    host: str
    url: str
    decision: str
    reason: str
    inspectors: list[dict]
    raw: dict
    port: int
    path: str
    source: str
    secrets_injected: list[str]
    secrets_redacted: list[str]

    @classmethod
    def from_dict(cls, d: dict) -> AuditEntry:
        return cls(
            ts=d.get("ts", ""),
            direction=d.get("direction", ""),
            method=d.get("method", ""),
            host=d.get("host", ""),
            url=d.get("url", ""),
            decision=d.get("decision", ""),
            reason=d.get("reason", ""),
            inspectors=d.get("inspectors", []),
            raw=d,
            port=d.get("port", 0),
            path=d.get("path", ""),
            source=d.get("source", ""),
            secrets_injected=d.get("secrets_injected", []),
            secrets_redacted=d.get("secrets_redacted", []),
        )


@dataclass
class AuditFilter:
    """Filter criteria for audit entries."""

    decisions: list[str] = field(default_factory=list)
    directions: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    inspectors: list[str] = field(default_factory=list)
    min_severity: str | None = None
    methods: list[str] = field(default_factory=list)

    def matches(self, entry: AuditEntry) -> bool:
        if self.decisions and entry.decision not in self.decisions:
            return False
        if self.directions and entry.direction not in self.directions:
            return False
        if self.hosts and not any(h in entry.host for h in self.hosts):
            return False
        if self.inspectors:
            entry_inspectors = {i.get("name", "") for i in entry.inspectors}
            if not any(name in entry_inspectors for name in self.inspectors):
                return False
        if self.min_severity:
            if not self._meets_severity(entry):
                return False
        if self.methods and entry.method.upper() not in [m.upper() for m in self.methods]:
            return False
        return True

    def _meets_severity(self, entry: AuditEntry) -> bool:
        order = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}
        min_ord = order.get(self.min_severity, 0)
        if min_ord == 0:
            return True
        for insp in entry.inspectors:
            sev = insp.get("severity", "info")
            if order.get(sev, 0) >= min_ord:
                return True
        # No inspector met the threshold — only pass if no severity filter needed
        return not entry.inspectors and min_ord == 0


# Regex matching VM-mode log prefix: [proxy:warning] or [dns:warning] {json...}
_VM_PREFIX_RE = re.compile(r"^\[(?:proxy|dns):(?:debug|info|warning|error|critical)\]\s*(.*)$")


def extract_audit_json(line: str) -> dict | None:
    """Extract an audit JSON dict from a raw journalctl line.

    Handles both container mode (raw JSON) and VM mode
    (``[proxy:level] {json}`` prefix).  Returns None for non-audit lines.
    """
    line = line.strip()
    if not line:
        return None

    # Try VM-mode prefix first
    m = _VM_PREFIX_RE.match(line)
    if m:
        line = m.group(1).strip()

    # Must look like JSON
    if not line.startswith("{"):
        return None

    try:
        d = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    # Must have the audit entry signature
    if "decision" not in d or "method" not in d:
        return None

    return d


def compute_summary(entries: list[AuditEntry]) -> dict:
    """Aggregate statistics from audit entries."""
    decisions: Counter = Counter()
    directions: Counter = Counter()
    hosts: Counter = Counter()
    blocked_hosts: Counter = Counter()
    inspector_triggers: Counter = Counter()
    methods: Counter = Counter()

    for e in entries:
        decisions[e.decision] += 1
        if e.direction:
            directions[e.direction] += 1
        hosts[e.host] += 1
        methods[e.method] += 1
        if e.decision == "blocked":
            blocked_hosts[e.host] += 1
        for insp in e.inspectors:
            inspector_triggers[insp.get("name", "unknown")] += 1

    return {
        "total": len(entries),
        "decisions": dict(decisions),
        "directions": dict(directions),
        "top_hosts": dict(hosts.most_common(10)),
        "top_blocked_hosts": dict(blocked_hosts.most_common(10)),
        "inspector_triggers": dict(inspector_triggers.most_common(10)),
        "methods": dict(methods),
    }


_DECISION_COLORS = {
    "blocked": "red",
    "flagged": "yellow",
    "allowed": "green",
}


def format_table_header() -> str:
    """Return column header for table output."""
    return (
        f"{'TIMESTAMP':<26} {'DIRECTION':<10} {'METHOD':<8} "
        f"{'HOST':<25} {'PORT':<5} {'PATH':<20} "
        f"{'DECISION':<10} REASON"
    )


def format_table_row(entry: AuditEntry, *, color: bool = True) -> str:
    """Format a single audit entry as a table row."""
    ts = entry.ts[:25] if len(entry.ts) > 25 else entry.ts
    dir_label = {"inbound": "INBOUND", "outbound": "OUTBOUND"}.get(entry.direction, "")
    method = entry.method[:7]
    host = entry.host[:24] if len(entry.host) > 24 else entry.host
    port = str(entry.port) if entry.port else ""
    path = entry.path[:19] if len(entry.path) > 19 else entry.path
    decision = entry.decision
    reason = entry.reason

    if not reason and entry.inspectors:
        # Build reason from inspector results
        parts = []
        for insp in entry.inspectors:
            name = insp.get("name", "")
            r = insp.get("reason", "")
            if name and r:
                parts.append(f"{name}: {r}")
            elif r:
                parts.append(r)
        reason = "; ".join(parts)

    # Append source IP for inbound requests
    if entry.source:
        reason = f"source {entry.source}; {reason}" if reason else f"source {entry.source}"

    # Append secret operation indicators
    if entry.secrets_injected:
        tag = f"[injected: {', '.join(entry.secrets_injected)}]"
        reason = f"{reason}; {tag}" if reason else tag
    if entry.secrets_redacted:
        tag = f"[redacted: {', '.join(entry.secrets_redacted)}]"
        reason = f"{reason}; {tag}" if reason else tag

    row = (
        f"{ts:<26} {dir_label:<10} {method:<8} "
        f"{host:<25} {port:<5} {path:<20} "
        f"{decision:<10} {reason}"
    )

    if color and decision in _DECISION_COLORS:
        from click import style
        # Color just the decision column
        colored_decision = style(f"{decision:<10}", fg=_DECISION_COLORS[decision])
        row = (
            f"{ts:<26} {dir_label:<4} {method:<8} "
            f"{host:<25} {port:<5} {path:<20} "
            f"{colored_decision} {reason}"
        )

    return row


def format_summary(summary: dict) -> str:
    """Format summary statistics as a human-readable report."""
    lines = []
    total = summary.get("total", 0)
    lines.append(f"Total entries: {total}")
    lines.append("")

    # Decisions
    decisions = summary.get("decisions", {})
    lines.append("Decisions:")
    for d in ("blocked", "flagged", "allowed"):
        count = decisions.get(d, 0)
        pct = f"({count * 100 // total}%)" if total else ""
        lines.append(f"  {d:<10} {count:>6}  {pct}")
    lines.append("")

    # Directions
    directions = summary.get("directions", {})
    if directions:
        lines.append("Directions:")
        for d in ("outbound", "inbound"):
            count = directions.get(d, 0)
            if count:
                pct = f"({count * 100 // total}%)" if total else ""
                lines.append(f"  {d:<10} {count:>6}  {pct}")
        lines.append("")

    # Top hosts
    top_hosts = summary.get("top_hosts", {})
    if top_hosts:
        lines.append("Top hosts:")
        for host, count in top_hosts.items():
            lines.append(f"  {host:<40} {count:>6}")
        lines.append("")

    # Top blocked hosts
    top_blocked = summary.get("top_blocked_hosts", {})
    if top_blocked:
        lines.append("Top blocked hosts:")
        for host, count in top_blocked.items():
            lines.append(f"  {host:<40} {count:>6}")
        lines.append("")

    # Inspector triggers
    triggers = summary.get("inspector_triggers", {})
    if triggers:
        lines.append("Inspector triggers:")
        for name, count in triggers.items():
            lines.append(f"  {name:<30} {count:>6}")
        lines.append("")

    # Methods
    methods = summary.get("methods", {})
    if methods:
        lines.append("Methods:")
        for method, count in methods.items():
            lines.append(f"  {method:<10} {count:>6}")

    return "\n".join(lines)
