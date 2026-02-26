"""Unit tests for agentcage.audit — parsing, filtering, summary."""

from __future__ import annotations

from agentcage.audit import (
    AuditEntry,
    AuditFilter,
    compute_summary,
    extract_audit_json,
    format_summary,
    format_table_header,
    format_table_row,
)


# ── sample data ──────────────────────────────────────────

_ALLOWED = {
    "ts": "2026-02-20T10:00:00+00:00",
    "direction": "outbound",
    "method": "GET",
    "host": "api.anthropic.com",
    "port": 443,
    "path": "/v1/messages",
    "url": "https://api.anthropic.com/v1/messages",
    "decision": "allowed",
    "reason": "",
    "inspectors": [],
}

_BLOCKED = {
    "ts": "2026-02-20T10:01:00+00:00",
    "direction": "outbound",
    "method": "POST",
    "host": "evil.com",
    "port": 443,
    "path": "/exfil",
    "url": "https://evil.com/exfil",
    "decision": "blocked",
    "reason": "domain not in allowlist",
    "inspectors": [
        {"name": "domain", "action": "block", "reason": "domain not in allowlist", "severity": "error"},
    ],
}

_FLAGGED = {
    "ts": "2026-02-20T10:02:00+00:00",
    "direction": "outbound",
    "method": "POST",
    "host": "api.anthropic.com",
    "port": 443,
    "path": "/v1/messages",
    "url": "https://api.anthropic.com/v1/messages",
    "decision": "flagged",
    "reason": "high entropy in body",
    "inspectors": [
        {"name": "entropy", "action": "flag", "reason": "body entropy 7.2 exceeds threshold 7.0", "severity": "warning"},
    ],
}

_SECRETS_BLOCKED = {
    "ts": "2026-02-20T10:03:00+00:00",
    "direction": "outbound",
    "method": "POST",
    "host": "httpbin.org",
    "port": 443,
    "path": "/post",
    "url": "https://httpbin.org/post",
    "decision": "blocked",
    "reason": "secret detected",
    "inspectors": [
        {"name": "secrets", "action": "block", "reason": "API key pattern detected", "severity": "critical"},
    ],
}

_DNS_BLOCKED = {
    "ts": "2026-02-20T10:06:00+00:00",
    "direction": "outbound",
    "method": "DNS",
    "host": "evil.com",
    "port": 53,
    "path": "",
    "url": "dns://evil.com",
    "decision": "blocked",
    "reason": "domain not in allowlist",
    "inspectors": [
        {"name": "dns", "action": "block", "reason": "domain not in allowlist", "severity": "warning"},
    ],
}

_DNS_ALLOWED = {
    "ts": "2026-02-20T10:06:01+00:00",
    "direction": "outbound",
    "method": "DNS",
    "host": "api.anthropic.com",
    "port": 53,
    "path": "",
    "url": "dns://api.anthropic.com",
    "decision": "allowed",
    "reason": "",
    "inspectors": [
        {"name": "dns", "action": "allow", "reason": "domain in allowlist", "severity": "info"},
    ],
}

_INBOUND = {
    "ts": "2026-02-20T10:04:00+00:00",
    "direction": "inbound",
    "method": "GET",
    "host": "10.89.0.2",
    "port": 8080,
    "path": "/api/health",
    "url": "http://10.89.0.2:8080/api/health",
    "decision": "allowed",
    "reason": "",
    "source": "10.0.0.5",
    "inspectors": [],
}

_INJECTED = {
    "ts": "2026-02-20T10:05:00+00:00",
    "direction": "outbound",
    "method": "POST",
    "host": "api.anthropic.com",
    "port": 443,
    "path": "/v1/messages",
    "url": "https://api.anthropic.com/v1/messages",
    "decision": "allowed",
    "reason": "",
    "secrets_injected": ["ANTHROPIC_API_KEY"],
    "inspectors": [],
}


# ── TestExtractAuditJson ─────────────────────────────────


class TestExtractAuditJson:
    def test_raw_json(self):
        import json
        line = json.dumps(_ALLOWED)
        result = extract_audit_json(line)
        assert result is not None
        assert result["decision"] == "allowed"

    def test_firecracker_prefix_warning(self):
        import json
        line = f"[proxy:warning] {json.dumps(_BLOCKED)}"
        result = extract_audit_json(line)
        assert result is not None
        assert result["decision"] == "blocked"

    def test_firecracker_prefix_info(self):
        import json
        line = f"[proxy:info] {json.dumps(_ALLOWED)}"
        result = extract_audit_json(line)
        assert result is not None
        assert result["decision"] == "allowed"

    def test_non_audit_json(self):
        """JSON without audit fields is ignored."""
        result = extract_audit_json('{"level": "info", "msg": "startup"}')
        assert result is None

    def test_non_json_line(self):
        result = extract_audit_json("Some random log line without JSON")
        assert result is None

    def test_empty_line(self):
        assert extract_audit_json("") is None
        assert extract_audit_json("   ") is None

    def test_invalid_json(self):
        result = extract_audit_json("{bad json")
        assert result is None

    def test_firecracker_dns_prefix_warning(self):
        import json
        line = f"[dns:warning] {json.dumps(_DNS_BLOCKED)}"
        result = extract_audit_json(line)
        assert result is not None
        assert result["decision"] == "blocked"
        assert result["method"] == "DNS"

    def test_firecracker_dns_prefix_info(self):
        import json
        line = f"[dns:info] {json.dumps(_DNS_ALLOWED)}"
        result = extract_audit_json(line)
        assert result is not None
        assert result["decision"] == "allowed"
        assert result["method"] == "DNS"

    def test_firecracker_non_audit(self):
        result = extract_audit_json("[proxy:debug] not json at all")
        assert result is None

    def test_whitespace_padding(self):
        import json
        line = f"  {json.dumps(_ALLOWED)}  "
        result = extract_audit_json(line)
        assert result is not None


# ── TestAuditFilter ──────────────────────────────────────


class TestAuditFilter:
    def _entry(self, d: dict) -> AuditEntry:
        return AuditEntry.from_dict(d)

    def test_empty_filter_matches_all(self):
        filt = AuditFilter()
        assert filt.matches(self._entry(_ALLOWED))
        assert filt.matches(self._entry(_BLOCKED))
        assert filt.matches(self._entry(_FLAGGED))

    def test_decision_filter(self):
        filt = AuditFilter(decisions=["blocked"])
        assert filt.matches(self._entry(_BLOCKED))
        assert not filt.matches(self._entry(_ALLOWED))
        assert not filt.matches(self._entry(_FLAGGED))

    def test_decision_filter_multiple(self):
        filt = AuditFilter(decisions=["blocked", "flagged"])
        assert filt.matches(self._entry(_BLOCKED))
        assert filt.matches(self._entry(_FLAGGED))
        assert not filt.matches(self._entry(_ALLOWED))

    def test_host_filter_substring(self):
        filt = AuditFilter(hosts=["anthropic"])
        assert filt.matches(self._entry(_ALLOWED))
        assert not filt.matches(self._entry(_BLOCKED))

    def test_host_filter_multiple(self):
        filt = AuditFilter(hosts=["anthropic", "evil"])
        assert filt.matches(self._entry(_ALLOWED))
        assert filt.matches(self._entry(_BLOCKED))

    def test_inspector_filter(self):
        filt = AuditFilter(inspectors=["domain"])
        assert filt.matches(self._entry(_BLOCKED))
        assert not filt.matches(self._entry(_ALLOWED))
        assert not filt.matches(self._entry(_FLAGGED))

    def test_inspector_filter_secrets(self):
        filt = AuditFilter(inspectors=["secrets"])
        assert filt.matches(self._entry(_SECRETS_BLOCKED))
        assert not filt.matches(self._entry(_BLOCKED))

    def test_severity_filter(self):
        filt = AuditFilter(min_severity="error")
        assert filt.matches(self._entry(_BLOCKED))  # domain inspector: error
        assert not filt.matches(self._entry(_FLAGGED))  # entropy: warning

    def test_severity_critical(self):
        filt = AuditFilter(min_severity="critical")
        assert filt.matches(self._entry(_SECRETS_BLOCKED))
        assert not filt.matches(self._entry(_BLOCKED))  # domain: error < critical

    def test_method_filter(self):
        filt = AuditFilter(methods=["POST"])
        assert filt.matches(self._entry(_BLOCKED))
        assert not filt.matches(self._entry(_ALLOWED))  # GET

    def test_method_filter_case_insensitive(self):
        filt = AuditFilter(methods=["post"])
        assert filt.matches(self._entry(_BLOCKED))

    def test_combined_filters(self):
        filt = AuditFilter(decisions=["blocked"], hosts=["evil"])
        assert filt.matches(self._entry(_BLOCKED))
        assert not filt.matches(self._entry(_ALLOWED))

    def test_combined_no_match(self):
        filt = AuditFilter(decisions=["blocked"], hosts=["anthropic"])
        # blocked + anthropic doesn't match any of our samples
        assert not filt.matches(self._entry(_BLOCKED))
        assert not filt.matches(self._entry(_ALLOWED))


# ── TestComputeSummary ───────────────────────────────────


class TestComputeSummary:
    def test_basic_summary(self):
        entries = [
            AuditEntry.from_dict(_ALLOWED),
            AuditEntry.from_dict(_BLOCKED),
            AuditEntry.from_dict(_FLAGGED),
        ]
        s = compute_summary(entries)
        assert s["total"] == 3
        assert s["decisions"]["allowed"] == 1
        assert s["decisions"]["blocked"] == 1
        assert s["decisions"]["flagged"] == 1
        assert "api.anthropic.com" in s["top_hosts"]
        assert "evil.com" in s["top_blocked_hosts"]
        assert "domain" in s["inspector_triggers"]
        assert "entropy" in s["inspector_triggers"]
        assert s["methods"]["GET"] == 1
        assert s["methods"]["POST"] == 2

    def test_empty_summary(self):
        s = compute_summary([])
        assert s["total"] == 0
        assert s["decisions"] == {}
        assert s["top_hosts"] == {}
        assert s["top_blocked_hosts"] == {}


# ── TestFormatting ───────────────────────────────────────


class TestFormatting:
    def test_table_header(self):
        h = format_table_header()
        assert "TIMESTAMP" in h
        assert "DIRECTION" in h
        assert "METHOD" in h
        assert "HOST" in h
        assert "PORT" in h
        assert "PATH" in h
        assert "DECISION" in h

    def test_table_row_no_color(self):
        entry = AuditEntry.from_dict(_BLOCKED)
        row = format_table_row(entry, color=False)
        assert "blocked" in row
        assert "evil.com" in row
        assert "POST" in row
        assert "443" in row
        assert "/exfil" in row

    def test_table_row_direction_outbound(self):
        entry = AuditEntry.from_dict(_ALLOWED)
        row = format_table_row(entry, color=False)
        assert "OUTBOUND" in row

    def test_table_row_direction_inbound(self):
        entry = AuditEntry.from_dict(_INBOUND)
        row = format_table_row(entry, color=False)
        assert "INBOUND" in row

    def test_table_row_direction_missing(self):
        """Entry without direction field shows empty string, no crash."""
        d = {**_ALLOWED}
        del d["direction"]
        entry = AuditEntry.from_dict(d)
        assert entry.direction == ""
        row = format_table_row(entry, color=False)
        assert "GET" in row

    def test_table_row_builds_reason_from_inspectors(self):
        entry = AuditEntry.from_dict({**_BLOCKED, "reason": ""})
        row = format_table_row(entry, color=False)
        assert "domain" in row

    def test_table_row_shows_source(self):
        entry = AuditEntry.from_dict(_INBOUND)
        row = format_table_row(entry, color=False)
        assert "source 10.0.0.5" in row

    def test_table_row_shows_injected_secrets(self):
        entry = AuditEntry.from_dict(_INJECTED)
        row = format_table_row(entry, color=False)
        assert "[injected: ANTHROPIC_API_KEY]" in row

    def test_table_row_shows_redacted_secrets(self):
        d = {**_ALLOWED, "secrets_redacted": ["KEY1", "KEY2"]}
        entry = AuditEntry.from_dict(d)
        row = format_table_row(entry, color=False)
        assert "[redacted: KEY1, KEY2]" in row

    def test_table_row_shows_port_and_path(self):
        entry = AuditEntry.from_dict(_INBOUND)
        row = format_table_row(entry, color=False)
        assert "8080" in row
        assert "/api/health" in row

    def test_format_summary(self):
        entries = [AuditEntry.from_dict(_ALLOWED), AuditEntry.from_dict(_BLOCKED)]
        s = compute_summary(entries)
        text = format_summary(s)
        assert "Total entries: 2" in text
        assert "blocked" in text
        assert "allowed" in text

    def test_format_summary_directions(self):
        entries = [
            AuditEntry.from_dict(_ALLOWED),
            AuditEntry.from_dict(_BLOCKED),
            AuditEntry.from_dict(_INBOUND),
        ]
        s = compute_summary(entries)
        text = format_summary(s)
        assert "Directions:" in text
        assert "outbound" in text
        assert "inbound" in text


# ── TestDirection ─────────────────────────────────────────


class TestDirection:
    def _entry(self, d: dict) -> AuditEntry:
        return AuditEntry.from_dict(d)

    def test_from_dict_populates_direction(self):
        entry = self._entry(_ALLOWED)
        assert entry.direction == "outbound"

    def test_from_dict_inbound(self):
        entry = self._entry(_INBOUND)
        assert entry.direction == "inbound"

    def test_from_dict_missing_direction(self):
        d = {**_ALLOWED}
        del d["direction"]
        entry = self._entry(d)
        assert entry.direction == ""

    def test_filter_direction_inbound(self):
        filt = AuditFilter(directions=["inbound"])
        assert filt.matches(self._entry(_INBOUND))
        assert not filt.matches(self._entry(_ALLOWED))

    def test_filter_direction_outbound(self):
        filt = AuditFilter(directions=["outbound"])
        assert filt.matches(self._entry(_ALLOWED))
        assert filt.matches(self._entry(_BLOCKED))
        assert not filt.matches(self._entry(_INBOUND))

    def test_filter_direction_both(self):
        filt = AuditFilter(directions=["inbound", "outbound"])
        assert filt.matches(self._entry(_ALLOWED))
        assert filt.matches(self._entry(_INBOUND))

    def test_filter_direction_empty_allows_all(self):
        filt = AuditFilter(directions=[])
        assert filt.matches(self._entry(_ALLOWED))
        assert filt.matches(self._entry(_INBOUND))

    def test_filter_direction_combined_with_decision(self):
        filt = AuditFilter(decisions=["allowed"], directions=["inbound"])
        assert filt.matches(self._entry(_INBOUND))
        assert not filt.matches(self._entry(_ALLOWED))  # outbound

    def test_summary_directions(self):
        entries = [
            self._entry(_ALLOWED),
            self._entry(_BLOCKED),
            self._entry(_INBOUND),
        ]
        s = compute_summary(entries)
        assert s["directions"]["outbound"] == 2
        assert s["directions"]["inbound"] == 1

    def test_summary_no_direction_field(self):
        """Entries without direction don't appear in directions counter."""
        d = {**_ALLOWED}
        del d["direction"]
        entries = [self._entry(d)]
        s = compute_summary(entries)
        assert s["directions"] == {}


# ── TestNewFields ────────────────────────────────────────


class TestNewFields:
    def _entry(self, d: dict) -> AuditEntry:
        return AuditEntry.from_dict(d)

    def test_from_dict_populates_port_and_path(self):
        entry = self._entry(_ALLOWED)
        assert entry.port == 443
        assert entry.path == "/v1/messages"

    def test_from_dict_populates_source(self):
        entry = self._entry(_INBOUND)
        assert entry.source == "10.0.0.5"

    def test_from_dict_populates_secrets_injected(self):
        entry = self._entry(_INJECTED)
        assert entry.secrets_injected == ["ANTHROPIC_API_KEY"]

    def test_from_dict_populates_secrets_redacted(self):
        d = {**_ALLOWED, "secrets_redacted": ["KEY1"]}
        entry = self._entry(d)
        assert entry.secrets_redacted == ["KEY1"]

    def test_backwards_compat_missing_fields(self):
        """Old entries without new fields get sensible defaults."""
        d = {
            "ts": "2026-02-20T10:00:00+00:00",
            "direction": "outbound",
            "method": "GET",
            "host": "example.com",
            "url": "https://example.com/",
            "decision": "allowed",
            "reason": "",
        }
        entry = self._entry(d)
        assert entry.port == 0
        assert entry.path == ""
        assert entry.source == ""
        assert entry.secrets_injected == []
        assert entry.secrets_redacted == []


# ── TestDnsAudit ─────────────────────────────────────────


class TestDnsAudit:
    def _entry(self, d: dict) -> AuditEntry:
        return AuditEntry.from_dict(d)

    def test_dns_blocked_entry_parsed(self):
        import json
        line = json.dumps(_DNS_BLOCKED)
        result = extract_audit_json(line)
        assert result is not None
        entry = AuditEntry.from_dict(result)
        assert entry.method == "DNS"
        assert entry.host == "evil.com"
        assert entry.port == 53
        assert entry.decision == "blocked"
        assert entry.url == "dns://evil.com"

    def test_dns_allowed_entry_parsed(self):
        import json
        line = json.dumps(_DNS_ALLOWED)
        result = extract_audit_json(line)
        assert result is not None
        entry = AuditEntry.from_dict(result)
        assert entry.method == "DNS"
        assert entry.decision == "allowed"

    def test_method_filter_dns(self):
        filt = AuditFilter(methods=["DNS"])
        assert filt.matches(self._entry(_DNS_BLOCKED))
        assert filt.matches(self._entry(_DNS_ALLOWED))
        assert not filt.matches(self._entry(_ALLOWED))  # GET

    def test_method_filter_dns_case_insensitive(self):
        filt = AuditFilter(methods=["dns"])
        assert filt.matches(self._entry(_DNS_BLOCKED))

    def test_summary_includes_dns_method(self):
        entries = [
            self._entry(_ALLOWED),
            self._entry(_DNS_BLOCKED),
            self._entry(_DNS_ALLOWED),
        ]
        s = compute_summary(entries)
        assert s["methods"]["DNS"] == 2
        assert s["methods"]["GET"] == 1
        assert s["decisions"]["blocked"] == 1
        assert "evil.com" in s["top_blocked_hosts"]
        assert "dns" in s["inspector_triggers"]

    def test_dns_blocked_table_row(self):
        entry = self._entry(_DNS_BLOCKED)
        row = format_table_row(entry, color=False)
        assert "DNS" in row
        assert "evil.com" in row
        assert "blocked" in row
        assert "53" in row
