"""Tests for ``DomainInspector`` runtime grant behavior (Policy API M3).

These cover the in-memory overlay added by the Policy API request endpoint:
``grant`` / ``revoke`` / ``is_granted`` / ``drop_expired`` / ``snapshot``,
the replay-safety of ``configure`` (hot-reload must not wipe live grants),
subdomain matching of granted domains, and that grants are no-ops in
blocklist mode. Baseline allow/block behavior is regression-tested too.

Style mirrors ``tests/test_inspectors.py``: a tiny module-level ``_ctx``
helper builds an ``InspectionContext`` directly. We import the inspector
from the same path the proxy package uses (``inspectors.domain``), added to
``pythonpath`` by ``pyproject.toml``.
"""

import pytest

from inspectors.base import InspectionContext
from inspectors.domain import DomainInspector


# ── Helper ───────────────────────────────────────────────


def _ctx(host, url=None):
    return InspectionContext(
        url=url or f"https://{host}/",
        host=host,
        method="GET",
        headers=[],
        content_type="application/json",
        body_bytes=None,
        body_text=None,
        body_size=0,
        body_entropy=None,
    )


# ── grant / inspect / revoke ─────────────────────────────


class TestGrantInspect:
    def test_grant_allows_unlisted_domain(self):
        d = DomainInspector()
        d.configure({"mode": "allowlist", "list": ["a.com"]})
        assert d.inspect_request(_ctx(host="x.com")) is not None  # blocked
        d.grant("x.com")
        assert d.inspect_request(_ctx(host="x.com")) is None  # now allowed

    def test_is_granted_true_after_grant(self):
        d = DomainInspector()
        d.configure({"mode": "allowlist", "list": ["a.com"]})
        d.grant("x.com")
        assert d.is_granted("x.com") is True
        assert d.is_granted("y.com") is False

    def test_revoke_returns_true_then_blocks(self):
        d = DomainInspector()
        d.configure({"mode": "allowlist", "list": ["a.com"]})
        d.grant("x.com")
        assert d.revoke("x.com") is True
        assert d.revoke("x.com") is False  # already gone
        assert d.is_granted("x.com") is False
        assert d.inspect_request(_ctx(host="x.com")) is not None  # blocked again


# ── subdomain matching for granted domains ───────────────


class TestSubdomainMatch:
    def test_grant_matches_subdomains(self):
        d = DomainInspector()
        d.configure({"mode": "allowlist", "list": ["a.com"]})
        d.grant("example.com")
        assert d.inspect_request(_ctx(host="api.example.com")) is None
        assert d.inspect_request(_ctx(host="sub.api.example.com")) is None


# ── replay-safe configure ─────────────────────────────────


class TestReplaySafe:
    def test_configure_does_not_clear_grants(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        d.grant("x.com")
        assert d.is_granted("x.com") is True
        # Hot-reload: baseline grows, grant survives.
        d.configure({"allow": ["a.com", "b.com"]})
        assert d.is_granted("x.com") is True
        assert d.inspect_request(_ctx(host="x.com")) is None
        # new baseline entry also works without a grant
        assert d.inspect_request(_ctx(host="b.com")) is None


# ── snapshot ─────────────────────────────────────────────


class TestSnapshot:
    def test_snapshot_shape(self):
        d = DomainInspector()
        d.configure({"allow": ["b.com", "a.com"]})
        d.grant("z.com")
        snap = d.snapshot()
        assert snap["mode"] == "allowlist"
        assert snap["baseline"] == ["a.com", "b.com"]  # sorted
        assert isinstance(snap["granted"], list)
        assert len(snap["granted"]) == 1
        assert snap["granted"][0]["domain"] == "z.com"

    def test_snapshot_empty_when_no_grants(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        snap = d.snapshot()
        assert snap["granted"] == []
        assert snap["baseline"] == ["a.com"]


# ── drop_expired ─────────────────────────────────────────


class TestDropExpired:
    def test_drops_only_expired(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        now = "2026-06-01T12:00:00Z"
        d.grant("past.com", expires_at="2026-06-01T11:00:00Z")
        d.grant("future.com", expires_at="2026-06-01T13:00:00Z")
        d.grant("noexp.com")  # no expiry
        expired = d.drop_expired(now_iso=now)
        assert expired == ["past.com"]
        assert d.is_granted("past.com") is False
        assert d.is_granted("future.com") is True
        assert d.is_granted("noexp.com") is True


class TestGrantTtlEnforcedAtL7:
    """A TTL'd grant must block at L7 the moment its expires_at passes —
    NOT keep passing for up to the sweeper's 30s poll. Regression guard
    for the 5th-review finding: ``_matched_expired`` consulted only the
    baseline ``domains.expires`` map, never the grant entry's own
    ``expires_at``."""

    def test_expired_grant_blocks_at_l7_immediately(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        # A grant whose expires_at is already past. Do NOT call
        # drop_expired — the point is that L7 blocks even before the
        # sweeper sees it.
        d.grant("past.com", expires_at="2000-01-01T00:00:00Z")
        result = d.inspect_request(_ctx(host="past.com"))
        assert result is not None
        assert result.action == "block"
        assert "expired" in result.reason

    def test_unexpired_grant_still_passes_l7(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        d.grant("future.com", expires_at="2999-01-01T00:00:00Z")
        assert d.inspect_request(_ctx(host="future.com")) is None

    def test_permanent_grant_has_no_l7_expiry(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        d.grant("perm.com")  # no expires_at
        assert d.inspect_request(_ctx(host="perm.com")) is None

    def test_baseline_expires_still_enforced_alongside_grants(self):
        # The baseline path (domain add --expires-in) must keep working:
        # a domain in BOTH the baseline-with-expiry and granted maps takes
        # the baseline expiry (the first matching suffix wins).
        d = DomainInspector()
        d.configure({"allow": ["a.com"],
                     "expires": {"a.com": "2000-01-01T00:00:00Z"}})
        result = d.inspect_request(_ctx(host="a.com"))
        assert result is not None
        assert result.action == "block"
        assert "expired" in result.reason
    def test_drop_expired_empty_now_keeps_all(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        d.grant("x.com", expires_at="2026-06-01T11:00:00Z")
        # With a real (later) now, the past grant drops.
        expired = d.drop_expired(now_iso="2026-06-02T00:00:00Z")
        assert expired == ["x.com"]


# ── blocklist mode: grants are no-ops ─────────────────────


class TestBlocklistGrants:
    def test_grant_noop_in_blocklist(self):
        d = DomainInspector()
        d.configure({"block": ["evil.com"]})
        d.grant("x.com")
        assert d.is_granted("x.com") is False
        # everything not blocked is already reachable; grant added nothing
        assert d.inspect_request(_ctx(host="x.com")) is None

    def test_grant_noop_then_allowlist_still_clean(self):
        """Switching to allowlist mode after a no-op grant in blocklist
        does not resurrect a phantom grant."""
        d = DomainInspector()
        d.configure({"block": ["evil.com"]})
        d.grant("x.com")
        d.configure({"allow": ["a.com"]})
        assert d.is_granted("x.com") is False
        assert d.inspect_request(_ctx(host="x.com")) is not None


# ── baseline regression ───────────────────────────────────


class TestBaselineRegression:
    def test_baseline_domain_allowed_without_grant(self):
        d = DomainInspector()
        d.configure({"allow": ["api.anthropic.com"]})
        assert d.inspect_request(_ctx(host="api.anthropic.com")) is None

    def test_neither_baseline_nor_grant_blocked(self):
        d = DomainInspector()
        d.configure({"allow": ["api.anthropic.com"]})
        r = d.inspect_request(_ctx(host="evil.com"))
        assert r is not None
        assert r.action == "block"
        assert "evil.com" in r.reason

    def test_domain_set_property(self):
        d = DomainInspector()
        d.configure({"allow": ["a.com"]})
        d.grant("x.com")
        ds = d.domain_set
        assert "a.com" in ds
        assert "x.com" in ds
        # blocklist mode returns baseline only
        d2 = DomainInspector()
        d2.configure({"block": ["evil.com"]})
        d2.grant("x.com")
        assert "x.com" not in d2.domain_set
