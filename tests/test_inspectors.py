"""Tests for built-in inspectors."""

import os
import pytest

from inspectors.base import InspectionContext, InspectionResult, Inspector
from inspectors.domain import DomainInspector
from inspectors.secrets import SecretsInspector
from inspectors.body_size import BodySizeInspector
from inspectors.entropy import EntropyInspector
from inspectors.content_type import ContentTypeInspector


# ── Helpers ──────────────────────────────────────────────


def _ctx(
    url="https://api.anthropic.com/v1/messages",
    host="api.anthropic.com",
    method="POST",
    headers=None,
    content_type="application/json",
    body_text=None,
    body_bytes=None,
    body_entropy=None,
):
    if body_text and body_bytes is None:
        body_bytes = body_text.encode()
    return InspectionContext(
        url=url,
        host=host,
        method=method,
        headers=headers or [],
        content_type=content_type,
        body_bytes=body_bytes,
        body_text=body_text,
        body_size=len(body_bytes) if body_bytes else 0,
        body_entropy=body_entropy,
    )


# ── DomainInspector ──────────────────────────────────────


class TestDomainInspector:
    def test_allowlist_allows_listed_domain(self):
        d = DomainInspector()
        d.configure({"mode": "allowlist", "list": ["api.anthropic.com"]})
        assert d.inspect_request(_ctx(host="api.anthropic.com")) is None

    def test_allowlist_blocks_unlisted_domain(self):
        d = DomainInspector()
        d.configure({"mode": "allowlist", "list": ["api.anthropic.com"]})
        r = d.inspect_request(_ctx(host="evil.com"))
        assert r is not None
        assert r.action == "block"
        assert "evil.com" in r.reason

    def test_allowlist_matches_subdomains(self):
        d = DomainInspector()
        d.configure({"mode": "allowlist", "list": ["anthropic.com"]})
        assert d.inspect_request(_ctx(host="api.anthropic.com")) is None

    def test_blocklist_blocks_listed_domain(self):
        d = DomainInspector()
        d.configure({"mode": "blocklist", "list": ["evil.com"]})
        r = d.inspect_request(_ctx(host="evil.com"))
        assert r is not None
        assert r.action == "block"

    def test_blocklist_allows_unlisted_domain(self):
        d = DomainInspector()
        d.configure({"mode": "blocklist", "list": ["evil.com"]})
        assert d.inspect_request(_ctx(host="api.anthropic.com")) is None

    def test_no_mode_defaults_to_deny(self):
        # Omitted/empty `domains:` section → fail closed (default-deny),
        # not fail open. Regression guard for the L7 allowlist fail-open.
        d = DomainInspector()
        d.configure({})
        r = d.inspect_request(_ctx(host="anything.example.com"))
        assert r is not None
        assert r.action == "block"
        assert "anything.example.com" in r.reason

    def test_empty_mode_string_defaults_to_deny(self):
        d = DomainInspector()
        d.configure({"mode": ""})
        r = d.inspect_request(_ctx(host="anything.example.com"))
        assert r is not None
        assert r.action == "block"

    def test_unknown_mode_defaults_to_deny(self):
        d = DomainInspector()
        d.configure({"mode": "bogus"})
        r = d.inspect_request(_ctx(host="anything.example.com"))
        assert r is not None
        assert r.action == "block"

    def test_empty_allowlist_blocks_everything(self):
        d = DomainInspector()
        d.configure({"allow": []})
        r = d.inspect_request(_ctx(host="anything.example.com"))
        assert r is not None
        assert r.action == "block"


class TestDomainExpirySemantics:
    """Fix 2 (medium): ``_matched_expired`` suffix-shadowing must not block
    legitimately-allowed traffic.

    New semantics: a host is expiry-blocked only if NO matching suffix
    would allow it if expired entries were removed. If ANY matching suffix
    is valid (in the allow set with no expires_at, or with a future
    expires_at), the host is allowed. Only if EVERY matching suffix is
    expired do we return the longest expired suffix for the error message.

    Expiry is supposed to REMOVE an allow entry, not introduce a deny rule.
    """

    def test_permanent_specific_unblocked_by_expired_broader(self):
        """allow=[api.example.com (permanent), example.com (expired)] →
        api.example.com is NOT blocked (the most-specific permanent entry
        allows it)."""
        d = DomainInspector()
        d.configure({
            "allow": ["api.example.com", "example.com"],
            "expires": {"example.com": "2000-01-01T00:00:00+00:00"},
        })
        assert d._matched_expired("api.example.com") is None
        assert d.inspect_request(_ctx(host="api.example.com")) is None

    def test_permanent_broader_unblocks_expired_specific(self):
        """allow=[example.com (permanent), sub.example.com (expired)] →
        sub.example.com is NOT blocked (matches via the broader permanent
        entry)."""
        d = DomainInspector()
        d.configure({
            "allow": ["example.com", "sub.example.com"],
            "expires": {"sub.example.com": "2000-01-01T00:00:00+00:00"},
        })
        assert d._matched_expired("sub.example.com") is None
        assert d.inspect_request(_ctx(host="sub.example.com")) is None

    def test_only_expired_entry_is_blocked(self):
        """allow=[example.com (expired)] → example.com IS blocked, with the
        error message naming example.com."""
        d = DomainInspector()
        d.configure({
            "allow": ["example.com"],
            "expires": {"example.com": "2000-01-01T00:00:00+00:00"},
        })
        assert d._matched_expired("example.com") == "example.com"
        r = d.inspect_request(_ctx(host="example.com"))
        assert r is not None
        assert r.action == "block"
        assert "example.com" in r.reason
        assert "expired" in r.reason

    def test_future_dated_expiry_not_blocked(self):
        """allow=[example.com (future expiry)] → not blocked."""
        d = DomainInspector()
        d.configure({
            "allow": ["example.com"],
            "expires": {"example.com": "2999-01-01T00:00:00+00:00"},
        })
        assert d._matched_expired("example.com") is None
        assert d.inspect_request(_ctx(host="example.com")) is None

    def test_subdomain_of_only_expired_is_blocked(self):
        """allow=[example.com (expired)] → sub.example.com is blocked (the
        only matching suffix is the expired example.com)."""
        d = DomainInspector()
        d.configure({
            "allow": ["example.com"],
            "expires": {"example.com": "2000-01-01T00:00:00+00:00"},
        })
        assert d._matched_expired("sub.example.com") == "example.com"
        r = d.inspect_request(_ctx(host="sub.example.com"))
        assert r is not None
        assert r.action == "block"
        assert "example.com" in r.reason

    def test_expired_grant_shadowed_by_permanent_baseline(self):
        """A permanent baseline entry for example.com plus an expired grant
        for sub.example.com → sub.example.com is allowed via the broader
        permanent baseline."""
        d = DomainInspector()
        d.configure({"allow": ["example.com"]})
        d.grant("sub.example.com", expires_at="2000-01-01T00:00:00+00:00")
        assert d._matched_expired("sub.example.com") is None
        assert d.inspect_request(_ctx(host="sub.example.com")) is None

    def test_only_expired_grant_is_blocked(self):
        """An expired grant with no broader permanent entry → blocked."""
        d = DomainInspector()
        d.configure({"allow": ["unrelated.com"]})
        d.grant("past.com", expires_at="2000-01-01T00:00:00+00:00")
        assert d._matched_expired("past.com") == "past.com"
        r = d.inspect_request(_ctx(host="past.com"))
        assert r is not None
        assert r.action == "block"
        assert "past.com" in r.reason


class TestExpiryOffsetNormalization:
    """Fix 2 (nit): ``_matched_expired`` compares expiry timestamps by PARSED
    timezone-aware datetimes, not a lexical string compare. Both programmatic
    producers (cli ``_expires_at_from_now`` and the PolicyApi ``_expires_at``
    grant path) emit ``datetime.now(timezone.utc).isoformat()`` (UTC,
    ``+00:00``), but operator-typed values in cage.yaml's ``domains.expires``
    are kept as raw ISO-8601 strings with NO offset normalization (config.py
    validates them loosely), so a non-UTC offset is representable. A lexical
    compare would order the same UTC instant wrong and block legitimate
    traffic; parsing with ``datetime.fromisoformat`` normalizes the offset.
    Malformed / tz-naive values fail open (no expiry) by design.

    These pin ``now`` via the module-level ``datetime`` so the offset cases are
    deterministic; the two distinguishing cases below are ones where a lexical
    compare would give the WRONG answer (blocked when allowed, or allowed
    when expired).
    """

    def _pin_now(self, monkeypatch, now_iso):
        import inspectors.domain as _dom
        from datetime import datetime as _real
        now_dt = _real.fromisoformat(now_iso)

        class _Clock:
            # Stand-in for the ``datetime`` class: ``now()`` returns the
            # pinned aware datetime; ``fromisoformat`` delegates to the real
            # one (so offsets are normalized on parse).
            now = staticmethod(lambda tz=None: now_dt)
            fromisoformat = staticmethod(_real.fromisoformat)

        monkeypatch.setattr(_dom, "datetime", _Clock)

    def test_positive_offset_past_is_blocked(self, monkeypatch):
        """A ``+05:00`` expiry at the SAME wall-clock as ``now`` is 5h in the
        PAST (UTC) → must be blocked. A lexical compare of ``+05:00`` vs
        ``+00:00`` would order it AFTER now (``5`` > ``0``) and wrongly ALLOW
        — this is the distinguishing case the parse fixes."""
        self._pin_now(monkeypatch, "2026-08-30T14:20:00+00:00")
        d = DomainInspector()
        d.configure({
            "allow": ["example.com"],
            "expires": {"example.com": "2026-08-30T14:20:00+05:00"},
        })
        assert d._matched_expired("example.com") == "example.com"
        r = d.inspect_request(_ctx(host="example.com"))
        assert r is not None and r.action == "block"

    def test_negative_offset_future_is_allowed(self, monkeypatch):
        """A ``-05:00`` expiry whose wall-clock is 1m BEFORE ``now`` is ~5h in
        the FUTURE (UTC) → must be allowed. A lexical compare would order the
        earlier wall-clock minute as past and wrongly BLOCK — this is the
        distinguishing case the parse fixes."""
        self._pin_now(monkeypatch, "2026-08-30T14:20:00+00:00")
        d = DomainInspector()
        d.configure({
            "allow": ["example.com"],
            "expires": {"example.com": "2026-08-30T14:19:00-05:00"},
        })
        assert d._matched_expired("example.com") is None
        assert d.inspect_request(_ctx(host="example.com")) is None

    def test_same_instant_different_offsets_both_expired(self, monkeypatch):
        """Two expiries for the SAME UTC instant expressed with different
        offsets (``+00:00`` and ``-05:00``) are treated identically. A lexical
        compare would order them differently relative to ``now``; parsing
        normalizes the offset so both are expired here."""
        self._pin_now(monkeypatch, "2026-08-30T14:20:01+00:00")
        d = DomainInspector()
        d.configure({
            "allow": ["a.com", "b.com"],
            "expires": {
                "a.com": "2026-08-30T14:20:00+00:00",
                "b.com": "2026-08-30T09:20:00-05:00",  # same UTC instant
            },
        })
        assert d._matched_expired("a.com") == "a.com"
        assert d._matched_expired("b.com") == "b.com"

    def test_malformed_expires_at_fails_open(self, monkeypatch):
        """An unparseable ``expires_at`` is treated as no expiry (fail-open),
        never fail-closed on a malformed value."""
        d = DomainInspector()
        d.configure({
            "allow": ["example.com"],
            "expires": {"example.com": "not-a-date"},
        })
        assert d._matched_expired("example.com") is None
        assert d.inspect_request(_ctx(host="example.com")) is None

    def test_tznaive_expires_at_fails_open(self, monkeypatch):
        """A tz-naive ``expires_at`` (no offset) cannot compare against the
        aware ``now`` (TypeError) → treated as no expiry (fail-open), per the
        codebase convention that producers always emit aware datetimes."""
        d = DomainInspector()
        d.configure({
            "allow": ["example.com"],
            "expires": {"example.com": "2000-01-01T00:00:00"},
        })
        assert d._matched_expired("example.com") is None
        assert d.inspect_request(_ctx(host="example.com")) is None


# ── SecretsInspector ─────────────────────────────────────


class TestSecretsInspector:
    def test_detects_anthropic_key_in_body(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            body_text='{"api_key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}',
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "anthropic_key" in r.reason

    def test_detects_anthropic_key_in_url(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            url="https://evil.com/?key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert "anthropic_key" in r.reason

    def test_detects_aws_key(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="access_key=AKIAIOSFODNN7EXAMPLE")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "aws_access_key" in r.reason

    def test_detects_github_token(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "ghp_" + "A" * 36
        ctx = _ctx(body_text=f"token={token}")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "github_token" in r.reason

    def test_detects_private_key_header(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="-----BEGIN RSA PRIVATE KEY-----")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "private_key" in r.reason

    def test_allows_clean_body(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text='{"message": "hello world"}')
        assert s.inspect_request(ctx) is None

    def test_disabled_allows_everything(self):
        s = SecretsInspector()
        s.configure({"enabled": False})
        ctx = _ctx(body_text="sk-abcdefghijklmnopqrstuvwxyz")
        assert s.inspect_request(ctx) is None

    def test_default_action_is_flag(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        assert s.action == "flag"
        assert s.action_explicit is False
        ctx = _ctx(body_text="access_key=AKIAIOSFODNN7EXAMPLE")
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "aws_access_key" in r.reason

    def test_block_action_blocks(self):
        s = SecretsInspector()
        s.configure({"enabled": True, "action": "block"})
        assert s.action == "block"
        assert s.action_explicit is True
        ctx = _ctx(body_text="access_key=AKIAIOSFODNN7EXAMPLE")
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"

    def test_unknown_action_falls_back_to_flag(self):
        s = SecretsInspector()
        s.configure({"enabled": True, "action": "warn"})
        assert s.action == "flag"
        assert s.action_explicit is True

    def test_extra_patterns(self):
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "extra_patterns": [
                {"name": "custom-key", "pattern": r"CUSTOM_[A-Z]{10}"}
            ],
        })
        ctx = _ctx(body_text="key=CUSTOM_ABCDEFGHIJ")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "custom-key" in r.reason

    def test_extra_patterns_env_matches_exact_value(self, monkeypatch):
        monkeypatch.setenv("TEST_SECRET", "my-custom-secret-value-1234")
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "extra_patterns": [
                {"name": "test-secret", "env": "TEST_SECRET"}
            ],
        })
        ctx = _ctx(body_text="key=my-custom-secret-value-1234", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "test-secret" in r.reason

    def test_extra_patterns_env_no_partial_match(self, monkeypatch):
        monkeypatch.setenv("TEST_SECRET", "my-custom-secret-value-1234")
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "extra_patterns": [
                {"name": "test-secret", "env": "TEST_SECRET"}
            ],
        })
        # Similar-looking string that is NOT the exact key
        ctx = _ctx(body_text="key=my-custom-secret-value-9999", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_extra_patterns_env_missing_skipped(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_SECRET", raising=False)
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "extra_patterns": [
                {"name": "missing-secret", "env": "NONEXISTENT_SECRET"}
            ],
        })
        assert "missing-secret" not in s.patterns

    # ── New pattern tests ──

    def test_detects_openrouter_key(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "sk-or-v1-" + "a1b2c3d4" * 8  # 64 hex chars
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "openrouter_key" in r.reason

    def test_no_false_positive_openrouter(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="sk-or-v1-tooshort", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_detects_perplexity_key(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "pplx-" + "Ab1Cd2Ef" * 6  # 48 alnum chars
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "perplexity_key" in r.reason

    def test_no_false_positive_perplexity(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="pplx-tooshort", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_detects_brave_api_key(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        # Brave keys are 32 chars total: BSAI prefix + 28 alphanumeric.
        key = "BSAI" + "A" * 28
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "brave_api_key" in r.reason

    def test_no_false_positive_brave(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="BSAIshort", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_brave_api_key_not_flagged_in_image_body(self):
        """Real-world false positive: a JPEG base64-encoded for the
        Anthropic vision API happens to contain a ``BSAI...{28+}``
        substring purely by coincidence (observed at ~40% per JPEG on
        a real user cage).  The secrets inspector must NOT flag base64
        photo bytes when the request advertises an image content type.
        """
        s = SecretsInspector()
        s.configure({"enabled": True})
        # Real harvested substring from a JPEG base64 body that triggered
        # a 403 on api.anthropic.com.
        harvested = "BSAIyD3rHwSgwFJdesDp3FaluWlRwdZ1ZDRMn17VieEZOIN1LR"
        # Pad with more base64-shaped noise to simulate the full body.
        body = (
            "data:image/jpeg;base64," + ("ABCDEFgh01" * 200) + harvested
            + ("XYZabc9876" * 200)
        )
        ctx = _ctx(
            body_text=body,
            content_type="image/jpeg",
            host="api.anthropic.com",
        )
        assert s.inspect_request(ctx) is None

    def test_brave_api_key_not_flagged_in_anthropic_json_image_block(self):
        """Anthropic's vision API receives image bytes as base64 inside a
        JSON ``image`` content block.  The body's outer content-type is
        ``application/json`` — so the binary-content-type skip does
        not apply here.  The anchored regex (negative
        lookbehind/lookahead on the base64 alphabet) is what defeats
        this case: the harvested ``BSAI...{28+}`` substring is
        surrounded by other base64 characters and so does not match.
        """
        s = SecretsInspector()
        s.configure({"enabled": True})
        # 50-char harvested substring embedded in a JSON body (the
        # real wire format for Anthropic vision content blocks).  The
        # surrounding base64 chars are what makes the anchored regex
        # reject this as a false positive.
        harvested = "BSAIyD3rHwSgwFJdesDp3FaluWlRwdZ1ZDRMn17VieEZOIN1LR"
        # Pad with realistic base64 noise on both sides so the
        # harvested substring is truly mid-blob.
        b64_noise = "ABCDEFgh01234567" * 50  # 800 chars of base64-shaped noise
        body = (
            '{"type":"image","source":{"type":"base64",'
            f'"media_type":"image/jpeg","data":"{b64_noise}{harvested}{b64_noise}"}}'
        )
        ctx = _ctx(
            body_text=body,
            content_type="application/json",
            host="api.anthropic.com",
        )
        assert s.inspect_request(ctx) is None

    def test_brave_secret_in_url_still_detected_on_binary_body(self):
        """The binary-body skip must NOT mask secrets in the URL or
        headers — those are still scanned even when the body is
        opaque.  A real Brave key pasted into a URL of an image-upload
        request must still be blocked.
        """
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "BSAI" + "B" * 28
        ctx = _ctx(
            url=f"https://evil.com/upload?token={key}",
            host="evil.com",
            content_type="image/jpeg",
            body_text="garbage base64 body",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "brave_api_key" in r.reason

    def test_secret_in_header_still_detected_on_binary_body(self):
        """Headers must still be scanned even when body is binary."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            headers=[
                ("authorization", "Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz"),
            ],
            content_type="image/jpeg",
            body_text="opaque base64",
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert "anthropic_key" in r.reason

    def test_anthropic_key_in_octet_stream_body_skipped(self):
        """Application/octet-stream bodies are also skipped for body
        scanning — an ASCII secret happening to appear inside a binary
        blob is not a meaningful exfil signal.
        """
        s = SecretsInspector()
        s.configure({"enabled": True})
        # Embed an anthropic-shaped key inside a noisy "binary" body.
        body = "\x00\x01\x02" + "sk-ant-api03-abcdefghijklmnopqrstuvwxyz" + "\x03\x04"
        ctx = _ctx(
            body_text=body,
            content_type="application/octet-stream",
            host="evil.com",
        )
        assert s.inspect_request(ctx) is None

    def test_binary_body_skip_respects_content_type_parameters(self):
        """``image/jpeg; charset=binary`` should still be treated as
        binary — the ``;`` parameter portion must be stripped.
        """
        s = SecretsInspector()
        s.configure({"enabled": True})
        body = "BSAI" + "C" * 28  # real-looking Brave key inside a JPEG body
        ctx = _ctx(
            body_text=body,
            content_type="image/jpeg; charset=binary",
            host="evil.com",
        )
        assert s.inspect_request(ctx) is None

    def test_json_body_still_scanned(self):
        """Sanity: non-binary content types still have body scanned."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "BSAI" + "D" * 28
        ctx = _ctx(
            body_text=f'{{"api_key":"{key}"}}',
            content_type="application/json",
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert "brave_api_key" in r.reason

    def test_detects_telegram_bot_token(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "123456789:" + "A" * 35
        ctx = _ctx(body_text=f"token={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "telegram_bot_token" in r.reason

    def test_no_false_positive_telegram(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="12345:short", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_detects_discord_bot_token(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "M" + "A" * 23 + "." + "B" * 6 + "." + "C" * 27
        ctx = _ctx(body_text=f"token={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "discord_bot_token" in r.reason

    def test_no_false_positive_discord(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="Mshort.AB.CD", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_detects_firecrawl_key(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "fc-" + "a" * 32
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "firecrawl_key" in r.reason

    def test_no_false_positive_firecrawl(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="fc-short", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_detects_google_oauth_access_token(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "ya29." + "A" * 80
        ctx = _ctx(body_text=f"token={token}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "google_oauth_access_token" in r.reason

    def test_no_false_positive_google_oauth_short(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="ya29.tooshort", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_google_oauth_token_allowed_to_googleapis(self):
        """Minted ya29. tokens are expected on the wire to googleapis.com."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "ya29." + "A" * 80
        ctx = _ctx(
            headers=[("authorization", f"Bearer {token}")],
            host="gmail.googleapis.com",
        )
        assert s.inspect_request(ctx) is None

    def test_google_oauth_token_blocked_to_wrong_domain(self):
        """ya29. token leaking to a non-Google host is blocked."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "ya29." + "A" * 80
        ctx = _ctx(
            headers=[("authorization", f"Bearer {token}")],
            host="attacker.example",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "google_oauth_access_token" in r.reason

    # ── Tightened pattern tests ──

    def test_brave_old_prefix_no_match(self):
        """Old BSA prefix (without the I) should no longer match."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="BSA" + "A" * 30, host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_openai_key_with_marker(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "sk-proj-" + "A" * 40 + "T3BlbkFJ" + "B" * 40
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "openai_key" in r.reason

    def test_openai_key_without_marker_no_match(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "sk-proj-" + "A" * 50
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_anthropic_key_with_api03(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "sk-ant-api03-" + "a" * 30
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "anthropic_key" in r.reason

    def test_huggingface_digits_no_match(self):
        """HuggingFace tokens are alphabetic only — digits should not match."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "hf_" + "A1B2" * 10  # contains digits, 40 chars
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        assert s.inspect_request(ctx) is None

    def test_github_token_exact_length(self):
        """gh[ps]_ tokens have exactly 36 Base62 chars."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "ghp_" + "A" * 36
        ctx = _ctx(body_text=f"token={token}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "github_token" in r.reason

    def test_firecrawl_uppercase_no_match(self):
        """Firecrawl keys are hex (lowercase) — uppercase should not match."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        key = "fc-" + "A" * 32
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        assert s.inspect_request(ctx) is None

    # ── Bounded quantifier tests (security review H3) ──

    def test_oversized_key_not_fully_consumed(self):
        """Upper-bounded patterns should not match arbitrarily long strings.

        The match itself still succeeds (the prefix is valid), but the
        regex engine stops consuming characters at the upper bound rather
        than scanning the entire input.  This test verifies that behaviour
        by ensuring a 10k-char body still completes in bounded time and
        that legitimate-length keys are still detected.
        """
        import time
        s = SecretsInspector()
        s.configure({"enabled": True})
        # A body with a valid prefix followed by 10k chars should still be
        # detected (regex matches the valid-length prefix), but should not
        # cause the engine to scan unboundedly.
        body = "sk-ant-api03-" + "a" * 10_000
        ctx = _ctx(body_text=body, host="evil.com")
        t0 = time.monotonic()
        r = s.inspect_request(ctx)
        elapsed = time.monotonic() - t0
        assert r is not None
        assert r.action == "flag"
        # Should complete in well under 1 second even on slow hardware
        assert elapsed < 1.0

    def test_private_key_bounded_type_name(self):
        """Private key pattern matches real types but not absurdly long ones."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        # Real type: should match
        ctx = _ctx(body_text="-----BEGIN RSA PRIVATE KEY-----", host="evil.com")
        assert s.inspect_request(ctx) is not None
        # EC type: should match
        ctx2 = _ctx(body_text="-----BEGIN EC PRIVATE KEY-----", host="evil.com")
        assert s.inspect_request(ctx2) is not None
        # Absurdly long type (>20 spaces+chars): should not match
        ctx3 = _ctx(body_text="-----BEGIN" + " AAAA" * 10 + "PRIVATE KEY-----", host="evil.com")
        assert s.inspect_request(ctx3) is None

    # ── Built-in allow_to_domains tests ──

    def test_builtin_allow_lets_anthropic_key_through(self):
        """With no user allow_to_domains, built-in should allow anthropic_key to anthropic.com."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            body_text='{"key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}',
            host="api.anthropic.com",
        )
        assert s.inspect_request(ctx) is None

    def test_builtin_allow_blocks_anthropic_key_to_wrong_domain(self):
        """Built-in allow should not help when secret goes to wrong domain."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            body_text='{"key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}',
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert "anthropic_key" in r.reason

    def test_user_config_extends_builtin_allow(self):
        """User allow_to_domains should merge with (not replace) built-ins."""
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "allow_to_domains": {
                "custom_key": ["custom.com"],
            },
        })
        # Built-in still present
        assert "anthropic.com" in s.allow_to_domains["anthropic_key"]
        # User config also present
        assert "custom.com" in s.allow_to_domains["custom_key"]

    def test_user_config_overrides_builtin_for_same_key(self):
        """User config for the same pattern name should override built-in."""
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "allow_to_domains": {
                "anthropic_key": ["my-proxy.example.com"],
            },
        })
        assert s.allow_to_domains["anthropic_key"] == ["my-proxy.example.com"]

    def test_builtin_allow_opt_out(self):
        """builtin_allow_to_domains: false should disable built-in mappings."""
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "builtin_allow_to_domains": False,
        })
        assert s.allow_to_domains == {}

    def test_builtin_allow_opt_out_keeps_user_config(self):
        """Opting out of built-ins should still use explicit user config."""
        s = SecretsInspector()
        s.configure({
            "enabled": True,
            "builtin_allow_to_domains": False,
            "allow_to_domains": {
                "anthropic_key": ["my-proxy.example.com"],
            },
        })
        assert s.allow_to_domains["anthropic_key"] == ["my-proxy.example.com"]
        # No built-in entries for keys the user didn't specify
        assert "openai_key" not in s.allow_to_domains

    def test_builtin_allow_lets_github_token_through(self):
        """ghp_ token to api.github.com should be allowed."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "ghp_" + "A" * 36
        ctx = _ctx(
            headers=[("authorization", f"Bearer {token}")],
            host="api.github.com",
        )
        assert s.inspect_request(ctx) is None

    def test_builtin_allow_lets_github_pat_through(self):
        """github_pat_ token to api.github.com should be allowed."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "github_pat_" + "A" * 22 + "_" + "B" * 59
        ctx = _ctx(
            headers=[("authorization", f"Bearer {token}")],
            host="api.github.com",
        )
        assert s.inspect_request(ctx) is None

    def test_builtin_allow_blocks_github_token_to_wrong_domain(self):
        """ghp_ token to evil.com should be blocked."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        token = "ghp_" + "A" * 36
        ctx = _ctx(
            headers=[("authorization", f"Bearer {token}")],
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "github_token" in r.reason

    def test_detects_secret_in_duplicate_header(self):
        """Multi-value headers: secret in a later value must still be caught."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            headers=[
                ("authorization", "Bearer safe-token"),
                ("x-custom", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"),
            ],
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "anthropic_key" in r.reason

    def test_detects_secret_in_repeated_header_value(self):
        """When the same header appears twice, both values are scanned."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            headers=[
                ("x-data", "harmless"),
                ("x-data", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"),
            ],
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert "anthropic_key" in r.reason


# ── BodySizeInspector ────────────────────────────────────


class TestBodySizeInspector:
    def test_blocks_oversized_body(self):
        b = BodySizeInspector()
        b.configure({"max_bytes": 100})
        ctx = _ctx(body_bytes=b"x" * 200)
        r = b.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert "200" in r.reason

    def test_allows_body_within_limit(self):
        b = BodySizeInspector()
        b.configure({"max_bytes": 100})
        ctx = _ctx(body_bytes=b"x" * 50)
        assert b.inspect_request(ctx) is None

    def test_zero_limit_allows_anything(self):
        b = BodySizeInspector()
        b.configure({"max_bytes": 0})
        ctx = _ctx(body_bytes=b"x" * 10_000_000)
        assert b.inspect_request(ctx) is None

    def test_no_body(self):
        b = BodySizeInspector()
        b.configure({"max_bytes": 100})
        ctx = _ctx(body_bytes=None)
        assert b.inspect_request(ctx) is None

    def test_host_max_bytes_raises_limit_for_matching_host(self):
        b = BodySizeInspector()
        b.configure({
            "max_bytes": 100,
            "host_max_bytes": {"fcos-vm-home-01": 1000},
        })
        ctx = _ctx(body_bytes=b"x" * 500, host="fcos-vm-home-01")
        assert b.inspect_request(ctx) is None

    def test_host_max_bytes_lowers_limit_for_matching_host(self):
        """Override can also tighten the limit, not only loosen it."""
        b = BodySizeInspector()
        b.configure({
            "max_bytes": 1000,
            "host_max_bytes": {"strict.example.com": 100},
        })
        ctx = _ctx(body_bytes=b"x" * 500, host="strict.example.com")
        r = b.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert r.metadata["max_bytes"] == 100

    def test_host_max_bytes_falls_back_to_global_for_unmatched_host(self):
        b = BodySizeInspector()
        b.configure({
            "max_bytes": 100,
            "host_max_bytes": {"fcos-vm-home-01": 1000},
        })
        ctx = _ctx(body_bytes=b"x" * 500, host="api.anthropic.com")
        r = b.inspect_request(ctx)
        assert r is not None
        assert r.metadata["max_bytes"] == 100

    def test_host_max_bytes_suffix_matches_subdomain(self):
        b = BodySizeInspector()
        b.configure({
            "max_bytes": 100,
            "host_max_bytes": {"ts.net": 1000},
        })
        ctx = _ctx(body_bytes=b"x" * 500, host="paperless.taile1b309.ts.net")
        assert b.inspect_request(ctx) is None

    def test_host_max_bytes_most_specific_match_wins(self):
        """Subdomain limit must override apex limit, not the other way around."""
        b = BodySizeInspector()
        b.configure({
            "max_bytes": 100,
            "host_max_bytes": {
                "ts.net": 10_000,
                "paperless.taile1b309.ts.net": 500,
            },
        })
        ctx = _ctx(body_bytes=b"x" * 1000, host="paperless.taile1b309.ts.net")
        r = b.inspect_request(ctx)
        assert r is not None
        assert r.metadata["max_bytes"] == 500

    def test_host_max_bytes_zero_disables_for_host(self):
        """Setting a host's limit to 0 follows the global semantics: no cap."""
        b = BodySizeInspector()
        b.configure({
            "max_bytes": 100,
            "host_max_bytes": {"unlimited.example.com": 0},
        })
        ctx = _ctx(body_bytes=b"x" * 10_000_000, host="unlimited.example.com")
        assert b.inspect_request(ctx) is None


# ── EntropyInspector ─────────────────────────────────────


class TestEntropyInspector:
    def test_flags_high_entropy(self):
        e = EntropyInspector()
        e.configure({"threshold": 7.0, "min_body_bytes": 64, "action": "flag"})
        # Random-ish bytes have high entropy
        ctx = _ctx(body_bytes=bytes(range(256)) * 4, body_entropy=8.0)
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "entropy" in r.reason

    def test_allows_low_entropy(self):
        e = EntropyInspector()
        e.configure({"threshold": 7.0, "min_body_bytes": 64, "action": "flag"})
        ctx = _ctx(
            body_bytes=b"aaaaaaaaaa" * 100,
            body_entropy=0.0,
        )
        assert e.inspect_request(ctx) is None

    def test_skips_small_bodies(self):
        e = EntropyInspector()
        e.configure({"threshold": 7.0, "min_body_bytes": 256, "action": "flag"})
        ctx = _ctx(body_bytes=b"x" * 100, body_entropy=7.5)
        assert e.inspect_request(ctx) is None

    def test_skips_exempt_content_types(self):
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "flag",
            "exempt_content_types": ["image/"],
        })
        ctx = _ctx(
            body_bytes=bytes(range(256)) * 4,
            body_entropy=8.0,
            content_type="image/png",
        )
        assert e.inspect_request(ctx) is None

    def test_blocks_when_action_is_block(self):
        e = EntropyInspector()
        e.configure({"threshold": 7.0, "min_body_bytes": 64, "action": "block"})
        ctx = _ctx(body_bytes=bytes(range(256)) * 4, body_entropy=7.9)
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"

    def test_no_body_entropy(self):
        e = EntropyInspector()
        e.configure({"threshold": 7.0, "min_body_bytes": 64, "action": "flag"})
        ctx = _ctx(body_bytes=None, body_entropy=None)
        assert e.inspect_request(ctx) is None

    def test_host_exempt_allows_matching_host(self):
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "exempt_content_types": [],
            "host_exempt_content_types": {
                "openclaw-01.taile1b309.ts.net": ["audio/", "video/"],
            },
        })
        ctx = _ctx(
            body_bytes=bytes(range(256)) * 4,
            body_entropy=7.99,
            content_type="audio/ogg",
            host="openclaw-01.taile1b309.ts.net",
        )
        assert e.inspect_request(ctx) is None

    def test_host_exempt_blocks_different_host(self):
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "exempt_content_types": [],
            "host_exempt_content_types": {
                "openclaw-01.taile1b309.ts.net": ["audio/", "video/"],
            },
        })
        ctx = _ctx(
            body_bytes=bytes(range(256)) * 4,
            body_entropy=7.99,
            content_type="audio/ogg",
            host="evil.com",
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"

    def test_host_exempt_matches_subdomain(self):
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "exempt_content_types": [],
            "host_exempt_content_types": {
                "ts.net": ["audio/"],
            },
        })
        ctx = _ctx(
            body_bytes=bytes(range(256)) * 4,
            body_entropy=7.99,
            content_type="audio/ogg",
            host="openclaw-01.taile1b309.ts.net",
        )
        assert e.inspect_request(ctx) is None

    def test_octet_stream_not_exempt_by_default(self):
        """application/octet-stream should NOT be globally exempt (too broad)."""
        e = EntropyInspector()
        e.configure({"threshold": 7.0, "min_body_bytes": 64, "action": "block"})
        ctx = _ctx(
            body_bytes=bytes(range(256)) * 4,
            body_entropy=7.99,
            content_type="application/octet-stream",
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"

    def test_websocket_frame_content_type_not_exempt(self):
        """WebSocket synthetic content-type must not match any default exemption."""
        e = EntropyInspector()
        e.configure({"threshold": 7.0, "min_body_bytes": 64, "action": "block"})
        ctx = _ctx(
            body_bytes=bytes(range(256)) * 4,
            body_entropy=7.99,
            content_type="application/x-websocket-frame",
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"

    def test_host_exempt_non_matching_content_type_still_blocks(self):
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "exempt_content_types": [],
            "host_exempt_content_types": {
                "openclaw-01.taile1b309.ts.net": ["audio/", "video/"],
            },
        })
        ctx = _ctx(
            body_bytes=bytes(range(256)) * 4,
            body_entropy=7.99,
            content_type="application/x-tar",
            host="openclaw-01.taile1b309.ts.net",
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"

    def test_url_param_high_entropy_blocked(self):
        """High-entropy URL query parameter values should be caught."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
        })
        # base64-like random string (~5.8 entropy, above 5.5 url_threshold)
        import base64, os
        high_ent_val = base64.urlsafe_b64encode(os.urandom(128)).decode()
        ctx = _ctx(
            url=f"https://github.com/search?q={high_ent_val}&type=code",
            host="github.com",
            body_bytes=None,
            body_entropy=None,
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert "URL param" in r.reason
        assert "'q'" in r.reason

    def test_url_param_normal_value_allowed(self):
        """Normal short query parameters should not trigger."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
        })
        ctx = _ctx(
            url="https://github.com/search?q=agentcage+python&type=code",
            host="github.com",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    def test_url_param_check_disabled(self):
        """check_url_params=false should skip URL analysis."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "check_url_params": False,
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
        })
        import base64, os
        high_ent_val = base64.urlsafe_b64encode(os.urandom(128)).decode()
        ctx = _ctx(
            url=f"https://github.com/search?q={high_ent_val}",
            host="github.com",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    def test_url_param_below_min_length_skipped(self):
        """Short param values should be skipped even if high entropy."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_min_value_bytes": 256,
        })
        high_ent_val = "".join(f"{b:02x}" for b in range(64))  # 128 bytes < 256
        ctx = _ctx(
            url=f"https://github.com/search?q={high_ent_val}",
            host="github.com",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    # ── URL path entropy tests ──

    def test_url_path_high_entropy_blocked(self):
        """High-entropy URL path segments should be caught."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
        })
        import base64, os
        high_ent_seg = base64.urlsafe_b64encode(os.urandom(128)).decode().rstrip("=")
        ctx = _ctx(
            url=f"https://cdn.jsdelivr.net/{high_ent_seg}/package.json",
            host="cdn.jsdelivr.net",
            body_bytes=None,
            body_entropy=None,
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert "URL path" in r.reason

    def test_url_path_normal_segments_allowed(self):
        """Normal URL path segments should not trigger."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
        })
        ctx = _ctx(
            url="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js",
            host="cdn.jsdelivr.net",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    def test_url_path_short_segments_skipped(self):
        """Path segments shorter than url_min_value_bytes should be skipped."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_min_value_bytes": 256,
        })
        # 128-byte hex segment, below 256 minimum
        seg = "".join(f"{b:02x}" for b in range(64))
        ctx = _ctx(
            url=f"https://example.com/{seg}/file",
            host="example.com",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    def test_url_path_check_disabled(self):
        """check_url_path=false should skip path analysis."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "check_url_path": False,
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
        })
        import base64, os
        high_ent_seg = base64.urlsafe_b64encode(os.urandom(128)).decode().rstrip("=")
        ctx = _ctx(
            url=f"https://cdn.jsdelivr.net/{high_ent_seg}/package.json",
            host="cdn.jsdelivr.net",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    # ── host_url_param_allowlist tests ──

    def test_url_param_host_allowlist_skips_on_matching_host(self):
        """High-entropy 'Policy' param on xethub.hf.co should be allowed (default allowlist)."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
        })
        # Simulated CloudFront Policy param (base64-encoded JSON, ~5.5-6.0 entropy)
        import base64
        policy_val = base64.b64encode(
            b'{"Statement":[{"Resource":"https://cdn.example.com/*",'
            b'"Condition":{"DateLessThan":{"AWS:EpochTime":1700000000}}}]}'
        ).decode()
        ctx = _ctx(
            url=(
                f"https://transfer.xethub.hf.co/some/model?Policy={policy_val}"
                f"&Signature=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkL"
                f"&Key-Pair-Id=APKAEIBAERJR2EXAMPLE"
            ),
            host="transfer.xethub.hf.co",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    def test_url_param_host_allowlist_blocks_on_different_host(self):
        """Same high-entropy 'Policy' param on evil.com should be blocked."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
        })
        import base64
        policy_val = base64.b64encode(
            b'{"Statement":[{"Resource":"https://cdn.example.com/*",'
            b'"Condition":{"DateLessThan":{"AWS:EpochTime":1700000000}}}]}'
        ).decode()
        ctx = _ctx(
            url=f"https://evil.com/exfil?Policy={policy_val}",
            host="evil.com",
            body_bytes=None,
            body_entropy=None,
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert "Policy" in r.reason

    def test_url_param_host_allowlist_custom_config(self):
        """User-provided host_url_param_allowlist merges with defaults."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
            "host_url_param_allowlist": {
                "custom-cdn.example.com": ["token", "sig"],
            },
        })
        # Default entry still present
        assert "policy" in e.host_url_param_allowlist["xethub.hf.co"]
        # Custom entry merged in
        assert "token" in e.host_url_param_allowlist["custom-cdn.example.com"]
        assert "sig" in e.host_url_param_allowlist["custom-cdn.example.com"]

    # ── wildcard "*" tests ──

    def test_url_param_host_allowlist_wildcard_skips_params(self):
        """Wildcard '*' allows all high-entropy params on the host."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
            "host_url_param_allowlist": {"example.com": ["*"]},
        })
        import base64, os
        tok = base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip("=")
        ctx = _ctx(
            url=f"https://example.com/x?pageToken={tok}&syncToken={tok}",
            host="example.com",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    def test_url_param_host_allowlist_wildcard_skips_path(self):
        """Wildcard '*' also disables path-segment entropy checks."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
            "host_url_param_allowlist": {"example.com": ["*"]},
        })
        import base64, os
        seg = base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip("=")
        ctx = _ctx(
            url=f"https://example.com/{seg}/file",
            host="example.com",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx) is None

    def test_url_param_host_allowlist_wildcard_matches_subdomain(self):
        """Wildcard inherits the existing suffix-match semantics."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
            "host_url_param_allowlist": {"example.com": ["*"]},
        })
        import base64, os
        tok = base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip("=")
        seg = base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip("=")
        ctx_param = _ctx(
            url=f"https://sub.example.com/x?pageToken={tok}",
            host="sub.example.com",
            body_bytes=None,
            body_entropy=None,
        )
        ctx_path = _ctx(
            url=f"https://sub.example.com/{seg}/file",
            host="sub.example.com",
            body_bytes=None,
            body_entropy=None,
        )
        assert e.inspect_request(ctx_param) is None
        assert e.inspect_request(ctx_path) is None

    def test_url_param_host_allowlist_no_wildcard_still_blocks(self):
        """Regression guard: without wildcard, high-entropy values still block."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
        })
        import base64, os
        tok = base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip("=")
        ctx_param = _ctx(
            url=f"https://example.com/x?pageToken={tok}",
            host="example.com",
            body_bytes=None,
            body_entropy=None,
        )
        r = e.inspect_request(ctx_param)
        assert r is not None
        assert r.action == "block"
        assert "pageToken" in r.reason

        seg = base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip("=")
        ctx_path = _ctx(
            url=f"https://example.com/{seg}/file",
            host="example.com",
            body_bytes=None,
            body_entropy=None,
        )
        r = e.inspect_request(ctx_path)
        assert r is not None
        assert r.action == "block"
        assert "path segment" in r.reason

    def test_url_param_host_allowlist_wildcard_other_host_still_blocks(self):
        """Wildcard on one host does not affect a different host."""
        e = EntropyInspector()
        e.configure({
            "threshold": 7.0,
            "min_body_bytes": 64,
            "action": "block",
            "url_threshold": 5.5,
            "url_min_value_bytes": 32,
            "host_url_param_allowlist": {"example.com": ["*"]},
        })
        import base64, os
        tok = base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip("=")
        ctx = _ctx(
            url=f"https://evil.com/exfil?pageToken={tok}",
            host="evil.com",
            body_bytes=None,
            body_entropy=None,
        )
        r = e.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"


# ── ContentTypeInspector ─────────────────────────────────


class TestContentTypeInspector:
    def test_flags_high_entropy_json(self):
        ct = ContentTypeInspector()
        ct.configure({"entropy_ceiling": 6.5, "action": "flag"})
        ctx = _ctx(
            content_type="application/json",
            body_text="some data",
            body_entropy=7.5,
        )
        r = ct.inspect_request(ctx)
        assert r is not None
        assert r.action == "flag"
        assert "mismatch" in r.reason

    def test_allows_normal_json(self):
        ct = ContentTypeInspector()
        ct.configure({"entropy_ceiling": 6.5, "action": "flag"})
        ctx = _ctx(
            content_type="application/json",
            body_text='{"key": "value"}',
            body_entropy=4.0,
        )
        assert ct.inspect_request(ctx) is None

    def test_skips_non_text_content_types(self):
        ct = ContentTypeInspector()
        ct.configure({"entropy_ceiling": 6.5, "action": "flag"})
        ctx = _ctx(
            content_type="application/octet-stream",
            body_text="some data",
            body_entropy=7.9,
        )
        assert ct.inspect_request(ctx) is None

    def test_detects_base64_blob(self):
        ct = ContentTypeInspector()
        ct.configure({
            "entropy_ceiling": 6.5,
            "detect_base64": True,
            "base64_min_len": 64,
            "action": "flag",
        })
        # Base64 on its own line (the regex is anchored to line boundaries)
        b64_line = "ABCDEFGHIJKLMNOP" * 20  # 320 chars, all base64-valid
        body = f"some preamble\n{b64_line}\nsome postamble"
        ctx = _ctx(
            content_type="text/plain",
            body_text=body,
            body_entropy=4.0,  # under entropy ceiling
        )
        r = ct.inspect_request(ctx)
        assert r is not None
        assert "base64" in r.reason

    def test_ignores_small_base64(self):
        ct = ContentTypeInspector()
        ct.configure({
            "entropy_ceiling": 6.5,
            "detect_base64": True,
            "base64_min_len": 256,
            "action": "flag",
        })
        ctx = _ctx(
            content_type="application/json",
            body_text='{"data": "aGVsbG8="}',
            body_entropy=4.0,
        )
        assert ct.inspect_request(ctx) is None

    def test_detects_url_safe_base64_blob(self):
        """URL-safe base64 uses -_ instead of +/ — must still be caught."""
        ct = ContentTypeInspector()
        ct.configure({
            "entropy_ceiling": 6.5,
            "detect_base64": True,
            "base64_min_len": 64,
            "action": "flag",
        })
        # URL-safe base64 with - and _ characters
        b64_line = "ABCDEFgh-_ABCDEFgh-_" * 20  # 400 chars
        body = f"preamble\n{b64_line}\npostamble"
        ctx = _ctx(
            content_type="text/plain",
            body_text=body,
            body_entropy=4.0,
        )
        r = ct.inspect_request(ctx)
        assert r is not None
        assert "base64" in r.reason

    def test_no_body(self):
        ct = ContentTypeInspector()
        ct.configure({"entropy_ceiling": 6.5, "action": "flag"})
        ctx = _ctx(content_type="application/json", body_text=None)
        assert ct.inspect_request(ctx) is None

    def test_host_exempt_content_type_skips_entropy_check(self):
        """Per-host exemption skips a body that would otherwise block."""
        ct = ContentTypeInspector()
        ct.configure({
            "entropy_ceiling": 6.5,
            "action": "block",
            "host_exempt_content_types": {
                "fcos-vm-home-01": ["multipart/form-data"],
            },
        })
        ctx = _ctx(
            content_type="multipart/form-data; boundary=abc",
            body_text="binary-ish multipart",
            body_entropy=7.82,  # PDF-shaped — would normally block
            host="fcos-vm-home-01",
        )
        assert ct.inspect_request(ctx) is None

    def test_host_exempt_blocks_different_host(self):
        """Exemption keyed to one host does not bleed to others."""
        ct = ContentTypeInspector()
        ct.configure({
            "entropy_ceiling": 6.5,
            "action": "block",
            "host_exempt_content_types": {
                "fcos-vm-home-01": ["multipart/form-data"],
            },
        })
        ctx = _ctx(
            content_type="multipart/form-data; boundary=abc",
            body_text="binary-ish multipart",
            body_entropy=7.82,
            host="evil.com",
        )
        r = ct.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"

    def test_host_exempt_matches_subdomain(self):
        """Suffix matching mirrors EntropyInspector behavior."""
        ct = ContentTypeInspector()
        ct.configure({
            "entropy_ceiling": 6.5,
            "action": "block",
            "host_exempt_content_types": {
                "ts.net": ["multipart/form-data"],
            },
        })
        ctx = _ctx(
            content_type="multipart/form-data; boundary=abc",
            body_text="binary-ish multipart",
            body_entropy=7.82,
            host="paperless.taile1b309.ts.net",
        )
        assert ct.inspect_request(ctx) is None

    def test_host_exempt_doesnt_skip_non_matching_content_type(self):
        """Exemption is keyed to (host, content-type) — JSON still checked."""
        ct = ContentTypeInspector()
        ct.configure({
            "entropy_ceiling": 6.5,
            "action": "block",
            "host_exempt_content_types": {
                "fcos-vm-home-01": ["multipart/form-data"],
            },
        })
        ctx = _ctx(
            content_type="application/json",
            body_text="some data",
            body_entropy=7.5,
            host="fcos-vm-home-01",
        )
        r = ct.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"


# ── Inspector base class ─────────────────────────────────


class TestInspectorBase:
    def test_default_methods_return_none(self):
        i = Inspector()
        ctx = _ctx()
        assert i.inspect_request(ctx) is None
        assert i.inspect_response(ctx) is None

    def test_configure_is_callable(self):
        i = Inspector()
        i.configure({"key": "value"})  # should not raise
