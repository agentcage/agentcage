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

    def test_no_mode_allows_everything(self):
        d = DomainInspector()
        d.configure({})
        assert d.inspect_request(_ctx(host="anything.example.com")) is None


# ── SecretsInspector ─────────────────────────────────────


class TestSecretsInspector:
    def test_detects_anthropic_key_in_body(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            body_text='{"api_key": "sk-ant-abcdefghijklmnopqrstuvwxyz"}',
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert "anthropic_key" in r.reason

    def test_detects_anthropic_key_in_url(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            url="https://evil.com/?key=sk-ant-abcdefghijklmnopqrstuvwxyz",
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
        key = "pplx-" + "ab12cd34" * 8  # 64 hex chars
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
        key = "BSA" + "A" * 20
        ctx = _ctx(body_text=f"key={key}", host="evil.com")
        r = s.inspect_request(ctx)
        assert r is not None
        assert "brave_api_key" in r.reason

    def test_no_false_positive_brave(self):
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(body_text="BSAshort", host="evil.com")
        assert s.inspect_request(ctx) is None

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
        body = "sk-ant-" + "a" * 10_000
        ctx = _ctx(body_text=body, host="evil.com")
        t0 = time.monotonic()
        r = s.inspect_request(ctx)
        elapsed = time.monotonic() - t0
        assert r is not None
        assert r.action == "block"
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
            body_text='{"key": "sk-ant-abcdefghijklmnopqrstuvwxyz"}',
            host="api.anthropic.com",
        )
        assert s.inspect_request(ctx) is None

    def test_builtin_allow_blocks_anthropic_key_to_wrong_domain(self):
        """Built-in allow should not help when secret goes to wrong domain."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            body_text='{"key": "sk-ant-abcdefghijklmnopqrstuvwxyz"}',
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

    def test_detects_secret_in_duplicate_header(self):
        """Multi-value headers: secret in a later value must still be caught."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            headers=[
                ("authorization", "Bearer safe-token"),
                ("x-custom", "sk-ant-abcdefghijklmnopqrstuvwxyz"),
            ],
            host="evil.com",
        )
        r = s.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert "anthropic_key" in r.reason

    def test_detects_secret_in_repeated_header_value(self):
        """When the same header appears twice, both values are scanned."""
        s = SecretsInspector()
        s.configure({"enabled": True})
        ctx = _ctx(
            headers=[
                ("x-data", "harmless"),
                ("x-data", "sk-ant-abcdefghijklmnopqrstuvwxyz"),
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
