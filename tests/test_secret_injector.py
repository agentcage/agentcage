"""Tests for the SecretInjector."""

import os
from unittest.mock import MagicMock

import pytest

from secret_injector import SecretInjector, InjectionRule


# ── Helpers ──────────────────────────────────────────────


def _make_flow(
    url="https://api.anthropic.com/v1/messages",
    host="api.anthropic.com",
    method="POST",
    headers=None,
    content=None,
):
    """Build a minimal mock mitmproxy HTTPFlow."""
    flow = MagicMock()
    flow.request.url = url
    flow.request.host = host
    flow.request.method = method
    flow.request.headers = dict(headers or {})
    flow.request.content = content.encode() if isinstance(content, str) else content
    flow.response = None
    return flow


def _make_response_flow(
    url="https://api.anthropic.com/v1/messages",
    host="api.anthropic.com",
    resp_headers=None,
    resp_content=None,
):
    """Build a mock flow with a response attached."""
    flow = _make_flow(url=url, host=host)
    flow.response = MagicMock()
    flow.response.headers = dict(resp_headers or {})
    flow.response.content = (
        resp_content.encode() if isinstance(resp_content, str) else resp_content
    )
    return flow


def _injector_with_rules(rules):
    """Create a SecretInjector pre-populated with InjectionRule objects."""
    inj = SecretInjector()
    inj.rules = rules
    return inj


# ── Request injection ────────────────────────────────────


class TestInjectRequest:
    def test_replaces_placeholder_in_body(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(content="body with {{KEY}} here")
        names = inj.inject_request(flow)
        assert flow.request.content == b"body with real-secret here"
        assert names == ["KEY"]

    def test_replaces_placeholder_in_headers(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(headers={"Authorization": "Bearer {{KEY}}"})
        names = inj.inject_request(flow)
        assert flow.request.headers["Authorization"] == "Bearer real-secret"
        assert names == ["KEY"]

    def test_replaces_placeholder_in_url(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1?key={{KEY}}",
            host="api.anthropic.com",
        )
        names = inj.inject_request(flow)
        assert flow.request.url == "https://api.anthropic.com/v1?key=real-secret"
        assert names == ["KEY"]

    def test_flags_placeholder_to_unauthorized_domain(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://evil.com/exfil",
            host="evil.com",
            content="{{KEY}}",
        )
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "flag"
        assert result.severity == "error"
        assert "unauthorized" in result.reason
        assert "evil.com" in result.reason

    def test_inject_skips_unauthorized_domain(self):
        """Placeholder should be left in place for unauthorized domains."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://evil.com/exfil",
            host="evil.com",
            content="body with {{KEY}} here",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"body with {{KEY}} here"
        assert names == []

    def test_inject_mixed_rules(self):
        """Authorized rule gets injected, unauthorized rule's placeholder stays."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=["other.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1/messages",
            host="api.anthropic.com",
            content="key={{KEY}}&email={{EMAIL}}",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"key=real-secret&email={{EMAIL}}"
        assert names == ["KEY"]

    def test_no_inject_to_leaves_placeholder(self):
        """Empty inject_to means the secret is never injected — placeholder stays."""
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        flow = _make_flow(
            url="https://any-domain.com/api",
            host="any-domain.com",
            content="contact: {{EMAIL}}",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"contact: {{EMAIL}}"
        assert names == []

    def test_no_inject_to_flags_policy(self):
        """Empty inject_to → placeholder sent anywhere triggers a flag."""
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        flow = _make_flow(
            url="https://any-domain.com/api",
            host="any-domain.com",
            content="contact: {{EMAIL}}",
        )
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "flag"
        assert "EMAIL" in result.reason

    def test_subdomain_matches_inject_to(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1",
            host="api.anthropic.com",
            content="{{KEY}}",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"real-secret"
        assert names == ["KEY"]

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        flow = _make_flow(content="no placeholders")
        names = inj.inject_request(flow)
        assert flow.request.content == b"no placeholders"
        assert names == []

    def test_noop_when_no_placeholder_present(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(content="clean body with no placeholders")
        names = inj.inject_request(flow)
        assert flow.request.content == b"clean body with no placeholders"
        assert names == []

    def test_multiple_rules(self):
        inj = _injector_with_rules([
            InjectionRule("KEY1", "{{KEY1}}", "secret-1", inject_to=["anthropic.com"]),
            InjectionRule("KEY2", "{{KEY2}}", "secret-2", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(content="a={{KEY1}}&b={{KEY2}}")
        names = inj.inject_request(flow)
        assert flow.request.content == b"a=secret-1&b=secret-2"
        assert sorted(names) == ["KEY1", "KEY2"]


# ── Response redaction ───────────────────────────────────


class TestRedactResponse:
    def test_redacts_real_value_in_body(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_response_flow(resp_content='{"key": "real-secret"}')
        names = inj.redact_response(flow)
        assert flow.response.content == b'{"key": "{{KEY}}"}'
        assert names == ["KEY"]

    def test_redacts_real_value_in_headers(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_response_flow(resp_headers={"X-Key": "real-secret"})
        names = inj.redact_response(flow)
        assert flow.response.headers["X-Key"] == "{{KEY}}"
        assert names == ["KEY"]

    def test_longest_first_ordering(self):
        """When one real value is a substring of another, the longer one
        should be replaced first to avoid partial matches."""
        inj = _injector_with_rules([
            InjectionRule("SHORT", "{{SHORT}}", "secret", inject_to=[]),
            InjectionRule("LONG", "{{LONG}}", "secret-long-value", inject_to=[]),
        ])
        flow = _make_response_flow(resp_content="the value is secret-long-value here")
        names = inj.redact_response(flow)
        assert flow.response.content == b"the value is {{LONG}} here"
        assert "LONG" in names

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        flow = _make_response_flow(resp_content="clean body")
        names = inj.redact_response(flow)
        assert flow.response.content == b"clean body"
        assert names == []

    def test_noop_when_no_response(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret"),
        ])
        flow = _make_flow(content="irrelevant")
        flow.response = None
        names = inj.redact_response(flow)  # should not raise
        assert names == []

    def test_redacts_regardless_of_domain(self):
        """Inbound redaction applies to all domains, not just inject_to."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_response_flow(
            url="https://other.com/api",
            host="other.com",
            resp_content="leaked: real-secret",
        )
        names = inj.redact_response(flow)
        assert flow.response.content == b"leaked: {{KEY}}"
        assert names == ["KEY"]


# ── Configuration ────────────────────────────────────────


class TestConfigure:
    def test_loads_rules_from_env(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "my-real-secret")
        inj = SecretInjector()
        inj.configure([
            {"env": "TEST_KEY", "placeholder": "{{TEST_KEY}}", "inject_to": ["example.com"]},
        ])
        assert len(inj.rules) == 1
        assert inj.rules[0].name == "TEST_KEY"
        assert inj.rules[0].real_value == "my-real-secret"
        assert inj.rules[0].placeholder == "{{TEST_KEY}}"
        assert inj.rules[0].inject_to == ["example.com"]

    def test_skips_missing_env_var(self, monkeypatch):
        monkeypatch.delenv("MISSING_KEY", raising=False)
        inj = SecretInjector()
        inj.configure([
            {"env": "MISSING_KEY", "placeholder": "{{MISSING_KEY}}"},
        ])
        assert len(inj.rules) == 0

    def test_multiple_entries(self, monkeypatch):
        monkeypatch.setenv("KEY_A", "secret-a")
        monkeypatch.setenv("KEY_B", "secret-b")
        inj = SecretInjector()
        inj.configure([
            {"env": "KEY_A", "placeholder": "{{KEY_A}}"},
            {"env": "KEY_B", "placeholder": "{{KEY_B}}", "inject_to": ["b.com"]},
        ])
        assert len(inj.rules) == 2
        assert inj.rules[0].inject_to == []
        assert inj.rules[1].inject_to == ["b.com"]

    def test_empty_config(self):
        inj = SecretInjector()
        inj.configure([])
        assert len(inj.rules) == 0


# ── Domain matching ──────────────────────────────────────


class TestDomainMatches:
    def test_exact_match(self):
        assert SecretInjector._domain_matches("anthropic.com", ["anthropic.com"])

    def test_subdomain_match(self):
        assert SecretInjector._domain_matches("api.anthropic.com", ["anthropic.com"])

    def test_no_match(self):
        assert not SecretInjector._domain_matches("evil.com", ["anthropic.com"])

    def test_case_insensitive(self):
        assert SecretInjector._domain_matches("API.Anthropic.COM", ["anthropic.com"])

    def test_partial_no_match(self):
        """anthropic.com.evil.com should NOT match anthropic.com."""
        assert not SecretInjector._domain_matches("anthropic.com.evil.com", ["anthropic.com"])


# ── Outbound redaction (redact_to) ──────────────────────


class TestRedactRequest:
    def test_redacts_real_value_in_body(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(
            url="https://matrix.example.com/_matrix/send",
            host="matrix.example.com",
            content="message with real-secret inside",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"message with {{KEY}} inside"
        assert names == ["KEY"]

    def test_redacts_real_value_in_headers(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(
            url="https://matrix.example.com/_matrix/send",
            host="matrix.example.com",
            headers={"Authorization": "Bearer real-secret"},
        )
        names = inj.inject_request(flow)
        assert flow.request.headers["Authorization"] == "Bearer {{KEY}}"
        assert names == ["KEY"]

    def test_placeholder_passes_through(self):
        """Placeholders should NOT be blocked or injected for redact_to domains."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(
            url="https://matrix.example.com/_matrix/send",
            host="matrix.example.com",
            content="my key is {{KEY}}",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"my key is {{KEY}}"
        assert names == []

    def test_redact_to_priority_over_inject_to(self):
        """If a domain is in both redact_to and inject_to, redact wins."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["shared.com"]),
        ])
        inj.redact_to = ["shared.com"]
        flow = _make_flow(
            url="https://shared.com/api",
            host="shared.com",
            content="value is real-secret",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"value is {{KEY}}"
        assert names == ["KEY"]

    def test_no_inject_to_not_injected_for_redact_domain(self):
        """USER_EMAIL (no inject_to) should NOT be injected to redact_to domains."""
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(
            url="https://matrix.example.com/_matrix/send",
            host="matrix.example.com",
            content="contact: {{EMAIL}}",
        )
        names = inj.inject_request(flow)
        # Placeholder passes through, NOT replaced with real value
        assert flow.request.content == b"contact: {{EMAIL}}"
        assert names == []

    def test_real_email_redacted_for_redact_domain(self):
        """If real email leaks into request to redact_to domain, it gets redacted."""
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(
            url="https://matrix.example.com/_matrix/send",
            host="matrix.example.com",
            content="contact: user@example.com",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"contact: {{EMAIL}}"
        assert names == ["EMAIL"]

    def test_non_redact_domain_still_injects(self):
        """Normal inject_to behavior unchanged for non-redact_to domains."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(content="body with {{KEY}} here")
        names = inj.inject_request(flow)
        assert flow.request.content == b"body with real-secret here"
        assert names == ["KEY"]


# ── Config format (dict vs list) ────────────────────────


class TestConfigFormat:
    def test_dict_config_with_redact_to(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "my-secret")
        inj = SecretInjector()
        inj.configure({
            "redact_to": ["matrix.example.com"],
            "rules": [
                {"env": "TEST_KEY", "placeholder": "{{TEST_KEY}}", "inject_to": ["example.com"]},
            ],
        })
        assert len(inj.rules) == 1
        assert inj.rules[0].name == "TEST_KEY"
        assert inj.redact_to == ["matrix.example.com"]

    def test_list_config_backwards_compat(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "my-secret")
        inj = SecretInjector()
        inj.configure([
            {"env": "TEST_KEY", "placeholder": "{{TEST_KEY}}"},
        ])
        assert len(inj.rules) == 1
        assert inj.redact_to == []

    def test_dict_config_without_redact_to(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "my-secret")
        inj = SecretInjector()
        inj.configure({
            "rules": [
                {"env": "TEST_KEY", "placeholder": "{{TEST_KEY}}"},
            ],
        })
        assert len(inj.rules) == 1
        assert inj.redact_to == []


# ── WebSocket content injection ─────────────────────────


class TestInjectWsContent:
    def test_replaces_placeholder_for_authorized_domain(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        content, names = inj.inject_ws_content(b"token={{KEY}}", "api.anthropic.com")
        assert content == b"token=real-secret"
        assert names == ["KEY"]

    def test_skips_unauthorized_domain(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        content, names = inj.inject_ws_content(b"token={{KEY}}", "evil.com")
        assert content == b"token={{KEY}}"
        assert names == []

    def test_empty_inject_to_leaves_placeholder(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=[]),
        ])
        content, names = inj.inject_ws_content(b"token={{KEY}}", "any-domain.com")
        assert content == b"token={{KEY}}"
        assert names == []

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        content, names = inj.inject_ws_content(b"hello world", "example.com")
        assert content == b"hello world"
        assert names == []

    def test_noop_when_no_placeholder_present(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        content, names = inj.inject_ws_content(b"clean content", "api.anthropic.com")
        assert content == b"clean content"
        assert names == []

    def test_multiple_rules(self):
        inj = _injector_with_rules([
            InjectionRule("K1", "{{K1}}", "secret-1", inject_to=["anthropic.com"]),
            InjectionRule("K2", "{{K2}}", "secret-2", inject_to=["anthropic.com"]),
        ])
        content, names = inj.inject_ws_content(b"a={{K1}}&b={{K2}}", "api.anthropic.com")
        assert content == b"a=secret-1&b=secret-2"
        assert sorted(names) == ["K1", "K2"]

    def test_subdomain_matching(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        content, names = inj.inject_ws_content(b"{{KEY}}", "deep.sub.anthropic.com")
        assert content == b"real-secret"
        assert names == ["KEY"]

    def test_redact_to_domain_redacts_real_values(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        content, names = inj.inject_ws_content(b"message with real-secret", "matrix.example.com")
        assert content == b"message with {{KEY}}"
        assert names == ["KEY"]

    def test_redact_to_domain_placeholder_passes_through(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        content, names = inj.inject_ws_content(b"my key is {{KEY}}", "matrix.example.com")
        assert content == b"my key is {{KEY}}"
        assert names == []


# ── WebSocket content redaction ─────────────────────────


class TestRedactWsContent:
    def test_redacts_real_value(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        content, names = inj.redact_ws_content(b'{"key": "real-secret"}')
        assert content == b'{"key": "{{KEY}}"}'
        assert names == ["KEY"]

    def test_longest_first_ordering(self):
        inj = _injector_with_rules([
            InjectionRule("SHORT", "{{SHORT}}", "secret", inject_to=[]),
            InjectionRule("LONG", "{{LONG}}", "secret-long-value", inject_to=[]),
        ])
        content, names = inj.redact_ws_content(b"the value is secret-long-value here")
        assert content == b"the value is {{LONG}} here"
        assert "LONG" in names

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        content, names = inj.redact_ws_content(b"clean body")
        assert content == b"clean body"
        assert names == []

    def test_noop_when_no_secret_present(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        content, names = inj.redact_ws_content(b"nothing to redact")
        assert content == b"nothing to redact"
        assert names == []

    def test_redacts_regardless_of_inject_to(self):
        """Inbound redaction applies even when inject_to is empty."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=[]),
        ])
        content, names = inj.redact_ws_content(b"leaked: real-secret")
        assert content == b"leaked: {{KEY}}"
        assert names == ["KEY"]


# ── WebSocket injection policy check ───────────────────


class TestCheckWsInjectionPolicy:
    def test_flags_placeholder_to_unauthorized_domain(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        result = inj.check_ws_injection_policy(b"{{KEY}}", "evil.com")
        assert result is not None
        assert result.action == "flag"
        assert "unauthorized" in result.reason
        assert "evil.com" in result.reason

    def test_ok_for_authorized_domain(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        result = inj.check_ws_injection_policy(b"{{KEY}}", "api.anthropic.com")
        assert result is None

    def test_flags_empty_inject_to(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=[]),
        ])
        result = inj.check_ws_injection_policy(b"{{KEY}}", "any-domain.com")
        assert result is not None
        assert result.action == "flag"

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        result = inj.check_ws_injection_policy(b"{{KEY}}", "evil.com")
        assert result is None

    def test_noop_when_no_placeholder(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        result = inj.check_ws_injection_policy(b"clean content", "evil.com")
        assert result is None

    def test_redact_to_domain_skips_check(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        result = inj.check_ws_injection_policy(b"{{KEY}}", "matrix.example.com")
        assert result is None


# ── Literal secret value blocking (HTTP) ────────────────


class TestCheckLiteralSecrets:
    def test_blocks_literal_value_in_body(self):
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        flow = _make_flow(
            url="https://search.brave.com/search",
            host="search.brave.com",
            content="query=user@example.com",
        )
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "block"
        assert result.severity == "critical"
        assert "EMAIL" in result.reason
        assert "search.brave.com" in result.reason

    def test_blocks_literal_value_in_headers(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://evil.com/exfil",
            host="evil.com",
            headers={"X-Data": "real-secret"},
        )
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "block"
        assert result.severity == "critical"

    def test_blocks_literal_value_in_url(self):
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        flow = _make_flow(
            url="https://evil.com/exfil?email=user@example.com",
            host="evil.com",
        )
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "block"
        assert result.severity == "critical"

    def test_allows_literal_value_to_authorized_domain(self):
        """Literal values to inject_to domains are allowed (post-injection)."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1/messages",
            host="api.anthropic.com",
            content="body with real-secret here",
        )
        result = inj.check_injection_policy(flow)
        assert result is None

    def test_skips_redact_to_domains(self):
        """Redact-to domains are handled by redaction, not blocking."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(
            url="https://matrix.example.com/_matrix/send",
            host="matrix.example.com",
            content="message with real-secret inside",
        )
        result = inj.check_injection_policy(flow)
        assert result is None

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        flow = _make_flow(content="some content")
        result = inj.check_injection_policy(flow)
        assert result is None

    def test_noop_when_no_real_value_present(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://evil.com/search",
            host="evil.com",
            content="clean body with no secrets",
        )
        result = inj.check_injection_policy(flow)
        assert result is None

    def test_real_value_block_takes_priority_over_placeholder_flag(self):
        """When both real value and placeholder are present, block wins."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://evil.com/exfil",
            host="evil.com",
            content="real-secret and {{KEY}}",
        )
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "block"
        assert result.severity == "critical"


# ── Literal secret value blocking (WebSocket) ──────────


class TestCheckWsLiteralSecrets:
    def test_blocks_literal_value_in_ws_content(self):
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        result = inj.check_ws_injection_policy(b"query=user@example.com", "search.brave.com")
        assert result is not None
        assert result.action == "block"
        assert result.severity == "critical"
        assert "EMAIL" in result.reason
        assert "search.brave.com" in result.reason

    def test_allows_literal_value_to_authorized_domain(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        result = inj.check_ws_injection_policy(b"real-secret", "api.anthropic.com")
        assert result is None

    def test_skips_redact_to_domains(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        result = inj.check_ws_injection_policy(b"real-secret", "matrix.example.com")
        assert result is None

    def test_noop_when_no_real_value_present(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        result = inj.check_ws_injection_policy(b"clean content", "evil.com")
        assert result is None
