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
        inj.inject_request(flow)
        assert flow.request.content == b"body with real-secret here"

    def test_replaces_placeholder_in_headers(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(headers={"Authorization": "Bearer {{KEY}}"})
        inj.inject_request(flow)
        assert flow.request.headers["Authorization"] == "Bearer real-secret"

    def test_replaces_placeholder_in_url(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1?key={{KEY}}",
            host="api.anthropic.com",
        )
        inj.inject_request(flow)
        assert flow.request.url == "https://api.anthropic.com/v1?key=real-secret"

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
        inj.inject_request(flow)
        assert flow.request.content == b"body with {{KEY}} here"

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
        inj.inject_request(flow)
        assert flow.request.content == b"key=real-secret&email={{EMAIL}}"

    def test_no_inject_to_injects_everywhere(self):
        inj = _injector_with_rules([
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com", inject_to=[]),
        ])
        flow = _make_flow(
            url="https://any-domain.com/api",
            host="any-domain.com",
            content="contact: {{EMAIL}}",
        )
        inj.inject_request(flow)
        assert flow.request.content == b"contact: user@example.com"

    def test_subdomain_matches_inject_to(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1",
            host="api.anthropic.com",
            content="{{KEY}}",
        )
        inj.inject_request(flow)
        assert flow.request.content == b"real-secret"

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        flow = _make_flow(content="no placeholders")
        inj.inject_request(flow)
        assert flow.request.content == b"no placeholders"

    def test_noop_when_no_placeholder_present(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(content="clean body with no placeholders")
        inj.inject_request(flow)
        assert flow.request.content == b"clean body with no placeholders"

    def test_multiple_rules(self):
        inj = _injector_with_rules([
            InjectionRule("KEY1", "{{KEY1}}", "secret-1", inject_to=["anthropic.com"]),
            InjectionRule("KEY2", "{{KEY2}}", "secret-2", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(content="a={{KEY1}}&b={{KEY2}}")
        inj.inject_request(flow)
        assert flow.request.content == b"a=secret-1&b=secret-2"


# ── Response redaction ───────────────────────────────────


class TestRedactResponse:
    def test_redacts_real_value_in_body(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_response_flow(resp_content='{"key": "real-secret"}')
        inj.redact_response(flow)
        assert flow.response.content == b'{"key": "{{KEY}}"}'

    def test_redacts_real_value_in_headers(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_response_flow(resp_headers={"X-Key": "real-secret"})
        inj.redact_response(flow)
        assert flow.response.headers["X-Key"] == "{{KEY}}"

    def test_longest_first_ordering(self):
        """When one real value is a substring of another, the longer one
        should be replaced first to avoid partial matches."""
        inj = _injector_with_rules([
            InjectionRule("SHORT", "{{SHORT}}", "secret", inject_to=[]),
            InjectionRule("LONG", "{{LONG}}", "secret-long-value", inject_to=[]),
        ])
        flow = _make_response_flow(resp_content="the value is secret-long-value here")
        inj.redact_response(flow)
        assert flow.response.content == b"the value is {{LONG}} here"

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        flow = _make_response_flow(resp_content="clean body")
        inj.redact_response(flow)
        assert flow.response.content == b"clean body"

    def test_noop_when_no_response(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret"),
        ])
        flow = _make_flow(content="irrelevant")
        flow.response = None
        inj.redact_response(flow)  # should not raise

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
        inj.redact_response(flow)
        assert flow.response.content == b"leaked: {{KEY}}"


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
        inj.inject_request(flow)
        assert flow.request.content == b"message with {{KEY}} inside"

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
        inj.inject_request(flow)
        assert flow.request.headers["Authorization"] == "Bearer {{KEY}}"

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
        inj.inject_request(flow)
        assert flow.request.content == b"my key is {{KEY}}"

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
        inj.inject_request(flow)
        assert flow.request.content == b"value is {{KEY}}"

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
        inj.inject_request(flow)
        # Placeholder passes through, NOT replaced with real value
        assert flow.request.content == b"contact: {{EMAIL}}"

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
        inj.inject_request(flow)
        assert flow.request.content == b"contact: {{EMAIL}}"

    def test_non_redact_domain_still_injects(self):
        """Normal inject_to behavior unchanged for non-redact_to domains."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(content="body with {{KEY}} here")
        inj.inject_request(flow)
        assert flow.request.content == b"body with real-secret here"


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
