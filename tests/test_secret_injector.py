"""Tests for the SecretInjector."""

import os
from unittest.mock import MagicMock

import pytest

from secret_injector import SecretInjector, InjectionRule, AUTH_HEADER_KEYWORDS


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
        # Body injection only happens when inject_body=True.
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
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
        # URL injection only happens when inject_body=True.
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1?key={{KEY}}",
            host="api.anthropic.com",
        )
        names = inj.inject_request(flow)
        assert flow.request.url == "https://api.anthropic.com/v1?key=real-secret"
        assert names == ["KEY"]

    def test_strict_default_injects_credential_headers(self):
        """By default, injection is confined to credential-bearing headers —
        Authorization AND x-api-key (Anthropic) and friends — but never the
        URL, the body, or a header with no auth/key/token in its name."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1?key={{KEY}}",
            host="api.anthropic.com",
            headers={
                "Authorization": "Bearer {{KEY}}",
                "X-Api-Key": "{{KEY}}",        # Anthropic's auth header
                "X-Custom-Trace": "{{KEY}}",   # no auth/key/token → not a credential header
            },
            content="body with {{KEY}} here",
        )
        names = inj.inject_request(flow)
        # Both recognized auth headers get the real value...
        assert flow.request.headers["Authorization"] == "Bearer real-secret"
        assert flow.request.headers["X-Api-Key"] == "real-secret"
        # ...while the URL, body, and non-credential headers keep the placeholder.
        # (Note: the *query param* `?key=` is not a header, so it is untouched
        # even though "key" is a keyword — the heuristic only applies to headers.)
        assert flow.request.url == "https://api.anthropic.com/v1?key={{KEY}}"
        assert flow.request.headers["X-Custom-Trace"] == "{{KEY}}"
        assert flow.request.content == b"body with {{KEY}} here"
        assert names == ["KEY"]

    def test_strict_injects_x_api_key_regression(self):
        """Regression guard (PR #251): Anthropic authenticates with the
        ``x-api-key`` header, not ``Authorization``. The first strict
        implementation injected only into ``Authorization``, so the literal
        ``{{ANTHROPIC_API_KEY}}`` placeholder went upstream and the API
        replied ``401 invalid x-api-key``. Strict mode must inject into
        ``x-api-key`` (matched by the "key" keyword)."""
        inj = _injector_with_rules([
            InjectionRule("ANTHROPIC_API_KEY", "{{ANTHROPIC_API_KEY}}",
                          "sk-ant-real", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(headers={"x-api-key": "{{ANTHROPIC_API_KEY}}"})
        names = inj.inject_request(flow)
        assert flow.request.headers["x-api-key"] == "sk-ant-real"
        assert names == ["ANTHROPIC_API_KEY"]

    # Real-world credential headers that all match the auth/key/token
    # heuristic — surveyed across popular APIs. (Honeycomb's
    # ``x-honeycomb-team`` is intentionally absent: it has no keyword and is
    # covered by ``inject_headers`` instead — see test below.)
    @pytest.mark.parametrize("header", [
        "Authorization",            # OpenAI, GitHub, Stripe, … (auth)
        "x-api-key",                # Anthropic, AWS API Gateway (key)
        "api-key",                  # Azure OpenAI, Pinecone, Qdrant (key)
        "apikey",                   # Supabase (key)
        "x-goog-api-key",           # Google Gemini / Cloud (key)
        "PRIVATE-TOKEN",            # GitLab (token)
        "X-Auth-Token",             # OpenStack (auth, token)
        "X-Auth-Key",               # Cloudflare legacy (auth, key)
        "X-Subscription-Token",     # Brave Search (token)
        "Ocp-Apim-Subscription-Key",  # Azure APIM / Bing (key)
        "DD-API-KEY",               # Datadog (key)
        "Circle-Token",             # CircleCI (token)
        "X-Algolia-API-Key",        # Algolia (key)
        "X-Figma-Token",            # Figma (token)
        "Fastly-Key",               # Fastly (key)
        "X-Postmark-Server-Token",  # Postmark (token)
        "X-Shopify-Access-Token",   # Shopify Admin (token)
    ])
    def test_strict_injects_real_world_credential_headers(self, header):
        """The keyword heuristic injects into the documented auth header of
        popular APIs without naming any of them in code."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(headers={header: "{{KEY}}"})
        names = inj.inject_request(flow)
        assert flow.request.headers[header] == "real-secret"
        assert names == ["KEY"]

    @pytest.mark.parametrize("header,matches", [
        ("X-Brand-New-Token", True),     # token
        ("My-Secret-Key", True),         # key
        ("X-Custom-Auth", True),         # auth
        ("AUTHORIZATION", True),         # case-insensitive
        ("x-honeycomb-team", False),     # no keyword
        ("X-Trace-Id", False),
        ("Content-Type", False),
        ("X-Request-Id", False),
    ])
    def test_strict_keyword_heuristic(self, header, matches):
        """The heuristic injects into any header whose name contains
        auth/key/token (case-insensitive), and leaves all others alone — no
        vendor-specific names involved."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(headers={header: "{{KEY}}"})
        names = inj.inject_request(flow)
        if matches:
            assert flow.request.headers[header] == "real-secret"
            assert names == ["KEY"]
        else:
            assert flow.request.headers[header] == "{{KEY}}"
            assert names == []

    @pytest.mark.parametrize("keyword", AUTH_HEADER_KEYWORDS)
    def test_each_keyword_triggers_injection(self, keyword):
        """Every keyword stem on its own marks a header as credential-bearing."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        header = f"X-Custom-{keyword}"
        flow = _make_flow(headers={header: "{{KEY}}"})
        names = inj.inject_request(flow)
        assert flow.request.headers[header] == "real-secret"
        assert names == ["KEY"]

    def test_inject_headers_covers_keywordless_header(self):
        """A credential header whose name has no auth/key/token keyword (e.g.
        Honeycomb's ``x-honeycomb-team``) is injected only when listed in the
        rule's ``inject_headers`` — and the keyword defaults still apply."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["example.com"],
                          inject_headers=["X-Honeycomb-Team"]),
        ])
        flow = _make_flow(
            url="https://api.example.com/v1",
            host="api.example.com",
            headers={
                "X-Honeycomb-Team": "{{KEY}}",      # opted-in, no keyword
                "Authorization": "Bearer {{KEY}}",  # keyword default still applies
            },
        )
        names = inj.inject_request(flow)
        assert flow.request.headers["X-Honeycomb-Team"] == "real-secret"
        assert flow.request.headers["Authorization"] == "Bearer real-secret"
        assert names == ["KEY"]

    def test_strict_credential_header_to_unauthorized_domain(self):
        """The broadened header match must still defer to ``inject_to``: a
        placeholder in a credential header heading to an unauthorized domain
        is left in place (not injected) and is flagged by the policy check."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://evil.com/exfil",
            host="evil.com",
            headers={"x-api-key": "{{KEY}}"},
        )
        names = inj.inject_request(flow)
        assert flow.request.headers["x-api-key"] == "{{KEY}}"
        assert names == []
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "flag"
        assert "evil.com" in result.reason

    def test_strict_default_no_auth_header_is_noop(self):
        """Strict mode with no Authorization header injects nothing."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            host="api.anthropic.com",
            content="body with {{KEY}} here",
        )
        names = inj.inject_request(flow)
        assert flow.request.content == b"body with {{KEY}} here"
        assert names == []

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
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
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
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
            InjectionRule("EMAIL", "{{EMAIL}}", "user@example.com",
                          inject_to=["other.com"], inject_body=True),
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
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
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
            InjectionRule("KEY1", "{{KEY1}}", "secret-1",
                          inject_to=["anthropic.com"], inject_body=True),
            InjectionRule("KEY2", "{{KEY2}}", "secret-2",
                          inject_to=["anthropic.com"], inject_body=True),
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

    def test_loads_inject_headers(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "secret")
        inj = SecretInjector()
        inj.configure([
            {"env": "TEST_KEY", "placeholder": "{{TEST_KEY}}",
             "inject_headers": ["X-Honeycomb-Team"]},
        ])
        rule = inj.rules[0]
        assert rule.inject_headers == ["X-Honeycomb-Team"]
        # The keyword-less custom header is recognized (case-insensitively)...
        assert rule.is_auth_header("x-honeycomb-team")
        # ...and the keyword heuristic still applies on top of it.
        assert rule.is_auth_header("Authorization")
        assert rule.is_auth_header("x-api-key")

    def test_default_rule_has_no_extra_inject_headers(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "secret")
        inj = SecretInjector()
        inj.configure([{"env": "TEST_KEY", "placeholder": "{{TEST_KEY}}"}])
        rule = inj.rules[0]
        assert rule.inject_headers == []
        # With no extras, only the keyword heuristic decides.
        assert rule.is_auth_header("x-api-key")
        assert not rule.is_auth_header("x-honeycomb-team")

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

    def test_falls_back_to_file_when_env_missing(self, monkeypatch, tmp_path):
        """Apple-container backend stages secrets to a bind-mounted file
        dir rather than injecting them as env vars on the egress (no
        cleartext on `container inspect` / process listings). The
        injector must read from that file when the env var is empty,
        otherwise the addon silently no-ops and every outbound request
        sends the literal `{{PLACEHOLDER}}` upstream → 401. Regression
        guard against the 0.22.0 file-delivery refactor (PR #196).
        """
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "ANTHROPIC_API_KEY").write_text("sk-ant-real-1234\n")
        monkeypatch.setenv("AGENTCAGE_SECRETS_DIR", str(secrets_dir))
        # Module reads AGENTCAGE_SECRETS_DIR once at import time, so
        # reload it to pick up the test override.
        import importlib, secret_injector
        importlib.reload(secret_injector)
        inj = secret_injector.SecretInjector()
        inj.configure([
            {"env": "ANTHROPIC_API_KEY",
             "placeholder": "{{ANTHROPIC_API_KEY}}",
             "inject_to": ["anthropic.com"]},
        ])
        assert len(inj.rules) == 1
        # Trailing newline must be stripped — file delivery writes with
        # \n at the end on apple-container, and the on-wire header would
        # include the \n verbatim otherwise (breaks HTTP framing).
        assert inj.rules[0].real_value == "sk-ant-real-1234"

    def test_file_fallback_missing_file_still_skips(self, monkeypatch, tmp_path):
        """Env var missing AND no fallback file → rule is skipped (the
        original behavior). The fallback only fires when the file exists.
        """
        monkeypatch.delenv("MISSING_KEY", raising=False)
        monkeypatch.setenv("AGENTCAGE_SECRETS_DIR", str(tmp_path))
        import importlib, secret_injector
        importlib.reload(secret_injector)
        inj = secret_injector.SecretInjector()
        inj.configure([
            {"env": "MISSING_KEY", "placeholder": "{{MISSING_KEY}}"},
        ])
        assert len(inj.rules) == 0

    def test_staged_file_takes_precedence_over_env(self, monkeypatch, tmp_path):
        """When BOTH env and file are present, the staged file wins. The
        process env is frozen at container creation, so only the file can
        carry a live value change (`agentcage secret set` on a running
        cage re-stages the file and bumps the config mtime); preferring
        env would pin the boot-time value forever. The env remains the
        fallback when no file was staged (pre-staging cages, podman < 4.7)."""
        monkeypatch.setenv("DUAL_KEY", "from-env")
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "DUAL_KEY").write_text("from-file\n")
        monkeypatch.setenv("AGENTCAGE_SECRETS_DIR", str(secrets_dir))
        import importlib, secret_injector
        importlib.reload(secret_injector)
        inj = secret_injector.SecretInjector()
        inj.configure([
            {"env": "DUAL_KEY", "placeholder": "{{DUAL_KEY}}"},
        ])
        assert len(inj.rules) == 1
        assert inj.rules[0].real_value == "from-file"


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
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
        ])
        inj.redact_to = ["matrix.example.com"]
        flow = _make_flow(content="body with {{KEY}} here")
        names = inj.inject_request(flow)
        assert flow.request.content == b"body with real-secret here"
        assert names == ["KEY"]


# ── Post-upstream request redaction (capture-leak fix) ──
#
# ``inject_request`` mutates ``flow.request`` in place, substituting the
# real secret value into headers, URL, and body so the upstream sees the
# real key. Without a symmetric ``redact_request`` running BEFORE the
# capture writer serializes the flow, those real-value bytes land on
# disk in ``capture.jsonl`` — which is bind-mounted into the cage
# rootfs at mode 0644 (cage-readable). A cage workload can then
# ``grep sk- /var/log/agentcage/capture.jsonl`` and recover the live
# ``ANTHROPIC_API_KEY``, defeating the entire placeholder-injection
# trust model.
#
# ``redact_request`` is the inverse of ``inject_request``: AFTER the
# proxy has forwarded the mutated request upstream, it restores
# placeholder form on the in-memory flow so subsequent serialization
# (capture writer, addon logging) never sees the raw secret bytes.


class TestRedactRequestPostUpstream:
    def test_redacts_real_value_in_request_body(self):
        """Symmetric to ``inject_request``: a real value injected into
        the body is replaced with the placeholder."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "sk-real-secret",
                          inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(content="payload with sk-real-secret here")
        names = inj.redact_request(flow)
        assert flow.request.content == b"payload with {{KEY}} here"
        assert names == ["KEY"]

    def test_redacts_real_value_in_request_headers(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "sk-real-secret",
                          inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(headers={"Authorization": "Bearer sk-real-secret"})
        names = inj.redact_request(flow)
        assert flow.request.headers["Authorization"] == "Bearer {{KEY}}"
        assert names == ["KEY"]

    def test_redacts_real_value_in_request_url(self):
        """URL-injected secrets (query string) are also redacted."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "sk-real-secret",
                          inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1?key=sk-real-secret",
        )
        names = inj.redact_request(flow)
        assert flow.request.url == (
            "https://api.anthropic.com/v1?key={{KEY}}"
        )
        assert names == ["KEY"]

    def test_redacts_regardless_of_domain(self):
        """Post-upstream redaction applies to all destinations, not just
        ``inject_to``. The flow object is about to be serialized to disk
        — any real-value byte that made it there for any reason has to
        be scrubbed before the cage can read the file."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "sk-real-secret",
                          inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(
            url="https://other.com/api",
            host="other.com",
            content="leaked: sk-real-secret",
        )
        names = inj.redact_request(flow)
        assert flow.request.content == b"leaked: {{KEY}}"
        assert names == ["KEY"]

    def test_longest_first_ordering(self):
        """When one real value is a substring of another, the longer one
        is replaced first — same defensive ordering as ``redact_response``."""
        inj = _injector_with_rules([
            InjectionRule("SHORT", "{{SHORT}}", "secret", inject_to=[]),
            InjectionRule("LONG", "{{LONG}}", "secret-long-value",
                          inject_to=[]),
        ])
        flow = _make_flow(content="the value is secret-long-value here")
        names = inj.redact_request(flow)
        assert flow.request.content == b"the value is {{LONG}} here"
        assert "LONG" in names

    def test_noop_when_no_rules(self):
        inj = SecretInjector()
        flow = _make_flow(content="clean body")
        names = inj.redact_request(flow)
        assert flow.request.content == b"clean body"
        assert names == []

    def test_noop_when_no_real_value_present(self):
        """Body that doesn't contain any rule's real value isn't mutated."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "sk-real-secret",
                          inject_to=["anthropic.com"]),
        ])
        flow = _make_flow(content="no secret in here")
        names = inj.redact_request(flow)
        assert flow.request.content == b"no secret in here"
        assert names == []

    def test_inject_then_redact_round_trip(self):
        """Full round-trip: inject_request mutates → redact_request
        restores. After the pair, the flow looks placeholder-form again
        — exactly what the capture writer needs to see before serializing.
        """
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "sk-real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
        ])
        flow = _make_flow(
            url="https://api.anthropic.com/v1?k={{KEY}}",
            headers={"Authorization": "Bearer {{KEY}}"},
            content="{{KEY}} in body",
        )
        # Inject — real value substituted in all three places.
        injected = inj.inject_request(flow)
        assert injected == ["KEY"]
        assert "sk-real-secret" in flow.request.url
        assert flow.request.headers["Authorization"] == (
            "Bearer sk-real-secret"
        )
        assert flow.request.content == b"sk-real-secret in body"

        # Redact — placeholder restored everywhere.
        redacted = inj.redact_request(flow)
        assert redacted == ["KEY"]
        assert "sk-real-secret" not in flow.request.url
        assert "sk-real-secret" not in flow.request.headers["Authorization"]
        assert b"sk-real-secret" not in flow.request.content
        assert flow.request.url == "https://api.anthropic.com/v1?k={{KEY}}"
        assert flow.request.headers["Authorization"] == "Bearer {{KEY}}"
        assert flow.request.content == b"{{KEY}} in body"

    def test_capture_serializes_only_placeholders_after_redact(self, tmp_path):
        """End-to-end: snapshot_request AFTER inject+redact must contain
        only placeholders, never the real value. This is the load-bearing
        assertion — what actually lands in ``capture.jsonl``."""
        import json
        import sys
        from pathlib import Path
        # Stage the proxy/ dir on sys.path so ``from capture import
        # CaptureWriter`` resolves at runtime — same trick the addon
        # uses inside the cage.
        capture_src = (
            Path(__file__).resolve().parent.parent
            / "src" / "agentcage" / "data" / "proxy"
        )
        if str(capture_src) not in sys.path:
            sys.path.insert(0, str(capture_src))
        from capture import CaptureWriter  # type: ignore

        inj = _injector_with_rules([
            InjectionRule(
                "ANTHROPIC_API_KEY",
                "{{ANTHROPIC_API_KEY}}",
                "sk-ant-api03-FAKE-TEST-VALUE-FOR-REDACTION-1234567890",
                inject_to=["anthropic.com"],
                # This case puts the placeholder in the URL/body, so it
                # needs the opt-in body-injection path to inject+redact.
                inject_body=True,
            ),
        ])

        class _Headers(dict):
            # CaptureWriter.snapshot_request calls items(multi=True);
            # a plain dict's items() doesn't accept the kwarg.
            def items(self, multi=False):  # noqa: ARG002
                return list(super().items())

        flow = _make_flow(
            url="https://api.anthropic.com/v1/messages",
            content='{"key": "{{ANTHROPIC_API_KEY}}"}',
        )
        flow.request.headers = _Headers(
            {"x-api-key": "{{ANTHROPIC_API_KEY}}"},
        )

        # Wire shape: inject (real value goes out), THEN redact (in-memory
        # flow restored to placeholder form), THEN serialize.
        injected = inj.inject_request(flow)
        assert injected == ["ANTHROPIC_API_KEY"]

        redacted = inj.redact_request(flow)
        assert redacted == ["ANTHROPIC_API_KEY"]

        # Need an http_version attribute for snapshot_request — it reads
        # it directly. Real mitmproxy flows always have it; mock doesn't
        # autovalue meaningfully.
        flow.request.http_version = "HTTP/1.1"
        writer = CaptureWriter(
            {"max_body_size": 0}, str(tmp_path / "capture.jsonl"),
        )
        snap = writer.snapshot_request(flow)
        line = json.dumps(snap)
        assert "sk-ant-api03-FAKE-TEST-VALUE-FOR-REDACTION" not in line, (
            f"real-key bytes leaked into capture snapshot: {line!r}"
        )
        assert "{{ANTHROPIC_API_KEY}}" in line


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
        # WebSocket frames carry no headers (the auth channel), so injection
        # only happens when the rule opts into body injection.
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
        ])
        content, names = inj.inject_ws_content(b"token={{KEY}}", "api.anthropic.com")
        assert content == b"token=real-secret"
        assert names == ["KEY"]

    def test_strict_default_leaves_ws_placeholder(self):
        """Without inject_body, WebSocket placeholders are left untouched."""
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret", inject_to=["anthropic.com"]),
        ])
        content, names = inj.inject_ws_content(b"token={{KEY}}", "api.anthropic.com")
        assert content == b"token={{KEY}}"
        assert names == []

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
            InjectionRule("K1", "{{K1}}", "secret-1",
                          inject_to=["anthropic.com"], inject_body=True),
            InjectionRule("K2", "{{K2}}", "secret-2",
                          inject_to=["anthropic.com"], inject_body=True),
        ])
        content, names = inj.inject_ws_content(b"a={{K1}}&b={{K2}}", "api.anthropic.com")
        assert content == b"a=secret-1&b=secret-2"
        assert sorted(names) == ["K1", "K2"]

    def test_subdomain_matching(self):
        inj = _injector_with_rules([
            InjectionRule("KEY", "{{KEY}}", "real-secret",
                          inject_to=["anthropic.com"], inject_body=True),
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


# ── Transform-driven rules ──────────────────────────────


class TestTransformRules:
    """Rules with transform_fn substitute a derived value at request time
    instead of the static real_value, and treat the underlying real_value
    as 'never legitimately on the wire' (block everywhere)."""

    def test_inject_calls_transform_fn(self):
        called = []

        def _mint():
            called.append(True)
            return "ya29.fresh-token"

        rule = InjectionRule(
            "GOOGLE_SA_KEY", "{{GOOGLE_BEARER}}", "PLAINTEXT_SA_KEY_BYTES",
            inject_to=["googleapis.com"],
            transform="google-jwt-bearer",
            transform_fn=_mint,
        )
        inj = _injector_with_rules([rule])
        flow = _make_flow(
            url="https://gmail.googleapis.com/gmail/v1/users/me/profile",
            host="gmail.googleapis.com",
            headers={"Authorization": "Bearer {{GOOGLE_BEARER}}"},
        )
        names = inj.inject_request(flow)
        assert flow.request.headers["Authorization"] == "Bearer ya29.fresh-token"
        assert names == ["GOOGLE_SA_KEY"]
        assert called == [True]

    def test_transform_fn_failure_leaves_placeholder(self):
        def _broken():
            raise RuntimeError("oauth endpoint down")

        rule = InjectionRule(
            "GOOGLE_SA_KEY", "{{GOOGLE_BEARER}}", "PLAINTEXT_SA_KEY_BYTES",
            inject_to=["googleapis.com"],
            transform="google-jwt-bearer",
            transform_fn=_broken,
        )
        inj = _injector_with_rules([rule])
        flow = _make_flow(
            url="https://gmail.googleapis.com/gmail/v1/users/me/profile",
            host="gmail.googleapis.com",
            headers={"Authorization": "Bearer {{GOOGLE_BEARER}}"},
        )
        names = inj.inject_request(flow)
        # Placeholder is left in place; cage's request will fail at Google
        # with an unauthenticated response, which is the safe outcome.
        assert flow.request.headers["Authorization"] == "Bearer {{GOOGLE_BEARER}}"
        assert names == []

    def test_raw_secret_blocked_even_to_authorized_domain(self):
        """For transform rules, the underlying real_value (e.g. SA key
        bytes) must never appear on the wire — not even to inject_to
        domains. This catches any accident where the cage gets hold of
        the raw key and tries to use it directly."""
        rule = InjectionRule(
            "GOOGLE_SA_KEY", "{{GOOGLE_BEARER}}", "PLAINTEXT_SA_KEY_BYTES",
            inject_to=["googleapis.com"],
            transform="google-jwt-bearer",
            transform_fn=lambda: "ya29.x",
        )
        inj = _injector_with_rules([rule])
        flow = _make_flow(
            url="https://gmail.googleapis.com/gmail/v1/users/me/profile",
            host="gmail.googleapis.com",
            content="here is the key: PLAINTEXT_SA_KEY_BYTES",
        )
        result = inj.check_injection_policy(flow)
        assert result is not None
        assert result.action == "block"
        assert result.severity == "critical"
        assert "GOOGLE_SA_KEY" in result.reason

    def test_static_rule_still_allows_real_value_to_inject_to(self):
        """Sanity: the inject_to-allow shortcut still applies for non-
        transform rules. Otherwise we'd have broken existing behavior."""
        rule = InjectionRule(
            "ANTHROPIC", "{{ANTHROPIC}}", "real-secret",
            inject_to=["anthropic.com"],
        )
        inj = _injector_with_rules([rule])
        flow = _make_flow(
            url="https://api.anthropic.com/v1/messages",
            host="api.anthropic.com",
            content="body with real-secret",
        )
        result = inj.check_injection_policy(flow)
        assert result is None

    def test_ws_inject_calls_transform_fn(self):
        rule = InjectionRule(
            "GOOGLE_SA_KEY", "{{GOOGLE_BEARER}}", "PLAINTEXT_SA_KEY_BYTES",
            inject_to=["googleapis.com"],
            transform="google-jwt-bearer",
            transform_fn=lambda: "ya29.ws-token",
            inject_body=True,
        )
        inj = _injector_with_rules([rule])
        content, names = inj.inject_ws_content(
            b"token={{GOOGLE_BEARER}}", "googleapis.com"
        )
        assert content == b"token=ya29.ws-token"
        assert names == ["GOOGLE_SA_KEY"]

    def test_ws_raw_secret_blocked_to_inject_to(self):
        rule = InjectionRule(
            "GOOGLE_SA_KEY", "{{GOOGLE_BEARER}}", "PLAINTEXT_SA_KEY_BYTES",
            inject_to=["googleapis.com"],
            transform="google-jwt-bearer",
            transform_fn=lambda: "ya29.x",
        )
        inj = _injector_with_rules([rule])
        result = inj.check_ws_injection_policy(
            b"raw key: PLAINTEXT_SA_KEY_BYTES", "googleapis.com"
        )
        assert result is not None
        assert result.action == "block"


# ── Configure with transform from rule list ─────────────


class TestConfigureWithTransform:
    def test_configure_loads_transform(self, monkeypatch):
        """Walk the configure() path end-to-end with a fake transform so
        we don't need cryptography or a real SA key."""
        # Register a deterministic stub transform.
        from transforms import register, _REGISTRY

        class _StubTransform:
            instances = []

            def __init__(self, secret, config):
                self.secret = secret
                self.config = config
                _StubTransform.instances.append(self)

            def get_value(self):
                return f"derived-from-{self.secret}"

        register("test-stub", _StubTransform)
        try:
            monkeypatch.setenv("FAKE_KEY", "raw-key-bytes")
            inj = SecretInjector()
            inj.configure([
                {
                    "env": "FAKE_KEY",
                    "placeholder": "{{FAKE}}",
                    "inject_to": ["example.com"],
                    "transform": "test-stub",
                    "transform_config": {"option": "v"},
                },
            ])
            assert len(inj.rules) == 1
            r = inj.rules[0]
            assert r.transform == "test-stub"
            assert r.transform_fn is not None
            assert r.transform_fn() == "derived-from-raw-key-bytes"
            assert _StubTransform.instances[0].config == {"option": "v"}
        finally:
            _REGISTRY.pop("test-stub", None)

    def test_configure_skips_rule_when_transform_init_fails(
        self, monkeypatch, caplog
    ):
        from transforms import register, _REGISTRY

        class _Broken:
            def __init__(self, secret, config):
                raise RuntimeError("bad config")

            def get_value(self):
                return ""

        register("test-broken", _Broken)
        try:
            monkeypatch.setenv("FAKE_KEY", "raw-key-bytes")
            inj = SecretInjector()
            inj.configure([
                {
                    "env": "FAKE_KEY",
                    "placeholder": "{{FAKE}}",
                    "inject_to": ["example.com"],
                    "transform": "test-broken",
                },
            ])
            assert len(inj.rules) == 0
        finally:
            _REGISTRY.pop("test-broken", None)


# ── Basic-auth (base64) injection / redaction — git over HTTPS ──────────────
#
# git sends `Authorization: Basic base64("x-access-token:<secret>")`, so the
# placeholder/secret never appears verbatim in the header. These tests guard
# the base64-aware path that lets git-over-HTTPS auth work (regression: the
# literal-only matcher injected for api.github.com `token`/`Bearer` but not for
# github.com git endpoints, so private `git pull` failed with "invalid
# credentials").

import base64 as _b64

from secret_injector import _rewrite_basic_auth


def _basic(userinfo: str) -> str:
    return "Basic " + _b64.b64encode(userinfo.encode()).decode()


def _decode_basic(value: str) -> str:
    return _b64.b64decode(value.split(" ", 1)[1]).decode()


def _gh_rule(placeholder="agentcage:secret:GH_TOKEN:deadbeef",
             real="ghp_realtokenvalue000000000000000000000000"):
    return InjectionRule(
        name="GH_TOKEN", placeholder=placeholder, real_value=real,
        inject_to=["github.com"],
    )


class TestRewriteBasicAuthHelper:
    def test_substitutes_inside_basic(self):
        rule = _gh_rule()
        v = _basic(f"x-access-token:{rule.placeholder}")
        out, changed = _rewrite_basic_auth(v, rule.placeholder, rule.real_value)
        assert changed is True
        assert _decode_basic(out) == f"x-access-token:{rule.real_value}"

    def test_non_basic_unchanged(self):
        v = f"Bearer agentcage:secret:GH_TOKEN:deadbeef"
        out, changed = _rewrite_basic_auth(v, "agentcage:secret:GH_TOKEN:deadbeef", "X")
        assert (out, changed) == (v, False)

    def test_invalid_base64_unchanged(self):
        v = "Basic not!!base64!!"
        out, changed = _rewrite_basic_auth(v, "anything", "X")
        assert (out, changed) == (v, False)

    def test_needle_absent_unchanged(self):
        v = _basic("user:somethingelse")
        out, changed = _rewrite_basic_auth(v, "agentcage:secret:GH_TOKEN:deadbeef", "X")
        assert (out, changed) == (v, False)


class TestBasicAuthInjection:
    def test_injects_into_basic_auth_header(self):
        rule = _gh_rule()
        inj = _injector_with_rules([rule])
        flow = _make_flow(
            url="https://github.com/TrueLayer/repo.git/info/refs",
            host="github.com",
            headers={"Authorization": _basic(f"x-access-token:{rule.placeholder}")},
        )
        names = inj.inject_request(flow)
        assert names == ["GH_TOKEN"]
        assert _decode_basic(flow.request.headers["Authorization"]) == (
            f"x-access-token:{rule.real_value}"
        )

    def test_bearer_literal_path_still_works(self):
        rule = _gh_rule()
        inj = _injector_with_rules([rule])
        flow = _make_flow(
            url="https://github.com/x", host="github.com",
            headers={"Authorization": f"token {rule.placeholder}"},
        )
        names = inj.inject_request(flow)
        assert names == ["GH_TOKEN"]
        assert flow.request.headers["Authorization"] == f"token {rule.real_value}"

    def test_unauthorized_domain_not_injected(self):
        rule = _gh_rule()
        inj = _injector_with_rules([rule])
        ph_header = _basic(f"x-access-token:{rule.placeholder}")
        flow = _make_flow(
            url="https://evil.example/x", host="evil.example",
            headers={"Authorization": ph_header},
        )
        names = inj.inject_request(flow)
        assert names == []
        assert flow.request.headers["Authorization"] == ph_header  # untouched


class TestBasicAuthRedaction:
    def test_redact_request_scrubs_basic_auth(self):
        # After injection the real token rides base64-encoded in the Basic
        # header; redact_request must restore placeholder form so capture.jsonl
        # never serializes the raw token (even base64-encoded).
        rule = _gh_rule()
        inj = _injector_with_rules([rule])
        flow = _make_flow(
            url="https://github.com/x", host="github.com",
            headers={"Authorization": _basic(f"x-access-token:{rule.real_value}")},
        )
        names = inj.redact_request(flow)
        assert names == ["GH_TOKEN"]
        assert _decode_basic(flow.request.headers["Authorization"]) == (
            f"x-access-token:{rule.placeholder}"
        )
