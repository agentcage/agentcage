"""Tests for the ``policy_api:`` config section — parsing + validation.

These exercise the config schema committed in M1 of the Policy API design
(``docs/explain/policy-api.md``): ``PolicyApiConfig`` and its sub-configs,
``effective_never_grant()``, ``load_config`` stripping of the decision-hook
auth secret from the cage env, and every ``validate_config`` rule. They do
NOT exercise any runtime behavior — that lives in
``tests/test_policy_api_grants.py``.

Style mirrors ``tests/test_config.py``: configs are written to temp files and
loaded with ``load_config``; validation is driven through ``validate_config``.
"""

import textwrap

import pytest

from agentcage.config import load_config, validate_config


# ── Helpers ──────────────────────────────────────────────


def _write(tmp_path, body, *, env=None, podman_secrets=None):
    """Write a cage.yaml. The minimal skeleton is provided; ``body`` is the
    extra YAML to append (typically a ``policy_api:`` section, already at
    column 0)."""
    lines = [
        "name: test",
        "dns_servers: [1.1.1.1]",
        "container:",
        "  image: test:latest",
    ]
    if podman_secrets:
        lines.append("  podman_secrets:")
        for s in podman_secrets:
            lines.append(f"    - {s}")
    if env:
        lines.append("  env:")
        for k, v in env.items():
            lines.append(f"    {k}: {v}")
    text = "\n".join(lines) + "\n"
    if body:
        text += body
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return str(p)


def _allowlist(extra=None):
    """A domains.allow baseline so policy_api.request can validate (it
    requires allowlist mode). Built without textwrap so multi-item lists keep
    correct indentation."""
    allows = ["github.com"]
    if extra:
        allows.append(extra)
    items = "\n".join("    - " + d for d in allows)
    return "domains:\n  allow:\n" + items + "\n"


def _enabled_webhook(
    url="https://approver.example.com/hook",
    *,
    auth_source=None,
    fail_open=None,
    never_grant=None,
    require_allowlist_mode=None,
    max_grants=None,
    ttl_seconds=None,
    host=None,
):
    """A full enabled policy_api block with the webhook provider, correctly
    nested. Optional kwargs add fields at the right nesting level."""
    out = ["policy_api:", "  enable: true"]
    if host is not None:
        out.append("  host: " + host)
    out.append("  request:")
    out.append("    enable: true")
    grant_lines = []
    if never_grant is not None:
        grant_lines.append("        never_grant: [" + ", ".join(never_grant) + "]")
    if require_allowlist_mode is not None:
        grant_lines.append("        require_allowlist_mode: " + str(require_allowlist_mode))
    if max_grants is not None:
        grant_lines.append("        max_grants: " + str(max_grants))
    if ttl_seconds is not None:
        grant_lines.append("        ttl_seconds: " + str(ttl_seconds))
    if grant_lines:
        out.append("    grant:")
        out.extend(grant_lines)
    out.append("    decision:")
    out.append("      provider: webhook")
    out.append("      webhook:")
    out.append("        url: " + url)
    if auth_source is not None:
        out.append("        auth_source: " + auth_source)
    if fail_open is not None:
        out.append("      fail_open: " + str(fail_open))
    return "\n".join(out) + "\n"


def _enabled_llm(provider="anthropic", model="claude-sonnet-4-5", auth_source="env:POLICY_LLM_KEY"):
    # The committed validator requires an LLM auth_source (the evaluator's own
    # API key, an egress-only secret) — see BUG note in TestLlmProvider. Tests
    # that need to omit it pass auth_source="".
    out = [
        "policy_api:",
        "  enable: true",
        "  request:",
        "    enable: true",
        "    decision:",
        "      provider: llm",
        "      llm:",
        "        provider: " + provider,
    ]
    if auth_source:
        out.append("        auth_source: " + auth_source)
    if model:
        out.append("        model: " + model)
    return "\n".join(out) + "\n"


def _enabled_provider_unknown(provider):
    out = [
        "policy_api:",
        "  enable: true",
        "  request:",
        "    enable: true",
        "    decision:",
        "      provider: " + provider,
    ]
    return "\n".join(out) + "\n"


def _enabled_no_url():
    out = [
        "policy_api:",
        "  enable: true",
        "  request:",
        "    enable: true",
        "    decision:",
        "      provider: webhook",
        "      webhook: {}",
    ]
    return "\n".join(out) + "\n"


def _blocklist_policy(require_allowlist_mode=None):
    block = "domains:\n  block:\n    - evil.com\n"
    out = [
        "policy_api:",
        "  enable: true",
        "  request:",
        "    enable: true",
    ]
    if require_allowlist_mode is not None:
        out.append("    grant:")
        out.append("      require_allowlist_mode: " + str(require_allowlist_mode))
    out.append("    decision:")
    out.append("      provider: webhook")
    out.append("      webhook:")
    out.append("        url: https://approver.example.com/hook")
    return block + "\n".join(out) + "\n"


def _host_body(host):
    out = [
        "policy_api:",
        "  enable: true",
        "  host: " + host,
        "  request:",
        "    enable: true",
        "    decision:",
        "      provider: webhook",
        "      webhook:",
        "        url: https://approver.example.com/hook",
    ]
    return _allowlist() + "\n".join(out) + "\n"


# ── Omitted section (silent no-op) ────────────────────────


class TestOmitted:
    def test_disabled_by_default(self, tmp_path):
        cfg = load_config(_write(tmp_path, ""))
        assert cfg.policy_api.enable is False

    def test_no_policy_warnings(self, tmp_path):
        cfg = load_config(_write(tmp_path, ""))
        warnings = validate_config(cfg)
        assert not any("policy_api" in w for w in warnings)

    def test_defaults_when_omitted(self, tmp_path):
        cfg = load_config(_write(tmp_path, ""))
        pa = cfg.policy_api
        assert pa.host == "agentcage.local"
        assert pa.introspection.enable is True
        assert pa.request.enable is True
        assert pa.request.decision.provider == "webhook"
        assert pa.request.grant.ttl_seconds == 3600
        assert pa.request.grant.max_grants == 32
        assert pa.request.grant.require_allowlist_mode is True


# ── Minimal enabled webhook config ───────────────────────


class TestWebhookParse:
    def test_minimal_enabled(self, tmp_path):
        body = _allowlist() + _enabled_webhook(auth_source="env:POLICY_HOOK_TOKEN")
        cfg = load_config(_write(
            tmp_path, body, env={"POLICY_HOOK_TOKEN": "tok"},
        ))
        pa = cfg.policy_api
        assert pa.enable is True
        assert pa.request.decision.provider == "webhook"
        assert pa.request.decision.webhook.url == "https://approver.example.com/hook"
        assert pa.request.decision.webhook.auth_source == "env:POLICY_HOOK_TOKEN"

    def test_effective_never_grant_includes_builtins(self, tmp_path):
        body = _allowlist() + _enabled_webhook()
        cfg = load_config(_write(tmp_path, body))
        ng = cfg.policy_api.effective_never_grant()
        assert "agentcage.local" in ng
        assert "internal" in ng
        assert "local" in ng
        assert "localhost" in ng

    def test_https_url_validates_clean(self, tmp_path):
        body = _allowlist() + _enabled_webhook()
        cfg = load_config(_write(tmp_path, body))
        validate_config(cfg)  # must not raise

    def test_loopback_http_ok(self, tmp_path):
        body = _allowlist() + _enabled_webhook(url="http://127.0.0.1:9999/x")
        cfg = load_config(_write(tmp_path, body))
        validate_config(cfg)  # must not raise

    def test_no_url_raises(self, tmp_path):
        body = _allowlist() + _enabled_no_url()
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="webhook.url"):
            validate_config(cfg)

    def test_http_non_loopback_raises(self, tmp_path):
        body = _allowlist() + _enabled_webhook(url="http://approver.example.com/x")
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="loopback"):
            validate_config(cfg)

    def test_bad_url_scheme_raises(self, tmp_path):
        body = _allowlist() + _enabled_webhook(url="ftp://example.com/x")
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="absolute http"):
            validate_config(cfg)


# ── auth_source validation ───────────────────────────────


class TestAuthSource:
    def test_bad_scheme_raises(self, tmp_path):
        body = _allowlist() + _enabled_webhook(auth_source="bogus:TOKEN")
        with pytest.raises(ValueError, match="unknown secret source scheme"):
            load_config(_write(
                tmp_path, body, env={"TOKEN": "x"},
            ))


# ── decision provider ────────────────────────────────────


class TestDecisionProvider:
    def test_unknown_provider_raises(self, tmp_path):
        body = _allowlist() + _enabled_provider_unknown("carrier-pigeon")
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="must be 'webhook' or 'llm'"):
            validate_config(cfg)


# ── blocklist mode interactions ────────────────────────────


class TestBlocklistMode:
    def test_blocklist_default_raises(self, tmp_path):
        cfg = load_config(_write(tmp_path, _blocklist_policy()))
        with pytest.raises(ValueError, match="allowlist mode"):
            validate_config(cfg)

    def test_blocklist_optout_warns_but_no_error(self, tmp_path):
        cfg = load_config(_write(
            tmp_path, _blocklist_policy(require_allowlist_mode=False),
        ))
        warnings = validate_config(cfg)  # must not raise
        assert any("blocklist" in w for w in warnings)


# ── control host validation ──────────────────────────────


class TestControlHost:
    def test_collision_with_allow_raises(self, tmp_path):
        body = _allowlist(extra="agentcage.local") + _enabled_webhook()
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="must not appear in"):
            validate_config(cfg)

    def test_bare_label_raises(self, tmp_path):
        cfg = load_config(_write(tmp_path, _host_body("agentcage")))
        with pytest.raises(ValueError, match="dotted hostname"):
            validate_config(cfg)

    @pytest.mark.xfail(
        reason="BUG (committed M1 code): policy_api.host validation claims to "
               "reject IP literals (code comment: 'not an IP literal') but the "
               "regex ^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$ plus the '.' in host "
               "check is satisfied by any dotted IPv4 literal (10.0.0.1, "
               "169.254.169.254). Design §3.6 requires IP literals rejected.",
        strict=True,
    )
    def test_ip_literal_raises(self, tmp_path):
        cfg = load_config(_write(tmp_path, _host_body("10.0.0.1")))
        with pytest.raises(ValueError, match="dotted hostname"):
            validate_config(cfg)


# ── llm provider ──────────────────────────────────────────


class TestLlmProvider:
    # NOTE: the committed validator REQUIRES llm.auth_source (the evaluator's
    # own API key, separate from webhook auth_source) — stricter than the
    # design doc, which lists it as optional. We supply it so the "valid llm"
    # cases pass; that strictness is a design-doc divergence, not a bug per se.

    @pytest.mark.xfail(
        reason="BUG (committed M1 code): the llm provider branch validates "
               "provider/model/auth_source but never appends the 'follow-up "
               "(not implemented in v1)' warning the design doc §3.6 and the "
               "task spec require. A valid llm config currently yields ZERO "
               "policy_api warnings.",
        strict=True,
    )
    def test_valid_llm_warns_followup(self, tmp_path):
        cfg = load_config(_write(
            tmp_path,
            _allowlist() + _enabled_llm(),
            env={"POLICY_LLM_KEY": "k"},
        ))
        warnings = validate_config(cfg)  # must not raise
        assert any("follow-up" in w for w in warnings)

    def test_unknown_llm_provider_raises(self, tmp_path):
        cfg = load_config(_write(
            tmp_path, _allowlist() + _enabled_llm(provider="grok"),
            env={"POLICY_LLM_KEY": "k"},
        ))
        with pytest.raises(ValueError, match="llm.provider must be"):
            validate_config(cfg)

    def test_missing_model_raises(self, tmp_path):
        cfg = load_config(_write(
            tmp_path, _allowlist() + _enabled_llm(model=""),
            env={"POLICY_LLM_KEY": "k"},
        ))
        with pytest.raises(ValueError, match="llm.model is required"):
            validate_config(cfg)


# ── fail_open ─────────────────────────────────────────────


class TestFailOpen:
    def test_fail_open_warns(self, tmp_path):
        body = _allowlist() + _enabled_webhook(fail_open=True)
        cfg = load_config(_write(tmp_path, body))
        warnings = validate_config(cfg)
        assert any("fail_open" in w for w in warnings)


# ── numeric bounds ───────────────────────────────────────


class TestNumericBounds:
    def test_negative_max_grants_raises(self, tmp_path):
        body = _allowlist() + _enabled_webhook(max_grants=-1)
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="max_grants must be >= 0"):
            validate_config(cfg)

    def test_negative_ttl_raises(self, tmp_path):
        body = _allowlist() + _enabled_webhook(ttl_seconds=-10)
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="ttl_seconds must be >= 0"):
            validate_config(cfg)


# ── operator never_grant union ────────────────────────────


class TestNeverGrantUnion:
    def test_operator_entries_unioned(self, tmp_path):
        body = _allowlist() + _enabled_webhook(
            never_grant=["metadata.aws", "evil.internal"],
        )
        cfg = load_config(_write(tmp_path, body))
        ng = cfg.policy_api.effective_never_grant()
        assert "metadata.aws" in ng
        assert "evil.internal" in ng
        assert "agentcage.local" in ng
        assert "internal" in ng


# ── proxy-config subset membership ─────────────────────────


class TestProxyConfigSubset:
    def test_policy_api_in_proxy_keys(self):
        from agentcage.state import _PROXY_KEYS
        assert "policy_api" in _PROXY_KEYS


# ── decision-hook auth secret stripping ───────────────────


class TestSecretStripping:
    def test_auth_source_env_stripped_from_cage_env(self, tmp_path):
        body = _allowlist() + _enabled_webhook(auth_source="env:POLICY_HOOK_TOKEN")
        cfg = load_config(_write(
            tmp_path, body, env={"POLICY_HOOK_TOKEN": "tok", "KEEP_ME": "yes"},
        ))
        assert "POLICY_HOOK_TOKEN" not in cfg.container.env
        assert "KEEP_ME" in cfg.container.env

    def test_auth_source_stripped_from_podman_secrets(self, tmp_path):
        body = _allowlist() + _enabled_webhook(auth_source="env:POLICY_HOOK_TOKEN")
        cfg = load_config(_write(
            tmp_path,
            body,
            env={"POLICY_HOOK_TOKEN": "tok"},
            podman_secrets=["POLICY_HOOK_TOKEN", "KEEP_SECRET"],
        ))
        assert "POLICY_HOOK_TOKEN" not in cfg.container.podman_secrets
        assert "KEEP_SECRET" in cfg.container.podman_secrets
