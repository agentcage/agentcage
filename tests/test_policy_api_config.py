"""Tests for the ``domains.auto`` config section — parsing + validation.

Exercises the config schema for auto-managed allowlists: ``DomainsAutoConfig``
and its sub-configs, ``effective_never_grant()``, ``load_config`` stripping of
the decider agent's API key from the cage env, and every ``validate_config``
rule. No runtime behavior here — that lives in ``test_policy_api_grants.py``.

Style mirrors ``tests/test_config.py``: configs are written to temp files and
loaded with ``load_config``; validation is driven through ``validate_config``.
"""

import pytest

from agentcage.config import load_config, validate_config


# ── Helpers ──────────────────────────────────────────────


def _write(tmp_path, body, *, env=None, podman_secrets=None):
    """Write a cage.yaml. ``body`` is the extra YAML to append (the
    ``domains:`` block, already at column 0)."""
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


def _domains(allow=("github.com",), auto_body=""):
    """A ``domains:`` block with an allowlist baseline (+ optional auto body).

    The auto body is indented under ``auto:`` so callers just pass the
    decider/agent lines.
    """
    allows = list(allow) if allow else []
    items = "\n".join("    - " + d for d in allows) if allows else "    []"
    out = ["domains:", "  allow:", items]
    if auto_body:
        out.append("  auto:")
        for line in auto_body.splitlines():
            out.append("    " + line if line else line)
    return "\n".join(out) + "\n"


def _agent_decider(provider="openrouter", model="anthropic/claude-sonnet-4-5",
                   api_key="env:POLICY_LLM_KEY", timeout=None, base_url=None):
    """The decider block (kind: agent) lines, flat under decider:."""
    out = [
        "decider:",
        "  kind: agent",
        "  provider: " + provider,
    ]
    if model:
        out.append("  model: " + model)
    if api_key:
        out.append("  api_key: " + api_key)
    if timeout is not None:
        out.append("  timeout_seconds: " + str(timeout))
    if base_url is not None:
        out.append("  base_url: " + base_url)
    return "\n".join(out)


def _enabled(auto_body, allow=("github.com",)):
    """A full enabled domains.auto block (allowlist + auto)."""
    return _domains(allow=allow, auto_body="enable: true\n" + auto_body)


# ── Omitted section (silent no-op) ────────────────────────


class TestOmitted:
    def test_disabled_by_default(self, tmp_path):
        cfg = load_config(_write(tmp_path, ""))
        assert cfg.domains.auto.enable is False

    def test_no_auto_warnings(self, tmp_path):
        cfg = load_config(_write(tmp_path, ""))
        warnings = validate_config(cfg)
        assert not any("auto" in w for w in warnings)

    def test_defaults_when_omitted(self, tmp_path):
        cfg = load_config(_write(tmp_path, ""))
        auto = cfg.domains.auto
        assert auto.host == "agentcage.local"
        assert auto.decider.kind == "agent"
        assert auto.rate_limit_rps == 1.0
        assert auto.rate_limit_burst == 5


# ── Minimal enabled agent config ────────────────────────


class TestAgentParse:
    def test_minimal_enabled(self, tmp_path):
        body = _enabled(_agent_decider())
        cfg = load_config(_write(
            tmp_path, body, env={"POLICY_LLM_KEY": "k"},
        ))
        auto = cfg.domains.auto
        assert auto.enable is True
        assert auto.decider.kind == "agent"
        assert auto.decider.agent.provider == "openrouter"
        assert auto.decider.agent.model == "anthropic/claude-sonnet-4-5"
        assert auto.decider.agent.api_key == "env:POLICY_LLM_KEY"

    def test_effective_never_grant_includes_builtins(self, tmp_path):
        body = _enabled(_agent_decider())
        cfg = load_config(_write(tmp_path, body))
        ng = cfg.domains.auto.effective_never_grant()
        assert "agentcage.local" in ng
        assert "internal" in ng
        assert "local" in ng
        assert "localhost" in ng

    def test_valid_agent_validates_clean(self, tmp_path):
        body = _enabled(_agent_decider())
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        validate_config(cfg)  # must not raise

    def test_base_url_override_parsed(self, tmp_path):
        body = _enabled(_agent_decider(base_url="https://llm.local"))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.decider.agent.base_url == "https://llm.local"


# ── api_key validation ────────────────────────────────


class TestBaseUrlScheme:
    """https-only: the decider API key is sent as a bearer header on
    every call — http:// (or garbage) must be rejected at config time
    rather than leak the key in cleartext at runtime."""

    def test_http_base_url_rejected(self, tmp_path):
        body = _enabled(_agent_decider(base_url="http://llm.local"))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="https"):
            validate_config(cfg)

    def test_non_url_base_url_rejected(self, tmp_path):
        body = _enabled(_agent_decider(base_url="llm.local"))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="https"):
            validate_config(cfg)

    def test_https_base_url_validates_clean(self, tmp_path):
        body = _enabled(_agent_decider(base_url="https://llm.example"))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        validate_config(cfg)  # must not raise


class TestRateLimitZeroParse:
    """An explicit ``requests_per_second: 0`` means 'rate limiting
    disabled' — the operator's deliberate choice, and the proxy parses it
    the same way. It must NOT be coerced to the 1.0 default (the
    5th-review LOW: `0` meant 'disabled' to the proxy but '1.0' to
    validation)."""

    def test_explicit_zero_preserved(self, tmp_path):
        body = _enabled(
            _agent_decider() +
            "\nrate_limit:\n  requests_per_second: 0\n  burst: 0")
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.rate_limit_rps == 0.0
        assert cfg.domains.auto.rate_limit_burst == 0
        validate_config(cfg)  # 0 is legal (>= 0)

    def test_absent_falls_back_to_defaults(self, tmp_path):
        body = _enabled(_agent_decider())
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.rate_limit_rps == 1.0
        assert cfg.domains.auto.rate_limit_burst == 5

    def test_explicit_values_preserved(self, tmp_path):
        body = _enabled(
            _agent_decider() +
            "\nrate_limit:\n  requests_per_second: 2.5\n  burst: 10")
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.rate_limit_rps == 2.5
        assert cfg.domains.auto.rate_limit_burst == 10


class TestApiKey:
    def test_bad_scheme_raises(self, tmp_path):
        body = _enabled(_agent_decider(api_key="bogus:TOKEN"))
        with pytest.raises(ValueError, match="unknown secret source scheme"):
            load_config(_write(tmp_path, body, env={"TOKEN": "x"}))

    def test_missing_api_key_raises(self, tmp_path):
        body = _enabled(_agent_decider(api_key=""))
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="api_key is required"):
            validate_config(cfg)


# ── decider kind ────────────────────────────────────────


class TestDeciderKind:
    def test_unknown_kind_raises(self, tmp_path):
        body = _enabled("decider:\n  kind: carrier-pigeon\n")
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="must be 'agent' or 'webhook'"):
            validate_config(cfg)

    def test_webhook_not_implemented(self, tmp_path):
        body = _enabled("decider:\n  kind: webhook\n")
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="webhook is not implemented"):
            validate_config(cfg)


# ── blocklist mode interaction ────────────────────────────


class TestBlocklistMode:
    def test_blocklist_raises(self, tmp_path):
        block = "domains:\n  block:\n    - evil.com\n  auto:\n    enable: true\n"
        block += "    " + "\n    ".join(_agent_decider().splitlines()) + "\n"
        cfg = load_config(_write(tmp_path, block, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="allowlist mode"):
            validate_config(cfg)


# ── control host validation ──────────────────────────────


class TestControlHost:
    def test_collision_with_allow_raises(self, tmp_path):
        body = _domains(
            allow=("github.com", "agentcage.local"),
            auto_body="enable: true\n" + _agent_decider(),
        )
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="must not appear in"):
            validate_config(cfg)

    def test_custom_host_ok(self, tmp_path):
        body = _enabled(_agent_decider(), allow=("github.com",))
        # override host
        body = body.replace("  auto:\n    enable: true",
                            "  auto:\n    enable: true\n    host: cage.control.test")
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.host == "cage.control.test"
        validate_config(cfg)

    def test_bare_label_raises(self, tmp_path):
        body = _enabled(_agent_decider())
        body = body.replace("    enable: true",
                            "    enable: true\n    host: agentcage")
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="dotted hostname"):
            validate_config(cfg)


# ── llm provider fields ──────────────────────────────────


class TestLlmProvider:
    def test_unknown_llm_provider_raises(self, tmp_path):
        body = _enabled(_agent_decider(provider="grok"))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="provider must be"):
            validate_config(cfg)

    def test_missing_model_raises(self, tmp_path):
        body = _enabled(_agent_decider(model=""))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="model is required"):
            validate_config(cfg)




# ── proxy-config subset membership ─────────────────────────


class TestProxyConfigSubset:
    def test_domains_key_in_proxy_keys(self):
        # domains.auto nests under domains, which is already in _PROXY_KEYS.
        from agentcage.state import _PROXY_KEYS
        assert "domains" in _PROXY_KEYS


# ── decider api_key stripping ─────────────────────────────


class TestSecretStripping:
    def test_api_key_env_stripped_from_cage_env(self, tmp_path):
        body = _enabled(_agent_decider(api_key="env:POLICY_LLM_KEY"))
        cfg = load_config(_write(
            tmp_path, body,
            env={"POLICY_LLM_KEY": "k", "KEEP_ME": "yes"},
        ))
        assert "POLICY_LLM_KEY" not in cfg.container.env
        assert "KEEP_ME" in cfg.container.env

    def test_api_key_stripped_from_podman_secrets(self, tmp_path):
        body = _enabled(_agent_decider(api_key="env:POLICY_LLM_KEY"))
        cfg = load_config(_write(
            tmp_path, body,
            env={"POLICY_LLM_KEY": "k"},
            podman_secrets=["POLICY_LLM_KEY", "KEEP_SECRET"],
        ))
        assert "POLICY_LLM_KEY" not in cfg.container.podman_secrets
        assert "KEEP_SECRET" in cfg.container.podman_secrets
