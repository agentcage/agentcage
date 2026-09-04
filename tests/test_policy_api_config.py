"""Tests for the ``domains.auto`` config section — parsing + validation.

Exercises the config schema for auto-managed allowlists: ``DomainsAutoConfig``
and its sub-configs, ``effective_never_grant()``, ``load_config`` stripping of
the decider agent's API key from the cage env, and every ``validate_config``
rule. No runtime behavior here — that lives in ``test_policy_api_grants.py``.

Style mirrors ``tests/test_config.py``: configs are written to temp files and
loaded with ``load_config``; validation is driven through ``validate_config``.
"""

import pytest

from agentcage.config import load_config, valid_domain, validate_config


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
                   api_key="env:POLICY_LLM_KEY", timeout=None, base_url=None,
                   max_tokens=None):
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
    if max_tokens is not None:
        out.append("  max_tokens: " + str(max_tokens))
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


class TestDeciderMaxTokens:
    """The forced tool call's completion budget.

    A reasoning model spends its thinking tokens inside this budget before
    emitting the tool call, so a budget sized for the verdict alone comes
    back ``finish_reason: length`` with NO tool call — which the decider
    fails closed on, denying every request (observed in production: every
    `policy_request` denied with "llm returned no usable decision").
    """

    def test_defaults_to_headroom(self, tmp_path):
        body = _enabled(_agent_decider())
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.decider.agent.max_tokens == 8192

    def test_explicit_value_preserved(self, tmp_path):
        body = _enabled(_agent_decider(max_tokens=16384))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.decider.agent.max_tokens == 16384

    def test_starving_budget_rejected(self, tmp_path):
        # 256 was the old hard-coded default and starves every reasoning
        # model measured (glm-5.2, glm-5.3-flash, gemini-3.8-flash).
        body = _enabled(_agent_decider(max_tokens=256))
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match="at least 1024"):
            validate_config(cfg)

    def test_floor_accepted(self, tmp_path):
        body = _enabled(_agent_decider(max_tokens=1024))
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


# ── operator context (domains.auto.context) ────────────────


class TestOperatorContext:
    """Operator-provided free-text describing the cage's purpose. Flows
    into the decider's system prompt (advisory only — never overrides
    never_grant/syntax/rate limits) and into the /v1/allowlist response.
    Capped at 4096 chars (stripped) because it rides every decider call's
    system prompt and through proxy-config.yaml."""

    _CTX = (
        "CI cage for the payments-reconciliation test suite. Talks to "
        "staging APIs (api.stripe.com), publishes test coverage to "
        "codecov.io, and installs dependencies from npm/pypi."
    )

    def _ctx_body(self, ctx_yaml):
        # context: must sit under `auto:` alongside enable/decider.
        return _enabled(
            _agent_decider() + "\ncontext: " + ctx_yaml
        )

    def test_default_empty_when_omitted(self, tmp_path):
        body = _enabled(_agent_decider())
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.context == ""
        validate_config(cfg)  # omitted is legal (feature off)

    def test_none_normalizes_to_empty(self, tmp_path):
        # YAML `context: null` (or absent) → "". The proxy reads
        # `cfg.get("context", "") or ""` the same way, so this stays in
        # lockstep with the runtime parse.
        body = _enabled(_agent_decider() + "\ncontext: null")
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.context == ""
        validate_config(cfg)

    def test_value_round_trips(self, tmp_path):
        body = _enabled(
            _agent_decider() + "\ncontext: \"" + self._CTX + "\"")
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.context == self._CTX
        validate_config(cfg)

    def test_multiline_block_scalar_round_trips(self, tmp_path):
        # The canonical operator example uses a `|` block scalar; make sure
        # the trailing newline it introduces is acceptable (validation
        # strips before measuring, and the proxy strips on read).
        body = _enabled(
            _agent_decider() + "\ncontext: |\n  " + self._CTX + "\n")
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.context.rstrip() == self._CTX
        validate_config(cfg)

    def test_empty_and_whitespace_only_fine(self, tmp_path):
        for val in ("\"\"", "'   '", "\"\n\n  \""):
            body = _enabled(_agent_decider() + "\ncontext: " + val)
            cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
            assert cfg.domains.auto.context.strip() == ""
            validate_config(cfg)  # whitespace-only is the feature-off case

    def test_non_string_rejected_with_actionable_message(self, tmp_path):
        # A mapping (the natural typo: indenting prose under `context:`) is
        # rejected at parse with a message naming the field and the actual
        # type, so the operator can fix the YAML rather than getting a
        # misleading repr like "{'enable': True}" in the system prompt.
        body = _enabled(
            _agent_decider() + "\ncontext:\n  purpose: ci\n  scope: payments")
        with pytest.raises(ValueError, match="domains.auto.context must be a string"):
            load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))

    def test_non_string_list_rejected(self, tmp_path):
        body = _enabled(_agent_decider() + "\ncontext: [a, b]")
        with pytest.raises(ValueError, match="domains.auto.context must be a string"):
            load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))

    def test_too_long_rejected_with_length_in_message(self, tmp_path):
        too_long = "x" * 4097
        body = _enabled(_agent_decider() + "\ncontext: " + too_long)
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        with pytest.raises(ValueError, match=r"is too long \(4097 chars, max 4096\)"):
            validate_config(cfg)

    def test_exactly_4096_accepted(self, tmp_path):
        # The cap is an explicit boundary: 4096 is still legal, 4097 is not.
        exact = "a" * 4096
        body = _enabled(_agent_decider() + "\ncontext: " + exact)
        cfg = load_config(_write(tmp_path, body, env={"POLICY_LLM_KEY": "k"}))
        assert cfg.domains.auto.context == exact
        validate_config(cfg)  # must not raise

    def test_length_measured_after_strip(self, tmp_path):
        # Leading/trailing whitespace doesn't count toward the cap (matches
        # the proxy, which strips on read). 4097 chars with a newline at
        # each end → 4095 after strip → legal.
        body = "\n" + ("b" * 4095) + "\n"
        body_yaml = _enabled(_agent_decider() + "\ncontext: \"" + body + "\"")
        cfg = load_config(_write(tmp_path, body_yaml, env={"POLICY_LLM_KEY": "k"}))
        validate_config(cfg)  # must not raise

    def test_disabled_auto_skips_context_validation(self, tmp_path):
        # A too-long context under a DISABLED auto block is never validated
        # (the whole auto block is a no-op when enable is false). Guards
        # against an over-eager check that runs regardless of enable.
        body = (
            "domains:\n  allow: [github.com]\n  auto:\n    enable: false\n"
            "    context: " + ("x" * 5000) + "\n"
        )
        cfg = load_config(_write(tmp_path, body))
        # enable=False → context not parsed into DomainsAutoConfig (the parse
        # block only runs when auto_raw.get("enable")), so it stays "".
        assert cfg.domains.auto.enable is False
        validate_config(cfg)  # must not raise


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

    def test_cmd_scheme_api_key_rejected(self, tmp_path):
        # cmd: would silently resolve to an empty key at runtime (the egress
        # container has no shell). validate_config must reject it early with
        # an actionable message.
        body = _enabled(_agent_decider(api_key="cmd:cat /run/secrets/key"))
        cfg = load_config(_write(tmp_path, body, env={}))
        with pytest.raises(ValueError, match="cmd"):
            validate_config(cfg)

    def test_env_api_key_still_valid(self, tmp_path):
        # env: is one of the supported schemes; it must validate cleanly.
        body = _enabled(_agent_decider(api_key="env:OPENROUTER_API_KEY"))
        cfg = load_config(_write(tmp_path, body, env={"OPENROUTER_API_KEY": "k"}))
        validate_config(cfg)  # must not raise
        assert cfg.domains.auto.decider.agent.api_key == "env:OPENROUTER_API_KEY"


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


# ── domains.allow / domains.block per-entry syntax validation ──────


class TestDomainSyntaxValidation:
    """Per-entry syntax validation of ``domains.allow`` / ``domains.block``.

    The values flow verbatim into dnsmasq ``server=`` directives and the
    grants overlay, so a string containing a newline or slash would inject
    extra directives. Validate at parse time (via ``validate_config``) so a
    bad entry is rejected loudly rather than rendered into dns-allowlist.conf.
    """

    def _allow_body(self, *items):
        # ``items`` are already-formatted YAML list-item lines (indented).
        return "domains:\n  allow:\n" + "\n".join(items) + "\n"

    def _block_body(self, *items):
        return "domains:\n  block:\n" + "\n".join(items) + "\n"

    def test_valid_allow_passes(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._allow_body("    - good.com")))
        # No ValueError: validate_config returns warnings (default-deny note
        # does not apply — allowlist mode with a non-empty list).
        validate_config(cfg)
        assert cfg.domains.allow == ["good.com"]

    def test_invalid_allow_entry_rejected(self, tmp_path):
        # YAML double-quoted string: \n is a real newline, / a slash — both
        # would inject extra dnsmasq directives.
        cfg = load_config(_write(tmp_path, self._allow_body(
            "    - good.com",
            '    - "bad\\ninjected/line"')))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_block_list_checked_too(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._block_body(
            "    - ok.com", "    - bad/line")))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_uppercase_domain_rejected(self, tmp_path):
        # The regex is lowercase-only; the config value flows verbatim into
        # dnsmasq, so reject uppercase rather than relying on a downstream
        # ``.lower()`` that may not run on every path.
        cfg = load_config(_write(
            tmp_path, self._allow_body("    - API.Example.COM")))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_error_message_names_offending_entry(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._allow_body(
            '    - "bad\\nline"')))
        with pytest.raises(ValueError, match="invalid domain syntax") as ei:
            validate_config(cfg)
        # The offending entry is named in the message (repr shows the newline
        # as an escape so it is greppable / not a literal break).
        assert "bad\\nline" in str(ei.value)


# ── Fix: $ anchor accepts one trailing newline (HIGH) ────────────────────


class TestDomainNewlineAnchor:
    """``DOMAIN_RE``'s ``$`` anchor matched immediately before ONE trailing
    newline, so ``"evil.com\\n"`` passed ``valid_domain``. Such a value
    appended to ``domains.allow`` renders as a split dnsmasq directive
    (``server=/evil.com/`` + a newline + the upstream on its own line) that
    fails ``dnsmasq --test`` — persistent per-cage config corruption. The
    anchor is now ``\\Z`` (absolute end-of-string) plus an explicit
    whitespace guard in ``valid_domain``."""

    @staticmethod
    def _allow_body(*items):
        return "domains:\n  allow:\n" + "\n".join(items) + "\n"

    def test_valid_domain_rejects_trailing_newline(self):
        # The regression the finding describes: ``$`` let this through; ``\Z``
        # (and the whitespace guard) must not.
        assert valid_domain("evil.com\n") is False

    def test_valid_domain_accepts_plain_domain(self):
        assert valid_domain("evil.com") is True

    def test_valid_domain_rejects_any_whitespace(self):
        # Defence in depth: leading/embedded/trailing whitespace of any
        # kind is rejected, not just a single trailing newline.
        assert valid_domain(" evil.com") is False
        assert valid_domain("evil.com ") is False
        assert valid_domain("evil.\tcom") is False
        assert valid_domain("evil.com\r") is False

    def test_newline_bearing_allow_entry_rejected_by_validate_config(
        self, tmp_path
    ):
        # A YAML double-quoted ``"evil.com\n"`` decodes to a string ending
        # in a real newline — the dnsmasq-injection payload. validate_config
        # must reject it (pre-fix it passed because ``$`` matches before one
        # trailing newline).
        cfg = load_config(_write(tmp_path, self._allow_body(
            '    - "evil.com\n"')))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_exactly_canonical_values_still_pass(self, tmp_path):
        # Regression guard: the stricter anchor must not over-reject. A
        # plain lowercase dotted hostname (the canonical form the promote
        # paths now write) still validates cleanly.
        cfg = load_config(_write(tmp_path, self._allow_body(
            "    - api.example.com",
            "    - github.com")))
        validate_config(cfg)  # must not raise
        assert cfg.domains.allow == ["api.example.com", "github.com"]


# ── Fix 1: domains.passthrough / domains.expires syntax validation ──────


class TestPassthroughSyntaxValidation:
    """``domains.passthrough`` entries flow into the same dnsmasq rendering
    chain as ``domains.allow`` (quadlets ``_effective_dns_allowlist`` merges
    them into the DNS allowlist; the in-container addon's ``_apply_
    passthrough`` escapes each entry into a mitmproxy ``--ignore-hosts``
    regex). They were never syntax-validated, so a newline/slash-bearing
    entry would inject extra ``server=`` directives or break the regex
    silently. The consumers add the subdomain-wildcard prefix themselves
    (``^(.+\\.)?<escaped>``), so passthrough entries are plain dotted
    hostnames — NO leading-dot ``.example.com`` / bare-TLD wildcard form is
    accepted at the config layer; ``valid_domain`` therefore applies
    directly (no stripping)."""

    @staticmethod
    def _passthrough_body(*items, allow=("anthropic.com",)):
        allows = "\n".join("    - " + d for d in allow)
        passes = "\n".join(items)
        return (
            "domains:\n  allow:\n"
            f"{allows}\n"
            "  passthrough:\n"
            f"{passes}\n"
        )

    def test_valid_passthrough_passes(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._passthrough_body(
            "    - whatsapp.com", "    - api.example.com")))
        validate_config(cfg)  # must not raise
        assert cfg.domains.passthrough == ["whatsapp.com", "api.example.com"]

    def test_invalid_passthrough_entry_rejected(self, tmp_path):
        # A newline/slash-bearing entry would inject extra dnsmasq
        # directives — reject at parse time, matching the allow/block style.
        cfg = load_config(_write(tmp_path, self._passthrough_body(
            "    - whatsapp.com",
            '    - "bad\\ninjected/line"')))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_passthrough_error_message_names_offending_entry(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._passthrough_body(
            '    - "bad/line"')))
        with pytest.raises(ValueError, match="invalid domain syntax") as ei:
            validate_config(cfg)
        assert "bad/line" in str(ei.value)

    def test_passthrough_ip_literal_rejected(self, tmp_path):
        # An IP literal is nonsensical as a ``server=/`` key / ignore-hosts
        # match; the tightened ``valid_domain`` rejects it.
        cfg = load_config(_write(tmp_path, self._passthrough_body(
            "    - 8.8.8.8")))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)


class TestExpiresKeySyntaxValidation:
    """``domains.expires`` KEYS are domains (the per-domain expiry map).
    ``load_config`` lowercases + strips a trailing dot off each key, but
    never validated the syntax — a newline/slash-bearing key would render
    into a dnsmasq ``server=/`` directive when the watcher promotes the
    entry. Validate every key with ``valid_domain``."""

    @staticmethod
    def _expires_body(allow, expires_yaml):
        allows = "\n".join("    - " + d for d in allow)
        return (
            "domains:\n  allow:\n"
            f"{allows}\n"
            "  expires:\n"
            f"{expires_yaml}\n"
        )

    def test_valid_expires_key_passes(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._expires_body(
            ("anthropic.com",),
            "    anthropic.com: \"2026-01-01T00:00:00+00:00\"")))
        validate_config(cfg)  # must not raise
        assert cfg.domains.expires == {"anthropic.com": "2026-01-01T00:00:00+00:00"}

    def test_invalid_expires_key_rejected(self, tmp_path):
        # A slash-bearing key would break the dnsmasq directive.
        cfg = load_config(_write(tmp_path, self._expires_body(
            ("anthropic.com",),
            '    "bad/line": "2026-01-01T00:00:00+00:00"')))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_invalid_expires_key_alongside_valid_one(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._expires_body(
            ("anthropic.com",),
            "    anthropic.com: \"2026-01-01T00:00:00+00:00\"\n"
            '    "evil.com\\n": "2026-01-01T00:00:00+00:00"')))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_expires_key_ip_literal_rejected(self, tmp_path):
        cfg = load_config(_write(tmp_path, self._expires_body(
            ("anthropic.com",),
            "    1.2.3.4: \"2026-01-01T00:00:00+00:00\"")))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)


# ── Fix 2: host valid_domain tightened to match the addon's _valid_domain ──


class TestValidDomainTightening:
    """The host ``valid_domain`` used to accept IP literals (``1.2.3.4``
    matches the regex's all-digits labels) and single-character last labels
    (``x.c``), while the in-container addon's ``_valid_domain`` rejected
    both — despite the \"kept in sync\" comment. The host validator now
    ports the addon's two extra checks (IP-literal rejection via
    ``ipaddress.ip_address`` and last-label length >= 2) so the two gates
    agree. The addon's copy is NOT changed."""

    def test_ip_literal_v4_rejected(self):
        assert valid_domain("1.2.3.4") is False

    def test_ip_literal_v4_octets_rejected(self):
        assert valid_domain("8.8.8.8") is False
        assert valid_domain("255.255.255.255") is False

    def test_ip_literal_v6_rejected(self):
        assert valid_domain("::1") is False
        assert valid_domain("2001:db8::1") is False

    def test_single_char_tld_rejected(self):
        # ``x.c`` passes the regex's dotted-label shape but a single-letter
        # last label is not a real public suffix — mirror the addon.
        assert valid_domain("x.c") is False

    def test_two_char_tld_accepted(self):
        assert valid_domain("a.co") is True
        assert valid_domain("x.io") is True

    def test_normal_domains_still_accepted(self):
        for d in ("x.com", "evil.com", "api.example.com", "github.com"):
            assert valid_domain(d) is True, d

    def test_ip_literal_in_allow_rejected_by_validate_config(self, tmp_path):
        # The tightened validator flows into the allow-list parse: an IP
        # literal in domains.allow is now rejected at config time (pre-fix
        # it passed ``valid_domain`` and would have rendered as a nonsense
        # dnsmasq ``server=/1.2.3.4/`` key).
        body = "domains:\n  allow:\n    - 1.2.3.4\n"
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)

    def test_single_char_tld_in_allow_rejected_by_validate_config(self, tmp_path):
        body = "domains:\n  allow:\n    - x.c\n"
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)


# ── Single-label LAN hostnames in operator-owned lists ───────────────────


class TestSingleLabelHostnames:
    """0.34.0's validator required a dotted name everywhere, breaking real
    configs whose ``domains.allow`` names a LAN/tailnet host by its bare
    hostname (``fcos-vm-home-01``) — entries that rendered and matched fine
    in every prior release. Operator-owned lists (the static domains lists
    and ``domain add``) now pass ``allow_single_label=True``; the runtime
    grant paths (addon request endpoint, reconcile, promote) stay
    strict-dotted per the Policy API threat model."""

    def test_valid_domain_rejects_single_label_by_default(self):
        # The strict default is what every runtime-grant path calls.
        assert valid_domain("fcos-vm-home-01") is False

    def test_valid_domain_accepts_single_label_when_allowed(self):
        assert valid_domain("fcos-vm-home-01", allow_single_label=True) is True
        assert valid_domain("nas", allow_single_label=True) is True

    def test_single_label_still_rejects_injection_shapes(self):
        # The relaxation must not weaken the dnsmasq-injection guards.
        for bad in ("bad\nline", "bad/path", "bad name", "UPPER",
                    "-leading", "trailing-", "host\n"):
            assert valid_domain(bad, allow_single_label=True) is False

    def test_single_label_still_rejects_short_and_ip(self):
        # The >=2-char last-label rule and IP-literal rejection apply to the
        # single-label branch too.
        assert valid_domain("x", allow_single_label=True) is False
        assert valid_domain("1.2.3.4", allow_single_label=True) is False

    def test_single_label_allow_entry_validates_clean(self, tmp_path):
        body = "domains:\n  allow:\n    - fcos-vm-home-01\n    - github.com\n"
        cfg = load_config(_write(tmp_path, body))
        validate_config(cfg)  # must not raise

    def test_single_label_passthrough_and_expires_validate_clean(
        self, tmp_path
    ):
        body = (
            "domains:\n"
            "  allow:\n"
            "    - fcos-vm-home-01\n"
            "  passthrough:\n"
            "    - fcos-vm-home-01\n"
            "  expires:\n"
            "    fcos-vm-home-01: \"2099-01-01T00:00:00+00:00\"\n"
        )
        cfg = load_config(_write(tmp_path, body))
        validate_config(cfg)  # must not raise

    def test_newline_bearing_single_label_still_rejected(self, tmp_path):
        body = 'domains:\n  allow:\n    - "badhost\n"\n'
        cfg = load_config(_write(tmp_path, body))
        with pytest.raises(ValueError, match="invalid domain syntax"):
            validate_config(cfg)
