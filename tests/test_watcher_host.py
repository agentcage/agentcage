"""The traffic watcher — host side.

Split out of ``tests/test_watcher.py`` (RUST-PORT-PLAN.md §2.4). The feature is
already two halves and the language boundary runs between them: this file holds
the host half — config parsing/validation of the ``agents.watcher`` cage.yaml
block, the egress-only credential stripping, the DNS allowlist entry for the
watcher's LLM provider host, the severity-ladder mapping, the secret-list
classification, and the read-only ``watcher findings`` / ``watcher status``
CLI. All of it becomes Rust.

``data/proxy/watcher.py`` — the digest builder, capture tail, review loop and
revocation path — stays Python and stays in ``tests/test_watcher.py``. Test
names are unchanged on both sides so failures stay greppable against history.
"""

from __future__ import annotations

import json
import textwrap
from types import SimpleNamespace

import pytest

_WATCHER_YAML = """
    agents:
      watcher:
        enable: true
        interval_seconds: 120
        window_seconds: 7200
        max_flows: 150
        auto_revoke: false
        context: "recon test suite against staging"
        provider: openai
        model: gpt-5-mini
        api_key: env:WATCHER_LLM_KEY
        timeout_seconds: 45
        base_url: https://api.example.com/v1
"""


def _cfg_with(tmp_path, extra: str = "", *, base: str | None = None) -> str:
    """Write a minimal cage.yaml plus an appended (dedented) block.

    ``base`` replaces the default document head entirely (for tests that
    need their own container: block without duplicating the key).
    """
    p = tmp_path / "config.yaml"
    doc = base if base is not None else (
        "name: test\ncontainer:\n  image: localhost/test:latest\n")
    p.write_text(doc + textwrap.dedent(extra))
    return str(p)


class TestWatcherConfigParsing:
    def test_block_parses(self, tmp_path):
        from agentcage.config import load_config
        cfg = load_config(_cfg_with(tmp_path, _WATCHER_YAML))
        w = cfg.agents.watcher
        assert w.enable is True
        assert w.interval_seconds == 120
        assert w.window_seconds == 7200
        assert w.max_flows == 150
        assert w.auto_revoke is False
        assert w.context == "recon test suite against staging"
        assert w.provider == "openai"
        assert w.model == "gpt-5-mini"
        assert w.api_key == "env:WATCHER_LLM_KEY"
        assert w.timeout_seconds == 45
        assert w.max_tokens == 8192  # default; no longer hard-coded 2048
        assert w.base_url == "https://api.example.com/v1"

    def test_absent_block_is_zero_surface(self, tmp_path):
        from agentcage.config import load_config
        cfg = load_config(_cfg_with(tmp_path, ""))
        assert cfg.agents.watcher.enable is False
        assert cfg.agents.watcher.model == ""

    def test_context_non_string_rejected(self, tmp_path):
        from agentcage.config import load_config
        bad = _cfg_with(tmp_path, """
            agents:
              watcher:
                enable: true
                provider: openai
                model: m
                api_key: env:K
                context: {nope: 1}
        """)
        with pytest.raises(ValueError, match=r"agents\.watcher\.context must be a string"):
            load_config(bad)

    # Review fix (correctness #7 / conventions #5): a malformed block
    # must not silently ride proxy-config.yaml and crash/degrade the
    # in-egress consumer — reject it at parse time.
    def test_non_mapping_block_rejected(self, tmp_path):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match=r"agents\.watcher must be a mapping"):
            load_config(_cfg_with(tmp_path, "agents:\n  watcher: true\n"))

    @pytest.mark.parametrize("block", ["{enable: true}", "{enable: false}", "{}", "null"])
    def test_legacy_top_level_watcher_rejected(self, tmp_path, block):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match="watcher.*no longer supported"):
            load_config(_cfg_with(tmp_path, f"watcher: {block}\n"))

    @pytest.mark.parametrize("block", ["{enable: true}", "{enable: false}", "{}", "null"])
    def test_legacy_domains_auto_rejected(self, tmp_path, block):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match=r"domains\.auto.*no longer supported"):
            load_config(_cfg_with(tmp_path, f"domains:\n  auto: {block}\n"))

    @pytest.mark.parametrize("enable", ["true", "false"])
    @pytest.mark.parametrize("agent", ["true", "{}", "null", "{provider: openai, model: m, api_key: 'env:K'}"])
    def test_nested_agent_wrapper_rejected(self, tmp_path, enable, agent):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match=r"agents\.watcher: LLM fields must be flat"):
            load_config(_cfg_with(tmp_path, f"""
                agents:
                  watcher:
                    enable: {enable}
                    agent: {agent}
            """))

    # Review fix: bool("false") is True — a YAML string must not silently
    # ENABLE autonomous revocation against the operator's written intent.
    def test_string_auto_revoke_rejected(self, tmp_path):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match=r"agents\.watcher\.auto_revoke must be a boolean"):
            load_config(_cfg_with(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    auto_revoke: "false"
                    provider: openai
                    model: m
                    api_key: env:K
            """))

    # Review fix (PR #340 follow-up): the block's own stated invariant
    # ("booleans must be REAL booleans") was implemented for auto_revoke
    # but not for enable itself — a quoted `enable: "false"` was truthy
    # and would silently turn the watcher (and auto_revoke, defaulting
    # true) ON against the operator's written intent.
    def test_string_enable_rejected(self, tmp_path):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match=r"agents\.watcher\.enable must be a boolean"):
            load_config(_cfg_with(tmp_path, """
                agents:
                  watcher:
                    enable: "false"
                    provider: openai
                    model: m
                    api_key: env:K
            """))

    # PR #340 follow-up review: in blocklist mode the static baseline IS
    # the block list, so the digest hands the model blocked domains under
    # the key ``current_baseline`` and a baseline recommendation becomes
    # "run `domain rm`" — removing a BLOCK, which WIDENS egress. A
    # narrowing-only auditor must never be able to recommend widening.
    def test_blocklist_mode_rejected(self, tmp_path):
        from agentcage.config import load_config, validate_config
        cfg = load_config(_cfg_with(tmp_path, """
            domains:
              block:
                - evil.example
            agents:
              watcher:
                enable: true
                provider: openai
                model: m
                api_key: env:K
        """))
        with pytest.raises(ValueError, match="blocklist mode"):
            validate_config(cfg)

    def test_cage_without_a_domains_section_is_allowed(self, tmp_path):
        # mode "" has an EMPTY baseline: nothing inverts, nothing is
        # recommended, so the guard must not reject it.
        from agentcage.config import load_config, validate_config
        validate_config(load_config(_cfg_with(tmp_path, _WATCHER_YAML)))

    def test_string_dedup_samples_rejected(self, tmp_path):
        # Same trap as auto_revoke: bool("false") is True, which would
        # quietly keep the expensive un-deduped digest.
        from agentcage.config import load_config
        with pytest.raises(ValueError, match=r"agents\.watcher\.dedup_samples must be a boolean"):
            load_config(_cfg_with(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    dedup_samples: "false"
                    provider: openai
                    model: m
                    api_key: env:K
            """))

    def test_dedup_defaults_on(self, tmp_path):
        from agentcage.config import load_config
        cfg = load_config(_cfg_with(tmp_path, _WATCHER_YAML))
        assert cfg.agents.watcher.dedup_samples is True

    def test_key_is_stripped_from_the_cage_env(self, tmp_path):
        # The watcher key is an EGRESS-only credential. If the operator
        # also declared the same env var for the cage, parse-time
        # stripping must remove it from the cage env (it must never be
        # cage-visible, even as a placeholder) — the same invariant and
        # the same mechanism as the decider's key.
        from agentcage.config import load_config
        cfg = load_config(_cfg_with(tmp_path, """
            agents:
              watcher:
                enable: true
                provider: openai
                model: m
                api_key: env:WATCHER_LLM_KEY
        """, base=(
            "name: test\n"
            "container:\n"
            "  image: localhost/test:latest\n"
            "  env:\n"
            "    WATCHER_LLM_KEY: dummy\n")))
        assert "WATCHER_LLM_KEY" not in cfg.container.env


class TestWatcherConfigValidation:
    def _validate(self, tmp_path, extra: str):
        from agentcage.config import load_config, validate_config
        cfg = load_config(_cfg_with(tmp_path, extra))
        return validate_config(cfg)

    def test_valid_block_passes(self, tmp_path):
        self._validate(tmp_path, _WATCHER_YAML)  # no exception

    def test_missing_model_rejected(self, tmp_path):
        with pytest.raises(ValueError, match=r"agents\.watcher\.model is required"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    provider: openai
                    api_key: env:K
            """)

    def test_missing_key_rejected(self, tmp_path):
        with pytest.raises(ValueError, match=r"agents\.watcher\.api_key is required"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    provider: openai
                    model: m
            """)

    def test_cmd_source_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="does not support cmd:"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    provider: openai
                    model: m
                    api_key: cmd:cat /tmp/key
            """)

    def test_starving_max_tokens_rejected(self, tmp_path):
        # Mirrors the decider's floor: a budget a reasoning model spends
        # on thinking leaves no tool call, which is a recorded scan
        # failure rather than a silent all-clear — but still a watcher
        # that never reviews anything.
        with pytest.raises(ValueError, match="at least 1024"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    provider: openai
                    model: m
                    api_key: env:K
                    max_tokens: 512
            """)

    # Review fix (conventions #4): the watcher agent block is documented
    # to follow the decider's rules VERBATIM — the decider rejects
    # `provider: Anthropic` with a message, so the watcher must too
    # (silently lowercasing is the mirror drifting).
    def test_mixed_case_provider_rejected_like_the_decider(self, tmp_path):
        with pytest.raises(ValueError, match="got 'Anthropic'"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    provider: Anthropic
                    model: m
                    api_key: env:K
            """)

    # Review fix (correctness #7 / conventions #5): an explicit 0 must
    # reach validation and be rejected by the bounds, not silently
    # coerced to the default by a bare `or` at parse time.
    def test_explicit_zero_interval_rejected_by_bounds(self, tmp_path):
        with pytest.raises(ValueError, match="interval_seconds must be >= 60"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    interval_seconds: 0
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_explicit_zero_window_rejected_by_bounds(self, tmp_path):
        with pytest.raises(ValueError, match="window_seconds"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    window_seconds: 0
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_non_numeric_interval_rejected(self, tmp_path):
        with pytest.raises(ValueError, match=r"agents\.watcher\.interval_seconds must be a number"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    interval_seconds: soon
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_bad_provider_rejected(self, tmp_path):
        with pytest.raises(ValueError, match=r"agents\.watcher\.provider"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    provider: ollama
                    model: m
                    api_key: env:K
            """)

    def test_http_base_url_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="https://"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    provider: openai
                    model: m
                    api_key: env:K
                    base_url: http://api.example.com
            """)

    def test_hot_loop_interval_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="interval_seconds"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    interval_seconds: 5
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_window_bounds_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="window_seconds"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    window_seconds: 999999
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_max_flows_bounds_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="max_flows"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    max_flows: 2
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_oversized_context_rejected(self, tmp_path):
        with pytest.raises(ValueError, match=r"agents\.watcher\.context is too long"):
            self._validate(tmp_path, """
                agents:
                  watcher:
                    enable: true
                    context: "%s"
                    provider: openai
                    model: m
                    api_key: env:K
            """ % ("x" * 4097))

    def test_disabled_block_skips_validation(self, tmp_path):
        # enable: false (or no block) must not demand a model/key — an
        # operator commenting the block out for a debug run must not be
        # blocked by validation for a feature that is off.
        self._validate(tmp_path, """
            agents:
              watcher:
                enable: false
                provider: ""
        """)


class TestWatcherPlumbing:
    def test_proxy_keys_forward_the_block(self):
        # The watcher is driven in-egress; its config rides proxy-config.yaml
        # under the `agents` namespace (0.40 restructure) through the same
        # key filter every other egress setting uses.
        from agentcage.state import _PROXY_KEYS
        assert "agents" in _PROXY_KEYS
        assert "watcher" not in _PROXY_KEYS

    def test_dns_allowlist_resolves_watcher_provider_host(self, tmp_path):
        # The watcher calls its model from the addon process over urllib,
        # OUTSIDE mitmproxy — like the decider, its provider host must be
        # resolvable via the egress's dnsmasq or every scan fails.
        from agentcage.config import load_config
        from agentcage.quadlets import _effective_dns_allowlist
        cfg = load_config(_cfg_with(tmp_path, """
            domains:
              allow: [registry.npmjs.org]
            agents:
              watcher:
                enable: true
                provider: openai
                model: m
                api_key: env:K
        """))
        merged = _effective_dns_allowlist(cfg)
        assert "registry.npmjs.org" in merged
        assert "api.openai.com" in merged

    def test_dns_allowlist_uses_custom_base_url_host(self, tmp_path):
        from agentcage.config import load_config
        from agentcage.quadlets import _effective_dns_allowlist
        cfg = load_config(_cfg_with(tmp_path, """
            domains:
              allow: [registry.npmjs.org]
            agents:
              watcher:
                enable: true
                provider: openai
                model: m
                api_key: env:K
                base_url: https://llm-proxy.internal.example.com/v1
        """))
        merged = _effective_dns_allowlist(cfg)
        assert "llm-proxy.internal.example.com" in merged


# ═══════════════════════════════════════════════════════════════════
# Host side: the audit ladder ranks the watcher vocabulary
# ═══════════════════════════════════════════════════════════════════

class TestWatcherKeyIsAnExpectedSecret:
    """PR #340 follow-up review: `secret set` called the key an orphan.

    ``services.expected_secrets`` was never extended with the egress LLM
    agents' api_keys, though ``cli._render_secret_list`` was. So
    ``agentcage secret set mycage WATCHER_LLM_KEY`` — the command the
    how-to prescribes — printed "has no secret_injection rule … (orphan)",
    and ``check_secrets`` gave no preflight warning when a watcher-enabled
    cage was deployed without its key (the egress then boots and skips
    every scan).
    """

    def _cfg(self, tmp_path, extra):
        from agentcage.config import load_config
        return load_config(_cfg_with(tmp_path, extra))

    def test_watcher_key_is_expected(self, tmp_path):
        from agentcage.services import expected_secrets
        cfg = self._cfg(tmp_path, """
            agents:
              watcher:
                enable: true
                provider: openai
                model: m
                api_key: env:WATCHER_LLM_KEY
        """)
        assert "WATCHER_LLM_KEY" in expected_secrets(cfg)

    def test_disabled_watcher_key_is_not_expected(self, tmp_path):
        from agentcage.services import expected_secrets
        cfg = self._cfg(tmp_path, "")
        assert "WATCHER_LLM_KEY" not in expected_secrets(cfg)

    def test_decider_key_is_expected_too(self, tmp_path):
        # Same gap, same fix — the decider's key was equally an "orphan".
        from agentcage.services import expected_secrets
        cfg = self._cfg(tmp_path, """
            domains:
              allow:
                - api.example.com
            agents:
              decider:
                enable: true
                provider: openai
                model: m
                api_key: env:DECIDER_LLM_KEY
        """)
        assert "DECIDER_LLM_KEY" in expected_secrets(cfg)


class TestWatcherSeverityLadder:
    """Review fix (conventions #1): a "high" watcher finding was invisible.

    The audit filter's ladder was a closed vocabulary
    (debug/info/warning/error/critical); order.get("high", 0) ranked a
    model-rated "high" finding BELOW "info", so `cage audit --severity
    warning` dropped it — contradicting the feature's own docs. The
    ladder now ranks low/medium/high on the same scale.
    """

    def _entry(self, severity: str):
        from agentcage.audit import AuditEntry
        return AuditEntry.from_dict({
            "ts": "2026-01-01T00:00:00+00:00", "decision": "flagged",
            "method": "", "host": "h",
            "inspectors": [{"name": "watcher", "severity": severity}],
        })

    @pytest.mark.parametrize("sev,min_sev", [
        ("high", "warning"),
        ("high", "error"),
        ("high", "high"),
        ("medium", "warning"),
        ("low", "info"),
        ("critical", "critical"),
    ])
    def test_watcher_severity_meets_the_filter(self, sev, min_sev):
        from agentcage.audit import AuditFilter
        assert AuditFilter(min_severity=min_sev).matches(self._entry(sev))

    @pytest.mark.parametrize("sev,min_sev", [
        ("low", "warning"),
        ("medium", "error"),
        ("info", "warning"),
    ])
    def test_watcher_severity_below_the_filter_drops(self, sev, min_sev):
        from agentcage.audit import AuditFilter
        assert not AuditFilter(min_severity=min_sev).matches(self._entry(sev))


class TestWatcherSecretClassification:
    """Review fix (conventions #2): the watcher key was classed `orphan`.

    `secret list` invites the operator to `secret rm` anything filed as
    an orphan; the repo already fixed exactly this for the decider's key
    (pinned in test_policy_api_fixes.py). The watcher key — an egress-only
    credential with no injection rule — gets the same treatment.
    """

    def test_reported_as_watcher_not_orphan(self, capsys):
        from agentcage.cli import _render_secret_list

        cfg = SimpleNamespace(
            secret_injection=[],
            container=SimpleNamespace(podman_secrets=[]),
            protocol_relays=[],
            domains=SimpleNamespace(mode="allowlist"),
            agents=SimpleNamespace(
                decider=SimpleNamespace(enable=False, api_key=""),
                watcher=SimpleNamespace(
                    enable=True,
                    api_key="env:WATCHER_LLM_KEY",
                ),
            ),
        )
        _render_secret_list(cfg, {"WATCHER_LLM_KEY"})
        out = capsys.readouterr().out
        assert "WATCHER_LLM_KEY" in out
        assert "watcher" in out
        assert "orphan" not in out


# ═══════════════════════════════════════════════════════════════════
# Host side: the read-only CLI
# ═══════════════════════════════════════════════════════════════════

def _mk_cage(patch_state_dirs, tmp_path, watcher_yaml=""):
    """Create a minimal cage the CLI can resolve, with watcher output."""
    state = patch_state_dirs
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "name: mycage\ncontainer:\n  image: localhost/test:latest\n"
        + textwrap.dedent(watcher_yaml))
    state.save_deployment("mycage", str(cfg_path))
    return state


class TestWatcherCli:
    def test_findings_reads_the_volume(self, tmp_path, monkeypatch,
                                       patch_state_dirs):
        state = _mk_cage(patch_state_dirs, tmp_path)
        wdir = state.grants_dir("mycage") / "watcher"
        wdir.mkdir(parents=True)
        (wdir / "findings.jsonl").write_text("\n".join(
            json.dumps(e) for e in [
                {"ts": "2026-01-01T00:00:00+00:00", "severity": "high",
                 "host": "evil.example", "title": "C2 beacon"},
                {"ts": "2026-01-01T00:01:00+00:00", "severity": "info",
                 "host": "ok.example", "title": "unusual UA"},
            ]) + "\n")
        from agentcage.cli import main
        from click.testing import CliRunner
        out = CliRunner().invoke(main, ["watcher", "findings", "mycage"])
        assert out.exit_code == 0
        assert "C2 beacon" in out.output
        assert "evil.example" in out.output
        # Review fix (conventions #8): the column matches its own --host
        # filter and the audit table's vocabulary.
        assert "HOST" in out.output
        assert "DOMAIN" not in out.output

    def test_findings_severity_filter(self, tmp_path, monkeypatch,
                                       patch_state_dirs):
        state = _mk_cage(patch_state_dirs, tmp_path)
        wdir = state.grants_dir("mycage") / "watcher"
        wdir.mkdir(parents=True)
        (wdir / "findings.jsonl").write_text(json.dumps(
            {"ts": "t", "severity": "high", "host": "h", "title": "x"}) + "\n")
        from agentcage.cli import main
        from click.testing import CliRunner
        out = CliRunner().invoke(
            main, ["watcher", "findings", "mycage", "-s", "info"])
        assert out.exit_code == 0
        assert "(no watcher findings recorded)" in out.output

    def test_findings_on_missing_cage(self, tmp_path, monkeypatch,
                                      patch_state_dirs):
        _mk_cage(patch_state_dirs, tmp_path)
        from agentcage.cli import main
        from click.testing import CliRunner
        out = CliRunner().invoke(main, ["watcher", "findings", "nope"])
        assert out.exit_code == 1
        assert "does not exist" in out.output

    def test_status_reports_config_and_state(self, tmp_path, monkeypatch,
                                             patch_state_dirs):
        state = _mk_cage(patch_state_dirs, tmp_path, _WATCHER_YAML)
        wdir = state.grants_dir("mycage") / "watcher"
        wdir.mkdir(parents=True)
        (wdir / "state.json").write_text(json.dumps(
            {"last_scan": "2026-01-01T00:05:00+00:00", "scans": 3,
             "flows_last_window": 42, "findings_total": 2}))
        from agentcage.cli import main
        from click.testing import CliRunner
        out = CliRunner().invoke(main, ["watcher", "status", "mycage"])
        assert out.exit_code == 0
        assert "enabled" in out.output
        assert "gpt-5-mini" in out.output
        assert "42" in out.output
        # Review fix (conventions #9): a plain `interval_seconds: 120`
        # prints 120s, not 120.0s.
        assert "120s" in out.output
        assert "120.0s" not in out.output

    def test_status_reports_disabled(self, tmp_path, monkeypatch,
                                     patch_state_dirs):
        _mk_cage(patch_state_dirs, tmp_path)
        from agentcage.cli import main
        from click.testing import CliRunner
        out = CliRunner().invoke(main, ["watcher", "status", "mycage"])
        assert out.exit_code == 0
        assert "not enabled" in out.output
