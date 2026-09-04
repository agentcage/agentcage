"""Tests for the traffic watcher — the in-egress, after-the-fact LLM auditor.

Two halves, matching the feature's split:

* host side — config parsing/validation (the ``watcher:`` cage.yaml
  block), the egress-only credential stripping, the DNS allowlist entry
  for the watcher's LLM provider host, the severity-ladder mapping, the
  secret-list classification, and the read-only CLI;
* egress side — ``data/proxy/watcher.py``: the digest builder's secret
  hygiene, the capture tail (torn-line / rotation safe, staged-commit),
  the fail-closed review, the drain-and-retry scan semantics, and the
  narrowing-only revocation path; plus the addon's audit-ring funnel.

The egress half imports the proxy modules the same way the other addon
tests do (proxy dir on sys.path, mitmproxy stubbed — see
test_addon_inspector_chain.py / test_policy_api_ssrf_guard.py).

Many tests here pin defects found by the three-lens review of the PR
(the correctness, security and conventions reviewers): each such test
carries a docstring explaining the defect it guards against.
"""

from __future__ import annotations

import asyncio
import json
import sys
import textwrap
import types
from collections import deque
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

# ── egress module import (convention: proxy dir on sys.path) ──────
_PROXY_DIR = Path(__file__).resolve().parent.parent / "src" / "agentcage" / "data" / "proxy"
if str(_PROXY_DIR) not in sys.path:
    sys.path.insert(0, str(_PROXY_DIR))
# Stub mitmproxy before importing the addon (mirrors
# test_addon_inspector_chain.py): the watcher module imports policy_api
# (mitmproxy.http), and the funnel/lifecycle tests import addon.py
# (mitmproxy.ctx, mitmproxy.http, mitmproxy.proxy.mode_specs).
_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []
_mitmproxy.ctx = types.SimpleNamespace(
    log=types.SimpleNamespace(info=lambda *a, **k: None,
                              warn=lambda *a, **k: None))
_mitmproxy.http = types.ModuleType("mitmproxy.http")
_proxy = types.ModuleType("mitmproxy.proxy")
_mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
_mode_specs.ReverseMode = object
_proxy.mode_specs = _mode_specs
_mitmproxy.proxy = _proxy
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)
sys.modules.setdefault("mitmproxy.proxy", _proxy)
sys.modules.setdefault("mitmproxy.proxy.mode_specs", _mode_specs)

from agentcage.data.proxy import watcher as wmod  # noqa: E402
from agentcage.data.proxy.watcher import (  # noqa: E402
    Watcher, build_digest, dedup_samples, parse_tool_args,
)
import policy_api as pa_mod  # noqa: E402  (bare name: egress-style import)


# ═══════════════════════════════════════════════════════════════════
# Host side: config
# ═══════════════════════════════════════════════════════════════════

_WATCHER_YAML = """
    watcher:
      enable: true
      interval_seconds: 120
      window_seconds: 7200
      max_flows: 150
      auto_revoke: false
      context: "recon test suite against staging"
      agent:
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
        w = cfg.watcher
        assert w.enable is True
        assert w.interval_seconds == 120
        assert w.window_seconds == 7200
        assert w.max_flows == 150
        assert w.auto_revoke is False
        assert w.context == "recon test suite against staging"
        assert w.agent.provider == "openai"
        assert w.agent.model == "gpt-5-mini"
        assert w.agent.api_key == "env:WATCHER_LLM_KEY"
        assert w.agent.timeout_seconds == 45
        assert w.agent.base_url == "https://api.example.com/v1"

    def test_absent_block_is_zero_surface(self, tmp_path):
        from agentcage.config import load_config
        cfg = load_config(_cfg_with(tmp_path, ""))
        assert cfg.watcher.enable is False
        assert cfg.watcher.agent.model == ""

    def test_context_non_string_rejected(self, tmp_path):
        from agentcage.config import load_config
        bad = _cfg_with(tmp_path, """
            watcher:
              enable: true
              agent:
                provider: openai
                model: m
                api_key: env:K
              context: {nope: 1}
        """)
        with pytest.raises(ValueError, match="watcher.context must be a string"):
            load_config(bad)

    # Review fix (correctness #7 / conventions #5): a malformed block
    # must not silently ride proxy-config.yaml and crash/degrade the
    # in-egress consumer — reject it at parse time.
    def test_non_mapping_block_rejected(self, tmp_path):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match="watcher must be a mapping"):
            load_config(_cfg_with(tmp_path, "watcher: true\n"))

    def test_non_mapping_agent_rejected(self, tmp_path):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match="watcher.agent must be a mapping"):
            load_config(_cfg_with(tmp_path, """
                watcher:
                  enable: true
                  agent: true
            """))

    # Review fix: bool("false") is True — a YAML string must not silently
    # ENABLE autonomous revocation against the operator's written intent.
    def test_string_auto_revoke_rejected(self, tmp_path):
        from agentcage.config import load_config
        with pytest.raises(ValueError, match="watcher.auto_revoke must be a boolean"):
            load_config(_cfg_with(tmp_path, """
                watcher:
                  enable: true
                  auto_revoke: "false"
                  agent:
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
        with pytest.raises(ValueError, match="watcher.enable must be a boolean"):
            load_config(_cfg_with(tmp_path, """
                watcher:
                  enable: "false"
                  agent:
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
            watcher:
              enable: true
              agent:
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
        with pytest.raises(ValueError, match="watcher.dedup_samples must be a boolean"):
            load_config(_cfg_with(tmp_path, """
                watcher:
                  enable: true
                  dedup_samples: "false"
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """))

    def test_dedup_defaults_on(self, tmp_path):
        from agentcage.config import load_config
        cfg = load_config(_cfg_with(tmp_path, _WATCHER_YAML))
        assert cfg.watcher.dedup_samples is True

    def test_key_is_stripped_from_the_cage_env(self, tmp_path):
        # The watcher key is an EGRESS-only credential. If the operator
        # also declared the same env var for the cage, parse-time
        # stripping must remove it from the cage env (it must never be
        # cage-visible, even as a placeholder) — the same invariant and
        # the same mechanism as the decider's key.
        from agentcage.config import load_config
        cfg = load_config(_cfg_with(tmp_path, """
            watcher:
              enable: true
              agent:
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
        with pytest.raises(ValueError, match="watcher.agent.model is required"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  agent:
                    provider: openai
                    api_key: env:K
            """)

    def test_missing_key_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="watcher.agent.api_key is required"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  agent:
                    provider: openai
                    model: m
            """)

    def test_cmd_source_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="does not support cmd:"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  agent:
                    provider: openai
                    model: m
                    api_key: cmd:cat /tmp/key
            """)

    # Review fix (conventions #4): the watcher agent block is documented
    # to follow the decider's rules VERBATIM — the decider rejects
    # `provider: Anthropic` with a message, so the watcher must too
    # (silently lowercasing is the mirror drifting).
    def test_mixed_case_provider_rejected_like_the_decider(self, tmp_path):
        with pytest.raises(ValueError, match="got 'Anthropic'"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  agent:
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
                watcher:
                  enable: true
                  interval_seconds: 0
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_explicit_zero_window_rejected_by_bounds(self, tmp_path):
        with pytest.raises(ValueError, match="window_seconds"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  window_seconds: 0
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_non_numeric_interval_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="watcher.interval_seconds must be a number"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  interval_seconds: soon
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_bad_provider_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="watcher.agent.provider"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  agent:
                    provider: ollama
                    model: m
                    api_key: env:K
            """)

    def test_http_base_url_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="https://"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
                    base_url: http://api.example.com
            """)

    def test_hot_loop_interval_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="interval_seconds"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  interval_seconds: 5
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_window_bounds_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="window_seconds"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  window_seconds: 999999
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_max_flows_bounds_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="max_flows"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  max_flows: 2
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """)

    def test_oversized_context_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="watcher.context is too long"):
            self._validate(tmp_path, """
                watcher:
                  enable: true
                  context: "%s"
                  agent:
                    provider: openai
                    model: m
                    api_key: env:K
            """ % ("x" * 4097))

    def test_disabled_block_skips_validation(self, tmp_path):
        # enable: false (or no block) must not demand a model/key — an
        # operator commenting the block out for a debug run must not be
        # blocked by validation for a feature that is off.
        self._validate(tmp_path, """
            watcher:
              enable: false
              agent:
                provider: ""
        """)


class TestWatcherPlumbing:
    def test_proxy_keys_forward_the_block(self):
        # The watcher is driven in-egress; its config rides proxy-config.yaml
        # through the same key filter every other egress setting uses.
        from agentcage.state import _PROXY_KEYS
        assert "watcher" in _PROXY_KEYS

    def test_dns_allowlist_resolves_watcher_provider_host(self, tmp_path):
        # The watcher calls its model from the addon process over urllib,
        # OUTSIDE mitmproxy — like the decider, its provider host must be
        # resolvable via the egress's dnsmasq or every scan fails.
        from agentcage.config import load_config
        from agentcage.quadlets import _effective_dns_allowlist
        cfg = load_config(_cfg_with(tmp_path, """
            domains:
              allow: [registry.npmjs.org]
            watcher:
              enable: true
              agent:
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
            watcher:
              enable: true
              agent:
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
            watcher:
              enable: true
              agent:
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
              auto:
                enable: true
                decider:
                  kind: agent
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
            domains=SimpleNamespace(auto=None),
            watcher=SimpleNamespace(
                enable=True,
                agent=SimpleNamespace(api_key="env:WATCHER_LLM_KEY"),
            ),
        )
        _render_secret_list(cfg, {"WATCHER_LLM_KEY"})
        out = capsys.readouterr().out
        assert "WATCHER_LLM_KEY" in out
        assert "watcher" in out
        assert "orphan" not in out


# ═══════════════════════════════════════════════════════════════════
# Egress side: the digest's secret hygiene
# ═══════════════════════════════════════════════════════════════════

class TestSampleDedup:
    """Repeated flow shapes collapse into one sample carrying a count.

    Real cage traffic is dominated by repetition, and forty near-identical
    samples buy nothing but tokens: measured on a real cage, 61 samples
    became 17 — 18.4% of the prompt payload. The collapse must not cost
    evidence, which is what most of these tests pin.
    """

    def _s(self, host="api.example.com", method="GET", path="/", ts="t",
           decision="allowed", status=200, body=None, size=0):
        d = {"ts": ts, "host": host, "method": method, "path": path,
             "decision": decision, "response_status": status,
             "request_body_size": size, "direction": "outbound",
             "inspectors": []}
        if body is not None:
            d["request_body_excerpt"] = body
        return d

    def test_identical_flows_collapse_with_a_count(self):
        out = dedup_samples([self._s(ts=f"t{i}") for i in range(43)])
        assert len(out) == 1
        assert out[0]["repeated"] == 43
        assert out[0]["first_ts"] == "t0" and out[0]["last_ts"] == "t42"
        assert "ts" not in out[0]   # a range, not a misleading single point

    def test_distinct_shapes_are_not_merged(self):
        out = dedup_samples([
            self._s(host="a.example"), self._s(host="b.example"),
            self._s(method="POST"), self._s(decision="blocked"),
            self._s(status=404),
        ])
        assert len(out) == 5

    def test_per_request_ids_in_paths_share_a_shape(self):
        out = dedup_samples([self._s(path=f"/repos/x/{i}") for i in range(10)])
        assert len(out) == 1 and out[0]["repeated"] == 10

    def test_hashes_in_paths_share_a_shape(self):
        out = dedup_samples([
            self._s(path="/objects/deadbeefcafe1234"),
            self._s(path="/objects/0123456789abcdef"),
        ])
        assert len(out) == 1 and out[0]["repeated"] == 2

    # The evidence-preserving property. A real revocation fired because
    # the model read a request body on an ALLOWED flow, so a group must
    # never be reduced to its first body.
    def test_distinct_bodies_survive_the_collapse(self):
        out = dedup_samples([
            self._s(method="POST", body='{"seq":1,"note":"benign"}'),
            self._s(method="POST", body='{"seq":2,"note":"benign"}'),
            self._s(method="POST", body='{"env_dump":"AWS_SECRET..."}'),
        ])
        assert len(out) == 1
        bodies = out[0]["request_body_excerpts"]
        assert any("env_dump" in b for b in bodies), bodies
        assert out[0]["distinct_request_bodies"] == 3

    def test_exfiltration_body_survives_among_many_benign_repeats(self):
        # The adversarial shape: bury one malicious body under a pile of
        # identical benign ones on the same path. A first-wins exemplar
        # would show the model only the benign body.
        flows = [self._s(method="POST", body='{"ping":1}') for _ in range(50)]
        flows.append(self._s(method="POST",
                             body='{"exfil_batch":1,"env_dump":{"GITHUB_TOKEN":"ghp_x"}}'))
        out = dedup_samples(flows)
        blob = json.dumps(out)
        assert out[0]["repeated"] == 51
        assert "exfil_batch" in blob, "the malicious body was collapsed away"

    def test_late_malicious_body_survives_many_DISTINCT_benign_bodies(self):
        """Regression: found on a real cage, not by the test above.

        With several DISTINCT benign bodies, keeping the first N distinct
        ones discarded a malicious body that arrived after them — six
        benign graphql bodies then an exfiltration body, N=3, evidence
        gone. Retention is ranked by rarity now: polling repeats,
        exfiltration does not.
        """
        flows = []
        for seq in (1, 2, 3):          # each benign body repeats
            for _ in range(2):
                flows.append(self._s(method="POST", path="/graphql",
                                     body='{"query":"{viewer}","seq":%d}' % seq))
        flows.append(self._s(method="POST", path="/graphql",
                             body='{"exfil_batch":1,"env_dump":{"AWS_KEY":"x"}}'))
        out = dedup_samples(flows, max_bodies=3)
        assert len(out) == 1
        blob = json.dumps(out)
        assert "exfil_batch" in blob, (
            "the rare (malicious) body must outrank common ones")
        assert out[0]["distinct_request_bodies"] == 4

    def test_the_common_body_is_kept_as_a_baseline(self):
        # The model needs something typical to compare the outlier to.
        flows = [self._s(method="POST", body='{"ping":1}') for _ in range(30)]
        flows += [self._s(method="POST", body='{"odd":%d}' % i) for i in range(5)]
        out = dedup_samples(flows, max_bodies=3)
        kept = out[0]["request_body_excerpts"]
        assert any("ping" in b for b in kept), kept
        assert any("odd" in b for b in kept), kept

    def test_identical_bodies_do_not_multiply(self):
        out = dedup_samples([self._s(method="POST", body="same")
                             for _ in range(20)])
        # One distinct body ⇒ the single-body field, no list, no bloat.
        assert out[0].get("request_body_excerpt") == "same"
        assert "request_body_excerpts" not in out[0]

    def test_bodies_per_group_are_bounded(self):
        out = dedup_samples([self._s(method="POST", body=f"b{i}")
                             for i in range(20)], max_bodies=3)
        assert len(out[0]["request_body_excerpts"]) == 3
        assert out[0]["distinct_request_bodies"] == 20   # count is honest

    def test_blocked_flows_keep_their_own_group(self):
        out = dedup_samples(
            [self._s(host="evil.test", decision="blocked") for _ in range(3)]
            + [self._s() for _ in range(3)])
        blocked = [s for s in out if s["decision"] == "blocked"]
        assert len(blocked) == 1 and blocked[0]["repeated"] == 3

    def test_repeat_counts_reach_the_digest(self):
        d = build_digest(audit_entries=[],
                         capture_samples=[self._s(ts=f"t{i}") for i in range(30)],
                         policy_events=[], granted=[], baseline=[],
                         max_flows=200)
        assert len(d["capture_samples"]) == 1
        assert d["capture_samples"][0]["repeated"] == 30
        # The model is told how to read a collapsed sample.
        assert "repeated" in d["note"]

    def test_dedup_can_be_turned_off(self):
        raw = [self._s(ts=f"t{i}") for i in range(30)]
        d = build_digest(audit_entries=[], capture_samples=raw,
                         policy_events=[], granted=[], baseline=[],
                         max_flows=200, dedup=False)
        assert len(d["capture_samples"]) == 30

    def test_max_flows_still_bounds_the_digest(self):
        raw = [self._s(host=f"h{i}.example") for i in range(50)]
        d = build_digest(audit_entries=[], capture_samples=raw,
                         policy_events=[], granted=[], baseline=[],
                         max_flows=10)
        assert len(d["capture_samples"]) == 10

    def test_aggregates_are_unaffected_by_collapsing(self):
        # totals come from the audit ring, not the samples — collapsing
        # capture samples must not change the flow counts.
        entries = [_flow_entry() for _ in range(7)]
        d = build_digest(audit_entries=entries,
                         capture_samples=[self._s(ts=f"t{i}") for i in range(9)],
                         policy_events=[], granted=[], baseline=[],
                         max_flows=200)
        assert d["totals"]["flows"] == 7


class TestBuildDigest:
    def test_aggregates_and_names_only_for_secrets(self):
        entries = [
            {"ts": "2026-01-01T00:00:01+00:00", "decision": "allowed",
             "host": "registry.npmjs.org", "method": "GET",
             "inspectors": [{"name": "entropy"}],
             "secrets_injected": ["API_TOKEN"],
             "secrets_redacted": ["AWS_KEY"]},
            {"ts": "2026-01-01T00:00:02+00:00", "decision": "blocked",
             "host": "evil.example", "method": "POST",
             "inspectors": [{"name": "entropy"}]},
        ]
        d = build_digest(entries, [], [], granted=[], baseline=["a.com"],
                         max_flows=10)
        assert d["totals"]["flows"] == 2
        assert d["totals"]["decisions"] == {"allowed": 1, "blocked": 1}
        assert d["top_hosts"]["registry.npmjs.org"] == 1
        assert d["top_blocked_hosts"]["evil.example"] == 1
        assert d["inspector_triggers"]["entropy"] == 2
        # NAMES only — never values.
        assert d["secrets_injected_names"] == {"API_TOKEN": 1}
        assert d["secrets_redacted_names"] == {"AWS_KEY": 1}
        assert "API_TOKEN" in json.dumps(d)
        assert "sk-real-secret" not in json.dumps(d)

    def test_carries_the_untrusted_note_and_lists(self):
        d = build_digest([], [], [], granted=["g.example"], baseline=["b.example"],
                         max_flows=10)
        assert "UNTRUSTED" in d["note"]
        assert d["current_granted"] == ["g.example"]
        assert d["current_baseline"] == ["b.example"]

    # Review fix (correctness #11): the cap kept the OLDEST samples —
    # dropping the activity that triggered the scan. Newest-keep now.
    def test_capture_samples_keep_the_newest_when_capped(self):
        samples = [{"host": f"h{i}"} for i in range(10)]
        d = build_digest([], samples, [], granted=[], baseline=[],
                         max_flows=3)
        assert [s["host"] for s in d["capture_samples"]] == ["h7", "h8", "h9"]

    def test_policy_events_are_capped_newest_keep(self):
        events = [{"kind": "policy_request", "domain": f"d{i}"} for i in range(300)]
        d = build_digest([], [], events, granted=[], baseline=[], max_flows=10)
        assert len(d["policy_events"]) == wmod._MAX_POLICY_EVENTS
        assert d["policy_events"][-1]["domain"] == "d299"


class TestSampleCapturePathSecrets:
    """PR #340 follow-up review (HIGH): the digest leaked real secrets.

    The capture entry's TOP-LEVEL ``path`` is snapshotted in
    ``addon.request()`` AFTER ``injector.inject_request`` runs, and an
    ``inject_body: true`` rule rewrites the placeholder inside
    ``flow.request.url`` — the documented ``?key=`` query-string case. So
    that field can hold the REAL secret, and ``_sample_capture`` was
    excerpting it straight into the prompt sent to a third-party model,
    breaking the module's stated invariant (secret NAMES may appear,
    values never).
    """

    def _entry(self, top_path, inbound_url):
        return {
            "ts": "2026-01-01T00:00:00+00:00", "direction": "outbound",
            "decision": "allowed", "host": "api.example.com",
            "method": "GET", "path": top_path, "inspectors": [],
            "inbound": {
                "request": {"method": "GET", "url": inbound_url,
                            "headers": [], "body": "", "bodySize": 0},
                "response": {"status": 200, "headers": [], "body": "",
                             "bodySize": 3},
            },
            "outbound": {"request": {"bodySize": 0}, "response": {}},
        }

    def test_injected_query_secret_never_reaches_the_sample(self):
        # Post-injection top-level path (what capture.jsonl records) vs
        # the pre-injection inbound url (placeholder intact).
        sample = wmod._sample_capture(self._entry(
            "/search?key=sk-real-live-secret-value",
            "https://api.example.com/search?key=agentcage:secret:GOOGLE_KEY:ab",
        ))
        blob = json.dumps(sample)
        assert "sk-real-live-secret-value" not in blob
        assert "agentcage:secret:GOOGLE_KEY:ab" in sample["path"]

    def test_path_still_carries_the_route_for_analysis(self):
        # Hygiene must not cost the signal: path + query still ride.
        sample = wmod._sample_capture(self._entry(
            "/v1/upload?id=7", "https://api.example.com/v1/upload?id=7"))
        assert sample["path"] == "/v1/upload?id=7"

    def test_falls_back_to_query_stripped_path_without_inbound_url(self):
        # No inbound url recorded (older capture file): strip the query,
        # since the query is where an injected secret rides.
        sample = wmod._sample_capture(self._entry(
            "/search?key=sk-real-live-secret-value", ""))
        assert sample["path"] == "/search"
        assert "sk-real" not in json.dumps(sample)


class TestSampleCapture:
    def _entry(self, **over):
        e = {
            "ts": "2026-01-01T00:00:00+00:00", "flow_id": "f1",
            "direction": "outbound", "decision": "allowed",
            "host": "api.example.com", "method": "POST", "path": "/v1/x",
            "inspectors": [],
            "inbound": {
                "request": {
                    "method": "POST", "url": "https://api.example.com/v1/x",
                    "headers": [["Authorization", "Bearer sk-real-secret"],
                                ["Content-Type", "application/json"]],
                    "body": '{"token": "agentcage:secret:API_TOKEN:abcd"}',
                    "bodyEncoding": None, "bodySize": 40,
                },
                "response": {"status": 200, "headers": [], "body": "",
                             "bodySize": 12},
            },
            "outbound": {
                "request": {"body": "sk-real-secret-on-the-wire", "bodySize": 26},
                "response": {},
            },
        }
        e.update(over)
        return e

    def test_outbound_body_never_rides(self):
        s = wmod._sample_capture(self._entry())
        blob = json.dumps(s)
        assert "sk-real-secret-on-the-wire" not in blob
        assert s["outbound_request_body_size"] == 26

    def test_sensitive_headers_redacted_by_name(self):
        red = wmod._redact_headers([["Authorization", "Bearer x"],
                                    ["content-type", "application/json"],
                                    ["Cookie", "a=b"]])
        assert red == [["Authorization", "[redacted]"],
                       ["content-type", "application/json"],
                       ["Cookie", "[redacted]"]]

    def test_inbound_body_excerpted_and_capped(self):
        s = wmod._sample_capture(self._entry())
        assert "request_body_excerpt" in s
        assert len(s["request_body_excerpt"]) <= wmod._BODY_EXCERPT_CHARS + 20
        long = self._entry()
        long["inbound"]["request"]["body"] = "A" * 5000
        s2 = wmod._sample_capture(long)
        assert s2["request_body_excerpt"].endswith("[truncated]")

    def test_base64_body_never_excerpted(self):
        e = self._entry()
        e["inbound"]["request"]["bodyEncoding"] = "base64"
        e["inbound"]["request"]["body"] = "c2stcmVhbC1zZWNyZXQ="
        s = wmod._sample_capture(e)
        assert "c2stcmVhbC1zZWNyZXQ" not in json.dumps(s)
        assert "binary body" in s["request_body_excerpt"]


# ═══════════════════════════════════════════════════════════════════
# Egress side: the review — fail-closed, narrowing-only
# ═══════════════════════════════════════════════════════════════════

class _FakeDom:
    def __init__(self, granted=(), baseline=(), expires=None,
                 mode="allowlist"):
        self._granted = {d: {} for d in granted}
        self._baseline = set(baseline)
        self._expires = dict(expires or {})
        # The real DomainInspector always carries a mode; the watcher's
        # blocklist guard reads it.
        self.mode = mode

    def granted_entries(self):
        return [{"domain": d, **e} for d, e in self._granted.items()]

    def baseline_list(self):
        return sorted(self._baseline)

    def is_granted(self, d):
        return d in self._granted

    def revoke(self, d):
        self._granted.pop(d, None)

    def matches_baseline(self, domain):
        parts = domain.split(".")
        return any(".".join(parts[i:]) in self._baseline
                   for i in range(len(parts)))


class _FakePa:
    def __init__(self, dom):
        self.dom = dom
        self.persisted = 0
        self.reloaded = 0

    # Reuse the REAL syntax gate — the watcher must not have its own.
    _valid_domain = staticmethod(pa_mod.PolicyApi._valid_domain)

    def maybe_reload_overlay(self):
        self.reloaded += 1

    def _persist_grants(self):
        self.persisted += 1


def _llm_ok_response(review: dict) -> dict:
    """An OpenAI-shaped response carrying one forced `review` tool call."""
    return {"choices": [{"message": {"tool_calls": [{
        "function": {"name": "review",
                     "arguments": json.dumps(review)}}]}}]}


def _mk_watcher(tmp_path, monkeypatch, *, dom=None, pa=None, ring=None,
                capture=None, cfg=None, auto_revoke=None, audit=None):
    if monkeypatch is not None:
        monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
        monkeypatch.setenv("TESTKEY", "sk-test")
    w_cfg = {
        "enable": True, "interval_seconds": 60, "window_seconds": 3600,
        "max_flows": 100, "auto_revoke": True,
        "agent": {"provider": "openai", "model": "gpt-test",
                  "api_key": "env:TESTKEY"},
    }
    if auto_revoke is not None:
        w_cfg["auto_revoke"] = auto_revoke
    w_cfg.update(cfg or {})
    cap_path = ""
    if capture is not None:
        cap_path = tmp_path / "capture.jsonl"
        cap_path.write_text("".join(json.dumps(e) + "\n" for e in capture))
    log = SimpleNamespace(warn=lambda *a, **k: None)
    audit_sink: list[dict] = audit if audit is not None else []
    w = Watcher({"watcher": w_cfg}, dom, pa, audit_sink.append, log,
                deque(ring or []), str(cap_path))
    return w, audit_sink


def _flow_entry(host="api.example.com", decision="allowed", ts=None):
    return {"ts": ts or datetime.now(timezone.utc).isoformat(),
            "decision": decision, "host": host, "method": "POST",
            "path": "/v1/x", "direction": "outbound", "inspectors": [],
            "port": 443, "url": f"https://{host}/v1/x", "reason": ""}


class TestReviewFailClosed:
    def test_llm_error_is_none(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        def boom(**kw):
            raise RuntimeError("provider down")
        monkeypatch.setattr(wmod, "llm_tool_call", boom)
        assert w._review_sync({"note": ""}) is None

    def test_no_tool_call_is_none(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: {"choices": [{"message": {}}]})
        assert w._review_sync({"note": ""}) is None

    # Review fix (correctness #6): the openai-compat parser took the
    # FIRST tool call's arguments without checking its NAME — a stray
    # call named `other` carrying revocation-shaped args was honored.
    def test_wrong_name_tool_call_is_none(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        raw = {"choices": [{"message": {"tool_calls": [{
            "function": {"name": "other",
                         "arguments": json.dumps({
                             "findings": [],
                             "allowlist_removals": [{"domain": "g.example",
                                                     "reason": "x"}]})}}]}}]}
        monkeypatch.setattr(wmod, "llm_tool_call", lambda **kw: raw)
        assert w._review_sync({"note": ""}) is None

    # Review fix: a verdict whose shape violates the contract (findings
    # present but not a list) is a scan failure, not "no findings".
    def test_malformed_verdict_structure_is_none(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch)

        def _resp(bad):
            return lambda **kw: _llm_ok_response(bad)

        for bad in ({"findings": "no"},
                    {"findings": [], "allowlist_removals": "g.example"},
                    {"findings": [], "baseline_recommendations": 42}):
            monkeypatch.setattr(wmod, "llm_tool_call", _resp(bad))
            assert w._review_sync({"note": ""}) is None

    def test_unconfigured_agent_is_none(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch,
                           cfg={"agent": {"provider": "", "model": "",
                                          "api_key": ""}})
        assert w._review_sync({"note": ""}) is None

    def test_shareable_parser_rejects_wrong_name_for_decider_too(self):
        # The shared helper now pins the name on BOTH wire formats —
        # the decider (which shares it) inherits the fix.
        raw = {"choices": [{"message": {"tool_calls": [{
            "function": {"name": "decide_plus",
                         "arguments": json.dumps({"decision": "grant"})}}]}}]}
        assert parse_tool_args(raw, "openai", "decide") == {}


class TestTick:
    def test_scan_failure_is_recorded_not_silent(self, tmp_path, monkeypatch):
        # A failed scan must leave a trace and revoke nothing.
        dom = _FakeDom(granted=["granted.example"])
        pa = _FakePa(dom)
        w, audit = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                                ring=[_flow_entry()])
        def boom(**kw):
            raise RuntimeError("timeout")
        monkeypatch.setattr(wmod, "llm_tool_call", boom)
        asyncio.run(w._tick())
        f = tmp_path / "watcher" / "findings.jsonl"
        assert f.is_file()
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        assert any("scan failed" in l["title"] for l in lines)
        assert dom.is_granted("granted.example")  # nothing revoked
        assert pa.persisted == 0
        assert any(e["kind"] == "watcher_finding" for e in audit)

    # Review fix (correctness #2): the LLM call runs off the event loop
    # (asyncio.to_thread, mirroring the decider). A slow provider must
    # never stall mitmproxy's loop — pin that the network call happens
    # in a worker thread by racing a concurrent loop task against it.
    def test_llm_call_does_not_block_the_event_loop(self, tmp_path, monkeypatch):
        import threading
        w, _ = _mk_watcher(tmp_path, monkeypatch, ring=[_flow_entry()])

        def slow(**kw):
            # From inside a worker thread, the loop must stay responsive.
            assert threading.current_thread() is not threading.main_thread()
            import time as _t
            _t.sleep(0.15)
            return _llm_ok_response({"findings": []})

        monkeypatch.setattr(wmod, "llm_tool_call", slow)
        ticks: list[float] = []

        async def heartbeat():
            loop = asyncio.get_event_loop()
            for _ in range(5):
                await asyncio.sleep(0.02)
                ticks.append(loop.time())

        async def race():
            await asyncio.gather(w._tick(), heartbeat())

        asyncio.run(race())
        # The heartbeat kept firing while the (slow) review ran, and the
        # verdict was still applied.
        assert len(ticks) >= 4
        st = json.loads((tmp_path / "watcher" / "state.json").read_text())
        assert st["scans"] == 1

    # Review fix (correctness #3): a failed scan must NOT consume the
    # evidence it failed to analyze — the drained batch is pushed back
    # to the front of the ring and re-analyzed on the next tick.
    def test_failed_scan_pushes_back_and_retries(self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["g.example"])
        pa = _FakePa(dom)
        w, _ = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                            ring=[_flow_entry("suspicious.example")])
        calls = {"n": 0}

        def flaky(**kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("timeout")
            return _llm_ok_response({"findings": [
                {"severity": "high", "title": "saw the retry",
                 "detail": "evidence", "recommendation": "none"}]})

        monkeypatch.setattr(wmod, "llm_tool_call", flaky)
        asyncio.run(w._tick())   # fails → evidence queued for retry
        assert len(w._ring) == 1
        assert w._ring[0]["host"] == "suspicious.example"
        asyncio.run(w._tick())   # succeeds → the retry was analyzed
        assert len(w._ring) == 0
        assert calls["n"] == 2
        f = tmp_path / "watcher" / "findings.jsonl"
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        assert any(l["title"] == "saw the retry" for l in lines)

    # Review fix: the failed-scan finding is throttled so a dead
    # provider cannot flood findings.jsonl (first failure, then every
    # 10th consecutive one).
    def test_scan_failure_finding_is_throttled(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch, ring=[_flow_entry()])
        def boom(**kw):
            raise RuntimeError("down")
        monkeypatch.setattr(wmod, "llm_tool_call", boom)
        asyncio.run(w._tick())
        asyncio.run(w._tick())
        f = tmp_path / "watcher" / "findings.jsonl"
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        scan_failures = [l for l in lines if "scan failed" in l["title"]]
        assert len(scan_failures) == 1  # second consecutive failure: silent

    # Review fix (correctness #3): the watcher's OWN audit records must
    # never be fed back into the model's evidence (a failed scan's
    # noise would otherwise become the next scan's subject).
    def test_self_emitted_records_are_not_reingested(self, tmp_path, monkeypatch):
        digests = []
        def spy(**kw):
            digests.append(json.loads(kw["user_content"]))
            return _llm_ok_response({"findings": []})
        monkeypatch.setattr(wmod, "llm_tool_call", spy)
        w, _ = _mk_watcher(
            tmp_path, monkeypatch, ring=[
                _flow_entry("real.example"),
                {"kind": "watcher_finding", "ts": "2026-01-01T00:00:00+00:00",
                 "decision": "flagged", "method": "", "host": "self",
                 "title": "old noise"},
            ])
        asyncio.run(w._tick())
        assert len(digests) == 1
        assert digests[0]["totals"]["flows"] == 1  # the real entry only
        assert "old noise" not in json.dumps(digests[0])

    def test_findings_revoke_recommended(self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["granted.example"], baseline=["base.example"])
        pa = _FakePa(dom)
        w, audit = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                                ring=[_flow_entry("granted.example")])
        review = {
            "findings": [{"severity": "high", "title": "C2 beacon",
                          "detail": "evidence",
                          "recommendation": "revoke"}],
            "allowlist_removals": [{"domain": "granted.example",
                                    "reason": "beaconed every 30s"}],
            "baseline_recommendations": [{"domain": "base.example",
                                          "reason": "unused for 30d"}],
        }
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())

        # The grant is revoked, persisted (overlay + DNS republish), audited.
        assert not dom.is_granted("granted.example")
        assert pa.persisted == 1
        assert any(e["kind"] == "watcher_revoke"
                   and e["domain"] == "granted.example" for e in audit)
        # The baseline domain is NOT revoked — only recommended.
        assert "base.example" in dom.baseline_list()
        f = tmp_path / "watcher" / "findings.jsonl"
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        assert any("base.example" in l["title"] and "domain rm" in
                   l["recommendation"] for l in lines)
        assert any(l["severity"] == "high" and l["title"] == "C2 beacon"
                   for l in lines)

    # Review fix (correctness #9): persist per-revocation (the removal
    # endpoint's posture) — a batched persist at the end widens the
    # documented revoke↔persist TOCTOU across the whole batch.
    def test_persist_happens_per_revocation(self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["g1.example", "g2.example"])
        pa = _FakePa(dom)
        w, _ = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                            ring=[_flow_entry()])
        review = {"findings": [],
                 "allowlist_removals": [
                     {"domain": "g1.example", "reason": "beacon"},
                     {"domain": "g2.example", "reason": "beacon"},
                 ]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())
        assert not dom.is_granted("g1.example")
        assert not dom.is_granted("g2.example")
        assert pa.persisted == 2

    # Review fix (correctness #10): a grant that an ACTIVE baseline
    # suffix also covers stays reachable after the revoke — the audit
    # must say so (still_allowed_by_baseline) and a baseline-removal
    # recommendation must be recorded, instead of claiming "blocked".
    def test_baseline_overlap_is_flagged(self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["api.example.com"], baseline=["example.com"])
        pa = _FakePa(dom)
        w, audit = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                                ring=[_flow_entry("api.example.com")])
        review = {"findings": [],
                 "allowlist_removals": [{"domain": "api.example.com",
                                         "reason": "beacon"}]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())
        assert not dom.is_granted("api.example.com")
        revoke = [e for e in audit if e["kind"] == "watcher_revoke"][0]
        assert revoke["still_allowed_by_baseline"] is True
        f = tmp_path / "watcher" / "findings.jsonl"
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        assert any("baseline still allows" in l["title"] for l in lines)

    def test_removal_of_a_baseline_domain_is_structurally_refused(
            self, tmp_path, monkeypatch):
        # A hallucinated or baseline domain in allowlist_removals must
        # never touch anything: it is not a live grant, so the watcher
        # records an info finding instead.
        dom = _FakeDom(granted=["g.example"], baseline=["base.example"])
        pa = _FakePa(dom)
        w, _ = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                            ring=[_flow_entry()])
        review = {"findings": [],
                  "allowlist_removals": [{"domain": "base.example",
                                          "reason": "hallucinated"}]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())
        assert dom.is_granted("g.example")      # untouched
        assert "base.example" in dom.baseline_list()  # untouched
        f = tmp_path / "watcher" / "findings.jsonl"
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        assert any("not a runtime grant" in l["title"] for l in lines)

    def test_never_revoke_and_invalid_syntax_skipped(
            self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["g.example"])
        pa = _FakePa(dom)
        w, _ = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                            ring=[_flow_entry()])
        review = {"findings": [],
                  "allowlist_removals": [
                      {"domain": "metadata.google.internal", "reason": "x"},
                      {"domain": "169-254-169-254.nip.io", "reason": "x"},
                      {"domain": "not a domain", "reason": "x"},
                  ]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())  # no crash, nothing revoked, nothing persisted
        assert dom.is_granted("g.example")
        assert pa.persisted == 0

    def test_auto_revoke_off_leaves_everything(self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["g.example"])
        pa = _FakePa(dom)
        w, _ = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                            ring=[_flow_entry()], auto_revoke=False)
        review = {"findings": [],
                  "allowlist_removals": [{"domain": "g.example",
                                          "reason": "beacon"}]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())
        assert dom.is_granted("g.example")
        assert pa.persisted == 0

    # PR #340 follow-up review: auto_revoke off DISCARDED the removals
    # with no record at all, though config.py's own field comment says
    # they "degrade to findings the operator applies" — and the how-to
    # tells operators to start in exactly this posture, so the
    # recommended starting mode threw away each scan's most actionable
    # output.
    def test_auto_revoke_off_still_records_the_recommendation(
            self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["g.example"])
        pa = _FakePa(dom)
        w, audit = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                               ring=[_flow_entry()], auto_revoke=False)
        review = {"findings": [],
                  "allowlist_removals": [{"domain": "g.example",
                                          "reason": "beacon"}]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())
        # Still narrowing nothing...
        assert dom.is_granted("g.example")
        assert pa.persisted == 0
        # ...but the operator can see what the analysis wanted done.
        titles = [e.get("title", "") for e in audit
                  if e.get("kind") == "watcher_finding"]
        assert any("g.example" in t and "revocation recommended" in t
                   for t in titles), titles

    # PR #340 follow-up review: in blocklist mode DomainInspector._baseline
    # IS the block list, so the digest and any baseline recommendation
    # invert — "remove this domain" would WIDEN egress. Rejected at config
    # time; re-checked here because a hot-reload can flip the mode.
    def test_blocklist_mode_skips_revocation_with_a_finding(
            self, tmp_path, monkeypatch):
        dom = _FakeDom(granted=["g.example"], mode="blocklist")
        pa = _FakePa(dom)
        w, audit = _mk_watcher(tmp_path, monkeypatch, dom=dom, pa=pa,
                               ring=[_flow_entry()])
        review = {"findings": [],
                  "allowlist_removals": [{"domain": "g.example",
                                          "reason": "beacon"}]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())
        assert dom.is_granted("g.example")
        assert pa.persisted == 0
        titles = [e.get("title", "") for e in audit
                  if e.get("kind") == "watcher_finding"]
        assert any("allowlist mode" in t for t in titles), titles

    def test_no_traffic_skips_the_llm_call(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch, ring=[], capture=[])
        def boom(**kw):
            raise AssertionError("quiet cage must not call the model")
        monkeypatch.setattr(wmod, "llm_tool_call", boom)
        asyncio.run(w._tick())  # no exception
        st = json.loads((tmp_path / "watcher" / "state.json").read_text())
        assert st["flows_last_window"] == 0

    def test_removals_degrade_to_findings_without_domains_auto(
            self, tmp_path, monkeypatch):
        # No PolicyApi ⇒ no runtime grants exist ⇒ removals become
        # findings, never crashes.
        w, _ = _mk_watcher(tmp_path, monkeypatch, dom=None, pa=None,
                            ring=[_flow_entry()])
        review = {"findings": [],
                  "allowlist_removals": [{"domain": "g.example",
                                          "reason": "beacon"}]}
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: _llm_ok_response(review))
        asyncio.run(w._tick())
        f = tmp_path / "watcher" / "findings.jsonl"
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        assert any("cannot revoke" in l["title"] for l in lines)


class TestCaptureTail:
    def _cap(self, host, minutes_ago):
        ts = (datetime.now(timezone.utc) -
              timedelta(minutes=minutes_ago)).isoformat()
        return {"ts": ts, "host": host, "direction": "outbound",
                "decision": "allowed", "method": "GET", "path": "/",
                "inspectors": [],
                "inbound": {"request": {"body": "", "bodySize": 1},
                            "response": {"status": 200, "bodySize": 2}},
                "outbound": {"request": {}, "response": {}}}

    def _commit(self, w, now):
        samples, off, fid = w._read_capture(now)
        w._cap_offset, w._cap_file_id = off, fid
        return samples, off

    def test_first_scan_windows_then_increments(self, tmp_path, monkeypatch):
        cap = tmp_path / "capture.jsonl"
        cap.write_text(json.dumps(self._cap("old.example", 300)) + "\n" +
                       json.dumps(self._cap("new.example", 1)) + "\n")
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        first, _ = self._commit(w, now)
        assert [s["host"] for s in first] == ["new.example"]
        # New bytes appear → only they are returned.
        with open(cap, "a") as f:
            f.write(json.dumps(self._cap("newer.example", 0)) + "\n")
        second, _ = self._commit(w, now)
        assert [s["host"] for s in second] == ["newer.example"]

    def test_truncated_file_resets(self, tmp_path, monkeypatch):
        cap = tmp_path / "capture.jsonl"
        cap.write_text(json.dumps(self._cap("a.example", 1)) + "\n")
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        self._commit(w, now)
        # Rotation/truncation: file shrinks below the offset.
        cap.write_text(json.dumps(self._cap("b.example", 0)) + "\n")
        w._cap_offset = w._cap_offset + 4096
        got, _ = self._commit(w, now)
        assert [s["host"] for s in got] == ["b.example"]

    # Review fix (correctness #5): a torn tail line (an in-flight write)
    # must stay UNCONSUMED — the offset advances only past complete
    # lines, so the completed line is parsed whole on the next scan.
    def test_torn_tail_line_is_not_consumed(self, tmp_path, monkeypatch):
        cap = tmp_path / "capture.jsonl"
        full = json.dumps(self._cap("torn.example", 0)) + "\n"
        cap.write_text(full[:len(full) // 2])  # torn: no trailing newline
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        samples, off = self._commit(w, now)
        assert samples == []
        assert off == 0  # nothing consumed
        # The writer completes the line; the next scan reads it WHOLE.
        cap.write_text(full)
        samples, _ = self._commit(w, now)
        assert [s["host"] for s in samples] == ["torn.example"]

    # Review fix (correctness #5): same-size rotation is invisible to a
    # size check — the tail tracks (st_dev, st_ino) and resets on
    # identity change.
    def test_rotation_by_inode_resets_the_tail(self, tmp_path, monkeypatch):
        cap = tmp_path / "capture.jsonl"
        entry_a = json.dumps(self._cap("a.example", 1)) + "\n"
        cap.write_text(entry_a)
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        first, off = self._commit(w, now)
        assert [s["host"] for s in first] == ["a.example"]
        old_size = cap.stat().st_size
        # Rotate: a NEW file (same size) replaces the old one.
        replacement = tmp_path / "replacement.jsonl"
        replacement.write_text(json.dumps(self._cap("b.example", 0)) + "\n")
        assert replacement.stat().st_size == old_size  # size check blind
        os_replace = __import__("os").replace
        os_replace(replacement, cap)
        got, _ = self._commit(w, now)
        assert [s["host"] for s in got] == ["b.example"]

    # Review fix (PR #340 follow-up): the window filter only applied to
    # the chunk read at offset==0. A reset backlog bigger than
    # _CAP_READ_CHUNK is read across several ticks, and every chunk
    # after the first had offset != 0 — so stale entries beyond the
    # first chunk bypassed the window filter entirely.
    def test_window_filter_applies_across_multiple_reset_chunks(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(wmod, "_CAP_READ_CHUNK", 300)
        cap = tmp_path / "capture.jsonl"
        old_lines = [json.dumps(self._cap(f"old{i}.example", 300))
                    for i in range(20)]  # well outside the window
        cap.write_text("\n".join(old_lines) +
                       "\n" + json.dumps(self._cap("new.example", 1)) + "\n")
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        all_hosts: list[str] = []
        for _ in range(50):  # catch up across as many ticks as it takes
            samples, off = self._commit(w, now)
            all_hosts.extend(s["host"] for s in samples)
            if off >= cap.stat().st_size:
                break
        # Every "old*" entry must be filtered out, in every chunk — not
        # just the first one.
        assert all_hosts == ["new.example"]

    # Review fix (PR #340 follow-up): a line with no newline was always
    # treated as an in-flight torn tail and left unconsumed forever —
    # correct for a write in progress, but an infinite stall if the
    # line is simply oversized (no terminator ever coming within a
    # sane budget). Past _MAX_LINE_BYTES it is now dropped instead.
    def test_oversized_line_advances_offset_instead_of_stalling(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(wmod, "_MAX_LINE_BYTES", 500)
        cap = tmp_path / "capture.jsonl"
        huge = self._cap("huge.example", 0)
        huge["inbound"]["request"]["body"] = "x" * 5000
        cap.write_text(json.dumps(huge))  # no trailing newline anywhere
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        samples, off = self._commit(w, now)
        assert samples == []
        assert off > 0  # pre-fix: off == 0 forever — a permanent stall

        # Recovery: a complete entry appended after the garbage is read
        # normally on the very next tick.
        with open(cap, "a") as f:
            f.write("\n" + json.dumps(self._cap("fresh.example", 0)) + "\n")
        samples2, _ = self._commit(w, now)
        assert [s["host"] for s in samples2] == ["fresh.example"]

    # Review fix (PR #340 follow-up): the sample cap was a fixed
    # _MAX_CAPTURE_SAMPLES=50 constant, making watcher.max_flows above
    # 50 — including the validated/documented 10-2000 range — a silent
    # no-op. The cap now follows the configured max_flows.
    def test_capture_samples_capped_at_configured_max_flows(
            self, tmp_path, monkeypatch):
        cap_entries = [self._cap(f"h{i}.example", 1) for i in range(15)]
        cap = tmp_path / "capture.jsonl"
        cap.write_text("".join(json.dumps(e) + "\n" for e in cap_entries))
        w, _ = _mk_watcher(tmp_path, monkeypatch, cfg={"max_flows": 12})
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        samples, _ = self._commit(w, now)
        assert len(samples) == 12
        assert [s["host"] for s in samples] == \
            [f"h{i}.example" for i in range(3, 15)]


    # PR #340 follow-up review: the oversized-line guard tested the whole
    # accumulated read instead of the un-terminated LINE. Any backlog
    # bigger than _MAX_LINE_BYTES ends its read mid-line, so every chunk
    # boundary looked "oversized" and one COMPLETE entry per tick was
    # silently dropped with a false warning — evidence loss in a security
    # auditor.
    def test_large_backlog_loses_no_entries(self, tmp_path, monkeypatch):
        monkeypatch.setattr(wmod, "_CAP_READ_CHUNK", 300)
        monkeypatch.setattr(wmod, "_MAX_LINE_BYTES", 1200)
        warns: list[str] = []
        cap = tmp_path / "capture.jsonl"
        n = 60
        cap.write_text("".join(
            json.dumps(self._cap(f"h{i:03d}.example", 1)) + "\n"
            for i in range(n)))
        w, _ = _mk_watcher(tmp_path, monkeypatch, cfg={"max_flows": 2000})
        w._capture_path = str(cap)
        w._window = 3600
        w._log = SimpleNamespace(warn=warns.append)
        now = datetime.now(timezone.utc)
        seen: list[str] = []
        for _ in range(300):
            samples, off = self._commit(w, now)
            seen.extend(x["host"] for x in samples)
            if off >= cap.stat().st_size:
                break
        assert seen == [f"h{i:03d}.example" for i in range(n)]
        assert warns == []  # no false "oversized" warnings

    # PR #340 follow-up review: the reset target was cleared inside
    # _read_capture, which only STAGES the offset. When the final
    # catch-up tick's scan then failed, the retry re-read the same bytes
    # with the window filter already dropped and fed out-of-window
    # traffic to the model.
    def test_reset_filter_survives_a_failed_scan(self, tmp_path, monkeypatch):
        cap = tmp_path / "capture.jsonl"
        # Everything is far outside the window.
        cap.write_text("".join(
            json.dumps(self._cap(f"old{i}.example", 7200)) + "\n"
            for i in range(4)))
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        now = datetime.now(timezone.utc)
        # A read whose scan FAILS: staged, never committed.
        first, _off, _fid = w._read_capture(now)
        assert first == []
        # The retry must still filter — the bytes were never analyzed.
        again, _off2, _fid2 = w._read_capture(now)
        assert again == []


class TestPushBack:
    """Review fix (PR #340 follow-up): ``extendleft(reversed(...))`` on
    a bounded deque evicts from the OPPOSITE (right/newest) end when
    full — the reverse of the documented intent. ``entries`` is the
    OLDER, already-drained batch; anything still in the ring arrived
    more recently and must not be displaced by it.
    """

    def test_keeps_newest_live_entries_over_the_stale_batch(
            self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._ring = deque(maxlen=5)
        w._ring.extend([{"n": "live-1"}, {"n": "live-2"}, {"n": "live-3"}])
        failed_batch = [{"n": "old-1"}, {"n": "old-2"},
                        {"n": "old-3"}, {"n": "old-4"}]
        w._push_back(failed_batch)
        names = [e["n"] for e in w._ring]
        # Only 2 slots free (5 - 3 live): keep the batch's own most
        # recent tail (old-3, old-4), never evict the live entries.
        assert names == ["old-3", "old-4", "live-1", "live-2", "live-3"]

    def test_noop_when_ring_already_full_of_live_entries(
            self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._ring = deque(maxlen=3)
        w._ring.extend([{"n": "live-1"}, {"n": "live-2"}, {"n": "live-3"}])
        w._push_back([{"n": "old-1"}])
        assert [e["n"] for e in w._ring] == ["live-1", "live-2", "live-3"]


class TestWatcherPrompt:
    def test_untrusted_data_framing(self):
        p = Watcher._system_prompt()
        assert "UNTRUSTED DATA" in p
        assert "never instructions" in p
        # Manipulation-attempts-are-findings rule is pinned.
        assert "ITSELF A FINDING" in p
        # Baseline immutability is stated as an output rule.
        assert "baseline_recommendations" in p

    def test_context_block_is_delimited_and_last_word_is_the_contract(self):
        w, _ = _mk_watcher(None, None, cfg={"context": "payments recon suite"})
        p = w._watcher_system_prompt()
        assert "BEGIN OPERATOR CONTEXT" in p
        assert "payments recon suite" in p
        assert "END OPERATOR CONTEXT" in p
        assert p.rstrip().endswith("enforced gate.")

    def test_no_context_is_unchanged_core(self):
        w, _ = _mk_watcher(None, None)
        assert w._watcher_system_prompt() == Watcher._system_prompt()


# ═══════════════════════════════════════════════════════════════════
# Egress side: the addon funnel + watcher lifecycle
# ═══════════════════════════════════════════════════════════════════

class TestAddonAuditFunnel:
    """Review fix (correctness #1 — BLOCKING): the ring was never fed.

    Ordinary HTTP decisions went through ``_log``, which wrote its own
    stderr/file sinks and never touched the ring — so with capture off
    (the default useful mode) the watcher saw NO traffic and every scan
    was a no-op. ``_log`` (and ``_log_peer_block``) now ride the ONE
    funnel (``_audit_write`` → ``_ring_ingest``), and ALLOWED traffic is
    ingested even when ``logging.allowed_requests`` suppresses the
    durable output — exfil patterns live in allowed traffic.
    """

    def _addon(self, *, ring=None, log_allowed=False):
        from agentcage.data.proxy.addon import Agentcage
        a = Agentcage()
        a._watcher_ring = ring if ring is not None else deque()
        a.log_allowed = log_allowed
        a._audit_file = None
        a._audit_capped = False
        return a

    def _flow(self, host="x.example"):
        req = SimpleNamespace(method="GET", host=host, port=443,
                              path="/p", url=f"https://{host}/p")
        return SimpleNamespace(request=req)

    def test_suppressed_allowed_traffic_still_feeds_the_ring(self):
        a = self._addon(log_allowed=False)
        a._log(self._flow(), "allowed", None, [])
        assert len(a._watcher_ring) == 1
        assert a._watcher_ring[0]["host"] == "x.example"
        assert a._watcher_ring[0]["decision"] == "allowed"

    def test_suppressed_allowed_writes_no_durable_output(self):
        a = self._addon(log_allowed=False)
        a._audit_file = StringIO()
        a._log(self._flow(), "allowed", None, [])
        assert len(a._watcher_ring) == 1
        assert a._audit_file.getvalue() == ""  # durable sinks suppressed

    def test_flagged_goes_through_the_full_funnel(self):
        a = self._addon(log_allowed=False)
        a._audit_file = StringIO()
        a._log(self._flow(), "flagged", "entropy", [])
        assert len(a._watcher_ring) == 1
        assert a._audit_file.getvalue() != ""  # durable sinks on

    def test_unsuppressed_allowed_feeds_the_ring_once(self):
        # log_allowed=True: the entry rides _audit_write (one funnel,
        # one ring append — no double ingestion).
        a = self._addon(log_allowed=True)
        a._log(self._flow(), "allowed", None, [])
        assert len(a._watcher_ring) == 1

    def test_peer_block_feeds_the_ring(self):
        a = self._addon()
        a._log_peer_block("h.internal", "169.254.169.254",
                          "connect", "peer is private")
        assert len(a._watcher_ring) == 1
        assert a._watcher_ring[0]["kind"] == "private_peer_blocked"

    def test_no_watcher_no_ring_no_crash(self):
        # Watcher disabled: _log must behave exactly as before (no ring,
        # durable sinks as configured) — zero-surface invariant.
        a = self._addon(ring=None, log_allowed=True)
        a._audit_file = StringIO()
        a._log(self._flow(), "allowed", None, [])
        assert a._audit_file.getvalue() != ""


class TestWatcherHotReload:
    """Review fix (correctness #8): every config reload rebuilt the
    watcher — discarding scan state (capture offset, counters) and
    re-analyzing the same window on an UNRELATED config edit (e.g.
    logging.level). _init_watcher now no-ops when the watcher block is
    unchanged, and constructs the replacement BEFORE cancelling the old
    task so a malformed hot-reload keeps the last working watcher.
    """

    W_CFG = {"enable": True, "interval_seconds": 60, "window_seconds": 3600,
             "max_flows": 100, "auto_revoke": True,
             "agent": {"provider": "openai", "model": "m",
                       "api_key": "env:TESTKEY"}}

    def _bare_addon(self, monkeypatch, tmp_path, cfg):
        monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
        monkeypatch.setenv("TESTKEY", "sk-test")
        from agentcage.data.proxy.addon import Agentcage
        a = Agentcage()
        a.cfg = cfg
        a.inspectors = []
        a.domain_requests = None
        a.traffic_watcher = None
        a._watcher_task = None
        a._watcher_ring = None
        a._running = False
        return a

    def test_unchanged_block_keeps_the_watcher_and_state(
            self, tmp_path, monkeypatch):
        a = self._bare_addon(monkeypatch, tmp_path,
                             {"watcher": dict(self.W_CFG)})
        a._init_watcher()
        first = a.traffic_watcher
        assert first is not None
        first._scans = 7  # simulated scan history
        # A hot-reload with the SAME watcher block (any unrelated config
        # change lands in _maybe_reload → _init_watcher):
        a._init_watcher()
        assert a.traffic_watcher is first
        assert a.traffic_watcher._scans == 7

    # Review fix (PR #340 follow-up): the unchanged-block path kept the
    # live watcher WITHOUT re-pointing its refs. ``domains.auto`` gets a
    # brand new ``PolicyApi`` on every reload (_init_domain_requests
    # runs unconditionally above _init_watcher), so an unrefreshed
    # ``_pa`` would keep revoking through a discarded, sweeper-cancelled
    # instance; and ``secret set`` re-stages the key file without
    # changing the config value that names it, so the key must be
    # re-read too.
    def test_unchanged_block_still_refreshes_pa_and_key(
            self, tmp_path, monkeypatch):
        a = self._bare_addon(monkeypatch, tmp_path,
                             {"watcher": dict(self.W_CFG)})
        a._init_watcher()
        watcher = a.traffic_watcher
        assert watcher is not None

        new_pa = object()
        a.domain_requests = new_pa
        monkeypatch.setenv("TESTKEY", "sk-rotated")
        a._init_watcher()  # watcher block unchanged → same instance kept

        assert a.traffic_watcher is watcher
        assert a.traffic_watcher._pa is new_pa
        assert a.traffic_watcher._secret == "sk-rotated"

    def test_changed_block_rebuilds(self, tmp_path, monkeypatch):
        a = self._bare_addon(monkeypatch, tmp_path,
                             {"watcher": dict(self.W_CFG)})
        a._init_watcher()
        first = a.traffic_watcher
        a.cfg = {"watcher": {**self.W_CFG, "interval_seconds": 120}}
        a._init_watcher()
        assert a.traffic_watcher is not first

    def test_disabled_block_stops_the_watcher(self, tmp_path, monkeypatch):
        a = self._bare_addon(monkeypatch, tmp_path, {"watcher": {}})
        a._init_watcher()
        assert a.traffic_watcher is None
        assert a._watcher_ring is None

    # Review fix (correctness #7): `watcher: true` rode proxy-config and
    # crashed _init_watcher OUTSIDE its guard (an AttributeError on
    # bool.get) — failing the addon load and taking the egress down.
    # A non-mapping block now disables the watcher with a warning.
    def test_non_mapping_block_disables_gracefully(self, tmp_path, monkeypatch):
        a = self._bare_addon(monkeypatch, tmp_path, {"watcher": True})
        a._init_watcher()  # must not raise
        assert a.traffic_watcher is None

    def test_malformed_rebuild_keeps_the_old_watcher(
            self, tmp_path, monkeypatch):
        a = self._bare_addon(monkeypatch, tmp_path,
                             {"watcher": dict(self.W_CFG)})
        a._init_watcher()
        first = a.traffic_watcher

        # Simulate a rebuild whose construction fails (the in-egress ctor
        # is defensive by design, so break it from outside — what the
        # keep-old path guards is any ctor failure, e.g. a future parse
        # that starts rejecting instead of warning).
        class _Broken(Watcher):
            def __init__(self, *a, **kw):
                raise RuntimeError("deformed block")

        # The addon imports its sibling by BARE module name (`from
        # watcher import Watcher` — the egress sys.path convention), which
        # is a separate module object from agentcage.data.proxy.watcher;
        # patch the bare one, that's the one _init_watcher imports from.
        monkeypatch.setattr(sys.modules["watcher"], "Watcher", _Broken)
        a.cfg = {"watcher": {**self.W_CFG, "interval_seconds": 120}}
        a._init_watcher()  # construction fails → old watcher kept
        assert a.traffic_watcher is first


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
