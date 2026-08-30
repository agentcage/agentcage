"""Tests for the traffic watcher — the in-egress, after-the-fact LLM auditor.

Two halves, matching the feature's split:

* host side — config parsing/validation (the ``watcher:`` cage.yaml
  block), the egress-only credential stripping, the DNS allowlist entry
  for the watcher's LLM provider host, and the read-only CLI;
* egress side — ``data/proxy/watcher.py``: the digest builder's secret
  hygiene, the capture tail, the fail-closed review, and the
  narrowing-only revocation path.

The egress half imports the proxy modules the same way the other addon
tests do (proxy dir on sys.path, mitmproxy stubbed — see
test_addon_inspector_chain.py / test_policy_api_ssrf_guard.py).
"""

from __future__ import annotations

import json
import sys
import textwrap
import types
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

# ── egress module import (convention: proxy dir on sys.path) ──────
_PROXY_DIR = Path(__file__).resolve().parent.parent / "src" / "agentcage" / "data" / "proxy"
if str(_PROXY_DIR) not in sys.path:
    sys.path.insert(0, str(_PROXY_DIR))
sys.modules.setdefault("mitmproxy", types.ModuleType("mitmproxy"))
sys.modules.setdefault("mitmproxy.http", types.ModuleType("mitmproxy.http"))

from agentcage.data.proxy import watcher as wmod  # noqa: E402
from agentcage.data.proxy.watcher import (  # noqa: E402
    Watcher, build_digest, parse_tool_args,
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
    need their own container: block without duplicating the key)."""
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
# Egress side: the digest's secret hygiene
# ═══════════════════════════════════════════════════════════════════

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
        s = wmod._sample_capture(self._entry())
        hdrs = {h[0]: h[1] for h in s.get("response_headers_sample", [])}
        # request headers ride via the excerpt only; response headers are
        # redacted by name — assert the redaction helper itself:
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
    def __init__(self, granted=(), baseline=()):
        self._granted = {d: {} for d in granted}
        self._baseline = list(baseline)

    def granted_entries(self):
        return [{"domain": d, **e} for d, e in self._granted.items()]

    def baseline_list(self):
        return list(self._baseline)

    def is_granted(self, d):
        return d in self._granted

    def revoke(self, d):
        self._granted.pop(d, None)


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
                capture=None, cfg=None, auto_revoke=None):
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
    audit: list[dict] = []
    w = Watcher({"watcher": w_cfg}, dom, pa, audit.append, log,
                deque(ring or []), str(cap_path))
    return w, audit


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
        assert w._review({"note": ""}) is None

    def test_no_tool_call_is_none(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        monkeypatch.setattr(wmod, "llm_tool_call",
                            lambda **kw: {"choices": [{"message": {}}]})
        assert w._review({"note": ""}) is None

    def test_unconfigured_agent_is_none(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch,
                           cfg={"agent": {"provider": "", "model": "",
                                          "api_key": ""}})
        assert w._review({"note": ""}) is None


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
        w._tick()
        f = tmp_path / "watcher" / "findings.jsonl"
        assert f.is_file()
        lines = [json.loads(l) for l in f.read_text().splitlines()]
        assert any("scan failed" in l["title"] for l in lines)
        assert dom.is_granted("granted.example")  # nothing revoked
        assert pa.persisted == 0
        assert any(e["kind"] == "watcher_finding" for e in audit)

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
        w._tick()

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
        w._tick()
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
        w._tick()  # no crash, nothing revoked, nothing persisted
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
        w._tick()
        assert dom.is_granted("g.example")
        assert pa.persisted == 0

    def test_no_traffic_skips_the_llm_call(self, tmp_path, monkeypatch):
        w, _ = _mk_watcher(tmp_path, monkeypatch, ring=[], capture=[])
        def boom(**kw):
            raise AssertionError("quiet cage must not call the model")
        monkeypatch.setattr(wmod, "llm_tool_call", boom)
        w._tick()  # no exception
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
        w._tick()
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

    def test_first_scan_windows_then_increments(self, tmp_path, monkeypatch):
        cap = tmp_path / "capture.jsonl"
        cap.write_text(json.dumps(self._cap("old.example", 300)) + "\n" +
                       json.dumps(self._cap("new.example", 1)) + "\n")
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        first = w._tail_capture(datetime.now(timezone.utc))
        assert [s["host"] for s in first] == ["new.example"]
        # New bytes appear → only they are returned.
        with open(cap, "a") as f:
            f.write(json.dumps(self._cap("newer.example", 0)) + "\n")
        second = w._tail_capture(datetime.now(timezone.utc))
        assert [s["host"] for s in second] == ["newer.example"]

    def test_truncated_file_resets(self, tmp_path, monkeypatch):
        cap = tmp_path / "capture.jsonl"
        cap.write_text(json.dumps(self._cap("a.example", 1)) + "\n")
        w, _ = _mk_watcher(tmp_path, monkeypatch)
        w._capture_path = str(cap)
        w._window = 3600
        w._tail_capture(datetime.now(timezone.utc))
        # Rotation/truncation: file shrinks below the offset.
        cap.write_text(json.dumps(self._cap("b.example", 0)) + "\n")
        w._cap_offset = w._cap_offset + 4096
        got = w._tail_capture(datetime.now(timezone.utc))
        assert [s["host"] for s in got] == ["b.example"]


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

    def test_status_reports_disabled(self, tmp_path, monkeypatch,
                                     patch_state_dirs):
        _mk_cage(patch_state_dirs, tmp_path)
        from agentcage.cli import main
        from click.testing import CliRunner
        out = CliRunner().invoke(main, ["watcher", "status", "mycage"])
        assert out.exit_code == 0
        assert "not enabled" in out.output
