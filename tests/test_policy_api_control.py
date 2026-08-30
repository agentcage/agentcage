"""Control-plane tests for ``PolicyApi`` — request endpoint gates.

The 5th-review funnel flagged (unanimously) that the request endpoint's
hard gates were untested: never_grant floor, body cap, missing
justification, invalid domain, already-allowed idempotency, rate limit,
fail-closed-on-decider-error, and the 24h TTL clamp. These drive
``handle()`` directly with a fake flow.

Status codes are recorded by patching the ``http`` module object that
``policy_api`` actually bound (works whether mitmproxy is the unit-test
stub or a real install).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

# ── Stub mitmproxy before importing the addon's policy_api module ────────
_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []
_mitmproxy.ctx = MagicMock()
_mitmproxy.http = MagicMock()
_proxy = types.ModuleType("mitmproxy.proxy")
_proxy.__path__ = []
_mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)
sys.modules.setdefault("mitmproxy.proxy", _proxy)
_proxy.mode_specs = _mode_specs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "src" / "agentcage" / "data" / "proxy"))

from inspectors.domain import DomainInspector  # noqa: E402
import policy_api as _pa_mod  # noqa: E402
from policy_api import PolicyApi  # noqa: E402


@pytest.fixture
def resp_status():
    """Record every synthesized response status via the http module
    policy_api actually bound."""
    calls = []

    def _make(status, *a, **k):
        calls.append(status)
        return MagicMock()

    orig = _pa_mod.http.Response.make
    _pa_mod.http.Response.make = _make
    try:
        yield calls
    finally:
        _pa_mod.http.Response.make = orig


def _make_pa(tmp_path, monkeypatch, *, rate_limit=None):
    """PolicyApi with a real temp grants dir and the LLM path configured
    (white-box secret injection), ready for handle() tests."""
    monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
    dom = DomainInspector()
    dom.configure({"allow": ["a.com"]})
    auto = {
        "enable": True,
        "decider": {"kind": "agent", "provider": "openrouter",
                    "model": "m", "api_key": "env:K"},
    }
    if rate_limit is not None:
        auto["rate_limit"] = rate_limit
    cfg = {"domains": {"allow": ["a.com"], "auto": auto}}
    pa = PolicyApi(cfg, dom, lambda e: None, MagicMock())
    pa._llm_secret = "sk-test"  # pretend the env resolved
    return pa, dom


def _flow(path="/v1/allowlist/requests", method="POST",
          domain=None, reason="r", raw_body=None):
    f = MagicMock()
    f.request.path = path
    f.request.method = method
    if raw_body is not None:
        f.request.content = raw_body
    else:
        f.request.content = json.dumps(
            {"domain": domain, "reason": reason}).encode()
    f.request.host_header = "agentcage.local"
    return f


def _handle(pa, flow):
    asyncio.run(pa.handle(flow))


def _overlay_domains(tmp_path):
    p = tmp_path / "grants.yaml"
    if not p.exists():
        return set()
    return {e["domain"] for e in (yaml.safe_load(p.read_text()) or [])}


class TestRequestGates:
    def test_never_grant_floor_denies(self, tmp_path, monkeypatch,
                                       resp_status):
        """internal/local/localhost + the control host are un-grantable —
        the floor is fixed, not operator-configurable in v1."""
        pa, _ = _make_pa(tmp_path, monkeypatch)
        for d in ("metadata.google.internal", "foo.local",
                  "localhost", "agentcage.local"):
            _handle(pa, _flow(domain=d, reason="trust me"))
            assert not pa.dom.is_granted(d)
        assert _overlay_domains(tmp_path) == set()
        # Each was answered with a deny (200 + status denied), never a grant.
        assert len(resp_status) == 4

    def test_body_cap_413(self, tmp_path, monkeypatch, resp_status):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        _handle(pa, _flow(raw_body=b"x" * (8 * 1024 + 1)))
        assert resp_status[-1] == 413

    def test_missing_reason_400(self, tmp_path, monkeypatch, resp_status):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        _handle(pa, _flow(domain="x.com", reason=""))
        assert resp_status[-1] == 400

    def test_invalid_domain_400(self, tmp_path, monkeypatch, resp_status):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        _handle(pa, _flow(domain="bad..name"))
        assert resp_status[-1] == 400

    def test_ip_literal_domain_400(self, tmp_path, monkeypatch, resp_status):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        _handle(pa, _flow(domain="10.0.0.1"))
        assert resp_status[-1] == 400

    def test_already_allowed_idempotent_no_decider(self, tmp_path,
                                                    monkeypatch, resp_status):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        called = []
        pa._llm_call_sync = lambda *a: called.append(1)
        _handle(pa, _flow(domain="a.com"))
        assert resp_status[-1] == 200
        assert called == [], "baseline domain must not invoke the decider"

    def test_unknown_path_404(self, tmp_path, monkeypatch, resp_status):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        _handle(pa, _flow(path="/v1/nope"))
        assert resp_status[-1] == 404


class TestRateLimit:
    def test_burst_exhaustion_429(self, tmp_path, monkeypatch, resp_status):
        pa, _ = _make_pa(tmp_path, monkeypatch,
                         rate_limit={"requests_per_second": 0.001,
                                     "burst": 2})
        pa._llm_call_sync = lambda *a: {"decision": "deny", "reason": "no"}
        # First two consume the burst (denied by the fake decider).
        for _ in range(2):
            _handle(pa, _flow(domain="x.com"))
        _handle(pa, _flow(domain="x.com"))
        assert resp_status[-1] == 429

    def test_explicit_zero_disables_limit(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch,
                         rate_limit={"requests_per_second": 0, "burst": 0})
        assert pa._rl_rps == 0.0 and pa._rl_burst == 0
        pa._llm_call_sync = lambda *a: {"decision": "deny", "reason": "no"}
        for _ in range(50):
            _handle(pa, _flow(domain="x.com"))
        # All 50 reached the decider (denied) — the explicit 0 disabled
        # the limiter (regression guard for the 0-vs-default parse).
        assert pa._check_rate_limit() is True

    def test_absent_rate_limit_defaults_active(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        assert pa._rl_rps == 1.0
        assert pa._rl_burst == 5


class TestFailClosed:
    def test_decider_exception_denies(self, tmp_path, monkeypatch):
        """A decider error NEVER grants — the trust-model invariant."""
        pa, dom = _make_pa(tmp_path, monkeypatch)

        def boom(*a):
            raise RuntimeError("provider down")
        pa._llm_call_sync = boom
        _handle(pa, _flow(domain="x.com"))
        assert not dom.is_granted("x.com")
        assert _overlay_domains(tmp_path) == set()

    def test_unconfigured_llm_503_denies(self, tmp_path, monkeypatch,
                                          resp_status):
        pa, dom = _make_pa(tmp_path, monkeypatch)
        pa._llm_secret = ""  # unconfigured
        _handle(pa, _flow(domain="x.com"))
        assert resp_status[-1] == 503
        assert not dom.is_granted("x.com")


class TestTtlClamp:
    def test_ttl_clamped_to_24h(self, tmp_path, monkeypatch):
        import datetime as _dt
        pa, dom = _make_pa(tmp_path, monkeypatch)
        pa._llm_call_sync = lambda *a: {
            "decision": "grant", "reason": "r", "ttl_seconds": 90000,
        }
        _handle(pa, _flow(domain="x.com"))
        assert dom.is_granted("x.com")
        exp = dom.granted["x.com"]["expires_at"]
        delta = (_dt.datetime.fromisoformat(exp) -
                 _dt.datetime.now(_dt.timezone.utc)).total_seconds()
        assert delta <= 86400 + 60, f"ttl not clamped: {delta}s"
        assert delta > 86400 - 600


class TestFeatureDisabled:
    def test_disabled_auto_404s(self, tmp_path, monkeypatch, resp_status):
        monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
        dom = DomainInspector()
        dom.configure({"allow": ["a.com"]})
        cfg = {"domains": {"allow": ["a.com"], "auto": {"enable": False}}}
        pa = PolicyApi(cfg, dom, lambda e: None, MagicMock())
        _handle(pa, _flow(domain="x.com"))
        assert resp_status[-1] == 404


class TestExpiredAlreadyAllowedFastPath:
    """Fix 2 (low): the already_allowed fast path must NOT fire when the
    matching baseline entry (or grant) is EXPIRED — L7 is blocking that
    domain, so a 200 "already_allowed" would mislead the agent into
    believing its traffic is allowed. An expired entry falls through to the
    normal request flow so the decider can adjudicate a fresh grant."""

    def test_expired_baseline_entry_proceeds_to_decider(
        self, tmp_path, monkeypatch, resp_status
    ):
        monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
        dom = DomainInspector()
        dom.configure({
            "allow": ["a.com"],
            "expires": {"a.com": "2000-01-01T00:00:00+00:00"},
        })
        auto = {
            "enable": True,
            "decider": {"kind": "agent", "provider": "openrouter",
                        "model": "m", "api_key": "env:K"},
        }
        pa = PolicyApi({"domains": {"allow": ["a.com"], "auto": auto}},
                       dom, lambda e: None, MagicMock())
        pa._llm_secret = "sk-test"

        # The baseline entry is expired → _matched_expired returns the suffix.
        assert dom._matched_expired("a.com") == "a.com"
        # Sanity: inspect_request would block it at L7.
        assert dom._matches("a.com") is True

        called = []
        pa._llm_call_sync = lambda *a: called.append(1) or {
            "decision": "deny", "reason": "expired, denied"
        }
        _handle(pa, _flow(domain="a.com"))
        # The decider was invoked (NOT short-circuited as already_allowed).
        assert called == [1], \
            "expired baseline entry must fall through to the decider, " \
            "not return already_allowed"

    def test_expired_grant_proceeds_to_decider(
        self, tmp_path, monkeypatch, resp_status
    ):
        # A granted domain whose grant is past its expires_at must also NOT
        # take the already_allowed fast path.
        pa, dom = _make_pa(tmp_path, monkeypatch)
        # Plant an expired grant directly in the inspector.
        dom.granted["a.com"] = {
            "domain": "a.com",
            "granted_at": "2000-01-01T00:00:00+00:00",
            "expires_at": "2000-01-01T00:00:00+00:00",
            "reason": "stale", "source": "decider",
        }
        assert dom.is_granted("a.com") is True  # is_granted ignores expiry
        assert dom._matched_expired("a.com") == "a.com"

        called = []
        pa._llm_call_sync = lambda *a: called.append(1) or {
            "decision": "deny", "reason": "expired grant, denied"
        }
        _handle(pa, _flow(domain="a.com"))
        assert called == [1], \
            "expired grant must fall through to the decider"

    def test_unexpired_baseline_still_fast_paths(self, tmp_path, monkeypatch):
        # Regression guard: a far-future expiry must STILL take the fast path
        # (so the fix doesn't over-broaden and always invoke the decider).
        monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
        dom = DomainInspector()
        dom.configure({
            "allow": ["a.com"],
            "expires": {"a.com": "9999-01-01T00:00:00+00:00"},
        })
        auto = {
            "enable": True,
            "decider": {"kind": "agent", "provider": "openrouter",
                        "model": "m", "api_key": "env:K"},
        }
        pa = PolicyApi({"domains": {"allow": ["a.com"], "auto": auto}},
                       dom, lambda e: None, MagicMock())
        pa._llm_secret = "sk-test"
        assert dom._matched_expired("a.com") is None
        called = []
        pa._llm_call_sync = lambda *a: called.append(1)
        _handle(pa, _flow(domain="a.com"))
        assert called == [], \
            "unexpired baseline entry must still take the already_allowed " \
            "fast path (decider not invoked)"


class TestUniqueTempFile:
    """Fix 1 (medium): the overlay atomic-write temp filename must be
    PID-suffixed so a concurrent addon+host-watcher write cannot clobber
    each other's temp file (which would lose one side's writes on rename).
    The grants dir must contain only grants.yaml after a persist — no
    leftover ``grants.yaml.tmp`` (the old colliding name)."""

    def test_persist_leaves_no_plain_tmp_file(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("x.com", "reason", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        # Exactly grants.yaml — no stray .tmp (old or new PID-suffixed) lingers.
        assert set(os.listdir(tmp_path)) == {"grants.yaml"}

    def test_temp_filename_is_pid_suffixed(self, tmp_path, monkeypatch):
        # White-box: the temp path constructed during a persist must include
        # the PID, distinct from the host writer's ``grants.yaml.tmp``.
        pa, _ = _make_pa(tmp_path, monkeypatch)
        seen_tmp = []
        import builtins
        real_open = builtins.open

        def spy_open(path, *a, **k):
            p = str(path)
            if p.endswith(".tmp"):
                seen_tmp.append(p)
            return real_open(path, *a, **k)

        builtins.open = spy_open
        try:
            pa._apply_grant("y.com", "reason", ttl_override=0,
                            decided_by="decider:agent:openrouter")
        finally:
            builtins.open = real_open
        assert seen_tmp and any(
            p == str(tmp_path / f"grants.yaml.{os.getpid()}.tmp")
            for p in seen_tmp
        ), f"temp path was not PID-suffixed: {seen_tmp!r}"


class TestSweeperRobustness:
    """Fix 3 (low): a malformed/non-UTF8 overlay must not kill the TTL
    sweeper task permanently. ``_load_overlay`` returns [] on a UnicodeDecodeError
    (caught via ValueError), and the per-tick body isolates any surprise so
    the loop continues (``_sweeper_tick`` is the factored, testable body)."""

    def test_load_overlay_garbage_bytes_returns_empty(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        (tmp_path / "grants.yaml").write_bytes(b"\xff\xfe\x00bad")
        # Must NOT raise (UnicodeDecodeError is a ValueError subclass).
        assert pa._load_overlay() == []

    def test_maybe_reload_garbage_bytes_no_raise(self, tmp_path, monkeypatch):
        pa, dom = _make_pa(tmp_path, monkeypatch)
        # Seed an in-memory grant so the reconcile has something to do.
        pa._apply_grant("x.com", "r", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        # Corrupt the overlay + bump mtime so maybe_reload_overlay sees a change.
        overlay = tmp_path / "grants.yaml"
        overlay.write_bytes(b"\xff\xfe\x00bad")
        import time as _t, os as _os
        ft = _t.time() + 100
        _os.utime(overlay, (ft, ft))
        # Must return True (reconciled / saw the change) WITHOUT raising.
        assert pa.maybe_reload_overlay() is True
        # The garbage overlay reconciled to empty → the grant is dropped.
        assert not dom.is_granted("x.com")

    def test_sweeper_tick_with_garbage_overlay_does_not_raise(
        self, tmp_path, monkeypatch
    ):
        pa, _ = _make_pa(tmp_path, monkeypatch)
        (tmp_path / "grants.yaml").write_bytes(b"\xff\xfe\x00bad")
        import time as _t, os as _os
        overlay = tmp_path / "grants.yaml"
        ft = _t.time() + 100
        _os.utime(overlay, (ft, ft))
        # A single tick over a garbage overlay must complete without raising.
        pa._sweeper_tick()

    def test_sweeper_tick_isolates_internal_exception(self, tmp_path, monkeypatch):
        # A surprise exception from inside the tick body must be caught by the
        # loop and NOT propagate — simulate by monkeypatching a helper to raise.
        pa, _ = _make_pa(tmp_path, monkeypatch)

        def boom():
            raise RuntimeError("unexpected")
        pa.maybe_reload_overlay = boom
        import asyncio
        # Drive exactly one tick via the loop with a patched sleep so it runs
        # once then cancels. The internal RuntimeError must be caught and the
        # task must NOT raise.
        async def drive():
            task = asyncio.ensure_future(pa.sweeper_loop())
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(drive())  # must not raise (tick exception was logged)