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

# ── Stub ReverseMode as a real class so the addon's isinstance check works ──
# conftest.py stubs ``ReverseMode`` as a MagicMock at collection time, which
# makes ``isinstance(proxy_mode, ReverseMode)`` in ``addon.request()`` crash
# with TypeError. Overwrite it with a real class BEFORE importing the addon
# module (the addon does ``from mitmproxy.proxy.mode_specs import ReverseMode``
# at module load and caches the binding). Pop any cached addon module so it
# re-imports with the patched binding.


class _StubReverseMode:
    """Standin so ``isinstance(x, ReverseMode)`` evaluates cleanly."""
    pass


sys.modules["mitmproxy.proxy.mode_specs"].ReverseMode = _StubReverseMode
for _mod in ("addon", "secret_injector"):
    sys.modules.pop(_mod, None)
from addon import Agentcage  # noqa: E402
from secret_injector import SecretInjector  # noqa: E402


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


def _make_pa(tmp_path, monkeypatch, *, rate_limit=None, context=None):
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
    if context is not None:
        auto["context"] = context
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

    def test_trailing_newline_domain_400(self, tmp_path, monkeypatch,
                                         resp_status):
        """The addon's ``_valid_domain`` is the trust-boundary gate that
        stops overlay strings (which cross the trust boundary via the grants
        dir) from being rendered into dnsmasq directives. ``$`` (vs the
        ``\\Z`` anchor now used) matched before ONE trailing newline, so
        ``"evil.com\\n"`` would have passed and reached the host watcher's
        promote; the request endpoint must reject it with a 400 and never
        grant it."""
        pa, dom = _make_pa(tmp_path, monkeypatch)
        _handle(pa, _flow(domain="evil.com\n"))
        assert resp_status[-1] == 400
        assert not dom.is_granted("evil.com\n")
        assert not dom.is_granted("evil.com")
        assert _overlay_domains(tmp_path) == set()

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
        # The persist now uses ``os.open`` (O_EXCL) rather than
        # ``builtins.open``, so spy on ``os.open``.
        pa, _ = _make_pa(tmp_path, monkeypatch)
        seen_tmp = []
        import os as _os
        real_os_open = _os.open

        def spy_open(path, flags, *a, **k):
            p = str(path)
            if p.endswith(".tmp"):
                seen_tmp.append(p)
            return real_os_open(path, flags, *a, **k)

        monkeypatch.setattr("os.open", spy_open)
        pa._apply_grant("y.com", "reason", ttl_override=0,
                        decided_by="decider:agent:openrouter")
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

# ── Headers helper for addon.request() tests ──────────────


class _Headers(dict):
    def items(self, multi=False):  # noqa: ARG002
        return list(super().items())

    def get(self, key, default=None):  # type: ignore[override]
        kl = key.lower()
        for k, v in super().items():
            if k.lower() == kl:
                return v
        return default

    def keys(self):  # type: ignore[override]
        return list(super().keys())


class TestControlHostEgressOnly:
    """Fix 1 (medium): the control-host short-circuit must NOT fire on
    inbound reverse-mode flows. Cages with published inbound ports
    (container.ports, wired as mitmproxy reverse listeners) forward client
    traffic with the client's Host preserved, so any client that can reach
    a published port could call the unauthenticated control plane if the
    check ran before the reverse-mode determination. The fix moves the
    control-host short-circuit to AFTER the ``is_reverse`` determination
    and gates it on ``not is_reverse`` (egress path only)."""

    def _build_addon(self, tmp_path, monkeypatch, pa):
        """Minimal Agentcage wired with a PolicyApi on domain_requests."""
        addon = Agentcage()
        addon.cfg = {}
        addon.log_allowed = False
        addon.inspectors = []
        addon._rl_rate = 0.0
        addon._rl_burst = 0
        addon._rl_buckets = {}
        addon._audit_file = (tmp_path / "audit.jsonl").open("a")
        addon._cap_pending = {}
        addon.injector = SecretInjector()
        addon.injector.rules = []
        addon.injector.redact_to = []
        addon._capture = None
        addon._running = False
        addon._policy_sweeper = None
        addon.domain_requests = pa

        # mitmproxy.http.Response.make is a MagicMock — make it return a
        # sentinel the tests can introspect.
        from mitmproxy import http as _http
        def _make_response(status, body, headers):
            resp = MagicMock()
            resp.status_code = status
            resp.content = body
            resp.headers = headers
            return resp
        _http.Response.make.side_effect = _make_response
        return addon

    def _make_flow(self, *, reverse_mode=False, sni=None,
                   host_header="agentcage.local"):
        flow = MagicMock()
        flow.id = "test-flow-control-egress"
        flow.metadata = {}
        flow.request.url = f"https://{host_header}/v1/allowlist"
        flow.request.host = host_header or "1.2.3.4"
        flow.request.pretty_host = host_header or "1.2.3.4"
        flow.request.host_header = host_header
        flow.request.pretty_url = flow.request.url
        flow.request.path = "/v1/allowlist"
        flow.request.port = 443
        flow.request.method = "GET"
        flow.request.http_version = "HTTP/1.1"
        h = {"Content-Type": "application/json"}
        if host_header:
            h["Host"] = host_header
        flow.request.headers = _Headers(h)
        flow.request.content = b""
        flow.request.get_text.side_effect = (
            lambda strict=False: flow.request.content.decode("utf-8", "replace")
        )
        flow.client_conn.sni = sni
        flow.client_conn.tls_established = sni is not None
        flow.client_conn.address = ("10.0.0.1", 54321)
        if reverse_mode:
            flow.client_conn.proxy_mode = _StubReverseMode()
        else:
            flow.client_conn.proxy_mode = MagicMock()
        flow.response = None
        return flow

    def test_reverse_flow_skips_control_host(self, tmp_path, monkeypatch):
        """A reverse-mode (inbound) flow whose Host = control host must NOT
        trigger ``pa.handle`` — the control plane is egress-only."""
        pa, _ = _make_pa(tmp_path, monkeypatch)
        called = []

        async def _handle_spy(flow):
            called.append(flow)
        pa.handle = _handle_spy

        addon = self._build_addon(tmp_path, monkeypatch, pa)
        flow = self._make_flow(reverse_mode=True, sni="agentcage.local")
        asyncio.run(addon.request(flow))
        assert called == [], (
            "pa.handle must NOT be called for a reverse-mode (inbound) flow "
            "even when Host/SNI match the control host"
        )

    def test_egress_flow_hits_control_host(self, tmp_path, monkeypatch):
        """Regression guard: an egress (non-reverse) flow whose Host/SNI =
        control host must STILL trigger ``pa.handle`` (the fix must not
        break the normal egress control-plane path)."""
        pa, _ = _make_pa(tmp_path, monkeypatch)
        called = []

        async def _handle_spy(flow):
            called.append(flow)
        pa.handle = _handle_spy

        addon = self._build_addon(tmp_path, monkeypatch, pa)
        flow = self._make_flow(reverse_mode=False, sni="agentcage.local")
        asyncio.run(addon.request(flow))
        assert len(called) == 1, (
            "pa.handle must be called for an egress flow targeting the "
            "control host (the fix only gates reverse/inbound flows)"
        )


class TestOExclTempCreation:
    """Fix 3 (defense-in-depth): the overlay temp is created with O_EXCL so
    a planted symlink at the predictable PID-suffixed temp path cannot be
    written through. Fix 1: on FileExistsError the colliding temp is NOT
    unlinked (it may be a concurrent writer's in-flight temp at a
    colliding numeric PID); the persist retries ONCE with a
    counter-suffixed name and aborts if that also exists."""

    def test_preplanted_symlink_not_written_through(self, tmp_path, monkeypatch):
        """A pre-planted symlink at the PID-suffixed temp path (pointing at
        an outside file) must NOT be written through (O_EXCL). Fix 1: the
        symlink is NOT unlinked — the persist retries once with a
        counter-suffixed name; the symlink survives, the outside file's
        content is unchanged, and grants.yaml is written correctly."""
        pa, _ = _make_pa(tmp_path, monkeypatch)
        # Plant a symlink at the exact temp path the addon will use.
        target = tmp_path.parent / f"fix3_target_{os.getpid()}.txt"
        target.write_text("outside content — must not be overwritten")
        symlink_tmp = tmp_path / f"grants.yaml.{os.getpid()}.tmp"
        os.symlink(target, symlink_tmp)
        assert symlink_tmp.is_symlink()

        pa._apply_grant("z.com", "reason", ttl_override=0,
                        decided_by="decider:agent:openrouter")

        # The symlink still exists (never unlinked) — Fix 1.
        assert symlink_tmp.is_symlink(), \
            "planted symlink was unlinked (Fix 1 regression)"
        # The outside file's content is unchanged (never written through).
        assert target.read_text() == "outside content — must not be overwritten"
        # grants.yaml has the correct content (persist succeeded via the
        # counter-suffixed name, now renamed away).
        import yaml as _yaml
        entries = _yaml.safe_load((tmp_path / "grants.yaml").read_text())
        assert any(e["domain"] == "z.com" for e in entries)
        # No counter-suffixed temp lingers (it was renamed to grants.yaml).
        assert not list(tmp_path.glob("*.1.tmp"))
        # The only ``*.tmp`` present is the planted symlink.
        assert [f.name for f in tmp_path.glob("*.tmp")] == [symlink_tmp.name]
        # Clean up the outside target.
        target.unlink(missing_ok=True)

    def test_preplanted_stale_temp_not_unlinked(self, tmp_path, monkeypatch):
        """Fix 1: a planted stale temp at the exact PID-suffixed path the
        addon uses is NOT unlinked by a subsequent persist — the persist
        retries once with a counter-suffixed name and the planted temp
        survives; the save succeeds via the counter-suffixed name."""
        pa, _ = _make_pa(tmp_path, monkeypatch)
        leftover = tmp_path / f"grants.yaml.{os.getpid()}.tmp"
        leftover.write_text("stale")
        pa._apply_grant("z.com", "reason", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert leftover.exists(), "planted temp was unlinked (Fix 1 regression)"
        assert leftover.read_text() == "stale", "planted temp was modified"
        import yaml as _yaml
        entries = _yaml.safe_load((tmp_path / "grants.yaml").read_text())
        assert any(e["domain"] == "z.com" for e in entries)
        assert not list(tmp_path.glob("*.1.tmp")), "counter-suffixed temp not published"
        assert [f.name for f in tmp_path.glob("*.tmp")] == [leftover.name]

    def test_persist_leaves_no_plain_tmp_file(self, tmp_path, monkeypatch):
        """After a normal persist, the grants dir contains exactly
        grants.yaml — no leftover temp."""
        pa, _ = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("x.com", "reason", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert set(os.listdir(tmp_path)) == {"grants.yaml"}


# ── Operator context (domains.auto.context) ──────────────────


class _RecordedResponse:
    """Fake urllib response: returns a canned OpenAI-style deny verdict so
    the decider path completes without a real network call. The request
    bodies are captured for assertion via the sibling ``requests`` list."""

    def __init__(self, requests, verdict=None):
        self._requests = requests
        self._verdict = verdict or {
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": {
                            "arguments": json.dumps({
                                "decision": "deny", "reason": "denied",
                            }),
                        },
                    }],
                },
            }],
        }

    def __call__(self, req, timeout=None):  # noqa: ARG002
        # Record the JSON body the egress actually tried to send.
        self._requests.append(json.loads(req.data.decode("utf-8", "replace")))
        resp = MagicMock()
        resp.read.return_value = json.dumps(self._verdict).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: False
        return resp


class TestOperatorContextPrompt:
    """The operator-provided ``context`` must flow into the decider's system
    prompt (framed as trusted, advisory-only) at BOTH LLM call sites, and
    must be absent from the system prompt when unset (bare core prompt)."""

    _CTX = (
        "CI cage for the payments-reconciliation test suite. Talks to "
        "staging APIs (api.stripe.com), publishes test coverage to "
        "codecov.io, and installs dependencies from npm/pypi."
    )

    def _record(self, pa, monkeypatch):
        """Patch urllib.request.urlopen so the LLM call records its request
        body (which carries the system content) and returns a canned deny."""
        requests = []
        monkeypatch.setattr(
            _pa_mod.urllib.request, "urlopen",
            _RecordedResponse(requests))
        return requests

    def test_context_appended_to_system_prompt(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch, context=self._CTX)
        requests = self._record(pa, monkeypatch)
        _handle(pa, _flow(domain="x.com", reason="need it"))
        assert len(requests) == 1
        system_content = requests[0]["messages"][0]["content"]
        # The bare core prompt is still there (the wrapper appends, never
        # replaces), so the static decision rules are intact.
        assert "autonomous-approval gate" in system_content
        # The operator context text rides in the system prompt.
        assert self._CTX in system_content
        # The trusted-operator framing is present verbatim.
        assert "OPERATOR CONTEXT" in system_content
        assert "trusted" in system_content
        assert "does NOT override the hard rules" in system_content

    def test_no_context_is_bare_core_prompt(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch)  # no context kwarg
        requests = self._record(pa, monkeypatch)
        _handle(pa, _flow(domain="x.com", reason="need it"))
        assert len(requests) == 1
        system_content = requests[0]["messages"][0]["content"]
        # No operator-context section is appended when context is empty.
        assert "OPERATOR CONTEXT" not in system_content
        # The system prompt is exactly the static core (byte-for-byte).
        assert system_content == pa._system_prompt()

    def test_anthropic_call_site_also_appends_context(self, tmp_path,
                                                       monkeypatch):
        """The Anthropic /v1/messages site puts the system content under the
        top-level ``system`` key (not in ``messages``); verify it carries
        the context too — both call sites were updated to _decider_system_prompt."""
        pa, _ = _make_pa(
            tmp_path, monkeypatch, context=self._CTX)
        pa._llm_provider = "anthropic"  # switch the dispatch target
        requests = self._record(pa, monkeypatch)
        _handle(pa, _flow(domain="x.com", reason="need it"))
        assert len(requests) == 1
        # Anthropic's wire format: top-level ``system`` string.
        system_content = requests[0]["system"]
        assert self._CTX in system_content
        assert "OPERATOR CONTEXT" in system_content
        # The agent's justification is in the user turn, NOT the system
        # prompt — the prompt-injection invariant holds even with context.
        assert "need it" not in system_content


class TestOperatorContextAllowlist:
    """The caged agent can read the operator context via GET /v1/allowlist so
    it can see the scope it's operating in and write justifications that
    match it."""

    def test_allowlist_response_includes_context(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch, context="ci cage for tests")
        body = pa._allowlist()
        assert body["context"] == "ci cage for tests"
        # The rest of the response shape is unchanged.
        assert body["mode"] == "allowlist"
        assert "baseline" in body and "granted" in body

    def test_allowlist_context_empty_when_unset(self, tmp_path, monkeypatch):
        pa, _ = _make_pa(tmp_path, monkeypatch)  # no context
        assert pa._allowlist()["context"] == ""

    def test_context_stripped_on_read(self, tmp_path, monkeypatch):
        # Whitespace-only context collapses to "" (feature-off), matching
        # validate_config's strip-before-measure and the proxy's read.
        pa, _ = _make_pa(tmp_path, monkeypatch, context="   \n  ")
        assert pa._context == ""
        assert pa._allowlist()["context"] == ""
