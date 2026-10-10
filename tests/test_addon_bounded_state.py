"""The addon's per-host and per-flow state is bounded.

Two leaks in a process that runs under ``prlimit --as=2G``:

* ``_rl_buckets`` (the per-host rate limiter) was a ``defaultdict`` keyed
  by ``flow.request.host`` and never evicted. The limiter runs before the
  allowlist, so a cage could grow it without bound by sending plain-HTTP
  requests with arbitrary ``Host`` values. It is now an LRU capped at
  ``_RL_MAX_HOSTS``.
* ``_cap_pending`` (capture entries staged in ``request()`` and popped in
  ``response()``) leaked for every flow that errored without a response,
  because the addon had no ``error`` hook; ``CaptureWriter._ws_buffers``
  had no release on websocket end. Both hooks now drop the flow's entries.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import yaml


def _addon_mod():
    # Imported lazily, like the other addon suites: an import at collection
    # time would pin the addon to a ``secret_injector`` module that
    # test_policy_api_control later evicts from sys.modules.
    from agentcage.data.proxy import addon
    return addon


def _loaded_addon(tmp_path, monkeypatch, rate_limit=None):
    """A real addon through ``load()``, so the limiter is the real one."""
    addon_mod = _addon_mod()
    cfg = {"domains": {"mode": "allowlist", "allow": ["example.com"]}}
    if rate_limit is not None:
        cfg["rate_limit"] = rate_limit
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(path))
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    addon = addon_mod.Agentcage()
    addon.load(loader=None)
    return addon


class TestRateLimitBuckets:
    def test_defaults_on_the_real_limiter(self, tmp_path, monkeypatch):
        addon = _loaded_addon(tmp_path, monkeypatch)
        assert addon._rl_rate == 10.0
        assert addon._rl_burst == 50
        for _ in range(50):
            assert addon._check_rate_limit("api.example.com") is True
        assert addon._check_rate_limit("api.example.com") is False
        # Per host: another host has its own full bucket.
        assert addon._check_rate_limit("api.example.org") is True

    def test_explicit_zero_disables(self, tmp_path, monkeypatch):
        addon = _loaded_addon(
            tmp_path, monkeypatch,
            rate_limit={"requests_per_second": 0})
        for _ in range(1000):
            assert addon._check_rate_limit("api.example.com") is True
        assert len(addon._rl_buckets) == 0

    def test_table_never_exceeds_capacity(self, tmp_path, monkeypatch):
        addon = _loaded_addon(tmp_path, monkeypatch)
        cap = getattr(_addon_mod(), "_RL_MAX_HOSTS", 4096)
        assert cap == 4096
        for i in range(cap + 1000):
            addon._check_rate_limit(f"h{i}.example.com")
            assert len(addon._rl_buckets) <= cap
        assert len(addon._rl_buckets) == cap
        # The most recent hosts survive, the oldest went first.
        assert f"h{cap + 999}.example.com" in addon._rl_buckets
        assert "h0.example.com" not in addon._rl_buckets
        assert "h999.example.com" not in addon._rl_buckets
        assert "h1000.example.com" in addon._rl_buckets

    def test_eviction_is_least_recently_used(self, tmp_path, monkeypatch):
        addon = _loaded_addon(
            tmp_path, monkeypatch,
            rate_limit={"requests_per_second": 0.0001, "burst": 2})
        monkeypatch.setattr(_addon_mod(), "_RL_MAX_HOSTS", 3, raising=False)
        check = addon._check_rate_limit
        # Drain a.example.com, then touch b and c.
        assert check("a.example.com") and check("a.example.com")
        assert check("b.example.com")
        assert check("c.example.com")
        # Using a again makes b the least recently used...
        assert not check("a.example.com")
        # ...so a new host evicts b, not a.
        assert check("d.example.com")
        assert set(addon._rl_buckets) == {
            "a.example.com", "c.example.com", "d.example.com"}
        # a kept its (drained) state: no free refill from the churn.
        assert not check("a.example.com")
        # The documented trade-off: an evicted host restarts full.
        assert check("b.example.com") and check("b.example.com")
        assert not check("b.example.com")
        assert "c.example.com" not in addon._rl_buckets


def _capture_addon(tmp_path):
    from capture import CaptureWriter
    addon = _addon_mod().Agentcage()
    addon._cap_pending = {}
    addon._capture = CaptureWriter({}, str(tmp_path / "capture.jsonl"))
    return addon


def _flow(flow_id="flow-1"):
    f = MagicMock()
    f.id = flow_id
    return f


class TestFlowEndReleasesCaptureState:
    def test_error_drops_the_pending_capture_entry(self, tmp_path):
        addon = _capture_addon(tmp_path)
        addon._cap_pending["flow-1"] = {"host": "example.com"}
        addon._cap_pending["flow-2"] = {"host": "example.org"}
        addon.error(_flow("flow-1"))
        assert "flow-1" not in addon._cap_pending
        # Other flows' staging is untouched.
        assert "flow-2" in addon._cap_pending
        # Dropped, not written: an errored flow has no response half.
        assert (tmp_path / "capture.jsonl").read_text() == ""

    def test_error_releases_websocket_buffer(self, tmp_path):
        addon = _capture_addon(tmp_path)
        addon._cap_pending["flow-1"] = {"host": "example.com"}
        addon._capture.add_ws_message("flow-1", {"type": "send", "data": "x"})
        addon.error(_flow("flow-1"))
        assert addon._capture._ws_buffers == {}

    def test_error_without_staged_state_is_a_noop(self, tmp_path):
        addon = _capture_addon(tmp_path)
        addon.error(_flow("unknown"))
        addon._capture = None  # capture disabled
        addon.error(_flow("unknown"))
        assert addon._cap_pending == {}

    def test_websocket_end_releases_buffer_and_staging(self, tmp_path):
        addon = _capture_addon(tmp_path)
        addon._cap_pending["flow-1"] = {"host": "example.com"}
        addon._capture.add_ws_message("flow-1", {"type": "send", "data": "a"})
        addon._capture.add_ws_message("flow-1", {"type": "receive", "data": "b"})
        addon._capture.add_ws_message("flow-2", {"type": "send", "data": "c"})
        addon.websocket_end(_flow("flow-1"))
        assert "flow-1" not in addon._capture._ws_buffers
        assert "flow-1" not in addon._cap_pending
        assert "flow-2" in addon._capture._ws_buffers
