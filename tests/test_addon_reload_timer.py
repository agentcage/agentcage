"""Config hot-reload runs on a timer too (Phase 0a fix 0a.14).

``_maybe_reload`` (an mtime poll of the config file) ran only at the top
of each proxied HTTP ``request()``. A cage that only used protocol relays,
or was idle, never applied a config edit: relay changes, Policy API
reconfiguration, re-staged secrets, passthrough.

The contract these tests pin:

* ``running()`` starts a background task that checks the file every
  ``_CONFIG_POLL_SECONDS``, so an edit with no HTTP traffic is applied;
  ``done()`` cancels it;
* the per-request check stays;
* a reload that fails is logged and the task keeps running; the failed
  version is not retried every tick, and the next edit is applied;
* the timer and a request never reload the same edit twice, and a check
  re-entered from inside a reload does not nest one.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock

import pytest
import yaml


class _StubReverseMode:
    """Real class so ``isinstance(..., ReverseMode)`` works (conftest
    stubs it as a MagicMock instance). No flow here is reverse-mode."""


@pytest.fixture
def env(tmp_path, monkeypatch):
    from agentcage.data.proxy import addon as addon_mod

    cfg_path = tmp_path / "config.yaml"
    monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(addon_mod, "CAPTURE_PATH", "")
    monkeypatch.setattr(addon_mod, "ReverseMode", _StubReverseMode)
    monkeypatch.setattr(addon_mod, "_CONFIG_POLL_SECONDS", 0.005,
                        raising=False)
    monkeypatch.setattr(addon_mod, "ctx", MagicMock())
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", "")
    return addon_mod, cfg_path


def _write_cfg(path, **sections):
    cfg = {"domains": {"allow": ["example.com"]}}
    cfg.update(sections)
    path.write_text(yaml.safe_dump(cfg))
    # Force a visible mtime change even on coarse-timestamp filesystems.
    st = os.stat(path)
    bump = getattr(_write_cfg, "_n", 0) + 5
    _write_cfg._n = bump
    os.utime(path, (st.st_atime, st.st_mtime + bump))


def _make_addon(env, **sections):
    addon_mod, cfg_path = env
    _write_cfg(cfg_path, **sections)
    addon = addon_mod.Agentcage()
    addon.load(loader=None)
    addon._audit_write = lambda entry: None
    # Count checks, so a test can wait for the poll task to have run
    # rather than for a wall-clock time.
    addon.checks = 0
    check = getattr(addon, "_reload_check", addon._maybe_reload)

    def counted_check():
        addon.checks += 1
        check()

    addon._reload_check = counted_check
    return addon


def _count_reloads(addon):
    """Count reloads that got past the parse, via a step every one runs."""
    calls = []
    inner = addon._init_watcher

    def counting():
        calls.append(1)
        inner()

    addon._init_watcher = counting
    return calls


async def _ticks(addon, n=3):
    """Wait until the poll task has checked ``n`` more times."""
    target = addon.checks + n
    async with asyncio.timeout(10):
        while addon.checks < target:
            await asyncio.sleep(0.001)


class TestPollTask:
    def test_running_starts_it_and_done_cancels_it(self, env):
        async def go():
            addon = _make_addon(env)
            addon.running()
            task = addon._reload_task
            assert task is not None and not task.done()
            await addon.done()
            assert task.cancelled()
            assert addon._reload_task is None

        asyncio.run(go())

    def test_edit_without_traffic_is_applied(self, env):
        _, cfg_path = env

        async def go():
            addon = _make_addon(env)
            addon.running()
            try:
                assert addon._rl_burst == 50
                _write_cfg(cfg_path, rate_limit={"burst": 7})
                await _ticks(addon)
                assert addon._rl_burst == 7
            finally:
                await addon.done()

        asyncio.run(go())

    def test_failure_is_logged_and_the_task_survives(self, env):
        addon_mod, cfg_path = env

        async def go():
            addon = _make_addon(env)
            inner = addon._init_watcher
            failures = []

            def failing():
                failures.append(1)
                raise RuntimeError("boom")

            addon._init_watcher = failing
            addon.running()
            try:
                _write_cfg(cfg_path, rate_limit={"burst": 7})
                await _ticks(addon)
                assert not addon._reload_task.done()
                assert any("boom" in str(c) for c in
                           addon_mod.ctx.log.error.call_args_list)
                # Applied up to the failing step, and not retried on
                # every tick.
                assert addon._rl_burst == 7
                assert failures == [1]

                # The next edit is applied by the same task.
                addon._init_watcher = inner
                _write_cfg(cfg_path, rate_limit={"burst": 9})
                await _ticks(addon)
                assert addon._rl_burst == 9
                assert not addon._reload_task.done()
            finally:
                await addon.done()

        asyncio.run(go())

    def test_unparsable_edit_is_retried_but_logged_once(self, env):
        addon_mod, cfg_path = env

        async def go():
            addon = _make_addon(env)
            addon.running()
            try:
                cfg_path.write_text("domains: [unclosed\n")
                st = os.stat(cfg_path)
                os.utime(cfg_path, (st.st_atime, st.st_mtime + 1000))
                await _ticks(addon)
                warns = [c for c in addon_mod.ctx.log.warn.call_args_list
                         if "keeping old config" in str(c)]
                assert len(warns) == 1
                # A good write afterwards is picked up.
                _write_cfg(cfg_path, rate_limit={"burst": 3})
                await _ticks(addon)
                assert addon._rl_burst == 3
            finally:
                await addon.done()

        asyncio.run(go())


class TestSingleFlight:
    def test_timer_and_requests_apply_an_edit_once(self, env):
        _, cfg_path = env

        async def go():
            addon = _make_addon(env)
            reloads = _count_reloads(addon)
            addon.running()
            try:
                _write_cfg(cfg_path, rate_limit={"burst": 7})

                async def request_side():
                    # The unwrapped check, so ``addon.checks`` counts
                    # only the poll task's.
                    for _ in range(20):
                        type(addon)._reload_check(addon)
                        await asyncio.sleep(0.001)

                await asyncio.gather(request_side(), _ticks(addon, 10))
                assert reloads == [1]
                assert addon._rl_burst == 7
            finally:
                await addon.done()

        asyncio.run(go())

    def test_check_inside_a_reload_does_not_nest(self, env):
        _, cfg_path = env
        addon = _make_addon(env)
        reloads = _count_reloads(addon)
        counted = addon._init_watcher

        def edits_and_rechecks():
            counted()
            # An edit landing mid-reload, and a check from inside it.
            _write_cfg(cfg_path, rate_limit={"burst": 9})
            addon._reload_check()

        addon._init_watcher = edits_and_rechecks
        _write_cfg(cfg_path, rate_limit={"burst": 7})
        addon._reload_check()
        assert reloads == [1]
        assert addon._rl_burst == 7
        # The edit made during the reload is applied by the next check.
        addon._init_watcher = counted
        addon._reload_check()
        assert reloads == [1, 1]
        assert addon._rl_burst == 9


class TestRequestPath:
    def test_request_still_checks(self, env):
        # No poll task here (running() not called): the request applies
        # the edit itself, and is refused by the limit it sets.
        _, cfg_path = env
        addon = _make_addon(env)
        _write_cfg(cfg_path,
                   rate_limit={"requests_per_second": 1, "burst": 0})
        flow = _flow()
        asyncio.run(addon.request(flow))
        assert addon._rl_burst == 0
        assert flow.metadata.get("agentcage_blocked") is True

    def test_failing_reload_does_not_abort_the_request(self, env):
        # Raised out of request(), a reload failure aborted the hook
        # before the inspector chain ran. Here the edit sets a limit
        # that refuses the request: it must still be answered.
        _, cfg_path = env
        addon = _make_addon(env)

        def failing():
            raise RuntimeError("boom")

        addon._init_watcher = failing
        _write_cfg(cfg_path,
                   rate_limit={"requests_per_second": 1, "burst": 0})
        flow = _flow()
        asyncio.run(addon.request(flow))
        assert flow.metadata.get("agentcage_blocked") is True


def _flow(host="example.com"):
    flow = MagicMock()
    flow.id = "f1"
    flow.metadata = {}
    flow.request.host = host
    flow.request.pretty_host = host
    flow.request.host_header = host
    flow.client_conn.sni = None
    flow.client_conn.proxy_mode = MagicMock()
    return flow
