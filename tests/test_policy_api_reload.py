"""A config hot-reload reconfigures the Policy API in place.

Every mtime change of the proxy config (each ``secret set``, ``domain add``,
``cage update``) runs ``_maybe_reload`` → ``_init_domain_requests``. That
used to construct a brand-new ``PolicyApi`` every time, which refilled the
decider's token bucket — so any reload handed the cage a fresh burst of
LLM-decider calls — and cancelled/restarted the sweeper task. These tests
drive the real reload path and pin the in-place behaviour: runtime state
(bucket tokens, sweeper task) survives, config-derived fields (host,
context, rate-limit parameters, LLM client) take effect, and the instance
is only built on disabled → enabled and dropped on enabled → disabled.
"""

from __future__ import annotations

import asyncio
import os

import yaml

from agentcage.data.proxy import addon as addon_mod


def _decider(**over):
    d = {
        "enable": True,
        "host": "agentcage.local",
        "provider": "openrouter",
        "model": "test-model",
        "api_key": "env:TEST_KEY",
        "base_url": "https://example.com",
        # A negligible refill rate, so a drained bucket stays drained for
        # the duration of a test.
        "rate_limit": {"requests_per_second": 0.0001, "burst": 3},
    }
    d.update(over)
    return d


class _Cage:
    """Writes the proxy config and drives load/reload on a real addon."""

    def __init__(self, tmp_path, monkeypatch):
        self.path = tmp_path / "config.yaml"
        monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
        monkeypatch.setenv("AGENTCAGE_DNS_PUBLISH",
                           str(tmp_path / "dns" / "granted"))
        monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(self.path))
        self.addon = None

    def write(self, decider=None, allow=("example.com",), watcher=None):
        agents = {}
        if decider is not None:
            agents["decider"] = decider
        if watcher is not None:
            agents["watcher"] = watcher
        self.path.write_text(yaml.safe_dump({
            "domains": {"mode": "allowlist", "allow": list(allow)},
            "agents": agents,
        }))

    def load(self):
        self.addon = addon_mod.Agentcage()
        self.addon.load(loader=None)
        return self.addon

    def reload(self, **write_kw):
        self.write(**write_kw)
        # Force a new mtime: two writes inside one mtime tick would
        # otherwise look like "unchanged" to the poll.
        os.utime(self.path, (0, os.stat(self.path).st_mtime + 5))
        self.addon._maybe_reload()
        return self.addon


def _drain(pa):
    while pa._check_rate_limit():
        pass


class TestBucketSurvivesReload:
    def test_unrelated_reload_does_not_refill_an_exhausted_bucket(
        self, tmp_path, monkeypatch,
    ):
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider())
        addon = cage.load()
        pa = addon.domain_requests
        _drain(pa)
        assert not pa._check_rate_limit()

        # E.g. `domain add` re-renders the config: the decider block is
        # untouched, so the cage must not get a fresh burst out of it.
        cage.reload(decider=_decider(), allow=("example.com", "example.org"))
        assert addon.domain_requests is pa
        assert not addon.domain_requests._check_rate_limit()

    def test_same_decider_block_reload_does_not_refill(
        self, tmp_path, monkeypatch,
    ):
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider())
        addon = cage.load()
        pa = addon.domain_requests
        _drain(pa)
        # `secret set` touches the config without changing it at all.
        cage.reload(decider=_decider())
        assert addon.domain_requests is pa
        assert not pa._check_rate_limit()

    def test_rate_limit_change_keeps_tokens_clamped_to_new_burst(
        self, tmp_path, monkeypatch,
    ):
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider(
            rate_limit={"requests_per_second": 0.0001, "burst": 10}))
        addon = cage.load()
        pa = addon.domain_requests
        assert pa._check_rate_limit()  # 9 tokens left
        cage.reload(decider=_decider(
            rate_limit={"requests_per_second": 0.0001, "burst": 2}))
        assert addon.domain_requests is pa
        assert pa._rl_burst == 2
        # Clamped to the new burst: exactly two more, then denied.
        assert pa._check_rate_limit()
        assert pa._check_rate_limit()
        assert not pa._check_rate_limit()

    def test_raising_burst_does_not_refill(self, tmp_path, monkeypatch):
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider())
        addon = cage.load()
        pa = addon.domain_requests
        _drain(pa)
        # A bigger burst raises the ceiling, not the current level.
        cage.reload(decider=_decider(
            rate_limit={"requests_per_second": 0.0001, "burst": 50}))
        assert pa._rl_burst == 50
        assert not pa._check_rate_limit()

    def test_rps_zero_on_reload_disables_limiting(self, tmp_path, monkeypatch):
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider())
        addon = cage.load()
        pa = addon.domain_requests
        _drain(pa)
        cage.reload(decider=_decider(
            rate_limit={"requests_per_second": 0, "burst": 3}))
        assert addon.domain_requests is pa
        assert all(pa._check_rate_limit() for _ in range(20))


class TestConfigFieldsTakeEffect:
    def test_host_and_context_change_apply_in_place(
        self, tmp_path, monkeypatch,
    ):
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider(context="context-v1"))
        addon = cage.load()
        pa = addon.domain_requests
        assert pa.is_control_host(None, "agentcage.local")

        cage.reload(decider=_decider(
            host="control.example.com", context="context-v2"))
        assert addon.domain_requests is pa
        assert pa.host == "control.example.com"
        assert pa._context == "context-v2"
        assert pa.is_control_host(None, "control.example.com")
        assert not pa.is_control_host(None, "agentcage.local")
        # The control host is always never_grant — the new one, and the
        # old one no longer is (by name; ``local`` is built-in anyway).
        assert "control.example.com" in pa._never_grant
        assert "agentcage.local" not in pa._never_grant

    def test_llm_client_fields_apply_in_place(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "key-v1")
        monkeypatch.setenv("OTHER_KEY", "key-v2")
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider())
        addon = cage.load()
        pa = addon.domain_requests
        assert pa._llm_secret == "key-v1"
        cage.reload(decider=_decider(
            provider="anthropic", model="model-v2",
            base_url="https://api.example.net/", api_key="env:OTHER_KEY",
            timeout_seconds=30, max_tokens=4096))
        assert addon.domain_requests is pa
        assert pa._llm_provider == "anthropic"
        assert pa._llm_model == "model-v2"
        assert pa._llm_base_url == "https://api.example.net"
        assert pa._llm_secret == "key-v2"
        assert pa._llm_timeout == 30.0
        assert pa._llm_max_tokens == 4096

    def test_restaged_secret_is_reread_on_reload(self, tmp_path, monkeypatch):
        # `secret set` re-stages the value without changing the config
        # value that names it; the reload must still pick it up.
        monkeypatch.setenv("TEST_KEY", "key-v1")
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider())
        addon = cage.load()
        monkeypatch.setenv("TEST_KEY", "key-v2")
        cage.reload(decider=_decider())
        assert addon.domain_requests._llm_secret == "key-v2"

    def test_malformed_reload_tears_down_like_a_failed_init(
        self, tmp_path, monkeypatch,
    ):
        cage = _Cage(tmp_path, monkeypatch)
        cage.write(decider=_decider())
        addon = cage.load()
        assert addon.domain_requests is not None
        cage.reload(decider=_decider(max_tokens="not-a-number"))
        assert addon.domain_requests is None


class TestLifecycle:
    def test_disable_enable_disable(self, tmp_path, monkeypatch):
        watcher = {"enable": True, "provider": "openrouter",
                   "model": "test-model", "api_key": "env:TEST_KEY"}

        async def scenario():
            cage = _Cage(tmp_path, monkeypatch)
            cage.write(decider=_decider(enable=False), watcher=watcher)
            addon = cage.load()
            addon.running()
            try:
                assert addon.domain_requests is None
                assert addon._policy_sweeper is None
                assert addon.traffic_watcher._pa is None

                # disabled → enabled: built, sweeper started, the watcher
                # re-pointed at it.
                cage.reload(decider=_decider(), watcher=watcher)
                pa = addon.domain_requests
                assert pa is not None
                sweeper = addon._policy_sweeper
                assert sweeper is not None and not sweeper.done()
                assert addon.traffic_watcher._pa is pa

                # enabled → enabled: the same instance, the same task.
                cage.reload(decider=_decider(context="c"), watcher=watcher)
                assert addon.domain_requests is pa
                assert addon._policy_sweeper is sweeper
                assert addon.traffic_watcher._pa is pa

                # enabled → disabled: dropped, sweeper cancelled, and the
                # watcher no longer revokes through the stale instance.
                cage.reload(decider=_decider(enable=False), watcher=watcher)
                assert addon.domain_requests is None
                assert addon._policy_sweeper is None
                await asyncio.sleep(0)
                assert sweeper.cancelled()
                assert addon.traffic_watcher._pa is None

                # Re-enabling builds a fresh instance (with a full bucket —
                # the one transition that is allowed to).
                cage.reload(decider=_decider(), watcher=watcher)
                assert addon.domain_requests is not None
                assert addon.domain_requests is not pa
                assert addon.traffic_watcher._pa is addon.domain_requests
            finally:
                await addon.done()

        asyncio.run(scenario())

    def test_unrelated_reload_does_not_restart_the_sweeper(
        self, tmp_path, monkeypatch,
    ):
        async def scenario():
            cage = _Cage(tmp_path, monkeypatch)
            cage.write(decider=_decider())
            addon = cage.load()
            addon.running()
            try:
                sweeper = addon._policy_sweeper
                assert sweeper is not None
                cage.reload(decider=_decider(),
                            allow=("example.com", "example.org"))
                await asyncio.sleep(0)
                assert addon._policy_sweeper is sweeper
                assert not sweeper.done()
            finally:
                await addon.done()

        asyncio.run(scenario())
