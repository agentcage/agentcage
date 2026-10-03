"""The breaking agents schema — egress side: the addon builds both agents.

Split out of ``tests/test_agents_config.py`` (RUST-PORT-PLAN.md §2.4): the host
half validates and canonicalises the ``agents`` block, this half asserts that
the in-egress addon constructs its two agents from the canonical keys the host
emits. The sample config is shared via ``tests/cross_language/vectors.py`` so
the two halves cannot drift onto different shapes.
"""

from copy import deepcopy
from unittest.mock import MagicMock

from tests.cross_language.vectors import (
    AGENTS_CLIENT as CLIENT, CANONICAL_AGENTS_CONFIG as CONFIG,
)


def test_addon_constructs_both_agents_from_canonical_keys(tmp_path, monkeypatch):
    from agentcage.data.proxy.addon import Agentcage
    from inspectors.domain import DomainInspector
    monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
    monkeypatch.setenv("TESTKEY", "test-key")
    monkeypatch.setenv("WATCHKEY", "watch-key")
    addon = Agentcage()
    addon.cfg = deepcopy(CONFIG)
    dom = DomainInspector()
    dom.configure(CONFIG["domains"])
    addon.inspectors = [dom]
    addon._policy_sweeper = addon._watcher_task = addon._watcher_ring = None
    addon.domain_requests = addon.traffic_watcher = None
    addon._running = False
    addon._audit_write = MagicMock()
    addon._init_domain_requests()
    assert addon.domain_requests is not None
    assert addon.domain_requests.host == "custom.test"
    assert addon.domain_requests._llm_model == CLIENT["model"]
    addon._init_watcher()
    assert addon.traffic_watcher is not None
    assert addon.traffic_watcher._provider == CLIENT["provider"]
    assert addon.traffic_watcher._secret == "watch-key"
    addon.cfg["agents"] = {}
    addon._init_domain_requests()
    addon._init_watcher()
    assert addon.domain_requests is None
    assert addon.traffic_watcher is None
