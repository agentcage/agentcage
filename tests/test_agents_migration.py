"""Canonical agent config, safe legacy migration, and egress wiring."""

from copy import deepcopy
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from agentcage.config import load_config, normalize_legacy_agents, validate_config


CLIENT = {
    "provider": "openrouter", "model": "m", "api_key": "env:TESTKEY",
    "timeout_seconds": 45, "max_tokens": 16384,
    "base_url": "https://models.example.com",
}
OLD = {
    "name": "test", "isolation": "container", "dns_servers": ["1.1.1.1"],
    "container": {"image": "node:22-slim"},
    "domains": {"allow": ["example.com"], "auto": {
        "enable": True, "host": "custom.test", "context": "CI cage\n",
        "rate_limit": {"requests_per_second": 0, "burst": 0},
        "decider": {"kind": "agent", **CLIENT},
    }},
    "watcher": {
        "enable": True, "interval_seconds": 120, "window_seconds": 7200,
        "max_flows": 150, "auto_revoke": False, "dedup_samples": False,
        "max_digest_tokens": 8000, "context": "Audit CI traffic\n",
        "agent": {**CLIENT, "api_key": "env:WATCHKEY"},
    },
}
NEW = {
    "name": "test", "isolation": "container", "dns_servers": ["1.1.1.1"],
    "container": {"image": "node:22-slim"},
    "domains": {"allow": ["example.com"]},
    "agents": {
        "decider": {
            "enable": True, "host": "custom.test", "context": "CI cage\n",
            "rate_limit": {"requests_per_second": 0, "burst": 0}, **CLIENT,
        },
        "watcher": {
            "enable": True, "interval_seconds": 120, "window_seconds": 7200,
            "max_flows": 150, "auto_revoke": False, "dedup_samples": False,
            "max_digest_tokens": 8000, "context": "Audit CI traffic\n",
            **CLIENT, "api_key": "env:WATCHKEY",
        },
    },
}


def test_normalization_is_lossless_idempotent_and_non_mutating():
    original = deepcopy(OLD)
    normalized, notices = normalize_legacy_agents(original)
    assert normalized == NEW
    assert original == OLD
    assert len(notices) == 2
    assert normalize_legacy_agents(normalized) == (NEW, [])


def test_legacy_and_new_typed_configs_are_equivalent(tmp_path):
    path = tmp_path / "cage.yaml"
    path.write_text(yaml.safe_dump(OLD))
    old = load_config(str(path))
    warnings = validate_config(old)
    assert all(notice in warnings for notice in old.legacy_form_notices)
    assert len(old.legacy_form_notices) == 2
    path.write_text(yaml.safe_dump(NEW))
    new = load_config(str(path))
    assert not new.legacy_form_notices
    assert old == new


@pytest.mark.parametrize("role,legacy,wrapper", [
    ("decider", "auto", "decider"), ("watcher", "watcher", "agent"),
])
@pytest.mark.parametrize("empty", [{}, None, {"enable": False}])
def test_duplicate_forms_rejected_by_presence(role, legacy, wrapper, empty):
    raw = {"agents": {role: empty}}
    owner = raw.setdefault("domains", {}) if role == "decider" else raw
    owner[legacy] = {"enable": True, wrapper: CLIENT}
    with pytest.raises(ValueError, match="ambiguous config"):
        normalize_legacy_agents(raw)


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("value", [{}, None])
def test_empty_legacy_blocks_are_removed(role, value):
    raw = {"domains": {"auto": value}} if role == "decider" else {"watcher": value}
    normalized, notices = normalize_legacy_agents(raw)
    assert normalized["agents"][role] == {}
    assert notices
    assert "auto" not in normalized.get("domains", {})
    assert "watcher" not in normalized


@pytest.mark.parametrize("role", ["decider", "watcher"])
def test_mixed_role_migration(role):
    raw = deepcopy(OLD)
    raw["agents"] = {role: deepcopy(NEW["agents"][role])}
    if role == "decider":
        del raw["domains"]["auto"]
    else:
        del raw["watcher"]
    result, notices = normalize_legacy_agents(raw)
    assert result == NEW
    assert len(notices) == 1


@pytest.mark.parametrize("bad", [False, 0, "", [], True, [1], "yes"])
@pytest.mark.parametrize("shape", [
    lambda v: {"agents": v},
    lambda v: {"agents": {"decider": v}},
    lambda v: {"agents": {"watcher": v}},
    lambda v: {"domains": {"auto": v}},
    lambda v: {"domains": {"auto": {"decider": v}}},
    lambda v: {"watcher": v},
    lambda v: {"watcher": {"agent": v}},
])
def test_non_mapping_blocks_rejected_even_when_falsy(shape, bad):
    with pytest.raises(ValueError, match="must be a mapping"):
        normalize_legacy_agents(shape(bad))


@pytest.mark.parametrize("kind", ["webhook", "carrier-pigeon"])
@pytest.mark.parametrize("legacy", [True, False])
def test_unsupported_kind_rejected_before_flattening(kind, legacy):
    raw = ({"domains": {"auto": {"decider": {"kind": kind}}}} if legacy
           else {"agents": {"decider": {"kind": kind}}})
    with pytest.raises(ValueError, match="kind"):
        normalize_legacy_agents(raw)


def test_explicit_agent_kind_removed_from_canonical_form():
    raw, _ = normalize_legacy_agents({"agents": {"decider": {"kind": "agent"}}})
    assert raw == {"agents": {"decider": {}}}


def test_nested_legacy_fields_cannot_override_operational_settings():
    raw = deepcopy(OLD)
    raw["domains"]["auto"]["decider"].update(enable=False, host="wrong.test")
    raw["watcher"]["agent"].update(auto_revoke=True, context="wrong context")
    normalized, _ = normalize_legacy_agents(raw)
    assert normalized == NEW


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("value", ["false", "true", "yes", 0, 1, None])
def test_enable_must_be_boolean(role, value):
    with pytest.raises(ValueError, match="enable must be a boolean"):
        normalize_legacy_agents({"agents": {role: {"enable": value}}})


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("field,value", [("max_tokens", 0), ("timeout_seconds", 0),
                                         ("timeout_seconds", float("inf"))])
def test_invalid_explicit_numbers_are_not_defaulted(tmp_path, role, field, value):
    raw = deepcopy(NEW)
    raw["agents"][role][field] = value
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    cfg = load_config(str(path))
    assert getattr(getattr(cfg.agents, role), field) == value
    with pytest.raises(ValueError, match=field):
        validate_config(cfg)


@pytest.fixture
def stored(tmp_path, monkeypatch):
    import agentcage.state as state
    monkeypatch.setattr(state, "_DEPLOYMENTS_DIR", tmp_path / "cages")
    monkeypatch.setattr(state, "_DATA_DIR", tmp_path / "data")
    directory = state.deployment_dir("test")
    directory.mkdir(parents=True)
    (directory / "cage.yaml").write_text(yaml.safe_dump(OLD))
    (directory / "metadata.json").write_text(json.dumps({"agentcage_version": "0.39.0"}))
    return state, directory


def test_raw_load_does_not_write_but_save_migrates(stored):
    state, directory = stored
    raw = state.load_raw_config("test")
    assert raw == NEW
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == OLD
    state.save_raw_config("test", raw)
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == NEW


def test_save_deployment_canonicalizes_legacy_config(stored, tmp_path):
    state, directory = stored
    source = tmp_path / "source.yaml"
    source.write_text(yaml.safe_dump(OLD))
    state.save_deployment("test", str(source))
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == NEW
    assert yaml.safe_load(source.read_text()) == OLD


def test_legacy_wire_projection_has_exact_old_shape_and_does_not_leak_to_disk(stored):
    state, directory = stored
    output = yaml.safe_load(Path(state.save_proxy_config("test")).read_text())
    assert output["agents"] == NEW["agents"]
    # These are the ACTUAL paths old egress consumers read. In particular,
    # enable/host/context/limits are NOT inside the LLM sub-blocks.
    assert output["domains"]["auto"] == OLD["domains"]["auto"]
    assert output["watcher"] == OLD["watcher"]
    del output["agents"]
    round_trip, _ = normalize_legacy_agents(output)
    assert round_trip["agents"] == NEW["agents"]
    assert "container" not in output
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == OLD


@pytest.mark.parametrize("remove", [False, True])
def test_disabling_or_removing_agents_clears_legacy_shadow(stored, remove):
    state, _ = stored
    state.save_proxy_config("test")
    raw = deepcopy(NEW)
    if remove:
        del raw["agents"]
    else:
        for block in raw["agents"].values():
            block["enable"] = False
    state.save_raw_config("test", raw)
    output = yaml.safe_load(Path(state.save_proxy_config("test")).read_text())
    assert "watcher" not in output
    assert "auto" not in output["domains"]


def test_host_never_grant_uses_custom_control_host():
    from agentcage.cli import _host_never_grant
    assert "custom.test" in _host_never_grant(NEW)
    assert "agentcage.local" in _host_never_grant({})


def test_addon_constructs_both_agents_and_prefers_new_keys(tmp_path, monkeypatch):
    from agentcage.data.proxy.addon import Agentcage
    from inspectors.domain import DomainInspector
    monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
    monkeypatch.setenv("TESTKEY", "test-key")
    monkeypatch.setenv("WATCHKEY", "watch-key")
    addon = Agentcage()
    addon.cfg = deepcopy(NEW)
    # New egress ignores the transitional legacy keys, including conflict.
    addon.cfg["domains"]["auto"] = {"enable": False}
    addon.cfg["watcher"] = {"enable": False}
    dom = DomainInspector()
    dom.configure(NEW["domains"])
    addon.inspectors = [dom]
    addon._policy_sweeper = addon._watcher_task = addon._watcher_ring = None
    addon.domain_requests = addon.traffic_watcher = None
    addon._running = False
    addon._audit_write = MagicMock()
    addon._init_domain_requests()
    assert addon.domain_requests is not None  # catches the missed addon gate
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


@pytest.mark.parametrize("action", ["cancel", "unchanged", "save", "paste-legacy"])
def test_cage_edit_normalizes_before_diff_and_preserves_cancel(stored, monkeypatch, action):
    from click.testing import CliRunner
    from agentcage.cli import main
    state, directory = stored
    seen = []

    def edit(text, **kwargs):
        seen.append(yaml.safe_load(text))
        if action == "cancel":
            return None
        if action == "save":
            return text + "\n# saved\n"
        if action == "paste-legacy":
            return yaml.safe_dump(OLD)
        return text

    monkeypatch.setattr("click.edit", edit)
    result = CliRunner().invoke(main, ["cage", "edit", "test"])
    assert result.exit_code == 0, result.output
    assert seen == [NEW]
    assert "Needs restart" not in result.output
    assert "warning:" in result.output
    on_disk = yaml.safe_load((directory / "cage.yaml").read_text())
    assert on_disk == (OLD if action in ("cancel", "unchanged") else NEW)


def test_normalized_noop_classifies_nothing():
    from agentcage.cli import _classify_changes
    before, _ = normalize_legacy_agents(OLD)
    after, _ = normalize_legacy_agents(NEW)
    assert _classify_changes(before, after) == (set(), set(), set())


@pytest.mark.parametrize("existing", [False, True])
def test_migration_preserves_private_yaml_permissions(stored, tmp_path, existing):
    state, directory = stored
    target = directory / "cage.yaml"
    prior_umask = os.umask(0o022)
    try:
        if existing:
            target.chmod(0o600)
            state.save_raw_config("test", state.load_raw_config("test"))
        else:
            source = tmp_path / "private.yaml"
            source.write_text(yaml.safe_dump(OLD))
            source.chmod(0o600)
            target.unlink()
            state.save_deployment("test", str(source))
        assert target.stat().st_mode & 0o777 == 0o600
        assert yaml.safe_load(target.read_text()) == NEW
    finally:
        os.umask(prior_umask)


def test_migration_notices_do_not_change_update_fingerprint(tmp_path):
    from agentcage.cli import _resolved_update_config
    path = tmp_path / "cage.yaml"
    path.write_text(yaml.safe_dump(OLD))
    legacy = load_config(str(path))
    assert legacy.legacy_form_notices
    before = _resolved_update_config(legacy)
    path.write_text(yaml.safe_dump(NEW))
    canonical = load_config(str(path))
    assert not canonical.legacy_form_notices
    assert _resolved_update_config(canonical) == before
    assert "legacy_form_notices" not in before[0]
