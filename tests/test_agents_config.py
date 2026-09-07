"""The breaking agents schema: strict input, canonical output, no migration."""

from copy import deepcopy
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from agentcage.config import load_config, validate_agents_raw, validate_config


CLIENT = {
    "provider": "openrouter", "model": "m", "api_key": "env:TESTKEY",
    "timeout_seconds": 45, "max_tokens": 16384,
    "base_url": "https://models.example.com",
}
CONFIG = {
    "name": "test", "isolation": "container", "dns_servers": ["1.1.1.1"],
    "container": {"image": "node:22-slim"},
    "domains": {"allow": ["example.com"]},
    "agents": {
        "decider": {
            "enable": True, "host": "custom.test", "context": "CI cage\n",
            "rate_limit": {"requests_per_second": 0, "burst": 0}, **CLIENT,
        },
        "watcher": {
            "enable": True, "interval_seconds": 900, "window_seconds": 7200,
            "max_flows": 150, "auto_revoke": False, "dedup_samples": False,
            "max_digest_tokens": 8000, "context": "Audit CI traffic\n",
            **CLIENT, "api_key": "env:WATCHKEY",
        },
    },
}


def test_validation_never_rewrites_input(tmp_path):
    raw = deepcopy(CONFIG)
    assert validate_agents_raw(raw) is None
    assert raw == CONFIG
    path = tmp_path / "cage.yaml"
    text = yaml.safe_dump(raw)
    path.write_text(text)
    cfg = load_config(str(path))
    assert validate_config(cfg) == []
    assert cfg.agents.decider.host == "custom.test"
    assert cfg.agents.decider.rate_limit_rps == 0
    assert cfg.agents.decider.max_tokens == 16384
    assert cfg.agents.watcher.context == "Audit CI traffic\n"
    assert not cfg.agents.watcher.auto_revoke
    assert path.read_text() == text


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("value", [None, {}, {"enable": False}, {"enable": True}, False, []])
@pytest.mark.parametrize("with_canonical", [True, False])
def test_removed_keys_rejected_by_presence(tmp_path, role, value, with_canonical):
    raw = deepcopy(CONFIG)
    if not with_canonical:
        del raw["agents"]
    if role == "decider":
        raw["domains"]["auto"] = value
    else:
        raw["watcher"] = value
    with pytest.raises(ValueError, match="no longer supported"):
        validate_agents_raw(raw)
    path = tmp_path / "cage.yaml"
    text = yaml.safe_dump(raw)
    path.write_text(text)
    with pytest.raises(ValueError, match="no longer supported"):
        load_config(str(path))
    assert path.read_text() == text


@pytest.mark.parametrize("bad", [False, 0, "", [], True, [1], "yes"])
@pytest.mark.parametrize("shape", [
    lambda v: {"agents": v},
    lambda v: {"agents": {"decider": v}},
    lambda v: {"agents": {"watcher": v}},
])
def test_non_mapping_blocks_rejected_even_when_falsy(shape, bad):
    with pytest.raises(ValueError, match="must be a mapping"):
        validate_agents_raw(shape(bad))


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("kind", ["agent", "webhook", None])
def test_kind_is_rejected_not_discarded(role, kind):
    with pytest.raises(ValueError, match="kind is no longer supported"):
        validate_agents_raw({"agents": {role: {"kind": kind}}})


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("wrapper", ["agent", "decider"])
def test_nested_llm_wrappers_rejected(role, wrapper):
    with pytest.raises(ValueError, match="LLM fields must be flat"):
        validate_agents_raw({"agents": {role: {wrapper: CLIENT}}})


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("value", ["false", "true", "yes", 0, 1, None])
def test_enable_must_be_boolean(role, value):
    with pytest.raises(ValueError, match="enable must be a boolean"):
        validate_agents_raw({"agents": {role: {"enable": value}}})


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("field,value", [("max_tokens", 0), ("timeout_seconds", 0),
                                         ("timeout_seconds", float("inf"))])
def test_invalid_explicit_numbers_are_not_defaulted(tmp_path, role, field, value):
    raw = deepcopy(CONFIG)
    raw["agents"][role][field] = value
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    cfg = load_config(str(path))
    assert getattr(getattr(cfg.agents, role), field) == value
    with pytest.raises(ValueError, match=field):
        validate_config(cfg)


@pytest.mark.parametrize("role", ["decider", "watcher"])
@pytest.mark.parametrize("bad_key", [
    "BARE_ENV_VAR",
    "env:",
    ":KEY_NAME",
    "cmd:echo secret",
    "unsupported:KEY",
])
def test_api_key_must_use_supported_source_scheme(tmp_path, role, bad_key):
    raw = deepcopy(CONFIG)
    raw["agents"][role]["api_key"] = bad_key
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match=r"(source:NAME|unknown secret source scheme|does not support cmd|unknown source scheme)"):
        cfg = load_config(str(path))
        validate_config(cfg)


@pytest.fixture
def stored(tmp_path, monkeypatch):
    import agentcage.state as state
    monkeypatch.setattr(state, "_DEPLOYMENTS_DIR", tmp_path / "cages")
    monkeypatch.setattr(state, "_DATA_DIR", tmp_path / "data")
    directory = state.deployment_dir("test")
    directory.mkdir(parents=True)
    (directory / "cage.yaml").write_text(yaml.safe_dump(CONFIG))
    (directory / "metadata.json").write_text(json.dumps({"agentcage_version": "0.39.0"}))
    return state, directory


def test_reads_and_saves_preserve_canonical_config(stored):
    state, directory = stored
    raw = state.load_raw_config("test")
    assert raw == CONFIG
    state.save_raw_config("test", raw)
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == CONFIG


@pytest.mark.parametrize("operation", ["read", "save", "copy", "render"])
def test_state_paths_reject_old_schema_without_rewriting(stored, tmp_path, operation):
    state, directory = stored
    old = {**deepcopy(CONFIG), "watcher": {"enable": False}}
    old_text = yaml.safe_dump(old)
    source = tmp_path / "old.yaml"
    source.write_text(old_text)
    target = directory / "cage.yaml"
    if operation in ("read", "render"):
        target.write_text(old_text)
    before = target.read_text()
    proxy = directory / "proxy-config.yaml"
    proxy.write_text("previous proxy config\n")
    with pytest.raises(ValueError, match="no longer supported"):
        if operation == "read":
            state.load_raw_config("test")
        elif operation == "save":
            state.save_raw_config("test", old)
        elif operation == "copy":
            state.save_deployment("test", str(source))
        else:
            state.save_proxy_config("test")
    assert target.read_text() == before
    assert source.read_text() == old_text
    assert proxy.read_text() == "previous proxy config\n"


def test_wire_output_has_canonical_keys_only(stored):
    state, directory = stored
    output = yaml.safe_load(Path(state.save_proxy_config("test")).read_text())
    assert output["agents"] == CONFIG["agents"]
    assert output["domains"] == CONFIG["domains"]
    assert "watcher" not in output
    assert "container" not in output
    assert "agent" not in output["agents"]["watcher"]
    assert "decider" not in output["agents"]["decider"]
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == CONFIG


def test_host_never_grant_uses_custom_control_host():
    from agentcage.cli import _host_never_grant
    assert "custom.test" in _host_never_grant(CONFIG)
    assert "agentcage.local" in _host_never_grant({})


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


@pytest.mark.parametrize("action", ["cancel", "unchanged", "save", "paste-legacy"])
def test_cage_edit_does_not_migrate(stored, monkeypatch, action):
    from click.testing import CliRunner
    from agentcage.cli import main
    state, directory = stored
    original_text = (directory / "cage.yaml").read_text()
    seen = []

    def edit(text, **kwargs):
        seen.append(text)
        if action == "cancel":
            return None
        if action == "save":
            return text + "\n# saved\n"
        if action == "paste-legacy":
            return text + "\nwatcher: {}\n"
        return text

    monkeypatch.setattr("click.edit", edit)
    result = CliRunner().invoke(main, ["cage", "edit", "test"])
    assert seen == [original_text]
    assert "Needs restart" not in result.output
    if action == "paste-legacy":
        assert result.exit_code == 1
        assert "no longer supported" in result.output
        assert (directory / "cage.yaml.rejected").exists()
    else:
        assert result.exit_code == 0, result.output
    if action != "save":
        assert (directory / "cage.yaml").read_text() == original_text
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == CONFIG


@pytest.mark.parametrize("command", ["edit", "update"])
def test_cli_rejects_old_stored_config_with_actionable_error(stored, command):
    from click.testing import CliRunner
    from agentcage.cli import main
    _, directory = stored
    target = directory / "cage.yaml"
    old_text = yaml.safe_dump({**deepcopy(CONFIG), "watcher": {}})
    target.write_text(old_text)
    result = CliRunner().invoke(main, ["cage", command, "test"])
    assert result.exit_code == 1
    assert "no longer supported" in result.output
    assert "agents.watcher" in result.output
    assert target.read_text() == old_text


def test_explicit_update_can_replace_unsupported_stored_config(stored, tmp_path, monkeypatch):
    """-c replaces old settings; it does not translate or merge them."""
    from click.testing import CliRunner
    from agentcage.cli import main
    state, directory = stored
    old = {"name": "test", "domains": {"auto": {"enable": False}}}
    (directory / "cage.yaml").write_text(yaml.safe_dump(old))
    replacement = tmp_path / "converted.yaml"
    replacement.write_text(yaml.safe_dump(CONFIG))
    monkeypatch.setattr("agentcage.cli.Podman", lambda: None)
    reached = []

    def stop_before_backend(podman, name, cfg):
        reached.append(cfg)
        raise RuntimeError("stop before backend operations")

    monkeypatch.setattr("agentcage.cli._check_secrets", stop_before_backend)
    result = CliRunner().invoke(main, ["cage", "update", "test", "-c", str(replacement)])
    assert reached, result.output
    assert str(result.exception) == "stop before backend operations"
    assert reached[0].agents.decider.enable
    assert yaml.safe_load((directory / "cage.yaml").read_text()) == CONFIG


@pytest.mark.parametrize("existing", [False, True])
def test_config_saves_preserve_private_yaml_permissions(stored, tmp_path, existing):
    state, directory = stored
    target = directory / "cage.yaml"
    prior_umask = os.umask(0o022)
    try:
        if existing:
            target.chmod(0o600)
            state.save_raw_config("test", state.load_raw_config("test"))
        else:
            source = tmp_path / "private.yaml"
            source.write_text(yaml.safe_dump(CONFIG))
            source.chmod(0o600)
            target.unlink()
            state.save_deployment("test", str(source))
        assert target.stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(prior_umask)
