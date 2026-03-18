"""Unit tests for agentcage.state — deployment state management."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import yaml

from agentcage.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_minimal_config(path: Path) -> Path:
    """Write a minimal cage.yaml and return the file path."""
    cfg = path / "config.yaml"
    cfg.write_text(textwrap.dedent("""\
        name: test
        container:
          image: localhost/test:latest
    """))
    return cfg


def _write_full_config(path: Path) -> Path:
    """Write a config that contains proxy and non-proxy keys."""
    cfg = path / "config.yaml"
    cfg.write_text(textwrap.dedent("""\
        name: myapp
        container:
          image: node:22-slim
        domains:
          allow:
            - example.com
        secrets:
          MY_KEY: secret123
        max_request_body: 4096
        entropy: true
        content_type: application/json
        inspectors:
          - type: keyword
        rate_limit:
          rpm: 60
        logging:
          level: info
        secret_injection:
          - env: MY_KEY
        capture: true
        dns_servers:
          - 1.1.1.1
    """))
    return cfg


@pytest.fixture
def _patch_state_dirs(tmp_path, monkeypatch):
    """Patch agentcage.state module-level dirs to use tmp_path, auto-reverted."""
    import agentcage.state as state
    config_dir = tmp_path / "config" / "agentcage"
    monkeypatch.setattr(state, "_CONFIG_DIR", config_dir)
    monkeypatch.setattr(state, "_DEPLOYMENTS_DIR", config_dir / "cages")
    return state


@pytest.fixture
def _patch_state_data_dir(tmp_path, monkeypatch):
    """Patch agentcage.state _DATA_DIR to use tmp_path, auto-reverted."""
    import agentcage.state as state
    monkeypatch.setattr(state, "_DATA_DIR", tmp_path / "data" / "agentcage")
    return state


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSaveAndLoadDeployment:
    """save_deployment / load_deployment_config round-trip."""

    def test_round_trip(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("demo", str(cfg_file))

        loaded = state.load_deployment_config("demo")
        assert isinstance(loaded, Config)
        assert loaded.name == "test"
        assert loaded.container.image == "localhost/test:latest"

    def test_load_missing_raises(self, _patch_state_dirs):
        state = _patch_state_dirs
        with pytest.raises(FileNotFoundError):
            state.load_deployment_config("nonexistent")


class TestSaveProxyConfig:
    """save_proxy_config should only keep _PROXY_KEYS."""

    def test_filters_keys(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_full_config(tmp_path)
        state.save_deployment("myapp", str(cfg_file))
        proxy_path = state.save_proxy_config("myapp")

        with open(proxy_path) as f:
            proxy_cfg = yaml.safe_load(f)

        # Proxy keys should be present
        assert "domains" in proxy_cfg
        assert "secrets" in proxy_cfg
        assert "max_request_body" in proxy_cfg

        # Non-proxy keys should be absent
        assert "container" not in proxy_cfg
        assert "dns_servers" not in proxy_cfg
        assert "name" not in proxy_cfg


class TestSaveAndLoadMetadata:
    """save_metadata / load_metadata round-trip."""

    def test_round_trip(self, _patch_state_dirs):
        state = _patch_state_dirs
        meta = {"backend": "container", "created": "2025-01-01"}
        state.save_metadata("demo", meta)

        loaded = state.load_metadata("demo")
        assert loaded == meta

    def test_load_missing_returns_empty(self, _patch_state_dirs):
        state = _patch_state_dirs
        assert state.load_metadata("nonexistent") == {}


class TestListDeployments:
    def test_empty(self, _patch_state_dirs):
        state = _patch_state_dirs
        assert state.list_deployments() == []

    def test_multiple(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("alpha", str(cfg_file))
        state.save_deployment("beta", str(cfg_file))

        result = state.list_deployments()
        assert result == ["alpha", "beta"]

    def test_ignores_dirs_without_cage_yaml(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        # Create a directory without cage.yaml
        (state._DEPLOYMENTS_DIR / "orphan").mkdir(parents=True)

        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("valid", str(cfg_file))

        assert state.list_deployments() == ["valid"]


class TestDeploymentExistsAndDir:
    def test_exists_true(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("demo", str(cfg_file))

        assert state.deployment_exists("demo") is True

    def test_exists_false(self, _patch_state_dirs):
        state = _patch_state_dirs
        assert state.deployment_exists("nope") is False

    def test_deployment_dir_path(self, _patch_state_dirs):
        state = _patch_state_dirs
        d = state.deployment_dir("demo")
        assert d == state._DEPLOYMENTS_DIR / "demo"


class TestCapturePaths:
    def test_capture_dir_created(self, _patch_state_data_dir):
        state = _patch_state_data_dir
        d = state.capture_dir("myapp")
        assert d.is_dir()
        assert d == state._DATA_DIR / "myapp" / "capture"

    def test_capture_file_path(self, _patch_state_data_dir):
        state = _patch_state_data_dir
        f = state.capture_file("myapp")
        assert f == state._DATA_DIR / "myapp" / "capture" / "capture.jsonl"


class TestEdgeCases:
    def test_corrupted_yaml(self, _patch_state_dirs):
        state = _patch_state_dirs
        # Manually write corrupted YAML
        d = state._DEPLOYMENTS_DIR / "bad"
        d.mkdir(parents=True)
        (d / "cage.yaml").write_text(": : : not valid yaml [[[")

        # load_raw_config should either raise or return something
        # The yaml parser may raise an exception
        with pytest.raises(Exception):
            state.load_raw_config("bad")

    def test_empty_config_file(self, _patch_state_dirs):
        state = _patch_state_dirs
        d = state._DEPLOYMENTS_DIR / "empty"
        d.mkdir(parents=True)
        (d / "cage.yaml").write_text("")

        raw = state.load_raw_config("empty")
        assert raw == {}

    def test_remove_deployment(self, tmp_path, _patch_state_dirs):
        state = _patch_state_dirs
        cfg_file = _write_minimal_config(tmp_path)
        state.save_deployment("todelete", str(cfg_file))
        assert state.deployment_exists("todelete")

        state.remove_deployment("todelete")
        assert not state.deployment_exists("todelete")
