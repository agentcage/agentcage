"""Tests for agentcage.run module (generate_name, execute)."""

import json
import re
from unittest.mock import MagicMock, patch

import pytest

from agentcage.run import (
    _ensure_volume_dirs,
    _stage_set_secrets,
    _vm_podman_prefix,
    generate_name,
)


class TestVmPodmanPrefix:
    """The interactive session must reach Podman inside the VM on macOS."""

    def test_vm_routes_through_limactl(self):
        assert _vm_podman_prefix("vm", "my-cage") == [
            "limactl", "shell", "agentcage-my-cage", "--",
        ]

    def test_container_needs_no_prefix(self):
        assert _vm_podman_prefix("container", "my-cage") == []


class TestEnsureVolumeDirs:
    """Missing bind-mount directories are created so cage state persists."""

    def test_creates_missing_directory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        target = tmp_path / ".claude"
        _ensure_volume_dirs([f"{target}:/home/node/.claude:rw"])
        assert target.is_dir()

    def test_skips_file_like_path(self, tmp_path, monkeypatch):
        # A host path with an extension is treated as a file — agentcage
        # must not create it as a directory.
        monkeypatch.setenv("HOME", str(tmp_path))
        target = tmp_path / ".claude.json"
        _ensure_volume_dirs([f"{target}:/home/node/.claude.json:rw"])
        assert not target.exists()

    def test_skips_existing_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        existing = tmp_path / "project"
        existing.mkdir()
        _ensure_volume_dirs([f"{existing}:/workspace:rw"])
        assert existing.is_dir()

    def test_skips_unexpanded_var(self, tmp_path, monkeypatch):
        # An unresolved ${VAR} must not raise and must not be created.
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("AGENTCAGE_UNSET_X", raising=False)
        _ensure_volume_dirs(["${AGENTCAGE_UNSET_X}/data:/x:rw"])

    def test_skips_path_outside_home(self, tmp_path, monkeypatch):
        # tmp_path is outside the mocked home — must not be created.
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        (tmp_path / "home").mkdir()
        outside = tmp_path / "elsewhere"
        _ensure_volume_dirs([f"{outside}:/x:rw"])
        assert not outside.exists()


class TestStageSetSecrets:
    """--set-secret values: host Podman in container mode, staged file in VM mode."""

    def test_vm_mode_writes_pending_file(self, tmp_path):
        with patch("agentcage.run.state.deployment_dir", return_value=tmp_path):
            keys = _stage_set_secrets("my-cage", ("API_KEY=secret123",), "vm", None)
        assert keys == {"API_KEY"}
        pending = tmp_path / "pending_secrets.json"
        assert json.loads(pending.read_text()) == [["API_KEY", "secret123"]]
        # 0600 — staged secrets must not be group/world readable
        assert (pending.stat().st_mode & 0o077) == 0

    def test_vm_mode_no_secrets_writes_nothing(self, tmp_path):
        with patch("agentcage.run.state.deployment_dir", return_value=tmp_path):
            keys = _stage_set_secrets("my-cage", (), "vm", None)
        assert keys == set()
        assert not (tmp_path / "pending_secrets.json").exists()

    def test_container_mode_uses_host_podman(self):
        podman = MagicMock()
        podman.secret_exists.return_value = False
        keys = _stage_set_secrets("my-cage", ("API_KEY=v",), "container", podman)
        assert keys == {"API_KEY"}
        podman.secret_create.assert_called_once_with("my-cage.API_KEY", "v")

    def test_vm_mode_never_calls_host_podman(self):
        # The whole point: VM mode must not touch host Podman.
        podman = MagicMock()
        with patch("agentcage.run.state.deployment_dir") as dd:
            import tempfile
            dd.return_value = __import__("pathlib").Path(tempfile.mkdtemp())
            _stage_set_secrets("c", ("K=V",), "vm", podman)
        podman.secret_create.assert_not_called()


class TestGenerateName:
    """Verify auto-naming for ephemeral/interactive cages."""

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_produces_valid_cage_name(self, _mock):
        name = generate_name("claude-code")
        assert re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', name)
        assert name.startswith("claude-")
        # Should use short prefix, not full scaffold name
        assert not name.startswith("claude-code-")

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_names_are_unique(self, _mock):
        names = {generate_name("test") for _ in range(50)}
        assert len(names) >= 40

    @patch("agentcage.run.state.list_deployments",
           return_value=["test-bold-fox", "test-calm-owl"])
    def test_avoids_existing_names(self, _mock):
        for _ in range(20):
            name = generate_name("test")
            assert name not in ("test-bold-fox", "test-calm-owl")

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_name_not_too_long(self, _mock):
        name = generate_name("claude-code")
        assert len(name) <= 63

    @patch("agentcage.run.state.list_deployments", return_value=[])
    def test_includes_scaffold_prefix(self, _mock):
        name = generate_name("codex")
        assert name.startswith("codex-")
        # Should have adjective-noun after prefix
        parts = name.split("-")
        assert len(parts) >= 3
