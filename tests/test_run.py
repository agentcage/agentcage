"""Tests for agentcage.run module (generate_name, execute)."""

import json
import re
from unittest.mock import MagicMock, patch

import pytest

from agentcage.run import (
    _ensure_volume_dirs,
    _resolve_exec_cmd,
    _stage_set_secrets,
    _vm_podman_prefix,
    execute,
    generate_name,
)


class _FakeCfg:
    def __init__(self, exec_aliases):
        self.exec_aliases = exec_aliases


class TestResolveExecCmd:
    """`agentcage run -- <extras>` must use extras AS-IS as the cage command.

    Pre-fix the code prepended the scaffold's first exec_alias to extras,
    so ``-- claude --dangerously-skip-permissions -p "<prompt>"`` became
    ``["claude", "claude", "--dangerously-skip-permissions", "-p", ...]``.
    Claude consumed the second positional ``claude`` as its prompt and
    silently ignored ``-p`` — the agent responded to the binary name
    instead of the operator's actual prompt.
    """

    def test_extras_replace_alias_no_prepend(self):
        cfg = _FakeCfg({"claude": ["claude"]})
        result = _resolve_exec_cmd(
            cfg,
            ("claude", "--dangerously-skip-permissions", "-p", "hi"),
        )
        # The leading `claude` from extras stays; the alias is NOT prepended.
        assert result == ["claude", "--dangerously-skip-permissions", "-p", "hi"]
        # Count to spell out the bug: there must be exactly ONE `claude`.
        assert result.count("claude") == 1

    def test_extras_without_binary_name_still_works(self):
        """The recommended invocation is `agentcage run claude-code --
        --dangerously-skip-permissions -p X` (no leading `claude` because
        the scaffold supplies it). But pre-fix that branch ran the bare
        flags directly as a command — now it still does, because extras
        are taken AS-IS."""
        cfg = _FakeCfg({"claude": ["claude"]})
        result = _resolve_exec_cmd(
            cfg, ("--dangerously-skip-permissions", "-p", "hi"),
        )
        assert result == ["--dangerously-skip-permissions", "-p", "hi"]

    def test_no_extras_uses_first_alias(self):
        cfg = _FakeCfg({"claude": ["claude", "--print"]})
        result = _resolve_exec_cmd(cfg, ())
        assert result == ["claude", "--print"]

    def test_no_extras_no_aliases_falls_back_to_bash(self):
        cfg = _FakeCfg({})
        result = _resolve_exec_cmd(cfg, ())
        assert result == ["/bin/bash"]

    def test_extras_win_over_aliases_even_for_unrelated_binary(self):
        """`agentcage run claude-code -- python /tmp/foo.py` must run
        python, not claude. Extras take precedence."""
        cfg = _FakeCfg({"claude": ["claude"]})
        result = _resolve_exec_cmd(cfg, ("python", "/tmp/foo.py"))
        assert result == ["python", "/tmp/foo.py"]


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


class TestExecuteMissingSecrets:
    """`agentcage run` must fail fast on a missing required secret, mirroring
    `agentcage cage create`. The pre-fix behaviour silently stripped the
    injection rule and started a cage whose proxy forwarded the unswapped
    placeholder — the agent then failed to authenticate with no clear signal.
    """

    @patch("agentcage.run.build_and_deploy")
    @patch("agentcage.run.run_scaffold_setup")
    @patch("agentcage.run.check_port_availability", return_value=[])
    @patch("agentcage.run.check_secrets", return_value=["ANTHROPIC_API_KEY"])
    @patch("agentcage.run.Podman")
    def test_aborts_before_build_when_secret_missing(
        self, _podman, _check, _ports, mock_setup, mock_deploy,
        patch_state_dirs, tmp_path, capsys,
    ):
        code = execute(
            "claude-code",
            project_dir=str(tmp_path),
            name="claude-test-missing-secret",
            isolation="container",
        )
        assert code == 1
        # Aborted before building or deploying anything.
        mock_setup.assert_not_called()
        mock_deploy.assert_not_called()
        err = capsys.readouterr().err
        assert "ANTHROPIC_API_KEY" in err
        assert "--set-secret" in err

    @patch("agentcage.run.build_and_deploy")
    @patch("agentcage.run.run_scaffold_setup")
    @patch("agentcage.run.check_port_availability", return_value=[])
    @patch("agentcage.run.check_secrets", return_value=["ANTHROPIC_API_KEY"])
    @patch("agentcage.run.Podman")
    def test_set_secret_satisfies_missing_requirement(
        self, _podman, _check, _ports, mock_setup, mock_deploy,
        patch_state_dirs, tmp_path,
    ):
        # check_secrets reports the key absent from the store, but it was
        # supplied via --set-secret, so the run must get PAST the gate.
        mock_deploy.side_effect = RuntimeError("stop after gate")
        code = execute(
            "claude-code",
            project_dir=str(tmp_path),
            name="claude-test-setsecret",
            isolation="container",
            secrets=("ANTHROPIC_API_KEY=sk-test",),
        )
        # RuntimeError aborts the build, but reaching build_and_deploy proves
        # the secret gate let it through.
        assert code == 1
        mock_deploy.assert_called_once()


class TestExecuteForwardsBuildFlags:
    """--no-cache / --pull must reach both image-build paths (the scaffold
    agent image via run_scaffold_setup and the helper images via
    build_and_deploy), matching `agentcage cage create`."""

    @patch("agentcage.run.build_and_deploy")
    @patch("agentcage.run.run_scaffold_setup")
    @patch("agentcage.run.check_port_availability", return_value=[])
    @patch("agentcage.run.check_secrets", return_value=[])
    @patch("agentcage.run.Podman")
    def test_no_cache_and_pull_reach_build_paths(
        self, _podman, _check, _ports, mock_setup, mock_deploy,
        patch_state_dirs, tmp_path,
    ):
        mock_deploy.side_effect = RuntimeError("stop after build")
        code = execute(
            "claude-code",
            project_dir=str(tmp_path),
            name="claude-test-flags",
            isolation="container",
            no_cache=True,
            pull=True,
        )
        assert code == 1
        assert mock_setup.call_args.kwargs["no_cache"] is True
        assert mock_setup.call_args.kwargs["pull"] is True
        assert mock_deploy.call_args.kwargs["no_cache"] is True
        assert mock_deploy.call_args.kwargs["pull"] is True

    @patch("agentcage.run.build_and_deploy")
    @patch("agentcage.run.run_scaffold_setup")
    @patch("agentcage.run.check_port_availability", return_value=[])
    @patch("agentcage.run.check_secrets", return_value=[])
    @patch("agentcage.run.Podman")
    def test_flags_default_false(
        self, _podman, _check, _ports, mock_setup, mock_deploy,
        patch_state_dirs, tmp_path,
    ):
        mock_deploy.side_effect = RuntimeError("stop after build")
        execute(
            "claude-code",
            project_dir=str(tmp_path),
            name="claude-test-noflags",
            isolation="container",
        )
        assert mock_setup.call_args.kwargs["no_cache"] is False
        assert mock_deploy.call_args.kwargs["pull"] is False
