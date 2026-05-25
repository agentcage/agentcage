"""Tests for custom scaffold management (create, list, show, edit, delete, export)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from agentcage.cli import main
from agentcage.init import (
    _SCAFFOLDS_DIR,
    _USER_SCAFFOLDS_DIR,
    is_builtin_scaffold,
    list_scaffolds,
    load_scaffold_meta,
    resolve_scaffold,
    run_scaffold_setup,
    scaffold_source,
)


def _runner():
    return CliRunner()


# ── resolve_scaffold tests ──────────────────────────────────────


class TestResolveScaffold:
    """Test the centralized resolve_scaffold() function."""

    def test_builtin_scaffold_resolved(self):
        result = resolve_scaffold("claude-code")
        assert result is not None
        assert result == _SCAFFOLDS_DIR / "claude-code"

    def test_nonexistent_returns_none(self):
        assert resolve_scaffold("nonexistent-xyz-999") is None

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_user_scaffold_overrides_builtin(self, _mock_proj, tmp_path):
        user_dir = tmp_path / "user-scaffolds"
        user_cc = user_dir / "claude-code"
        user_cc.mkdir(parents=True)
        (user_cc / "cage.yaml.j2").write_text("name: {{ name }}")

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir):
            result = resolve_scaffold("claude-code")
            assert result == user_cc

    @patch("agentcage.init._project_scaffolds_dir")
    def test_project_local_overrides_user_and_builtin(self, mock_proj, tmp_path):
        project_dir = tmp_path / "project-scaffolds"
        project_cc = project_dir / "claude-code"
        project_cc.mkdir(parents=True)
        (project_cc / "cage.yaml.j2").write_text("name: {{ name }}")
        mock_proj.return_value = project_dir

        result = resolve_scaffold("claude-code")
        assert result == project_cc

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_user_only_scaffold(self, _mock_proj, tmp_path):
        user_dir = tmp_path / "user-scaffolds"
        custom = user_dir / "my-custom"
        custom.mkdir(parents=True)
        (custom / "cage.yaml.j2").write_text("name: {{ name }}")

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir):
            result = resolve_scaffold("my-custom")
            assert result == custom


class TestIsBuiltinScaffold:

    def test_known_builtin(self):
        assert is_builtin_scaffold("claude-code") is True

    def test_nonexistent(self):
        assert is_builtin_scaffold("nonexistent-xyz") is False


class TestScaffoldSource:

    def test_builtin_source(self):
        assert scaffold_source("claude-code") == "built-in"

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_user_source(self, _mock_proj, tmp_path):
        user_dir = tmp_path / "user-scaffolds"
        custom = user_dir / "my-thing"
        custom.mkdir(parents=True)
        (custom / "cage.yaml.j2").write_text("name: {{ name }}")

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir):
            assert scaffold_source("my-thing") == "user"


# ── list_scaffolds with user scaffolds ──────────────────────────


class TestListScaffoldsExtended:

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_includes_user_scaffolds(self, _mock_proj, tmp_path):
        user_dir = tmp_path / "user-scaffolds"
        custom = user_dir / "zzz-custom"
        custom.mkdir(parents=True)
        (custom / "cage.yaml.j2").write_text("name: {{ name }}")

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir):
            names = list_scaffolds()
            assert "zzz-custom" in names
            # Still includes built-ins
            assert "claude-code" in names


# ── load_scaffold_meta with user scaffolds ──────────────────────


class TestLoadScaffoldMetaExtended:

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_loads_user_scaffold_meta(self, _mock_proj, tmp_path):
        user_dir = tmp_path / "user-scaffolds"
        custom = user_dir / "my-custom"
        custom.mkdir(parents=True)
        (custom / "cage.yaml.j2").write_text("name: {{ name }}")
        (custom / "scaffold.yaml").write_text(
            "description: My custom\nlifecycle: interactive\n"
        )

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir):
            meta = load_scaffold_meta("my-custom")
            assert meta is not None
            assert meta["description"] == "My custom"


# ── scaffold create CLI ─────────────────────────────────────────


class TestScaffoldCreate:

    def test_create_from_scratch(self, tmp_path):
        user_dir = tmp_path / "scaffolds"
        with patch("agentcage.scaffold_cli._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._project_scaffolds_dir", return_value=None):
            result = _runner().invoke(main, ["scaffold", "create", "my-agent"])
            assert result.exit_code == 0, result.output
            assert "Created scaffold" in result.output
            assert (user_dir / "my-agent" / "cage.yaml.j2").exists()
            assert (user_dir / "my-agent" / "Containerfile").exists()
            assert (user_dir / "my-agent" / "scaffold.yaml").exists()
            # Verify scaffold name is substituted
            content = (user_dir / "my-agent" / "scaffold.yaml").read_text()
            assert "my-agent" in content

    def test_create_from_existing(self, tmp_path):
        user_dir = tmp_path / "scaffolds"
        with patch("agentcage.scaffold_cli._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._project_scaffolds_dir", return_value=None):
            result = _runner().invoke(main, ["scaffold", "create", "my-cc", "--from", "claude-code"])
            assert result.exit_code == 0, result.output
            assert "from 'claude-code'" in result.output
            assert (user_dir / "my-cc" / "cage.yaml.j2").exists()
            assert (user_dir / "my-cc" / "Containerfile").exists()

    def test_create_from_nonexistent(self, tmp_path):
        user_dir = tmp_path / "scaffolds"
        with patch("agentcage.scaffold_cli._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._project_scaffolds_dir", return_value=None):
            result = _runner().invoke(main, ["scaffold", "create", "foo", "--from", "nonexistent-xyz"])
            assert result.exit_code != 0
            assert "not found" in result.output

    def test_create_already_exists(self, tmp_path):
        user_dir = tmp_path / "scaffolds"
        existing = user_dir / "my-agent"
        existing.mkdir(parents=True)
        (existing / "cage.yaml.j2").write_text("existing")
        with patch("agentcage.scaffold_cli._USER_SCAFFOLDS_DIR", user_dir):
            result = _runner().invoke(main, ["scaffold", "create", "my-agent"])
            assert result.exit_code != 0
            assert "already exists" in result.output

    def test_create_force_overwrites(self, tmp_path):
        user_dir = tmp_path / "scaffolds"
        existing = user_dir / "my-agent"
        existing.mkdir(parents=True)
        (existing / "cage.yaml.j2").write_text("ORIGINAL_MARKER_CONTENT")
        with patch("agentcage.scaffold_cli._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.init._project_scaffolds_dir", return_value=None):
            result = _runner().invoke(main, ["scaffold", "create", "my-agent", "--force"])
            assert result.exit_code == 0
            # Starter template should have replaced old content
            content = (user_dir / "my-agent" / "cage.yaml.j2").read_text()
            assert "ORIGINAL_MARKER_CONTENT" not in content

    def test_create_invalid_name(self):
        result = _runner().invoke(main, ["scaffold", "create", "INVALID_NAME"])
        assert result.exit_code != 0
        assert "must be" in result.output


# ── scaffold list CLI ───────────────────────────────────────────


class TestScaffoldListCLI:

    def test_list_shows_builtins(self):
        result = _runner().invoke(main, ["scaffold", "list"])
        assert result.exit_code == 0
        assert "claude-code" in result.output
        assert "built-in" in result.output

    def test_list_shows_headers(self):
        result = _runner().invoke(main, ["scaffold", "list"])
        assert "NAME" in result.output
        assert "SOURCE" in result.output
        assert "LIFECYCLE" in result.output
        assert "DESCRIPTION" in result.output

    def test_list_shows_description(self):
        result = _runner().invoke(main, ["scaffold", "list"])
        assert "Anthropic Claude Code CLI agent" in result.output

    def test_list_shows_lifecycle(self):
        result = _runner().invoke(main, ["scaffold", "list"])
        assert "interactive" in result.output
        assert "service" in result.output

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_list_includes_user_scaffolds(self, _mock_proj, tmp_path):
        user_dir = tmp_path / "scaffolds"
        custom = user_dir / "my-custom"
        custom.mkdir(parents=True)
        (custom / "cage.yaml.j2").write_text("name: {{ name }}")
        (custom / "scaffold.yaml").write_text("description: My stuff\nlifecycle: interactive\n")

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir):
            result = _runner().invoke(main, ["scaffold", "list"])
            assert "my-custom" in result.output
            assert "user" in result.output
            assert "My stuff" in result.output


# ── scaffold show CLI ───────────────────────────────────────────


class TestScaffoldShow:

    def test_show_builtin(self):
        result = _runner().invoke(main, ["scaffold", "show", "claude-code"])
        assert result.exit_code == 0
        assert "claude-code" in result.output
        assert "built-in" in result.output

    def test_show_nonexistent(self):
        result = _runner().invoke(main, ["scaffold", "show", "nonexistent-xyz"])
        assert result.exit_code != 0
        assert "not found" in result.output


# ── scaffold edit CLI ───────────────────────────────────────────


class TestScaffoldEdit:

    def test_edit_builtin_rejected(self):
        result = _runner().invoke(main, ["scaffold", "edit", "claude-code"])
        assert result.exit_code != 0
        assert "built-in" in result.output
        assert "Fork it first" in result.output

    def test_edit_nonexistent(self):
        result = _runner().invoke(main, ["scaffold", "edit", "nonexistent-xyz"])
        assert result.exit_code != 0
        assert "not found" in result.output


# ── scaffold delete CLI ─────────────────────────────────────────


class TestScaffoldDelete:

    def test_delete_builtin_rejected(self):
        result = _runner().invoke(main, ["scaffold", "delete", "claude-code", "-y"])
        assert result.exit_code != 0
        assert "built-in" in result.output

    def test_delete_nonexistent(self, tmp_path):
        user_dir = tmp_path / "scaffolds"
        user_dir.mkdir()
        with patch("agentcage.scaffold_cli._USER_SCAFFOLDS_DIR", user_dir):
            result = _runner().invoke(main, ["scaffold", "delete", "nonexistent", "-y"])
            assert result.exit_code != 0
            assert "no user scaffold" in result.output

    def test_delete_user_scaffold(self, tmp_path):
        user_dir = tmp_path / "scaffolds"
        target = user_dir / "my-agent"
        target.mkdir(parents=True)
        (target / "cage.yaml.j2").write_text("test")

        with patch("agentcage.scaffold_cli._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.scaffold_cli.is_builtin_scaffold", return_value=False):
            result = _runner().invoke(main, ["scaffold", "delete", "my-agent", "-y"])
            assert result.exit_code == 0
            assert "Deleted" in result.output
            assert not target.exists()


# ── scaffold export CLI ─────────────────────────────────────────


class TestScaffoldExport:

    def test_export_builtin(self, tmp_path):
        dest = tmp_path / "exported"
        result = _runner().invoke(main, ["scaffold", "export", "claude-code", str(dest)])
        assert result.exit_code == 0
        assert "Exported" in result.output
        assert (dest / "claude-code" / "cage.yaml.j2").exists()
        assert (dest / "claude-code" / "Containerfile").exists()

    def test_export_nonexistent(self, tmp_path):
        dest = tmp_path / "exported"
        result = _runner().invoke(main, ["scaffold", "export", "nonexistent-xyz", str(dest)])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_export_dest_exists(self, tmp_path):
        dest = tmp_path / "exported"
        (dest / "claude-code").mkdir(parents=True)
        result = _runner().invoke(main, ["scaffold", "export", "claude-code", str(dest)])
        assert result.exit_code != 0
        assert "already exists" in result.output


# ── scaffold metadata fields ────────────────────────────────────


class TestScaffoldMetadataFields:

    def test_all_builtins_have_description(self):
        for name in ["claude-code", "codex", "openclaw"]:
            meta = load_scaffold_meta(name)
            assert meta is not None, f"{name} has no scaffold.yaml"
            assert "description" in meta, f"{name} missing description"
            assert meta["description"], f"{name} has empty description"

    def test_all_builtins_have_lifecycle(self):
        for name in ["claude-code", "codex", "openclaw"]:
            meta = load_scaffold_meta(name)
            assert meta is not None
            assert "lifecycle" in meta, f"{name} missing lifecycle"
            assert meta["lifecycle"] in ("interactive", "service"), \
                f"{name} has invalid lifecycle: {meta['lifecycle']}"


# ── run_scaffold_setup isolation gating ─────────────────────────


class TestRunScaffoldSetupIsolation:
    """Verify host-podman build path is skipped on non-container isolation.

    On macOS users have ``vm`` or ``apple-container`` isolation and host
    podman is not installed; invoking it would crash with FileNotFoundError.
    Both backends build images themselves at cage create time.
    """

    def _make_scaffold(self, tmp_path: Path) -> Path:
        """Create a user scaffold with a build entry and a provision entry."""
        user_dir = tmp_path / "scaffolds"
        scaffold = user_dir / "test-iso"
        scaffold.mkdir(parents=True)
        (scaffold / "cage.yaml.j2").write_text("name: {{ name }}\n")
        (scaffold / "Containerfile").write_text("FROM scratch\n")
        provision_src = scaffold / "provision-file.txt"
        provision_src.write_text("hello\n")
        (scaffold / "scaffold.yaml").write_text(yaml.safe_dump({
            "description": "test",
            "lifecycle": "interactive",
            "build": [{
                "image": "localhost/agentcage-scaffold-test-iso:latest",
                "containerfile": "Containerfile",
            }],
            "provision": [{
                "src": "provision-file.txt",
                "dest": str(tmp_path / "out" / "provision-file.txt"),
            }],
        }))
        return user_dir

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_apple_container_isolation_skips_podman(self, _mock_proj, tmp_path):
        user_dir = self._make_scaffold(tmp_path)

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.podman.Podman") as mock_podman_cls:
            # Any podman instantiation would raise — but we shouldn't get here
            mock_podman_cls.side_effect = FileNotFoundError(
                "[Errno 2] No such file or directory: 'podman'"
            )
            # Must not raise
            run_scaffold_setup(
                "test-iso", "cage1", str(tmp_path / "cage.yaml"),
                isolation="apple-container",
            )
            assert mock_podman_cls.call_count == 0
            # Provision still ran
            assert (tmp_path / "out" / "provision-file.txt").is_file()

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_vm_isolation_skips_podman(self, _mock_proj, tmp_path):
        user_dir = self._make_scaffold(tmp_path)

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.podman.Podman") as mock_podman_cls:
            mock_podman_cls.side_effect = FileNotFoundError(
                "[Errno 2] No such file or directory: 'podman'"
            )
            run_scaffold_setup(
                "test-iso", "cage1", str(tmp_path / "cage.yaml"),
                isolation="vm",
            )
            assert mock_podman_cls.call_count == 0
            assert (tmp_path / "out" / "provision-file.txt").is_file()

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_container_isolation_invokes_podman(self, _mock_proj, tmp_path):
        user_dir = self._make_scaffold(tmp_path)

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.podman.Podman") as mock_podman_cls:
            mock_podman = MagicMock()
            mock_podman.image_exists.return_value = False
            mock_podman_cls.return_value = mock_podman

            run_scaffold_setup(
                "test-iso", "cage1", str(tmp_path / "cage.yaml"),
                isolation="container",
            )
            mock_podman_cls.assert_called_once()
            mock_podman.image_exists.assert_called_once_with(
                "localhost/agentcage-scaffold-test-iso:latest"
            )
            mock_podman.build_image.assert_called_once()
            assert (tmp_path / "out" / "provision-file.txt").is_file()

    @patch("agentcage.init._project_scaffolds_dir", return_value=None)
    def test_isolation_none_preserves_legacy_behavior(self, _mock_proj, tmp_path):
        """Callers that don't pass isolation still hit the build loop."""
        user_dir = self._make_scaffold(tmp_path)

        with patch("agentcage.init._USER_SCAFFOLDS_DIR", user_dir), \
             patch("agentcage.podman.Podman") as mock_podman_cls:
            mock_podman = MagicMock()
            mock_podman.image_exists.return_value = True  # short-circuit build
            mock_podman_cls.return_value = mock_podman

            run_scaffold_setup(
                "test-iso", "cage1", str(tmp_path / "cage.yaml"),
            )
            mock_podman_cls.assert_called_once()
            mock_podman.image_exists.assert_called_once()
