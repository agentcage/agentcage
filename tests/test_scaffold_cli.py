"""Tests for scaffold-related CLI commands and cage list/destroy integration."""

from __future__ import annotations

import textwrap
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


class TestInitListScaffolds:
    """Test 'agentcage init --list-scaffolds'."""

    def test_list_scaffolds_shows_available(self):
        result = _runner().invoke(main, ["init", "--list-scaffolds"])
        assert result.exit_code == 0
        assert "openclaw" in result.output
        assert "nanoclaw" in result.output
        assert "picoclaw" in result.output

    def test_list_scaffolds_header(self):
        result = _runner().invoke(main, ["init", "--list-scaffolds"])
        assert "Available scaffolds" in result.output


class TestInitWithScaffold:
    """Test 'agentcage init <name> --scaffold <scaffold>'."""

    def test_invalid_scaffold_rejected(self):
        result = _runner().invoke(main, ["init", "test", "--scaffold", "nonexistent"])
        assert result.exit_code != 0
        assert "unknown scaffold" in result.output

    @patch("agentcage.registry.resolve_latest_tag", return_value="2026.2.24")
    def test_openclaw_scaffold_creates_file(self, mock_resolve, tmp_path):
        dest = tmp_path / "cage.yaml"
        result = _runner().invoke(main, [
            "init", "my-oc", "--scaffold", "openclaw", "-o", str(dest),
        ])
        assert result.exit_code == 0
        assert dest.exists()
        content = dest.read_text()
        assert "my-oc" in content

    def test_nanoclaw_scaffold_creates_file(self, tmp_path):
        dest = tmp_path / "cage.yaml"
        result = _runner().invoke(main, [
            "init", "my-nano", "--scaffold", "nanoclaw", "-o", str(dest),
        ])
        assert result.exit_code == 0
        assert dest.exists()
        content = dest.read_text()
        assert "my-nano" in content

    def test_init_invalid_name_rejected(self):
        result = _runner().invoke(main, ["init", "INVALID_NAME"])
        assert result.exit_code != 0
        assert "must be" in result.output

    def test_init_requires_name(self):
        result = _runner().invoke(main, ["init"])
        assert result.exit_code != 0


class TestCageListColumns:
    """Test that cage list shows the expected columns."""

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_name_column(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        cfg = MagicMock()
        cfg.isolation = "container"
        cfg.lifecycle = "service"
        cfg.scaffold = ""
        cfg.container.nested_containers = False
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "NAME" in result.output
        assert "myapp" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_isolation_column(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        cfg = MagicMock()
        cfg.isolation = "container"
        cfg.lifecycle = "service"
        cfg.scaffold = ""
        cfg.container.nested_containers = False
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert "ISOLATION" in result.output
        assert "container" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_lifecycle_column(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        cfg = MagicMock()
        cfg.isolation = "container"
        cfg.lifecycle = "interactive"
        cfg.scaffold = "claude-code"
        cfg.container.nested_containers = False
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {"lifecycle": "interactive", "scaffold": "claude-code"}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "list"])
        assert "LIFECYCLE" in result.output
        assert "interactive" in result.output
        assert "claude-code" in result.output
        assert "exited" in result.output

    @patch("agentcage.cli.state")
    def test_list_empty(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "No" in result.output


class TestCageDestroyCommand:
    """Test cage destroy CLI command."""

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_aborts_without_confirmation(self, mock_destroy):
        result = _runner().invoke(main, ["cage", "destroy", "test"], input="n\n")
        assert result.exit_code != 0
        mock_destroy.assert_not_called()

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_with_yes_flag(self, mock_destroy):
        mock_destroy.return_value = ["state:test"]
        result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_nothing_to_remove(self, mock_destroy):
        mock_destroy.return_value = []
        result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0
        assert "Nothing to remove" in result.output


class TestRunCommand:
    """Test agentcage run CLI command basics."""

    def test_run_help(self):
        result = _runner().invoke(main, ["run", "--help"])
        assert result.exit_code == 0
        assert "scaffold" in result.output.lower() or "SCAFFOLD" in result.output


class TestCageHelp:
    """Verify cage help includes expected subcommands."""

    def test_cage_help_shows_list(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "list" in result.output

    def test_cage_help_shows_destroy(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "destroy" in result.output

    def test_cage_help_shows_create(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "create" in result.output

    def test_cage_help_shows_verify(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "verify" in result.output
