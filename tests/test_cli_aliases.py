"""Tests for CLI command aliases and completions."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


class TestCageAliases:
    """cage ls/ps/status → list, cage rm → destroy."""

    @patch("agentcage.cli.state")
    def test_ls_resolves_to_list(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "ls"])
        assert result.exit_code == 0

    @patch("agentcage.cli.state")
    def test_ps_resolves_to_list(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "ps"])
        assert result.exit_code == 0

    @patch("agentcage.cli.state")
    def test_status_resolves_to_list(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "status"])
        assert result.exit_code == 0

    def test_rm_resolves_to_destroy(self):
        result = _runner().invoke(main, ["cage", "rm", "--help"])
        assert result.exit_code == 0
        assert "destroy" in result.output.lower() or "Stop" in result.output or "NAME" in result.output

    def test_unknown_subcommand_fails(self):
        result = _runner().invoke(main, ["cage", "nonexistent"])
        assert result.exit_code != 0

    def test_help_shows_aliases(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert result.exit_code == 0
        assert "Aliases:" in result.output
        assert "ls" in result.output
        assert "rm" in result.output


class TestSecretAliases:
    """secret ls → list."""

    def test_ls_resolves_to_list(self):
        result = _runner().invoke(main, ["secret", "ls", "--help"])
        assert result.exit_code == 0

    def test_help_shows_aliases(self):
        result = _runner().invoke(main, ["secret", "--help"])
        assert result.exit_code == 0
        assert "Aliases:" in result.output
        assert "ls" in result.output


class TestDomainAliases:
    """domain ls → list."""

    def test_ls_resolves_to_list(self):
        result = _runner().invoke(main, ["domain", "ls", "--help"])
        assert result.exit_code == 0

    def test_help_shows_aliases(self):
        result = _runner().invoke(main, ["domain", "--help"])
        assert result.exit_code == 0
        assert "Aliases:" in result.output
        assert "ls" in result.output


class TestCompletions:
    """completions command prints eval snippet."""

    def test_bash(self):
        result = _runner().invoke(main, ["completions", "bash"])
        assert result.exit_code == 0
        assert "_AGENTCAGE_COMPLETE=bash_source" in result.output

    def test_zsh(self):
        result = _runner().invoke(main, ["completions", "zsh"])
        assert result.exit_code == 0
        assert "_AGENTCAGE_COMPLETE=zsh_source" in result.output

    def test_fish(self):
        result = _runner().invoke(main, ["completions", "fish"])
        assert result.exit_code == 0
        assert "_AGENTCAGE_COMPLETE=fish_source" in result.output

    def test_invalid_shell(self):
        result = _runner().invoke(main, ["completions", "powershell"])
        assert result.exit_code != 0
