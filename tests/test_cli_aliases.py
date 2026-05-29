"""Tests for CLI command aliases."""

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
    def test_status_without_name_lists(self, mock_state):
        # `systemctl status`-style: no NAME → list every cage.
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "status"])
        assert result.exit_code == 0

    @patch("agentcage.cli.state")
    def test_status_with_name_routes_to_show(self, mock_state):
        # `systemctl status <unit>`-style: a NAME → single-cage detail (show),
        # NOT the list. `show` checks existence and says "does not exist";
        # `list` would print "No cages found." with exit 0.
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "status", "ghost"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_rm_resolves_to_destroy(self):
        result = _runner().invoke(main, ["cage", "rm", "--help"])
        assert result.exit_code == 0
        assert "destroy" in result.output.lower() or "Stop" in result.output or "NAME" in result.output

    def test_delete_resolves_to_destroy(self):
        result = _runner().invoke(main, ["cage", "delete", "--help"])
        assert result.exit_code == 0
        assert "destroy" in result.output.lower() or "Stop" in result.output or "NAME" in result.output

    def test_describe_resolves_to_show(self):
        result = _runner().invoke(main, ["cage", "describe", "--help"])
        assert result.exit_code == 0
        assert "Show" in result.output or "NAME" in result.output

    def test_inspect_resolves_to_show(self):
        result = _runner().invoke(main, ["cage", "inspect", "--help"])
        assert result.exit_code == 0
        assert "Show" in result.output or "NAME" in result.output

    def test_reload_resolves_to_restart(self):
        result = _runner().invoke(main, ["cage", "reload", "--help"])
        assert result.exit_code == 0
        assert "Restart" in result.output or "NAME" in result.output

    def test_unknown_subcommand_fails(self):
        result = _runner().invoke(main, ["cage", "nonexistent"])
        assert result.exit_code != 0

    def test_help_shows_aliases(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert result.exit_code == 0
        assert "Aliases:" in result.output
        assert "ls" in result.output
        assert "rm" in result.output
        assert "delete" in result.output
        assert "describe" in result.output
        assert "inspect" in result.output


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


class TestTopLevelAliases:
    """Top-level aliases that drop the `cage` group prefix (PR #240):
    `agentcage ls`/`logs`/`update`/... resolve to their `cage <cmd>`
    equivalents via _BannerGroup.get_command."""

    @patch("agentcage.cli.state")
    def test_top_level_ls_resolves_to_cage_list(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["ls"])
        assert result.exit_code == 0
        assert "No cages found" in result.output or "NAME" in result.output

    @patch("agentcage.cli.state")
    def test_top_level_ps_and_status_resolve_to_cage_list(self, mock_state):
        mock_state.list_deployments.return_value = []
        for alias in ("ps", "status"):
            result = _runner().invoke(main, [alias])
            assert result.exit_code == 0, f"alias {alias!r} failed"

    def test_top_level_update_resolves_to_cage_update(self):
        # `update` was the missing mapping #240 added; --help proves routing
        # without needing a real cage.
        result = _runner().invoke(main, ["update", "--help"])
        assert result.exit_code == 0
        assert "Rebuild and restart an existing cage" in result.output

    def test_top_level_aliases_route_to_right_command(self):
        # Each alias's --help should match the target cage command's help.
        cases = {
            "rm": "destroy",
            "show": "show",
            "logs": "logs",
            "exec": "exec",
            "restart": "restart",
        }
        for alias, target in cases.items():
            aliased = _runner().invoke(main, [alias, "--help"])
            direct = _runner().invoke(main, ["cage", target, "--help"])
            assert aliased.exit_code == 0, f"alias {alias!r} failed"
            # Usage line differs (prog name) but the body/options should match.
            assert direct.output.split("\n", 1)[1] == aliased.output.split("\n", 1)[1], (
                f"alias {alias!r} routed to wrong command"
            )

    def test_help_lists_top_level_aliases(self):
        result = _runner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Aliases:" in result.output
        assert "ls → cage list" in result.output

    def test_unknown_top_level_command_still_errors(self):
        # The alias override must not swallow genuinely unknown commands.
        result = _runner().invoke(main, ["definitely-not-a-command"])
        assert result.exit_code != 0
