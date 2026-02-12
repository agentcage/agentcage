"""Tests for the 'lobstercage domain' CLI subcommands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from lobstercage.cli import main


def _runner():
    return CliRunner()


SAMPLE_CONFIG = {
    "name": "basic",
    "container": {"image": "node:22-slim", "command": ["node", "/app/agent.js"]},
    "domains": {"mode": "allowlist", "list": ["anthropic.com", "httpbin.org", "github.com"]},
}


class TestDomainList:
    @patch("lobstercage.cli.state")
    def test_domain_list(self, mock_state):
        mock_state.load_raw_config.return_value = dict(SAMPLE_CONFIG)

        result = _runner().invoke(main, ["domain", "list", "basic"])
        assert result.exit_code == 0
        assert "Mode: allowlist" in result.output
        assert "anthropic.com" in result.output
        assert "httpbin.org" in result.output
        assert "github.com" in result.output

    @patch("lobstercage.cli.state")
    def test_domain_list_empty(self, mock_state):
        mock_state.load_raw_config.return_value = {"name": "basic"}

        result = _runner().invoke(main, ["domain", "list", "basic"])
        assert result.exit_code == 0
        assert "Mode: allowlist" in result.output

    @patch("lobstercage.cli.state")
    def test_domain_list_no_cage(self, mock_state):
        mock_state.load_raw_config.side_effect = FileNotFoundError("No stored config for cage 'nope'")

        result = _runner().invoke(main, ["domain", "list", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output


class TestDomainAdd:
    @patch("lobstercage.cli.Podman")
    @patch("lobstercage.cli.state")
    def test_domain_add(self, mock_state, MockPodman):
        raw = {
            "name": "basic",
            "domains": {"mode": "allowlist", "list": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        podman = MockPodman.return_value
        podman.container_running.return_value = True

        result = _runner().invoke(main, ["domain", "add", "basic", "github.com"])
        assert result.exit_code == 0
        assert "Added 'github.com' to cage 'basic'" in result.output
        assert "Cage reloaded." in result.output
        mock_state.save_raw_config.assert_called_once()
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "github.com" in saved["domains"]["list"]

    @patch("lobstercage.cli.state")
    def test_domain_add_duplicate(self, mock_state):
        raw = {
            "name": "basic",
            "domains": {"mode": "allowlist", "list": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw

        result = _runner().invoke(main, ["domain", "add", "basic", "httpbin.org"])
        assert result.exit_code == 0
        assert "already in" in result.output
        mock_state.save_raw_config.assert_not_called()

    @patch("lobstercage.cli.Podman")
    @patch("lobstercage.cli.state")
    def test_domain_add_creates_section(self, mock_state, MockPodman):
        raw = {"name": "basic"}
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        podman = MockPodman.return_value
        podman.container_running.return_value = False

        result = _runner().invoke(main, ["domain", "add", "basic", "example.com"])
        assert result.exit_code == 0
        assert "Added 'example.com'" in result.output
        saved = mock_state.save_raw_config.call_args[0][1]
        assert saved["domains"]["mode"] == "allowlist"
        assert "example.com" in saved["domains"]["list"]


class TestDomainRm:
    @patch("lobstercage.cli.Podman")
    @patch("lobstercage.cli.state")
    def test_domain_rm(self, mock_state, MockPodman):
        raw = {
            "name": "basic",
            "domains": {"mode": "allowlist", "list": ["httpbin.org", "github.com"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        podman = MockPodman.return_value
        podman.container_running.return_value = True

        result = _runner().invoke(main, ["domain", "rm", "basic", "github.com"])
        assert result.exit_code == 0
        assert "Removed 'github.com' from cage 'basic'" in result.output
        assert "Cage reloaded." in result.output
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "github.com" not in saved["domains"]["list"]
        assert "httpbin.org" in saved["domains"]["list"]

    @patch("lobstercage.cli.state")
    def test_domain_rm_not_found(self, mock_state):
        raw = {
            "name": "basic",
            "domains": {"mode": "allowlist", "list": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw

        result = _runner().invoke(main, ["domain", "rm", "basic", "nope.com"])
        assert result.exit_code != 0
        assert "not in" in result.output
