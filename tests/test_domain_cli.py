"""Tests for the 'agentcage domain' CLI subcommands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


SAMPLE_CONFIG = {
    "name": "basic",
    "container": {"image": "node:22-slim", "command": ["node", "/app/agent.js"]},
    "domains": {"allow": ["anthropic.com", "httpbin.org", "github.com"]},
}


class TestDomainList:
    @patch("agentcage.cli.state")
    def test_domain_list(self, mock_state):
        mock_state.load_raw_config.return_value = dict(SAMPLE_CONFIG)

        result = _runner().invoke(main, ["domain", "list", "basic"])
        assert result.exit_code == 0
        assert "Mode: allowlist" in result.output
        assert "anthropic.com" in result.output
        assert "httpbin.org" in result.output
        assert "github.com" in result.output

    @patch("agentcage.cli.state")
    def test_domain_list_empty(self, mock_state):
        mock_state.load_raw_config.return_value = {"name": "basic"}

        result = _runner().invoke(main, ["domain", "list", "basic"])
        assert result.exit_code == 0
        assert "Mode: allowlist" in result.output

    @patch("agentcage.cli.state")
    def test_domain_list_no_cage(self, mock_state):
        mock_state.load_raw_config.side_effect = FileNotFoundError("No stored config for cage 'nope'")

        result = _runner().invoke(main, ["domain", "list", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.state")
    def test_domain_list_with_passthrough(self, mock_state):
        raw = {
            "name": "basic",
            "domains": {"allow": ["anthropic.com", "whatsapp.com"], "passthrough": ["whatsapp.com"]},
        }
        mock_state.load_raw_config.return_value = raw

        result = _runner().invoke(main, ["domain", "list", "basic"])
        assert result.exit_code == 0
        assert "whatsapp.com [passthrough]" in result.output

    @patch("agentcage.cli.state")
    def test_domain_list_legacy_format(self, mock_state):
        raw = {
            "name": "basic",
            "domains": {"mode": "allowlist", "list": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw

        result = _runner().invoke(main, ["domain", "list", "basic"])
        assert result.exit_code == 0
        assert "Mode: allowlist" in result.output
        assert "httpbin.org" in result.output


class TestDomainAdd:
    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add(self, mock_state, mock_get_backend, mock_update_dns):
        raw = {
            "name": "basic",
            "domains": {"allow": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = True

        result = _runner().invoke(main, ["domain", "add", "basic", "github.com"])
        assert result.exit_code == 0
        assert "Added 'github.com' to cage 'basic'" in result.output
        assert "DNS and proxy updated." in result.output
        mock_state.save_raw_config.assert_called_once()
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "github.com" in saved["domains"]["allow"]
        mock_update_dns.assert_called_once_with(cfg)

    @patch("agentcage.cli.state")
    def test_domain_add_duplicate(self, mock_state):
        raw = {
            "name": "basic",
            "domains": {"allow": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw

        result = _runner().invoke(main, ["domain", "add", "basic", "httpbin.org"])
        assert result.exit_code == 0
        assert "already in" in result.output
        mock_state.save_raw_config.assert_not_called()

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add_creates_section(self, mock_state, mock_get_backend, mock_update_dns):
        raw = {"name": "basic"}
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = False

        result = _runner().invoke(main, ["domain", "add", "basic", "example.com"])
        assert result.exit_code == 0
        assert "Added 'example.com'" in result.output
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "example.com" in saved["domains"]["allow"]
        mock_update_dns.assert_called_once_with(cfg)

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add_with_passthrough(self, mock_state, mock_get_backend, mock_update_dns):
        raw = {
            "name": "basic",
            "domains": {"allow": ["anthropic.com"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = True

        result = _runner().invoke(main, ["domain", "add", "basic", "whatsapp.com", "--passthrough"])
        assert result.exit_code == 0
        assert "passthrough" in result.output
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "whatsapp.com" in saved["domains"]["allow"]
        assert "whatsapp.com" in saved["domains"]["passthrough"]

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add_multiple(self, mock_state, mock_get_backend, mock_update_dns):
        """Adding multiple domains in one call: save and reload happen exactly once."""
        raw = {
            "name": "basic",
            "domains": {"allow": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = True

        result = _runner().invoke(main, ["domain", "add", "basic", "github.com", "example.com"])
        assert result.exit_code == 0
        assert "Added 'github.com' to cage 'basic'" in result.output
        assert "Added 'example.com' to cage 'basic'" in result.output
        assert "DNS and proxy updated." in result.output

        mock_state.save_raw_config.assert_called_once()
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "github.com" in saved["domains"]["allow"]
        assert "example.com" in saved["domains"]["allow"]
        # Critical: only one reload for the batch.
        mock_update_dns.assert_called_once_with(cfg)

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add_multiple_mixed_with_duplicate(self, mock_state, mock_get_backend, mock_update_dns):
        """Batch with one new and one already-present domain: still saves and reloads once."""
        raw = {
            "name": "basic",
            "domains": {"allow": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = True

        result = _runner().invoke(main, ["domain", "add", "basic", "httpbin.org", "github.com"])
        assert result.exit_code == 0
        assert "'httpbin.org' is already in cage 'basic'" in result.output
        assert "Added 'github.com' to cage 'basic'" in result.output
        mock_state.save_raw_config.assert_called_once()
        mock_update_dns.assert_called_once_with(cfg)

    @patch("agentcage.cli.state")
    def test_domain_add_multiple_all_duplicates(self, mock_state):
        """Batch of all-duplicates: no save, no reload."""
        raw = {
            "name": "basic",
            "domains": {"allow": ["httpbin.org", "github.com"]},
        }
        mock_state.load_raw_config.return_value = raw

        result = _runner().invoke(main, ["domain", "add", "basic", "httpbin.org", "github.com"])
        assert result.exit_code == 0
        assert "'httpbin.org' is already in cage 'basic'" in result.output
        assert "'github.com' is already in cage 'basic'" in result.output
        mock_state.save_raw_config.assert_not_called()

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add_legacy_format_migrates(self, mock_state, mock_get_backend, mock_update_dns):
        """Adding to a legacy mode+list config migrates it to allow format."""
        raw = {
            "name": "basic",
            "domains": {"mode": "allowlist", "list": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = False

        result = _runner().invoke(main, ["domain", "add", "basic", "github.com"])
        assert result.exit_code == 0
        saved = mock_state.save_raw_config.call_args[0][1]
        # Should have been migrated to new format
        assert "allow" in saved["domains"]
        assert "github.com" in saved["domains"]["allow"]
        assert "httpbin.org" in saved["domains"]["allow"]


class TestDomainRm:
    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_rm(self, mock_state, mock_get_backend, mock_update_dns):
        raw = {
            "name": "basic",
            "domains": {"allow": ["httpbin.org", "github.com"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = True

        result = _runner().invoke(main, ["domain", "rm", "basic", "github.com"])
        assert result.exit_code == 0
        assert "Removed 'github.com' from cage 'basic'" in result.output
        assert "DNS and proxy updated." in result.output
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "github.com" not in saved["domains"]["allow"]
        assert "httpbin.org" in saved["domains"]["allow"]
        mock_update_dns.assert_called_once_with(cfg)

    @patch("agentcage.cli.state")
    def test_domain_rm_not_found(self, mock_state):
        raw = {
            "name": "basic",
            "domains": {"allow": ["httpbin.org"]},
        }
        mock_state.load_raw_config.return_value = raw

        result = _runner().invoke(main, ["domain", "rm", "basic", "nope.com"])
        assert result.exit_code != 0
        assert "not in" in result.output

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_rm_also_removes_passthrough(self, mock_state, mock_get_backend, mock_update_dns):
        raw = {
            "name": "basic",
            "domains": {"allow": ["anthropic.com", "whatsapp.com"], "passthrough": ["whatsapp.com"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = False

        result = _runner().invoke(main, ["domain", "rm", "basic", "whatsapp.com"])
        assert result.exit_code == 0
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "whatsapp.com" not in saved["domains"]["allow"]
        assert "whatsapp.com" not in saved["domains"]["passthrough"]

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_rm_passthrough_only(self, mock_state, mock_get_backend, mock_update_dns):
        raw = {
            "name": "basic",
            "domains": {"allow": ["whatsapp.com"], "passthrough": ["whatsapp.com"]},
        }
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = False

        result = _runner().invoke(main, ["domain", "rm", "basic", "whatsapp.com", "--passthrough"])
        assert result.exit_code == 0
        saved = mock_state.save_raw_config.call_args[0][1]
        # Should still be in allow, but removed from passthrough
        assert "whatsapp.com" in saved["domains"]["allow"]
        assert "whatsapp.com" not in saved["domains"]["passthrough"]
