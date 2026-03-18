"""Tests for the 'agentcage secret' CLI subcommands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


def _mock_container_config():
    cfg = MagicMock()
    cfg.isolation = "container"
    cfg.name = "myapp"
    cfg.secret_injection = []
    cfg.container.podman_secrets = []
    return cfg


class TestSecretSet:
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_set_creates_secret(self, mock_state, MockPodman):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()

        result = _runner().invoke(main, ["secret", "set", "myapp", "API_KEY"], input="s3cret\n")
        assert result.exit_code == 0
        podman.secret_create.assert_called_once_with("myapp.API_KEY", "s3cret")
        assert "myapp.API_KEY" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_set_replaces_existing(self, mock_state, MockPodman):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()

        result = _runner().invoke(main, ["secret", "set", "myapp", "API_KEY"], input="newval\n")
        assert result.exit_code == 0
        podman.secret_remove.assert_called_once_with("myapp.API_KEY")
        podman.secret_create.assert_called_once_with("myapp.API_KEY", "newval")

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_set_reloads_running_deployment(self, mock_state, MockPodman, mock_get_backend):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False
        mock_state.deployment_exists.return_value = True
        cfg = _mock_container_config()
        mock_state.load_deployment_config.return_value = cfg
        backend = mock_get_backend.return_value
        backend.is_running.return_value = True

        result = _runner().invoke(main, ["secret", "set", "myapp", "API_KEY"], input="val\n")
        assert result.exit_code == 0
        assert "Restarting" in result.output

    def test_set_requires_existing_cage(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = False
            result = _runner().invoke(main, ["secret", "set", "myapp", "API_KEY"], input="val\n")
            assert result.exit_code != 0
            assert "does not exist" in result.output


class TestSecretList:
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_list_with_secrets(self, mock_state, MockPodman):
        podman = MockPodman.return_value
        podman.secret_list.return_value = [
            {"Name": "myapp.API_KEY"},
            {"Name": "myapp.OTHER"},
        ]
        cfg = _mock_container_config()
        cfg.secret_injection = [MagicMock(env="API_KEY")]
        cfg.container.podman_secrets = ["OTHER"]
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = cfg

        result = _runner().invoke(main, ["secret", "list", "myapp"])
        assert result.exit_code == 0
        assert "API_KEY" in result.output
        assert "OTHER" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_list_with_state_shows_status(self, mock_state, MockPodman):
        podman = MockPodman.return_value
        podman.secret_list.return_value = [{"Name": "myapp.API_KEY"}]
        mock_state.deployment_exists.return_value = True
        cfg = _mock_container_config()
        cfg.secret_injection = [MagicMock(env="API_KEY")]
        cfg.container.podman_secrets = ["TOKEN"]
        mock_state.load_deployment_config.return_value = cfg

        result = _runner().invoke(main, ["secret", "list", "myapp"])
        assert result.exit_code != 0  # TOKEN is missing
        assert "API_KEY" in result.output
        assert "ok" in result.output
        assert "MISSING" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_list_empty(self, mock_state, MockPodman):
        podman = MockPodman.return_value
        podman.secret_list.return_value = []
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()

        result = _runner().invoke(main, ["secret", "list", "myapp"])
        assert result.exit_code == 0
        # With no expected secrets and no actual secrets, just shows header
        assert "NAME" in result.output

    def test_list_requires_existing_cage(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = False
            result = _runner().invoke(main, ["secret", "list", "myapp"])
            assert result.exit_code != 0
            assert "does not exist" in result.output


class TestSecretRm:
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_rm_removes_secret(self, mock_state, MockPodman):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        podman.container_running.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()

        result = _runner().invoke(main, ["secret", "rm", "myapp", "API_KEY"])
        assert result.exit_code == 0
        podman.secret_remove.assert_called_once_with("myapp.API_KEY")

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_rm_nonexistent_fails(self, mock_state, MockPodman):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()

        result = _runner().invoke(main, ["secret", "rm", "myapp", "API_KEY"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_rm_requires_existing_cage(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = False
            result = _runner().invoke(main, ["secret", "rm", "myapp", "API_KEY"])
            assert result.exit_code != 0
            assert "does not exist" in result.output
