"""Tests for the 'agentcage secret' CLI subcommands."""

from __future__ import annotations

import platform
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agentcage.cli import main
from tests.markers import REQUIRES_PODMAN

# These drive `secret set/rm` through the host's default secret backend
# (systemd-creds / podman secrets on Linux). On macOS the default backend is
# the Keychain and the Linux tooling is absent, so gate them to the Linux CI;
# macOS backend resolution is covered by tests/test_secret_store.py.
LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="host default secret backend is Linux-specific here; runs on Linux CI",
)


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
    @LINUX_ONLY
    @REQUIRES_PODMAN
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

    @LINUX_ONLY
    @REQUIRES_PODMAN
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


class TestSecretFailClosed:
    """Without systemd-creds, agentcage must refuse cleartext storage unless
    the operator opted in via secrets.allow_plaintext."""

    def _cfg(self, allow_plaintext):
        cfg = MagicMock()
        cfg.isolation = "container"
        cfg.name = "myapp"
        cfg.secret_injection = []
        cfg.container.podman_secrets = []
        cfg.secrets.scope = "auto"
        cfg.secrets.allow_plaintext = allow_plaintext
        return cfg

    @patch("agentcage.secret_resolver.detect_default_backend", return_value="podman")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_set_fails_closed_without_systemd_creds(
        self, mock_state, MockPodman, _backend,
    ):
        podman = MockPodman.return_value
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = self._cfg(False)
        result = _runner().invoke(
            main, ["secret", "set", "myapp", "API_KEY"], input="s3cret\n",
        )
        assert result.exit_code != 0
        assert "refusing to store" in result.output
        podman.secret_create.assert_not_called()

    @LINUX_ONLY
    @REQUIRES_PODMAN
    @patch("agentcage.secret_resolver.detect_default_backend", return_value="podman")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_set_allows_plaintext_when_opted_in(
        self, mock_state, MockPodman, _backend,
    ):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = self._cfg(True)
        result = _runner().invoke(
            main, ["secret", "set", "myapp", "API_KEY"], input="s3cret\n",
        )
        assert result.exit_code == 0
        podman.secret_create.assert_called_once_with("myapp.API_KEY", "s3cret")
        assert "UNENCRYPTED" in result.output


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
    def test_list_shows_orphan_stored_but_undeclared(self, mock_state, MockPodman):
        # A secret set for a key with no injection rule / podman_secret is
        # still stored at rest; it must be surfaced (type 'orphan') rather
        # than silently hidden by the expected-only filter.
        podman = MockPodman.return_value
        podman.secret_list.return_value = [
            {"Name": "myapp.API_KEY"},
            {"Name": "myapp.STRAY"},
        ]
        mock_state.deployment_exists.return_value = True
        cfg = _mock_container_config()
        cfg.secret_injection = [MagicMock(env="API_KEY")]
        cfg.container.podman_secrets = []
        mock_state.load_deployment_config.return_value = cfg

        result = _runner().invoke(main, ["secret", "list", "myapp"])
        assert result.exit_code == 0
        assert "API_KEY" in result.output
        assert "injection" in result.output
        assert "STRAY" in result.output
        assert "orphan" in result.output

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
    @LINUX_ONLY
    @REQUIRES_PODMAN
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_rm_removes_secret(self, mock_state, MockPodman, tmp_path):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        podman.container_running.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()
        # Real path: secret_rm probes deployment_dir()/creds/<KEY>.cred on
        # the filesystem — a MagicMock path would read as an existing blob.
        mock_state.deployment_dir.return_value = tmp_path

        result = _runner().invoke(main, ["secret", "rm", "myapp", "API_KEY"])
        assert result.exit_code == 0
        podman.secret_remove.assert_called_once_with("myapp.API_KEY")

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_rm_nonexistent_fails(self, mock_state, MockPodman, tmp_path):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()
        mock_state.deployment_dir.return_value = tmp_path

        result = _runner().invoke(main, ["secret", "rm", "myapp", "API_KEY"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_rm_requires_existing_cage(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = False
            result = _runner().invoke(main, ["secret", "rm", "myapp", "API_KEY"])
            assert result.exit_code != 0
            assert "does not exist" in result.output


class TestSecretRmAtRest:
    """`secret rm` has to remove the value *at rest*, not just the two
    places the container backend keeps it.

    The keychain delete used to be gated on ``_is_apple_container``, but
    a **vm** cage on a Mac resolves to the keychain too — so `secret rm`
    removed the guest podman copy and the ``.cred``, reported
    ``Secret 'rsvm.API_KEY' removed.``, and left the value. Measured on
    real hardware: the next `cage restart` brought it straight back.
    """

    @staticmethod
    def _vm_config():
        cfg = MagicMock()
        cfg.isolation = "vm"
        cfg.name = "rsvm"
        cfg.secret_injection = []
        cfg.container.podman_secrets = []
        return cfg

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_rm_deletes_from_the_at_rest_store(
        self, mock_state, MockPodman, tmp_path,
    ):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = self._vm_config()
        mock_state.deployment_dir.return_value = tmp_path

        store = MagicMock()
        store.name = "keychain"
        store.runtime_decrypts = False
        store.names.return_value = ["API_KEY"]
        with patch("agentcage.secret_store.resolve_store", return_value=store), \
             patch("agentcage.cli._apply_secret_live_or_restart"):
            result = _runner().invoke(main, ["secret", "rm", "rsvm", "API_KEY"])

        assert result.exit_code == 0, result.output
        store.delete.assert_called_once_with(
            "rsvm", "API_KEY", state_dir=tmp_path,
        )

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_rm_finds_a_secret_that_exists_only_at_rest(
        self, mock_state, MockPodman, tmp_path,
    ):
        """A vm cage that has never been started has no runtime copy at
        all. `secret rm` used to call that "does not exist" while the
        keychain held the value — so there was no way to remove it."""
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = self._vm_config()
        mock_state.deployment_dir.return_value = tmp_path

        store = MagicMock()
        store.name = "keychain"
        store.runtime_decrypts = False
        store.names.return_value = ["API_KEY"]
        with patch("agentcage.secret_store.resolve_store", return_value=store), \
             patch("agentcage.cli._apply_secret_live_or_restart"):
            result = _runner().invoke(main, ["secret", "rm", "rsvm", "API_KEY"])

        assert result.exit_code == 0, result.output
        assert "removed" in result.output
        store.delete.assert_called_once()

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_rm_still_refuses_a_key_that_is_nowhere(
        self, mock_state, MockPodman, tmp_path,
    ):
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = self._vm_config()
        mock_state.deployment_dir.return_value = tmp_path

        store = MagicMock()
        store.runtime_decrypts = False
        store.names.return_value = ["OTHER_KEY"]
        with patch("agentcage.secret_store.resolve_store", return_value=store):
            result = _runner().invoke(main, ["secret", "rm", "rsvm", "API_KEY"])

        assert result.exit_code != 0
        assert "does not exist" in result.output
        store.delete.assert_not_called()

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_a_store_that_will_not_delete_warns_rather_than_failing(
        self, mock_state, MockPodman, tmp_path,
    ):
        """The runtime copies are already gone by then, so the secret has
        stopped being injected either way. The operator still has to be
        told, because the next start would otherwise restore it."""
        from agentcage.secret_store import SecretStoreError

        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = self._vm_config()
        mock_state.deployment_dir.return_value = tmp_path

        store = MagicMock()
        store.name = "keychain"
        store.runtime_decrypts = False
        store.names.return_value = ["API_KEY"]
        store.delete.side_effect = SecretStoreError("keychain is locked")
        with patch("agentcage.secret_store.resolve_store", return_value=store), \
             patch("agentcage.cli._apply_secret_live_or_restart"):
            result = _runner().invoke(main, ["secret", "rm", "rsvm", "API_KEY"])

        assert result.exit_code == 0, result.output
        assert "could not remove" in result.output
        assert "keychain is locked" in result.output

    @LINUX_ONLY
    @REQUIRES_PODMAN
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_a_container_cage_resolves_no_extra_store(
        self, mock_state, MockPodman, tmp_path,
    ):
        """The container backend's runtime copy *is* the value, so there
        is nothing extra to delete — and nothing extra to resolve, which
        matters because resolving a keychain store runs a write probe."""
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_container_config()
        mock_state.deployment_dir.return_value = tmp_path

        store = MagicMock()
        store.runtime_decrypts = True
        with patch("agentcage.secret_store.resolve_store", return_value=store), \
             patch("agentcage.cli._apply_secret_live_or_restart"):
            result = _runner().invoke(main, ["secret", "rm", "myapp", "API_KEY"])

        assert result.exit_code == 0, result.output
        store.delete.assert_not_called()
        store.names.assert_not_called()
