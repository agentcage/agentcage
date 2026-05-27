"""Tests for the v0.21 legacy-cage detector at the CLI entry point.

v0.22 collapsed the per-cage container shape from 3 services (cage /
proxy / dns) to 2 (cage / egress). cages created with v0.21 cannot be
addressed by v0.22 commands — their containers have the wrong names,
their quadlets reference the deleted templates, and the resolver IPs
are off-by-one (the old ip_dns slot is now ip_egress). Rather than fail
with confusing podman/systemctl errors deep in the stack, v0.22 detects
the legacy shape from each cage's persisted metadata and exits early
with a clear migration procedure.

Two commands are *exempt* from the detector:

  * ``cage destroy`` — destroy is the documented escape hatch (it has
    to work on a stuck v0.21 cage to let the operator clean up).
  * ``cage list`` — annotates legacy entries inline instead of running
    ``is_running`` against the new shape (which would mislabel a
    still-running v0.21 cage as stopped).

This test file pins both halves of that contract.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import click
from click.testing import CliRunner

from agentcage.cli import main


def _runner() -> CliRunner:
    return CliRunner()


def _mock_legacy_metadata(version: str = "0.21.5") -> dict:
    """A metadata payload that the v0.22 detector treats as legacy."""
    return {"agentcage_version": version}


# ---------------------------------------------------------------------------
# Guarded commands — these MUST exit with code 2 and the migration message
# ---------------------------------------------------------------------------

GUARDED_COMMANDS = [
    pytest_param := ["cage", "restart", "test"],
    ["cage", "stop", "test"],
    ["cage", "start", "test"],
    ["cage", "show", "test"],
    ["cage", "logs", "test"],
    ["cage", "verify", "test"],
    ["cage", "backup", "test"],
    ["cage", "exec", "test", "--", "ls"],
    ["cage", "shell", "test"],
    ["cage", "audit", "test"],
    ["cage", "har", "test"],
    ["cage", "update", "test"],
    ["cage", "edit", "test"],
    ["domain", "list", "test"],
    ["domain", "add", "test", "example.com"],
    ["domain", "rm", "test", "example.com"],
    ["secret", "list", "test"],
    ["secret", "rm", "test", "KEY"],
]


def _make_mock_config(isolation="container"):
    """Minimal mock so the various command handlers can read .isolation
    etc — we only care that the version check fires BEFORE any of this
    matters, so a MagicMock is enough."""
    cfg = MagicMock()
    cfg.isolation = isolation
    cfg.name = "test"
    cfg.lifecycle = "service"
    cfg.scaffold = ""
    cfg.exec_aliases = {}
    return cfg


class TestLegacyCageDetector:
    """v0.21 cages exit with code 2 and a migration message on every
    guarded command."""

    def test_restart_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 2
        assert "v0.21.5" in result.output
        assert "destroy" in result.output

    def test_stop_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "stop", "test"])
        assert result.exit_code == 2

    def test_start_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "start", "test"])
        assert result.exit_code == 2

    def test_show_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "show", "test"])
        assert result.exit_code == 2

    def test_logs_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "logs", "test"])
        assert result.exit_code == 2

    def test_verify_blocked(self):
        with patch("agentcage.cli.state") as mock_state, \
             patch("agentcage.cli.get_backend"):
            mock_state.load_deployment_config.return_value = _make_mock_config()
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "verify", "test"])
        assert result.exit_code == 2

    def test_backup_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "backup", "test"])
        assert result.exit_code == 2

    def test_exec_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "exec", "test", "--", "ls"])
        assert result.exit_code == 2

    def test_shell_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "shell", "test"])
        assert result.exit_code == 2

    def test_audit_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "audit", "test"])
        assert result.exit_code == 2

    def test_har_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "har", "test"])
        assert result.exit_code == 2

    def test_update_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "update", "test"])
        assert result.exit_code == 2

    def test_edit_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 2

    def test_domain_list_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.load_raw_config.return_value = {
                "name": "test", "domains": {"allow": []},
            }
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["domain", "list", "test"])
        assert result.exit_code == 2

    def test_domain_add_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.load_raw_config.return_value = {
                "name": "test", "domains": {"allow": []},
            }
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, [
                "domain", "add", "test", "example.com",
            ])
        assert result.exit_code == 2

    def test_domain_rm_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.load_raw_config.return_value = {
                "name": "test", "domains": {"allow": ["example.com"]},
            }
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, [
                "domain", "rm", "test", "example.com",
            ])
        assert result.exit_code == 2

    def test_secret_list_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["secret", "list", "test"])
        assert result.exit_code == 2

    def test_secret_rm_blocked(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            result = _runner().invoke(main, ["secret", "rm", "test", "KEY"])
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Exempt commands — `cage destroy` and `cage list` MUST NOT be blocked
# ---------------------------------------------------------------------------


class TestLegacyCageDestroyEscapeHatch:
    """``cage destroy`` is the documented way out of a stuck v0.21 cage —
    it must NOT call the version detector, and its filename enumeration
    in ContainerBackend.destroy_resources must cover the legacy proxy/
    dns quadlets (covered by test_container_backend's
    test_removes_legacy_v021_quadlet_files)."""

    def test_destroy_works_on_legacy_cage(self):
        with patch("agentcage.cli._destroy_cage") as mock_destroy, \
             patch("agentcage.cli.state") as mock_state:
            # Even with legacy metadata, destroy must proceed.
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            mock_destroy.return_value = ["state:test"]
            result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0
        mock_destroy.assert_called_once_with(
            "test", keep_secrets=False, echo=click.echo,
        )


class TestLegacyCageListAnnotation:
    """``cage list`` lists legacy entries inline rather than blocking —
    the operator needs to see what's on disk to know which cages to
    destroy + recreate. is_running checks against the new shape would
    mislabel still-running v0.21 cages as stopped, so the legacy
    annotation replaces them."""

    def test_list_annotates_legacy_cage(self):
        with patch("agentcage.cli.state") as mock_state, \
             patch("agentcage.cli.get_backend") as mock_get_backend:
            mock_state.list_deployments.return_value = ["old"]
            mock_state.load_deployment_config.return_value = _make_mock_config()
            mock_state.load_metadata.return_value = _mock_legacy_metadata()
            backend = mock_get_backend.return_value
            backend.service_names.return_value = ["cage", "egress"]
            backend.is_running.return_value = True
            result = _runner().invoke(main, ["cage", "list"])
        # Doesn't exit early — does NOT use code 2.
        assert result.exit_code == 0
        assert "old" in result.output
        # Inline annotation surfaces the issue.
        assert "legacy v0.21" in result.output
        # is_running was NOT called against the new shape for legacy
        # entries — it would query containers that don't exist
        # ({name}-egress) and mislabel the running v0.21 cage as
        # stopped.
        backend.is_running.assert_not_called()

    def test_list_normal_cage_unaffected(self):
        """Regression guard: a v0.22+ cage in `cage list` takes the
        normal status path (is_running against the new shape)."""
        with patch("agentcage.cli.state") as mock_state, \
             patch("agentcage.cli.get_backend") as mock_get_backend:
            mock_state.list_deployments.return_value = ["new"]
            mock_state.load_deployment_config.return_value = _make_mock_config()
            mock_state.load_metadata.return_value = {
                "agentcage_version": "0.22.0",
            }
            backend = mock_get_backend.return_value
            backend.service_names.return_value = ["cage", "egress"]
            backend.is_running.return_value = True
            result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "new" in result.output
        assert "legacy v0.21" not in result.output
        # is_running WAS called for the v0.22 cage.
        assert backend.is_running.called


# ---------------------------------------------------------------------------
# Version parser edge cases
# ---------------------------------------------------------------------------


class TestVersionParseEdges:
    """The detector must fail closed on metadata it can't parse — a
    cage with missing or malformed agentcage_version is treated as
    pre-v0.22, not as future / opt-in / etc."""

    def test_missing_version_key_is_treated_as_legacy(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = {}  # no version key
            result = _runner().invoke(main, ["cage", "stop", "test"])
        assert result.exit_code == 2

    def test_garbage_version_string_is_treated_as_legacy(self):
        with patch("agentcage.cli.state") as mock_state:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = {
                "agentcage_version": "not-a-version",
            }
            result = _runner().invoke(main, ["cage", "stop", "test"])
        assert result.exit_code == 2

    def test_v022_exactly_passes(self):
        """A cage created with exactly 0.22.0 must NOT be flagged."""
        with patch("agentcage.cli.state") as mock_state, \
             patch("agentcage.cli.get_backend") as mock_get_backend:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = {
                "agentcage_version": "0.22.0",
            }
            mock_state.load_deployment_config.return_value = _make_mock_config()
            backend = mock_get_backend.return_value
            result = _runner().invoke(main, ["cage", "stop", "test"])
        # Detector didn't fire — the command attempted to call
        # backend.stop (which is the mock, so it succeeds).
        assert result.exit_code == 0

    def test_future_v0_99_passes(self):
        with patch("agentcage.cli.state") as mock_state, \
             patch("agentcage.cli.get_backend") as mock_get_backend:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = {
                "agentcage_version": "0.99.0",
            }
            mock_state.load_deployment_config.return_value = _make_mock_config()
            backend = mock_get_backend.return_value
            result = _runner().invoke(main, ["cage", "stop", "test"])
        assert result.exit_code == 0

    def test_v1_0_passes(self):
        with patch("agentcage.cli.state") as mock_state, \
             patch("agentcage.cli.get_backend") as mock_get_backend:
            mock_state.deployment_exists.return_value = True
            mock_state.load_metadata.return_value = {
                "agentcage_version": "1.0.0",
            }
            mock_state.load_deployment_config.return_value = _make_mock_config()
            backend = mock_get_backend.return_value
            result = _runner().invoke(main, ["cage", "stop", "test"])
        assert result.exit_code == 0
