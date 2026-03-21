"""Tests for the 'agentcage cage' CLI subcommands."""

from __future__ import annotations

import json
import textwrap
from unittest.mock import MagicMock, patch, call, ANY

import click
from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


class TestCageCreate:
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_fails_if_exists(self, mock_state, MockPodman, mock_systemd, minimal_yaml):
        mock_state.deployment_exists.return_value = True
        result = _runner().invoke(main, ["cage", "create", "-c", minimal_yaml])
        assert result.exit_code != 0
        assert "already exists" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_fails_on_missing_secrets(self, mock_state, MockPodman, mock_systemd, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
        """))
        mock_state.deployment_exists.return_value = False
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False

        result = _runner().invoke(main, ["cage", "create", "-c", str(p)])
        assert result.exit_code != 0
        assert "missing secrets" in result.output
        assert "--set-secret" in result.output or "agentcage secret set" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_requires_config(self, mock_state, MockPodman, mock_systemd):
        result = _runner().invoke(main, ["cage", "create"])
        assert result.exit_code != 0


class TestCageUpdate:
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_fails_if_not_exists(self, mock_state, MockPodman, mock_systemd):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "update", "test"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_name_mismatch(self, mock_state, MockPodman, mock_systemd, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: other
            container:
              image: test:latest
        """))
        mock_state.deployment_exists.return_value = True
        result = _runner().invoke(main, ["cage", "update", "test", "-c", str(p)])
        assert result.exit_code != 0
        assert "does not match" in result.output


class TestCageDestroy:
    @patch("agentcage.cli._destroy_cage")
    def test_destroy_with_yes(self, mock_destroy, tmp_path):
        mock_destroy.return_value = ["state:test"]

        result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0
        mock_destroy.assert_called_once_with("test", keep_secrets=False, echo=click.echo)

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_prompts_without_yes(self, mock_destroy):
        result = _runner().invoke(main, ["cage", "destroy", "test"], input="n\n")
        assert result.exit_code != 0  # aborted
        mock_destroy.assert_not_called()


class TestCageList:
    @patch("agentcage.cli.state")
    def test_list_empty(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "No" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_container_cage(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        mock_state.load_deployment_config.return_value = _mock_config("container")
        mock_state.load_metadata.return_value = {"agentcage_version": "1.2.3"}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "myapp" in result.output
        assert "container" in result.output
        assert "service" in result.output  # default lifecycle
        assert "running (3/3)" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_vm_cage(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myvm"]
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        mock_state.load_metadata.return_value = {"agentcage_version": "0.9.0"}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "myvm" in result.output
        assert "vm" in result.output
        assert "running (1/1)" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_missing_metadata_shows_dash(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["old"]
        mock_state.load_deployment_config.return_value = _mock_config("container")
        mock_state.load_metadata.return_value = {}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "old" in result.output
        # LIFECYCLE column header present
        assert "LIFECYCLE" in result.output
        lines = result.output.strip().split("\n")
        data_line = [l for l in lines if "old" in l][0]
        assert "service" in data_line  # default lifecycle

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_config_error(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["broken"]
        mock_state.load_deployment_config.side_effect = Exception("bad config")
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "broken" in result.output
        assert "config error" in result.output


class TestCageRestart:
    @patch("agentcage.cli.state")
    def test_restart_fails_if_not_exists(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_container(self, mock_state, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        assert "Restarted" in result.output
        backend.restart.assert_called_once_with("test")

    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_vm(self, mock_state, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        backend = mock_get_backend.return_value
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        assert "Restarted" in result.output
        backend.restart.assert_called_once_with("test")


class TestCageEdit:
    @patch("agentcage.cli.state")
    def test_edit_nonexistent(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "edit", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("click.edit")
    @patch("agentcage.cli.validate_config")
    @patch("agentcage.cli.load_config")
    @patch("agentcage.cli.state")
    def test_edit_opens_editor(self, mock_state, mock_load_config, mock_validate,
                               mock_click_edit, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.stored_config_path.return_value = "/fake/path/cage.yaml"
        mock_load_config.return_value = _mock_config()
        mock_validate.return_value = []
        mock_get_backend.return_value.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0
        mock_click_edit.assert_called_once_with(filename="/fake/path/cage.yaml",
                                                extension='.yaml')

    @patch("agentcage.cli.get_backend")
    @patch("click.edit")
    @patch("agentcage.cli.validate_config")
    @patch("agentcage.cli.load_config")
    @patch("agentcage.cli.state")
    def test_edit_validates_after_save(self, mock_state, mock_load_config,
                                      mock_validate, mock_click_edit,
                                      mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.stored_config_path.return_value = "/fake/path/cage.yaml"
        cfg = _mock_config()
        mock_load_config.return_value = cfg
        mock_validate.return_value = []
        mock_get_backend.return_value.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0
        mock_load_config.assert_called_once_with("/fake/path/cage.yaml")
        mock_validate.assert_called_once_with(cfg)

    @patch("agentcage.cli.get_backend")
    @patch("click.edit")
    @patch("agentcage.cli.load_config")
    @patch("agentcage.cli.state")
    def test_edit_invalid_config_after_save(self, mock_state, mock_load_config,
                                           mock_click_edit, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.stored_config_path.return_value = "/fake/path/cage.yaml"
        mock_load_config.side_effect = ValueError("bad config")
        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code != 0
        assert "bad config" in result.output

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    @patch("click.edit")
    @patch("agentcage.cli.validate_config")
    @patch("agentcage.cli.load_config")
    @patch("agentcage.cli.state")
    def test_edit_reloads_running_cage(self, mock_state, mock_load_config,
                                      mock_validate, mock_click_edit,
                                      mock_get_backend, mock_restart):
        mock_state.deployment_exists.return_value = True
        mock_state.stored_config_path.return_value = "/fake/path/cage.yaml"
        cfg = _mock_config()
        mock_load_config.return_value = cfg
        mock_validate.return_value = []
        mock_get_backend.return_value.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0
        assert "restarted" in result.output.lower()
        mock_restart.assert_called_once_with("test", cfg)

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    @patch("click.edit")
    @patch("agentcage.cli.validate_config")
    @patch("agentcage.cli.load_config")
    @patch("agentcage.cli.state")
    def test_edit_no_reload_stopped_cage(self, mock_state, mock_load_config,
                                        mock_validate, mock_click_edit,
                                        mock_get_backend, mock_restart):
        mock_state.deployment_exists.return_value = True
        mock_state.stored_config_path.return_value = "/fake/path/cage.yaml"
        mock_load_config.return_value = _mock_config()
        mock_validate.return_value = []
        mock_get_backend.return_value.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0
        assert "restarted" not in result.output.lower()
        mock_restart.assert_not_called()


class TestCageVerify:
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_nonexistent_cage(self, mock_state, mock_get_backend):
        mock_state.load_deployment_config.side_effect = FileNotFoundError()
        result = _runner().invoke(main, ["cage", "verify", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_container_all_running(self, mock_state, mock_get_backend, MockPodman):
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        podman = MockPodman.return_value
        # CA cert check → success; which curl → found; curl egress → blocked
        podman.container_exec.side_effect = [
            (0, ""),       # test -f /certs/...
            (0, "/usr/bin/curl"),  # which curl
            (0, "403"),    # curl blocked domain
        ]
        podman.container_inspect.return_value = {
            "Config": {"Env": ["HTTP_PROXY=http://x", "HTTPS_PROXY=http://x"]}
        }
        podman.info.return_value = {
            "host": {"security": {"rootless": True}}
        }
        result = _runner().invoke(main, ["cage", "verify", "test"])
        assert result.exit_code == 0
        assert "container" in result.output
        assert "PASS" in result.output

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_vm_running(self, mock_state, mock_get_backend, MockLimaInstance):
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        # Mock Lima instance
        mock_lima = MockLimaInstance.return_value
        mock_lima.is_running.return_value = True
        mock_lima.exec.return_value = MagicMock(stdout="active\n")
        result = _runner().invoke(main, ["cage", "verify", "myvm"])
        assert result.exit_code == 0
        assert "vm" in result.output
        assert "PASS" in result.output
        assert "Lima VM" in result.output

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_vm_stopped(self, mock_state, mock_get_backend, MockLimaInstance):
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = False
        mock_lima = MockLimaInstance.return_value
        mock_lima.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "verify", "myvm"])
        assert result.exit_code != 0
        assert "FAIL" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_egress_python_fallback(self, mock_state, mock_get_backend, MockPodman):
        """When curl and node are missing, python3 urllib fallback works."""
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        podman = MockPodman.return_value
        podman.container_exec.side_effect = [
            (0, ""),            # test -f /certs/...
            (1, ""),            # which curl → not found
            (1, ""),            # node fallback → fails
            (0, "403\n"),       # python3 urllib → 403
        ]
        podman.container_inspect.return_value = {
            "Config": {"Env": ["HTTP_PROXY=http://x", "HTTPS_PROXY=http://x"]}
        }
        podman.info.return_value = {
            "host": {"security": {"rootless": True}}
        }
        result = _runner().invoke(main, ["cage", "verify", "test"])
        assert result.exit_code == 0
        assert "PASS" in result.output
        assert "403" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_egress_no_client_warns(self, mock_state, mock_get_backend, MockPodman):
        """When no HTTP client is available, verify warns instead of failing."""
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        podman = MockPodman.return_value
        podman.container_exec.side_effect = [
            (0, ""),            # test -f /certs/...
            (1, ""),            # which curl → not found
            (1, ""),            # node fallback → fails
            (1, ""),            # python3 fallback → fails
        ]
        podman.container_inspect.return_value = {
            "Config": {"Env": ["HTTP_PROXY=http://x", "HTTPS_PROXY=http://x"]}
        }
        podman.info.return_value = {
            "host": {"security": {"rootless": True}}
        }
        result = _runner().invoke(main, ["cage", "verify", "test"])
        assert result.exit_code == 0  # warnings don't fail verify
        assert "WARN" in result.output
        assert "No HTTP client" in result.output
        assert "1 warnings" in result.output


def _mock_config(isolation="container", lifecycle="service", scaffold=""):
    cfg = MagicMock()
    cfg.isolation = isolation
    cfg.lifecycle = lifecycle
    cfg.scaffold = scaffold
    cfg.container.nested_containers = False
    return cfg


class TestCageLogs:
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_default(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-proxy", "-u", "basic-dns",
            "-n", "50",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_follow(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic", "-f"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-proxy", "-u", "basic-dns",
            "-n", "50", "-f",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_filtered(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic", "-s", "proxy"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-proxy",
            "-n", "50",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_no_cage(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "logs", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output
        mock_execvp.assert_not_called()

    # -- VM isolation --

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_vm_default(self, mock_state, mock_execvp, MockLimaInstance):
        """All services requested → limactl shell + journalctl with all units."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"
        result = _runner().invoke(main, ["cage", "logs", "basic"])
        mock_execvp.assert_called_once_with("limactl", [
            "limactl", "shell", "agentcage-basic", "--",
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-proxy", "-u", "basic-dns",
            "-n", "50", "-o", "cat",
        ])

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_vm_filtered(self, mock_state, mock_execvp, MockLimaInstance, mock_popen):
        """Single service with severity filter → Popen + Python filtering."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"

        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc

        result = _runner().invoke(main, [
            "cage", "logs", "basic", "-s", "proxy", "--no-follow", "-l", "warning",
        ])

        # Should call Popen with limactl shell
        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "limactl"
        assert "agentcage-basic" in call_args
        assert "basic-proxy" in call_args
        mock_execvp.assert_not_called()

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_vm_multi_units(self, mock_state, mock_execvp, MockLimaInstance, mock_popen):
        """Two services with no severity filter → execvp limactl with both units."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"
        result = _runner().invoke(main, [
            "cage", "logs", "basic", "-s", "proxy", "-s", "dns",
        ])
        # execvp called with limactl and both units
        mock_execvp.assert_called_once()
        call_args = mock_execvp.call_args[0][1]
        assert "basic-proxy" in call_args
        assert "basic-dns" in call_args


# ── sample audit JSON lines ──────────────────────────────

_AUDIT_ALLOWED = json.dumps({
    "ts": "2026-02-20T10:00:00+00:00", "method": "GET",
    "host": "api.anthropic.com", "url": "https://api.anthropic.com/v1/messages",
    "decision": "allowed", "reason": "", "inspectors": [],
})

_AUDIT_BLOCKED = json.dumps({
    "ts": "2026-02-20T10:01:00+00:00", "method": "POST",
    "host": "evil.com", "url": "https://evil.com/exfil",
    "decision": "blocked", "reason": "domain not in allowlist",
    "inspectors": [{"name": "domain", "action": "block",
                    "reason": "domain not in allowlist", "severity": "error"}],
})

_AUDIT_FLAGGED = json.dumps({
    "ts": "2026-02-20T10:02:00+00:00", "method": "POST",
    "host": "api.anthropic.com", "url": "https://api.anthropic.com/v1/messages",
    "decision": "flagged", "reason": "high entropy",
    "inspectors": [{"name": "entropy", "action": "flag",
                    "reason": "high entropy", "severity": "warning"}],
})

_NON_AUDIT = "some non-json log line\n"


def _mock_popen_output(lines):
    """Create a mock Popen whose stdout yields the given lines."""
    mock_proc = MagicMock()
    mock_proc.stdout = iter(lines)
    mock_proc.wait.return_value = 0
    return mock_proc


class TestCageAudit:
    @patch("agentcage.cli.state")
    def test_audit_fails_if_not_exists(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "audit", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_container_mode(self, mock_state, mock_popen):
        """Parses raw JSON from mocked subprocess in container mode."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _NON_AUDIT, _AUDIT_BLOCKED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, ["cage", "audit", "myapp", "--no-color"])
        assert result.exit_code == 0
        assert "api.anthropic.com" in result.output
        assert "evil.com" in result.output

        # Verify journal command uses proxy unit
        cmd = mock_popen.call_args[0][0]
        assert "-u" in cmd
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "myapp-proxy"

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_vm_mode(self, mock_state, mock_popen, MockLimaInstance):
        """VM mode uses limactl shell + journalctl with proxy and dns units."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-myvm"

        lines = [_AUDIT_BLOCKED + "\n", _NON_AUDIT]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, ["cage", "audit", "myvm", "--no-color"])
        assert result.exit_code == 0
        assert "evil.com" in result.output

        # Verify command uses limactl shell with proxy unit
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "limactl"
        assert "agentcage-myvm" in cmd
        assert "myvm-proxy" in cmd

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_decision_filter(self, mock_state, mock_popen):
        """-d blocked filters out allowed entries."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _AUDIT_BLOCKED + "\n", _AUDIT_FLAGGED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "-d", "blocked", "--no-color",
        ])
        assert result.exit_code == 0
        assert "evil.com" in result.output
        assert "api.anthropic.com" not in result.output

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_json_output(self, mock_state, mock_popen):
        """--json outputs valid JSON lines."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _AUDIT_BLOCKED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "--json",
        ])
        assert result.exit_code == 0
        output_lines = [l for l in result.output.strip().split("\n") if l]
        assert len(output_lines) == 2
        for line in output_lines:
            parsed = json.loads(line)
            assert "decision" in parsed

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_summary_mode(self, mock_state, mock_popen):
        """--summary shows aggregated stats."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _AUDIT_BLOCKED + "\n", _AUDIT_FLAGGED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "--summary",
        ])
        assert result.exit_code == 0
        assert "Total entries: 3" in result.output
        assert "blocked" in result.output
        assert "allowed" in result.output

    @patch("agentcage.cli.state")
    def test_audit_summary_follow_conflict(self, mock_state):
        """--summary --follow errors."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "--summary", "--follow",
        ])
        assert result.exit_code != 0
        assert "incompatible" in result.output


class TestCageExec:
    @patch("agentcage.cli.state")
    def test_exec_nonexistent(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "exec", "nope", "--", "ls"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_simple_command(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, ["cage", "exec", "myapp", "--", "ls", "-la"])
        mock_run.assert_called_once_with(["podman", "exec", "myapp-cage", "ls", "-la"])

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_alias_expansion(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {"openclaw": ["node", "openclaw.mjs"]}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "--", "openclaw", "devices", "list",
        ])
        mock_run.assert_called_once_with(
            ["podman", "exec", "myapp-cage", "node", "openclaw.mjs", "devices", "list"]
        )

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_custom_service(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "-s", "proxy", "--", "ls",
        ])
        mock_run.assert_called_once_with(["podman", "exec", "myapp-proxy", "ls"])

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_vm_uses_limactl(self, mock_state, mock_execvp, MockLimaInstance):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("vm")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        MockLimaInstance.return_value.name = "agentcage-myvm"

        result = _runner().invoke(main, ["cage", "exec", "myvm", "--", "ls"])
        # No -it in test because stdin is not a TTY
        mock_execvp.assert_called_once_with("limactl", [
            "limactl", "shell", "agentcage-myvm", "--",
            "podman", "exec", "myvm-cage", "ls",
        ])

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_no_alias_match(self, mock_state, mock_run):
        """When command doesn't match any alias, it passes through unchanged."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {"openclaw": ["node", "openclaw.mjs"]}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "--", "cat", "/etc/hostname",
        ])
        mock_run.assert_called_once_with(
            ["podman", "exec", "myapp-cage", "cat", "/etc/hostname"]
        )
