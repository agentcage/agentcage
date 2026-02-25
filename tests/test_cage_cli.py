"""Tests for the 'agentcage cage' CLI subcommands."""

from __future__ import annotations

import json
import textwrap
from unittest.mock import MagicMock, patch, call, ANY

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
        assert "agentcage secret set" in result.output

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
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_destroy_with_yes(self, mock_state, MockPodman, mock_systemd, tmp_path):
        podman = MockPodman.return_value
        podman.network_remove.return_value = False
        podman.volume_remove.return_value = False
        podman.secret_list.return_value = [{"Name": "test.API_KEY"}]
        podman.secret_remove.return_value = True
        mock_state.deployment_exists.return_value = True

        result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0
        mock_state.remove_deployment.assert_called_once_with("test")

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_destroy_prompts_without_yes(self, mock_state, MockPodman, mock_systemd):
        podman = MockPodman.return_value
        podman.network_remove.return_value = False
        podman.volume_remove.return_value = False
        podman.secret_list.return_value = []
        mock_state.deployment_exists.return_value = False

        result = _runner().invoke(main, ["cage", "destroy", "test"], input="n\n")
        assert result.exit_code != 0  # aborted


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
        assert "1.2.3" in result.output
        assert "running (3/3)" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_firecracker_cage(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myvm"]
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")
        mock_state.load_metadata.return_value = {"agentcage_version": "0.9.0"}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "myvm" in result.output
        assert "firecracker" in result.output
        assert "0.9.0" in result.output
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
        # VERSION column header present, value is "-"
        assert "VERSION" in result.output
        lines = result.output.strip().split("\n")
        data_line = [l for l in lines if "old" in l][0]
        assert "-" in data_line

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

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_container(self, mock_state, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        assert "Restarted" in result.output
        backend.restart.assert_called_once_with("test")

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_firecracker(self, mock_state, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")
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

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_firecracker_running(self, mock_state, mock_get_backend):
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "verify", "myvm"])
        assert result.exit_code == 0
        assert "firecracker" in result.output
        assert "PASS" in result.output
        assert "VM Internals" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_firecracker_stopped(self, mock_state, mock_get_backend):
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "verify", "myvm"])
        assert result.exit_code != 0
        assert "FAIL" in result.output


def _mock_config(isolation="container"):
    cfg = MagicMock()
    cfg.isolation = isolation
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
            "-n", "50", "-f",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_filtered(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic", "-s", "proxy", "--no-follow"])
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

    # -- Firecracker isolation --

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_firecracker_default(self, mock_state, mock_execvp):
        """All services requested → single unit, no grep, uses -o cat."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")
        result = _runner().invoke(main, ["cage", "logs", "basic"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user", "-u", "basic-cage",
            "-n", "50", "-o", "cat", "-f",
        ])

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_firecracker_filtered(self, mock_state, mock_execvp, mock_popen):
        """Single service requested → pipes through grep on [proxy] prefix."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")

        mock_journal = MagicMock()
        mock_grep = MagicMock()
        mock_grep.wait.return_value = 0
        mock_popen.side_effect = [mock_journal, mock_grep]

        result = _runner().invoke(main, [
            "cage", "logs", "basic", "-s", "proxy", "--no-follow",
        ])

        # journalctl Popen
        mock_popen.assert_any_call(
            ["journalctl", "--user", "-u", "basic-cage",
             "-n", "50", "-o", "cat"],
            stdout=ANY,
        )
        # grep Popen — pattern matches [proxy:(debug|info|warning|error|critical)]
        grep_call = mock_popen.call_args_list[1]
        pattern = grep_call[0][0][3]
        assert "proxy" in pattern
        assert "debug|info|warning|error|critical" in pattern
        mock_execvp.assert_not_called()

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_firecracker_multi_filter(self, mock_state, mock_execvp, mock_popen):
        """Two services requested → grep alternation pattern."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")

        mock_journal = MagicMock()
        mock_grep = MagicMock()
        mock_grep.wait.return_value = 0
        mock_popen.side_effect = [mock_journal, mock_grep]

        result = _runner().invoke(main, [
            "cage", "logs", "basic", "-s", "proxy", "-s", "dns", "--no-follow",
        ])

        # grep pattern should match both [proxy:*] and [dns:*]
        grep_call = mock_popen.call_args_list[1]
        pattern = grep_call[0][0][3]  # 4th element of the command list
        assert "proxy" in pattern
        assert "dns" in pattern
        assert "debug|info|warning|error|critical" in pattern
        mock_execvp.assert_not_called()


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

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_firecracker_mode(self, mock_state, mock_popen):
        """Uses cage unit for Firecracker mode; parses [proxy:*] prefixed lines."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("firecracker")

        fc_line = f"[proxy:warning] {_AUDIT_BLOCKED}\n"
        lines = [fc_line, _NON_AUDIT]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, ["cage", "audit", "myvm", "--no-color"])
        assert result.exit_code == 0
        assert "evil.com" in result.output

        # Verify journal command uses cage unit (Firecracker)
        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "myvm-cage"

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

    @patch("agentcage.cli.state")
    def test_exec_firecracker_rejected(self, mock_state):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("firecracker")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg

        result = _runner().invoke(main, ["cage", "exec", "myvm", "--", "ls"])
        assert result.exit_code != 0
        assert "not supported" in result.output

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
