"""Tests for `agentcage cage <subcommand>` on apple-container isolation.

Regression coverage for the bug where every `cage <subcommand>` other
than `cage create`/`update`/`list`/`destroy` fell through to host
``podman`` on apple-container, crashing with FileNotFoundError on
macOS hosts without podman installed.

Each test patches the apple-container ``container_binary`` resolver and
asserts the subprocess argv routes through ``container ...`` (not
``podman ...``), or that the command exits cleanly with a helpful
message instead of crashing.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


def _mock_config(isolation="apple-container", lifecycle="service", scaffold=""):
    cfg = MagicMock()
    cfg.isolation = isolation
    cfg.lifecycle = lifecycle
    cfg.scaffold = scaffold
    cfg.container.nested_containers = False
    cfg.exec_aliases = {}
    cfg.name = "demo"
    return cfg


# ── cage exec ────────────────────────────────────────────


class TestCageExecAppleContainer:
    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_calls_container_exec(self, mock_state, mock_execvp, mock_binary):
        """exec on apple-container goes through `container exec`, not podman."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"

        _runner().invoke(main, ["cage", "exec", "demo", "--", "ls", "-la"])

        # Routed through the apple `container` CLI on the resolved path.
        mock_execvp.assert_called_once_with(
            "/usr/local/bin/container",
            ["/usr/local/bin/container", "exec", "demo", "ls", "-la"],
        )

    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_rejects_proxy_service(self, mock_state, mock_execvp, mock_binary):
        """--service proxy is rejected with a clear message (not a crash)."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"

        result = _runner().invoke(
            main, ["cage", "exec", "demo", "-s", "proxy", "--", "ls"],
        )
        assert result.exit_code != 0
        assert "proxy" in result.output
        assert "apple-container" in result.output
        mock_execvp.assert_not_called()

    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_errors_when_binary_missing(
        self, mock_state, mock_execvp, mock_binary,
    ):
        """A missing Apple `container` CLI exits with a clean message."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = None

        result = _runner().invoke(main, ["cage", "exec", "demo", "--", "ls"])
        assert result.exit_code != 0
        assert "container" in result.output.lower()
        mock_execvp.assert_not_called()


# ── cage shell ──────────────────────────────────────────


class TestCageShellAppleContainer:
    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_shell_autodetects_bash(
        self, mock_state, mock_execvp, mock_run, mock_binary,
    ):
        """shell probes /bin/bash via `container exec test -x` then execs it.

        ``os.execvp`` is mocked so it doesn't actually replace the
        process; the test asserts on the first call (what would have
        happened on a real host).
        """
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"
        # First probe (bash) succeeds.
        mock_run.return_value = MagicMock(returncode=0)

        _runner().invoke(main, ["cage", "shell", "demo"])

        # Bash probe goes through `container exec`.
        first_probe = mock_run.call_args_list[0]
        assert first_probe.args[0] == [
            "/usr/local/bin/container", "exec", "demo", "test", "-x", "/bin/bash",
        ]
        # And the *first* execvp call is the bash that probed OK.
        # (Without a real exec, control falls through to a host-podman
        # fallback in container mode — but on apple-container we never
        # reach that fallthrough; first call must already be /bin/bash.)
        first_exec = mock_execvp.call_args_list[0]
        assert first_exec.args == (
            "/usr/local/bin/container",
            ["/usr/local/bin/container", "exec", "demo", "/bin/bash"],
        )

    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_shell_falls_back_to_sh_via_container(
        self, mock_state, mock_execvp, mock_run, mock_binary,
    ):
        """Neither /bin/bash nor /bin/sh probes match → fall back to
        `container exec ... /bin/sh`, never to host `podman`."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"
        # All probes fail.
        mock_run.return_value = MagicMock(returncode=1)

        _runner().invoke(main, ["cage", "shell", "demo"])

        # First execvp call is the apple-container /bin/sh fallback.
        # CRITICAL: it must NOT be `podman`. (The post-apple-container
        # fall-through path in cage_shell only runs because os.execvp is
        # mocked in tests; on a real host it would have replaced the
        # process already.)
        first_exec = mock_execvp.call_args_list[0]
        assert first_exec.args == (
            "/usr/local/bin/container",
            ["/usr/local/bin/container", "exec", "demo", "/bin/sh"],
        )


# ── cage logs ───────────────────────────────────────────


class TestCageLogsAppleContainer:
    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_streams_container_logs(
        self, mock_state, mock_execvp, mock_binary,
    ):
        """cage logs runs `container logs <name>`, not journalctl/podman."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"

        _runner().invoke(main, ["cage", "logs", "demo"])

        mock_execvp.assert_called_once_with(
            "/usr/local/bin/container",
            ["/usr/local/bin/container", "logs", "demo"],
        )

    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_follow_passes_f(
        self, mock_state, mock_execvp, mock_binary,
    ):
        """`-f` propagates to `container logs -f <name>`."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"

        _runner().invoke(main, ["cage", "logs", "demo", "-f"])

        mock_execvp.assert_called_once_with(
            "/usr/local/bin/container",
            ["/usr/local/bin/container", "logs", "-f", "demo"],
        )


# ── cage verify ─────────────────────────────────────────


class TestCageVerifyAppleContainer:
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_short_circuits_with_notice(
        self, mock_state, mock_get_backend,
    ):
        """verify on apple-container reports service status only and never
        shells out to host podman."""
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        backend = MagicMock()
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend

        result = _runner().invoke(main, ["cage", "verify", "demo"])

        # No crash and the info banner mentions the limitation.
        assert "PASS" in result.output
        assert "apple-container" in result.output


# ── cage audit / har / backup / restore: gated on apple-container ──


class TestCageGatedCommandsAppleContainer:
    @patch("agentcage.cli.state")
    def test_audit_exits_unsupported(self, mock_state):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        result = _runner().invoke(main, ["cage", "audit", "demo"])
        assert result.exit_code != 0
        assert "apple-container" in result.output
        assert "not yet implemented" in result.output

    @patch("agentcage.cli.state")
    def test_backup_exits_unsupported(self, mock_state):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        result = _runner().invoke(main, ["cage", "backup", "demo"])
        assert result.exit_code != 0
        assert "apple-container" in result.output
        assert "not yet implemented" in result.output


# ── cage start / restart: do not instantiate host Podman ──


class TestCageStartRestartAppleContainer:
    """Regression: `cage start` / `cage restart` on apple-container must not
    call _ensure_patches(Podman()) — instantiating and using host podman
    fails on macOS hosts where podman isn't installed. The backend's own
    start/restart are the only thing that should run."""

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._ensure_patches")
    @patch("agentcage.cli.state")
    def test_start_skips_ensure_patches(
        self, mock_state, mock_ensure_patches, mock_get_backend,
    ):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        backend = MagicMock()
        mock_get_backend.return_value = backend

        result = _runner().invoke(main, ["cage", "start", "demo"])

        # The host-podman patches step must not run on apple-container.
        mock_ensure_patches.assert_not_called()
        # The backend's start() is still what brings the cage up.
        backend.start.assert_called_once_with("demo")
        assert result.exit_code == 0

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli._ensure_patches")
    @patch("agentcage.cli.state")
    def test_restart_skips_ensure_patches(
        self, mock_state, mock_ensure_patches, mock_restart, mock_get_backend,
    ):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_get_backend.return_value = MagicMock()

        result = _runner().invoke(main, ["cage", "restart", "demo"])

        mock_ensure_patches.assert_not_called()
        mock_restart.assert_called_once()
        assert result.exit_code == 0


# ── secret list/set/rm: must not fall through to host podman ──


class TestSecretCommandsAppleContainer:
    """Regression: `agentcage secret list/set/rm <cage>` on apple-container
    must exit cleanly with the unsupported message instead of crashing into
    host podman (which doesn't exist on most macOS installs).

    The proper apple-container secret store is tracked in #120 (heavy lift
    for `cage backup/restore` brings the secret-store abstraction). Until
    then `cage create` env-passes secrets directly via the supervisor's
    config; users edit them by editing cage.yaml + `cage update`.
    """

    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_list_exits_unsupported(self, mock_state, mock_podman):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")

        result = _runner().invoke(main, ["secret", "list", "demo"])

        assert result.exit_code != 0
        assert "apple-container" in result.output
        assert "not yet implemented" in result.output
        # Host podman must NEVER be instantiated.
        mock_podman.assert_not_called()

    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_set_exits_unsupported(self, mock_state, mock_podman):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")

        result = _runner().invoke(
            main, ["secret", "set", "demo", "MY_KEY"], input="value\n",
        )

        assert result.exit_code != 0
        assert "apple-container" in result.output
        assert "not yet implemented" in result.output
        mock_podman.assert_not_called()

    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_rm_exits_unsupported(self, mock_state, mock_podman):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")

        result = _runner().invoke(main, ["secret", "rm", "demo", "MY_KEY"])

        assert result.exit_code != 0
        assert "apple-container" in result.output
        assert "not yet implemented" in result.output
        mock_podman.assert_not_called()
