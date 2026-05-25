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
    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_runs_without_crashing(
        self, mock_state, mock_get_backend, mock_run, mock_binary,
    ):
        """Service-status checks pass and the deeper probes run via
        `container exec` rather than host podman — confirms the basic
        contract regardless of probe outcomes."""
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        backend = MagicMock()
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        mock_binary.return_value = "/usr/local/bin/container"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = _runner().invoke(main, ["cage", "verify", "demo"])

        assert "PASS" in result.output
        assert "apple-container" in result.output


# ── cage audit + har: bridged via host-bind-mounted JSONL ──


class TestCageAuditHarAppleContainer:
    """`cage audit` / `cage har` no longer exit unsupported — they read
    audit.jsonl / capture.jsonl from the host-bind-mounted logs dir
    (PR-5 added the bind mount; PR-6 wired the readers). If the JSONL
    file doesn't exist yet (cage just created and no traffic, or the
    cage predates 0.20.6), the command exits with a clear pointer to
    `cage update`."""

    @patch("agentcage.cli._apple_container_audit_path")
    @patch("agentcage.cli.state")
    def test_audit_missing_file_exits_with_hint(
        self, mock_state, mock_path, tmp_path,
    ):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        # Non-existent path → friendly error pointing at `cage update`.
        mock_path.return_value = tmp_path / "does-not-exist.jsonl"

        result = _runner().invoke(main, ["cage", "audit", "demo"])

        assert result.exit_code != 0
        assert "no audit log yet" in result.output
        assert "cage update" in result.output

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli._apple_container_audit_path")
    @patch("agentcage.cli.state")
    def test_audit_uses_tail_reader_on_apple_container(
        self, mock_state, mock_path, mock_popen, tmp_path,
    ):
        """Once the audit file exists, audit reads it via `tail -n 10000`
        rather than journalctl; subprocess.Popen receives the right argv.

        The CLI dispatches through Backend.audit_argv (lifted onto the
        protocol in PR-8) — for apple-container that returns
        ``tail -n 10000 <host-audit.jsonl>``. We mock the backend's
        logs_dir to point at tmp_path so audit_argv resolves to a path
        we control."""
        from agentcage.backends.apple_container import AppleContainerBackend
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        audit_path = tmp_path / "audit.jsonl"
        audit_path.touch()
        # _apple_container_audit_path is the "does the file exist?" probe
        # at the CLI layer; the actual argv is built by backend.audit_argv,
        # which calls logs_dir(name) — patch THAT to control the path.
        mock_path.return_value = audit_path

        fake_proc = MagicMock()
        fake_proc.stdout = iter([])
        mock_popen.return_value = fake_proc

        with patch.object(AppleContainerBackend, "logs_dir", return_value=tmp_path):
            _runner().invoke(main, ["cage", "audit", "demo"])

        # First Popen call is the tail of the host audit file.
        popen_argv = mock_popen.call_args.args[0]
        assert popen_argv[0] == "tail"
        assert str(audit_path) in popen_argv


# ── cage verify: deeper probes on apple-container ──


class TestCageVerifyAppleContainerProbes:
    """`cage verify` on apple-container now runs the same shape of
    deeper-than-service-status checks the container backend does:
    CA cert, DNS routing, egress filtering. They exec into the cage
    via Apple's `container exec` (not host podman) so they work on
    macOS without podman."""

    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_runs_deeper_probes_and_passes(
        self, mock_state, mock_get_backend, mock_run, mock_binary,
    ):
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        backend = MagicMock()
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        mock_binary.return_value = "/usr/local/bin/container"

        def fake_run(argv, **_kwargs):
            text = " ".join(argv)
            if "test -f /certs/mitmproxy-ca-cert.pem" in text:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "cat /etc/resolv.conf" in text:
                return MagicMock(returncode=0, stdout="nameserver 127.0.0.1\n", stderr="")
            if "which curl" in text:
                return MagicMock(returncode=0, stdout="/usr/bin/curl\n", stderr="")
            if "curl" in text and "evil-exfil" in text:
                return MagicMock(returncode=0, stdout="403", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run

        result = _runner().invoke(main, ["cage", "verify", "demo"])

        assert "CA Certificate" in result.output
        assert "DNS routing" in result.output
        assert "Egress Filtering" in result.output
        assert "[PASS] mitmproxy CA cert" in result.output
        assert "[PASS] /etc/resolv.conf" in result.output
        assert "Blocked domain" in result.output and "denied" in result.output
        # Old INFO banner ("deeper checks not yet implemented") must be gone.
        assert "not yet implemented" not in result.output

    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_fails_loudly_when_ca_missing(
        self, mock_state, mock_get_backend, mock_run, mock_binary,
    ):
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        backend = MagicMock()
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        mock_binary.return_value = "/usr/local/bin/container"

        def fake_run(argv, **_kwargs):
            text = " ".join(argv)
            if "test -f /certs/mitmproxy-ca-cert.pem" in text:
                return MagicMock(returncode=1, stdout="", stderr="")
            if "cat /etc/resolv.conf" in text:
                return MagicMock(returncode=0, stdout="nameserver 127.0.0.1\n", stderr="")
            if "which curl" in text:
                return MagicMock(returncode=1, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run

        result = _runner().invoke(main, ["cage", "verify", "demo"])

        assert "[FAIL] mitmproxy CA cert NOT found" in result.output
        # Egress check skipped when curl is missing — should WARN, not FAIL.
        assert "[WARN]" in result.output
        # Overall verify exits non-zero when any [FAIL].
        assert result.exit_code != 0


# ── cage backup / restore: still unsupported (Plan 3 PR-10) ──


class TestCageBackupRestoreStillUnsupported:
    """Backup/restore stay unsupported on apple-container until the
    secret-store abstraction lands (Plan 3 PR-10)."""

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


# ── domain add/rm: auto-rebuild wrapper on apple-container ──


class TestDomainCommandsAppleContainer:
    """REGRESSION: `agentcage domain add/rm` on apple-container must rebuild
    the wrapper image (which has the dnsmasq + mitmproxy allowlists baked in
    at build time) before restarting the cage. Pre-fix, the command saved
    cage.yaml + restarted the cage — but the restart re-executed the OLD
    image, so the change silently didn't apply. Users had to remember to
    run `cage update` manually.
    """

    @patch("agentcage.cli._is_apple_container", return_value=True)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_update_dns_quadlet_rebuilds_wrapper(
        self, mock_state, mock_get_backend, _mock_is_apple,
    ):
        """`_update_dns_quadlet(cfg)` on apple-container must call
        `backend.build_artifacts()` (the rebuild path) before restart."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_config("apple-container")
        cfg.name = "demo"

        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        # Stop → build → start ordering matters: the rebuild must happen
        # while the cage is stopped (otherwise Apple's `container build`
        # would try to tag an image name in use by a running container).
        mock_calls = [c[0] for c in backend.mock_calls]
        stop_idx = next(i for i, c in enumerate(mock_calls) if c == "stop")
        build_idx = next(i for i, c in enumerate(mock_calls) if c == "build_artifacts")
        start_idx = next(i for i, c in enumerate(mock_calls) if c == "start")
        assert stop_idx < build_idx < start_idx

        backend.build_artifacts.assert_called_once()
        ba_args = backend.build_artifacts.call_args
        assert ba_args.args[1] == "demo"

    @patch("agentcage.cli._is_apple_container", return_value=True)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_update_dns_quadlet_skips_start_when_cage_not_running(
        self, mock_state, mock_get_backend, _mock_is_apple,
    ):
        """If the cage isn't running, rebuild the image but don't start it
        (matches the container backend's behavior — `domain add` on a
        stopped cage updates the state but doesn't auto-start)."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_config("apple-container")
        cfg.name = "demo"

        backend = MagicMock()
        backend.is_running.return_value = False
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        backend.build_artifacts.assert_called_once()
        backend.stop.assert_not_called()
        backend.start.assert_not_called()
