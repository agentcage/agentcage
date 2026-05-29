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

import json
import os
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
    @patch("agentcage.backends.apple_container.ac_cli.inspect",
           return_value={"status": "running"})
    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_default_wraps_in_setpriv_with_full_cap_drop(
        self, mock_state, mock_execvp, mock_binary, _mock_inspect,
    ):
        """CTF F3 (v0.22.1): default ``cage exec`` enters via setpriv
        as the image's USER (root), drops all caps + sets NoNewPrivs,
        then setresuid/setresgid to 1000:1000 before execve'ing the
        operator's cmd. Previously this path was a flat ``container
        exec -u 1000:1000`` which left CapBnd=0xa80435fb intact and
        NoNewPrivs=0; any setuid-root binary in the base image
        (ubuntu:24.04 ships /usr/bin/su as 4755) could regrant
        CapEff = CapBnd and chain to the F2 route-replace bypass
        without --as-root.

        Wrap shape mirrors cage-init.sh stage D, which is what the
        WORKLOAD's PID 1 already does — this just closes the gap
        between PID 1's posture and every subsequent ``container
        exec`` session.
        """
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"

        _runner().invoke(main, ["cage", "exec", "demo", "--", "ls", "-la"])

        argv = mock_execvp.call_args.args[1]
        # Outer shape: `container exec demo sh -c <script> <$0> ls -la`.
        # The sh -c wrapper exists to re-export HOME/USER/LOGNAME for the
        # dropped-uid workload (setpriv itself does NOT touch env). See
        # the `else` branch in apple_container.py exec_argv for why.
        assert argv[:4] == ["/usr/local/bin/container", "exec", "demo", "sh"]
        assert argv[4] == "-c"
        script = argv[5]
        # $0 placeholder must come after the script; the operator's cmd
        # tail must come after that and be reachable via "$@" inside
        # the script.
        assert argv[6] == "agentcage-exec-wrap"
        assert argv[-2:] == ["ls", "-la"]
        # The script reads /etc/passwd for uid 1000 and exports the
        # right HOME/USER/LOGNAME before exec'ing setpriv. This is the
        # load-bearing change vs. the pre-0.22.4 flat-setpriv shape that
        # left HOME=/root for the cage workload and broke claude-code
        # 2.1.x in `-p` mode (silent exit-0 on EACCES at ~/.claude/).
        assert "getent passwd 1000" in script
        assert 'HOME="$CH"' in script
        assert 'USER="$CU"' in script
        assert 'LOGNAME="$CU"' in script
        # All of the F3 setpriv guards are still present in the script,
        # so the cap-drop posture is unchanged.
        assert "setpriv" in script
        assert "--reuid=1000" in script
        assert "--regid=1000" in script
        assert "--clear-groups" in script
        assert "--no-new-privs" in script
        assert "--bounding-set=-all" in script
        assert "--inh-caps=-all" in script

    @patch("agentcage.backends.apple_container.ac_cli.inspect",
           return_value={"status": "running"})
    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_as_root_drops_net_admin_via_setpriv(
        self, mock_state, mock_execvp, mock_binary, _mock_inspect,
    ):
        """``--as-root`` gets a uid-0 shell with NET_ADMIN DROPPED from
        the bounding set, so ``ip route replace`` returns EPERM and the
        operator cannot bypass the egress filter. CTF F2 (v0.22.1).

        The cage VM is started with ``--cap-add CAP_NET_ADMIN`` because
        ``cage-init.sh`` stage B needs it to set the default route via
        the egress sibling. Apple's runtime reconstructs that cap in
        CapEff on every ``container exec --user 0``, so before this fix
        an operator could ``ip route replace default via
        <apple-gateway>`` and reach the internet without mitmproxy
        interposition — full egress bypass via the operator-debug door.

        ``setpriv --bounding-set=-net_admin
        --inh-caps=-net_admin`` runs as uid 0 (no setuid happens),
        drops NET_ADMIN from the bounding + inheritable sets, then
        execve's the operator's cmd. execve recomputes CapEff/CapPrm
        from CapBnd, so the new process starts with NET_ADMIN cleared.
        Other caps (CHOWN, SETUID, SETGID, etc.) survive — ``apt-get
        install`` and similar debug ops continue to work.
        """
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"

        _runner().invoke(
            main, ["cage", "exec", "demo", "--as-root", "--", "iptables", "-L"],
        )

        argv = mock_execvp.call_args.args[1]
        # Setpriv wrap drops NET_ADMIN before exec'ing the operator's cmd.
        assert "setpriv" in argv
        assert "--bounding-set=-net_admin" in argv
        assert "--inh-caps=-net_admin" in argv
        # Still --as-root → uid 0:0 (operator's debug intent).
        assert "0:0" in argv
        # The operator's actual cmd still reaches the executable.
        assert "iptables" in argv

    @patch("agentcage.backends.apple_container.ac_cli.inspect",
           return_value={"status": "running"})
    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_rejects_proxy_service(self, mock_state, mock_execvp,
                                         mock_binary, _mock_inspect):
        """--service proxy is rejected with a clear message (not a crash).

        Post-v0.22 (#196): Click's `Choice(["cage", "egress"])` rejects
        the value at argument-parse time, before the backend-specific
        message had a chance to fire. The rejection message names the
        valid alternatives, which is what an operator needs.
        """
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = "/usr/local/bin/container"

        result = _runner().invoke(
            main, ["cage", "exec", "demo", "-s", "proxy", "--", "ls"],
        )
        assert result.exit_code != 0
        # Click rejects "proxy" at parse-time and names the alternatives.
        assert "proxy" in result.output
        assert "egress" in result.output
        mock_execvp.assert_not_called()

    @patch("agentcage.apple_container.cli.container_binary")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_errors_when_binary_missing(
        self, mock_state, mock_execvp, mock_binary,
    ):
        """A missing Apple `container` CLI exits with a clean message.

        After PR-bundle "torture-session-findings" the new is_running
        pre-flight runs first; for apple-container that calls
        ac_cli.inspect which returns None when the binary is missing, so
        is_running returns False and the user sees "is not running"
        before they'd see "container CLI not found". Both error messages
        are valid — the follow-up `cage start` will surface the binary
        issue if the user runs it. Test now asserts on the friendly
        "not running" message instead of the binary-missing one.
        """
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_binary.return_value = None

        result = _runner().invoke(main, ["cage", "exec", "demo", "--", "ls"])
        assert result.exit_code != 0
        assert "is not running" in result.output or "container" in result.output.lower()
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
        # And the *first* execvp call is the bash that probed OK,
        # WRAPPED in `/bin/sh -c '... capsh --no-new-privs --drop=all
        # --user="$CAGE_USER" ...'` (same primitive supervisor.sh uses
        # at stage 90; see cage_exec tests for the security rationale).
        # The shell wrapper resolves uid 1000 to its name because
        # capsh's --user= takes a name, not a numeric uid.
        first_exec = mock_execvp.call_args_list[0]
        assert first_exec.args == (
            "/usr/local/bin/container",
            ["/usr/local/bin/container", "exec", "-u", "0",
             "demo",
             "/bin/sh", "-c",
             'CAGE_USER=$(getent passwd 1000 | cut -d: -f1) && '
             'exec capsh --no-new-privs --drop=all '
             '--user="$CAGE_USER" --shell=/bin/sh '
             "-- -c 'exec /bin/bash'"],
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
            ["/usr/local/bin/container", "exec", "-u", "0",
             "demo",
             "/bin/sh", "-c",
             'CAGE_USER=$(getent passwd 1000 | cut -d: -f1) && '
             'exec capsh --no-new-privs --drop=all '
             '--user="$CAGE_USER" --shell=/bin/sh '
             "-- -c 'exec /bin/sh'"],
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


class TestCageBackupRestoreAppleContainer:
    """`cage backup` / `cage restore` are wired on apple-container (PR-10).
    Secret VALUES are NOT serialized — the manifest records expected env
    names; operator re-sets them host-side before restore."""

    @patch("agentcage.cli.state")
    def test_backup_rejects_include_secrets(self, mock_state):
        """--include-secrets has no meaning on apple-container; reject
        with a clear message instead of silently succeeding with empty
        values."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        result = _runner().invoke(
            main, ["cage", "backup", "demo", "--include-secrets"],
        )
        assert result.exit_code != 0
        assert "apple-container" in result.output
        assert "env-passed" in result.output


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


# ── secret list/set/rm: operate on pending_secrets.json ──


class TestSecretCommandsAppleContainer:
    """`agentcage secret list/set/rm <cage>` on apple-container edits the
    cage's pending_secrets.json (the backend re-stages it into the egress
    microVM on next start) and must NEVER touch host podman, which doesn't
    exist on most macOS installs.
    """

    @patch("agentcage.cli._apple_restart_if_running")
    @patch("agentcage.cli._write_apple_pending_secrets")
    @patch("agentcage.cli._load_apple_pending_secrets")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_set_writes_pending(
        self, mock_state, mock_podman, mock_load, mock_write, mock_restart,
    ):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_load.return_value = []

        result = _runner().invoke(
            main, ["secret", "set", "demo", "MY_KEY"], input="value\n",
        )

        assert result.exit_code == 0
        mock_write.assert_called_once_with("demo", [("MY_KEY", "value")])
        mock_restart.assert_called_once()
        # Host podman must NEVER be instantiated.
        mock_podman.assert_not_called()

    @patch("agentcage.cli._apple_restart_if_running")
    @patch("agentcage.cli._write_apple_pending_secrets")
    @patch("agentcage.cli._load_apple_pending_secrets")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_set_upserts_existing_key(
        self, mock_state, mock_podman, mock_load, mock_write, mock_restart,
    ):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_load.return_value = [("MY_KEY", "old"), ("OTHER", "x")]

        result = _runner().invoke(
            main, ["secret", "set", "demo", "MY_KEY"], input="new\n",
        )

        assert result.exit_code == 0
        # OTHER preserved, MY_KEY replaced (not duplicated).
        mock_write.assert_called_once_with(
            "demo", [("OTHER", "x"), ("MY_KEY", "new")],
        )
        mock_podman.assert_not_called()

    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_set_rejects_empty_value(self, mock_state, mock_podman):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")

        result = _runner().invoke(
            main, ["secret", "set", "demo", "MY_KEY"], input="\n",
        )

        assert result.exit_code != 0
        assert "empty secret value" in result.output
        mock_podman.assert_not_called()

    @patch("agentcage.cli._apple_restart_if_running")
    @patch("agentcage.cli._write_apple_pending_secrets")
    @patch("agentcage.cli._load_apple_pending_secrets")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_rm_removes_key(
        self, mock_state, mock_podman, mock_load, mock_write, mock_restart,
    ):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_load.return_value = [("MY_KEY", "v"), ("KEEP", "y")]

        result = _runner().invoke(main, ["secret", "rm", "demo", "MY_KEY"])

        assert result.exit_code == 0
        mock_write.assert_called_once_with("demo", [("KEEP", "y")])
        mock_restart.assert_called_once()
        mock_podman.assert_not_called()

    @patch("agentcage.cli._write_apple_pending_secrets")
    @patch("agentcage.cli._load_apple_pending_secrets")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_rm_missing_key_errors(
        self, mock_state, mock_podman, mock_load, mock_write,
    ):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("apple-container")
        mock_load.return_value = [("OTHER", "x")]

        result = _runner().invoke(main, ["secret", "rm", "demo", "MY_KEY"])

        assert result.exit_code != 0
        assert "does not exist" in result.output
        mock_write.assert_not_called()
        mock_podman.assert_not_called()

    @patch("agentcage.cli._expected_secrets")
    @patch("agentcage.cli._load_apple_pending_secrets")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_secret_list_marks_present_and_missing(
        self, mock_state, mock_podman, mock_load, mock_expected,
    ):
        cfg = _mock_config("apple-container")
        cfg.secret_injection = [MagicMock(env="MY_KEY")]
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = cfg
        mock_load.return_value = [("MY_KEY", "v")]
        mock_expected.return_value = ["MY_KEY", "ABSENT"]

        result = _runner().invoke(main, ["secret", "list", "demo"])

        # ABSENT is expected but not staged → MISSING → non-zero exit.
        assert result.exit_code != 0
        assert "MY_KEY" in result.output
        assert "injection" in result.output
        assert "ok" in result.output
        assert "ABSENT" in result.output
        assert "MISSING" in result.output
        mock_podman.assert_not_called()

    @patch("agentcage.cli._ensure_v022_cage")
    @patch("agentcage.cli._expected_secrets")
    @patch("agentcage.cli._load_apple_pending_secrets")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_show_reports_per_secret_present_and_missing(
        self, mock_state, mock_podman, mock_get_backend,
        mock_load, mock_expected, _mock_ensure,
    ):
        """`cage show` on apple-container reports the present/expected
        secret count from pending_secrets.json (the same source as
        `secret list`), not the old "status not tracked" placeholder, and
        never instantiates host podman.
        """
        cfg = _mock_config("apple-container")
        cfg.container.ports = []
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}
        backend = MagicMock()
        backend.service_names.return_value = ["cage", "egress"]
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        # MY_KEY staged; ABSENT expected but missing.
        mock_load.return_value = [("MY_KEY", "v")]
        mock_expected.return_value = ["MY_KEY", "ABSENT"]

        result = _runner().invoke(main, ["cage", "show", "demo"])

        assert result.exit_code == 0
        # 1 of 2 present, 1 missing — mirrors the container branch wording.
        assert "Secrets:    1/2 (1 missing)" in result.output
        assert "status not tracked" not in result.output
        # Host podman must NEVER be instantiated on apple-container.
        mock_podman.assert_not_called()

    @patch("agentcage.cli._ensure_v022_cage")
    @patch("agentcage.cli._expected_secrets")
    @patch("agentcage.cli._load_apple_pending_secrets")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.state")
    def test_show_reports_all_secrets_present(
        self, mock_state, mock_podman, mock_get_backend,
        mock_load, mock_expected, _mock_ensure,
    ):
        """When every expected secret is staged, `cage show` reports the
        full N/N count with no "missing" suffix.
        """
        cfg = _mock_config("apple-container")
        cfg.container.ports = []
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}
        backend = MagicMock()
        backend.service_names.return_value = ["cage", "egress"]
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        mock_load.return_value = [("MY_KEY", "v"), ("OTHER", "w")]
        mock_expected.return_value = ["MY_KEY", "OTHER"]

        result = _runner().invoke(main, ["cage", "show", "demo"])

        assert result.exit_code == 0
        assert "Secrets:    2/2" in result.output
        assert "missing" not in result.output
        mock_podman.assert_not_called()


class TestPendingSecretsHelpers:
    """The pending_secrets.json reader/writer must round-trip in exactly
    the ``[[key, value], ...]`` shape the backend's _stage_secrets parses,
    and the on-disk file must be mode 0600 (secrets at rest).
    """

    def _patch_dir(self, tmp_path):
        return patch("agentcage.cli.state.deployment_dir", return_value=tmp_path)

    def test_roundtrip_preserves_pairs(self, tmp_path):
        from agentcage.cli import (
            _load_apple_pending_secrets,
            _write_apple_pending_secrets,
        )

        with self._patch_dir(tmp_path):
            assert _load_apple_pending_secrets("demo") == []
            _write_apple_pending_secrets("demo", [("A", "1"), ("B", "2")])
            assert _load_apple_pending_secrets("demo") == [("A", "1"), ("B", "2")]

        # On-disk shape matches what apple_container._stage_secrets parses.
        raw = json.loads((tmp_path / "pending_secrets.json").read_text())
        assert raw == [["A", "1"], ["B", "2"]]
        assert dict((k, v) for k, v in raw) == {"A": "1", "B": "2"}

    def test_written_file_is_0600(self, tmp_path):
        from agentcage.cli import _write_apple_pending_secrets

        with self._patch_dir(tmp_path):
            _write_apple_pending_secrets("demo", [("A", "1")])
        mode = os.stat(tmp_path / "pending_secrets.json").st_mode & 0o777
        assert mode == 0o600

    def test_load_tolerates_garbage(self, tmp_path):
        from agentcage.cli import _load_apple_pending_secrets

        (tmp_path / "pending_secrets.json").write_text("{not json")
        with self._patch_dir(tmp_path):
            assert _load_apple_pending_secrets("demo") == []


# ── domain add/rm: live SIGHUP reload on apple-container (no restart) ──


class TestDomainCommandsAppleContainer:
    """`agentcage domain add/rm` on apple-container live-reloads the egress
    allowlist (re-render bind-mounted config + SIGHUP dnsmasq) instead of
    rebuilding the wrapper image and restarting the cage. `_update_dns_quadlet`
    delegates to `backend.reload_domains`; the stopped-egress short-circuit
    lives inside that method (unit-tested in test_apple_container.py).
    Regression guard against the old stop→build→start path that killed any
    interactive session in the cage on every domain edit.
    """

    @patch("agentcage.cli._is_apple_container", return_value=True)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_update_dns_quadlet_live_reloads_no_rebuild(
        self, mock_state, mock_get_backend, _mock_is_apple,
    ):
        """`_update_dns_quadlet(cfg)` on apple-container delegates to
        `backend.reload_domains(cfg, name)` and never rebuilds/restarts."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_config("apple-container")
        cfg.name = "demo"

        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        backend.reload_domains.assert_called_once_with(cfg, "demo")
        backend.stop.assert_not_called()
        backend.build_artifacts.assert_not_called()
        backend.start.assert_not_called()
