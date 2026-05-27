"""Tests for live-reload of the dnsmasq allowlist via _update_dns_quadlet.

A domain add/rm must not restart the cage container — interactive sessions
inside the cage (e.g. ``agentcage run``) need to survive a config update.

v0.22 shape (cage + egress):
  - Container backend: validate the new allowlist via ``dnsmasq --test
    --servers-file=<allowlist>`` run inside the egress container, then
    SIGHUP dnsmasq via the pidfile the supervisor writes at
    /run/dnsmasq.pid. Both steps use ``podman exec <name>-egress …``.
  - VM backend: same shape, wrapped in ``limactl shell <vm> -- podman
    exec <name>-egress …``. Lima's reverse-sshfs caching is sidestepped
    by writing the rewritten host files into the VM-local mount path
    first (``push_config_files`` in agentcage.backends.vm).
  - Apple-container backend: allowlist is image-baked, so the path
    stays "stop + rebuild + start". Unchanged.

``kill -HUP $(cat /run/dnsmasq.pid)`` rather than ``pkill -HUP dnsmasq``
because the supervisor uses ``setpriv --reuid=acdns`` — pkill from the
supervisor's process tree wouldn't find dnsmasq, and ``podman kill
--signal HUP`` would hit tini at PID 1. The pidfile is the reliable
handle.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _mock_cfg(isolation: str, name: str = "demo") -> MagicMock:
    cfg = MagicMock()
    cfg.isolation = isolation
    cfg.name = name
    return cfg


class TestContainerBackendLiveReload:
    """On the container (rootless podman) backend, a domain change
    SIGHUPs dnsmasq inside the egress container — the proxy addon
    hot-reloads via mtime poll, and the cage container is never
    touched."""

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_signals_dnsmasq_via_pidfile(
        self, mock_state, mock_get_backend, mock_run,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        # dns_allowlist_path → real Path object so .read_text/.write_text work
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path
        # `dnsmasq --test` returns 0 → publish + SIGHUP
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        _update_dns_quadlet(cfg)

        # Two podman-exec calls: validation + SIGHUP.
        argvs = [c.args[0] for c in mock_run.call_args_list]
        assert ["podman", "exec", "demo-egress", "dnsmasq", "--test",
                "--servers-file=/etc/agentcage/dns-allowlist.conf"] in argvs, (
            f"expected dnsmasq --test invocation; got {argvs}"
        )
        # SIGHUP via pidfile.
        kill_calls = [a for a in argvs if any("kill" in part for part in a)]
        assert kill_calls, f"no kill -HUP invocation found in {argvs}"
        last_arg = kill_calls[0][-1]
        assert "/run/dnsmasq.pid" in last_arg
        assert "-HUP" in last_arg

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_does_not_stop_or_start_any_unit(
        self, mock_state, mock_get_backend, mock_systemd, mock_run,
    ):
        """Cage interactive sessions must survive a domain add — no
        systemctl stop/start of ANY cage service."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        _update_dns_quadlet(cfg)

        mock_systemd.stop_unit.assert_not_called()
        mock_systemd.start_unit.assert_not_called()
        mock_systemd.restart_unit.assert_not_called()

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_skips_signal_when_egress_not_running(
        self, mock_state, mock_get_backend, mock_run,
    ):
        """If the egress container isn't running, the file is rewritten
        but no validation or signal is sent — there's no dnsmasq to
        reload."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = False
        mock_get_backend.return_value = backend
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path

        _update_dns_quadlet(cfg)

        mock_run.assert_not_called()
        # Allowlist file IS rewritten — next start picks it up.
        mock_state.save_dns_allowlist.assert_called_once_with("demo")

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_rewrites_allowlist_file(
        self, mock_state, mock_get_backend, mock_run,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        _update_dns_quadlet(cfg)

        mock_state.save_dns_allowlist.assert_called_once_with("demo")

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_rejects_invalid_allowlist_and_reverts(
        self, mock_state, mock_get_backend, mock_run,
    ):
        """If ``dnsmasq --test`` rejects the new allowlist, revert and
        surface the parse error rather than SIGHUPing into a silently
        broken state."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        # Previous file content the revert should restore.
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = "server=/old.example.com/1.1.1.1\n"
        mock_state.dns_allowlist_path.return_value = state_path
        # `dnsmasq --test` rejects.
        mock_run.return_value = MagicMock(
            returncode=2, stdout="", stderr="bad config: parse error at line 7",
        )

        result_exit_code = None
        try:
            _update_dns_quadlet(cfg)
        except SystemExit as e:
            result_exit_code = e.code

        assert result_exit_code == 1
        # Previous contents were restored.
        state_path.write_text.assert_called_with(
            "server=/old.example.com/1.1.1.1\n",
        )
        # No SIGHUP — the SIGHUP would re-read the now-reverted file
        # but we don't get there because we sys.exit on rejection.
        kill_calls = [
            c for c in mock_run.call_args_list
            if "kill" in str(c.args[0])
        ]
        assert kill_calls == []


class TestVmBackendLiveReload:
    """On VM (Lima), live-reload works the same way as container backend:
    SIGHUP dnsmasq inside the egress container, let mtime-poll handle
    proxy hot-reload, never touch the cage container. The historical
    Lima reverse-sshfs caching problem is sidestepped by writing the
    config files to a VM-local path (NOT under the cached
    ``~/.config/agentcage`` mount) via ``inst.exec``."""

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_signals_dnsmasq_via_pidfile(
        self, mock_state, mock_get_backend, mock_lima_cls, mock_push,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "egress"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True
        # `dnsmasq --test` returns 0 → publish + SIGHUP.
        inst.exec.return_value = MagicMock(returncode=0, stdout="", stderr="")
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path

        _update_dns_quadlet(cfg)

        # Two podman-exec calls inside the VM: validation + SIGHUP.
        argvs = [c.args[0] for c in inst.exec.call_args_list
                 if isinstance(c.args[0], list)
                 and c.args[0][:2] == ["podman", "exec"]]
        # Validation.
        assert any(a == ["podman", "exec", "demo-egress", "dnsmasq", "--test",
                         "--servers-file=/etc/agentcage/dns-allowlist.conf"]
                   for a in argvs), (
            f"expected dnsmasq --test inside VM; got {argvs}"
        )
        # SIGHUP via pidfile.
        kill_calls = [a for a in argvs if any("kill" in part for part in a)]
        assert kill_calls
        assert "/run/dnsmasq.pid" in kill_calls[0][-1]

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_does_not_stop_or_start_any_unit(
        self, mock_state, mock_get_backend, mock_lima_cls, mock_push,
    ):
        """Cage interactive sessions inside the VM must survive a
        domain add — i.e. NO ``systemctl stop/start`` of any cage
        service. The legacy migration path that used `systemctl restart
        <name>-dns` is gone in v0.22 (there is no dns service)."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "egress"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True
        inst.exec.return_value = MagicMock(returncode=0, stdout="", stderr="")
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path

        _update_dns_quadlet(cfg)

        for call in inst.exec.call_args_list:
            argv = call.args[0] if call.args else []
            if not isinstance(argv, list):
                continue
            # No systemctl stop / start / restart anywhere in the path.
            assert not (argv[:1] == ["systemctl"] and "stop" in argv), (
                f"unexpected systemctl stop call: {argv}"
            )
            assert not (argv[:1] == ["systemctl"] and "start" in argv), (
                f"unexpected systemctl start call: {argv}"
            )
            assert not (argv[:1] == ["systemctl"] and "restart" in argv), (
                f"unexpected systemctl restart call: {argv}"
            )

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_pushes_files_to_vm_local_path(
        self, mock_state, mock_get_backend, mock_lima_cls, mock_push,
    ):
        """Domain edit must write the rewritten host files into the
        VM-local path the egress container actually bind-mounts,
        bypassing the Lima reverse-sshfs cache."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "egress"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True
        inst.exec.return_value = MagicMock(returncode=0, stdout="", stderr="")
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path

        _update_dns_quadlet(cfg)

        # Allowlist file rewritten host-side AND pushed VM-local.
        mock_state.save_dns_allowlist.assert_called_once_with("demo")
        mock_push.assert_called_once_with("demo", inst)

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_skips_signal_when_egress_not_running(
        self, mock_state, mock_get_backend, mock_lima_cls, mock_push,
    ):
        """VM running but egress service stopped: still push files (so
        the next start picks them up) but skip the SIGHUP."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = False  # egress not running
        backend.service_names.return_value = ["cage", "egress"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path

        _update_dns_quadlet(cfg)

        # File push happened (push_config_files runs unconditionally
        # for vm cages once the VM itself is running — the next start
        # mounts the file).
        mock_push.assert_called_once_with("demo", inst)
        # No podman exec — egress isn't running.
        podman_calls = [
            c for c in inst.exec.call_args_list
            if len(c.args) > 0
            and isinstance(c.args[0], list)
            and c.args[0][:2] == ["podman", "exec"]
        ]
        assert podman_calls == []

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_skips_everything_when_vm_not_running(
        self, mock_state, mock_get_backend, mock_lima_cls, mock_push,
    ):
        """VM stopped entirely: host file rewrite is enough — ``cage
        start`` will push and mount on next boot. Don't try to ``inst.exec``
        into a non-running VM."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = False
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = False
        state_path = MagicMock()
        state_path.is_file.return_value = True
        state_path.read_text.return_value = ""
        mock_state.dns_allowlist_path.return_value = state_path

        _update_dns_quadlet(cfg)

        # Allowlist file IS rewritten host-side
        mock_state.save_dns_allowlist.assert_called_once_with("demo")
        # But no VM operations
        mock_push.assert_not_called()
        inst.exec.assert_not_called()


class TestAppleContainerBackendStillRebuilds:
    """The apple-container path is unchanged — its allowlist is baked
    into the wrapper image at build time, so a domain change still
    requires rebuilding the image and restarting the cage. Regression
    guard."""

    @patch("agentcage.cli._is_apple_container", return_value=True)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_apple_container_path_unchanged(
        self, mock_state, mock_get_backend, _mock_is_apple,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("apple-container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        backend.stop.assert_called_once_with("demo")
        backend.build_artifacts.assert_called_once()
        backend.start.assert_called_once()
