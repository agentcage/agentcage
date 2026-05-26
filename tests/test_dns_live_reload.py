"""Tests for live-reload of the dnsmasq allowlist via _update_dns_quadlet.

A domain add/rm must not restart the cage container — interactive sessions
inside the cage (e.g. ``agentcage run``) need to survive a config update.

Container backend: SIGHUP dnsmasq via ``podman exec ... pkill -HUP dnsmasq``;
                   proxy hot-reloads via mtime poll.
VM backend:        same, routed through ``limactl shell -- podman exec ...``.
Apple-container:   image bake — must rebuild + restart (no bind-mount yet).

Why pkill instead of `podman kill --signal HUP`: the dns container's PID 1
is dns-audit.sh (the audit-log wrapper), not dnsmasq. A signal to PID 1
would be eaten by the wrapper. pkill targets the dnsmasq process directly.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _mock_cfg(isolation: str, name: str = "demo") -> MagicMock:
    cfg = MagicMock()
    cfg.isolation = isolation
    cfg.name = name
    return cfg


class TestContainerBackendLiveReload:
    """On the container (rootless podman) backend, a domain change SIGHUPs
    the dnsmasq sidecar — the proxy addon hot-reloads via mtime poll, and
    the cage container is never touched."""

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_signals_dnsmasq_via_pkill(
        self, mock_state, mock_get_backend, _mock_ensure, mock_podman_cls,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend
        podman = mock_podman_cls.return_value

        _update_dns_quadlet(cfg)

        # pkill -HUP dnsmasq runs inside the dns container — not a
        # `podman kill --signal HUP` (which would hit dns-audit.sh PID 1)
        # and not a stop_unit/start_unit of the cage.
        podman.container_exec.assert_called_once_with(
            "demo-dns", ["pkill", "-HUP", "dnsmasq"],
        )

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_does_not_stop_or_start_any_unit(
        self, mock_state, mock_get_backend, _mock_ensure,
        _mock_podman_cls, mock_systemd,
    ):
        """Cage interactive sessions must survive a domain add — i.e. NO
        systemctl stop/start of {name}-cage.service, -proxy.service, or
        -dns.service."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        mock_systemd.stop_unit.assert_not_called()
        mock_systemd.start_unit.assert_not_called()

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_skips_signal_when_dns_not_running(
        self, mock_state, mock_get_backend, _mock_ensure, mock_podman_cls,
    ):
        """If the cage isn't running, the file is rewritten but no signal
        is sent — there's no dnsmasq to reload."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = False
        mock_get_backend.return_value = backend
        podman = mock_podman_cls.return_value

        _update_dns_quadlet(cfg)

        podman.container_exec.assert_not_called()
        # Allowlist file IS rewritten — next start picks it up
        mock_state.save_dns_allowlist.assert_called_once_with("demo")

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_rewrites_allowlist_file(
        self, mock_state, mock_get_backend, _mock_ensure, _mock_podman_cls,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        mock_state.save_dns_allowlist.assert_called_once_with("demo")


class TestVmBackendLiveReload:
    """On VM (Lima), live-reload works the same way as container backend:
    SIGHUP dnsmasq, let mtime-poll handle proxy hot-reload, never touch
    the cage container. The historical Lima reverse-sshfs caching problem
    is sidestepped by writing the config files to a VM-local path (NOT
    under the cached ``~/.config/agentcage`` mount) via ``inst.exec``."""

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current", return_value=False)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_signals_dnsmasq_via_pkill(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
        mock_push,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True

        _update_dns_quadlet(cfg)

        # Exactly one podman-exec pkill call to the dns sidecar.
        pkill_calls = [
            c for c in inst.exec.call_args_list
            if len(c.args) > 0
            and isinstance(c.args[0], list)
            and c.args[0][:2] == ["podman", "exec"]
            and "pkill" in c.args[0]
        ]
        assert len(pkill_calls) == 1
        assert pkill_calls[0].args[0] == [
            "podman", "exec", "demo-dns", "pkill", "-HUP", "dnsmasq",
        ]

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current", return_value=False)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_does_not_stop_or_start_any_unit(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
        mock_push,
    ):
        """Cage interactive sessions inside the VM must survive a domain
        add — i.e. NO ``systemctl stop/start`` of any cage service."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True

        _update_dns_quadlet(cfg)

        for call in inst.exec.call_args_list:
            argv = call.args[0] if call.args else []
            if not isinstance(argv, list):
                continue
            # No systemctl stop / start anywhere in the live-reload path.
            assert not (argv[:1] == ["systemctl"] and "stop" in argv), (
                f"unexpected systemctl stop call: {argv}"
            )
            assert not (argv[:1] == ["systemctl"] and "start" in argv), (
                f"unexpected systemctl start call: {argv}"
            )

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current", return_value=False)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_pushes_files_to_vm_local_path(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
        mock_push,
    ):
        """Domain edit must write the rewritten host files into the VM-local
        path the proxy/dns containers actually bind-mount, bypassing the
        Lima reverse-sshfs cache."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True

        _update_dns_quadlet(cfg)

        # Allowlist file rewritten host-side AND pushed VM-local.
        mock_state.save_dns_allowlist.assert_called_once_with("demo")
        mock_push.assert_called_once_with("demo", inst)

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current", return_value=False)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_skips_signal_when_dns_not_running(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
        mock_push,
    ):
        """VM running but dns service stopped: still push files (so the
        next start picks them up) but skip the SIGHUP."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = False  # dns not running
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True

        _update_dns_quadlet(cfg)

        # File push happened
        mock_push.assert_called_once_with("demo", inst)
        # No pkill — dnsmasq isn't running
        pkill_calls = [
            c for c in inst.exec.call_args_list
            if len(c.args) > 0
            and isinstance(c.args[0], list)
            and "pkill" in c.args[0]
        ]
        assert pkill_calls == []

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current", return_value=False)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_skips_everything_when_vm_not_running(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
        mock_push,
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

        _update_dns_quadlet(cfg)

        # Allowlist file IS rewritten host-side
        mock_state.save_dns_allowlist.assert_called_once_with("demo")
        # But no VM operations
        mock_push.assert_not_called()
        inst.exec.assert_not_called()

    @patch("agentcage.backends.vm.push_config_files")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current", return_value=True)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_migration_restarts_dns_when_quadlet_rewritten(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
        mock_push,
    ):
        """One-shot migration: on a pre-upgrade VM cage the on-disk
        quadlet still bind-mounts the cached host path. After
        ``_ensure_dns_quadlet_current`` rewrites the unit to the new
        VM-local shape, the *running* dnsmasq container is still mounting
        the old path — SIGHUP would re-read the stale cache. Restart the
        dns sidecar so it picks up the new mount; every subsequent edit
        on this cage takes the fast SIGHUP path."""
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value
        inst.is_running.return_value = True

        _update_dns_quadlet(cfg)

        # systemctl restart of ONLY the dns service — not proxy, not cage.
        restart_calls = [
            c for c in inst.exec.call_args_list
            if len(c.args) > 0
            and isinstance(c.args[0], list)
            and c.args[0][:3] == ["systemctl", "--user", "restart"]
        ]
        assert len(restart_calls) == 1
        assert restart_calls[0].args[0] == [
            "systemctl", "--user", "restart", "demo-dns.service",
        ]
        # And no SIGHUP — the restart supersedes it on the migration
        # path (the new container picks up the new mount on the way up).
        pkill_calls = [
            c for c in inst.exec.call_args_list
            if len(c.args) > 0
            and isinstance(c.args[0], list)
            and "pkill" in c.args[0]
        ]
        assert pkill_calls == []


class TestAppleContainerBackendStillRebuilds:
    """The apple-container path is unchanged — its allowlist is baked into
    the wrapper image at build time, so a domain change still requires
    rebuilding the image and restarting the cage. Regression guard."""

    @patch("agentcage.cli._is_apple_container", return_value=True)
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_apple_container_path_unchanged(
        self, mock_state, mock_get_backend, _mock_ensure, _mock_is_apple,
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
