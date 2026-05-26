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


class TestVmBackendKeepsLegacyRestart:
    """On VM (Lima), live-reload via SIGHUP would not actually take effect:
    Lima's reverse-sshfs mount caches host file contents, so dnsmasq inside
    the VM would re-read the same stale bytes regardless of signal. The
    legacy restart-all behavior had the same limitation but is documented
    and what existing users expect, so we keep it. Regression guard: a
    domain add on a running VM cage still issues a stop/start cycle of
    all infra services."""

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_restarts_all_services(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = True
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        mock_get_backend.return_value = backend
        inst = mock_lima_cls.return_value

        _update_dns_quadlet(cfg)

        # Stops cage, proxy, dns (in that order); starts dns, proxy, cage.
        argv_list = [c.args[0] for c in inst.exec.call_args_list]
        stops = [a for a in argv_list if "stop" in a]
        starts = [a for a in argv_list if "start" in a]
        assert ["systemctl", "--user", "stop", "demo-cage.service"] in stops
        assert ["systemctl", "--user", "stop", "demo-proxy.service"] in stops
        assert ["systemctl", "--user", "stop", "demo-dns.service"] in stops
        assert ["systemctl", "--user", "start", "demo-dns.service"] in starts
        assert ["systemctl", "--user", "start", "demo-proxy.service"] in starts
        assert ["systemctl", "--user", "start", "demo-cage.service"] in starts

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_skips_restart_when_dns_not_running(
        self, mock_state, mock_get_backend, _mock_ensure, mock_lima_cls,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("vm")
        backend = MagicMock()
        backend.is_running.return_value = False
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        mock_lima_cls.assert_not_called()
        mock_state.save_dns_allowlist.assert_called_once_with("demo")


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
