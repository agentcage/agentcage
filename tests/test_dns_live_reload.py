"""Tests for live-reload of the dnsmasq allowlist via _update_dns_quadlet.

A domain add/rm must not restart the cage container — interactive sessions
inside the cage (e.g. ``agentcage run``) need to survive a config update.

v0.22 shape (cage + egress):
  - Container backend: validate the new allowlist via ``dnsmasq --test
    --servers-file=<allowlist>`` run inside the egress container, then
    raise the egress supervisor's reload flag (``: > /home/acproxy/dns/reload``)
    when the runtime servers-file exists so the supervisor re-renders
    BASELINE+GRANTED and SIGHUPs within ~1s; in fallback mode (no runtime
    servers-file) SIGHUP dnsmasq via the pidfile the supervisor writes at
    ``/home/acdns/dnsmasq.pid``. Both steps use ``podman exec
    <name>-egress …``.
  - VM backend: same shape, wrapped in ``limactl shell <vm> -- podman
    exec <name>-egress …``. Lima's reverse-sshfs caching is sidestepped
    by writing the rewritten host files into the VM-local mount path
    first (``push_config_files`` in agentcage.backends.vm).
  - Apple-container backend: allowlist is image-baked, so the path
    stays "stop + rebuild + start". Unchanged.

The host does NOT regenerate the runtime servers-file from the baseline:
that would strip every in-flight policy-API granted zone out of dnsmasq's
servers-file on every edit (the round-11 review finding). The supervisor's
``_render_servers_file`` is the single implementation of the rewrite.

The pidfile lives under acdns's pre-chowned home dir (set up at image
build time in Containerfile.egress) instead of /run because /run is a
fresh tmpfs at container start. The earlier /run/agentcage path needed
a runtime ``chown acdns:acdns`` which required CAP_CHOWN; rootless
podman setups with ``default_capabilities = []`` in containers.conf
drop that and the supervisor died on the first chown call.

``kill -HUP $(cat /home/acdns/dnsmasq.pid)`` (fallback branch) rather than
``pkill -HUP dnsmasq`` because the supervisor uses ``setpriv --reuid=acdns`` —
pkill from the supervisor's process tree wouldn't find dnsmasq, and
``podman kill --signal HUP`` would hit tini at PID 1. The pidfile is
the reliable handle.
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
        # Pidfile lives under acdns's pre-chowned home dir
        # (/home/acdns/dnsmasq.pid) — eliminates the runtime CAP_CHOWN
        # dependency that the earlier /run/agentcage location had.
        assert "/home/acdns/dnsmasq.pid" in last_arg
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
        # SIGHUP via pidfile (under acdns's pre-chowned home dir).
        kill_calls = [a for a in argvs if any("kill" in part for part in a)]
        assert kill_calls
        assert "/home/acdns/dnsmasq.pid" in kill_calls[0][-1]

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


class TestAppleContainerBackendLiveReloads:
    """apple-container now live-reloads domain changes too: the egress
    bind-mounts the rendered allowlist, so a domain edit re-renders +
    SIGHUPs dnsmasq via ``backend.reload_domains`` — NO image rebuild and
    NO cage stop/start (an interactive session survives). Regression guard
    against the old rebuild path."""

    @patch("agentcage.cli._is_apple_container", return_value=True)
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_apple_container_path_live_reloads(
        self, mock_state, mock_get_backend, _mock_is_apple,
    ):
        from agentcage.cli import _update_dns_quadlet
        cfg = _mock_cfg("apple-container")
        backend = MagicMock()
        backend.is_running.return_value = True
        mock_get_backend.return_value = backend

        _update_dns_quadlet(cfg)

        # Live reload, not rebuild: reload_domains is called and the cage
        # is never stopped/rebuilt/started.
        backend.reload_domains.assert_called_once_with(cfg, "demo")
        backend.stop.assert_not_called()
        backend.build_artifacts.assert_not_called()
        backend.start.assert_not_called()


# ---------------------------------------------------------------------------
# Linux (container/vm) transparent host-tracking DNS via the default-route
# gateway — matches the apple-container vmnet-gateway behavior.
# ---------------------------------------------------------------------------
def _read_src(*parts):
    from pathlib import Path
    return (Path(__file__).resolve().parent.parent
            / "src" / "agentcage").joinpath(*parts).read_text()


def test_supervisor_container_path_forwards_to_default_route_gateway():
    """The container/vm egress dnsmasq forwards allowlisted zones to the
    runtime DEFAULT-ROUTE gateway (host-tracking, like the apple vmnet
    gateway) IN ADDITION to the baked cfg.dns_servers, with --all-servers so
    a degraded gateway falls back instantly. Derived from the default route
    (NOT eth0-subnet .1): the Linux egress is dual-homed and <name>-net is
    internal."""
    s = _read_src("data", "containers", "supervisor-egress.sh")
    assert "ip route 2>/dev/null | awk '/^default/{print $3; exit}'" in s
    # The gateway rewrite now lives in _render_servers_file (so the same
    # recipe can be re-run when the addon publishes a grant), parameterised
    # over $SERVERS_BASE rather than the literal bind-mount path. Same
    # behavior: gateway-rewritten lines first, baked resolver lines kept.
    assert 'sed "s#/[^/]*\\$#/$_SF_GW#" \\\n        "$SERVERS_BASE"' in s \
        or 'sed "s#/[^/]*\\$#/$_SF_GW#" "$SERVERS_BASE"' in s
    assert 'SERVERS_BASE=/etc/agentcage/dns-allowlist.conf' in s
    assert '_SF_STYLE=prepend' in s
    assert "/run/agentcage/dns-allowlist.egress.conf" in s
    assert '_all_servers="--all-servers"' in s
    assert "$_all_servers" in s
    # --all-servers is UNCONDITIONAL (not gated on deriving a gateway): dnsmasq
    # must prefer a positive answer over a public resolver's NXDOMAIN so a
    # split-horizon apex resolves, and mitmproxy now resolves through this
    # dnsmasq, so the correctness must hold even when no gateway is derived.
    assert '_all_servers=""' not in s


def test_supervisor_points_mitmproxy_resolver_at_local_dnsmasq():
    """mitmproxy re-resolves the upstream SNI/Host, so its OWN resolver
    (/etc/resolv.conf) must track the host AND resolve split-horizon names.
    The supervisor rebuilds it each start to point at the egress's local
    dnsmasq (the cage-facing DNS_LISTEN_IP), which forwards to the
    default-route gateway + baked dns_servers in parallel (--all-servers) and
    prefers a positive answer — so a public resolver's NXDOMAIN can't shadow a
    split-horizon apex and a dead gateway adds no latency. A flat resolv.conf
    of upstream nameservers cannot: glibc getaddrinfo queries them
    sequentially and stops at the first definitive answer (NXDOMAIN included).
    Requires the rw resolv bind."""
    s = _read_src("data", "containers", "supervisor-egress.sh")
    # resolv.conf is a single nameserver pointing at the local dnsmasq
    # (loopback when DNS_LISTEN_IP is the 0.0.0.0 wildcard).
    assert '_resolver_ip="$DNS_LISTEN_IP"' in s
    assert 'echo "nameserver $_resolver_ip"' in s
    assert "> /etc/resolv.conf" in s
    # Regression guard (split-DNS): mitmproxy's resolv.conf must NOT be rebuilt
    # as a flat list of upstream nameservers again. The old code wrote
    # `nameserver $_gw` + the dns_servers piped through `sort -u`; the sort
    # reordered the operator's deliberate dns_servers order (a public
    # NXDOMAIN-ing resolver could sort ahead of a split-horizon one) and broke
    # MagicDNS-homed cages.
    assert 'echo "nameserver $_gw"' not in s
    assert "dns-allowlist.conf | sort" not in s
    # egress.container.j2 must mount resolv.conf rw so the supervisor can rewrite it
    j2 = _read_src("templates", "egress.container.j2")
    assert "resolv-egress-{{ name }}.conf:/etc/resolv.conf:rw,Z" in j2
    assert ":/etc/resolv.conf:ro,Z" not in j2


def test_update_dns_quadlet_raises_supervisor_reload_flag_for_linux():
    """Live `domain add/rm` on container/vm must NOT regenerate the gateway-
    rewritten runtime servers-file from the baseline on the host — that would
    strip every in-flight policy-API granted zone out of dnsmasq's servers-file
    on every edit (the round-11 review finding). Instead the host raises the
    egress supervisor's reload flag (``: > /home/acproxy/dns/reload``); the
    supervisor's 1s liveness loop re-renders BASELINE+GRANTED and SIGHUPs.
    In fallback mode (no runtime servers-file) it SIGHUPs via the pidfile."""
    import inspect
    from agentcage.cli import _update_dns_quadlet
    src = inspect.getsource(_update_dns_quadlet)
    assert "/run/agentcage/dns-allowlist.egress.conf" in src
    # The host NO LONGER writes the runtime servers-file from the baseline.
    assert 'sed "s#/[^/]*' not in src, (
        "host must not regenerate the runtime servers-file from the baseline "
        "(would clobber in-flight granted zones)"
    )
    assert 'cat /etc/agentcage/dns-allowlist.conf; } > "$rt"' not in src
    # It raises the supervisor's reload flag, guarded on $rt existing.
    assert ': > /home/acproxy/dns/reload' in src
    assert 'if [ -f "$rt" ]' in src
    # Fallback branch still SIGHUPs via the pidfile.
    assert 'kill -HUP' in src
    assert '/home/acdns/dnsmasq.pid' in src


class TestSupervisorFlagReload:
    """The host-side sh -c raises the supervisor's reload flag instead of
    regenerating the runtime servers-file from the baseline (which would
    clobber in-flight granted zones). Behavioral assertions on the actual
    ``podman exec … sh -c`` argv emitted by ``_update_dns_quadlet``."""

    @staticmethod
    def _sh_c_argv(mock_run):
        """Return the single sh -c script string emitted, or None."""
        for call in mock_run.call_args_list:
            argv = call.args[0]
            if isinstance(argv, list) and argv[:3] == ["podman", "exec", "demo-egress"]:
                # ["podman","exec","demo-egress","sh","-c", <script>]
                if "sh" in argv and "-c" in argv:
                    idx = argv.index("-c")
                    if idx + 1 < len(argv):
                        return argv[idx + 1]
        return None

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_sh_c_raises_reload_flag_guarded_on_rt(
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

        script = self._sh_c_argv(mock_run)
        assert script is not None, "no sh -c invocation found"
        # The flag raise, guarded on $rt existing.
        assert 'rt=/run/agentcage/dns-allowlist.egress.conf' in script
        assert 'if [ -f "$rt" ]' in script
        assert ': > /home/acproxy/dns/reload' in script
        # The host MUST NOT write $rt from the baseline (would clobber grants).
        assert 'sed "s#/[^/]*' not in script
        assert '> "$rt"' not in script
        assert 'cat /etc/agentcage/dns-allowlist.conf' not in script

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_sh_c_fallback_branch_sighups_via_pidfile(
        self, mock_state, mock_get_backend, mock_run,
    ):
        """The else (fallback) branch still SIGHUPs via the pidfile so a
        no-gateway cage reloads its bind-mounted allowlist directly."""
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

        script = self._sh_c_argv(mock_run)
        assert script is not None
        # else branch: pidfile SIGHUP.
        assert 'else' in script
        assert '/home/acdns/dnsmasq.pid' in script
        assert 'kill -HUP "$pid"' in script


class TestDestroyCleansLegacyWatcher:
    """``cage destroy`` removes the legacy host-side grants-watcher
    artifacts (pre-rework cages) before stopping the cage, so an upgraded
    cage doesn't leave a crash-looping unit/plist behind."""

    @patch("agentcage.cli._destroy_cage")
    @patch("agentcage.cli.state")
    def test_destroy_calls_remove_legacy_grants_watcher(
        self, mock_state, mock_destroy,
    ):
        from click.testing import CliRunner
        from agentcage.cli import main
        from agentcage import legacy_watcher

        mock_state.deployment_exists.return_value = True
        cfg = MagicMock()
        cfg.name = "demo"
        cfg.isolation = "vm"
        mock_state.load_deployment_config.return_value = cfg
        mock_destroy.return_value = ["state:demo"]

        called = []

        def _fake_remove(name, isolation=""):
            called.append((name, isolation))

        # Patch where the destroy flow imports it: the source module, so the
        # lazy ``from agentcage.legacy_watcher import remove_legacy_grants_watcher``
        # picks up the stub.
        with patch.object(
            legacy_watcher, "remove_legacy_grants_watcher", _fake_remove,
        ):
            result = CliRunner().invoke(main, ["cage", "destroy", "demo", "-y"])

        assert result.exit_code == 0, result.output
        assert called == [("demo", "vm")]
        mock_destroy.assert_called_once()

    @patch("agentcage.cli._destroy_cage")
    @patch("agentcage.cli.state")
    def test_destroy_skips_cleanup_when_cage_missing(
        self, mock_state, mock_destroy,
    ):
        """A cage that was never created has no watcher artifacts and no
        stored config — cleanup must be skipped, not crash destroy."""
        from click.testing import CliRunner
        from agentcage.cli import main
        from agentcage import legacy_watcher

        mock_state.deployment_exists.return_value = False
        mock_destroy.return_value = []

        called = []
        with patch.object(
            legacy_watcher, "remove_legacy_grants_watcher",
            lambda *a, **k: called.append(a),
        ):
            result = CliRunner().invoke(main, ["cage", "destroy", "ghost", "-y"])

        assert result.exit_code == 0, result.output
        assert called == []  # nothing to clean
        mock_destroy.assert_called_once()
