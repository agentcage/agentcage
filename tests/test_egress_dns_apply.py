"""Egress-local DNS apply: the addon publishes, the supervisor renders.

Covers the mechanism that replaced the host-side grants watcher. See
``docs/explain/egress-local-dns-apply.md``.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = (
    REPO_ROOT / "src" / "agentcage" / "data" / "containers" / "supervisor-egress.sh"
).read_text()
CONTAINERFILE = (
    REPO_ROOT / "src" / "agentcage" / "data" / "containers" / "Containerfile.egress"
).read_text()


class TestSupervisorAppliesGrants:
    """The supervisor renders + reloads from its existing liveness loop."""

    def test_monitor_loop_watches_the_published_list(self):
        # The whole point: no new process, no new service. The check rides
        # the loop that already polls both children for liveness.
        assert 'while kill -0 "$DNSMASQ_PID"' in SUPERVISOR
        assert '[ "$GRANTED_DOMAINS" -nt "$SERVERS_OUT" ]' in SUPERVISOR

    def test_sighup_targets_the_pidfile_not_the_wrapper(self):
        """Regression: SIGHUPing $DNSMASQ_PID kills the whole egress.

        dnsmasq runs under dns-audit.sh, so $DNSMASQ_PID is that WRAPPER's
        pid — and SIGHUP is fatal to a plain shell. Signalling it kills the
        wrapper, the liveness poll sees a dead child, and the container
        exits. Observed against a live cage before the fix.
        """
        assert '_hup_pid=$(cat "$DNSMASQ_PID_FILE"' in SUPERVISOR
        assert 'kill -HUP "$_hup_pid"' in SUPERVISOR
        assert 'kill -HUP "$DNSMASQ_PID"' not in SUPERVISOR

    def test_render_is_atomic(self):
        # dnsmasq must never read a half-written servers-file, and the
        # `-nt` gate must flip exactly once per completed render.
        assert '_sf_tmp="${SERVERS_OUT}.tmp"' in SUPERVISOR
        assert 'mv -f "$_sf_tmp" "$SERVERS_OUT"' in SUPERVISOR

    def test_baseline_is_read_only_and_rebuilt_each_render(self):
        # A grant is strictly additive: the rendered file is always
        # baseline-then-grants, regenerated from the read-only bind mount,
        # so a grant can never delete or repoint an operator zone.
        assert "SERVERS_BASE=/etc/agentcage/dns-allowlist.conf" in SUPERVISOR
        assert "SERVERS_OUT=/run/agentcage/dns-allowlist.egress.conf" in SUPERVISOR
        base_i = SUPERVISOR.index('cat "$SERVERS_BASE" >> "$_sf_tmp"')
        grants_i = SUPERVISOR.index('if [ -s "$GRANTED_DOMAINS" ]')
        assert base_i < grants_i, "baseline must be emitted before grants"

    def test_supervisor_chooses_the_upstream_not_the_addon(self):
        """The addon names a zone; the supervisor routes it.

        The published file holds bare domain names. If the addon could emit
        `server=` directives it could point a zone at a resolver it
        controls, which is strictly more authority than deciding grants.
        """
        assert "printf 'server=/%s/%s\\n' \"$_sf_dom\" \"$_sf_up\"" in SUPERVISOR
        # ...and the shell re-validates the name as a second gate.
        assert "grep -E '^[a-z0-9]" in SUPERVISOR

    def test_granted_upstreams_do_not_come_from_the_baseline(self):
        """Under full default-deny the baseline is EMPTY.

        Scraping upstreams out of the rendered baseline would mean a grant
        could never resolve on exactly the cage the feature exists for.
        """
        assert "AGENTCAGE_DNS_UPSTREAMS" in SUPERVISOR

    def test_runtime_servers_file_is_always_rendered(self):
        # Both branches must end up on the writable /run path; pointing
        # dnsmasq at the read-only bind mount would make a grant
        # unappliable without a restart.
        assert SUPERVISOR.count("_render_servers_file") >= 4
        assert '--servers-file="$SERVERS_OUT"' in SUPERVISOR


class TestPublishDirIsPreChowned:
    def test_image_creates_an_acproxy_owned_dir(self):
        """No runtime chown: hardened rootless podman drops CAP_CHOWN.

        Same reason /home/acdns is pre-chowned in an image layer.
        """
        assert "mkdir -p /home/acproxy/dns" in CONTAINERFILE
        assert "chown acproxy:acproxy /home/acproxy/dns" in CONTAINERFILE


class TestAddonPublishesDomains:
    """The addon side of the handshake."""

    def _api(self, tmp_path, granted):
        from agentcage.data.proxy import policy_api as pa
        api = pa.PolicyApi.__new__(pa.PolicyApi)
        api._dns_publish_path = str(tmp_path / "dns" / "granted")
        api._log = MagicMock()
        api.dom = MagicMock()
        api.dom.granted = granted
        return api

    def test_publishes_sorted_domain_names(self, tmp_path):
        api = self._api(tmp_path, {"b.example.com": {}, "a.example.com": {}})
        api._publish_dns_domains()
        out = Path(api._dns_publish_path).read_text()
        assert out == "a.example.com\nb.example.com\n"

    def test_drops_anything_that_is_not_a_hostname(self, tmp_path):
        """Defense in depth against a malformed in-memory entry.

        A newline-bearing entry would otherwise render as a split dnsmasq
        directive once the supervisor expands it.
        """
        api = self._api(tmp_path, {
            "good.example.com": {},
            "evil.com\nserver=/hijack.com/1.2.3.4": {},
            "not a domain": {},
            "": {},
        })
        api._publish_dns_domains()
        assert Path(api._dns_publish_path).read_text() == "good.example.com\n"

    def test_empty_grant_set_publishes_an_empty_file(self, tmp_path):
        # Not "no file": the supervisor keys off mtime, so a revoke has to
        # be observable as a change too.
        api = self._api(tmp_path, {})
        api._publish_dns_domains()
        assert Path(api._dns_publish_path).read_text() == ""

    def test_publish_failure_is_not_fatal(self, tmp_path):
        """A grant is already enforced at L7; only DNS lags."""
        api = self._api(tmp_path, {"a.example.com": {}})
        api._dns_publish_path = "/proc/nonexistent/granted"
        api._publish_dns_domains()  # must not raise
        assert api._log.warn.called


class TestWatcherIsGone:
    """The host-side watcher must leave no residue."""

    def test_no_watcher_module(self):
        assert not (REPO_ROOT / "src" / "agentcage" / "watcher.py").exists()

    def test_no_grants_unit_is_generated(self):
        from agentcage import quadlets
        assert not hasattr(quadlets, "_grants_service_unit")

    def test_no_installer_in_the_cli(self):
        from agentcage import cli
        assert not hasattr(cli, "_ensure_grants_watcher")

    def test_backends_expose_no_grants_supervisor_hooks(self):
        from agentcage.backends.container import ContainerBackend
        from agentcage.backends.vm import VmBackend
        for backend in (ContainerBackend, VmBackend):
            assert not hasattr(backend, "grants_unit_path"), backend
