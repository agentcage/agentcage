"""Connect-time peer-address validation for policy-API grants.

Every other check in the feature reasons about the NAME: `never_grant`, the
IP-encoding guard, the decider's own judgement. DNS answers the name, and the
answer can change after the grant — so a name-based check cannot close this.

Two concrete cases motivate it:

* **Rebinding.** A domain granted while it resolved somewhere harmless has
  its A record repointed at 169.254.169.254 a second later.
* **No rebinding needed.** `localtest.me` is a real, public, ordinary-looking
  domain whose A record is simply 127.0.0.1. The IP-encoding guard added in
  the previous change does not fire on it — nothing about the *name* is
  suspicious.

Scope matters as much as the check: only GRANT-ONLY hosts are subject to it.
An operator who allowlists an internal mirror on 10.x meant to, and
mitmproxy's own inbound forwarding runs `--mode reverse:http://<cage-ip>`
straight at a private address.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── Stub mitmproxy before importing the addon (same bootstrap the other
# addon tests use: the shipped addon imports mitmproxy, which is not a
# dependency of the CLI package). ────────────────────────
_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []
_mitmproxy.ctx = MagicMock()
_mitmproxy.http = MagicMock()
_proxy = types.ModuleType("mitmproxy.proxy")
_proxy.__path__ = []
_mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
_mitmproxy.proxy = _proxy
_proxy.mode_specs = _mode_specs
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)
sys.modules.setdefault("mitmproxy.proxy", _proxy)
sys.modules.setdefault("mitmproxy.proxy.mode_specs", _mode_specs)
sys.modules["mitmproxy.proxy.mode_specs"].ReverseMode = type("ReverseMode", (), {})

_PROXY_DIR = (
    Path(__file__).resolve().parent.parent
    / "src" / "agentcage" / "data" / "proxy"
)
if str(_PROXY_DIR) not in sys.path:
    sys.path.insert(0, str(_PROXY_DIR))

from addon import Agentcage  # noqa: E402
from inspectors.domain import DomainInspector  # noqa: E402


@pytest.fixture
def inspector():
    dom = DomainInspector()
    dom.configure({"allow": ["registry.npmjs.org", "mirror.corp.example"]})
    dom.granted = {"granted.example.com": {}, "evil.example.org": {}}
    return dom


class TestGrantOnlyScoping:
    """The check must fire for grants and only for grants."""

    def test_granted_host_is_grant_only(self, inspector):
        assert inspector.is_grant_only("granted.example.com")

    def test_subdomain_of_a_grant_is_covered(self, inspector):
        # A grant for example.com covers sub.example.com at L7, so the peer
        # check has to follow the same matching or it is trivially evaded.
        assert inspector.is_grant_only("api.granted.example.com")

    def test_baseline_domain_is_not_grant_only(self, inspector):
        # The operator chose this one; an internal mirror here is legitimate.
        assert not inspector.is_grant_only("mirror.corp.example")
        assert not inspector.is_grant_only("registry.npmjs.org")

    def test_unrelated_host_is_not_grant_only(self, inspector):
        assert not inspector.is_grant_only("example.net")

    def test_baseline_wins_when_a_host_matches_both(self, inspector):
        """Operator intent beats an auto-grant for the same name."""
        inspector.granted["mirror.corp.example"] = {}
        assert not inspector.is_grant_only("mirror.corp.example")


class TestNonGlobalDetection:
    def _fn(self):
        return Agentcage._non_global_ip

    @pytest.mark.parametrize("addr", [
        "169.254.169.254",          # cloud metadata
        "127.0.0.1",                # loopback — localtest.me
        "10.0.0.5", "192.168.1.1", "172.16.0.1",   # RFC1918
        "100.64.0.1",               # CGNAT
        "::1",                      # v6 loopback
        "fd00::1",                  # v6 ULA
        "fe80::1%eth0",             # v6 link-local with scope
        "::ffff:169.254.169.254",   # v4-mapped metadata
    ])
    def test_non_global_detected(self, addr):
        assert self._fn()(addr) is not None, addr

    @pytest.mark.parametrize("addr", [
        "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111",
    ])
    def test_global_allowed(self, addr):
        assert self._fn()(addr) is None, addr

    def test_hostname_is_not_judged(self):
        # Before mitmproxy resolves, address[0] is a name. Nothing to say yet.
        assert self._fn()("registry.npmjs.org") is None

    def test_accepts_the_peername_tuple_shape(self):
        assert self._fn()(("169.254.169.254", 443)) == "169.254.169.254"

    def test_v4_mapped_is_unwrapped_not_laundered(self):
        """An IPv4 target over a v6 socket must not slip past."""
        assert self._fn()("::ffff:127.0.0.1") == "127.0.0.1"


class TestGuardBehaviour:
    def _addon(self, inspector):
        a = Agentcage.__new__(Agentcage)
        a.inspectors = [inspector]
        a._audit_file = None
        a._peer_dns_cache = {}
        a._poisoned_peers = set()
        return a

    def _data(self, host, peer):
        server = MagicMock()
        server.address = (host, 443)
        server.peername = (peer, 443) if peer else None
        server.sni = None
        server.error = None
        return types.SimpleNamespace(server=server, client=MagicMock())

    def test_granted_host_on_metadata_ip_is_refused(self, inspector):
        a = self._addon(inspector)
        d = self._data("granted.example.com", "169.254.169.254")
        a.server_connected(d)
        assert d.server.error and "169.254.169.254" in d.server.error

    def test_granted_host_on_loopback_is_refused(self, inspector):
        """The localtest.me case — an ordinary name, a loopback answer."""
        a = self._addon(inspector)
        d = self._data("granted.example.com", "127.0.0.1")
        a.server_connected(d)
        assert d.server.error

    def test_baseline_host_on_private_ip_is_allowed(self, inspector):
        """An operator's internal mirror must keep working."""
        a = self._addon(inspector)
        d = self._data("mirror.corp.example", "10.0.0.5")
        a.server_connected(d)
        assert d.server.error is None

    def test_inbound_reverse_mode_to_the_cage_is_allowed(self, inspector):
        """mitmproxy connects to the cage's private IP on purpose."""
        a = self._addon(inspector)
        d = self._data("10.89.0.20", "10.89.0.20")
        a.server_connected(d)
        assert d.server.error is None

    def test_granted_host_on_public_ip_is_allowed(self, inspector):
        a = self._addon(inspector)
        d = self._data("granted.example.com", "93.184.216.34")
        a.server_connected(d)
        assert d.server.error is None

    def test_sni_is_considered_for_tls_flows(self, inspector):
        a = self._addon(inspector)
        d = self._data("93.184.216.34", "127.0.0.1")
        d.server.sni = "granted.example.com"
        a.server_connected(d)
        assert d.server.error

    def test_no_grants_means_no_work(self, inspector):
        inspector.granted = {}
        a = self._addon(inspector)
        d = self._data("anything.example.com", "127.0.0.1")
        a.server_connected(d)
        assert d.server.error is None

    def test_server_connect_catches_a_literal_address(self, inspector):
        """Refuse before the socket opens when the target is already an IP."""
        a = self._addon(inspector)
        a._resolve_all = lambda host: []   # no real DNS in tests
        server = MagicMock()
        server.address = ("169.254.169.254", 80)
        server.peername = None
        server.sni = "granted.example.com"
        server.error = None
        a.server_connect(types.SimpleNamespace(server=server, client=MagicMock()))
        assert server.error

    def test_guard_never_raises_into_the_proxy(self, inspector):
        """A bug here must not take the proxy down with it."""
        a = self._addon(inspector)
        a.server_connected(types.SimpleNamespace(server=None, client=None))
        a.server_connected(object())  # no .server at all


class TestServerConnectIsTheEnforcementPoint:
    """`server_connect` is the ONLY hook that can abort the connection.

    mitmproxy reads `connection.error` after it and skips connecting; after
    `ServerConnectedHook` it proceeds unconditionally, so a verdict reached
    there cannot stop the in-flight request. Verified against mitmproxy
    12.2.1's proxy/server.py — and observed live: a guard that only ran at
    server_connected audited the block while curl still got a 200.
    """

    def _addon(self, inspector, answers):
        a = Agentcage.__new__(Agentcage)
        a.inspectors = [inspector]
        a._audit_file = None
        a._peer_dns_cache = {}
        a._poisoned_peers = set()
        a._resolve_all = lambda host: answers
        return a

    def _data(self, host):
        server = MagicMock()
        server.address = (host, 443)
        server.peername = None
        server.sni = None
        server.error = None
        return types.SimpleNamespace(server=server, client=MagicMock())

    def test_refuses_before_connecting_when_resolution_is_private(self, inspector):
        a = self._addon(inspector, ["127.0.0.1"])
        d = self._data("granted.example.com")
        a.server_connect(d)
        assert d.server.error and "127.0.0.1" in d.server.error

    def test_every_answer_is_checked_not_just_the_first(self, inspector):
        """Rebinding payloads return a public answer beside the internal one."""
        a = self._addon(inspector, ["93.184.216.34", "169.254.169.254"])
        d = self._data("granted.example.com")
        a.server_connect(d)
        assert d.server.error and "169.254.169.254" in d.server.error

    def test_public_resolution_connects_normally(self, inspector):
        a = self._addon(inspector, ["93.184.216.34"])
        d = self._data("granted.example.com")
        a.server_connect(d)
        assert d.server.error is None

    def test_baseline_host_is_never_resolved_or_refused(self, inspector):
        """No lookup at all for operator-chosen domains."""
        called = []
        a = self._addon(inspector, [])
        a._resolve_all = lambda h: called.append(h) or ["10.0.0.5"]
        d = self._data("mirror.corp.example")
        a.server_connect(d)
        assert d.server.error is None
        assert called == [], "baseline hosts must not trigger a lookup"

    def test_a_caught_host_is_poisoned_for_later_requests(self, inspector):
        a = self._addon(inspector, ["127.0.0.1"])
        a.server_connect(self._data("granted.example.com"))
        assert "granted.example.com" in a._poisoned_peers
