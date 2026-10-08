"""Egress-local DNS apply — the addon side of the handshake.

Split out of ``tests/test_egress_dns_apply.py`` (RUST-PORT-PLAN.md §2.4):
``policy_api`` publishes the granted-domain list that the egress supervisor
renders into dnsmasq. Both ends are inside the egress container and stay
Python; the host-side and image-side assertions stayed behind. Test names are
unchanged so failures stay greppable against history.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock


class TestAddonPublishesDomains:
    """The addon side of the handshake."""

    def _api(self, tmp_path, granted):
        from agentcage.data.proxy import policy_api as pa
        api = pa.PolicyApi.__new__(pa.PolicyApi)
        api._dns_publish_path = str(tmp_path / "dns" / "granted")
        api._dns_reload_path = str(tmp_path / "dns" / "reload")
        api._log = MagicMock()
        api.dom = MagicMock()
        api.dom.granted = granted
        return api

    def test_publishes_sorted_domain_names(self, tmp_path):
        api = self._api(tmp_path, {"b.example.com": {}, "a.example.com": {}})
        api._publish_dns_domains()
        out = Path(api._dns_publish_path).read_text()
        assert out == "a.example.com\nb.example.com\n"
        # ...and the supervisor is told to pick it up.
        assert Path(api._dns_reload_path).exists()

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
        api._dns_reload_path = "/proc/nonexistent/reload"
        api._publish_dns_domains()  # must not raise
        assert api._log.warn.called
