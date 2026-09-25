"""Structural guard against IP-encoded hostnames (wildcard-DNS SSRF) — host side.

The host mirror of the addon's structural refusal: ``cli._is_never_grant`` and
``config.encoded_private_ip`` run during the reconcile step, so an overlay entry
written by an older addon (or edited by hand) cannot be promoted into the
operator's baseline.

Boundary note (RUST-PORT-PLAN.md §2.4): split out of
``tests/test_policy_api_ssrf_guard.py``, which now holds the egress half only.
The "host and addon agree" assertions live in
``tests/cross_language/test_ssrf_guard_conformance.py``.
"""

from __future__ import annotations

import pytest

from agentcage.cli import _is_never_grant as host_is_never_grant
from agentcage.config import encoded_private_ip
from tests.cross_language.vectors import ALLOWED, BYPASS


@pytest.mark.parametrize("domain", BYPASS)
def test_host_side_mirror_agrees(domain):
    """The reconcile step must refuse what the addon refuses.

    Otherwise an overlay entry written by an older addon (or edited by hand)
    could still be promoted into the operator's baseline.
    """
    assert host_is_never_grant(domain, {"internal", "local", "localhost"})


@pytest.mark.parametrize("domain", ALLOWED)
def test_host_side_mirror_does_not_overblock(domain):
    assert not host_is_never_grant(domain, {"internal", "local", "localhost"})


class TestEncodedPrivateIp:
    def test_returns_the_decoded_address(self):
        assert encoded_private_ip("169-254-169-254.nip.io") == "169.254.169.254"
        assert encoded_private_ip("10-0-0-1.sslip.io") == "10.0.0.1"

    def test_public_addresses_are_not_flagged(self):
        # Naming a public host the long way round is no more dangerous than
        # naming it directly, and flagging it would block real nip.io use.
        assert encoded_private_ip("93-184-216-34.nip.io") is None

    def test_only_leftmost_labels_are_read(self):
        # The address has to be where these services put it. Otherwise a
        # legitimate host whose name merely contains a dotted-quad-looking
        # run would be misread.
        assert encoded_private_ip("cdn.10-0-0-1.example.com") is None

    def test_zero_padded_octets_are_ignored(self):
        # Not how the services encode, and octal ambiguity is a footgun.
        assert encoded_private_ip("010-0-0-1.nip.io") is None


class TestMetadataGoogIsNeverGranted:
    """GCP's public metadata alias does not end in `.internal`."""

    def test_metadata_goog_blocked(self):
        from agentcage.config import _AUTO_NEVER_GRANT
        assert "metadata.goog" in _AUTO_NEVER_GRANT
        assert host_is_never_grant(
            "metadata.goog", {"internal", "local", "localhost", "metadata.goog"}
        )
