"""Unit tests for agentcage.services helpers."""

from __future__ import annotations

from pathlib import Path

from agentcage.services import write_resolv_files


class TestWriteResolvFiles:
    """The cage and egress resolv.conf writers (the egress DNS race fix)."""

    def test_cage_resolv_points_at_egress(self, tmp_path: Path):
        """The cage's resolv.conf routes DNS through its egress sidecar
        (the egress's bundled, allowlist-scoped dnsmasq)."""
        cage_path, _ = write_resolv_files(
            str(tmp_path), "test", "10.89.7.2", ["1.1.1.1", "8.8.8.8"],
        )
        assert Path(cage_path).name == "resolv-test.conf"
        assert Path(cage_path).read_text() == "nameserver 10.89.7.2\n"

    def test_egress_resolv_pins_upstreams_only(self, tmp_path: Path):
        """REGRESSION GUARD (egress DNS resolv.conf ordering race).

        The egress's resolv.conf must list ONLY the configured upstream
        resolvers — never the egress sidecar IP, never an aardvark
        address. mitmproxy resolves allowlisted upstream hostnames via
        this file; if aardvark were ever consulted (which is what happens
        when podman's auto-generated resolv.conf wins, via the racy `DNS=`
        directive), external names intermittently fail to resolve and
        every allowlisted host returns 502 Bad Gateway. Pinning the
        upstreams here and bind-mounting the result removes aardvark from
        the egress's resolution path entirely.
        """
        _, egress_path = write_resolv_files(
            str(tmp_path), "test", "10.89.7.2", ["1.1.1.1", "8.8.8.8"],
        )
        assert Path(egress_path).name == "resolv-egress-test.conf"
        content = Path(egress_path).read_text()
        assert content == "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        # The egress IP must NOT appear — that would point mitmproxy's
        # upstream resolution back at the egress's own dnsmasq (which is
        # --no-resolv and refuses non-allowlisted recursion → no upstream
        # IPs for real hosts).
        assert "10.89.7.2" not in content

    def test_egress_resolv_single_upstream(self, tmp_path: Path):
        _, egress_path = write_resolv_files(
            str(tmp_path), "solo", "10.89.9.2", ["192.0.2.53"],
        )
        assert Path(egress_path).read_text() == "nameserver 192.0.2.53\n"

    def test_both_files_written_under_patches_dir(self, tmp_path: Path):
        cage_path, egress_path = write_resolv_files(
            str(tmp_path), "abc", "10.0.0.2", ["1.1.1.1"],
        )
        assert Path(cage_path).parent == tmp_path
        assert Path(egress_path).parent == tmp_path
