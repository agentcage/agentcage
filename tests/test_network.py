"""Tests for Firecracker networking helpers."""

from __future__ import annotations

from agentcage.firecracker.network import cage_ip, tap_name, BRIDGE_IP, BRIDGE_NETMASK


class TestTapName:
    def test_basic(self):
        assert tap_name("myapp") == "tap-myapp"

    def test_with_hyphen(self):
        assert tap_name("my-app") == "tap-my-app"


class TestCageIp:
    def test_returns_valid_ip(self):
        ip = cage_ip("myapp")
        parts = ip.split(".")
        assert len(parts) == 4
        assert parts[0] == "10"
        assert parts[1] == "88"
        assert parts[2] == "0"
        octet = int(parts[3])
        assert 2 <= octet <= 254

    def test_deterministic(self):
        assert cage_ip("myapp") == cage_ip("myapp")

    def test_different_names_different_ips(self):
        # Different names should (almost certainly) get different IPs
        ips = {cage_ip(f"cage-{i}") for i in range(20)}
        # With 20 names and 253 slots, collisions are possible but unlikely
        assert len(ips) >= 15


class TestConstants:
    def test_bridge_ip(self):
        assert BRIDGE_IP == "10.88.0.1"

    def test_bridge_netmask(self):
        assert BRIDGE_NETMASK == "255.255.255.0"
