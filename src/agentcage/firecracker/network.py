"""Firecracker VM networking — bridge and TAP management.

All operations require root (run via ``sudo agentcage``).
"""

from __future__ import annotations

import hashlib
import subprocess


BRIDGE = "agentcage-br0"
BRIDGE_IP = "10.88.0.1"
BRIDGE_CIDR = f"{BRIDGE_IP}/24"
BRIDGE_SUBNET = "10.88.0.0/24"
BRIDGE_NETMASK = "255.255.255.0"


def _run(*args: str) -> str:
    """Run a command, raising on failure."""
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _iptables_has(*args: str) -> bool:
    """Check if an iptables rule already exists."""
    result = subprocess.run(
        ["iptables", *args], capture_output=True, text=True,
    )
    return result.returncode == 0


def _link_exists(name: str) -> bool:
    """Check if a network interface exists."""
    result = subprocess.run(
        ["ip", "link", "show", name],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def _nft_chain_exists(family: str, table: str, chain: str) -> bool:
    """Check if an nftables chain exists."""
    result = subprocess.run(
        ["nft", "list", "chain", family, table, chain],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def _nft_has() -> bool:
    """Check if nft binary is available."""
    result = subprocess.run(
        ["which", "nft"], capture_output=True, text=True,
    )
    return result.returncode == 0


# ── Bridge ────────────────────────────────────────────────


def create_bridge() -> str:
    """Create the shared bridge for VM networking."""
    if _link_exists(BRIDGE):
        return f"bridge {BRIDGE} already exists"

    _run("ip", "link", "add", "name", BRIDGE, "type", "bridge")
    _run("ip", "addr", "add", BRIDGE_CIDR, "dev", BRIDGE)
    _run("ip", "link", "set", BRIDGE, "up")

    # Enable IP forwarding
    _run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

    # MASQUERADE for VM traffic (idempotent)
    if not _iptables_has("-t", "nat", "-C", "POSTROUTING",
                         "-s", BRIDGE_SUBNET, "!", "-o", BRIDGE,
                         "-j", "MASQUERADE"):
        _run("iptables", "-t", "nat", "-A", "POSTROUTING",
             "-s", BRIDGE_SUBNET, "!", "-o", BRIDGE, "-j", "MASQUERADE")

    # FORWARD: allow VM→internet
    if not _iptables_has("-C", "FORWARD",
                         "-i", BRIDGE, "!", "-o", BRIDGE, "-j", "ACCEPT"):
        _run("iptables", "-I", "FORWARD",
             "-i", BRIDGE, "!", "-o", BRIDGE, "-j", "ACCEPT")

    # FORWARD: allow established return traffic
    if not _iptables_has("-C", "FORWARD",
                         "-o", BRIDGE, "-m", "conntrack",
                         "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"):
        _run("iptables", "-I", "FORWARD",
             "-o", BRIDGE, "-m", "conntrack",
             "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")

    # FORWARD: block VM-to-VM
    if not _iptables_has("-C", "FORWARD",
                         "-i", BRIDGE, "-o", BRIDGE, "-j", "DROP"):
        _run("iptables", "-I", "FORWARD",
             "-i", BRIDGE, "-o", BRIDGE, "-j", "DROP")

    # nftables FORWARD rules (some hosts use nft alongside iptables)
    if _nft_has() and _nft_chain_exists("inet", "filter", "forward"):
        # VM-to-VM drop
        subprocess.run(
            ["nft", "add", "rule", "inet", "filter", "forward",
             "iifname", BRIDGE, "oifname", BRIDGE, "drop"],
            capture_output=True,
        )
        # VM→internet
        subprocess.run(
            ["nft", "add", "rule", "inet", "filter", "forward",
             "iifname", BRIDGE, "oifname", "!=", BRIDGE, "accept"],
            capture_output=True,
        )
        # Established return traffic
        subprocess.run(
            ["nft", "add", "rule", "inet", "filter", "forward",
             "oifname", BRIDGE, "ct", "state", "established,related", "accept"],
            capture_output=True,
        )

    # INPUT: allow VMs to reach bridge gateway IP only
    if _nft_has() and _nft_chain_exists("inet", "filter", "input"):
        subprocess.run(
            ["nft", "add", "rule", "inet", "filter", "input",
             "iifname", BRIDGE, "ip", "daddr", BRIDGE_IP, "accept"],
            capture_output=True,
        )

    if not _iptables_has("-C", "INPUT",
                         "-i", BRIDGE, "-d", BRIDGE_IP, "-j", "ACCEPT"):
        _run("iptables", "-I", "INPUT",
             "-i", BRIDGE, "-d", BRIDGE_IP, "-j", "ACCEPT")

    # Drop other VM→host traffic
    if not _iptables_has("-C", "INPUT", "-i", BRIDGE, "-j", "DROP"):
        _run("iptables", "-A", "INPUT", "-i", BRIDGE, "-j", "DROP")

    # Tailscale ts-input chain
    if _iptables_has("-L", "ts-input", "-n"):
        if not _iptables_has("-C", "ts-input",
                             "-i", BRIDGE, "-d", BRIDGE_IP, "-j", "ACCEPT"):
            _run("iptables", "-I", "ts-input", "3",
                 "-i", BRIDGE, "-d", BRIDGE_IP, "-j", "ACCEPT")

    return f"created bridge {BRIDGE} ({BRIDGE_CIDR})"


def destroy_bridge() -> str:
    """Destroy the shared bridge and remove all associated rules."""
    # Remove nftables rules
    if _nft_has():
        for chain in ("forward", "input"):
            if _nft_chain_exists("inet", "filter", chain):
                # List rules, find handles referencing the bridge, delete them
                result = subprocess.run(
                    ["nft", "-a", "list", "chain", "inet", "filter", chain],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if f'"{BRIDGE}"' in line or f"iifname {BRIDGE}" in line or f"oifname {BRIDGE}" in line:
                            # Extract handle number
                            parts = line.rsplit("# handle ", 1)
                            if len(parts) == 2:
                                handle = parts[1].strip()
                                subprocess.run(
                                    ["nft", "delete", "rule", "inet", "filter",
                                     chain, "handle", handle],
                                    capture_output=True,
                                )

    # Remove iptables FORWARD rules
    for args in (
        ["-D", "FORWARD", "-i", BRIDGE, "-o", BRIDGE, "-j", "DROP"],
        ["-D", "FORWARD", "-i", BRIDGE, "!", "-o", BRIDGE, "-j", "ACCEPT"],
        ["-D", "FORWARD", "-o", BRIDGE, "-m", "conntrack",
         "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ):
        subprocess.run(["iptables", *args], capture_output=True)

    # Remove iptables INPUT rules
    for args in (
        ["-D", "INPUT", "-i", BRIDGE, "-d", BRIDGE_IP, "-j", "ACCEPT"],
        ["-D", "INPUT", "-i", BRIDGE, "-j", "DROP"],
    ):
        subprocess.run(["iptables", *args], capture_output=True)

    # Remove Tailscale ts-input rule
    if _iptables_has("-L", "ts-input", "-n"):
        subprocess.run(
            ["iptables", "-D", "ts-input",
             "-i", BRIDGE, "-d", BRIDGE_IP, "-j", "ACCEPT"],
            capture_output=True,
        )

    # Remove MASQUERADE rule
    subprocess.run(
        ["iptables", "-t", "nat", "-D", "POSTROUTING",
         "-s", BRIDGE_SUBNET, "!", "-o", BRIDGE, "-j", "MASQUERADE"],
        capture_output=True,
    )

    # Delete the bridge interface
    subprocess.run(["ip", "link", "delete", BRIDGE], capture_output=True)

    return f"destroyed bridge {BRIDGE}"


# ── TAP ───────────────────────────────────────────────────


def create_tap(name: str) -> str:
    """Create a TAP device for a cage VM."""
    import os

    tap = tap_name(name)
    caller_uid = os.environ.get("SUDO_UID", str(os.getuid()))

    # Ensure bridge exists
    if not _link_exists(BRIDGE):
        create_bridge()

    if _link_exists(tap):
        return f"TAP {tap} already exists"

    _run("ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", caller_uid)
    _run("ip", "link", "set", tap, "master", BRIDGE)
    _run("ip", "link", "set", tap, "up")

    return f"created TAP {tap} (owner uid={caller_uid})"


def destroy_tap(name: str) -> str:
    """Destroy a TAP device for a cage VM."""
    tap = tap_name(name)
    if _link_exists(tap):
        _run("ip", "link", "delete", tap)
        return f"destroyed TAP {tap}"
    return f"TAP {tap} does not exist"


# ── Helpers ───────────────────────────────────────────────


def tap_name(cage_name: str) -> str:
    """Return the TAP device name for a cage."""
    return f"tap-{cage_name}"


def cage_ip(cage_name: str) -> str:
    """Derive a deterministic IP for a cage VM (10.88.0.2-254)."""
    h = hashlib.md5(cage_name.encode()).hexdigest()
    octet = (int(h[:8], 16) % 253) + 2
    return f"10.88.0.{octet}"
