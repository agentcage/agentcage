"""Firecracker VM networking via agentcage-nethelper."""

from __future__ import annotations

import hashlib
import shutil
import subprocess


_NETHELPER = "agentcage-nethelper"


def _run_nethelper(*args: str) -> str:
    """Run the nethelper with the given arguments."""
    helper = shutil.which(_NETHELPER)
    if not helper:
        raise RuntimeError(
            f"'{_NETHELPER}' not found in PATH — "
            "install it with: agentcage firecracker setup"
        )
    result = subprocess.run(
        [helper, *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{_NETHELPER} {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def create_bridge() -> str:
    """Create the shared bridge for VM networking."""
    return _run_nethelper("create-bridge")


def destroy_bridge() -> str:
    """Destroy the shared bridge."""
    return _run_nethelper("destroy-bridge")


def create_tap(name: str) -> str:
    """Create a TAP device for a cage VM."""
    return _run_nethelper("create-tap", name)


def destroy_tap(name: str) -> str:
    """Destroy a TAP device for a cage VM."""
    return _run_nethelper("destroy-tap", name)


def tap_name(cage_name: str) -> str:
    """Return the TAP device name for a cage."""
    return f"tap-{cage_name}"


def cage_ip(cage_name: str) -> str:
    """Derive a deterministic IP for a cage VM (10.88.0.2-254)."""
    h = hashlib.md5(cage_name.encode()).hexdigest()
    octet = (int(h[:8], 16) % 253) + 2
    return f"10.88.0.{octet}"


BRIDGE_IP = "10.88.0.1"
BRIDGE_NETMASK = "255.255.255.0"
