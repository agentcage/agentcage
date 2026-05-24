"""Prerequisite checks for the apple-container backend.

Apple's `container` requires macOS 26+ on Apple Silicon. The apiserver also
needs to be running (`container system start`). We distinguish "not installed"
from "stopped" so the doctor command can suggest the right fix.
"""

from __future__ import annotations

import platform

from agentcage.apple_container import cli as ac_cli


_MIN_MACOS_MAJOR = 26


def macos_major() -> int | None:
    """Return the macOS major version as int, or None if not Darwin / unreadable."""
    if platform.system() != "Darwin":
        return None
    release = platform.mac_ver()[0]  # e.g. '26.3.2'
    if not release:
        return None
    try:
        return int(release.split(".")[0])
    except (ValueError, IndexError):
        return None


def check_prerequisites() -> list[str]:
    """Return a list of unmet prerequisites (empty = all OK)."""
    issues: list[str] = []

    if platform.system() != "Darwin":
        issues.append(
            "apple-container isolation requires macOS; current platform is "
            f"{platform.system()}"
        )
        return issues

    if platform.machine() != "arm64":
        issues.append(
            "apple-container isolation requires Apple Silicon (arm64); "
            f"current arch is {platform.machine()}"
        )

    mver = macos_major()
    if mver is None or mver < _MIN_MACOS_MAJOR:
        issues.append(
            f"apple-container isolation requires macOS {_MIN_MACOS_MAJOR}+; "
            f"detected major version {mver}"
        )

    if ac_cli.container_binary() is None:
        issues.append(
            "'container' CLI not found — install from "
            "https://github.com/apple/container/releases (the .pkg installer)"
        )
        return issues

    if not ac_cli.system_running():
        issues.append(
            "Apple container apiserver is not running — run "
            "'container system start --enable-kernel-install'"
        )

    return issues
