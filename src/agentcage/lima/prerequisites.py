"""Check prerequisites for Lima VM isolation."""

from __future__ import annotations

import platform
import shutil


def detect_platform() -> str:
    """Return "linux", "macos", or "unsupported" based on the current OS."""
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Darwin":
        return "macos"
    return "unsupported"


def check_prerequisites() -> list[str]:
    """Return a list of unmet prerequisites (empty = all OK)."""
    issues: list[str] = []

    if not shutil.which("limactl"):
        issues.append(
            "'limactl' not found in PATH — "
            "install Lima: https://lima-vm.io/docs/installation/"
        )

    plat = detect_platform()
    if plat == "unsupported":
        issues.append(
            f"unsupported platform: {platform.system()} — "
            "Lima requires Linux or macOS"
        )

    return issues
