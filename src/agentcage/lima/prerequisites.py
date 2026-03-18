"""Check prerequisites for Lima VM isolation."""

from __future__ import annotations

import os
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
    elif plat == "linux":
        # Lima uses QEMU on Linux
        if not shutil.which("qemu-system-x86_64") and not shutil.which("qemu-system-aarch64"):
            issues.append(
                "QEMU not found — Lima requires QEMU on Linux. "
                "Install: apt install qemu-system / dnf install qemu-kvm / pacman -S qemu-full"
            )
        if not os.path.exists("/dev/kvm"):
            issues.append(
                "/dev/kvm not found — KVM is required for acceptable VM performance. "
                "Enable virtualization in BIOS and load the kvm module."
            )

    return issues
