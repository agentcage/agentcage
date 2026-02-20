"""Check prerequisites for Firecracker microVM isolation."""

from __future__ import annotations

import os
import shutil

from agentcage.config import Config


def check_prerequisites(config: Config) -> list[str]:
    """Return a list of unmet prerequisites (empty = all OK)."""
    issues: list[str] = []
    fc = config.firecracker

    # /dev/kvm must exist and be accessible
    if not os.path.exists("/dev/kvm"):
        issues.append("/dev/kvm does not exist — KVM is required for Firecracker")
    elif not os.access("/dev/kvm", os.R_OK | os.W_OK):
        issues.append(
            "/dev/kvm is not accessible — add your user to the 'kvm' group: "
            "sudo usermod -aG kvm $USER"
        )

    # firecracker binary
    if not shutil.which(fc.firecracker_bin):
        from agentcage.firecracker.binaries import default_firecracker_path, ensure_firecracker
        if fc.firecracker_bin == "firecracker":
            # Default name, not in PATH — try auto-download
            try:
                ensure_firecracker()
                fc.firecracker_bin = default_firecracker_path()
            except Exception as e:
                issues.append(f"firecracker not found and auto-download failed: {e}")
        else:
            issues.append(
                f"'{fc.firecracker_bin}' not found in PATH — "
                "install Firecracker: https://github.com/firecracker-microvm/firecracker/releases"
            )

    # Kernel image
    if not fc.kernel:
        issues.append("firecracker.kernel is not set in config")
    elif not os.path.isfile(fc.kernel):
        from agentcage.firecracker.kernel import default_kernel_path, ensure_kernel
        if fc.kernel == default_kernel_path():
            try:
                ensure_kernel(fc.kernel)
            except Exception as e:
                issues.append(f"kernel not found and auto-download failed: {e}")
        else:
            issues.append(f"kernel image not found: {fc.kernel}")

    # Root check
    if os.geteuid() != 0:
        issues.append(
            "not running as root — Firecracker networking requires root: "
            "sudo agentcage ..."
        )

    # Podman (still needed inside the VM)
    if not shutil.which("podman"):
        issues.append("'podman' not found in PATH")

    return issues
