"""Check prerequisites for Firecracker microVM isolation."""

from __future__ import annotations

import grp
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

    # agentcage-nethelper
    nethelper = shutil.which("agentcage-nethelper")
    if not nethelper:
        issues.append(
            "'agentcage-nethelper' not found in PATH — "
            "install it with: agentcage firecracker setup"
        )
    elif not _is_setuid_root(nethelper):
        issues.append(
            f"'{nethelper}' is not setuid root — "
            "reinstall with: agentcage firecracker setup"
        )

    # Podman (still needed inside the VM)
    if not shutil.which("podman"):
        issues.append("'podman' not found in PATH")

    return issues


def _is_setuid_root(path: str) -> bool:
    """Check if a file is setuid and owned by root."""
    try:
        st = os.stat(path)
        return (st.st_mode & 0o4000) != 0 and st.st_uid == 0
    except OSError:
        return False
