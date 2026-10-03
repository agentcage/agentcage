"""Shared pytest skip markers for optional host dependencies.

Some unit tests drive code paths that shell out to real host tooling
(``podman``) or probe host devices (``/dev/kvm``). Those binaries/devices
exist on the Linux CI runners, so the tests run there — but on a developer
laptop, a macOS host, or a minimal/sandboxed environment they are absent and
the test fails with a ``FileNotFoundError`` (or a spurious prerequisite issue)
for reasons unrelated to what it asserts.

Gate such tests on the dependency actually being *usable* so the suite skips
gracefully instead of failing where the dependency is missing. "Usable" rather
than "installed" is deliberate: see :func:`_podman_is_usable`.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest


def _podman_is_usable() -> bool:
    """Whether `podman` is installed **and can reach a running service**.

    The binary existing is not the same thing, and the difference is a
    macOS laptop: Homebrew's `podman` is a client for a Linux VM, so
    `shutil.which` finds it while every call fails with "Cannot connect
    to Podman ... try `podman machine init`". A marker that only checked
    `which` therefore did not fire, the test ran, and it failed on the
    connection rather than skipping — which is the thing this module's
    docstring says it exists to prevent.

    `podman info` is the probe because it is the cheapest call that
    needs the service rather than just the client; `podman version`
    answers from the client alone and would not tell these two cases
    apart.
    """
    if shutil.which("podman") is None:
        return False
    try:
        return (
            subprocess.run(
                ["podman", "info"],
                capture_output=True,
                timeout=30,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


REQUIRES_PODMAN = pytest.mark.skipif(
    not _podman_is_usable(),
    reason="needs a usable host `podman` (installed and connected; present on Linux CI)",
)

REQUIRES_KVM = pytest.mark.skipif(
    not os.path.exists("/dev/kvm"),
    reason="needs /dev/kvm (present on the virtualization-enabled Linux CI)",
)

REQUIRES_GNU_REALPATH = pytest.mark.skipif(
    shutil.which("realpath") is None
    or subprocess.run(
        ["realpath", "-m", "--", "/nonexistent/agentcage/probe"],
        capture_output=True,
    ).returncode != 0,
    reason="needs GNU coreutils `realpath -m` (present on Linux CI)",
)
