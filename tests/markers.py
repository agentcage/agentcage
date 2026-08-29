"""Shared pytest skip markers for optional host dependencies.

Some unit tests drive code paths that shell out to real host tooling
(``podman``) or probe host devices (``/dev/kvm``). Those binaries/devices
exist on the Linux CI runners, so the tests run there — but on a developer
laptop, a macOS host, or a minimal/sandboxed environment they are absent and
the test fails with a ``FileNotFoundError`` (or a spurious prerequisite issue)
for reasons unrelated to what it asserts.

Gate such tests on the dependency actually being present so the suite skips
gracefully instead of failing where the dependency is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

REQUIRES_PODMAN = pytest.mark.skipif(
    shutil.which("podman") is None,
    reason="needs the host `podman` binary (present on Linux CI)",
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
