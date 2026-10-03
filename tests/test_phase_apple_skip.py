"""Tests for the nested-virt skip guard in ``tests/e2e/phase_apple.sh``.

GitHub's hosted ``macos-26`` runner is itself a VM, so Apple's
Virtualization.framework refuses to boot nested VMs with
``VZErrorDomain Code=2 "Virtualization is not available on this
hardware."`` (issue #215). Rather than erroring mid-run, the phase
probes for nested virt and SKIPS (exit 0, clear reason) on a
no-nested-virt host, while still running the real e2e when nested
virt IS available.

These tests run the script under a temp ``PATH`` populated with fake
``uname`` / ``container`` / ``sysctl`` / ``security`` shims and a
sandboxed ``HOME`` so the macOS-only guards can be exercised from any
CI *without* the phase reaching anything real. The "still runs the real
e2e when nested virt IS available" path is not asserted here — it's
documented in the phase header and verified manually on bare-metal
Apple Silicon.

Note what "not asserted" does **not** mean: the force-override case
below still *enters* that path, and on a Mac it is not inert. An
earlier version of this module inherited the real environment on the
grounds that the phase "then fails for unrelated reasons (no real
backend on the test host)" — true on the Linux CI this was written
against, false on Apple Silicon, where it got as far as creating a cage
and writing to the login keychain. The shims and the sandbox are what
make the docstring's claim true on every host rather than on most of
them.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

PHASE = Path(__file__).resolve().parent / "e2e" / "phase_apple.sh"


def _make_fake_bin(tmp_path: Path) -> Path:
    """Create a temp bin dir with fake uname/container/sysctl shims."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir()

    def _write(name: str, body: str) -> None:
        p = bindir / name
        p.write_text(f"#!/bin/sh\n{body}\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IREAD)

    # `uname` reports Darwin so the phase passes its macOS guard.
    _write("uname", "echo Darwin")
    # `container` is present so the phase passes the CLI-installed guard.
    _write("container", "exit 0")
    # `sysctl` for kern.hv.supported; tests override per-case.
    _write("sysctl", "echo 0")
    # `security` so the macOS keychain is never reached. On a Mac the
    # force-override case below does not stop at the probe — it goes on
    # into the real phase, which runs `cage create -s API_KEY=...`, and
    # the apple backend's secret store is the login keychain. Without
    # this shim a plain `pytest -q` raised a keychain-access dialog and
    # left a real `agentcage / e2e-apple.API_KEY` entry behind holding
    # the literal string `test-secret-value`. The keychain is not
    # HOME-scoped, so the sandbox in `_run_phase` cannot contain it and
    # a shim is the only thing that can.
    _write("security", "exit 0")
    return bindir


def _run_phase(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    bindir = _make_fake_bin(tmp_path)
    # A sandboxed HOME, for the same reason as the shims above: the
    # force-override case reaches the phase body, and the phase drives a
    # real `agentcage` against `$HOME/.config/agentcage/`. Inheriting the
    # developer's HOME meant `pytest -q` created and destroyed an
    # `e2e-apple` cage in their actual state directory — a unit test
    # reaching into the operator's real environment, on the one platform
    # where the phase is not inert.
    #
    # XDG is pinned too rather than left to follow HOME: `state.py`
    # resolves both at import, and the apple backend's own root ignores
    # XDG entirely and expands `~` directly, so HOME alone does not
    # redirect everything.
    home = tmp_path / "home"
    (home / ".config").mkdir(parents=True, exist_ok=True)
    (home / ".local" / "share").mkdir(parents=True, exist_ok=True)
    full_env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ.get('PATH', '')}",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        # Unset any inherited CI markers so the test's env is authoritative.
        "ImageOS": "",
    }
    full_env.update(env)
    return subprocess.run(
        ["bash", str(PHASE)],
        capture_output=True, text=True, env=full_env, timeout=30,
    )


class TestPhaseAppleNestedVirtSkip:
    def test_skips_on_github_hosted_macos_runner(self, tmp_path):
        """ImageOS=macos* ⇒ hosted VM ⇒ no nested virt ⇒ SKIP exit 0."""
        result = _run_phase(tmp_path, {"ImageOS": "macos26"})
        assert result.returncode == 0, result.stdout + result.stderr
        assert "SKIP" in result.stdout
        assert "nested virtualization unavailable" in result.stdout
        assert "ImageOS=macos26" in result.stdout
        assert "#215" in result.stdout

    def test_skips_when_kern_hv_supported_is_zero(self, tmp_path):
        """kern.hv.supported=0 ⇒ no hypervisor support ⇒ SKIP exit 0."""
        # ImageOS unset so only the sysctl probe fires.
        result = _run_phase(tmp_path, {"ImageOS": ""})
        assert result.returncode == 0, result.stdout + result.stderr
        assert "SKIP" in result.stdout
        assert "nested virtualization unavailable" in result.stdout
        assert "kern.hv.supported=0" in result.stdout
        assert "#215" in result.stdout

    def test_force_override_bypasses_probe(self, tmp_path):
        """AGENTCAGE_APPLE_E2E_FORCE=1 bypasses the probe. With nested virt
        nominally unavailable (ImageOS=macos26, hv_vcpus=0) the script must
        NOT print the nested-virt SKIP message — it proceeds to the real e2e,
        which then fails for unrelated reasons (no real backend on the test
        host). We only assert the skip was *not* taken, not that the e2e
        passed (that path is macOS-gated)."""
        result = _run_phase(
            tmp_path,
            {"ImageOS": "macos26", "AGENTCAGE_APPLE_E2E_FORCE": "1"},
        )
        # It did NOT take the nested-virt skip (returncode may be non-zero
        # because the real e2e can't run here; that's expected and out of
        # scope). The defining assertion: no nested-virt SKIP message.
        assert "nested virtualization unavailable" not in result.stdout
        assert "nested virtualization unavailable" not in result.stderr

    def test_guard_logic_present_in_script(self):
        """Minimum: assert the guard scaffolding exists in the phase script
        even if a host can't exercise the bash path."""
        text = PHASE.read_text()
        assert "AGENTCAGE_APPLE_E2E_FORCE" in text
        assert "ImageOS" in text
        assert "kern.hv.supported" in text
        assert "#215" in text
        assert "nested virtualization unavailable" in text
