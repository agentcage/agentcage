"""Tests for the nested-virt skip guard in ``tests/e2e/phase_apple.sh``.

GitHub's hosted ``macos-26`` runner is itself a VM, so Apple's
Virtualization.framework refuses to boot nested VMs with
``VZErrorDomain Code=2 "Virtualization is not available on this
hardware."`` (issue #215). Rather than erroring mid-run, the phase
probes for nested virt and SKIPS (exit 0, clear reason) on a
no-nested-virt host, while still running the real e2e when nested
virt IS available.

These tests run the script under a temp ``PATH`` populated with fake
``uname`` / ``container`` / ``sysctl`` shims so the macOS-only guards
can be exercised from any CI. The "still runs the real e2e when
nested virt IS available" path is macOS-gated and intentionally not
asserted here — it's documented in the phase header and verified
manually on bare-metal Apple Silicon.
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
    return bindir


def _run_phase(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    bindir = _make_fake_bin(tmp_path)
    full_env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ.get('PATH', '')}",
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
