"""Tests for the e2e harness's failure diagnostics and macOS host guard.

Issue #317 reported two halves of the same problem: running
``bash tests/e2e/run.sh container`` on macOS produced

    Phase 1: FAIL (0/0, 46s)
    Total: 0 passed

with no explanation whatsoever.

1. ``tests/e2e/lib.sh`` swallowed the reason. ``create_cage`` folded
   stderr into stdout and every caller redirected stdout to
   ``/dev/null``; ``start_mock``'s image lookup died on a bare
   ``set -e``/``pipefail`` assignment before it could say anything.
2. ``tests/e2e/run.sh container`` ran the wrong backend in the first
   place: the e2e configs pin no ``isolation:`` key, ``container``
   isolation is rejected on macOS, so the phases silently resolved to
   apple-container whose image store podman cannot see.

These tests follow ``test_phase_apple_skip.py``: drive the real shell
scripts under a temp ``PATH`` of fake shims so the host-specific paths
can be exercised from any CI, plus a couple of static assertions for
the branches that cannot be executed without launching a real phase.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

E2E_DIR = Path(__file__).resolve().parent / "e2e"
RUN_SH = E2E_DIR / "run.sh"
LIB_SH = E2E_DIR / "lib.sh"
REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_shim(bindir: Path, name: str, body: str) -> Path:
    p = bindir / name
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IREAD)
    return p


def _run_bash(script: str, bindir: Path, timeout: int = 30):
    """Run *script* with *bindir* prepended to PATH."""
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ.get('PATH', '')}",
        "REPO_ROOT": str(REPO_ROOT),
    }
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, env=env, timeout=timeout,
    )


class TestRunShMacOSContainerGuard:
    """``run.sh`` must refuse the podman-backed phases on a macOS host."""

    @pytest.fixture
    def bindir(self, tmp_path):
        b = tmp_path / "fakebin"
        b.mkdir()
        # `uname -s` reports Darwin so the guard fires from any CI host.
        _write_shim(b, "uname", "echo Darwin")
        # Tripwires: the guard must fire BEFORE any backend command runs.
        # If run.sh reaches its stale-cage sweep or a phase, these record it.
        touched = tmp_path / "touched"
        for cmd in ("agentcage", "podman", "limactl", "container"):
            _write_shim(b, cmd, f'echo "$0 $*" >> "{touched}"\nexit 0')
        return b

    @pytest.fixture
    def touched(self, tmp_path):
        return tmp_path / "touched"

    def _run(self, bindir, args: str):
        return _run_bash(f'bash "{RUN_SH}" {args}', bindir)

    @pytest.mark.parametrize(
        "args, expected_phases",
        [
            ("container", "1 2 3 4 5 6"),
            ("openclaw", "8"),
            ("all", "1 2 3 4 5 6 8"),
            ("", "1 2 3 4 5 6 8"),   # no args ⇒ all phases
            ("1", "1"),
            ("3 7", "3"),            # 7 alone is fine, 3 is not
        ],
    )
    def test_refuses_container_phases_on_darwin(
        self, bindir, touched, args, expected_phases
    ):
        result = self._run(bindir, args)
        assert result.returncode == 1, result.stdout + result.stderr
        assert f"phase(s) {expected_phases} need" in result.stderr
        assert not touched.exists(), (
            f"guard ran backend commands before refusing: {touched.read_text()}"
        )

    def test_message_names_the_real_constraint(self, bindir):
        """The message must explain *why*, not just say no."""
        err = self._run(bindir, "container").stderr
        assert "'container' isolation (rootless podman)" in err
        assert "does not support on macOS" in err
        assert "podman cannot see" in err
        assert "#317" in err

    def test_message_is_actionable(self, bindir):
        """It must point at the paths that DO work on macOS."""
        err = self._run(bindir, "container").stderr
        assert "run.sh vm" in err
        assert "phase_apple.sh" in err
        assert "Linux host" in err

    def test_refusal_goes_to_stderr(self, bindir):
        """stdout stays clean so it can't be mistaken for a phase result."""
        result = self._run(bindir, "container")
        assert "ERROR" not in result.stdout
        assert result.stderr.startswith("ERROR:")

    def test_help_still_works_on_darwin(self, bindir, touched):
        """``-h`` is handled during arg parsing and must not be blocked."""
        result = self._run(bindir, "-h")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Usage:" in result.stdout
        assert "ERROR" not in result.stderr
        assert not touched.exists()

    def test_unknown_arg_still_rejected_on_darwin(self, bindir):
        result = self._run(bindir, "bogus")
        assert result.returncode == 1
        assert "Unknown argument: bogus" in result.stdout

    def test_guard_is_darwin_scoped_and_excludes_the_vm_phase(self):
        """Static: phase 7 (Lima VM) is supported on macOS, so it must not
        appear in the blocked set, and the whole guard must sit behind a
        Darwin test so Linux behaviour is unchanged.

        Asserted statically rather than by running ``run.sh vm``: that
        would launch the real phase 7 against the host's Lima/podman.
        """
        text = RUN_SH.read_text()
        assert '[ "$(uname -s)" = "Darwin" ]' in text
        assert "1|2|3|4|5|6|8) BLOCKED+=" in text
        assert "|7|" not in text
        # The guard block must precede the stale-cage sweep, which is the
        # first thing that talks to a backend.
        assert text.index("BLOCKED+=") < text.index("agentcage cage list")


class TestCreateCageFailureDiagnostics:
    """``create_cage`` must explain a failed create even when the caller
    redirects its stdout to /dev/null (every phase script does)."""

    @pytest.fixture
    def bindir(self, tmp_path):
        b = tmp_path / "fakebin"
        b.mkdir()
        # envsubst isn't installed everywhere; `cat` is a faithful stand-in
        # for a config with no ${VAR} references.
        _write_shim(b, "envsubst", "exec cat")
        return b

    @pytest.fixture
    def config(self, tmp_path):
        cfg = tmp_path / "cage.yaml"
        cfg.write_text("name: e2e-fake\n")
        return cfg

    def _create(self, bindir, config, redirect: str):
        script = (
            f'source "{LIB_SH}"\n'
            "rc=0\n"
            f'create_cage "{config}" {redirect} || rc=$?\n'
            'echo "RC=$rc"\n'
        )
        return _run_bash(script, bindir)

    def test_failure_output_survives_dev_null_caller(self, bindir, config):
        """The phase-script idiom ``create_cage ... >/dev/null`` must still
        show why a create failed — the #317 regression."""
        _write_shim(
            bindir, "agentcage",
            'echo "Building egress image..."\n'
            'echo "Error: container isolation is not available on macOS" >&2\n'
            "exit 42",
        )
        result = self._create(bindir, config, ">/dev/null")
        assert "RC=42" in result.stdout
        assert "cage create FAILED (exit 42)" in result.stderr
        # Both streams of the failed command are preserved.
        assert "container isolation is not available on macOS" in result.stderr
        assert "Building egress image..." in result.stderr

    def test_failure_names_the_config(self, bindir, config):
        _write_shim(bindir, "agentcage", "exit 1")
        result = self._create(bindir, config, ">/dev/null")
        assert config.name in result.stderr

    def test_failure_with_no_output_still_reports(self, bindir, config):
        """A create that dies mutely still yields an exit code and a frame,
        never a bare `FAIL (0/0)`."""
        _write_shim(bindir, "agentcage", "exit 7")
        result = self._create(bindir, config, ">/dev/null")
        assert "RC=7" in result.stdout
        assert "cage create FAILED (exit 7)" in result.stderr
        assert "(no output)" in result.stderr

    def test_success_stays_quiet(self, bindir, config):
        """A successful create prints nothing on either stream, so phases
        keep their current clean output."""
        _write_shim(bindir, "agentcage", 'echo "Cage created."\nexit 0')
        # Deliberately NOT redirecting: output is captured, not streamed.
        result = self._create(bindir, config, "")
        assert "RC=0" in result.stdout
        assert "Cage created." not in result.stdout
        assert result.stderr == "", result.stderr


class TestStartMockDiagnostics:
    """``start_mock`` must not die mutely when podman has no egress image."""

    @pytest.fixture
    def bindir(self, tmp_path):
        b = tmp_path / "fakebin"
        b.mkdir()
        return b

    def _start_mock(self, bindir):
        script = (
            f'source "{LIB_SH}"\n'
            "rc=0\n"
            'start_mock e2e-fake httpbin.org || rc=$?\n'
            'echo "RC=$rc"\n'
        )
        return _run_bash(script, bindir)

    def test_empty_image_store_does_not_kill_the_phase_silently(self, bindir):
        """`podman images | grep` finding nothing used to abort the whole
        phase through `set -e`/`pipefail` before printing anything — the
        exact `FAIL (0/0)` with no output from #317."""
        _write_shim(
            bindir, "podman",
            'case "$1" in\n'
            "  images) exit 0 ;;\n"
            '  run) echo "Error: no such image" >&2; exit 125 ;;\n'
            "  *) exit 0 ;;\n"
            "esac",
        )
        result = self._start_mock(bindir)
        # It returned an error instead of aborting the caller...
        assert "RC=1" in result.stdout, result.stdout + result.stderr
        # ...and said why, naming the cross-image-store cause.
        assert "no localhost/agentcage-egress:* image" in result.stderr
        assert "different image store" in result.stderr
        assert "#317" in result.stderr

    def test_podman_run_error_is_surfaced(self, bindir):
        """A failed `podman run` reports podman's own message, not just a
        bare 'failed to start mock container'."""
        _write_shim(
            bindir, "podman",
            'case "$1" in\n'
            '  images) echo "localhost/agentcage-egress:0.32.0" ;;\n'
            '  run) echo "Error: network e2e-fake-net not found" >&2; exit 125 ;;\n'
            "  *) exit 0 ;;\n"
            "esac",
        )
        result = self._start_mock(bindir)
        assert "RC=1" in result.stdout, result.stdout + result.stderr
        assert "failed to start mock container" in result.stderr
        assert "localhost/agentcage-egress:0.32.0" in result.stderr
        assert "podman run FAILED (exit 125)" in result.stderr
        assert "network e2e-fake-net not found" in result.stderr


class TestPhaseCallersKeepStderr:
    """Static: callers must not re-swallow what create_cage now emits."""

    # Every phase script except phase 7 (see below). ``phase8_openclaw.sh``
    # builds its cage from a rendered scaffold, not via ``create_cage``.
    CALLERS = [
        "phase1_lifecycle.sh",
        "phase2_audit_logs.sh",
        "phase3_secrets.sh",
        "phase4_domains.sh",
        "phase5_backup.sh",
        "phase6_hardening.sh",
    ]

    @pytest.mark.parametrize("script", CALLERS)
    def test_caller_does_not_redirect_stderr(self, script):
        calls = [
            line.strip()
            for line in (E2E_DIR / script).read_text().splitlines()
            if "create_cage " in line and not line.lstrip().startswith("#")
        ]
        assert calls, f"{script}: no create_cage call found"
        for line in calls:
            assert "2>&1" not in line, (
                f"{script}: create_cage stderr is swallowed, hiding the "
                f"#317 failure dump: {line}"
            )

    def test_phase7_suppression_is_documented(self):
        """Phase 7 is the one deliberate exception (its create is expected
        to fail every run); the waiver must carry its reason."""
        text = (E2E_DIR / "phase7_vm.sh").read_text()
        assert 'create_cage "$CONFIGS/vm.yaml" >/dev/null 2>&1 || true' in text
        assert "stderr is suppressed here on purpose" in text
