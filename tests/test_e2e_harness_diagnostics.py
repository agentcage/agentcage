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
        # first thing that talks to a backend. The sweep goes through
        # "$AGENTCAGE" (the overridable CLI-under-test), not a bare
        # `agentcage` off PATH.
        assert text.index("BLOCKED+=") < text.index('"$AGENTCAGE" cage list')


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
    """``start_mock`` must not die mutely when podman cannot see the egress."""

    @pytest.fixture
    def bindir(self, tmp_path):
        b = tmp_path / "fakebin"
        b.mkdir()
        # start_mock polls for the egress for up to 30s; don't actually wait.
        _write_shim(b, "sleep", "exit 0")
        return b

    def _start_mock(self, bindir):
        script = (
            f'source "{LIB_SH}"\n'
            "rc=0\n"
            'start_mock e2e-fake httpbin.org || rc=$?\n'
            'echo "RC=$rc"\n'
        )
        return _run_bash(script, bindir)

    def test_invisible_egress_does_not_kill_the_phase_silently(self, bindir):
        """An egress podman cannot see (the cage was built by a vm or
        apple-container backend) must yield an explanation and a non-zero
        return, never a bare `FAIL (0/0)` from `set -e` (#317)."""
        _write_shim(
            bindir, "podman",
            'case "$1" in\n'
            '  inspect) echo "Error: no such container" >&2; exit 125 ;;\n'
            '  run) echo "run must not be reached" >&2; exit 99 ;;\n'
            "  *) exit 0 ;;\n"
            "esac",
        )
        result = self._start_mock(bindir)
        assert "RC=1" in result.stdout, result.stdout + result.stderr
        assert "e2e-fake-egress is not running in the podman store" in result.stderr
        assert "different container store" in result.stderr
        assert "#317" in result.stderr
        assert "run must not be reached" not in result.stderr

    def test_podman_run_error_is_surfaced(self, bindir):
        """A failed `podman run` reports podman's own message, not just a
        bare 'failed to start mock container'."""
        _write_shim(
            bindir, "podman",
            'case "$1" in\n'
            "  inspect) echo /run/user/1000/netns/netns-egress ;;\n"
            '  run) echo "Error: initializing source docker://python: '
            'pull rate limit" >&2; exit 125 ;;\n'
            "  *) exit 0 ;;\n"
            "esac",
        )
        result = self._start_mock(bindir)
        assert "RC=1" in result.stdout, result.stdout + result.stderr
        assert "failed to start mock container" in result.stderr
        assert "python:" in result.stderr  # names the mock image
        assert "podman run FAILED (exit 125)" in result.stderr
        assert "pull rate limit" in result.stderr


def _netns_podman_shim(bindir: Path, log: Path, mock_netns: str) -> None:
    """A podman stand-in for the mock lifecycle.

    The egress reports namespace ``/run/netns/egress-new``; the mock
    reports *mock_netns*. ``run`` invocations are appended to *log*.
    """
    _write_shim(
        bindir, "podman",
        'case "$1" in\n'
        "  inspect)\n"
        '    for a; do last="$a"; done\n'
        '    case "$last" in\n'
        "      *-egress) echo /run/netns/egress-new ;;\n"
        f"      *-mock) echo '{mock_netns}' ;;\n"
        "    esac ;;\n"
        f'  run) echo "$*" >> "{log}"; echo cid ;;\n'
        # _patch_egress_hosts pipes into `exec -i`; drain it so the
        # writer never sees EPIPE (pipefail would turn that into a fail).
        '  exec) case " $* " in *" -i "*) cat >/dev/null ;; esac; exit 0 ;;\n'
        "  *) exit 0 ;;\n"
        "esac",
    )


class TestMockSharesEgressNetns:
    """The mock runs in its own container inside the egress's network
    namespace, joined by namespace path, and follows the egress across
    restarts."""

    @pytest.fixture
    def bindir(self, tmp_path):
        b = tmp_path / "fakebin"
        b.mkdir()
        _write_shim(b, "sleep", "exit 0")
        return b

    def _run(self, bindir, call: str):
        script = (
            f'source "{LIB_SH}"\n'
            "rc=0\n"
            f"{call} || rc=$?\n"
            'echo "RC=$rc"\n'
        )
        return _run_bash(script, bindir)

    def test_start_joins_egress_netns_by_path(self, bindir, tmp_path):
        log = tmp_path / "runlog"
        _netns_podman_shim(bindir, log, "")
        result = self._run(bindir, "start_mock e2e-fake httpbin.org")
        assert "RC=0" in result.stdout, result.stdout + result.stderr
        run = log.read_text()
        assert "--network ns:/run/netns/egress-new" in run
        assert "agentcage.e2e.netns=/run/netns/egress-new" in run
        # Bound to loopback inside the shared namespace.
        assert "python3 /mock.py 127.0.0.1" in run
        # Never the egress image, never a container: join (see below).
        assert "agentcage-egress" not in run
        assert "container:" not in run

    def test_repatch_rehomes_mock_after_egress_restart(self, bindir, tmp_path):
        """A restarted egress has a new namespace; the mock must follow."""
        log = tmp_path / "runlog"
        _netns_podman_shim(bindir, log, "/run/netns/egress-old")
        result = self._run(bindir, "repatch_mock e2e-fake httpbin.org")
        assert "RC=0" in result.stdout, result.stdout + result.stderr
        assert "--network ns:/run/netns/egress-new" in log.read_text()

    def test_repatch_leaves_mock_alone_when_netns_unchanged(
        self, bindir, tmp_path
    ):
        log = tmp_path / "runlog"
        _netns_podman_shim(bindir, log, "/run/netns/egress-new")
        result = self._run(bindir, "repatch_mock e2e-fake httpbin.org")
        assert "RC=0" in result.stdout, result.stdout + result.stderr
        assert not log.exists(), log.read_text()

    def test_no_container_join(self):
        """Static: `--network container:<cage>-egress` makes the mock a
        dependent of the egress, and podman then refuses to remove or
        --replace the egress — every egress restart would fail."""
        code = [
            line for line in LIB_SH.read_text().splitlines()
            if not line.lstrip().startswith("#")
        ]
        assert not [line for line in code if "container:" in line], code

    def test_mock_image_is_pinned(self):
        ref = (E2E_DIR / "mock-image.ref").read_text().strip()
        name, _, digest = ref.partition("@sha256:")
        assert len(digest) == 64, ref
        tag = name.rsplit(":", 1)[1]
        assert tag[0].isdigit() and "alpine" in tag, ref  # exact, not :3-alpine


class TestNoPythonInEgress:
    """Static: nothing in the harness may run an interpreter in the egress
    container — the replacement egress image ships none."""

    SCRIPTS = sorted(E2E_DIR.glob("*.sh"))

    @pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
    def test_no_interpreter_exec_in_egress(self, script):
        offenders = []
        lines = script.read_text().splitlines()
        for i, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue
            # Commands targeting the egress sibling, including a
            # continuation line or two after them.
            if not ("-egress" in line or "-s egress" in line) or not any(
                k in line for k in ("podman exec", "cage exec", "container exec")
            ):
                continue
            window = " ".join(lines[i:i + 3])
            if any(k in window for k in ("python", "node ", "perl")):
                offenders.append(f"{script.name}:{i + 1}: {line.strip()}")
        assert not offenders, "\n".join(offenders)


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

    def test_phase7_create_output_is_kept(self):
        """Phase 7 is the one deliberate exception (its create is expected
        to fail every run), so its output goes to a log rather than the
        terminal. Kept, not discarded: when the VM never comes up, that log
        is the only record of why, and it is printed at the failure."""
        text = (E2E_DIR / "phase7_vm.sh").read_text()
        assert 'create_cage "$CONFIGS/vm.yaml" >"$CREATE_LOG" 2>&1 || true' in text
        assert 'create_cage "$CONFIGS/vm.yaml" >/dev/null' not in text
        assert '"$CREATE_LOG" | head' in text, "the log must be printed on failure"
