"""Unit tests for agentcage.doctor — diagnostic checks."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from agentcage.doctor import (
    CheckResult,
    _python_version_info,
    _safe_check,
    check_cgroup_v2,
    check_disk_space,
    check_dns,
    check_lima,
    check_podman,
    check_podman_rootless,
    check_port,
    check_python_version,
    check_qemu,
    check_subnet_conflicts,
    check_systemd_linger,
    run_doctor,
)


# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

class TestCheckPythonVersion:
    def test_pass_on_312(self):
        with patch("agentcage.doctor._python_version_info", return_value=(3, 12, 5)):
            r = check_python_version()
        assert r.level == "pass"
        assert "3.12.5" in r.message

    def test_fail_on_311(self):
        with patch("agentcage.doctor._python_version_info", return_value=(3, 11, 0)):
            r = check_python_version()
        assert r.level == "error"
        assert "3.12" in r.hint


class TestCheckPodman:
    def test_pass(self):
        result = subprocess.CompletedProcess([], 0, stdout="podman version 4.9.3\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_podman()
        assert r.level == "pass"
        assert "4.9.3" in r.message

    def test_not_found(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman()
        assert r.level == "error"
        assert "docs/installation.md" in r.hint


class TestCheckPodmanRootless:
    def test_rootless(self):
        result = subprocess.CompletedProcess([], 0, stdout="true\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_podman_rootless()
        assert r.level == "pass"

    def test_not_rootless(self):
        result = subprocess.CompletedProcess([], 0, stdout="false\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_podman_rootless()
        assert r.level == "warn"


class TestCheckLima:
    def test_found(self):
        result = subprocess.CompletedProcess([], 0, stdout="limactl version 1.0.2\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_lima()
        assert r.level == "pass"
        assert "1.0.2" in r.message

    def test_not_found(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_lima()
        assert r.level == "warn"
        assert "docs/installation.md" in r.hint


class TestCheckQemu:
    def test_found(self):
        result = subprocess.CompletedProcess([], 0,
                                             stdout="QEMU emulator version 8.2.0\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_qemu()
        assert r.level == "pass"

    def test_not_found(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_qemu()
        assert r.level == "warn"
        assert "docs/installation.md" in r.hint


class TestCheckSystemdLinger:
    def test_enabled(self):
        result = subprocess.CompletedProcess([], 0, stdout="Linger=yes\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            with patch.dict("os.environ", {"USER": "testuser"}):
                r = check_systemd_linger()
        assert r.level == "pass"

    def test_disabled(self):
        result = subprocess.CompletedProcess([], 0, stdout="Linger=no\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            with patch.dict("os.environ", {"USER": "testuser"}):
                r = check_systemd_linger()
        assert r.level == "warn"
        assert "enable-linger" in r.hint


# ---------------------------------------------------------------------------
# System checks
# ---------------------------------------------------------------------------

class TestCheckDiskSpace:
    def test_enough_space(self):
        usage = MagicMock()
        usage.free = 50 * 1024 ** 3  # 50 GB
        with patch("agentcage.doctor.shutil.disk_usage", return_value=usage):
            r = check_disk_space()
        assert r.level == "pass"
        assert "50GB" in r.message

    def test_low_space(self):
        usage = MagicMock()
        usage.free = 1 * 1024 ** 3  # 1 GB
        with patch("agentcage.doctor.shutil.disk_usage", return_value=usage):
            r = check_disk_space()
        assert r.level == "error"


class TestCheckCgroupV2:
    def test_enabled(self):
        with patch("agentcage.doctor.Path.exists", return_value=True):
            r = check_cgroup_v2()
        assert r.level == "pass"

    def test_not_enabled(self):
        with patch("agentcage.doctor.Path.exists", return_value=False):
            r = check_cgroup_v2()
        assert r.level == "warn"


# ---------------------------------------------------------------------------
# Network checks
# ---------------------------------------------------------------------------

class TestCheckDns:
    def test_working(self):
        with patch("agentcage.doctor.socket.getaddrinfo", return_value=[("result",)]):
            r = check_dns()
        assert r.level == "pass"

    def test_failing(self):
        import socket as _socket
        with patch("agentcage.doctor.socket.getaddrinfo",
                   side_effect=_socket.gaierror("fail")):
            r = check_dns()
        assert r.level == "error"


class TestCheckSubnetConflicts:
    def test_no_conflicts(self):
        result = subprocess.CompletedProcess([], 0, stdout="[]")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_subnet_conflicts()
        assert r.level == "pass"

    def test_with_conflicts(self):
        import json
        nets = [{"name": "test-net", "subnets": [{"subnet": "10.89.1.0/24", "gateway": "10.89.1.1"}]}]
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(nets))
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_subnet_conflicts()
        assert r.level == "warn"
        assert "test-net" in r.message


class TestCheckPort:
    def test_available(self):
        mock_sock = MagicMock()
        with patch("agentcage.doctor.socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            r = check_port(8080)
        assert r.level == "pass"

    def test_in_use(self):
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError("in use")
        with patch("agentcage.doctor.socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            # Also mock the ss call
            ss_result = subprocess.CompletedProcess([], 0, stdout="")
            with patch("agentcage.doctor.subprocess.run", return_value=ss_result):
                r = check_port(8080)
        assert r.level == "warn"
        assert "8080" in r.message


# ---------------------------------------------------------------------------
# Integration: run_doctor
# ---------------------------------------------------------------------------

class TestRunDoctor:
    def _mock_all_passing(self):
        """Set up mocks for a fully healthy system."""
        patches = []

        # Python version
        p = patch("agentcage.doctor._python_version_info", return_value=(3, 12, 5))
        p.start()
        patches.append(p)

        # subprocess calls (podman, lima, qemu, loginctl, ss)
        def fake_run(cmd, **kwargs):
            prog = cmd[0] if cmd else ""
            if prog == "podman":
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout="podman version 4.9.3\n")
                if "info" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout="true\n")
                if "network" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout="[]")
            if prog == "limactl":
                return subprocess.CompletedProcess(cmd, 0, stdout="limactl version 1.0.2\n")
            if prog == "qemu-system-x86_64":
                return subprocess.CompletedProcess(cmd, 0, stdout="QEMU emulator version 8.2.0\n")
            if prog == "loginctl":
                return subprocess.CompletedProcess(cmd, 0, stdout="Linger=yes\n")
            if prog == "ss":
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            return subprocess.CompletedProcess(cmd, 0, stdout="")

        p = patch("agentcage.doctor.subprocess.run", side_effect=fake_run)
        p.start()
        patches.append(p)

        # Disk space
        usage = MagicMock()
        usage.free = 50 * 1024 ** 3
        p = patch("agentcage.doctor.shutil.disk_usage", return_value=usage)
        p.start()
        patches.append(p)

        # cgroup v2
        p = patch("agentcage.doctor.Path.exists", return_value=True)
        p.start()
        patches.append(p)

        # DNS
        p = patch("agentcage.doctor.socket.getaddrinfo", return_value=[("ok",)])
        p.start()
        patches.append(p)

        # Socket bind (ports available)
        mock_sock = MagicMock()
        p = patch("agentcage.doctor.socket.socket")
        m = p.start()
        m.return_value.__enter__ = MagicMock(return_value=mock_sock)
        m.return_value.__exit__ = MagicMock(return_value=False)
        patches.append(p)

        # USER env
        p = patch.dict("os.environ", {"USER": "testuser"})
        p.start()
        patches.append(p)

        return patches

    def test_healthy_system_returns_no_errors(self):
        patches = self._mock_all_passing()
        try:
            results = run_doctor()
            assert not any(r.level == "error" for r in results)
        finally:
            for p in patches:
                p.stop()

    def test_exit_code_zero_when_healthy(self):
        patches = self._mock_all_passing()
        try:
            results = run_doctor()
            exit_code = 1 if any(r.level == "error" for r in results) else 0
            assert exit_code == 0
        finally:
            for p in patches:
                p.stop()

    def test_exit_code_one_when_error(self):
        patches = self._mock_all_passing()
        try:
            # Stop the passing python version mock so we can override it
            patches[0].stop()
            with patch("agentcage.doctor._python_version_info", return_value=(3, 11, 0)):
                results = run_doctor()
                exit_code = 1 if any(r.level == "error" for r in results) else 0
                assert exit_code == 1
        finally:
            for p in patches[1:]:
                p.stop()


# ---------------------------------------------------------------------------
# Resilience: _safe_check wrapper
# ---------------------------------------------------------------------------

class TestSafeCheck:
    def test_passes_through_normal_result(self):
        def ok():
            return CheckResult("pass", "all good")
        r = _safe_check(ok, label="test")
        assert r.level == "pass"

    def test_catches_unexpected_exception(self):
        def boom():
            raise RuntimeError("unexpected")
        r = _safe_check(boom, label="test check")
        assert r.level == "warn"
        assert "crashed" in r.message
        assert "unexpected" in r.message

    def test_passes_args(self):
        def needs_arg(x):
            return CheckResult("pass", f"got {x}")
        r = _safe_check(needs_arg, "hello", label="test")
        assert "hello" in r.message


# ---------------------------------------------------------------------------
# Resilience: individual check error handling
# ---------------------------------------------------------------------------

class TestCheckResilience:
    def test_dns_timeout(self):
        import socket as _socket
        with patch("agentcage.doctor.socket.getaddrinfo",
                   side_effect=_socket.timeout("timed out")):
            r = check_dns()
        assert r.level == "error"
        assert "timed out" in r.message.lower()

    def test_disk_space_oserror(self):
        with patch("agentcage.doctor.shutil.disk_usage",
                   side_effect=OSError("Permission denied")):
            r = check_disk_space()
        assert r.level == "warn"
        assert "Permission denied" in r.message

    def test_cgroup_oserror(self):
        with patch("agentcage.doctor.Path.exists",
                   side_effect=OSError("permission denied")):
            r = check_cgroup_v2()
        assert r.level == "warn"
