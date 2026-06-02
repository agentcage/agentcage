"""Unit tests for agentcage.doctor — diagnostic checks."""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# These assert Linux distro-specific remediation hints (apt-get/dnf/pacman).
# On macOS the doctor emits brew/macOS guidance instead, so gate them to the
# Linux CI where the behavior under test actually applies.
LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux distro-specific behavior; exercised on the Linux CI",
)

from agentcage.doctor import (
    CheckResult,
    _detect_distro,
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
# Distro detection
# ---------------------------------------------------------------------------

class TestDetectDistro:
    def test_arch(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text('ID=arch\nNAME="Arch Linux"\n')
        with patch("agentcage.doctor.Path") as mock_path:
            mock_path.return_value.read_text.return_value = os_release.read_text()
            assert _detect_distro() == "arch"

    def test_debian(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text('ID=ubuntu\nID_LIKE=debian\n')
        with patch("agentcage.doctor.Path") as mock_path:
            mock_path.return_value.read_text.return_value = os_release.read_text()
            assert _detect_distro() == "debian"

    def test_fedora(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text('ID=fedora\n')
        with patch("agentcage.doctor.Path") as mock_path:
            mock_path.return_value.read_text.return_value = os_release.read_text()
            assert _detect_distro() == "fedora"

    def test_unknown(self, tmp_path):
        with patch("agentcage.doctor.Path") as mock_path:
            mock_path.return_value.read_text.side_effect = OSError("not found")
            assert _detect_distro() == "unknown"


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
            r = check_podman("arch")
        assert r.level == "pass"
        assert "4.9.3" in r.message

    @LINUX_ONLY
    def test_not_found(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman("arch")
        assert r.level == "error"
        assert "pacman" in r.hint

    @LINUX_ONLY
    def test_debian_hint(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman("debian")
        assert r.level == "error"
        assert "apt-get" in r.hint

    @LINUX_ONLY
    def test_fedora_hint(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman("fedora")
        assert r.level == "error"
        assert "dnf" in r.hint


class TestCheckPodmanRootless:
    def test_rootless(self):
        result = subprocess.CompletedProcess([], 0, stdout="true\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_podman_rootless("arch")
        assert r.level == "pass"

    def test_not_rootless(self):
        result = subprocess.CompletedProcess([], 0, stdout="false\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_podman_rootless("arch")
        assert r.level == "warn"


class TestCheckLima:
    def test_found(self):
        result = subprocess.CompletedProcess([], 0, stdout="limactl version 1.0.2\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_lima("arch")
        assert r.level == "pass"
        assert "1.0.2" in r.message

    @LINUX_ONLY
    def test_not_found(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_lima("arch")
        assert r.level == "warn"


class TestCheckQemu:
    def test_found(self):
        result = subprocess.CompletedProcess([], 0,
                                             stdout="QEMU emulator version 8.2.0\n")
        with patch("agentcage.doctor.subprocess.run", return_value=result):
            r = check_qemu("arch")
        assert r.level == "pass"

    def test_not_found(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_qemu("debian")
        assert r.level == "warn"
        assert "apt-get" in r.hint


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

        # Distro
        p = patch("agentcage.doctor._detect_distro", return_value="arch")
        p.start()
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
# Distro-specific remediation hints
# ---------------------------------------------------------------------------

@LINUX_ONLY
class TestRemediationHints:
    @pytest.mark.parametrize("distro,expected", [
        ("arch", "pacman"),
        ("debian", "apt-get"),
        ("fedora", "dnf"),
        ("rhel", "dnf"),
        ("opensuse", "zypper"),
    ])
    def test_podman_hint_per_distro(self, distro, expected):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman(distro)
        assert expected in r.hint

    @pytest.mark.parametrize("distro,expected", [
        ("arch", "pacman"),
        ("debian", "apt-get"),
        ("fedora", "dnf"),
    ])
    def test_qemu_hint_per_distro(self, distro, expected):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_qemu(distro)
        assert expected in r.hint

    @pytest.mark.parametrize("distro,expected", [
        ("arch", "AUR"),
        ("debian", "apt-get"),
        ("fedora", "dnf"),
    ])
    def test_lima_hint_per_distro(self, distro, expected):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_lima(distro)
        assert expected in r.hint


# ---------------------------------------------------------------------------
# Resilience: _safe_check wrappers
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


# ---------------------------------------------------------------------------
# macOS awareness — Linux-only checks must not fire on macOS
# ---------------------------------------------------------------------------

class TestMacOS:
    def test_podman_optional_when_missing(self):
        """On macOS a missing host Podman is not an error — it is optional."""
        with patch("agentcage.doctor._IS_MACOS", True), \
             patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman("unknown")
        assert r.level == "pass"
        assert "macOS" in r.message

    def test_lima_required_error_on_macos(self):
        """On macOS the VM is the only isolation mode — missing Lima is fatal,
        so it must report as an error, not a soft warning."""
        with patch("agentcage.doctor._IS_MACOS", True), \
             patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_lima("unknown")
        assert r.level == "error"
        assert "brew install lima" in r.hint

    def test_secret_backend_macos_with_podman(self):
        from agentcage.doctor import _check_secret_backend
        with patch("agentcage.doctor._IS_MACOS", True), \
             patch("agentcage.doctor.shutil.which", return_value="/opt/homebrew/bin/podman"):
            r = _check_secret_backend()
        assert r.level == "pass"
        assert "systemd" not in r.message

    def test_secret_backend_macos_without_podman(self):
        """When Podman is absent on macOS, the secret check must warn — not
        falsely report a working secret store."""
        from agentcage.doctor import _check_secret_backend
        with patch("agentcage.doctor._IS_MACOS", True), \
             patch("agentcage.doctor.shutil.which", return_value=None):
            r = _check_secret_backend()
        assert r.level == "warn"
        assert "Podman" in r.message

    def test_run_doctor_skips_linux_only_checks(self):
        """QEMU / systemd-linger / cgroup checks must not run on macOS, and a
        healthy fresh macOS install must report zero errors."""
        def fake_run(cmd, **kwargs):
            prog = cmd[0] if cmd else ""
            if prog == "podman":
                raise FileNotFoundError
            if prog == "limactl":
                return subprocess.CompletedProcess(cmd, 0, stdout="limactl version 2.1.1\n")
            return subprocess.CompletedProcess(cmd, 0, stdout="")

        usage = MagicMock()
        usage.free = 50 * 1024 ** 3
        mock_sock = MagicMock()
        with patch("agentcage.doctor._IS_MACOS", True), \
             patch("agentcage.doctor._python_version_info", return_value=(3, 12, 5)), \
             patch("agentcage.doctor.subprocess.run", side_effect=fake_run), \
             patch("agentcage.doctor.shutil.disk_usage", return_value=usage), \
             patch("agentcage.doctor.socket.getaddrinfo", return_value=[("ok",)]), \
             patch("agentcage.doctor.socket.socket") as msock, \
             patch("agentcage.doctor._detect_distro", return_value="unknown"):
            msock.return_value.__enter__ = MagicMock(return_value=mock_sock)
            msock.return_value.__exit__ = MagicMock(return_value=False)
            results = run_doctor()

        messages = " ".join(r.message for r in results)
        assert "QEMU" not in messages
        assert "cgroup" not in messages
        assert "linger" not in messages
        assert not any(r.level == "error" for r in results)
