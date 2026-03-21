"""Unit tests for agentcage.doctor — diagnostic checks."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from agentcage.doctor import (
    CheckResult,
    _detect_distro,
    _python_version_info,
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
    check_cages,
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

    def test_not_found(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman("arch")
        assert r.level == "error"
        assert "pacman" in r.hint

    def test_debian_hint(self):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_podman("debian")
        assert r.level == "error"
        assert "apt-get" in r.hint

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
# Cage health checks
# ---------------------------------------------------------------------------

class TestCheckCages:
    def test_no_deployments(self):
        with patch("agentcage.state.list_deployments", return_value=[]):
            results = check_cages()
        assert len(results) == 1
        assert results[0].level == "pass"

    def test_running_container(self):
        mock_cfg = MagicMock()
        mock_cfg.isolation = "container"
        with patch("agentcage.state.list_deployments", return_value=["test-cage"]):
            with patch("agentcage.state.load_deployment_config", return_value=mock_cfg):
                with patch("agentcage.backends.container.ContainerBackend.is_running",
                           return_value=True):
                    results = check_cages()
        assert len(results) == 1
        assert results[0].level == "pass"
        assert "running" in results[0].message

    def test_stopped_container(self):
        mock_cfg = MagicMock()
        mock_cfg.isolation = "container"
        with patch("agentcage.state.list_deployments", return_value=["test-cage"]):
            with patch("agentcage.state.load_deployment_config", return_value=mock_cfg):
                with patch("agentcage.backends.container.ContainerBackend.is_running",
                           return_value=False):
                    results = check_cages()
        assert len(results) == 1
        assert results[0].level == "warn"
        assert "stopped" in results[0].message


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

        # No cages
        p = patch("agentcage.state.list_deployments", return_value=[])
        p.start()
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
        ("arch", "pacman"),
        ("debian", "apt-get"),
        ("fedora", "dnf"),
    ])
    def test_lima_hint_per_distro(self, distro, expected):
        with patch("agentcage.doctor.subprocess.run", side_effect=FileNotFoundError):
            r = check_lima(distro)
        assert expected in r.hint
