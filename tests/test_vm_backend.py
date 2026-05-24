"""Unit tests for VmBackend."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from agentcage.backends.vm import VmBackend
from agentcage.config import Config, ContainerConfig, VmConfig


def _make_config(name: str = "testcage") -> Config:
    cfg = Config()
    cfg.name = name
    cfg.isolation = "vm"
    cfg.container = ContainerConfig()
    cfg.container.image = "myimage:latest"
    cfg.container.ports = ["8080:80"]
    cfg.vm = VmConfig(vcpus=2, mem_mb=2048)
    cfg.dns_servers = ["1.1.1.1"]
    return cfg


class TestCheckPrerequisites:
    def test_delegates_to_lima_prerequisites(self):
        backend = VmBackend()
        with patch(
            "agentcage.backends.vm.lima_prerequisites.check_prerequisites",
            return_value=["limactl not found"],
        ) as mock_check:
            result = backend.check_prerequisites(_make_config())
        mock_check.assert_called_once()
        assert result == ["limactl not found"]

    def test_returns_empty_when_all_ok(self):
        backend = VmBackend()
        with patch(
            "agentcage.backends.vm.lima_prerequisites.check_prerequisites",
            return_value=[],
        ):
            result = backend.check_prerequisites(_make_config())
        assert result == []


class TestBuildArtifacts:
    def test_builds_images_inside_vm(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_inst.name = "agentcage-testcage"
        config = _make_config()

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch("subprocess.run") as mock_sp_run:
            mock_sp_run.return_value = MagicMock(returncode=0)
            backend.build_artifacts(config, "testcage")

        # Should call: rm, cp, podman build proxy, podman build dns, podman pull, rm
        exec_calls = mock_inst.exec.call_args_list
        build_calls = [c for c in exec_calls if "podman" in str(c) and "build" in str(c)]
        assert len(build_calls) == 2
        assert "agentcage-proxy" in str(build_calls[0])
        assert "agentcage-dns" in str(build_calls[1])
        # Should have pulled the cage image
        pull_calls = [c for c in exec_calls if "pull" in str(c)]
        assert len(pull_calls) == 1

    def test_skips_build_when_vm_not_running(self, capsys):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = False

        with patch.object(backend, "_instance", return_value=mock_inst):
            backend.build_artifacts(_make_config(), "testcage")

        mock_inst.exec.assert_not_called()
        captured = capsys.readouterr()
        assert "not running" in captured.out.lower()


class TestGenerateUnits:
    def test_returns_lima_yaml_and_quadlets(self):
        backend = VmBackend()
        config = _make_config()

        with patch(
            "agentcage.backends.vm.generate_lima_config",
            return_value="lima: yaml content",
        ) as mock_lima, patch(
            "agentcage.backends.vm.generate_quadlets",
            return_value={
                "testcage-cage.container": "[Container]\nImage=myimage",
                "testcage-net.network": "[Network]\n",
            },
        ) as mock_quadlets:
            units = backend.generate_units(config, "/path/config.yaml", "/path/patches", "testcage")

        mock_lima.assert_called_once_with(config)
        mock_quadlets.assert_called_once_with(
            config,
            "/path/config.yaml",
            "/path/patches",
            "testcage",
            used_octets=None,
            network_octet=None,
        )

        assert "lima.yaml" in units
        assert units["lima.yaml"] == "lima: yaml content"
        assert "quadlets/testcage-cage.container" in units
        assert "quadlets/testcage-net.network" in units

    def test_quadlet_keys_prefixed_correctly(self):
        backend = VmBackend()
        config = _make_config()

        with patch("agentcage.backends.vm.generate_lima_config", return_value="yaml"), \
             patch("agentcage.backends.vm.generate_quadlets", return_value={"foo.container": "content"}):
            units = backend.generate_units(config, "", "", "testcage")

        assert "quadlets/foo.container" in units
        assert "foo.container" not in units


class TestUnitDir:
    def test_unit_dir_path(self):
        backend = VmBackend()
        expected = Path(os.path.expanduser("~/.config/agentcage/lima"))
        assert backend.unit_dir() == expected


class TestInstallUnits:
    def test_writes_files_to_unit_dir(self, tmp_path):
        backend = VmBackend()
        units = {
            "lima.yaml": "lima yaml content",
            "quadlets/testcage-cage.container": "[Container]\nImage=test",
        }

        with patch.object(backend, "unit_dir", return_value=tmp_path):
            backend.install_units(units)

        assert (tmp_path / "lima.yaml").read_text() == "lima yaml content"
        assert (tmp_path / "quadlets" / "testcage-cage.container").read_text() == "[Container]\nImage=test"

    def test_creates_parent_dirs(self, tmp_path):
        backend = VmBackend()
        units = {"quadlets/nested/dir/file.container": "content"}

        with patch.object(backend, "unit_dir", return_value=tmp_path):
            backend.install_units(units)

        assert (tmp_path / "quadlets" / "nested" / "dir" / "file.container").exists()

    def test_echoes_install_message(self, tmp_path, capsys):
        backend = VmBackend()
        with patch.object(backend, "unit_dir", return_value=tmp_path):
            backend.install_units({"lima.yaml": "content"})
        captured = capsys.readouterr()
        assert "Installed" in captured.out


class TestStart:
    def test_creates_instance_if_not_exists(self, tmp_path):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = False
        mock_inst.name = "agentcage-testcage"

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=tmp_path), \
             patch.object(backend, "_deploy_cage"):
            backend.start("testcage")

        mock_inst.create.assert_called_once_with(str(tmp_path / "lima.yaml"))
        mock_inst.start.assert_not_called()

    def test_starts_stopped_instance(self, tmp_path):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = True
        mock_inst.is_running.return_value = False
        mock_inst.name = "agentcage-testcage"

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=tmp_path), \
             patch.object(backend, "_deploy_cage"):
            backend.start("testcage")

        mock_inst.start.assert_called_once()
        mock_inst.create.assert_not_called()

    def test_skips_start_if_already_running(self, tmp_path):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = True
        mock_inst.is_running.return_value = True
        mock_inst.name = "agentcage-testcage"

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=tmp_path), \
             patch.object(backend, "_deploy_cage"):
            backend.start("testcage")

        mock_inst.start.assert_not_called()
        mock_inst.create.assert_not_called()

    def test_deploys_cage_after_start(self, tmp_path):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = True
        mock_inst.is_running.return_value = True

        deploy_calls = []
        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=tmp_path), \
             patch.object(backend, "_deploy_cage", side_effect=lambda n, i, c=None: deploy_calls.append((n, i))), \
             patch("agentcage.state.load_deployment_config", return_value=MagicMock()):
            backend.start("testcage")

        assert len(deploy_calls) == 1
        assert deploy_calls[0][0] == "testcage"

    def test_echoes_started_message(self, tmp_path, capsys):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = True
        mock_inst.is_running.return_value = True

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=tmp_path), \
             patch.object(backend, "_deploy_cage"), \
             patch("agentcage.state.load_deployment_config", return_value=MagicMock()):
            backend.start("testcage")

        captured = capsys.readouterr()
        assert "testcage" in captured.out
        assert "Lima VM" in captured.out


class TestStop:
    def test_stops_services_then_vm_when_running(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True

        with patch.object(backend, "_instance", return_value=mock_inst):
            backend.stop("testcage")

        # systemctl stop called for each service
        exec_calls = [c[0][0] for c in mock_inst.exec.call_args_list]
        service_stop_calls = [c for c in exec_calls if "stop" in c]
        assert len(service_stop_calls) == 3  # cage, proxy, dns

        mock_inst.stop.assert_called_once()

    def test_stops_all_service_names(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True

        with patch.object(backend, "_instance", return_value=mock_inst):
            backend.stop("testcage")

        exec_calls = mock_inst.exec.call_args_list
        stopped_services = []
        for c in exec_calls:
            cmd = c[0][0]
            if "stop" in cmd:
                stopped_services.append(cmd[-1])

        assert "testcage-cage.service" in stopped_services
        assert "testcage-proxy.service" in stopped_services
        assert "testcage-dns.service" in stopped_services

    def test_does_not_stop_if_not_running(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = False

        with patch.object(backend, "_instance", return_value=mock_inst):
            backend.stop("testcage")

        mock_inst.stop.assert_not_called()
        mock_inst.exec.assert_not_called()

    def test_continues_if_service_stop_fails(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_inst.exec.side_effect = Exception("service stop failed")

        with patch.object(backend, "_instance", return_value=mock_inst):
            # Should not raise
            backend.stop("testcage")

        mock_inst.stop.assert_called_once()


class TestDestroyResources:
    def test_deletes_instance_if_exists(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = True
        mock_inst.name = "agentcage-testcage"
        backend._podman = MagicMock()
        backend._podman.secret_list.return_value = []

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=Path("/nonexistent/path")):
            removed = backend.destroy_resources("testcage")

        mock_inst.delete.assert_called_once()
        assert "lima-instance:agentcage-testcage" in removed

    def test_skips_delete_if_not_exists(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = False
        backend._podman = MagicMock()
        backend._podman.secret_list.return_value = []

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=Path("/nonexistent/path")):
            removed = backend.destroy_resources("testcage")

        mock_inst.delete.assert_not_called()
        assert not any("lima-instance" in r for r in removed)

    def test_removes_cage_config_files_not_shared_dir(self, tmp_path):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = False
        backend._podman = MagicMock()
        backend._podman.secret_list.return_value = []

        unit_dir = tmp_path / "lima"
        unit_dir.mkdir()
        (unit_dir / "lima.yaml").write_text("content")
        quadlets_dir = unit_dir / "quadlets"
        quadlets_dir.mkdir()
        (quadlets_dir / "test.container").write_text("content")

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=unit_dir):
            removed = backend.destroy_resources("testcage")

        # Shared parent directory must be preserved
        assert unit_dir.exists()
        # But cage-specific files should be removed
        assert not (unit_dir / "lima.yaml").exists()
        assert not quadlets_dir.exists()
        assert f"config:{unit_dir / 'lima.yaml'}" in removed
        assert f"quadlets:{quadlets_dir}" in removed

    def test_removes_secrets_by_default(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = False

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=Path("/nonexistent/path")):
            removed = backend.destroy_resources("testcage")

        # No host-side secrets to remove (everything is inside the VM)
        assert removed == []


class TestIsRunning:
    def test_false_when_vm_not_running(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = False

        with patch.object(backend, "_instance", return_value=mock_inst):
            result = backend.is_running("testcage", "cage")

        assert result is False
        mock_inst.exec.assert_not_called()

    def test_true_when_service_active(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_exec_result = MagicMock()
        mock_exec_result.stdout = "active\n"
        mock_inst.exec.return_value = mock_exec_result

        with patch.object(backend, "_instance", return_value=mock_inst):
            result = backend.is_running("testcage", "cage")

        assert result is True
        mock_inst.exec.assert_called_once_with(
            ["systemctl", "--user", "is-active", "testcage-cage.service"],
            check=False,
        )

    def test_false_when_service_inactive(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_exec_result = MagicMock()
        mock_exec_result.stdout = "inactive"
        mock_inst.exec.return_value = mock_exec_result

        with patch.object(backend, "_instance", return_value=mock_inst):
            result = backend.is_running("testcage", "cage")

        assert result is False

    def test_false_when_exec_raises(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_inst.exec.side_effect = Exception("limactl error")

        with patch.object(backend, "_instance", return_value=mock_inst):
            result = backend.is_running("testcage", "cage")

        assert result is False

    def test_checks_correct_service_name(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_exec_result = MagicMock()
        mock_exec_result.stdout = "active"
        mock_inst.exec.return_value = mock_exec_result

        with patch.object(backend, "_instance", return_value=mock_inst):
            backend.is_running("mycage", "proxy")

        cmd = mock_inst.exec.call_args[0][0]
        assert "mycage-proxy.service" in cmd


class TestServiceNames:
    def test_returns_cage_proxy_dns(self):
        backend = VmBackend()
        assert backend.service_names("anything") == ["cage", "proxy", "dns"]

    def test_name_argument_ignored(self):
        backend = VmBackend()
        assert backend.service_names("foo") == backend.service_names("bar")


class TestWaitInfraActive:
    """Behavioral tests for _wait_infra_active — the replacement for
    the unconditional 5-second sleep that previously gated systemd startup."""

    def test_returns_empty_immediately_when_all_active(self):
        from agentcage.backends.vm import _wait_infra_active

        mock_inst = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "active"
        mock_inst.exec.return_value = mock_result

        import time as _time
        t0 = _time.monotonic()
        pending = _wait_infra_active(
            mock_inst, ["a-net-network", "b-certs-volume"],
            timeout_s=5.0, interval_s=0.01,
        )
        elapsed = _time.monotonic() - t0

        assert pending == []
        # The whole call should be a single poll round (no sleep) — well
        # under the old unconditional 5-second wait.
        assert elapsed < 0.5

    def test_returns_pending_when_timeout_elapses(self):
        from agentcage.backends.vm import _wait_infra_active

        mock_inst = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "activating"
        mock_inst.exec.return_value = mock_result

        pending = _wait_infra_active(
            mock_inst, ["x-foo"],
            timeout_s=0.05, interval_s=0.01,
        )
        assert pending == ["x-foo"]

    def test_polls_until_active(self):
        from agentcage.backends.vm import _wait_infra_active

        mock_inst = MagicMock()
        # First two polls report not-active, third reports active.
        sequence = [
            MagicMock(stdout="activating"),
            MagicMock(stdout="activating"),
            MagicMock(stdout="active"),
        ]
        mock_inst.exec.side_effect = sequence

        pending = _wait_infra_active(
            mock_inst, ["a-net"],
            timeout_s=5.0, interval_s=0.01,
        )
        assert pending == []
        assert mock_inst.exec.call_count == 3


class TestGetBackend:
    def test_returns_vm_backend_for_vm_isolation(self):
        from agentcage.backends import get_backend
        config = _make_config()
        config.isolation = "vm"
        backend = get_backend(config)
        assert isinstance(backend, VmBackend)

    def test_returns_container_backend_for_container_isolation(self):
        from agentcage.backends import get_backend
        from agentcage.backends.container import ContainerBackend
        config = _make_config()
        config.isolation = "container"
        backend = get_backend(config)
        assert isinstance(backend, ContainerBackend)

    def test_returns_container_backend_for_default(self):
        from agentcage.backends import get_backend
        from agentcage.backends.container import ContainerBackend
        config = Config()
        backend = get_backend(config)
        assert isinstance(backend, ContainerBackend)
