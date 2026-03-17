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
    def test_builds_proxy_and_dns_images(self):
        backend = VmBackend()
        mock_podman = MagicMock()
        backend._podman = mock_podman
        config = _make_config()

        backend.build_artifacts(config, "testcage")

        assert mock_podman.build_image.call_count == 2
        proxy_call = mock_podman.build_image.call_args_list[0]
        dns_call = mock_podman.build_image.call_args_list[1]

        assert proxy_call[0][0] == "agentcage-proxy"
        assert "Containerfile.proxy" in proxy_call[0][1]
        assert proxy_call[1]["no_cache"] is True
        assert "CAP_CHOWN" in proxy_call[1]["cap_add"]

        assert dns_call[0][0] == "agentcage-dns"
        assert "Containerfile.dns" in dns_call[0][1]
        assert "CAP_SETFCAP" in dns_call[1]["cap_add"]

    def test_proxy_build_echoes_message(self, capsys):
        backend = VmBackend()
        backend._podman = MagicMock()
        backend.build_artifacts(_make_config(), "testcage")
        captured = capsys.readouterr()
        assert "proxy" in captured.out.lower()
        assert "dns" in captured.out.lower()


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
        mock_quadlets.assert_called_once_with(config, "/path/config.yaml", "/path/patches", "testcage")

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
             patch.object(backend, "_deploy_cage", side_effect=lambda n, i: deploy_calls.append((n, i))):
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
             patch.object(backend, "_deploy_cage"):
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

    def test_removes_unit_dir_if_exists(self, tmp_path):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = False
        backend._podman = MagicMock()
        backend._podman.secret_list.return_value = []

        unit_dir = tmp_path / "lima"
        unit_dir.mkdir()
        (unit_dir / "lima.yaml").write_text("content")

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=unit_dir):
            removed = backend.destroy_resources("testcage")

        assert not unit_dir.exists()
        assert f"config-dir:{unit_dir}" in removed

    def test_removes_secrets_by_default(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = False
        backend._podman = MagicMock()
        backend._podman.secret_list.return_value = [{"Name": "testcage.mysecret"}]
        backend._podman.secret_remove.return_value = True

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=Path("/nonexistent/path")):
            removed = backend.destroy_resources("testcage")

        backend._podman.secret_list.assert_called_once_with(prefix="testcage.")
        backend._podman.secret_remove.assert_called_once_with("testcage.mysecret")
        assert "secret:testcage.mysecret" in removed

    def test_keep_secrets_skips_secret_removal(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exists.return_value = False
        backend._podman = MagicMock()

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch.object(backend, "unit_dir", return_value=Path("/nonexistent/path")):
            backend.destroy_resources("testcage", keep_secrets=True)

        backend._podman.secret_list.assert_not_called()
        backend._podman.secret_remove.assert_not_called()


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
