"""Unit tests for agentcage.backends.container — ContainerBackend."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from agentcage.backends.container import ContainerBackend
from agentcage.config import Config, ContainerConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(name: str = "testcage") -> Config:
    cfg = Config()
    cfg.name = name
    cfg.container = ContainerConfig()
    cfg.container.image = "localhost/test:latest"
    return cfg


# ---------------------------------------------------------------------------
# check_prerequisites
# ---------------------------------------------------------------------------

class TestCheckPrerequisites:
    def test_ok_when_podman_available(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "info", return_value={}):
            issues = backend.check_prerequisites(_make_config())
        assert issues == []

    def test_issue_when_podman_fails(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "info", side_effect=RuntimeError("not found")):
            issues = backend.check_prerequisites(_make_config())
        assert len(issues) == 1
        assert "Podman" in issues[0]


# ---------------------------------------------------------------------------
# build_artifacts
# ---------------------------------------------------------------------------

class TestBuildArtifacts:
    def test_builds_proxy_and_dns(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "build_image") as mock_build:
            backend.build_artifacts(_make_config(), "testcage")

        assert mock_build.call_count == 2
        tags = [c.args[0] for c in mock_build.call_args_list]
        assert "agentcage-proxy" in tags
        assert "agentcage-dns" in tags


# ---------------------------------------------------------------------------
# generate_units
# ---------------------------------------------------------------------------

class TestGenerateUnits:
    def test_returns_dict_of_quadlet_files(self):
        backend = ContainerBackend()
        info_data = {"host": {"security": {"rootless": True}}}

        with patch.object(backend._podman, "info", return_value=info_data), \
             patch("agentcage.backends.container.generate_quadlets", return_value={
                 "test-cage.container": "[Container]\nImage=test",
                 "test-proxy.container": "[Container]\nImage=proxy",
             }) as mock_gen:
            units = backend.generate_units(
                _make_config(), "/path/to/config.yaml", "/path/to/patches", "test"
            )

        assert "test-cage.container" in units
        assert "test-proxy.container" in units
        mock_gen.assert_called_once()


# ---------------------------------------------------------------------------
# install_units
# ---------------------------------------------------------------------------

class TestInstallUnits:
    def test_writes_files_to_unit_dir(self, tmp_path):
        backend = ContainerBackend()
        unit_dir = tmp_path / "systemd"

        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload"):
            backend.install_units({
                "test-cage.container": "[Container]\nImage=test",
                "test-net.network": "[Network]\nSubnet=10.0.0.0/24",
            })

        assert (unit_dir / "test-cage.container").read_text() == "[Container]\nImage=test"
        assert (unit_dir / "test-net.network").read_text() == "[Network]\nSubnet=10.0.0.0/24"

    def test_calls_daemon_reload(self, tmp_path):
        backend = ContainerBackend()
        unit_dir = tmp_path / "systemd"

        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload") as mock_reload:
            backend.install_units({"f.container": "content"})

        mock_reload.assert_called_once()


# ---------------------------------------------------------------------------
# start / stop / restart
# ---------------------------------------------------------------------------

class TestStart:
    def test_starts_cage_service(self):
        backend = ContainerBackend()
        with patch("agentcage.backends.container.systemd") as mock_sd, \
             patch.object(backend, "unit_dir", return_value=Path("/fake")):
            backend.start("myapp")

        mock_sd.start_unit.assert_called_once_with("myapp-cage.service")

    def test_restarts_network_and_volume_first(self):
        backend = ContainerBackend()
        with patch("agentcage.backends.container.systemd") as mock_sd, \
             patch.object(backend, "unit_dir", return_value=Path("/fake")):
            backend.start("myapp")

        mock_sd.restart_unit.assert_any_call("myapp-net-network.service")
        mock_sd.restart_unit.assert_any_call("myapp-certs-volume.service")


class TestStop:
    def test_stops_all_services(self):
        backend = ContainerBackend()
        with patch("agentcage.backends.container.systemd") as mock_sd:
            backend.stop("myapp")

        expected = [
            call("myapp-cage.service"),
            call("myapp-proxy.service"),
            call("myapp-dns.service"),
        ]
        mock_sd.stop_unit.assert_has_calls(expected, any_order=True)

    def test_continues_on_stop_failure(self):
        backend = ContainerBackend()
        with patch("agentcage.backends.container.systemd") as mock_sd:
            mock_sd.stop_unit.side_effect = RuntimeError("failed")
            # Should not raise
            backend.stop("myapp")


class TestRestart:
    def test_restarts_all_services(self):
        backend = ContainerBackend()
        with patch("agentcage.backends.container.systemd") as mock_sd:
            backend.restart("myapp")

        expected = [
            call("myapp-cage.service"),
            call("myapp-proxy.service"),
            call("myapp-dns.service"),
        ]
        mock_sd.restart_unit.assert_has_calls(expected, any_order=True)


# ---------------------------------------------------------------------------
# destroy_resources
# ---------------------------------------------------------------------------

class TestDestroyResources:
    def test_removes_quadlet_files(self, tmp_path):
        backend = ContainerBackend()
        unit_dir = tmp_path / "systemd"
        unit_dir.mkdir()

        # Create some quadlet files
        (unit_dir / "myapp-cage.container").write_text("")
        (unit_dir / "myapp-proxy.container").write_text("")
        (unit_dir / "myapp-net.network").write_text("")

        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload"), \
             patch.object(backend._podman, "network_remove", return_value=True), \
             patch.object(backend._podman, "volume_remove", return_value=True), \
             patch.object(backend._podman, "secret_list", return_value=[]), \
             patch.object(backend._podman, "secret_remove", return_value=True):
            removed = backend.destroy_resources("myapp")

        assert "myapp-cage.container" in removed
        assert "myapp-proxy.container" in removed
        assert not (unit_dir / "myapp-cage.container").exists()

    def test_removes_podman_resources(self, tmp_path):
        backend = ContainerBackend()
        unit_dir = tmp_path / "systemd"
        unit_dir.mkdir()

        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload"), \
             patch.object(backend._podman, "network_remove", return_value=True) as mock_net, \
             patch.object(backend._podman, "volume_remove", return_value=True) as mock_vol, \
             patch.object(backend._podman, "secret_list", return_value=[]), \
             patch.object(backend._podman, "secret_remove", return_value=True):
            removed = backend.destroy_resources("myapp")

        mock_net.assert_called_once_with("myapp-net")
        assert "network:myapp-net" in removed
        assert "volume:agentcage-certs-myapp" in removed

    def test_removes_secrets_by_default(self, tmp_path):
        backend = ContainerBackend()
        unit_dir = tmp_path / "systemd"
        unit_dir.mkdir()

        secrets = [{"Name": "myapp.API_KEY"}, {"Name": "myapp.OTHER"}]
        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload"), \
             patch.object(backend._podman, "network_remove", return_value=False), \
             patch.object(backend._podman, "volume_remove", return_value=False), \
             patch.object(backend._podman, "secret_list", return_value=secrets), \
             patch.object(backend._podman, "secret_remove", return_value=True) as mock_rm:
            removed = backend.destroy_resources("myapp")

        assert mock_rm.call_count == 2
        assert "secret:myapp.API_KEY" in removed
        assert "secret:myapp.OTHER" in removed

    def test_keep_secrets_flag(self, tmp_path):
        backend = ContainerBackend()
        unit_dir = tmp_path / "systemd"
        unit_dir.mkdir()

        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload"), \
             patch.object(backend._podman, "network_remove", return_value=False), \
             patch.object(backend._podman, "volume_remove", return_value=False), \
             patch.object(backend._podman, "secret_list", return_value=[]) as mock_list:
            backend.destroy_resources("myapp", keep_secrets=True)

        mock_list.assert_not_called()


# ---------------------------------------------------------------------------
# is_running / service_names
# ---------------------------------------------------------------------------

class TestIsRunning:
    def test_delegates_to_podman(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "container_running", return_value=True) as mock:
            assert backend.is_running("myapp", "proxy") is True
        mock.assert_called_once_with("myapp-proxy")

    def test_not_running(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "container_running", return_value=False):
            assert backend.is_running("myapp", "cage") is False


class TestServiceNames:
    def test_returns_expected_services(self):
        backend = ContainerBackend()
        assert backend.service_names("myapp") == ["cage", "proxy", "dns"]


# ---------------------------------------------------------------------------
# exec_argv — uid wiring for ``agentcage run --as-root`` parity with Apple
# ---------------------------------------------------------------------------

class TestExecArgv:
    """SECURITY: ``podman exec`` must pass ``-u`` explicitly so the cage
    Quadlet's possibly-empty ``User=`` (ubuntu scaffold) doesn't cause
    the session to inherit the image's USER (root on ubuntu:latest).

    Pre-fix history:
      - ``agentcage run ubuntu`` on linux/podman landed at uid 0, while
        the apple-container path correctly dropped to uid 1000 via
        capsh — the inconsistency this test guards against."""

    def test_default_drops_to_uid_1000(self):
        backend = ContainerBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"])
        assert argv == ["podman", "exec", "-u", "1000", "myapp-cage", "bash"]

    def test_as_root_uses_uid_0(self):
        backend = ContainerBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"], as_root=True)
        assert argv == ["podman", "exec", "-u", "0", "myapp-cage", "bash"]

    def test_interactive_adds_it_flag(self):
        backend = ContainerBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"], interactive=True)
        assert argv == ["podman", "exec", "-u", "1000", "-it", "myapp-cage", "bash"]

    def test_as_root_with_interactive(self):
        backend = ContainerBackend()
        argv = backend.exec_argv(
            "myapp", "proxy", ["sh"], interactive=True, as_root=True,
        )
        assert argv == ["podman", "exec", "-u", "0", "-it", "myapp-proxy", "sh"]

    def test_service_suffix_applied(self):
        backend = ContainerBackend()
        argv = backend.exec_argv("foo", "dns", ["cat", "/etc/hosts"])
        assert argv == [
            "podman", "exec", "-u", "1000", "foo-dns", "cat", "/etc/hosts",
        ]
