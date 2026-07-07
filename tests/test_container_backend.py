"""Unit tests for agentcage.backends.container — ContainerBackend."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from agentcage.backends.container import ContainerBackend
from agentcage.config import Config, ContainerConfig
from agentcage.podman import secret_env_names


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
# secret_env_names (agentcage.podman helper — issue #262)
# ---------------------------------------------------------------------------

class TestSecretEnvNames:
    def test_strips_deploy_prefix(self):
        podman = MagicMock()
        podman.secret_list.return_value = [
            {"Name": "myapp.API_KEY"}, {"Name": "myapp.TOKEN"},
        ]
        assert secret_env_names(podman, "myapp") == {"API_KEY", "TOKEN"}
        podman.secret_list.assert_called_once_with(prefix="myapp.")

    def test_bare_names_without_deploy_name(self):
        podman = MagicMock()
        podman.secret_list.return_value = [{"Name": "API_KEY"}]
        assert secret_env_names(podman, "") == {"API_KEY"}
        podman.secret_list.assert_called_once_with(prefix="")

    def test_empty_store(self):
        podman = MagicMock()
        podman.secret_list.return_value = []
        assert secret_env_names(podman, "myapp") == set()


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
    def test_builds_egress(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "build_image") as mock_build:
            backend.build_artifacts(_make_config(), "testcage")

        # The v0.22 2-service shape ships a single agentcage-egress image
        # (mitmproxy + dnsmasq combined) instead of the legacy proxy+dns pair.
        assert mock_build.call_count == 1
        tag = mock_build.call_args.args[0]
        assert tag.startswith("agentcage-egress:"), (
            f"expected agentcage-egress:<version>, got {tag!r}"
        )
        # The Containerfile path passed in is Containerfile.egress.
        cf = mock_build.call_args.args[1]
        assert cf.endswith("Containerfile.egress"), cf

    def test_does_not_build_legacy_proxy_or_dns(self):
        """B2: the legacy agentcage-proxy / agentcage-dns image tags are
        gone — confirm we don't accidentally still produce them."""
        backend = ContainerBackend()
        with patch.object(backend._podman, "build_image") as mock_build:
            backend.build_artifacts(_make_config(), "testcage")
        tags = [c.args[0] for c in mock_build.call_args_list]
        for legacy in ("agentcage-proxy", "agentcage-dns"):
            assert not any(t == legacy or t.startswith(f"{legacy}:")
                           for t in tags), (
                f"unexpected legacy image build: {tags}"
            )

    def test_no_cache_and_pull_forwarded_to_egress_build(self):
        # The egress build used to drop these flags; a forced clean rebuild
        # must now rebuild the egress image too, like the vm/apple backends.
        backend = ContainerBackend()
        with patch.object(backend._podman, "build_image") as mock_build:
            backend.build_artifacts(
                _make_config(), "testcage", no_cache=True, pull=True,
            )
        assert mock_build.call_args.kwargs["no_cache"] is True
        assert mock_build.call_args.kwargs["pull"] is True

    def test_egress_build_defaults_no_force(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "build_image") as mock_build:
            backend.build_artifacts(_make_config(), "testcage")
        assert mock_build.call_args.kwargs.get("no_cache") is False
        assert mock_build.call_args.kwargs.get("pull") is False


# ---------------------------------------------------------------------------
# generate_units
# ---------------------------------------------------------------------------

class TestGenerateUnits:
    def test_returns_dict_of_quadlet_files(self):
        backend = ContainerBackend()
        info_data = {"host": {"security": {"rootless": True}}}

        with patch.object(backend._podman, "info", return_value=info_data), \
             patch.object(backend._podman, "secret_list", return_value=[]), \
             patch("agentcage.backends.container.generate_quadlets", return_value={
                 "test-cage.container": "[Container]\nImage=test",
                 "test-egress.container": "[Container]\nImage=egress",
             }) as mock_gen:
            units = backend.generate_units(
                _make_config(), "/path/to/config.yaml", "/path/to/patches", "test"
            )

        assert "test-cage.container" in units
        assert "test-egress.container" in units
        mock_gen.assert_called_once()

    def test_passes_store_secret_env_names(self):
        """Issue #262: generate_units must pass the env-name set of the
        cage's store entries so quadlet generation can skip Secret=
        directives that would not resolve at boot (`secret rm` leftovers)."""
        backend = ContainerBackend()
        info_data = {"host": {"security": {"rootless": True}}}
        listed = [{"Name": "test.API_KEY"}, {"Name": "test.OTHER"}]

        with patch.object(backend._podman, "info", return_value=info_data), \
             patch.object(backend._podman, "secret_list", return_value=listed) as mock_ls, \
             patch("agentcage.backends.container.generate_quadlets",
                   return_value={}) as mock_gen:
            backend.generate_units(
                _make_config(), "/c.yaml", "/patches", "test"
            )

        mock_ls.assert_called_once_with(prefix="test.")
        assert mock_gen.call_args.kwargs["store_secrets"] == {"API_KEY", "OTHER"}

    def test_store_query_failure_falls_back_to_none(self):
        """A store query failure must not drop Secret= lines — pass None
        (legacy emit-all) instead of an empty set."""
        backend = ContainerBackend()
        info_data = {"host": {"security": {"rootless": True}}}

        with patch.object(backend._podman, "info", return_value=info_data), \
             patch.object(backend._podman, "secret_list",
                          side_effect=RuntimeError("podman down")), \
             patch("agentcage.backends.container.generate_quadlets",
                   return_value={}) as mock_gen:
            backend.generate_units(
                _make_config(), "/c.yaml", "/patches", "test"
            )

        assert mock_gen.call_args.kwargs["store_secrets"] is None


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
        mock_sd.restart_unit.assert_any_call("myapp-public-certs-volume.service")


class TestStop:
    def test_stops_all_services(self):
        backend = ContainerBackend()
        with patch("agentcage.backends.container.systemd") as mock_sd:
            backend.stop("myapp")

        expected = [
            call("myapp-cage.service"),
            call("myapp-egress.service"),
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
            call("myapp-egress.service"),
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

        # Create some v0.22 quadlet files
        (unit_dir / "myapp-cage.container").write_text("")
        (unit_dir / "myapp-egress.container").write_text("")
        (unit_dir / "myapp-net.network").write_text("")

        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload"), \
             patch.object(backend._podman, "network_remove", return_value=True), \
             patch.object(backend._podman, "volume_remove", return_value=True), \
             patch.object(backend._podman, "secret_list", return_value=[]), \
             patch.object(backend._podman, "secret_remove", return_value=True):
            removed = backend.destroy_resources("myapp")

        assert "myapp-cage.container" in removed
        assert "myapp-egress.container" in removed
        assert not (unit_dir / "myapp-cage.container").exists()

    def test_removes_legacy_v021_quadlet_files(self, tmp_path):
        """B2 (eng review): destroy must enumerate the legacy proxy/dns
        filenames too so a v0.21 cage's leftovers can still be cleaned up
        after the v0.22 upgrade. _ensure_v022_cage blocks every OTHER cage
        command on legacy cages, but destroy is the documented escape
        hatch — the legacy filenames have to be in the enumeration here."""
        backend = ContainerBackend()
        unit_dir = tmp_path / "systemd"
        unit_dir.mkdir()

        # v0.21 layout — both proxy and dns containers in addition to cage
        (unit_dir / "myapp-cage.container").write_text("")
        (unit_dir / "myapp-proxy.container").write_text("")
        (unit_dir / "myapp-dns.container").write_text("")
        (unit_dir / "myapp-net.network").write_text("")
        (unit_dir / "myapp-certs.volume").write_text("")

        with patch.object(backend, "unit_dir", return_value=unit_dir), \
             patch("agentcage.backends.container.systemd.daemon_reload"), \
             patch.object(backend._podman, "network_remove", return_value=True), \
             patch.object(backend._podman, "volume_remove", return_value=True), \
             patch.object(backend._podman, "secret_list", return_value=[]), \
             patch.object(backend._podman, "secret_remove", return_value=True):
            removed = backend.destroy_resources("myapp")

        for legacy in ("myapp-proxy.container", "myapp-dns.container"):
            assert legacy in removed, (
                f"{legacy} not removed; v0.21 cleanup will leave the file behind. "
                f"(removed={removed})"
            )
            assert not (unit_dir / legacy).exists()

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
        # The public-certs volume is a separate podman volume — leaving it
        # behind across destroy would leave stale published certs that the
        # next cage with the same name would silently inherit.
        assert "volume:agentcage-public-certs-myapp" in removed
        mock_vol.assert_any_call("agentcage-public-certs-myapp")

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
            assert backend.is_running("myapp", "egress") is True
        mock.assert_called_once_with("myapp-egress")

    def test_not_running(self):
        backend = ContainerBackend()
        with patch.object(backend._podman, "container_running", return_value=False):
            assert backend.is_running("myapp", "cage") is False


class TestServiceNames:
    def test_returns_expected_services(self):
        backend = ContainerBackend()
        assert backend.service_names("myapp") == ["cage", "egress"]


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
        assert argv == ["podman", "exec", "-u", "1000:1000", "myapp-cage", "bash"]

    def test_as_root_uses_uid_0(self):
        backend = ContainerBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"], as_root=True)
        assert argv == ["podman", "exec", "-u", "0:0", "myapp-cage", "bash"]

    def test_interactive_adds_it_flag(self):
        backend = ContainerBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"], interactive=True)
        assert argv == ["podman", "exec", "-u", "1000:1000", "-it", "myapp-cage", "bash"]

    def test_as_root_with_interactive(self):
        backend = ContainerBackend()
        argv = backend.exec_argv(
            "myapp", "egress", ["sh"], interactive=True, as_root=True,
        )
        assert argv == ["podman", "exec", "-u", "0:0", "-it", "myapp-egress", "sh"]

    def test_service_suffix_applied(self):
        backend = ContainerBackend()
        argv = backend.exec_argv("foo", "egress", ["cat", "/etc/hosts"])
        assert argv == [
            "podman", "exec", "-u", "1000:1000", "foo-egress", "cat", "/etc/hosts",
        ]
