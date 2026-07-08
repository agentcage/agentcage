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
    def test_builds_egress_image_inside_vm(self):
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_inst.name = "agentcage-testcage"
        config = _make_config()

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch("subprocess.run") as mock_sp_run:
            mock_sp_run.return_value = MagicMock(returncode=0)
            backend.build_artifacts(config, "testcage")

        # v0.22: a single agentcage-egress image replaces the legacy proxy
        # + dns image pair. The cage image is pulled (or built) too.
        exec_calls = mock_inst.exec.call_args_list
        build_calls = [c for c in exec_calls if "podman" in str(c) and "build" in str(c)]
        assert len(build_calls) == 1, (
            f"expected exactly one image build (egress); got {len(build_calls)}"
        )
        assert "agentcage-egress" in str(build_calls[0])
        # Legacy tags must NOT appear — verifies the legacy pair was dropped.
        for legacy in ("agentcage-proxy", "agentcage-dns"):
            assert legacy not in str(build_calls[0]), (
                f"unexpected legacy image build: {build_calls[0]}"
            )
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

    def _egress_build_call(self, *, no_cache: bool, pull: bool):
        """Run build_artifacts inside a mocked VM and return the egress
        `podman build` exec call as a string."""
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_inst.name = "agentcage-testcage"
        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)):
            backend.build_artifacts(
                _make_config(), "testcage", no_cache=no_cache, pull=pull,
            )
        build_calls = [
            c for c in mock_inst.exec.call_args_list
            if "podman" in str(c) and "build" in str(c)
        ]
        assert len(build_calls) == 1
        return str(build_calls[0])

    def test_no_cache_and_pull_reach_egress_build(self):
        # The flags must force a clean egress rebuild inside the VM — the
        # bug this fixes was vm.build_artifacts dropping them entirely.
        egress = self._egress_build_call(no_cache=True, pull=True)
        assert "--no-cache" in egress
        assert "--pull=always" in egress

    def test_egress_build_omits_flags_by_default(self):
        egress = self._egress_build_call(no_cache=False, pull=False)
        assert "--no-cache" not in egress
        assert "--pull=always" not in egress

    def test_cage_image_build_receives_flags(self):
        # When the scaffold ships a Containerfile, the in-VM cage build must
        # also get the flags (threaded via build_flags).
        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.is_running.return_value = True
        mock_inst.name = "agentcage-testcage"
        config = _make_config()
        config.container.build.containerfile = "Containerfile"

        with patch.object(backend, "_instance", return_value=mock_inst), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)), \
             patch.object(backend, "_build_cage_image_in_vm") as mock_build:
            backend.build_artifacts(config, "testcage", no_cache=True, pull=True)

        mock_build.assert_called_once()
        assert mock_build.call_args.kwargs["build_flags"] == [
            "--no-cache", "--pull=always",
        ]


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
            store_secrets=None,
        )

        assert "lima.yaml" in units
        assert units["lima.yaml"] == "lima: yaml content"
        assert "quadlets/testcage-cage.container" in units
        assert "quadlets/testcage-net.network" in units

    def test_store_secrets_queried_from_running_guest(self):
        """Issue #262: for VM cages the podman secret store lives inside
        the guest — when the Lima instance is running, generate_units
        must pass the guest store's env-name set so `secret rm` leftovers
        drop their Secret= directive."""
        backend = VmBackend()
        config = _make_config()
        inst = MagicMock()
        inst.exists.return_value = True
        inst.is_running.return_value = True
        vm_podman = MagicMock()
        vm_podman.secret_list_strict.return_value = [{"Name": "testcage.API_KEY"}]

        with patch("agentcage.backends.vm.generate_lima_config", return_value="y"), \
             patch("agentcage.backends.vm.LimaInstance", return_value=inst), \
             patch("agentcage.lima.podman.VmPodman", return_value=vm_podman), \
             patch("agentcage.backends.vm.generate_quadlets",
                   return_value={}) as mock_q:
            backend.generate_units(config, "", "", "testcage")

        vm_podman.secret_list_strict.assert_called_once_with(prefix="testcage.")
        assert mock_q.call_args.kwargs["store_secrets"] == {"API_KEY"}

    def test_store_secrets_none_when_guest_stopped(self):
        """Guest not running → store unqueryable → None (legacy emit-all;
        also the initial-create path where pending secrets land only
        after the VM first starts)."""
        backend = VmBackend()
        config = _make_config()
        inst = MagicMock()
        inst.exists.return_value = True
        inst.is_running.return_value = False

        with patch("agentcage.backends.vm.generate_lima_config", return_value="y"), \
             patch("agentcage.backends.vm.LimaInstance", return_value=inst), \
             patch("agentcage.backends.vm.generate_quadlets",
                   return_value={}) as mock_q:
            backend.generate_units(config, "", "", "testcage")

        assert mock_q.call_args.kwargs["store_secrets"] is None

    def test_store_secrets_none_when_guest_query_fails(self):
        """Guest running but `podman secret ls` fails → None (legacy
        emit-all), NOT an empty set, which would drop every Secret= line
        (issue #262)."""
        backend = VmBackend()
        config = _make_config()
        inst = MagicMock()
        inst.exists.return_value = True
        inst.is_running.return_value = True
        vm_podman = MagicMock()
        vm_podman.secret_list_strict.side_effect = RuntimeError("guest podman down")

        with patch("agentcage.backends.vm.generate_lima_config", return_value="y"), \
             patch("agentcage.backends.vm.LimaInstance", return_value=inst), \
             patch("agentcage.lima.podman.VmPodman", return_value=vm_podman), \
             patch("agentcage.backends.vm.generate_quadlets",
                   return_value={}) as mock_q:
            backend.generate_units(config, "", "", "testcage")

        assert mock_q.call_args.kwargs["store_secrets"] is None

    def test_quadlet_keys_prefixed_correctly(self):
        backend = VmBackend()
        config = _make_config()

        with patch("agentcage.backends.vm.generate_lima_config", return_value="yaml"), \
             patch("agentcage.backends.vm.generate_quadlets", return_value={"foo.container": "content"}):
            units = backend.generate_units(config, "", "", "testcage")

        assert "quadlets/foo.container" in units
        assert "foo.container" not in units

    def test_floors_timeout_start_sec_for_vm(self):
        """Cage start inside Lima brushes 90-120s on first run (qemu boot +
        fuse-overlayfs layer extraction + per-cage podman network). The
        pi scaffold's default of 60s reliably times out the cage
        container with a baffling 'failed because a timeout was
        exceeded'. VM-mode floors to 300s so a real start has room to
        finish but a genuinely stuck cage still fails before the
        operator gives up."""
        backend = VmBackend()
        config = _make_config()
        config.container.timeout_start_sec = 60  # what the pi scaffold sets

        with patch("agentcage.backends.vm.generate_lima_config", return_value="y"), \
             patch("agentcage.backends.vm.generate_quadlets",
                   return_value={}) as mock_q:
            backend.generate_units(config, "", "", "testcage")

        # Quadlets must be generated with the floored value, not the
        # 60s the scaffold wrote.
        passed_cfg = mock_q.call_args.args[0]
        assert passed_cfg.container.timeout_start_sec == 300

    def test_preserves_timeout_start_sec_above_floor(self):
        """If the scaffold/user already set a value >= 300s, don't lower it."""
        backend = VmBackend()
        config = _make_config()
        config.container.timeout_start_sec = 600

        with patch("agentcage.backends.vm.generate_lima_config", return_value="y"), \
             patch("agentcage.backends.vm.generate_quadlets",
                   return_value={}) as mock_q:
            backend.generate_units(config, "", "", "testcage")

        passed_cfg = mock_q.call_args.args[0]
        assert passed_cfg.container.timeout_start_sec == 600


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
        assert len(service_stop_calls) == 2  # cage, egress

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
        assert "testcage-egress.service" in stopped_services

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
            backend.is_running("mycage", "egress")

        cmd = mock_inst.exec.call_args[0][0]
        assert "mycage-egress.service" in cmd


class TestServiceNames:
    def test_returns_cage_egress(self):
        backend = VmBackend()
        assert backend.service_names("anything") == ["cage", "egress"]

    def test_name_argument_ignored(self):
        backend = VmBackend()
        assert backend.service_names("foo") == backend.service_names("bar")


# ---------------------------------------------------------------------------
# exec_argv — uid wiring for ``agentcage run --as-root`` parity with Apple
# ---------------------------------------------------------------------------

class TestExecArgv:
    """SECURITY: ``podman exec`` inside the Lima VM must pass ``-u``
    explicitly. The cage Quadlet's ``User=`` may be empty (ubuntu
    scaffold), so without an explicit ``-u`` the session inherits the
    image's USER — root on ubuntu:latest. Same fix as
    ContainerBackend.exec_argv — keeps linux/vm/apple aligned."""

    def test_default_drops_to_uid_1000(self):
        backend = VmBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"])
        assert argv == [
            "limactl", "shell", "--workdir", "/", "agentcage-myapp", "--",
            "podman", "exec", "-u", "1000:1000", "myapp-cage", "bash",
        ]

    def test_as_root_uses_uid_0(self):
        backend = VmBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"], as_root=True)
        assert argv == [
            "limactl", "shell", "--workdir", "/", "agentcage-myapp", "--",
            "podman", "exec", "-u", "0:0", "myapp-cage", "bash",
        ]

    def test_interactive_adds_it_flag(self):
        backend = VmBackend()
        argv = backend.exec_argv("myapp", "cage", ["bash"], interactive=True)
        assert argv == [
            "limactl", "shell", "--workdir", "/", "agentcage-myapp", "--",
            "podman", "exec", "-u", "1000:1000", "-it", "myapp-cage", "bash",
        ]

    def test_as_root_with_interactive(self):
        backend = VmBackend()
        argv = backend.exec_argv(
            "myapp", "egress", ["sh"], interactive=True, as_root=True,
        )
        assert argv == [
            "limactl", "shell", "--workdir", "/", "agentcage-myapp", "--",
            "podman", "exec", "-u", "0:0", "-it", "myapp-egress", "sh",
        ]


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


class TestSystemctlStart:
    """Regression coverage for the diagnostic improvements around
    systemctl --user start failures inside the VM."""

    def test_surfaces_stderr_and_journal_on_failure(self, capsys):
        from agentcage.backends.vm import _systemctl_start
        import subprocess

        mock_inst = MagicMock()
        start_err = subprocess.CalledProcessError(
            1, ["systemctl", "--user", "start", "foo-cage.service"],
            stderr="Failed to start foo-cage.service: Unit not found.\n",
        )
        status_result = MagicMock(stdout="● foo-cage.service - agentcage cage\n"
                                         "   Active: failed (Result: exit-code)\n")
        journal_result = MagicMock(stdout="May 26 18:42 boom: ExecStartPre "
                                          "timed out waiting for CA cert\n")
        # First call raises (the start). Then status, then journal succeed.
        mock_inst.exec.side_effect = [start_err, status_result, journal_result]

        _systemctl_start(mock_inst, "foo-cage")

        err = capsys.readouterr().err
        # Operator now sees: the warning header, systemctl stderr, status
        # output, AND the journalctl lines — instead of an opaque
        # CalledProcessError repr.
        assert "failed to start foo-cage" in err
        assert "Unit not found" in err
        assert "Active: failed" in err
        assert "timed out waiting for CA cert" in err

    def test_silent_on_success(self, capsys):
        from agentcage.backends.vm import _systemctl_start

        mock_inst = MagicMock()
        mock_inst.exec.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _systemctl_start(mock_inst, "foo-cage")

        assert capsys.readouterr().err == ""
        mock_inst.exec.assert_called_once_with(
            ["systemctl", "--user", "start", "foo-cage.service"]
        )

    def test_restart_flag_uses_restart_verb(self, capsys):
        from agentcage.backends.vm import _systemctl_start

        mock_inst = MagicMock()
        mock_inst.exec.return_value = MagicMock(returncode=0)
        _systemctl_start(mock_inst, "foo-egress", restart=True)

        mock_inst.exec.assert_called_once_with(
            ["systemctl", "--user", "restart", "foo-egress.service"]
        )


class TestDeployCageStartOrder:
    """The cage's ExecStartPre is a 30s poll for mitmproxy's CA cert.
    Starting cage in the same loop as the egress container races that
    cert generation and produces a spurious 'failed to start <name>-cage'
    warning before the second-attempt cage start (which is gated on
    wait_egress) succeeds. The fix: never start cage in the first loop;
    only start it after egress is confirmed active."""

    def test_cage_not_in_first_start_loop(self):
        from agentcage.backends.vm import VmBackend

        backend = VmBackend()
        mock_inst = MagicMock()
        mock_inst.exec.return_value = MagicMock(stdout="active", returncode=0)
        # Skip build_artifacts and the quadlet install step — focus on the
        # systemctl start ordering.
        with patch.object(backend, "build_artifacts"), \
             patch.object(backend, "_bridge_secrets"), \
             patch.object(backend, "_create_pending_secrets"), \
             patch("agentcage.backends.vm.VmBackend.unit_dir") as mock_unit_dir, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.iterdir", return_value=iter([])):
            mock_unit_dir.return_value = MagicMock()
            mock_unit_dir.return_value.__truediv__ = lambda self, other: MagicMock(
                exists=lambda: True, iterdir=lambda: iter([]),
            )
            backend._deploy_cage("foo", mock_inst, config=None)

        # Inspect every systemctl start/restart call that was issued.
        started = [
            call.args[0]
            for call in mock_inst.exec.call_args_list
            if len(call.args) > 0 and isinstance(call.args[0], list)
            and len(call.args[0]) >= 3
            and call.args[0][:3] == ["systemctl", "--user", "start"]
        ]
        # Sequence must be: infra services first, THEN cage — never both
        # in one loop. Asserting cage appears AFTER all infra entries
        # captures the ordering invariant the race-fix relies on.
        unit_seq = [s[3] for s in started]
        if "foo-cage.service" in unit_seq:
            cage_idx = unit_seq.index("foo-cage.service")
            infra = {"foo-net-network.service", "foo-certs-volume.service",
                     "foo-public-certs-volume.service", "foo-egress.service"}
            earlier = set(unit_seq[:cage_idx])
            # Every infra service that ran must have run before cage.
            assert infra.intersection(unit_seq).issubset(earlier), (
                f"cage started before some infra service: {unit_seq}"
            )


class TestPushConfigFiles:
    """``push_config_files`` mirrors proxy-config.yaml + dns-allowlist.conf
    into a VM-local path the cage quadlets bind-mount (bypassing the Lima
    reverse-sshfs cache). Called from ``_deploy_cage`` on every start /
    restart / deploy AND from ``_update_dns_quadlet`` on every domain edit."""

    @staticmethod
    def _mock_inst(home: str = "/home/lima") -> MagicMock:
        """Build a MagicMock LimaInstance that returns *home* for ``echo ~``.

        ``push_config_files`` resolves ``$HOME`` once in the guest before
        building any further shell commands; the mock must answer that
        probe so the later calls receive a real absolute path.
        """
        inst = MagicMock()
        inst.exec.return_value = MagicMock(stdout=f"{home}\n")
        return inst

    def test_creates_vm_local_directory(self, tmp_path, monkeypatch):
        # state._DEPLOYMENTS_DIR is computed at import time from env, so
        # monkeypatching the env var doesn't move the path — patch the
        # state.deployment_dir helper directly.
        d = tmp_path / "cages" / "demo"
        d.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(
            "agentcage.state.deployment_dir", lambda _name: d,
        )
        monkeypatch.setattr(
            "agentcage.state.dns_allowlist_path",
            lambda _name: d / "dns-allowlist.conf",
        )

        from agentcage.backends.vm import push_config_files
        inst = self._mock_inst(home="/home/lima")
        push_config_files("demo", inst)

        calls = inst.exec.call_args_list
        # First call resolves $HOME in the guest.
        assert calls[0].args[0] == ["bash", "-c", "echo ~"]
        # Second call must `mkdir -p` the VM-local config dir as an
        # absolute path — no `%h` (or `~`) left for the shell.
        assert calls[1].args[0] == [
            "mkdir", "-p", "/home/lima/.config/agentcage-vm/cages/demo",
        ]

    def test_pushes_both_files_when_present(self, tmp_path, monkeypatch):
        d = tmp_path / "cages" / "demo"
        d.mkdir(parents=True, exist_ok=True)
        (d / "proxy-config.yaml").write_text("domains: {allow: [example.com]}")
        (d / "dns-allowlist.conf").write_text("server=/example.com/1.1.1.1\n")
        monkeypatch.setattr(
            "agentcage.state.deployment_dir", lambda _name: d,
        )
        monkeypatch.setattr(
            "agentcage.state.dns_allowlist_path",
            lambda _name: d / "dns-allowlist.conf",
        )

        from agentcage.backends.vm import push_config_files
        inst = self._mock_inst(home="/home/lima")
        push_config_files("demo", inst)

        scripts = [
            c.args[0][2] for c in inst.exec.call_args_list
            if c.args[0][:2] == ["bash", "-c"]
        ]
        assert any(
            "/home/lima/.config/agentcage-vm/cages/demo/proxy-config.yaml"
            in s for s in scripts
        )
        assert any(
            "/home/lima/.config/agentcage-vm/cages/demo/dns-allowlist.conf"
            in s for s in scripts
        )

    def test_no_unexpanded_home_marker_in_shell_args(
        self, tmp_path, monkeypatch,
    ):
        """Regression: ``vm_local_*`` paths use ``%h`` (the systemd
        home-directory specifier) so quadlet ``Volume=`` lines work.
        Bash does NOT expand ``%h``, and ``shlex.quote`` would suppress
        ``~`` expansion too — so every shell argument we hand to the
        guest must already be absolute. Assert no ``%h`` or ``~`` leaks
        through. Without this, ``mkdir`` (or ``podman volume create``)
        sees a literal marker and fails."""
        d = tmp_path / "cages" / "demo"
        d.mkdir(parents=True, exist_ok=True)
        (d / "proxy-config.yaml").write_text("x")
        (d / "dns-allowlist.conf").write_text("y")
        monkeypatch.setattr("agentcage.state.deployment_dir", lambda _n: d)
        monkeypatch.setattr(
            "agentcage.state.dns_allowlist_path",
            lambda _n: d / "dns-allowlist.conf",
        )

        from agentcage.backends.vm import push_config_files
        inst = self._mock_inst(home="/home/lima")
        push_config_files("demo", inst)

        # Skip the first call (``echo ~`` — the legitimate home probe).
        for call in inst.exec.call_args_list[1:]:
            argv = call.args[0]
            for arg in argv:
                assert "%h" not in arg, (
                    f"unexpanded %h leaked into shell argument: {arg!r} "
                    f"(full argv: {argv!r})"
                )
                assert "~" not in arg, (
                    f"unexpanded ~ leaked into shell argument: {arg!r} "
                    f"(full argv: {argv!r})"
                )

    def test_skips_missing_files(self, tmp_path, monkeypatch):
        """A cage in blocklist mode may have an empty/missing allowlist
        file; missing file = skip push, never crash."""
        d = tmp_path / "cages" / "demo"
        d.mkdir(parents=True, exist_ok=True)
        # No proxy-config.yaml, no dns-allowlist.conf
        monkeypatch.setattr(
            "agentcage.state.deployment_dir", lambda _name: d,
        )
        monkeypatch.setattr(
            "agentcage.state.dns_allowlist_path",
            lambda _name: d / "dns-allowlist.conf",
        )

        from agentcage.backends.vm import push_config_files
        inst = self._mock_inst(home="/home/lima")
        push_config_files("demo", inst)

        # Two calls: resolve $HOME, then the mkdir. No file pushes.
        assert inst.exec.call_count == 2


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
