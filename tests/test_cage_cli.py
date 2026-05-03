"""Tests for the 'agentcage cage' CLI subcommands."""

from __future__ import annotations

import json
import textwrap
from unittest.mock import MagicMock, patch, call, ANY

import click
from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


class TestCageCreate:
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_fails_if_exists(self, mock_state, MockPodman, mock_systemd, minimal_yaml):
        mock_state.deployment_exists.return_value = True
        result = _runner().invoke(main, ["cage", "create", "-c", minimal_yaml])
        assert result.exit_code != 0
        assert "already exists" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_fails_on_missing_secrets(self, mock_state, MockPodman, mock_systemd, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
        """))
        mock_state.deployment_exists.return_value = False
        podman = MockPodman.return_value
        podman.secret_exists.return_value = False

        result = _runner().invoke(main, ["cage", "create", "-c", str(p)])
        assert result.exit_code != 0
        assert "missing secrets" in result.output
        assert "--set-secret" in result.output or "agentcage secret set" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_requires_config(self, mock_state, MockPodman, mock_systemd):
        result = _runner().invoke(main, ["cage", "create"])
        assert result.exit_code != 0


class TestCageUpdate:
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_fails_if_not_exists(self, mock_state, MockPodman, mock_systemd):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "update", "test"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_name_mismatch(self, mock_state, MockPodman, mock_systemd, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: other
            container:
              image: test:latest
        """))
        mock_state.deployment_exists.return_value = True
        result = _runner().invoke(main, ["cage", "update", "test", "-c", str(p)])
        assert result.exit_code != 0
        assert "does not match" in result.output


class TestCageUpdateBuildArgs:
    """Verify `cage update` re-resolves scaffold-declared-untagged build args."""

    def _mock_stored_raw(self, build_args: dict[str, str], scaffold: str = "openclaw"):
        """Return a minimal raw config dict with the given build_args."""
        return {
            "name": "test",
            "scaffold": scaffold,
            "container": {
                "image": "localhost/agentcage-scaffold-openclaw:latest",
                "build": {
                    "containerfile": "Containerfile",
                    "args": dict(build_args),
                },
            },
            "domains": {"allow": ["example.com"]},
        }

    def _run_update(
        self,
        stored_raw,
        scaffold_meta,
        resolver_returns,
        mock_state,
        MockPodman,
        mock_systemd,
        tmp_path,
    ):
        """Invoke `cage update test` with everything below the resolver mocked out."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_raw_config.return_value = stored_raw
        # After save_raw_config, capture the raw dict so tests can assert on it.
        saved: dict = {}

        def _save(name, raw):
            saved.clear()
            saved.update(raw)

        mock_state.save_raw_config.side_effect = _save
        # Make load_deployment_config pass through validate_config by reusing the
        # raw dict the test handed in (state saves are captured but we want
        # validation to succeed regardless).
        from agentcage.config import Config, ContainerConfig, BuildConfig
        mock_cfg = Config(
            name=stored_raw["name"],
            isolation="container",
            container=ContainerConfig(
                image=stored_raw["container"]["image"],
                build=BuildConfig(
                    containerfile="Containerfile",
                    args=stored_raw["container"]["build"]["args"],
                ),
            ),
        )
        mock_state.load_deployment_config.return_value = mock_cfg
        mock_state.load_metadata.return_value = {"scaffold": "openclaw"}
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        mock_state.save_metadata.return_value = None
        # Use a real tmp dir so scaffold-refresh's shutil.copy2 call doesn't
        # create a file named after the MagicMock's repr in the cwd.
        mock_state.deployment_dir.return_value = tmp_path

        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        podman.pull.return_value = True

        with patch("agentcage.init.load_scaffold_meta", return_value=scaffold_meta), \
             patch("agentcage.registry.resolve_latest_tag", side_effect=resolver_returns), \
             patch("agentcage.cli._build_container_image"), \
             patch("agentcage.cli._build_and_deploy"), \
             patch("agentcage.cli._check_port_availability", return_value=[]), \
             patch("agentcage.cli._check_secrets", return_value=[]), \
             patch("agentcage.cli.get_backend") as mock_backend:
            mock_backend.return_value.stop.return_value = None
            result = _runner().invoke(main, ["cage", "update", "test"])
        return result, saved

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_bumps_scaffold_untagged_arg(self, mock_state, MockPodman, mock_systemd, tmp_path):
        stored = self._mock_stored_raw({"BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.3.13-1"})
        scaffold_meta = {"build": [{"build_args": {"BASE_IMAGE": "ghcr.io/openclaw/openclaw"}}]}
        result, saved = self._run_update(
            stored, scaffold_meta, lambda _: "2026.4.1-1",
            mock_state, MockPodman, mock_systemd, tmp_path,
        )
        assert result.exit_code == 0, result.output
        assert "Build arg BASE_IMAGE:" in result.output
        assert "2026.3.13-1" in result.output
        assert "2026.4.1-1" in result.output
        assert saved["container"]["build"]["args"]["BASE_IMAGE"] == "ghcr.io/openclaw/openclaw:2026.4.1-1"

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_respects_scaffold_pinned_arg(self, mock_state, MockPodman, mock_systemd, tmp_path):
        stored = self._mock_stored_raw({"BASE_IMAGE": "ghcr.io/openclaw/openclaw:v1.0.0"})
        scaffold_meta = {"build": [{"build_args": {"BASE_IMAGE": "ghcr.io/openclaw/openclaw:v1.0.0"}}]}
        resolve_calls: list[str] = []

        def _resolver(base):
            resolve_calls.append(base)
            return "v9.9.9"

        result, _saved = self._run_update(
            stored, scaffold_meta, _resolver,
            mock_state, MockPodman, mock_systemd, tmp_path,
        )
        assert result.exit_code == 0, result.output
        # Scaffold pin matches stored pin — nothing changed, no resolver call
        assert "Build arg BASE_IMAGE:" not in result.output
        # resolve_latest_tag MUST NOT have been called for the scaffold-pinned arg
        # (may have been called for container.image but that starts with "localhost/"
        # so we short-circuited that path too)
        assert resolve_calls == []

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_preserves_pin_on_resolver_failure(self, mock_state, MockPodman, mock_systemd, tmp_path):
        """REGRESSION: offline update MUST NOT un-pin a working build."""
        stored = self._mock_stored_raw({"BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.3.13-1"})
        scaffold_meta = {"build": [{"build_args": {"BASE_IMAGE": "ghcr.io/openclaw/openclaw"}}]}
        result, saved = self._run_update(
            stored, scaffold_meta, lambda _: None,  # resolver fails
            mock_state, MockPodman, mock_systemd, tmp_path,
        )
        assert result.exit_code == 0, result.output
        assert "Build arg BASE_IMAGE:" not in result.output
        # No state write for build_args happened — saved is either empty (never
        # called) or has the original value untouched.
        if saved:
            assert saved["container"]["build"]["args"]["BASE_IMAGE"] == "ghcr.io/openclaw/openclaw:2026.3.13-1"

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_migrates_on_scaffold_base_change(self, mock_state, MockPodman, mock_systemd, tmp_path):
        """Scaffold author renamed the upstream image — users auto-migrate + warning."""
        stored = self._mock_stored_raw({"BASE_IMAGE": "ghcr.io/old/base:v1"})
        scaffold_meta = {"build": [{"build_args": {"BASE_IMAGE": "ghcr.io/new/base"}}]}
        result, saved = self._run_update(
            stored, scaffold_meta, lambda _: "v2",
            mock_state, MockPodman, mock_systemd, tmp_path,
        )
        assert result.exit_code == 0, result.output
        assert "Build arg BASE_IMAGE:" in result.output
        assert "ghcr.io/new/base:v2" in result.output
        # Drift warning visible
        assert "base image for BASE_IMAGE changed" in result.output
        assert "ghcr.io/old/base" in result.output
        assert saved["container"]["build"]["args"]["BASE_IMAGE"] == "ghcr.io/new/base:v2"

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_infers_scaffold_from_image_when_metadata_missing(
        self, mock_state, MockPodman, mock_systemd, tmp_path,
    ):
        """Cages created before scaffold-persistence landed still auto-bump."""
        stored = self._mock_stored_raw({"BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.3.13-1"})
        # Legacy cage: no scaffold field anywhere — only the image name hints at it
        stored.pop("scaffold", None)
        scaffold_meta = {"build": [{"build_args": {"BASE_IMAGE": "ghcr.io/openclaw/openclaw"}}]}
        # Metadata has NO scaffold key — force inference from image name
        mock_state.load_metadata.return_value = {"agentcage_version": "0.10.1"}
        mock_state.deployment_exists.return_value = True
        mock_state.load_raw_config.return_value = stored
        saved: dict = {}
        mock_state.save_raw_config.side_effect = lambda _n, r: saved.update(r) or None
        from agentcage.config import Config, ContainerConfig, BuildConfig
        mock_state.load_deployment_config.return_value = Config(
            name=stored["name"], isolation="container",
            container=ContainerConfig(
                image=stored["container"]["image"],
                build=BuildConfig(
                    containerfile="Containerfile",
                    args=stored["container"]["build"]["args"],
                ),
            ),
        )
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        mock_state.deployment_dir.return_value = tmp_path
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        podman.pull.return_value = True

        with patch("agentcage.init.load_scaffold_meta", return_value=scaffold_meta), \
             patch("agentcage.registry.resolve_latest_tag", side_effect=lambda _b: "2026.4.9"), \
             patch("agentcage.cli._build_container_image"), \
             patch("agentcage.cli._build_and_deploy"), \
             patch("agentcage.cli._check_port_availability", return_value=[]), \
             patch("agentcage.cli._check_secrets", return_value=[]), \
             patch("agentcage.cli.get_backend") as mock_backend:
            mock_backend.return_value.stop.return_value = None
            result = _runner().invoke(main, ["cage", "update", "test"])

        assert result.exit_code == 0, result.output
        # Scaffold inferred from "localhost/agentcage-scaffold-openclaw:latest"
        assert "Build arg BASE_IMAGE:" in result.output
        assert saved["container"]["build"]["args"]["BASE_IMAGE"] == "ghcr.io/openclaw/openclaw:2026.4.9"

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_suppresses_localhost_warning(self, mock_state, MockPodman, mock_systemd, tmp_path):
        """localhost/... image refs must not produce `could not resolve latest tag` noise."""
        stored = self._mock_stored_raw({"BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.3.13-1"})
        scaffold_meta = {"build": [{"build_args": {"BASE_IMAGE": "ghcr.io/openclaw/openclaw"}}]}
        # stored["container"]["image"] is "localhost/agentcage-scaffold-openclaw:latest"
        result, _saved = self._run_update(
            stored, scaffold_meta, lambda _: "2026.4.1-1",
            mock_state, MockPodman, mock_systemd, tmp_path,
        )
        assert result.exit_code == 0, result.output
        assert "could not resolve latest tag" not in result.output


class TestCageDestroy:
    @patch("agentcage.cli._destroy_cage")
    def test_destroy_with_yes(self, mock_destroy, tmp_path):
        mock_destroy.return_value = ["state:test"]

        result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0
        mock_destroy.assert_called_once_with("test", keep_secrets=False, echo=click.echo)

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_prompts_without_yes(self, mock_destroy):
        result = _runner().invoke(main, ["cage", "destroy", "test"], input="n\n")
        assert result.exit_code != 0  # aborted
        mock_destroy.assert_not_called()


class TestCageList:
    @patch("agentcage.cli.state")
    def test_list_empty(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "No" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_container_cage(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        mock_state.load_deployment_config.return_value = _mock_config("container")
        mock_state.load_metadata.return_value = {"agentcage_version": "1.2.3"}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "myapp" in result.output
        assert "container" in result.output
        assert "service" in result.output  # default lifecycle
        assert "running (3/3)" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_vm_cage(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myvm"]
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        mock_state.load_metadata.return_value = {"agentcage_version": "0.9.0"}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "myvm" in result.output
        assert "vm" in result.output
        assert "running (1/1)" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_missing_metadata_shows_dash(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["old"]
        mock_state.load_deployment_config.return_value = _mock_config("container")
        mock_state.load_metadata.return_value = {}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "old" in result.output
        # LIFECYCLE column header present
        assert "LIFECYCLE" in result.output
        lines = result.output.strip().split("\n")
        data_line = [l for l in lines if "old" in l][0]
        assert "service" in data_line  # default lifecycle

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_config_error(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["broken"]
        mock_state.load_deployment_config.side_effect = Exception("bad config")
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "broken" in result.output
        assert "config error" in result.output


class TestCageRestart:
    @patch("agentcage.cli.state")
    def test_restart_fails_if_not_exists(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_container(self, mock_state, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        assert "Restarted" in result.output
        backend.restart.assert_called_once_with("test")

    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_vm(self, mock_state, mock_get_backend):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        backend = mock_get_backend.return_value
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        assert "Restarted" in result.output
        backend.restart.assert_called_once_with("test")


class TestCageVerify:
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_nonexistent_cage(self, mock_state, mock_get_backend):
        mock_state.load_deployment_config.side_effect = FileNotFoundError()
        result = _runner().invoke(main, ["cage", "verify", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_container_all_running(self, mock_state, mock_get_backend, MockPodman):
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        podman = MockPodman.return_value
        # CA cert check → success; which curl → found; curl egress → blocked
        podman.container_exec.side_effect = [
            (0, ""),       # test -f /certs/...
            (0, "/usr/bin/curl"),  # which curl
            (0, "403"),    # curl blocked domain
        ]
        podman.container_inspect.return_value = {
            "Config": {"Env": ["HTTP_PROXY=http://x", "HTTPS_PROXY=http://x"]}
        }
        podman.info.return_value = {
            "host": {"security": {"rootless": True}}
        }
        result = _runner().invoke(main, ["cage", "verify", "test"])
        assert result.exit_code == 0
        assert "container" in result.output
        assert "PASS" in result.output

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_vm_running(self, mock_state, mock_get_backend, MockLimaInstance):
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        # Mock Lima instance
        mock_lima = MockLimaInstance.return_value
        mock_lima.is_running.return_value = True
        mock_lima.exec.return_value = MagicMock(stdout="active\n")
        result = _runner().invoke(main, ["cage", "verify", "myvm"])
        assert result.exit_code == 0
        assert "vm" in result.output
        assert "PASS" in result.output
        assert "Lima VM" in result.output

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_vm_stopped(self, mock_state, mock_get_backend, MockLimaInstance):
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = False
        mock_lima = MockLimaInstance.return_value
        mock_lima.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "verify", "myvm"])
        assert result.exit_code != 0
        assert "FAIL" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_egress_python_fallback(self, mock_state, mock_get_backend, MockPodman):
        """When curl and node are missing, python3 urllib fallback works."""
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        podman = MockPodman.return_value
        podman.container_exec.side_effect = [
            (0, ""),            # test -f /certs/...
            (1, ""),            # which curl → not found
            (1, ""),            # node fallback → fails
            (0, "403\n"),       # python3 urllib → 403
        ]
        podman.container_inspect.return_value = {
            "Config": {"Env": ["HTTP_PROXY=http://x", "HTTPS_PROXY=http://x"]}
        }
        podman.info.return_value = {
            "host": {"security": {"rootless": True}}
        }
        result = _runner().invoke(main, ["cage", "verify", "test"])
        assert result.exit_code == 0
        assert "PASS" in result.output
        assert "403" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_verify_egress_no_client_warns(self, mock_state, mock_get_backend, MockPodman):
        """When no HTTP client is available, verify warns instead of failing."""
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        podman = MockPodman.return_value
        podman.container_exec.side_effect = [
            (0, ""),            # test -f /certs/...
            (1, ""),            # which curl → not found
            (1, ""),            # node fallback → fails
            (1, ""),            # python3 fallback → fails
        ]
        podman.container_inspect.return_value = {
            "Config": {"Env": ["HTTP_PROXY=http://x", "HTTPS_PROXY=http://x"]}
        }
        podman.info.return_value = {
            "host": {"security": {"rootless": True}}
        }
        result = _runner().invoke(main, ["cage", "verify", "test"])
        assert result.exit_code == 0  # warnings don't fail verify
        assert "WARN" in result.output
        assert "No HTTP client" in result.output
        assert "1 warnings" in result.output


def _mock_config(isolation="container", lifecycle="service", scaffold=""):
    cfg = MagicMock()
    cfg.isolation = isolation
    cfg.lifecycle = lifecycle
    cfg.scaffold = scaffold
    cfg.container.nested_containers = False
    return cfg


class TestCageLogs:
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_default(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-proxy", "-u", "basic-dns",
            "-n", "50",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_follow(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic", "-f"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-proxy", "-u", "basic-dns",
            "-n", "50", "-f",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_filtered(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic", "-s", "proxy"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-proxy",
            "-n", "50",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_no_cage(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "logs", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output
        mock_execvp.assert_not_called()

    # -- VM isolation --

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_vm_default(self, mock_state, mock_execvp, MockLimaInstance):
        """All services requested → limactl shell + journalctl with all units."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"
        result = _runner().invoke(main, ["cage", "logs", "basic"])
        mock_execvp.assert_called_once_with("limactl", [
            "limactl", "shell", "agentcage-basic", "--",
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-proxy", "-u", "basic-dns",
            "-n", "50", "-o", "cat",
        ])

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_vm_filtered(self, mock_state, mock_execvp, MockLimaInstance, mock_popen):
        """Single service with severity filter → Popen + Python filtering."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"

        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc

        result = _runner().invoke(main, [
            "cage", "logs", "basic", "-s", "proxy", "--no-follow", "-l", "warning",
        ])

        # Should call Popen with limactl shell
        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "limactl"
        assert "agentcage-basic" in call_args
        assert "basic-proxy" in call_args
        mock_execvp.assert_not_called()

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_vm_multi_units(self, mock_state, mock_execvp, MockLimaInstance, mock_popen):
        """Two services with no severity filter → execvp limactl with both units."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"
        result = _runner().invoke(main, [
            "cage", "logs", "basic", "-s", "proxy", "-s", "dns",
        ])
        # execvp called with limactl and both units
        mock_execvp.assert_called_once()
        call_args = mock_execvp.call_args[0][1]
        assert "basic-proxy" in call_args
        assert "basic-dns" in call_args


# ── sample audit JSON lines ──────────────────────────────

_AUDIT_ALLOWED = json.dumps({
    "ts": "2026-02-20T10:00:00+00:00", "method": "GET",
    "host": "api.anthropic.com", "url": "https://api.anthropic.com/v1/messages",
    "decision": "allowed", "reason": "", "inspectors": [],
})

_AUDIT_BLOCKED = json.dumps({
    "ts": "2026-02-20T10:01:00+00:00", "method": "POST",
    "host": "evil.com", "url": "https://evil.com/exfil",
    "decision": "blocked", "reason": "domain not in allowlist",
    "inspectors": [{"name": "domain", "action": "block",
                    "reason": "domain not in allowlist", "severity": "error"}],
})

_AUDIT_FLAGGED = json.dumps({
    "ts": "2026-02-20T10:02:00+00:00", "method": "POST",
    "host": "api.anthropic.com", "url": "https://api.anthropic.com/v1/messages",
    "decision": "flagged", "reason": "high entropy",
    "inspectors": [{"name": "entropy", "action": "flag",
                    "reason": "high entropy", "severity": "warning"}],
})

_NON_AUDIT = "some non-json log line\n"


def _mock_popen_output(lines):
    """Create a mock Popen whose stdout yields the given lines."""
    mock_proc = MagicMock()
    mock_proc.stdout = iter(lines)
    mock_proc.wait.return_value = 0
    return mock_proc


class TestCageAudit:
    @patch("agentcage.cli.state")
    def test_audit_fails_if_not_exists(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "audit", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_container_mode(self, mock_state, mock_popen):
        """Parses raw JSON from mocked subprocess in container mode."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _NON_AUDIT, _AUDIT_BLOCKED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, ["cage", "audit", "myapp", "--no-color"])
        assert result.exit_code == 0
        assert "api.anthropic.com" in result.output
        assert "evil.com" in result.output

        # Verify journal command uses proxy unit
        cmd = mock_popen.call_args[0][0]
        assert "-u" in cmd
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "myapp-proxy"

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_vm_mode(self, mock_state, mock_popen, MockLimaInstance):
        """VM mode uses limactl shell + journalctl with proxy and dns units."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-myvm"

        lines = [_AUDIT_BLOCKED + "\n", _NON_AUDIT]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, ["cage", "audit", "myvm", "--no-color"])
        assert result.exit_code == 0
        assert "evil.com" in result.output

        # Verify command uses limactl shell with proxy unit
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "limactl"
        assert "agentcage-myvm" in cmd
        assert "myvm-proxy" in cmd

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_decision_filter(self, mock_state, mock_popen):
        """-d blocked filters out allowed entries."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _AUDIT_BLOCKED + "\n", _AUDIT_FLAGGED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "-d", "blocked", "--no-color",
        ])
        assert result.exit_code == 0
        assert "evil.com" in result.output
        assert "api.anthropic.com" not in result.output

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_json_output(self, mock_state, mock_popen):
        """--json outputs valid JSON lines."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _AUDIT_BLOCKED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "--json",
        ])
        assert result.exit_code == 0
        output_lines = [l for l in result.output.strip().split("\n") if l]
        assert len(output_lines) == 2
        for line in output_lines:
            parsed = json.loads(line)
            assert "decision" in parsed

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_summary_mode(self, mock_state, mock_popen):
        """--summary shows aggregated stats."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        lines = [_AUDIT_ALLOWED + "\n", _AUDIT_BLOCKED + "\n", _AUDIT_FLAGGED + "\n"]
        mock_popen.return_value = _mock_popen_output(lines)

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "--summary",
        ])
        assert result.exit_code == 0
        assert "Total entries: 3" in result.output
        assert "blocked" in result.output
        assert "allowed" in result.output

    @patch("agentcage.cli.state")
    def test_audit_summary_follow_conflict(self, mock_state):
        """--summary --follow errors."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")

        result = _runner().invoke(main, [
            "cage", "audit", "myapp", "--summary", "--follow",
        ])
        assert result.exit_code != 0
        assert "incompatible" in result.output


class TestCageExec:
    @patch("agentcage.cli.state")
    def test_exec_nonexistent(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "exec", "nope", "--", "ls"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_simple_command(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, ["cage", "exec", "myapp", "--", "ls", "-la"])
        mock_run.assert_called_once_with(["podman", "exec", "myapp-cage", "ls", "-la"])

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_alias_expansion(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {"openclaw": ["node", "openclaw.mjs"]}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "--", "openclaw", "devices", "list",
        ])
        mock_run.assert_called_once_with(
            ["podman", "exec", "myapp-cage", "node", "openclaw.mjs", "devices", "list"]
        )

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_custom_service(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "-s", "proxy", "--", "ls",
        ])
        mock_run.assert_called_once_with(["podman", "exec", "myapp-proxy", "ls"])

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_vm_uses_limactl(self, mock_state, mock_execvp, MockLimaInstance):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("vm")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        MockLimaInstance.return_value.name = "agentcage-myvm"

        result = _runner().invoke(main, ["cage", "exec", "myvm", "--", "ls"])
        # No -it in test because stdin is not a TTY
        mock_execvp.assert_called_once_with("limactl", [
            "limactl", "shell", "agentcage-myvm", "--",
            "podman", "exec", "myvm-cage", "ls",
        ])

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_no_alias_match(self, mock_state, mock_run):
        """When command doesn't match any alias, it passes through unchanged."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {"openclaw": ["node", "openclaw.mjs"]}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0)

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "--", "cat", "/etc/hostname",
        ])
        mock_run.assert_called_once_with(
            ["podman", "exec", "myapp-cage", "cat", "/etc/hostname"]
        )
