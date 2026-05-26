"""Tests for the 'agentcage cage' CLI subcommands."""

from __future__ import annotations

import json
import textwrap
from unittest.mock import MagicMock, patch, call, ANY

import click
from click.testing import CliRunner

from agentcage.cli import main, _stage_build_context


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

    def test_update_requires_name_or_config(self):
        """Either positional NAME or -c must be supplied — without one of
        them there is no way to identify which cage to update."""
        result = _runner().invoke(main, ["cage", "update"])
        assert result.exit_code != 0
        assert "NAME or -c/--config is required" in result.output

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._build_container_image")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_infers_name_from_config(
        self, mock_state, MockPodman, mock_systemd, mock_build, mock_backend,
        _check_secrets, _check_ports, _build_deploy, tmp_path,
    ):
        """`cage update -c cage.yaml` must work without a positional NAME —
        cfg.name is authoritative when -c is given (matches cage create)."""
        from agentcage.config import Config, ContainerConfig, BuildConfig
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: inferred-from-config
            container:
              image: test:latest
        """))
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = tmp_path
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        mock_state.load_metadata.return_value = {}
        mock_state.load_deployment_config.return_value = Config(
            name="inferred-from-config",
            isolation="container",
            container=ContainerConfig(
                image="test:latest",
                build=BuildConfig(containerfile=None, args={}),
            ),
        )
        result = _runner().invoke(main, ["cage", "update", "-c", str(p)])
        assert result.exit_code == 0, result.output
        # state.save_deployment should be called with the inferred name.
        save_calls = [c for c in mock_state.save_deployment.call_args_list]
        assert save_calls, "save_deployment was not called"
        assert save_calls[0].args[0] == "inferred-from-config"

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_vm_does_not_query_host_podman_for_secrets(
        self, mock_state, MockPodman, mock_systemd, mock_backend,
        _check_ports, _build_deploy, tmp_path,
    ):
        """For VM cages, secrets live in the VM's podman, not on the host.
        Querying host podman (the historical bug) always reported the
        secret as missing and blocked every `cage update` on a Linux host
        that happened to have podman installed. The fix routes the check
        through VmPodman (when the VM is running) or skips it (when the
        VM is stopped — backend.start() will re-create from
        pending_secrets.json before services come up)."""
        from agentcage.config import (
            Config, ContainerConfig, BuildConfig, SecretInjectionRule,
        )
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = tmp_path
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        mock_state.load_metadata.return_value = {}
        mock_state.load_raw_config.return_value = {
            "name": "test",
            "container": {"image": "test:latest", "build": {"args": {}}},
        }
        mock_state.load_deployment_config.return_value = Config(
            name="test",
            isolation="vm",
            container=ContainerConfig(
                image="test:latest",
                build=BuildConfig(containerfile=None, args={}),
            ),
            secret_injection=[
                SecretInjectionRule(env="OPENAI_API_KEY", placeholder="X"),
            ],
        )
        # Host Podman returns "no secret" for everything — the historical
        # blocker. The fix must NOT consult it for VM cages.
        host_podman = MockPodman.return_value
        host_podman.secret_exists.return_value = False
        # VM is stopped → no VmPodman to query → check is skipped.
        with patch("agentcage.cli.LimaInstance") as MockLima:
            MockLima.return_value.is_running.return_value = False
            result = _runner().invoke(main, ["cage", "update", "test"])
        assert result.exit_code == 0, result.output
        assert "missing secrets" not in result.output


class TestCageUpdateNoCache:
    """`agentcage cage update --no-cache` must propagate the flag down to
    the build-image step so podman gets `--no-cache` and rebuilds every
    layer instead of short-circuiting from the layer cache. Default
    (`no_cache=False`) must keep the cached behavior."""

    def _setup(self, mock_state, MockPodman, tmp_path):
        from agentcage.config import Config, ContainerConfig, BuildConfig
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = tmp_path
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        mock_state.load_metadata.return_value = {}
        # cage_update reads raw config via state.load_raw_config to do
        # scaffold-aware tag resolution; return a real dict so the
        # `image_base, _, current_tag = current_image.rpartition(":")`
        # tuple-unpack doesn't blow up on a MagicMock.
        mock_state.load_raw_config.return_value = {
            "name": "test",
            "container": {"image": "test:latest", "build": {"args": {}}},
        }
        mock_state.load_deployment_config.return_value = Config(
            name="test",
            isolation="container",
            container=ContainerConfig(
                image="test:latest",
                build=BuildConfig(containerfile="Containerfile", args={}),
            ),
        )
        podman = MockPodman.return_value
        podman.pull.return_value = True
        return podman

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._build_container_image")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_no_cache_flag_propagates(self, mock_state, MockPodman, mock_systemd,
                                      mock_build, mock_backend, _check_secrets,
                                      _check_ports, _build_deploy, tmp_path):
        self._setup(mock_state, MockPodman, tmp_path)
        result = _runner().invoke(main, ["cage", "update", "test", "--no-cache"])
        assert result.exit_code == 0, result.output
        # _build_container_image is the CLI wrapper; must be called with no_cache=True.
        assert mock_build.called
        assert mock_build.call_args.kwargs.get("no_cache") is True

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._build_container_image")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_default_keeps_layer_cache(self, mock_state, MockPodman, mock_systemd,
                                       mock_build, mock_backend, _check_secrets,
                                       _check_ports, _build_deploy, tmp_path):
        """Default `cage update` (no flag) must keep cache-on behavior — this
        is what makes incremental rebuilds fast."""
        self._setup(mock_state, MockPodman, tmp_path)
        result = _runner().invoke(main, ["cage", "update", "test"])
        assert result.exit_code == 0, result.output
        assert mock_build.called
        assert mock_build.call_args.kwargs.get("no_cache") is False
        assert mock_build.call_args.kwargs.get("pull") is False

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._build_container_image")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_pull_flag_propagates(self, mock_state, MockPodman, mock_systemd,
                                  mock_build, mock_backend, _check_secrets,
                                  _check_ports, _build_deploy, tmp_path):
        """`cage update --pull` must propagate pull=True to the build wrapper
        so podman gets `--pull=always` and re-fetches the base image from
        the registry instead of reusing the local image cache."""
        self._setup(mock_state, MockPodman, tmp_path)
        result = _runner().invoke(main, ["cage", "update", "test", "--pull"])
        assert result.exit_code == 0, result.output
        assert mock_build.called
        assert mock_build.call_args.kwargs.get("pull") is True
        # --pull alone leaves layer cache on.
        assert mock_build.call_args.kwargs.get("no_cache") is False

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._build_container_image")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_pull_combines_with_no_cache(self, mock_state, MockPodman, mock_systemd,
                                         mock_build, mock_backend, _check_secrets,
                                         _check_ports, _build_deploy, tmp_path):
        """`cage update --pull --no-cache` is the fully-clean-rebuild path:
        both base-image cache (--pull) and layer cache (--no-cache) are
        invalidated. This is what an operator wants when an upstream
        :latest base bumped versions and the Containerfile changed too."""
        self._setup(mock_state, MockPodman, tmp_path)
        result = _runner().invoke(
            main, ["cage", "update", "test", "--pull", "--no-cache"]
        )
        assert result.exit_code == 0, result.output
        assert mock_build.called
        assert mock_build.call_args.kwargs.get("pull") is True
        assert mock_build.call_args.kwargs.get("no_cache") is True


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


class TestCageUpdatePreservesNetworkOctet:
    """`agentcage cage update` must reuse the cage's already-allocated network
    octet instead of re-deriving it from the cage-name hash.

    Regression test for the bug where `cage update` regenerated quadlets with
    a fresh octet that didn't match the existing ``<name>-net`` podman network,
    causing the DNS sidecar to fail at start with::

        Error: requested static ip 10.89.X.10 not in any subnet on network <name>-net

    The fix reads ``network_octet`` from the cage's persisted metadata and
    threads it through ``build_and_deploy`` so the renderer pins the subnet
    to the existing one instead of re-allocating.
    """

    def _setup(self, mock_state, MockPodman, tmp_path, *, persisted_octet):
        from agentcage.config import Config, ContainerConfig, BuildConfig
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = tmp_path
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        # The cage was already created and its network octet was persisted
        # to metadata.json. cage_update must read this and pass it through.
        mock_state.load_metadata.return_value = {
            "network_octet": persisted_octet,
            "agentcage_version": "0.0.0",
        }
        mock_state.load_raw_config.return_value = {
            "name": "test",
            "container": {"image": "test:latest", "build": {"args": {}}},
        }
        mock_state.load_deployment_config.return_value = Config(
            name="test",
            isolation="container",
            container=ContainerConfig(
                image="test:latest",
                build=BuildConfig(containerfile="Containerfile", args={}),
            ),
        )
        podman = MockPodman.return_value
        podman.pull.return_value = True
        return podman

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._build_container_image")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_passes_persisted_octet(
        self, mock_state, MockPodman, mock_systemd,
        mock_build_img, mock_backend, _check_secrets,
        _check_ports, _build_deploy, tmp_path,
    ):
        # An existing cage whose network was allocated octet 174 at
        # cage-create time. The hash for "test" can land on a different
        # octet — the point is that `update` must honor what's persisted.
        self._setup(mock_state, MockPodman, tmp_path, persisted_octet=174)
        result = _runner().invoke(main, ["cage", "update", "test"])
        assert result.exit_code == 0, result.output
        assert _build_deploy.called
        # The persisted octet must be passed through unchanged.
        assert _build_deploy.call_args.kwargs.get("network_octet") == 174

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._build_container_image")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_update_passes_none_when_metadata_missing(
        self, mock_state, MockPodman, mock_systemd,
        mock_build_img, mock_backend, _check_secrets,
        _check_ports, _build_deploy, tmp_path,
    ):
        """Legacy cages with no ``network_octet`` in metadata fall back to the
        hash-based allocator (network_octet=None). Update must not crash."""
        from agentcage.config import Config, ContainerConfig, BuildConfig
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = tmp_path
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        mock_state.load_metadata.return_value = {}  # legacy: no octet persisted
        mock_state.load_raw_config.return_value = {
            "name": "test",
            "container": {"image": "test:latest", "build": {"args": {}}},
        }
        mock_state.load_deployment_config.return_value = Config(
            name="test",
            isolation="container",
            container=ContainerConfig(
                image="test:latest",
                build=BuildConfig(containerfile="Containerfile", args={}),
            ),
        )
        MockPodman.return_value.pull.return_value = True

        result = _runner().invoke(main, ["cage", "update", "test"])
        assert result.exit_code == 0, result.output
        assert _build_deploy.called
        assert _build_deploy.call_args.kwargs.get("network_octet") is None


class TestCageUpdateNetworkOctetEndToEnd:
    """Verify the renderer honors network_octet through the full
    ``build_and_deploy`` → ``generate_quadlets`` chain.

    This is the "did the plumbing actually work" check: even if cli.py reads
    the octet and passes it down, the quadlet content has to reflect the
    pinned subnet."""

    def test_pinned_octet_appears_in_generated_quadlets(self):
        """generate_quadlets with network_octet must produce IPs in that subnet."""
        from agentcage.config import Config, ContainerConfig
        from agentcage.quadlets import generate_quadlets

        cfg = Config(
            name="pi01",
            isolation="container",
            container=ContainerConfig(image="x:latest"),
            domains=__import__(
                "agentcage.config", fromlist=["DomainConfig"],
            ).DomainConfig(mode="allowlist", allow=["example.com"]),
        )
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="pi01", network_octet=174,
        )
        # The network subnet must be 10.89.174.0/24
        net = files["pi01-net.network"]
        assert "10.89.174.0/24" in net, net
        # DNS sidecar must request 10.89.174.10 (in the subnet)
        dns = files["pi01-dns.container"]
        assert "10.89.174.10" in dns, dns
        # Proxy must request 10.89.174.11
        proxy = files["pi01-proxy.container"]
        assert "10.89.174.11" in proxy, proxy
        # Cage gets 10.89.174.2
        cage = files["pi01-cage.container"]
        assert "10.89.174.2" in cage, cage

    def test_pinned_octet_overrides_hash(self):
        """When network_octet is given, the hash-derived octet is ignored —
        the renderer trusts the caller's pin. This is what makes
        ``cage update`` preserve the existing subnet."""
        from agentcage.config import Config, ContainerConfig
        from agentcage.quadlets import cage_network_addrs, generate_quadlets

        # Pick a cage name whose hash octet is NOT 7 (almost any name).
        natural = cage_network_addrs("pi01")
        natural_octet = int(natural["subnet"].split(".")[2])
        pinned_octet = 1 if natural_octet != 1 else 2
        assert pinned_octet != natural_octet

        cfg = Config(
            name="pi01",
            isolation="container",
            container=ContainerConfig(image="x:latest"),
            domains=__import__(
                "agentcage.config", fromlist=["DomainConfig"],
            ).DomainConfig(mode="allowlist", allow=["example.com"]),
        )
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches",
            deploy_name="pi01", network_octet=pinned_octet,
        )
        assert f"10.89.{pinned_octet}.0/24" in files["pi01-net.network"]
        assert f"10.89.{natural_octet}." not in files["pi01-net.network"]

    def test_build_and_deploy_threads_network_octet_to_backend(self):
        """services.build_and_deploy must hand network_octet to the backend
        (which forwards it to generate_quadlets) — verifies the plumbing
        between cli.py and the renderer."""
        from agentcage.config import Config, ContainerConfig
        from agentcage.services import build_and_deploy

        cfg = Config(
            name="pi01",
            isolation="container",
            container=ContainerConfig(image="x:latest"),
        )

        with patch("agentcage.services.get_backend") as mock_get_backend, \
             patch("agentcage.services.ensure_patches", return_value="/tmp"), \
             patch("agentcage.services.state") as mock_state, \
             patch("builtins.open", MagicMock()):
            mock_backend = MagicMock()
            mock_backend.generate_units.return_value = {}
            mock_get_backend.return_value = mock_backend
            mock_state.load_metadata.return_value = {}

            build_and_deploy(
                cfg, "/cfg.yaml", "pi01", MagicMock(), network_octet=174,
            )

        # The backend must receive the same network_octet.
        kwargs = mock_backend.generate_units.call_args.kwargs
        assert kwargs.get("network_octet") == 174
        # And the persisted octet must be the pinned one, not a hash.
        saved = mock_state.save_metadata.call_args[0][1]
        assert saved["network_octet"] == 174


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

    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_container(self, mock_state, mock_get_backend, _mock_ensure_dns):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        backend = mock_get_backend.return_value
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        assert "Restarted" in result.output
        backend.restart.assert_called_once_with("test")

    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_restarts_vm(self, mock_state, mock_get_backend, _mock_ensure_dns):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        backend = mock_get_backend.return_value
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        assert "Restarted" in result.output
        backend.restart.assert_called_once_with("test")

    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_regenerates_proxy_config(self, mock_state, mock_get_backend,
                                              mock_ensure_dns):
        """Restart must regenerate proxy-config.yaml from cage.yaml so
        out-of-band edits to cage.yaml are picked up on reload."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        mock_state.load_deployment_config.return_value = cfg
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        mock_state.save_proxy_config.assert_called_once_with("test")

    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_regenerates_dns_allowlist(self, mock_state, mock_get_backend,
                                               mock_ensure_dns):
        """Restart must regenerate the dns-allowlist.conf sidecar file so
        dnsmasq picks up domain changes — and must run the quadlet-current
        check too, which is the (cheap) migration safety net."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        mock_state.load_deployment_config.return_value = cfg
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        mock_state.save_dns_allowlist.assert_called_once_with("test")
        mock_ensure_dns.assert_called_once_with(cfg)


class TestCageStart:
    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.secret_resolver.resolve_and_populate")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._ensure_patches")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_start_regenerates_proxy_config(self, mock_state, MockPodman,
                                            mock_ensure_patches,
                                            mock_get_backend, mock_resolve,
                                            mock_ensure_dns):
        """Start must regenerate proxy-config.yaml from cage.yaml so any
        edits made while the cage was stopped are applied on next start."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "start", "test"])
        assert result.exit_code == 0
        mock_state.save_proxy_config.assert_called_once_with("test")
        mock_get_backend.return_value.start.assert_called_once_with("test")

    @patch("agentcage.cli._ensure_dns_quadlet_current")
    @patch("agentcage.secret_resolver.resolve_and_populate")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._ensure_patches")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_start_regenerates_dns_allowlist(self, mock_state, MockPodman,
                                             mock_ensure_patches,
                                             mock_get_backend, mock_resolve,
                                             mock_ensure_dns):
        """Start must regenerate dns-allowlist.conf and run the quadlet
        migration check before starting services."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        mock_state.load_deployment_config.return_value = cfg
        result = _runner().invoke(main, ["cage", "start", "test"])
        assert result.exit_code == 0
        mock_state.save_dns_allowlist.assert_called_once_with("test")
        mock_ensure_dns.assert_called_once_with(cfg)


class TestEnsureDnsQuadletCurrent:
    """The DNS-quadlet migration check execs inside the Lima VM — it must
    not crash when that VM is stopped (the normal state for `cage start`,
    `cage restart` and domain edits on an exited cage)."""

    @patch("agentcage.quadlets.render_dns_quadlet", return_value="DESIRED")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_not_running_is_noop(self, mock_state, mock_get_backend,
                                    MockLima, _mock_render):
        from agentcage.cli import _ensure_dns_quadlet_current
        mock_state.load_metadata.return_value = {"network_octet": 42}
        inst = MockLima.return_value
        inst.is_running.return_value = False
        cfg = _mock_config("vm")
        cfg.name = "test"

        result = _ensure_dns_quadlet_current(cfg)

        assert result is False
        inst.exec.assert_not_called()

    @patch("agentcage.quadlets.render_dns_quadlet", return_value="DESIRED")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_vm_running_reads_quadlet(self, mock_state, mock_get_backend,
                                      MockLima, _mock_render):
        from agentcage.cli import _ensure_dns_quadlet_current
        mock_state.load_metadata.return_value = {"network_octet": 42}
        inst = MockLima.return_value
        inst.is_running.return_value = True
        inst.exec.return_value = MagicMock(stdout="DESIRED")
        cfg = _mock_config("vm")
        cfg.name = "test"

        result = _ensure_dns_quadlet_current(cfg)

        assert result is False
        inst.exec.assert_called_once()  # the read; no write (current == desired)


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
        """All services requested → limactl shell + sg systemd-journal -c journalctl --user-unit."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"
        result = _runner().invoke(main, ["cage", "logs", "basic"])
        mock_execvp.assert_called_once_with("limactl", [
            "limactl", "shell", "agentcage-basic", "--",
            "sg", "systemd-journal", "-c",
            "journalctl --user-unit basic-cage --user-unit basic-proxy --user-unit basic-dns -n 50 -o cat",
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

        # Should call Popen with limactl shell wrapping journalctl in sg systemd-journal -c
        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "limactl"
        assert "agentcage-basic" in call_args
        assert "sg" in call_args and "systemd-journal" in call_args
        assert "basic-proxy" in call_args[-1]
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
        # execvp called with limactl wrapping journalctl in sg systemd-journal -c
        mock_execvp.assert_called_once()
        call_args = mock_execvp.call_args[0][1]
        assert "sg" in call_args and "systemd-journal" in call_args
        assert "basic-proxy" in call_args[-1]
        assert "basic-dns" in call_args[-1]


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

        # Verify command uses limactl shell + sg systemd-journal -c wrapping journalctl
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "limactl"
        assert "agentcage-myvm" in cmd
        assert "sg" in cmd and "systemd-journal" in cmd
        assert "myvm-proxy" in cmd[-1]

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


class TestStageBuildContext:
    """`_stage_build_context` snapshots a Containerfile's build inputs into
    the cage state dir so `cage update` (without -c) can rebuild."""

    def _src(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "Containerfile").write_text("FROM scratch\nCOPY skill /opt/skill\n")
        return src

    def test_stages_sibling_directory(self, tmp_path):
        """REGRESSION (#95): a directory the Containerfile COPYs in must be
        staged — the old file-only copy silently dropped it, breaking the
        rebuild with 'no such file or directory'."""
        src, dest = self._src(tmp_path), tmp_path / "dest"
        dest.mkdir()
        skill = src / "skill"
        skill.mkdir()
        (skill / "main.py").write_text("print('hi')")
        (skill / "nested").mkdir()
        (skill / "nested" / "data.txt").write_text("payload")

        _stage_build_context(src, dest)

        assert (dest / "skill" / "main.py").read_text() == "print('hi')"
        assert (dest / "skill" / "nested" / "data.txt").read_text() == "payload"

    def test_stages_sibling_files(self, tmp_path):
        src, dest = self._src(tmp_path), tmp_path / "dest"
        dest.mkdir()
        (src / "entrypoint.sh").write_text("#!/bin/sh\n")

        _stage_build_context(src, dest)

        assert (dest / "Containerfile").exists()
        assert (dest / "entrypoint.sh").read_text() == "#!/bin/sh\n"

    def test_skips_config_files(self, tmp_path):
        """cage.yaml-style configs and .j2 templates are not build inputs."""
        src, dest = self._src(tmp_path), tmp_path / "dest"
        dest.mkdir()
        (src / "cage.yaml").write_text("name: test\n")
        (src / "other.yml").write_text("x: 1\n")
        (src / "tpl.j2").write_text("{{ x }}\n")

        _stage_build_context(src, dest)

        assert not (dest / "cage.yaml").exists()
        assert not (dest / "other.yml").exists()
        assert not (dest / "tpl.j2").exists()

    def test_filters_build_noise_from_directories(self, tmp_path):
        """Caches and VCS metadata must not pollute the staged context."""
        src, dest = self._src(tmp_path), tmp_path / "dest"
        dest.mkdir()
        skill = src / "skill"
        (skill / "__pycache__").mkdir(parents=True)
        (skill / "__pycache__" / "x.pyc").write_text("junk")
        (skill / ".git").mkdir()
        (skill / ".git" / "config").write_text("junk")
        (skill / "node_modules").mkdir()
        (skill / "real.py").write_text("ok")

        _stage_build_context(src, dest)

        assert (dest / "skill" / "real.py").exists()
        assert not (dest / "skill" / "__pycache__").exists()
        assert not (dest / "skill" / ".git").exists()
        assert not (dest / "skill" / "node_modules").exists()

    def test_clobber_false_preserves_existing(self, tmp_path):
        """Scaffold init must not overwrite inputs the operator already has."""
        src, dest = self._src(tmp_path), tmp_path / "dest"
        dest.mkdir()
        (dest / "Containerfile").write_text("USER EDITED\n")

        _stage_build_context(src, dest, clobber=False)

        assert (dest / "Containerfile").read_text() == "USER EDITED\n"

    def test_clobber_true_refreshes_existing_dir(self, tmp_path):
        """Re-running an update merges fresh files into an already-staged
        directory rather than failing on the existing path."""
        src, dest = self._src(tmp_path), tmp_path / "dest"
        dest.mkdir()
        (src / "skill").mkdir()
        (src / "skill" / "v.py").write_text("v2")
        (dest / "skill").mkdir()
        (dest / "skill" / "v.py").write_text("v1")

        _stage_build_context(src, dest)

        assert (dest / "skill" / "v.py").read_text() == "v2"
