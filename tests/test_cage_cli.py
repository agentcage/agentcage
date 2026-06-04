"""Tests for the 'agentcage cage' CLI subcommands."""

from __future__ import annotations

import json
import platform
import textwrap
from unittest.mock import MagicMock, patch, call, ANY

import click
import pytest
from click.testing import CliRunner

from agentcage.cli import main, _stage_build_context

# These drive `cage create/update` with the default/container isolation, which
# resolves to the rootless-podman backend on Linux. On macOS the default is the
# apple-container backend (container isolation is rejected; create/update gate
# on the apple apiserver), so the Linux create/update flow under test only
# applies on the Linux CI. apple-container's flow is covered by
# tests/test_apple_container*.py.
LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux/container cage create+update flow; runs on the Linux CI",
)


@pytest.fixture(autouse=True)
def _bypass_backend_gate(monkeypatch):
    """Neutralize the create/update/start prerequisite gate for these tests.

    ``_ensure_backend_ready`` (auto-start the substrate + enforce
    ``check_prerequisites``) is a cross-cutting glue step unit-tested on its
    own (see test_apple_container.py). Here we only want it to resolve the
    test's (mocked) backend without running enforcement on a MagicMock —
    otherwise ``check_prerequisites`` returns a truthy Mock and trips the
    gate. Resolve ``get_backend`` lazily so the per-test ``@patch`` mock is
    the one returned.
    """
    import agentcage.cli as _cli
    monkeypatch.setattr(
        _cli, "_ensure_backend_ready",
        lambda cfg, **kw: _cli.get_backend(cfg),
    )


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

    @LINUX_ONLY
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
        assert "missing config" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_accepts_positional_config(self, mock_state, MockPodman, mock_systemd, minimal_yaml):
        # Positional config is sugar for -c (docker/podman style). It reaches
        # the same load path; deployment_exists=True short-circuits to the
        # "already exists" error, proving the positional config resolved.
        mock_state.deployment_exists.return_value = True
        result = _runner().invoke(main, ["cage", "create", minimal_yaml])
        assert result.exit_code != 0
        assert "already exists" in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_create_rejects_conflicting_config_sources(
        self, mock_state, MockPodman, mock_systemd, minimal_yaml, tmp_path,
    ):
        other = tmp_path / "other.yaml"
        other.write_text("name: other\ncontainer:\n  image: x:latest\n")
        result = _runner().invoke(
            main, ["cage", "create", minimal_yaml, "-c", str(other)],
        )
        assert result.exit_code != 0
        assert "specify it once" in result.output

    @patch("agentcage.config.platform.machine", return_value="arm64")
    @patch("agentcage.config.platform.system", return_value="Darwin")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_apple_container_rw_host_bind_warning(
        self, mock_state, MockPodman, mock_systemd, _ms, _mm, tmp_path,
    ):
        """CTF F4: warn when an apple-container cage has rw host bind
        mounts. Apple's runtime uses identity uid_map so rw mounts
        grant the cage workload host-uid-1000 write access to anything
        readable by the macOS user.

        Test still expects cage create to FAIL on a later step (we
        don't mock the full backend); the assertion is just that the
        F4 warning is emitted to stderr.
        """
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: testaa
            isolation: apple-container
            container:
              image: test:latest
              volumes:
                - "/Users/op/project:/workspace"
                - "/Users/op/cache:/cache:ro"
                - "agentcage-named:/data"
        """))
        mock_state.deployment_exists.return_value = False

        result = _runner().invoke(main, ["cage", "create", "-c", str(p)])
        assert "apple-container has identity uid_map" in result.output
        # The rw mount is flagged.
        assert "/Users/op/project:/workspace" in result.output
        # The :ro mount is NOT flagged.
        assert "/Users/op/cache" not in result.output
        # The named volume is NOT flagged.
        assert "agentcage-named" not in result.output

    @LINUX_ONLY
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_container_backend_no_apple_warning(
        self, mock_state, MockPodman, mock_systemd, tmp_path,
    ):
        """Container backend has user-namespace shift via rootless
        podman, so rw host bind mounts don't grant identity host-uid
        access. The F4 warning should NOT fire."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: testbb
            container:
              image: test:latest
              volumes:
                - "/home/u/project:/workspace"
        """))
        mock_state.deployment_exists.return_value = False
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True

        result = _runner().invoke(main, ["cage", "create", "-c", str(p)])
        # No F4 warning on the container backend.
        assert "apple-container has identity uid_map" not in result.output


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
        mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}
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
        mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}
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


@LINUX_ONLY
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
        mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}
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


@LINUX_ONLY
class TestCageUpdateFreezesConfig:
    """`cage update` (without -c) treats cage.yaml + the staged Containerfile
    as frozen: it rebuilds the staged image and restarts, but never re-reads
    the scaffold and never mutates the stored config.

    Regression for the old behavior where update re-staged the scaffold's
    Containerfile (clobbering operator edits), re-rendered command/env, and
    auto-bumped scaffold-declared build args.
    """

    def _run_update(self, mock_state, MockPodman, tmp_path):
        from agentcage.config import Config, ContainerConfig, BuildConfig
        stored = {
            "name": "test",
            "scaffold": "openclaw",
            "container": {
                # A real registry ref (not localhost/) so the OLD code would
                # have tried resolve_latest_tag; an untagged build arg so the
                # OLD code would have auto-bumped it. Freeze must do neither.
                "image": "ghcr.io/openclaw/openclaw:2026.3.13-1",
                "build": {
                    "containerfile": "Containerfile",
                    "args": {"BASE_IMAGE": "ghcr.io/openclaw/openclaw"},
                },
            },
            "domains": {"allow": ["example.com"]},
        }
        mock_state.deployment_exists.return_value = True
        mock_state.load_raw_config.return_value = stored
        mock_state.load_metadata.return_value = {
            "scaffold": "openclaw", "agentcage_version": "0.22.0",
        }
        mock_state.deployment_dir.return_value = tmp_path
        mock_state.save_proxy_config.return_value = "/fake/proxy.yaml"
        mock_state.load_deployment_config.return_value = Config(
            name="test",
            isolation="container",
            container=ContainerConfig(
                image=stored["container"]["image"],
                build=BuildConfig(
                    containerfile="Containerfile",
                    args=stored["container"]["build"]["args"],
                ),
            ),
        )
        podman = MockPodman.return_value
        podman.secret_exists.return_value = True
        podman.pull.return_value = True

        with patch("agentcage.init.load_scaffold_meta") as mock_meta, \
             patch("agentcage.registry.resolve_latest_tag") as mock_tag, \
             patch("agentcage.cli._stage_build_context") as mock_stage, \
             patch("agentcage.cli._build_container_image") as mock_build, \
             patch("agentcage.cli._build_and_deploy"), \
             patch("agentcage.cli._check_port_availability", return_value=[]), \
             patch("agentcage.cli._check_secrets", return_value=[]), \
             patch("agentcage.cli.get_backend") as mock_backend:
            mock_backend.return_value.stop.return_value = None
            result = _runner().invoke(main, ["cage", "update", "test"])
        return result, mock_meta, mock_tag, mock_stage, mock_build, podman

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_does_not_mutate_stored_config(
        self, mock_state, MockPodman, mock_systemd, tmp_path,
    ):
        result, *_ = self._run_update(mock_state, MockPodman, tmp_path)
        assert result.exit_code == 0, result.output
        # The frozen config is never rewritten...
        assert not mock_state.save_raw_config.called
        # ...and none of the old mutation chatter appears.
        assert "Build arg" not in result.output
        assert "Image:" not in result.output
        assert "Command updated" not in result.output
        assert "Added env" not in result.output

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_does_not_read_or_restage_scaffold(
        self, mock_state, MockPodman, mock_systemd, tmp_path,
    ):
        result, mock_meta, mock_tag, mock_stage, _build, _podman = \
            self._run_update(mock_state, MockPodman, tmp_path)
        assert result.exit_code == 0, result.output
        # The scaffold is never consulted...
        mock_meta.assert_not_called()
        mock_tag.assert_not_called()
        # ...and the staged Containerfile is never overwritten.
        mock_stage.assert_not_called()

    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_still_rebuilds_and_pulls(
        self, mock_state, MockPodman, mock_systemd, tmp_path,
    ):
        result, _meta, _tag, _stage, mock_build, podman = \
            self._run_update(mock_state, MockPodman, tmp_path)
        assert result.exit_code == 0, result.output
        # Freeze still rebuilds the staged image from the cage's state dir...
        mock_build.assert_called_once()
        assert mock_build.call_args.args[1] == tmp_path
        # ...and pulls a fresh base image.
        assert podman.pull.called


@LINUX_ONLY
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
            "agentcage_version": "0.22.0",
            "network_octet": persisted_octet,
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
        mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}  # legacy: no octet persisted
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
        # Egress container (combined mitmproxy + dnsmasq) gets the
        # single 10.89.174.10 address (the v0.22 layout drops the
        # separate dns at .10 / proxy at .11 pair).
        egress = files["pi01-egress.container"]
        assert "10.89.174.10" in egress, egress
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
            mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}

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
        backend.service_names.return_value = ["cage", "egress"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "myapp" in result.output
        assert "container" in result.output
        assert "service" in result.output  # default lifecycle
        assert "running (2/2)" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_vm_cage(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myvm"]
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        # v0.22-or-newer metadata so cage_list takes the normal status
        # path rather than annotating as legacy.
        mock_state.load_metadata.return_value = {"agentcage_version": "0.22.0"}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "egress"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "myvm" in result.output
        assert "vm" in result.output
        assert "running (2/2)" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_missing_metadata_shows_legacy(self, mock_state, mock_get_backend):
        """A cage with no metadata at all is treated as pre-v0.22 (the
        agentcage_version key was added before v0.22, so any cage
        missing it is older than the egress unification). cage_list
        annotates it accordingly rather than running is_running checks
        against the new shape — which would mislabel a still-running
        legacy cage as 0/N stopped."""
        mock_state.list_deployments.return_value = ["old"]
        mock_state.load_deployment_config.return_value = _mock_config("container")
        # Empty metadata — no agentcage_version key recorded. The v0.21
        # detector treats this as legacy (the key was always present in
        # v0.22+ metadata).
        mock_state.load_metadata.return_value = {}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "egress"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "old" in result.output
        # LIFECYCLE column header present
        assert "LIFECYCLE" in result.output
        # The legacy annotation surfaces explicitly so the operator
        # knows to destroy+recreate.
        assert "legacy v0.21" in result.output
        # is_running must not have been called against the new shape
        # for legacy entries — it would query the wrong containers.
        backend.is_running.assert_not_called()

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

    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_regenerates_proxy_config(self, mock_state, mock_get_backend):
        """Restart must regenerate proxy-config.yaml from cage.yaml so
        out-of-band edits to cage.yaml are picked up on reload."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        mock_state.load_deployment_config.return_value = cfg
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        mock_state.save_proxy_config.assert_called_once_with("test")

    @patch("agentcage.services.get_backend")
    @patch("agentcage.cli.state")
    def test_restart_regenerates_dns_allowlist(self, mock_state, mock_get_backend):
        """Restart must regenerate the dns-allowlist.conf sidecar file so
        dnsmasq picks up domain changes."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        mock_state.load_deployment_config.return_value = cfg
        result = _runner().invoke(main, ["cage", "restart", "test"])
        assert result.exit_code == 0
        mock_state.save_dns_allowlist.assert_called_once_with("test")


class TestCageEdit:
    """`cage edit` opens the stored cage.yaml in $EDITOR, validates the
    result, writes atomically with a backup, and surfaces what just
    changed. These tests exercise the rationale that justifies the
    command's existence over a bare `$EDITOR <path>` shell call."""

    @staticmethod
    def _setup_cage(tmp_path, yaml_text):
        """Lay down a fake state dir with a cage.yaml and wire state mocks."""
        cage_dir = tmp_path / "cages" / "test"
        cage_dir.mkdir(parents=True)
        (cage_dir / "cage.yaml").write_text(yaml_text)
        return cage_dir

    _GOOD_YAML = (
        "name: test\n"
        "container:\n"
        "  image: node:22-slim\n"
        "  command: [node, /app/agent.js]\n"
        "domains:\n"
        "  allow:\n"
        "  - anthropic.com\n"
        "  - github.com\n"
    )

    @patch("agentcage.cli.state")
    def test_edit_nonexistent_cage(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "edit", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_no_changes_returns_none(self, mock_state, mock_click_edit, tmp_path):
        """click.edit returns None when the user exits without saving."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        mock_state.load_raw_config.return_value = {"name": "test"}
        mock_click_edit.return_value = None

        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0
        assert "No changes" in result.output
        # Nothing should have been written.
        assert not (cage_dir / "cage.yaml.bak").exists()
        mock_state.save_proxy_config.assert_not_called()

    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_no_changes_identical_text(self, mock_state, mock_click_edit, tmp_path):
        """click.edit returns same text — still a no-op, no backup written."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        mock_state.load_raw_config.return_value = {"name": "test"}
        mock_click_edit.return_value = self._GOOD_YAML

        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0
        assert "No changes" in result.output
        assert not (cage_dir / "cage.yaml.bak").exists()
        mock_state.save_proxy_config.assert_not_called()

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_domain_change_live_reloads_dnsmasq(self, mock_state,
                                                     mock_click_edit,
                                                     mock_update_dns, tmp_path):
        """Adding a domain triggers _update_dns_quadlet — no cage restart."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        # Pre-edit raw config (the in-memory before-image)
        import yaml as _yaml
        mock_state.load_raw_config.return_value = _yaml.safe_load(self._GOOD_YAML)

        edited = self._GOOD_YAML.replace(
            "  - github.com\n",
            "  - github.com\n  - httpbin.org\n",
        )
        mock_click_edit.return_value = edited

        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0, result.output
        assert "Live-applied" in result.output
        assert "domains" in result.output
        mock_update_dns.assert_called_once()
        # save_proxy_config is always called on a real edit so proxy and
        # cage.yaml stay in lockstep.
        mock_state.save_proxy_config.assert_called_once_with("test")
        # Backup written.
        assert (cage_dir / "cage.yaml.bak").exists()
        # The new on-disk cage.yaml contains the added domain.
        written = (cage_dir / "cage.yaml").read_text()
        assert "httpbin.org" in written
        # Backup preserves the prior contents (no httpbin.org yet).
        backup = (cage_dir / "cage.yaml.bak").read_text()
        assert "httpbin.org" not in backup

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_non_domain_change_prints_restart_hint(self, mock_state,
                                                       mock_click_edit,
                                                       mock_update_dns, tmp_path):
        """Editing container.image needs `cage restart` — no DNS reload."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        import yaml as _yaml
        mock_state.load_raw_config.return_value = _yaml.safe_load(self._GOOD_YAML)

        edited = self._GOOD_YAML.replace("node:22-slim", "node:24-slim")
        mock_click_edit.return_value = edited

        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0, result.output
        assert "cage restart test" in result.output
        mock_update_dns.assert_not_called()
        mock_state.save_proxy_config.assert_called_once_with("test")

    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_invalid_yaml_writes_rejected(self, mock_state, mock_click_edit,
                                               tmp_path):
        """Bad YAML lands in cage.yaml.rejected; the original is untouched."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        import yaml as _yaml
        mock_state.load_raw_config.return_value = _yaml.safe_load(self._GOOD_YAML)

        # Unterminated string — yaml.safe_load raises.
        mock_click_edit.return_value = self._GOOD_YAML + "broken: 'unterminated\n"

        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code != 0
        assert "not valid YAML" in result.output
        assert "cage.yaml.rejected" in result.output
        # Rejected file was created with the bad edits.
        assert (cage_dir / "cage.yaml.rejected").exists()
        # The original cage.yaml on disk is byte-for-byte unchanged.
        assert (cage_dir / "cage.yaml").read_text() == self._GOOD_YAML
        # No backup since we never wrote a new good config.
        assert not (cage_dir / "cage.yaml.bak").exists()
        mock_state.save_proxy_config.assert_not_called()

    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_validation_failure_writes_rejected(self, mock_state,
                                                     mock_click_edit, tmp_path):
        """load_config raising ValueError → reject, preserve original."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        import yaml as _yaml
        mock_state.load_raw_config.return_value = _yaml.safe_load(self._GOOD_YAML)

        # The edited YAML is parseable but semantically rejected by the real
        # loader. Patch load_config so the test doesn't depend on the real
        # schema rules (which can drift).
        with patch("agentcage.cli.load_config",
                   side_effect=ValueError("inspector 'nope' not found")):
            edited = self._GOOD_YAML.replace(
                "domains:\n", "inspectors:\n  - nope\ndomains:\n"
            )
            mock_click_edit.return_value = edited
            result = _runner().invoke(main, ["cage", "edit", "test"])

        assert result.exit_code != 0
        assert "failed validation" in result.output
        assert "inspector 'nope' not found" in result.output
        assert (cage_dir / "cage.yaml.rejected").exists()
        # Original untouched.
        assert (cage_dir / "cage.yaml").read_text() == self._GOOD_YAML
        assert not (cage_dir / "cage.yaml.bak").exists()

    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_rename_attempt_rejected(self, mock_state, mock_click_edit,
                                          tmp_path):
        """Changing top-level `name:` is outside this command's contract."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        import yaml as _yaml
        mock_state.load_raw_config.return_value = _yaml.safe_load(self._GOOD_YAML)

        mock_click_edit.return_value = self._GOOD_YAML.replace(
            "name: test\n", "name: renamed\n"
        )
        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code != 0
        assert "renaming a cage" in result.output
        assert (cage_dir / "cage.yaml.rejected").exists()
        assert (cage_dir / "cage.yaml").read_text() == self._GOOD_YAML

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("click.edit")
    @patch("agentcage.cli.state")
    def test_edit_shows_unified_diff(self, mock_state, mock_click_edit,
                                     _mock_update_dns, tmp_path):
        """The diff of the change is printed before the success line."""
        cage_dir = self._setup_cage(tmp_path, self._GOOD_YAML)
        mock_state.deployment_exists.return_value = True
        mock_state.deployment_dir.return_value = cage_dir
        import yaml as _yaml
        mock_state.load_raw_config.return_value = _yaml.safe_load(self._GOOD_YAML)

        edited = self._GOOD_YAML.replace(
            "  - github.com\n", "  - github.com\n  - httpbin.org\n"
        )
        mock_click_edit.return_value = edited

        result = _runner().invoke(main, ["cage", "edit", "test"])
        assert result.exit_code == 0, result.output
        # Unified-diff signature: ---/+++ headers and the added domain on
        # a +-prefixed line.
        assert "--- " in result.output
        assert "+++ " in result.output
        assert "+" in result.output and "httpbin.org" in result.output
        # The unified-diff block precedes the "Updated cage" summary.
        assert result.output.index("---") < result.output.index("Updated cage")

    def test_edit_alias_config_routes_to_edit(self):
        """`cage config` is an alias for `cage edit` (registered on AliasGroup)."""
        from agentcage.cli import cage as cage_group
        assert cage_group.get_command(None, "config").name == "edit"


class TestCageStart:
    @patch("agentcage.secret_resolver.resolve_and_populate")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._ensure_patches")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_start_regenerates_proxy_config(self, mock_state, MockPodman,
                                            mock_ensure_patches,
                                            mock_get_backend, mock_resolve):
        """Start must regenerate proxy-config.yaml from cage.yaml so any
        edits made while the cage was stopped are applied on next start."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "start", "test"])
        assert result.exit_code == 0
        mock_state.save_proxy_config.assert_called_once_with("test")
        mock_get_backend.return_value.start.assert_called_once_with("test")

    @patch("agentcage.secret_resolver.resolve_and_populate")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._ensure_patches")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_start_regenerates_dns_allowlist(self, mock_state, MockPodman,
                                             mock_ensure_patches,
                                             mock_get_backend, mock_resolve):
        """Start must regenerate dns-allowlist.conf before starting services."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        mock_state.load_deployment_config.return_value = cfg
        result = _runner().invoke(main, ["cage", "start", "test"])
        assert result.exit_code == 0
        mock_state.save_dns_allowlist.assert_called_once_with("test")


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
        backend.service_names.return_value = ["cage", "egress"]
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
        backend.service_names.return_value = ["cage", "egress"]
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
        backend.service_names.return_value = ["cage", "egress"]
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
        # v0.22 default-selected services are cage + egress (was
        # cage + proxy + dns).
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-egress",
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
            "-u", "basic-cage", "-u", "basic-egress",
            "-n", "50", "-f",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_tail_alias(self, mock_state, mock_execvp):
        """`--tail N` is a docker/podman-style alias for `-n/--lines`."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic", "--tail", "7"])
        assert result.exit_code == 0
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-egress",
            "-n", "7",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_since(self, mock_state, mock_execvp):
        """`--since` threads through to journalctl (docker/journalctl style)."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(
            main, ["cage", "logs", "basic", "--since", "10 min ago"],
        )
        assert result.exit_code == 0
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-cage", "-u", "basic-egress",
            "-n", "50", "--since", "10 min ago",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_filtered(self, mock_state, mock_execvp):
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("container")
        result = _runner().invoke(main, ["cage", "logs", "basic", "-s", "egress"])
        mock_execvp.assert_called_once_with("journalctl", [
            "journalctl", "--user",
            "-u", "basic-egress",
            "-n", "50",
        ])

    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_rejects_legacy_proxy_service_choice(self, mock_state, mock_execvp):
        """`-s proxy` / `-s dns` were valid in v0.21 but the v0.22
        Click Choice() only accepts ``cage`` / ``egress`` — invocation
        must fail at parse time with a clear error."""
        mock_state.deployment_exists.return_value = True
        result = _runner().invoke(main, ["cage", "logs", "basic", "-s", "proxy"])
        assert result.exit_code != 0
        assert "'proxy' is not one of" in result.output
        mock_execvp.assert_not_called()

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
        """All services requested → limactl shell + sg systemd-journal -c journalctl --user-unit.
        v0.22: the default set is cage + egress (was cage + proxy + dns)."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"
        result = _runner().invoke(main, ["cage", "logs", "basic"])
        # --workdir / suppresses the spurious cd warning when host cwd
        # isn't mounted in the VM (PR-bundle "torture-session-findings").
        mock_execvp.assert_called_once_with("limactl", [
            "limactl", "shell", "--workdir", "/", "agentcage-basic", "--",
            "sg", "systemd-journal", "-c",
            "journalctl --user-unit basic-cage --user-unit basic-egress -n 50 -o cat",
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
            "cage", "logs", "basic", "-s", "egress", "--no-follow", "-l", "warning",
        ])

        # Should call Popen with limactl shell wrapping journalctl in sg systemd-journal -c
        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "limactl"
        assert "agentcage-basic" in call_args
        assert "sg" in call_args and "systemd-journal" in call_args
        assert "basic-egress" in call_args[-1]
        mock_execvp.assert_not_called()

    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_logs_vm_multi_units(self, mock_state, mock_execvp, MockLimaInstance, mock_popen):
        """Both services with no severity filter → execvp limactl with both units."""
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config("vm")
        MockLimaInstance.return_value.name = "agentcage-basic"
        result = _runner().invoke(main, [
            "cage", "logs", "basic", "-s", "cage", "-s", "egress",
        ])
        # execvp called with limactl wrapping journalctl in sg systemd-journal -c
        mock_execvp.assert_called_once()
        call_args = mock_execvp.call_args[0][1]
        assert "sg" in call_args and "systemd-journal" in call_args
        assert "basic-cage" in call_args[-1]
        assert "basic-egress" in call_args[-1]


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

        # v0.22: audit reads the single egress unit (was proxy + dns).
        cmd = mock_popen.call_args[0][0]
        assert "-u" in cmd
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "myapp-egress"

    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.subprocess.Popen")
    @patch("agentcage.cli.state")
    def test_audit_vm_mode(self, mock_state, mock_popen, MockLimaInstance):
        """VM mode uses limactl shell + journalctl with the egress unit."""
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
        assert "myvm-egress" in cmd[-1]

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

    # Test helper: `cage exec` now pre-flights backend.is_running before
    # invoking podman/limactl exec, so the test mocks must report the cage
    # as `running` (subprocess.run returning `stdout="running"` for the
    # container_running probe) AND we now assert on the LAST run call (the
    # actual exec) rather than asserting it's the only call.

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_simple_command(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0, stdout="running")

        result = _runner().invoke(main, ["cage", "exec", "myapp", "--", "ls", "-la"])
        mock_run.assert_called_with(
            ["podman", "exec", "-u", "1000:1000", "myapp-cage", "ls", "-la"]
        )

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_alias_expansion(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {"openclaw": ["node", "openclaw.mjs"]}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0, stdout="running")

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "--", "openclaw", "devices", "list",
        ])
        mock_run.assert_called_with(
            ["podman", "exec", "-u", "1000:1000", "myapp-cage",
             "node", "openclaw.mjs", "devices", "list"]
        )

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_custom_service(self, mock_state, mock_run):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0, stdout="running")

        # v0.22: `-s proxy` / `-s dns` are gone; `-s egress` is the only
        # non-cage target.
        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "-s", "egress", "--", "ls",
        ])
        mock_run.assert_called_with(
            ["podman", "exec", "-u", "1000:1000", "myapp-egress", "ls"]
        )

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_rejects_legacy_proxy_service_choice(self, mock_state, mock_run):
        """v0.21 invocations like `-s proxy` / `-s dns` are rejected at
        Click parse time — no migration alias, just a clean error."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "-s", "proxy", "--", "ls",
        ])
        assert result.exit_code != 0
        assert "'proxy' is not one of" in result.output
        mock_run.assert_not_called()

    @patch("agentcage.backends.vm.LimaInstance")
    @patch("agentcage.cli.LimaInstance")
    @patch("agentcage.cli.os.execvp")
    @patch("agentcage.cli.state")
    def test_exec_vm_uses_limactl(self, mock_state, mock_execvp,
                                   MockCliLima, MockBackendLima):
        """`cage exec` on a vm-mode cage execs through limactl shell.

        The is_running pre-flight goes through VmBackend (which imports
        LimaInstance from agentcage.lima.instance), then exec_argv is
        invoked and os.execvp runs the resulting argv. Both LimaInstance
        import sites must be mocked: cli.py imports it directly,
        backends/vm.py imports it for is_running's systemctl probe.
        """
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("vm")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        for M in (MockCliLima, MockBackendLima):
            M.return_value.name = "agentcage-myvm"
            M.return_value.is_running.return_value = True
            M.return_value.exec.return_value = MagicMock(
                stdout="active\n", returncode=0,
            )

        result = _runner().invoke(main, ["cage", "exec", "myvm", "--", "ls"])
        # No -it in test because stdin is not a TTY. --workdir / suppresses
        # the spurious "cd: <host-cwd>: No such file or directory" warning
        # that defaulted in (see PR-bundle "torture-session-findings").
        mock_execvp.assert_called_once_with("limactl", [
            "limactl", "shell", "--workdir", "/", "agentcage-myvm", "--",
            "podman", "exec", "-u", "1000:1000", "myvm-cage", "ls",
        ])

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_no_alias_match(self, mock_state, mock_run):
        """When command doesn't match any alias, it passes through unchanged."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {"openclaw": ["node", "openclaw.mjs"]}
        mock_state.load_deployment_config.return_value = cfg
        mock_run.return_value = MagicMock(returncode=0, stdout="running")

        result = _runner().invoke(main, [
            "cage", "exec", "myapp", "--", "cat", "/etc/hostname",
        ])
        mock_run.assert_called_with(
            ["podman", "exec", "-u", "1000:1000", "myapp-cage", "cat", "/etc/hostname"]
        )

    @patch("agentcage.cli.subprocess.run")
    @patch("agentcage.cli.state")
    def test_exec_refuses_stopped_cage(self, mock_state, mock_run):
        """`cage exec` on a stopped cage must error with a friendly message
        instead of letting the raw downstream podman/limactl error surface.
        Without this pre-flight the operator saw
        `no container with name or ID "<name>-cage" found` (container,
        exit 125) or `instance "<name>" is stopped` (vm, exit 1) — both of
        which buried the actual problem."""
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config("container")
        cfg.exec_aliases = {}
        mock_state.load_deployment_config.return_value = cfg
        # is_running probe returns "exited" (or anything other than
        # "running") → cage is stopped, exec must refuse.
        mock_run.return_value = MagicMock(returncode=0, stdout="exited")

        result = _runner().invoke(main, ["cage", "exec", "myapp", "--", "ls"])
        assert result.exit_code != 0
        assert "is not running" in result.output
        assert "cage start" in result.output
        # No exec call must have fired.
        for call in mock_run.call_args_list:
            assert "exec" not in call.args[0], f"unexpected exec: {call.args[0]}"


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
