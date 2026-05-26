"""Tests for ``services.destroy_cage`` dispatch when state is missing.

Before this fix, a ``destroy`` on a name with no stored deployment config
fell back to ``ContainerBackend``, which calls ``podman`` — crashing on
macOS where podman isn't installed even when the cage was an
apple-container artifact. The fix probes each backend via
``has_resources(name)`` and dispatches to the one that owns artifacts,
or no-ops cleanly when nothing exists.
"""

from __future__ import annotations

from unittest.mock import patch

from agentcage.services import destroy_cage


def test_destroy_unknown_cage_is_clean_noop_without_calling_backends():
    """Destroying a name with no state and no backend artifacts must not
    invoke ``podman`` (or any tool). Reproduces the macOS crash."""
    messages: list[str] = []

    with (
        patch("agentcage.state.load_deployment_config",
              side_effect=FileNotFoundError("no config")),
        patch("agentcage.state.deployment_exists", return_value=False),
        patch("agentcage.backends.container.ContainerBackend.has_resources",
              return_value=False) as container_probe,
        patch("agentcage.backends.apple_container.AppleContainerBackend.has_resources",
              return_value=False) as apple_probe,
        patch("agentcage.backends.vm.VmBackend.has_resources",
              return_value=False) as vm_probe,
        patch("agentcage.backends.container.ContainerBackend.stop") as container_stop,
    ):
        removed = destroy_cage("ghost", echo=messages.append)

    assert removed == []
    assert any("Nothing to remove" in m for m in messages)
    # The probe must happen, but no backend ``stop``/``destroy_resources``
    # should be called when nothing claims the name.
    assert container_probe.called or apple_probe.called or vm_probe.called
    container_stop.assert_not_called()


def test_destroy_dispatches_to_apple_container_when_it_owns_the_name():
    """When apple-container claims the name (e.g. agentcage run wiped the
    deployment dir but left the launchd plist / state dir), dispatch must
    go there, not to the container backend's podman path."""
    with (
        patch("agentcage.state.load_deployment_config",
              side_effect=FileNotFoundError("no config")),
        patch("agentcage.state.deployment_exists", return_value=False),
        patch("agentcage.backends.apple_container.AppleContainerBackend.has_resources",
              return_value=True),
        patch("agentcage.backends.apple_container.AppleContainerBackend.stop") as ac_stop,
        patch(
            "agentcage.backends.apple_container.AppleContainerBackend.destroy_resources",
            return_value=["container:c"],
        ) as ac_destroy,
        patch("agentcage.backends.container.ContainerBackend.has_resources",
              return_value=False),
        patch("agentcage.backends.container.ContainerBackend.stop") as container_stop,
    ):
        removed = destroy_cage("c", echo=lambda _: None)

    assert removed == ["container:c"]
    ac_stop.assert_called_once_with("c")
    ac_destroy.assert_called_once()
    container_stop.assert_not_called()


def test_destroy_with_stored_config_skips_probe_and_uses_get_backend():
    """The happy path (stored config present) must not change: dispatch
    via ``get_backend(cfg)`` without consulting ``has_resources``."""
    from agentcage.config import Config, ContainerConfig

    cfg = Config(name="c", isolation="container",
                 container=ContainerConfig(image="x:latest"))
    with (
        patch("agentcage.state.load_deployment_config", return_value=cfg),
        patch("agentcage.state.deployment_exists", return_value=False),
        patch("agentcage.backends.container.ContainerBackend.has_resources") as probe,
        patch("agentcage.backends.container.ContainerBackend.stop"),
        patch(
            "agentcage.backends.container.ContainerBackend.destroy_resources",
            return_value=[],
        ),
    ):
        destroy_cage("c", echo=lambda _: None)

    probe.assert_not_called()


def test_destroy_orphan_state_dir_is_cleaned_even_without_backend_resources():
    """If the stored config is corrupt/missing but the deployment dir
    still exists, the no-op path should still clean up ``state:<name>``."""
    with (
        patch("agentcage.state.load_deployment_config",
              side_effect=FileNotFoundError("no config")),
        patch("agentcage.state.deployment_exists", return_value=True),
        patch("agentcage.state.remove_deployment") as remove_state,
        patch("agentcage.backends.container.ContainerBackend.has_resources",
              return_value=False),
        patch("agentcage.backends.apple_container.AppleContainerBackend.has_resources",
              return_value=False),
        patch("agentcage.backends.vm.VmBackend.has_resources",
              return_value=False),
    ):
        removed = destroy_cage("c", echo=lambda _: None)

    assert removed == ["state:c"]
    remove_state.assert_called_once_with("c")


def test_apple_container_has_resources_uses_filesystem_only(tmp_path, monkeypatch):
    """``has_resources`` must be tool-free — no ``container`` CLI calls."""
    from agentcage.backends.apple_container import AppleContainerBackend

    monkeypatch.setenv("HOME", str(tmp_path))
    backend = AppleContainerBackend()
    assert backend.has_resources("nope") is False

    unit = backend.unit_dir() / "mine.json"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text("{}")
    assert backend.has_resources("mine") is True


def test_container_has_resources_uses_filesystem_only(tmp_path, monkeypatch):
    """``has_resources`` on container backend must not shell out to podman."""
    from agentcage.backends.container import ContainerBackend

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    backend = ContainerBackend()
    assert backend.has_resources("nope") is False

    unit_dir = backend.unit_dir()
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / "mine-cage.container").write_text("")
    assert backend.has_resources("mine") is True
