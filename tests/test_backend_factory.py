"""Tests for the backend factory."""

from __future__ import annotations

from agentcage.config import Config, ContainerConfig, VmConfig
from agentcage.backends import get_backend
from agentcage.backends.container import ContainerBackend


class TestGetBackend:
    def test_default_returns_container_backend(self):
        cfg = Config(name="test", container=ContainerConfig(image="test:latest"))
        backend = get_backend(cfg)
        assert isinstance(backend, ContainerBackend)

    def test_container_mode_returns_container_backend(self):
        cfg = Config(
            name="test",
            isolation="container",
            container=ContainerConfig(image="test:latest"),
        )
        backend = get_backend(cfg)
        assert isinstance(backend, ContainerBackend)

    def test_vm_mode_returns_vm_backend(self):
        cfg = Config(
            name="test",
            isolation="vm",
            container=ContainerConfig(image="test:latest"),
            vm=VmConfig(),
        )
        backend = get_backend(cfg)
        from agentcage.backends.vm import VmBackend
        assert isinstance(backend, VmBackend)
