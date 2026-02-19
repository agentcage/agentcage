"""Tests for the backend factory."""

from __future__ import annotations

from agentcage.config import Config, ContainerConfig, FirecrackerConfig
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

    def test_firecracker_mode_returns_firecracker_backend(self):
        cfg = Config(
            name="test",
            isolation="firecracker",
            container=ContainerConfig(image="test:latest"),
            firecracker=FirecrackerConfig(kernel="/boot/vmlinux"),
        )
        backend = get_backend(cfg)
        from agentcage.backends.firecracker import FirecrackerBackend
        assert isinstance(backend, FirecrackerBackend)
