"""Backend factory for cage isolation strategies."""

from __future__ import annotations

from agentcage.backend import Backend
from agentcage.config import Config


def get_backend(config: Config) -> Backend:
    """Return the appropriate backend for the given config."""
    isolation = getattr(config, "isolation", "container")
    if isolation == "vm":
        from agentcage.backends.vm import VmBackend

        return VmBackend()
    from agentcage.backends.container import ContainerBackend

    return ContainerBackend()
