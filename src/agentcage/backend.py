"""Backend protocol for cage isolation strategies."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from agentcage.config import Config


class Backend(Protocol):
    """Interface that all isolation backends must implement."""

    def check_prerequisites(self, config: Config) -> list[str]:
        """Return list of unmet prerequisite descriptions (empty = all OK)."""
        ...

    def build_artifacts(self, config: Config, deploy_name: str) -> None:
        """Build container images or VM rootfs as needed."""
        ...

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
    ) -> dict[str, str]:
        """Return {filename: content} for systemd unit / quadlet files."""
        ...

    def unit_dir(self) -> Path:
        """Return the directory where unit files should be installed."""
        ...

    def install_units(self, units: dict[str, str]) -> None:
        """Write unit files to unit_dir() and reload systemd."""
        ...

    def start(self, name: str) -> None:
        """Start a cage by name."""
        ...

    def stop(self, name: str) -> None:
        """Stop a cage by name."""
        ...

    def restart(self, name: str) -> None:
        """Restart all services for a cage."""
        ...

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:
        """Remove backend-specific resources. Return list of removed items."""
        ...

    def is_running(self, name: str, service: str) -> bool:
        """Check if a specific service of a cage is running."""
        ...

    def service_names(self, name: str) -> list[str]:
        """Return the service suffixes for a cage (e.g. ['cage', 'proxy', 'dns'])."""
        ...
