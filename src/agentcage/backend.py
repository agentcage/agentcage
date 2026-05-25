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

    def build_artifacts(self, config: Config, deploy_name: str, *, quiet: bool = False) -> None:
        """Build container images or VM rootfs as needed."""
        ...

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
        used_octets: set[int] | None = None,
    ) -> dict[str, str]:
        """Return {filename: content} for systemd unit / quadlet files."""
        ...

    def unit_dir(self) -> Path:
        """Return the directory where unit files should be installed."""
        ...

    def install_units(self, units: dict[str, str], *, quiet: bool = False) -> None:
        """Write unit files to unit_dir() and reload systemd."""
        ...

    def start(self, name: str, *, quiet: bool = False) -> None:
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

    # ── Process inspection & streaming (lifted from cli.py if/elif/else) ────
    #
    # exec_argv / logs_argv / audit_argv return argv lists the CLI hands to
    # subprocess.run / os.execvp / subprocess.Popen. Returning argv (rather
    # than running the subprocess inside the backend) keeps the contract
    # simple: the CLI owns I/O and process control; the backend owns the
    # backend-specific "how do I reach the cage's stdout / journal / proxy
    # log?" decision.
    #
    # Implementations should raise ``BackendUnsupported`` (defined alongside
    # this protocol) when a request shape can't be served — for example
    # ``--service proxy`` on apple-container, where the proxy isn't a
    # separately-addressable container.

    def exec_argv(
        self,
        name: str,
        service: str,
        cmd: list[str],
        *,
        interactive: bool = False,
    ) -> list[str]:
        """Argv to exec a command inside the cage's ``service`` component.

        ``service`` is one of ``service_names(name)`` (typically ``cage`` /
        ``proxy`` / ``dns``). ``cmd`` is the user's command vector; the
        backend prepends its own runner (e.g. ``podman exec [-it] <c> <cmd>``).
        """
        ...

    def logs_argv(
        self,
        name: str,
        services: list[str],
        *,
        follow: bool = False,
        lines: int = 0,
        min_level: str | None = None,
    ) -> list[str]:
        """Argv to stream the cage's combined log output.

        Backends decide what "combined" means: the container backend reads
        per-service journal units; apple-container reads ``container logs``
        for the single microVM; vm wraps journalctl in ``limactl shell``.
        ``min_level`` is a hint; not every backend can filter at source.
        """
        ...

    def audit_argv(
        self,
        name: str,
        *,
        since: str | None = None,
        follow: bool = False,
    ) -> list[str]:
        """Argv that emits one audit JSON line per line on stdout.

        The CLI parses each line via :func:`agentcage.audit.extract_audit_json`
        and feeds matching entries through ``AuditFilter``.
        """
        ...


class BackendUnsupported(Exception):
    """Raised by Backend methods when the requested shape isn't supported.

    The CLI catches this and prints the message to stderr before exit(1),
    so each backend can produce a helpful, context-specific error (e.g.
    ``--service proxy on apple-container``).
    """
