"""Container backend — existing Podman/quadlet/systemd isolation."""

from __future__ import annotations

import os
from pathlib import Path

import click

from agentcage import systemd
from agentcage._timing import Phase
from agentcage.config import Config
from agentcage.podman import Podman
from agentcage.quadlets import generate_quadlets


def _cage_from_units(units: dict[str, str]) -> str | None:
    """Recover the cage name from a quadlet filename ("foo-cage.container" → "foo")."""
    for fname in units:
        for suffix in ("-cage.container", "-proxy.container", "-dns.container",
                       "-net.network", "-certs.volume"):
            if fname.endswith(suffix):
                return fname[: -len(suffix)]
    return None


class ContainerBackend:
    """Backend using rootless Podman containers with quadlet units."""

    def __init__(self) -> None:
        self._podman = Podman()

    @property
    def podman(self) -> Podman:
        return self._podman

    def check_prerequisites(self, config: Config) -> list[str]:
        issues: list[str] = []
        try:
            self._podman.info()
        except Exception:
            issues.append("Podman is not available")
        return issues

    def build_artifacts(self, config: Config, deploy_name: str, *, quiet: bool = False) -> None:
        data_dir = Path(__file__).resolve().parent.parent / "data"
        containers_dir = str(data_dir / "containers")
        build_context = str(data_dir)

        if not quiet:
            click.echo("Building proxy image...")
        with Phase("build.proxy", cage=deploy_name):
            self._podman.build_image(
                "agentcage-proxy",
                os.path.join(containers_dir, "Containerfile.proxy"),
                build_context,
                cap_add=["CAP_CHOWN", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE"],
                quiet=quiet,
            )
        if not quiet:
            click.echo("Building DNS image...")
        with Phase("build.dns", cage=deploy_name):
            self._podman.build_image(
                "agentcage-dns",
                os.path.join(containers_dir, "Containerfile.dns"),
                build_context,
                cap_add=["CAP_SETFCAP"],
                quiet=quiet,
            )

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
        used_octets: set[int] | None = None,
        network_octet: int | None = None,
    ) -> dict[str, str]:
        rootless = self._podman.info().get("host", {}).get("security", {}).get("rootless", True)
        return generate_quadlets(
            config,
            config_host_path,
            patches_host_dir,
            deploy_name,
            rootless=rootless,
            used_octets=used_octets,
            network_octet=network_octet,
        )

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/containers/systemd"))

    def install_units(self, units: dict[str, str], *, quiet: bool = False) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        # The deploy_name isn't threaded down here; pull it from any unit name
        # (units are keyed "<name>-cage.container" / etc.). Best-effort.
        cage = _cage_from_units(units)
        with Phase("deploy.quadlets", cage=cage):
            for filename, content in units.items():
                (dest / filename).write_text(content)
            if not quiet:
                click.echo(f"Installed quadlet files to {dest}/")
            systemd.daemon_reload()

    def start(self, name: str, *, quiet: bool = False) -> None:
        # Restart network/volume first so they're recreated
        # (systemd may think they're still active from a previous run even if
        # podman resources were removed by 'cage destroy')
        with Phase("systemd.start", cage=name):
            try:
                systemd.restart_unit(f"{name}-net-network.service")
            except Exception as e:
                if not quiet:
                    click.echo(f"warning: failed to restart network service: {e}", err=True)
            try:
                systemd.restart_unit(f"{name}-certs-volume.service")
            except Exception as e:
                if not quiet:
                    click.echo(f"warning: failed to restart volume service: {e}", err=True)
            if (self.unit_dir() / f"{name}-podman-storage.volume").exists():
                try:
                    systemd.restart_unit(f"{name}-podman-storage-volume.service")
                except Exception:
                    pass
        with Phase("systemd.start_cage", cage=name):
            systemd.start_unit(f"{name}-cage.service")
        if not quiet:
            click.echo(f"Started {name}-cage")

    def stop(self, name: str) -> None:
        for svc in self.service_names(name):
            try:
                systemd.stop_unit(f"{name}-{svc}.service")
            except Exception as e:
                click.echo(f"warning: failed to stop {name}-{svc}: {e}", err=True)

    def restart(self, name: str) -> None:
        for svc in self.service_names(name):
            try:
                systemd.restart_unit(f"{name}-{svc}.service")
            except Exception as e:
                click.echo(f"warning: failed to restart {name}-{svc}: {e}", err=True)

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:
        removed: list[str] = []

        # Remove quadlet files
        quadlet_dir = self.unit_dir()
        quadlet_files = [
            f"{name}-cage.container",
            f"{name}-proxy.container",
            f"{name}-dns.container",
            f"{name}-net.network",
            f"{name}-certs.volume",
            f"{name}-podman-storage.volume",
        ]
        for fname in quadlet_files:
            fpath = quadlet_dir / fname
            if fpath.exists():
                fpath.unlink()
                removed.append(fname)

        systemd.daemon_reload()

        # Remove Podman resources
        if self._podman.network_remove(f"{name}-net"):
            removed.append(f"network:{name}-net")
        if self._podman.volume_remove(f"agentcage-certs-{name}"):
            removed.append(f"volume:agentcage-certs-{name}")
        if self._podman.volume_remove(f"agentcage-podman-{name}"):
            removed.append(f"volume:agentcage-podman-{name}")

        # Remove scoped secrets
        if not keep_secrets:
            for s in self._podman.secret_list(prefix=f"{name}."):
                sname = s.get("Name", "")
                if self._podman.secret_remove(sname):
                    removed.append(f"secret:{sname}")

        return removed

    def is_running(self, name: str, service: str) -> bool:
        return self._podman.container_running(f"{name}-{service}")

    def service_names(self, name: str) -> list[str]:
        return ["cage", "proxy", "dns"]

    # --- Backend protocol: process inspection / streaming --------------------
    #
    # These return argv lists for the CLI to subprocess.Popen / os.execvp.
    # See agentcage.backend.Backend for the contract.

    def exec_argv(
        self,
        name: str,
        service: str,
        cmd: list[str],
        *,
        interactive: bool = False,
    ) -> list[str]:
        """``podman exec [-it] <name>-<service> <cmd>``."""
        flags = ["-it"] if interactive else []
        return ["podman", "exec", *flags, f"{name}-{service}", *cmd]

    def logs_argv(
        self,
        name: str,
        services: list[str],
        *,
        follow: bool = False,
        lines: int = 0,
        min_level: str | None = None,  # noqa: ARG002 — caller-side filter
    ) -> list[str]:
        """``journalctl --user -u <name>-<svc> -o cat`` for the requested
        services. Container backend's services are systemd --user units
        managed by Quadlet; this reads their combined output. ``min_level``
        isn't passed through because journalctl's priority filter would
        require numeric levels that don't map cleanly to our string set —
        the CLI's per-line filter handles it post-parse."""
        argv = ["journalctl", "--user", "-o", "cat"]
        for svc in services:
            argv += ["-u", f"{name}-{svc}"]
        if follow:
            argv.append("-f")
        if lines:
            argv += ["-n", str(lines)]
        return argv

    def audit_argv(
        self,
        name: str,
        *,
        since: str | None = None,
        follow: bool = False,
    ) -> list[str]:
        """``journalctl`` for the proxy+dns units. Audit JSON lines are
        emitted by the mitmproxy addon to stderr (= journal stream)."""
        argv = ["journalctl", "--user",
                "-u", f"{name}-proxy", "-u", f"{name}-dns", "-o", "cat"]
        if since:
            argv += ["--since", since]
        if follow:
            argv.append("-f")
        else:
            argv += ["-n", "10000"]  # over-read; many lines aren't audit
        return argv
