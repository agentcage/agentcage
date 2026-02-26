"""Container backend — existing Podman/quadlet/systemd isolation."""

from __future__ import annotations

import os
from pathlib import Path

import click

from agentcage import systemd
from agentcage.config import Config
from agentcage.podman import Podman
from agentcage.quadlets import generate_quadlets


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
            info = self._podman.info()
            rootless = info.get("host", {}).get("security", {}).get("rootless", False)
            if not rootless:
                issues.append("Podman is not running in rootless mode")
        except Exception:
            issues.append("Podman is not available")
        return issues

    def build_artifacts(self, config: Config, deploy_name: str) -> None:
        data_dir = Path(__file__).resolve().parent.parent / "data"
        containers_dir = str(data_dir / "containers")
        build_context = str(data_dir)

        click.echo("Building proxy image...")
        self._podman.build_image(
            "agentcage-proxy",
            os.path.join(containers_dir, "Containerfile.proxy"),
            build_context,
            no_cache=True,
            cap_add=["CAP_CHOWN", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE"],
        )
        click.echo("Building DNS image...")
        self._podman.build_image(
            "agentcage-dns",
            os.path.join(containers_dir, "Containerfile.dns"),
            build_context,
            cap_add=["CAP_SETFCAP"],
        )

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
    ) -> dict[str, str]:
        return generate_quadlets(config, config_host_path, patches_host_dir, deploy_name)

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/containers/systemd"))

    def install_units(self, units: dict[str, str]) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        for filename, content in units.items():
            (dest / filename).write_text(content)
        click.echo(f"Installed quadlet files to {dest}/")
        systemd.daemon_reload()

    def start(self, name: str) -> None:
        # Restart network/volume first so they're recreated
        # (systemd may think they're still active from a previous run even if
        # podman resources were removed by 'cage destroy')
        try:
            systemd.restart_unit(f"{name}-net-network.service")
        except Exception as e:
            click.echo(f"warning: failed to restart network service: {e}", err=True)
        try:
            systemd.restart_unit(f"{name}-certs-volume.service")
        except Exception as e:
            click.echo(f"warning: failed to restart volume service: {e}", err=True)
        try:
            systemd.restart_unit(f"{name}-podman-storage-volume.service")
        except Exception:
            pass  # volume only exists when nested_containers is enabled
        systemd.start_unit(f"{name}-cage.service")
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
