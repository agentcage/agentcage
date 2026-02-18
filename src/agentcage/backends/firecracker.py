"""Firecracker backend — microVM isolation with Podman inside the VM."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import click
from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage import systemd
from agentcage.config import Config
from agentcage.firecracker import network, prerequisites
from agentcage.firecracker.rootfs import prepare_vm_rootfs, cleanup_rootfs, build_base_rootfs
from agentcage.firecracker.secrets import (
    create_secrets_drive,
    secrets_drive_path,
    remove_all_secrets,
)
from agentcage.firecracker.vmconfig import (
    generate_vm_config,
    write_vm_config,
    vm_config_path,
)
from agentcage.podman import Podman
from agentcage.quadlets import generate_quadlets

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


class FirecrackerBackend:
    """Backend using Firecracker microVMs with Podman containers inside."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._podman = Podman()

    def check_prerequisites(self, config: Config) -> list[str]:
        return prerequisites.check_prerequisites(config)

    def build_artifacts(self, config: Config, deploy_name: str) -> None:
        fc = config.firecracker

        # Build the container images on the host (they'll be exported into the VM rootfs)
        data_dir = Path(__file__).resolve().parent.parent / "data"
        containers_dir = str(data_dir / "containers")
        build_context = str(data_dir)

        click.echo("Building proxy image...")
        self._podman.build_image(
            "agentcage-proxy",
            os.path.join(containers_dir, "Containerfile.proxy"),
            build_context,
        )
        click.echo("Building DNS image...")
        self._podman.build_image(
            "agentcage-dns",
            os.path.join(containers_dir, "Containerfile.dns"),
            build_context,
            cap_add=["CAP_SETFCAP"],
        )

        # Build base VM rootfs if needed
        click.echo("Preparing base VM rootfs...")
        build_base_rootfs(self._podman)

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
    ) -> dict[str, str]:
        name = config.name
        fc = config.firecracker

        # Generate quadlet files (these go inside the VM, not on the host)
        quadlets = generate_quadlets(config, config_host_path, patches_host_dir, deploy_name)

        # Prepare VM rootfs with quadlets baked in
        click.echo("Preparing VM rootfs...")
        rootfs = prepare_vm_rootfs(
            self._podman, deploy_name, config, quadlets, config_host_path
        )

        # Build secrets drive
        sec_path = secrets_drive_path(deploy_name)
        has_secrets = create_secrets_drive(deploy_name, sec_path)

        # Generate VM config JSON
        vm_cfg_path = vm_config_path(deploy_name)
        vm_cfg = generate_vm_config(
            config, deploy_name, rootfs,
            secrets_drive_path=sec_path if has_secrets else None,
        )
        write_vm_config(vm_cfg, vm_cfg_path)

        # Generate the host systemd unit (one service for the entire VM)
        nethelper = shutil.which("agentcage-nethelper") or "agentcage-nethelper"
        runtime_dir = f"/run/user/{os.getuid()}/agentcage/{name}"

        env = SandboxedEnvironment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR / "firecracker")),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("fc-cage.service.j2")
        unit_content = template.render(
            name=name,
            nethelper=nethelper,
            firecracker_bin=fc.firecracker_bin,
            vm_config_path=vm_cfg_path,
            runtime_dir=runtime_dir,
            restart=config.container.restart,
            restart_sec=config.container.restart_sec,
            timeout_start_sec=config.container.timeout_start_sec,
            timeout_stop_sec=config.container.timeout_stop_sec,
        )

        return {f"{name}-cage.service": unit_content}

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/systemd/user"))

    def install_units(self, units: dict[str, str]) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        for filename, content in units.items():
            (dest / filename).write_text(content)
        click.echo(f"Installed unit files to {dest}/")
        systemd.daemon_reload()

    def start(self, name: str) -> None:
        # Ensure networking bridge exists
        try:
            network.create_bridge()
        except Exception as e:
            click.echo(f"warning: failed to create bridge: {e}", err=True)

        systemd.start_unit(f"{name}-cage.service")
        click.echo(f"Started {name} (Firecracker VM)")

    def stop(self, name: str) -> None:
        try:
            systemd.stop_unit(f"{name}-cage.service")
        except Exception as e:
            click.echo(f"warning: failed to stop {name}: {e}", err=True)

    def restart(self, name: str) -> None:
        try:
            systemd.restart_unit(f"{name}-cage.service")
        except Exception as e:
            click.echo(f"warning: failed to restart {name}: {e}", err=True)

    def destroy_resources(self, name: str) -> list[str]:
        removed: list[str] = []

        # Remove unit file
        unit_path = self.unit_dir() / f"{name}-cage.service"
        if unit_path.exists():
            unit_path.unlink()
            removed.append(f"{name}-cage.service")

        systemd.daemon_reload()

        # Destroy TAP device
        try:
            network.destroy_tap(name)
            removed.append(f"tap:{name}")
        except Exception:
            pass

        # Remove VM rootfs
        if cleanup_rootfs(name):
            removed.append("rootfs")

        # Remove secrets
        secret_keys = remove_all_secrets(name)
        for key in secret_keys:
            removed.append(f"secret:{key}")

        # Remove secrets drive
        sec_drive = secrets_drive_path(name)
        if os.path.isfile(sec_drive):
            os.unlink(sec_drive)
            removed.append("secrets-drive")

        # Remove VM config
        cfg_path = vm_config_path(name)
        if os.path.isfile(cfg_path):
            os.unlink(cfg_path)
            removed.append("vm-config")

        return removed

    def is_running(self, name: str, service: str) -> bool:
        # In Firecracker mode, there's only one service
        result = subprocess.run(
            ["systemctl", "--user", "is-active", f"{name}-cage.service"],
            capture_output=True, text=True,
        )
        return result.stdout.strip() == "active"

    def service_names(self, name: str) -> list[str]:
        # Single service for the entire VM
        return ["cage"]
