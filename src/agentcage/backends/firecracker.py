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
from agentcage.firecracker.rootfs import (
    prepare_vm_rootfs, cleanup_rootfs, build_base_rootfs,
    ensure_data_drive, data_drive_path,
)
from agentcage.firecracker.secrets import (
    create_secrets_drive,
    secrets_drive_path,
    remove_all_secrets,
    save_secret,
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

        # Container images to bake into the VM rootfs
        container_images = ["agentcage-proxy", "agentcage-dns"]
        # Also include the user's cage image if it exists locally
        user_image = config.container.image
        result = subprocess.run(
            ["podman", "image", "exists", user_image],
            capture_output=True,
        )
        if result.returncode == 0:
            container_images.append(user_image)
        else:
            click.echo(f"Note: image '{user_image}' not local — VM will pull on first boot")

        # Bridge secrets from Podman store → file-based store for the VM
        all_secret_names = list(config.container.podman_secrets)
        for rule in config.secret_injection:
            if rule.env not in all_secret_names:
                all_secret_names.append(rule.env)

        if all_secret_names:
            click.echo("Bridging secrets from Podman store to VM file store...")
            for secret_name in all_secret_names:
                podman_name = f"{deploy_name}.{secret_name}"
                try:
                    value = self._podman.secret_read(podman_name)
                    save_secret(deploy_name, secret_name, value)
                    click.echo(f"  Bridged secret: {secret_name}")
                except subprocess.CalledProcessError:
                    click.echo(
                        f"  Warning: secret '{podman_name}' not found in Podman store",
                        err=True,
                    )

        # Prepare VM rootfs with quadlets, images, and startup script baked in
        click.echo("Preparing VM rootfs...")
        rootfs = prepare_vm_rootfs(
            self._podman, deploy_name, config, quadlets, config_host_path,
            container_images=container_images,
        )

        # Build secrets drive
        sec_path = secrets_drive_path(deploy_name)
        has_secrets = create_secrets_drive(deploy_name, sec_path)

        # Create persistent data drive for named volumes (survives rootfs rebuilds)
        data_path = None
        if config.container.named_volumes:
            data_path = ensure_data_drive(deploy_name)

        # Generate VM config JSON
        vm_cfg_path = vm_config_path(deploy_name)
        vm_cfg = generate_vm_config(
            config, deploy_name, rootfs,
            secrets_drive_path=sec_path if has_secrets else None,
            data_drive_path=data_path,
        )
        write_vm_config(vm_cfg, vm_cfg_path)

        # Parse port forwards from config
        vm_ip = network.cage_ip(deploy_name)
        port_forwards = []
        for port_spec in config.container.ports:
            parts = port_spec.split(":")
            if len(parts) == 3:
                host_bind, host_port, container_port = parts
            elif len(parts) == 2:
                host_bind = "0.0.0.0"
                host_port, container_port = parts
            else:
                continue
            port_forwards.append({
                "host_bind": host_bind,
                "host_port": host_port,
                "vm_port": host_port,  # VM maps host_port → host_port internally
            })

        # Generate the host systemd unit (one service for the entire VM)
        firecracker_path = shutil.which(fc.firecracker_bin) or fc.firecracker_bin
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
            firecracker_bin=firecracker_path,
            vm_config_path=vm_cfg_path,
            runtime_dir=runtime_dir,
            restart=config.container.restart,
            restart_sec=config.container.restart_sec,
            timeout_start_sec=config.container.timeout_start_sec,
            timeout_stop_sec=config.container.timeout_stop_sec,
            port_forwards=port_forwards,
            vm_ip=vm_ip,
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

        # Create TAP device before starting the service (requires sudo,
        # which is incompatible with systemd hardening directives)
        network.create_tap(name)

        systemd.start_unit(f"{name}-cage.service")
        click.echo(f"Started {name} (Firecracker VM)")

    def stop(self, name: str) -> None:
        try:
            systemd.stop_unit(f"{name}-cage.service")
        except Exception as e:
            click.echo(f"warning: failed to stop {name}: {e}", err=True)

        # Destroy TAP device after stopping the service
        try:
            network.destroy_tap(name)
        except Exception:
            pass

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

        # Remove data drive
        d_drive = data_drive_path(name)
        if os.path.isfile(d_drive):
            os.unlink(d_drive)
            removed.append("data-drive")

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
