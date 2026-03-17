"""VM backend — Lima VM with Podman + quadlets inside."""

from __future__ import annotations

import os
from pathlib import Path

import click

from agentcage.config import Config
from agentcage.lima import prerequisites as lima_prerequisites
from agentcage.lima.instance import LimaInstance
from agentcage.lima.provisioning import generate_lima_config
from agentcage.quadlets import generate_quadlets


class VmBackend:
    """Backend using Lima VMs with Podman + quadlets inside.

    No host-side Podman required — all container operations happen
    inside the Lima VM. The host only needs limactl.
    """

    def _instance(self, name: str) -> LimaInstance:
        return LimaInstance(name)

    def check_prerequisites(self, config: Config) -> list[str]:
        return lima_prerequisites.check_prerequisites()

    def build_artifacts(self, config: Config, deploy_name: str) -> None:
        """Build proxy and DNS images inside the VM.

        Lima shares the host home directory via virtiofs, so the
        Containerfiles and build context are accessible inside the VM
        at the same paths.
        """
        inst = self._instance(deploy_name)
        if not inst.is_running():
            click.echo("VM is not running — skipping image build (will build on start)")
            return

        data_dir = Path(__file__).resolve().parent.parent / "data"
        containers_dir = str(data_dir / "containers")
        build_context = str(data_dir)

        click.echo("Building proxy image inside VM...")
        inst.exec([
            "podman", "build", "--no-cache",
            "--cap-add=CAP_CHOWN", "--cap-add=CAP_FOWNER",
            "--cap-add=CAP_SETUID", "--cap-add=CAP_SETGID",
            "--cap-add=CAP_DAC_OVERRIDE",
            "-t", "agentcage-proxy",
            "-f", os.path.join(containers_dir, "Containerfile.proxy"),
            build_context,
        ])
        click.echo("Building DNS image inside VM...")
        inst.exec([
            "podman", "build",
            "--cap-add=CAP_SETFCAP",
            "-t", "agentcage-dns",
            "-f", os.path.join(containers_dir, "Containerfile.dns"),
            build_context,
        ])

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
    ) -> dict[str, str]:
        """Generate Lima YAML as the primary 'unit', plus quadlet files for inside the VM."""
        lima_yaml = generate_lima_config(config)
        # Also generate quadlets (these will be installed inside the VM)
        quadlets = generate_quadlets(config, config_host_path, patches_host_dir, deploy_name)
        # Return both: Lima YAML and quadlets bundled together
        result: dict[str, str] = {"lima.yaml": lima_yaml}
        for qname, qcontent in quadlets.items():
            result[f"quadlets/{qname}"] = qcontent
        return result

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/lima"))

    def install_units(self, units: dict[str, str]) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        for filename, content in units.items():
            fpath = dest / filename
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content)
        click.echo(f"Installed Lima config to {dest}/")

    def start(self, name: str) -> None:
        inst = self._instance(name)
        config_path = self.unit_dir() / "lima.yaml"

        if not inst.exists():
            click.echo("Creating Lima VM instance...")
            inst.create(str(config_path))
            click.echo("VM created. Starting...")

        if not inst.is_running():
            click.echo("Starting Lima VM...")
            inst.start()
            click.echo("VM started and provisioned.")

        # Deploy cage into the VM
        self._deploy_cage(name, inst)
        click.echo(f"Started {name} (Lima VM)")

    def _deploy_cage(self, name: str, inst: LimaInstance) -> None:
        """Deploy quadlet files and start services inside the Lima VM."""
        quadlet_dir = self.unit_dir() / "quadlets"
        if not quadlet_dir.exists():
            return

        # Install quadlets inside the VM (use ~ to get the correct home dir,
        # Lima maps the host user into the guest)
        inst.exec(["bash", "-c", "mkdir -p ~/.config/containers/systemd"])
        vm_quadlet_dir = inst.exec(
            ["bash", "-c", "echo ~/.config/containers/systemd"]
        ).stdout.strip()

        for qfile in quadlet_dir.iterdir():
            if qfile.is_file():
                content = qfile.read_text()
                # Write quadlet file inside VM via shell
                inst.exec(["bash", "-c", f"cat > {vm_quadlet_dir}/{qfile.name} << 'QUADLET_EOF'\n{content}\nQUADLET_EOF"])

        # Build container images inside the VM (uses virtiofs-shared host files)
        self.build_artifacts(None, name)  # type: ignore[arg-type]

        # Reload systemd and start services
        inst.exec(["systemctl", "--user", "daemon-reload"])

        # Start services in order (network, volumes, then cage)
        for svc in [f"{name}-net-network", f"{name}-certs-volume", f"{name}-cage"]:
            try:
                inst.exec(["systemctl", "--user", "start", f"{svc}.service"])
            except Exception as e:
                click.echo(f"warning: failed to start {svc}: {e}", err=True)

    def stop(self, name: str) -> None:
        inst = self._instance(name)
        if inst.is_running():
            # Stop cage services inside VM first
            for svc in self.service_names(name):
                try:
                    inst.exec(
                        ["systemctl", "--user", "stop", f"{name}-{svc}.service"],
                        check=False,
                    )
                except Exception:
                    pass
            inst.stop()

    def restart(self, name: str) -> None:
        self.stop(name)
        self.start(name)

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:
        removed: list[str] = []
        inst = self._instance(name)
        if inst.exists():
            inst.delete()
            removed.append(f"lima-instance:{inst.name}")

        # Remove local config directory
        unit_dir = self.unit_dir()
        if unit_dir.exists():
            import shutil
            shutil.rmtree(unit_dir)
            removed.append(f"config-dir:{unit_dir}")

        return removed

    def is_running(self, name: str, service: str) -> bool:
        inst = self._instance(name)
        if not inst.is_running():
            return False
        # Check if the specific service is running inside the VM
        try:
            result = inst.exec(
                ["systemctl", "--user", "is-active", f"{name}-{service}.service"],
                check=False,
            )
            return result.stdout.strip() == "active"
        except Exception:
            return False

    def service_names(self, name: str) -> list[str]:
        return ["cage", "proxy", "dns"]
