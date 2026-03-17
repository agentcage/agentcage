"""VM backend — Lima VM with Podman + quadlets inside."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import click

from agentcage.config import Config
from agentcage.lima import prerequisites as lima_prerequisites
from agentcage.lima.instance import LimaInstance
from agentcage.lima.provisioning import generate_lima_config
from agentcage.podman import Podman
from agentcage.quadlets import generate_quadlets


class VmBackend:
    """Backend using Lima VMs with Podman + quadlets inside."""

    def __init__(self) -> None:
        self._podman = Podman()

    def _instance(self, name: str) -> LimaInstance:
        return LimaInstance(name)

    def check_prerequisites(self, config: Config) -> list[str]:
        return lima_prerequisites.check_prerequisites()

    def build_artifacts(self, config: Config, deploy_name: str) -> None:
        """Build proxy and DNS images on the host."""
        # Same as ContainerBackend — build images on the host,
        # they'll be exported into the VM later
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
            # After create, VM is started and provisioned (Podman installed)
            click.echo("VM created and provisioned.")
        elif not inst.is_running():
            inst.start()

        # Deploy cage into the VM
        self._deploy_cage(name, inst)
        click.echo(f"Started {name} (Lima VM)")

    def _deploy_cage(self, name: str, inst: LimaInstance) -> None:
        """Deploy quadlet files and start services inside the Lima VM."""
        quadlet_dir = self.unit_dir() / "quadlets"
        if not quadlet_dir.exists():
            return

        # Install quadlets inside the VM
        vm_quadlet_dir = f"/home/{self._lima_user()}/.config/containers/systemd"
        inst.exec(["mkdir", "-p", vm_quadlet_dir])

        for qfile in quadlet_dir.iterdir():
            if qfile.is_file():
                content = qfile.read_text()
                # Write quadlet file inside VM via shell
                inst.exec(["bash", "-c", f"cat > {vm_quadlet_dir}/{qfile.name} << 'QUADLET_EOF'\n{content}\nQUADLET_EOF"])

        # Export and load container images into the VM
        self._load_images_into_vm(name, inst)

        # Reload systemd and start services
        inst.exec(["systemctl", "--user", "daemon-reload"])

        # Start services in order (network, volumes, then cage)
        for svc in [f"{name}-net-network", f"{name}-certs-volume", f"{name}-cage"]:
            try:
                inst.exec(["systemctl", "--user", "start", f"{svc}.service"])
            except Exception as e:
                click.echo(f"warning: failed to start {svc}: {e}", err=True)

    def _load_images_into_vm(self, name: str, inst: LimaInstance) -> None:
        """Export container images from host and load them into the VM."""
        images = ["agentcage-proxy", "agentcage-dns"]
        for image in images:
            try:
                # Export image from host podman, pipe into VM's podman
                click.echo(f"  Loading {image} into VM...")
                subprocess.run(
                    f"podman save {image} | limactl shell {inst.name} -- podman load",
                    shell=True,
                    check=True,
                )
            except Exception as e:
                click.echo(f"warning: failed to load {image}: {e}", err=True)

    def _lima_user(self) -> str:
        """Return the default Lima user (used for paths inside the VM)."""
        return "lima"

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

        # Remove podman secrets on host
        if not keep_secrets:
            for s in self._podman.secret_list(prefix=f"{name}."):
                sname = s.get("Name", "")
                if self._podman.secret_remove(sname):
                    removed.append(f"secret:{sname}")

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
