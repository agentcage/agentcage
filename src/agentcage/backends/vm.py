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

        Lima mounts the host home directory via virtiofs, so the build
        context (inside the agentcage package) is directly accessible.
        We copy it to /tmp inside the VM first since podman build
        needs local filesystem access for its build containers.
        """
        inst = self._instance(deploy_name)
        if not inst.is_running():
            click.echo("VM is not running — skipping image build (will build on start)")
            return

        data_dir = Path(__file__).resolve().parent.parent / "data"
        vm_build_dir = "/tmp/agentcage-build"

        # Copy build context to VM-local filesystem.
        # Lima mounts ~ via virtiofs, so paths under $HOME are accessible
        # inside the VM. Paths outside ~ (e.g. system-wide installs) need
        # limactl copy instead.
        click.echo("Copying build context into VM...")
        inst.exec(["rm", "-rf", vm_build_dir], check=False)
        home = Path.home()
        try:
            data_dir.relative_to(home)
            # Path is under home — accessible via virtiofs mount
            inst.exec(["bash", "-c", f"cp -r {data_dir} {vm_build_dir}"])
        except ValueError:
            # Path is outside home — use limactl copy
            import subprocess as sp
            inst.exec(["mkdir", "-p", vm_build_dir])
            sp.run(
                ["limactl", "copy", "-r",
                 f"{data_dir}/.", f"{inst.name}:{vm_build_dir}/"],
                check=True,
            )

        click.echo("Building proxy image inside VM...")
        inst.exec([
            "podman", "build", "--no-cache",
            "--cap-add=CAP_CHOWN", "--cap-add=CAP_FOWNER",
            "--cap-add=CAP_SETUID", "--cap-add=CAP_SETGID",
            "--cap-add=CAP_DAC_OVERRIDE",
            "-t", "agentcage-proxy",
            "-f", f"{vm_build_dir}/containers/Containerfile.proxy",
            vm_build_dir,
        ])
        click.echo("Building DNS image inside VM...")
        inst.exec([
            "podman", "build",
            "--cap-add=CAP_SETFCAP",
            "-t", "agentcage-dns",
            "-f", f"{vm_build_dir}/containers/Containerfile.dns",
            vm_build_dir,
        ])

        # Pull the cage image inside the VM
        if config and config.container.image:
            click.echo(f"Pulling {config.container.image} inside VM...")
            inst.exec(["podman", "pull", config.container.image], check=False)

        # Cleanup
        inst.exec(["rm", "-rf", vm_build_dir], check=False)

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
        # Load config from state to pass to build_artifacts
        from agentcage import state
        config = None
        try:
            config = state.load_deployment_config(name)
        except Exception:
            pass
        self._deploy_cage(name, inst, config)
        click.echo(f"Started {name} (Lima VM)")

    def _deploy_cage(self, name: str, inst: LimaInstance, config: Config | None = None) -> None:
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

        # Bridge secrets from host Podman into VM's Podman
        self._bridge_secrets(name, inst)

        # Build container images and pull cage image inside the VM
        self.build_artifacts(config, name)

        # Reload systemd and start services in dependency order
        inst.exec(["systemctl", "--user", "daemon-reload"])

        services = [
            f"{name}-net-network",
            f"{name}-certs-volume",
            f"{name}-proxy",
            f"{name}-dns",
            f"{name}-cage",
        ]

        # First attempt
        import time
        for svc in services:
            try:
                inst.exec(["systemctl", "--user", "start", f"{svc}.service"])
            except Exception as e:
                click.echo(f"warning: failed to start {svc}: {e}", err=True)

        # Check for failed services and retry after a delay
        # (handles race conditions like virtiofs mounts not being ready)
        time.sleep(5)
        inst.exec(["systemctl", "--user", "reset-failed"], check=False)

        # Retry failed infrastructure services first (not cage)
        infra = services[:-1]  # everything except cage
        for svc in infra:
            try:
                result = inst.exec(
                    ["systemctl", "--user", "is-active", f"{svc}.service"],
                    check=False,
                )
                if result.stdout.strip() != "active":
                    click.echo(f"Retrying {svc}...")
                    inst.exec(["systemctl", "--user", "restart", f"{svc}.service"])
            except Exception as e:
                click.echo(f"warning: retry failed for {svc}: {e}", err=True)

        # Wait for proxy to be ready (CA cert generated) before starting cage
        click.echo("Waiting for proxy to be ready...")
        for _ in range(30):
            result = inst.exec(
                ["systemctl", "--user", "is-active", f"{name}-proxy.service"],
                check=False,
            )
            if result.stdout.strip() == "active":
                break
            time.sleep(1)

        # Now start the cage
        cage_svc = f"{name}-cage"
        try:
            result = inst.exec(
                ["systemctl", "--user", "is-active", f"{cage_svc}.service"],
                check=False,
            )
            if result.stdout.strip() != "active":
                inst.exec(["systemctl", "--user", "reset-failed"], check=False)
                inst.exec(["systemctl", "--user", "start", f"{cage_svc}.service"])
        except Exception as e:
            click.echo(f"warning: failed to start {cage_svc}: {e}", err=True)

    def _bridge_secrets(self, name: str, inst: LimaInstance) -> None:
        """Copy Podman secrets from the host into the VM's Podman store."""
        import subprocess as sp

        # List host secrets scoped to this cage
        try:
            result = sp.run(
                ["podman", "secret", "ls", "--format", "{{.Name}}"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                return
            host_secrets = [
                s.strip() for s in result.stdout.splitlines()
                if s.strip().startswith(f"{name}.")
            ]
        except FileNotFoundError:
            # No host podman — secrets may have been set via other means
            return

        for secret_name in host_secrets:
            try:
                # Read secret value from host
                value = sp.run(
                    ["podman", "secret", "inspect", "--showsecret",
                     "--format", "{{.SecretData}}", secret_name],
                    capture_output=True, text=True, check=True,
                ).stdout.strip()

                # Create in VM (replace if exists)
                inst.exec(
                    ["podman", "secret", "rm", secret_name],
                    check=False,
                )
                inst.exec(
                    ["bash", "-c",
                     f"echo -n '{value}' | podman secret create {secret_name} -"],
                )
                click.echo(f"  Bridged secret: {secret_name}")
            except Exception as e:
                click.echo(f"warning: failed to bridge secret {secret_name}: {e}", err=True)

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
