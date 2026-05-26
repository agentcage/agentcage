"""VM backend — Lima VM with Podman + quadlets inside."""

from __future__ import annotations

import base64
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import click

from agentcage._timing import Phase
from agentcage.config import Config
from agentcage.lima import prerequisites as lima_prerequisites
from agentcage.lima.instance import LimaInstance
from agentcage.lima.provisioning import generate_lima_config
from agentcage.quadlets import generate_quadlets


VM_SERVICE_STARTUP_DELAY_S = 5
VM_SERVICE_STARTUP_POLL_INTERVAL_S = 0.1
PROXY_READINESS_TIMEOUT_S = 30
PROXY_READINESS_POLL_INTERVAL_S = 0.25


def _wait_infra_active(
    inst: LimaInstance,
    services: list[str],
    timeout_s: float = VM_SERVICE_STARTUP_DELAY_S,
    interval_s: float = VM_SERVICE_STARTUP_POLL_INTERVAL_S,
) -> list[str]:
    """Poll ``systemctl --user is-active`` for *services* until all active or *timeout_s*.

    Returns the list of services still not active when the function returns
    (empty on success). Replaces a blanket ``time.sleep(5)`` that previously
    waited the full delay even when services came up in milliseconds.
    """
    deadline = time.monotonic() + timeout_s
    pending = list(services)
    while pending:
        next_pending: list[str] = []
        for svc in pending:
            r = inst.exec(
                ["systemctl", "--user", "is-active", f"{svc}.service"],
                check=False,
            )
            if r.stdout.strip() != "active":
                next_pending.append(svc)
        pending = next_pending
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    return pending


class VmBackend:
    """Backend using Lima VMs with Podman + quadlets inside.

    No host-side Podman required — all container operations happen
    inside the Lima VM. The host only needs limactl.
    """

    def _instance(self, name: str) -> LimaInstance:
        return LimaInstance(name)

    def check_prerequisites(self, config: Config) -> list[str]:
        return lima_prerequisites.check_prerequisites()

    def build_artifacts(self, config: Config, deploy_name: str, *, quiet: bool = False) -> None:
        """Build proxy and DNS images inside the VM.

        The build context (package data directory) is copied into the VM
        via ``limactl copy`` since the home directory is not mounted
        (only specific directories are exposed via virtiofs for security).
        """
        inst = self._instance(deploy_name)
        if not inst.is_running():
            click.echo("VM is not running — skipping image build (will build on start)")
            return

        data_dir = Path(__file__).resolve().parent.parent / "data"
        vm_build_dir = "/tmp/agentcage-build"

        # Copy build context into the VM via limactl copy.
        # The home directory is not mounted (only targeted subdirectories
        # are exposed), so we always use limactl copy regardless of where
        # the package is installed.
        click.echo("Copying build context into VM...")
        inst.exec(["rm", "-rf", vm_build_dir], check=False)
        inst.exec(["mkdir", "-p", vm_build_dir])
        with Phase("copy.build_context", cage=deploy_name):
            subprocess.run(
                ["limactl", "copy", "-r",
                 f"{data_dir}/.", f"{inst.name}:{vm_build_dir}/"],
                check=True,
            )

        click.echo("Building proxy image inside VM...")
        with Phase("build.proxy", cage=deploy_name):
            inst.exec([
                "podman", "build",
                "--cap-add=CAP_CHOWN", "--cap-add=CAP_FOWNER",
                "--cap-add=CAP_SETUID", "--cap-add=CAP_SETGID",
                "--cap-add=CAP_DAC_OVERRIDE",
                "-t", "agentcage-proxy",
                "-f", f"{vm_build_dir}/containers/Containerfile.proxy",
                vm_build_dir,
            ])
        click.echo("Building DNS image inside VM...")
        with Phase("build.dns", cage=deploy_name):
            inst.exec([
                "podman", "build",
                "--cap-add=CAP_SETFCAP",
                "-t", "agentcage-dns",
                "-f", f"{vm_build_dir}/containers/Containerfile.dns",
                vm_build_dir,
            ])

        # Build or pull the cage image inside the VM
        if config and config.container.image:
            if config.container.build.containerfile:
                # Scaffold image — copy Containerfile and build inside the VM
                with Phase("build.cage", cage=deploy_name):
                    self._build_cage_image_in_vm(config, deploy_name, inst, vm_build_dir)
            else:
                click.echo(f"Pulling {config.container.image} inside VM...")
                with Phase("pull.cage", cage=deploy_name):
                    inst.exec(["podman", "pull", config.container.image], check=False)

        # Cleanup
        inst.exec(["rm", "-rf", vm_build_dir], check=False)

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
        used_octets: set[int] | None = None,
        network_octet: int | None = None,
    ) -> dict[str, str]:
        """Generate Lima YAML as the primary 'unit', plus quadlet files for inside the VM."""
        lima_yaml = generate_lima_config(config)
        # Also generate quadlets (these will be installed inside the VM)
        quadlets = generate_quadlets(
            config,
            config_host_path,
            patches_host_dir,
            deploy_name,
            used_octets=used_octets,
            network_octet=network_octet,
        )
        # Return both: Lima YAML and quadlets bundled together
        result: dict[str, str] = {"lima.yaml": lima_yaml}
        for qname, qcontent in quadlets.items():
            result[f"quadlets/{qname}"] = qcontent
        return result

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/lima"))

    def install_units(self, units: dict[str, str], *, quiet: bool = False) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        for filename, content in units.items():
            fpath = dest / filename
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content)
        if not quiet:
            click.echo(f"Installed Lima config to {dest}/")

    def start(self, name: str, *, quiet: bool = False) -> None:
        inst = self._instance(name)
        config_path = self.unit_dir() / "lima.yaml"

        if not inst.exists():
            click.echo("Creating Lima VM instance...")
            with Phase("lima.create", cage=name):
                inst.create(str(config_path))
            click.echo("VM created. Starting...")

        if not inst.is_running():
            click.echo("Starting Lima VM...")
            with Phase("lima.start", cage=name):
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

    def _build_cage_image_in_vm(
        self, config: Config, deploy_name: str, inst: LimaInstance, vm_build_dir: str,
    ) -> None:
        """Build a scaffold's cage image inside the VM."""
        from agentcage import state as _state

        # Resolve the Containerfile from the state dir (copied there during run/create)
        state_dir = _state.deployment_dir(deploy_name)
        containerfile = state_dir / Path(config.container.build.containerfile).name
        if not containerfile.exists():
            # Fall back to scaffold source
            from agentcage.init import _SCAFFOLDS_DIR
            meta = _state.load_metadata(deploy_name)
            scaffold = meta.get("scaffold", "")
            if scaffold:
                containerfile = _SCAFFOLDS_DIR / scaffold / config.container.build.containerfile
        if not containerfile.exists():
            click.echo(f"warning: Containerfile not found for {config.container.image}", err=True)
            return

        scaffold_dir = containerfile.parent
        vm_scaffold_dir = f"{vm_build_dir}/scaffold"
        inst.exec(["mkdir", "-p", vm_scaffold_dir])
        subprocess.run(
            ["limactl", "copy", "-r",
             f"{scaffold_dir}/.", f"{inst.name}:{vm_scaffold_dir}/"],
            check=True,
        )

        click.echo(f"Building {config.container.image} inside VM...")
        build_cmd = [
            "podman", "build",
            "--cap-add=CAP_CHOWN", "--cap-add=CAP_FOWNER",
            "--cap-add=CAP_SETUID", "--cap-add=CAP_SETGID",
            "--cap-add=CAP_DAC_OVERRIDE", "--cap-add=CAP_SETFCAP",
            "-t", config.container.image,
            "-f", f"{vm_scaffold_dir}/{containerfile.name}",
            vm_scaffold_dir,
        ]
        inst.exec(build_cmd)

    def _deploy_cage(self, name: str, inst: LimaInstance, config: Config | None = None) -> None:
        """Deploy quadlet files and start services inside the Lima VM."""
        quadlet_dir = self.unit_dir() / "quadlets"
        if not quadlet_dir.exists():
            return

        # Install quadlets inside the VM (use ~ to get the correct home dir,
        # Lima maps the host user into the guest)
        with Phase("deploy.quadlets", cage=name):
            inst.exec(["bash", "-c", "mkdir -p ~/.config/containers/systemd"])
            vm_quadlet_dir = inst.exec(
                ["bash", "-c", "echo ~/.config/containers/systemd"]
            ).stdout.strip()

            for qfile in quadlet_dir.iterdir():
                if qfile.is_file():
                    content = qfile.read_text()
                    # Write quadlet file inside VM via base64 to avoid
                    # heredoc injection (content could contain the delimiter)
                    encoded = base64.b64encode(content.encode()).decode()
                    inst.exec([
                        "bash", "-c",
                        f"echo '{encoded}' | base64 -d > {shlex.quote(vm_quadlet_dir)}/{shlex.quote(qfile.name)}",
                    ])

        # Bridge secrets from host Podman into VM's Podman
        with Phase("deploy.bridge_secrets", cage=name):
            self._bridge_secrets(name, inst)

        # Create any pending secrets (from cage create --set-secret)
        with Phase("deploy.pending_secrets", cage=name):
            self._create_pending_secrets(name, inst)

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

        with Phase("systemd.start", cage=name):
            # First attempt
            for svc in services:
                try:
                    inst.exec(["systemctl", "--user", "start", f"{svc}.service"])
                except Exception as e:
                    click.echo(f"warning: failed to start {svc}: {e}", err=True)

            # Wait for infrastructure services to come up, polling every 100ms
            # instead of sleeping the full delay. On warm restarts the services
            # are usually active within a few hundred ms; the old unconditional
            # 5s sleep was pure idle time. The deadline is the same as before
            # (handles race conditions like virtiofs targeted mounts not being
            # ready), so cold runs are unaffected.
            infra = services[:-1]  # everything except cage
            not_yet_active = _wait_infra_active(inst, infra)
            inst.exec(["systemctl", "--user", "reset-failed"], check=False)

            # Retry whatever did not come up within the deadline.
            for svc in not_yet_active:
                try:
                    click.echo(f"Retrying {svc}...")
                    inst.exec(["systemctl", "--user", "restart", f"{svc}.service"])
                except Exception as e:
                    click.echo(f"warning: retry failed for {svc}: {e}", err=True)

        # Wait for proxy to be ready (CA cert generated) before starting cage.
        # Time-based deadline (not iteration count) so the poll interval can
        # be tightened without shrinking the timeout — mitmproxy is usually
        # ready in 2-6s, so a sub-second interval shaves time off the median.
        click.echo("Waiting for proxy to be ready...")
        with Phase("systemd.wait_proxy", cage=name):
            proxy_deadline = time.monotonic() + PROXY_READINESS_TIMEOUT_S
            while time.monotonic() < proxy_deadline:
                result = inst.exec(
                    ["systemctl", "--user", "is-active", f"{name}-proxy.service"],
                    check=False,
                )
                if result.stdout.strip() == "active":
                    break
                time.sleep(PROXY_READINESS_POLL_INTERVAL_S)

        # Now start the cage
        cage_svc = f"{name}-cage"
        with Phase("systemd.start_cage", cage=name):
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

    def _create_pending_secrets(self, name: str, inst: LimaInstance) -> None:
        """Create secrets from cage create --set-secret inside the VM."""
        from agentcage import state as _state
        import json as _json

        secrets_file = _state.deployment_dir(name) / "pending_secrets.json"
        if not secrets_file.exists():
            return

        try:
            pending = _json.loads(secrets_file.read_text())
        except Exception:
            secrets_file.unlink(missing_ok=True)
            return

        try:
            for key, value in pending:
                full = f"{name}.{key}"
                inst.exec(["podman", "secret", "rm", full], check=False)
                # Pipe stdin via inst.exec so we get --tty=false (no PTY
                # cooking) and --workdir / (no spurious cd warnings).
                inst.exec(
                    ["podman", "secret", "create", full, "-"],
                    input=value,
                )
                click.echo(f"  Secret '{full}' set in VM.")
        finally:
            # Always clean up secrets file, even on error
            secrets_file.unlink(missing_ok=True)

    def _bridge_secrets(self, name: str, inst: LimaInstance) -> None:
        """Copy secrets from the host into the VM's Podman store.

        Handles both Podman-stored secrets and systemd-creds encrypted blobs.
        For encrypted blobs, decrypts on the host and pipes plaintext into the VM.
        """
        from agentcage import state as _state

        # --- Bridge systemd-creds encrypted secrets ---
        creds_dir = _state.deployment_dir(name) / "creds"
        if creds_dir.is_dir():
            for cred_file in creds_dir.iterdir():
                if not cred_file.suffix == ".cred":
                    continue
                key = cred_file.stem
                secret_name = f"{name}.{key}"
                try:
                    # Decrypt on host
                    r = subprocess.run(
                        ["systemd-creds", "decrypt", str(cred_file), "-"],
                        capture_output=True, text=True, check=True,
                    )
                    value = r.stdout
                    # Create in VM (replace if exists)
                    inst.exec(
                        ["podman", "secret", "rm", secret_name],
                        check=False,
                    )
                    inst.exec(
                        ["podman", "secret", "create", secret_name, "-"],
                        input=value,
                    )
                    click.echo(f"  Bridged secret (decrypted): {secret_name}")
                except Exception as e:
                    click.echo(
                        f"warning: failed to bridge encrypted secret {secret_name}: {e}",
                        err=True,
                    )

        # --- Bridge Podman-stored secrets ---
        try:
            result = subprocess.run(
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
                value = subprocess.run(
                    ["podman", "secret", "inspect", "--showsecret",
                     "--format", "{{.SecretData}}", secret_name],
                    capture_output=True, text=True, check=True,
                ).stdout.strip()

                # Create in VM (replace if exists)
                inst.exec(
                    ["podman", "secret", "rm", secret_name],
                    check=False,
                )
                # Pipe value via stdin to avoid shell injection
                inst.exec(
                    ["podman", "secret", "create", secret_name, "-"],
                    input=value,
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

        # Remove cage-specific config files (not the shared directory)
        lima_yaml = self.unit_dir() / "lima.yaml"
        if lima_yaml.exists():
            lima_yaml.unlink()
            removed.append(f"config:{lima_yaml}")
        quadlets_dir = self.unit_dir() / "quadlets"
        if quadlets_dir.exists():
            import shutil
            shutil.rmtree(quadlets_dir)
            removed.append(f"quadlets:{quadlets_dir}")

        return removed

    def has_resources(self, name: str) -> bool:
        if shutil.which("limactl") is None:
            return False
        try:
            return self._instance(name).exists()
        except (FileNotFoundError, OSError):
            return False

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

    # --- Backend protocol: process inspection / streaming --------------------
    #
    # The VM backend wraps everything in ``limactl shell <inst> --`` and the
    # journal needs ``sg systemd-journal`` because Lima's persistent SSH
    # ControlMaster establishes the session before provisioning runs
    # ``usermod -aG systemd-journal`` and the SSH inherits stale groups.

    def exec_argv(
        self,
        name: str,
        service: str,
        cmd: list[str],
        *,
        interactive: bool = False,
        as_root: bool = False,  # noqa: ARG002 — vm Quadlets already unprivileged
    ) -> list[str]:
        inst = self._instance(name)
        flags = ["-it"] if interactive else []
        return ["limactl", "shell", inst.name, "--",
                "podman", "exec", *flags, f"{name}-{service}", *cmd]

    def logs_argv(
        self,
        name: str,
        services: list[str],
        *,
        follow: bool = False,
        lines: int = 0,
        min_level: str | None = None,  # noqa: ARG002
    ) -> list[str]:
        import shlex
        inst = self._instance(name)
        # conmon routes proxy/dns logs to the system journal even when the
        # service unit is a `--user` one, so the right filter is
        # `--user-unit` rather than `--user -u`.
        journal_argv = ["journalctl", "-o", "cat"]
        for svc in services:
            journal_argv += ["--user-unit", f"{name}-{svc}"]
        if follow:
            journal_argv.append("-f")
        if lines:
            journal_argv += ["-n", str(lines)]
        return ["limactl", "shell", inst.name, "--",
                "sg", "systemd-journal", "-c", shlex.join(journal_argv)]

    def audit_argv(
        self,
        name: str,
        *,
        since: str | None = None,
        follow: bool = False,
    ) -> list[str]:
        import shlex
        inst = self._instance(name)
        journal_argv = ["journalctl", "--user-unit", f"{name}-proxy",
                        "--user-unit", f"{name}-dns", "-o", "cat"]
        if since:
            journal_argv += ["--since", since]
        if follow:
            journal_argv.append("-f")
        else:
            journal_argv += ["-n", "10000"]
        return ["limactl", "shell", inst.name, "--",
                "sg", "systemd-journal", "-c", shlex.join(journal_argv)]
