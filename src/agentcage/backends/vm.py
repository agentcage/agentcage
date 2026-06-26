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
from agentcage.quadlets import (
    generate_quadlets,
    vm_local_config_dir,
    vm_local_dns_allowlist_path,
    vm_local_proxy_config_path,
)


def push_config_files(name: str, inst: LimaInstance) -> None:
    """Mirror the host's proxy-config.yaml + dns-allowlist.conf into the VM.

    The proxy and dns sidecar containers bind-mount these files. On the VM
    backend the source can't be the host path under
    ``~/.config/agentcage/cages/<name>/`` because Lima's reverse-sshfs mount
    caches host writes — dnsmasq SIGHUP and the mitmproxy mtime-poll would
    re-read the same stale bytes forever. So we keep the host file as the
    authoritative state (preserved for ``cage backup``, audit tooling, etc.)
    and additionally push a copy to a VM-local path that the quadlets
    actually mount.

    Idempotent. Safe to call on every deploy / start / restart / domain
    edit; the cost is two ``inst.exec`` round-trips per file.
    """
    from agentcage import state
    # vm_local_*() return ``%h/...`` paths so podman-quadlet can bind-mount
    # them (systemd expands ``%h`` to the user's home before podman parses
    # the unit). Bash does NOT expand systemd specifiers, so for shell-
    # context use here we must resolve ``$HOME`` in the guest ourselves
    # and substitute before invocation.
    home = inst.exec(["bash", "-c", "echo ~"]).stdout.strip()

    def _abs(p: str) -> str:
        return home + p[2:] if p.startswith("%h") else p

    vm_dir = _abs(vm_local_config_dir(name))
    inst.exec(["mkdir", "-p", vm_dir])

    proxy_cfg = state.deployment_dir(name) / "proxy-config.yaml"
    if proxy_cfg.is_file():
        encoded = base64.b64encode(proxy_cfg.read_bytes()).decode()
        inst.exec([
            "bash", "-c",
            f"echo '{encoded}' | base64 -d > "
            f"{shlex.quote(_abs(vm_local_proxy_config_path(name)))}",
        ])

    dns_allow = state.dns_allowlist_path(name)
    if dns_allow.is_file():
        encoded = base64.b64encode(dns_allow.read_bytes()).decode()
        inst.exec([
            "bash", "-c",
            f"echo '{encoded}' | base64 -d > "
            f"{shlex.quote(_abs(vm_local_dns_allowlist_path(name)))}",
        ])

    placeholders_env = state.placeholders_env_path(name)
    if placeholders_env.is_file():
        from agentcage.quadlets import (
            vm_local_cage_env_dir, vm_local_placeholders_env_path,
        )
        inst.exec(["mkdir", "-p", _abs(vm_local_cage_env_dir(name))])
        encoded = base64.b64encode(placeholders_env.read_bytes()).decode()
        inst.exec([
            "bash", "-c",
            f"echo '{encoded}' | base64 -d > "
            f"{shlex.quote(_abs(vm_local_placeholders_env_path(name)))}",
        ])


VM_SERVICE_STARTUP_DELAY_S = 5
VM_SERVICE_STARTUP_POLL_INTERVAL_S = 0.1
PROXY_READINESS_TIMEOUT_S = 30
PROXY_READINESS_POLL_INTERVAL_S = 0.25


def _dump_service_failure(inst: LimaInstance, svc: str) -> None:
    """Print ``systemctl status`` + last ``journalctl`` lines for ``svc``.

    Used when a service fails to start so the operator sees WHY instead of
    just an opaque ``returned non-zero exit status 1``. Best-effort: if
    the diagnostic calls themselves fail, swallow them — we are already
    on the error path and the original failure is what matters.
    """
    try:
        status = inst.exec(
            ["systemctl", "--user", "status", f"{svc}.service",
             "--no-pager", "-l"],
            check=False,
        )
        if status.stdout:
            click.echo(status.stdout.rstrip(), err=True)
    except Exception:
        pass
    try:
        journal = inst.exec(
            ["journalctl", "--user", "-u", f"{svc}.service",
             "--no-pager", "-n", "40"],
            check=False,
        )
        if journal.stdout:
            click.echo(journal.stdout.rstrip(), err=True)
    except Exception:
        pass


def _systemctl_start(
    inst: LimaInstance, svc: str, *, restart: bool = False,
) -> None:
    """Run ``systemctl --user start`` (or ``restart``) for *svc*.

    On failure, surface stderr + the service's recent journal lines. The
    previous behavior was ``click.echo(f"warning: ... {e}", err=True)`` —
    ``e`` was the CalledProcessError repr (command + exit code), which
    told the operator nothing about *why* the unit failed. Now they see
    systemctl's actual diagnostic plus the unit's last journal entries.
    """
    action = "restart" if restart else "start"
    try:
        inst.exec(["systemctl", "--user", action, f"{svc}.service"])
    except subprocess.CalledProcessError as e:
        click.echo(f"warning: failed to {action} {svc}", err=True)
        if e.stderr:
            click.echo(e.stderr.rstrip(), err=True)
        _dump_service_failure(inst, svc)
    except Exception as e:
        click.echo(f"warning: failed to {action} {svc}: {e}", err=True)


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

    def ensure_ready(self, *, quiet: bool = False) -> None:
        # The Lima VM (this backend's substrate) is created and started
        # on demand inside start(); there's nothing to bring up ahead of
        # it here. A missing limactl/QEMU is reported by
        # check_prerequisites().
        return

    def build_artifacts(
        self, config: Config, deploy_name: str, *, quiet: bool = False,
        no_cache: bool = False, pull: bool = False,
    ) -> None:
        """Build the egress and cage images inside the VM.

        ``no_cache``/``pull`` come from ``--no-cache``/``--pull`` and are
        honored for every build/pull step inside the VM — the egress image,
        the scaffold cage image, and a direct image pull — so a forced clean
        rebuild actually rebuilds, matching the container and apple-container
        backends. They map to ``podman build --no-cache`` / ``--pull=always``
        (and ``podman pull`` always re-fetches from the registry).

        The build context (package data directory) is copied into the VM
        via ``limactl copy`` since the home directory is not mounted
        (only specific directories are exposed via virtiofs for security).
        """
        from importlib.metadata import version as _pkg_version

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

        # --no-cache / --pull map to the same podman build flags inside the
        # VM as on the host (see Podman.build_image).
        build_flags = []
        if no_cache:
            build_flags.append("--no-cache")
        if pull:
            build_flags.append("--pull=always")

        version = _pkg_version("agentcage")
        click.echo(f"Building egress image inside VM (agentcage-egress:{version})...")
        with Phase("build.egress", cage=deploy_name):
            inst.exec([
                "podman", "build", *build_flags,
                "--cap-add=CAP_CHOWN", "--cap-add=CAP_FOWNER",
                "--cap-add=CAP_SETUID", "--cap-add=CAP_SETGID",
                "--cap-add=CAP_DAC_OVERRIDE", "--cap-add=CAP_SETFCAP",
                "-t", f"agentcage-egress:{version}",
                "-f", f"{vm_build_dir}/containers/Containerfile.egress",
                vm_build_dir,
            ])

        # Build or pull the cage image inside the VM
        if config and config.container.image:
            if config.container.build.containerfile:
                # Scaffold image — copy Containerfile and build inside the VM
                with Phase("build.cage", cage=deploy_name):
                    self._build_cage_image_in_vm(
                        config, deploy_name, inst, vm_build_dir,
                        build_flags=build_flags,
                    )
            else:
                click.echo(f"Pulling {config.container.image} inside VM...")
                with Phase("pull.cage", cage=deploy_name):
                    inst.exec(["podman", "pull", config.container.image], check=False)

        # Cleanup
        inst.exec(["rm", "-rf", vm_build_dir], check=False)

    # Cage start inside a Lima VM has to spin up the qemu virtual disk,
    # extract image layers through fuse-overlayfs (the rootless storage
    # driver provisioned by agentcage), wire up the per-cage podman
    # network, and bind-mount user volumes that virtiofs forwards from
    # the host. Anything that fits comfortably in 60s on bare metal
    # routinely brushes 90-120s in the VM; the pi scaffold's default of
    # 60s reliably times out the cage container on first start, which
    # surfaces to the operator as a baffling "failed because a timeout
    # was exceeded" with no obvious knob to turn. Floor every VM-mode
    # cage to 300s — generous enough for slow hosts, still tight enough
    # that a genuinely stuck cage fails before the operator gives up.
    VM_MIN_TIMEOUT_START_SEC = 300

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
        # Floor the cage's TimeoutStartSec for VM-mode cages. Mutates the
        # in-memory config; the on-disk cage.yaml is untouched.
        if config.container.timeout_start_sec < self.VM_MIN_TIMEOUT_START_SEC:
            config.container.timeout_start_sec = self.VM_MIN_TIMEOUT_START_SEC
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
        *, build_flags: list[str] | None = None,
    ) -> None:
        """Build a scaffold's cage image inside the VM.

        ``build_flags`` carries the resolved ``--no-cache``/``--pull=always``
        podman build flags from ``build_artifacts`` so a forced clean rebuild
        rebuilds the cage image too.
        """
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
            "podman", "build", *(build_flags or []),
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

        # Mirror proxy-config.yaml + dns-allowlist.conf into a VM-local
        # path. Quadlets bind-mount this VM-local copy (NOT the host path
        # under ~/.config/agentcage) so SIGHUP / mtime-poll live-reload
        # actually sees ``domain add``/``domain rm`` rewrites — see
        # ``push_config_files`` and ``cli._update_dns_quadlet``.
        with Phase("deploy.vm_local_config", cage=name):
            push_config_files(name, inst)

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

        # Infrastructure services start FIRST and complete before we touch
        # the cage. The cage's ExecStartPre is a 30-attempt 1s poll for
        # mitmproxy's CA cert (generated on first egress run); racing it
        # against egress startup turns the first cage start into a near-
        # certain failure that surfaces as a scary
        #   "warning: failed to start <name>-cage: ... non-zero exit status 1"
        # right before the wait-for-proxy block — the actual second attempt
        # below would succeed, but the user has already pressed Ctrl-C
        # convinced something is wrong. Starting the cage strictly after
        # the egress is "active" eliminates that spurious failure path.
        infra_services = [
            f"{name}-net-network",
            f"{name}-certs-volume",
            f"{name}-public-certs-volume",
            f"{name}-egress",
        ]

        with Phase("systemd.start", cage=name):
            # First attempt
            for svc in infra_services:
                _systemctl_start(inst, svc)

            # Wait for infrastructure services to come up, polling every 100ms
            # instead of sleeping the full delay. On warm restarts the services
            # are usually active within a few hundred ms; the old unconditional
            # 5s sleep was pure idle time. The deadline is the same as before
            # (handles race conditions like virtiofs targeted mounts not being
            # ready), so cold runs are unaffected.
            not_yet_active = _wait_infra_active(inst, infra_services)
            inst.exec(["systemctl", "--user", "reset-failed"], check=False)

            # Retry whatever did not come up within the deadline.
            for svc in not_yet_active:
                click.echo(f"Retrying {svc}...")
                _systemctl_start(inst, svc, restart=True)

        # Wait for the egress container to be ready (CA cert generated)
        # before starting cage. Time-based deadline (not iteration count)
        # so the poll interval can be tightened without shrinking the
        # timeout — mitmproxy is usually ready in 2-6s, so a sub-second
        # interval shaves time off the median.
        click.echo("Waiting for egress to be ready...")
        with Phase("systemd.wait_egress", cage=name):
            egress_deadline = time.monotonic() + PROXY_READINESS_TIMEOUT_S
            egress_active = False
            while time.monotonic() < egress_deadline:
                result = inst.exec(
                    ["systemctl", "--user", "is-active", f"{name}-egress.service"],
                    check=False,
                )
                if result.stdout.strip() == "active":
                    egress_active = True
                    break
                time.sleep(PROXY_READINESS_POLL_INTERVAL_S)

        if not egress_active:
            # Don't pretend to start the cage when egress never came up —
            # the cage's ExecStartPre will just spin for 30s and then fail
            # on the same root cause. Surface the egress's actual failure
            # reason instead.
            _dump_service_failure(inst, f"{name}-egress")
            raise RuntimeError(
                f"egress {name}-egress did not become active within "
                f"{PROXY_READINESS_TIMEOUT_S}s; cage not started"
            )

        # Now start the cage
        cage_svc = f"{name}-cage"
        with Phase("systemd.start_cage", cage=name):
            result = inst.exec(
                ["systemctl", "--user", "is-active", f"{cage_svc}.service"],
                check=False,
            )
            if result.stdout.strip() != "active":
                inst.exec(["systemctl", "--user", "reset-failed"], check=False)
                _systemctl_start(inst, cage_svc)
                # Confirm cage actually came up — _systemctl_start surfaces
                # stderr + journalctl on failure but doesn't raise (so the
                # infra-services loop can continue past a single dead unit).
                # For the cage itself the deploy is meaningless without it,
                # so verify is-active and fail the whole `cage update` /
                # `cage create` loudly. Previously this path silently
                # returned and the CLI printed "Updated cage X" while the
                # cage's status was failed.
                final = inst.exec(
                    ["systemctl", "--user", "is-active", f"{cage_svc}.service"],
                    check=False,
                )
                if final.stdout.strip() != "active":
                    raise RuntimeError(
                        f"cage {cage_svc} failed to start "
                        f"(state={final.stdout.strip() or 'unknown'}); see "
                        f"diagnostic output above"
                    )

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
        return ["cage", "egress"]

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
        as_root: bool = False,
    ) -> list[str]:
        inst = self._instance(name)
        flags = ["-it"] if interactive else []
        # --workdir / suppresses the spurious "cd: <host-cwd>: No such file
        # or directory" warning when the host's cwd isn't mounted in the VM
        # (only ~/.config/agentcage and ~/.local/share/agentcage are). The
        # v0.21.13 fix lives in LimaInstance.exec; this argv builder bypasses
        # the helper (caller uses os.execvp), so the flag has to be inlined
        # here too. Same for logs_argv / audit_argv below.
        #
        # ``-u`` is explicit for the same reason as ContainerBackend.exec_argv:
        # the cage Quadlet's ``User=`` may be empty (ubuntu scaffold uses
        # ``user: ""``), so ``podman exec`` would inherit the image's USER
        # (root on ubuntu:latest). NoNewPrivs=1 + dropped CapBnd from the
        # Quadlet are inherited by the exec session inside the VM, so no
        # capsh wrap is needed — ``-u 1000:1000`` is sufficient. Pinning
        # gid avoids a minor leak on busybox/scratch images that lack a
        # uid 1000 entry in /etc/passwd (default gid would be 0).
        spec = "0:0" if as_root else "1000:1000"
        # Same as ContainerBackend.exec_argv: cage sessions carry the
        # current placeholders (decoy tokens) read from the stored config
        # at exec time, so secrets declared after the cage started are
        # usable in new sessions without a restart.
        env_flags: list[str] = []
        if service == "cage":
            from agentcage.services import current_placeholders
            for env_name, placeholder in current_placeholders(name):
                env_flags += ["--env", f"{env_name}={placeholder}"]
        return ["limactl", "shell", "--workdir", "/", inst.name, "--",
                "podman", "exec", "-u", spec, *flags, *env_flags,
                f"{name}-{service}", *cmd]

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
        # conmon routes the egress container's logs to the system journal
        # even when the service unit is a `--user` one, so the right filter
        # is `--user-unit` rather than `--user -u`.
        journal_argv = ["journalctl", "-o", "cat"]
        for svc in services:
            journal_argv += ["--user-unit", f"{name}-{svc}"]
        if follow:
            journal_argv.append("-f")
        if lines:
            journal_argv += ["-n", str(lines)]
        return ["limactl", "shell", "--workdir", "/", inst.name, "--",
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
        # mitmproxy + dnsmasq audit lines both flow through the egress
        # container's stderr → conmon → journal; a single --user-unit
        # filter catches both.
        journal_argv = ["journalctl", "--user-unit", f"{name}-egress",
                        "-o", "cat"]
        if since:
            journal_argv += ["--since", since]
        if follow:
            journal_argv.append("-f")
        else:
            journal_argv += ["-n", "10000"]
        return ["limactl", "shell", "--workdir", "/", inst.name, "--",
                "sg", "systemd-journal", "-c", shlex.join(journal_argv)]
