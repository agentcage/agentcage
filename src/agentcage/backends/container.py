"""Container backend — existing Podman/quadlet/systemd isolation."""

from __future__ import annotations

import os
from importlib.metadata import version as _pkg_version
from pathlib import Path

import click

from agentcage import systemd
from agentcage._timing import Phase
from agentcage.config import Config
from agentcage.podman import Podman, _podman_cmd, secret_env_names
from agentcage.quadlets import generate_quadlets


def _cage_from_units(units: dict[str, str]) -> str | None:
    """Recover the cage name from a quadlet filename ("foo-cage.container" → "foo")."""
    # Include legacy `-proxy.container` / `-dns.container` suffixes so v0.21
    # cages still resolve. Safe to drop after v0.23 (see destroy_resources).
    for fname in units:
        for suffix in ("-cage.container", "-egress.container",
                       "-proxy.container", "-dns.container",
                       "-net.network", "-public-certs.volume", "-certs.volume"):
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

    def ensure_ready(self, *, quiet: bool = False) -> None:
        # Nothing to auto-recover: rootless podman's systemd socket
        # activation brings the service up on demand when the quadlets
        # start. A missing podman is reported by check_prerequisites().
        return

    def build_artifacts(
        self, config: Config, deploy_name: str, *, quiet: bool = False,
        no_cache: bool = False, pull: bool = False,
    ) -> None:
        # The container backend builds/pulls the user image separately in
        # cli (_build_container_image + podman.pull) and, for `agentcage
        # run`, via run_scaffold_setup — all of which honor --no-cache/--pull.
        # This builds the static helper/egress image; --no-cache/--pull are
        # forwarded here too so a forced clean rebuild rebuilds the egress
        # proxy as well, matching the vm and apple-container backends.
        data_dir = Path(__file__).resolve().parent.parent / "data"
        containers_dir = str(data_dir / "containers")
        build_context = str(data_dir)

        # Tag with the running agentcage version so the egress.container.j2
        # quadlet's Image= pin matches what we just built. Reusing
        # importlib.metadata keeps this consistent with the version stamped
        # into cage.container.j2 via `agentcage_version` (see quadlets.py).
        version = _pkg_version("agentcage")
        if not quiet:
            click.echo(f"Building egress image (agentcage-egress:{version})...")
        with Phase("build.egress", cage=deploy_name):
            self._podman.build_image(
                f"agentcage-egress:{version}",
                os.path.join(containers_dir, "Containerfile.egress"),
                build_context,
                # setfcap → dnsmasq's NET_BIND_SERVICE file cap; the other
                # caps mirror the legacy proxy build (chown/setuid/setgid
                # for the user creation + apt-get install steps).
                cap_add=["CAP_CHOWN", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID",
                         "CAP_DAC_OVERRIDE", "CAP_SETFCAP"],
                quiet=quiet,
                no_cache=no_cache,
                pull=pull,
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
        # Store-aware Secret= emission (issue #262): pass the env-name set
        # of secrets actually present in the podman store so a `secret
        # rm`'d entry drops its quadlet directive instead of failing the
        # next boot with an unresolvable Secret= (start-limit-hit). The
        # info() call above already proved podman is reachable; on a
        # query failure fall back to None (= legacy emit-everything).
        try:
            store_secrets = secret_env_names(self._podman, deploy_name)
        except Exception:
            store_secrets = None
        return generate_quadlets(
            config,
            config_host_path,
            patches_host_dir,
            deploy_name,
            rootless=rootless,
            used_octets=used_octets,
            network_octet=network_octet,
            store_secrets=store_secrets,
        )

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/containers/systemd"))

    def user_unit_dir(self) -> Path:
        """Directory for plain (non-quadlet) systemd user units.

        Quadlet ``.container``/``.network``/``.volume`` files live in
        :meth:`unit_dir` and are transpiled by the quadlet generator. A plain
        ``.service`` (like the Policy API grants watcher) must be installed
        here so systemd-user picks it up directly.
        """
        return Path(os.path.expanduser("~/.config/systemd/user"))

    def grants_unit_path(self, name: str) -> Path:
        return self.user_unit_dir() / f"{name}-grants.service"

    def install_units(self, units: dict[str, str], *, quiet: bool = False) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        user_dest = self.user_unit_dir()
        user_dest.mkdir(parents=True, exist_ok=True)
        # The deploy_name isn't threaded down here; pull it from any unit name
        # (units are keyed "<name>-cage.container" / etc.). Best-effort.
        cage = _cage_from_units(units)
        with Phase("deploy.quadlets", cage=cage):
            for filename, content in units.items():
                # Plain .service units go to the systemd user dir; quadlet
                # types (.container/.network/.volume) go to the quadlet dir.
                if filename.endswith(".service"):
                    (user_dest / filename).write_text(content)
                else:
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
            try:
                systemd.restart_unit(f"{name}-public-certs-volume.service")
            except Exception as e:
                if not quiet:
                    click.echo(f"warning: failed to restart public-certs volume service: {e}", err=True)
            if (self.unit_dir() / f"{name}-podman-storage.volume").exists():
                try:
                    systemd.restart_unit(f"{name}-podman-storage-volume.service")
                except Exception:
                    pass
        with Phase("systemd.start_cage", cage=name):
            systemd.start_unit(f"{name}-cage.service")
        # Auto-start the Policy API grants watcher if its unit is installed
        # (transparent — the operator never starts it by hand). It is bound
        # to the egress, so it tracks the egress lifecycle on stop.
        if self.grants_unit_path(name).exists():
            try:
                systemd.start_unit(f"{name}-grants.service")
            except Exception as e:
                if not quiet:
                    click.echo(
                        f"warning: failed to start grants watcher: {e}",
                        err=True,
                    )
        if not quiet:
            click.echo(f"Started {name}-cage")

    def stop(self, name: str) -> None:
        for svc in self.service_names(name):
            try:
                systemd.stop_unit(f"{name}-{svc}.service")
            except Exception as e:
                click.echo(f"warning: failed to stop {name}-{svc}: {e}", err=True)
        if self.grants_unit_path(name).exists():
            try:
                systemd.stop_unit(f"{name}-grants.service")
            except Exception as e:
                click.echo(f"warning: failed to stop grants watcher: {e}", err=True)

    def restart(self, name: str) -> None:
        for svc in self.service_names(name):
            try:
                systemd.restart_unit(f"{name}-{svc}.service")
            except Exception as e:
                click.echo(f"warning: failed to restart {name}-{svc}: {e}", err=True)
        if self.grants_unit_path(name).exists():
            try:
                systemd.restart_unit(f"{name}-grants.service")
            except Exception as e:
                click.echo(f"warning: failed to restart grants watcher: {e}", err=True)

    # Quadlet filenames enumerated by destroy_resources / has_resources.
    # The list intentionally includes the LEGACY `-proxy.container` and
    # `-dns.container` entries from the pre-v0.22 3-service shape (B2 fix
    # from the eng review): `cage destroy` must still be able to clean up
    # a stuck v0.21 cage even though every other v0.22 CLI command will
    # refuse to operate on it (see cli._ensure_v022_cage). Safe to drop
    # after v0.23 — by then there are no v0.21 cages left in the wild.
    _QUADLET_FILES = (
        "-cage.container",
        "-egress.container",
        "-net.network",
        "-certs.volume",
        "-public-certs.volume",
        "-podman-storage.volume",
        # legacy v0.21 layout — kept for `cage destroy` cleanup only
        "-proxy.container",
        "-dns.container",
    )

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:
        removed: list[str] = []

        # Remove quadlet files
        quadlet_dir = self.unit_dir()
        for suffix in self._QUADLET_FILES:
            fname = f"{name}{suffix}"
            fpath = quadlet_dir / fname
            if fpath.exists():
                fpath.unlink()
                removed.append(fname)

        # Remove the Policy API grants watcher unit (plain .service, lives
        # in the systemd user dir, not the quadlet dir).
        grants_path = self.grants_unit_path(name)
        if grants_path.exists():
            grants_path.unlink()
            removed.append(grants_path.name)

        systemd.daemon_reload()

        # Remove Podman resources
        if self._podman.network_remove(f"{name}-net"):
            removed.append(f"network:{name}-net")
        if self._podman.volume_remove(f"agentcage-certs-{name}"):
            removed.append(f"volume:agentcage-certs-{name}")
        if self._podman.volume_remove(f"agentcage-public-certs-{name}"):
            removed.append(f"volume:agentcage-public-certs-{name}")
        if self._podman.volume_remove(f"agentcage-podman-{name}"):
            removed.append(f"volume:agentcage-podman-{name}")

        # Remove scoped secrets
        if not keep_secrets:
            for s in self._podman.secret_list(prefix=f"{name}."):
                sname = s.get("Name", "")
                if self._podman.secret_remove(sname):
                    removed.append(f"secret:{sname}")

        return removed

    def has_resources(self, name: str) -> bool:
        quadlet_dir = self.unit_dir()
        return any((quadlet_dir / f"{name}{suffix}").exists()
                   for suffix in self._QUADLET_FILES) or \
            self.grants_unit_path(name).exists()

    def is_running(self, name: str, service: str) -> bool:
        return self._podman.container_running(f"{name}-{service}")

    def service_names(self, name: str) -> list[str]:
        return ["cage", "egress"]

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
        as_root: bool = False,
    ) -> list[str]:
        """``podman exec [-it] -u <uid:gid> <name>-<service> <cmd>``.

        We pass ``-u`` explicitly because the Quadlet ``User=`` directive
        may be empty (the ubuntu scaffold sets ``user: ""`` because a
        default of 1000:1000 doesn't resolve to a real user in minimal
        base images), so without ``-u`` ``podman exec`` inherits the
        image's USER — typically root on ubuntu:latest. That made
        ``agentcage run ubuntu`` land at uid 0 on linux/podman while the
        apple-container path correctly dropped to uid 1000.

        ``as_root=False`` → ``-u 1000:1000`` (the cage workload's user).
        ``as_root=True``  → ``-u 0:0`` (operator debug — re-acquires
        the container's full cap set). NoNewPrivs=1 + dropped CapBnd
        from the cage's Quadlet are inherited by the exec session, so
        a capsh wrap (apple-container's primitive) isn't required here.

        Both uid and gid are pinned. ``-u 1000`` alone leaves the gid
        at the container default — for images without a uid 1000 in
        ``/etc/passwd`` (busybox, scratch-based) that default is gid 0
        (root group), which can read group-readable root files. Setting
        ``-u 1000:1000`` closes that minor leak.
        """
        flags = ["-it"] if interactive else []
        spec = "0:0" if as_root else "1000:1000"
        # Cage sessions get the CURRENT secret-injection placeholders from
        # the stored config (decoy tokens, never sensitive): a secret
        # declared after the cage container started is usable in a new
        # exec/shell session without any restart. PID 1's env refreshes
        # via EnvironmentFile= on the next restart.
        env_flags: list[str] = []
        if service == "cage":
            from agentcage.services import current_placeholders
            for env_name, placeholder in current_placeholders(name):
                env_flags += ["--env", f"{env_name}={placeholder}"]
        return [
            "podman", "exec", "-u", spec, *flags, *env_flags,
            f"{name}-{service}", *cmd,
        ]

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

    # Log drivers that keep container output in a file podman owns
    # rather than in the systemd journal. `journalctl -u <unit>` shows
    # nothing for these.
    _FILE_LOG_DRIVERS = frozenset({"k8s-file", "json-file"})

    def container_log_driver(self, container: str) -> str:
        """Resolved podman log driver for *container*, ``""`` if unknown.

        Podman selects ``journald`` only when it can actually write there
        — which needs a conmon built with journald support — and falls
        back to ``k8s-file`` silently otherwise. The choice is made per
        container at run time, so it can only be read back, not derived
        from config.
        """
        try:
            info = self._podman.container_inspect(container)
        except Exception:
            return ""
        log_cfg = (info.get("HostConfig") or {}).get("LogConfig") or {}
        return str(log_cfg.get("Type") or "").lower()

    def audit_reads_journal(self, name: str) -> bool:
        """Whether this cage's audit stream is readable from the journal.

        ``False`` means the egress landed on a file-based driver and the
        audit trail has to be read back through ``podman logs`` instead.
        An unreadable container (destroyed, never started) reports
        ``True``: the journal is then the only place history could still
        live.
        """
        driver = self.container_log_driver(f"{name}-egress")
        return driver not in self._FILE_LOG_DRIVERS

    def audit_argv(
        self,
        name: str,
        *,
        since: str | None = None,
        follow: bool = False,
    ) -> list[str]:
        """Read the egress's audit stream.

        Audit JSON lines are emitted by the mitmproxy addon to stderr;
        dnsmasq audit lines flow through the same stream (the supervisor
        wraps both processes under tini/PID 1). Where that stderr *lands*
        depends on the log driver podman picked, so the source is chosen
        to match:

        * ``journald`` — ``journalctl`` on the unit. Preferred: it spans
          container recreation, so `cage restart` doesn't truncate the
          audit history.
        * ``k8s-file`` / ``json-file`` — ``podman logs``, the only reader
          for output the journal never received. Bounded to the current
          container generation, which is all that driver retains anyway.

        Reading the wrong one is silent: the proxy looks healthy and
        `cage audit` simply prints nothing.
        """
        if self.audit_reads_journal(name):
            argv = ["journalctl", "--user",
                    "-u", f"{name}-egress", "-o", "cat"]
            if since:
                argv += ["--since", since]
            if follow:
                argv.append("-f")
            else:
                argv += ["-n", "10000"]  # over-read; many lines aren't audit
            return argv

        # `podman logs` has no journalctl-compatible time syntax (it takes
        # Go durations / RFC3339, not "10 minutes ago"), so `since` is not
        # forwarded. The CLI applies AuditFilter.since post-parse on every
        # backend, which covers this path exactly as it covers
        # apple-container's tail.
        argv = [*_podman_cmd(), "logs"]
        if follow:
            argv.append("-f")
        else:
            argv += ["--tail", "10000"]
        argv.append(f"{name}-egress")
        return argv
