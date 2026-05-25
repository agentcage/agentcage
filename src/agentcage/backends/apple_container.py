"""Apple container backend — single hardened microVM per cage.

See issue #120 for the design. This backend uses Apple's `container` CLI on
macOS 26+ Apple Silicon. Each cage is one Apple container (one microVM); the
agentcage supervisor runs as PID 1 and applies hardening before exec'ing the
user's cage workload.

What ships in this backend:
  - Hardened cage process: uid 1000, CapEff/Prm/Inh/Bnd all empty,
    NoNewPrivs=1, hidepid=2 on /proc.
  - Egress filter: in-microVM mitmproxy (uid 200) intercepts the cage's
    tcp/80 + tcp/443 via iptables REDIRECT; non-allowlisted hosts get a
    403 from the proxy. dnsmasq (uid 201) is the only DNS path. IPv6 is
    killed at netfilter + sysctl so AAAA records can't bypass v4 NAT.
  - Cage HTTPS is MITMed with a per-cage CA installed in the cage's trust
    store before the workload starts.

Not yet shipped (follow-ups tracked in #120):
  - Server-side {{SECRET:...}} placeholder injection via the existing
    SecretInjector — for now the cage sees env-injected secrets raw.
  - `agentcage cage audit` integration (mitmproxy already writes proxy.log
    inside the cage; CLI plumbing is part of the Backend protocol lift).
  - Backend protocol lift for exec/logs/audit.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
from pathlib import Path

import click

from agentcage.apple_container import cli as ac_cli
from agentcage.apple_container import prerequisites as ac_prereq
from agentcage.apple_container import scaffold as ac_scaffold
from agentcage.apple_container import wrapper as ac_wrapper
from agentcage.config import Config


def _normalize_cpus(value: str) -> str:
    """Apple's `container run --cpus` rejects fractional values; ceil to int.

    Podman accepts "0.5" / "1.5"; Apple wants "1" / "2". Round up so the
    cage gets at least the cap the user wrote. Returns the original
    string if it's already an integer or doesn't parse as a float.
    """
    try:
        f = float(value)
    except ValueError:
        return value
    return str(math.ceil(f)) if f != int(f) else str(int(f))


_MEMORY_SUFFIX_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([kKmMgGtTpP][iI]?[bB]?)?$")


def _normalize_memory(value: str) -> str:
    """Apple's `container run --memory` requires UPPERCASE K/M/G/T/P.

    Lowercase suffixes ("512m", "2g") that podman/docker accept are
    rejected. Uppercase the suffix in place; pass through unchanged if
    the value doesn't match the expected `<n><suffix>` shape so any
    operator-supplied novelty (e.g. raw byte counts) still reaches Apple
    for its own error reporting rather than being silently mangled.
    """
    m = _MEMORY_SUFFIX_RE.match(value.strip())
    if not m:
        return value
    number, suffix = m.group(1), (m.group(2) or "")
    return f"{number}{suffix.upper()}"


class AppleContainerBackend:
    """Backend using Apple's `container` CLI with a hardened supervisor."""

    # --- helpers --------------------------------------------------------------

    def _state_dir(self, name: str) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/apple-container")) / name

    def logs_dir(self, name: str) -> Path:
        """Per-cage logs dir on the host, bind-mounted into the microVM.

        The supervisor writes proxy.log + capture.jsonl + dnsmasq.log to
        /var/log/agentcage/ inside the microVM; we mount this host path
        there so `agentcage cage audit` and `cage har` can read those
        files from the host without having to exec into the microVM.

        Created on demand (start), preserved on stop/restart, removed by
        destroy_resources alongside the rest of the per-cage state.
        """
        return self._state_dir(name) / "logs"

    # --- Backend protocol -----------------------------------------------------

    def check_prerequisites(self, config: Config) -> list[str]:  # noqa: ARG002
        return ac_prereq.check_prerequisites()

    def build_artifacts(
        self, config: Config, deploy_name: str, *, quiet: bool = False
    ) -> None:
        """Build the per-cage wrapper image.

        For the apple-container backend, the only artifact we produce is the
        wrapped user image (user's image + supervisor). The user's cage image
        itself must already be pullable / built — we don't build it here.
        """
        user_image = config.container.image
        if not user_image:
            raise ValueError("cage has no container.image set")

        # If the cage came from a scaffold (cage.yaml has `scaffold:`),
        # build any scaffold-declared images via Apple `container build`
        # FIRST. The wrapper's `FROM <user_image>` references one of these
        # tags, so it must exist before wrapper build kicks off. This
        # replaces the host-podman path in `run.py`'s `run_scaffold_setup`
        # which does not work on macOS (no host podman).
        scaffold_name = getattr(config, "scaffold", "") or ""
        if scaffold_name:
            ac_scaffold.build_scaffold_images(scaffold_name, quiet=quiet)

        # Pull the user image (no-op if it was just built by the scaffold
        # step above, or if it's already local).
        if not quiet:
            click.echo(f"Ensuring user image is available: {user_image}")
        pull_result = ac_cli.run(
            ["image", "pull", user_image],
            check=False,
            capture_output=False,
        )
        if pull_result.returncode != 0 and not ac_cli.image_inspect(user_image):
            raise RuntimeError(
                f"failed to pull user image {user_image!r} and it is not built locally"
            )

        # Resolve the cage's CMD. Precedence: cage.yaml `container.command:`
        # wins (it's the cage author's explicit intent and is portable across
        # backends), and we fall back to the user image's OCI CMD only when
        # the cage hasn't set one. Without this precedence the apple-container
        # backend silently ignores cage.yaml `command:` and execs the base
        # image's CMD instead (e.g. ubuntu → `/bin/bash`, which exits
        # immediately under `run -d` with no TTY).
        if config.container.command:
            user_cmd = list(config.container.command)
        else:
            try:
                user_cmd = ac_wrapper._user_cmd(user_image)
            except ValueError as e:
                raise RuntimeError(
                    f"cannot determine cage entrypoint: {e}; "
                    "set CMD in your Containerfile or use a scaffold that provides one"
                ) from e

        if not quiet:
            click.echo(f"Building apple-container wrapper for {deploy_name}...")
        # Collect the cage's domain allowlist for the mitmproxy addon.
        # config.domains and .allow are dataclass fields with safe defaults,
        # so no defensive getattr is needed. An empty allowlist means
        # "block all egress" (safer default than "allow all").
        allowlist = list(config.domains.allow or [])
        # Secret-injection rules — only the metadata (env name, placeholder,
        # inject_to allow-list of domains) is baked into the image. The
        # actual secret VALUES are env-passed at `container run` time
        # (see `start()` below) so the build context — which ends up in
        # the image layer — stays free of secrets.
        secret_rules = [
            {
                "env": r.env,
                "placeholder": r.placeholder,
                "inject_to": list(r.inject_to or []),
            }
            for r in (config.secret_injection or [])
        ]
        ac_wrapper.build_wrapper(
            deploy_name, user_image,
            user_cmd=user_cmd,
            allowlist=allowlist,
            secret_injection_rules=secret_rules,
        )
        if not quiet:
            click.echo(f"Built {ac_wrapper.wrapped_image_name(deploy_name)}")

    def generate_units(
        self,
        config: Config,
        config_host_path: str,  # noqa: ARG002
        patches_host_dir: str,  # noqa: ARG002
        deploy_name: str,
        used_octets: set[int] | None = None,  # noqa: ARG002
        network_octet: int | None = None,  # noqa: ARG002
    ) -> dict[str, str]:
        """Generate a cage metadata JSON used by `start` to construct argv.

        ``used_octets`` and ``network_octet`` are accepted to match the
        Backend protocol but ignored. Apple `container` networks are
        per-cage with auto-allocated subnets — there is no shared 10.89.X
        pool to coordinate against, and the cage's effective network is
        Apple's default vmnet (no custom network created by this backend
        in v1; egress is locked to localhost via iptables in the
        supervisor).
        """
        # Resource resolution precedence: cage.yaml's `container.cpus` /
        # `container.memory` (the per-cage cap the user actually wrote)
        # wins over `vm.vcpus` / `vm.mem_mb` (which exist primarily for
        # the Lima backend's outer VM but used to be the only thing this
        # backend respected — silently dropping `container.cpus/memory`
        # was a real footgun on Mac, where users edit cage.yaml not a
        # separate vm section). Empty / unset on both → no --cpus or
        # --memory flag, letting Apple's defaults apply.
        cpus = config.container.cpus or (
            str(config.vm.vcpus) if getattr(config.vm, "vcpus", 0) else ""
        )
        memory = config.container.memory or (
            f"{config.vm.mem_mb}m" if getattr(config.vm, "mem_mb", 0) else ""
        )
        # Persist the secret-injection rule list so `start()` knows which
        # env vars to forward into the microVM at `container run` time.
        # Only the env names are stored — the actual secret values come
        # from the host environment (or, in future, a Keychain lookup).
        secret_envs = [r.env for r in (config.secret_injection or [])]
        unit_json = json.dumps(
            {
                "name": deploy_name,
                "user_image": config.container.image,
                "cpus": cpus,
                "memory": memory,
                "lifecycle": config.lifecycle,
                "secret_envs": secret_envs,
            },
            indent=2,
            sort_keys=True,
        )
        return {f"{deploy_name}.json": unit_json}

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/apple-container"))

    def install_units(self, units: dict[str, str], *, quiet: bool = False) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        for filename, content in units.items():
            (dest / filename).write_text(content)
        if not quiet:
            click.echo(f"Installed apple-container unit metadata to {dest}/")

    def start(self, name: str, *, quiet: bool = False) -> None:
        """Run the wrapped image as a long-lived Apple container."""
        # Read the unit metadata to recover cage config.
        unit_path = self.unit_dir() / f"{name}.json"
        if not unit_path.exists():
            raise RuntimeError(
                f"apple-container unit metadata missing at {unit_path}; "
                f"run `agentcage cage create {name}` first"
            )
        meta = json.loads(unit_path.read_text())

        image = ac_wrapper.wrapped_image_name(name)
        if not ac_cli.image_inspect(image):
            raise RuntimeError(
                f"wrapped image {image!r} not found — was build_artifacts() called?"
            )

        # If a container with this name already exists, stop+delete it first
        # (start should be idempotent like the other backends).
        existing = ac_cli.inspect(name)
        if existing is not None:
            ac_cli.run(["stop", name], check=False)
            ac_cli.run(["delete", "-f", name], check=False)

        # Per-cage logs dir on the host: bind-mounted into the microVM
        # at /var/log/agentcage so `cage audit` / `cage har` can read
        # proxy.log + capture.jsonl from the host without exec'ing in.
        # Create as 0o755 owned by the current user; the supervisor's
        # `chown acproxy:acproxy /var/log/agentcage` inside the cage
        # adjusts ownership to the per-component uids — Apple's bind
        # mount transparently maps host uid ↔ guest uid.
        logs_dir = self.logs_dir(name)
        logs_dir.mkdir(parents=True, exist_ok=True)
        # virtiofs locks ownership inside the cage to the host file's
        # owner (currently the user running agentcage). uid 200
        # (mitmproxy) and uid 201 (dnsmasq) in the guest can only write
        # to this dir if the host-side permissions allow them — so set
        # the dir 1777 (world-writable + sticky bit). Sticky means each
        # file is owned (host-side) by `m1`, with all in-cage writes
        # showing as root in the guest because of virtiofs uid mapping;
        # that's fine — the supervisor's own chown attempts are now
        # best-effort and tolerate EPERM.
        os.chmod(logs_dir, 0o1777)

        # CAP_SYS_ADMIN: supervisor needs it to remount /proc with hidepid=2
        # and to mount the proxy's private tmpfs. CAP_NET_ADMIN: supervisor
        # needs it to apply the iptables egress lockdown. Both are dropped
        # by capsh before the cage workload starts.
        argv = [
            "run", "-d", "--name", name,
            "--cap-add", "CAP_SYS_ADMIN",
            "--cap-add", "CAP_NET_ADMIN",
            "--volume", f"{logs_dir}:/var/log/agentcage",
        ]
        # Apple's `container run --cpus / --memory` has stricter input
        # acceptance than podman: --cpus requires an integer (fractional
        # like "0.5" or "1.5" → "Help: --cpus <cpus> ..." rejection), and
        # --memory requires an UPPERCASE suffix (`512m` → rejected,
        # `512M` accepted). agentcage config historically uses podman's
        # looser forms, so normalize on the way out: ceil fractional cpus
        # to the next integer (give users at least the cap they asked
        # for) and uppercase the memory suffix.
        # Backward compat for unit JSON: 0.20.5 and earlier used integer
        # `cpus` + integer `mem_mb` (mb-only); accept both so cages
        # created before this change keep starting after upgrade.
        cpus_raw = meta.get("cpus")
        if cpus_raw not in (None, "", 0):
            argv += ["--cpus", _normalize_cpus(str(cpus_raw))]
        memory_raw = meta.get("memory")
        if memory_raw:
            argv += ["--memory", _normalize_memory(str(memory_raw))]
        elif meta.get("mem_mb"):  # pre-0.20.6 unit JSON
            argv += ["--memory", f"{meta['mem_mb']}M"]

        # Secret-injection env-passing. For each env named in the cage's
        # `secret_injection:` rules, look it up in the current host
        # environment and forward via `-e NAME=value` to `container run`.
        # The mitmproxy addon inside the cage reads these at startup and
        # uses them to substitute `{{NAME}}` placeholders in outbound
        # requests destined for the rule's inject_to allow-list.
        # Missing env vars are skipped with a stderr warning rather than
        # failing — the cage may not need every secret on every host.
        for env_name in meta.get("secret_envs") or []:
            value = os.environ.get(env_name)
            if value is None:
                click.echo(
                    f"warning: secret_injection env {env_name!r} "
                    f"not set in host environment; placeholder will "
                    f"NOT be substituted in cage requests",
                    err=True,
                )
                continue
            argv += ["-e", f"{env_name}={value}"]

        argv.append(image)

        result = ac_cli.run(argv, check=False, capture_output=False)
        if result.returncode != 0:
            raise RuntimeError(f"`container run` failed (exit {result.returncode})")
        if not quiet:
            click.echo(f"Started {name} (apple-container)")

    def stop(self, name: str) -> None:
        ac_cli.run(["stop", name], check=False)

    def restart(self, name: str) -> None:
        self.stop(name)
        self.start(name)

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:  # noqa: ARG002
        removed: list[str] = []
        # Container
        if ac_cli.inspect(name) is not None:
            ac_cli.run(["stop", name], check=False)
            r = ac_cli.run(["delete", "-f", name], check=False)
            if r.returncode == 0:
                removed.append(f"container:{name}")
        # Image
        image = ac_wrapper.wrapped_image_name(name)
        if ac_cli.image_inspect(image) is not None:
            r = ac_cli.run(["image", "delete", image], check=False)
            if r.returncode == 0:
                removed.append(f"image:{image}")
        # State dir
        unit_path = self.unit_dir() / f"{name}.json"
        if unit_path.exists():
            unit_path.unlink()
            removed.append(f"unit:{unit_path}")
        state = self._state_dir(name)
        if state.exists():
            shutil.rmtree(state)
            removed.append(f"state:{state}")
        return removed

    def is_running(self, name: str, service: str) -> bool:  # noqa: ARG002
        data = ac_cli.inspect(name)
        if not data:
            return False
        # Apple's inspect returns {"status": "running" | "stopped" | ...}.
        status = data.get("status") or data.get("Status")
        return status == "running"

    def service_names(self, name: str) -> list[str]:  # noqa: ARG002
        # Three components run inside one Apple microVM per cage:
        # the cage workload, mitmproxy (the egress filter), and dnsmasq
        # (the resolver). cli.py uses these names for status display and
        # — once `exec`/`logs`/`audit` are lifted onto the Backend
        # protocol — for targeted component access.
        return ["cage", "proxy", "dns"]

    # --- Backend protocol: process inspection / streaming --------------------

    def exec_argv(
        self,
        name: str,
        service: str,
        cmd: list[str],
        *,
        interactive: bool = False,
    ) -> list[str]:
        """`container exec [-it] <name> <cmd>`.

        proxy / dns run in-process inside the cage microVM (supervised),
        not as separate Apple containers, so they aren't addressable by
        targeted exec. Reject those service names with a clear message.
        """
        from agentcage.backend import BackendUnsupported
        if service != "cage":
            raise BackendUnsupported(
                f"'cage exec --service {service}' is not yet supported on "
                f"the apple-container backend; only --service cage is "
                f"addressable (proxy and dnsmasq run inside the same microVM)"
            )
        binary = ac_cli.container_binary()
        if binary is None:
            raise BackendUnsupported(
                "Apple `container` CLI not found; install from "
                "https://github.com/apple/container/releases"
            )
        flags = ["-it"] if interactive else []
        return [binary, "exec", *flags, name, *cmd]

    def logs_argv(
        self,
        name: str,
        services: list[str],  # noqa: ARG002 — single-microVM model
        *,
        follow: bool = False,
        lines: int = 0,
        min_level: str | None = None,  # noqa: ARG002 — Apple doesn't filter
    ) -> list[str]:
        """`container logs [-f] <name>` — combined supervisor stdout/stderr.

        The supervisor multiplexes the cage workload + proxy + dnsmasq into
        one stream; we can't filter per-service the way container/vm do
        with their per-unit journal cursors. ``services`` is accepted for
        protocol parity but ignored. ``lines`` is similarly ignored — Apple
        ``container logs`` doesn't accept ``-n``; the CLI can post-trim if
        it cares.
        """
        from agentcage.backend import BackendUnsupported
        binary = ac_cli.container_binary()
        if binary is None:
            raise BackendUnsupported(
                "Apple `container` CLI not found; install from "
                "https://github.com/apple/container/releases"
            )
        argv = [binary, "logs"]
        if follow:
            argv.append("-f")
        argv.append(name)
        return argv

    def audit_argv(
        self,
        name: str,
        *,
        since: str | None = None,  # noqa: ARG002 — no time index host-side
        follow: bool = False,
    ) -> list[str]:
        """`tail` the host-side audit.jsonl bind-mounted from the microVM.

        The mitmproxy addon writes one JSON line per request decision into
        /var/log/agentcage/audit.jsonl, which `start()` bind-mounts to
        `<state>/<cage>/logs/audit.jsonl` on the host. `since` is not yet
        respected (the host JSONL has no journalctl-style time index);
        the CLI's AuditFilter still applies time filtering post-parse.
        """
        path = self.logs_dir(name) / "audit.jsonl"
        if follow:
            return ["tail", "-n", "0", "-F", str(path)]
        return ["tail", "-n", "10000", str(path)]
