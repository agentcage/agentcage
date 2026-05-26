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

    def secrets_dir(self, name: str) -> Path:
        """Per-cage secrets dir on the host, bind-mounted into the microVM
        read-only at /run/agentcage/secrets.

        Each ``secret_injection`` rule's resolved value gets written to
        ``<secrets_dir>/<env-name>`` (mode 0600, owned by the host user)
        at ``start()`` time. The cage's ``container run`` argv carries
        only the PLACEHOLDER (``-e API_KEY={{API_KEY}}``) — the raw value
        is never on the command line (visible to host `ps`) nor in
        ``container inspect`` output. Inside the cage, virtiofs preserves
        the host's 0600 perms so only root in the microVM can read; the
        supervisor (PID 1, root) re-stages each file into
        /home/acproxy/secrets/<env-name> (mode 0400, owned by acproxy
        uid 200) so mitmproxy can read them but the cage workload (uid
        1000) cannot.

        Created on demand (start), removed by destroy_resources alongside
        the rest of the per-cage state.
        """
        return self._state_dir(name) / "secrets"

    @staticmethod
    def _user_volume_argv(raw_entries: list[str]) -> list[str]:
        """Expand and validate user-supplied ``container.volumes`` entries.

        Returns a list of ``host:cage[:mode]`` strings ready to splice
        into ``container run --volume <entry>``. Mirrors the quadlet
        backend's safety rules so behavior is identical across backends:

        - Expand ``~`` and ``$VAR`` in the host portion.
        - Skip (with a warning) entries whose host path still contains an
          unresolved ``$``.
        - Reject (with a warning + skip) entries whose host path resolves
          outside the operator's home directory — prevents bind-ing
          ``/etc``, ``/var``, ``/root``, etc. by accident.
        - Reject (warning + skip) entries with no ``:`` separator (no
          target path).
        """
        out: list[str] = []
        home = os.path.realpath(os.path.expanduser("~"))
        for v in raw_entries:
            if ":" not in v:
                click.echo(
                    f"warning: skipping volume {v!r} on apple-container "
                    "(missing ':<cage-path>')",
                    err=True,
                )
                continue
            parts = v.split(":", 1)
            host_part = os.path.expandvars(os.path.expanduser(parts[0]))
            if "$" in host_part:
                click.echo(
                    f"warning: skipping volume {host_part!r} on apple-container "
                    "(unresolved variable in host path)",
                    err=True,
                )
                continue
            real = os.path.realpath(host_part)
            if not (real == home or real.startswith(home + os.sep)):
                click.echo(
                    f"warning: skipping volume {host_part!r} on apple-container "
                    f"(host path resolves outside {home!r})",
                    err=True,
                )
                continue
            out.append(f"{real}:{parts[1]}")
        return out

    def _launchd_plist_path(self, name: str) -> Path:
        """Host path of the per-cage launchd plist.

        We install into the user's LaunchAgents dir (no sudo needed; runs
        as the user at every login). The plist label and filename follow
        reverse-DNS form `io.agentcage.<cage>` so they don't collide with
        non-agentcage daemons in launchctl listings.
        """
        return Path(
            os.path.expanduser(f"~/Library/LaunchAgents/io.agentcage.{name}.plist")
        )

    def _install_launchd_plist(self, name: str) -> None:
        """Write + load the per-cage launchd plist.

        The plist re-execs `container start <cage>` at user login. Logs
        go under the per-cage state dir so `cage logs` already finds
        them. Idempotent: an existing plist is overwritten and reloaded.
        """
        binary = ac_cli.container_binary()
        if binary is None:
            click.echo(
                "warning: cannot install launchd autostart — Apple "
                "`container` CLI not found",
                err=True,
            )
            return
        plist = self._launchd_plist_path(name)
        plist.parent.mkdir(parents=True, exist_ok=True)
        state_dir = self._state_dir(name)
        state_dir.mkdir(parents=True, exist_ok=True)
        plist_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.agentcage.{name}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>start</string>
        <string>{name}</string>
    </array>
    <key>StandardOutPath</key>
    <string>{state_dir}/launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{state_dir}/launchd.err.log</string>
</dict>
</plist>
"""
        plist.write_text(plist_xml)
        # bootstrap + load. `launchctl load` exits 0 even if already
        # loaded; if it changes, run unload first so reload picks up
        # the new ProgramArguments.
        import subprocess as _sp
        _sp.run(["launchctl", "unload", str(plist)],
                check=False, capture_output=True)
        result = _sp.run(["launchctl", "load", "-w", str(plist)],
                         check=False, capture_output=True, text=True)
        if result.returncode != 0:
            click.echo(
                f"warning: launchctl load failed for {plist}: "
                f"{result.stderr.strip()}",
                err=True,
            )

    def _uninstall_launchd_plist(self, name: str) -> None:
        """Unload + remove the per-cage launchd plist. No-op if absent."""
        plist = self._launchd_plist_path(name)
        if not plist.exists():
            return
        import subprocess as _sp
        _sp.run(["launchctl", "unload", str(plist)],
                check=False, capture_output=True)
        plist.unlink(missing_ok=True)

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
        # inject_to allow-list of domains, transform name + its config) is
        # baked into the image. The actual secret VALUES are env-passed at
        # `container run` time (see `start()` below) so the build context —
        # which ends up in the image layer — stays free of secrets. The
        # ``transform`` field tells the in-cage addon to derive a value
        # (e.g. mint a Google OAuth bearer from a service-account JWT)
        # instead of substituting the raw env value verbatim.
        secret_rules = [
            {
                "env": r.env,
                "placeholder": r.placeholder,
                "inject_to": list(r.inject_to or []),
                "transform": r.transform or "",
                "transform_config": dict(r.transform_config or {}),
            }
            for r in (config.secret_injection or [])
        ]
        # Protocol relays (IMAP, SMTP) — same metadata-only contract as
        # secret_injection: the credential VALUES never go into the
        # image layer; only the structural config does. Credential env
        # names are resolved at `start()` and written to the per-cage
        # secrets bind mount alongside secret_injection values, so the
        # in-cage addon can read them at relay-start time.
        relay_rules = [
            {
                "name": r.name,
                "type": r.type,
                "listen": r.listen,
                "upstream": {
                    "host": r.upstream.host,
                    "port": r.upstream.port,
                    "tls": r.upstream.tls,
                },
                "auth": {
                    "type": r.auth.type,
                    "user_source": r.auth.user_source,
                    "password_source": r.auth.password_source,
                },
                "policy": {
                    "readonly": r.policy.readonly,
                    "folder_allowlist": list(r.policy.folder_allowlist or []),
                    "sender_allowlist": list(r.policy.sender_allowlist or []),
                    "recipient_allowlist": {
                        "addresses": list(
                            r.policy.recipient_allowlist.addresses or []
                        ),
                        "domains": list(
                            r.policy.recipient_allowlist.domains or []
                        ),
                    },
                    "max_message_bytes": r.policy.max_message_bytes,
                    "max_recipients": r.policy.max_recipients,
                    "conn_rate_limit": r.policy.conn_rate_limit,
                    "send_rate_limit": r.policy.send_rate_limit,
                    "idle_timeout_seconds": r.policy.idle_timeout_seconds,
                    "bypass_inspectors_for_allowlisted": list(
                        r.policy.bypass_inspectors_for_allowlisted or []
                    ),
                },
            }
            for r in (config.protocol_relays or [])
        ]
        # Capture config — when ``capture.enable_har: true`` is set in
        # cage.yaml, the in-cage mitmproxy addon stages request+response
        # body snapshots (subject to ``max_body_size`` + binary-skip) and
        # writes them as ``{inbound, outbound}``-keyed entries to
        # capture.jsonl. ``cage har`` reads that file on the host (already
        # bind-mounted out of the microVM since 0.20.6) and renders HAR
        # 1.2 with non-zero ``content.size`` / ``request.postData.text``.
        # Disabled / empty config preserves the legacy headers-only
        # capture path (no body bytes ever written).
        cap = getattr(config, "capture", None)
        capture_dict: dict = {}
        if cap is not None:
            capture_dict = {
                "enable_har": bool(cap.enable_har),
                "max_body_size": int(cap.max_body_size),
                "min_action": str(cap.min_action or "all"),
                "domains": list(cap.domains or []),
                "exclude_domains": list(cap.exclude_domains or []),
            }
        # Inspector chain — passed through verbatim. The cage.yaml
        # ``inspectors:`` list is the same shape the container backend
        # addon reads, so we keep the dicts opaque here and let the
        # in-cage addon dispatch through the bundled ``inspectors``
        # registry. An empty/missing list means allowlist-only mode,
        # which is the legacy apple-container behavior.
        inspectors = [dict(e) for e in (config.inspectors or [])]
        ac_wrapper.build_wrapper(
            deploy_name, user_image,
            user_cmd=user_cmd,
            allowlist=allowlist,
            secret_injection_rules=secret_rules,
            protocol_relays=relay_rules,
            capture_config=capture_dict,
            inspectors=inspectors,
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
        # Persist the secret-injection env→placeholder map so `start()` knows
        # which env vars to resolve from the host environment AND which
        # placeholder string to pass to the cage in their place. The
        # placeholder (not the real value) ends up in the cage's env via
        # `-e ENV={{ENV}}` so cage code that reads `os.environ["KEY"]`
        # gets the placeholder; the real value lives only in the
        # bind-mounted secrets file and the mitmproxy addon substitutes
        # it on the wire. ``secret_envs`` kept (list of env names) for
        # backward compat with cages last started on 0.21.0 or earlier.
        secret_envs = [r.env for r in (config.secret_injection or [])]
        secret_env_placeholders = {
            r.env: r.placeholder for r in (config.secret_injection or [])
        }
        # Protocol-relay credential env names — must reach the mitmproxy
        # process inside the cage (where the relay's _resolve_credential
        # reads them) but must NOT reach the cage workload's env. We
        # write each value into the same per-cage secrets bind mount
        # secret_injection uses; the addon reads it at relay-start time
        # and sets os.environ[<env>] before constructing the relay.
        # Critically, these env names do NOT get a `-e` flag on
        # `container run` — that's how we keep them off the cage
        # workload's environ block.
        relay_secret_envs: list[str] = []
        for relay in (config.protocol_relays or []):
            for src in (relay.auth.user_source, relay.auth.password_source):
                scheme, _, var = (src or "").partition(":")
                if scheme and var and var not in relay_secret_envs:
                    relay_secret_envs.append(var)
        unit_json = json.dumps(
            {
                "name": deploy_name,
                "user_image": config.container.image,
                "cpus": cpus,
                "memory": memory,
                "lifecycle": config.lifecycle,
                "secret_envs": secret_envs,
                "secret_env_placeholders": secret_env_placeholders,
                "relay_secret_envs": relay_secret_envs,
                "autostart": bool(getattr(config, "apple_container_autostart", False)),
                # User-defined host bind mounts. Apple's `container run`
                # accepts `--volume host:cage[:mode]` just like podman, so
                # we pass each through verbatim at start() time. Persisted
                # in the unit JSON (rather than re-read from cage.yaml at
                # start) so a `cage update` controls the surface, matching
                # how the rest of the runtime config flows.
                "volumes": list(config.container.volumes),
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
        # User-defined bind mounts. Each entry is `host:cage[:mode]`; we
        # expand ~ / $VAR in the host path, validate it lives under $HOME
        # (same containment rule the container backend's quadlet template
        # enforces — prevents accidental /etc, /var, /root bind-ins), and
        # pass through verbatim. Unresolved $VAR yields a warning + skip
        # to match quadlets.py's behavior for parity.
        for vol_entry in self._user_volume_argv(meta.get("volumes") or []):
            argv += ["--volume", vol_entry]
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

        # Secret-injection. For each env named in the cage's
        # `secret_injection:` rules:
        #   - Resolve the real value from <deployment_dir>/pending_secrets.json,
        #     written by `agentcage cage create -s KEY=VAL` and
        #     `agentcage run -s KEY=VAL`. Values are NEVER read from the
        #     host shell's environment — anything not passed via
        #     --set-secret is treated as missing and a warning is emitted.
        #   - Write the real value to <secrets_dir>/<env-name> on the
        #     host (mode 0600). The dir gets bind-mounted at
        #     /run/agentcage/secrets:ro in the cage; supervisor stage 35
        #     re-stages each file as /home/acproxy/secrets/<env-name>
        #     (chown 200:200, mode 0400) for mitmproxy.
        #   - Pass `-e <env>={{PLACEHOLDER}}` (the placeholder, NOT the
        #     real value) to `container run`. The cage's env carries the
        #     placeholder so cage code that reads `os.environ["API_KEY"]`
        #     gets `{{API_KEY}}` and the proxy substitutes the real
        #     value on the wire. This means the cleartext value is NOT
        #     visible via host `ps -ef`, NOT in `container inspect`,
        #     and NOT in the cage workload's `/proc/self/environ`.
        placeholders = meta.get("secret_env_placeholders") or {}
        secret_envs = meta.get("secret_envs") or list(placeholders.keys())
        # Protocol-relay credential env names. Same secrets bind mount as
        # secret_injection — but NO `-e` flag is added to `container run`,
        # so the cage workload's environ block never carries the relay
        # password. The in-cage mitmproxy addon reads each file in its
        # `running()` hook and `os.environ[var] = value` before calling
        # the relay's constructor.
        relay_secret_envs = meta.get("relay_secret_envs") or []
        all_secret_envs = list(secret_envs) + [
            v for v in relay_secret_envs if v not in secret_envs
        ]
        if all_secret_envs:
            # Load --set-secret values staged by run.py / cli.py at the
            # per-cage 0600 plaintext file. No host podman / Keychain on
            # apple-container yet (#120); plaintext-at-0600 is the
            # persistence mechanism. Missing file = no secrets provided.
            from agentcage import state as _state
            provided: dict[str, str] = {}
            pending_path = _state.deployment_dir(name) / "pending_secrets.json"
            if pending_path.is_file():
                try:
                    provided = {k: v for k, v in json.loads(pending_path.read_text())}
                except Exception:
                    click.echo(
                        f"warning: failed to parse {pending_path}; treating "
                        f"all secret_injection rules as unprovided",
                        err=True,
                    )

            secrets_dir = self.secrets_dir(name)
            secrets_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(secrets_dir, 0o700)
            # Drop any stale secret files from a prior start so removed
            # rules don't linger in the bind mount.
            for stale in secrets_dir.iterdir():
                stale.unlink()
            relay_only = set(relay_secret_envs) - set(secret_envs)
            for env_name in all_secret_envs:
                value = provided.get(env_name)
                if value is None:
                    if env_name in relay_only:
                        click.echo(
                            f"warning: protocol_relays env {env_name!r} "
                            f"not provided via --set-secret; the relay "
                            f"will fail to start with empty credentials",
                            err=True,
                        )
                    else:
                        click.echo(
                            f"warning: secret_injection env {env_name!r} "
                            f"not provided via --set-secret; placeholder "
                            f"will NOT be substituted in cage requests",
                            err=True,
                        )
                    continue
                if env_name in relay_only:
                    # Relay credential — file goes in the bind mount so
                    # the addon can read it, but no `-e` so the cage
                    # workload never sees the credential name in its env.
                    secret_file = secrets_dir / env_name
                    secret_file.write_text(value)
                    os.chmod(secret_file, 0o600)
                    continue
                placeholder = placeholders.get(env_name)
                if not placeholder:
                    # Unit JSON predates the placeholder map (pre-0.21.1).
                    # Refuse to fall back to cleartext-env delivery — the
                    # whole point of placeholders is to keep the raw value
                    # off `container run`'s argv and out of the cage's
                    # /proc/self/environ. Operator must `cage update` to
                    # regenerate the unit JSON.
                    click.echo(
                        f"warning: secret_injection env {env_name!r} has "
                        f"no placeholder in unit JSON (pre-0.21.1 cage); "
                        f"run `agentcage cage update` to regenerate. "
                        f"Skipping injection.",
                        err=True,
                    )
                    continue
                secret_file = secrets_dir / env_name
                secret_file.write_text(value)
                os.chmod(secret_file, 0o600)
                argv += ["-e", f"{env_name}={placeholder}"]
            # Mount the per-cage secrets dir read-only into the microVM.
            # Only mount if any files were written (avoid mounting an empty
            # dir when every secret env was unprovided).
            if any(secrets_dir.iterdir()):
                argv += ["--volume", f"{secrets_dir}:/run/agentcage/secrets:ro"]

        argv.append(image)

        # Clear any stale readiness marker from a prior run BEFORE we kick
        # `container run -d`. The supervisor will touch this file again as
        # its final action of stage 90; we poll for it below.
        ready_marker = self.logs_dir(name) / "ready"
        try:
            ready_marker.unlink()
        except FileNotFoundError:
            pass

        result = ac_cli.run(argv, check=False, capture_output=False)
        if result.returncode != 0:
            raise RuntimeError(f"`container run` failed (exit {result.returncode})")

        # Wait for the supervisor to finish booting before returning. Apple's
        # `container run -d` returns when the microVM is up — NOT when the
        # user CMD (supervisor.sh) has progressed past stage 90. Without
        # this poll, the next operator action (`cage exec`, `agentcage run`'s
        # integrated claude exec, etc.) races the supervisor and may hit the
        # cage before dnsmasq binds, mitmproxy listens, iptables NAT applies,
        # or secrets are re-staged into /home/acproxy/secrets/. The supervisor
        # `touch`es /var/log/agentcage/ready right before its `exec capsh`,
        # which lands on the host-side virtiofs bind at logs_dir(name)/ready.
        # See issue #168.
        self._wait_supervisor_ready(name, ready_marker)

        # Install (or refresh) the launchd plist if the cage opted in to
        # autostart. Read from the unit metadata so plists stick across
        # reloads — the user-visible cage.yaml may have been edited since
        # but `cage create / update` is what propagates flags into the
        # unit JSON, so we honor whatever was set at the last create/update.
        if meta.get("autostart"):
            self._install_launchd_plist(name)
        if not quiet:
            click.echo(f"Started {name} (apple-container)")

    # Polling interval and total timeout for the supervisor readiness wait.
    # Module-level so tests can monkeypatch them to ~0 without subclassing.
    _READY_POLL_INTERVAL_S = 0.1
    _READY_TIMEOUT_S = 30.0

    def _wait_supervisor_ready(self, name: str, marker: Path) -> None:
        """Block until ``marker`` exists or the cage exits.

        Raises ``RuntimeError`` if the cage exits before signaling ready
        (so the operator sees a real error, not a successful return that
        then 401s on the first request).
        """
        import time as _time

        deadline = _time.monotonic() + self._READY_TIMEOUT_S
        while _time.monotonic() < deadline:
            if marker.exists():
                return
            # If the cage exited (supervisor `die`d at some stage, or the
            # workload itself crashed before we got a chance to wait), we'd
            # otherwise loop until timeout. Detect it and surface the error.
            data = ac_cli.inspect(name)
            status = (data or {}).get("status") or (data or {}).get("Status")
            if data is not None and status not in ("running", None):
                raise RuntimeError(
                    f"cage {name!r} exited before becoming ready "
                    f"(status={status!r}); see `container logs {name}`"
                )
            _time.sleep(self._READY_POLL_INTERVAL_S)
        raise RuntimeError(
            f"cage {name!r} did not signal ready within "
            f"{self._READY_TIMEOUT_S:.0f}s; see `container logs {name}` "
            f"for the supervisor's last stage"
        )

    def stop(self, name: str) -> None:
        ac_cli.run(["stop", name], check=False)

    def restart(self, name: str) -> None:
        self.stop(name)
        self.start(name)

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:  # noqa: ARG002
        removed: list[str] = []
        # launchd plist (best-effort; only present when autostart was enabled).
        plist = self._launchd_plist_path(name)
        if plist.exists():
            self._uninstall_launchd_plist(name)
            removed.append(f"launchd:{plist}")
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

    def has_resources(self, name: str) -> bool:
        if (self.unit_dir() / f"{name}.json").exists():
            return True
        if self._state_dir(name).exists():
            return True
        return False

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
        as_root: bool = False,
    ) -> list[str]:
        """`container exec [-it] -u 0 <cage> -- capsh ... -- -c "exec <cmd>"`.

        proxy / dns run in-process inside the cage microVM (supervised),
        not as separate Apple containers. Reject those service names.

        Privilege model — `as_root=False` (default) execs the user's
        command via capsh with the same primitive the supervisor uses
        at stage 90:

            capsh --no-new-privs --drop=all --user=1000 --shell=/bin/sh
                  -- -c "exec <user-cmd>"

        That gives the exec session:

          1. uid 1000 — same as the cage workload
          2. CapEff/Prm/Inh/Bnd all empty — drop=all clears CapBnd
             BEFORE the user switch (uid 0→1000 clears the rest)
          3. NoNewPrivs=1 — the kernel refuses to grant caps via
             setuid binaries, even though the cage image still ships
             /usr/bin/su, /usr/bin/mount, etc. as 4755-mode
          4. inherits the proxy/dns/secrets isolation the workload has

        Without (2)+(3), an earlier-fix `-u 1000` alone left CapBnd
        non-empty (a82435fb = cap_net_admin + cap_sys_admin + the
        default container set) AND NoNewPrivs=0, so a setuid-root
        binary inside the cage could re-acquire caps and `iptables -F`
        the egress filter. capsh closes the door.

        Apple's `container` CLI doesn't support `--security-opt
        no-new-privileges`, so the only way to set NoNewPrivs on the
        exec session is via capsh/prctl from inside. capsh ships as
        part of libcap2-bin in the wrapper image (installed at
        Containerfile build for the supervisor's own stage-90 use).

        `as_root=True` bypasses capsh entirely: the operator gets a
        root shell with the container's full cap set. Only for explicit
        debugging.
        """
        from agentcage.backend import BackendUnsupported
        import shlex as _shlex
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
        if as_root:
            # Operator debug — pass through to the image's USER (root
            # on the wrapper). Skips capsh entirely so apt-get install
            # etc. work for the operator.
            return [binary, "exec", *flags, name, *cmd]
        # Secure default — invoke capsh as root so prctl(PR_SET_NO_NEW_PRIVS)
        # is allowed, then capsh drops caps + setuid's to the uid-1000
        # user + execs the user's command via sh -c so shell
        # metacharacters work.
        #
        # capsh's `--user=` resolves by NAME via getpwnam (it does NOT
        # accept a numeric uid — `--user=1000` errors with "User [1000]
        # not known"). The uid-1000 user's name varies by base image
        # (e.g. `ubuntu` on ubuntu:24.04, `node` on node:*, `cage` on
        # bases without a uid-1000 user via the Containerfile.wrapper.j2
        # useradd fallback). Resolve at exec time via a shell `getent`
        # so we don't have to teach the CLI about every base image's
        # user name. Same trick the supervisor uses at stage 90 (PR #140).
        inner = (
            "CAGE_USER=$(getent passwd 1000 | cut -d: -f1) && "
            "exec capsh --no-new-privs --drop=all "
            "--user=\"$CAGE_USER\" --shell=/bin/sh "
            "-- -c " + _shlex.quote("exec " + _shlex.join(cmd))
        )
        return [
            binary, "exec", "-u", "0", *flags, name,
            "/bin/sh", "-c", inner,
        ]

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
