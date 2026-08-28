"""Generate quadlet files from a Config object using Jinja2 templates."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
from importlib.metadata import version as _pkg_version
from pathlib import Path

import click
from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.config import Config


def cage_network_addrs(
    name: str,
    used_octets: set[int] | None = None,
    network_octet: int | None = None,
) -> dict[str, str]:
    """Derive deterministic, unique network addresses for a cage.

    Each cage gets a ``/24`` subnet under ``10.89.x.0`` where *x* is
    derived from the cage name via a hash (range 1–254).  This avoids
    subnet collisions when multiple cages run simultaneously.

    If *used_octets* is provided, the function checks for collisions and
    increments the third octet until a free slot is found.  Raises
    ``RuntimeError`` if all 254 slots are taken.

    If *network_octet* is provided, the addresses are derived directly
    from that octet, bypassing the hash and any collision resolution.
    This is the correct path for updates to an already-deployed cage
    whose podman network is pinned to the previously-allocated subnet —
    re-allocating would produce IPs that fall outside the existing
    ``<name>-net`` subnet and the egress container would refuse to
    start with ``requested static ip not in any subnet on network``.
    *used_octets* is ignored when *network_octet* is set.
    """
    if network_octet is not None:
        prefix = f"10.89.{network_octet}"
        return {
            "subnet": f"{prefix}.0/24",
            "ip_cage": f"{prefix}.2",
            "ip_egress": f"{prefix}.10",
        }
    h = hashlib.md5(name.encode()).hexdigest()
    octet = (int(h[:8], 16) % 254) + 1
    if used_octets is not None:
        attempts = 0
        while octet in used_octets and attempts < 254:
            octet = (octet % 254) + 1
            attempts += 1
        if octet in used_octets:
            raise RuntimeError(
                "All 254 subnet slots are in use — cannot allocate a new cage network"
            )
    prefix = f"10.89.{octet}"
    return {
        "subnet": f"{prefix}.0/24",
        "ip_cage": f"{prefix}.2",
        "ip_egress": f"{prefix}.10",
    }


def collect_used_octets(exclude: str = "") -> set[int]:
    """Return the set of third-octets already used by deployed cages.

    Reads the actual assigned octet from each deployment's metadata
    (persisted at deploy time).  Falls back to the hash-based octet
    for legacy deployments that pre-date metadata tracking.

    The optional *exclude* parameter omits a cage name (useful when
    updating an existing cage that should keep its own slot).
    """
    from agentcage.state import list_deployments, load_deployment_config, load_metadata

    used: set[int] = set()
    for dep_name in list_deployments():
        if dep_name == exclude:
            continue
        try:
            meta = load_metadata(dep_name)
            if "network_octet" in meta:
                used.add(meta["network_octet"])
                continue
            # Fallback for legacy deployments without metadata
            cfg = load_deployment_config(dep_name)
        except Exception:
            continue
        addrs = cage_network_addrs(cfg.name)
        octet = int(addrs["subnet"].split(".")[2])
        used.add(octet)
    return used

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Characters that require quoting in systemd Exec= lines.
_SYSTEMD_NEEDS_QUOTE = re.compile(r'[\s"\\$%]')


def _systemd_exec_join(args: list[str]) -> str:
    """Join a command list into a systemd ``Exec=`` value.

    Arguments containing spaces or special characters are wrapped in
    double-quotes with inner ``"`` and ``\\`` escaped per the systemd
    exec parsing rules.
    """
    parts: list[str] = []
    for arg in args:
        if _SYSTEMD_NEEDS_QUOTE.search(arg):
            escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
            parts.append(f'"{escaped}"')
        else:
            parts.append(arg)
    return " ".join(parts)


def _passthrough_regex(domains: list[str]) -> str:
    """Build a mitmproxy --ignore-hosts regex from a list of domains.

    Each domain becomes ``^(.+\\.)?example\\.com(:\\d+)?$`` so both the bare
    domain and any subdomain match (with optional port).  Multiple domains
    are OR-joined.  mitmproxy matches against ``host:port``, so the port
    suffix is required.
    """
    parts = []
    for domain in domains:
        escaped = re.escape(domain)
        parts.append(f"^(.+\\.)?{escaped}(:\\d+)?$")
    return "|".join(parts)


def _effective_dns_allowlist(config: Config) -> list[str]:
    """Merge passthrough domains into the DNS allowlist.

    Passthrough domains must resolve via upstream DNS (not the sinkhole),
    so they are auto-added to the allowlist when in allowlist mode.
    """
    if config.domains.mode != "allowlist":
        return []
    merged = list(config.domains.allow)
    for d in config.domains.passthrough:
        if d not in merged:
            merged.append(d)
    return merged


def _effective_port_policy(
    config: Config,
) -> tuple[list[int], list[int], list[int]]:
    """Resolve the nested ports config into the three lists rendered
    into the proxy quadlet, preserving operator-supplied order:

    - inspected_tcp = tcp.allow MINUS tcp.passthrough (deduped). Becomes
      one nat:PREROUTING REDIRECT rule per port.
    - passthrough_tcp = tcp.passthrough (deduped). Becomes one
      filter:FORWARD -p tcp ACCEPT per port. Auto-merges into the
      effective allow set if the operator didn't list it in tcp.allow.
    - allow_udp = udp.allow (deduped). Becomes one filter:FORWARD
      -p udp ACCEPT per port. UDP is never inspected.
    """
    passthrough_set = set(config.ports.tcp.passthrough)
    inspected_tcp: list[int] = []
    seen: set[int] = set()
    for p in config.ports.tcp.allow:
        if p in passthrough_set or p in seen:
            continue
        inspected_tcp.append(p)
        seen.add(p)
    passthrough_tcp: list[int] = []
    seen_pt: set[int] = set()
    for p in config.ports.tcp.passthrough:
        if p in seen_pt:
            continue
        passthrough_tcp.append(p)
        seen_pt.add(p)
    allow_udp: list[int] = []
    seen_udp: set[int] = set()
    for p in config.ports.udp.allow:
        if p in seen_udp:
            continue
        allow_udp.append(p)
        seen_udp.add(p)
    return inspected_tcp, passthrough_tcp, allow_udp


def _make_env() -> SandboxedEnvironment:
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["systemd_exec"] = _systemd_exec_join
    return env


def vm_local_config_dir(name: str) -> str:
    """VM-local path where the cage's egress config files live.

    The host's ``~/.config/agentcage/cages/<name>/`` is exposed inside the
    Lima VM as a reverse-sshfs mount that caches file contents aggressively
    — so a host-side rewrite of ``proxy-config.yaml`` or
    ``dns-allowlist.conf`` is invisible to processes running inside the VM
    until the mount itself is reset. We sidestep that by writing a VM-local
    copy of those two files into a parallel directory tree under the user's
    home that is *not* a Lima mount, and bind-mounting the VM-local copy
    into the egress container.

    Returned with the systemd ``%h`` home-directory specifier instead of
    ``~``: systemd-quadlet expands ``%h`` to the user's absolute home before
    podman parses the unit, so ``Volume=%h/...`` works as a bind mount.
    Using ``~`` would NOT work — podman-quadlet treats unprefixed paths as
    named volumes, and the resulting "name" fails podman's
    ``[a-zA-Z0-9_.-]*`` validator. Shell-context callers (e.g. ``mkdir`` /
    ``base64`` in :func:`agentcage.backends.vm.push_config_files`) must
    substitute ``%h`` with the actual ``$HOME`` before invocation; bash
    does not expand systemd specifiers.
    """
    return f"%h/.config/agentcage-vm/cages/{name}"


def vm_local_dns_allowlist_path(name: str) -> str:
    """VM-local path of the dnsmasq allowlist file. See ``vm_local_config_dir``."""
    return f"{vm_local_config_dir(name)}/dns-allowlist.conf"


def vm_local_proxy_config_path(name: str) -> str:
    """VM-local path of the proxy config file. See ``vm_local_config_dir``."""
    return f"{vm_local_config_dir(name)}/proxy-config.yaml"


def vm_local_cage_env_dir(name: str) -> str:
    """VM-local copy of the cage-env dir. See ``vm_local_config_dir``."""
    return f"{vm_local_config_dir(name)}/cage-env"


def vm_local_placeholders_env_path(name: str) -> str:
    """VM-local path of placeholders.env. See ``vm_local_config_dir``."""
    return f"{vm_local_cage_env_dir(name)}/placeholders.env"


# Note: a render_dns_quadlet() helper used to live here for the 3-service
# shape so ``domain add`` / ``domain rm`` could regenerate just the dns
# sidecar's quadlet when its --servers-file shape changed. In the 2-
# service (cage + egress) shape the dnsmasq allowlist is mounted into the
# egress container at /etc/agentcage/dns-allowlist.conf and re-read on
# SIGHUP — the quadlet itself is stable across allowlist edits, so the
# fast path is a uniform ``<runtime> exec <name>-egress kill -HUP $(cat
# /home/acdns/dnsmasq.pid)``. See cli.py:_update_dns_quadlet.


def _split_volume_spec(spec: str) -> tuple[str, str, str]:
    """Split a Docker/Podman-style volume spec into source/target/options.

    agentcage only accepts path-like host bind sources for ``container.volumes``;
    named volumes are carried in ``container.named_volumes``. The parser keeps
    drive-letter edge cases out of scope because Linux/VM paths are POSIX and
    apple-container volume parsing is separate.
    """
    parts = spec.split(":", 2)
    if len(parts) < 2:
        return spec, "", ""
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return parts[0], parts[1], parts[2]


def _non_persistent_overlay_mount(
    volume_spec: str,
    *,
    name: str,
    index: int,
) -> tuple[str, str, str] | None:
    """Return (volume, upperdir, workdir) for an ephemeral overlay bind.

    Podman's ``:O`` bind option mounts the host source as an overlay lowerdir.
    Supplying explicit upper/work dirs under ``%t`` keeps all writes in the
    user's runtime tmpfs instead of in container storage. The host source is
    never mounted writable, while the cage still sees a writable target.
    """
    source, target, options = _split_volume_spec(volume_spec)
    if not source or not target:
        return None

    mount_id = f"vol-{index}"
    upper = f"%t/agentcage/{name}/mounts/{mount_id}/upper"
    work = f"%t/agentcage/{name}/mounts/{mount_id}/work"
    passthrough_opts = [
        o for o in (options.split(",") if options else [])
        if o and o not in ("ro", "rw", "O", "np") and not o.startswith("upperdir=")
        and not o.startswith("workdir=")
    ]
    opts = ["O", f"upperdir={upper}", f"workdir={work}", *passthrough_opts]
    return (f"{source}:{target}:{','.join(opts)}", upper, work)


def _stage_vm_file_volume(real_path: str, deploy_name: str) -> str:
    """Stage a single-file volume source so the VM backend can mount it.

    Lima's virtiofs shares directories, not single files, so a volume
    whose host source is a regular file (e.g. a scaffold mounting a
    single dotfile from the host) cannot be handed to the VM directly.
    Copy it into
    ``~/.local/share/agentcage/<cage>/seed/`` instead — that directory is
    already virtiofs-mounted into the VM — and return the staged path for
    the cage quadlet to bind-mount.

    The copy is one-way: the cage reads and may write the staged file,
    but changes are not propagated back to the host original. Staging
    runs on every deploy, so the seed tracks the host file over time.
    """
    data_dir = os.path.realpath(os.path.expanduser("~/.local/share/agentcage"))
    seed_dir = os.path.join(data_dir, deploy_name, "seed")
    os.makedirs(seed_dir, exist_ok=True)
    staged = os.path.join(seed_dir, os.path.basename(real_path))
    shutil.copy2(real_path, staged)
    return staged


def generate_quadlets(
    config: Config,
    config_host_path: str,
    patches_host_dir: str,
    deploy_name: str = "",
    rootless: bool = True,
    used_octets: set[int] | None = None,
    network_octet: int | None = None,
    store_secrets: set[str] | None = None,
) -> dict[str, str]:
    """Return {filename: content} for all 5 quadlet files.

    Args:
        config: Parsed agentcage config.
        config_host_path: Absolute host path to config.yaml (for proxy Volume=).
        patches_host_dir: Absolute host path to patches/ dir (for cage Volume=).
        deploy_name: Deployment name for secret prefixing.  When set, podman
            secret references become ``{deploy_name}.{key}`` with
            ``target={key}`` so the container still sees the original env name.
        network_octet: When set, pins the cage to a specific ``10.89.<octet>.0/24``
            subnet, bypassing hash-based allocation. Used by ``cage update`` to
            preserve the already-allocated subnet of an existing cage — the
            podman network is created once at cage-create time and re-deriving
            a different octet on update would generate quadlets whose static
            IPs don't fall in the existing ``<name>-net`` subnet.
        store_secrets: Env-name set (deploy prefix stripped) of secrets
            currently present in the podman secret store, or ``None`` when
            the store cannot be queried (e.g. VM backend with the guest
            stopped). When a set is given, ``Secret=`` emission becomes
            *store-aware* (issue #262): a store-backed reference whose
            entry is absent — and that will not be materialized before
            container start by a decrypt ``ExecStartPre`` (present ``.cred``
            blob, including ``systemd-creds:`` sources) or by the start
            path's ``resolve_and_populate`` (``env:`` / ``cmd:`` source) — is
            skipped instead of rendered as an unresolvable directive that
            fails the next boot with ``start-limit-hit``. ``None`` keeps
            the legacy emit-everything behavior.
    """
    env = _make_env()
    name = config.name
    cc = config.container
    files: dict[str, str] = {}

    # Expand ~ and env vars in volume paths and env values. The inline ``np``
    # option marks one bind non-persistent: it uses Podman's overlay bind with
    # explicit %t-backed upper/work dirs, so cage writes never reach the host.
    expanded_volumes = []
    non_persistent_precreate_dirs = []
    non_persistent_file_copies = []
    home = os.path.realpath(os.path.expanduser("~"))
    for v in cc.volumes:
        # Split inline options first: ``np`` is agentcage-only and must not
        # reach podman. All other mount options are preserved.
        source, target, raw_opts = _split_volume_spec(v)
        option_list = [o for o in raw_opts.split(",") if o]
        is_np = "np" in option_list
        kept_opts = [o for o in option_list if o != "np"]
        source = os.path.expandvars(os.path.expanduser(source))
        expanded = f"{source}:{target}"
        if kept_opts:
            expanded += ":" + ",".join(kept_opts)
        host_path = source

        # Skip a volume whose ${VAR} did not expand — it cannot be mounted.
        if "$" in host_path:
            click.echo(
                f"warning: skipping volume {host_path!r} (unresolved variable)",
                err=True,
            )
            continue

        # Validate host path portion (before first ':') resolves safely
        real = os.path.realpath(host_path)
        if not (real.startswith(home + os.sep) or real == home):
            raise ValueError(
                f"volume host path {host_path!r} resolves to {real!r} "
                f"which is outside the home directory ({home!r})"
            )

        # Skip optional mounts whose host source does not exist. podman
        # cannot bind-mount a missing path — the container fails to start
        # with `statfs ...: no such file or directory` — and on the VM
        # backend the path is not mounted into the VM either.
        if not os.path.exists(real):
            click.echo(
                f"warning: skipping volume {host_path!r} (host path does not exist)",
                err=True,
            )
            continue

        # VM backend: Lima's virtiofs shares directories, not single
        # files, so a file-source volume (a scaffold mounting a single
        # host dotfile) cannot be mounted into the VM directly. Stage
        # a copy into the cage's data dir — which is virtiofs-mounted —
        # and bind-mount the staged path instead. Container mode
        # bind-mounts files directly.
        if config.isolation == "vm" and not os.path.isdir(real):
            staged = _stage_vm_file_volume(real, deploy_name or name)
            container_part = expanded.split(":", 1)[1]
            expanded = f"{staged}:{container_part}"
            real_for_mount = staged
        else:
            real_for_mount = real

        if is_np and not os.path.isdir(real):
            _src, target, _opts = _split_volume_spec(expanded)
            if not target:
                click.echo(
                    f"warning: skipping volume {expanded!r} with the "
                    "np flag (invalid volume spec)",
                    err=True,
                )
                continue
            copy_id = f"file-{len(non_persistent_file_copies)}"
            runtime_file = f"%t/agentcage/{deploy_name or name}/mounts/{copy_id}/{os.path.basename(real_for_mount)}"
            expanded_volumes.append(f"{runtime_file}:{target}:rw")
            non_persistent_file_copies.append({
                "src": shlex.quote(real_for_mount),
                "dst": shlex.quote(runtime_file),
                "dir": shlex.quote(os.path.dirname(runtime_file)),
            })
            continue

        if is_np:
            overlay = _non_persistent_overlay_mount(
                expanded,
                name=deploy_name or name,
                index=len(non_persistent_precreate_dirs) // 2,
            )
            if overlay is None:
                click.echo(
                    f"warning: skipping volume {expanded!r} with the "
                    "np flag (invalid volume spec)",
                    err=True,
                )
                continue
            expanded_volumes.append(overlay[0])
            non_persistent_precreate_dirs.extend([
                shlex.quote(overlay[1]),
                shlex.quote(overlay[2]),
            ])
            continue

        expanded_volumes.append(expanded)
    expanded_env = {k: os.path.expandvars(str(v)) for k, v in cc.env.items()}

    # Cage placeholders are delivered via an EnvironmentFile (read by podman
    # at every container creation) instead of baked Environment= lines, so a
    # plain `cage restart` — not just `cage update` — picks up placeholder
    # changes. The file is a cage.yaml-derived sibling of proxy-config.yaml,
    # regenerated by state.save_proxy_config on every deploy/restart path.
    # Rules whose placeholder hasn't been generated yet
    # (config.fill_raw_placeholders runs at declare time) don't count.
    has_placeholders = any(r.placeholder for r in config.secret_injection)
    if has_placeholders:
        if config.isolation == "vm":
            # Lima's reverse-sshfs caches host writes; mount the VM-local
            # copy pushed by backends.vm.push_config_files instead.
            placeholders_env_path = vm_local_placeholders_env_path(
                deploy_name or name
            )
            cage_env_dir = vm_local_cage_env_dir(deploy_name or name)
        else:
            from agentcage import state as _state
            placeholders_env_path = str(
                _state.placeholders_env_path(deploy_name or name)
            )
            cage_env_dir = str(_state.cage_env_dir(deploy_name or name))
    else:
        placeholders_env_path = ""
        cage_env_dir = ""

    # Proxy secrets: split by backend for quadlet generation.
    # A rule gets a decrypt ExecStartPre if:
    #   (a) its source scheme is "systemd-creds:" (explicit opt-in), OR
    #   (b) a .cred file exists in the state dir (auto-encrypted via
    #       `agentcage secret set` on a systemd-creds default host).
    # Either way the rule still needs the podman Secret= directive — the
    # ExecStartPre decrypts the blob and populates the podman store before
    # the proxy container starts.
    from agentcage import state as _state_mod
    _state_creds_dir = _state_mod.deployment_dir(deploy_name or name) / "creds"

    def _boot_resolvable(env_name: str, scheme: str, has_cred_file: bool) -> bool:
        """True when a ``Secret=`` reference to *env_name* will resolve
        at container start (issue #262 store-aware gate).

        Always true when *store_secrets* is None (store state unknown —
        keep the legacy behavior). Otherwise true when the entry is in
        the store now, or a pre-start channel materializes it: the
        decrypt ExecStartPre (present ``.cred`` blob, including
        ``systemd-creds:`` sources) or the start path's
        resolve_and_populate (``env:`` / ``cmd:`` source).
        """
        if store_secrets is None:
            return True
        if has_cred_file or scheme in ("env", "cmd"):
            return True
        return env_name in store_secrets

    proxy_secrets = []
    creds_secrets = []
    for r in config.secret_injection:
        scheme = (r.source or "").partition(":")[0]
        has_cred_file = (_state_creds_dir / f"{r.env}.cred").exists()
        if not _boot_resolvable(r.env, scheme, has_cred_file):
            # `secret rm` removed the store entry but the declared rule
            # stays in cage.yaml — rendering the directive anyway would
            # make the next egress boot fail with an unresolvable
            # `Secret=`. Skip it; the next `secret set` re-converges the
            # units and the line comes back.
            continue
        if scheme == "systemd-creds" or has_cred_file:
            creds_secrets.append(r.env)
        proxy_secrets.append(r.env)

    # Protocol-relay credentials live in the same podman secret store and
    # need a Secret= directive on the proxy container so the relay can
    # resolve them via env at startup. The CLI parser strips them from the
    # cage's podman_secrets/env so the cage container never sees them; they
    # only land in the proxy. Auto-decrypt the .cred file if systemd-creds
    # is the default backend, mirroring secret_injection above.
    for relay in getattr(config, "protocol_relays", []):
        for src in (relay.auth.user_source, relay.auth.password_source):
            scheme, _, arg = (src or "").partition(":")
            if not arg or arg in proxy_secrets:
                continue
            has_cred_file = (_state_creds_dir / f"{arg}.cred").exists()
            if not _boot_resolvable(arg, scheme, has_cred_file):
                continue
            if scheme == "systemd-creds" or has_cred_file:
                creds_secrets.append(arg)
            proxy_secrets.append(arg)

    # Direct podman_secrets on the cage container hit the same boot
    # failure when their store entry was `secret rm`'d — gate them with
    # the same store-aware rule (no source: concept here; a .cred blob
    # is materialized by the egress decrypt ExecStartPre, which runs
    # before the cage starts).
    cage_podman_secrets = [
        s for s in cc.podman_secrets
        if _boot_resolvable(
            s, "", (_state_creds_dir / f"{s}.cred").exists()
        )
    ]

    # Parse ports into structured forwards for proxy reverse mode
    inbound_forwards = []
    for port_spec in cc.ports:
        parts = port_spec.split(":")
        if len(parts) == 3:
            host_bind, host_port, container_port = parts
        elif len(parts) == 2:
            host_bind, host_port, container_port = "127.0.0.1", parts[0], parts[1]
        else:
            continue
        if container_port == "8080":
            raise ValueError(
                f"container port 8080 conflicts with the mitmproxy forward proxy "
                f"(port spec: {port_spec!r}). Use a different container port."
            )
        if container_port == "8443":
            raise ValueError(
                f"container port 8443 conflicts with the mitmproxy transparent proxy "
                f"(port spec: {port_spec!r}). Use a different container port."
            )
        inbound_forwards.append({
            "host_bind": host_bind,
            "host_port": host_port,
            "container_port": container_port,
            "publish_spec": f"{host_bind}:{host_port}:{container_port}",
        })

    addrs = cage_network_addrs(
        name, used_octets=used_octets, network_octet=network_octet,
    )
    common = {"name": name, **addrs}

    # Network
    files[f"{name}-net.network"] = env.get_template("network.j2").render(**common)

    # Volumes
    #
    # Two cert volumes, not one:
    #   * agentcage-certs-<name>        — mitmproxy state dir (private key,
    #     .p12 bundles, public cert). Mounted RW into the egress only.
    #   * agentcage-public-certs-<name> — published public cert only.
    #     Mounted RW into the egress (so supervisor-egress.sh Step E can
    #     install the cert there) and RO into the cage at /certs.
    #
    # The cage MUST NOT see the private-key volume. CTF findings F6 (container)
    # and F9 (vm) on agentcage 0.22.0 flagged the prior single-volume layout
    # as a defense-in-depth violation: a uid/perm regression would let the
    # cage mint trusted certs for any allowlisted host. Mirrors the apple-
    # container split done in #208 (a1dcb4a).
    files[f"{name}-certs.volume"] = env.get_template("volume.j2").render(
        volume_name=f"agentcage-certs-{name}",
    )
    files[f"{name}-public-certs.volume"] = env.get_template("volume.j2").render(
        volume_name=f"agentcage-public-certs-{name}",
    )

    # DNS allowlist sidecar file path — bind-mounted into the egress
    # container at /etc/agentcage/dns-allowlist.conf. The quadlet only
    # encodes whether allowlist mode is on; the contents change without
    # touching the systemd unit.
    #
    # VM backend: the bind mount source is a VM-local path, NOT the host
    # path under ~/.config/agentcage. Lima's reverse-sshfs mount caches
    # host writes, so a host-side rewrite of dns-allowlist.conf would not
    # propagate into the egress container; the VM-local copy is rewritten
    # by ``_update_dns_quadlet`` via ``inst.exec`` and dnsmasq SIGHUPs to
    # pick it up.
    if config.isolation == "vm":
        dns_allowlist_path_str = vm_local_dns_allowlist_path(deploy_name or name)
    else:
        from agentcage.state import dns_allowlist_path
        dns_allowlist_path_str = str(dns_allowlist_path(deploy_name or name))

    # Capture volume — host path for capture JSONL
    capture_enabled = config.capture.enable_har
    if capture_enabled:
        from agentcage.state import capture_dir as _capture_dir
        capture_host_dir = str(_capture_dir(deploy_name or name))
    else:
        capture_host_dir = ""

    # Egress container (combined mitmproxy + dnsmasq) — published ports
    # are served here via reverse proxy mode; the supervisor inside the
    # image applies the iptables FORWARD-chain shape and starts both
    # daemons under stripped CapBnd. See data/containers/Containerfile.egress
    # and data/containers/supervisor-egress.sh.
    pt_regex = (
        _passthrough_regex(config.domains.passthrough)
        if config.domains.passthrough else ""
    )
    creds_dir = str(_state_creds_dir)
    _inspected_tcp, _passthrough_tcp, _allow_udp = _effective_port_policy(config)

    # Resolve secrets.scope (auto/user/system) into the concrete flag passed
    # to systemd-creds decrypt in the egress quadlet's ExecStartPre. The
    # quadlet runs under `systemctl --user`, so --user picks the per-user
    # decryption key — no polkit prompt at start time.
    creds_scope_flag = ""
    if creds_secrets:
        from agentcage.secret_resolver import resolve_scope
        try:
            _scope = resolve_scope(config.secrets.scope)
        except ValueError:
            _scope = "system"
        if _scope == "user":
            creds_scope_flag = "--user "

    # VM backend: rewrite proxy-config.yaml mount source to a VM-local
    # path for the same reason as dns-allowlist.conf above — Lima's
    # reverse-sshfs caching would otherwise hide host-side rewrites from
    # mitmproxy's mtime-poll hot-reload.
    if config.isolation == "vm":
        proxy_config_path = vm_local_proxy_config_path(deploy_name or name)
    else:
        proxy_config_path = config_host_path

    files[f"{name}-egress.container"] = env.get_template("egress.container.j2").render(
        **common,
        agentcage_version=_pkg_version("agentcage"),
        patches_host_dir=patches_host_dir,
        config_host_path=proxy_config_path,
        dns_allowlist_enabled=(config.domains.mode == "allowlist"),
        dns_allowlist_host_path=dns_allowlist_path_str,
        proxy_secrets=proxy_secrets,
        deploy_name=deploy_name,
        creds_secrets=creds_secrets,
        creds_dir=creds_dir,
        creds_scope_flag=creds_scope_flag,
        log_dns_queries=config.logging.dns_queries,
        log_proxy_connections=config.logging.proxy_connections,
        dns_servers=config.dns_servers,
        inbound_forwards=inbound_forwards,
        capture_enabled=capture_enabled,
        capture_host_dir=capture_host_dir,
        passthrough_regex=pt_regex,
        rootless=rootless,
        inspected_tcp_ports=_inspected_tcp,
        passthrough_tcp_ports=_passthrough_tcp,
        allow_udp_ports=_allow_udp,
        allow_icmp=config.ports.icmp.allow,
    )

    # Nested containers support
    nested_containers = cc.nested_containers
    cage_drop_caps = cc.drop_capabilities
    cage_add_caps = list(cc.add_capabilities)
    cage_no_new_privs = cc.no_new_privileges
    cage_user = cc.user
    if nested_containers:
        cage_drop_caps = []
        # Inner podman needs a broad capability set: SYS_ADMIN for namespaces,
        # SYS_CHROOT for tar applier, CHOWN/FOWNER/DAC_OVERRIDE for file ops,
        # SETUID/SETGID for user mapping, MKNOD for device nodes, etc.
        nested_caps = (
            "SYS_ADMIN", "SYS_CHROOT", "MKNOD", "SETUID", "SETGID",
            "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
            "NET_ADMIN", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETPCAP",
            "AUDIT_WRITE",
        )
        for cap in nested_caps:
            if cap not in cage_add_caps:
                cage_add_caps.append(cap)
        cage_no_new_privs = False
        # Run as root inside the user namespace so setuid helpers
        # (newuidmap/newgidmap) work for inner rootless podman.
        cage_user = "0"
        # Storage volume for inner podman state
        files[f"{name}-podman-storage.volume"] = env.get_template("volume.j2").render(
            volume_name=f"agentcage-podman-{name}",
        )

    # Map lifecycle to systemd restart policy
    lifecycle = config.lifecycle
    restart = cc.restart
    if lifecycle in ("interactive", "ephemeral"):
        restart = "no"

    # Cage container — no published ports (traffic arrives via proxy reverse mode)
    files[f"{name}-cage.container"] = env.get_template("cage.container.j2").render(
        **common,
        image=cc.image,
        agentcage_version=_pkg_version("agentcage"),
        patches_host_dir=patches_host_dir,
        volumes=expanded_volumes,
        named_volumes=cc.named_volumes,
        tmpfs=cc.tmpfs,
        non_persistent_precreate_dirs=non_persistent_precreate_dirs,
        non_persistent_file_copies=non_persistent_file_copies,
        podman_secrets=cage_podman_secrets,
        placeholders_env_path=placeholders_env_path,
        cage_env_dir=cage_env_dir,
        env=expanded_env,
        userns=cc.userns,
        user=cage_user,
        read_only=cc.read_only,
        security_label_disable=cc.security_label_disable,
        no_new_privileges=cage_no_new_privs,
        drop_capabilities=cage_drop_caps,
        add_capabilities=cage_add_caps,
        memory=cc.memory,
        cpus=cc.cpus,
        command=cc.command,
        restart=restart,
        restart_sec=cc.restart_sec,
        timeout_start_sec=cc.timeout_start_sec,
        timeout_stop_sec=cc.timeout_stop_sec,
        deploy_name=deploy_name,
        nested_containers=nested_containers,
        lifecycle=lifecycle,
    )

    return files
