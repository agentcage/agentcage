"""Generate quadlet files from a Config object using Jinja2 templates."""

from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import re
import shlex
import shutil
from importlib.metadata import version as _pkg_version
from pathlib import Path

import click
from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.config import Config
from agentcage.volume_mounts import (
    TMPFS_COPYUP_OPTIONS,
    enclosing_mount,
    is_non_persistent_volume,
    mask_copyup_entries,
    mask_mountpoint_dirs,
    split_volume_spec,
    tmpfs_spec_target,
    validate_non_persistent_volume,
    volume_options,
)


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
    source, target, options = split_volume_spec(volume_spec)
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


def _b64(value: str) -> str:
    """Base64-encode *value* for safe embedding in a systemd Exec line."""
    return base64.b64encode(value.encode()).decode()


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


# ``/tmp`` semantics: writable by every uid in the cage, sticky so one uid
# cannot delete another's entries. Applied only to tmpfs entries that mask a
# path inside another mount — see _apply_tmpfs_mask_options().
_TMPFS_MASK_MODE = "mode=1777"

# Copy-up default for a mask that declares neither ``tmpcopyup`` nor
# ``notmpcopyup`` (#328). Podman appends ``tmpcopyup`` to every tmpfs in that
# position (``pkg/util/mountOpts.go``), so a mask silently came up holding the
# very host content it was added to hide, while apple-container — whose
# ``--tmpfs`` has no option channel — came up empty. Pinning the default here
# makes "unspecified" mean the same thing on both backends and matches what a
# mask is for: an operator who overlays a bind wants that path hidden, and
# copy-up under the masks' ``noexec`` only delivers files the cage can look at
# but never run. Opt in per entry with ``tmpcopyup`` (the ``.claude/`` mask
# does).
_TMPFS_MASK_NO_COPYUP = "notmpcopyup"


def _apply_tmpfs_mask_options(
    tmpfs: list[str],
    mount_targets: list[tuple[str, str]],
) -> list[str]:
    """Pin agentcage's mask defaults on tmpfs entries nested inside a mount.

    Neither OCI runtime gives a tmpfs the kernel's default ``1777`` root
    mode when the mount spec carries no explicit ``mode=``: both copy the
    mode of the directory the tmpfs is mounted *over* instead — runc in
    ``mountEntry.createOpenMountpoint`` (``mode=%04o`` prepended to the
    mount data), crun in ``append_tmpfs_mode_if_missing`` ("only when the
    mount does not already request an explicit mode= option"). The tmpfs
    root is then owned by the userns root the runtime mounts as, not by
    the cage workload's ``user:``.

    For a tmpfs that masks a path inside a host bind-mount — the #170
    ``/workspace/.git/hooks/`` and #173 ``/workspace/.claude/`` masks the
    scaffolds ship — the inherited mode is the **host** directory's,
    typically ``0755``. The mask therefore comes up root-owned and
    read-only for the uid the cage actually runs as, so a legitimate
    in-cage write (``git`` installing a hook, an agent writing project
    ``.claude`` state) fails with EACCES and only ``--as-root`` can write
    (#321). Ownership cannot be expressed here — tmpfs ``uid=``/``gid=``
    would have to hardcode the workload uid — but the mode can, and a
    sticky world-writable root makes the mask usable by any ``user:``.

    This does not weaken the mask. The tmpfs stays private to the cage's
    mount namespace and mounted ``rprivate``, so cage writes still never
    reach the host; the declared ``noexec,nosuid,nodev`` options are
    untouched, so nothing planted there is executable; and the sticky bit
    keeps one in-cage uid from clobbering another's entries.

    The second pin is ``notmpcopyup`` (#328). Podman appends ``tmpcopyup``
    to every tmpfs whose spec names neither copy-up option
    (``pkg/util/mountOpts.go``), so the masks came up on podman holding a
    copy of the host's ``.git/hooks/`` and project ``.claude/`` — the exact
    content the mask exists to hide — while apple-container's bare
    ``--tmpfs`` (no option channel at all) came up empty. Neither was a
    decision. Defaulting masks to ``notmpcopyup`` makes "unspecified" mean
    the same thing on both backends, matches what a mask is for, and drops
    a usability trap: the copied-up files land owned by the userns root, so
    an agent editing one hit ``Permission denied`` on a file it could not
    have executed anyway (the masks are ``noexec``). An entry that *wants*
    the host content — the ``.claude/`` mask, so a caged agent can read the
    project's ``settings.json`` — opts in with an explicit ``tmpcopyup``,
    which podman passes through verbatim and which
    :func:`~agentcage.volume_mounts.mask_copyup_entries` hands to the
    per-backend seeding/ownership fixups.

    Only masking entries are rewritten, and each pin only when the operator
    named that option themselves. A tmpfs over an image directory
    (``/tmp``, ``/var/cache``, …) is left entirely alone: its mode and its
    contents are the image author's intent and are already expressed in the
    cage's own uid space, so there is nothing to fix.

    Args:
        tmpfs: Raw ``container.tmpfs`` specs (``target[:options]``).
        mount_targets: ``(container_target, host_source)`` for every mount
            the cage quadlet emits, in the same shape
            :func:`~agentcage.volume_mounts.mask_mountpoint_dirs` consumes.
            Only the *topology* matters here — a mask inherits the mode and
            the contents of whatever it covers whether or not that mount
            reaches the host — so unlike the mount-point bookkeeping this
            ignores *host_source*.
    """
    rewritten = []
    for spec in tmpfs:
        target = tmpfs_spec_target(spec)
        options = [o for o in spec[len(target):].lstrip(":").split(",") if o]
        if not target.startswith("/"):
            rewritten.append(spec)
            continue
        enclosing, _source = enclosing_mount(
            posixpath.normpath(target), mount_targets
        )
        if not enclosing:
            rewritten.append(spec)
            continue
        pinned = list(options)
        if not any(o in TMPFS_COPYUP_OPTIONS for o in options):
            pinned.append(_TMPFS_MASK_NO_COPYUP)
        # ``mode=`` stays LAST: both runtimes prepend the mount point's
        # inherited mode to the mount data and the kernel takes the last
        # ``mode=`` it parses.
        if not any(o.startswith("mode=") for o in options):
            pinned.append(_TMPFS_MASK_MODE)
        if pinned == options:
            rewritten.append(spec)
            continue
        # The operator's literal target is emitted back unchanged; only the
        # comparison above is normalized.
        rewritten.append(f"{target}:{','.join(pinned)}")
    return rewritten


# uid:gid the copied-up mask content is handed to when ``container.user``
# does not name a numeric one. Matches the uid every first-party scaffold
# image gives its workload user, the uid apple-container's cage-init hands
# its seeded copies (``data/apple-container/cage-init.sh`` stage C'), and the
# uid interactive ``cage exec`` / ``cage shell`` sessions are pinned to
# regardless of ``container.user``.
_MASK_COPYUP_DEFAULT_OWNER = "1000:1000"


def _mask_copyup_owner(user: str) -> str:
    """Return the ``uid:gid`` a copy-up mask's contents must be handed to.

    Both OCI runtimes perform ``tmpcopyup`` as the user-namespace root they
    mount as, and neither replays the source's ownership onto the copy, so
    the content lands ``0:0`` — unwritable and undeletable for the non-root
    uid the cage actually runs as, even with :data:`_TMPFS_MASK_MODE`'s
    sticky world-writable tmpfs root (the sticky bit lets the workload
    *create* siblings but never modify or remove a root-owned entry). #328
    measured exactly that: an agent could read the seeded project
    ``.claude/settings.json`` but got ``Permission denied`` editing its own
    throwaway copy.

    Returns ``""`` when no chown is needed or possible: a cage that already
    runs as uid 0 owns the copy outright (``nested_containers`` forces
    ``User=0``), and a ``container.user`` naming a *name* rather than a uid
    cannot be resolved host-side — the cage image's ``/etc/passwd`` is not
    readable from here.
    """
    spec = (user or "").strip()
    if not spec:
        # Image default. Every first-party scaffold image puts its workload
        # user at uid 1000 and interactive sessions are pinned there anyway.
        return _MASK_COPYUP_DEFAULT_OWNER
    uid, _sep, gid = spec.partition(":")
    if not uid.isdigit():
        return ""
    if int(uid) == 0:
        return ""
    return f"{uid}:{gid}" if gid.isdigit() else f"{uid}:{uid}"


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
    # (container_target, host_source) for every mount emitted below, with an
    # empty source for mounts that do not write through to the host. Feeds the
    # tmpfs-mask mount-point bookkeeping (#320) after the loop.
    mount_targets: list[tuple[str, str]] = [
        (mount.split(":", 1)[0], "") for mount in cc.named_volumes.values()
    ]
    home = os.path.realpath(os.path.expanduser("~"))
    for v in cc.volumes:
        # Split inline options first: ``np`` is agentcage-only and must not
        # reach podman. All other mount options are preserved.
        validate_non_persistent_volume(v)
        source, target, _raw_opts = split_volume_spec(v)
        is_np = is_non_persistent_volume(v)
        kept_opts = [o for o in volume_options(v) if o != "np"]
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
            # Name np explicitly: for an np bind the consequence is not just a
            # missing mount but a silently unmet isolation expectation, which a
            # generic warning makes easy to overlook (e.g. a typo'd source).
            detail = (
                "host path does not exist; the np bind is not mounted at all"
                if is_np else "host path does not exist"
            )
            click.echo(
                f"warning: skipping volume {host_path!r} ({detail})",
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
            _src, target, _opts = split_volume_spec(expanded)
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
            mount_targets.append((target, ""))
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
            mount_targets.append((split_volume_spec(overlay[0])[1], ""))
            non_persistent_precreate_dirs.extend([
                shlex.quote(overlay[1]),
                shlex.quote(overlay[2]),
            ])
            continue

        expanded_volumes.append(expanded)
        bind_source, bind_target, _bind_opts = split_volume_spec(expanded)
        mount_targets.append((bind_target, bind_source))

    non_persistent_runtime_root = ""
    if non_persistent_precreate_dirs or non_persistent_file_copies:
        non_persistent_runtime_root = shlex.quote(
            f"%t/agentcage/{deploy_name or name}/mounts"
        )

    # tmpfs masks whose target sits under a host bind-mount make the OCI
    # runtime create the mount point on the HOST side of the bind, littering
    # the operator's project dir with e.g. an empty `.git/hooks/` (#320). One
    # ExecStartPre/ExecStopPost pair per bind root records which of those
    # paths were absent right before start and removes exactly those, still
    # only while empty, on teardown. Grouping by root lets the teardown line
    # bake its own containment root, so a removal can never step outside the
    # bind-mounted project directory.
    mask_state_dir = f"%t/agentcage/{deploy_name or name}/masks"
    mask_mountpoints = []
    for idx, (root, dirs) in enumerate(
        sorted(mask_mountpoint_dirs(cc.tmpfs, mount_targets).items())
    ):
        # Host paths reach the unit base64-encoded. A systemd Exec line is
        # word-split with its own quoting rules *before* /bin/bash ever sees
        # it, so there is no single escaping that survives both layers for an
        # arbitrary project path (a plain `~/My Project` already needs a quote
        # that would terminate the systemd-level quoting early). Base64's
        # alphabet is inert to systemd (no `%`, `$`, quote or backslash) and
        # to the shell, so the decode happens inside bash where normal
        # newline-delimited `read -r` handles spaces and quotes correctly.
        if any("\n" in d or "\r" in d for d in [root, *dirs]):
            click.echo(
                f"warning: skipping tmpfs mask cleanup for {root!r} "
                "(path contains a newline)",
                err=True,
            )
            continue
        mask_mountpoints.append({
            "root_b64": _b64(root),
            "state_dir": shlex.quote(mask_state_dir),
            "state_file": shlex.quote(f"{mask_state_dir}/root-{idx}"),
            # Trailing newline: `read` returns non-zero at EOF, so an
            # unterminated last line would be dropped by the while loop.
            "dirs_b64": _b64("".join(f"{d}\n" for d in dirs)),
        })

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

    # Policy API decision-hook auth credential — same shape and same
    # egress-only invariant as a relay credential: it uses a ``*_source``
    # scheme (env:/cmd:/systemd-creds:) and must NEVER reach the cage (the
    # CLI parser already stripped it from cage env/podman_secrets in
    # config.load_config). Stage it into the proxy's tmpfs secret files so
    # the addon can read the real value when calling the decision hook.
    # See docs/explain/policy-api.md §3.3.
    pa = getattr(config, "policy_api", None)
    if pa is not None and getattr(pa, "enable", False):
        for src in (
            pa.request.decision.webhook.auth_source,
            pa.request.decision.llm.auth_source,
        ):
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

    # tmpfs masks that opted into copy-up (#328). Podman hands the option to
    # the OCI runtime verbatim, so the content is already in place when the
    # workload starts — but it is owned by the userns root the runtime copied
    # it as, which the cage's non-root uid can neither modify nor delete. A
    # post-start chown inside the container's namespaces repairs exactly that;
    # see the ExecStartPost in cage.container.j2 for why it cannot run earlier
    # (ExecStartPre precedes the container, so the tmpfs does not exist yet).
    cage_tmpfs = _apply_tmpfs_mask_options(cc.tmpfs, mount_targets)
    copyup_owner = _mask_copyup_owner(cage_user)
    copyup_masks = []
    if copyup_owner:
        for target, _src, _root in mask_copyup_entries(
            cage_tmpfs, mount_targets
        ):
            # Same escaping story as the mask mount-point hooks above: a
            # systemd Exec line applies its own quoting before bash sees it,
            # so the cage path travels base64-encoded and is decoded inside
            # bash where it can be quoted normally.
            copyup_masks.append({"target_b64": _b64(target)})

    # Cage container — no published ports (traffic arrives via proxy reverse mode)
    files[f"{name}-cage.container"] = env.get_template("cage.container.j2").render(
        **common,
        image=cc.image,
        agentcage_version=_pkg_version("agentcage"),
        patches_host_dir=patches_host_dir,
        volumes=expanded_volumes,
        named_volumes=cc.named_volumes,
        tmpfs=cage_tmpfs,
        copyup_masks=copyup_masks,
        copyup_owner=copyup_owner,
        non_persistent_runtime_root=non_persistent_runtime_root,
        non_persistent_precreate_dirs=non_persistent_precreate_dirs,
        non_persistent_file_copies=non_persistent_file_copies,
        mask_mountpoints=mask_mountpoints,
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

    # Policy API grants watcher — a host-side systemd user service that
    # auto-starts with the egress and promotes agent-requested, hook-approved
    # The watcher is installed when (a) the Policy API is enabled (it
    # promotes hook-approved grants) OR (b) any allowlist entry has an expiry
    # (it prunes expired ``domain add --expires-in`` entries from the
    # baseline + dnsmasq). A cage using neither has no watcher — zero new
    # surface, matching the opt-in posture. ``domain add --expires-in`` on a
    # cage that lacked the watcher installs it on demand (see cli
    # _ensure_grants_watcher) so time-limited domains always get pruned.
    needs_watcher = (
        getattr(config.policy_api, "enable", False)
        or bool(getattr(config.domains, "expires", None))
    )
    if needs_watcher:
        files[f"{name}-grants.service"] = _grants_service_unit(
            name, deploy_name or name
        )

    return files


def _grants_service_unit(name: str, deploy_name: str) -> str:
    """Render the auto-start grants-watcher systemd user unit.

    Plain ``.service`` (not a quadlet): the watcher must run on the host so
    it can write the operator's ``cage.yaml`` baseline and exec into the
    egress to SIGHUP dnsmasq — neither of which the in-container addon can
    do. It is bound to the egress lifecycle (starts after it, stops with it)
    and pulled in at boot via ``WantedBy=default.target``, so the operator
    never starts or stops it by hand.
    """
    return f"""[Unit]
Description=agentcage policy-api grants watcher for {name}
# Start after the egress is up (the addon that decides grants lives there)
# and track its lifecycle — stop the watcher when the egress stops.
Requires={name}-egress.service
After={name}-egress.service
BindsTo={name}-egress.service
PartOf={name}-egress.service

[Service]
Type=simple
# Reuses the literal ``domain add`` live-reload chain for every grant.
ExecStart={shlex.quote(_agentcage_cli())} cage grants {shlex.quote(name)} watch --interval 1
Restart=on-failure
RestartSec=2
# Stop cleanly on shutdown so a restart doesn't leave a stale loop.
KillSignal=SIGINT

[Install]
WantedBy=default.target
"""


def _agentcage_cli() -> str:
    """Absolute path to the agentcage CLI for use in generated units."""
    path = shutil.which("agentcage")
    return path or "agentcage"
