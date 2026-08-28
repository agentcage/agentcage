"""Business logic extracted from cli.py.

This module contains the core service functions that orchestrate cage
operations (building, deploying, secret checking, etc.) without depending
on Click or any CLI framework.
"""

from __future__ import annotations

import os
import shutil
import socket
from pathlib import Path
from typing import Callable

from agentcage import state
from agentcage.backends import get_backend
from agentcage.podman import Podman

_DATA_DIR = Path(__file__).resolve().parent / "data"

_BUILD_CAPS = [
    "CAP_SETFCAP", "CAP_SETUID", "CAP_SETGID",
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER",
]


def expected_secrets(cfg) -> list[str]:
    """Return all secret names a cage expects (injection + direct +
    protocol-relay credentials)."""
    names: list[str] = []
    for r in cfg.secret_injection:
        names.append(r.env)
    for s in cfg.container.podman_secrets:
        names.append(s)
    # Protocol-relay credentials are stripped from cage's podman_secrets/env
    # (the cage must not see them) but the proxy container still needs them
    # mounted via the same podman secret store.
    for relay in getattr(cfg, "protocol_relays", []):
        for src in (relay.auth.user_source, relay.auth.password_source):
            _, _, arg = (src or "").partition(":")
            if arg and arg not in names:
                names.append(arg)
    return names


def check_secrets(podman: Podman, deploy_name: str, cfg) -> list[str]:
    """Return list of missing secrets for a cage.

    Secrets with a configured ``source`` are checked differently:
      env:VAR         — host env var must be set (or ``env`` field name
                        used as fallback)
      cmd:COMMAND     — command must exist on PATH (lightweight check —
                        full execution happens at resolve time)
      systemd-creds:  — .cred file must exist in state dir (or auto-
                        encrypted .cred file must exist)
      podman:/empty   — must exist in Podman store
    """
    import os
    import shutil
    from agentcage import state as _state

    creds_dir = _state.deployment_dir(deploy_name) / "creds"

    missing = []
    for key in expected_secrets(cfg):
        rule = next((r for r in cfg.secret_injection if r.env == key), None)
        if rule and rule.source:
            scheme, _, arg = rule.source.partition(":")
            if scheme == "env":
                var = arg or key
                if os.environ.get(var) is None:
                    missing.append(key)
                continue
            if scheme == "cmd":
                if not arg.strip():
                    missing.append(key)
                    continue
                # Verify first token resolves on PATH — full execution
                # happens at resolve time. Skip the check for shell
                # builtins or chained commands (too complex to validate).
                first = arg.split()[0] if arg.split() else ""
                if first and "/" not in first and "=" not in first:
                    if shutil.which(first) is None:
                        missing.append(key)
                continue
            if scheme == "systemd-creds":
                if not (creds_dir / f"{key}.cred").exists():
                    missing.append(key)
                continue
        # Legacy: check podman store, but also accept a present .cred
        # file (covers the auto-default case where `secret set` encrypted
        # without an explicit source field).
        if (creds_dir / f"{key}.cred").exists():
            continue
        if not podman.secret_exists(f"{deploy_name}.{key}"):
            missing.append(key)
    return missing


def suggest_alt_port(port: int) -> int:
    """Return a suggested alternative port that stays within 1-65535."""
    alt = port + 1
    if alt > 65535:
        alt = port - 1
    return alt


def check_port_availability(cfg) -> list[tuple[str, str, str]]:
    """Return list of (port_spec, host_bind, host_port) that are already in use."""
    unavailable = []
    for port_spec in cfg.container.ports:
        parts = port_spec.split(":")
        if len(parts) == 3:
            host_bind, host_port, _container_port = parts
        elif len(parts) == 2:
            host_bind, host_port = "0.0.0.0", parts[0]
        else:
            continue
        try:
            port_num = int(host_port)
        except ValueError:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host_bind, port_num))
        except OSError:
            unavailable.append((port_spec, host_bind, host_port))
        finally:
            sock.close()
    return unavailable


def patches_work_dir() -> str:
    """Return (and create) the patches working directory."""
    d = os.path.join(
        os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
        "agentcage", "patches",
    )
    os.makedirs(d, exist_ok=True)
    return d


def ensure_patches(podman: Podman) -> str:
    """Refresh patch files from package data.

    Copies nested container support files so that any tampering in the
    work directory is overwritten.  Returns the patches work directory path.
    """
    patches_work = patches_work_dir()

    # Copy nested container support files
    nested_src = str(_DATA_DIR / "nested")
    nested_dst = os.path.join(patches_work, "nested")
    if os.path.isdir(nested_src):
        if os.path.isdir(nested_dst):
            shutil.rmtree(nested_dst)
        shutil.copytree(nested_src, nested_dst)
        docker_shim = os.path.join(nested_dst, "docker")
        if os.path.isfile(docker_shim):
            os.chmod(docker_shim, 0o755)

    return patches_work


def build_container_image(
    cfg,
    config_dir: Path,
    podman: Podman,
    echo: Callable[[str], None] | None = None,
    no_cache: bool = False,
    pull: bool = False,
) -> None:
    """Build the main container image from a Containerfile.

    *config_dir* is the directory containing the cage.yaml (or the state
    directory for stored configs).  The ``containerfile`` path is resolved
    relative to it.

    *echo* is an optional callback for progress messages (e.g. click.echo).

    *no_cache* forces ``podman build --no-cache`` so every layer is rebuilt
    from scratch. Use this when the on-disk Containerfile changed but the
    layer cache would otherwise short-circuit the rebuild — for example
    after pulling a fresh agentcage release that changed the Containerfile
    or any of the files it COPYs in.

    *pull* forces ``podman build --pull=always`` so the Containerfile's
    ``FROM`` base image is re-fetched from the registry instead of reused
    from the local image cache. Complements *no_cache*: *no_cache*
    invalidates the per-layer build cache, *pull* invalidates the
    base-image cache. Combine both for a fully clean rebuild (e.g. when a
    ``:latest`` upstream base bumped versions and you want the new one).
    """
    from agentcage.registry import resolve_build_args

    bc = cfg.container.build
    containerfile = Path(bc.containerfile)
    if not containerfile.is_absolute():
        containerfile = config_dir / containerfile
    containerfile = containerfile.resolve()

    context_dir = str(containerfile.parent)

    # Point-in-time tag resolution for build args. Scaffold-aware bumping
    # happens earlier in the update path — here we only fill in tags for
    # untagged registry refs (user-provided configs).
    resolved_args, changes = resolve_build_args(bc.args)
    if echo:
        for key, _old, new in changes:
            echo(f"Build arg {key}: {new}")

    if echo:
        # Show the resolved Containerfile path so the operator can see which
        # copy is actually built — for an existing cage this is the staged
        # copy in the cage's state dir, NOT the file they authored at create
        # time. Editing the original has no effect; edit this one (or use
        # `cage update -c <config>` to re-stage from a config you control).
        echo(f"Building {cfg.container.image} from {containerfile}"
             f"{' (no-cache)' if no_cache else ''}...")
    podman.build_image(
        cfg.container.image,
        str(containerfile),
        context_dir,
        cap_add=_BUILD_CAPS,
        build_args=resolved_args,
        no_cache=no_cache,
        pull=pull,
    )


def write_resolv_files(
    patches_work: str,
    name: str,
    ip_egress: str,
    dns_servers: list[str],
) -> tuple[str, str]:
    """Write the cage's and egress's resolv.conf files into *patches_work*.

    Returns ``(cage_resolv_path, egress_resolv_path)``.

    The cage's resolv.conf (``resolv-<name>.conf``) points at this cage's
    egress sidecar, so the cage's DNS goes through the egress's bundled,
    allowlist-scoped dnsmasq.

    The egress's resolv.conf (``resolv-egress-<name>.conf``) is pinned to
    the configured upstream resolvers (*dns_servers*) and NOTHING else.

    Why the egress needs its own pinned resolv.conf — the resolv.conf
    ordering race: the egress sidecar joins two podman networks — the
    per-cage ``<name>-net`` and the default ``podman`` network — both of
    which have aardvark-dns enabled. podman injects aardvark's address as
    the FIRST nameserver in the egress's auto-generated /etc/resolv.conf,
    ahead of any upstream servers passed via the quadlet's ``DNS=``
    directive. mitmproxy resolves allowlisted upstream hostnames
    (archive.ubuntu.com, …) via THIS resolv.conf. When aardvark wins the
    order and intermittently fails to forward external names — which it
    does after rapid create/destroy churn degrades the aardvark network
    state — mitmproxy gets "Name or service not known" and returns 502 Bad
    Gateway to the cage for every allowlisted host. (The allowlist-gate
    403 path is unaffected because it short-circuits before upstream
    resolution.)

    The egress never needs aardvark name resolution: it only ever resolves
    REAL upstream hostnames for mitmproxy, and the cage's own DNS goes
    through the egress's bundled dnsmasq (not aardvark). So we bind-mount a
    deterministic resolv.conf that lists only the upstream servers,
    mirroring how the cage gets its own ``resolv-<name>.conf`` and how the
    apple-container backend rewrites the cage's resolv.conf to its dnsmasq
    (CHANGELOG 0.22.11). aardvark is never consulted, so the ordering race
    cannot occur.
    """
    cage_resolv_path = os.path.join(patches_work, f"resolv-{name}.conf")
    with open(cage_resolv_path, "w") as f:
        f.write(f"nameserver {ip_egress}\n")

    egress_resolv_path = os.path.join(patches_work, f"resolv-egress-{name}.conf")
    with open(egress_resolv_path, "w") as f:
        f.write("".join(f"nameserver {srv}\n" for srv in dns_servers))

    return cage_resolv_path, egress_resolv_path


def build_and_deploy(
    cfg,
    config_host_path: str,
    deploy_name: str,
    podman: Podman,
    used_octets: set[int] | None = None,
    network_octet: int | None = None,
    quiet: bool = False,
    no_cache: bool = False,
    pull: bool = False,
):
    """Build images, generate quadlets, install, and start.

    When *network_octet* is provided the cage's subnet is pinned to
    ``10.89.<network_octet>.0/24`` instead of being re-derived from
    the cage name hash.  This is the path ``cage update`` takes so an
    existing cage keeps the subnet its podman network was created
    with — re-allocating would generate quadlets whose static IPs
    fall outside the existing ``<name>-net`` and the egress sidecar
    would refuse to start.
    """
    from agentcage.quadlets import cage_network_addrs

    backend = get_backend(cfg)

    patches_work = ensure_patches(podman)

    # Write the per-cage resolv.conf files (cage + egress) into the
    # patches dir; the quadlets bind-mount them at /etc/resolv.conf.
    addrs = cage_network_addrs(
        cfg.name, used_octets=used_octets, network_octet=network_octet,
    )
    write_resolv_files(
        patches_work, cfg.name, addrs["ip_egress"], cfg.dns_servers,
    )

    backend.build_artifacts(
        cfg, deploy_name, quiet=quiet, no_cache=no_cache, pull=pull,
    )

    units = backend.generate_units(
        cfg,
        config_host_path,
        patches_work,
        deploy_name,
        used_octets=used_octets,
        network_octet=network_octet,
    )
    backend.install_units(units, quiet=quiet)

    # Persist the actual assigned network octet so collect_used_octets()
    # can read the real value instead of recomputing the hash (which
    # would be wrong if collision resolution shifted the octet).
    octet = int(addrs["subnet"].split(".")[2])
    meta = state.load_metadata(deploy_name)
    meta["network_octet"] = octet
    state.save_metadata(deploy_name, meta)

    backend.start(cfg.name, quiet=quiet)
    return units


def current_placeholders(name: str) -> list[tuple[str, str]]:
    """(env, placeholder) pairs from a cage's stored config, live.

    Read from the raw stored cage.yaml at call time — exec sessions built
    from this see placeholders declared *after* the cage container started,
    which is what makes new secrets usable without a restart. Rules whose
    placeholder was never filled are skipped.
    """
    try:
        raw = state.load_raw_config(name)
    except FileNotFoundError:
        return []
    si = raw.get("secret_injection") or []
    rules = si.get("rules", []) if isinstance(si, dict) else si
    pairs: list[tuple[str, str]] = []
    for entry in rules if isinstance(rules, list) else []:
        if isinstance(entry, dict) and entry.get("env") \
                and entry.get("placeholder"):
            pairs.append((entry["env"], entry["placeholder"]))
    return pairs


def cage_has_live_secret_channel(name: str, cfg) -> bool:
    """True if the RUNNING egress container mounts the staged-secrets dir.

    Inspects the live container rather than the installed unit files:
    units may have been converged (regenerated + installed without a
    restart) after the container started, in which case the running egress
    still lacks the ``/home/acproxy/secrets`` mount and a live-staged
    value could never reach its proxy — callers must fall back to the
    restart path, which also adopts the converged units. apple-container
    has its own staging lifecycle tied to ``start()`` and is handled
    separately.
    """
    if cfg.isolation not in ("container", "vm"):
        return False
    try:
        if cfg.isolation == "vm":
            from agentcage.lima.podman import VmPodman
            podman = VmPodman(name)
        else:
            podman = Podman()
        info = podman.container_inspect(f"{name}-egress")
    except Exception:
        return False
    for mount in (info.get("Mounts") or []):
        if isinstance(mount, dict) \
                and mount.get("Destination") == "/home/acproxy/secrets":
            return True
    return False


_STAGE_WRITE_SCRIPT = (
    # Runs inside `podman unshare` so uid 0 == the host user and the
    # chown maps to the in-container acproxy uid through the rootless
    # user namespace. Overwrites files the previous egress start chowned
    # to the acproxy subuid (plain host-user writes would get EACCES).
    'umask 077; mkdir -p "$(dirname "$1")"; cat > "$1" && chown 200:200 "$1"'
)


def stage_secret_value(cfg, name: str, key: str, value: str) -> None:
    """Write *value* into the cage's staged-secrets tmpfs file, live.

    The egress quadlet mounts the staging dir read-only at
    ``/home/acproxy/secrets``; the proxy's secret_injector prefers staged
    files over its (frozen) process env and re-reads them on the next
    proxy-config.yaml mtime bump — callers pair this with
    ``state.save_proxy_config``. An empty *value* writes a tombstone:
    the injector skips the rule instead of falling back to the stale env.

    Raises on failure — callers fall back to the restart path.
    """
    import subprocess
    if cfg.isolation == "vm":
        from agentcage.lima.instance import LimaInstance
        inst = LimaInstance(name)
        runtime_dir = inst.exec(
            ["sh", "-c", 'echo "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"'],
        ).stdout.strip()
        target = f"{runtime_dir}/agentcage/{name}/secrets/{key}"
        inst.exec(
            ["podman", "unshare", "sh", "-c", _STAGE_WRITE_SCRIPT, "_", target],
            input=value,
        )
        return
    # Path-only composition — deliberately NOT state.runtime_secrets_dir(),
    # whose mkdir/chmod runs as the host user: once the egress has started,
    # the staging dir is owned by the acproxy subuid (the quadlet's
    # `podman unshare chown -R 200:200`) and a host-side chmod EPERMs.
    # The unshare script below mkdir -p's with the right identity.
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    target = Path(base) / "agentcage" / name / "secrets" / key
    subprocess.run(
        ["podman", "unshare", "sh", "-c", _STAGE_WRITE_SCRIPT, "_", str(target)],
        input=value.encode(),
        check=True,
        capture_output=True,
    )


def restart_cage(name: str, cfg=None):
    """Restart all services for a cage using the appropriate backend.

    Polls the cage service's ``is_running`` for up to 30 seconds after the
    backend's ``restart`` returns. Without this, ``cage restart`` returns
    while the cage container is still in podman's "starting" phase, the
    operator runs ``cage ls`` immediately after and sees ``degraded
    (2/3)``, and concludes the restart failed. Returns silently once the
    cage is active; logs a one-line warning if it's still not active at
    the deadline (the unit may genuinely be slow to start, or
    ``backend.restart`` may have surfaced its own failure already).
    """
    import time

    if cfg is None:
        cfg = state.load_deployment_config(name)
    backend = get_backend(cfg)
    backend.restart(name)

    # 30s deadline matches the cage quadlet's ExecStartPre CA-cert poll plus
    # a few extra seconds for podman to register the container as running.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if backend.is_running(name, "cage"):
                return
        except Exception:
            pass
        time.sleep(0.5)


def _find_owning_backend(name: str):
    """Return the backend that owns artifacts for ``name``, or None.

    Used by :func:`destroy_cage` when the stored deployment config can't
    be loaded — see comment there.
    """
    from agentcage.backends.apple_container import AppleContainerBackend
    from agentcage.backends.container import ContainerBackend
    from agentcage.backends.vm import VmBackend

    for backend in (AppleContainerBackend(), VmBackend(), ContainerBackend()):
        try:
            if backend.has_resources(name):
                return backend
        except Exception:
            continue
    return None


def destroy_cage(
    name: str,
    *,
    keep_secrets: bool = False,
    echo: Callable[[str], None] | None = None,
) -> list[str]:
    """Stop and destroy a cage, removing all resources.

    Returns a list of removed resource descriptions.
    """
    _echo = echo or (lambda _: None)

    try:
        cfg = state.load_deployment_config(name)
        backend = get_backend(cfg)
    except Exception:
        # No stored config — ask each backend whether it owns artifacts for
        # ``name`` and dispatch to the one that does. Without this probe the
        # default fell back to ContainerBackend, which calls ``podman`` —
        # crashing on macOS where podman isn't installed even when the cage
        # is an apple-container artifact (e.g. cleanup after ``agentcage run``
        # which wipes the deployment dir on exit).
        backend = _find_owning_backend(name)
        if backend is None:
            _echo(f"Nothing to remove for '{name}' "
                  "(no stored config and no backend resources).")
            if state.deployment_exists(name):
                state.remove_deployment(name)
                return [f"state:{name}"]
            return []

    _echo("Stopping services...")
    backend.stop(name)

    _echo("Removing resources...")
    removed = backend.destroy_resources(name, keep_secrets=keep_secrets)

    if state.deployment_exists(name):
        state.remove_deployment(name)
        removed.append(f"state:{name}")

    return removed
