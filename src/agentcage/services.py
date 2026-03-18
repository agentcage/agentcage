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
    """Return all secret names a cage expects (injection + direct)."""
    names: list[str] = []
    for r in cfg.secret_injection:
        names.append(r.env)
    for s in cfg.container.podman_secrets:
        names.append(s)
    return names


def check_secrets(podman: Podman, deploy_name: str, cfg) -> list[str]:
    """Return list of missing secrets for a cage."""
    missing = []
    for key in expected_secrets(cfg):
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
) -> None:
    """Build the main container image from a Containerfile.

    *config_dir* is the directory containing the cage.yaml (or the state
    directory for stored configs).  The ``containerfile`` path is resolved
    relative to it.

    *echo* is an optional callback for progress messages (e.g. click.echo).
    """
    from agentcage.registry import resolve_latest_tag

    bc = cfg.container.build
    containerfile = Path(bc.containerfile)
    if not containerfile.is_absolute():
        containerfile = config_dir / containerfile
    containerfile = containerfile.resolve()

    context_dir = str(containerfile.parent)

    # Auto-resolve latest tags for remote image refs in build args
    resolved_args: dict[str, str] = {}
    for key, val in bc.args.items():
        image_base, _, tag = val.rpartition(":")
        if image_base and tag:
            resolved_args[key] = val
        elif "/" in val:
            # Looks like a remote image without tag — resolve latest
            new_tag = resolve_latest_tag(val)
            if new_tag:
                resolved_args[key] = f"{val}:{new_tag}"
                if echo:
                    echo(f"Build arg {key}: {val}:{new_tag}")
            else:
                resolved_args[key] = val
        else:
            resolved_args[key] = val

    if echo:
        echo(f"Building {cfg.container.image}...")
    podman.build_image(
        cfg.container.image,
        str(containerfile),
        context_dir,
        cap_add=_BUILD_CAPS,
        build_args=resolved_args,
    )


def build_and_deploy(
    cfg,
    config_host_path: str,
    deploy_name: str,
    podman: Podman,
    used_octets: set[int] | None = None,
):
    """Build images, generate quadlets, install, and start."""
    from agentcage.quadlets import cage_network_addrs

    backend = get_backend(cfg)

    patches_work = ensure_patches(podman)

    # Write per-cage resolv.conf pointing to this cage's dnsmasq sidecar
    addrs = cage_network_addrs(cfg.name, used_octets=used_octets)
    resolv_path = os.path.join(patches_work, f"resolv-{cfg.name}.conf")
    with open(resolv_path, "w") as f:
        f.write(f"nameserver {addrs['ip_dns']}\n")

    backend.build_artifacts(cfg, deploy_name)

    units = backend.generate_units(cfg, config_host_path, patches_work, deploy_name, used_octets=used_octets)
    backend.install_units(units)

    # Persist the actual assigned network octet so collect_used_octets()
    # can read the real value instead of recomputing the hash (which
    # would be wrong if collision resolution shifted the octet).
    octet = int(addrs["subnet"].split(".")[2])
    meta = state.load_metadata(deploy_name)
    meta["network_octet"] = octet
    state.save_metadata(deploy_name, meta)

    backend.start(cfg.name)


def restart_cage(name: str, cfg=None):
    """Restart all services for a cage using the appropriate backend."""
    if cfg is None:
        cfg = state.load_deployment_config(name)
    backend = get_backend(cfg)
    backend.restart(name)
