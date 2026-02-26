"""Generate quadlet files from a Config object using Jinja2 templates."""

from __future__ import annotations

import hashlib
import os
import re
from importlib.metadata import version as _pkg_version
from pathlib import Path

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.config import Config


def cage_network_addrs(name: str) -> dict[str, str]:
    """Derive deterministic, unique network addresses for a cage.

    Each cage gets a ``/24`` subnet under ``10.89.x.0`` where *x* is
    derived from the cage name via a hash (range 1–254).  This avoids
    subnet collisions when multiple cages run simultaneously.
    """
    h = hashlib.md5(name.encode()).hexdigest()
    octet = (int(h[:8], 16) % 254) + 1
    prefix = f"10.89.{octet}"
    return {
        "subnet": f"{prefix}.0/24",
        "ip_cage": f"{prefix}.2",
        "ip_dns": f"{prefix}.10",
        "ip_proxy": f"{prefix}.11",
    }

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


def _make_env() -> SandboxedEnvironment:
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["systemd_exec"] = _systemd_exec_join
    return env


def render_dns_quadlet(config: Config) -> str:
    """Render just the DNS container quadlet for a given config.

    Used by ``domain add``/``domain rm`` to update DNS forwarding rules
    without a full rebuild.
    """
    env = _make_env()
    name = config.name
    addrs = cage_network_addrs(name)
    dns_allowlist = (
        config.domains.list if config.domains.mode == "allowlist" else []
    )
    return env.get_template("dns.container.j2").render(
        name=name,
        **addrs,
        dns_servers=config.dns_servers,
        log_dns_queries=config.logging.dns_queries,
        dns_allowlist=dns_allowlist,
    )


def generate_quadlets(
    config: Config,
    config_host_path: str,
    patches_host_dir: str,
    deploy_name: str = "",
) -> dict[str, str]:
    """Return {filename: content} for all 5 quadlet files.

    Args:
        config: Parsed agentcage config.
        config_host_path: Absolute host path to config.yaml (for proxy Volume=).
        patches_host_dir: Absolute host path to patches/ dir (for cage Volume=).
        deploy_name: Deployment name for secret prefixing.  When set, podman
            secret references become ``{deploy_name}.{key}`` with
            ``target={key}`` so the container still sees the original env name.
    """
    env = _make_env()
    name = config.name
    cc = config.container
    files: dict[str, str] = {}

    # Expand env vars in volume paths and env values
    expanded_volumes = []
    for v in cc.volumes:
        expanded = os.path.expandvars(v)
        # Validate host path portion (before first ':') resolves safely
        host_path = expanded.split(":")[0]
        real = os.path.realpath(host_path)
        home = os.path.realpath(os.path.expanduser("~"))
        if not (real.startswith(home + os.sep) or real == home):
            raise ValueError(
                f"volume host path {host_path!r} resolves to {real!r} "
                f"which is outside the home directory ({home!r})"
            )
        expanded_volumes.append(expanded)
    expanded_env = {k: os.path.expandvars(str(v)) for k, v in cc.env.items()}

    # Build cage placeholder list: (env_name, placeholder_value)
    cage_placeholders = [(r.env, r.placeholder) for r in config.secret_injection]

    # Proxy secrets: env names from secret_injection rules
    proxy_secrets = [r.env for r in config.secret_injection]

    # Parse ports into structured forwards for proxy reverse mode
    inbound_forwards = []
    for port_spec in cc.ports:
        parts = port_spec.split(":")
        if len(parts) == 3:
            host_bind, host_port, container_port = parts
        elif len(parts) == 2:
            host_bind, host_port, container_port = "0.0.0.0", parts[0], parts[1]
        else:
            continue
        if container_port == "8080":
            raise ValueError(
                f"container port 8080 conflicts with the mitmproxy forward proxy "
                f"(port spec: {port_spec!r}). Use a different container port."
            )
        inbound_forwards.append({
            "host_bind": host_bind,
            "host_port": host_port,
            "container_port": container_port,
            "publish_spec": f"{host_bind}:{host_port}:{container_port}",
        })

    addrs = cage_network_addrs(name)
    common = {"name": name, **addrs}

    # Network
    files[f"{name}-net.network"] = env.get_template("network.j2").render(**common)

    # Volume
    files[f"{name}-certs.volume"] = env.get_template("volume.j2").render(
        volume_name=f"agentcage-certs-{name}",
    )

    # DNS container — pass domain allowlist for DNS-level filtering
    dns_allowlist = (
        config.domains.list if config.domains.mode == "allowlist" else []
    )
    files[f"{name}-dns.container"] = env.get_template("dns.container.j2").render(
        **common,
        dns_servers=config.dns_servers,
        log_dns_queries=config.logging.dns_queries,
        dns_allowlist=dns_allowlist,
    )

    # Capture volume — host path for capture JSONL
    capture_enabled = config.capture.enable_har
    if capture_enabled:
        from agentcage.state import capture_dir as _capture_dir
        capture_host_dir = str(_capture_dir(deploy_name or name))
    else:
        capture_host_dir = ""

    # Proxy container — published ports are served here via reverse proxy mode
    files[f"{name}-proxy.container"] = env.get_template("proxy.container.j2").render(
        **common,
        config_host_path=config_host_path,
        proxy_secrets=proxy_secrets,
        deploy_name=deploy_name,
        log_proxy_connections=config.logging.proxy_connections,
        dns_servers=config.dns_servers,
        inbound_forwards=inbound_forwards,
        capture_enabled=capture_enabled,
        capture_host_dir=capture_host_dir,
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

    # Cage container — no published ports (traffic arrives via proxy reverse mode)
    files[f"{name}-cage.container"] = env.get_template("cage.container.j2").render(
        **common,
        image=cc.image,
        agentcage_version=_pkg_version("agentcage"),
        patches_host_dir=patches_host_dir,
        volumes=expanded_volumes,
        named_volumes=cc.named_volumes,
        tmpfs=cc.tmpfs,
        podman_secrets=cc.podman_secrets,
        cage_placeholders=cage_placeholders,
        env=expanded_env,
        user=cage_user,
        read_only=cc.read_only,
        security_label_disable=cc.security_label_disable,
        no_new_privileges=cage_no_new_privs,
        drop_capabilities=cage_drop_caps,
        add_capabilities=cage_add_caps,
        memory=cc.memory,
        cpus=cc.cpus,
        command=cc.command,
        restart=cc.restart,
        restart_sec=cc.restart_sec,
        timeout_start_sec=cc.timeout_start_sec,
        timeout_stop_sec=cc.timeout_stop_sec,
        deploy_name=deploy_name,
        nested_containers=nested_containers,
    )

    return files
