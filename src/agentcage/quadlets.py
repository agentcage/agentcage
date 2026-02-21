"""Generate quadlet files from a Config object using Jinja2 templates."""

from __future__ import annotations

import os
from pathlib import Path

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.config import Config

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _make_env() -> SandboxedEnvironment:
    return SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
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

    common = {"name": name}

    # Network
    files[f"{name}-net.network"] = env.get_template("network.j2").render(**common)

    # Volume
    files[f"{name}-certs.volume"] = env.get_template("volume.j2").render(**common)

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
    capture_enabled = config.capture.enabled
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

    # Cage container — no published ports (traffic arrives via proxy reverse mode)
    files[f"{name}-cage.container"] = env.get_template("cage.container.j2").render(
        **common,
        image=cc.image,
        patches_host_dir=patches_host_dir,
        volumes=expanded_volumes,
        named_volumes=cc.named_volumes,
        tmpfs=cc.tmpfs,
        podman_secrets=cc.podman_secrets,
        cage_placeholders=cage_placeholders,
        env=expanded_env,
        user=cc.user,
        read_only=cc.read_only,
        security_label_disable=cc.security_label_disable,
        no_new_privileges=cc.no_new_privileges,
        drop_capabilities=cc.drop_capabilities,
        add_capabilities=cc.add_capabilities,
        memory=cc.memory,
        cpus=cc.cpus,
        command=cc.command,
        restart=cc.restart,
        restart_sec=cc.restart_sec,
        timeout_start_sec=cc.timeout_start_sec,
        timeout_stop_sec=cc.timeout_stop_sec,
        deploy_name=deploy_name,
    )

    return files
