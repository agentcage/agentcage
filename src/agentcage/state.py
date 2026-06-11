"""Deployment state management — track configs in ~/.config/agentcage/."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import yaml

from agentcage.config import Config, load_config

_CONFIG_DIR = Path(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
) / "agentcage"
_DEPLOYMENTS_DIR = _CONFIG_DIR / "cages"


def _deploy_dir(name: str) -> Path:
    return _DEPLOYMENTS_DIR / name


def deployment_dir(name: str) -> Path:
    """Return the state directory for a deployment."""
    return _deploy_dir(name)


def deployment_exists(name: str) -> bool:
    return (_deploy_dir(name) / "cage.yaml").is_file()


def save_deployment(name: str, config_path: str) -> None:
    """Copy a config file into the state directory for a deployment."""
    d = _deploy_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy2(config_path, d / "cage.yaml")


def remove_deployment(name: str) -> None:
    """Remove the state directory for a deployment."""
    d = _deploy_dir(name)
    if d.is_dir():
        shutil.rmtree(d)


def load_deployment_config(name: str) -> Config:
    """Load the stored config for a deployment."""
    p = _deploy_dir(name) / "cage.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"No stored config for deployment '{name}'")
    return load_config(str(p))


def stored_config_path(name: str) -> str:
    """Return the absolute path to the stored config for a deployment."""
    return str(_deploy_dir(name) / "cage.yaml")


def list_deployments() -> list[str]:
    """Return names of all deployments with stored config."""
    if not _DEPLOYMENTS_DIR.is_dir():
        return []
    return sorted(
        d.name
        for d in _DEPLOYMENTS_DIR.iterdir()
        if d.is_dir() and (d / "cage.yaml").is_file()
    )


def load_raw_config(name: str) -> dict:
    """Load stored config as raw dict (preserves all fields)."""
    p = _deploy_dir(name) / "cage.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"No stored config for cage '{name}'")
    with open(p) as f:
        return yaml.safe_load(f) or {}


def save_raw_config(name: str, raw: dict) -> None:
    """Write raw config dict back to state dir."""
    p = _deploy_dir(name) / "cage.yaml"
    with open(p, "w") as f:
        yaml.safe_dump(raw, f, default_flow_style=False, sort_keys=False)


def fill_placeholders(name: str, prev_raw: dict | None = None) -> bool:
    """Fill omitted secret-injection placeholders in a stored cage.yaml.

    Persists a generated entropic token for every rule that omits
    ``placeholder:`` (see :func:`agentcage.config.fill_raw_placeholders`).
    Returns True if the stored config was rewritten — callers must then
    reload their Config so downstream rendering sees the filled values.
    Note: rewriting goes through yaml.safe_dump and drops YAML comments;
    this only happens when at least one rule actually omits a placeholder.
    """
    from agentcage.config import fill_raw_placeholders
    raw = load_raw_config(name)
    if fill_raw_placeholders(raw, prev_raw):
        save_raw_config(name, raw)
        return True
    return False


# Keys from cage.yaml that the proxy addon actually reads
_PROXY_KEYS = frozenset({
    "domains", "secrets", "max_request_body", "entropy", "content_type",
    "inspectors", "rate_limit", "logging", "secret_injection", "capture",
    "protocol_relays",
})


_DATA_DIR = Path(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
) / "agentcage"


def capture_dir(name: str) -> Path:
    """Return (and create) ~/.local/share/agentcage/<name>/capture/."""
    d = _DATA_DIR / name / "capture"
    d.mkdir(parents=True, exist_ok=True)
    return d


def capture_file(name: str) -> Path:
    """Return path to capture.jsonl for a cage."""
    return capture_dir(name) / "capture.jsonl"


def save_metadata(name: str, metadata: dict) -> None:
    """Write metadata.json to the deployment state directory."""
    d = _deploy_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "metadata.json", "w") as f:
        json.dump(metadata, f)


def load_metadata(name: str) -> dict:
    """Read metadata.json for a deployment, returning {} if missing."""
    p = _deploy_dir(name) / "metadata.json"
    if not p.is_file():
        return {}
    with open(p) as f:
        return json.load(f)


def save_proxy_config(name: str) -> str:
    """Write a proxy-specific config subset and return its path.

    Strips container, dns_servers, name, and other keys that the proxy
    does not need, so the full config is not exposed inside the proxy container.
    """
    raw = load_raw_config(name)
    proxy_cfg = {k: v for k, v in raw.items() if k in _PROXY_KEYS}
    p = _deploy_dir(name) / "proxy-config.yaml"
    with open(p, "w") as f:
        yaml.safe_dump(proxy_cfg, f, default_flow_style=False, sort_keys=False)
    return str(p)


def dns_allowlist_path(name: str) -> Path:
    """Return the host path of the dnsmasq sidecar's allowlist file.

    The dnsmasq quadlet mounts this file read-only at
    ``/etc/dnsmasq-allow.conf`` and reads it via ``--servers-file``. Decoupling
    the allowlist from the quadlet's command line means a domain change is
    just a file rewrite — no systemd unit churn, no daemon-reload.
    """
    return _deploy_dir(name) / "dns-allowlist.conf"


def save_dns_allowlist(name: str) -> str:
    """Write the dnsmasq allowlist file for *name* from its stored cage.yaml.

    The output is dnsmasq's ``--servers-file`` format: one ``server=/<domain>/<upstream>``
    line per (allowed-domain × upstream-server) pair. dnsmasq treats this as
    a partial config, additive to anything in the main quadlet command line,
    and re-reads it on container start (or SIGHUP). Returns the path written.

    Idempotent. Cheap. Always safe to call. Empty when the cage isn't in
    allowlist mode — dnsmasq is fine with an empty file.
    """
    from agentcage.quadlets import _effective_dns_allowlist
    cfg = load_deployment_config(name)
    p = dns_allowlist_path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"server=/{domain}/{srv}"
        for domain in _effective_dns_allowlist(cfg)
        for srv in cfg.dns_servers
    ]
    p.write_text("\n".join(lines) + ("\n" if lines else ""))
    return str(p)
