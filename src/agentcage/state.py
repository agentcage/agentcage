"""Deployment state management — track configs in ~/.config/agentcage/."""

from __future__ import annotations

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


def deployment_exists(name: str) -> bool:
    return (_deploy_dir(name) / "config.yaml").is_file()


def save_deployment(name: str, config_path: str) -> None:
    """Copy a config file into the state directory for a deployment."""
    d = _deploy_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy2(config_path, d / "config.yaml")


def remove_deployment(name: str) -> None:
    """Remove the state directory for a deployment."""
    d = _deploy_dir(name)
    if d.is_dir():
        shutil.rmtree(d)


def load_deployment_config(name: str) -> Config:
    """Load the stored config for a deployment."""
    p = _deploy_dir(name) / "config.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"No stored config for deployment '{name}'")
    return load_config(str(p))


def stored_config_path(name: str) -> str:
    """Return the absolute path to the stored config for a deployment."""
    return str(_deploy_dir(name) / "config.yaml")


def list_deployments() -> list[str]:
    """Return names of all deployments with stored config."""
    if not _DEPLOYMENTS_DIR.is_dir():
        return []
    return sorted(
        d.name
        for d in _DEPLOYMENTS_DIR.iterdir()
        if d.is_dir() and (d / "config.yaml").is_file()
    )


def load_raw_config(name: str) -> dict:
    """Load stored config as raw dict (preserves all fields)."""
    p = _deploy_dir(name) / "config.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"No stored config for cage '{name}'")
    with open(p) as f:
        return yaml.safe_load(f) or {}


def save_raw_config(name: str, raw: dict) -> None:
    """Write raw config dict back to state dir."""
    p = _deploy_dir(name) / "config.yaml"
    with open(p, "w") as f:
        yaml.safe_dump(raw, f, default_flow_style=False, sort_keys=False)


# Keys from config.yaml that the proxy addon actually reads
_PROXY_KEYS = frozenset({
    "domains", "secrets", "max_request_body", "entropy", "content_type",
    "inspectors", "rate_limit", "logging", "secret_injection",
})


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
