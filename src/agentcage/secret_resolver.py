"""Resolve secrets from pluggable backends.

Supported source schemes:
  env:VAR_NAME      — read from host environment variable
  cmd:COMMAND       — run shell command, capture stdout
  systemd-creds:    — encrypted blob on disk, quadlet handles decryption
  podman:           — existing Podman secret store (explicit)
  (empty)           — existing behavior, Podman secret store
"""

from __future__ import annotations

import enum
import functools
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class ResolveAction(enum.Enum):
    RESOLVED = "resolved"
    QUADLET_HANDLED = "quadlet"
    EXISTING = "existing"


@dataclass
class ResolveResult:
    action: ResolveAction
    value: str = ""


KNOWN_SCHEMES = frozenset({"env", "cmd", "systemd-creds", "podman", ""})


def validate_source(source: str) -> None:
    """Validate source scheme at config parse time.

    Raises ValueError for unknown schemes so typos are caught early.
    """
    if not source:
        return
    scheme = source.partition(":")[0]
    if scheme not in KNOWN_SCHEMES:
        valid = ", ".join(sorted(KNOWN_SCHEMES - {""}))
        raise ValueError(
            f"unknown secret source scheme: '{scheme}'. Valid schemes: {valid}"
        )


@functools.lru_cache(maxsize=1)
def detect_default_backend() -> str:
    """Detect the best available secret backend for this platform.

    Returns "systemd-creds" only if the binary exists, systemd is 250+,
    and encryption actually works (host key or TPM2 available).
    """
    if shutil.which("systemd-creds") and _systemd_version() >= 250:
        if _systemd_creds_usable():
            return "systemd-creds"
    return "podman"


def _systemd_creds_usable() -> bool:
    """Test whether systemd-creds encrypt/decrypt actually works."""
    try:
        r = subprocess.run(
            ["systemd-creds", "encrypt", "--name", "_probe", "-", "-"],
            input="probe", text=True, capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def resolve(source: str, env_name: str, state_dir: Path) -> ResolveResult:
    """Resolve a secret value from the configured backend.

    Returns a ResolveResult indicating the action taken:
      RESOLVED        — value is in result.value, caller should create podman secret
      QUADLET_HANDLED — systemd-creds .cred file exists, quadlet handles decryption
      EXISTING        — secret is already in the Podman store
    """
    scheme, _, arg = source.partition(":")

    if scheme == "env":
        var = arg or env_name
        val = os.environ.get(var)
        if val is None:
            raise ValueError(f"env var '{var}' not set")
        return ResolveResult(ResolveAction.RESOLVED, val)

    elif scheme == "cmd":
        if not arg.strip():
            raise ValueError("cmd: source requires a command after 'cmd:'")
        try:
            r = subprocess.run(
                arg, shell=True, capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            raise ValueError(f"command timed out after 30s: {arg}")
        if r.returncode != 0:
            raise ValueError(
                f"command failed (exit {r.returncode}): {r.stderr.strip()}"
            )
        return ResolveResult(ResolveAction.RESOLVED, r.stdout.rstrip("\n"))

    elif scheme == "systemd-creds":
        cred_file = state_dir / "creds" / f"{env_name}.cred"
        if not cred_file.exists():
            raise ValueError(f"encrypted credential not found: {cred_file}")
        return ResolveResult(ResolveAction.QUADLET_HANDLED)

    elif scheme == "podman" or source == "":
        return ResolveResult(ResolveAction.EXISTING)

    else:
        raise ValueError(f"unknown secret source scheme: '{scheme}'")


def encrypt_secret(name: str, value: str, state_dir: Path) -> Path:
    """Encrypt a secret with systemd-creds and store the encrypted blob."""
    creds_dir = state_dir / "creds"
    creds_dir.mkdir(parents=True, exist_ok=True)
    out_path = creds_dir / f"{name}.cred"

    r = subprocess.run(
        ["systemd-creds", "encrypt", "--name", name, "-", str(out_path)],
        input=value, text=True, capture_output=True,
    )
    if r.returncode != 0:
        raise ValueError(
            f"systemd-creds encrypt failed: {r.stderr.strip()}"
        )
    return out_path


def _systemd_version() -> int:
    """Get the major systemd version number, or 0 if unavailable."""
    try:
        r = subprocess.run(
            ["systemctl", "--version"], capture_output=True, text=True,
        )
        # First line: "systemd 256 (256.11-1-arch)"
        return int(r.stdout.split()[1])
    except Exception:
        return 0
