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
import re
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

# Standard POSIX env-var identifier. Also shell-safe: no metacharacters
# can appear, so the value can be interpolated into quadlet ExecStartPre
# bash commands without injection risk.
_ENV_NAME_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")


def validate_env_name(env_name: str) -> None:
    """Validate that an env name is a safe identifier.

    Raises ValueError if the name contains anything outside the standard
    POSIX env-var character set. This prevents shell injection when the
    name is interpolated into generated quadlet ExecStartPre commands.
    """
    if not env_name:
        raise ValueError("secret_injection rule requires a non-empty env name")
    if not _ENV_NAME_RE.match(env_name):
        raise ValueError(
            f"invalid env name: {env_name!r}. Must match [A-Za-z_][A-Za-z0-9_]*"
        )


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
    and encryption actually works (host key, TPM2, or per-user key).
    """
    if shutil.which("systemd-creds") and _systemd_version() >= 250:
        if detect_default_scope() is not None:
            return "systemd-creds"
    return "podman"


@functools.lru_cache(maxsize=1)
def detect_default_scope() -> str | None:
    """Pick the encryption scope to use when secrets.scope=auto.

    Prefers "user" when the invoker is non-root and user-scoped encryption
    works (no polkit prompt routed to the desktop user). Falls back to
    "system" when only the host key is available. Returns None when no
    scope works.
    """
    non_root = os.geteuid() != 0 if hasattr(os, "geteuid") else True
    if non_root and _systemd_creds_works("user"):
        return "user"
    if _systemd_creds_works("system"):
        return "system"
    return None


@functools.lru_cache(maxsize=2)
def _systemd_creds_works(scope: str) -> bool:
    """Test whether systemd-creds encrypt works for the given scope."""
    cmd = ["systemd-creds"]
    if scope == "user":
        cmd.append("--user")
    cmd += ["encrypt", "--name", "_probe", "-", "-"]
    try:
        r = subprocess.run(
            cmd, input="probe", text=True, capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _systemd_creds_usable() -> bool:
    """Back-compat shim: True if any scope works."""
    return detect_default_scope() is not None


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


def resolve_and_populate(podman, cfg, deploy_name: str, state_dir: Path,
                         skip_keys: set[str] | None = None,
                         strict: bool = True) -> set[str]:
    """Resolve env:/cmd:/systemd-creds: sources into Podman secrets.

    Returns the set of env names that were resolved (caller should add
    these to provided_keys so they survive the rule-strip filter).

    ``strict=True`` (default): raise ValueError on resolution failure so
    callers like ``cage create`` / ``cage start`` abort before the
    systemd unit is launched with a missing secret. ``strict=False``:
    print warnings and continue — useful for ``agentcage run`` which
    has its own error handling and may want a best-effort attempt.
    """
    import click

    skip = skip_keys or set()
    resolved: set[str] = set()
    for rule in cfg.secret_injection:
        source = rule.source or ""
        if not source or rule.env in skip:
            continue
        try:
            result = resolve(source, rule.env, state_dir)
        except ValueError as e:
            if strict:
                raise ValueError(
                    f"failed to resolve secret '{rule.env}': {e}"
                ) from e
            click.echo(f"warning: failed to resolve {rule.env}: {e}", err=True)
            continue
        if result.action == ResolveAction.RESOLVED:
            full = f"{deploy_name}.{rule.env}"
            if podman.secret_exists(full):
                podman.secret_remove(full)
            podman.secret_create(full, result.value)
            resolved.add(rule.env)
        elif result.action == ResolveAction.QUADLET_HANDLED:
            resolved.add(rule.env)
    return resolved


def resolve_scope(configured: str) -> str:
    """Resolve a configured scope ("auto"/"user"/"system") to a concrete one.

    "auto" picks "user" when the invoker is non-root and user-scoped
    encryption works, otherwise "system". Explicit values pass through.
    Raises ValueError if no usable scope is found in auto mode.
    """
    if configured in ("user", "system"):
        return configured
    if configured != "auto":
        raise ValueError(f"invalid secrets.scope: {configured!r}")
    detected = detect_default_scope()
    if detected is None:
        raise ValueError(
            "systemd-creds encryption is not usable in either user or "
            "system scope on this host"
        )
    return detected


def encrypt_secret(
    name: str, value: str, state_dir: Path, scope: str = "system",
) -> Path:
    """Encrypt a secret with systemd-creds and store the encrypted blob.

    ``scope="user"`` uses the per-user key (no polkit prompt — required
    for service users on hosts with an active graphical session).
    ``scope="system"`` uses the host key / TPM2.

    Uses a 30s timeout because TPM2 operations can occasionally block
    on hardware (slow TPM chip, contention with another process).
    """
    if scope not in ("user", "system"):
        raise ValueError(f"invalid scope: {scope!r}")
    creds_dir = state_dir / "creds"
    creds_dir.mkdir(parents=True, exist_ok=True)
    out_path = creds_dir / f"{name}.cred"

    cmd = ["systemd-creds"]
    if scope == "user":
        cmd.append("--user")
    cmd += ["encrypt", "--name", name, "-", str(out_path)]

    try:
        r = subprocess.run(
            cmd, input=value, text=True, capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise ValueError(
            "systemd-creds encrypt timed out after 30s "
            "(TPM2 may be unavailable or contended)"
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
