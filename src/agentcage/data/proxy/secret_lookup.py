"""Credential lookup shared by the egress's protocol relays.

The egress receives secret values through up to three channels, and the
order they are consulted in decides which one wins:

1. ``$AGENTCAGE_SECRETS_DIR/<NAME>`` (default ``/home/acproxy/secrets``),
   the staged tmpfs file. The egress ExecStartPre stages it and
   ``agentcage secret set`` re-writes it live; on apple-container it is the
   ONLY channel (no quadlet env-secret primitive). The process env is frozen
   at container creation, so only this file can carry a value change.
2. ``$XDG_RUNTIME_DIR/<NAME>`` (default ``/run``).
3. The process env (the Podman Secret ``type=env`` channel).

An EXISTING file is authoritative, with its trailing newline stripped (file
delivery writes one). An existing-but-EMPTY file is a tombstone (``secret
rm`` / failed staging of a deleted store entry): the value is "" and the
lookup does not fall back to a stale env value. Only a MISSING file moves
on to the next channel. This is the injector's staged-file contract
(``secret_injector.py``) with the Policy API's ``$XDG_RUNTIME_DIR`` step.

Stdlib only — the proxy image installs nothing beyond pyyaml and
cryptography, and the relays import it by bare name.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("agentcage.secret_lookup")

# Every scheme the host accepts for a relay ``*_source``. The host validates
# the scheme and arranges delivery; by the time the egress runs, every one
# of them has landed in a channel above under NAME, so only NAME is used
# here.
_SOURCE_SCHEMES = ("env", "cmd", "systemd-creds", "podman", "")


def _search_dirs() -> tuple[Path, Path]:
    # Read per call rather than at import, so a relay started after the env
    # is (re)configured — and the tests — see the current values.
    staged = os.environ.get("AGENTCAGE_SECRETS_DIR") or "/home/acproxy/secrets"
    runtime = os.environ.get("XDG_RUNTIME_DIR") or "/run"
    return Path(staged), Path(runtime)


def read_secret(name: str) -> str:
    """Resolve secret ``name``: staged file → ``$XDG_RUNTIME_DIR`` → env.

    Returns "" when unset or tombstoned; callers fail closed on "".
    """
    if not name:
        return ""
    for directory in _search_dirs():
        path = directory / name
        try:
            if not path.is_file():
                continue
            return path.read_text().rstrip("\n")
        except OSError as e:
            # Present but unreadable (or un-stat-able): treat it like the
            # injector does (staged, no value) rather than silently
            # falling through to an older channel.
            log.warning("secret_lookup: failed reading %s: %s", path, e)
            return ""
    return os.environ.get(name, "")


def resolve_credential(source: str) -> str:
    """Read a relay ``auth.*_source`` (``scheme:NAME``) at relay startup."""
    scheme, _, arg = (source or "").partition(":")
    if scheme in _SOURCE_SCHEMES:
        return read_secret(arg)
    raise ValueError(f"unsupported relay credential source: {source!r}")
