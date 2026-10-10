"""The egress's one secret lookup.

Every egress consumer of a secret value resolves it here: the secret
injector (``secret_injector.py``), the Policy API's decider key and the
traffic watcher's key (``policy_api.py`` ``_read_secret``), and the protocol
relays' credentials (``resolve_credential``). One chain, so a value change,
a tombstone or a delivery channel behaves the same for all of them.

The egress receives secret values through two channels, consulted in this
order:

1. ``$AGENTCAGE_SECRETS_DIR/<NAME>`` (default ``/home/acproxy/secrets``),
   the staged tmpfs file. The egress ExecStartPre stages it and
   ``agentcage secret set`` re-writes it live; on apple-container it is the
   ONLY channel (no quadlet env-secret primitive). The process env is frozen
   at container creation, so only this file can carry a value change.
2. The process env (the Podman Secret ``type=env`` channel).

There is deliberately no ``$XDG_RUNTIME_DIR/<NAME>`` step (the Policy API
had one from its first commit, and this helper inherited it): nothing
delivers secrets there, and the egress has no ``XDG_RUNTIME_DIR`` set, so
the step only ever read ``/run/<NAME>`` — a secret name colliding with a
pid file, a lock or a runtime dir under the egress's ``/run`` would have
been used as the credential.

An EXISTING file is authoritative, with its trailing newline(s) stripped
(file delivery writes one) and nothing else: the host already trims trailing
newlines off ``cmd:`` output and ``secret set`` input and keeps every other
byte, so any other whitespace is part of the value. An env value is used
verbatim. An existing-but-EMPTY file is a tombstone (``secret rm`` / failed
staging of a deleted store entry): the value is "" and the lookup does not
fall back to a stale env value. Only a MISSING file moves on to the env.
An existing but unreadable file is "" too (fail closed).

The staged directory is read per call, never cached at import.

Stdlib only — the proxy image installs nothing beyond pyyaml and
cryptography, and every consumer imports it by bare name.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("agentcage.secret_lookup")

# Every scheme the host accepts for a relay ``*_source``. The host validates
# the scheme and arranges delivery; by the time the egress runs, every one
# of them has landed in one of the two channels above under NAME, so only NAME is used
# here.
_SOURCE_SCHEMES = ("env", "cmd", "systemd-creds", "podman", "")


def _secrets_dir() -> Path:
    # Read per call rather than at import, so a consumer (re)configured
    # after the env changes — the injector on every live-apply reload, a
    # relay at startup, and the tests — sees the current value.
    return Path(os.environ.get("AGENTCAGE_SECRETS_DIR") or "/home/acproxy/secrets")


def read_secret(name: str) -> str:
    """Resolve secret ``name``: staged file → env.

    Returns "" when unset or tombstoned; callers fail closed on "".
    """
    if not name:
        return ""
    path = _secrets_dir() / name
    try:
        if path.is_file():
            return path.read_text().rstrip("\n")
    except OSError as e:
        # Present but unreadable (or un-stat-able): staged, no value —
        # never a silent fall-through to the stale env channel.
        log.warning("secret_lookup: failed reading %s: %s", path, e)
        return ""
    return os.environ.get(name, "")


def resolve_credential(source: str) -> str:
    """Read a relay ``auth.*_source`` (``scheme:NAME``) at relay startup."""
    scheme, _, arg = (source or "").partition(":")
    if scheme in _SOURCE_SCHEMES:
        return read_secret(arg)
    raise ValueError(f"unsupported relay credential source: {source!r}")
