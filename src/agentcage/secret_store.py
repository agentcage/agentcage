"""Pluggable at-rest secret storage backends.

Selected via the cage.yaml ``secrets.backend`` field:

  ``auto``            — best available for the platform (Linux: systemd-creds;
                        macOS: system-keychain — added in a follow-up).
  ``systemd-creds``   — Linux: an encrypted ``.cred`` blob the systemd Quadlet
                        decrypts at unit start (TPM2 / host / per-user key).
  ``system-keychain`` — macOS: the System keychain (host-key, boot-unlocked,
                        headless). Added in the macOS follow-up.
  ``plaintext``       — the unencrypted podman secret store. Only reachable via
                        an explicit opt-in (``backend: plaintext`` or
                        ``secrets.allow_plaintext: true``).

Every backend encrypts at rest EXCEPT ``plaintext``. The resolver is
fail-closed: if no encrypting backend is available and the operator hasn't
opted into plaintext, resolution raises rather than silently storing cleartext.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


class SecretStoreError(Exception):
    """Raised when a backend is unavailable or an operation fails."""


class SecretStore:
    """A place to keep a cage's secrets encrypted at rest.

    Subclasses implement the small management surface used by
    ``secret set`` / ``secret rm`` / ``secret list`` and the deploy paths.
    """

    #: stable identifier used in cage.yaml ``secrets.backend``
    name: str = "base"
    #: True when the cage runtime decrypts the secret itself (e.g. the systemd
    #: Quadlet via ``LoadCredentialEncrypted``); False when agentcage must
    #: retrieve and deliver the value at deploy time.
    runtime_decrypts: bool = False

    def available(self) -> bool:
        raise NotImplementedError

    def set(self, cage: str, key: str, value: str, *,
            state_dir: Path) -> None:
        raise NotImplementedError

    def delete(self, cage: str, key: str, *, state_dir: Path) -> None:
        raise NotImplementedError

    def get(self, cage: str, key: str, *, state_dir: Path) -> Optional[str]:
        """Return the cleartext value, or None. Backends whose runtime
        decrypts (systemd-creds) need not implement retrieval."""
        raise SecretStoreError(
            f"backend {self.name!r} does not support value retrieval"
        )


class SystemdCredsStore(SecretStore):
    """Linux: encrypt to ``<state>/creds/<key>.cred`` (Quadlet decrypts)."""

    name = "systemd-creds"
    runtime_decrypts = True

    def __init__(self, scope: str = "auto", podman=None) -> None:
        self._scope = scope
        self._podman = podman

    def available(self) -> bool:
        from agentcage.secret_resolver import detect_default_backend
        return detect_default_backend() == "systemd-creds"

    def set(self, cage: str, key: str, value: str, *, state_dir: Path) -> None:
        from agentcage.secret_resolver import encrypt_secret, resolve_scope
        scope = resolve_scope(self._scope)
        encrypt_secret(key, value, state_dir, scope=scope)
        # Drop any stale podman secret of the same name — the Quadlet's
        # ExecStartPre repopulates it from the encrypted blob at start.
        full = f"{cage}.{key}"
        if self._podman is not None and self._podman.secret_exists(full):
            self._podman.secret_remove(full)

    def delete(self, cage: str, key: str, *, state_dir: Path) -> None:
        cred = state_dir / "creds" / f"{key}.cred"
        cred.unlink(missing_ok=True)
        full = f"{cage}.{key}"
        if self._podman is not None and self._podman.secret_exists(full):
            self._podman.secret_remove(full)


class PlaintextStore(SecretStore):
    """Unencrypted podman secret store. Explicit opt-in only."""

    name = "plaintext"
    runtime_decrypts = True  # value already lives in the podman store

    def __init__(self, podman) -> None:
        self._podman = podman

    def available(self) -> bool:
        return self._podman is not None

    def set(self, cage: str, key: str, value: str, *, state_dir: Path) -> None:
        full = f"{cage}.{key}"
        if self._podman.secret_exists(full):
            self._podman.secret_remove(full)
        self._podman.secret_create(full, value)

    def delete(self, cage: str, key: str, *, state_dir: Path) -> None:
        full = f"{cage}.{key}"
        if self._podman.secret_exists(full):
            self._podman.secret_remove(full)

    def get(self, cage: str, key: str, *, state_dir: Path) -> Optional[str]:
        full = f"{cage}.{key}"
        if not self._podman.secret_exists(full):
            return None
        return self._podman.secret_read(full)


# Backend names valid in cage.yaml ``secrets.backend``.
KNOWN_BACKENDS = frozenset({
    "auto", "systemd-creds", "system-keychain", "plaintext",
})


def resolve_store(cfg, *, podman=None, source_scheme: str = "") -> SecretStore:
    """Pick the secret store for *cfg* (fail-closed).

    Honors an explicit per-rule ``source:`` scheme first (``systemd-creds:`` /
    ``podman:``), then ``cfg.secrets.backend``. ``auto`` resolves to the best
    encrypting backend for the platform; if none is available it raises unless
    ``secrets.allow_plaintext`` is set (then plaintext), so cleartext is never
    a silent default.
    """
    import sys as _sys

    sec = cfg.secrets
    allow_plaintext = bool(getattr(sec, "allow_plaintext", False))

    # Explicit per-rule scheme wins.
    if source_scheme == "podman":
        return PlaintextStore(podman)
    if source_scheme == "systemd-creds":
        return SystemdCredsStore(scope=sec.scope, podman=podman)

    backend = getattr(sec, "backend", "auto") or "auto"

    if backend == "systemd-creds":
        store = SystemdCredsStore(scope=sec.scope, podman=podman)
        if not store.available():
            raise SecretStoreError(
                "secrets.backend is 'systemd-creds' but systemd-creds "
                "encryption is not usable on this host"
            )
        return store
    if backend == "plaintext":
        return PlaintextStore(podman)
    if backend == "system-keychain":
        raise SecretStoreError(
            "secrets.backend 'system-keychain' is only available on macOS "
            "(apple-container)"
        )

    # auto: prefer an encrypting backend; fail-closed otherwise.
    if _sys.platform == "linux":
        creds = SystemdCredsStore(scope=sec.scope, podman=podman)
        if creds.available():
            return creds
    if allow_plaintext:
        return PlaintextStore(podman)
    raise SecretStoreError(
        "no encrypting secret backend is available (systemd-creds unusable) "
        "and secrets.allow_plaintext is not set"
    )
