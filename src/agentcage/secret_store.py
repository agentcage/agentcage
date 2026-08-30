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

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

#: macOS System keychain — root-owned, unlocked at boot, headless-capable.
_SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
#: keychain service namespace for all agentcage secrets.
_KEYCHAIN_SERVICE = "agentcage"


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

    def names(self, cage: str, *, state_dir: Path) -> list[str]:
        """Names of secrets currently stored for *cage*."""
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


def _security_interaction_blocked(stderr: str) -> bool:
    return "interaction is not allowed" in (stderr or "").lower()


class KeychainStore(SecretStore):
    """macOS: store secrets in a keychain, encrypted at rest.

    Target selection (per the operator's requested policy):
      1. the **login keychain** if it's accessible (an unlocked GUI session) —
         no sudo, per-user, the strongest option;
      2. else the **System keychain** *only if passwordless sudo already works*
         (``sudo -n``) — boot-unlocked, headless, host-key encrypted;
      3. else **bail** (fail-closed) — never prompts for sudo.

    A non-secret name index (``<state>/secret_keys.json``) records which keys
    exist, since the `security` CLI can't enumerate by service/account.
    """

    name = "keychain"
    runtime_decrypts = False  # agentcage retrieves + materializes at start

    def __init__(self) -> None:
        self._target_cache: Optional[tuple] = None

    @staticmethod
    def _account(cage: str, key: str) -> str:
        return f"{cage}.{key}"

    @staticmethod
    def _writable(prefix: list, kc: Optional[str]) -> bool:
        """Probe real write-ability: add a throwaway item, then delete it.

        A read probe is insufficient — the login keychain answers reads over
        headless SSH but refuses writes ("interaction not allowed"). Only an
        actual add reflects whether secrets can be stored here.
        """
        acct = "__agentcage_probe__"
        kc_arg = [kc] if kc else []
        add = subprocess.run(
            prefix + ["security", "add-generic-password",
                      "-s", _KEYCHAIN_SERVICE, "-a", acct, "-w", "x", "-U"]
            + kc_arg,
            capture_output=True, text=True,
        )
        if add.returncode != 0:
            return False
        subprocess.run(
            prefix + ["security", "delete-generic-password",
                      "-s", _KEYCHAIN_SERVICE, "-a", acct] + kc_arg,
            capture_output=True, text=True,
        )
        return True

    def _target(self) -> tuple:
        """Return (sudo_prefix, keychain_path_or_None), or raise.

        The System-keychain probe runs ``sudo -n security …`` directly, so a
        narrow ``NOPASSWD: /usr/bin/security`` sudoers rule (the recommended
        headless setup) is enough — we don't require blanket passwordless sudo.
        """
        if self._target_cache is not None:
            return self._target_cache
        if sys.platform != "darwin":
            raise SecretStoreError("keychain backend is macOS-only")
        if self._writable([], None):
            self._target_cache = ([], None)            # login keychain
        elif self._writable(["sudo", "-n"], _SYSTEM_KEYCHAIN):
            self._target_cache = (["sudo", "-n"], _SYSTEM_KEYCHAIN)
        else:
            raise SecretStoreError(
                "macOS keychain unavailable: the login keychain is locked "
                "(no unlocked GUI session) and passwordless sudo for the "
                "System keychain is not configured. Log into the Mac's GUI, "
                "set up NOPASSWD sudo for /usr/bin/security, or set "
                "secrets.allow_plaintext."
            )
        return self._target_cache

    def available(self) -> bool:
        try:
            self._target()
            return True
        except SecretStoreError:
            return False

    def set(self, cage: str, key: str, value: str, *, state_dir: Path) -> None:
        prefix, kc = self._target()
        argv = prefix + [
            "security", "add-generic-password",
            "-s", _KEYCHAIN_SERVICE, "-a", self._account(cage, key),
            "-w", value, "-U",
        ]
        if kc:
            argv.append(kc)
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            raise SecretStoreError(f"keychain add failed: {r.stderr.strip()}")
        self._index_add(state_dir, key)

    def get(self, cage: str, key: str, *, state_dir: Path) -> Optional[str]:
        prefix, kc = self._target()
        argv = prefix + [
            "security", "find-generic-password",
            "-s", _KEYCHAIN_SERVICE, "-a", self._account(cage, key), "-w",
        ]
        if kc:
            argv.append(kc)
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            return None
        return r.stdout.rstrip("\n")

    def delete(self, cage: str, key: str, *, state_dir: Path) -> None:
        prefix, kc = self._target()
        argv = prefix + [
            "security", "delete-generic-password",
            "-s", _KEYCHAIN_SERVICE, "-a", self._account(cage, key),
        ]
        if kc:
            argv.append(kc)
        subprocess.run(argv, capture_output=True, text=True)
        self._index_remove(state_dir, key)

    # ── non-secret name index ──────────────────────────────
    @staticmethod
    def _index_path(state_dir: Path) -> Path:
        return state_dir / "secret_keys.json"

    def names(self, cage: str, *, state_dir: Path) -> list[str]:
        p = self._index_path(state_dir)
        if not p.is_file():
            return []
        try:
            return list(json.loads(p.read_text()))
        except Exception:
            return []

    def _index_add(self, state_dir: Path, key: str) -> None:
        keys = [k for k in self.names("", state_dir=state_dir) if k != key]
        keys.append(key)
        self._index_path(state_dir).write_text(json.dumps(sorted(keys)))

    def _index_remove(self, state_dir: Path, key: str) -> None:
        keys = [k for k in self.names("", state_dir=state_dir) if k != key]
        self._index_path(state_dir).write_text(json.dumps(sorted(keys)))


class ApplePlaintextStore(SecretStore):
    """macOS opt-in cleartext: the legacy ``pending_secrets.json`` (0600)."""

    name = "plaintext"
    runtime_decrypts = False

    @staticmethod
    def _path(state_dir: Path) -> Path:
        return state_dir / "pending_secrets.json"

    def _load(self, state_dir: Path) -> dict:
        p = self._path(state_dir)
        if not p.is_file():
            return {}
        try:
            return {k: v for k, v in json.loads(p.read_text())}
        except Exception:
            return {}

    def _save(self, state_dir: Path, pairs: dict) -> None:
        import os
        p = self._path(state_dir)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps([[k, v] for k, v in pairs.items()]).encode())
        finally:
            os.close(fd)

    def available(self) -> bool:
        return True

    def set(self, cage: str, key: str, value: str, *, state_dir: Path) -> None:
        pairs = self._load(state_dir)
        pairs[key] = value
        self._save(state_dir, pairs)

    def get(self, cage: str, key: str, *, state_dir: Path) -> Optional[str]:
        return self._load(state_dir).get(key)

    def delete(self, cage: str, key: str, *, state_dir: Path) -> None:
        pairs = self._load(state_dir)
        pairs.pop(key, None)
        self._save(state_dir, pairs)

    def names(self, cage: str, *, state_dir: Path) -> list[str]:
        return sorted(self._load(state_dir).keys())


# Backend names valid in cage.yaml ``secrets.backend``.
KNOWN_BACKENDS = frozenset({
    "auto", "systemd-creds", "keychain", "plaintext",
})


def plaintext_store_for(cfg, podman=None) -> SecretStore:
    """The platform's explicit-opt-in cleartext store."""
    if getattr(cfg, "isolation", "") == "apple-container":
        return ApplePlaintextStore()
    return PlaintextStore(podman)


def resolve_store(cfg, *, podman=None, source_scheme: str = "") -> SecretStore:
    """Pick the secret store for *cfg* (fail-closed).

    Honors an explicit per-rule ``source:`` scheme first (``systemd-creds:`` /
    ``podman:``), then ``cfg.secrets.backend``. ``auto`` resolves to the best
    encrypting backend for the platform; if none is available it raises unless
    ``secrets.allow_plaintext`` is set (then plaintext), so cleartext is never
    a silent default.
    """
    sec = cfg.secrets
    allow_plaintext = bool(getattr(sec, "allow_plaintext", False))
    is_apple = getattr(cfg, "isolation", "") == "apple-container"
    # A vm cage on a macOS host stores its secrets on the HOST (that is
    # where `secret set` runs); systemd-creds lives in the guest and is
    # not reachable from here, so `auto` would find no encrypting backend
    # and refuse every `secret set` — which made domains.auto, whose
    # decider api_key is mandatory, unusable on a Mac without opting into
    # plaintext. The keychain is the host's encrypting store; the vm
    # backend bridges the value into the guest at deploy time.
    host_keychain = is_apple or (
        getattr(cfg, "isolation", "") == "vm" and sys.platform == "darwin"
    )

    # Platform-appropriate stores.
    plaintext = ApplePlaintextStore() if is_apple else PlaintextStore(podman)

    def encrypting():
        return KeychainStore() if host_keychain else SystemdCredsStore(
            scope=sec.scope, podman=podman)

    # Explicit per-rule scheme wins (container/vm only).
    if source_scheme == "podman":
        return plaintext
    if source_scheme == "systemd-creds":
        return SystemdCredsStore(scope=sec.scope, podman=podman)

    backend = getattr(sec, "backend", "auto") or "auto"

    if backend == "plaintext":
        return plaintext
    if backend == "systemd-creds":
        store = SystemdCredsStore(scope=sec.scope, podman=podman)
        if not store.available():
            raise SecretStoreError(
                "secrets.backend is 'systemd-creds' but systemd-creds "
                "encryption is not usable on this host"
            )
        return store
    if backend == "keychain":
        store = KeychainStore()
        if not store.available():
            raise SecretStoreError(
                "secrets.backend 'keychain' requires macOS with an unlocked "
                "login keychain or passwordless sudo for the System keychain"
            )
        return store

    # auto: prefer the platform's encrypting backend; fail-closed otherwise.
    enc = encrypting()
    if enc.available():
        return enc
    if allow_plaintext:
        return plaintext
    raise SecretStoreError(
        "no encrypting secret backend is available and "
        "secrets.allow_plaintext is not set"
    )
