"""Tests for the pluggable SecretStore backend resolver."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentcage.config import SecretsConfig
from agentcage.secret_store import (
    PlaintextStore,
    SecretStoreError,
    SystemdCredsStore,
    resolve_store,
)


class _Cfg:
    def __init__(self, **kw):
        self.secrets = SecretsConfig(**kw)


def _backend(monkeypatch, value):
    monkeypatch.setattr(
        "agentcage.secret_resolver.detect_default_backend", lambda: value,
    )


def test_explicit_systemd_creds_available(monkeypatch):
    _backend(monkeypatch, "systemd-creds")
    store = resolve_store(_Cfg(backend="systemd-creds"), podman=MagicMock())
    assert isinstance(store, SystemdCredsStore)


def test_explicit_systemd_creds_unavailable_raises(monkeypatch):
    _backend(monkeypatch, "podman")
    with pytest.raises(SecretStoreError):
        resolve_store(_Cfg(backend="systemd-creds"), podman=MagicMock())


def test_explicit_plaintext(monkeypatch):
    _backend(monkeypatch, "podman")
    store = resolve_store(_Cfg(backend="plaintext"), podman=MagicMock())
    assert isinstance(store, PlaintextStore)


def test_keychain_on_linux_raises(monkeypatch):
    _backend(monkeypatch, "systemd-creds")
    with pytest.raises(SecretStoreError):
        resolve_store(_Cfg(backend="keychain"), podman=MagicMock())


def test_auto_prefers_systemd_creds(monkeypatch):
    _backend(monkeypatch, "systemd-creds")
    store = resolve_store(_Cfg(backend="auto"), podman=MagicMock())
    assert isinstance(store, SystemdCredsStore)


def test_auto_fail_closed_without_encrypting_backend(monkeypatch):
    _backend(monkeypatch, "podman")
    with pytest.raises(SecretStoreError):
        resolve_store(_Cfg(backend="auto", allow_plaintext=False), podman=MagicMock())


def test_auto_allows_plaintext_when_opted_in(monkeypatch):
    _backend(monkeypatch, "podman")
    store = resolve_store(
        _Cfg(backend="auto", allow_plaintext=True), podman=MagicMock(),
    )
    assert isinstance(store, PlaintextStore)


def test_source_scheme_overrides_backend(monkeypatch):
    _backend(monkeypatch, "systemd-creds")
    # An explicit podman: source wins over the configured systemd-creds backend.
    store = resolve_store(
        _Cfg(backend="systemd-creds"), podman=MagicMock(), source_scheme="podman",
    )
    assert isinstance(store, PlaintextStore)


def test_config_rejects_invalid_backend(tmp_path):
    from agentcage.config import load_config
    p = tmp_path / "cage.yaml"
    p.write_text(
        "name: t\n"
        "container:\n  image: x:latest\n"
        "secrets:\n  backend: bogus\n"
    )
    with pytest.raises(ValueError, match="invalid secrets.backend"):
        load_config(str(p))


def test_apple_plaintext_store_roundtrip(tmp_path):
    from agentcage.secret_store import ApplePlaintextStore
    s = ApplePlaintextStore()
    s.set("c", "K", "v", state_dir=tmp_path)
    assert s.get("c", "K", state_dir=tmp_path) == "v"
    assert s.names("c", state_dir=tmp_path) == ["K"]
    s.delete("c", "K", state_dir=tmp_path)
    assert s.get("c", "K", state_dir=tmp_path) is None


def test_keychain_target_prefers_login(monkeypatch):
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    kc = ss.KeychainStore()
    monkeypatch.setattr(kc, "_writable", lambda prefix, k: prefix == [])
    assert kc._target() == ([], None)


def test_keychain_target_falls_to_system_when_login_locked(monkeypatch):
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    kc = ss.KeychainStore()
    monkeypatch.setattr(kc, "_writable", lambda prefix, k: prefix == ["sudo", "-n"])
    monkeypatch.setattr(kc, "_sudo_n_ok", lambda: True)
    assert kc._target() == (["sudo", "-n"], ss._SYSTEM_KEYCHAIN)


def test_keychain_bails_when_neither_works(monkeypatch):
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    kc = ss.KeychainStore()
    monkeypatch.setattr(kc, "_writable", lambda prefix, k: False)
    monkeypatch.setattr(kc, "_sudo_n_ok", lambda: False)
    with pytest.raises(ss.SecretStoreError):
        kc._target()
