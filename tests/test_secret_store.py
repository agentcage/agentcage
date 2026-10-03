"""Tests for the pluggable SecretStore backend resolver."""

from __future__ import annotations

import platform
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agentcage.config import SecretsConfig

LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="asserts keychain is unavailable on Linux; on macOS the keychain "
           "backend resolves (covered by the keychain-target tests)",
)
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


@LINUX_ONLY
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
    assert kc._target() == (["sudo", "-n"], ss._SYSTEM_KEYCHAIN)


def test_keychain_bails_when_neither_works(monkeypatch):
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    kc = ss.KeychainStore()
    monkeypatch.setattr(kc, "_writable", lambda prefix, k: False)
    with pytest.raises(ss.SecretStoreError):
        kc._target()


# --- The keychain write channel ---------------------------------------
#
# `KeychainStore.set` used to pass the cleartext as `security
# add-generic-password … -w <VALUE> -U`, where `ps -axww` could read it
# for the life of the child. It was the only place in agentcage where
# secret material travelled in argv. These pin the fix: the command
# line goes on `security -i`'s stdin, and the value is in no argv at
# all. The Rust side asserts the same shape in
# `rust/agentcage-exec/tests/tool_argv.rs` and
# `rust/agentcage-cli/tests/secrets_argv.rs`; the round trip against a
# real keychain is `rust/agentcage-exec/tests/keychain_stdin_probe.rs`.

_CANARY = "TEST-NOT-A-REAL-SECRET-hunter2"


def _record_security(monkeypatch):
    """Capture every `security` invocation's argv and stdin."""
    from agentcage import secret_store as ss

    calls = []

    def fake_run(argv, **kw):
        calls.append((list(argv), kw.get("input")))
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ss.subprocess, "run", fake_run)
    return calls


def test_keychain_set_puts_the_cleartext_on_stdin_not_argv(monkeypatch, tmp_path):
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    calls = _record_security(monkeypatch)

    kc = ss.KeychainStore()
    kc.set("acme", "API_KEY", _CANARY, state_dir=tmp_path)

    # probe add, probe delete, the real add.
    argv, stdin = calls[-1]
    assert argv == ["security", "-i"]
    assert stdin == (
        "add-generic-password -s agentcage -a 'acme.API_KEY' "
        f"-w '{_CANARY}' -U\n"
    )
    # Not in any argv, in any call — including the write probe.
    assert not any(_CANARY in arg for a, _ in calls for arg in a)
    assert kc.names("acme", state_dir=tmp_path) == ["API_KEY"]


def test_keychain_write_probe_uses_the_same_channel_as_set(monkeypatch):
    """Otherwise `available()` could pass on a shape `set` never uses."""
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    calls = _record_security(monkeypatch)

    assert ss.KeychainStore().available()
    assert calls[0] == (
        ["security", "-i"],
        "add-generic-password -s agentcage -a '__agentcage_probe__' -w 'x' -U\n",
    )
    assert calls[1][0][:2] == ["security", "delete-generic-password"]


def test_keychain_system_target_keeps_the_path_last_on_stdin(monkeypatch, tmp_path):
    """The ordering bug, in its new hiding place: `security -i` splits
    the line and hands it to the same handler, so a keychain path that
    is not last is still stored as the password."""
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    calls = _record_security(monkeypatch)
    kc = ss.KeychainStore()
    monkeypatch.setattr(kc, "_writable", lambda prefix, k: prefix == ["sudo", "-n"])

    kc.set("acme", "API_KEY", _CANARY, state_dir=tmp_path)

    argv, stdin = calls[-1]
    assert argv == ["sudo", "-n", "security", "-i"]
    assert stdin.rstrip("\n").endswith(f"-U '{ss._SYSTEM_KEYCHAIN}'")


@pytest.mark.parametrize("value, needle", [
    ("two\nlines", "line terminator"),
    ("carriage\rreturn", "line terminator"),
    ("x" * 5000, "too long"),
])
def test_keychain_refuses_a_value_it_would_corrupt(monkeypatch, tmp_path, value, needle):
    """`security -i`'s reader is line-oriented with a 4096-byte buffer,
    and in both cases the remainder is parsed as the *next* command —
    storing the wrong bytes and echoing a fragment of the secret to
    stderr. Refuse rather than truncate."""
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    calls = _record_security(monkeypatch)

    with pytest.raises(ss.SecretStoreError) as e:
        ss.KeychainStore().set("acme", "API_KEY", value, state_dir=tmp_path)
    assert needle in str(e.value)
    # The two probes ran; the add did not.
    assert len(calls) == 2
    assert not any(value in arg for a, _ in calls for arg in a)


def test_keychain_quoting_matches_securitys_own_splitter(monkeypatch):
    """Not `shlex.quote`: SecurityTool's `split_line` treats a backslash
    as an escape *inside* single quotes, where a POSIX shell does not.
    Verified by round trip against a real keychain — see the probe."""
    from agentcage import secret_store as ss
    assert ss.KeychainStore._quote("plain") == "'plain'"
    assert ss.KeychainStore._quote("a'b") == r"'a\'b'"
    assert ss.KeychainStore._quote("a\\b") == r"'a\\b'"
    assert ss.KeychainStore._quote('a"b') == "'a\"b'"


# --- at_rest_store: the predicate three commands depend on ------------
#
# `runtime_decrypts` was documentation before it decided anything.
# `secret rm`, `cage destroy` and `cage backup --include-secrets` all
# assumed the container backend's shape, where the runtime copy *is*
# the value — and all three were wrong on a vm cage on a Mac, where the
# value is in the login keychain. These pin the predicate.

def _cfg(isolation, backend="auto", allow_plaintext=False):
    class C:
        pass
    c = C()
    c.isolation = isolation
    c.secrets = SecretsConfig(
        backend=backend, allow_plaintext=allow_plaintext, scope="auto",
    )
    return c


def test_at_rest_store_is_the_keychain_for_a_mac_vm_cage(monkeypatch):
    """The bug's cage. `auto` on a Mac vm cage resolves to the login
    keychain, which neither the podman removal nor the .cred removal in
    `secret rm` touches."""
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    monkeypatch.setattr(ss.KeychainStore, "available", lambda self: True)
    for isolation in ("vm", "apple-container"):
        store = ss.at_rest_store(_cfg(isolation))
        assert isinstance(store, ss.KeychainStore), isolation
        assert store.runtime_decrypts is False


@pytest.mark.parametrize("isolation, backend, allow, why", [
    ("container", "plaintext", True, "the podman store"),
    ("vm", "plaintext", True, "the podman store"),
])
def test_at_rest_store_is_none_when_the_runtime_holds_the_value(
    monkeypatch, isolation, backend, allow, why,
):
    """A store whose runtime already holds the value needs nothing
    extra: removing the runtime copy removes the value. Answering
    otherwise would make `secret rm` delete twice and `cage backup`
    resolve a store for nothing."""
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "darwin")
    assert ss.at_rest_store(_cfg(isolation, backend, allow), podman=MagicMock()) is None


def test_at_rest_store_is_none_when_nothing_resolves(monkeypatch):
    """`auto` with no encrypting backend and no plaintext opt-in refuses,
    which is the fail-closed behaviour `secret set` wants. Callers use
    this helper to do strictly *more* cleanup, so a refusal has to leave
    them where they were rather than failing a removal."""
    from agentcage import secret_store as ss
    monkeypatch.setattr(ss.sys, "platform", "linux")
    monkeypatch.setattr(
        "agentcage.secret_resolver.detect_default_backend", lambda: None,
    )
    with pytest.raises(ss.SecretStoreError):
        ss.resolve_store(_cfg("container"))
    assert ss.at_rest_store(_cfg("container")) is None


def test_at_rest_names_tolerates_a_store_without_names(monkeypatch):
    """`names` is optional in the SecretStore surface — SystemdCredsStore
    and PlaintextStore do not implement it, so the base class's
    NotImplementedError is a real outcome. A destroy must not fail to
    say so."""
    from agentcage import secret_store as ss
    assert ss.at_rest_names(
        ss.PlaintextStore(MagicMock()), "acme", state_dir=Path("/unused"),
    ) == []
