"""Regression tests for the domains.auto runtime-wiring fixes.

Each test here corresponds to a defect found by running the feature against
a live cage on both the apple-container and vm backends. They are grouped by
the thing that was broken rather than by module, because each defect spanned
several layers.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agentcage.config import AgentDeciderConfig, DeciderConfig, DomainsAutoConfig


def _auto(api_key: str = "env:OPENROUTER_API_KEY", enable: bool = True):
    return DomainsAutoConfig(
        enable=enable,
        decider=DeciderConfig(
            kind="agent",
            agent=AgentDeciderConfig(
                provider="openrouter",
                model="anthropic/claude-sonnet-4-5",
                api_key=api_key,
            ),
        ),
    )


class TestDeciderSecretIsMaterialized:
    """The decider api_key must become a real podman secret.

    ``quadlets`` emits a ``Secret=`` directive for the decider's key, and
    ``_boot_resolvable`` green-lights ``env:``/``cmd:`` schemes *because*
    ``resolve_and_populate`` is documented to materialize them. It did not:
    it only walked ``secret_injection``. The egress unit then referenced a
    podman secret nobody created and the container died at start with
    ``no such secret`` — taking the whole cage down, not just the decider.
    """

    def test_env_sourced_decider_key_becomes_a_podman_secret(self, tmp_path, monkeypatch):
        from agentcage.secret_resolver import resolve_and_populate

        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-value")
        cfg = SimpleNamespace(
            secret_injection=[],
            domains=SimpleNamespace(auto=_auto()),
        )
        podman = MagicMock()
        podman.secret_exists.return_value = False

        resolved = resolve_and_populate(podman, cfg, "mycage", tmp_path)

        assert "OPENROUTER_API_KEY" in resolved
        podman.secret_create.assert_called_once_with(
            "mycage.OPENROUTER_API_KEY", "sk-test-value"
        )

    def test_disabled_auto_creates_nothing(self, tmp_path, monkeypatch):
        from agentcage.secret_resolver import resolve_and_populate

        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-value")
        cfg = SimpleNamespace(
            secret_injection=[],
            domains=SimpleNamespace(auto=_auto(enable=False)),
        )
        podman = MagicMock()

        resolved = resolve_and_populate(podman, cfg, "mycage", tmp_path)

        assert resolved == set()
        podman.secret_create.assert_not_called()


class TestVmSecretsReachTheGuest:
    """A vm cage resolves ``source:`` secrets into the guest podman store.

    ``resolve_and_populate`` is gated to ``isolation == "container"`` and
    ``_bridge_secrets`` only mirrors an existing HOST podman store — which a
    macOS host does not have. Without a guest-side resolve step the decider
    key never arrives.
    """

    def test_decider_key_created_inside_the_vm(self, tmp_path, monkeypatch):
        from agentcage.backends.vm import VmBackend

        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-guest-value")
        monkeypatch.setattr(
            "agentcage.state.deployment_dir", lambda name: tmp_path
        )
        config = SimpleNamespace(
            secret_injection=[],
            protocol_relays=[],
            domains=SimpleNamespace(auto=_auto()),
        )
        inst = MagicMock()
        backend = VmBackend.__new__(VmBackend)

        backend._resolve_source_secrets("mycage", inst, config)

        created = [
            c for c in inst.exec.call_args_list
            if c.args and c.args[0][:3] == ["podman", "secret", "create"]
        ]
        assert created, "expected a `podman secret create` inside the guest"
        assert created[0].args[0][3] == "mycage.OPENROUTER_API_KEY"
        assert created[0].kwargs["input"] == "sk-guest-value"

    def test_no_config_is_a_no_op(self):
        from agentcage.backends.vm import VmBackend

        inst = MagicMock()
        backend = VmBackend.__new__(VmBackend)
        backend._resolve_source_secrets("mycage", inst, None)
        inst.exec.assert_not_called()


class TestSecretStoreOnMacOsVmHost:
    """A vm cage on macOS stores secrets in the host keychain.

    ``resolve_store`` only reached for the keychain when isolation was
    ``apple-container``; a vm cage on a Mac fell through to systemd-creds,
    which lives in the guest and is unavailable on the host. ``auto`` then
    found no encrypting backend and refused every ``secret set`` — making
    ``domains.auto``, whose api_key is mandatory, unusable without opting
    into plaintext storage.
    """

    def test_vm_on_darwin_picks_the_keychain(self, monkeypatch):
        import agentcage.secret_store as ss

        monkeypatch.setattr(ss.sys, "platform", "darwin")
        monkeypatch.setattr(ss.KeychainStore, "available", lambda self: True)
        cfg = SimpleNamespace(
            isolation="vm",
            secrets=SimpleNamespace(
                backend="auto", allow_plaintext=False, scope="auto",
            ),
        )
        assert isinstance(ss.resolve_store(cfg), ss.KeychainStore)

    def test_vm_on_linux_still_uses_systemd_creds(self, monkeypatch):
        import agentcage.secret_store as ss

        monkeypatch.setattr(ss.sys, "platform", "linux")
        monkeypatch.setattr(
            ss.SystemdCredsStore, "available", lambda self: True
        )
        cfg = SimpleNamespace(
            isolation="vm",
            secrets=SimpleNamespace(
                backend="auto", allow_plaintext=False, scope="auto",
            ),
        )
        assert isinstance(ss.resolve_store(cfg), ss.SystemdCredsStore)


class TestSecretListClassifiesTheDeciderKey:
    """The decider's key is not an orphan.

    It is not a ``secret_injection`` rule, so ``secret list`` filed it under
    ``orphan`` — "stored but never used" — inviting an operator to
    ``secret rm`` the one credential the decider needs.
    """

    def test_reported_as_decider_not_orphan(self, capsys):
        from agentcage.cli import _render_secret_list

        cfg = SimpleNamespace(
            secret_injection=[],
            container=SimpleNamespace(podman_secrets=[]),
            protocol_relays=[],
            domains=SimpleNamespace(auto=_auto()),
        )
        _render_secret_list(cfg, {"OPENROUTER_API_KEY"})
        out = capsys.readouterr().out
        assert "OPENROUTER_API_KEY" in out
        assert "decider" in out
        assert "orphan" not in out

