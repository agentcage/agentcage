"""Exec-time placeholder injection + unit convergence + secret declare.

Phases 3+4 of the zero-restart secrets work: `cage exec`/`cage shell`
sessions carry the CURRENT placeholders (read from the stored config at
exec time), `secret set` converges the quadlet files without restarting,
and `secret set --declare` makes a brand-new secret usable in one command.
"""

import textwrap
from unittest.mock import MagicMock, patch

import pytest


def _seed(state, name, rules_yaml=""):
    d = state.deployment_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    base = textwrap.dedent(f"""\
        name: {name}
        container:
          image: localhost/test:latest
        dns_servers: ["1.1.1.1"]
    """)
    (d / "cage.yaml").write_text(base + rules_yaml)


RULES = """\
secret_injection:
  - env: MY_KEY
    placeholder: "{{placeholder_my_key_0123456789abcdef}}"
"""


class TestCurrentPlaceholders:

    def test_reads_live_stored_config(self, patch_state_dirs):
        from agentcage.services import current_placeholders
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        assert current_placeholders("c1") == [
            ("MY_KEY", "{{placeholder_my_key_0123456789abcdef}}"),
        ]

    def test_missing_cage_returns_empty(self, patch_state_dirs):
        from agentcage.services import current_placeholders
        assert current_placeholders("nope") == []

    def test_unfilled_rules_skipped(self, patch_state_dirs):
        from agentcage.services import current_placeholders
        state = patch_state_dirs
        _seed(state, "c1", "secret_injection:\n  - env: RAW\n")
        assert current_placeholders("c1") == []


class TestExecArgvInjection:

    def test_container_cage_exec_carries_placeholders(self, patch_state_dirs):
        from agentcage.backends.container import ContainerBackend
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        backend = ContainerBackend()
        argv = backend.exec_argv("c1", "cage", ["bash"])
        joined = " ".join(argv)
        assert "--env MY_KEY={{placeholder_my_key_0123456789abcdef}}" in joined
        # env flags must precede the container name
        assert argv.index("--env") < argv.index("c1-cage")

    def test_container_egress_exec_does_not(self, patch_state_dirs):
        from agentcage.backends.container import ContainerBackend
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        backend = ContainerBackend()
        argv = backend.exec_argv("c1", "egress", ["sh"])
        assert "--env" not in argv

    def test_vm_cage_exec_carries_placeholders(self, patch_state_dirs):
        from agentcage.backends.vm import VmBackend
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        backend = VmBackend()
        argv = backend.exec_argv("c1", "cage", ["bash"])
        joined = " ".join(argv)
        assert "--env MY_KEY={{placeholder_my_key_0123456789abcdef}}" in joined

    def test_no_rules_leaves_argv_unchanged(self, patch_state_dirs):
        from agentcage.backends.container import ContainerBackend
        state = patch_state_dirs
        _seed(state, "c1")
        backend = ContainerBackend()
        argv = backend.exec_argv("c1", "cage", ["bash"])
        assert argv == [
            "podman", "exec", "-u", "1000:1000", "c1-cage", "bash",
        ]


class TestRefreshUnits:

    @patch("agentcage.cli.get_backend")
    def test_installs_when_units_changed_no_restart(
        self, mock_get_backend, patch_state_dirs, tmp_path,
    ):
        from agentcage.cli import _refresh_units
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        meta = state.load_metadata("c1")
        meta["network_octet"] = 42
        state.save_metadata("c1", meta)
        cfg = state.load_deployment_config("c1")
        backend = mock_get_backend.return_value
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        backend.unit_dir.return_value = unit_dir
        # Installed content differs from generated → must reinstall.
        (unit_dir / "c1-cage.container").write_text("OLD")
        backend.generate_units.return_value = {"c1-cage.container": "NEW"}

        _refresh_units("c1", cfg)

        backend.generate_units.assert_called_once()
        # The octet is pinned from metadata — regenerating from the name
        # hash could shift the subnet outside the existing podman network.
        assert backend.generate_units.call_args.kwargs["network_octet"] == 42
        backend.install_units.assert_called_once()
        backend.restart.assert_not_called()
        backend.stop.assert_not_called()
        backend.start.assert_not_called()

    @patch("agentcage.cli.get_backend")
    def test_skips_install_when_units_unchanged(
        self, mock_get_backend, patch_state_dirs, tmp_path,
    ):
        """`secret set` of an already-declared secret changes no unit file,
        so no reinstall and — critically — no global `daemon-reload` that
        could race a concurrent `cage create` (e2e phases run in parallel)."""
        from agentcage.cli import _refresh_units
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        cfg = state.load_deployment_config("c1")
        backend = mock_get_backend.return_value
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        backend.unit_dir.return_value = unit_dir
        (unit_dir / "c1-cage.container").write_text("SAME")
        (unit_dir / "c1-egress.container").write_text("SAME2")
        backend.generate_units.return_value = {
            "c1-cage.container": "SAME",
            "c1-egress.container": "SAME2",
        }

        _refresh_units("c1", cfg)

        backend.generate_units.assert_called_once()
        backend.install_units.assert_not_called()

    @patch("agentcage.cli.get_backend")
    def test_installs_when_unit_missing(
        self, mock_get_backend, patch_state_dirs, tmp_path,
    ):
        from agentcage.cli import _refresh_units
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        cfg = state.load_deployment_config("c1")
        backend = mock_get_backend.return_value
        unit_dir = tmp_path / "units"
        unit_dir.mkdir()
        backend.unit_dir.return_value = unit_dir
        backend.generate_units.return_value = {"c1-cage.container": "NEW"}

        _refresh_units("c1", cfg)
        backend.install_units.assert_called_once()

    def test_apple_container_is_noop(self, patch_state_dirs):
        from agentcage.cli import _refresh_units
        cfg = MagicMock()
        cfg.isolation = "apple-container"
        with patch("agentcage.cli.get_backend") as mock_get_backend:
            _refresh_units("c1", cfg)
            mock_get_backend.assert_not_called()


class TestSecretSetDeclare:

    def _invoke_set(self, args, input="value\n"):
        from click.testing import CliRunner
        from agentcage.cli import main
        return CliRunner().invoke(main, ["secret", "set", *args], input=input)

    @pytest.fixture
    def cage(self, patch_state_dirs):
        state = patch_state_dirs
        _seed(state, "c1")
        meta = state.load_metadata("c1")
        meta["agentcage_version"] = "0.22.22"
        state.save_metadata("c1", meta)
        return state

    @patch("agentcage.cli._apply_secret_live_or_restart")
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    def test_declare_adds_rule_with_entropic_placeholder(
        self, _podman, _store, _apply, cage,
    ):
        import re
        result = self._invoke_set(["c1", "NEW_KEY", "--declare"])
        assert result.exit_code == 0, result.output
        raw = cage.load_raw_config("c1")
        rules = raw["secret_injection"]
        assert rules[0]["env"] == "NEW_KEY"
        assert re.match(
            r"^\{\{placeholder_new_key_[0-9a-f]{16}\}\}$",
            rules[0]["placeholder"],
        )
        assert "Declared secret_injection rule" in result.output
        # No inject_to → warn that injection is unscoped.
        assert "ALL allowed domains" in result.output

    @patch("agentcage.cli._apply_secret_live_or_restart")
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    def test_inject_to_implies_declare_and_scopes(
        self, _podman, _store, _apply, cage,
    ):
        result = self._invoke_set(
            ["c1", "NEW_KEY", "--inject-to", "api.example.com"],
        )
        assert result.exit_code == 0, result.output
        rules = cage.load_raw_config("c1")["secret_injection"]
        assert rules[0]["inject_to"] == ["api.example.com"]
        assert "ALL allowed domains" not in result.output

    @patch("agentcage.cli._apply_secret_live_or_restart")
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    def test_explicit_placeholder_respected(
        self, _podman, _store, _apply, cage,
    ):
        result = self._invoke_set(
            ["c1", "NEW_KEY", "--placeholder", "fake-tok-123"],
        )
        assert result.exit_code == 0, result.output
        rules = cage.load_raw_config("c1")["secret_injection"]
        assert rules[0]["placeholder"] == "fake-tok-123"

    @patch("agentcage.cli._apply_secret_live_or_restart")
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    def test_declare_existing_rule_untouched(
        self, _podman, _store, _apply, patch_state_dirs,
    ):
        state = patch_state_dirs
        _seed(state, "c1", RULES)
        meta = state.load_metadata("c1")
        meta["agentcage_version"] = "0.22.22"
        state.save_metadata("c1", meta)
        result = self._invoke_set(["c1", "MY_KEY", "--declare"])
        assert result.exit_code == 0, result.output
        rules = state.load_raw_config("c1")["secret_injection"]
        assert len(rules) == 1
        assert rules[0]["placeholder"] == \
            "{{placeholder_my_key_0123456789abcdef}}"
        assert "already exists" in result.output

    @patch("agentcage.cli._apply_secret_live_or_restart")
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    def test_orphan_hint_without_declare(
        self, _podman, _store, _apply, cage,
    ):
        result = self._invoke_set(["c1", "STRAY_KEY"])
        assert result.exit_code == 0, result.output
        assert "orphan" in result.output
        assert "--declare" in result.output
        assert "secret_injection" not in cage.load_raw_config("c1") or \
            not cage.load_raw_config("c1").get("secret_injection")
