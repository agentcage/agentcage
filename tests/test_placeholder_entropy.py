"""Entropic secret-injection placeholders.

Covers generation (config.generate_placeholder), declare-time filling of
omitted placeholders (config.fill_raw_placeholders / state.fill_placeholders),
parser acceptance of placeholder-less rules, the guessable-placeholder
warning, empty-placeholder guards in quadlet rendering and the proxy
injector, scaffold render-time generation, and the `secret list`
PLACEHOLDER column.
"""

import platform
import re
import textwrap
from unittest.mock import patch

import pytest
import yaml

from agentcage.config import (
    fill_raw_placeholders,
    generate_placeholder,
    load_config,
    validate_config,
)

TOKEN_RE = re.compile(r"^\{\{placeholder_[a-z0-9_]+_[0-9a-f]{16}\}\}$")


class TestGeneratePlaceholder:

    def test_format(self):
        tok = generate_placeholder("GH_TOKEN")
        assert TOKEN_RE.match(tok)
        assert tok.startswith("{{placeholder_gh_token_")

    def test_unique_per_call(self):
        assert generate_placeholder("KEY") != generate_placeholder("KEY")


class TestFillRawPlaceholders:

    def test_fills_omitted(self):
        raw = {"secret_injection": [{"env": "GH_TOKEN"}]}
        assert fill_raw_placeholders(raw) is True
        assert TOKEN_RE.match(raw["secret_injection"][0]["placeholder"])

    def test_preserves_explicit(self):
        raw = {"secret_injection": [
            {"env": "GH_TOKEN", "placeholder": "ghp_fake000"},
        ]}
        assert fill_raw_placeholders(raw) is False
        assert raw["secret_injection"][0]["placeholder"] == "ghp_fake000"

    def test_carry_over_from_prev(self):
        prev = {"secret_injection": [
            {"env": "GH_TOKEN", "placeholder": "{{placeholder_gh_token_aaaaaaaaaaaaaaaa}}"},
        ]}
        raw = {"secret_injection": [{"env": "GH_TOKEN"}, {"env": "NEW_KEY"}]}
        assert fill_raw_placeholders(raw, prev_raw=prev) is True
        rules = raw["secret_injection"]
        assert rules[0]["placeholder"] == "{{placeholder_gh_token_aaaaaaaaaaaaaaaa}}"
        assert TOKEN_RE.match(rules[1]["placeholder"])
        assert rules[1]["placeholder"] != rules[0]["placeholder"]

    def test_rules_dict_form(self):
        raw = {"secret_injection": {"rules": [{"env": "K"}], "redact_to": []}}
        assert fill_raw_placeholders(raw) is True
        assert TOKEN_RE.match(raw["secret_injection"]["rules"][0]["placeholder"])

    def test_no_rules_is_noop(self):
        raw = {"name": "x"}
        assert fill_raw_placeholders(raw) is False

    def test_malformed_entries_skipped(self):
        raw = {"secret_injection": ["not-a-dict", {"placeholder": "x"}, None]}
        assert fill_raw_placeholders(raw) is False


class TestParserAcceptsOmittedPlaceholder:

    def _load(self, tmp_path, body: str):
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent(body))
        return load_config(str(p))

    def test_rule_kept_with_empty_placeholder(self, tmp_path):
        cfg = self._load(tmp_path, """\
            name: test
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
        """)
        assert len(cfg.secret_injection) == 1
        assert cfg.secret_injection[0].env == "MY_KEY"
        assert cfg.secret_injection[0].placeholder == ""

    def test_placeholderless_rule_still_strips_cage_env(self, tmp_path):
        """An injected secret must never reach the cage env/podman_secrets,
        placeholder or not."""
        cfg = self._load(tmp_path, """\
            name: test
            container:
              image: localhost/test:latest
              podman_secrets: [MY_KEY]
              env:
                MY_KEY: "${MY_KEY}"
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
        """)
        assert "MY_KEY" not in cfg.container.podman_secrets
        assert "MY_KEY" not in cfg.container.env

    def test_guessable_placeholder_warns(self, tmp_path):
        cfg = self._load(tmp_path, """\
            name: test
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: GH_TOKEN
                placeholder: "{{GH_TOKEN}}"
        """)
        warnings = validate_config(cfg)
        assert any("guessable" in w for w in warnings)

    def test_entropic_placeholder_does_not_warn(self, tmp_path):
        cfg = self._load(tmp_path, """\
            name: test
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: GH_TOKEN
                placeholder: "{{placeholder_gh_token_0123456789abcdef}}"
        """)
        warnings = validate_config(cfg)
        assert not any("guessable" in w for w in warnings)


class TestStateFillPlaceholders:

    def _seed(self, state, name, body: str):
        d = state.deployment_dir(name)
        d.mkdir(parents=True, exist_ok=True)
        (d / "cage.yaml").write_text(textwrap.dedent(body))

    def test_fill_persists_to_stored_config(self, patch_state_dirs):
        state = patch_state_dirs
        self._seed(state, "c1", """\
            name: c1
            container:
              image: localhost/test:latest
            secret_injection:
              - env: MY_KEY
        """)
        assert state.fill_placeholders("c1") is True
        raw = state.load_raw_config("c1")
        assert TOKEN_RE.match(raw["secret_injection"][0]["placeholder"])
        # Idempotent: second call must not rewrite
        assert state.fill_placeholders("c1") is False

    def test_fill_carry_over_stable_across_update(self, patch_state_dirs):
        state = patch_state_dirs
        self._seed(state, "c2", """\
            name: c2
            container:
              image: localhost/test:latest
            secret_injection:
              - env: MY_KEY
        """)
        state.fill_placeholders("c2")
        first = state.load_raw_config("c2")["secret_injection"][0]["placeholder"]
        # Simulate `cage update -c`: stored config replaced by a user file
        # that still omits the placeholder.
        prev_raw = state.load_raw_config("c2")
        self._seed(state, "c2", """\
            name: c2
            container:
              image: localhost/test:latest
            secret_injection:
              - env: MY_KEY
        """)
        assert state.fill_placeholders("c2", prev_raw=prev_raw) is True
        second = state.load_raw_config("c2")["secret_injection"][0]["placeholder"]
        assert second == first


class TestQuadletEmptyPlaceholderGuard:

    def _cfg(self, tmp_path, placeholder_line: str = ""):
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent(f"""\
            name: guardtest
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
            {placeholder_line}
        """))
        return load_config(str(p))

    def test_empty_placeholder_renders_no_env_delivery(
        self, tmp_path, patch_state_dirs,
    ):
        """A rule whose placeholder was never generated must not produce an
        EnvironmentFile reference (the derived file would hold no line for
        it anyway) nor any baked Environment= line."""
        from agentcage.quadlets import generate_quadlets
        cfg = self._cfg(tmp_path)
        units = generate_quadlets(
            cfg, str(tmp_path / "proxy-config.yaml"), str(tmp_path), "guardtest",
        )
        cage_unit = units["guardtest-cage.container"]
        assert 'Environment="MY_KEY=' not in cage_unit
        assert "EnvironmentFile=" not in cage_unit
        assert "/run/agentcage/env" not in cage_unit

    def test_filled_placeholder_delivered_via_env_file(
        self, tmp_path, patch_state_dirs,
    ):
        """Placeholders are delivered via EnvironmentFile + a cage-env dir
        mount — podman re-reads the file at container creation, so a plain
        `cage restart` applies placeholder changes."""
        from agentcage.quadlets import generate_quadlets
        state = patch_state_dirs
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: guardtest
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
                placeholder: "{{placeholder_my_key_0123456789abcdef}}"
        """))
        cfg = load_config(str(p))
        units = generate_quadlets(
            cfg, str(tmp_path / "proxy-config.yaml"), str(tmp_path), "guardtest",
        )
        cage_unit = units["guardtest-cage.container"]
        env_path = str(state.placeholders_env_path("guardtest"))
        assert f"EnvironmentFile={env_path}" in cage_unit
        assert (
            f"Volume={state.cage_env_dir('guardtest')}:/run/agentcage/env:ro,Z"
            in cage_unit
        )
        assert 'Environment="MY_KEY=' not in cage_unit
        # The egress stages the secret value into the tmpfs dir at start
        # and mounts it where the injector's file fallback looks.
        egress_unit = units["guardtest-egress.container"]
        assert (
            "Volume=%t/agentcage/guardtest/secrets:/home/acproxy/secrets:ro,Z"
            in egress_unit
        )
        assert "podman secret inspect --showsecret" in egress_unit
        assert '"%t/agentcage/guardtest/secrets/MY_KEY"' in egress_unit


class TestInjectorEmptyPlaceholderGuard:

    def test_empty_placeholder_rule_skipped(self, monkeypatch):
        """`"" in text` is always True and `text.replace("", v)` corrupts
        content — an empty placeholder must never become an active rule."""
        monkeypatch.setenv("MY_KEY", "real-value")
        from agentcage.data.proxy.secret_injector import SecretInjector
        inj = SecretInjector()
        inj.configure([{"env": "MY_KEY", "placeholder": ""}])
        assert inj.rules == []

    def test_normal_rule_kept(self, monkeypatch):
        monkeypatch.setenv("MY_KEY", "real-value")
        from agentcage.data.proxy.secret_injector import SecretInjector
        inj = SecretInjector()
        inj.configure([
            {"env": "MY_KEY",
             "placeholder": "{{placeholder_my_key_0123456789abcdef}}"},
        ])
        assert len(inj.rules) == 1


class TestScaffoldRenderTimeGeneration:

    @pytest.mark.parametrize("scaffold,env", [
        ("claude-code", "ANTHROPIC_API_KEY"),
        ("codex", "OPENAI_API_KEY"),
        ("pi", "ANTHROPIC_API_KEY"),
        ("openclaw", "ANTHROPIC_API_KEY"),
    ])
    def test_active_rules_render_entropic_tokens(self, scaffold, env):
        from agentcage.init import render_config
        parsed = yaml.safe_load(render_config("t", scaffold=scaffold))
        rules = {r["env"]: r for r in parsed.get("secret_injection", [])}
        assert env in rules
        assert TOKEN_RE.match(rules[env]["placeholder"])

    def test_tokens_unique_per_render(self):
        from agentcage.init import render_config
        a = yaml.safe_load(render_config("t", scaffold="claude-code"))
        b = yaml.safe_load(render_config("t", scaffold="claude-code"))
        pa = a["secret_injection"][0]["placeholder"]
        pb = b["secret_injection"][0]["placeholder"]
        assert pa != pb


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux/container cage create flow; runs on the Linux CI",
)
class TestCageCreateFillsPlaceholders:
    """End-to-end through the CLI: `cage create` must persist a generated
    placeholder into the stored cage.yaml and hand a *filled* Config to
    build_and_deploy (real state module, mocked podman/systemd/deploy)."""

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli._check_port_availability", return_value=[])
    @patch("agentcage.cli._check_secrets", return_value=[])
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.systemd")
    @patch("agentcage.cli.Podman")
    def test_create_persists_and_deploys_filled_placeholder(
        self, MockPodman, mock_systemd, mock_backend, _check_secrets,
        _check_ports, mock_build_deploy, tmp_path, patch_state_dirs,
        monkeypatch,
    ):
        from click.testing import CliRunner
        import agentcage.cli as cli_mod
        from agentcage.cli import main

        monkeypatch.setattr(
            cli_mod, "_ensure_backend_ready",
            lambda cfg, **kw: cli_mod.get_backend(cfg),
        )
        state = patch_state_dirs
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: fill-e2e
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
        """))
        result = CliRunner().invoke(main, ["cage", "create", "-c", str(p)])
        assert result.exit_code == 0, result.output

        # Stored config carries the generated token…
        raw = state.load_raw_config("fill-e2e")
        stored = raw["secret_injection"][0]["placeholder"]
        assert TOKEN_RE.match(stored)
        # …and build_and_deploy received the *reloaded* (filled) Config.
        deployed_cfg = mock_build_deploy.call_args.args[0]
        assert deployed_cfg.secret_injection[0].placeholder == stored
        # The user's original file is never mutated.
        assert "placeholder" not in p.read_text()


class TestSecretListPlaceholderColumn:

    def test_placeholder_shown(self, tmp_path, capsys):
        from agentcage.cli import _render_secret_list
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: listtest
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
                placeholder: "{{placeholder_my_key_0123456789abcdef}}"
        """))
        cfg = load_config(str(p))
        _render_secret_list(cfg, {"MY_KEY"})
        out = capsys.readouterr().out
        assert "PLACEHOLDER" in out
        assert "{{placeholder_my_key_0123456789abcdef}}" in out
