"""`agentcage secret rotate-placeholders`.

Covers minting fresh entropic tokens for all or named injection rules,
persistence to the stored cage.yaml, restart-if-running vs persist-if-
stopped, the named-key/empty-cage error and no-op paths, and that a
rotated guessable placeholder clears the validate_config lint warning.
"""

import re
import textwrap
from unittest.mock import patch

from click.testing import CliRunner

from agentcage.cli import main

TOKEN_RE = re.compile(r"^\{\{placeholder_[a-z0-9_]+_[0-9a-f]{16}\}\}$")


def _seed(state, name, body: str):
    d = state.deployment_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    (d / "cage.yaml").write_text(textwrap.dedent(body))
    meta = state.load_metadata(name)
    meta["agentcage_version"] = "0.22.22"
    state.save_metadata(name, meta)


_TWO_RULES = """\
    name: c1
    container:
      image: localhost/test:latest
    dns_servers: ["1.1.1.1"]
    secret_injection:
      - env: ANTHROPIC_API_KEY
        placeholder: "{{ANTHROPIC_API_KEY}}"
        inject_to: [anthropic.com]
      - env: GITHUB_TOKEN
        placeholder: "{{GITHUB_TOKEN}}"
        inject_to: [github.com]
"""


def _rules(state, name):
    raw = state.load_raw_config(name)
    return {r["env"]: r["placeholder"] for r in raw["secret_injection"]}


class TestRotatePlaceholders:

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    def test_rotate_all_persists_and_restarts(
        self, mock_backend, mock_restart, patch_state_dirs,
    ):
        state = patch_state_dirs
        _seed(state, "c1", _TWO_RULES)
        mock_backend.return_value.is_running.return_value = True

        result = CliRunner().invoke(
            main, ["secret", "rotate-placeholders", "c1"],
        )
        assert result.exit_code == 0, result.output
        rules = _rules(state, "c1")
        assert TOKEN_RE.match(rules["ANTHROPIC_API_KEY"])
        assert TOKEN_RE.match(rules["GITHUB_TOKEN"])
        # Distinct tokens, both rotated away from the guessable originals.
        assert rules["ANTHROPIC_API_KEY"] != rules["GITHUB_TOKEN"]
        mock_restart.assert_called_once()
        assert "Rotated 2 placeholder" in result.output

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    def test_rotate_named_key_only(
        self, mock_backend, mock_restart, patch_state_dirs,
    ):
        state = patch_state_dirs
        _seed(state, "c1", _TWO_RULES)
        mock_backend.return_value.is_running.return_value = True

        result = CliRunner().invoke(
            main, ["secret", "rotate-placeholders", "c1", "GITHUB_TOKEN"],
        )
        assert result.exit_code == 0, result.output
        rules = _rules(state, "c1")
        assert TOKEN_RE.match(rules["GITHUB_TOKEN"])
        # The untargeted rule is left exactly as it was.
        assert rules["ANTHROPIC_API_KEY"] == "{{ANTHROPIC_API_KEY}}"

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    def test_stopped_cage_persists_without_restart(
        self, mock_backend, mock_restart, patch_state_dirs,
    ):
        state = patch_state_dirs
        _seed(state, "c1", _TWO_RULES)
        mock_backend.return_value.is_running.return_value = False

        result = CliRunner().invoke(
            main, ["secret", "rotate-placeholders", "c1"],
        )
        assert result.exit_code == 0, result.output
        assert TOKEN_RE.match(_rules(state, "c1")["ANTHROPIC_API_KEY"])
        mock_restart.assert_not_called()
        assert "apply on next start" in result.output

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    def test_unknown_key_errors_and_changes_nothing(
        self, mock_backend, mock_restart, patch_state_dirs,
    ):
        state = patch_state_dirs
        _seed(state, "c1", _TWO_RULES)
        mock_backend.return_value.is_running.return_value = True

        result = CliRunner().invoke(
            main, ["secret", "rotate-placeholders", "c1", "NOPE"],
        )
        assert result.exit_code == 1
        assert "no secret_injection rule for: NOPE" in result.output
        # Nothing rotated, nothing restarted.
        assert _rules(state, "c1")["ANTHROPIC_API_KEY"] == "{{ANTHROPIC_API_KEY}}"
        mock_restart.assert_not_called()

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    def test_cage_with_no_rules_is_noop(
        self, mock_backend, mock_restart, patch_state_dirs,
    ):
        state = patch_state_dirs
        _seed(state, "c1", """\
            name: c1
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
        """)

        result = CliRunner().invoke(
            main, ["secret", "rotate-placeholders", "c1"],
        )
        assert result.exit_code == 0, result.output
        assert "no secret_injection rules to rotate" in result.output
        mock_restart.assert_not_called()

    def test_nonexistent_cage_errors(self, patch_state_dirs):
        result = CliRunner().invoke(
            main, ["secret", "rotate-placeholders", "ghost"],
        )
        assert result.exit_code == 1
        assert "does not exist" in result.output

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.cli.get_backend")
    def test_rotation_clears_guessable_lint_warning(
        self, mock_backend, mock_restart, patch_state_dirs,
    ):
        """The migration payoff: a guessable {{ENV}} placeholder trips the
        validate_config warning; after rotation the stored config validates
        clean."""
        from agentcage.config import load_config, validate_config
        state = patch_state_dirs
        _seed(state, "c1", _TWO_RULES)
        mock_backend.return_value.is_running.return_value = False

        before = validate_config(load_config(str(state.stored_config_path("c1"))))
        assert any("guessable" in w for w in before)

        result = CliRunner().invoke(
            main, ["secret", "rotate-placeholders", "c1"],
        )
        assert result.exit_code == 0, result.output
        after = validate_config(load_config(str(state.stored_config_path("c1"))))
        assert not any("guessable" in w for w in after)
