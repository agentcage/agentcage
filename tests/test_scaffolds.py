"""Tests for scaffold listing, rendering, and metadata loading."""

import re
import textwrap
from pathlib import Path

import pytest
import yaml

from agentcage.init import (
    infer_scaffold_from_image,
    list_scaffolds,
    load_scaffold_meta,
    render_config,
)


class TestListScaffolds:
    """Verify list_scaffolds() returns all available scaffold names."""

    def test_returns_sorted_list(self):
        scaffolds = list_scaffolds()
        assert scaffolds == sorted(scaffolds)

    def test_includes_known_scaffolds(self):
        """The scaffolds/ directory should contain at least the shipped scaffolds."""
        scaffolds = list_scaffolds()
        assert "openclaw" in scaffolds
        assert "claude-code" in scaffolds
        assert "codex" in scaffolds

    def test_returns_list_of_strings(self):
        scaffolds = list_scaffolds()
        assert isinstance(scaffolds, list)
        for s in scaffolds:
            assert isinstance(s, str)


class TestScaffoldMeta:
    """Verify scaffold.yaml metadata files are loadable."""

    def test_openclaw_has_build_entry(self):
        meta = load_scaffold_meta("openclaw")
        assert meta is not None
        assert "build" in meta
        assert len(meta["build"]) > 0

    def test_nonexistent_scaffold_returns_none(self):
        assert load_scaffold_meta("nonexistent-scaffold-xyz") is None


class TestScaffoldRendering:
    """Verify scaffold templates render to valid YAML."""

    def test_openclaw_renders_valid_yaml(self):
        cfg_text = render_config("my-oc", scaffold="openclaw")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "my-oc"
        assert "container" in parsed
        assert "image" in parsed["container"]

    def test_openclaw_renders_parseable_config(self, tmp_path):
        from agentcage.config import load_config
        cfg_text = render_config("test-oc", scaffold="openclaw")
        p = tmp_path / "cage.yaml"
        p.write_text(cfg_text)
        cfg = load_config(str(p))
        assert cfg.name == "test-oc"
        assert cfg.container.image != ""

    def test_default_scaffold_renders_valid_yaml(self):
        cfg_text = render_config("my-test")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "my-test"

    def test_invalid_scaffold_raises(self):
        """Attempting to render a non-existent scaffold should raise."""
        with pytest.raises(Exception):
            render_config("test", scaffold="nonexistent-scaffold-xyz")

    def test_openclaw_with_vm_isolation(self):
        cfg_text = render_config("vm-oc", scaffold="openclaw", isolation="vm")
        parsed = yaml.safe_load(cfg_text)
        assert parsed.get("isolation") == "vm"
        assert "vm" in parsed

    def test_openclaw_with_custom_port(self):
        cfg_text = render_config("port-oc", scaffold="openclaw", port=9999)
        parsed = yaml.safe_load(cfg_text)
        # The port should appear in the ports config
        ports = parsed.get("container", {}).get("ports", [])
        assert any("9999" in p for p in ports)


class TestCodingAgentScaffolds:
    """Verify claude-code and codex scaffolds render and validate correctly."""

    def test_claude_code_renders_valid_yaml(self):
        cfg_text = render_config("my-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "my-cc"
        assert parsed["lifecycle"] == "interactive"
        assert parsed["scaffold"] == "claude-code"
        assert "container" in parsed
        assert parsed["container"]["command"] == ["sleep", "infinity"]

    def test_codex_renders_valid_yaml(self):
        cfg_text = render_config("my-cx", scaffold="codex")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "my-cx"
        assert parsed["lifecycle"] == "interactive"
        assert parsed["scaffold"] == "codex"
        assert "container" in parsed

    def test_claude_code_has_anthropic_domain(self):
        cfg_text = render_config("test-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        domains = parsed.get("domains", {}).get("allow", [])
        assert "anthropic.com" in domains

    def test_codex_has_openai_domain(self):
        cfg_text = render_config("test-cx", scaffold="codex")
        parsed = yaml.safe_load(cfg_text)
        domains = parsed.get("domains", {}).get("allow", [])
        assert "openai.com" in domains

    def test_claude_code_has_exec_alias(self):
        cfg_text = render_config("test-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        assert "exec_aliases" in parsed
        assert "claude" in parsed["exec_aliases"]

    def test_codex_has_exec_alias(self):
        cfg_text = render_config("test-cx", scaffold="codex")
        parsed = yaml.safe_load(cfg_text)
        assert "exec_aliases" in parsed
        assert "codex" in parsed["exec_aliases"]

    def test_claude_code_passes_validation(self, tmp_path):
        from agentcage.config import load_config, validate_config
        cfg_text = render_config("test-cc", scaffold="claude-code")
        p = tmp_path / "cage.yaml"
        p.write_text(cfg_text)
        cfg = load_config(str(p))
        validate_config(cfg)

    def test_codex_passes_validation(self, tmp_path):
        from agentcage.config import load_config, validate_config
        cfg_text = render_config("test-cx", scaffold="codex")
        p = tmp_path / "cage.yaml"
        p.write_text(cfg_text)
        cfg = load_config(str(p))
        validate_config(cfg)

    def test_claude_code_has_secret_injection(self):
        cfg_text = render_config("test-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        secrets = parsed.get("secret_injection", [])
        assert any(s["env"] == "ANTHROPIC_API_KEY" for s in secrets)

    def test_claude_code_oauth_token_rule_present_but_inactive(self):
        """The CLAUDE_CODE_OAUTH_TOKEN injection rule ships commented out —
        present as guidance, but not active (an active rule would make
        `cage create` demand the secret). The placeholder renders as a
        concrete entropic token even inside the comment, so uncommenting
        the rule yields a ready-to-use config."""
        cfg_text = render_config("test-cc", scaffold="claude-code")
        assert "#- env: CLAUDE_CODE_OAUTH_TOKEN" in cfg_text
        assert re.search(
            r"\{\{placeholder_claude_code_oauth_token_[0-9a-f]{16}\}\}",
            cfg_text,
        )
        parsed = yaml.safe_load(cfg_text)
        active = [s["env"] for s in parsed.get("secret_injection", [])]
        assert active == ["ANTHROPIC_API_KEY"]

    def test_claude_code_has_help_text(self):
        cfg_text = render_config("test-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        assert parsed.get("help", "") != ""

    def test_claude_code_scaffold_meta(self):
        meta = load_scaffold_meta("claude-code")
        assert meta is not None
        assert "build" in meta
        assert meta["build"][0]["image"] == "localhost/agentcage-scaffold-claude-code:latest"

    def test_codex_scaffold_meta(self):
        meta = load_scaffold_meta("codex")
        assert meta is not None
        assert "build" in meta
        assert meta["build"][0]["image"] == "localhost/agentcage-scaffold-codex:latest"


class TestScaffoldConfigIntegration:
    """Verify scaffolds produce configs that pass validate_config."""

    def test_openclaw_passes_validation(self, tmp_path):
        from agentcage.config import load_config, validate_config
        cfg_text = render_config("test-oc", scaffold="openclaw")
        p = tmp_path / "cage.yaml"
        p.write_text(cfg_text)
        cfg = load_config(str(p))
        # Should not raise
        validate_config(cfg)


class TestInferScaffoldFromImage:
    """Verify infer_scaffold_from_image() correctly maps image refs to scaffold names."""

    def test_tagged_openclaw_matches(self):
        assert infer_scaffold_from_image(
            "localhost/agentcage-scaffold-openclaw:latest"
        ) == "openclaw"

    def test_untagged_openclaw_matches(self):
        """scaffold.yaml build entries use untagged refs — must match too."""
        assert infer_scaffold_from_image("localhost/agentcage-scaffold-openclaw") == "openclaw"

    def test_hyphenated_scaffold_name(self):
        assert infer_scaffold_from_image(
            "localhost/agentcage-scaffold-claude-code:latest"
        ) == "claude-code"

    def test_non_matching_prefix_returns_none(self):
        assert infer_scaffold_from_image("docker.io/library/node:22") is None
        assert infer_scaffold_from_image("ghcr.io/foo/bar:v1") is None

    def test_unknown_scaffold_name_returns_none(self):
        """Prefix matches the convention but the scaffold doesn't exist."""
        assert infer_scaffold_from_image(
            "localhost/agentcage-scaffold-definitely-not-a-real-scaffold:latest"
        ) is None

    def test_empty_string_returns_none(self):
        assert infer_scaffold_from_image("") is None

    def test_similar_but_wrong_prefix_returns_none(self):
        """'scaffold' without the 'agentcage-' prefix should not match."""
        assert infer_scaffold_from_image("localhost/scaffold-openclaw:latest") is None
