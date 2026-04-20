"""Tests for scaffold listing, rendering, and metadata loading."""

import textwrap
from pathlib import Path

import pytest
import yaml

from agentcage.init import list_scaffolds, render_config, load_scaffold_meta


class TestListScaffolds:
    """Verify list_scaffolds() returns all available scaffold names."""

    def test_returns_sorted_list(self):
        scaffolds = list_scaffolds()
        assert scaffolds == sorted(scaffolds)

    def test_includes_known_scaffolds(self):
        """The scaffolds/ directory should contain at least the shipped scaffolds."""
        scaffolds = list_scaffolds()
        assert "openclaw" in scaffolds
        assert "nanoclaw" in scaffolds
        assert "picoclaw" in scaffolds
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

    def test_nanoclaw_has_next_steps(self):
        meta = load_scaffold_meta("nanoclaw")
        assert meta is not None
        assert "next_steps" in meta

    def test_picoclaw_has_build_entry(self):
        meta = load_scaffold_meta("picoclaw")
        assert meta is not None
        assert "build" in meta

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

    def test_nanoclaw_renders_valid_yaml(self):
        cfg_text = render_config("my-nano", scaffold="nanoclaw")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "my-nano"
        assert "container" in parsed
        assert parsed["container"]["nested_containers"] is True

    def test_nanoclaw_renders_parseable_config(self, tmp_path):
        from agentcage.config import load_config
        cfg_text = render_config("test-nano", scaffold="nanoclaw")
        p = tmp_path / "cage.yaml"
        p.write_text(cfg_text)
        cfg = load_config(str(p))
        assert cfg.name == "test-nano"
        assert cfg.container.nested_containers is True

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

    def test_claude_code_mounts_host_claude_dir(self):
        cfg_text = render_config("test-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        volumes = parsed.get("container", {}).get("volumes", [])
        assert any(".claude:" in v for v in volumes)

    def test_claude_code_has_secret_injection(self):
        cfg_text = render_config("test-cc", scaffold="claude-code")
        parsed = yaml.safe_load(cfg_text)
        secrets = parsed.get("secret_injection", [])
        assert any(s["env"] == "ANTHROPIC_API_KEY" for s in secrets)

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

    def test_nanoclaw_passes_validation(self, tmp_path):
        from agentcage.config import load_config, validate_config
        cfg_text = render_config("test-nano", scaffold="nanoclaw")
        p = tmp_path / "cage.yaml"
        p.write_text(cfg_text)
        cfg = load_config(str(p))
        # validate_config returns warnings for nested_containers; should not raise
        warnings = validate_config(cfg)
        assert isinstance(warnings, list)
