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
            r"agentcage:secret:CLAUDE_CODE_OAUTH_TOKEN:[0-9a-f]{32}",
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


class TestWorkspaceExecutableConfigMasks:
    """Regression guards for the workspace executable-config tmpfs masks
    (#170, #173).

    Every scaffold that bind-mounts ``${PROJECT_DIR}:/workspace:rw`` exposes
    the host's ``.git/hooks/`` (a cage→host git-hook pivot, #170) and the
    claude-code scaffold additionally exposes the project-local
    ``.claude/settings.json`` (a cage→cage hooks-injection chain, #173) to
    cage writes. The fix is a ``tmpfs:`` entry per affected scaffold that
    overlays the bind-mounted path with an empty, transient tmpfs.

    ``openclaw`` is intentionally exempt: it mounts ``/workspace`` from a
    Podman named volume (``{{ name }}-workspace``), not a host bind-mount,
    so there is no host ``.git``/``.claude`` tree for a caged agent to reach
    or pivot to.
    """

    # Scaffolds that bind-mount ${PROJECT_DIR}:/workspace:rw — must mask
    # the host's .git/hooks/ (#170). openclaw uses a named volume, not a
    # bind-mount, so it is excluded.
    _WORKSPACE_BINDMOUNT_SCAFFOLDS = [
        "arch",
        "busybox",
        "claude-code",
        "codex",
        "debian",
        "pi",
        "ubuntu",
    ]

    @pytest.mark.parametrize("scaffold", _WORKSPACE_BINDMOUNT_SCAFFOLDS)
    def test_git_hooks_mask_present(self, scaffold):
        """Every workspace-bind-mount scaffold must tmpfs-mask
        /workspace/.git/hooks/ so a caged agent can't plant a git hook that
        the next host-side `git commit` runs as the host user (#170)."""
        cfg_text = render_config("demo", scaffold=scaffold)
        assert "${PROJECT_DIR}:/workspace:rw" in cfg_text, (
            f"{scaffold} no longer bind-mounts ${{PROJECT_DIR}}:/workspace:rw — "
            "update the mask set if the mount shape changed"
        )
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        masks = [e for e in tmpfs if e.split(":", 1)[0] == "/workspace/.git/hooks/"]
        assert masks, (
            f"{scaffold} mounts the workspace RW but is missing the "
            "/workspace/.git/hooks/ tmpfs mask (#170)"
        )
        # The mask must be noexec so even transient cage-written binaries land
        # on a non-executable mount.
        assert "noexec" in masks[0], (
            f"{scaffold} .git/hooks mask is missing noexec: {masks[0]!r}"
        )

    def test_claude_code_dotclaude_mask_present(self):
        """The claude-code scaffold must tmpfs-mask /workspace/.claude/ so a
        caged agent can't plant a malicious .claude/settings.json `hooks`
        block that Claude Code in another cage honors on launch (#173)."""
        cfg_text = render_config("demo", scaffold="claude-code")
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        masks = [e for e in tmpfs if e.split(":", 1)[0] == "/workspace/.claude/"]
        assert masks, (
            "claude-code is missing the /workspace/.claude/ tmpfs mask (#173)"
        )
        assert "noexec" in masks[0], (
            f"claude-code .claude mask is missing noexec: {masks[0]!r}"
        )

    def test_openclaw_exempt_from_git_hooks_mask(self):
        """openclaw mounts /workspace from a Podman named volume, not a host
        bind-mount, so there is no host .git/hooks/ to pivot to. It must NOT
        gain the bind-mount-driven .git/hooks mask — and must not accidentally
        start bind-mounting ${PROJECT_DIR} either."""
        cfg_text = render_config("demo", scaffold="openclaw")
        assert "${PROJECT_DIR}:/workspace" not in cfg_text, (
            "openclaw now bind-mounts ${PROJECT_DIR}:/workspace — re-evaluate "
            "whether it needs the #170/.git/hooks mask"
        )
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        assert not any(
            e.split(":", 1)[0] == "/workspace/.git/hooks/" for e in tmpfs
        ), "openclaw (named-volume workspace) gained a spurious .git/hooks mask"

    @pytest.mark.parametrize("scaffold", ["codex", "pi"])
    def test_other_agent_scaffolds_no_dotclaude_mask(self, scaffold):
        """codex/pi don't read a project-level executable-config file the way
        Claude Code reads .claude/settings.json `hooks`, so they get the
        .git/hooks mask only — not the .claude/ mask. This pins that decision:
        if a codex/pi project-local executable-config surface is later
        identified, add the analogous mask here rather than blanket-masking."""
        cfg_text = render_config("demo", scaffold=scaffold)
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        assert not any(
            "/workspace/.claude/" in e for e in tmpfs
        ), f"{scaffold} should not carry the claude-code .claude/ mask"

    def test_claude_code_home_dotclaude_not_masked(self):
        """The claude-code scaffold masks the PROJECT-level
        ``/workspace/.claude/`` (#173) but must NOT mask the cage's own
        HOME ``~/.claude`` (``/home/node/.claude``). The home tree holds
        ``CLAUDE.md``, login credentials (``.credentials.json`` from an
        in-cage ``claude login``), and in-cage settings — masking it would
        break ``claude login`` / credential persistence. This pins the core
        distinction so a future mask-list edit can't silently widen the
        project-level mask onto the cage home."""
        cfg_text = render_config("demo", scaffold="claude-code")
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        assert not any(
            e.split(":", 1)[0] == "/home/node/.claude"
            or e.split(":", 1)[0] == "/home/node/.claude/"
            for e in tmpfs
        ), (
            "claude-code tmpfs must not mask the cage HOME ~/.claude "
            "(/home/node/.claude) — only the project-level "
            "/workspace/.claude/. Masking HOME breaks claude login/creds."
        )

    def _apple_warnings(self, tmp_path, scaffold="claude-code"):
        """validate_config() for a scaffold-rendered cage.yaml, forced onto
        the apple-container backend on a simulated macOS 26 ASi host."""
        import platform as _platform
        from unittest import mock
        from agentcage.config import load_config, validate_config
        p = tmp_path / "cage.yaml"
        p.write_text(render_config("demo", scaffold=scaffold))
        cfg = load_config(str(p))
        cfg.isolation = "apple-container"
        with mock.patch.object(_platform, "system", return_value="Darwin"), \
             mock.patch.object(_platform, "machine", return_value="arm64"):
            return validate_config(cfg)

    def test_apple_container_git_hooks_mask_no_longer_reported_dropped(
        self, tmp_path
    ):
        """#318: the #170 /workspace/.git/hooks/ mask is WIRED on
        apple-container now (start() emits `--tmpfs /workspace/.git/hooks`).
        validate_config must therefore stop telling operators the cage->host
        pivot "remains exploitable" — a stale scare warning trains people to
        ignore the SECURITY-RELEVANT prefix, and this one would now be
        factually wrong."""
        warnings = self._apple_warnings(tmp_path)
        stale = [
            w for w in warnings
            if "/workspace/.git/hooks/" in w and "exploitable" in w
        ]
        assert not stale, (
            "the .git/hooks mask is applied on apple-container since #318 — "
            "validate_config must not report it as a dropped, still-"
            "exploitable pivot: " + " | ".join(stale)
        )

    def test_apple_container_dotclaude_mask_no_longer_reported_dropped(
        self, tmp_path
    ):
        """Symmetric to the git-hooks case: the #173 /workspace/.claude/
        mask is applied on apple-container since #318, so the "injection
        chain remains exploitable" warning must be gone."""
        warnings = self._apple_warnings(tmp_path)
        stale = [
            w for w in warnings
            if "/workspace/.claude/" in w and "exploitable" in w
        ]
        assert not stale, (
            "the .claude/ mask is applied on apple-container since #318 — "
            "validate_config must not report it as a dropped, still-"
            "exploitable injection chain: " + " | ".join(stale)
        )

    def test_apple_container_tmpfs_warning_names_dropped_options_only(
        self, tmp_path
    ):
        """What apple-container really loses is the tmpfs OPTION list
        (Apple's `--tmpfs` takes a bare path). The warning must say the
        mounts ARE applied, and name noexec/nosuid/nodev and `size=` as the
        part that is not — overstating enforcement is worse than the old
        loud warning."""
        warnings = self._apple_warnings(tmp_path)
        tmpfs_warns = [w for w in warnings if "container.tmpfs" in w]
        assert tmpfs_warns, (
            "the stock scaffold ships tmpfs entries WITH options, so "
            "apple-container must warn that the options are dropped"
        )
        joined = " | ".join(tmpfs_warns)
        assert "ARE applied" in joined, joined
        assert "noexec" in joined and "size=" in joined, joined
        # Never claim the whole field is inert.
        assert not any(
            "container.tmpfs: silently has no effect" in w for w in warnings
        ), joined

    def test_apple_container_plain_tmp_warning_not_security_flagged(self):
        """A plain /tmp tmpfs entry (the stock scaffold default) must stay a
        generic parity warning about its dropped OPTIONS — it must NOT be
        mis-flagged SECURITY-RELEVANT, otherwise operators learn to treat
        the security flag as noise too. Pins the specificity of Major 1."""
        import platform as _platform
        from unittest import mock
        from agentcage.config import Config, validate_config
        cfg = Config(name="t", isolation="apple-container")
        cfg.container.image = "alpine:3.20"
        cfg.container.tmpfs = ["/tmp:rw,noexec,nosuid,size=256M"]
        with mock.patch.object(_platform, "system", return_value="Darwin"), \
             mock.patch.object(_platform, "machine", return_value="arm64"):
            warnings = validate_config(cfg)
        tmp_warns = [w for w in warnings if "container.tmpfs" in w]
        assert not any("SECURITY-RELEVANT" in w for w in tmp_warns), (
            "a plain /tmp tmpfs drop must not be flagged SECURITY-RELEVANT: "
            + " | ".join(tmp_warns)
        )
