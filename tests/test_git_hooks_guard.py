"""Tests for Git hook masking and tamper warnings (issue #170)."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

from agentcage.config import load_config
from agentcage.git_hooks_guard import (
    diff_tamper_state,
    discover_git_hooks_masks,
    snapshot_tamper_state,
)
from agentcage.quadlets import generate_quadlets


def _vol(host: Path, cage: str = "/workspace") -> str:
    return f"{host}:{cage}:rw"


class TestDiscovery:
    def test_discovers_top_level_nested_and_extra_repo_binds(self, tmp_path):
        workspace = tmp_path / "workspace"
        other = tmp_path / "other"
        (workspace / ".git" / "hooks").mkdir(parents=True)
        (workspace / "sub" / ".git" / "hooks").mkdir(parents=True)
        (other / ".git" / "hooks").mkdir(parents=True)

        plan = discover_git_hooks_masks(
            [_vol(workspace), _vol(other, "/other")], enabled=True
        )

        assert [m.cage_path for m in plan.masks] == [
            "/workspace/.git/hooks",
            "/workspace/sub/.git/hooks",
            "/other/.git/hooks",
        ]

    def test_does_not_mask_absent_hooks_or_read_only_binds(self, tmp_path):
        workspace = tmp_path / "workspace"
        readonly = tmp_path / "readonly"
        (workspace / ".git").mkdir(parents=True)
        (readonly / ".git" / "hooks").mkdir(parents=True)

        plan = discover_git_hooks_masks(
            [f"{workspace}:/workspace:rw", f"{readonly}:/readonly:ro"],
            enabled=True,
        )

        assert plan.masks == ()
        assert plan.watch_roots == (os.path.realpath(workspace),)

    def test_opt_out_keeps_watch_roots_but_no_masks(self, tmp_path):
        workspace = tmp_path / "workspace"
        (workspace / ".git" / "hooks").mkdir(parents=True)
        plan = discover_git_hooks_masks([_vol(workspace)], enabled=False)
        assert plan.masks == ()
        assert plan.watch_roots == (os.path.realpath(workspace),)


class TestTamperSnapshot:
    def test_warns_on_active_hook_git_config_and_claude_settings(self, tmp_path):
        before = snapshot_tamper_state((str(tmp_path),))
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        (tmp_path / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
        (tmp_path / ".git" / "hooks" / "pre-commit.sample").write_text("ignored\n")
        (tmp_path / ".git" / "config").write_text("[core]\n")
        (tmp_path / "nested" / ".claude").mkdir(parents=True)
        (tmp_path / "nested" / ".claude" / "settings.json").write_text("{}\n")

        warnings = diff_tamper_state(before, snapshot_tamper_state((str(tmp_path),)))

        assert any("pre-commit" in w for w in warnings)
        assert not any("pre-commit.sample" in w for w in warnings)
        assert any(".git/config" in w for w in warnings)
        assert any(".claude/settings.json" in w for w in warnings)


def _yaml_with_workspace(tmp_path, project_dir, *, extra=""):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(f"""\
        name: test
        dns_servers: ["1.1.1.1"]
        container:
          image: localhost/test:latest
          volumes:
            - "{project_dir}:/workspace:rw"
        {extra}
    """))
    return str(p)


class TestQuadletIntegration:
    def test_masks_all_existing_hooks_and_adds_tamper_check(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        project = tmp_path / "project"
        (project / ".git" / "hooks").mkdir(parents=True)
        (project / "sub" / ".git" / "hooks").mkdir(parents=True)

        cfg = load_config(_yaml_with_workspace(tmp_path, project))
        content = generate_quadlets(cfg, "/c.yaml", "/patches")["test-cage.container"]

        assert "Tmpfs=/workspace/.git/hooks:rw,noexec,nosuid,size=8M" in content
        assert "Tmpfs=/workspace/sub/.git/hooks:rw,noexec,nosuid,size=8M" in content
        assert "workspace-guard.baseline" in content
        assert "ExecStopPost=" in content

    def test_opt_out_suppresses_masks_and_tamper_check(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        project = tmp_path / "project"
        (project / ".git" / "hooks").mkdir(parents=True)

        cfg = load_config(
            _yaml_with_workspace(tmp_path, project, extra="git_hooks_mask: false")
        )
        content = generate_quadlets(cfg, "/c.yaml", "/patches")["test-cage.container"]

        assert "/workspace/.git/hooks" not in content
        assert "workspace-guard.baseline" not in content

    def test_default_config_field_is_true(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("name: test\ndns_servers: ['1.1.1.1']\ncontainer:\n  image: x\n")
        assert load_config(str(p)).git_hooks_mask is True
