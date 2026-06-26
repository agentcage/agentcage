"""Tests for the /workspace/.git/hooks masking policy (issue #170)."""

from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

import pytest

from agentcage.config import load_config
from agentcage.git_hooks_mask import (
    GIT_HOOKS_CAGE_PATH,
    GIT_HOOKS_TMPFS_SPEC,
    git_hooks_mask_path,
    workspace_host_dir,
)
from agentcage.quadlets import generate_quadlets


class TestWorkspaceHostDir:
    def test_finds_host_bind_at_workspace(self):
        vols = ["/home/me/proj:/workspace:rw", "/home/me/.cache:/cache"]
        assert workspace_host_dir(vols) == "/home/me/proj"

    def test_ignores_non_workspace_binds(self):
        assert workspace_host_dir(["/home/me/x:/data:rw"]) is None

    def test_no_volumes(self):
        assert workspace_host_dir([]) is None

    def test_workspace_subpath_is_not_workspace(self):
        # A bind at /workspace/sub must not be mistaken for the /workspace bind.
        assert workspace_host_dir(["/home/me/x:/workspace/sub:rw"]) is None


class TestGitHooksMaskPath:
    def test_masks_when_repo_present(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        assert git_hooks_mask_path(str(tmp_path), enabled=True) == GIT_HOOKS_CAGE_PATH

    def test_no_mask_when_hooks_absent(self, tmp_path):
        # Has .git but no hooks dir (unusual, but the guard is on hooks).
        (tmp_path / ".git").mkdir()
        assert git_hooks_mask_path(str(tmp_path), enabled=True) is None

    def test_no_mask_when_no_git_at_all(self, tmp_path):
        assert git_hooks_mask_path(str(tmp_path), enabled=True) is None

    def test_no_mask_when_disabled(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        assert git_hooks_mask_path(str(tmp_path), enabled=False) is None

    def test_no_mask_when_no_workspace(self):
        assert git_hooks_mask_path(None, enabled=True) is None


@pytest.fixture
def home_proj():
    """A project dir under $HOME (the quadlet backend rejects volume host
    paths outside the home directory), cleaned up after the test."""
    d = tempfile.mkdtemp(prefix="agentcage-ghm-", dir=Path.home())
    try:
        yield Path(d)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


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
    """The cage quadlet gets a Tmpfs= line only for a real host git repo."""

    def _cage(self, cfg):
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        return files["test-cage.container"]

    def test_masks_real_repo(self, tmp_path, home_proj):
        (home_proj / ".git" / "hooks").mkdir(parents=True)
        cfg = load_config(_yaml_with_workspace(tmp_path, home_proj))
        assert f"Tmpfs={GIT_HOOKS_TMPFS_SPEC}" in self._cage(cfg)

    def test_no_mask_for_non_repo(self, tmp_path, home_proj):
        cfg = load_config(_yaml_with_workspace(tmp_path, home_proj))
        assert "/workspace/.git/hooks" not in self._cage(cfg)

    def test_opt_out(self, tmp_path, home_proj):
        (home_proj / ".git" / "hooks").mkdir(parents=True)
        cfg = load_config(
            _yaml_with_workspace(tmp_path, home_proj, extra="git_hooks_mask: false")
        )
        assert "/workspace/.git/hooks" not in self._cage(cfg)

    def test_default_config_field_is_true(self, minimal_yaml):
        assert load_config(minimal_yaml).git_hooks_mask is True
