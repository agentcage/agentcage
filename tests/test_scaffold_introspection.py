"""The claude-code scaffold bakes a 'you are sandboxed' brief into Claude
Code's user memory.

This is a *scaffold* feature, not an agentcage-core one: where the brief
lives and what format it takes is agent-specific, so it belongs to the agent
image rather than the generic cage runtime. The only core piece is the
``AGENTCAGE_VERSION`` env var (tested per-backend elsewhere).
"""

from pathlib import Path

import agentcage


def _scaffold_dir() -> Path:
    return Path(agentcage.__file__).parent / "scaffolds" / "claude-code"


def test_scaffold_ships_brief():
    brief = (_scaffold_dir() / "AGENTS.md").read_text()
    assert brief.startswith("# You are running inside agentcage")
    # Mentions the gotchas that actually trip an agent up.
    low = brief.lower()
    assert "proxy" in low
    assert "placeholder" in low
    assert "agentcage_version" in low
    # Short — it lands in the agent's context window.
    assert len(brief.splitlines()) < 60


def test_containerfile_bakes_brief_into_user_memory_writable():
    cf = (_scaffold_dir() / "Containerfile").read_text()
    # Plain COPY into Claude's own memory file, before USER node, and the
    # home dir is chowned back to node so the file stays writable and
    # `claude login` / settings / history still work.
    assert "COPY AGENTS.md /home/node/.claude/CLAUDE.md" in cf
    assert "chown -R node:node /home/node/.claude" in cf
    copy_idx = cf.index("COPY AGENTS.md")
    user_idx = cf.index("USER node")
    assert copy_idx < user_idx
    # Delivered as a real file, not written via a shell redirect (which is how
    # the earlier `@import`-into-CLAUDE.md approach worked).
    assert "> /home/node/.claude/CLAUDE.md" not in cf


def test_brief_is_a_md_file_so_build_context_staging_picks_it_up():
    # _stage_build_context copies sibling files into the build context but
    # skips .yaml/.yml/.j2. The brief must therefore be a .md (or other
    # non-skipped) file or `COPY AGENTS.md` would fail at build time.
    from agentcage.cli import _BUILD_CONTEXT_SKIP_SUFFIXES

    assert (_scaffold_dir() / "AGENTS.md").suffix not in _BUILD_CONTEXT_SKIP_SUFFIXES
