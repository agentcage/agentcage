"""Scaffolds bake a 'you are sandboxed' brief into each agent's memory file.

This is a *scaffold* feature, not an agentcage-core one: where the brief lives
and what format it takes is agent-specific, so it belongs to the agent image
rather than the generic cage runtime. The only core piece is the
``AGENTCAGE_VERSION`` env var (tested per-backend elsewhere).

Each scaffold ships an identical ``AGENTS.md`` next to its ``Containerfile``
and ``COPY``s it into that agent's own memory file as a plain, writable,
node-owned file (no read-only mount over the home dir, no ``@import``).
"""

from pathlib import Path

import pytest

import agentcage

# scaffold name -> (memory file the agent reads, home dir chowned back to node)
SCAFFOLD_WIRING = {
    "claude-code": ("/home/node/.claude/CLAUDE.md", "/home/node/.claude"),
    "codex": ("/home/node/.codex/AGENTS.md", "/home/node/.codex"),
    "pi": ("/home/node/.pi/agent/AGENTS.md", "/home/node/.pi"),
}


def _scaffolds_dir() -> Path:
    return Path(agentcage.__file__).parent / "scaffolds"


def test_all_scaffold_briefs_are_byte_identical():
    """Single source of truth: every scaffold ships the same brief bytes."""
    briefs = {
        name: (_scaffolds_dir() / name / "AGENTS.md").read_text()
        for name in SCAFFOLD_WIRING
    }
    canonical = briefs["claude-code"]
    for name, text in briefs.items():
        assert text == canonical, f"{name}/AGENTS.md drifted from claude-code"


@pytest.mark.parametrize("scaffold", sorted(SCAFFOLD_WIRING))
def test_scaffold_ships_brief(scaffold):
    brief = (_scaffolds_dir() / scaffold / "AGENTS.md").read_text()
    assert brief.startswith("# You are running inside agentcage")
    low = brief.lower()
    assert "proxy" in low
    assert "placeholder" in low
    assert "agentcage_version" in low
    # Short — it lands in the agent's context window.
    assert len(brief.splitlines()) < 60


@pytest.mark.parametrize("scaffold,mem_path,home_dir",
                         [(n, m, h) for n, (m, h) in sorted(SCAFFOLD_WIRING.items())])
def test_containerfile_bakes_brief_into_agent_memory_writable(
    scaffold, mem_path, home_dir,
):
    cf = (_scaffolds_dir() / scaffold / "Containerfile").read_text()
    # Plain COPY into the agent's own memory file, before USER node, with the
    # home dir chowned back to node so the file stays writable and the agent's
    # own state writes (auth, settings, history) still work.
    assert f"COPY AGENTS.md {mem_path}" in cf
    assert f"chown -R node:node {home_dir}" in cf
    assert cf.index("COPY AGENTS.md") < cf.index("USER node")
    # Real file, not a shell-redirect / @import indirection.
    assert f"> {mem_path}" not in cf


@pytest.mark.parametrize("scaffold", sorted(SCAFFOLD_WIRING))
def test_brief_is_staged_into_build_context(scaffold):
    # _stage_build_context copies sibling files into the build context but
    # skips .yaml/.yml/.j2. The brief must be a non-skipped suffix or
    # `COPY AGENTS.md` would fail at build time.
    from agentcage.cli import _BUILD_CONTEXT_SKIP_SUFFIXES

    brief = _scaffolds_dir() / scaffold / "AGENTS.md"
    assert brief.suffix not in _BUILD_CONTEXT_SKIP_SUFFIXES
