"""Scaffolds bake a 'you are sandboxed' brief into each agent's memory file.

The brief is a *scaffold* feature, not an agentcage-core one: where it lives
and what format it takes is agent-specific. There is a SINGLE canonical brief
(``scaffolds/AGENTS.md``); scaffolds ``COPY AGENTS.md`` into the agent's memory
file but don't each ship a copy — :func:`agentcage.scaffold_brief.stage_scaffold_brief`
stages the canonical brief into the build context at build time.
"""

from pathlib import Path

import pytest

import agentcage
from agentcage.scaffold_brief import CANONICAL_BRIEF, stage_scaffold_brief

# scaffold name -> (agent memory file the COPY targets, home dir chowned to node)
SCAFFOLD_WIRING = {
    "claude-code": ("/home/node/.claude/CLAUDE.md", "/home/node/.claude"),
    "codex": ("/home/node/.codex/AGENTS.md", "/home/node/.codex"),
    "pi": ("/home/node/.pi/agent/AGENTS.md", "/home/node/.pi"),
}


def _scaffolds_dir() -> Path:
    return Path(agentcage.__file__).parent / "scaffolds"


# ── canonical brief ──────────────────────────────────────────────────────────

def test_single_canonical_brief_exists():
    assert CANONICAL_BRIEF == _scaffolds_dir() / "AGENTS.md"
    assert CANONICAL_BRIEF.is_file()


def test_no_per_scaffold_brief_copies():
    # DRY: the brief is NOT duplicated into each scaffold dir.
    for name in SCAFFOLD_WIRING:
        assert not (_scaffolds_dir() / name / "AGENTS.md").exists()


def test_canonical_brief_content():
    brief = CANONICAL_BRIEF.read_text()
    assert brief.startswith("# You are running inside agentcage")
    low = brief.lower()
    assert "proxy" in low
    assert "placeholder" in low
    assert "agentcage_version" in low
    # Short — it lands in the agent's context window.
    assert len(brief.splitlines()) < 60


# ── per-scaffold Containerfile wiring ────────────────────────────────────────

@pytest.mark.parametrize("scaffold,mem_path,home_dir",
                         [(n, m, h) for n, (m, h) in sorted(SCAFFOLD_WIRING.items())])
def test_containerfile_copies_brief_into_agent_memory_writable(
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


# ── staging behaviour ────────────────────────────────────────────────────────

def _fake_scaffold_ctx(tmp_path, copy_line="COPY AGENTS.md /home/node/.claude/CLAUDE.md"):
    cf = tmp_path / "Containerfile"
    cf.write_text(f"FROM x\n{copy_line}\nUSER node\n")
    return cf


def test_stage_injects_brief_for_scaffold_build(tmp_path):
    cf = _fake_scaffold_ctx(tmp_path)
    dest = tmp_path / "ctx"
    dest.mkdir()
    assert stage_scaffold_brief(cf, dest, scaffold="claude-code") is True
    assert (dest / "AGENTS.md").read_text() == CANONICAL_BRIEF.read_text()


def test_stage_noop_without_scaffold(tmp_path):
    # Arbitrary (non-scaffold) build contexts are never touched.
    cf = _fake_scaffold_ctx(tmp_path)
    dest = tmp_path / "ctx"
    dest.mkdir()
    assert stage_scaffold_brief(cf, dest, scaffold=None) is False
    assert not (dest / "AGENTS.md").exists()


def test_stage_noop_when_containerfile_does_not_reference_brief(tmp_path):
    cf = _fake_scaffold_ctx(tmp_path, copy_line="RUN echo hi")
    dest = tmp_path / "ctx"
    dest.mkdir()
    assert stage_scaffold_brief(cf, dest, scaffold="claude-code") is False
    assert not (dest / "AGENTS.md").exists()


def test_stage_does_not_clobber_existing_brief(tmp_path):
    # A context that ships its own AGENTS.md always wins.
    cf = _fake_scaffold_ctx(tmp_path)
    dest = tmp_path / "ctx"
    dest.mkdir()
    (dest / "AGENTS.md").write_text("custom brief")
    assert stage_scaffold_brief(cf, dest, scaffold="claude-code") is False
    assert (dest / "AGENTS.md").read_text() == "custom brief"


# ── scaffold base-image build sees the brief ─────────────────────────────────
#
# Regression: `run_scaffold_setup` built the `agentcage-scaffold-<name>` image
# straight from the package scaffold dir, which does NOT contain AGENTS.md (the
# brief lives one level up and is staged in, not shipped per-scaffold). So the
# Containerfile's `COPY AGENTS.md` failed the build with exit 125 — a fresh
# claude-code/codex/pi cage couldn't build at all. The build must run against a
# context that has the brief staged in.

@pytest.mark.parametrize("scaffold", sorted(SCAFFOLD_WIRING))
def test_run_scaffold_setup_stages_brief_into_build_context(scaffold, monkeypatch):
    from agentcage import init as init_mod

    captured = {}

    class _FakePodman:
        def image_exists(self, image):
            return False  # force the build path

        def build_image(self, image, containerfile, context, **kwargs):
            brief = Path(context) / "AGENTS.md"
            captured["has_brief"] = brief.is_file()
            captured["brief_text"] = brief.read_text() if brief.is_file() else None
            # the Containerfile must live in the same context we build from
            captured["cf_in_context"] = Path(containerfile).parent == Path(context)

    monkeypatch.setattr("agentcage.podman.Podman", lambda: _FakePodman())
    init_mod.run_scaffold_setup(
        scaffold, "demo", "/tmp/unused", quiet=True, isolation="container",
    )
    assert captured.get("has_brief") is True
    assert captured.get("brief_text") == CANONICAL_BRIEF.read_text()
    assert captured.get("cf_in_context") is True
