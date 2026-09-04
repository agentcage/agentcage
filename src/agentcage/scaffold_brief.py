"""Single source of truth for the in-cage "you are sandboxed" brief and skill.

Two canonical assets live under ``scaffolds/``:

* ``AGENTS.md`` — the short *brief* that scaffold ``Containerfile``s
  ``COPY AGENTS.md <agent-memory-path>`` into the agent's own memory file, so
  the agent learns it is caged with zero setup.
* ``skills/agentcage/SKILL.md`` — the *skill* (Agent Skills standard,
  https://agentskills.io) that scaffold ``Containerfile``s
  ``COPY skills/agentcage <agent-skills-dir>/agentcage`` so the agent can load,
  on demand, how to use the Policy API on ``agentcage.local``: reflect on its
  effective allowlist, request a new egress domain with a justification, and
  give a grant back.

Scaffolds do NOT each ship a copy of either asset: that would duplicate the
same bytes across every scaffold and drift over time. Instead
:func:`stage_scaffold_assets` drops the canonical files into a scaffold's
staged build context at build time, so the ``COPY`` lines resolve. Staging is
opt-in and defers to the context:

* only for scaffold-backed cages (``cfg.scaffold`` set),
* only for the assets the ``Containerfile`` actually references,
* a context that ships its own copy *next to the Containerfile* always wins,
* otherwise the staged copy is agentcage's own and is refreshed whenever the
  canonical asset changes (an upgrade must not leave a stale brief or skill
  behind in a cage that only ever got agentcage's copy).

This keeps one editable brief and one editable skill in the repo while every
scaffold (and any downstream template that sets ``scaffold:`` and adds the
``COPY`` lines) gets them for free.
"""

from __future__ import annotations

import filecmp
import shutil
from pathlib import Path

_SCAFFOLDS = Path(__file__).parent / "scaffolds"

#: The one canonical brief. Shipped as package data under scaffolds/.
CANONICAL_BRIEF = _SCAFFOLDS / "AGENTS.md"

#: The one canonical skill directory (``SKILL.md`` plus any supporting files).
#: Shipped as package data under scaffolds/skills/.
CANONICAL_SKILL_DIR = _SCAFFOLDS / "skills" / "agentcage"

#: Build-context-relative path of the skill directory — what the scaffold
#: ``Containerfile``'s ``COPY`` source names.
SKILL_CONTEXT_PATH = Path("skills") / "agentcage"


def _wants(containerfile: Path, needle: str) -> bool:
    try:
        return needle in Path(containerfile).read_text()
    except OSError:
        return False


def _context_ships(containerfile: Path, rel: Path) -> bool:
    """True when the *source* context (the Containerfile's directory) provides *rel*.

    When the source context is the destination itself (a fresh staged copy of
    a scaffold dir), an existing *rel* is by definition the context's own, so
    the same test holds.
    """
    return (Path(containerfile).parent / rel).exists()


def stage_scaffold_brief(
    containerfile: Path, dest_dir: Path, scaffold: str | None,
) -> bool:
    """Stage the canonical brief into *dest_dir* for a scaffold build.

    Returns True if the brief was written (first staging or refresh of a
    stale agentcage-staged copy). No-op (returns False) unless this is a
    scaffold build whose ``Containerfile`` references ``AGENTS.md``; a
    context that ships its own ``AGENTS.md`` next to the Containerfile is
    never overridden.
    """
    if not scaffold or not CANONICAL_BRIEF.is_file():
        return False
    if not _wants(containerfile, "AGENTS.md"):
        return False
    rel = Path("AGENTS.md")
    if _context_ships(containerfile, rel):
        return False
    dest = Path(dest_dir) / rel
    if dest.is_file() and filecmp.cmp(CANONICAL_BRIEF, dest, shallow=False):
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(CANONICAL_BRIEF), str(dest))
    return True


def stage_scaffold_skill(
    containerfile: Path, dest_dir: Path, scaffold: str | None,
) -> bool:
    """Stage the canonical ``agentcage`` skill into *dest_dir*.

    Mirrors :func:`stage_scaffold_brief` for ``skills/agentcage/``: only for
    scaffold builds whose ``Containerfile`` references ``skills/agentcage``,
    never overriding a context that ships its own, and refreshing a stale
    agentcage-staged copy. Returns True if anything was written.
    """
    if not scaffold or not (CANONICAL_SKILL_DIR / "SKILL.md").is_file():
        return False
    if not _wants(containerfile, SKILL_CONTEXT_PATH.as_posix()):
        return False
    if _context_ships(containerfile, SKILL_CONTEXT_PATH):
        return False
    dest = Path(dest_dir) / SKILL_CONTEXT_PATH
    if dest.is_dir():
        cmp = filecmp.dircmp(CANONICAL_SKILL_DIR, dest)
        if not (cmp.left_only or cmp.right_only or cmp.diff_files
                or cmp.funny_files):
            return False
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(CANONICAL_SKILL_DIR, dest)
    return True


def stage_scaffold_assets(
    containerfile: Path, dest_dir: Path, scaffold: str | None,
) -> bool:
    """Stage every canonical asset the scaffold's Containerfile references.

    Returns True if any asset was written.
    """
    wrote_brief = stage_scaffold_brief(containerfile, dest_dir, scaffold)
    wrote_skill = stage_scaffold_skill(containerfile, dest_dir, scaffold)
    return wrote_brief or wrote_skill
