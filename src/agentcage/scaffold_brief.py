"""Single source of truth for the in-cage "you are sandboxed" brief.

The canonical brief lives at ``scaffolds/AGENTS.md`` (one file). Scaffold
``Containerfile``s ``COPY AGENTS.md <agent-memory-path>`` to bake it into the
agent's own memory file, but they do NOT each ship a copy of the brief: that
would duplicate the same bytes across every scaffold and drift over time.

Instead, :func:`stage_scaffold_brief` drops the canonical brief into a
scaffold's staged build context at build time, so the ``COPY`` resolves. It is
opt-in and non-clobbering:

* only for scaffold-backed cages (``cfg.scaffold`` set),
* only when the ``Containerfile`` actually references ``AGENTS.md``,
* never overwriting an ``AGENTS.md`` the context already provides.

This keeps one editable brief in the repo while every scaffold (and any
downstream template that sets ``scaffold:`` and ``COPY AGENTS.md``) gets it for
free.
"""

from __future__ import annotations

import shutil
from pathlib import Path

#: The one canonical brief. Shipped as package data under scaffolds/.
CANONICAL_BRIEF = Path(__file__).parent / "scaffolds" / "AGENTS.md"


def stage_scaffold_brief(
    containerfile: Path, dest_dir: Path, scaffold: str | None,
) -> bool:
    """Stage the canonical brief into *dest_dir* for a scaffold build.

    Returns True if the brief was written. No-op (returns False) unless this
    is a scaffold build whose ``Containerfile`` references ``AGENTS.md`` and
    *dest_dir* doesn't already contain one (so a context that ships its own
    brief always wins).
    """
    if not scaffold:
        return False
    dest = Path(dest_dir) / "AGENTS.md"
    if dest.exists():
        return False
    try:
        containerfile_text = Path(containerfile).read_text()
    except OSError:
        return False
    if "AGENTS.md" not in containerfile_text:
        return False
    if not CANONICAL_BRIEF.is_file():
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(CANONICAL_BRIEF), str(dest))
    return True
