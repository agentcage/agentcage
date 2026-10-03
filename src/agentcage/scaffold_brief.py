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
* only for assets the Containerfile actually ``COPY``s (a comment that
  merely mentions the path — e.g. the scaffolds' own staging notes — is not
  a reference, and neither is a longer name like ``skills/agentcage-x``),
* a context that ships its own copy *next to the Containerfile* always wins,
* otherwise the staged copy is agentcage's own and is refreshed whenever the
  canonical asset changes, at any depth of the staged tree (an upgrade must
  not leave a stale brief or skill behind in a cage that only ever got
  agentcage's copy).

This keeps one editable brief and one editable skill in the repo while every
scaffold (and any downstream template that sets ``scaffold:`` and adds the
``COPY`` lines) gets them for free.
"""

from __future__ import annotations

import filecmp
import re
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


def _copy_references(containerfile: Path, path: str) -> bool:
    """True when the Containerfile COPYs build-context *path*.

    Matches an actual ``COPY`` instruction (case-insensitive, like the
    Dockerfile parser; any ``--flag``s and a source-path prefix allowed),
    and stops at the end of the path — ``COPY skills/agentcage-x`` is not a
    reference to ``skills/agentcage``. A comment line that mentions the path
    never matches, and neither does a mention in the copy *destination*
    (the match must start at the instruction's first source token).
    """
    try:
        text = Path(containerfile).read_text()
    except OSError:
        return False
    pattern = (rf"(?mi)^\s*COPY\s+(?:--\S+\s+)*\S*{re.escape(path)}"
               rf"(?=[\s/,\"']|$)")
    return re.search(pattern, text) is not None


def _context_ships(containerfile: Path, rel: Path) -> bool:
    """True when the *source* context (the Containerfile's directory) provides *rel*.

    When the source context is the destination itself (a fresh staged copy of
    a scaffold dir), an existing *rel* is by definition the context's own, so
    the same test holds.
    """
    return (Path(containerfile).parent / rel).exists()


def _remove_path(path: Path) -> None:
    """Remove *path* whether it is a file, a symlink, or a directory tree."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    else:
        shutil.rmtree(path)


def _trees_differ(a: Path, b: Path) -> bool:
    """True when the directory trees under *a* and *b* differ.

    Recursive and byte-deep. (``filecmp.dircmp`` alone is neither: it does
    not descend into subdirectories, and its file comparison is a
    size/mtime signature — a changed file with a matching signature, or a
    stale file in a subdirectory under an otherwise current tree, reads as
    equal.)
    """
    a_names = {p.name for p in a.iterdir()}
    b_names = {p.name for p in b.iterdir()}
    if a_names != b_names:
        return True
    for name in a_names:
        ae, be = a / name, b / name
        if ae.is_dir() != be.is_dir():
            return True  # a file where a directory should be, or vice versa
        if ae.is_dir():
            if _trees_differ(ae, be):
                return True
        elif not filecmp.cmp(ae, be, shallow=False):
            return True
    return False


def staged_asset_sources(
    containerfile: Path, scaffold: str | None,
) -> list[tuple[Path, Path]]:
    """``(build-context-relative path, canonical source)`` for each asset
    :func:`stage_scaffold_assets` would write beside *containerfile*.

    The three conditions in the module docstring that gate *every*
    canonical asset — a scaffold build, an asset agentcage actually ships,
    and a ``COPY`` of it in a context that does not ship its own — live
    here once. :func:`stage_scaffold_brief` and
    :func:`stage_scaffold_skill` consult this rather than re-deriving
    them, and so does ``cli.init``'s pre-flight conflict check, which has
    to know what staging *would* write before it writes anything.

    Says nothing about whether the destination is already current: that is
    per-asset (a byte compare for the brief, a tree compare for the
    skill) and belongs to the caller.
    """
    out: list[tuple[Path, Path]] = []
    if not scaffold:
        return out
    for rel, source, shipped in (
        (Path("AGENTS.md"), CANONICAL_BRIEF, CANONICAL_BRIEF.is_file()),
        (SKILL_CONTEXT_PATH, CANONICAL_SKILL_DIR,
         (CANONICAL_SKILL_DIR / "SKILL.md").is_file()),
    ):
        if not shipped:
            continue
        if not _copy_references(containerfile, rel.as_posix()):
            continue
        if _context_ships(containerfile, rel):
            continue
        out.append((rel, source))
    return out


def _would_stage(containerfile: Path, rel: Path, scaffold: str | None) -> bool:
    """Whether :func:`staged_asset_sources` names *rel*."""
    return any(r == rel for r, _ in staged_asset_sources(containerfile, scaffold))


def stage_scaffold_brief(
    containerfile: Path, dest_dir: Path, scaffold: str | None,
) -> bool:
    """Stage the canonical brief into *dest_dir* for a scaffold build.

    Returns True if the brief was written (first staging or refresh of a
    stale agentcage-staged copy). No-op (returns False) unless this is a
    scaffold build whose ``Containerfile`` COPYs ``AGENTS.md``; a context
    that ships its own ``AGENTS.md`` next to the Containerfile is never
    overridden. A directory or symlink squatting on the staged name is
    replaced: the staged copy is agentcage's own file.
    """
    rel = Path("AGENTS.md")
    if not _would_stage(containerfile, rel, scaffold):
        return False
    dest = Path(dest_dir) / rel
    if dest.is_symlink() or (dest.exists() and not dest.is_file()):
        _remove_path(dest)
    elif dest.is_file() and filecmp.cmp(CANONICAL_BRIEF, dest, shallow=False):
        return False  # current — nothing to refresh
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(CANONICAL_BRIEF), str(dest))
    return True


def stage_scaffold_skill(
    containerfile: Path, dest_dir: Path, scaffold: str | None,
) -> bool:
    """Stage the canonical ``agentcage`` skill into *dest_dir*.

    Mirrors :func:`stage_scaffold_brief` for ``skills/agentcage/``: only for
    scaffold builds whose ``Containerfile`` COPYs ``skills/agentcage``,
    never overriding a context that ships its own, and refreshing a stale
    agentcage-staged copy (recursively — any file anywhere under the staged
    tree). A file or symlink squatting on the staged directory (or on its
    ``skills/`` parent) is replaced. Returns True if anything was written.
    """
    if not _would_stage(containerfile, SKILL_CONTEXT_PATH, scaffold):
        return False
    dest = Path(dest_dir) / SKILL_CONTEXT_PATH
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        _remove_path(dest)
    elif dest.is_dir():
        if not _trees_differ(CANONICAL_SKILL_DIR, dest):
            return False  # current — nothing to refresh
        _remove_path(dest)
    if dest.parent.is_symlink() or (dest.parent.exists()
                                    and not dest.parent.is_dir()):
        _remove_path(dest.parent)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(CANONICAL_SKILL_DIR, dest)
    return True


def staged_asset_differs(source: Path, dest: Path) -> bool:
    """Whether *dest* is something other than a current copy of *source*.

    True when *dest* does not exist at all, so callers that want "exists
    and disagrees" must test existence themselves. Byte-deep for a file
    and recursive for a directory, which is what the two stagers' own
    "nothing to refresh" tests do — the same comparison, asked before the
    write instead of during it.
    """
    if dest.is_symlink():
        return True
    if source.is_dir():
        return not dest.is_dir() or _trees_differ(source, dest)
    return not dest.is_file() or not filecmp.cmp(source, dest, shallow=False)


def stage_scaffold_assets(
    containerfile: Path, dest_dir: Path, scaffold: str | None,
) -> bool:
    """Stage every canonical asset the scaffold's Containerfile COPYs.

    Returns True if any asset was written.
    """
    wrote_brief = stage_scaffold_brief(containerfile, dest_dir, scaffold)
    wrote_skill = stage_scaffold_skill(containerfile, dest_dir, scaffold)
    return wrote_brief or wrote_skill
