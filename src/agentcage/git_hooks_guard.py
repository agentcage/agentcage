"""Git hook masking and workspace tamper warnings (issue #170).

The primary cage→host pivot is a writable host bind that exposes one or more
Git hook directories to the cage.  A malicious in-cage agent can plant an
active hook and have it execute later when the operator runs ``git`` on the
host.

The guard has two layers:

* mask every **existing** ``.git/.../hooks`` directory discovered under
  writable host binds; the existence guard avoids runtime-created mountpoints
  littering clean host projects;
* snapshot selected host-trusted files before the cage starts and warn on stop
  if they were created, removed, or modified.  This catches newly-created repos
  and adjacent pivots that cannot be safely tmpfs-mounted after the container
  has already started.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import shlex
from pathlib import Path, PurePosixPath

# tmpfs spec used by the container/vm (quadlet) backends. Apple's
# ``container run --tmpfs`` takes a *bare path* only, so the apple backend uses
# the discovered cage paths directly instead of this ``path:opts`` form.
GIT_HOOKS_TMPFS_OPTS = "rw,noexec,nosuid,size=8M"

# Git executes only these exact basenames from a hooks directory.  ``*.sample``
# files are intentionally not listed: they are templates, not active hooks.
GIT_HOOK_NAMES = (
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "reference-transaction",
    "push-to-checkout",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "fsmonitor-watchman",
    "p4-pre-submit",
    "post-index-change",
)

# Other workspace files that can affect host-side tool execution.  This is a
# warning layer (not a blocker) because these files are normal project files and
# broad prevention would break legitimate edits.
TAMPER_SENTINELS = (
    ".git",  # worktree gitdir pointer file
    ".git/config",
    ".git/config.worktree",
    ".git/info/attributes",
    ".gitattributes",
    ".gitmodules",
    ".lfsconfig",
    ".claude/settings.json",
)

# Common project-local hook script directories.  ``.git/**/hooks`` is masked
# when present; the rest are warning-only because projects often legitimately
# track them as source files and broad prevention would be too disruptive.
TAMPER_HOOK_DIR_NAMES = ("hooks", ".githooks", ".husky")

# Keep scans bounded in common large dependency/cache trees.  Nested git repos
# inside these directories are intentionally ignored to avoid turning every cage
# start/stop into a full dependency traversal.
_PRUNE_DIRS = frozenset({"node_modules", ".venv", "venv", "__pycache__", ".cache"})


@dataclass(frozen=True)
class BindMount:
    """A writable host bind visible in the cage."""

    host_path: str
    cage_path: str
    options: tuple[str, ...] = ()


@dataclass(frozen=True)
class GitHooksMask:
    """One host hook directory and its corresponding cage-side path."""

    host_path: str
    cage_path: str

    @property
    def tmpfs_spec(self) -> str:
        return f"{self.cage_path}:{GIT_HOOKS_TMPFS_OPTS}"


@dataclass(frozen=True)
class GitHooksGuardPlan:
    """Computed guard actions for a set of expanded volume specs."""

    binds: tuple[BindMount, ...]
    masks: tuple[GitHooksMask, ...]

    @property
    def watch_roots(self) -> tuple[str, ...]:
        """Host paths to snapshot/check for tampering."""
        seen: set[str] = set()
        out: list[str] = []
        for bind in self.binds:
            real = os.path.realpath(bind.host_path)
            if real not in seen:
                seen.add(real)
                out.append(real)
        return tuple(out)


def _split_volume_spec(spec: str) -> tuple[str, str, tuple[str, ...]] | None:
    """Parse ``host:cage[:opts]`` volume specs.

    The project already limits host bind sources to Unix-like paths, so a split
    on ``:`` is sufficient here (no Windows drive-letter support).
    """
    parts = spec.split(":")
    if len(parts) < 2:
        return None
    host, cage = parts[0], parts[1]
    options = tuple(
        opt for field in parts[2:] for opt in field.split(",") if opt
    )
    return host, cage, options


def writable_host_binds(expanded_volumes: list[str]) -> tuple[BindMount, ...]:
    """Return writable host binds from already-expanded volume specs.

    Named volumes are ignored (their source is not a host path) and read-only
    binds are ignored (the cage cannot plant hooks through them).  The caller is
    expected to pass the same validated/expanded volume list that will be
    rendered into the runtime configuration.
    """
    out: list[BindMount] = []
    for spec in expanded_volumes:
        parsed = _split_volume_spec(spec)
        if not parsed:
            continue
        host, cage, options = parsed
        if not host.startswith(("/", "~")):
            continue
        if not cage.startswith("/"):
            continue
        if "ro" in options:
            continue
        out.append(BindMount(host, cage, options))
    return tuple(out)


def _is_git_hooks_dir(host_root: str, dirpath: str) -> bool:
    rel = os.path.relpath(dirpath, host_root)
    if rel == os.curdir:
        return False
    parts = rel.split(os.sep)
    return parts[-1] == "hooks" and ".git" in parts[:-1]


def discover_git_hooks_masks(expanded_volumes: list[str], *, enabled: bool) -> GitHooksGuardPlan:
    """Discover all existing Git hook dirs under writable host binds.

    Only existing directories are returned.  This is load-bearing: container
    runtimes create an absent tmpfs/bind mountpoint *through* the parent host
    bind, which would litter clean projects with stray ``.git`` directories.
    """
    binds = writable_host_binds(expanded_volumes)
    if not enabled:
        return GitHooksGuardPlan(binds=binds, masks=())

    masks: list[GitHooksMask] = []
    seen_cage_paths: set[str] = set()
    for bind in binds:
        host_root = os.path.realpath(os.path.expanduser(bind.host_path))
        if not os.path.isdir(host_root):
            continue
        for dirpath, dirnames, _filenames in os.walk(host_root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
            if not _is_git_hooks_dir(host_root, dirpath):
                continue
            rel = os.path.relpath(dirpath, host_root)
            cage_path = str(PurePosixPath(bind.cage_path, *rel.split(os.sep)))
            if cage_path in seen_cage_paths:
                continue
            seen_cage_paths.add(cage_path)
            masks.append(GitHooksMask(host_path=dirpath, cage_path=cage_path))
    return GitHooksGuardPlan(binds=binds, masks=tuple(masks))


def _file_fingerprint(path: Path) -> str:
    if path.is_symlink():
        return "symlink:" + os.readlink(path)
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _is_active_hook(path: Path) -> bool:
    if path.name not in GIT_HOOK_NAMES:
        return False
    if path.parent.name == "hooks" and ".git" in path.parts:
        return True
    return path.parent.name in {".githooks", ".husky"}


def _is_tamper_sentinel(root: Path, path: Path) -> bool:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return False
    if _is_active_hook(path):
        return True
    return rel in TAMPER_SENTINELS or rel.endswith("/.claude/settings.json")


def snapshot_tamper_state(roots: tuple[str, ...]) -> dict[str, str]:
    """Return ``{path: fingerprint}`` for host-trusted files under *roots*."""
    state: dict[str, str] = {}
    for root_s in roots:
        root = Path(os.path.realpath(os.path.expanduser(root_s)))
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
            dpath = Path(dirpath)
            for filename in filenames:
                path = dpath / filename
                if not _is_tamper_sentinel(root, path):
                    continue
                try:
                    state[str(path)] = _file_fingerprint(path)
                except OSError:
                    continue
    return dict(sorted(state.items()))


def diff_tamper_state(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """Return human-readable tamper warnings for changed sentinel files."""
    warnings: list[str] = []
    for path in sorted(set(before) | set(after)):
        if path not in before:
            warnings.append(f"created: {path}")
        elif path not in after:
            warnings.append(f"removed: {path}")
        elif before[path] != after[path]:
            warnings.append(f"modified: {path}")
    return warnings


def _bash_array(values: tuple[str, ...]) -> str:
    return " ".join(shlex.quote(v) for v in values)


def _guard_snapshot_bash() -> str:
    hooks = _bash_array(GIT_HOOK_NAMES)
    hook_dirs = _bash_array(TAMPER_HOOK_DIR_NAMES)
    sentinels = _bash_array(TAMPER_SENTINELS)
    prunes = " -o ".join(f"-name {shlex.quote(d)}" for d in sorted(_PRUNE_DIRS))
    prune_expr = f"\\( {prunes} \\) -prune -o" if prunes else ""
    # Emits ``<hash>  <path>`` lines.  Active Git hooks and selected
    # host-trusted config files are included; sample hooks are ignored.
    return (
        f"hooks=({hooks}); hook_dirs=({hook_dirs}); sentinels=({sentinels}); "
        "is_hook(){ local p=\"$1\" b=\"${p##*/}\" parent=\"${p%/*}\" d=\"${parent##*/}\"; "
        "[[ \" ${hooks[*]} \" == *\" $b \"* ]] || return 1; "
        "[[ \"$p\" == */.git/hooks/* || \"$p\" == */.git/*/hooks/* ]] && return 0; "
        "[[ \" ${hook_dirs[*]} \" == *\" $d \"* ]] && [[ \"$d\" != hooks ]] && return 0; "
        "return 1; }; "
        "is_sentinel(){ local r=\"$1\" p=\"$2\" rel=\"${p#$r/}\"; for s in \"${sentinels[@]}\"; do [[ \"$rel\" == \"$s\" || \"$rel\" == */.claude/settings.json ]] && return 0; done; return 1; }; "
        "snapshot(){ "
        "for root in \"${roots[@]}\"; do "
        "[ -d \"$root\" ] || continue; "
        f"while IFS= read -r -d '' p; do "
        "is_hook \"$p\" || is_sentinel \"$root\" \"$p\" || continue; "
        "if command -v sha256sum >/dev/null 2>&1; then sha256sum -- \"$p\" 2>/dev/null || true; "
        "else cksum \"$p\" 2>/dev/null || true; fi; "
        f"done < <(find \"$root\" {prune_expr} \\( -type f -o -type l \\) -print0 2>/dev/null); "
        "done | sort; "
        "}; "
    )


def render_guard_baseline_command(name: str, roots: tuple[str, ...]) -> str:
    """Return a systemd ExecStartPre command that snapshots tamper state."""
    if not roots:
        return ""
    roots_arr = _bash_array(roots)
    script = (
        "set -u; "
        f"roots=({roots_arr}); "
        f"base=\"%t/agentcage-{name}-workspace-guard.baseline\"; "
        + _guard_snapshot_bash()
        + "snapshot > \"$base\""
    )
    return "/bin/bash -lc " + shlex.quote(script)


def render_guard_check_command(name: str, roots: tuple[str, ...]) -> str:
    """Return a systemd ExecStopPost command that warns about tampering."""
    if not roots:
        return ""
    roots_arr = _bash_array(roots)
    script = (
        "set -u; "
        f"roots=({roots_arr}); "
        f"base=\"%t/agentcage-{name}-workspace-guard.baseline\"; "
        + _guard_snapshot_bash()
        + "if [ -f \"$base\" ]; then "
        "now=\"$base.now\"; snapshot > \"$now\"; "
        "comm -13 \"$base\" \"$now\" | while IFS= read -r line; do "
        "echo \"agentcage warning: host-trusted workspace file created or modified while cage ran: $line\" >&2; done; "
        "comm -23 \"$base\" \"$now\" | while IFS= read -r line; do "
        "echo \"agentcage warning: host-trusted workspace file removed while cage ran: $line\" >&2; done; "
        "rm -f \"$now\" \"$base\"; "
        "fi"
    )
    return "/bin/bash -lc " + shlex.quote(script)
