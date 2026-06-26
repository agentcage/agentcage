"""Workspace ``.git/hooks`` masking policy (issue #170).

Every scaffold bind-mounts the operator's project directory into the cage at
``/workspace:rw`` — which includes ``.git/hooks/``. A malicious in-cage agent
can plant ``.git/hooks/pre-commit`` (or ``post-checkout`` etc.); the next time
the operator runs ``git`` on the **host**, git executes the planted hook as the
host user. Full cage→host pivot via the most mundane post-cage action.

The fix masks ``/workspace/.git/hooks`` with an ephemeral overlay (a tmpfs)
so in-cage writes there never reach the host. A spike
(``docs/spikes/2026-06-tmpfs-workspace-mask-spike.md``) established two
load-bearing facts:

1. The overlay stops cage→host persistence on every backend (in-cage writes
   land in the tmpfs and vanish on stop; the host's real hooks are untouched).
2. Masking a subpath that does **not** exist on the host makes the runtime
   ``mkdir`` the mountpoint *through* the bind, **littering the host** with a
   stray ``.git/``. So the mask must only be emitted when the host's
   ``.git/hooks`` already exists — which is true for every real git repo, the
   only case the pivot threat applies to.

This module is the single source of truth for that policy; the container/vm
quadlet path and the apple-container backend both consume it.
"""

from __future__ import annotations

import os

#: Cage-side path masked. A real, sandboxed agent only ever sees an empty,
#: ephemeral directory here.
GIT_HOOKS_CAGE_PATH = "/workspace/.git/hooks"

#: tmpfs spec used by the container/vm (quadlet) backends. Apple's
#: ``container run --tmpfs`` takes a *bare path* only (it treats ``:opts`` as a
#: literal directory name — see the spike), so the apple backend passes
#: :data:`GIT_HOOKS_CAGE_PATH` directly instead of this spec.
GIT_HOOKS_TMPFS_SPEC = f"{GIT_HOOKS_CAGE_PATH}:rw,noexec,nosuid,size=8M"


def workspace_host_dir(expanded_volumes: list[str]) -> str | None:
    """Return the host directory bind-mounted at ``/workspace``, or ``None``.

    *expanded_volumes* are ``host:cage[:mode]`` strings with the host side
    already resolved to an absolute path. Only a host **bind** of ``/workspace``
    is a pivot surface; openclaw mounts ``/workspace`` from a podman *named
    volume* (handled separately, never appears here), so it correctly yields
    ``None`` and gets no mask.
    """
    for entry in expanded_volumes:
        parts = entry.split(":")
        if len(parts) >= 2 and parts[1] == "/workspace":
            return parts[0]
    return None


def git_hooks_mask_path(host_workspace: str | None, *, enabled: bool) -> str | None:
    """Return :data:`GIT_HOOKS_CAGE_PATH` if the mask should be applied, else
    ``None``.

    The mask is applied only when (a) the operator hasn't opted out
    (``enabled``), (b) a host dir is bind-mounted at ``/workspace``, and
    (c) that dir actually has a ``.git/hooks`` directory. Condition (c) is the
    litter guard from the spike: masking an absent path would create a stray
    ``.git/`` on the host.
    """
    if not enabled or not host_workspace:
        return None
    if os.path.isdir(os.path.join(host_workspace, ".git", "hooks")):
        return GIT_HOOKS_CAGE_PATH
    return None
