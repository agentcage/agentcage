"""Shared parsing and validation for user-declared host bind mounts."""

from __future__ import annotations

import os


# Keep np deliberately portable across Podman and apple-container. In
# particular, Podman's overlay ``O`` cannot compose with z/Z, U mutates the
# host source, and Apple container's bare --tmpfs has no option channel.
_NP_ALLOWED_OPTIONS = {"np", "rw"}


def split_volume_spec(spec: str) -> tuple[str, str, str]:
    """Split ``host:target[:options]`` into its three fields."""
    parts = spec.split(":", 2)
    if len(parts) < 2:
        return spec, "", ""
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return parts[0], parts[1], parts[2]


def volume_options(spec: str) -> list[str]:
    """Return non-empty comma-separated options from a volume spec."""
    _source, _target, raw_options = split_volume_spec(spec)
    return [option for option in raw_options.split(",") if option]


def is_non_persistent_volume(spec: str) -> bool:
    """Return whether *spec* carries agentcage's inline ``np`` option."""
    return "np" in volume_options(spec)


def validate_non_persistent_volume(spec: str) -> None:
    """Reject options that cannot safely compose with ``np``.

    ``np`` creates a writable overlay whose host source is read-only. In
    particular, Podman's ``O`` overlay cannot combine with ``z``/``Z``;
    ``U`` would recursively chown the host source; and caller-provided overlay
    directories would escape agentcage's cleanup lifecycle.
    """
    options = volume_options(spec)
    if "np" not in options:
        return

    unsupported = [
        option for option in options
        if option not in _NP_ALLOWED_OPTIONS
    ]
    if unsupported:
        joined = ", ".join(unsupported)
        raise ValueError(
            f"volume {spec!r}: the np option cannot be combined with "
            f"{joined}; only rw,np is supported"
        )


def mask_mountpoint_dirs(
    tmpfs: list[str],
    mount_targets: list[tuple[str, str]],
) -> dict[str, list[str]]:
    """Map bind-mount host source -> host dirs a ``tmpfs:`` mask materializes.

    A ``tmpfs:`` entry whose target sits *under* a host bind-mount forces the
    OCI runtime to create the mount point, and because a bind shares inodes
    with its source, that ``mkdir -p`` lands in the operator's project
    directory on the host. The scaffold masks are the common case: masking
    ``/workspace/.git/hooks/`` on a project that is not a git repo leaves a
    stray host ``.git/hooks/``, which makes the ubiquitous ``test -d .git``
    idiom misreport the directory as a repository (issue #320).

    The mask itself stays unconditional — dropping it when ``.git`` is absent
    would reopen the #170 cage->host git-hook pivot for any ``.git`` created
    later. Instead the caller records which of these paths were absent
    immediately before container start and removes exactly those, and only
    while still empty, on teardown.

    Args:
        tmpfs: Raw ``container.tmpfs`` specs (``target[:options]``).
        mount_targets: ``(container_target, host_source)`` for every mount the
            backend emits, where *host_source* is empty for mounts that do not
            write through to the host (named volumes, ``np`` mounts whose
            writes land in an overlay upperdir or a tmpfs). Longest-prefix
            matching runs over the whole list so that a mask under, say, a
            named volume nested inside a bind is correctly attributed to the
            named volume and therefore skipped.

    Returns:
        ``{host_source: [host_path, ...]}`` with each list ordered deepest
        first, so removing ``<project>/.git/hooks`` is attempted before the
        ``<project>/.git`` parent that the same mask also created.
    """
    normalized = [
        (target.rstrip("/") or "/", source)
        for target, source in mount_targets
        if target.startswith("/")
    ]
    result: dict[str, list[str]] = {}
    for spec in tmpfs:
        target = spec.split(":", 1)[0].rstrip("/")
        if not target.startswith("/"):
            continue
        best_target = ""
        best_source = ""
        for mount_target, source in normalized:
            if target != mount_target and not target.startswith(mount_target + "/"):
                continue
            if len(mount_target) >= len(best_target):
                best_target, best_source = mount_target, source
        # No enclosing mount (the mount point is created in the container's
        # own writable layer), the mask covers the whole mount (nothing to
        # create), or the enclosing mount does not reach the host.
        if not best_source or target == best_target:
            continue
        parts = [p for p in target[len(best_target):].split("/") if p]
        if not parts or any(p in (".", "..") for p in parts):
            continue
        dirs = result.setdefault(best_source, [])
        for depth in range(len(parts), 0, -1):
            path = os.path.join(best_source, *parts[:depth])
            if path not in dirs:
                dirs.append(path)
    for dirs in result.values():
        dirs.sort(key=lambda path: path.count("/"), reverse=True)
    return result
