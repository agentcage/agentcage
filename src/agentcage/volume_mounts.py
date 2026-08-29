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


def tmpfs_spec_target(spec: str) -> str:
    """Return the container path of a ``container.tmpfs`` spec.

    An entry is ``target[:options]``; only the target is meaningful to the
    mount-topology helpers below.
    """
    return spec.split(":", 1)[0]


def tmpfs_spec_options(spec: str) -> list[str]:
    """Return the non-empty options of a ``container.tmpfs`` spec."""
    _target, _sep, raw_options = spec.partition(":")
    return [option for option in raw_options.split(",") if option]


# Copy-up options, as podman's ``pkg/util/mountOpts.go`` spells them. Podman
# appends ``tmpcopyup`` to every tmpfs that declares neither, which is why the
# scaffold masks came up on podman holding the host's hooks and project
# ``.claude/`` while apple-container (whose ``--tmpfs`` has no option channel
# at all) came up empty — issue #328.
TMPFS_COPYUP_OPTIONS = ("tmpcopyup", "notmpcopyup")


def tmpfs_wants_copyup(spec: str) -> bool:
    """Return whether *spec* explicitly asks for ``tmpcopyup``.

    Only an explicit request counts. agentcage pins ``notmpcopyup`` on mask
    entries that declare neither option (see
    :func:`agentcage.quadlets._apply_tmpfs_mask_options`), so "unspecified"
    means *empty* on every backend rather than whatever the runtime happens
    to default to.
    """
    options = tmpfs_spec_options(spec)
    return "tmpcopyup" in options and "notmpcopyup" not in options


def enclosing_mount(
    target: str,
    mount_targets: list[tuple[str, str]],
) -> tuple[str, str]:
    """Return the deepest mount in *mount_targets* that contains *target*.

    Args:
        target: An absolute container path, without a trailing slash.
        mount_targets: ``(container_target, host_source)`` for every mount the
            backend emits, where *host_source* is empty for mounts that do not
            write through to the host (named volumes, ``np`` mounts whose
            writes land in an overlay upperdir or a tmpfs).

    Returns:
        ``(mount_target, host_source)`` for the longest matching mount target,
        or ``("", "")`` when no mount encloses *target*. A mount at ``/`` never
        matches: it would make every path in the cage look nested.
    """
    best_target = ""
    best_source = ""
    for raw_target, source in mount_targets:
        if not raw_target.startswith("/"):
            continue
        mount_target = raw_target.rstrip("/") or "/"
        if target != mount_target and not target.startswith(mount_target + "/"):
            continue
        if len(mount_target) >= len(best_target):
            best_target, best_source = mount_target, source
    return best_target, best_source


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
    result: dict[str, list[str]] = {}
    for spec in tmpfs:
        target = tmpfs_spec_target(spec).rstrip("/")
        if not target.startswith("/"):
            continue
        best_target, best_source = enclosing_mount(target, mount_targets)
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


def mask_copyup_entries(
    tmpfs: list[str],
    mount_targets: list[tuple[str, str]],
) -> list[tuple[str, str, str]]:
    """Return ``(container_target, host_source, host_root)`` for copy-up masks.

    A *mask* is a ``tmpfs:`` entry whose target sits at or below another
    emitted mount — the same relation :func:`mask_mountpoint_dirs` and
    :func:`agentcage.quadlets._apply_tmpfs_mask_options` use. A tmpfs over a
    plain image directory (``/tmp``, ``/var/cache``) has no enclosing mount
    and is never returned: its contents are the image author's intent and
    the runtime's own copy-up already expresses them.

    Args:
        tmpfs: Raw ``container.tmpfs`` specs (``target[:options]``).
        mount_targets: ``(container_target, host_source)`` for every mount the
            backend emits, in the shape :func:`mask_mountpoint_dirs` consumes.

    Returns:
        One entry per copy-up mask, ordered as declared. *container_target*
        is normalized (no trailing slash). *host_source* is the host
        directory the mask covers — ``<bind source>/<relative path>`` — and
        *host_root* the enclosing bind's own source, so a caller that turns
        *host_source* into a mount can require it to resolve inside the
        directory the operator already agreed to share (a project-supplied
        ``.claude -> ../../.ssh`` symlink must not become a new host
        exposure). Both are ``""`` when the enclosing mount does not reach
        the host (a named volume, an ``np`` bind), in which case only a
        runtime-side copy-up can populate the tmpfs.
    """
    entries: list[tuple[str, str, str]] = []
    for spec in tmpfs:
        target = tmpfs_spec_target(spec).rstrip("/")
        if not target.startswith("/") or not tmpfs_wants_copyup(spec):
            continue
        normalized = os.path.normpath(target)
        best_target, best_source = enclosing_mount(normalized, mount_targets)
        if not best_target:
            continue
        source = ""
        if best_source:
            parts = [
                p for p in normalized[len(best_target):].split("/") if p
            ]
            if not any(p in (".", "..") for p in parts):
                source = os.path.join(best_source, *parts)
        entries.append((normalized, source, best_source if source else ""))
    return entries
