"""Shared parsing and validation for user-declared host bind mounts."""

from __future__ import annotations


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
