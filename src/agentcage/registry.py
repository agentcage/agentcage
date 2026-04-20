"""Resolve the latest version tag for a container image via skopeo."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Callable


def _version_key(tag: str) -> list[int | str]:
    """Sort key for dotted version strings (e.g. '2026.2.24', 'v0.1.2')."""
    raw = tag.lstrip("v")
    parts = raw.split(".")
    result: list[int | str] = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(p)
    return result


def resolve_latest_tag(image: str) -> str | None:
    """Return the highest version tag for *image*, or ``None`` on failure.

    Queries the registry via ``skopeo list-tags`` and filters to tags that
    look like version numbers (``YYYY.M.D``, ``vX.Y.Z``, etc.), excluding
    architecture suffixes (``-amd64``, ``-arm64``).
    """
    try:
        r = subprocess.run(
            ["skopeo", "list-tags", f"docker://{image}"],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        import sys
        print(
            "warning: skopeo is not installed — "
            "install it for automatic image version pinning",
            file=sys.stderr,
        )
        return None
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return None

    try:
        data = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return None

    tags = data.get("Tags", [])
    # Match version-like tags: bare dotted numbers or v-prefixed
    version_re = re.compile(r"^v?\d[\d.]*$")
    # Exclude arch suffixes
    arch_re = re.compile(r"-(amd64|arm64|x86_64|aarch64)$")
    matching = [
        t for t in tags
        if version_re.match(t) and not arch_re.search(t)
    ]
    if not matching:
        return None

    matching.sort(key=_version_key)
    return matching[-1]


def _resolve_one(
    current: str,
    scaffold_val: str | None,
    resolver: Callable[[str], str | None],
) -> str:
    """Resolve a single build-arg value. See resolve_build_args for semantics."""
    if scaffold_val is not None:
        _, _, scaffold_tag = scaffold_val.rpartition(":")
        if ":" in scaffold_val and scaffold_tag:
            # Scaffold author pinned it — use scaffold value verbatim
            return scaffold_val
        # Scaffold declares untagged — re-resolve against scaffold base
        scaffold_base = scaffold_val.split(":", 1)[0]
        new_tag = resolver(scaffold_base)
        if new_tag is None:
            # Resolver failure — preserve existing pin to avoid breaking builds
            return current
        return f"{scaffold_base}:{new_tag}"

    # User-added arg.
    _, _, tag = current.rpartition(":")
    if ":" in current and tag:
        return current  # already pinned, respect
    if "/" in current:
        # Registry-path-like ref without a tag — try to resolve
        new_tag = resolver(current)
        if new_tag:
            return f"{current}:{new_tag}"
    return current


def resolve_build_args(
    build_args: dict[str, str],
    scaffold_args: dict[str, str] | None = None,
    resolver: Callable[[str], str | None] | None = None,
) -> tuple[dict[str, str], list[tuple[str, str, str]]]:
    """Resolve image tags in *build_args*, returning (resolved, changes).

    *changes* lists (key, old_value, new_value) tuples for each arg whose value
    changed, so callers can echo transitions. When the scaffold-declared base
    differs from the stored base (upstream rename/migration), callers can detect
    drift by comparing the base portion of old vs new.

    +-------------------+--------------------------------------+
    | scaffold declares | behavior                             |
    +-------------------+--------------------------------------+
    | tagged value      | use scaffold value verbatim (respect |
    |                   | author's pin; migrate on change)     |
    | untagged value    | re-resolve using scaffold base       |
    |                   | (auto-bump; migrate base on rename;  |
    |                   | preserve stored on resolver failure) |
    | not present       | user-added: resolve if untagged &    |
    |                   | registry-like, else passthrough      |
    +-------------------+--------------------------------------+

    *resolver* is injectable for tests; defaults to :func:`resolve_latest_tag`.
    """
    scaffold_args = scaffold_args or {}
    resolver = resolver or resolve_latest_tag
    resolved: dict[str, str] = {}
    changes: list[tuple[str, str, str]] = []
    for key, current in build_args.items():
        new_val = _resolve_one(current, scaffold_args.get(key), resolver)
        resolved[key] = new_val
        if new_val != current:
            changes.append((key, current, new_val))
    return resolved, changes
