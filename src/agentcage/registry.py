"""Resolve the latest version tag for a container image via skopeo."""

from __future__ import annotations

import json
import re
import subprocess


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
