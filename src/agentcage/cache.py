"""Build cache for fast warm starts.

Caches image builds and quadlet installations so that repeat ``agentcage run``
invocations skip expensive rebuild steps when nothing has changed.

Cache failures are never fatal — callers should always fall through to a
full build on any exception.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from pathlib import Path

from agentcage.podman import Podman

logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".cache" / "agentcage"


# ── Image cache ──────────────────────────────────────────


def image_cache_key(scaffold: str, containerfile_content: str, scaffold_config: str) -> str:
    """Hash the Containerfile + scaffold config to create a cache key."""
    h = hashlib.sha256()
    h.update(scaffold.encode())
    h.update(containerfile_content.encode())
    h.update(scaffold_config.encode())
    return h.hexdigest()[:16]


def is_image_cached(scaffold: str, cache_key: str, podman: Podman) -> bool:
    """Check if image with this cache key exists in Podman."""
    marker = CACHE_DIR / "images" / f"{scaffold}-{cache_key}.built"
    if not marker.exists():
        return False
    # Also verify the image actually exists in podman
    image_tag = marker.read_text().strip()
    if not image_tag:
        return False
    return podman.image_exists(image_tag)


def mark_image_built(scaffold: str, cache_key: str, image_tag: str) -> None:
    """Record that an image was built with this cache key."""
    marker_dir = CACHE_DIR / "images"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = marker_dir / f"{scaffold}-{cache_key}.built"
    marker.write_text(image_tag)


# ── Quadlet cache ────────────────────────────────────────


def quadlet_cache_key(quadlet_contents: dict[str, str]) -> str:
    """Hash all quadlet file contents."""
    h = hashlib.sha256()
    for name in sorted(quadlet_contents):
        h.update(name.encode())
        h.update(quadlet_contents[name].encode())
    return h.hexdigest()[:16]


def are_quadlets_cached(cage_name: str, cache_key: str) -> bool:
    """Check if installed quadlets match this cache key."""
    marker = CACHE_DIR / "quadlets" / f"{cage_name}-{cache_key}.installed"
    return marker.exists()


def mark_quadlets_installed(cage_name: str, cache_key: str) -> None:
    """Record that quadlets were installed with this cache key."""
    marker_dir = CACHE_DIR / "quadlets"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = marker_dir / f"{cage_name}-{cache_key}.installed"
    marker.write_text("")


# ── Cache cleanup ────────────────────────────────────────


def clear_cage_cache(cage_name: str) -> int:
    """Remove all cache markers for a specific cage.

    Returns the number of markers removed.
    """
    removed = 0
    for subdir in ("images", "quadlets"):
        cache_subdir = CACHE_DIR / subdir
        if not cache_subdir.is_dir():
            continue
        for marker in cache_subdir.iterdir():
            if marker.name.startswith(f"{cage_name}-"):
                marker.unlink(missing_ok=True)
                removed += 1
    return removed


def clear_all_cache() -> int:
    """Remove the entire cache directory.

    Returns the number of markers removed.
    """
    removed = 0
    for subdir in ("images", "quadlets"):
        cache_subdir = CACHE_DIR / subdir
        if not cache_subdir.is_dir():
            continue
        for marker in cache_subdir.iterdir():
            marker.unlink(missing_ok=True)
            removed += 1
    # Remove directory structure too
    if CACHE_DIR.is_dir():
        shutil.rmtree(str(CACHE_DIR), ignore_errors=True)
    return removed
