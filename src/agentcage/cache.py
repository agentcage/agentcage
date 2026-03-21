"""Build cache for fast warm starts.

Caches image builds and quadlet installations so that repeat ``agentcage run``
invocations skip expensive rebuild steps when nothing has changed.

Cache failures are never fatal — every public function in this module is
designed so callers can wrap calls in ``try/except Exception`` and fall
through to a full build.

Limitation: the cache key does NOT include the upstream base-image digest.
If a base image (e.g. ``node:22-slim``) receives a security update, the
cache will still report a hit.  Users can force a rebuild with
``agentcage cache clear``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tempfile
from pathlib import Path

from agentcage.podman import Podman

logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".cache" / "agentcage"


def _package_version() -> str:
    """Return the installed agentcage version (part of every cache key)."""
    try:
        from importlib.metadata import version
        return version("agentcage")
    except Exception:
        return "unknown"


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically via rename.

    Prevents partial reads when two processes write concurrently.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    closed = False
    try:
        os.write(fd, content.encode())
        os.close(fd)
        closed = True
        os.rename(tmp, str(path))
    except BaseException:
        if not closed:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── Image cache ──────────────────────────────────────────


def image_cache_key(scaffold: str, containerfile_content: str, scaffold_config: str) -> str:
    """Hash the Containerfile + scaffold config + package version to create a cache key.

    The package version is included so that upgrading agentcage (which may
    ship new infra images or scaffold changes) automatically invalidates
    the cache.
    """
    h = hashlib.sha256()
    h.update(scaffold.encode())
    h.update(containerfile_content.encode())
    h.update(scaffold_config.encode())
    h.update(_package_version().encode())
    return h.hexdigest()[:16]


def is_image_cached(scaffold: str, cache_key: str, podman: Podman) -> bool:
    """Check if image with this cache key exists in Podman.

    Returns ``False`` (never raises) on any I/O or Podman error.
    """
    try:
        marker = CACHE_DIR / "images" / f"{scaffold}-{cache_key}.built"
        if not marker.exists():
            return False
        image_tag = marker.read_text().strip()
        if not image_tag:
            return False
        return podman.image_exists(image_tag)
    except Exception:
        return False


def mark_image_built(scaffold: str, cache_key: str, image_tag: str) -> None:
    """Record that an image was built with this cache key.

    Atomically writes the marker and removes stale markers for the same
    scaffold (previous cache keys).
    """
    marker_dir = CACHE_DIR / "images"
    marker_dir.mkdir(parents=True, exist_ok=True)

    # Remove stale markers for this scaffold before writing the new one
    prefix = f"{scaffold}-"
    new_name = f"{scaffold}-{cache_key}.built"
    try:
        for old in marker_dir.iterdir():
            if old.name.startswith(prefix) and old.name != new_name:
                old.unlink(missing_ok=True)
    except OSError:
        pass

    marker = marker_dir / new_name
    _atomic_write(marker, image_tag)


# ── Quadlet cache ────────────────────────────────────────


def quadlet_cache_key(quadlet_contents: dict[str, str]) -> str:
    """Hash all quadlet file contents."""
    h = hashlib.sha256()
    for name in sorted(quadlet_contents):
        h.update(name.encode())
        h.update(quadlet_contents[name].encode())
    return h.hexdigest()[:16]


def are_quadlets_cached(cage_name: str, cache_key: str) -> bool:
    """Check if installed quadlets match this cache key.

    Returns ``False`` (never raises) on any I/O error.
    """
    try:
        marker = CACHE_DIR / "quadlets" / f"{cage_name}-{cache_key}.installed"
        return marker.exists()
    except Exception:
        return False


def mark_quadlets_installed(cage_name: str, cache_key: str) -> None:
    """Record that quadlets were installed with this cache key.

    Removes stale markers for the same cage before writing.
    """
    marker_dir = CACHE_DIR / "quadlets"
    marker_dir.mkdir(parents=True, exist_ok=True)

    # Remove stale markers for this cage
    prefix = f"{cage_name}-"
    new_name = f"{cage_name}-{cache_key}.installed"
    try:
        for old in marker_dir.iterdir():
            if old.name.startswith(prefix) and old.name != new_name:
                old.unlink(missing_ok=True)
    except OSError:
        pass

    _atomic_write(marker_dir / new_name, "")


# ── Cache cleanup ────────────────────────────────────────


def clear_cage_cache(cage_name: str) -> int:
    """Remove all cache markers for a specific cage.

    Checks both cage name (quadlet markers) and scaffold name (image
    markers) prefixes.

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
