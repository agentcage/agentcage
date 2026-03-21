"""Tests for agentcage.cache — build cache for fast warm starts."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentcage import cache


# ── Helpers ──────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path, monkeypatch):
    """Redirect CACHE_DIR to a temp directory for every test."""
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / ".cache" / "agentcage")


def _make_podman(image_exists: bool = True) -> MagicMock:
    podman = MagicMock()
    podman.image_exists.return_value = image_exists
    return podman


# ── image_cache_key ──────────────────────────────────────


class TestImageCacheKey:
    def test_deterministic(self):
        k1 = cache.image_cache_key("claude-code", "FROM node:22", "name: test")
        k2 = cache.image_cache_key("claude-code", "FROM node:22", "name: test")
        assert k1 == k2

    def test_length(self):
        k = cache.image_cache_key("s", "cf", "cfg")
        assert len(k) == 16

    def test_hex_chars(self):
        k = cache.image_cache_key("s", "cf", "cfg")
        assert all(c in "0123456789abcdef" for c in k)

    def test_changes_on_containerfile(self):
        k1 = cache.image_cache_key("s", "FROM node:22", "cfg")
        k2 = cache.image_cache_key("s", "FROM node:23", "cfg")
        assert k1 != k2

    def test_changes_on_scaffold(self):
        k1 = cache.image_cache_key("a", "cf", "cfg")
        k2 = cache.image_cache_key("b", "cf", "cfg")
        assert k1 != k2

    def test_changes_on_config(self):
        k1 = cache.image_cache_key("s", "cf", "config-a")
        k2 = cache.image_cache_key("s", "cf", "config-b")
        assert k1 != k2

    def test_includes_package_version(self, monkeypatch):
        """Cache key changes when agentcage version changes."""
        monkeypatch.setattr(cache, "_package_version", lambda: "1.0.0")
        k1 = cache.image_cache_key("s", "cf", "cfg")
        monkeypatch.setattr(cache, "_package_version", lambda: "1.1.0")
        k2 = cache.image_cache_key("s", "cf", "cfg")
        assert k1 != k2


# ── is_image_cached / mark_image_built ───────────────────


class TestImageCache:
    def test_miss_when_no_marker(self):
        podman = _make_podman()
        assert not cache.is_image_cached("s", "key123", podman)

    def test_hit_after_mark(self):
        podman = _make_podman(image_exists=True)
        cache.mark_image_built("s", "key123", "localhost/test:latest")
        assert cache.is_image_cached("s", "key123", podman)
        podman.image_exists.assert_called_with("localhost/test:latest")

    def test_miss_when_image_removed(self):
        podman = _make_podman(image_exists=False)
        cache.mark_image_built("s", "key123", "localhost/test:latest")
        assert not cache.is_image_cached("s", "key123", podman)

    def test_miss_on_different_key(self):
        podman = _make_podman(image_exists=True)
        cache.mark_image_built("s", "key-aaa", "localhost/test:latest")
        assert not cache.is_image_cached("s", "key-bbb", podman)

    def test_miss_on_empty_marker(self):
        """A corrupted marker with empty content is a miss."""
        podman = _make_podman(image_exists=True)
        marker_dir = cache.CACHE_DIR / "images"
        marker_dir.mkdir(parents=True)
        (marker_dir / "s-key123.built").write_text("")
        assert not cache.is_image_cached("s", "key123", podman)

    def test_fallthrough_on_corrupted_cache(self):
        """Corrupted marker file should not crash."""
        podman = _make_podman(image_exists=True)
        marker_dir = cache.CACHE_DIR / "images"
        marker_dir.mkdir(parents=True)
        (marker_dir / "s-key123.built").write_text("\x00\x01bad-data")
        result = cache.is_image_cached("s", "key123", podman)
        assert isinstance(result, bool)

    def test_fallthrough_on_podman_error(self):
        """If podman.image_exists raises, is_image_cached returns False."""
        podman = _make_podman()
        podman.image_exists.side_effect = RuntimeError("podman died")
        cache.mark_image_built("s", "key123", "localhost/test:latest")
        assert not cache.is_image_cached("s", "key123", podman)

    def test_stale_markers_cleaned_on_write(self):
        """Writing a new marker for the same scaffold removes old ones."""
        marker_dir = cache.CACHE_DIR / "images"
        cache.mark_image_built("scaffold-a", "old-key", "img:old")
        assert (marker_dir / "scaffold-a-old-key.built").exists()
        cache.mark_image_built("scaffold-a", "new-key", "img:new")
        assert not (marker_dir / "scaffold-a-old-key.built").exists()
        assert (marker_dir / "scaffold-a-new-key.built").exists()

    def test_stale_cleanup_does_not_affect_other_scaffolds(self):
        """Stale marker cleanup only removes markers for the same scaffold."""
        marker_dir = cache.CACHE_DIR / "images"
        cache.mark_image_built("scaffold-a", "k1", "img:a")
        cache.mark_image_built("scaffold-b", "k2", "img:b")
        # Re-mark scaffold-a with new key
        cache.mark_image_built("scaffold-a", "k3", "img:a2")
        assert not (marker_dir / "scaffold-a-k1.built").exists()
        assert (marker_dir / "scaffold-b-k2.built").exists()


# ── quadlet_cache_key ────────────────────────────────────


class TestQuadletCacheKey:
    def test_deterministic(self):
        contents = {"a.container": "content-a", "b.network": "content-b"}
        k1 = cache.quadlet_cache_key(contents)
        k2 = cache.quadlet_cache_key(contents)
        assert k1 == k2

    def test_order_independent(self):
        k1 = cache.quadlet_cache_key({"a": "1", "b": "2"})
        k2 = cache.quadlet_cache_key({"b": "2", "a": "1"})
        assert k1 == k2

    def test_changes_on_content(self):
        k1 = cache.quadlet_cache_key({"a.container": "v1"})
        k2 = cache.quadlet_cache_key({"a.container": "v2"})
        assert k1 != k2

    def test_length(self):
        k = cache.quadlet_cache_key({"f": "c"})
        assert len(k) == 16


# ── are_quadlets_cached / mark_quadlets_installed ────────


class TestQuadletCache:
    def test_miss_when_no_marker(self):
        assert not cache.are_quadlets_cached("cage1", "key123")

    def test_hit_after_mark(self):
        cache.mark_quadlets_installed("cage1", "key123")
        assert cache.are_quadlets_cached("cage1", "key123")

    def test_miss_on_different_key(self):
        cache.mark_quadlets_installed("cage1", "key-aaa")
        assert not cache.are_quadlets_cached("cage1", "key-bbb")

    def test_stale_markers_cleaned_on_write(self):
        """Writing a new quadlet marker removes old ones for the same cage."""
        marker_dir = cache.CACHE_DIR / "quadlets"
        cache.mark_quadlets_installed("cage1", "old-key")
        assert (marker_dir / "cage1-old-key.installed").exists()
        cache.mark_quadlets_installed("cage1", "new-key")
        assert not (marker_dir / "cage1-old-key.installed").exists()
        assert (marker_dir / "cage1-new-key.installed").exists()


# ── clear_cage_cache ─────────────────────────────────────


class TestClearCageCache:
    def test_clear_removes_markers(self):
        podman = _make_podman()
        cache.mark_image_built("mycage", "k1", "img:1")
        cache.mark_quadlets_installed("mycage", "k2")
        assert cache.is_image_cached("mycage", "k1", podman)
        assert cache.are_quadlets_cached("mycage", "k2")

        removed = cache.clear_cage_cache("mycage")
        assert removed == 2
        assert not cache.is_image_cached("mycage", "k1", podman)
        assert not cache.are_quadlets_cached("mycage", "k2")

    def test_clear_only_affects_target(self):
        podman = _make_podman()
        cache.mark_image_built("cage-a", "k1", "img:1")
        cache.mark_image_built("cage-b", "k2", "img:2")

        cache.clear_cage_cache("cage-a")
        assert not cache.is_image_cached("cage-a", "k1", podman)
        assert cache.is_image_cached("cage-b", "k2", podman)

    def test_clear_empty_returns_zero(self):
        assert cache.clear_cage_cache("nonexistent") == 0


# ── clear_all_cache ──────────────────────────────────────


class TestClearAllCache:
    def test_clear_all(self):
        cache.mark_image_built("a", "k1", "img:1")
        cache.mark_image_built("b", "k2", "img:2")
        cache.mark_quadlets_installed("c", "k3")

        removed = cache.clear_all_cache()
        assert removed == 3
        assert not cache.CACHE_DIR.exists()

    def test_clear_all_empty(self):
        assert cache.clear_all_cache() == 0
