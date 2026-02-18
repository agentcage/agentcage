"""Tests for agentcage.firecracker.binaries module."""

from __future__ import annotations

import os
import stat
from unittest.mock import patch

import pytest

from agentcage.firecracker.binaries import (
    _FIRECRACKER_VERSION,
    default_firecracker_path,
    ensure_firecracker,
    firecracker_tarball_url,
)


class TestDefaultFirecrackerPath:
    def test_uses_xdg_data_home(self, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", "/custom/data")
        path = default_firecracker_path()
        assert path == f"/custom/data/agentcage/firecracker/firecracker-{_FIRECRACKER_VERSION}"

    def test_falls_back_to_home(self, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        path = default_firecracker_path()
        home = os.path.expanduser("~")
        assert path == os.path.join(
            home, ".local", "share", "agentcage", "firecracker",
            f"firecracker-{_FIRECRACKER_VERSION}",
        )

    def test_contains_version(self):
        path = default_firecracker_path()
        assert _FIRECRACKER_VERSION in path


class TestFirecrackerTarballUrl:
    def test_x86_64(self, monkeypatch):
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        url = firecracker_tarball_url()
        assert "x86_64" in url
        assert _FIRECRACKER_VERSION in url
        assert url.startswith("https://")
        assert url.endswith(".tgz")

    def test_aarch64(self, monkeypatch):
        monkeypatch.setattr("platform.machine", lambda: "aarch64")
        url = firecracker_tarball_url()
        assert "aarch64" in url
        assert _FIRECRACKER_VERSION in url

    def test_unsupported_arch(self, monkeypatch):
        monkeypatch.setattr("platform.machine", lambda: "riscv64")
        with pytest.raises(RuntimeError, match="unsupported architecture"):
            firecracker_tarball_url()


class TestEnsureFirecracker:
    def test_returns_existing_executable(self, tmp_path):
        fc = tmp_path / "firecracker"
        fc.write_bytes(b"fake-binary")
        fc.chmod(fc.stat().st_mode | stat.S_IXUSR)
        result = ensure_firecracker(str(fc))
        assert result == str(fc)

    def test_downloads_when_missing(self, tmp_path, monkeypatch):
        fc = tmp_path / "subdir" / "firecracker"
        monkeypatch.setattr("platform.machine", lambda: "x86_64")

        import tarfile
        import io

        # Build a fake tarball with the expected member
        member_name = f"release-{_FIRECRACKER_VERSION}-x86_64/firecracker-{_FIRECRACKER_VERSION}-x86_64"

        def fake_download(url, dest):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                data = b"fake-firecracker-binary"
                info = tarfile.TarInfo(name=member_name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            with open(dest, "wb") as f:
                f.write(buf.getvalue())

        with patch(
            "agentcage.firecracker.kernel.download_with_progress"
        ) as mock_dl:
            mock_dl.side_effect = fake_download
            result = ensure_firecracker(str(fc))

        assert result == str(fc)
        assert fc.exists()
        assert fc.read_bytes() == b"fake-firecracker-binary"
        assert fc.stat().st_mode & stat.S_IXUSR
        mock_dl.assert_called_once()
        # Tarball should be cleaned up
        assert not (tmp_path / "subdir" / "firecracker.tgz").exists()

    def test_cleans_up_on_failure(self, tmp_path, monkeypatch):
        fc = tmp_path / "firecracker"
        monkeypatch.setattr("platform.machine", lambda: "x86_64")

        with patch(
            "agentcage.firecracker.kernel.download_with_progress"
        ) as mock_dl:
            mock_dl.side_effect = OSError("network error")

            with pytest.raises(OSError, match="network error"):
                ensure_firecracker(str(fc))

        assert not fc.exists()
        assert not (tmp_path / "firecracker.tmp").exists()
        assert not (tmp_path / "firecracker.tgz").exists()

    def test_uses_default_path_when_none(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        expected = default_firecracker_path()

        import tarfile
        import io

        member_name = f"release-{_FIRECRACKER_VERSION}-x86_64/firecracker-{_FIRECRACKER_VERSION}-x86_64"

        def fake_download(url, dest):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                data = b"fc-binary"
                info = tarfile.TarInfo(name=member_name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            with open(dest, "wb") as f:
                f.write(buf.getvalue())

        with patch(
            "agentcage.firecracker.kernel.download_with_progress"
        ) as mock_dl:
            mock_dl.side_effect = fake_download
            result = ensure_firecracker()

        assert result == expected
        assert os.path.isfile(expected)
