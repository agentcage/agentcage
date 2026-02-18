"""Tests for agentcage.firecracker.kernel module."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from agentcage.firecracker.kernel import (
    _KERNEL_VERSION,
    default_kernel_path,
    ensure_kernel,
    kernel_url,
)


class TestDefaultKernelPath:
    def test_uses_xdg_data_home(self, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", "/custom/data")
        path = default_kernel_path()
        assert path == f"/custom/data/agentcage/firecracker/vmlinux-{_KERNEL_VERSION}"

    def test_falls_back_to_home(self, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        path = default_kernel_path()
        home = os.path.expanduser("~")
        assert path == os.path.join(
            home, ".local", "share", "agentcage", "firecracker",
            f"vmlinux-{_KERNEL_VERSION}",
        )

    def test_contains_kernel_version(self):
        path = default_kernel_path()
        assert _KERNEL_VERSION in path


class TestKernelUrl:
    def test_x86_64(self, monkeypatch):
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        url = kernel_url()
        assert "x86_64" in url
        assert _KERNEL_VERSION in url
        assert url.startswith("https://")

    def test_aarch64(self, monkeypatch):
        monkeypatch.setattr("platform.machine", lambda: "aarch64")
        url = kernel_url()
        assert "aarch64" in url
        assert _KERNEL_VERSION in url

    def test_unsupported_arch(self, monkeypatch):
        monkeypatch.setattr("platform.machine", lambda: "riscv64")
        with pytest.raises(RuntimeError, match="unsupported architecture"):
            kernel_url()


class TestEnsureKernel:
    def test_returns_existing_file(self, tmp_path):
        kernel = tmp_path / "vmlinux"
        kernel.write_bytes(b"fake-kernel")
        result = ensure_kernel(str(kernel))
        assert result == str(kernel)

    def test_downloads_when_missing(self, tmp_path):
        kernel = tmp_path / "subdir" / "vmlinux"

        with patch(
            "agentcage.firecracker.kernel.download_with_progress"
        ) as mock_dl:
            def fake_download(url, dest):
                with open(dest, "wb") as f:
                    f.write(b"downloaded-kernel")
            mock_dl.side_effect = fake_download

            result = ensure_kernel(str(kernel))

        assert result == str(kernel)
        assert kernel.exists()
        assert kernel.read_bytes() == b"downloaded-kernel"
        mock_dl.assert_called_once()

    def test_cleans_up_on_failure(self, tmp_path):
        kernel = tmp_path / "vmlinux"

        with patch(
            "agentcage.firecracker.kernel.download_with_progress"
        ) as mock_dl:
            mock_dl.side_effect = OSError("network error")

            with pytest.raises(OSError, match="network error"):
                ensure_kernel(str(kernel))

        assert not kernel.exists()
        assert not (tmp_path / "vmlinux.tmp").exists()

    def test_uses_default_path_when_none(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        expected = default_kernel_path()

        with patch(
            "agentcage.firecracker.kernel.download_with_progress"
        ) as mock_dl:
            def fake_download(url, dest):
                with open(dest, "wb") as f:
                    f.write(b"kernel")
            mock_dl.side_effect = fake_download

            result = ensure_kernel()

        assert result == expected
        assert os.path.isfile(expected)
