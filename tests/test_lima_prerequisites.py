"""Tests for Lima prerequisites checker."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agentcage.lima.prerequisites import check_prerequisites, detect_platform


class TestDetectPlatform:
    def test_linux(self):
        with patch("platform.system", return_value="Linux"):
            assert detect_platform() == "linux"

    def test_macos(self):
        with patch("platform.system", return_value="Darwin"):
            assert detect_platform() == "macos"

    def test_windows_unsupported(self):
        with patch("platform.system", return_value="Windows"):
            assert detect_platform() == "unsupported"

    def test_unknown_unsupported(self):
        with patch("platform.system", return_value="FreeBSD"):
            assert detect_platform() == "unsupported"


class TestCheckPrerequisites:
    def test_limactl_missing(self):
        with patch("shutil.which", return_value=None), \
             patch("platform.system", return_value="Linux"):
            issues = check_prerequisites()
        assert any("limactl" in i for i in issues)
        assert any("https://" in i for i in issues)

    def test_limactl_available_on_linux(self):
        with patch("shutil.which", return_value="/usr/bin/limactl"), \
             patch("platform.system", return_value="Linux"):
            issues = check_prerequisites()
        assert issues == []

    def test_limactl_available_on_macos(self):
        with patch("shutil.which", return_value="/usr/local/bin/limactl"), \
             patch("platform.system", return_value="Darwin"):
            issues = check_prerequisites()
        assert issues == []

    def test_unsupported_platform(self):
        with patch("shutil.which", return_value="/usr/bin/limactl"), \
             patch("platform.system", return_value="Windows"):
            issues = check_prerequisites()
        assert any("Windows" in i for i in issues)

    def test_unsupported_platform_and_missing_limactl(self):
        with patch("shutil.which", return_value=None), \
             patch("platform.system", return_value="Windows"):
            issues = check_prerequisites()
        assert any("limactl" in i for i in issues)
        assert any("Windows" in i for i in issues)
        assert len(issues) == 2
