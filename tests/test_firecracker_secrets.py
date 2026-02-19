"""Tests for Firecracker file-based secrets."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from agentcage.firecracker.secrets import (
    _secrets_dir,
    save_secret,
    load_secret,
    secret_exists,
    list_secrets,
    remove_secret,
    remove_all_secrets,
)


@pytest.fixture
def secrets_home(tmp_path, monkeypatch):
    """Override XDG_CONFIG_HOME so secrets go to tmp_path."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path


class TestFileSecretStore:
    def test_save_and_load(self, secrets_home):
        save_secret("myapp", "API_KEY", "secret123")
        assert load_secret("myapp", "API_KEY") == "secret123"

    def test_secret_exists(self, secrets_home):
        assert not secret_exists("myapp", "API_KEY")
        save_secret("myapp", "API_KEY", "val")
        assert secret_exists("myapp", "API_KEY")

    def test_list_secrets(self, secrets_home):
        save_secret("myapp", "KEY_B", "b")
        save_secret("myapp", "KEY_A", "a")
        assert list_secrets("myapp") == ["KEY_A", "KEY_B"]

    def test_list_secrets_empty(self, secrets_home):
        assert list_secrets("noapp") == []

    def test_remove_secret(self, secrets_home):
        save_secret("myapp", "KEY", "val")
        assert remove_secret("myapp", "KEY") is True
        assert not secret_exists("myapp", "KEY")
        assert remove_secret("myapp", "KEY") is False

    def test_remove_all_secrets(self, secrets_home):
        save_secret("myapp", "A", "1")
        save_secret("myapp", "B", "2")
        removed = remove_all_secrets("myapp")
        assert sorted(removed) == ["A", "B"]
        assert list_secrets("myapp") == []

    def test_load_nonexistent_raises(self, secrets_home):
        with pytest.raises(FileNotFoundError):
            load_secret("myapp", "NOPE")

    def test_secret_file_permissions(self, secrets_home):
        save_secret("myapp", "PRIV", "sensitive")
        secret_path = _secrets_dir("myapp") / "PRIV"
        mode = oct(secret_path.stat().st_mode & 0o777)
        assert mode == "0o600"

    def test_secrets_dir_permissions(self, secrets_home):
        save_secret("myapp", "KEY", "val")
        dir_path = _secrets_dir("myapp")
        mode = oct(dir_path.stat().st_mode & 0o777)
        assert mode == "0o700"

    def test_isolation_between_cages(self, secrets_home):
        save_secret("cage-a", "KEY", "a")
        save_secret("cage-b", "KEY", "b")
        assert load_secret("cage-a", "KEY") == "a"
        assert load_secret("cage-b", "KEY") == "b"
        assert list_secrets("cage-a") == ["KEY"]

    def test_path_traversal_save_rejected(self, secrets_home):
        with pytest.raises(ValueError, match="path traversal"):
            save_secret("myapp", "../../etc/passwd", "malicious")

    def test_path_traversal_load_rejected(self, secrets_home):
        with pytest.raises(ValueError, match="path traversal"):
            load_secret("myapp", "../../../etc/shadow")

    def test_path_traversal_exists_rejected(self, secrets_home):
        with pytest.raises(ValueError, match="path traversal"):
            secret_exists("myapp", "../../etc/passwd")

    def test_path_traversal_remove_rejected(self, secrets_home):
        with pytest.raises(ValueError, match="path traversal"):
            remove_secret("myapp", "../../../etc/passwd")
