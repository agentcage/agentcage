"""Tests for secret_resolver module."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from agentcage.secret_resolver import (
    ResolveAction,
    ResolveResult,
    detect_default_backend,
    encrypt_secret,
    resolve,
    resolve_and_populate,
    validate_env_name,
    validate_source,
)


class TestValidateEnvName:
    def test_valid_env_names(self):
        validate_env_name("FOO")
        validate_env_name("FOO_BAR")
        validate_env_name("_UNDERSCORE")
        validate_env_name("lowercase")
        validate_env_name("Mixed123")

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="non-empty env name"):
            validate_env_name("")

    def test_starts_with_digit_raises(self):
        with pytest.raises(ValueError, match="invalid env name"):
            validate_env_name("1FOO")

    def test_shell_injection_attempts_rejected(self):
        bad = [
            'FOO"; rm -rf /; #',
            "FOO$(whoami)",
            "FOO`id`",
            "FOO;bar",
            "FOO bar",
            "FOO\n",
            "FOO-BAR",  # hyphen not allowed
            "FOO.BAR",  # dot not allowed
        ]
        for name in bad:
            with pytest.raises(ValueError, match="invalid env name"):
                validate_env_name(name)


class TestValidateSource:
    def test_empty_source_valid(self):
        validate_source("")

    def test_known_schemes_valid(self):
        validate_source("env:MY_VAR")
        validate_source("cmd:echo hello")
        validate_source("systemd-creds:")
        validate_source("podman:")

    def test_unknown_scheme_raises(self):
        with pytest.raises(ValueError, match="unknown secret source scheme"):
            validate_source("keyring:service/key")

    def test_typo_scheme_raises(self):
        with pytest.raises(ValueError, match="unknown secret source scheme"):
            validate_source("sytsemd-creds:")


class TestResolveEnv:
    def test_env_with_explicit_var(self):
        with mock.patch.dict(os.environ, {"MY_SECRET": "test-value"}):
            result = resolve("env:MY_SECRET", "UNUSED", Path("/tmp"))
        assert result.action == ResolveAction.RESOLVED
        assert result.value == "test-value"

    def test_env_uses_env_name_when_no_arg(self):
        with mock.patch.dict(os.environ, {"API_KEY": "the-key"}):
            result = resolve("env:", "API_KEY", Path("/tmp"))
        assert result.action == ResolveAction.RESOLVED
        assert result.value == "the-key"

    def test_env_missing_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="env var 'MISSING' not set"):
                resolve("env:MISSING", "x", Path("/tmp"))


class TestResolveCmd:
    def test_cmd_captures_stdout(self):
        result = resolve("cmd:echo test-value", "x", Path("/tmp"))
        assert result.action == ResolveAction.RESOLVED
        assert result.value == "test-value"

    def test_cmd_strips_trailing_newline(self):
        result = resolve("cmd:printf 'no-newline'", "x", Path("/tmp"))
        assert result.action == ResolveAction.RESOLVED
        assert result.value == "no-newline"

    def test_cmd_empty_arg_raises(self):
        with pytest.raises(ValueError, match="requires a command"):
            resolve("cmd:", "x", Path("/tmp"))

    def test_cmd_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="requires a command"):
            resolve("cmd:   ", "x", Path("/tmp"))

    def test_cmd_nonzero_exit_raises(self):
        with pytest.raises(ValueError, match="command failed"):
            resolve("cmd:false", "x", Path("/tmp"))

    def test_cmd_timeout_raises(self):
        with mock.patch("agentcage.secret_resolver.subprocess.run",
                        side_effect=subprocess.TimeoutExpired("cmd", 30)):
            with pytest.raises(ValueError, match="timed out after 30s"):
                resolve("cmd:sleep 60", "x", Path("/tmp"))

    def test_cmd_with_shell_metacharacters(self):
        """Shell metacharacters work because shell=True is intentional."""
        result = resolve("cmd:echo foo && echo bar", "x", Path("/tmp"))
        assert result.action == ResolveAction.RESOLVED
        assert "foo" in result.value


class TestResolveSystemdCreds:
    def test_systemd_creds_with_existing_file(self, tmp_path):
        creds_dir = tmp_path / "creds"
        creds_dir.mkdir()
        (creds_dir / "API_KEY.cred").write_bytes(b"encrypted-blob")
        result = resolve("systemd-creds:", "API_KEY", tmp_path)
        assert result.action == ResolveAction.QUADLET_HANDLED
        assert result.value == ""

    def test_systemd_creds_missing_file_raises(self, tmp_path):
        with pytest.raises(ValueError, match="encrypted credential not found"):
            resolve("systemd-creds:", "MISSING", tmp_path)


class TestResolvePodman:
    def test_podman_explicit(self):
        result = resolve("podman:", "x", Path("/tmp"))
        assert result.action == ResolveAction.EXISTING

    def test_empty_source(self):
        result = resolve("", "x", Path("/tmp"))
        assert result.action == ResolveAction.EXISTING


class TestDetectDefaultBackend:
    def test_detects_systemd_creds(self):
        detect_default_backend.cache_clear()
        with mock.patch("agentcage.secret_resolver.shutil.which", return_value="/usr/bin/systemd-creds"):
            with mock.patch("agentcage.secret_resolver._systemd_version", return_value=256):
                with mock.patch("agentcage.secret_resolver._systemd_creds_usable", return_value=True):
                    assert detect_default_backend() == "systemd-creds"
        detect_default_backend.cache_clear()

    def test_falls_back_to_podman(self):
        detect_default_backend.cache_clear()
        with mock.patch("agentcage.secret_resolver.shutil.which", return_value=None):
            assert detect_default_backend() == "podman"
        detect_default_backend.cache_clear()

    def test_unusable_systemd_creds_falls_back(self):
        detect_default_backend.cache_clear()
        with mock.patch("agentcage.secret_resolver.shutil.which", return_value="/usr/bin/systemd-creds"):
            with mock.patch("agentcage.secret_resolver._systemd_version", return_value=256):
                with mock.patch("agentcage.secret_resolver._systemd_creds_usable", return_value=False):
                    assert detect_default_backend() == "podman"
        detect_default_backend.cache_clear()

    def test_old_systemd_falls_back(self):
        detect_default_backend.cache_clear()
        with mock.patch("agentcage.secret_resolver.shutil.which", return_value="/usr/bin/systemd-creds"):
            with mock.patch("agentcage.secret_resolver._systemd_version", return_value=249):
                assert detect_default_backend() == "podman"
        detect_default_backend.cache_clear()


class _FakeRule:
    def __init__(self, env, source=""):
        self.env = env
        self.source = source


class _FakeCfg:
    def __init__(self, rules):
        self.secret_injection = rules


class _FakePodman:
    def __init__(self):
        self.secrets: dict[str, str] = {}

    def secret_exists(self, name):
        return name in self.secrets

    def secret_remove(self, name):
        self.secrets.pop(name, None)

    def secret_create(self, name, value):
        self.secrets[name] = value


class TestResolveAndPopulate:
    def test_strict_raises_on_missing_env_var(self, tmp_path):
        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = _FakeCfg([_FakeRule("MY_KEY", "env:NOT_SET")])
            with pytest.raises(ValueError, match="failed to resolve secret 'MY_KEY'"):
                resolve_and_populate(_FakePodman(), cfg, "cage", tmp_path)

    def test_lenient_warns_on_missing(self, tmp_path, capsys):
        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = _FakeCfg([_FakeRule("MY_KEY", "env:NOT_SET")])
            resolved = resolve_and_populate(
                _FakePodman(), cfg, "cage", tmp_path, strict=False,
            )
            assert resolved == set()
            err = capsys.readouterr().err
            assert "warning: failed to resolve MY_KEY" in err

    def test_strict_populates_podman_on_success(self, tmp_path):
        with mock.patch.dict(os.environ, {"FOO": "bar"}):
            cfg = _FakeCfg([_FakeRule("MY_KEY", "env:FOO")])
            pm = _FakePodman()
            resolved = resolve_and_populate(pm, cfg, "cage", tmp_path)
            assert resolved == {"MY_KEY"}
            assert pm.secrets == {"cage.MY_KEY": "bar"}

    def test_skip_keys_respected(self, tmp_path):
        with mock.patch.dict(os.environ, {"FOO": "bar"}):
            cfg = _FakeCfg([_FakeRule("MY_KEY", "env:FOO")])
            pm = _FakePodman()
            resolved = resolve_and_populate(
                pm, cfg, "cage", tmp_path, skip_keys={"MY_KEY"},
            )
            assert resolved == set()
            assert pm.secrets == {}


class TestEncryptSecret:
    def test_encrypt_calls_systemd_creds(self, tmp_path):
        with mock.patch("agentcage.secret_resolver.subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0)
            path = encrypt_secret("API_KEY", "secret-value", tmp_path)
        assert path == tmp_path / "creds" / "API_KEY.cred"
        assert (tmp_path / "creds").is_dir()
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0][0] == "systemd-creds"
        assert call_args[1]["input"] == "secret-value"

    def test_encrypt_failure_raises(self, tmp_path):
        with mock.patch("agentcage.secret_resolver.subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                returncode=1, stderr="no TPM2 device"
            )
            with pytest.raises(ValueError, match="systemd-creds encrypt failed"):
                encrypt_secret("KEY", "val", tmp_path)
