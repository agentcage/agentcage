"""Unit tests for agentcage.podman — Podman CLI wrapper."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch, call

import pytest

from agentcage.podman import Podman, _podman_cmd


# ---------------------------------------------------------------------------
# _podman_cmd
# ---------------------------------------------------------------------------

class TestPodmanCmd:
    def test_normal_user(self):
        with patch("agentcage.podman.os.geteuid", return_value=1000), \
             patch.dict("os.environ", {}, clear=True):
            assert _podman_cmd() == ["podman"]

    def test_root_with_sudo_user(self):
        with patch("agentcage.podman.os.geteuid", return_value=0), \
             patch.dict("os.environ", {"SUDO_USER": "alice"}):
            assert _podman_cmd() == ["runuser", "-u", "alice", "--", "podman"]

    def test_root_without_sudo_user(self):
        with patch("agentcage.podman.os.geteuid", return_value=0), \
             patch.dict("os.environ", {}, clear=True):
            assert _podman_cmd() == ["podman"]


# ---------------------------------------------------------------------------
# image_exists
# ---------------------------------------------------------------------------

class TestImageExists:
    def test_exists(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert p.image_exists("myimg:latest") is True
        cmd = mock_run.call_args[0][0]
        assert cmd[-2:] == ["image", "exists"] or "image" in cmd

    def test_not_exists(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert p.image_exists("myimg:latest") is False


# ---------------------------------------------------------------------------
# build_image
# ---------------------------------------------------------------------------

class TestBuildImage:
    def test_basic_build(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            p.build_image("myimg:latest", "/path/Containerfile", "/ctx")
        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd
        assert "myimg:latest" in cmd
        assert "-f" in cmd
        assert "/path/Containerfile" in cmd
        assert cmd[-1] == "/ctx"

    def test_no_cache(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            p.build_image("img", None, "/ctx", no_cache=True)
        cmd = mock_run.call_args[0][0]
        assert "--no-cache" in cmd
        assert "-f" not in cmd

    def test_cap_add(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            p.build_image("img", None, "/ctx", cap_add=["CAP_CHOWN", "CAP_FOWNER"])
        cmd = mock_run.call_args[0][0]
        assert "--cap-add" in cmd
        assert "CAP_CHOWN" in cmd
        assert "CAP_FOWNER" in cmd

    def test_build_args(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            p.build_image("img", None, "/ctx", build_args={"FOO": "bar"})
        cmd = mock_run.call_args[0][0]
        assert "--build-arg" in cmd
        assert "FOO=bar" in cmd

    def test_raises_on_failure(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run", side_effect=subprocess.CalledProcessError(1, "podman")):
            with pytest.raises(subprocess.CalledProcessError):
                p.build_image("img", None, "/ctx")


# ---------------------------------------------------------------------------
# container_running / container_inspect
# ---------------------------------------------------------------------------

class TestContainerRunning:
    def test_running(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="running\n")
            assert p.container_running("mycontainer") is True

    def test_not_running(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="exited\n")
            assert p.container_running("mycontainer") is False

    def test_container_missing(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert p.container_running("mycontainer") is False


class TestContainerInspect:
    def test_returns_first_item(self):
        p = Podman()
        data = [{"Id": "abc123", "State": {"Status": "running"}}]
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(data))
            result = p.container_inspect("mycontainer")
        assert result["Id"] == "abc123"

    def test_raises_on_missing(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run", side_effect=subprocess.CalledProcessError(1, "podman")):
            with pytest.raises(subprocess.CalledProcessError):
                p.container_inspect("missing")


# ---------------------------------------------------------------------------
# network_remove / volume_remove / volume_exists
# ---------------------------------------------------------------------------

class TestNetworkRemove:
    def test_success(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert p.network_remove("mynet") is True

    def test_failure(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert p.network_remove("mynet") is False


class TestVolumeRemove:
    def test_success(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert p.volume_remove("myvol") is True

    def test_failure(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert p.volume_remove("myvol") is False


class TestVolumeExists:
    def test_exists(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert p.volume_exists("myvol") is True

    def test_not_exists(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert p.volume_exists("myvol") is False


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

class TestSecretExists:
    def test_exists(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert p.secret_exists("mysecret") is True

    def test_not_exists(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert p.secret_exists("mysecret") is False


class TestSecretCreate:
    def test_creates_with_stdin(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            p.secret_create("mysecret", "supersecretvalue")
        kwargs = mock_run.call_args
        assert kwargs[1]["input"] == "supersecretvalue"
        assert kwargs[1]["text"] is True
        cmd = kwargs[0][0]
        assert "secret" in cmd
        assert "create" in cmd
        assert "mysecret" in cmd

    def test_raises_on_failure(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run", side_effect=subprocess.CalledProcessError(1, "podman")):
            with pytest.raises(subprocess.CalledProcessError):
                p.secret_create("mysecret", "val")


class TestSecretRemove:
    def test_success(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert p.secret_remove("mysecret") is True

    def test_failure(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert p.secret_remove("mysecret") is False


class TestSecretList:
    def test_returns_all(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="myapp.KEY1\nmyapp.KEY2\nother.KEY3\n"
            )
            result = p.secret_list()
        assert len(result) == 3

    def test_filters_by_prefix(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="myapp.KEY1\nmyapp.KEY2\nother.KEY3\n"
            )
            result = p.secret_list(prefix="myapp.")
        assert len(result) == 2
        assert all(s["Name"].startswith("myapp.") for s in result)

    def test_empty_output(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            result = p.secret_list()
        assert result == []

    def test_command_failure(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = p.secret_list()
        assert result == []


class TestSecretRead:
    def test_reads_value(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="secretval\n")
            result = p.secret_read("mysecret")
        assert result == "secretval"

    def test_raises_on_missing(self):
        p = Podman()
        with patch("agentcage.podman.subprocess.run", side_effect=subprocess.CalledProcessError(1, "podman")):
            with pytest.raises(subprocess.CalledProcessError):
                p.secret_read("missing")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

class TestInfo:
    def test_returns_parsed_json(self):
        p = Podman()
        data = {"host": {"security": {"rootless": True}}}
        with patch("agentcage.podman.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(data))
            result = p.info()
        assert result == data
