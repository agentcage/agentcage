"""Unit tests for LimaInstance lifecycle management."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from agentcage.lima.instance import LimaInstance


class TestInstanceName:
    def test_instance_name(self):
        inst = LimaInstance("mycage")
        assert inst.name == "agentcage-mycage"

    def test_instance_name_preserves_cage_name(self):
        inst = LimaInstance("my-special-cage")
        assert inst.name == "agentcage-my-special-cage"


class TestCreate:
    def test_create_calls_limactl(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.create("/path/to/config.yaml")
            mock_run.assert_called_once_with(
                ["limactl", "create", "--name=agentcage-mycage", "/path/to/config.yaml"],
                check=True,
            )


class TestStart:
    def test_start_calls_limactl_linux(self):
        inst = LimaInstance("mycage")
        with patch("platform.system", return_value="Linux"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.start()
            mock_run.assert_called_once_with(
                ["limactl", "start", "agentcage-mycage"],
                check=True,
            )

    def test_start_uses_launchd_on_macos(self):
        inst = LimaInstance("mycage")
        mock_shell_result = MagicMock(returncode=0)
        with patch("platform.system", return_value="Darwin"), \
             patch("subprocess.run", return_value=mock_shell_result) as mock_run, \
             patch.object(inst, "_start_via_launchd") as mock_launchd:
            inst.start()
            mock_launchd.assert_called_once()


class TestStop:
    def test_stop_calls_limactl(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.stop()
            mock_run.assert_called_once_with(
                ["limactl", "stop", "agentcage-mycage"],
                check=True,
            )


class TestDelete:
    def test_delete_calls_limactl(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.delete()
            mock_run.assert_called_once_with(
                ["limactl", "delete", "--force", "agentcage-mycage"],
                check=True,
            )


class TestExec:
    def test_exec_runs_command_in_vm(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")
            result = inst.exec(["echo", "hello"])
            mock_run.assert_called_once_with(
                ["limactl", "shell", "agentcage-mycage", "--", "echo", "hello"],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_exec_default_flags(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.exec(["ls"])
            _, kwargs = mock_run.call_args
            assert kwargs["check"] is True
            assert kwargs["capture_output"] is True
            assert kwargs["text"] is True

    def test_exec_check_false(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            inst.exec(["false"], check=False)
            _, kwargs = mock_run.call_args
            assert kwargs["check"] is False

    def test_exec_returns_completed_process(self):
        inst = LimaInstance("mycage")
        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = "hello\n"
        with patch("subprocess.run", return_value=fake_result) as mock_run:
            result = inst.exec(["echo", "hello"])
            assert result is fake_result


class TestIsRunning:
    def test_is_running_active(self):
        inst = LimaInstance("mycage")
        output = json.dumps({"name": "agentcage-mycage", "status": "Running"})
        mock_result = MagicMock(stdout=output)
        with patch("subprocess.run", return_value=mock_result):
            assert inst.is_running() is True

    def test_is_running_stopped(self):
        inst = LimaInstance("mycage")
        output = json.dumps({"name": "agentcage-mycage", "status": "Stopped"})
        mock_result = MagicMock(stdout=output)
        with patch("subprocess.run", return_value=mock_result):
            assert inst.is_running() is False

    def test_is_running_not_found(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "limactl")):
            assert inst.is_running() is False

    def test_is_running_invalid_json(self):
        inst = LimaInstance("mycage")
        mock_result = MagicMock(stdout="not-json")
        with patch("subprocess.run", return_value=mock_result):
            assert inst.is_running() is False

    def test_is_running_calls_limactl_list(self):
        inst = LimaInstance("mycage")
        output = json.dumps({"name": "agentcage-mycage", "status": "Running"})
        mock_result = MagicMock(stdout=output)
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            inst.is_running()
            mock_run.assert_called_once_with(
                ["limactl", "list", "--json", "agentcage-mycage"],
                check=True,
                capture_output=True,
                text=True,
            )


class TestExists:
    def test_exists_true_when_running(self):
        inst = LimaInstance("mycage")
        output = json.dumps({"name": "agentcage-mycage", "status": "Running"})
        mock_result = MagicMock(stdout=output)
        with patch("subprocess.run", return_value=mock_result):
            assert inst.exists() is True

    def test_exists_true_when_stopped(self):
        inst = LimaInstance("mycage")
        output = json.dumps({"name": "agentcage-mycage", "status": "Stopped"})
        mock_result = MagicMock(stdout=output)
        with patch("subprocess.run", return_value=mock_result):
            assert inst.exists() is True

    def test_exists_false_on_error(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "limactl")):
            assert inst.exists() is False

    def test_exists_false_on_invalid_json(self):
        inst = LimaInstance("mycage")
        mock_result = MagicMock(stdout="not-json")
        with patch("subprocess.run", return_value=mock_result):
            assert inst.exists() is False
