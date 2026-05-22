"""Unit tests for agentcage.systemd."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agentcage import systemd


# ---------------------------------------------------------------------------
# _systemctl_cmd — preserve existing behavior
# ---------------------------------------------------------------------------

class TestSystemctlCmd:
    def test_default_command(self):
        with patch.dict("os.environ", {}, clear=True), \
             patch("agentcage.systemd.os.geteuid", return_value=1000):
            assert systemd._systemctl_cmd() == ["systemctl", "--user"]

    def test_runuser_when_sudo(self):
        with patch.dict("os.environ", {"SUDO_USER": "alice"}, clear=True), \
             patch("agentcage.systemd.os.geteuid", return_value=0):
            assert systemd._systemctl_cmd() == [
                "runuser", "-u", "alice", "--", "systemctl", "--user",
            ]

    def test_no_runuser_when_sudo_user_unset(self):
        """Root without SUDO_USER (e.g. real root shell) should not wrap."""
        with patch.dict("os.environ", {}, clear=True), \
             patch("agentcage.systemd.os.geteuid", return_value=0):
            assert systemd._systemctl_cmd() == ["systemctl", "--user"]


# ---------------------------------------------------------------------------
# Public functions — invoke systemctl when available, no-op when not
# ---------------------------------------------------------------------------

PUBLIC_FUNCS = [
    pytest.param(
        lambda: systemd.daemon_reload(),
        ["systemctl", "--user", "daemon-reload"],
        id="daemon_reload",
    ),
    pytest.param(
        lambda: systemd.start_unit("foo.service"),
        ["systemctl", "--user", "start", "foo.service"],
        id="start_unit",
    ),
    pytest.param(
        lambda: systemd.stop_unit("foo.service"),
        ["systemctl", "--user", "stop", "foo.service"],
        id="stop_unit",
    ),
    pytest.param(
        lambda: systemd.restart_unit("foo.service"),
        ["systemctl", "--user", "restart", "foo.service"],
        id="restart_unit",
    ),
]


@pytest.mark.parametrize("invoke,expected_cmd", PUBLIC_FUNCS)
def test_invokes_systemctl_when_available(invoke, expected_cmd):
    with patch("agentcage.systemd.shutil.which", return_value="/usr/bin/systemctl"), \
         patch("agentcage.systemd.subprocess.run") as mock_run, \
         patch("agentcage.systemd.os.geteuid", return_value=1000), \
         patch.dict("os.environ", {}, clear=True):
        invoke()

    mock_run.assert_called_once_with(expected_cmd, check=True)


@pytest.mark.parametrize("invoke,expected_cmd", PUBLIC_FUNCS)
def test_noop_when_systemctl_missing(invoke, expected_cmd):
    """On hosts without systemctl (e.g. macOS), calls must not raise."""
    with patch("agentcage.systemd.shutil.which", return_value=None), \
         patch("agentcage.systemd.subprocess.run") as mock_run:
        invoke()  # must not raise

    mock_run.assert_not_called()
