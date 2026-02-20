"""Interact with systemd via systemctl --user."""

from __future__ import annotations

import os
import subprocess


def _systemctl_cmd() -> list[str]:
    """Return the base systemctl --user command.

    When running as root via sudo, prefix with ``runuser -u <real-user>``
    so that systemctl connects to the real user's systemd instance.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        return ["runuser", "-u", sudo_user, "--", "systemctl", "--user"]
    return ["systemctl", "--user"]


def daemon_reload() -> None:
    subprocess.run([*_systemctl_cmd(), "daemon-reload"], check=True)


def start_unit(name: str) -> None:
    subprocess.run([*_systemctl_cmd(), "start", name], check=True)


def stop_unit(name: str) -> None:
    subprocess.run([*_systemctl_cmd(), "stop", name], check=True)


def restart_unit(name: str) -> None:
    subprocess.run([*_systemctl_cmd(), "restart", name], check=True)
