"""Interact with systemd via systemctl --user."""

from __future__ import annotations

import subprocess


def daemon_reload() -> None:
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)


def start_unit(name: str) -> None:
    subprocess.run(["systemctl", "--user", "start", name], check=True)


def stop_unit(name: str) -> None:
    subprocess.run(["systemctl", "--user", "stop", name], check=True)


def restart_unit(name: str) -> None:
    subprocess.run(["systemctl", "--user", "restart", name], check=True)
