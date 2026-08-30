"""Interact with systemd via systemctl --user.

On platforms without systemd (notably macOS), ``systemctl`` is absent from
``PATH``. The public functions in this module become no-ops in that case so
that callers running on a host that genuinely has no systemd (e.g. cleaning
up resources from a container-backed cage on macOS) do not crash with
``FileNotFoundError``.
"""

from __future__ import annotations

import os
import shutil
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


def _systemctl_available() -> bool:
    return shutil.which("systemctl") is not None


def daemon_reload() -> None:
    if not _systemctl_available():
        return
    subprocess.run([*_systemctl_cmd(), "daemon-reload"], check=True)


def start_unit(name: str) -> None:
    if not _systemctl_available():
        return
    subprocess.run([*_systemctl_cmd(), "start", name], check=True)


def stop_unit(name: str) -> None:
    if not _systemctl_available():
        return
    subprocess.run([*_systemctl_cmd(), "stop", name], check=True)


def restart_unit(name: str) -> None:
    if not _systemctl_available():
        return
    subprocess.run([*_systemctl_cmd(), "restart", name], check=True)


def enable_unit(name: str) -> None:
    """Enable a unit so it is pulled in at future boots/logins.

    Needed for NATIVE ``.service`` units (e.g. the grants watcher): unlike
    quadlet-generated units, which the systemd generator activates
    automatically, a native unit's ``[Install] WantedBy=`` stanza only names
    the symlink that ``systemctl enable`` creates — nothing creates it unless
    enable is called explicitly.
    """
    if not _systemctl_available():
        return
    subprocess.run([*_systemctl_cmd(), "enable", name], check=True)


def disable_unit(name: str) -> None:
    """Disable a unit so it is no longer pulled in at future boots/logins.

    The undo of :func:`enable_unit`: removes the ``WantedBy=`` symlink that
    ``systemctl enable`` created. Called from
    :func:`agentcage.watcher.uninstall_grants_watcher` during ``cage
    destroy`` so a removed cage's grants-watcher does not survive the next
    host boot. No-op on hosts without systemd (see :func:`enable_unit`).
    """
    if not _systemctl_available():
        return
    subprocess.run([*_systemctl_cmd(), "disable", name], check=True)
