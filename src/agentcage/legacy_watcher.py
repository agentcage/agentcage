"""Remove the legacy host-side grants-watcher supervision from a cage.

The egress-local DNS-apply rework deleted the host-side grants watcher —
the systemd user unit on Linux hosts, the launchd plist on macOS hosts,
and the in-guest systemd user unit for VM cages. Cages created BEFORE
that rework still carry those artifacts, and their command no longer
exists: the unit's ExecStart / plist ProgramArguments runs
``agentcage cage grants <name> watch --interval 1``, and the ``watch``
subcommand was removed with the watcher. On an upgraded Linux host the
enabled ``WantedBy=default.target`` unit therefore fails at every boot
until systemd's start limit kills it; on macOS the ``KeepAlive=true``
plist relaunches the failing command indefinitely (launchd throttles to
~10s — a permanent crash loop).

:func:`remove_legacy_grants_watcher` removes the artifacts. It is called
from ``cage destroy`` and ``cage update`` and is:

* **idempotent** — every step is best-effort; missing files, missing
  launchd services, and unreachable VMs are silent no-ops, so it is safe
  to call on every cage, including ones created entirely post-rework;
* **never fatal** — cleanup failures are logged to stderr, never raised,
  because a stale watcher must not block a cage destroy/update.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _grants_service_path(name: str) -> Path:
    """Host path of the legacy per-cage grants-watcher systemd user unit."""
    return Path(
        os.path.expanduser(f"~/.config/systemd/user/{name}-grants.service")
    )


def _grants_plist_path(name: str) -> Path:
    """Host path of the legacy per-cage grants-watcher launchd plist."""
    return Path(
        os.path.expanduser(f"~/Library/LaunchAgents/io.agentcage.{name}.grants.plist")
    )


def remove_legacy_grants_watcher(name: str, isolation: str = "") -> None:
    """Best-effort removal of the pre-rework watcher artifacts for ``name``.

    ``isolation`` is the cage's isolation setting (``vm`` triggers the
    in-guest cleanup); anything else (or empty) is a host-local cage.
    """
    if sys.platform == "darwin":
        _remove_macos_watcher(name)
    else:
        _remove_linux_watcher(name)
    if isolation == "vm":
        _remove_vm_watcher(name)


def _remove_linux_watcher(name: str) -> None:
    unit = f"{name}-grants.service"
    path = _grants_service_path(name)
    if not path.is_file():
        return
    # disable --now so a currently-running watcher stops before its unit
    # file vanishes; then drop the file and refresh the generator view.
    # disable_unit is a no-op without systemd; its `disable` alone does
    # not stop a running instance, hence the explicit best-effort stop.
    subprocess.run(
        ["systemctl", "--user", "disable", "--now", unit],
        capture_output=True, check=False,
    )
    try:
        path.unlink()
    except OSError as e:
        print(
            f"warn: could not remove legacy grants watcher unit {path}: {e}",
            file=sys.stderr,
        )
        return
    subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True, check=False,
    )


def _remove_macos_watcher(name: str) -> None:
    label = f"io.agentcage.{name}.grants"
    path = _grants_plist_path(name)
    # bootout (not unload) — the plist was registered in the per-user GUI
    # domain. Both a missing service and a missing file are fine.
    subprocess.run(
        ["launchctl", "bootout", f"gui/{os.getuid()}", label],
        capture_output=True, check=False,
    )
    if not path.is_file():
        return
    try:
        path.unlink()
    except OSError as e:
        print(
            f"warn: could not remove legacy grants watcher plist {path}: {e}",
            file=sys.stderr,
        )


def _remove_vm_watcher(name: str) -> None:
    """Remove the in-guest unit of a VM cage (best-effort, needs the VM up).

    The VM watcher ran inside the guest as a systemd user unit, so removal
    needs a ``limactl shell`` round-trip. If the VM is unreachable the unit
    dies with the VM's disk when the cage is destroyed; for an update on a
    running VM this stops the crash loop immediately.
    """
    try:
        from .backends.vm import LimaInstance
    except ImportError:
        return
    try:
        inst = LimaInstance(name)
        if not inst.is_running():
            return
        unit = f"{name}-grants.service"
        # One shell: stop+disable, remove the file, refresh systemd. All
        # best-effort (`|| true`) so a partial manual removal still exits 0
        # and never fails the host-side destroy/update.
        inst.exec([
            "sh", "-c",
            f"systemctl --user disable --now {unit} 2>/dev/null; "
            f"rm -f \"$HOME/.config/systemd/user/{unit}\" 2>/dev/null; "
            "systemctl --user daemon-reload 2>/dev/null; true",
        ], check=False)
    except Exception as e:  # noqa: BLE001 — cleanup must never be fatal
        print(
            f"warn: could not clean the in-VM legacy grants watcher for "
            f"'{name}' (VM unreachable?): {e}",
            file=sys.stderr,
        )
