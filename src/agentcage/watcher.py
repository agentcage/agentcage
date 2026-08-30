"""Shared installers for the host-side grants watcher.

The grants watcher is a host process (``agentcage cage <name> grants
watch``) regardless of isolation backend — it writes the operator's
``cage.yaml`` baseline and drives the backend-aware live-reload chain
(``_apply_baseline_change``). Only its supervisor differs by platform:

* Linux hosts: a systemd user unit (``quadlets._grants_service_unit``,
  installed by ``cli._ensure_grants_watcher``).
* macOS hosts: a launchd agent plist (this module) — used by BOTH the
  apple-container backend and the vm backend (Lima/vz cages on macOS).

Extracted from ``backends/apple_container.py`` so the vm backend can
install the identical plist without importing macOS-backend code.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _gui_domain_reachable(uid: int) -> bool:
    """Probe whether the ``gui/<uid>`` launchd domain is reachable now.

    ``~/Library/LaunchAgents/`` plists live in the per-user *GUI* domain.
    That domain is only addressable from a session that owns the Aqua
    console (a local Terminal.app window, or a GUI login). Over SSH the
    user session runs in the non-GUI ``user/<uid>`` context:
    ``launchctl bootstrap gui/<uid>`` exits 0 but silently no-ops, because
    the GUI domain isn't actually reachable from the SSH context — so the
    watcher would appear "installed" but never load. We probe
    reachability and, when unavailable, leave the plist file on disk (the
    FILE is the persistence — it loads at the next GUI login).
    """
    try:
        result = subprocess.run(
            ["launchctl", "print", f"gui/{uid}"],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except OSError:
        return False


def grants_watcher_plist_path(name: str) -> Path:
    """Host path of the per-cage grants-watcher launchd plist."""
    return Path(
        os.path.expanduser(f"~/Library/LaunchAgents/io.agentcage.{name}.grants.plist")
    )


def install_grants_watcher_plist(
    name: str,
    *,
    log_dir: Path,
    interval: int = 1,
    plist_path: Path | None = None,
) -> None:
    """Write + load the per-cage grants-watcher launchd plist.

    ``KeepAlive=true`` (unlike the cage autostart plist, which is
    ``RunAtLoad`` only) so approved grants are promoted promptly and
    expired ``--expires-in`` entries pruned, and the watcher restarts if
    it dies. Idempotent (bootout before bootstrap reloads a changed
    plist). Best-effort immediate-load (the SSH GUI-domain caveat in
    :func:`_gui_domain_reachable`); the FILE is the persistence.

    ``log_dir`` receives the watcher's stdout/stderr logs; callers own
    creating it.
    """
    binary = shutil.which("agentcage") or "agentcage"
    plist = plist_path or grants_watcher_plist_path(name)
    plist.parent.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    label = f"io.agentcage.{name}.grants"
    plist_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>cage</string>
        <string>grants</string>
        <string>{name}</string>
        <string>watch</string>
        <string>--interval</string>
        <string>{interval}</string>
    </array>
    <key>StandardOutPath</key>
    <string>{log_dir}/grants.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/grants.err.log</string>
</dict>
</plist>
"""
    plist.write_text(plist_xml)
    uid = os.getuid()
    domain = f"gui/{uid}"
    if not _gui_domain_reachable(uid):
        return  # file is persistence; immediate-load not available over SSH
    subprocess.run(["launchctl", "bootout", f"{domain}/{label}"],
                   check=False, capture_output=True)
    subprocess.run(["launchctl", "bootstrap", domain, str(plist)],
                   check=False, capture_output=True)
