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


def grants_watcher_unit_path(name: str) -> Path:
    """Host-side systemd user-unit path for the grants watcher.

    Mirrors :meth:`agentcage.backends.vm.VmBackend.grants_unit_path` and
    :meth:`agentcage.backends.container.ContainerBackend.grants_unit_path`:
    the watcher is a NATIVE ``.service`` (not a quadlet) in
    ``~/.config/systemd/user/``. Centralized here so
    :func:`uninstall_grants_watcher` can unlink the file without importing
    a backend (it is called from ``cage destroy``, which dispatches on
    isolation before the backend is even constructed for the resource
    teardown — and on macOS hosts the vm backend's
    ``grants_unit_path`` would still point here, but importing the backend
    module pulls in Lima code that is irrelevant to a plist teardown).
    """
    return Path(os.path.expanduser("~/.config/systemd/user")) / f"{name}-grants.service"


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


def _watcher_path(binary: str) -> str:
    """PATH for the watcher process.

    launchd starts agents with a bare
    ``/usr/bin:/bin:/usr/sbin:/sbin`` — it does NOT inherit the operator's
    shell PATH. That is fine for an apple-container cage, but a vm cage's
    watcher shells out to ``limactl`` on every tick to pull the guest-local
    grants overlay and to drive the live-reload chain. Homebrew installs
    ``limactl`` in ``/opt/homebrew/bin`` (or ``/usr/local/bin`` on Intel),
    so without this the watcher loads, runs, and fails every single tick
    with ``FileNotFoundError`` — a watcher that is up but can never promote
    a grant.

    Includes the resolved ``agentcage`` and ``limactl`` directories so a
    pipx/venv/Homebrew layout works without the operator configuring
    anything.
    """
    entries: list[str] = []
    for tool in (binary, shutil.which("limactl")):
        if not tool:
            continue
        parent = str(Path(tool).resolve().parent)
        if parent not in entries:
            entries.append(parent)
    for default in (
        "/opt/homebrew/bin", "/usr/local/bin",
        "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ):
        if default not in entries:
            entries.append(default)
    return ":".join(entries)


def uninstall_grants_watcher(name: str, *, darwin: bool) -> None:
    """Best-effort, idempotent removal of a cage's host-side grants watcher.

    Undoes :func:`install_grants_watcher_plist` (macOS) and the systemd
    user unit installed by ``cli._ensure_grants_watcher`` (Linux). Called
    from ``VmBackend.destroy_resources`` and ``ContainerBackend``'s
    teardown so a destroyed cage does not leave an ENABLED systemd unit
    polling a nonexistent cage (or, on macOS, a ``KeepAlive=true``
    launchd agent that relaunches forever).

    Never raises: every step is wrapped so a half-installed watcher (e.g.
    the unit file was written but ``systemctl enable`` failed) still cleans
    up as much as exists. ``systemd`` is imported lazily because this
    module is imported on macOS too, where ``systemctl`` is absent —
    :mod:`agentcage.systemd` is already no-op-safe there.
    """
    if darwin:
        uid = os.getuid()
        domain = f"gui/{uid}"
        label = f"io.agentcage.{name}.grants"
        try:
            subprocess.run(
                ["launchctl", "bootout", f"{domain}/{label}"],
                check=False, capture_output=True,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        plist = grants_watcher_plist_path(name)
        if plist.exists():
            try:
                plist.unlink()
            except OSError:
                pass
        return

    # Linux / systemd host.
    from agentcage import systemd
    unit = f"{name}-grants.service"
    try:
        systemd.stop_unit(unit)
    except Exception:
        pass  # unit may not exist (never installed, or already gone)
    try:
        systemd.disable_unit(unit)
    except Exception:
        pass  # best-effort; mirroring enable_unit's tolerance
    try:
        systemd.daemon_reload()
    except Exception:
        pass
    unit_path = grants_watcher_unit_path(name)
    if unit_path.exists():
        try:
            unit_path.unlink()
        except OSError:
            pass


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
    watcher_path = _watcher_path(binary)
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
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{watcher_path}</string>
    </dict>
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
