"""Lima instance lifecycle management."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from pathlib import Path
from subprocess import CompletedProcess

# launchd label prefix for Lima hostagent services
_LAUNCHD_PREFIX = "com.agentcage.lima."


def _launchd_label(instance_name: str) -> str:
    return f"{_LAUNCHD_PREFIX}{instance_name}"


def _launchd_plist_path(instance_name: str) -> Path:
    """Return ~/Library/LaunchAgents/<label>.plist."""
    return Path.home() / "Library" / "LaunchAgents" / f"{_launchd_label(instance_name)}.plist"


def _generate_plist(instance_name: str) -> str:
    """Generate a launchd plist that runs limactl start --foreground."""
    import shutil
    limactl = shutil.which("limactl") or "/opt/homebrew/bin/limactl"
    label = _launchd_label(instance_name)
    log_dir = Path.home() / "Library" / "Logs" / "agentcage"
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{limactl}</string>
        <string>start</string>
        <string>--foreground</string>
        <string>{instance_name}</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{log_dir}/{instance_name}.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/{instance_name}.err.log</string>
</dict>
</plist>
"""


class LimaInstance:
    """Manages a Lima VM instance for a given cage."""

    def __init__(self, cage_name: str) -> None:
        self.name = f"agentcage-{cage_name}"

    def create(self, config_path: str) -> None:
        """Create a Lima instance using the given config file."""
        subprocess.run(
            ["limactl", "create", f"--name={self.name}", config_path],
            check=True,
        )

    def start(self) -> None:
        """Start the Lima instance.

        On macOS with the VZ driver, the hostagent IS the VM process.
        ``limactl start`` (non-foreground) kills the hostagent on exit,
        stopping the VM. We use launchd to run ``limactl start
        --foreground`` as a persistent user service.

        On Linux (QEMU), plain ``limactl start`` works because QEMU
        properly daemonizes.
        """
        if platform.system() == "Darwin":
            self._start_via_launchd()
        else:
            subprocess.run(
                ["limactl", "start", self.name],
                check=True,
            )

    def _start_via_launchd(self) -> None:
        """Start the Lima hostagent as a launchd user service."""
        plist_path = _launchd_plist_path(self.name)
        label = _launchd_label(self.name)

        # Create log directory
        log_dir = Path.home() / "Library" / "Logs" / "agentcage"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Write plist
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_path.write_text(_generate_plist(self.name))

        # Load and start
        # Unload first in case stale
        subprocess.run(
            ["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
            capture_output=True,
        )
        subprocess.run(
            ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path)],
            check=True,
        )
        subprocess.run(
            ["launchctl", "kickstart", f"gui/{os.getuid()}/{label}"],
            check=True,
        )

        # Poll until SSH is ready
        for _ in range(120):
            try:
                result = subprocess.run(
                    ["limactl", "shell", self.name, "--", "true"],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return
            except (subprocess.TimeoutExpired, Exception):
                pass
            time.sleep(2)
        raise RuntimeError(
            f"Lima instance {self.name} did not become SSH-ready within 240 seconds"
        )

    def stop(self) -> None:
        """Stop the Lima instance."""
        if platform.system() == "Darwin":
            # Stop via launchd first
            label = _launchd_label(self.name)
            subprocess.run(
                ["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
                capture_output=True,
            )
        subprocess.run(
            ["limactl", "stop", self.name],
            check=True,
        )

    def delete(self) -> None:
        """Delete the Lima instance forcefully."""
        if platform.system() == "Darwin":
            label = _launchd_label(self.name)
            subprocess.run(
                ["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
                capture_output=True,
            )
            plist = _launchd_plist_path(self.name)
            if plist.exists():
                plist.unlink()
        subprocess.run(
            ["limactl", "delete", "--force", self.name],
            check=True,
        )

    def exec(
        self,
        cmd: list[str],
        *,
        check: bool = True,
        capture_output: bool = True,
        text: bool = True,
    ) -> CompletedProcess:
        """Run a command inside the Lima VM."""
        return subprocess.run(
            ["limactl", "shell", self.name, "--"] + cmd,
            check=check,
            capture_output=capture_output,
            text=text,
        )

    def _list_json(self) -> dict:
        """Return parsed JSON output of `limactl list --json <name>`."""
        result = subprocess.run(
            ["limactl", "list", "--json", self.name],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout.strip())

    def is_running(self) -> bool:
        """Return True if the Lima instance status is 'Running'."""
        try:
            data = self._list_json()
            return data.get("status") == "Running"
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return False

    def exists(self) -> bool:
        """Return True if the Lima instance exists (any status)."""
        try:
            self._list_json()
            return True
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return False
