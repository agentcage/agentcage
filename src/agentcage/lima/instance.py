"""Lima instance lifecycle management."""

from __future__ import annotations

import json
import subprocess
from subprocess import CompletedProcess


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

        ``limactl start`` handles daemonization internally — it forks
        the hostagent, waits for all requirements (SSH, guest agent,
        boot scripts) to be satisfied, then exits. The hostagent
        daemon keeps running in the background.

        We use os.system() rather than subprocess.run() because Lima's
        hostagent daemonization works correctly when launched from a
        real shell (/bin/sh) but fails when launched directly via
        Python's subprocess (the daemon inherits pipe file descriptors
        that prevent proper detachment).
        """
        import os
        ret = os.system(f"limactl start {self.name}")
        if ret != 0:
            raise subprocess.CalledProcessError(ret >> 8, f"limactl start {self.name}")

    def stop(self) -> None:
        """Stop the Lima instance."""
        subprocess.run(
            ["limactl", "stop", self.name],
            check=True,
        )

    def delete(self) -> None:
        """Delete the Lima instance forcefully."""
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
