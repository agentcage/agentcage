"""Lima instance lifecycle management."""

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

        On macOS with the VZ driver, the hostagent process runs the VM.
        Without protection, it receives SIGHUP when the parent process
        exits (e.g. when invoked over SSH), causing the VM to shut down.
        We use nohup + start_new_session to prevent this.
        """
        subprocess.run(
            ["nohup", "limactl", "start", self.name],
            check=True,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for the VM to be ready (nohup may return before hostagent
        # finishes initialization)
        import time
        for _ in range(60):
            if self.is_running():
                return
            time.sleep(1)
        raise RuntimeError(f"Lima instance {self.name} did not start within 60 seconds")

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
