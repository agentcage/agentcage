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

        On macOS with the VZ driver, the hostagent IS the VM process —
        it cannot daemonize. ``limactl start`` (non-foreground) kills
        the hostagent on exit, stopping the VM.

        We use ``limactl start --foreground`` via Popen and keep the
        process alive (never wait on it). The Popen object is stored
        so the process isn't garbage-collected. We poll with
        ``limactl shell ... -- true`` until SSH is ready.
        """
        import time

        # Launch foreground hostagent — must stay alive for VM to run
        self._hostagent = subprocess.Popen(
            ["limactl", "start", "--foreground", self.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

        # Poll until VM is SSH-ready
        for _ in range(120):
            if self._hostagent.poll() is not None:
                raise RuntimeError(
                    f"Lima hostagent exited unexpectedly with code {self._hostagent.returncode}"
                )
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
