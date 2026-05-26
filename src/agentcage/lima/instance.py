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
        """Create a Lima instance using the given config file.

        ``--yes`` skips ``limactl create``'s interactive "Proceed with the
        current configuration / Open an editor / ..." survey. Lima only shows
        that survey when a TTY is attached, so without ``--yes`` the first
        interactive ``agentcage run`` on a fresh machine would hang on a
        prompt hidden behind the "Starting cage..." spinner.
        """
        subprocess.run(
            ["limactl", "create", "--yes", f"--name={self.name}", config_path],
            check=True,
        )

    def start(self) -> None:
        """Start the Lima instance.

        ``limactl start`` handles daemonization internally — it forks
        the hostagent, waits for all requirements (SSH, guest agent,
        boot scripts) to be satisfied, then exits. The hostagent
        daemon keeps running in the background.

        We use ``start_new_session=True`` so the hostagent daemon runs
        in its own process group and does not inherit pipe FDs from
        Python's subprocess machinery, which would otherwise prevent
        ``limactl start`` from completing.
        """
        subprocess.run(
            ["limactl", "start", self.name],
            check=True,
            start_new_session=True,
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
        input: str | bytes | None = None,
    ) -> CompletedProcess:
        """Run a command inside the Lima VM.

        ``--workdir /`` pins the guest cwd to ``/`` so the SSH shell does
        not try to ``cd`` into the host's current directory. By default
        ``limactl shell`` mirrors the host cwd inside the VM, which only
        the explicitly-mounted ``~/.config/agentcage`` /
        ``~/.local/share/agentcage`` paths can satisfy — every other
        invocation prints a spurious ``cd: <path>: No such file or
        directory`` and runs from $HOME anyway.

        ``--tty=false`` (``-y``) keeps SSH from allocating a PTY. Without
        it, piping ``input=`` while stdout is attached to a terminal
        causes Lima to default to a PTY and the kernel line discipline
        cooks the stream (CR↔LF translation, control-char handling),
        which silently mangles secret values fed to ``podman secret
        create -``.
        """
        return subprocess.run(
            ["limactl", "shell", "--workdir", "/", "--tty=false",
             self.name, "--"] + cmd,
            check=check,
            capture_output=capture_output,
            text=text,
            input=input,
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
