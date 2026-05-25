"""Thin subprocess wrapper around Apple's `container` CLI.

The `container` binary is installed by the Apple `container` .pkg at
/usr/local/bin/container, which is not always on PATH for non-login shells
(notably the one launched by agentcage via subprocess). We resolve the path
explicitly so the backend works regardless of how it was invoked.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from subprocess import CompletedProcess

from agentcage import output


_CANDIDATE_PATHS = (
    "/usr/local/bin/container",
    "/opt/homebrew/bin/container",
)


def container_binary() -> str | None:
    """Return the resolved path to the `container` binary, or None if missing."""
    on_path = shutil.which("container")
    if on_path:
        return on_path
    for p in _CANDIDATE_PATHS:
        if shutil.which(p):
            return p
    return None


def run(
    args: list[str],
    *,
    check: bool = True,
    capture_output: bool = True,
    text: bool = True,
    input: str | None = None,
) -> CompletedProcess:
    """Run `container <args>` and return the CompletedProcess."""
    binary = container_binary()
    if binary is None:
        raise FileNotFoundError(
            "Apple `container` CLI not found; install from "
            "https://github.com/apple/container/releases"
        )
    if capture_output:
        return subprocess.run(
            [binary, *args],
            check=check,
            capture_output=capture_output,
            text=text,
            input=input,
        )
    # Streaming case: Apple's `container` CLI writes its own progress
    # (e.g. "[1/2] Fetching image [13s]") to stderr. If an agentcage
    # Spinner is currently running it would fight for the same line,
    # producing a flickering double-spinner. Pause our spinner for the
    # duration of the child process so its output is unobstructed.
    with output.pause_active_spinner():
        return subprocess.run(
            [binary, *args],
            check=check,
            capture_output=capture_output,
            text=text,
            input=input,
        )


def system_running() -> bool:
    """Return True if the container apiserver is running."""
    try:
        r = run(["system", "status"], check=False)
        return "status" in r.stdout and "running" in r.stdout
    except FileNotFoundError:
        return False


def inspect(name: str) -> dict | None:
    """Return the parsed JSON inspect result for a container, or None if absent."""
    try:
        r = run(["inspect", name], check=False)
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout)
        return data[0] if isinstance(data, list) and data else data
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def image_inspect(image: str) -> dict | None:
    """Return the parsed JSON image inspect result, or None if absent."""
    try:
        r = run(["image", "inspect", image], check=False)
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout)
        return data[0] if isinstance(data, list) and data else data
    except (FileNotFoundError, json.JSONDecodeError):
        return None
