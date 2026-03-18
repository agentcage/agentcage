"""Podman operations routed through a Lima VM instance."""

from __future__ import annotations

import subprocess

from agentcage.lima.instance import LimaInstance


class VmPodman:
    """Podman secret/image operations inside a Lima VM.

    Mirrors the subset of agentcage.podman.Podman methods used by the
    CLI for secret management, so the CLI can use either host Podman
    or VM Podman transparently.
    """

    def __init__(self, cage_name: str) -> None:
        self._inst = LimaInstance(cage_name)

    def _run(self, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        """Run a podman command inside the VM."""
        return subprocess.run(
            ["limactl", "shell", self._inst.name, "--", *cmd],
            **kwargs,
        )

    def secret_list(self, prefix: str = "") -> list[dict]:
        r = self._run(
            ["podman", "secret", "ls", "--noheading", "--format", "{{.Name}}"],
            capture_output=True, text=True,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return []
        secrets = [{"Name": name} for name in r.stdout.strip().splitlines()]
        if prefix:
            secrets = [s for s in secrets if s["Name"].startswith(prefix)]
        return secrets

    def secret_exists(self, name: str) -> bool:
        r = self._run(
            ["podman", "secret", "inspect", name],
            capture_output=True,
        )
        return r.returncode == 0

    def secret_create(self, name: str, value: str) -> None:
        self._run(
            ["podman", "secret", "create", name, "-"],
            input=value, text=True, check=True,
            stdout=subprocess.DEVNULL,
        )

    def secret_read(self, name: str) -> str:
        r = self._run(
            ["podman", "secret", "inspect", "--showsecret",
             "--format", "{{.SecretData}}", name],
            capture_output=True, text=True, check=True,
        )
        return r.stdout.strip()

    def secret_remove(self, name: str) -> bool:
        r = self._run(
            ["podman", "secret", "rm", name],
            capture_output=True,
        )
        return r.returncode == 0
