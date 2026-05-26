"""Podman operations routed through a Lima VM instance."""

from __future__ import annotations

from agentcage.lima.instance import LimaInstance
from agentcage.podman import filter_secrets_by_prefix


class VmPodman:
    """Podman secret/image operations inside a Lima VM.

    Mirrors the subset of agentcage.podman.Podman methods used by the
    CLI for secret management, so the CLI can use either host Podman
    or VM Podman transparently. All ``limactl shell`` invocations go
    through ``LimaInstance.exec`` so they share the ``--tty=false``
    (no PTY cooking of piped secret values) and ``--workdir /`` (no
    spurious ``cd: No such file or directory`` warnings) flags.
    """

    def __init__(self, cage_name: str) -> None:
        self._inst = LimaInstance(cage_name)

    def secret_list(self, prefix: str = "") -> list[dict]:
        r = self._inst.exec(
            ["podman", "secret", "ls", "--noheading", "--format", "{{.Name}}"],
            check=False,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return []
        return filter_secrets_by_prefix(r.stdout.strip().splitlines(), prefix)

    def secret_exists(self, name: str) -> bool:
        r = self._inst.exec(
            ["podman", "secret", "inspect", name],
            check=False,
        )
        return r.returncode == 0

    def secret_create(self, name: str, value: str) -> None:
        self._inst.exec(
            ["podman", "secret", "create", name, "-"],
            input=value,
        )

    def secret_read(self, name: str) -> str:
        r = self._inst.exec(
            ["podman", "secret", "inspect", "--showsecret",
             "--format", "{{.SecretData}}", name],
        )
        return r.stdout.strip()

    def secret_remove(self, name: str) -> bool:
        r = self._inst.exec(
            ["podman", "secret", "rm", name],
            check=False,
        )
        return r.returncode == 0
