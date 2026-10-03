"""Podman operations routed through a Lima VM instance."""

from __future__ import annotations

import json

from agentcage.lima.instance import LimaInstance
from agentcage.podman import _parse_secret_list, filter_secrets_by_prefix


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

    def pull(self, image: str) -> bool:
        """Pull an image in the guest, returning whether it succeeded."""
        result = self._inst.exec(["podman", "pull", image], check=False)
        return result.returncode == 0

    def image_inspect(self, image: str) -> dict:
        """Inspect an image in the guest using Podman's JSON format."""
        result = self._inst.exec(["podman", "image", "inspect", image])
        return json.loads(result.stdout)[0]

    def container_inspect(self, name: str) -> dict:
        """Inspect a container in the guest using Podman's JSON format.

        This method was missing, and its absence made the VM live-secret
        path unreachable: ``services.cage_has_live_secret_channel``
        builds a ``VmPodman`` for an ``isolation: vm`` cage and calls
        ``container_inspect`` on it, so every call raised
        ``AttributeError`` into that function's bare ``except
        Exception`` and returned False. The consequence was not an error
        anyone saw — it was that ``secret set`` and ``secret rm`` on a
        *running* vm cage always took the restart path, costing the
        workload its process state, while the zero-restart branch
        written for them (``stage_secret_value``'s vm arm and the
        ``push_config_files`` follow-up) never ran at all.

        Spelled ``podman container inspect`` rather than the host
        method's bare ``podman inspect``: the bare form also matches
        images, and the one thing this is asked about is a container.
        """
        result = self._inst.exec(["podman", "container", "inspect", name])
        return json.loads(result.stdout)[0]

    def secret_list(self, prefix: str = "") -> list[dict]:
        r = self._inst.exec(
            ["podman", "secret", "ls", "--noheading", "--format", "{{.Name}}"],
            check=False,
        )
        return _parse_secret_list(r, prefix)

    def secret_list_strict(self, prefix: str = "") -> list[dict]:
        """List secrets, raising on a guest ``podman secret ls`` failure.

        Mirrors :meth:`agentcage.podman.Podman.secret_list_strict`: lets
        the store-aware ``Secret=`` emission path (issue #262) fall back
        to legacy emit-everything on a transient failure instead of
        dropping every directive against an empty view. The VM backend
        already guards the call with ``inst.is_running()`` so a stopped
        guest never reaches here, but an in-flight failure still can.
        """
        r = self._inst.exec(
            ["podman", "secret", "ls", "--noheading", "--format", "{{.Name}}"],
            check=False,
        )
        if r.returncode != 0:
            raise RuntimeError(
                "podman secret ls failed in VM: "
                f"{(r.stderr or r.stdout or '').strip()}"
            )
        if not r.stdout.strip():
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
