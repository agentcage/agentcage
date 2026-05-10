"""Thin wrapper around the podman CLI."""

from __future__ import annotations

import json
import os
import subprocess


def filter_secrets_by_prefix(lines: list[str], prefix: str) -> list[dict]:
    """Parse secret names from output lines and optionally filter by prefix.

    Shared by both host Podman and VM Podman secret_list() implementations.
    """
    secrets = [{"Name": name} for name in lines]
    if prefix:
        secrets = [s for s in secrets if s["Name"].startswith(prefix)]
    return secrets


def _podman_cmd() -> list[str]:
    """Return the base command for running podman.

    When running as root via sudo, prefix with ``runuser -u <real-user>``
    so that Podman uses the real user's rootless storage and networking.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        return ["runuser", "-u", sudo_user, "--", "podman"]
    return ["podman"]


class Podman:
    def image_exists(self, name: str) -> bool:
        r = subprocess.run([*_podman_cmd(), "image", "exists", name])
        return r.returncode == 0

    def build_image(
        self,
        tag: str,
        containerfile: str | None,
        context_dir: str,
        cap_add: list[str] | None = None,
        no_cache: bool = False,
        build_args: dict[str, str] | None = None,
        quiet: bool = False,
        pull: bool = False,
    ) -> None:
        """Run ``podman build`` to produce *tag*.

        *no_cache* invalidates podman's per-layer build cache.
        *pull* forces ``--pull=always``, re-fetching the base image (the
        Containerfile's ``FROM`` ref) from the registry instead of reusing
        the locally cached copy. The two flags are independent: ``no_cache``
        alone will reuse a stale base image; ``pull`` alone will reuse
        cached intermediate layers built on top of the freshly-pulled base.
        Pass both for a fully clean rebuild.
        """
        cmd = [*_podman_cmd(), "build", "-t", tag]
        if containerfile is not None:
            cmd.extend(["-f", containerfile])
        if no_cache:
            cmd.append("--no-cache")
        if pull:
            cmd.append("--pull=always")
        for cap in cap_add or []:
            cmd.extend(["--cap-add", cap])
        for k, v in (build_args or {}).items():
            cmd.extend(["--build-arg", f"{k}={v}"])
        cmd.append(context_dir)
        if quiet:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, cmd,
                    output=result.stdout, stderr=result.stderr,
                )
        else:
            subprocess.run(cmd, check=True)

    def run_and_remove(
        self,
        image: str,
        command: list[str],
        volumes: dict[str, dict[str, str]] | None = None,
    ) -> None:
        cmd = [*_podman_cmd(), "run", "--rm"]
        for host_path, opts in (volumes or {}).items():
            bind = opts.get("bind", host_path)
            mode = opts.get("mode", "")
            mount = f"{host_path}:{bind}"
            if mode:
                mount += f":{mode}"
            cmd.extend(["-v", mount])
        cmd.append(image)
        cmd.extend(command)
        subprocess.run(cmd, check=True)

    def container_running(self, name: str) -> bool:
        r = subprocess.run(
            [*_podman_cmd(), "inspect", "--format", "{{.State.Status}}", name],
            capture_output=True, text=True,
        )
        return r.returncode == 0 and r.stdout.strip() == "running"

    def container_inspect(self, name: str) -> dict:
        r = subprocess.run(
            [*_podman_cmd(), "inspect", name],
            capture_output=True, text=True, check=True,
        )
        return json.loads(r.stdout)[0]

    def container_exec(self, name: str, cmd: list[str]) -> tuple[int, str]:
        r = subprocess.run(
            [*_podman_cmd(), "exec", name, *cmd],
            capture_output=True, text=True,
        )
        return r.returncode, r.stdout

    def network_remove(self, name: str) -> bool:
        r = subprocess.run([*_podman_cmd(), "network", "rm", name],
                           capture_output=True)
        return r.returncode == 0

    def volume_remove(self, name: str) -> bool:
        r = subprocess.run([*_podman_cmd(), "volume", "rm", name],
                           capture_output=True)
        return r.returncode == 0

    def volume_exists(self, name: str) -> bool:
        r = subprocess.run([*_podman_cmd(), "volume", "exists", name])
        return r.returncode == 0

    def volume_export(self, name: str, output_path: str) -> None:
        """Export a Podman volume to a tar file."""
        with open(output_path, "wb") as f:
            subprocess.run(
                [*_podman_cmd(), "volume", "export", name],
                stdout=f, check=True,
            )

    def volume_create(self, name: str) -> None:
        subprocess.run(
            [*_podman_cmd(), "volume", "create", name],
            capture_output=True, check=True,
        )

    def volume_import(self, name: str, tar_path: str) -> None:
        """Import a tar archive into a Podman volume."""
        with open(tar_path, "rb") as f:
            subprocess.run(
                [*_podman_cmd(), "volume", "import", name, "-"],
                stdin=f, check=True,
            )

    def pull(self, image: str) -> bool:
        """Pull a container image from the registry.

        Returns ``True`` on success, ``False`` on failure (e.g. local-only
        images or no network).
        """
        r = subprocess.run([*_podman_cmd(), "pull", image])
        return r.returncode == 0

    def info(self) -> dict:
        r = subprocess.run(
            [*_podman_cmd(), "info", "--format", "json"],
            capture_output=True, text=True, check=True,
        )
        return json.loads(r.stdout)

    def image_inspect(self, name: str) -> dict:
        r = subprocess.run(
            [*_podman_cmd(), "image", "inspect", name],
            capture_output=True, text=True, check=True,
        )
        return json.loads(r.stdout)[0]

    def secret_list(self, prefix: str = "") -> list[dict]:
        """List podman secrets, optionally filtered by name prefix."""
        r = subprocess.run(
            [*_podman_cmd(), "secret", "ls", "--noheading",
             "--format", "{{.Name}}"],
            capture_output=True, text=True,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return []
        return filter_secrets_by_prefix(r.stdout.strip().splitlines(), prefix)

    def secret_exists(self, name: str) -> bool:
        r = subprocess.run(
            [*_podman_cmd(), "secret", "inspect", name],
            capture_output=True,
        )
        return r.returncode == 0

    def secret_create(self, name: str, value: str) -> None:
        subprocess.run(
            [*_podman_cmd(), "secret", "create", name, "-"],
            input=value, text=True, check=True,
            stdout=subprocess.DEVNULL,
        )

    def secret_read(self, name: str) -> str:
        """Read a secret's value from Podman's secret store."""
        r = subprocess.run(
            [*_podman_cmd(), "secret", "inspect", "--showsecret",
             "--format", "{{.SecretData}}", name],
            capture_output=True, text=True, check=True,
        )
        return r.stdout.strip()

    def secret_remove(self, name: str) -> bool:
        r = subprocess.run(
            [*_podman_cmd(), "secret", "rm", name],
            capture_output=True,
        )
        return r.returncode == 0
