"""Thin wrapper around the podman CLI."""

from __future__ import annotations

import json
import subprocess


class Podman:
    def image_exists(self, name: str) -> bool:
        r = subprocess.run(["podman", "image", "exists", name])
        return r.returncode == 0

    def build_image(
        self,
        tag: str,
        containerfile: str,
        context_dir: str,
        cap_add: list[str] | None = None,
    ) -> None:
        cmd = ["podman", "build", "-t", tag, "-f", containerfile]
        for cap in cap_add or []:
            cmd.extend(["--cap-add", cap])
        cmd.append(context_dir)
        subprocess.run(cmd, check=True)

    def run_and_remove(
        self,
        image: str,
        command: list[str],
        volumes: dict[str, dict[str, str]] | None = None,
    ) -> None:
        cmd = ["podman", "run", "--rm"]
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
            ["podman", "inspect", "--format", "{{.State.Status}}", name],
            capture_output=True, text=True,
        )
        return r.returncode == 0 and r.stdout.strip() == "running"

    def container_inspect(self, name: str) -> dict:
        r = subprocess.run(
            ["podman", "inspect", name],
            capture_output=True, text=True, check=True,
        )
        return json.loads(r.stdout)[0]

    def container_exec(self, name: str, cmd: list[str]) -> tuple[int, str]:
        r = subprocess.run(
            ["podman", "exec", name, *cmd],
            capture_output=True, text=True,
        )
        return r.returncode, r.stdout

    def network_remove(self, name: str) -> bool:
        r = subprocess.run(["podman", "network", "rm", name],
                           capture_output=True)
        return r.returncode == 0

    def volume_remove(self, name: str) -> bool:
        r = subprocess.run(["podman", "volume", "rm", name],
                           capture_output=True)
        return r.returncode == 0

    def info(self) -> dict:
        r = subprocess.run(
            ["podman", "info", "--format", "json"],
            capture_output=True, text=True, check=True,
        )
        return json.loads(r.stdout)

    def image_inspect(self, name: str) -> dict:
        r = subprocess.run(
            ["podman", "image", "inspect", name],
            capture_output=True, text=True, check=True,
        )
        return json.loads(r.stdout)[0]

    def secret_list(self, prefix: str = "") -> list[dict]:
        """List podman secrets, optionally filtered by name prefix."""
        r = subprocess.run(
            ["podman", "secret", "ls", "--noheading",
             "--format", "{{.Name}}"],
            capture_output=True, text=True,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return []
        secrets = [{"Name": name} for name in r.stdout.strip().splitlines()]
        if prefix:
            secrets = [s for s in secrets if s["Name"].startswith(prefix)]
        return secrets

    def secret_exists(self, name: str) -> bool:
        r = subprocess.run(
            ["podman", "secret", "inspect", name],
            capture_output=True,
        )
        return r.returncode == 0

    def secret_create(self, name: str, value: str) -> None:
        subprocess.run(
            ["podman", "secret", "create", name, "-"],
            input=value, text=True, check=True,
        )

    def secret_read(self, name: str) -> str:
        """Read a secret's value from Podman's secret store."""
        r = subprocess.run(
            ["podman", "secret", "inspect", "--showsecret",
             "--format", "{{.SecretData}}", name],
            capture_output=True, text=True, check=True,
        )
        return r.stdout.strip()

    def secret_remove(self, name: str) -> bool:
        r = subprocess.run(
            ["podman", "secret", "rm", name],
            capture_output=True,
        )
        return r.returncode == 0
