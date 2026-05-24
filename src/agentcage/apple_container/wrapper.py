"""Per-cage wrapper image generation for the apple-container backend.

For each cage we generate a small Containerfile that layers the agentcage
supervisor + hardening onto the user's cage image. The supervisor is then the
PID 1 of the Apple container microVM and exec's the user's original CMD after
hardening setup.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterable

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.apple_container import cli as ac_cli


_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "apple-container"


def _user_cmd(user_image: str) -> list[str]:
    """Resolve the user image's effective CMD (ENTRYPOINT + CMD, exec form).

    Apple's `container image inspect` returns the OCI image index plus a
    per-platform variant block; the OCI image config lives at
    ``variants[<host-platform>].config.config`` and uses OCI-style
    capitalized keys (``Cmd``, ``Entrypoint``).
    """
    data = ac_cli.image_inspect(user_image)
    if not data:
        raise ValueError(
            f"cannot inspect user cage image {user_image!r}; is it pulled/built?"
        )

    cfg: dict | None = None
    # Newer Apple schema: data["variants"][i]["config"]["config"]
    variants = data.get("variants") or data.get("Variants")
    if isinstance(variants, list):
        # Prefer the arm64 variant (we're on Apple Silicon); fall back to any.
        for v in variants:
            plat = (v.get("platform") or {})
            if plat.get("architecture") == "arm64":
                cfg = ((v.get("config") or {}).get("config")) or {}
                break
        if cfg is None and variants:
            cfg = ((variants[0].get("config") or {}).get("config")) or {}
    # Older / generic schemas:
    if cfg is None:
        cfg = (
            (data.get("config", {}) or {}).get("config")
            or data.get("config")
            or data.get("Config")
            or {}
        )

    entrypoint = cfg.get("Entrypoint") or cfg.get("entrypoint") or []
    cmd = cfg.get("Cmd") or cfg.get("cmd") or []
    if isinstance(entrypoint, str):
        entrypoint = [entrypoint]
    if isinstance(cmd, str):
        cmd = [cmd]
    combined = [*entrypoint, *cmd]
    if not combined:
        raise ValueError(
            f"user cage image {user_image!r} has neither ENTRYPOINT nor CMD; "
            "agentcage cannot determine what to run"
        )
    return combined


def render_wrapper_containerfile(user_image: str, *, user_cmd: list[str] | None = None) -> str:
    """Render the per-cage wrapper Containerfile to a string."""
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_DATA_DIR)),
        keep_trailing_newline=True,
    )
    if user_cmd is None:
        user_cmd = _user_cmd(user_image)
    tmpl = env.get_template("Containerfile.wrapper.j2")
    return tmpl.render(user_image=user_image)


def stage_build_context(dest: Path, user_cmd: list[str]) -> None:
    """Stage supervisor + cage-cmd.json into *dest* for the build context.

    Writing the cage CMD as a JSON file (not an ENV var) sidesteps the
    Containerfile ENV-quoting nightmare for commands containing shell
    metacharacters. The supervisor parses it at runtime with `jq @sh`.
    """
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_DATA_DIR / "supervisor.sh", dest / "supervisor.sh")
    (dest / "cage-cmd.json").write_text(json.dumps(user_cmd))


def wrapped_image_name(cage_name: str) -> str:
    """Return the OCI image reference for the wrapped per-cage image."""
    return f"localhost/agentcage-apple-{cage_name}:latest"


def build_wrapper(cage_name: str, user_image: str, *, user_cmd: list[str] | None = None) -> str:
    """Generate Containerfile, stage build context, run `container build`.

    Returns the built image reference.
    """
    import tempfile

    image = wrapped_image_name(cage_name)
    containerfile = render_wrapper_containerfile(user_image, user_cmd=user_cmd)

    if user_cmd is None:
        user_cmd = _user_cmd(user_image)

    with tempfile.TemporaryDirectory(prefix="agentcage-apple-build-") as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "Containerfile").write_text(containerfile)
        stage_build_context(tmpdir, user_cmd)
        ac_cli.run(
            ["build", "-t", image, "-f", str(tmpdir / "Containerfile"), str(tmpdir)],
            capture_output=False,  # stream output to user
        )
    return image


def collect_image_artifacts(cage_name: str) -> Iterable[str]:
    """Return image references owned by *cage_name* (for cleanup)."""
    yield wrapped_image_name(cage_name)
