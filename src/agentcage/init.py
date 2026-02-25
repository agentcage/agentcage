"""Scaffold a new agentcage configuration file."""

from __future__ import annotations

import sys
from pathlib import Path

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Scaffold name → base image (without tag) for version pinning
_SCAFFOLD_IMAGES: dict[str, str] = {
    "openclaw": "ghcr.io/openclaw/openclaw",
    "picoclaw": "docker.io/sipeed/picoclaw",
}


def _make_env() -> SandboxedEnvironment:
    return SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def list_scaffolds() -> list[str]:
    """Return sorted names of available scaffold templates."""
    preset_dir = _TEMPLATES_DIR / "presets"
    if not preset_dir.is_dir():
        return []
    return sorted(
        p.stem.removesuffix(".yaml") for p in preset_dir.glob("*.yaml.j2")
    )


def render_config(
    name: str,
    *,
    image: str = "node:22-slim",
    isolation: str = "container",
    scaffold: str | None = None,
    port: int | None = None,
) -> str:
    """Render a starter config.yaml from a template.

    When *scaffold* is ``None`` the default blank scaffold is used.
    Otherwise *scaffold* selects a file from ``templates/presets/``.
    """
    env = _make_env()
    if scaffold is None:
        tmpl = env.get_template("init-config.yaml.j2")
        return tmpl.render(name=name, image=image, isolation=isolation, port=port)
    tmpl = env.get_template(f"presets/{scaffold}.yaml.j2")

    image_tag: str | None = None
    image_base = _SCAFFOLD_IMAGES.get(scaffold)
    if image_base:
        from agentcage.registry import resolve_latest_tag

        image_tag = resolve_latest_tag(image_base)
        if image_tag is None:
            print(
                f"warning: could not resolve latest tag for {image_base}, "
                f"falling back to 'latest'",
                file=sys.stderr,
            )

    return tmpl.render(name=name, isolation=isolation, port=port, image_tag=image_tag)
