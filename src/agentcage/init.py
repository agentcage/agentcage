"""Scaffold a new agentcage configuration file."""

from __future__ import annotations

from pathlib import Path

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _make_env() -> SandboxedEnvironment:
    return SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def list_presets() -> list[str]:
    """Return sorted names of available preset templates."""
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
    preset: str | None = None,
) -> str:
    """Render a starter config.yaml from a template.

    When *preset* is ``None`` the default blank scaffold is used.
    Otherwise *preset* selects a file from ``templates/presets/``.
    """
    env = _make_env()
    if preset is None:
        tmpl = env.get_template("init-config.yaml.j2")
        return tmpl.render(name=name, image=image, isolation=isolation)
    tmpl = env.get_template(f"presets/{preset}.yaml.j2")
    return tmpl.render(name=name, isolation=isolation)
