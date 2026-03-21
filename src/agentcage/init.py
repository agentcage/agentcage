"""Scaffold a new agentcage configuration file."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import click
import yaml
from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_SCAFFOLDS_DIR = Path(__file__).parent / "scaffolds"

# Scaffold name → base image (without tag) for version pinning.
# picoclaw uses a local build (see scaffold comments) until a release
# with HTTP proxy support ships upstream.
_SCAFFOLD_IMAGES: dict[str, str] = {
    "openclaw": "ghcr.io/openclaw/openclaw",
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
    names: set[str] = set()
    if preset_dir.is_dir():
        names.update(p.stem.removesuffix(".yaml") for p in preset_dir.glob("*.yaml.j2"))
    if _SCAFFOLDS_DIR.is_dir():
        names.update(d.name for d in _SCAFFOLDS_DIR.iterdir()
                     if d.is_dir() and (d / "cage.yaml.j2").exists())
    return sorted(names)


def render_config(
    name: str,
    *,
    image: str = "node:22-slim",
    isolation: str = "container",
    scaffold: str | None = None,
    port: int | None = None,
) -> tuple[str, str | None]:
    """Render a starter config.yaml from a template.

    When *scaffold* is ``None`` the default blank scaffold is used.
    Otherwise *scaffold* selects a file from ``templates/presets/``
    or ``scaffolds/<name>/cage.yaml.j2``.
    """
    env = _make_env()
    if scaffold is None:
        tmpl = env.get_template("init-config.yaml.j2")
        return tmpl.render(name=name, image=image, isolation=isolation, port=port), None

    # Check scaffolds/ directory first, then fall back to templates/presets/
    scaffold_file = _SCAFFOLDS_DIR / scaffold / "cage.yaml.j2"
    if scaffold_file.exists():
        env = SandboxedEnvironment(
            loader=FileSystemLoader(str(scaffold_file.parent)),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        tmpl = env.get_template("cage.yaml.j2")
    else:
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

    from agentcage.quadlets import cage_network_addrs

    addrs = cage_network_addrs(name)
    return tmpl.render(name=name, isolation=isolation, port=port, image_tag=image_tag, **addrs), image_tag


def load_scaffold_meta(scaffold: str) -> dict | None:
    """Load scaffold.yaml from a scaffold directory, if present."""
    meta_file = _SCAFFOLDS_DIR / scaffold / "scaffold.yaml"
    if not meta_file.exists():
        return None
    with open(meta_file) as f:
        return yaml.safe_load(f) or {}


def run_scaffold_setup(
    scaffold: str, name: str, dest: str, *, image_tag: str | None = None, quiet: bool = False,
) -> None:
    """Execute build/provision steps from scaffold.yaml."""
    meta = load_scaffold_meta(scaffold)
    if meta is None:
        return

    from agentcage.podman import Podman

    podman = Podman()
    scaffold_dir = _SCAFFOLDS_DIR / scaffold

    def _echo(msg: str) -> None:
        if not quiet:
            click.echo(msg)

    # 1. Process build entries
    for entry in meta.get("build", []):
        image = entry["image"]
        if podman.image_exists(image):
            _echo(f"Image {image} already exists, skipping build.")
            continue

        # Resolve build_args — append resolved tag for scaffold images
        build_args = dict(entry.get("build_args") or {})
        for key, val in list(build_args.items()):
            if val in _SCAFFOLD_IMAGES.values() and image_tag:
                build_args[key] = f"{val}:{image_tag}"

        if "containerfile" in entry:
            containerfile = str(scaffold_dir / entry["containerfile"])
            _echo(f"Building {image}...")
            podman.build_image(
                image, containerfile, str(scaffold_dir),
                cap_add=entry.get("cap_add"), build_args=build_args,
                quiet=quiet,
            )
        elif "git" in entry:
            git_url = entry["git"]
            depth = entry.get("depth", 1)
            with tempfile.TemporaryDirectory() as tmpdir:
                _echo(f"Cloning {git_url}...")
                cmd = ["git", "clone", f"--depth={depth}", git_url, tmpdir]
                if quiet:
                    subprocess.run(cmd, check=True, capture_output=True)
                else:
                    subprocess.run(cmd, check=True)
                _echo(f"Building {image}...")
                podman.build_image(
                    image, None, tmpdir,
                    cap_add=entry.get("cap_add"), build_args=build_args,
                    quiet=quiet,
                )

    # 2. Process provision entries
    for entry in meta.get("provision", []):
        src = scaffold_dir / entry["src"]
        dest_path = Path(entry["dest"]).expanduser()
        if dest_path.exists():
            _echo(f"{dest_path} already exists, skipping.")
            continue
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dest_path))
        _echo(f"Created {dest_path}")
