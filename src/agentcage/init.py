"""Scaffold a new agentcage configuration file."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import click
import yaml
from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_SCAFFOLDS_DIR = Path(__file__).parent / "scaffolds"

# Scaffold upstream image mapping lives in each scaffold's scaffold.yaml
# (build[].build_args). resolve_build_args() in registry.py resolves tags
# against those declarations.

_SCAFFOLD_IMAGE_RE = re.compile(r"^localhost/agentcage-scaffold-([a-z0-9-]+?)(?::|$)")


def infer_scaffold_from_image(image: str) -> str | None:
    """Infer scaffold name from the ``localhost/agentcage-scaffold-<NAME>:...``
    image naming convention used by scaffold-built images.

    Returns the scaffold name if it maps to a known scaffold, else ``None``.
    Used by update to auto-discover the scaffold for cages created before
    scaffold-name persistence landed in metadata.
    """
    m = _SCAFFOLD_IMAGE_RE.match(image or "")
    if not m:
        return None
    name = m.group(1)
    return name if name in list_scaffolds() else None


_SCAFFOLD_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')


def _valid_scaffold_name(name: str) -> bool:
    """Return True if name is a valid scaffold name (no path traversal)."""
    return bool(_SCAFFOLD_NAME_RE.match(name))


def resolve_scaffold(name: str) -> Path | None:
    """Resolve a scaffold name to its built-in directory path.

    Returns the scaffold directory Path, or None if not found.
    """
    if not _valid_scaffold_name(name):
        return None

    candidate = _SCAFFOLDS_DIR / name
    if (candidate / "cage.yaml.j2").exists():
        return candidate

    return None


def _make_env() -> SandboxedEnvironment:
    return SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def list_scaffolds() -> list[str]:
    """Return sorted names of available built-in scaffold templates."""
    if not _SCAFFOLDS_DIR.is_dir():
        return []
    return sorted(
        d.name for d in _SCAFFOLDS_DIR.iterdir()
        if d.is_dir() and (d / "cage.yaml.j2").exists()
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
    Otherwise *scaffold* selects a file from the scaffold search path.

    Upstream image tag resolution happens later, in :func:`run_scaffold_setup`
    (via :func:`agentcage.registry.resolve_build_args`), so the rendered
    config holds the scaffold's untagged reference verbatim and each cage
    tracks its own pinned tag via state.
    """
    env = _make_env()
    if scaffold is None:
        tmpl = env.get_template("init-config.yaml.j2")
        return tmpl.render(name=name, image=image, isolation=isolation, port=port)

    scaffold_dir = resolve_scaffold(scaffold)
    if scaffold_dir is None:
        raise click.ClickException(f"scaffold {scaffold!r} not found")

    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(scaffold_dir)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template("cage.yaml.j2")

    from agentcage.quadlets import cage_network_addrs

    addrs = cage_network_addrs(name)
    return tmpl.render(name=name, isolation=isolation, port=port, **addrs)


def load_scaffold_meta(scaffold: str) -> dict | None:
    """Load scaffold.yaml from a scaffold directory, if present."""
    scaffold_dir = resolve_scaffold(scaffold)
    if scaffold_dir is None:
        return None
    meta_file = scaffold_dir / "scaffold.yaml"
    if not meta_file.exists():
        return None
    with open(meta_file) as f:
        return yaml.safe_load(f) or {}


def run_scaffold_setup(
    scaffold: str, name: str, dest: str, *, quiet: bool = False,
) -> None:
    """Execute build/provision steps from scaffold.yaml."""
    meta = load_scaffold_meta(scaffold)
    if meta is None:
        return

    from agentcage.podman import Podman
    from agentcage.registry import resolve_build_args

    podman = Podman()
    scaffold_dir = resolve_scaffold(scaffold)
    if scaffold_dir is None:
        return

    def _echo(msg: str) -> None:
        if not quiet:
            click.echo(msg)

    # 1. Process build entries
    for entry in meta.get("build", []):
        image = entry["image"]
        if podman.image_exists(image):
            _echo(f"Image {image} already exists, skipping build.")
            continue

        # Resolve tags for scaffold-declared build args.
        declared = entry.get("build_args") or {}
        build_args, changes = resolve_build_args(declared, declared)
        for key, _old, new in changes:
            _echo(f"Build arg {key}: {new}")

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
