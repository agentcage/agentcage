"""Scaffold a new agentcage configuration file."""

from __future__ import annotations

import os
import re
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
_USER_SCAFFOLDS_DIR = Path(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
) / "agentcage" / "scaffolds"

# Scaffold name → base image (without tag) for version pinning.
# picoclaw uses a local build (see scaffold comments) until a release
# with HTTP proxy support ships upstream.
_SCAFFOLD_IMAGES: dict[str, str] = {
    "openclaw": "ghcr.io/openclaw/openclaw",
}


def _project_scaffolds_dir() -> Path | None:
    """Return the project-local scaffolds dir, or None if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip()) / ".agentcage" / "scaffolds"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


_SCAFFOLD_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')


def _valid_scaffold_name(name: str) -> bool:
    """Return True if name is a valid scaffold name (no path traversal)."""
    return bool(_SCAFFOLD_NAME_RE.match(name))


def resolve_scaffold(name: str) -> Path | None:
    """Resolve a scaffold name to its directory path.

    Search order:
      1. Project-local: <git-root>/.agentcage/scaffolds/<name>/
      2. User: ~/.config/agentcage/scaffolds/<name>/
      3. Built-in: package scaffolds/<name>/
      4. Legacy: package templates/presets/<name>.yaml.j2

    Returns the scaffold directory Path, or None if not found.
    """
    if not _valid_scaffold_name(name):
        return None

    # 1. Project-local
    project_dir = _project_scaffolds_dir()
    if project_dir is not None:
        candidate = project_dir / name
        if (candidate / "cage.yaml.j2").exists():
            return candidate

    # 2. User scaffolds
    candidate = _USER_SCAFFOLDS_DIR / name
    if (candidate / "cage.yaml.j2").exists():
        return candidate

    # 3. Built-in scaffolds
    candidate = _SCAFFOLDS_DIR / name
    if (candidate / "cage.yaml.j2").exists():
        return candidate

    # 4. Legacy presets (templates/presets/*.yaml.j2)
    preset = _TEMPLATES_DIR / "presets" / f"{name}.yaml.j2"
    if preset.exists():
        return preset.parent  # return the presets dir (special case)

    return None


def is_builtin_scaffold(name: str) -> bool:
    """Return True if the scaffold is a built-in (shipped with the package)."""
    candidate = _SCAFFOLDS_DIR / name
    return (candidate / "cage.yaml.j2").exists()


def scaffold_source(name: str) -> str:
    """Return the source label for a scaffold: 'local', 'user', or 'built-in'."""
    project_dir = _project_scaffolds_dir()
    if project_dir is not None and (project_dir / name / "cage.yaml.j2").exists():
        return "local"
    if (_USER_SCAFFOLDS_DIR / name / "cage.yaml.j2").exists():
        return "user"
    return "built-in"


def _make_env() -> SandboxedEnvironment:
    return SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _scaffold_search_dirs() -> list[Path]:
    """Return all scaffold directories in resolution order."""
    dirs: list[Path] = []
    project_dir = _project_scaffolds_dir()
    if project_dir is not None and project_dir.is_dir():
        dirs.append(project_dir)
    if _USER_SCAFFOLDS_DIR.is_dir():
        dirs.append(_USER_SCAFFOLDS_DIR)
    if _SCAFFOLDS_DIR.is_dir():
        dirs.append(_SCAFFOLDS_DIR)
    return dirs


def list_scaffolds() -> list[str]:
    """Return sorted names of available scaffold templates."""
    preset_dir = _TEMPLATES_DIR / "presets"
    names: set[str] = set()
    if preset_dir.is_dir():
        names.update(p.stem.removesuffix(".yaml") for p in preset_dir.glob("*.yaml.j2"))
    for search_dir in _scaffold_search_dirs():
        names.update(d.name for d in search_dir.iterdir()
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
    Otherwise *scaffold* selects a file from the scaffold search path.
    """
    env = _make_env()
    if scaffold is None:
        tmpl = env.get_template("init-config.yaml.j2")
        return tmpl.render(name=name, image=image, isolation=isolation, port=port), None

    scaffold_dir = resolve_scaffold(scaffold)
    if scaffold_dir is None:
        raise click.ClickException(f"scaffold {scaffold!r} not found")

    scaffold_file = scaffold_dir / "cage.yaml.j2"
    if scaffold_file.exists():
        env = SandboxedEnvironment(
            loader=FileSystemLoader(str(scaffold_dir)),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        tmpl = env.get_template("cage.yaml.j2")
    else:
        tmpl = env.get_template(f"presets/{scaffold}.yaml.j2")

    # Warn if user/local scaffold shadows a built-in
    source = scaffold_source(scaffold)
    if source != "built-in" and is_builtin_scaffold(scaffold):
        click.echo(
            f"note: using {source} scaffold {scaffold!r} "
            f"(shadows built-in)",
            err=True,
        )

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
    scaffold_dir = resolve_scaffold(scaffold)
    if scaffold_dir is None:
        return None
    meta_file = scaffold_dir / "scaffold.yaml"
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
