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


def _add_template_globals(env: SandboxedEnvironment) -> SandboxedEnvironment:
    """Install helpers available to config templates.

    ``placeholder("ENV")`` renders an entropic secret-injection placeholder
    token at template-render time, so the generated cage.yaml carries a
    concrete, unguessable value (and the stored config never needs a
    comment-stripping rewrite to fill it in).
    """
    from agentcage.config import generate_placeholder
    env.globals["placeholder"] = generate_placeholder
    return env


def _make_env() -> SandboxedEnvironment:
    return _add_template_globals(SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    ))


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

    scaffold_file = scaffold_dir / "cage.yaml.j2"
    if scaffold_file.exists():
        env = _add_template_globals(SandboxedEnvironment(
            loader=FileSystemLoader(str(scaffold_dir)),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        ))
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


def scaffold_aliases() -> dict[str, str]:
    """Return ``alias → scaffold-name`` for every scaffold declaring ``aliases``.

    Read from each scaffold's ``scaffold.yaml`` so the alias list is
    extensible — agentcage core has no hardcoded knowledge of which
    scaffolds exist or how they prefer to be invoked.
    """
    out: dict[str, str] = {}
    for name in list_scaffolds():
        meta = load_scaffold_meta(name) or {}
        for alias in meta.get("aliases") or []:
            out[str(alias)] = name
    return out


def scaffold_name_prefix(scaffold: str) -> str:
    """Return the cage-name prefix declared in a scaffold's ``scaffold.yaml``.

    Falls back to the scaffold's own name when no prefix is declared.
    """
    meta = load_scaffold_meta(scaffold) or {}
    return str(meta.get("name_prefix") or scaffold)


def run_scaffold_setup(
    scaffold: str, name: str, dest: str, *, quiet: bool = False,
    isolation: str | None = None,
) -> None:
    """Execute build/provision steps from scaffold.yaml.

    The host-podman build path is only meaningful for the ``container``
    isolation backend. For ``vm`` and ``apple-container``, images are built
    by the backend itself (inside the Lima VM or via Apple's ``container``
    CLI) at cage create time, so we skip the host build loop entirely.
    When *isolation* is ``None`` we preserve the legacy behavior (run the
    build loop) for existing callers that don't pass isolation.
    """
    meta = load_scaffold_meta(scaffold)
    if meta is None:
        return

    scaffold_dir = resolve_scaffold(scaffold)
    if scaffold_dir is None:
        return

    def _echo(msg: str) -> None:
        if not quiet:
            click.echo(msg)

    # 1. Process build entries — host podman only relevant for container isolation
    if isolation in (None, "container"):
        from agentcage.podman import Podman
        from agentcage.registry import resolve_build_args

        podman = Podman()
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
    elif meta.get("build"):
        _echo(
            f"Skipping host image build for {isolation} isolation; "
            f"images will be built by the backend at cage create."
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
