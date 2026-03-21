"""CLI commands for managing user scaffolds."""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

import click
import yaml

from agentcage.init import (
    _SCAFFOLDS_DIR,
    _USER_SCAFFOLDS_DIR,
    is_builtin_scaffold,
    list_scaffolds,
    load_scaffold_meta,
    resolve_scaffold,
    scaffold_source,
)


_STARTER_DIR = Path(__file__).parent / "templates" / "scaffold-starter"


@click.group()
def scaffold():
    """Create and manage custom scaffolds."""


@scaffold.command("create")
@click.argument("name")
@click.option("--from", "from_scaffold", default=None,
              help="Fork an existing scaffold as starting point.")
@click.option("--force", is_flag=True, help="Overwrite existing scaffold.")
def scaffold_create(name: str, from_scaffold: str | None, force: bool):
    """Create a new user scaffold.

    \b
    Examples:
      agentcage scaffold create my-agent
      agentcage scaffold create my-claude --from claude-code
    """
    if not re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', name):
        click.echo(
            "error: name must be 1-63 lowercase alphanumeric characters or "
            f"hyphens, starting with a letter or digit (got: {name!r})",
            err=True,
        )
        sys.exit(1)

    dest = _USER_SCAFFOLDS_DIR / name
    if dest.exists() and not force:
        click.echo(
            f"error: scaffold {name!r} already exists at {dest}\n"
            f"  Use --force to overwrite.",
            err=True,
        )
        sys.exit(1)

    if from_scaffold is not None:
        # Validate source exists
        src_dir = resolve_scaffold(from_scaffold)
        if src_dir is None:
            available = list_scaffolds()
            click.echo(
                f"error: scaffold {from_scaffold!r} not found "
                f"(available: {', '.join(available) or 'none'})",
                err=True,
            )
            sys.exit(1)
        # Copy source scaffold
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(str(src_dir), str(dest))
        click.echo(f"Created scaffold {name!r} from {from_scaffold!r}")
    else:
        # Generate from starter template
        dest.mkdir(parents=True, exist_ok=True)
        for src_file in _STARTER_DIR.iterdir():
            if src_file.is_file():
                content = src_file.read_text()
                content = content.replace("{{SCAFFOLD_NAME}}", name)
                (dest / src_file.name).write_text(content)
        click.echo(f"Created scaffold {name!r}")

    click.echo(f"  {dest}/")
    click.echo(f"\nEdit your scaffold, then use it:")
    click.echo(f"  agentcage run {name}")
    click.echo(f"  agentcage init my-cage --scaffold {name}")


@scaffold.command("list")
def scaffold_list():
    """List all available scaffolds."""
    names = list_scaffolds()
    if not names:
        click.echo("No scaffolds available.")
        return

    # Collect metadata for each scaffold
    rows: list[tuple[str, str, str, str]] = []
    for name in names:
        source = scaffold_source(name)
        meta = load_scaffold_meta(name) or {}
        lifecycle = meta.get("lifecycle", "")
        description = meta.get("description", "")
        rows.append((name, source, lifecycle, description))

    # Calculate column widths
    headers = ("NAME", "SOURCE", "LIFECYCLE", "DESCRIPTION")
    widths = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]

    # Print table
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    click.echo(header_line)
    for row in rows:
        line = "  ".join(val.ljust(w) for val, w in zip(row, widths))
        click.echo(line)


@scaffold.command("show")
@click.argument("name")
def scaffold_show(name: str):
    """Show details of a scaffold."""
    scaffold_dir = resolve_scaffold(name)
    if scaffold_dir is None:
        click.echo(f"error: scaffold {name!r} not found", err=True)
        sys.exit(1)

    source = scaffold_source(name)
    meta = load_scaffold_meta(name) or {}

    click.echo(f"Scaffold: {name}")
    click.echo(f"Source:   {source}")
    click.echo(f"Path:     {scaffold_dir}")
    if meta.get("description"):
        click.echo(f"Description: {meta['description']}")
    if meta.get("lifecycle"):
        click.echo(f"Lifecycle: {meta['lifecycle']}")

    # Show build entries
    builds = meta.get("build", [])
    if builds:
        click.echo(f"\nBuild steps:")
        for entry in builds:
            if "containerfile" in entry:
                click.echo(f"  - build {entry['image']} from {entry['containerfile']}")
            elif "git" in entry:
                click.echo(f"  - clone {entry['git']} → build {entry['image']}")

    # Show domains from cage.yaml.j2
    template_file = scaffold_dir / "cage.yaml.j2"
    if template_file.exists():
        try:
            # Quick parse — render with dummy values to extract domains
            content = template_file.read_text()
            # Look for domains.allow section
            if "domains:" in content:
                click.echo(f"\nTemplate: {template_file.name}")
        except Exception:
            pass


@scaffold.command("edit")
@click.argument("name")
def scaffold_edit(name: str):
    """Open a user scaffold in $EDITOR."""
    scaffold_dir = resolve_scaffold(name)
    if scaffold_dir is None:
        click.echo(f"error: scaffold {name!r} not found", err=True)
        sys.exit(1)

    source = scaffold_source(name)
    if source == "built-in":
        click.echo(
            f"error: {name!r} is a built-in scaffold and cannot be edited directly.\n"
            f"  Fork it first: agentcage scaffold create my-{name} --from {name}",
            err=True,
        )
        sys.exit(1)

    editor = os.environ.get("EDITOR", os.environ.get("VISUAL", ""))
    if editor:
        os.execvp(editor, [editor, str(scaffold_dir)])
    else:
        click.echo(f"Scaffold directory: {scaffold_dir}")
        click.echo("  Set $EDITOR to open it automatically.")


@scaffold.command("delete")
@click.argument("name")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation.")
def scaffold_delete(name: str, yes: bool):
    """Delete a user scaffold."""
    if is_builtin_scaffold(name) and not (_USER_SCAFFOLDS_DIR / name / "cage.yaml.j2").exists():
        click.echo(f"error: {name!r} is a built-in scaffold and cannot be deleted.", err=True)
        sys.exit(1)

    target = _USER_SCAFFOLDS_DIR / name
    if not target.exists():
        click.echo(f"error: no user scaffold {name!r} at {target}", err=True)
        sys.exit(1)

    if not yes:
        click.confirm(f"Delete scaffold {name!r} at {target}?", abort=True)

    shutil.rmtree(target)
    click.echo(f"Deleted scaffold {name!r}")


@scaffold.command("export")
@click.argument("name")
@click.argument("dest", type=click.Path())
def scaffold_export(name: str, dest: str):
    """Export a scaffold to a directory."""
    scaffold_dir = resolve_scaffold(name)
    if scaffold_dir is None:
        click.echo(f"error: scaffold {name!r} not found", err=True)
        sys.exit(1)

    dest_path = Path(dest) / name
    if dest_path.exists():
        click.echo(f"error: {dest_path} already exists", err=True)
        sys.exit(1)

    Path(dest).mkdir(parents=True, exist_ok=True)
    shutil.copytree(str(scaffold_dir), str(dest_path))
    click.echo(f"Exported {name!r} to {dest_path}")
