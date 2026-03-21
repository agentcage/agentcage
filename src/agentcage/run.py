"""Lifecycle orchestration for interactive and ephemeral cages.

The ``execute()`` function creates a cage from a scaffold, opens an
interactive session, and cleans up on exit.  Signal handling ensures
the cage is stopped even if the user hits Ctrl+C.

Architecture:
  agentcage run <scaffold> [--project DIR] [--name NAME]
       │
       ├─ resolve scaffold → render config
       ├─ auto-generate name if needed
       ├─ build image + deploy cage
       ├─ subprocess.run(podman exec -it ...)  ← returns on exit
       └─ finally: stop cage (state dir preserved)
"""

from __future__ import annotations

import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import click

from agentcage import state
from agentcage.backends import get_backend
from agentcage.config import load_config, validate_config
from agentcage.init import list_scaffolds, load_scaffold_meta, render_config, run_scaffold_setup
from agentcage.podman import Podman
from agentcage.services import build_and_deploy, check_port_availability, destroy_cage

# Word lists for auto-generated cage names (Docker-style)
_ADJECTIVES = [
    "bold", "brave", "bright", "calm", "cool", "dark", "deep", "dry",
    "fair", "fast", "firm", "free", "glad", "gold", "good", "gray",
    "keen", "kind", "late", "lean", "long", "mild", "neat", "new",
    "odd", "old", "pale", "pure", "rare", "raw", "red", "rich",
    "safe", "shy", "slim", "soft", "tall", "thin", "warm", "wide",
    "wild", "wise", "blue", "grim", "hale", "lush", "prim", "tame",
    "true", "vast",
]

# Short aliases for scaffold names
_SCAFFOLD_ALIASES: dict[str, str] = {
    "claude": "claude-code",
}

_NOUNS = [
    "ant", "bay", "bee", "cod", "cow", "dew", "doe", "elm",
    "elk", "emu", "ewe", "fig", "fox", "gem", "gnu", "hog",
    "ivy", "jay", "kit", "lad", "log", "mew", "nit", "oak",
    "orb", "owl", "pea", "ram", "ray", "roe", "rue", "rye",
    "sap", "sky", "sow", "sun", "tar", "tern", "tic", "vow",
    "wax", "web", "yak", "yam", "yew", "zap", "ash", "birch",
    "fern", "hawk",
]


def generate_name(scaffold: str) -> str:
    """Generate a unique cage name like ``claude-code-bold-fox``."""
    existing = set(state.list_deployments())
    for _ in range(100):
        adj = random.choice(_ADJECTIVES)
        noun = random.choice(_NOUNS)
        name = f"{scaffold}-{adj}-{noun}"
        if name not in existing:
            return name
    raise RuntimeError("Could not generate a unique cage name after 100 attempts")


def execute(
    scaffold: str,
    *,
    project_dir: str | None = None,
    name: str | None = None,
    secrets: tuple[str, ...] = (),
    extra_args: tuple[str, ...] = (),
) -> int:
    """Create a cage from a scaffold, run an interactive session, and clean up.

    Returns the exit code from the interactive session.
    """
    # Resolve scaffold aliases
    scaffold = _SCAFFOLD_ALIASES.get(scaffold, scaffold)

    # Validate scaffold exists
    available = list_scaffolds()
    if scaffold not in available:
        click.echo(
            f"error: unknown scaffold '{scaffold}'. "
            f"Available: {', '.join(available)}",
            err=True,
        )
        return 1

    # Resolve project directory
    if project_dir is None:
        project_dir = os.getcwd()
    project_dir = os.path.abspath(project_dir)

    # Warn if mounting home directory
    home = os.path.expanduser("~")
    if os.path.realpath(project_dir) == os.path.realpath(home):
        click.echo(
            f"warning: mounting home directory ({project_dir}) as project workspace. "
            f"Sensitive files (e.g. .ssh, .aws) will be accessible to the agent.",
            err=True,
        )

    # Generate or validate cage name
    cage_name = name or generate_name(scaffold)

    if state.deployment_exists(cage_name):
        click.echo(
            f"error: cage '{cage_name}' already exists. "
            f"Use --name to specify a different name, or destroy it first.",
            err=True,
        )
        return 1

    # Render config from scaffold template
    click.echo(f"Creating cage '{cage_name}'...")
    os.environ["PROJECT_DIR"] = project_dir
    config_text, image_tag = render_config(
        cage_name, scaffold=scaffold, isolation="container",
    )

    # Write temp config file
    config_dir = Path(tempfile.mkdtemp(prefix="agentcage-run-"))
    config_path = config_dir / "cage.yaml"
    config_path.write_text(config_text)

    cfg = load_config(str(config_path))
    warnings = validate_config(cfg)
    for w in warnings:
        click.echo(f"warning: {w}", err=True)

    # Check port availability
    unavailable = check_port_availability(cfg)
    if unavailable:
        for spec, _bind, port in unavailable:
            click.echo(f"error: port {port} is already in use ({spec})", err=True)
        return 1

    # Save deployment state
    state.save_deployment(cage_name, str(config_path))
    meta = state.load_metadata(cage_name)
    meta["scaffold"] = scaffold
    meta["lifecycle"] = cfg.lifecycle
    state.save_metadata(cage_name, meta)

    # Copy scaffold Containerfile to state dir if build is configured
    if cfg.container.build.containerfile:
        from agentcage.init import _SCAFFOLDS_DIR
        scaffold_dir = _SCAFFOLDS_DIR / scaffold
        containerfile_src = scaffold_dir / cfg.container.build.containerfile
        if containerfile_src.exists():
            dest_cf = Path(state.stored_config_path(cage_name)).parent / "Containerfile"
            shutil.copy2(str(containerfile_src), str(dest_cf))

    # Run scaffold setup (build images) and deploy
    try:
        run_scaffold_setup(scaffold, cage_name, str(config_path), image_tag=image_tag)

        podman = Podman()

        # Set secrets passed via --set-secret
        provided_keys: set[str] = set()
        for spec in secrets:
            if "=" in spec:
                key, val = spec.split("=", 1)
            else:
                key = spec
                val = click.prompt(f"Value for {key}", hide_input=True)
            full = f"{cage_name}.{key}"
            if podman.secret_exists(full):
                podman.secret_remove(full)
            podman.secret_create(full, val)
            provided_keys.add(key)
            click.echo(f"Secret '{key}' set.")

        # Strip secret injection rules for secrets not provided —
        # keeps only rules whose secrets were passed via --set-secret.
        cfg.secret_injection = [
            r for r in cfg.secret_injection if r.env in provided_keys
        ]
        cfg.container.podman_secrets = [
            s for s in cfg.container.podman_secrets if s in provided_keys
        ]

        from agentcage.quadlets import collect_used_octets
        used_octets = collect_used_octets(exclude=cage_name)

        # Save proxy config and get its host path (mounted into proxy container)
        config_host_path = state.save_proxy_config(cage_name)

        build_and_deploy(
            cfg,
            config_host_path=config_host_path,
            deploy_name=cage_name,
            podman=podman,
            used_octets=used_octets,
        )
    except Exception as e:
        click.echo(f"error: failed to build/deploy cage: {e}", err=True)
        # Clean up partial state
        if state.deployment_exists(cage_name):
            state.remove_deployment(cage_name)
        shutil.rmtree(str(config_dir), ignore_errors=True)
        return 1

    click.echo(f"Cage '{cage_name}' started.")

    if cfg.help:
        click.echo("")
        click.echo(cfg.help.rstrip())
        click.echo("")

    # Determine the exec command
    meta_loaded = load_scaffold_meta(scaffold) or {}
    # Use exec alias if defined, otherwise shell
    exec_cmd: list[str] = []
    if extra_args:
        exec_cmd = list(extra_args)
    elif cfg.exec_aliases:
        # Use the first defined alias
        first_alias = next(iter(cfg.exec_aliases.values()))
        exec_cmd = list(first_alias)
    else:
        exec_cmd = ["/bin/bash"]

    # Run interactive session
    exit_code = 0
    container_name = f"{cfg.name}-cage"
    exec_flags = ["-it"] if sys.stdin.isatty() else []

    try:
        click.echo(f"Starting interactive session... (Ctrl+D to exit)")
        result = subprocess.run(
            ["podman", "exec"] + exec_flags + [container_name] + exec_cmd,
        )
        exit_code = result.returncode
    except KeyboardInterrupt:
        click.echo("\nSession interrupted.")
        exit_code = 130
    finally:
        click.echo(f"Stopping cage '{cage_name}'...")
        try:
            backend = get_backend(cfg)
            backend.stop(cfg.name)
        except Exception as e:
            click.echo(f"warning: failed to stop cage: {e}", err=True)
        click.echo(
            f"Cage '{cage_name}' stopped. "
            f"Audit: agentcage cage audit {cage_name}"
        )

    # Clean up temp config dir
    shutil.rmtree(str(config_dir), ignore_errors=True)

    return exit_code
