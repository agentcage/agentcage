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

# Short prefixes for auto-generated cage names
_NAME_PREFIXES: dict[str, str] = {
    "claude-code": "claude",
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
    """Generate a unique cage name like ``claude-bold-fox``."""
    prefix = _NAME_PREFIXES.get(scaffold, scaffold)
    existing = set(state.list_deployments())
    for _ in range(100):
        adj = random.choice(_ADJECTIVES)
        noun = random.choice(_NOUNS)
        name = f"{prefix}-{adj}-{noun}"
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
    verbose: bool = False,
) -> int:
    """Create a cage from a scaffold, run an interactive session, and clean up.

    Returns the exit code from the interactive session.
    """
    from agentcage import output

    # Resolve scaffold aliases
    scaffold = _SCAFFOLD_ALIASES.get(scaffold, scaffold)

    # Validate scaffold exists
    available = list_scaffolds()
    if scaffold not in available:
        output.step_fail(
            f"Unknown scaffold '{scaffold}'. "
            f"Available: {', '.join(available)}"
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
        output.step_fail(
            f"Cage '{cage_name}' already exists. "
            f"Use --name to specify a different name, or destroy it first."
        )
        return 1

    # Print header
    output.header(scaffold)

    # Render config from scaffold template
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
            output.step_fail(f"Port {port} is already in use ({spec})")
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
        if verbose:
            run_scaffold_setup(
                scaffold, cage_name, str(config_path),
                image_tag=image_tag,
            )
        else:
            with output.Spinner("Building image..."):
                run_scaffold_setup(
                    scaffold, cage_name, str(config_path),
                    image_tag=image_tag, quiet=True,
                )
        output.step_done("Image ready")

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

        if verbose:
            build_and_deploy(
                cfg,
                config_host_path=config_host_path,
                deploy_name=cage_name,
                podman=podman,
                used_octets=used_octets,
            )
        else:
            with output.Spinner("Building proxy..."):
                build_and_deploy(
                    cfg,
                    config_host_path=config_host_path,
                    deploy_name=cage_name,
                    podman=podman,
                    used_octets=used_octets,
                    quiet=True,
                )
        output.step_done("Proxy built")
        output.step_done("DNS ready")
        output.step_done(f"Cage {click.style(cage_name, bold=True)} started")
    except subprocess.CalledProcessError as e:
        output.step_fail("Build failed")
        # Dump captured build output for debugging
        if e.stderr:
            click.echo(e.stderr, err=True)
        if e.stdout:
            click.echo(e.stdout, err=True)
        if state.deployment_exists(cage_name):
            state.remove_deployment(cage_name)
        shutil.rmtree(str(config_dir), ignore_errors=True)
        return 1
    except Exception as e:
        output.step_fail(f"Failed to build/deploy cage: {e}")
        # Clean up partial state
        if state.deployment_exists(cage_name):
            state.remove_deployment(cage_name)
        shutil.rmtree(str(config_dir), ignore_errors=True)
        return 1

    # Summary info
    click.echo()
    output.info("Project", project_dir)

    # Detect mounted auth
    claude_dir = Path.home() / ".claude"
    if claude_dir.is_dir():
        output.info("Auth", "~/.claude (mounted)")
    else:
        output.info("Auth", output.dim("not configured"))

    click.echo()
    output.info("Ctrl+D", "to exit")
    output.info("Audit", f"agentcage cage audit {cage_name}")
    click.echo()
    output.separator()

    # Determine the exec command: agent binary + any extra args
    if cfg.exec_aliases:
        first_alias = next(iter(cfg.exec_aliases.values()))
        exec_cmd = list(first_alias) + list(extra_args)
    elif extra_args:
        exec_cmd = list(extra_args)
    else:
        exec_cmd = ["/bin/bash"]

    # Run interactive session
    exit_code = 0
    container_name = f"{cfg.name}-cage"
    exec_flags = ["-it"] if sys.stdin.isatty() else []

    try:
        result = subprocess.run(
            ["podman", "exec"] + exec_flags + [container_name] + exec_cmd,
        )
        exit_code = result.returncode
    except KeyboardInterrupt:
        click.echo("\nSession interrupted.")
        exit_code = 130
    finally:
        click.echo()
        output.separator()
        with output.Spinner("Stopping cage..."):
            try:
                backend = get_backend(cfg)
                backend.stop(cfg.name)
            except Exception as e:
                click.echo(f"warning: failed to stop cage: {e}", err=True)
        output.step_done(f"Cage {click.style(cage_name, bold=True)} stopped")
        output.info("Audit", f"agentcage cage audit {cage_name}")

    # Clean up temp config dir
    shutil.rmtree(str(config_dir), ignore_errors=True)

    return exit_code
