"""agentcage CLI — cage and secret command groups."""

from __future__ import annotations

import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import tarfile
import tempfile
from pathlib import Path

import click

from importlib.metadata import version

from agentcage.audit import (
    AuditEntry,
    AuditFilter,
    compute_summary,
    extract_audit_json,
    format_summary,
    format_table_header,
    format_table_row,
)
from agentcage.config import load_config, validate_config, _LEVEL_ORDER
from agentcage.podman import Podman
from agentcage.backends import get_backend
from agentcage import state, systemd
from agentcage.lima.instance import LimaInstance
from agentcage.services import (
    expected_secrets as _expected_secrets,
    check_secrets as _check_secrets,
    suggest_alt_port as _suggest_alt_port,
    check_port_availability as _check_port_availability,
    ensure_patches as _ensure_patches,
    build_container_image as _build_container_image_svc,
    build_and_deploy as _build_and_deploy,
    destroy_cage as _destroy_cage,
)


def _podman_for_cage(name: str) -> Podman:
    """Return the right Podman interface for a cage.

    For VM-mode cages with a running Lima instance, returns a VmPodman
    that routes operations through the VM. Otherwise returns a host Podman.
    """
    if state.deployment_exists(name):
        cfg = state.load_deployment_config(name)
        if cfg.isolation == "vm":
            from agentcage.lima.podman import VmPodman
            inst = LimaInstance(name)
            if inst.is_running():
                return VmPodman(name)  # type: ignore[return-value]
    return Podman()


def _build_container_image(cfg, config_dir: Path, podman: Podman) -> None:
    """CLI wrapper that passes click.echo to the service layer."""
    _build_container_image_svc(cfg, config_dir, podman, echo=click.echo)


def _restart_cage(name: str, cfg=None):
    """Restart all services for a cage using the appropriate backend.

    Delegates to :func:`agentcage.services.restart_cage`.
    """
    from agentcage.services import restart_cage
    restart_cage(name, cfg)


class AliasGroup(click.Group):
    """Click group with command aliases."""

    def __init__(self, *args, aliases=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._aliases = aliases or {}

    def get_command(self, ctx, cmd_name):
        return super().get_command(ctx, self._aliases.get(cmd_name, cmd_name))

    def format_help(self, ctx, formatter):
        super().format_help(ctx, formatter)
        if self._aliases:
            formatter.write_paragraph()
            formatter.write_text("Aliases:")
            with formatter.indentation():
                for alias, target in sorted(self._aliases.items()):
                    formatter.write_text(f"{alias} → {target}")


class _BannerGroup(click.Group):
    """Show the agentcage banner before help text."""

    def get_help(self, ctx: click.Context) -> str:
        from agentcage.output import banner_text
        return banner_text(version("agentcage")) + "\n" + super().get_help(ctx)


@click.group(cls=_BannerGroup)
@click.version_option(version=version("agentcage"), prog_name="agentcage")
def main():
    """Defense-in-depth proxy sandbox for AI agents."""


# ── completions ──────────────────────────────────────────


@main.command("completions")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completions(shell: str):
    """Print shell completion script."""
    click.echo(f'eval "$(_AGENTCAGE_COMPLETE={shell}_source agentcage)"')


# ── init ─────────────────────────────────────────────────


@main.command()
@click.argument("name", required=False, default=None)
@click.option("-o", "--output", default="cage.yaml",
              help="Output file path.", show_default=True)
@click.option("--image", default="node:22-slim",
              help="Container image.", show_default=True)
@click.option("--isolation", type=click.Choice(["container", "vm"]),
              default="container", help="Isolation backend.", show_default=True)
@click.option("--force", is_flag=True, help="Overwrite existing file.")
@click.option("--scaffold", default=None,
              help="Use a scaffold template (e.g. openclaw).")
@click.option("--list-scaffolds", is_flag=True,
              help="List available scaffolds and exit.")
@click.option("--port", type=int, default=None,
              help="Host port to publish (scaffold-specific).")
def init(name: str | None, output: str, image: str, isolation: str,
         force: bool, scaffold: str | None, list_scaffolds: bool,
         port: int | None):
    """Scaffold a new agentcage config file."""
    from agentcage.init import list_scaffolds as _list_scaffolds, render_config

    if list_scaffolds:
        scaffolds = _list_scaffolds()
        if not scaffolds:
            click.echo("No scaffolds available.")
        else:
            click.echo("Available scaffolds:")
            for p in scaffolds:
                click.echo(f"  {p}")
        return

    if name is None:
        click.echo("error: missing argument 'NAME'", err=True)
        sys.exit(1)

    if not re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', name):
        click.echo(
            "error: name must be 1-63 lowercase alphanumeric characters or "
            f"hyphens, starting with a letter or digit (got: {name!r})",
            err=True,
        )
        sys.exit(1)

    if scaffold is not None and scaffold not in _list_scaffolds():
        click.echo(
            f"error: unknown scaffold {scaffold!r} "
            f"(available: {', '.join(_list_scaffolds()) or 'none'})",
            err=True,
        )
        sys.exit(1)

    dest = Path(output)
    if dest.exists() and not force:
        click.echo(f"error: {dest} already exists (use --force to overwrite)", err=True)
        sys.exit(1)

    content, image_tag = render_config(name, image=image, isolation=isolation, scaffold=scaffold, port=port)
    dest.write_text(content)
    click.echo(f"Created {dest}")

    from agentcage.init import load_scaffold_meta, run_scaffold_setup, _SCAFFOLDS_DIR

    meta = load_scaffold_meta(scaffold) if scaffold else None
    if scaffold and meta:
        run_scaffold_setup(scaffold, name, str(dest), image_tag=image_tag)
        # Copy Containerfiles referenced in scaffold build entries
        scaffold_dir_path = _SCAFFOLDS_DIR / scaffold
        for entry in meta.get("build", []):
            if "containerfile" in entry:
                src = scaffold_dir_path / entry["containerfile"]
                dst = dest.parent / entry["containerfile"]
                if src.is_file() and not dst.exists():
                    shutil.copy2(str(src), str(dst))
    scaffold_dir = _SCAFFOLDS_DIR / scaffold if scaffold else None
    if meta and meta.get("next_steps"):
        click.echo("\nNext steps:")
        for i, step in enumerate(meta["next_steps"], 1):
            click.echo(f"  {i}. {step.format(name=name, dest=dest, scaffold_dir=scaffold_dir)}")
    elif scaffold is None:
        click.echo(f"\nNext steps:")
        click.echo(f"  1. Edit {dest} — set your image, domains, and secrets")
        click.echo(f"  2. agentcage cage create -c {dest}")




# ── run ──────────────────────────────────────────────────


@main.command(context_settings={"ignore_unknown_options": True})
@click.argument("scaffold")
@click.option("--project", "project_dir", default=None, type=click.Path(exists=True),
              help="Project directory to mount (default: current directory).")
@click.option("--name", default=None,
              help="Cage name (default: auto-generated).")
@click.option("-s", "--set-secret", "secrets", multiple=True,
              help="Set a secret (KEY=VALUE or KEY to prompt). Repeatable.")
@click.option("-v", "--verbose", is_flag=True, help="Show full build output.")
@click.option("--isolation", type=click.Choice(["container", "vm"]), default=None,
              help="Isolation backend (default: auto-detect from platform).")
@click.option("--mcp", "mcp_servers", multiple=True,
              help="Add an MCP server by name (e.g. github, filesystem). Repeatable.")
@click.argument("extra_args", nargs=-1, type=click.UNPROCESSED)
def run(scaffold: str, project_dir: str | None, name: str | None,
        secrets: tuple[str, ...], verbose: bool, isolation: str | None,
        mcp_servers: tuple[str, ...], extra_args: tuple[str, ...]):
    """Run a coding agent in a sandboxed cage.

    \b
    Examples:
      agentcage run claude-code
      agentcage run codex --project /path/to/repo
      agentcage run claude-code -s ANTHROPIC_API_KEY=sk-...
      agentcage run claude-code --isolation vm
      agentcage run claude-code --mcp github --mcp filesystem
      agentcage run claude-code --name my-session -- claude --help
    """
    from agentcage.run import execute
    exit_code = execute(
        scaffold, project_dir=project_dir, name=name,
        secrets=secrets, extra_args=extra_args, verbose=verbose,
        isolation=isolation, mcp_servers=mcp_servers,
    )
    sys.exit(exit_code)


# ── cage group ────────────────────────────────────────────


@main.group(cls=AliasGroup, aliases={"ls": "list", "rm": "destroy", "ps": "list", "status": "list", "reload": "restart", "delete": "destroy", "describe": "show", "inspect": "show"})
def cage():
    """Manage cages."""


@cage.command("create")
@click.option("-c", "--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("-s", "--set-secret", "secrets", multiple=True,
              help="Set a secret (KEY=VALUE or KEY to prompt). Repeatable.")
def cage_create(config_path: str, secrets: tuple):
    """Build images, generate quadlets, install, and start a new cage."""
    from agentcage import output as _out
    _out.banner(version("agentcage"))

    cfg = load_config(config_path)
    try:
        warnings = validate_config(cfg)
    except ValueError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    for w in warnings:
        click.echo(f"warning: {w}", err=True)

    name = cfg.name

    if state.deployment_exists(name):
        click.echo(f"error: cage '{name}' already exists", err=True)
        click.echo(f"  Use 'agentcage cage update {name}' to update it.", err=True)
        sys.exit(1)

    podman = Podman()

    # Check secrets — skip keys provided via --set-secret
    secret_keys_being_set = {s.split("=", 1)[0] for s in secrets} if secrets else set()
    if cfg.isolation == "container" or shutil.which("podman"):
        missing = [k for k in _check_secrets(podman, name, cfg) if k not in secret_keys_being_set]
    else:
        missing = []
    if missing:
        click.echo(f"error: missing secrets for cage '{name}':", err=True)
        for key in missing:
            click.echo(f"  {key}", err=True)
        click.echo("Create them with --set-secret or after creation:", err=True)
        click.echo(f"  agentcage cage create -c {config_path}" +
                   "".join(f" -s {k}=VALUE" for k in missing), err=True)
        sys.exit(1)

    # Check port availability
    conflicts = _check_port_availability(cfg)
    if conflicts:
        for port_spec, host_bind, host_port in conflicts:
            click.echo(
                f"error: port {host_port} on {host_bind} is already in use\n"
                f"  Another cage or service may be using this port.\n"
                f"  Change the host port in your cage config, e.g.:\n"
                f"    ports:\n"
                f'      - "{host_bind}:{_suggest_alt_port(int(host_port))}:{port_spec.split(":")[-1]}"',
                err=True,
            )
        sys.exit(1)

    # Save state
    state.save_deployment(name, config_path)
    state.save_metadata(name, {"agentcage_version": version("agentcage")})

    # Copy Containerfile into state dir so cage update can rebuild
    if cfg.container.build.containerfile:
        src_cf = Path(config_path).parent / cfg.container.build.containerfile
        if src_cf.is_file():
            dst_cf = state.deployment_dir(name) / Path(cfg.container.build.containerfile).name
            shutil.copy2(str(src_cf), str(dst_cf))

            # Append MCP server npm installs to the Containerfile
            if cfg.mcp_servers:
                from agentcage.mcp import mcp_npm_packages
                packages = mcp_npm_packages(cfg.mcp_servers)
                if packages:
                    pkg_str = " ".join(packages)
                    with open(str(dst_cf), "a") as f:
                        f.write(
                            f"\n# MCP servers (added by agentcage)\n"
                            f"USER root\n"
                            f"RUN npm install -g {pkg_str}\n"
                            f"USER node\n"
                        )

    # Merge MCP server domains into allowlist
    if cfg.mcp_servers and cfg.domains.mode == "allowlist":
        from agentcage.mcp import merge_mcp_domains
        cfg.domains.allow = merge_mcp_domains(cfg.domains.allow, cfg.mcp_servers)

    # Set secrets passed via --set-secret (before build so they're available)
    if secrets:
        # For VM mode, secrets are set after the VM starts (in _deploy_cage).
        # For container mode, set them now on the host.
        if cfg.isolation == "container":
            podman_secrets = Podman()
            for spec in secrets:
                if "=" in spec:
                    key, val = spec.split("=", 1)
                else:
                    key = spec
                    val = click.prompt(f"Value for {key}", hide_input=True)
                full = f"{name}.{key}"
                if podman_secrets.secret_exists(full):
                    podman_secrets.secret_remove(full)
                podman_secrets.secret_create(full, val)
                click.echo(f"Secret '{full}' set.")
        else:
            # VM mode: store secrets for bridging after VM starts.
            # We need host podman for this — prompt to install if missing.
            _pending_secrets = []
            for spec in secrets:
                if "=" in spec:
                    key, val = spec.split("=", 1)
                else:
                    key = spec
                    val = click.prompt(f"Value for {key}", hide_input=True)
                _pending_secrets.append((key, val))
            # Store in a temp file for _deploy_cage to pick up
            secrets_file = state.deployment_dir(name) / "pending_secrets.json"
            import json as _json
            # Create with restrictive permissions (0o600) to protect secrets at rest
            fd = os.open(str(secrets_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, _json.dumps(_pending_secrets).encode())
            finally:
                os.close(fd)

    config_host_path = state.save_proxy_config(name)

    # Build from Containerfile if configured (container mode only)
    if cfg.isolation == "container" and cfg.container.build.containerfile:
        _build_container_image(cfg, Path(config_path).parent, podman)

    # Pull image on host (container mode) — VM mode pulls inside the VM
    if cfg.isolation == "container":
        click.echo(f"Pulling {cfg.container.image}...")
        if not podman.pull(cfg.container.image):
            click.echo(
                f"warning: pull failed for {cfg.container.image} "
                f"(local image or no network — continuing with cached image)",
                err=True,
            )

    # Collect existing subnets to avoid collisions with other cages
    from agentcage.quadlets import collect_used_octets
    used_octets = collect_used_octets()

    try:
        _build_and_deploy(cfg, config_host_path, name, podman, used_octets=used_octets)
    except Exception:
        # Stop partially-started services but preserve state for debugging
        backend = get_backend(cfg)
        try:
            backend.stop(name)
        except Exception:
            pass
        click.echo()
        click.echo("Create failed. State preserved for debugging:", err=True)
        click.echo(f"  Inspect logs:    agentcage cage logs {name}", err=True)
        click.echo(f"  Inspect quadlets: ls {backend.unit_dir()}/{name}-*", err=True)
        click.echo(f"  Retry:           agentcage cage update {name}", err=True)
        click.echo(f"  Clean up:        agentcage cage destroy {name}", err=True)
        raise

    click.echo()
    click.echo("Logs:")
    click.echo(f"  agentcage cage logs {name}")

    if cfg.help:
        click.echo()
        click.echo(cfg.help.rstrip())


@cage.command("update")
@click.argument("name")
@click.option("-c", "--config", "config_path", type=click.Path(exists=True))
def cage_update(name: str, config_path: str | None):
    """Rebuild and restart an existing cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    if config_path:
        cfg = load_config(config_path)
        try:
            warnings = validate_config(cfg)
        except ValueError as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(1)
        for w in warnings:
            click.echo(f"warning: {w}", err=True)
        if cfg.name != name:
            click.echo(
                f"error: config name '{cfg.name}' does not match cage '{name}'",
                err=True,
            )
            sys.exit(1)
        state.save_deployment(name, config_path)
        # Copy Containerfile into state dir so future updates can rebuild
        if cfg.container.build.containerfile:
            src_cf = Path(config_path).parent / cfg.container.build.containerfile
            if src_cf.is_file():
                dst_cf = state.deployment_dir(name) / Path(cfg.container.build.containerfile).name
                shutil.copy2(str(src_cf), str(dst_cf))
    else:
        # Auto-resolve latest image tag for stored configs
        from agentcage.registry import resolve_latest_tag

        raw = state.load_raw_config(name)
        current_image = raw.get("container", {}).get("image", "")
        image_base, _, current_tag = current_image.rpartition(":")
        if image_base and current_tag:
            new_tag = resolve_latest_tag(image_base)
            if new_tag and new_tag != current_tag:
                raw["container"]["image"] = f"{image_base}:{new_tag}"
                state.save_raw_config(name, raw)
                click.echo(f"Image: {image_base}:{current_tag} \u2192 {new_tag}")
            elif new_tag is None:
                click.echo(
                    f"warning: could not resolve latest tag for {image_base}, "
                    f"keeping {current_tag}",
                    err=True,
                )

        # Auto-resolve latest tags for untagged build arg image refs
        build_raw = raw.get("container", {}).get("build", {})
        build_args = build_raw.get("args") or {}
        args_changed = False
        for key, val in list(build_args.items()):
            image_base, _, tag = val.rpartition(":")
            if image_base and tag:
                # Already has an explicit tag — leave it alone
                continue
            # Untagged image ref (contains "/" so looks like a registry path)
            if "/" in val:
                new_tag = resolve_latest_tag(val)
                if new_tag:
                    build_args[key] = f"{val}:{new_tag}"
                    args_changed = True
                    click.echo(f"Build arg {key}: {val} \u2192 {val}:{new_tag}")
        if args_changed:
            raw.setdefault("container", {}).setdefault("build", {})["args"] = build_args
            state.save_raw_config(name, raw)

        cfg = state.load_deployment_config(name)
        try:
            warnings = validate_config(cfg)
        except ValueError as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(1)
        for w in warnings:
            click.echo(f"warning: {w}", err=True)

    state.save_metadata(name, {"agentcage_version": version("agentcage")})
    config_host_path = state.save_proxy_config(name)

    podman = Podman()

    # Check secrets (requires host Podman — skip for VM mode if unavailable)
    missing = _check_secrets(podman, name, cfg) if cfg.isolation == "container" or shutil.which("podman") else []
    if missing:
        click.echo(f"error: missing secrets for cage '{name}':", err=True)
        for key in missing:
            click.echo(f"  {key}", err=True)
        click.echo("Create them with:", err=True)
        for key in missing:
            click.echo(f"  agentcage secret set {name} {key}", err=True)
        sys.exit(1)

    # Stop existing services before port check — the running cage's own
    # ports would otherwise be detected as conflicts.
    click.echo("Stopping services...")
    backend = get_backend(cfg)
    backend.stop(name)

    # Check port availability (after stop so the cage's own ports are free).
    # Retry briefly — container port release can lag behind service stop.
    conflicts = _check_port_availability(cfg)
    if conflicts:
        for attempt in range(5):
            time.sleep(1)
            conflicts = _check_port_availability(cfg)
            if not conflicts:
                break
    if conflicts:
        for port_spec, host_bind, host_port in conflicts:
            click.echo(
                f"error: port {host_port} on {host_bind} is already in use\n"
                f"  Another cage or service may be using this port.\n"
                f"  Change the host port in your cage config, e.g.:\n"
                f"    ports:\n"
                f'      - "{host_bind}:{_suggest_alt_port(int(host_port))}:{port_spec.split(":")[-1]}"',
                err=True,
            )
        sys.exit(1)

    # Build from Containerfile if configured (container mode only)
    if cfg.isolation == "container" and cfg.container.build.containerfile:
        config_dir = Path(config_path).parent if config_path else state.deployment_dir(name)
        _build_container_image(cfg, config_dir, podman)

    # Pull image on host (container mode) — VM mode pulls inside the VM
    if cfg.isolation == "container":
        click.echo(f"Pulling {cfg.container.image}...")
        if not podman.pull(cfg.container.image):
            click.echo(
                f"warning: pull failed for {cfg.container.image} "
                f"(local image or no network — continuing with cached image)",
                err=True,
            )

    from agentcage.quadlets import collect_used_octets as _collect_update
    _build_and_deploy(cfg, config_host_path, name, podman, used_octets=_collect_update(exclude=name))
    click.echo(f"Updated cage '{name}'")

    if cfg.help:
        click.echo()
        click.echo(cfg.help.rstrip())


@cage.command("list")
def cage_list():
    """List all cages with status."""
    names = state.list_deployments()
    if not names:
        click.echo("No cages found.")
        return

    click.echo(f"{'NAME':<25} {'LIFECYCLE':<14} {'ISOLATION':<12} {'SCAFFOLD':<15} STATUS")
    for name in names:
        try:
            cfg = state.load_deployment_config(name)
            backend = get_backend(cfg)
        except Exception:
            click.echo(f"{name:<25} {'?':<14} {'?':<12} {'-':<15} unknown (config error)")
            continue

        isolation = cfg.isolation
        meta = state.load_metadata(name)
        lifecycle = meta.get("lifecycle", cfg.lifecycle)
        scaffold_name = meta.get("scaffold", cfg.scaffold) or "-"
        services = backend.service_names(name)
        total = len(services)
        running = sum(
            1 for svc in services
            if backend.is_running(name, svc)
        )
        if running == total:
            status = f"running ({running}/{total})"
        elif running == 0:
            if lifecycle in ("interactive", "ephemeral"):
                status = "exited"
            else:
                status = f"stopped (0/{total})"
        else:
            status = f"degraded ({running}/{total})"
        click.echo(f"{name:<25} {lifecycle:<14} {isolation:<12} {scaffold_name:<15} {status}")


@cage.command("destroy")
@click.argument("name")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt")
@click.option("--keep-secrets", is_flag=True,
              help="Keep scoped secrets (useful for recreating the cage)")
def cage_destroy(name: str, yes: bool, keep_secrets: bool):
    """Stop containers, remove quadlets, state, and scoped secrets."""
    if not yes:
        detail = "This will stop containers, remove quadlets, and state."
        if not keep_secrets:
            detail += " Scoped secrets will also be removed."
        else:
            detail += " Scoped secrets will be kept."
        click.confirm(
            f'Destroy cage "{name}"? ' + detail,
            abort=True,
        )

    removed = _destroy_cage(name, keep_secrets=keep_secrets, echo=click.echo)

    click.echo()
    if removed:
        click.echo("Removed:")
        for item in removed:
            click.echo(f"  {item}")
    else:
        click.echo(f'Nothing to remove (cage "{name}" not found).')


@cage.command("prune")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt")
def cage_prune(yes: bool):
    """Remove all exited interactive and ephemeral cages."""
    names = state.list_deployments()
    candidates = []
    for name in names:
        try:
            cfg = state.load_deployment_config(name)
            backend = get_backend(cfg)
        except Exception:
            continue
        meta = state.load_metadata(name)
        lifecycle = meta.get("lifecycle", cfg.lifecycle)
        if lifecycle not in ("interactive", "ephemeral"):
            continue
        services = backend.service_names(name)
        running = sum(1 for svc in services if backend.is_running(name, svc))
        if running == 0:
            candidates.append(name)

    if not candidates:
        click.echo("Nothing to prune.")
        return

    click.echo(f"The following exited cages will be removed:")
    for name in candidates:
        click.echo(f"  {name}")

    if not yes:
        click.confirm(f"\nRemove {len(candidates)} cage(s)?", abort=True)

    for name in candidates:
        click.echo(f"Removing {name}...")
        try:
            _destroy_cage(name, keep_secrets=False)
        except Exception as e:
            click.echo(f"  warning: failed to remove {name}: {e}", err=True)
            continue
    click.echo(f"Pruned {len(candidates)} cage(s).")


@cage.command("verify")
@click.argument("name")
def cage_verify(name: str):
    """Check that a cage is healthy."""
    try:
        cfg = state.load_deployment_config(name)
        backend = get_backend(cfg)
    except Exception:
        click.echo(f"error: cage '{name}' does not exist or has invalid config", err=True)
        sys.exit(1)

    passed = 0
    failed = 0
    warned = 0

    def _pass(msg: str):
        nonlocal passed
        click.echo(f"  [PASS] {msg}")
        passed += 1

    def _fail(msg: str):
        nonlocal failed
        click.echo(f"  [FAIL] {msg}")
        failed += 1

    def _warn(msg: str):
        nonlocal warned
        click.echo(f"  [WARN] {msg}")
        warned += 1

    click.echo(f"=== agentcage verify: {name} ({cfg.isolation}) ===")
    click.echo()

    # Service checks (backend-agnostic)
    click.echo("-- Services --")
    services = backend.service_names(name)
    for svc in services:
        if backend.is_running(name, svc):
            _pass(f"{name}-{svc} is running")
        else:
            _fail(f"{name}-{svc} is NOT running")

    if cfg.isolation == "container":
        _verify_container(name, _pass, _fail, _warn)
    else:
        _verify_vm(name, _pass, _fail)

    # Summary
    click.echo()
    click.echo(f"=== Results: {passed} passed, {failed} failed, {warned} warnings ===")
    if failed > 0:
        click.echo("    Review failures above.")
        sys.exit(1)


def _verify_container(name: str, _pass, _fail, _warn):
    """Container-specific health checks (exec into host containers)."""
    podman = Podman()

    # CA certificate check
    click.echo()
    click.echo("-- CA Certificate --")
    try:
        exit_code, _ = podman.container_exec(
            f"{name}-cage", ["test", "-f", "/certs/mitmproxy-ca-cert.pem"]
        )
        if exit_code == 0:
            _pass("mitmproxy CA cert exists in shared volume")
        else:
            _fail("mitmproxy CA cert NOT found at /certs/mitmproxy-ca-cert.pem")
    except Exception:
        _fail("mitmproxy CA cert NOT found at /certs/mitmproxy-ca-cert.pem")

    # Proxy environment check
    click.echo()
    click.echo("-- Proxy Configuration --")
    try:
        attrs = podman.container_inspect(f"{name}-cage")
        env_list = attrs.get("Config", {}).get("Env", [])
        env_names = {e.split("=", 1)[0] for e in env_list if "=" in e}
        if "HTTP_PROXY" in env_names:
            _pass("HTTP_PROXY is set")
        else:
            _fail("HTTP_PROXY is NOT set")
        if "HTTPS_PROXY" in env_names:
            _pass("HTTPS_PROXY is set")
        else:
            _fail("HTTPS_PROXY is NOT set")
    except Exception:
        _fail("HTTP_PROXY is NOT set")
        _fail("HTTPS_PROXY is NOT set")

    # Egress filtering check
    click.echo()
    click.echo("-- Egress Filtering --")
    try:
        # Try curl first, fall back to node, then python3 urllib
        status = ""
        exit_code, output = podman.container_exec(
            f"{name}-cage", ["which", "curl"]
        )
        if exit_code == 0:
            exit_code, output = podman.container_exec(
                f"{name}-cage",
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "5", "https://evil-exfil-server.io"],
            )
            status = output.strip()
        else:
            # Use node fetch as fallback
            exit_code, output = podman.container_exec(
                f"{name}-cage",
                ["node", "-e",
                 "fetch('http://evil-exfil-server.io')"
                 ".then(r=>console.log(r.status))"
                 ".catch(()=>console.log('000'))"],
            )
            if exit_code == 0 and output.strip():
                status = output.strip()
            else:
                # Use python3 urllib as last resort
                exit_code, output = podman.container_exec(
                    f"{name}-cage",
                    ["python3", "-c",
                     "import urllib.request, urllib.error\n"
                     "try:\n"
                     "    urllib.request.urlopen('https://evil-exfil-server.io', timeout=5)\n"
                     "    print('200')\n"
                     "except urllib.error.HTTPError as e:\n"
                     "    print(e.code)\n"
                     "except Exception:\n"
                     "    print('000')"],
                )
                if exit_code == 0 and output.strip():
                    status = output.strip()
        if not status:
            _warn("No HTTP client (curl/node/python3) in cage — cannot verify egress filtering")
        elif status in ("403", "000"):
            _pass(f"Blocked domain (evil-exfil-server.io) is denied (HTTP {status})")
        else:
            _fail(f"Blocked domain returned HTTP {status} — egress filtering may be broken")
    except Exception:
        _pass("Blocked domain (evil-exfil-server.io) is denied (HTTP 000)")

    # Nested containers check
    cfg = state.load_deployment_config(name)
    if cfg.container.nested_containers:
        click.echo()
        click.echo("-- Nested Containers --")
        try:
            exit_code, output = podman.container_exec(
                f"{name}-cage", ["podman", "--version"]
            )
            if exit_code == 0:
                _pass(f"Inner podman available ({output.strip()})")
            else:
                _fail("Inner podman is NOT available")
        except Exception:
            _fail("Inner podman is NOT available")
        try:
            exit_code, output = podman.container_exec(
                f"{name}-cage", ["docker", "--version"]
            )
            if exit_code == 0:
                _pass("Docker shim available")
            else:
                _fail("Docker shim is NOT available")
        except Exception:
            _fail("Docker shim is NOT available")

    # Podman rootless check
    click.echo()
    click.echo("-- Podman --")
    try:
        info = podman.info()
        rootless = info.get("host", {}).get("security", {}).get("rootless", False)
        if rootless:
            _pass("Podman is running rootless")
        else:
            _fail("Podman is NOT rootless")
    except Exception:
        _fail("Podman is NOT rootless")


def _verify_vm(name: str, _pass, _fail):
    """Verify a VM cage is running correctly."""
    inst = LimaInstance(name)

    # Check Lima VM is running
    click.echo()
    click.echo("-- Lima VM --")
    if inst.is_running():
        _pass("Lima VM instance is running")
    else:
        _fail("Lima VM instance is not running")
        return

    # Check services inside VM
    click.echo()
    click.echo("-- VM Services --")
    for svc in ["cage", "proxy", "dns"]:
        try:
            result = inst.exec(
                ["systemctl", "--user", "is-active", f"{name}-{svc}.service"],
                check=False,
            )
            if result.stdout.strip() == "active":
                _pass(f"{svc} service is active")
            else:
                _fail(f"{svc} service is not active ({result.stdout.strip()})")
        except Exception as e:
            _fail(f"Cannot check {svc} service: {e}")


@cage.command("edit")
@click.argument("name")
def cage_edit(name: str):
    """Open the stored cage config in $EDITOR."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    config_path = state.stored_config_path(name)
    click.edit(filename=config_path, extension='.yaml')

    try:
        cfg = load_config(config_path)
        warnings = validate_config(cfg)
    except ValueError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    for w in warnings:
        click.echo(f"warning: {w}", err=True)

    state.save_proxy_config(name)

    reloaded = False
    backend = get_backend(cfg)
    if backend.is_running(name, "cage"):
        _restart_cage(name, cfg)
        reloaded = True

    msg = f"Config updated for cage '{name}'."
    if reloaded:
        msg += " Cage restarted."
    click.echo(msg)


@cage.command("restart")
@click.argument("name")
def cage_restart(name: str):
    """Restart services without rebuilding images."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)

    # Re-copy patch files from package data to overwrite any tampering
    _ensure_patches(Podman())

    _restart_cage(name, cfg)
    click.echo(f"Restarted cage '{name}'")


@cage.command("stop")
@click.argument("name")
def cage_stop(name: str):
    """Stop a running cage without destroying it."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)
    backend = get_backend(cfg)
    backend.stop(name)
    click.echo(f"Stopped cage '{name}'")


@cage.command("start")
@click.argument("name")
def cage_start(name: str):
    """Start a stopped cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)
    _ensure_patches(Podman())

    backend = get_backend(cfg)
    backend.start(name)
    click.echo(f"Started cage '{name}'")


@cage.command("show")
@click.argument("name")
def cage_show(name: str):
    """Show cage configuration and status."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)
    meta = state.load_metadata(name)
    backend = get_backend(cfg)

    # Status
    services = backend.service_names(name)
    total = len(services)
    running = sum(1 for svc in services if backend.is_running(name, svc))
    if running == total:
        status = f"running ({running}/{total})"
    elif running == 0:
        status = f"stopped (0/{total})"
    else:
        status = f"degraded ({running}/{total})"

    click.echo(f"Name:       {cfg.name}")
    click.echo(f"Isolation:  {cfg.isolation}")
    click.echo(f"Image:      {cfg.container.image}")
    click.echo(f"Version:    {meta.get('agentcage_version', '-')}")
    click.echo(f"Status:     {status}")

    if cfg.container.ports:
        click.echo(f"Ports:      {', '.join(cfg.container.ports)}")

    # Domain info
    try:
        raw = state.load_raw_config(name)
        mode, domain_entries, passthrough = _read_domain_config(raw)
        click.echo(f"Domains:    {mode} ({len(domain_entries)} domains)")
        if passthrough:
            click.echo(f"Passthrough: {len(passthrough)} domains")
    except Exception:
        pass

    # Secrets
    podman = _podman_for_cage(name)
    secrets = podman.secret_list(prefix=f"{name}.")
    expected = _expected_secrets(cfg)
    present_keys = {
        s.get("Name", "").removeprefix(f"{name}.")
        for s in secrets
    }
    missing = [k for k in expected if k not in present_keys]
    if expected:
        if missing:
            click.echo(f"Secrets:    {len(present_keys)}/{len(expected)} ({len(missing)} missing)")
        else:
            click.echo(f"Secrets:    {len(expected)}/{len(expected)}")


@cage.command("logs")
@click.argument("name")
@click.option("-s", "--service", "services", multiple=True,
              type=click.Choice(["cage", "proxy", "dns"]))
@click.option("-n", "--lines", default=50, show_default=True,
              help="Number of lines to show.")
@click.option("-f", "--follow", is_flag=True, help="Stream logs in real time.")
@click.option("--no-follow", is_flag=True, hidden=True, help="Backward compat no-op.")
@click.option("-l", "--severity", "min_level", default=None,
              type=click.Choice(["debug", "info", "warning", "error", "critical"]),
              help="Minimum severity level to show.")
def cage_logs(name, services, lines, follow, no_follow, min_level):
    """Show journalctl logs for a cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)
    selected = services or ("cage", "proxy", "dns")

    no_follow_effective = not follow

    if cfg.isolation == "vm":
        _logs_vm(name, selected, lines, no_follow_effective, min_level)
    else:
        _logs_container(name, selected, lines, no_follow_effective, min_level)


def _classify_line(service: str, line: str) -> str:
    """Classify a log line's severity for container-mode filtering."""
    if service == "dns":
        if '"decision":"blocked"' in line or '"decision": "blocked"' in line:
            return "warning"
        if '"decision":"allowed"' in line or '"decision": "allowed"' in line:
            return "info"
        low = line.lower()
        for pat in ("query[", "reply", "cached", "forwarded"):
            if pat in low:
                return "debug"
        for pat in ("error", "refused", "servfail"):
            if pat in low:
                return "error"
        return "info"
    if service == "proxy":
        if '"decision":"blocked"' in line or '"decision": "blocked"' in line:
            return "warning"
        if '"decision":"flagged"' in line or '"decision": "flagged"' in line:
            return "warning"
        if '"decision":"allowed"' in line or '"decision": "allowed"' in line:
            return "info"
        low = line.lower()
        if "error" in low or "traceback" in low:
            return "error"
        return "debug"
    # cage
    low = line.lower()
    for pat in ("error", "traceback", "fatal", "exit code"):
        if pat in low:
            return "error"
    if "warn" in low:
        return "warning"
    return "info"


def _logs_container(name, services, lines, no_follow, min_level=None):
    """Exec into journalctl with one -u per host-level service unit."""
    units = [f"{name}-{svc}" for svc in services]
    cmd = ["journalctl", "--user"]
    for u in units:
        cmd += ["-u", u]
    cmd += ["-n", str(lines)]
    if not no_follow:
        cmd.append("-f")

    if min_level is None:
        os.execvp("journalctl", cmd)
    else:
        # Filter by severity on the Python side
        min_ord = _LEVEL_ORDER.get(min_level, 1)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        try:
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n")
                # Detect which service this line belongs to
                svc = None
                for s in services:
                    if f"{name}-{s}" in line:
                        svc = s
                        break
                if svc is None:
                    svc = "cage"  # fallback
                lvl = _classify_line(svc, line)
                if _LEVEL_ORDER.get(lvl, 1) >= min_ord:
                    click.echo(line)
        except KeyboardInterrupt:
            pass
        finally:
            proc.terminate()


def _level_grep_pattern(services: tuple, min_level: str | None) -> str:
    """Build a grep -E pattern matching [service:level] tags."""
    levels_at_or_above = ("debug", "info", "warning", "error", "critical")
    if min_level:
        min_ord = _LEVEL_ORDER.get(min_level, 1)
        levels_at_or_above = tuple(
            l for l, o in _LEVEL_ORDER.items() if o >= min_ord
        )
    lvl_alt = "|".join(levels_at_or_above)
    svc_alt = "|".join(services)
    return rf"\[({svc_alt}):({lvl_alt})\]"


def _logs_vm(name, services, lines, no_follow, min_level=None):
    """Show logs from inside the Lima VM via limactl shell."""
    inst = LimaInstance(name)
    # Inside the VM, journalctl works normally with the quadlet services
    units = [f"{name}-{svc}" for svc in services]
    cmd = ["journalctl", "--user"]
    for u in units:
        cmd += ["-u", u]
    cmd += ["-n", str(lines), "-o", "cat"]
    if not no_follow:
        cmd.append("-f")

    full_cmd = ["limactl", "shell", inst.name, "--"] + cmd
    if min_level is None:
        os.execvp("limactl", full_cmd)
    else:
        min_ord = _LEVEL_ORDER.get(min_level, 1)
        proc = subprocess.Popen(full_cmd, stdout=subprocess.PIPE, text=True)
        try:
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n")
                svc = None
                for s in services:
                    if f"{name}-{s}" in line:
                        svc = s
                        break
                if svc is None:
                    svc = "cage"
                lvl = _classify_line(svc, line)
                if _LEVEL_ORDER.get(lvl, 1) >= min_ord:
                    click.echo(line)
        except KeyboardInterrupt:
            pass
        finally:
            proc.terminate()


@cage.command("exec", context_settings={"ignore_unknown_options": True})
@click.argument("name")
@click.option("-s", "--service", default="cage",
              type=click.Choice(["cage", "proxy", "dns"]),
              help="Container service to exec into.", show_default=True)
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
def cage_exec(name: str, service: str, command: tuple[str, ...]):
    """Run a command inside a cage container.

    \b
    Example:
      agentcage cage exec myapp -- openclaw devices list
    """
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)

    cmd = list(command)
    if not cmd:
        click.echo("error: no command specified", err=True)
        sys.exit(1)

    # Alias expansion: if the first word matches an exec_alias, expand it
    if cmd[0] in cfg.exec_aliases:
        cmd = cfg.exec_aliases[cmd[0]] + cmd[1:]

    if cfg.isolation == "vm":
        inst = LimaInstance(name)
        exec_flags = ["-it"] if sys.stdin.isatty() else []
        os.execvp("limactl", ["limactl", "shell", inst.name, "--",
                  "podman", "exec", *exec_flags, f"{name}-{service}", *cmd])

    container = f"{name}-{service}"
    exec_flags = []
    if sys.stdin.isatty():
        exec_flags = ["-it"]
    result = subprocess.run(
        ["podman", "exec"] + exec_flags + [container] + cmd,
    )
    sys.exit(result.returncode)


@cage.command("shell")
@click.argument("name")
@click.option("-s", "--service", default="cage",
              type=click.Choice(["cage", "proxy", "dns"]),
              help="Container service to shell into.", show_default=True)
def cage_shell(name: str, service: str):
    """Open an interactive shell in a cage container."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)

    if cfg.isolation == "vm":
        inst = LimaInstance(name)
        container = f"{name}-{service}"
        # Auto-detect bash or fall back to sh inside the VM
        for shell in ("/bin/bash", "/bin/sh"):
            result = subprocess.run(
                ["limactl", "shell", inst.name, "--",
                 "podman", "exec", container, "test", "-x", shell],
                capture_output=True,
            )
            if result.returncode == 0:
                exec_flags = ["-it"] if sys.stdin.isatty() else []
                os.execvp("limactl", ["limactl", "shell", inst.name, "--",
                          "podman", "exec", *exec_flags, container, shell])
        exec_flags = ["-it"] if sys.stdin.isatty() else []
        os.execvp("limactl", ["limactl", "shell", inst.name, "--",
                  "podman", "exec", *exec_flags, container, "/bin/sh"])

    container = f"{name}-{service}"
    # Auto-detect bash or fall back to sh
    for shell in ("/bin/bash", "/bin/sh"):
        result = subprocess.run(
            ["podman", "exec", container, "test", "-x", shell],
            capture_output=True,
        )
        if result.returncode == 0:
            exec_flags = ["-it"] if sys.stdin.isatty() else []
            os.execvp("podman", ["podman", "exec", *exec_flags, container, shell])
    # Fallback
    exec_flags = ["-it"] if sys.stdin.isatty() else []
    os.execvp("podman", ["podman", "exec", *exec_flags, container, "/bin/sh"])


# ── cage audit ─────────────────────────────────────────────


def _normalize_since(since: str) -> str:
    """Convert shorthand durations to journalctl --since format.

    Accepts ``1h``, ``30m``, ``7d`` or ISO dates (passed through).
    """
    m = re.match(r"^(\d+)([hHmMdD])$", since)
    if not m:
        return since  # assume ISO date, pass through
    val, unit = int(m.group(1)), m.group(2).lower()
    if unit == "h":
        return f"{val} hours ago"
    elif unit == "m":
        return f"{val} minutes ago"
    elif unit == "d":
        return f"{val} days ago"
    return since


def _build_audit_journal_cmd(
    name: str, cfg, *, since: str | None = None, follow: bool = False,
) -> list[str]:
    """Build the journalctl command for reading audit entries."""
    if cfg.isolation == "vm":
        inst = LimaInstance(name)
        cmd = ["limactl", "shell", inst.name, "--",
               "journalctl", "--user", "-u", f"{name}-proxy", "-u", f"{name}-dns", "-o", "cat"]
    else:
        cmd = ["journalctl", "--user", "-u", f"{name}-proxy", "-u", f"{name}-dns", "-o", "cat"]

    if since:
        cmd += ["--since", _normalize_since(since)]

    if follow:
        cmd.append("-f")
    else:
        # Over-read: many lines aren't audit entries
        cmd += ["-n", "10000"]

    return cmd


def _audit_batch(name, cfg, filt, lines, since, as_json, no_color):
    """Read historical audit entries, filter, and output."""
    cmd = _build_audit_journal_cmd(name, cfg, since=since)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    entries = []
    try:
        for raw_line in proc.stdout:
            d = extract_audit_json(raw_line)
            if d is None:
                continue
            entry = AuditEntry.from_dict(d)
            if filt.matches(entry):
                entries.append(entry)
    finally:
        proc.wait()

    # Keep only last N
    if lines > 0:
        entries = entries[-lines:]

    if as_json:
        for entry in entries:
            click.echo(json.dumps(entry.raw))
    else:
        click.echo(format_table_header())
        for entry in entries:
            click.echo(format_table_row(entry, color=not no_color))


def _audit_follow(name, cfg, filt, as_json, no_color):
    """Stream audit entries in real time."""
    cmd = _build_audit_journal_cmd(name, cfg, follow=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

    if not as_json:
        click.echo(format_table_header())

    try:
        for raw_line in proc.stdout:
            d = extract_audit_json(raw_line)
            if d is None:
                continue
            entry = AuditEntry.from_dict(d)
            if filt.matches(entry):
                if as_json:
                    click.echo(json.dumps(entry.raw))
                else:
                    click.echo(format_table_row(entry, color=not no_color))
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()


def _audit_summary(name, cfg, filt, since):
    """Compute and display summary statistics."""
    cmd = _build_audit_journal_cmd(name, cfg, since=since)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    entries = []
    try:
        for raw_line in proc.stdout:
            d = extract_audit_json(raw_line)
            if d is None:
                continue
            entry = AuditEntry.from_dict(d)
            if filt.matches(entry):
                entries.append(entry)
    finally:
        proc.wait()

    summary = compute_summary(entries)
    click.echo(format_summary(summary))


@cage.command("audit")
@click.argument("name")
@click.option("-d", "--decision", "decisions", multiple=True,
              type=click.Choice(["blocked", "flagged", "allowed"]),
              help="Filter by decision (repeatable).")
@click.option("--host", "hosts", multiple=True,
              help="Filter by target host (substring match, repeatable).")
@click.option("--inspector", "inspectors", multiple=True,
              help="Filter by inspector name (repeatable).")
@click.option("--severity", type=click.Choice(["debug", "info", "warning", "error", "critical"]),
              help="Minimum inspector severity.")
@click.option("--direction", "directions", multiple=True,
              type=click.Choice(["inbound", "outbound"]),
              help="Filter by traffic direction (repeatable).")
@click.option("--method", "methods", multiple=True,
              help="Filter by HTTP method (repeatable).")
@click.option("--since", default=None,
              help="Time window: 1h, 30m, 7d, or ISO date.")
@click.option("-n", "--max-entries", default=100, show_default=True,
              help="Max entries to show (0 = unlimited).")
@click.option("--lines", "max_entries_compat", default=None, type=int, hidden=True,
              help="Backward compat alias for --max-entries.")
@click.option("-f", "--follow", is_flag=True,
              help="Stream new entries in real time.")
@click.option("--json", "as_json", is_flag=True,
              help="Output as JSON lines.")
@click.option("--json-lines", "as_json_lines", is_flag=True, hidden=True,
              help="Backward compat alias for --json.")
@click.option("--summary", is_flag=True,
              help="Show aggregated statistics.")
@click.option("--no-color", is_flag=True,
              help="Disable colored output.")
def cage_audit(name, decisions, directions, hosts, inspectors, severity,
               methods, since, max_entries, max_entries_compat, follow, as_json,
               as_json_lines, summary, no_color):
    """Query, filter, and summarize proxy audit logs."""
    # Resolve backward-compat aliases
    lines = max_entries_compat if max_entries_compat is not None else max_entries
    as_json = as_json or as_json_lines

    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    if summary and follow:
        click.echo("error: --summary and --follow are incompatible", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)

    filt = AuditFilter(
        decisions=list(decisions),
        directions=list(directions),
        hosts=list(hosts),
        inspectors=list(inspectors),
        min_severity=severity,
        methods=list(methods),
    )

    if summary:
        _audit_summary(name, cfg, filt, since)
    elif follow:
        _audit_follow(name, cfg, filt, as_json, no_color)
    else:
        _audit_batch(name, cfg, filt, lines, since, as_json, no_color)


# ── cage har ───────────────────────────────────────────────


@cage.command("har")
@click.argument("name")
@click.option("--view", type=click.Choice(["inbound", "outbound"]), default="inbound",
              show_default=True,
              help="Perspective to export: inbound (cage sees, safe to share) or outbound (wire, contains secrets).")
@click.option("-d", "--decision", "decisions", multiple=True,
              type=click.Choice(["blocked", "flagged", "allowed"]),
              help="Filter by decision (repeatable).")
@click.option("--host", "hosts", multiple=True,
              help="Filter by host (substring match, repeatable).")
@click.option("--method", "methods", multiple=True,
              help="Filter by HTTP method (repeatable).")
@click.option("--direction", "directions", multiple=True,
              type=click.Choice(["inbound", "outbound"]),
              help="Filter by traffic direction (repeatable).")
@click.option("--since", default=None,
              help="Time window: 1h, 30m, 7d, or ISO date.")
@click.option("-n", "--max-entries", default=0, show_default=True,
              help="Max entries (0 = unlimited).")
@click.option("-o", "--output", "output_file", default=None,
              type=click.Path(),
              help="Output file (default: stdout).")
@click.option("--json-lines", is_flag=True,
              help="Output raw capture JSONL instead of HAR.")
@click.option("--json", "json_compat", is_flag=True, hidden=True,
              help="Backward compat alias for --json-lines.")
def cage_har(name, view, decisions, hosts, methods, directions, since,
             max_entries, output_file, json_lines, json_compat):
    """Export captured HTTP traffic as HAR 1.2 JSON.

    Reads the capture JSONL file for a cage and produces standard HAR JSON
    loadable in Chrome DevTools (Network > Import HAR).

    Two perspectives are available:

    \b
      inbound   What the bot saw inside the cage (placeholders, redacted
                secrets). Safe to share. This is the default.
      outbound  What went on the wire (real injected secrets, raw server
                responses). Treat as sensitive.
    """
    # Resolve backward-compat alias
    json_lines = json_lines or json_compat

    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    from agentcage.har import CaptureFilter, capture_to_har, parse_since

    capture_path = state.capture_file(name)
    if not capture_path.is_file():
        click.echo(f"error: no capture file found for cage '{name}'", err=True)
        click.echo(f"  Expected: {capture_path}", err=True)
        click.echo("", err=True)
        click.echo("  Add this to your cage.yaml and run `agentcage cage update`:", err=True)
        click.echo("    capture:", err=True)
        click.echo("      enable_har: true", err=True)
        sys.exit(1)

    # Warn about sensitive outbound data
    if view == "outbound" and not json_lines:
        click.echo(
            "WARNING: --view outbound includes real secrets (API keys, tokens). "
            "Treat the output as sensitive.",
            err=True,
        )

    # Build filter
    since_dt = parse_since(since) if since else None
    filt = CaptureFilter(
        decisions=list(decisions),
        directions=list(directions),
        hosts=list(hosts),
        methods=list(methods),
        since=since_dt,
    )

    # Read and filter capture entries
    entries = []
    with open(capture_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if filt.matches(entry):
                entries.append(entry)

    # Apply max-entries limit (keep last N)
    if max_entries > 0:
        entries = entries[-max_entries:]

    # Output
    if json_lines:
        out = sys.stdout if output_file is None else open(output_file, "w")
        try:
            for entry in entries:
                out.write(json.dumps(entry) + "\n")
        finally:
            if output_file is not None:
                out.close()
    else:
        har = capture_to_har(entries, view=view)
        text = json.dumps(har, indent=2)
        if output_file:
            with open(output_file, "w") as f:
                f.write(text + "\n")
            click.echo(f"Wrote {len(entries)} entries to {output_file}", err=True)
        else:
            click.echo(text)


# ── cage backup / restore ─────────────────────────────────


@cage.command("backup")
@click.argument("name")
@click.option("-o", "--output", default=None, type=click.Path(),
              help="Output path (default: ./{name}-backup-{timestamp}.tar.gz)")
@click.option("--include-secrets", is_flag=True,
              help="Include secret values in the backup (handle with care)")
def cage_backup(name: str, output: str | None, include_secrets: bool):
    """Create a backup tarball of a cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)
    podman = _podman_for_cage(name)

    # Determine output path
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    if output is None:
        output = f"{name}-backup-{ts}.tar.gz"

    with tempfile.TemporaryDirectory() as staging:
        staging_path = Path(staging)

        # ── Config ──
        config_dir = staging_path / "config"
        config_dir.mkdir()
        src_dir = Path(state.stored_config_path(name)).parent
        for fname in ("cage.yaml", "metadata.json", "proxy-config.yaml"):
            src = src_dir / fname
            if src.is_file():
                shutil.copy2(str(src), str(config_dir / fname))

        # ── Secrets ──
        expected = _expected_secrets(cfg)
        secrets_in_store = podman.secret_list(prefix=f"{name}.")
        secret_keys = [
            s["Name"].removeprefix(f"{name}.")
            for s in secrets_in_store
        ]
        if include_secrets:
            click.echo(
                "WARNING: Including secrets in backup. "
                "Store the tarball securely.",
                err=True,
            )
            if secret_keys:
                secrets_dir = staging_path / "secrets"
                secrets_dir.mkdir()
                for s in secrets_in_store:
                    full_name = s["Name"]
                    key = full_name.removeprefix(f"{name}.")
                    value = podman.secret_read(full_name)
                    (secrets_dir / key).write_text(value)
        else:
            click.echo(
                "Secrets not included. Use --include-secrets to include them. "
                "You will need to re-set secrets after restore.",
            )

        # ── Volumes (container mode) ──
        vol_names = []
        if cfg.isolation == "container" and cfg.container.named_volumes:
            volumes_dir = staging_path / "volumes"
            volumes_dir.mkdir()
            for vol_name in cfg.container.named_volumes:
                if podman.volume_exists(vol_name):
                    vol_tar = str(volumes_dir / f"{vol_name}.tar")
                    podman.volume_export(vol_name, vol_tar)
                    vol_names.append(vol_name)
                else:
                    click.echo(
                        f"warning: volume '{vol_name}' does not exist, skipping",
                        err=True,
                    )

        # ── Capture ──
        has_capture = False
        capture_path = state.capture_file(name)
        if capture_path.is_file() and capture_path.stat().st_size > 0:
            cap_dir = staging_path / "capture"
            cap_dir.mkdir()
            shutil.copy2(str(capture_path), str(cap_dir / "capture.jsonl"))
            has_capture = True

        # ── Manifest ──
        manifest = {
            "format_version": 1,
            "agentcage_version": version("agentcage"),
            "cage_name": name,
            "isolation": cfg.isolation,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "has_secrets": bool(expected),
            "has_capture": has_capture,
            "named_volumes": vol_names,
            "secret_keys": expected,
            "secrets_included": include_secrets and bool(secret_keys),
        }
        (staging_path / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )

        # ── Create tarball ──
        with tarfile.open(output, "w:gz") as tar:
            for item in staging_path.iterdir():
                tar.add(str(item), arcname=f"agentcage-backup/{item.name}")

    # ── Summary ──
    click.echo(f"Backup saved to {output}")
    click.echo(f"  Secrets: {len(secret_keys)} keys"
               f" ({'included' if include_secrets else 'not included'})")
    click.echo(f"  Volumes: {len(vol_names)}")
    click.echo(f"  Capture: {'yes' if has_capture else 'no'}")


@cage.command("restore")
@click.argument("tarball", type=click.Path(exists=True))
@click.option("--name", "new_name", default=None,
              help="Restore with a different name (for cloning)")
@click.option("--force", is_flag=True, help="Overwrite existing cage")
@click.option("--no-start", is_flag=True, help="Restore without starting")
def cage_restore(tarball: str, new_name: str | None, force: bool, no_start: bool):
    """Restore a cage from a backup tarball."""
    # ── Read manifest ──
    with tarfile.open(tarball, "r:gz") as tar:
        try:
            mf = tar.extractfile("agentcage-backup/manifest.json")
            if mf is None:
                raise KeyError
            manifest = json.loads(mf.read())
        except (KeyError, json.JSONDecodeError):
            click.echo(
                "error: invalid backup — missing or corrupt manifest.json",
                err=True,
            )
            sys.exit(1)

    # ── Validate ──
    fmt_ver = manifest.get("format_version", 0)
    if fmt_ver > 1:
        click.echo(
            f"error: unsupported backup format version {fmt_ver} "
            f"(this agentcage supports version 1)",
            err=True,
        )
        sys.exit(1)

    target_name = new_name or manifest["cage_name"]

    if not re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', target_name):
        click.echo(
            "error: name must be 1-63 lowercase alphanumeric characters or "
            f"hyphens, starting with a letter or digit (got: {target_name!r})",
            err=True,
        )
        sys.exit(1)

    # ── Handle existing cage ──
    if state.deployment_exists(target_name):
        if not force:
            click.echo(
                f"error: cage '{target_name}' already exists "
                f"(use --force to overwrite)",
                err=True,
            )
            sys.exit(1)
        click.echo(f"Destroying existing cage '{target_name}'...")
        try:
            cfg = state.load_deployment_config(target_name)
            backend = get_backend(cfg)
            backend.stop(target_name)
            backend.destroy_resources(target_name)
        except Exception:
            from agentcage.backends.container import ContainerBackend
            backend = ContainerBackend()
            backend.stop(target_name)
            backend.destroy_resources(target_name)
        if state.deployment_exists(target_name):
            state.remove_deployment(target_name)

    podman = _podman_for_cage(target_name)

    # ── Extract tarball ──
    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(tarball, "r:gz") as tar:
            tar.extractall(tmpdir, filter="data")

        backup_dir = Path(tmpdir) / "agentcage-backup"

        # ── Restore secrets ──
        secrets_dir = backup_dir / "secrets"
        secrets_included = manifest.get("secrets_included", False)
        expected_keys = manifest.get("secret_keys", [])

        if secrets_dir.is_dir() and secrets_included:
            for secret_file in secrets_dir.iterdir():
                key = secret_file.name
                value = secret_file.read_text()
                full_name = f"{target_name}.{key}"
                if podman.secret_exists(full_name):
                    podman.secret_remove(full_name)
                podman.secret_create(full_name, value)
            click.echo(
                f"Restored {len(list(secrets_dir.iterdir()))} secrets."
            )
        elif not secrets_included and expected_keys:
            missing = [
                k for k in expected_keys
                if not podman.secret_exists(f"{target_name}.{k}")
            ]
            if missing:
                click.echo(
                    "Secrets were not included in this backup. "
                    "Set them with:",
                    err=True,
                )
                for k in missing:
                    click.echo(
                        f"  agentcage secret set {target_name} {k}",
                        err=True,
                    )

        # ── Restore config ──
        config_src = backup_dir / "config"
        cage_yaml_src = config_src / "cage.yaml"
        if not cage_yaml_src.is_file():
            click.echo(
                "error: invalid backup — missing config/cage.yaml",
                err=True,
            )
            sys.exit(1)

        # If renaming, update the name field in cage.yaml
        if new_name:
            with open(cage_yaml_src) as f:
                import yaml
                raw = yaml.safe_load(f)
            raw["name"] = new_name
            with open(cage_yaml_src, "w") as f:
                yaml.safe_dump(raw, f, default_flow_style=False, sort_keys=False)

        state.save_deployment(target_name, str(cage_yaml_src))

        # Copy metadata.json if present
        meta_src = config_src / "metadata.json"
        if meta_src.is_file():
            deploy_dir = Path(state.stored_config_path(target_name)).parent
            shutil.copy2(str(meta_src), str(deploy_dir / "metadata.json"))

        # Regenerate proxy-config.yaml
        state.save_proxy_config(target_name)

        # ── Build and deploy ──
        if no_start:
            click.echo(
                f"Cage state restored. "
                f"Run: agentcage cage update {target_name} to build and start."
            )
            if manifest.get("named_volumes"):
                click.echo(
                    "Note: Named volumes will be imported when the cage "
                    "is started for the first time."
                )
        else:
            # Check secrets before starting
            cfg = state.load_deployment_config(target_name)
            if not secrets_included and expected_keys:
                missing = _check_secrets(podman, target_name, cfg)
                if missing:
                    click.echo(
                        f"warning: {len(missing)} secrets are missing — "
                        f"cage may fail to start",
                        err=True,
                    )

            config_host_path = state.stored_config_path(target_name)
            proxy_config_path = str(
                Path(config_host_path).parent / "proxy-config.yaml"
            )
            # Collect existing subnets to avoid collisions on restore
            from agentcage.quadlets import collect_used_octets as _collect_used_octets
            _restore_used = _collect_used_octets()
            _build_and_deploy(cfg, proxy_config_path, target_name, podman, used_octets=_restore_used)

            # ── Import named volumes ──
            volumes_dir = backup_dir / "volumes"
            if volumes_dir.is_dir() and any(volumes_dir.iterdir()):
                click.echo("Importing volumes...")
                backend = get_backend(cfg)
                backend.stop(target_name)
                for vol_tar in sorted(volumes_dir.glob("*.tar")):
                    vol_name = vol_tar.stem
                    podman.volume_import(vol_name, str(vol_tar))
                    click.echo(f"  Imported volume '{vol_name}'")
                backend.start(target_name)

        # ── Restore capture ──
        cap_src = backup_dir / "capture" / "capture.jsonl"
        if cap_src.is_file():
            dest = state.capture_file(target_name)
            shutil.copy2(str(cap_src), str(dest))

    click.echo(f"Cage '{target_name}' restored from {tarball}")


# ── secret group ─────────────────────────────────────────


@main.group(cls=AliasGroup, aliases={"ls": "list"})
def secret():
    """Manage cage-scoped secrets."""


@secret.command("list")
@click.argument("name")
def secret_list(name: str):
    """List secrets for a cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    podman = _podman_for_cage(name)
    secrets = podman.secret_list(prefix=f"{name}.")

    # If cage state exists, cross-reference with expected secrets
    if state.deployment_exists(name):
        cfg = state.load_deployment_config(name)
        expected = _expected_secrets(cfg)

        # Determine which type each secret is
        injection_names = {r.env for r in cfg.secret_injection}
        present_keys = {
            s.get("Name", "").removeprefix(f"{name}.")
            for s in secrets
        }

        click.echo(f"{'NAME':<30} {'TYPE':<12} STATUS")
        any_missing = False
        for key in expected:
            stype = "injection" if key in injection_names else "direct"
            if key in present_keys:
                status = "ok"
            else:
                status = "MISSING"
                any_missing = True
            click.echo(f"{key:<30} {stype:<12} {status}")

        if any_missing:
            sys.exit(1)
    else:
        if not secrets:
            click.echo(f"No secrets found for '{name}'.")
            return
        click.echo(f"{'NAME':<30}")
        for s in secrets:
            sname = s.get("Name", "")
            key = sname.removeprefix(f"{name}.")
            click.echo(f"{key:<30}")


@secret.command("set")
@click.argument("name")
@click.argument("key")
def secret_set(name: str, key: str):
    """Set a secret for a cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist — create it first with 'cage create'", err=True)
        sys.exit(1)
    podman = _podman_for_cage(name)
    full_name = f"{name}.{key}"

    # Read value from TTY or stdin
    if sys.stdin.isatty():
        value = click.prompt(f"Value for {key}", hide_input=True)
    else:
        value = sys.stdin.read().rstrip("\n")

    if not value:
        click.echo("error: empty secret value", err=True)
        sys.exit(1)

    # Remove existing if present
    if podman.secret_exists(full_name):
        podman.secret_remove(full_name)

    podman.secret_create(full_name, value)
    click.echo(f"Secret '{full_name}' set.")

    # Auto-reload if cage is running
    if state.deployment_exists(name):
        cfg = state.load_deployment_config(name)
        cage_name = cfg.name
        backend = get_backend(cfg)
        if backend.is_running(cage_name, "cage"):
            click.echo(f"Restarting cage '{cage_name}'...")
            _restart_cage(cage_name, cfg)


@secret.command("rm")
@click.argument("name")
@click.argument("key")
def secret_rm(name: str, key: str):
    """Remove a secret for a cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    podman = _podman_for_cage(name)
    full_name = f"{name}.{key}"

    if not podman.secret_exists(full_name):
        click.echo(f"error: secret '{full_name}' does not exist", err=True)
        sys.exit(1)

    podman.secret_remove(full_name)
    click.echo(f"Secret '{full_name}' removed.")

    # Auto-reload if cage is running
    if state.deployment_exists(name):
        cfg = state.load_deployment_config(name)
        cage_name = cfg.name
        backend = get_backend(cfg)
        if backend.is_running(cage_name, "cage"):
            click.echo(f"Restarting cage '{cage_name}'...")
            _restart_cage(cage_name, cfg)


# ── domain group ─────────────────────────────────────────


@main.group(cls=AliasGroup, aliases={"ls": "list"})
def domain():
    """Manage cage domain filters."""


def _read_domain_config(raw: dict) -> tuple[str, list[str], list[str]]:
    """Extract (mode, domain_list, passthrough) from raw config dict.

    Supports both new (allow/block) and legacy (mode+list) formats.
    """
    domains = raw.get("domains") or {}
    passthrough = list(domains.get("passthrough") or [])
    if "allow" in domains:
        return "allowlist", list(domains.get("allow") or []), passthrough
    if "block" in domains:
        return "blocklist", list(domains.get("block") or []), passthrough
    # Legacy format
    mode = domains.get("mode", "allowlist")
    entries = list(domains.get("list") or [])
    return mode, entries, passthrough


def _ensure_domain_section(raw: dict) -> None:
    """Ensure raw config has a domains section with allow key."""
    if "domains" not in raw:
        raw["domains"] = {"allow": []}
    dom = raw["domains"]
    # Migrate legacy mode+list to allow
    if "allow" not in dom and "block" not in dom:
        mode = dom.pop("mode", "allowlist")
        entries = dom.pop("list", [])
        if mode == "allowlist":
            dom["allow"] = list(entries)
        elif mode == "blocklist":
            dom["block"] = list(entries)
        else:
            dom["allow"] = list(entries)


@domain.command("list")
@click.argument("name")
def domain_list(name: str):
    """List domains for a cage."""
    try:
        raw = state.load_raw_config(name)
    except FileNotFoundError:
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    mode, domain_entries, passthrough = _read_domain_config(raw)
    pt_set = set(passthrough)

    click.echo(f"Mode: {mode}")
    for d in sorted(domain_entries):
        suffix = " [passthrough]" if d in pt_set else ""
        click.echo(f"{d}{suffix}")
    # Show passthrough-only domains (in passthrough but not in the main list)
    for d in sorted(passthrough):
        if d not in domain_entries:
            click.echo(f"{d} [passthrough only]")


def _update_dns_quadlet(cfg) -> None:
    """Regenerate the DNS quadlet and restart all cage services.

    A DNS-only restart cascades via the Requires= dependency chain
    (proxy Requires dns, cage Requires proxy) and leaves proxy/cage
    stopped.  We stop all three explicitly, then start in dependency
    order so everything comes back up cleanly.
    """
    from agentcage.quadlets import render_dns_quadlet

    backend = get_backend(cfg)
    name = cfg.name

    # Read the actual deployed network octet from metadata so we
    # preserve the existing subnet.  Recomputing via the hash could
    # yield a different octet if collision resolution shifted it at
    # deploy time.
    meta = state.load_metadata(name)
    octet = meta.get("network_octet")
    dns_content = render_dns_quadlet(cfg, network_octet=octet)

    if cfg.isolation == "vm":
        inst = LimaInstance(name)
        # Write quadlet inside VM then restart services
        import base64
        encoded = base64.b64encode(dns_content.encode()).decode()
        inst.exec(["bash", "-c",
                   f"mkdir -p ~/.config/containers/systemd && "
                   f"echo '{encoded}' | base64 -d > ~/.config/containers/systemd/{shlex.quote(name)}-dns.container"])
        inst.exec(["systemctl", "--user", "daemon-reload"])
        if backend.is_running(name, "dns"):
            services = backend.service_names(name)
            for svc in services:
                inst.exec(["systemctl", "--user", "stop", f"{name}-{svc}.service"],
                          check=False)
            for svc in reversed(services):
                inst.exec(["systemctl", "--user", "start", f"{name}-{svc}.service"])
    else:
        quadlet_dir = backend.unit_dir()
        (quadlet_dir / f"{name}-dns.container").write_text(dns_content)
        systemd.daemon_reload()
        if backend.is_running(name, "dns"):
            # Stop most-dependent first, start dependencies first.
            services = backend.service_names(name)
            for svc in services:
                try:
                    systemd.stop_unit(f"{name}-{svc}.service")
                except Exception:
                    pass
            for svc in reversed(services):
                systemd.start_unit(f"{name}-{svc}.service")


@domain.command("add")
@click.argument("name")
@click.argument("domain_name")
@click.option("--passthrough", is_flag=True,
              help="Also add to TLS passthrough list (no MITM interception).")
def domain_add(name: str, domain_name: str, passthrough: bool):
    """Add a domain to a cage's filter list."""
    try:
        raw = state.load_raw_config(name)
    except FileNotFoundError:
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    _ensure_domain_section(raw)
    dom = raw["domains"]

    # Determine the active list key
    list_key = "allow" if "allow" in dom else "block" if "block" in dom else "allow"
    if list_key not in dom:
        dom[list_key] = []

    already_in_list = domain_name in dom[list_key]
    already_passthrough = domain_name in dom.get("passthrough", [])

    if already_in_list and (not passthrough or already_passthrough):
        click.echo(f"'{domain_name}' is already in cage '{name}'.")
        return

    if not already_in_list:
        dom[list_key].append(domain_name)
    if passthrough and not already_passthrough:
        if "passthrough" not in dom:
            dom["passthrough"] = []
        dom["passthrough"].append(domain_name)

    state.save_raw_config(name, raw)
    state.save_proxy_config(name)

    cfg = state.load_deployment_config(name)
    _update_dns_quadlet(cfg)

    pt_note = " (passthrough)" if passthrough else ""
    msg = f"Added '{domain_name}'{pt_note} to cage '{name}'."
    if get_backend(cfg).is_running(cfg.name, "cage"):
        msg += " DNS and proxy updated."
    click.echo(msg)


@domain.command("rm")
@click.argument("name")
@click.argument("domain_name")
@click.option("--passthrough", is_flag=True,
              help="Remove only from passthrough list (keep in allow/block).")
def domain_rm(name: str, domain_name: str, passthrough: bool):
    """Remove a domain from a cage's filter list."""
    try:
        raw = state.load_raw_config(name)
    except FileNotFoundError:
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    _ensure_domain_section(raw)
    dom = raw["domains"]

    # Determine the active list key
    list_key = "allow" if "allow" in dom else "block" if "block" in dom else "allow"
    domain_entries = dom.get(list_key, [])
    pt_entries = dom.get("passthrough", [])

    if passthrough:
        # Only remove from passthrough
        if domain_name not in pt_entries:
            click.echo(f"error: '{domain_name}' is not in passthrough for cage '{name}'", err=True)
            sys.exit(1)
        dom["passthrough"].remove(domain_name)
    else:
        # Remove from both main list and passthrough
        if domain_name not in domain_entries:
            click.echo(f"error: '{domain_name}' is not in cage '{name}'", err=True)
            sys.exit(1)
        dom[list_key].remove(domain_name)
        if domain_name in pt_entries:
            dom["passthrough"].remove(domain_name)

    state.save_raw_config(name, raw)
    state.save_proxy_config(name)

    cfg = state.load_deployment_config(name)
    _update_dns_quadlet(cfg)

    msg = f"Removed '{domain_name}' from cage '{name}'."
    if get_backend(cfg).is_running(cfg.name, "cage"):
        msg += " DNS and proxy updated."
    click.echo(msg)


