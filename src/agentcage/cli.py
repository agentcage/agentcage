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


def _is_apple_container(cfg) -> bool:
    """True if the cage uses the apple-container isolation backend."""
    return getattr(cfg, "isolation", None) == "apple-container"


def _exit_apple_container_unsupported(command: str) -> None:
    """Exit cleanly when a subcommand isn't implemented on apple-container.

    The apple-container backend does not yet support every cage subcommand
    that container/vm do. Rather than fall through to host podman (which
    crashes on macOS without podman installed), we exit non-zero with a
    helpful message. Tracked as a follow-up in issue #120.
    """
    click.echo(
        f"error: 'cage {command}' is not yet implemented for the "
        f"apple-container backend (see issue #120)",
        err=True,
    )
    sys.exit(1)


def _parse_version(ver: str) -> tuple[int, int]:
    """Parse 'X.Y[.Z…]' → (X, Y); return (0, 0) on garbage."""
    try:
        parts = ver.split(".")
        return int(parts[0]), int(parts[1])
    except (ValueError, TypeError, IndexError):
        return 0, 0


def _ensure_v022_cage(name: str) -> None:
    """Refuse to operate on a v0.21 cage (legacy 3-service shape).

    v0.22 collapsed the per-cage container shape from 3 services (cage /
    proxy / dns) into 2 (cage / egress). The new CLI commands are wired
    to the 2-service shape — running ``cage exec``, ``cage logs``, etc.
    against a v0.21 cage's leftover containers would either fail with
    confusing podman errors (``no container named '<name>-egress'``) or,
    worse, silently target the wrong workload. We detect the legacy shape
    from the version recorded in the cage's metadata and exit with a clear
    cleanup procedure.

    ``cage destroy`` deliberately does NOT call this — destroy is the
    documented escape hatch and its filename enumeration in
    ``ContainerBackend.destroy_resources()`` covers both shapes. ``cage
    list`` similarly skips this check and annotates legacy entries
    inline so the operator can see them without --force or special flags.
    """
    meta = state.load_metadata(name)
    ver = meta.get("agentcage_version") or "0.0.0"
    if _parse_version(ver) < (0, 22):
        click.echo(
            f"error: cage '{name}' was created with agentcage v{ver}, which used the\n"
            f"  legacy 3-service layout (cage / proxy / dns). v0.22 unified these into a\n"
            f"  single 'egress' service. The cage cannot be addressed by v0.22 commands.\n"
            f"\n"
            f"  To migrate, run:\n"
            f"    systemctl --user stop {name}-cage {name}-proxy {name}-dns\n"
            f"    agentcage cage destroy {name}\n"
            f"    agentcage cage create -c <your cage.yaml>\n",
            err=True,
        )
        sys.exit(2)


def _require_cage_service_on_apple_container(service: str, command: str) -> None:
    """Reject --service proxy|dns on apple-container with a clear message.

    On apple-container the cage is a single Apple microVM (one container)
    with mitmproxy and dnsmasq running inside it as supervised processes,
    not as separate Apple containers. Targeted proxy/dns exec/shell access
    isn't wired up yet; the only addressable target today is `cage`.
    """
    if service != "cage":
        click.echo(
            f"error: 'cage {command} --service {service}' is not yet "
            f"supported on the apple-container backend; only --service cage "
            f"is addressable (proxy and dnsmasq run inside the same microVM)",
            err=True,
        )
        sys.exit(1)


def _build_container_image(cfg, config_dir: Path, podman: Podman,
                           no_cache: bool = False,
                           pull: bool = False) -> None:
    """CLI wrapper that passes click.echo to the service layer."""
    _build_container_image_svc(cfg, config_dir, podman, echo=click.echo,
                               no_cache=no_cache, pull=pull)


# Entries in a Containerfile's directory that are agentcage config, not
# build inputs — skipped when staging the build context.
_BUILD_CONTEXT_SKIP_SUFFIXES = (".yaml", ".yml", ".j2")

# Build noise that must never be copied into a cage's staged build context:
# caches, VCS metadata, dependency trees, soft-deleted leftovers.
_BUILD_CONTEXT_IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", ".git", "node_modules", "*.deleted.*",
)


def _stage_build_context(src_dir: Path, dest_dir: Path,
                         *, clobber: bool = True) -> None:
    """Copy a Containerfile's sibling build inputs into a cage's state dir.

    Stages both files *and* directories so a later ``cage update`` (without
    ``-c``) — which rebuilds from the state dir — has the complete build
    context. A Containerfile that ``COPY``s a directory tree (skill
    bundles, vendored packages) would otherwise fail the rebuild because
    only sibling files were staged.

    cage.yaml-style configs and ``.j2`` templates are skipped; build noise
    (``__pycache__``, ``.git``, ``node_modules``, ...) is filtered out of
    copied directories. With *clobber* false, entries already present in
    *dest_dir* are left untouched.
    """
    for f in src_dir.iterdir():
        if f.suffix in _BUILD_CONTEXT_SKIP_SUFFIXES:
            continue
        dest = dest_dir / f.name
        if not clobber and dest.exists():
            continue
        if f.is_dir():
            shutil.copytree(
                f, dest, ignore=_BUILD_CONTEXT_IGNORE, dirs_exist_ok=True,
            )
        elif f.is_file():
            shutil.copy2(str(f), str(dest))


def _restart_cage(name: str, cfg=None):
    """Restart all services for a cage using the appropriate backend.

    Regenerates the two cage.yaml-derived files first so out-of-band edits
    to ``cage.yaml`` (or older state where the derived files drifted) are
    picked up on restart:

    - ``proxy-config.yaml`` — what mitmdump reads for HTTP/HTTPS allowlist
      decisions.
    - ``dns-allowlist.conf`` — what dnsmasq reads via ``--servers-file`` for
      DNS-layer allowlist filtering. Mounted into the dnsmasq sidecar; not
      part of the systemd unit, so updating it doesn't require a
      daemon-reload — just a service restart, which we're about to do anyway.

    The DNS quadlet itself almost never has to change (its content no longer
    depends on the domain list); :func:`_ensure_dns_quadlet_current` handles
    the rare migration case where an older agentcage left a stale unit on
    disk. Delegates the actual service restart to
    :func:`agentcage.services.restart_cage`.
    """
    if cfg is None:
        cfg = state.load_deployment_config(name)
    state.save_proxy_config(name)
    state.save_dns_allowlist(name)
    _ensure_dns_quadlet_current(cfg)
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


# ── doctor ───────────────────────────────────────────────


@main.command()
def doctor():
    """Check system health and diagnose common issues."""
    from agentcage.doctor import run_doctor

    results = run_doctor()
    sys.exit(1 if any(r.level == "error" for r in results) else 0)


# ── scaffold group ──────────────────────────────────────

from agentcage.scaffold_cli import scaffold  # noqa: E402
main.add_command(scaffold)


# ── init ─────────────────────────────────────────────────


@main.command()
@click.argument("name", required=False, default=None)
@click.option("-o", "--output", default="cage.yaml",
              help="Output file path.", show_default=True)
@click.option("--image", default="node:22-slim",
              help="Container image.", show_default=True)
@click.option("--isolation",
              type=click.Choice(["container", "vm", "apple-container"]),
              default=None,
              help="Isolation backend (default: auto-detect from platform — "
                   "container on Linux, apple-container on macOS 26+ ASi "
                   "when Apple `container` is installed, vm otherwise).")
@click.option("--force", is_flag=True, help="Overwrite existing file.")
@click.option("--scaffold", default=None,
              help="Use a scaffold template (e.g. openclaw).")
@click.option("--list-scaffolds", is_flag=True,
              help="List available scaffolds and exit.")
@click.option("--port", type=int, default=None,
              help="Host port to publish (scaffold-specific).")
def init(name: str | None, output: str, image: str, isolation: str | None,
         force: bool, scaffold: str | None, list_scaffolds: bool,
         port: int | None):
    """Scaffold a new agentcage config file."""
    from agentcage.config import default_isolation
    from agentcage.init import list_scaffolds as _list_scaffolds, render_config
    if isolation is None:
        isolation = default_isolation()

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

    content = render_config(name, image=image, isolation=isolation, scaffold=scaffold, port=port)
    dest.write_text(content)
    click.echo(f"Created {dest}")

    from agentcage.init import load_scaffold_meta, run_scaffold_setup, resolve_scaffold

    meta = load_scaffold_meta(scaffold) if scaffold else None
    if scaffold and meta:
        run_scaffold_setup(scaffold, name, str(dest), isolation=isolation)
        # Copy Containerfile and sibling build context files from scaffold
        scaffold_dir_path = resolve_scaffold(scaffold)
        if scaffold_dir_path is not None:
            for entry in meta.get("build", []):
                if "containerfile" in entry:
                    src_cf = scaffold_dir_path / entry["containerfile"]
                    if src_cf.is_file():
                        _stage_build_context(
                            src_cf.parent, dest.parent, clobber=False,
                        )
    scaffold_dir = resolve_scaffold(scaffold) if scaffold else None
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
@click.option("--isolation",
              type=click.Choice(["container", "vm", "apple-container"]),
              default=None,
              help="Isolation backend (default: auto-detect from platform).")
@click.option("--as-root", is_flag=True,
              help="Run the session as root inside the cage (debug only — "
                   "bypasses the cage's egress filter via CAP_NET_ADMIN). "
                   "Default is the cage workload's uid 1000 user. "
                   "NOTE: on apple-container the egress filter and secret "
                   "store share the cage's microVM, so --as-root can "
                   "disable iptables and read injected secrets — a known "
                   "limitation of the single-microVM architecture.")
@click.option("--time", "show_timing", is_flag=True,
              help="Echo per-phase wall times and print a summary on completion.")
@click.argument("extra_args", nargs=-1, type=click.UNPROCESSED)
def run(scaffold: str, project_dir: str | None, name: str | None,
        secrets: tuple[str, ...], verbose: bool, isolation: str | None,
        as_root: bool,
        show_timing: bool,
        extra_args: tuple[str, ...]):
    """Run a coding agent in a sandboxed cage.

    \b
    Examples:
      agentcage run claude-code
      agentcage run codex --project /path/to/repo
      agentcage run codex -s OPENAI_API_KEY=sk-...
      agentcage run claude-code --isolation vm
      agentcage run codex --name my-session -- codex --help
    """
    from agentcage.run import execute
    if show_timing:
        os.environ["AGENTCAGE_TIMING"] = "1"
    exit_code = execute(
        scaffold, project_dir=project_dir, name=name,
        secrets=secrets, extra_args=extra_args, verbose=verbose,
        isolation=isolation,
        as_root=as_root,
        show_timing=show_timing,
    )
    sys.exit(exit_code)


# ── cage group ────────────────────────────────────────────


@main.group(cls=AliasGroup, aliases={"ls": "list", "rm": "destroy", "ps": "list", "status": "list", "reload": "restart", "delete": "destroy", "describe": "show", "inspect": "show", "config": "edit"})
def cage():
    """Manage cages."""


@cage.command("create")
@click.option("-c", "--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("-s", "--set-secret", "secrets", multiple=True,
              help="Set a secret (KEY=VALUE or KEY to prompt). Repeatable.")
@click.option("--no-cache", is_flag=True,
              help="Force a full image rebuild (ignore podman's layer cache).")
@click.option("--pull", is_flag=True,
              help="Force re-pull of the base image from the registry.")
@click.option("--time", "show_timing", is_flag=True,
              help="Echo per-phase wall times and print a summary on completion.")
def cage_create(config_path: str, secrets: tuple, no_cache: bool, pull: bool,
                show_timing: bool):
    """Build images, generate quadlets, install, and start a new cage."""
    from agentcage import output as _out
    from agentcage import _timing
    _out.banner(version("agentcage"))

    if show_timing:
        os.environ["AGENTCAGE_TIMING"] = "1"

    try:
        cfg = load_config(config_path)
    except ValueError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
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
    from agentcage.init import infer_scaffold_from_image
    metadata = {"agentcage_version": version("agentcage")}
    scaffold_name = infer_scaffold_from_image(cfg.container.image)
    if scaffold_name:
        metadata["scaffold"] = scaffold_name
    state.save_metadata(name, metadata)

    # Copy the Containerfile and its sibling build inputs into the state dir
    # so cage update can rebuild (Containerfiles may COPY files and whole
    # directory trees from the build context)
    if cfg.container.build.containerfile:
        src_cf = Path(config_path).parent / cfg.container.build.containerfile
        if src_cf.is_file():
            _stage_build_context(src_cf.parent, state.deployment_dir(name))

    # Set secrets passed via --set-secret (before build so they're available)
    if secrets:
        # For VM mode, secrets are set after the VM starts (in _deploy_cage).
        # For container mode, set them now on the host.
        if cfg.isolation == "container":
            from agentcage.secret_resolver import detect_default_backend, encrypt_secret
            podman_secrets = Podman()
            default_backend = detect_default_backend()
            for spec in secrets:
                if "=" in spec:
                    key, val = spec.split("=", 1)
                else:
                    key = spec
                    val = click.prompt(f"Value for {key}", hide_input=True)
                # Route to systemd-creds if rule or default calls for it
                rule = next((r for r in cfg.secret_injection if r.env == key), None)
                source_scheme = ""
                if rule and rule.source:
                    source_scheme = rule.source.partition(":")[0]
                if source_scheme == "podman":
                    use_creds = False  # operator explicitly asked for Podman store
                else:
                    use_creds = (source_scheme == "systemd-creds"
                                 or (not source_scheme and default_backend == "systemd-creds"))
                if use_creds:
                    from agentcage.secret_resolver import resolve_scope
                    try:
                        scope = resolve_scope(cfg.secrets.scope)
                        encrypt_secret(
                            key, val, state.deployment_dir(name), scope=scope,
                        )
                        click.echo(
                            f"Secret '{key}' encrypted with systemd-creds "
                            f"({scope}-scope)."
                        )
                        continue
                    except ValueError as e:
                        click.echo(f"warning: systemd-creds encrypt failed: {e}", err=True)
                        click.echo("Falling back to Podman store.", err=True)
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

    # Resolve env: and cmd: source secrets (container mode only)
    if cfg.isolation == "container":
        from agentcage.secret_resolver import resolve_and_populate
        resolve_and_populate(
            Podman(), cfg, name, state.deployment_dir(name),
        )

    config_host_path = state.save_proxy_config(name)
    state.save_dns_allowlist(name)

    # Build from Containerfile if configured (container mode only)
    if cfg.isolation == "container" and cfg.container.build.containerfile:
        with _timing.Phase("build.cage", cage=name):
            _build_container_image(cfg, Path(config_path).parent, podman, no_cache=no_cache, pull=pull)

    # Pull image on host (container mode) — VM mode pulls inside the VM
    if cfg.isolation == "container":
        click.echo(f"Pulling {cfg.container.image}...")
        with _timing.Phase("pull.cage", cage=name):
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
        if show_timing:
            _timing.print_summary(name)
        raise

    click.echo()
    click.echo("Logs:")
    click.echo(f"  agentcage cage logs {name}")

    if cfg.help:
        click.echo()
        click.echo(cfg.help.rstrip())

    if show_timing:
        _timing.print_summary(name)


@cage.command("update")
@click.argument("name", required=False)
@click.option("-c", "--config", "config_path", type=click.Path(exists=True))
@click.option("--no-cache", is_flag=True,
              help="Force a full image rebuild (ignore podman's layer cache). "
                   "Use after pulling a fresh agentcage release that changed "
                   "the Containerfile or any of its build context.")
@click.option("--pull", is_flag=True,
              help="Force re-pull of the base image from the registry "
                   "(--pull=always). Combine with --no-cache for a fully "
                   "clean rebuild.")
def cage_update(name: str | None, config_path: str | None,
                no_cache: bool, pull: bool):
    """Rebuild and restart an existing cage.

    NAME is optional when ``-c`` is given — the cage to update is taken
    from the config's ``name:`` field. Mirrors ``cage create``, which
    has never required a positional NAME for the same reason.
    """
    if name is None and config_path is None:
        click.echo(
            "error: either NAME or -c/--config is required (the cage to "
            "update must be identifiable)",
            err=True,
        )
        sys.exit(1)

    if config_path:
        try:
            cfg = load_config(config_path)
        except ValueError as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(1)
        try:
            warnings = validate_config(cfg)
        except ValueError as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(1)
        for w in warnings:
            click.echo(f"warning: {w}", err=True)
        if name is None:
            name = cfg.name
        elif cfg.name != name:
            click.echo(
                f"error: config name '{cfg.name}' does not match cage '{name}'",
                err=True,
            )
            sys.exit(1)
        if not state.deployment_exists(name):
            click.echo(f"error: cage '{name}' does not exist", err=True)
            sys.exit(1)
        _ensure_v022_cage(name)
        state.save_deployment(name, config_path)
        # Copy the Containerfile and its sibling build inputs into the state
        # dir so future updates can rebuild (Containerfiles may COPY files
        # and whole directory trees from the build context)
        if cfg.container.build.containerfile:
            src_cf = Path(config_path).parent / cfg.container.build.containerfile
            if src_cf.is_file():
                _stage_build_context(src_cf.parent, state.deployment_dir(name))
    else:
        if not state.deployment_exists(name):
            click.echo(f"error: cage '{name}' does not exist", err=True)
            sys.exit(1)
        _ensure_v022_cage(name)
        # Auto-resolve latest image tags for stored configs
        from agentcage.init import (
            infer_scaffold_from_image,
            load_scaffold_meta,
        )
        from agentcage.registry import resolve_build_args, resolve_latest_tag

        raw = state.load_raw_config(name)

        # Resolve the scaffold name for this cage. Precedence:
        #   1. metadata.json "scaffold" (populated by cage create / run)
        #   2. raw.get("scaffold") (legacy inline field)
        #   3. infer from container.image naming convention
        stored_meta = state.load_metadata(name) or {}
        scaffold_name = (
            stored_meta.get("scaffold")
            or raw.get("scaffold", "")
            or infer_scaffold_from_image(raw.get("container", {}).get("image", ""))
            or ""
        )

        # Top-level container.image — skip scaffold-built local images
        # (e.g. "localhost/agentcage-scaffold-openclaw:latest") since those
        # are never in a real registry.
        current_image = raw.get("container", {}).get("image", "")
        image_base, _, current_tag = current_image.rpartition(":")
        if image_base and current_tag and not image_base.startswith("localhost/"):
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

        # Build args — scaffold.yaml declaration is authoritative.
        # Untagged-in-scaffold ⇒ auto-bump on every update (tracks upstream).
        # Tagged-in-scaffold   ⇒ respected (author pinned on purpose).
        # User-added args      ⇒ resolved once if untagged, then respected.
        scaffold_declared_args: dict[str, str] = {}
        if scaffold_name:
            scaffold_meta = load_scaffold_meta(scaffold_name) or {}
            for entry in scaffold_meta.get("build", []):
                scaffold_declared_args.update(entry.get("build_args") or {})

        build_raw = raw.get("container", {}).get("build", {})
        stored_args = build_raw.get("args") or {}
        resolved_args, changes = resolve_build_args(
            stored_args, scaffold_declared_args,
        )
        for key, old, new in changes:
            click.echo(f"Build arg {key}: {old} \u2192 {new}")
            old_base = old.rsplit(":", 1)[0]
            new_base = new.rsplit(":", 1)[0]
            if old_base != new_base:
                click.echo(
                    f"warning: base image for {key} changed "
                    f"({old_base} \u2192 {new_base}) \u2014 scaffold updated "
                    f"upstream reference",
                    err=True,
                )
        if changes:
            raw.setdefault("container", {}).setdefault("build", {})["args"] = resolved_args
            state.save_raw_config(name, raw)

        # Refresh scaffold build artifacts and command if scaffold is known
        if scaffold_name:
            from agentcage.init import resolve_scaffold, render_config

            scaffold_dir = resolve_scaffold(scaffold_name)
            if scaffold_dir is not None:
                # Copy fresh Containerfile + sibling build inputs (files and
                # directory trees) from the scaffold
                _stage_build_context(scaffold_dir, state.deployment_dir(name))

                # Re-render scaffold template and patch command + new env vars
                try:
                    import yaml
                    rendered = render_config(name, scaffold=scaffold_name)
                    scaffold_cfg = yaml.safe_load(rendered) or {}
                    scaffold_container = scaffold_cfg.get("container", {})

                    # Update command
                    new_cmd = scaffold_container.get("command")
                    old_cmd = raw.get("container", {}).get("command")
                    if new_cmd and new_cmd != old_cmd:
                        raw.setdefault("container", {})["command"] = new_cmd
                        click.echo(f"Command updated from scaffold")

                    # Merge new env vars (additive — never remove user's vars)
                    scaffold_env = scaffold_container.get("env", {})
                    stored_env = raw.get("container", {}).get("env", {})
                    for key, val in scaffold_env.items():
                        if key not in stored_env:
                            stored_env[key] = val
                            click.echo(f"Added env: {key}")
                    if stored_env:
                        raw.setdefault("container", {})["env"] = stored_env

                    state.save_raw_config(name, raw)
                except Exception as e:
                    click.echo(
                        f"warning: could not refresh scaffold: {e}",
                        err=True,
                    )

        cfg = state.load_deployment_config(name)
        try:
            warnings = validate_config(cfg)
        except ValueError as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(1)
        for w in warnings:
            click.echo(f"warning: {w}", err=True)

    # Merge into existing metadata so scaffold/network_octet/etc. survive updates
    meta = state.load_metadata(name) or {}
    meta["agentcage_version"] = version("agentcage")
    state.save_metadata(name, meta)
    config_host_path = state.save_proxy_config(name)
    state.save_dns_allowlist(name)

    podman = Podman()

    # Check secrets against the store that actually backs this cage.
    # The container backend keeps secrets on host Podman. The VM backend
    # keeps them inside the VM's Podman — querying host Podman there
    # always reports "missing" and blocks every cage update on Linux
    # hosts that have podman installed. The apple-container backend
    # reads pending_secrets.json at start(), so existence on disk is
    # what counts; check_secrets's host-Podman path can't see that.
    missing: list[str] = []
    if cfg.isolation == "container":
        missing = _check_secrets(podman, name, cfg)
    elif cfg.isolation == "vm":
        inst = LimaInstance(name)
        if inst.is_running():
            from agentcage.lima.podman import VmPodman
            missing = _check_secrets(VmPodman(name), name, cfg)
        # VM is stopped: backend.start() will recreate any pending
        # secrets from pending_secrets.json before services come up,
        # so a stopped VM is not a "missing secrets" condition.
    elif cfg.isolation == "apple-container":
        from agentcage import state as _state
        pending = _state.deployment_dir(name) / "pending_secrets.json"
        if pending.is_file():
            try:
                provided = {
                    k for k, _ in json.loads(pending.read_text())
                }
            except Exception:
                provided = set()
        else:
            provided = set()
        from agentcage.services import expected_secrets
        missing = [k for k in expected_secrets(cfg) if k not in provided]
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
        _build_container_image(cfg, config_dir, podman, no_cache=no_cache, pull=pull)

    # Pull image on host (container mode) — VM mode pulls inside the VM
    if cfg.isolation == "container":
        click.echo(f"Pulling {cfg.container.image}...")
        if not podman.pull(cfg.container.image):
            click.echo(
                f"warning: pull failed for {cfg.container.image} "
                f"(local image or no network — continuing with cached image)",
                err=True,
            )

    # Preserve the cage's existing network octet across updates. The podman
    # network was created at cage-create time with the originally-assigned
    # subnet; re-deriving from the hash here (which can land on a different
    # octet if create-time collision resolution shifted it) would generate
    # quadlets whose static IPs don't fall in `<name>-net` and the DNS
    # sidecar would refuse to start with:
    #   "requested static ip 10.89.X.10 not in any subnet on network <name>-net"
    # See: https://github.com/agentcage/agentcage/issues/... (cage update
    # regenerated quadlets with a fresh octet on single-cage systems).
    from agentcage.quadlets import collect_used_octets as _collect_update
    _existing_meta = state.load_metadata(name) or {}
    _existing_octet = _existing_meta.get("network_octet")
    _build_and_deploy(
        cfg,
        config_host_path,
        name,
        podman,
        used_octets=_collect_update(exclude=name),
        network_octet=_existing_octet,
    )
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

        # Don't run is_running against a v0.21 cage — its containers have
        # the legacy {name}-proxy / {name}-dns names which the v0.22
        # backend's service_names() no longer knows about, so the check
        # would mislabel a still-running v0.21 cage as "stopped (0/2)".
        ver = meta.get("agentcage_version") or "0.0.0"
        if _parse_version(ver) < (0, 22):
            status = "(legacy v0.21 — destroy + recreate)"
            click.echo(f"{name:<25} {lifecycle:<14} {isolation:<12} "
                       f"{scaffold_name:<15} {status}")
            continue

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
        # Skip v0.21 cages — `is_running` would query against the new
        # 2-service shape and mislabel still-running legacy cages as
        # prune candidates. The operator must `cage destroy` them
        # explicitly (see `_ensure_v022_cage`).
        ver = meta.get("agentcage_version") or "0.0.0"
        if _parse_version(ver) < (0, 22):
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
    _ensure_v022_cage(name)

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
    elif _is_apple_container(cfg):
        _verify_apple_container(name, _pass, _fail, _warn)
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


def _verify_apple_container(name: str, _pass, _fail, _warn):
    """Apple-container probes: CA cert, dnsmasq DNS, egress filter.

    Service-status (is the cage `running`?) was already checked in the
    backend-agnostic block above; this only adds the inside-the-cage
    invariants that mean the supervisor wired itself up correctly.

    Each check execs `container exec <cage> ...` via Apple's CLI and
    inspects the exit code / output. Failures don't abort the verify
    run — every check independently reports PASS/FAIL/WARN.
    """
    from agentcage.apple_container import cli as ac_cli

    binary = ac_cli.container_binary()
    if binary is None:
        _warn(
            "Apple `container` CLI not found; install from "
            "https://github.com/apple/container/releases"
        )
        return

    def _exec(argv: list[str]) -> tuple[int, str]:
        """`container exec <name> <argv>` returning (exit, combined output).

        Run via subprocess.run (not os.execvp like the cage_exec
        command, which replaces the process) — verify is a query, not
        a hand-off.
        """
        cp = subprocess.run(
            [binary, "exec", name, *argv],
            capture_output=True, text=True, check=False,
        )
        return cp.returncode, (cp.stdout + cp.stderr).strip()

    # -- 1. CA cert at /certs/mitmproxy-ca-cert.pem (mirrored at stage 60)
    click.echo()
    click.echo("-- CA Certificate --")
    ec, _ = _exec(["test", "-f", "/certs/mitmproxy-ca-cert.pem"])
    if ec == 0:
        _pass("mitmproxy CA cert exists at /certs/mitmproxy-ca-cert.pem")
    else:
        _fail("mitmproxy CA cert NOT found at /certs/mitmproxy-ca-cert.pem")

    # -- 2. /etc/resolv.conf points to local dnsmasq (stage 70)
    click.echo()
    click.echo("-- DNS routing --")
    ec, out = _exec(["cat", "/etc/resolv.conf"])
    if ec == 0 and "nameserver 127.0.0.1" in out:
        _pass("/etc/resolv.conf points to local dnsmasq (127.0.0.1)")
    else:
        _fail(
            f"/etc/resolv.conf does NOT route to local dnsmasq "
            f"(got: {out!r})"
        )

    # -- 3. Egress filtering: blocked domain returns 403 from mitmproxy
    # Use a fixed domain that should never be in any cage's allowlist;
    # mitmproxy's allowlist_addon should respond with 403.
    click.echo()
    click.echo("-- Egress Filtering --")
    ec, _ = _exec(["which", "curl"])
    if ec != 0:
        _warn(
            "curl not in cage image — cannot probe egress filtering "
            "(consider installing curl in the user image to enable "
            "this check)"
        )
    else:
        # `-w '%{http_code}'` prints the HTTP status to stdout; `-o
        # /dev/null` discards the body; `--max-time 5` caps the probe.
        ec, status = _exec([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", "5",
            "https://evil-exfil-server.io",
        ])
        if status == "403":
            _pass(
                "Blocked domain (evil-exfil-server.io) is denied "
                "(HTTP 403 from mitmproxy)"
            )
        elif status in ("000", ""):
            # Connection refused / timeout — also a pass (the proxy or
            # iptables dropped it); just less informative.
            _pass(
                f"Blocked domain (evil-exfil-server.io) is denied "
                f"(HTTP {status or '000'})"
            )
        else:
            _fail(
                f"Blocked domain returned HTTP {status} — egress "
                f"filtering may be broken"
            )


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
    for svc in ["cage", "egress"]:
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


@cage.command("restart")
@click.argument("name")
def cage_restart(name: str):
    """Restart services without rebuilding images."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    _ensure_v022_cage(name)

    cfg = state.load_deployment_config(name)

    # Re-copy patch files from package data to overwrite any tampering.
    # The apple-container backend doesn't use host-side nested-container
    # patch files (the cage runs as a single Apple microVM with no
    # bind-mounted podman shim), so skip this on apple-container —
    # instantiating Podman() would crash later when its methods shell
    # out to a missing host podman.
    if not _is_apple_container(cfg):
        _ensure_patches(Podman())

    _restart_cage(name, cfg)
    click.echo(f"Restarted cage '{name}'")


# Fields the proxy hot-reloads via mtime polling on proxy-config.yaml.
# A change here only needs `save_proxy_config()` — no cage restart.
_PROXY_HOT_RELOAD_KEYS = frozenset({
    "max_request_body", "entropy", "content_type", "inspectors",
    "rate_limit", "logging", "secret_injection", "capture", "protocol_relays",
})

# Fields that need a destroy + recreate (image rebuild, network changes, etc).
_REBUILD_KEYS = frozenset({"isolation", "vm"})


def _yaml_dump(raw: dict) -> str:
    """Render a raw config dict as YAML with the project's conventions."""
    import yaml
    return yaml.safe_dump(raw, default_flow_style=False, sort_keys=False)


def _classify_changes(before: dict, after: dict) -> tuple[set[str], set[str], set[str]]:
    """Bucket top-level config-key changes into (live, restart, rebuild) sets.

    - live: applied in-place without a cage restart (domains via SIGHUP,
      proxy keys via mtime polling).
    - restart: needs `agentcage cage restart NAME` to take effect.
    - rebuild: needs `agentcage cage destroy + create` (image, isolation).
    """
    changed = {
        k for k in set(before) | set(after)
        if before.get(k) != after.get(k)
    }
    live: set[str] = set()
    restart: set[str] = set()
    rebuild: set[str] = set()
    for k in changed:
        if k == "domains":
            live.add(k)
        elif k in _PROXY_HOT_RELOAD_KEYS:
            live.add(k)
        elif k in _REBUILD_KEYS:
            rebuild.add(k)
        else:
            restart.add(k)
    return live, restart, rebuild


@cage.command("edit")
@click.argument("name")
def cage_edit(name: str):
    """Edit a cage's stored config in $EDITOR, with validation and safe save.

    Unlike `$EDITOR ~/.config/agentcage/cages/NAME/cage.yaml`, this command:

      - Validates the edited YAML before saving (rejected edits are written
        to cage.yaml.rejected so you don't lose them).
      - Writes atomically (temp file + rename) so a crash mid-edit cannot
        corrupt your cage state.
      - Backs up the previous good config to cage.yaml.bak.
      - Shows a unified diff of what changed.
      - Auto-applies domain changes via dnsmasq SIGHUP (no cage restart).
      - Tells you exactly which next command will pick up other changes.
    """
    import difflib
    import yaml

    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    _ensure_v022_cage(name)

    state_dir = state.deployment_dir(name)
    config_path = state_dir / "cage.yaml"
    rejected_path = state_dir / "cage.yaml.rejected"
    backup_path = state_dir / "cage.yaml.bak"

    original_text = config_path.read_text()
    original_raw = state.load_raw_config(name)

    # click.edit returns the edited text when given `text=`, or None if the
    # user exited without saving / made no changes. We pass the text so we
    # can detect "no change" without depending on editor mtime semantics.
    edited_text = click.edit(text=original_text, extension=".yaml",
                             require_save=True)

    if edited_text is None or edited_text == original_text:
        click.echo(f"No changes to cage '{name}'.")
        return

    # Parse edited content. Any YAML error → reject, preserve original.
    try:
        edited_raw = yaml.safe_load(edited_text)
    except yaml.YAMLError as e:
        rejected_path.write_text(edited_text)
        loc = getattr(e, "problem_mark", None)
        where = f" at line {loc.line + 1}, column {loc.column + 1}" if loc else ""
        problem = getattr(e, "problem", None) or str(e)
        click.echo(f"error: edited config is not valid YAML{where}: {problem}",
                   err=True)
        click.echo(f"  Rejected edits saved to {rejected_path}", err=True)
        click.echo(f"  Original config at {config_path} is unchanged.", err=True)
        sys.exit(1)

    if not isinstance(edited_raw, dict):
        rejected_path.write_text(edited_text)
        click.echo("error: edited config must be a YAML mapping at the top level",
                   err=True)
        click.echo(f"  Rejected edits saved to {rejected_path}", err=True)
        click.echo(f"  Original config at {config_path} is unchanged.", err=True)
        sys.exit(1)

    # Don't allow renaming a cage via `cage edit` — that requires state
    # directory moves, podman secret renames, quadlet rewrites, and is
    # outside this command's contract.
    orig_name = original_raw.get("name")
    new_name = edited_raw.get("name")
    if orig_name != new_name:
        rejected_path.write_text(edited_text)
        click.echo(
            f"error: renaming a cage via 'cage edit' is not supported "
            f"(cage.yaml 'name' changed from '{orig_name}' to '{new_name}')",
            err=True)
        click.echo(f"  Rejected edits saved to {rejected_path}", err=True)
        click.echo(f"  Original config at {config_path} is unchanged.", err=True)
        sys.exit(1)

    # Re-render so we can validate via the real loader (writes to a tempfile
    # because load_config takes a path, not a dict).
    rendered = _yaml_dump(edited_raw)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, dir=str(state_dir)
    ) as tf:
        tmp_validate_path = Path(tf.name)
        tf.write(rendered)
    try:
        try:
            cfg = load_config(str(tmp_validate_path))
            warnings = validate_config(cfg)
        except ValueError as e:
            rejected_path.write_text(edited_text)
            click.echo(f"error: edited config failed validation: {e}", err=True)
            click.echo(f"  Rejected edits saved to {rejected_path}", err=True)
            click.echo(f"  Original config at {config_path} is unchanged.",
                       err=True)
            sys.exit(1)
    finally:
        tmp_validate_path.unlink(missing_ok=True)

    for w in warnings:
        click.echo(f"warning: {w}", err=True)

    # Show a unified diff of the change before writing.
    diff = "".join(difflib.unified_diff(
        original_text.splitlines(keepends=True),
        rendered.splitlines(keepends=True),
        fromfile=f"{name}/cage.yaml (before)",
        tofile=f"{name}/cage.yaml (after)",
    ))
    if diff:
        click.echo(diff, nl=False)

    # Clear any stale rejected file from a prior failed edit — we now have
    # a good edit superseding it.
    rejected_path.unlink(missing_ok=True)

    # Atomic write: temp + fsync + rename. Backup the previous good file
    # first so a crash between rename and "all done" still leaves the
    # operator able to recover.
    shutil.copy2(config_path, backup_path)
    fd, tmp_name = tempfile.mkstemp(dir=str(state_dir), prefix=".cage.yaml.",
                                    suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(rendered)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, config_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    # Persist the proxy-side subset (always — even if nothing in
    # _PROXY_KEYS changed, this is cheap and keeps proxy-config.yaml in
    # lockstep with cage.yaml).
    state.save_proxy_config(name)

    live, restart_keys, rebuild_keys = _classify_changes(original_raw, edited_raw)

    if "domains" in live:
        _update_dns_quadlet(cfg)

    # Tell the operator what just happened and what (if anything) they
    # still need to do. Be specific about which fields fall into which
    # bucket so the next command is obvious.
    click.echo(f"Updated cage '{name}'. Backup at {backup_path}.")
    if live:
        applied = sorted(live)
        click.echo(f"  Live-applied: {', '.join(applied)}")
    if restart_keys:
        keys = sorted(restart_keys)
        click.echo(f"  Needs restart ({', '.join(keys)}): "
                   f"agentcage cage restart {name}")
    if rebuild_keys:
        keys = sorted(rebuild_keys)
        click.echo(f"  Needs rebuild ({', '.join(keys)}): "
                   f"agentcage cage update {name} (or destroy + create)")


@cage.command("stop")
@click.argument("name")
def cage_stop(name: str):
    """Stop a running cage without destroying it."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    _ensure_v022_cage(name)

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
    _ensure_v022_cage(name)

    cfg = state.load_deployment_config(name)

    # Host-podman-backed steps are skipped on apple-container: there's
    # no host podman to instantiate, no host-side patches to refresh,
    # and no host podman secret store to (re)populate. Secrets for the
    # apple-container backend are env-passed by `start` itself.
    if not _is_apple_container(cfg):
        podman = Podman()
        _ensure_patches(podman)

        # Refresh env:/cmd: secrets before starting (they may have changed)
        from agentcage.secret_resolver import resolve_and_populate
        resolve_and_populate(podman, cfg, name, state.deployment_dir(name))

        # Regenerate derived files from cage.yaml so any edits made while
        # the cage was stopped are applied on the next start. The dns
        # allowlist is a sidecar file mounted into dnsmasq; the quadlet
        # itself only needs rewriting on the (rare) migration case.
        state.save_proxy_config(name)
        state.save_dns_allowlist(name)
        _ensure_dns_quadlet_current(cfg)

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
    _ensure_v022_cage(name)

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

    # Secrets — host podman is the secret store, so skip the count on
    # apple-container (which has no host podman) rather than crash.
    if _is_apple_container(cfg):
        expected = _expected_secrets(cfg)
        if expected:
            click.echo(f"Secrets:    {len(expected)} expected (status not tracked on apple-container)")
    else:
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
              type=click.Choice(["cage", "egress"]))
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
    _ensure_v022_cage(name)

    cfg = state.load_deployment_config(name)
    selected = services or ("cage", "egress")

    no_follow_effective = not follow

    if cfg.isolation == "vm":
        _logs_vm(name, selected, lines, no_follow_effective, min_level)
    elif _is_apple_container(cfg):
        _logs_apple_container(name, selected, lines, no_follow_effective, min_level)
    else:
        _logs_container(name, selected, lines, no_follow_effective, min_level)


def _classify_line(service: str, line: str) -> str:
    """Classify a log line's severity for container-mode filtering.

    The ``egress`` service is the combined mitmproxy + dnsmasq container
    (v0.22 unified shape) — its log stream carries both inspector decision
    JSON (from mitmproxy) and dnsmasq query/reply lines. The classifier
    is the union of the two pre-unification severity heuristics; falling
    through to "info" matches the legacy ``dns`` branch's default.
    """
    if service == "egress":
        if '"decision":"blocked"' in line or '"decision": "blocked"' in line:
            return "warning"
        if '"decision":"flagged"' in line or '"decision": "flagged"' in line:
            return "warning"
        if '"decision":"allowed"' in line or '"decision": "allowed"' in line:
            return "info"
        low = line.lower()
        if "error" in low or "traceback" in low:
            return "error"
        for pat in ("refused", "servfail"):
            if pat in low:
                return "error"
        for pat in ("query[", "reply", "cached", "forwarded"):
            if pat in low:
                return "debug"
        return "info"
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
    # Quadlets run as systemd --user units, but conmon writes their logs to
    # the system journal — so query via --user-unit. Lima's persistent SSH
    # ControlMaster is established before provisioning runs `usermod -aG
    # systemd-journal`, so the SSH session lacks the group; `sg` adds it
    # for the journalctl process.
    units = [f"{name}-{svc}" for svc in services]
    inner = ["journalctl"]
    for u in units:
        inner += ["--user-unit", u]
    inner += ["-n", str(lines), "-o", "cat"]
    if not no_follow:
        inner.append("-f")

    # --workdir / suppresses the spurious "cd: <host-cwd>: No such file or
    # directory" warning when the host's cwd isn't mounted in the VM. The
    # LimaInstance.exec helper does this already but this code path bypasses
    # it (uses os.execvp), so the flag has to be inlined here too.
    full_cmd = ["limactl", "shell", "--workdir", "/", inst.name, "--",
                "sg", "systemd-journal", "-c", shlex.join(inner)]
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


def _logs_apple_container(name, services, lines, no_follow, min_level=None):  # noqa: ARG001
    """Stream logs from the per-cage Apple container.

    Apple's `container logs` reads the supervisor's stdout/stderr for the
    one microVM that backs the cage. There are no separate proxy/dns
    journal units to filter on — those run as processes inside the same
    container — so the ``services`` and ``min_level`` arguments are
    accepted for parity with the other backends but currently don't
    sub-filter output. The user gets the full combined stream.
    """
    from agentcage.apple_container import cli as ac_cli
    binary = ac_cli.container_binary()
    if binary is None:
        click.echo(
            "error: Apple `container` CLI not found; install from "
            "https://github.com/apple/container/releases",
            err=True,
        )
        sys.exit(1)
    argv = [binary, "logs"]
    if not no_follow:
        argv.append("-f")
    argv.append(name)
    os.execvp(binary, argv)


@cage.command("exec", context_settings={"ignore_unknown_options": True})
@click.argument("name")
@click.option("-s", "--service", default="cage",
              type=click.Choice(["cage", "egress"]),
              help="Container service to exec into.", show_default=True)
@click.option("--as-root", is_flag=True,
              help="Run the command as root inside the cage (debug only — "
                   "bypasses the cage's egress filter via CAP_NET_ADMIN). "
                   "Default is the cage workload's uid 1000 user. "
                   "NOTE: on apple-container the egress filter and secret "
                   "store share the cage's microVM, so --as-root can "
                   "disable iptables and read injected secrets — a known "
                   "limitation of the single-microVM architecture.")
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
def cage_exec(name: str, service: str, command: tuple[str, ...], as_root: bool):
    """Run a command inside a cage container.

    \b
    Example:
      agentcage cage exec myapp -- openclaw devices list
    """
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    _ensure_v022_cage(name)

    cfg = state.load_deployment_config(name)

    cmd = list(command)
    if not cmd:
        click.echo("error: no command specified", err=True)
        sys.exit(1)

    # Pre-flight: refuse to exec into a stopped cage. Without this the user
    # got a raw downstream error — `no container with name or ID "<name>-
    # cage" found` (podman, exit 125) or `instance "<name>" is stopped`
    # (limactl, exit 1) — which buries the actual problem (cage isn't
    # running). For VM cages also requires the Lima VM itself to be up;
    # `is_running` returns false when the VM is shut down (the cage service
    # check goes via systemctl which needs the VM running).
    backend = get_backend(cfg)
    try:
        cage_active = backend.is_running(name, "cage")
    except Exception:
        cage_active = False
    if not cage_active:
        click.echo(
            f"error: cage '{name}' is not running — "
            f"start it with 'agentcage cage start {name}' first",
            err=True,
        )
        sys.exit(1)

    # Alias expansion: if the first word matches an exec_alias, expand it
    if cmd[0] in cfg.exec_aliases:
        cmd = cfg.exec_aliases[cmd[0]] + cmd[1:]

    # Dispatch via Backend.exec_argv (lifted onto the protocol in PR-8).
    # Each backend returns the argv that runs the command inside the
    # cage's <service>; the CLI owns the process control. The `as_root`
    # kwarg is honored by backends that need to gate root vs unprivileged
    # exec sessions (apple-container in particular — pre-this-fix every
    # cage exec was root because Apple's runtime respects the wrapper
    # image's USER directive, which is root so the supervisor can boot;
    # without an explicit -u override, claude / agent code ran as root
    # with CAP_NET_ADMIN). container / vm ignore the kwarg — their proxy
    # / dns / cage units already drop privileges per Quadlet.
    from agentcage.backend import BackendUnsupported
    backend = get_backend(cfg)
    try:
        argv = backend.exec_argv(
            name, service, cmd,
            interactive=sys.stdin.isatty(),
            as_root=as_root,
        )
    except BackendUnsupported as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)

    # vm and apple-container backends want exec semantics (replace the
    # current process); container backend's `podman exec` we run as a
    # subprocess and propagate the exit code. Distinguishing here keeps
    # the existing UX for both shapes — limactl shell + container exec
    # benefit from os.execvp's tty handling, while podman exec on Linux
    # has historically been run via subprocess.run.
    if cfg.isolation in ("vm", "apple-container"):
        os.execvp(argv[0], argv)
    result = subprocess.run(argv)
    sys.exit(result.returncode)


@cage.command("shell")
@click.argument("name")
@click.option("-s", "--service", default="cage",
              type=click.Choice(["cage", "egress"]),
              help="Container service to shell into.", show_default=True)
@click.option("--as-root", is_flag=True,
              help="Open the shell as root (debug only — bypasses the "
                   "cage's egress filter via CAP_NET_ADMIN). Default is "
                   "the cage workload's uid 1000 user. "
                   "NOTE: on apple-container the egress filter and secret "
                   "store share the cage's microVM, so --as-root can "
                   "disable iptables and read injected secrets — a known "
                   "limitation of the single-microVM architecture.")
def cage_shell(name: str, service: str, as_root: bool):
    """Open an interactive shell in a cage container."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    _ensure_v022_cage(name)

    cfg = state.load_deployment_config(name)

    if cfg.isolation == "vm":
        inst = LimaInstance(name)
        container = f"{name}-{service}"
        # --workdir / on every `limactl shell` for the same reason as
        # _logs_vm and vm.exec_argv — host cwd isn't mounted, default cd
        # spews a "No such file or directory" before our command runs.
        # ``-u`` matches the security intent of the apple-container path
        # below: the cage Quadlet's ``User=`` may be empty (ubuntu
        # scaffold), so without an explicit ``-u`` ``podman exec``
        # inherits the image's USER (root on ubuntu:latest). gid is
        # pinned too — see ContainerBackend.exec_argv for rationale.
        spec = "0:0" if as_root else "1000:1000"
        # Auto-detect bash or fall back to sh inside the VM
        for shell in ("/bin/bash", "/bin/sh"):
            result = subprocess.run(
                ["limactl", "shell", "--workdir", "/", inst.name, "--",
                 "podman", "exec", "-u", spec, container, "test", "-x", shell],
                capture_output=True,
            )
            if result.returncode == 0:
                exec_flags = ["-it"] if sys.stdin.isatty() else []
                os.execvp("limactl", ["limactl", "shell", "--workdir", "/",
                          inst.name, "--",
                          "podman", "exec", "-u", spec, *exec_flags, container, shell])
        exec_flags = ["-it"] if sys.stdin.isatty() else []
        os.execvp("limactl", ["limactl", "shell", "--workdir", "/",
                  inst.name, "--",
                  "podman", "exec", "-u", spec, *exec_flags, container, "/bin/sh"])

    if _is_apple_container(cfg):
        _require_cage_service_on_apple_container(service, "shell")
        from agentcage.apple_container import cli as ac_cli
        binary = ac_cli.container_binary()
        if binary is None:
            click.echo(
                "error: Apple `container` CLI not found; install from "
                "https://github.com/apple/container/releases",
                err=True,
            )
            sys.exit(1)
        # Probes run as root so `test -x` can read setuid files that
        # uid 1000 might not.
        for shell in ("/bin/bash", "/bin/sh"):
            result = subprocess.run(
                [binary, "exec", name, "test", "-x", shell],
                capture_output=True,
            )
            if result.returncode == 0:
                chosen_shell = shell
                break
        else:
            chosen_shell = "/bin/sh"
        exec_flags = ["-it"] if sys.stdin.isatty() else []
        if as_root:
            # Operator debug path — image's USER (root on wrapper),
            # full cap set, NoNewPrivs=0. For apt-get install etc.
            os.execvp(binary, [binary, "exec", *exec_flags, name, chosen_shell])
        # Secure default — wrap in capsh exactly like the supervisor's
        # stage-90 privilege drop: NoNewPrivs=1 + drop=all (CapBnd=0)
        # + setuid to the uid-1000 user (resolved by name via getent;
        # capsh --user= takes a name, not a numeric uid). Closes the
        # setuid-binary-re-acquire-caps escalation that a plain `-u
        # 1000` would leave open (cage ships /usr/bin/su,
        # /usr/bin/mount, etc. setuid-root; without NoNewPrivs=1 a
        # kernel-side re-grant of CapBnd via setuid is the documented
        # escape path).
        inner = (
            "CAGE_USER=$(getent passwd 1000 | cut -d: -f1) && "
            "exec capsh --no-new-privs --drop=all "
            "--user=\"$CAGE_USER\" --shell=/bin/sh "
            f"-- -c 'exec {chosen_shell}'"
        )
        os.execvp(binary, [
            binary, "exec", "-u", "0", *exec_flags, name,
            "/bin/sh", "-c", inner,
        ])

    container = f"{name}-{service}"
    # ``-u`` matches the security intent of the apple-container path
    # above: the cage Quadlet's ``User=`` may be empty (ubuntu scaffold),
    # so without an explicit ``-u`` ``podman exec`` inherits the image's
    # USER (root on ubuntu:latest). gid is pinned too — see
    # ContainerBackend.exec_argv for rationale.
    spec = "0:0" if as_root else "1000:1000"
    # Auto-detect bash or fall back to sh
    for shell in ("/bin/bash", "/bin/sh"):
        result = subprocess.run(
            ["podman", "exec", "-u", spec, container, "test", "-x", shell],
            capture_output=True,
        )
        if result.returncode == 0:
            exec_flags = ["-it"] if sys.stdin.isatty() else []
            os.execvp("podman", ["podman", "exec", "-u", spec, *exec_flags, container, shell])
    # Fallback
    exec_flags = ["-it"] if sys.stdin.isatty() else []
    os.execvp("podman", ["podman", "exec", "-u", spec, *exec_flags, container, "/bin/sh"])


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


def _apple_container_audit_path(name: str) -> Path:
    """Host-side path to a cage's audit.jsonl, written by the apple-container
    supervisor's mitmproxy addon into /var/log/agentcage/audit.jsonl
    (which is bind-mounted from the per-cage state dir's logs/ subdir)."""
    from agentcage.backends.apple_container import AppleContainerBackend
    return AppleContainerBackend().logs_dir(name) / "audit.jsonl"


def _apple_container_capture_path(name: str) -> Path:
    """Host-side path to a cage's capture.jsonl (mitmproxy addon output)."""
    from agentcage.backends.apple_container import AppleContainerBackend
    return AppleContainerBackend().logs_dir(name) / "capture.jsonl"


def _build_audit_journal_cmd(
    name: str, cfg, *, since: str | None = None, follow: bool = False,
) -> list[str]:
    """Build the command for reading audit entries.

    Backend.audit_argv (lifted onto the protocol in PR-8) returns the
    backend-specific argv: journalctl for container, journalctl wrapped
    in `limactl shell` + `sg systemd-journal` for vm, `tail` of the
    host-bind-mounted audit.jsonl for apple-container. This function is
    now a thin wrapper that normalizes the `--since` value for the two
    backends that accept time-based filtering (apple-container's tail
    has no time index — filtering happens via AuditFilter post-parse).
    """
    backend = get_backend(cfg)
    normalized_since = _normalize_since(since) if since else None
    return backend.audit_argv(
        name, since=normalized_since, follow=follow,
    )


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
    _ensure_v022_cage(name)

    if summary and follow:
        click.echo("error: --summary and --follow are incompatible", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)

    # apple-container reads audit.jsonl from the per-cage logs dir
    # (bind-mounted from the microVM by `start()`); _build_audit_journal_cmd
    # below dispatches to a tail-based reader for this backend.
    if _is_apple_container(cfg):
        path = _apple_container_audit_path(name)
        if not path.is_file():
            click.echo(
                f"error: no audit log yet for cage '{name}'\n"
                f"  Expected: {path}\n"
                f"  Either the cage hasn't received any proxy traffic since "
                f"start, or it was last started before 0.20.6 (the audit-bridge "
                f"is wired only for cages created on 0.20.6+). Try:\n"
                f"    agentcage cage update {name}    # rebuild + restart",
                err=True,
            )
            sys.exit(1)

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
    _ensure_v022_cage(name)

    cfg = state.load_deployment_config(name)

    from agentcage.har import CaptureFilter, capture_to_har, parse_since

    # apple-container's capture.jsonl is host-visible via the bind-mounted
    # logs dir (0.20.6+); container/vm use the central state path.
    if _is_apple_container(cfg):
        capture_path = _apple_container_capture_path(name)
    else:
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


def _cage_backup_apple_container(
    name: str, cfg, output: str | None, include_secrets: bool,
) -> None:
    """Backup an apple-container cage to a tarball.

    Apple-container backup is a different shape than container/vm:
      - No host-podman secret store. Secrets are env-passed at start
        from os.environ. We CANNOT serialize their values (we don't
        know them after start). Manifest records the secret env names
        so the operator knows what to re-set on the restore host;
        --include-secrets is rejected with a clear message.
      - No podman named_volumes. Apple-container has no equivalent yet
        (it's in the silently-dropped knobs list, validated in PR-4).
        Backup manifest's `named_volumes` is always empty.
      - capture.jsonl + audit.jsonl live in the per-cage logs dir
        (host-bind-mounted from the microVM by PR-5). Include both
        when present.

    The resulting tarball restores via the unchanged cage_restore code
    path's apple-container branch (which also skips podman calls).
    """
    if include_secrets:
        click.echo(
            "error: --include-secrets is not supported on apple-container "
            "(secrets are env-passed at start from the host environment, "
            "not stored in a secret store; the backup manifest records the "
            "expected env names so you can re-set them on the restore host)",
            err=True,
        )
        sys.exit(1)

    from agentcage.backends.apple_container import AppleContainerBackend
    backend = AppleContainerBackend()
    logs_dir = backend.logs_dir(name)

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

        # ── Secret env names (no values) ──
        secret_envs = [r.env for r in (cfg.secret_injection or [])]
        if secret_envs:
            click.echo(
                f"Secrets not included (apple-container env-pass model). "
                f"After restore, re-set these on the host environment: "
                f"{', '.join(secret_envs)}",
            )

        # ── Capture ──
        has_capture = False
        capture_src = logs_dir / "capture.jsonl"
        if capture_src.is_file() and capture_src.stat().st_size > 0:
            cap_dir = staging_path / "capture"
            cap_dir.mkdir()
            shutil.copy2(str(capture_src), str(cap_dir / "capture.jsonl"))
            has_capture = True

        # ── Audit log ──
        has_audit = False
        audit_src = logs_dir / "audit.jsonl"
        if audit_src.is_file() and audit_src.stat().st_size > 0:
            audit_dir = staging_path / "audit"
            audit_dir.mkdir()
            shutil.copy2(str(audit_src), str(audit_dir / "audit.jsonl"))
            has_audit = True

        # ── Manifest ──
        manifest = {
            "format_version": 1,
            "agentcage_version": version("agentcage"),
            "cage_name": name,
            "isolation": "apple-container",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "has_secrets": bool(secret_envs),
            "has_capture": has_capture,
            "has_audit": has_audit,
            "named_volumes": [],  # not supported on apple-container
            "secret_keys": secret_envs,
            "secrets_included": False,
        }
        (staging_path / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )

        with tarfile.open(output, "w:gz") as tar:
            for item in staging_path.iterdir():
                tar.add(str(item), arcname=f"agentcage-backup/{item.name}")

    click.echo(f"Backup saved to {output}")
    click.echo(f"  Secrets: {len(secret_envs)} env names (values not stored — re-set on restore host)")
    click.echo(f"  Volumes: 0 (not supported on apple-container)")
    click.echo(f"  Capture: {'yes' if has_capture else 'no'}")
    click.echo(f"  Audit:   {'yes' if has_audit else 'no'}")


def _cage_restore_apple_container(
    tarball: str,
    manifest: dict,
    *,
    new_name: str | None,
    force: bool,
    no_start: bool,
) -> None:
    """Restore an apple-container cage from a backup tarball.

    Mirror of `_cage_backup_apple_container`: skip every host-podman
    code path (secret store, named volume import), copy capture.jsonl
    and audit.jsonl back into the per-cage logs dir, run `cage update`
    style build + start.
    """
    from agentcage.backends.apple_container import AppleContainerBackend

    target_name = new_name or manifest["cage_name"]
    if not re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', target_name):
        click.echo(
            "error: name must be 1-63 lowercase alphanumeric characters or "
            f"hyphens, starting with a letter or digit (got: {target_name!r})",
            err=True,
        )
        sys.exit(1)

    # Handle existing cage
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
            backend = AppleContainerBackend()
            backend.stop(target_name)
            backend.destroy_resources(target_name)
        if state.deployment_exists(target_name):
            state.remove_deployment(target_name)

    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(tarball, "r:gz") as tar:
            tar.extractall(tmpdir, filter="data")
        backup_dir = Path(tmpdir) / "agentcage-backup"

        # Warn about secrets the operator needs to re-set host-side.
        expected_keys = manifest.get("secret_keys", [])
        if expected_keys:
            click.echo(
                "Secrets are env-passed at start on apple-container — set "
                "these on the host environment before `cage start`:",
                err=True,
            )
            for k in expected_keys:
                click.echo(f"  export {k}=<value>", err=True)

        # Restore config
        config_src = backup_dir / "config"
        cage_yaml_src = config_src / "cage.yaml"
        if not cage_yaml_src.is_file():
            click.echo(
                "error: invalid backup — missing config/cage.yaml",
                err=True,
            )
            sys.exit(1)
        if new_name:
            with open(cage_yaml_src) as f:
                import yaml
                raw = yaml.safe_load(f)
            raw["name"] = new_name
            with open(cage_yaml_src, "w") as f:
                yaml.safe_dump(raw, f, default_flow_style=False, sort_keys=False)
        state.save_deployment(target_name, str(cage_yaml_src))

        meta_src = config_src / "metadata.json"
        if meta_src.is_file():
            deploy_dir = Path(state.stored_config_path(target_name)).parent
            shutil.copy2(str(meta_src), str(deploy_dir / "metadata.json"))

        # Regenerate derived files
        state.save_proxy_config(target_name)
        state.save_dns_allowlist(target_name)

        # Restore capture / audit into the per-cage logs dir BEFORE the
        # backend's start() recreates the dir (start chmods to 1777 but
        # preserves existing files).
        ac_backend = AppleContainerBackend()
        logs_dir = ac_backend.logs_dir(target_name)
        logs_dir.mkdir(parents=True, exist_ok=True)
        for sub in ("capture", "audit"):
            src = backup_dir / sub / f"{sub}.jsonl"
            if src.is_file():
                shutil.copy2(str(src), str(logs_dir / f"{sub}.jsonl"))

        if no_start:
            click.echo(
                f"Cage state restored. "
                f"Run: agentcage cage update {target_name} to build and start."
            )
            return

        cfg = state.load_deployment_config(target_name)
        # Build the wrapper image + start. We don't call `_build_and_deploy`
        # (container/vm path with host podman + quadlets); just exercise
        # the backend's own build + start directly.
        ac_backend.build_artifacts(cfg, target_name)
        ac_backend.generate_units(cfg, "", "", target_name)
        ac_backend.install_units(
            ac_backend.generate_units(cfg, "", "", target_name)
        )
        ac_backend.start(target_name)

    click.echo(f"Cage '{target_name}' restored from {tarball}")


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
    _ensure_v022_cage(name)

    cfg = state.load_deployment_config(name)
    if _is_apple_container(cfg):
        _cage_backup_apple_container(name, cfg, output, include_secrets)
        return
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

    if manifest.get("isolation") == "apple-container":
        _cage_restore_apple_container(
            tarball, manifest, new_name=new_name, force=force, no_start=no_start,
        )
        return

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

        # Regenerate derived files (proxy + dns allowlist)
        state.save_proxy_config(target_name)
        state.save_dns_allowlist(target_name)

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
    _ensure_v022_cage(name)
    cfg = state.load_deployment_config(name)
    if _is_apple_container(cfg):
        _exit_apple_container_unsupported("secret list")
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
    _ensure_v022_cage(name)
    cfg = state.load_deployment_config(name)
    if _is_apple_container(cfg):
        _exit_apple_container_unsupported("secret set")
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

    # Determine storage backend
    from agentcage.secret_resolver import detect_default_backend, encrypt_secret

    cfg = state.load_deployment_config(name)
    rule = next((r for r in cfg.secret_injection if r.env == key), None)
    source_scheme = ""
    if rule and rule.source:
        source_scheme = rule.source.partition(":")[0]

    backend = detect_default_backend()
    if source_scheme == "podman":
        use_creds = False  # operator explicitly asked for Podman store
    else:
        use_creds = (source_scheme == "systemd-creds"
                     or (not source_scheme and backend == "systemd-creds"))

    if use_creds:
        from agentcage.secret_resolver import resolve_scope
        try:
            scope = resolve_scope(cfg.secrets.scope)
            encrypt_secret(key, value, state.deployment_dir(name), scope=scope)
            # Remove any stale podman secret with the same name — the
            # ExecStartPre in the quadlet will repopulate it from the
            # encrypted blob at service start.
            if podman.secret_exists(full_name):
                podman.secret_remove(full_name)
            click.echo(
                f"Secret '{key}' encrypted with systemd-creds "
                f"({scope}-scope)."
            )
        except ValueError as e:
            click.echo(f"error: {e}", err=True)
            click.echo("Falling back to Podman secret store.", err=True)
            if podman.secret_exists(full_name):
                podman.secret_remove(full_name)
            podman.secret_create(full_name, value)
            click.echo(f"Secret '{full_name}' set (unencrypted).")
    else:
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
    _ensure_v022_cage(name)
    cfg = state.load_deployment_config(name)
    if _is_apple_container(cfg):
        _exit_apple_container_unsupported("secret rm")
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
    _ensure_v022_cage(name)

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


def _ensure_dns_quadlet_current(cfg) -> bool:
    """No-op in the v0.22 2-service shape.

    Kept as a callable so the cage-restart path's invocation site doesn't
    need a conditional. In the legacy 3-service shape this helper rendered
    a fresh ``<name>-dns.container`` quadlet and ``daemon-reload``-ed when
    the rendered content drifted from disk (e.g. after a pre-allowlist-
    sidecar upgrade). In the v0.22 shape the egress quadlet is the only
    DNS-bearing unit, its content is stable across domain edits (the
    allowlist lives in a bind-mounted sidecar file), and the file rewrite
    + SIGHUP fast path handled by :func:`_update_dns_quadlet` is sufficient.

    Always returns ``False`` so existing call sites that branch on a
    "quadlet was rewritten" return value (e.g. tests pinning the
    legacy-migration ``systemctl restart`` path) take the no-op branch.
    """
    return False


def _update_dns_quadlet(cfg) -> None:
    """Apply a domain-allowlist change to the egress container's dnsmasq.

    Rewrites the dns-allowlist sidecar and proxy-config files, then signals
    the running daemons to pick them up.

    Container + VM backend (live-reload, no cage restart):
      - dnsmasq runs inside the egress container with
        ``--servers-file=/etc/agentcage/dns-allowlist.conf`` and re-reads
        it on SIGHUP. We signal the dnsmasq PID directly via
        ``<runtime> exec <name>-egress kill -HUP "$(cat /home/acdns/dnsmasq.pid)"``
        (the supervisor writes the pid to ``/home/acdns/dnsmasq.pid`` —
        see ``supervisor-egress.sh`` step B; the path lives in acdns's
        pre-chowned home dir so dnsmasq can write it after setpriv drops
        to uid 201, without requiring CAP_CHOWN at runtime). ``kill -HUP
        <pid>`` rather than ``pkill -HUP dnsmasq`` because the supervisor
        uses ``setpriv --reuid=acdns`` so pkill from the supervisor's
        process tree finds nothing — the pidfile is the reliable handle.
      - The mitmproxy addon polls ``/etc/agentcage/config.yaml`` mtime on
        every request and hot-reloads inspectors in-place (see
        ``data/proxy/addon.py:_maybe_reload``). No signal needed.
      - Net effect: the cage container is untouched. Any interactive
        session inside it (e.g. ``agentcage run``) survives a domain
        add/rm.
      - The ``<runtime>`` is ``podman`` for the container backend and
        ``limactl shell -- podman`` for the VM backend; same SIGHUP shape
        either way, only the wrapper differs.

    VM backend extra: Lima's reverse-sshfs mount of ``~/.config/agentcage``
    caches host writes, so the egress quadlet bind-mounts a *VM-local*
    copy of the allowlist file (``~/.config/agentcage-vm/cages/<name>/``
    — outside any Lima mount). The host file is rewritten as the
    authoritative source-of-truth, then pushed into the VM-local path
    via ``inst.exec`` (base64 over the limactl ssh channel) before the
    SIGHUP.

    Apple-container backend:
      - Allowlist is baked into the wrapper image at build time, so a
        domain change requires rebuilding the image and restarting the
        cage. The observability bridge (see #120) is expected to add a
        bind-mounted allowlist path on apple-container, at which point
        this branch can collapse.

    Pre-flight validation: before publishing the rewritten allowlist we
    run ``dnsmasq --test --servers-file=<allowlist>`` inside the egress
    container; if it exits non-zero we revert the file to its previous
    contents and surface the parse error. This prevents a malformed
    user-supplied allowlist from breaking DNS resolution on the next
    SIGHUP (dnsmasq's re-read is best-effort and a parse error leaves
    the daemon serving the previous config silently).
    """
    backend = get_backend(cfg)
    name = cfg.name

    if _is_apple_container(cfg):
        # Image-bake path — keep the rebuild semantics.
        state.save_dns_allowlist(name)
        was_running = backend.is_running(name, "cage")
        if was_running:
            backend.stop(name)
        backend.build_artifacts(cfg, name, quiet=True)
        if was_running:
            backend.start(name, quiet=True)
        return

    # Container + VM: write the new file, validate inside the egress
    # container, SIGHUP dnsmasq. Backup the old contents in case
    # validation rejects the new ones.
    allow_path = state.dns_allowlist_path(name)
    previous = allow_path.read_text() if allow_path.is_file() else ""
    state.save_dns_allowlist(name)

    container = f"{name}-egress"

    def _runtime_exec(argv: list[str]):
        """Run *argv* inside the egress container via the right runtime
        wrapper. Returns a CompletedProcess (.returncode/.stdout/.stderr)."""
        if cfg.isolation == "vm":
            inst = LimaInstance(name)
            return inst.exec(["podman", "exec", container, *argv], check=False)
        return subprocess.run(
            ["podman", "exec", container, *argv],
            capture_output=True, text=True,
        )

    if cfg.isolation == "vm":
        inst = LimaInstance(name)
        if not inst.is_running():
            return
        from agentcage.backends.vm import push_config_files
        push_config_files(name, inst)

    if not backend.is_running(name, "egress"):
        # File rewrite is enough — the next start picks it up.
        return

    # Validate inside the egress container against the mounted path.
    result = _runtime_exec([
        "dnsmasq", "--test",
        "--servers-file=/etc/agentcage/dns-allowlist.conf",
    ])
    if result.returncode != 0:
        # Revert and surface the parse error.
        allow_path.write_text(previous)
        if cfg.isolation == "vm":
            # Restore the VM-local copy too — push_config_files reads
            # the host file, so re-pushing aligns the VM-local cache.
            from agentcage.backends.vm import push_config_files
            push_config_files(name, LimaInstance(name))
        click.echo(
            f"error: dnsmasq rejected the updated allowlist for cage "
            f"'{name}'; the previous configuration has been restored:",
            err=True,
        )
        err = (result.stderr or result.stdout or "").rstrip()
        if err:
            click.echo(err, err=True)
        sys.exit(1)

    # SIGHUP dnsmasq via the pidfile the supervisor writes. The path is
    # /home/acdns/dnsmasq.pid (pre-chowned dir, no runtime CAP_CHOWN
    # needed). The `cat || true` makes the path failure loud rather than
    # silent — bash's $(cat missing-file) returns empty, and `kill -HUP ""`
    # exits 0 with nothing happening, so a future path drift would
    # otherwise reproduce the silent-no-op bug this comment was added in
    # response to.
    _runtime_exec([
        "sh", "-c",
        'pid="$(cat /home/acdns/dnsmasq.pid)" && '
        '[ -n "$pid" ] && kill -HUP "$pid"',
    ])


@domain.command("add")
@click.argument("name")
@click.argument("domain_names", nargs=-1, required=True)
@click.option("--passthrough", is_flag=True,
              help="Also add to TLS passthrough list (no MITM interception).")
def domain_add(name: str, domain_names: tuple[str, ...], passthrough: bool):
    """Add one or more domains to a cage's filter list.

    Multiple domains may be passed; the cage is reloaded at most once.
    """
    try:
        raw = state.load_raw_config(name)
    except FileNotFoundError:
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)
    _ensure_v022_cage(name)

    _ensure_domain_section(raw)
    dom = raw["domains"]

    list_key = "allow" if "allow" in dom else "block" if "block" in dom else "allow"
    if list_key not in dom:
        dom[list_key] = []

    pt_note = " (passthrough)" if passthrough else ""
    changed = False
    messages: list[str] = []

    for domain_name in domain_names:
        already_in_list = domain_name in dom[list_key]
        already_passthrough = domain_name in dom.get("passthrough", [])

        if already_in_list and (not passthrough or already_passthrough):
            messages.append(f"'{domain_name}' is already in cage '{name}'.")
            continue

        if not already_in_list:
            dom[list_key].append(domain_name)
        if passthrough and not already_passthrough:
            if "passthrough" not in dom:
                dom["passthrough"] = []
            dom["passthrough"].append(domain_name)

        changed = True
        messages.append(f"Added '{domain_name}'{pt_note} to cage '{name}'.")

    if changed:
        state.save_raw_config(name, raw)
        state.save_proxy_config(name)

        cfg = state.load_deployment_config(name)
        _update_dns_quadlet(cfg)

        if get_backend(cfg).is_running(cfg.name, "cage"):
            messages.append("DNS and proxy updated.")

    for line in messages:
        click.echo(line)


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
    _ensure_v022_cage(name)

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


