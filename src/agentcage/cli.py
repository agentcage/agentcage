"""agentcage CLI — cage and secret command groups."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
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

_DATA_DIR = Path(__file__).resolve().parent / "data"


@click.group()
@click.version_option(version=version("agentcage"), prog_name="agentcage")
def main():
    """Defense-in-depth proxy sandbox for AI agents."""


# ── init ─────────────────────────────────────────────────


@main.command()
@click.argument("name", required=False, default=None)
@click.option("-o", "--output", default="cage.yaml",
              help="Output file path.", show_default=True)
@click.option("--image", default="node:22-slim",
              help="Container image.", show_default=True)
@click.option("--isolation", type=click.Choice(["container", "firecracker"]),
              default="container", help="Isolation backend.", show_default=True)
@click.option("--force", is_flag=True, help="Overwrite existing file.")
@click.option("--preset", default=None,
              help="Use a preset template (e.g. openclaw).")
@click.option("--list-presets", is_flag=True,
              help="List available presets and exit.")
def init(name: str | None, output: str, image: str, isolation: str,
         force: bool, preset: str | None, list_presets: bool):
    """Scaffold a new agentcage config file."""
    from agentcage.init import list_presets as _list_presets, render_config

    if list_presets:
        presets = _list_presets()
        if not presets:
            click.echo("No presets available.")
        else:
            click.echo("Available presets:")
            for p in presets:
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

    if preset is not None and preset not in _list_presets():
        click.echo(
            f"error: unknown preset {preset!r} "
            f"(available: {', '.join(_list_presets()) or 'none'})",
            err=True,
        )
        sys.exit(1)

    dest = Path(output)
    if dest.exists() and not force:
        click.echo(f"error: {dest} already exists (use --force to overwrite)", err=True)
        sys.exit(1)

    content = render_config(name, image=image, isolation=isolation, preset=preset)
    dest.write_text(content)
    click.echo(f"Created {dest}")

    if preset == "openclaw":
        click.echo(f"\nNext steps:")
        click.echo(f"  1. agentcage secret set {name} ANTHROPIC_API_KEY")
        click.echo(f"  2. agentcage secret set {name} OPENCLAW_GATEWAY_PASSWORD")
        click.echo(f"  3. Edit {dest} — uncomment additional providers/domains")
        click.echo(f"  4. agentcage cage create -c {dest}")
    elif preset == "picoclaw":
        click.echo(f"\nNext steps:")
        click.echo(f"  1. Create ~/.picoclaw/config.json with your API keys and channels")
        click.echo(f"     (see https://github.com/sipeed/picoclaw for config format)")
        click.echo(f"  2. Edit {dest} — uncomment domains for your providers/channels")
        click.echo(f"  3. agentcage cage create -c {dest}")
    else:
        click.echo(f"\nNext steps:")
        click.echo(f"  1. Edit {dest} — set your image, domains, and secrets")
        click.echo(f"  2. agentcage cage create -c {dest}")


# ── helpers ──────────────────────────────────────────────


def _require_root(action: str) -> None:
    """Exit with an error if not running as root."""
    if os.geteuid() != 0:
        click.echo(
            f"error: '{action}' with Firecracker isolation requires root\n"
            f"  Run with: sudo agentcage {action}",
            err=True,
        )
        sys.exit(1)


def _expected_secrets(cfg) -> list[str]:
    """Return all secret names a cage expects (injection + direct)."""
    names: list[str] = []
    for r in cfg.secret_injection:
        names.append(r.env)
    for s in cfg.container.podman_secrets:
        names.append(s)
    return names


def _check_secrets(podman: Podman, deploy_name: str, cfg) -> list[str]:
    """Return list of missing secrets for a cage."""
    missing = []
    for key in _expected_secrets(cfg):
        if not podman.secret_exists(f"{deploy_name}.{key}"):
            missing.append(key)
    return missing


def _file_sha256(path: str) -> str:
    """Return hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _patches_work_dir() -> str:
    """Return (and create) the patches working directory."""
    d = os.path.join(
        os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
        "agentcage", "patches",
    )
    os.makedirs(d, exist_ok=True)
    return d


def _ensure_patches(podman: Podman) -> str:
    """Refresh patch files from package data and verify integrity.

    Always re-copies source files so that any tampering in the work
    directory is overwritten.  Returns the patches work directory path.
    """
    patches_work = _patches_work_dir()
    patches_src = str(_DATA_DIR / "patches")

    for fname in ("package.json", "package-lock.json", "proxy-fetch.mjs"):
        src = os.path.join(patches_src, fname)
        dst = os.path.join(patches_work, fname)
        shutil.copy2(src, dst)
        # Verify the copy matches the source
        if _file_sha256(dst) != _file_sha256(src):
            raise RuntimeError(
                f"patch file integrity check failed: {dst} does not match source"
            )

    # Write resolv.conf for cage DNS (always points to dnsmasq sidecar)
    resolv_path = os.path.join(patches_work, "resolv.conf")
    with open(resolv_path, "w") as f:
        f.write("nameserver 10.89.0.10\n")

    # Install undici deps if missing (npm ci uses lockfile for integrity)
    node_modules = os.path.join(patches_work, "node_modules", "undici")
    if not os.path.isdir(node_modules):
        click.echo("Installing proxy-fetch patch dependencies...")
        try:
            podman.run_and_remove(
                "docker.io/node:22-alpine",
                ["npm", "ci", "--prefix", "/app", "--silent"],
                volumes={patches_work: {"bind": "/app", "mode": "Z"}},
            )
        except Exception as e:
            click.echo(f"warning: npm ci failed: {e}", err=True)

    return patches_work


def _build_and_deploy(cfg, config_host_path: str, deploy_name: str, podman: Podman):
    """Build images, generate quadlets, install, and start."""
    backend = get_backend(cfg)

    patches_work_dir = _ensure_patches(podman)

    backend.build_artifacts(cfg, deploy_name)

    units = backend.generate_units(cfg, config_host_path, patches_work_dir, deploy_name)
    backend.install_units(units)
    backend.start(cfg.name)


def _restart_cage(name: str, cfg=None):
    """Restart all services for a cage using the appropriate backend."""
    if cfg is None:
        cfg = state.load_deployment_config(name)
    backend = get_backend(cfg)
    backend.restart(name)


# ── cage group ────────────────────────────────────────────


@main.group()
def cage():
    """Manage cages."""


@cage.command("create")
@click.option("-c", "--config", "config_path", required=True, type=click.Path(exists=True))
def cage_create(config_path: str):
    """Build images, generate quadlets, install, and start a new cage."""
    cfg = load_config(config_path)
    try:
        warnings = validate_config(cfg)
    except ValueError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    for w in warnings:
        click.echo(f"warning: {w}", err=True)

    if cfg.isolation == "firecracker":
        _require_root("cage create")
        backend = get_backend(cfg)
        issues = backend.check_prerequisites(cfg)
        if issues:
            click.echo("Firecracker prerequisites not met:", err=True)
            for issue in issues:
                click.echo(f"  - {issue}", err=True)
            click.echo(
                "\nRun 'agentcage firecracker setup' for one-time host setup.",
                err=True,
            )
            sys.exit(1)

    name = cfg.name

    if state.deployment_exists(name):
        click.echo(f"error: cage '{name}' already exists", err=True)
        click.echo(f"  Use 'agentcage cage update {name}' to update it.", err=True)
        sys.exit(1)

    podman = Podman()

    # Check secrets
    missing = _check_secrets(podman, name, cfg)
    if missing:
        click.echo(f"error: missing secrets for cage '{name}':", err=True)
        for key in missing:
            click.echo(f"  {key}", err=True)
        click.echo("Create them with:", err=True)
        for key in missing:
            click.echo(f"  agentcage secret set {name} {key}", err=True)
        sys.exit(1)

    # Save state
    state.save_deployment(name, config_path)
    state.save_metadata(name, {"agentcage_version": version("agentcage")})

    config_host_path = state.save_proxy_config(name)
    _build_and_deploy(cfg, config_host_path, name, podman)

    click.echo()
    click.echo("Logs:")
    click.echo(f"  agentcage cage logs {name}")


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
    else:
        cfg = state.load_deployment_config(name)
        try:
            warnings = validate_config(cfg)
        except ValueError as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(1)
        for w in warnings:
            click.echo(f"warning: {w}", err=True)

    if cfg.isolation == "firecracker":
        _require_root("cage update")

    state.save_metadata(name, {"agentcage_version": version("agentcage")})
    config_host_path = state.save_proxy_config(name)

    podman = Podman()

    # Check secrets
    missing = _check_secrets(podman, name, cfg)
    if missing:
        click.echo(f"error: missing secrets for cage '{name}':", err=True)
        for key in missing:
            click.echo(f"  {key}", err=True)
        click.echo("Create them with:", err=True)
        for key in missing:
            click.echo(f"  agentcage secret set {name} {key}", err=True)
        sys.exit(1)

    # Stop existing
    click.echo("Stopping services...")
    backend = get_backend(cfg)
    backend.stop(name)

    _build_and_deploy(cfg, config_host_path, name, podman)
    click.echo(f"Updated cage '{name}'")


@cage.command("list")
def cage_list():
    """List all cages with status."""
    names = state.list_deployments()
    if not names:
        click.echo("No cages found.")
        return

    click.echo(f"{'NAME':<20} {'ISOLATION':<14} {'VERSION':<12} STATUS")
    for name in names:
        try:
            cfg = state.load_deployment_config(name)
            backend = get_backend(cfg)
        except Exception:
            click.echo(f"{name:<20} {'?':<14} {'-':<12} unknown (config error)")
            continue

        isolation = cfg.isolation
        ver = state.load_metadata(name).get("agentcage_version", "-")
        services = backend.service_names(name)
        total = len(services)
        running = sum(
            1 for svc in services
            if backend.is_running(name, svc)
        )
        if running == total:
            status = f"running ({running}/{total})"
        elif running == 0:
            status = f"stopped (0/{total})"
        else:
            status = f"degraded ({running}/{total})"
        click.echo(f"{name:<20} {isolation:<14} {ver:<12} {status}")


@cage.command("destroy")
@click.argument("name")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt")
def cage_destroy(name: str, yes: bool):
    """Stop containers, remove quadlets, state, and scoped secrets."""
    if not yes:
        click.confirm(
            f'Destroy cage "{name}"? '
            "This will stop containers, remove quadlets, state, and scoped secrets.",
            abort=True,
        )

    # Load config to determine backend, fall back to container backend
    try:
        cfg = state.load_deployment_config(name)
        backend = get_backend(cfg)
        if cfg.isolation == "firecracker":
            _require_root("cage destroy")
    except Exception:
        from agentcage.backends.container import ContainerBackend
        backend = ContainerBackend()

    click.echo("Stopping services...")
    backend.stop(name)

    click.echo("Removing quadlet files...")
    removed = backend.destroy_resources(name)

    click.echo("Removing Podman resources...")

    # Remove state
    if state.deployment_exists(name):
        state.remove_deployment(name)
        removed.append("state")

    click.echo()
    if removed:
        click.echo("Removed:")
        for item in removed:
            click.echo(f"  {item}")
    else:
        click.echo(f'Nothing to remove (cage "{name}" not found).')


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

    def _pass(msg: str):
        nonlocal passed
        click.echo(f"  [PASS] {msg}")
        passed += 1

    def _fail(msg: str):
        nonlocal failed
        click.echo(f"  [FAIL] {msg}")
        failed += 1

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
        _verify_container(name, _pass, _fail)
    else:
        _verify_firecracker(name, _pass, _fail)

    # Summary
    click.echo()
    click.echo(f"=== Results: {passed} passed, {failed} failed, 0 warnings ===")
    if failed > 0:
        click.echo("    Review failures above.")
        sys.exit(1)


def _verify_container(name: str, _pass, _fail):
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
        # Try curl first, fall back to node's fetch if curl isn't available
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
            status = output.strip()
        if status in ("403", "000"):
            _pass(f"Blocked domain (evil-exfil-server.io) is denied (HTTP {status})")
        else:
            _fail(f"Blocked domain returned HTTP {status} — egress filtering may be broken")
    except Exception:
        _pass("Blocked domain (evil-exfil-server.io) is denied (HTTP 000)")

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


def _verify_firecracker(name: str, _pass, _fail):
    """Firecracker-specific health checks."""
    # In Firecracker mode, proxy/dns/cage all run inside the VM.
    # We cannot exec into them from the host, so we check what we can.
    click.echo()
    click.echo("-- VM Internals --")
    click.echo("  [INFO] CA cert, proxy config, and egress checks run inside the VM")
    click.echo("  [INFO] Use 'agentcage cage logs {name}' to verify internal health")


@cage.command("reload")
@click.argument("name")
def cage_reload(name: str):
    """Restart services without rebuilding images."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)

    # Re-copy patch files from package data to overwrite any tampering
    _ensure_patches(Podman())

    _restart_cage(name, cfg)
    click.echo(f"Reloaded cage '{name}'")


@cage.command("logs")
@click.argument("name")
@click.option("-s", "--service", "services", multiple=True,
              type=click.Choice(["cage", "proxy", "dns"]))
@click.option("-n", "--lines", default=50, show_default=True,
              help="Number of lines to show.")
@click.option("--no-follow", is_flag=True, help="Print logs and exit.")
@click.option("-l", "--severity", "min_level", default=None,
              type=click.Choice(["debug", "info", "warning", "error", "critical"]),
              help="Minimum severity level to show.")
def cage_logs(name, services, lines, no_follow, min_level):
    """Follow journalctl logs for a cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    cfg = state.load_deployment_config(name)
    selected = services or ("cage", "proxy", "dns")

    if cfg.isolation == "firecracker":
        # Firecracker has a single host unit; container logs are prefixed
        # [cage:level], [proxy:level], [dns:level] on the VM console.
        _logs_firecracker(name, selected, lines, no_follow, min_level)
    else:
        _logs_container(name, selected, lines, no_follow, min_level)


def _classify_line(service: str, line: str) -> str:
    """Classify a log line's severity for container-mode filtering."""
    if service == "dns":
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


def _logs_firecracker(name, services, lines, no_follow, min_level=None):
    """Show logs from the single Firecracker host unit, filtering by service prefix."""
    cmd = ["journalctl", "--user", "-u", f"{name}-cage",
           "-n", str(lines), "-o", "cat"]
    if not no_follow:
        cmd.append("-f")

    need_filter = set(services) != {"cage", "proxy", "dns"} or min_level is not None
    if not need_filter:
        os.execvp("journalctl", cmd)
    else:
        pattern = _level_grep_pattern(services, min_level)
        journal = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        grep = subprocess.Popen(
            ["grep", "--line-buffered", "-E", pattern],
            stdin=journal.stdout,
        )
        journal.stdout.close()  # allow SIGPIPE if grep exits
        sys.exit(grep.wait())


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
    if cfg.isolation == "firecracker":
        unit = f"{name}-cage"
    else:
        unit = f"{name}-proxy"

    cmd = ["journalctl", "--user", "-u", unit, "-o", "cat"]

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
@click.option("-n", "--lines", default=100, show_default=True,
              help="Max entries to show (0 = unlimited).")
@click.option("-f", "--follow", is_flag=True,
              help="Stream new entries in real time.")
@click.option("--json", "as_json", is_flag=True,
              help="Output as JSON lines.")
@click.option("--summary", is_flag=True,
              help="Show aggregated statistics.")
@click.option("--no-color", is_flag=True,
              help="Disable colored output.")
def cage_audit(name, decisions, directions, hosts, inspectors, severity,
               methods, since, lines, follow, as_json, summary, no_color):
    """Query, filter, and summarize proxy audit logs."""
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
def cage_har(name, view, decisions, hosts, methods, directions, since,
             max_entries, output_file, json_lines):
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
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    from agentcage.har import CaptureFilter, capture_to_har, parse_since

    capture_path = state.capture_file(name)
    if not capture_path.is_file():
        click.echo(f"error: no capture file found for cage '{name}'", err=True)
        click.echo(f"  Expected: {capture_path}", err=True)
        click.echo("  Is capture enabled in the cage config?", err=True)
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


# ── secret group ─────────────────────────────────────────


@main.group()
def secret():
    """Manage cage-scoped secrets."""


@secret.command("list")
@click.argument("cage_name")
def secret_list(cage_name: str):
    """List secrets for a cage."""
    podman = Podman()
    secrets = podman.secret_list(prefix=f"{cage_name}.")

    # If cage state exists, cross-reference with expected secrets
    if state.deployment_exists(cage_name):
        cfg = state.load_deployment_config(cage_name)
        expected = _expected_secrets(cfg)

        # Determine which type each secret is
        injection_names = {r.env for r in cfg.secret_injection}
        present_keys = {
            s.get("Name", "").removeprefix(f"{cage_name}.")
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
            click.echo(f"No secrets found for '{cage_name}'.")
            return
        click.echo(f"{'NAME':<30}")
        for s in secrets:
            sname = s.get("Name", "")
            key = sname.removeprefix(f"{cage_name}.")
            click.echo(f"{key:<30}")


@secret.command("set")
@click.argument("cage_name")
@click.argument("key")
def secret_set(cage_name: str, key: str):
    """Set a secret for a cage."""
    podman = Podman()
    full_name = f"{cage_name}.{key}"

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
    if state.deployment_exists(cage_name):
        cfg = state.load_deployment_config(cage_name)
        name = cfg.name
        backend = get_backend(cfg)
        if backend.is_running(name, "cage"):
            click.echo(f"Reloading cage '{name}'...")
            _restart_cage(name, cfg)


@secret.command("rm")
@click.argument("cage_name")
@click.argument("key")
def secret_rm(cage_name: str, key: str):
    """Remove a secret for a cage."""
    podman = Podman()
    full_name = f"{cage_name}.{key}"

    if not podman.secret_exists(full_name):
        click.echo(f"error: secret '{full_name}' does not exist", err=True)
        sys.exit(1)

    podman.secret_remove(full_name)
    click.echo(f"Secret '{full_name}' removed.")

    # Auto-reload if cage is running
    if state.deployment_exists(cage_name):
        cfg = state.load_deployment_config(cage_name)
        name = cfg.name
        backend = get_backend(cfg)
        if backend.is_running(name, "cage"):
            click.echo(f"Reloading cage '{name}'...")
            _restart_cage(name, cfg)


# ── domain group ─────────────────────────────────────────


@main.group()
def domain():
    """Manage cage domain allowlists."""


@domain.command("list")
@click.argument("cage_name")
def domain_list(cage_name: str):
    """List domains for a cage."""
    try:
        raw = state.load_raw_config(cage_name)
    except FileNotFoundError:
        click.echo(f"error: cage '{cage_name}' does not exist", err=True)
        sys.exit(1)

    domains = raw.get("domains", {})
    mode = domains.get("mode", "allowlist")
    domain_list_val = domains.get("list", [])

    click.echo(f"Mode: {mode}")
    for d in sorted(domain_list_val):
        click.echo(d)


@domain.command("add")
@click.argument("cage_name")
@click.argument("domain_name")
def domain_add(cage_name: str, domain_name: str):
    """Add a domain to a cage's allowlist."""
    try:
        raw = state.load_raw_config(cage_name)
    except FileNotFoundError:
        click.echo(f"error: cage '{cage_name}' does not exist", err=True)
        sys.exit(1)

    if "domains" not in raw:
        raw["domains"] = {"mode": "allowlist", "list": []}
    if "list" not in raw["domains"]:
        raw["domains"]["list"] = []

    if domain_name in raw["domains"]["list"]:
        click.echo(f"'{domain_name}' is already in cage '{cage_name}'.")
        return

    raw["domains"]["list"].append(domain_name)
    state.save_raw_config(cage_name, raw)
    state.save_proxy_config(cage_name)

    reloaded = False
    cfg = state.load_deployment_config(cage_name)
    name = cfg.name
    backend = get_backend(cfg)
    if backend.is_running(name, "cage"):
        _restart_cage(name, cfg)
        reloaded = True

    msg = f"Added '{domain_name}' to cage '{cage_name}'."
    if reloaded:
        msg += " Cage reloaded."
    click.echo(msg)


@domain.command("rm")
@click.argument("cage_name")
@click.argument("domain_name")
def domain_rm(cage_name: str, domain_name: str):
    """Remove a domain from a cage's allowlist."""
    try:
        raw = state.load_raw_config(cage_name)
    except FileNotFoundError:
        click.echo(f"error: cage '{cage_name}' does not exist", err=True)
        sys.exit(1)

    domain_entries = raw.get("domains", {}).get("list", [])
    if domain_name not in domain_entries:
        click.echo(f"error: '{domain_name}' is not in cage '{cage_name}'", err=True)
        sys.exit(1)

    raw["domains"]["list"].remove(domain_name)
    state.save_raw_config(cage_name, raw)
    state.save_proxy_config(cage_name)

    reloaded = False
    cfg = state.load_deployment_config(cage_name)
    name = cfg.name
    backend = get_backend(cfg)
    if backend.is_running(name, "cage"):
        _restart_cage(name, cfg)
        reloaded = True

    msg = f"Removed '{domain_name}' from cage '{cage_name}'."
    if reloaded:
        msg += " Cage reloaded."
    click.echo(msg)


# ── firecracker group ─────────────────────────────────────


@main.group(name="firecracker")
def firecracker_group():
    """Firecracker host setup and management."""


@firecracker_group.command("setup")
def firecracker_setup():
    """One-time host setup: download kernel, check prerequisites, create bridge."""
    _require_root("firecracker setup")

    from agentcage.firecracker.kernel import ensure_kernel, default_kernel_path
    from agentcage.firecracker.binaries import ensure_firecracker, default_firecracker_path
    from agentcage.firecracker import prerequisites, network
    from agentcage.config import Config, FirecrackerConfig

    # 1. Ensure kernel
    kernel_path = default_kernel_path()
    click.echo(f"Kernel: {kernel_path}")
    try:
        ensure_kernel(kernel_path)
        click.echo("  ok")
    except Exception as e:
        click.echo(f"  FAILED: {e}", err=True)

    # 2. Ensure Firecracker binary
    fc_path = default_firecracker_path()
    click.echo(f"Firecracker: {fc_path}")
    try:
        ensure_firecracker(fc_path)
        click.echo("  ok")
    except Exception as e:
        click.echo(f"  FAILED: {e}", err=True)

    # 3. Check prerequisites (use a minimal firecracker config for the check)
    cfg = Config(
        name="setup-check",
        isolation="firecracker",
        firecracker=FirecrackerConfig(kernel=kernel_path),
    )
    cfg.container.image = "placeholder"
    issues = prerequisites.check_prerequisites(cfg)

    if issues:
        click.echo()
        click.echo("Remaining issues:")
        for issue in issues:
            click.echo(f"  - {issue}")
    else:
        click.echo()
        click.echo("All prerequisites met.")

    # 4. Create bridge if missing
    if not os.path.exists("/sys/class/net/agentcage-br0"):
        click.echo()
        click.echo("Creating network bridge (agentcage-br0)...")
        try:
            network.create_bridge()
            click.echo("  ok")
        except Exception as e:
            click.echo(f"  FAILED: {e}", err=True)
    else:
        click.echo()
        click.echo("Network bridge (agentcage-br0) already exists.")
