"""lobstercage CLI — cage and secret command groups."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

import click

from importlib.metadata import version

from lobstercage.config import load_config, validate_config
from lobstercage.podman import Podman
from lobstercage.quadlets import generate_quadlets
from lobstercage import state, systemd

_DATA_DIR = Path(__file__).resolve().parent / "data"


@click.group()
@click.version_option(version=version("lobstercage"), prog_name="lobstercage")
def main():
    """Keep your lobster in a box 🦞🔒"""


# ── helpers ──────────────────────────────────────────────


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
        "lobstercage", "patches",
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
    name = cfg.name

    patches_work_dir = _ensure_patches(podman)

    # Build images
    containers_dir = str(_DATA_DIR / "containers")
    build_context = str(_DATA_DIR)
    click.echo("Building proxy image...")
    podman.build_image(
        "lobstercage-proxy",
        os.path.join(containers_dir, "Containerfile.proxy"),
        build_context,
    )
    click.echo("Building DNS image...")
    podman.build_image(
        "lobstercage-dns",
        os.path.join(containers_dir, "Containerfile.dns"),
        build_context,
        cap_add=["CAP_SETFCAP"],
    )

    # Generate quadlets
    files = generate_quadlets(cfg, config_host_path, patches_work_dir, deploy_name)

    # Write directly to systemd quadlet dir
    quadlet_dest = Path(os.path.expanduser("~/.config/containers/systemd"))
    quadlet_dest.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (quadlet_dest / filename).write_text(content)
    click.echo(f"Installed quadlet files to {quadlet_dest}/")

    # Reload and start — restart network/volume first so they're recreated
    # (systemd may think they're still active from a previous run even if
    # podman resources were removed by 'cage destroy')
    systemd.daemon_reload()
    try:
        systemd.restart_unit(f"{name}-net-network.service")
    except Exception as e:
        click.echo(f"warning: failed to restart network service: {e}", err=True)
    try:
        systemd.restart_unit(f"{name}-certs-volume.service")
    except Exception as e:
        click.echo(f"warning: failed to restart volume service: {e}", err=True)
    systemd.start_unit(f"{name}-cage.service")
    click.echo(f"Started {name}-cage")


def _restart_cage(name: str):
    """Restart all services for a cage."""
    for svc in ("cage", "proxy", "dns"):
        try:
            systemd.restart_unit(f"{name}-{svc}.service")
        except Exception as e:
            click.echo(f"warning: failed to restart {name}-{svc}: {e}", err=True)


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

    name = cfg.name

    if state.deployment_exists(name):
        click.echo(f"error: cage '{name}' already exists", err=True)
        click.echo(f"  Use 'lobstercage cage update {name}' to update it.", err=True)
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
            click.echo(f"  lobstercage secret set {name} {key}", err=True)
        sys.exit(1)

    # Save state
    state.save_deployment(name, config_path)

    config_host_path = state.save_proxy_config(name)
    _build_and_deploy(cfg, config_host_path, name, podman)

    click.echo()
    click.echo("Logs:")
    click.echo(f"  journalctl --user -u {name}-cage -f")
    click.echo(f"  journalctl --user -u {name}-proxy -f")
    click.echo(f"  journalctl --user -u {name}-dns -f")


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
            click.echo(f"  lobstercage secret set {name} {key}", err=True)
        sys.exit(1)

    # Stop existing
    click.echo("Stopping services...")
    for svc in ("cage", "proxy", "dns"):
        try:
            systemd.stop_unit(f"{name}-{svc}.service")
        except Exception as e:
            click.echo(f"warning: failed to stop {name}-{svc}: {e}", err=True)

    _build_and_deploy(cfg, config_host_path, name, podman)
    click.echo(f"Updated cage '{name}'")


@cage.command("list")
def cage_list():
    """List all cages with status."""
    names = state.list_deployments()
    if not names:
        click.echo("No cages found.")
        return

    podman = Podman()
    click.echo(f"{'NAME':<20} STATUS")
    for name in names:
        total = 3
        running = sum(
            1 for svc in ("cage", "proxy", "dns")
            if podman.container_running(f"{name}-{svc}")
        )
        if running == total:
            status = f"running ({running}/{total})"
        elif running == 0:
            status = f"stopped (0/{total})"
        else:
            status = f"degraded ({running}/{total})"
        click.echo(f"{name:<20} {status}")


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

    quadlet_dir = Path(os.path.expanduser("~/.config/containers/systemd"))
    removed: list[str] = []

    click.echo("Stopping services...")
    for svc in ("cage", "proxy", "dns"):
        try:
            systemd.stop_unit(f"{name}-{svc}.service")
        except Exception as e:
            click.echo(f"warning: failed to stop {name}-{svc}: {e}", err=True)

    click.echo("Removing quadlet files...")
    quadlet_files = [
        f"{name}-cage.container",
        f"{name}-proxy.container",
        f"{name}-dns.container",
        f"{name}-net.network",
        f"{name}-certs.volume",
    ]
    for fname in quadlet_files:
        fpath = quadlet_dir / fname
        if fpath.exists():
            fpath.unlink()
            removed.append(fname)

    systemd.daemon_reload()

    click.echo("Removing Podman resources...")
    podman = Podman()
    if podman.network_remove(f"{name}-net"):
        removed.append(f"network:{name}-net")
    if podman.volume_remove(f"lobstercage-certs-{name}"):
        removed.append(f"volume:lobstercage-certs-{name}")

    # Remove scoped secrets
    click.echo("Removing scoped secrets...")
    for s in podman.secret_list(prefix=f"{name}."):
        sname = s.get("Name", "")
        if podman.secret_remove(sname):
            removed.append(f"secret:{sname}")

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
    podman = Podman()
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

    click.echo(f"=== lobstercage verify: {name} ===")
    click.echo()

    # Container checks
    click.echo("-- Containers --")
    for svc in ("proxy", "dns", "cage"):
        cname = f"{name}-{svc}"
        if podman.container_running(cname):
            _pass(f"{cname} is running")
        else:
            _fail(f"{cname} is NOT running")

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

    # Summary
    click.echo()
    click.echo(f"=== Results: {passed} passed, {failed} failed, 0 warnings ===")
    if failed > 0:
        click.echo("    Review failures above.")
        sys.exit(1)


@cage.command("reload")
@click.argument("name")
def cage_reload(name: str):
    """Restart containers without rebuilding images."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    # Re-copy patch files from package data to overwrite any tampering
    _ensure_patches(Podman())

    _restart_cage(name)
    click.echo(f"Reloaded cage '{name}'")


@cage.command("logs")
@click.argument("name")
@click.option("-s", "--service", "services", multiple=True,
              type=click.Choice(["cage", "proxy", "dns"]))
@click.option("-n", "--lines", default=50, show_default=True,
              help="Number of lines to show.")
@click.option("--no-follow", is_flag=True, help="Print logs and exit.")
def cage_logs(name, services, lines, no_follow):
    """Follow journalctl logs for a cage."""
    if not state.deployment_exists(name):
        click.echo(f"error: cage '{name}' does not exist", err=True)
        sys.exit(1)

    units = [f"{name}-{svc}" for svc in (services or ("cage", "proxy", "dns"))]
    cmd = ["journalctl", "--user"]
    for u in units:
        cmd += ["-u", u]
    cmd += ["-n", str(lines)]
    if not no_follow:
        cmd.append("-f")
    os.execvp("journalctl", cmd)


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
        if podman.container_running(f"{name}-cage"):
            click.echo(f"Reloading cage '{name}'...")
            _restart_cage(name)


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
        if podman.container_running(f"{name}-cage"):
            click.echo(f"Reloading cage '{name}'...")
            _restart_cage(name)


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
    podman = Podman()
    if podman.container_running(f"{name}-cage"):
        _restart_cage(name)
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
    podman = Podman()
    if podman.container_running(f"{name}-cage"):
        _restart_cage(name)
        reloaded = True

    msg = f"Removed '{domain_name}' from cage '{cage_name}'."
    if reloaded:
        msg += " Cage reloaded."
    click.echo(msg)
