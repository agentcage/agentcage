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

import ipaddress
import json
import os
import platform
import random
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import click

from agentcage import state
from agentcage.backends import get_backend
from agentcage.config import load_config, validate_config
from agentcage.init import list_scaffolds, load_scaffold_meta, render_config, resolve_scaffold, run_scaffold_setup
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
    "alpine": "alpine-curl",
}

# Short prefixes for auto-generated cage names
_NAME_PREFIXES: dict[str, str] = {
    "claude-code": "claude",
    "alpine-curl": "alpine",
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


def _is_ip_address(host: str) -> bool:
    """Return True if *host* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _extract_parent_domain(host: str) -> str:
    """Extract the registrable parent domain from a hostname.

    api.stripe.com -> stripe.com
    cdn.example.co.uk -> example.co.uk
    stripe.com -> stripe.com (already a parent)
    localhost -> localhost
    10.0.0.1 -> 10.0.0.1 (IP addresses returned as-is)
    """
    # IP addresses and single-label hosts are returned unchanged
    if _is_ip_address(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Use last 3 parts for known compound TLDs, otherwise last 2
    known_compound_tlds = {
        "co.uk", "org.uk", "me.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "or.jp", "ne.jp",
        "com.br", "net.br", "org.br",
        "co.nz", "net.nz", "org.nz",
        "co.in", "net.in", "org.in",
        "com.mx", "org.mx",
        "com.cn", "net.cn", "org.cn",
        "co.kr",
        "com.sg",
        "com.hk",
    }
    if ".".join(parts[-2:]) in known_compound_tlds:
        return ".".join(parts[-3:]) if len(parts) >= 3 else host
    return ".".join(parts[-2:])


def _monitor_proxy(
    proxy_container: str,
    stop_event: threading.Event,
    cage_name: str | None = None,
    interactive: bool = False,
) -> None:
    """Tail proxy logs and print blocked-request notifications to the terminal.

    Runs as a daemon thread alongside the interactive session.  Writes
    directly to ``/dev/tty`` so output appears even while podman exec
    owns stdout/stderr.

    When *interactive* is True and a domain-based block occurs, prompts
    the user (via ``/dev/tty``) to add the domain to the allowlist.
    """
    # Timeout (seconds) for waiting on user input.  Prevents the monitor
    # thread from blocking indefinitely if the user ignores the prompt.
    _PROMPT_TIMEOUT = 10

    try:
        tty_w = open("/dev/tty", "w")
        tty_r = open("/dev/tty", "r") if interactive else None
    except OSError:
        return

    try:
        proc = subprocess.Popen(
            ["podman", "logs", "-f", proxy_container],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError:
        tty_w.close()
        if tty_r:
            tty_r.close()
        return

    dim = "\x1b[2m"
    red = "\x1b[31m"
    yellow = "\x1b[33m"
    green = "\x1b[32m"
    reset = "\x1b[0m"

    prompted_domains: set[str] = set()

    def _read_response_with_timeout(fd: int, timeout: float) -> str | None:
        """Read a line from *fd* with a timeout via select().

        Returns the stripped response, or ``None`` on timeout / error.
        Using select() avoids blocking the monitor thread indefinitely,
        which is important because `podman exec -it` shares the same
        controlling terminal.
        """
        try:
            ready, _, _ = select.select([fd], [], [], timeout)
        except (OSError, ValueError):
            return None
        if not ready:
            return None
        # Read one line (user presses Enter)
        try:
            data = os.read(fd, 256)
            return data.decode("utf-8", errors="replace").strip().lower()
        except OSError:
            return None

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if stop_event.is_set():
                break
            line = line.strip()
            if not line or '"decision"' not in line:
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if entry.get("decision") != "blocked":
                continue
            host = entry.get("host", "?")
            reason = entry.get("reason", "blocked")
            tty_w.write(
                f"\r{dim}[agentcage]{reset} {red}blocked{reset}"
                f" {dim}\u2192{reset} {host} {dim}({reason}){reset}\n"
            )
            tty_w.flush()

            # Interactive domain prompt
            if (
                interactive
                and tty_r
                and cage_name
                and reason == "domain"
                and host not in prompted_domains
            ):
                prompted_domains.add(host)
                domain_to_add = _extract_parent_domain(host)
                # Also skip if the parent domain was already prompted
                if domain_to_add in prompted_domains:
                    continue
                prompted_domains.add(domain_to_add)

                tty_w.write(
                    f"  Add {domain_to_add} to allowlist? "
                    f"[y/N {dim}{_PROMPT_TIMEOUT}s{reset}] "
                )
                tty_w.flush()

                try:
                    response = _read_response_with_timeout(
                        tty_r.fileno(), _PROMPT_TIMEOUT,
                    )
                    if response is None:
                        # Timeout — treat as decline
                        tty_w.write(
                            f"\n  {yellow}(timed out, skipped){reset}\n"
                        )
                        tty_w.flush()
                    elif response == "y":
                        subprocess.run(
                            ["agentcage", "domain", "add", cage_name, domain_to_add],
                            capture_output=True,
                        )
                        tty_w.write(
                            f"  {green}\u2713{reset} {domain_to_add} added\n"
                        )
                        tty_w.flush()
                except (OSError, ValueError):
                    pass
    except (OSError, ValueError):
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        tty_w.close()
        if tty_r:
            tty_r.close()


def _detect_isolation() -> str:
    """Return 'vm' on macOS, 'container' on Linux."""
    return "vm" if platform.system() == "Darwin" else "container"


def execute(
    scaffold: str,
    *,
    project_dir: str | None = None,
    name: str | None = None,
    secrets: tuple[str, ...] = (),
    extra_args: tuple[str, ...] = (),
    verbose: bool = False,
    isolation: str | None = None,
    interactive_domains: bool = False,
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
    from importlib.metadata import version
    output.banner(version("agentcage"))

    # Determine isolation mode
    isolation = isolation or _detect_isolation()

    # Render config from scaffold template
    os.environ["PROJECT_DIR"] = project_dir
    config_text, image_tag = render_config(
        cage_name, scaffold=scaffold, isolation=isolation,
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

    # Copy scaffold Containerfile and sibling files to state dir so cage
    # update can rebuild (Containerfiles may COPY from build context)
    if cfg.container.build.containerfile:
        scaffold_dir = resolve_scaffold(scaffold)
        containerfile_src = scaffold_dir / cfg.container.build.containerfile if scaffold_dir else None
        if containerfile_src is not None and containerfile_src.exists():
            dest_dir = Path(state.stored_config_path(cage_name)).parent
            for f in containerfile_src.parent.iterdir():
                if f.is_file() and f.suffix not in (".yaml", ".yml", ".j2"):
                    shutil.copy2(str(f), str(dest_dir / f.name))

    # Run scaffold setup (build images) and deploy
    try:
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
            # VM mode builds images inside the VM — skip host scaffold setup
            if cfg.isolation != "vm":
                run_scaffold_setup(
                    scaffold, cage_name, str(config_path),
                    image_tag=image_tag,
                )
            build_and_deploy(
                cfg,
                config_host_path=config_host_path,
                deploy_name=cage_name,
                podman=podman,
                used_octets=used_octets,
            )
        else:
            with output.Spinner("Starting cage..."):
                # VM mode builds images inside the VM — skip host scaffold setup
                if cfg.isolation != "vm":
                    run_scaffold_setup(
                        scaffold, cage_name, str(config_path),
                        image_tag=image_tag, quiet=True,
                    )
                build_and_deploy(
                    cfg,
                    config_host_path=config_host_path,
                    deploy_name=cage_name,
                    podman=podman,
                    used_octets=used_octets,
                    quiet=True,
                )
        output.step_done(output.dim(cage_name))
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

    # Summary
    click.echo()
    click.echo(f"  {output.dim(project_dir)}")
    click.echo(f"  {output.dim('Ctrl+D to exit')} {output.dim('·')} {output.dim('agentcage cage audit ' + cage_name)}")
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
    proxy_container = f"{cfg.name}-proxy"
    exec_flags = ["-it"] if sys.stdin.isatty() else []

    # Monitor proxy logs for blocked requests
    monitor_stop = threading.Event()
    monitor_thread = threading.Thread(
        target=_monitor_proxy,
        args=(proxy_container, monitor_stop),
        kwargs={"cage_name": cage_name, "interactive": interactive_domains},
        daemon=True,
    )
    monitor_thread.start()

    try:
        result = subprocess.run(
            ["podman", "exec"] + exec_flags + [container_name] + exec_cmd,
        )
        exit_code = result.returncode
    except KeyboardInterrupt:
        click.echo("\nSession interrupted.")
        exit_code = 130
    finally:
        monitor_stop.set()
        monitor_thread.join(timeout=3)
        click.echo()
        output.separator()
        with output.Spinner("Stopping cage..."):
            try:
                backend = get_backend(cfg)
                backend.stop(cfg.name)
            except Exception as e:
                click.echo(f"warning: failed to stop cage: {e}", err=True)
        click.echo(f"  {output.dim(cage_name + ' stopped')}")
        click.echo(f"  {output.dim('agentcage cage audit ' + cage_name)}")

    # Clean up temp config dir
    shutil.rmtree(str(config_dir), ignore_errors=True)

    return exit_code
