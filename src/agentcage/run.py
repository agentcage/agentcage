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
from agentcage.init import (
    list_scaffolds,
    render_config,
    resolve_scaffold,
    run_scaffold_setup,
    scaffold_aliases,
    scaffold_name_prefix,
)
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
    """Generate a unique cage name like ``claude-bold-fox``.

    The prefix comes from the scaffold's ``scaffold.yaml`` (``name_prefix``
    field) and falls back to the scaffold name itself when not declared.
    """
    prefix = scaffold_name_prefix(scaffold)
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
    podman_prefix: list[str] | None = None,
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
            (podman_prefix or []) + ["podman", "logs", "-f", proxy_container],
            # Detach stdin from the controlling terminal. On the VM
            # backend the command is wrapped in `limactl shell` → ssh,
            # and ssh reads its stdin to forward it to the remote side.
            # If it inherits the terminal it races the interactive
            # `podman exec -it` session for the user's keystrokes —
            # roughly half are stolen, so every key has to be pressed
            # twice. The monitor never reads stdin (the interactive
            # domain prompt opens /dev/tty directly), so DEVNULL is safe.
            stdin=subprocess.DEVNULL,
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
    """Return the best default isolation for this host.

    On macOS 26+ Apple Silicon with the Apple `container` CLI installed,
    this returns 'apple-container'. Older macOS or Intel falls back to
    'vm' (Lima). Linux returns 'container' (rootless podman on host).
    Centralised in :func:`agentcage.config.default_isolation` so the
    cage.yaml parser and ``agentcage run`` agree on the default.
    """
    from agentcage.config import default_isolation
    return default_isolation()


def _ensure_volume_dirs(volumes: list[str]) -> None:
    """Create missing host directories for a cage's bind-mount volumes.

    Scaffolds may declare host bind-mounts for state persistence. On a
    fresh machine the source directory may not exist yet; podman cannot
    bind-mount a missing source, and the Lima/quadlet layers would skip
    it (so a login inside the cage never round-trips to the host).
    Create it up front instead.

    Only *directory* sources inside the home directory are created. A
    spec whose host path looks like a file (has an extension) or still
    carries an unexpanded ``${VAR}`` is left untouched — a single file
    cannot be shared into the Lima VM, and the mount layers skip those
    safely on their own.
    """
    home = os.path.realpath(os.path.expanduser("~"))
    for vol in volumes:
        host_part = vol.split(":")[0]
        expanded = os.path.expandvars(os.path.expanduser(host_part))
        if "$" in expanded:
            continue  # unresolved variable — not ours to create
        real = os.path.realpath(expanded)
        if os.path.exists(real):
            continue
        if os.path.splitext(os.path.basename(real))[1]:
            continue  # looks like a file — leave it to the skip logic
        if real == home or real.startswith(home + os.sep):
            os.makedirs(real, exist_ok=True)


def _stage_set_secrets(
    cage_name: str, secrets: tuple[str, ...], isolation: str, podman,
) -> set[str]:
    """Stage ``--set-secret`` values and return the set of provided keys.

    Container mode writes them straight to the host Podman store. The VM
    backend has no host Podman, so values are staged to
    ``pending_secrets.json`` in the deployment dir (mode 0600) — the VM
    backend reads it and creates the secrets inside the VM. This mirrors
    what ``agentcage cage create`` already does for VM cages.
    """
    parsed: list[tuple[str, str]] = []
    for spec in secrets:
        if "=" in spec:
            key, val = spec.split("=", 1)
        else:
            key = spec
            val = click.prompt(f"Value for {key}", hide_input=True)
        parsed.append((key, val))

    if isolation in ("vm", "apple-container"):
        # Neither backend has access to host podman on macOS. Stage to a
        # per-cage pending_secrets.json (0600) and let the backend pick
        # it up at start time. VM backend reads the file and creates
        # podman secrets INSIDE the VM (then unlinks the file).
        # apple-container backend reads the file at every start() to
        # resolve `secret_injection` rules — the 0600 plaintext file IS
        # the persistence mechanism (no host podman; Keychain is a
        # follow-up, see #120). Values are NEVER read from the host
        # shell's environment for the apple-container backend.
        if parsed:
            secrets_file = state.deployment_dir(cage_name) / "pending_secrets.json"
            # 0o600 — staged secret values must not be world-readable.
            fd = os.open(str(secrets_file),
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(parsed).encode())
            finally:
                os.close(fd)
    else:
        for key, val in parsed:
            full = f"{cage_name}.{key}"
            if podman.secret_exists(full):
                podman.secret_remove(full)
            podman.secret_create(full, val)

    return {key for key, _ in parsed}


def _vm_podman_prefix(isolation: str, cage_name: str) -> list[str]:
    """Command prefix needed to reach Podman for a cage.

    On the VM backend there is no host Podman — containers run inside the
    Lima VM, so podman commands must be routed through ``limactl shell``.
    On the container backend Podman runs on the host and no prefix is
    needed.
    """
    if isolation == "vm":
        return ["limactl", "shell", f"agentcage-{cage_name}", "--"]
    return []


def _resolve_exec_cmd(cfg, extra_args: tuple[str, ...]) -> list[str]:
    """Build the cage's session command from extras + scaffold aliases.

    When the user passes ``--`` extras, they are a COMPLETE command (binary
    + args) — matching the docs example ``agentcage run codex --name X --
    codex --help``. Without extras, default to the first ``exec_alias``
    (the scaffold's primary binary, e.g. ``["claude"]``). Fall back to
    ``/bin/bash`` if neither.

    Pre-fix the code prepended the alias EVEN WHEN extras were given, so
    ``agentcage run claude-code -- claude --dangerously-skip-permissions
    -p "<prompt>"`` became ``claude claude --dangerously-skip-permissions
    -p "<prompt>"``. Claude consumed the second ``claude`` as its
    positional prompt and silently ignored ``-p`` — the agent responded
    to "claude" instead of the user's actual prompt.
    """
    if extra_args:
        return list(extra_args)
    if cfg.exec_aliases:
        first_alias = next(iter(cfg.exec_aliases.values()))
        return list(first_alias)
    return ["/bin/bash"]


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
    show_timing: bool = False,
) -> int:
    """Create a cage from a scaffold, run an interactive session, and clean up.

    Returns the exit code from the interactive session.
    """
    from agentcage import output

    # Resolve scaffold aliases declared in each scaffold's scaffold.yaml.
    scaffold = scaffold_aliases().get(scaffold, scaffold)

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
    config_text = render_config(
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

    # Create missing bind-mount directories so state persists for any
    # scaffold whose user has opted into host bind-mounts (e.g. a
    # commented-out ~/.<agent> mount the user has chosen to enable).
    # Without this, a login inside the cage never round-trips to the host.
    _ensure_volume_dirs(cfg.container.volumes)

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

        # Set secrets passed via --set-secret. Container mode writes the
        # host Podman store; VM mode stages them for the VM backend (there
        # is no host Podman on macOS).
        provided_keys = _stage_set_secrets(cage_name, secrets, cfg.isolation, podman)

        # Resolve secrets from configured backends (env:, cmd:, systemd-creds:).
        # Container mode only — matches `agentcage cage create`; on the VM
        # backend the VM bridges its own secrets after it starts.
        if cfg.isolation == "container":
            from agentcage.secret_resolver import resolve_and_populate
            provided_keys |= resolve_and_populate(
                podman, cfg, cage_name,
                state.deployment_dir(cage_name),
                skip_keys=provided_keys,
                strict=False,  # agentcage run has its own cleanup on failure
            )

        # Strip secret injection rules for secrets not provided —
        # keeps only rules whose secrets were passed via --set-secret
        # or resolved from a configured source.
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
        state.save_dns_allowlist(cage_name)

        if verbose:
            # VM mode builds images inside the VM, apple-container builds
            # via Apple's `container` CLI from inside the backend — skip
            # the host-podman scaffold setup for both.
            if cfg.isolation == "container":
                run_scaffold_setup(
                    scaffold, cage_name, str(config_path),
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
                # VM mode builds images inside the VM, apple-container builds
                # via Apple's `container` CLI from inside the backend — skip
                # the host-podman scaffold setup for both.
                if cfg.isolation == "container":
                    run_scaffold_setup(
                        scaffold, cage_name, str(config_path),
                        quiet=True,
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
        if show_timing:
            from agentcage import _timing
            _timing.print_summary(cage_name)
        if state.deployment_exists(cage_name):
            state.remove_deployment(cage_name)
        shutil.rmtree(str(config_dir), ignore_errors=True)
        return 1
    except Exception as e:
        output.step_fail(f"Failed to build/deploy cage: {e}")
        # Clean up partial state
        if show_timing:
            from agentcage import _timing
            _timing.print_summary(cage_name)
        if state.deployment_exists(cage_name):
            state.remove_deployment(cage_name)
        shutil.rmtree(str(config_dir), ignore_errors=True)
        return 1

    if show_timing:
        from agentcage import _timing
        _timing.print_summary(cage_name)

    # Summary
    click.echo()
    click.echo(f"  {output.dim(project_dir)}")
    click.echo(f"  {output.dim('Ctrl+D to exit')} {output.dim('·')} {output.dim('agentcage cage audit ' + cage_name)}")
    click.echo()
    output.separator()

    exec_cmd = _resolve_exec_cmd(cfg, extra_args)

    # Run interactive session
    exit_code = 0
    # On apple-container the supervised cage workload runs as PID 1 of a
    # single Apple `container` per cage (no -proxy / -dns / -cage suffix
    # split). Both the container name and the exec path use Apple's
    # `container` CLI; proxy log monitoring goes through the same single
    # container. Backend-protocol lift for `exec`/`logs`/`audit` is the
    # right long-term fix — these special-cases live in cli/run.py today.
    is_apple = cfg.isolation == "apple-container"
    if is_apple:
        container_name = cfg.name
        proxy_container = cfg.name
    else:
        container_name = f"{cfg.name}-cage"
        proxy_container = f"{cfg.name}-proxy"
    exec_flags = ["-it"] if sys.stdin.isatty() else []

    # On the VM backend, route exec and log monitoring through the Lima VM.
    podman_prefix = _vm_podman_prefix(cfg.isolation, cage_name)

    # Skip the proxy-log monitor on apple-container — it relies on
    # `podman logs -f <proxy-container>` and we don't have a separate
    # proxy container or host podman. The audit log inside the cage is
    # still written (mitmproxy → /var/log/agentcage/proxy.log); CLI
    # integration is part of the deferred Backend-protocol lift.
    monitor_stop = threading.Event()
    if not is_apple:
        monitor_thread = threading.Thread(
            target=_monitor_proxy,
            args=(proxy_container, monitor_stop),
            kwargs={"cage_name": cage_name, "interactive": interactive_domains,
                    "podman_prefix": podman_prefix},
            daemon=True,
        )
        monitor_thread.start()
    else:
        monitor_thread = None

    try:
        if is_apple:
            # Route through AppleContainerBackend.exec_argv() so the
            # interactive session is wrapped in capsh: NoNewPrivs + drop=all
            # + --user=$CAGE_USER (uid 1000). A raw `container exec` would
            # inherit the wrapper image's USER (root) because supervisor
            # hardening only applies to the cage workload at stage 90, not
            # to fresh `exec` sessions. See PR #163 for the cage-exec fix —
            # this is the same fix applied to the `agentcage run` path.
            from agentcage.backends.apple_container import AppleContainerBackend
            backend = AppleContainerBackend()
            cmd = backend.exec_argv(
                container_name, "cage", exec_cmd,
                interactive=bool(exec_flags),
                as_root=False,
            )
        else:
            cmd = (
                podman_prefix + ["podman", "exec"]
                + exec_flags + [container_name] + exec_cmd
            )
        result = subprocess.run(cmd)
        exit_code = result.returncode
    except KeyboardInterrupt:
        click.echo("\nSession interrupted.")
        exit_code = 130
    finally:
        monitor_stop.set()
        if monitor_thread is not None:
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
