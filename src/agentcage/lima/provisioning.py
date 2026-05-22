"""Lima VM provisioning — generate Lima YAML config and cloud-init scripts."""

from __future__ import annotations

import math
import os
import platform
import pwd
from pathlib import Path

import click
from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "lima"

# Directories that must NEVER be mounted into the VM, even if a user volume
# points inside them.  Checked as resolved real-path prefixes.
_BLOCKED_MOUNT_DIRS = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".docker",
)


def _parse_port_forwards(ports: list[str]) -> list[dict]:
    """Parse Docker-style port specs into Lima portForwards dicts.

    Accepted formats:
      "HOST:GUEST"           -> host_bind="127.0.0.1", host_port=HOST, guest_port=GUEST
      "BIND:HOST:GUEST"      -> host_bind=BIND, host_port=HOST, guest_port=GUEST

    Returns a list of dicts with keys: host_bind, host_port, guest_port.
    """
    result: list[dict] = []
    for spec in ports:
        parts = spec.split(":")
        if len(parts) == 2:
            host_bind = "127.0.0.1"
            host_port = int(parts[0])
            guest_port = int(parts[1])
        elif len(parts) == 3:
            host_bind = parts[0]
            host_port = int(parts[1])
            guest_port = int(parts[2])
        else:
            raise ValueError(f"Invalid port spec {spec!r}: expected HOST:GUEST or BIND:HOST:GUEST")
        result.append({"host_bind": host_bind, "host_port": host_port, "guest_port": guest_port})
    return result


def _extra_mounts_for_volumes(volumes: list[str]) -> list[dict]:
    """Derive additional Lima mounts for user-defined container volumes.

    Each volume spec ``host:container[:opts]`` needs the *host* portion
    visible inside the VM via virtiofs.  The host path is expanded (both
    ``~`` and ``${VARS}`` such as ``${PROJECT_DIR}``), checked against the
    blocked sensitive directories, and — crucially — skipped if it does
    not exist.  Lima only *warns* about a missing mount source, but the
    VM then never finishes starting (SSH bring-up wedges), so a bogus
    mount must never be emitted.

    Returns a list of ``{"location": ..., "writable": ...}`` dicts.
    """
    home = os.path.realpath(os.path.expanduser("~"))
    config_dir = os.path.realpath(os.path.expanduser("~/.config/agentcage"))
    data_dir = os.path.realpath(os.path.expanduser("~/.local/share/agentcage"))
    seen: set[str] = set()
    mounts: list[dict] = []

    for vol in volumes:
        host_part = vol.split(":")[0]
        # Expand ~ and ${VARS} (e.g. ${PROJECT_DIR}) before resolving.
        expanded = os.path.expandvars(os.path.expanduser(host_part))
        host_path = os.path.realpath(expanded)

        # Block sensitive directories — checked before the existence test
        # below so an explicit attempt to mount ~/.ssh always fails loudly.
        for blocked in _BLOCKED_MOUNT_DIRS:
            blocked_path = os.path.join(home, blocked)
            if host_path == blocked_path or host_path.startswith(blocked_path + os.sep):
                raise ValueError(
                    f"volume host path {host_part!r} resolves under ~/{blocked} "
                    f"which must not be exposed to the VM"
                )

        # Skip if already covered by the default mounts
        if host_path.startswith(config_dir + os.sep) or host_path == config_dir:
            continue
        if host_path.startswith(data_dir + os.sep) or host_path == data_dir:
            continue

        # Skip paths that did not expand or do not exist on the host.
        # Lima cannot virtiofs-mount a missing source, and handing it one
        # anyway wedges VM startup at the SSH requirement.
        if "$" in host_path or not os.path.exists(host_path):
            click.echo(
                f"warning: not mounting {host_part!r} into the VM "
                f"(host path does not exist)",
                err=True,
            )
            continue

        # Lima only virtiofs-shares directories, so a file-source volume
        # (e.g. the claude-code scaffold's ~/.claude.json) cannot be a
        # Lima mount — `limactl create` would fail fatally with "refers
        # to a non-directory path". Skip it here: it is not lost, the
        # quadlet layer stages a copy into ~/.local/share/agentcage
        # (already mounted) and bind-mounts that.
        if not os.path.isdir(host_path):
            continue

        if host_path in seen:
            continue
        seen.add(host_path)

        # Determine writable from volume opts (default read-only for safety)
        parts = vol.split(":")
        writable = False
        if len(parts) >= 3:
            opts = parts[2].lower().split(",")
            if "rw" in opts:
                writable = True

        mounts.append({"location": host_path, "writable": writable})

    return mounts


def generate_lima_config(config: object) -> str:
    """Generate a Lima YAML configuration string for *config*.

    Uses duck typing — *config* must expose:
      - config.name (str)
      - config.vm.vcpus (int)
      - config.vm.mem_mb (int)
      - config.container.ports (list[str])
      - config.container.volumes (list[str])

    Returns the rendered Lima YAML as a string.
    """
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
    )

    # Determine vmType based on host OS
    system = platform.system()
    vm_type = "vz" if system == "Darwin" else "qemu"

    # Compute memory in GiB (ceiling division)
    mem_gb = math.ceil(config.vm.mem_mb / 1024)

    # Render provisioning script. Lima names the guest user after the host
    # user, deriving it from the invoking UID's passwd entry. Resolve it the
    # same way — pwd.getpwuid(os.getuid()), not getpass.getuser(), which
    # trusts $USER/$LOGNAME and can disagree under sudo or an overridden env.
    provision_tmpl = env.get_template("provision.sh.j2")
    provision_script = provision_tmpl.render(
        lima_user=pwd.getpwuid(os.getuid()).pw_name,
    )

    # Parse port forwards
    port_forwards = _parse_port_forwards(config.container.ports)

    # Compute extra mounts for user-defined volumes
    volumes = getattr(getattr(config, "container", None), "volumes", []) or []
    extra_mounts = _extra_mounts_for_volumes(volumes)

    # Render main Lima YAML
    lima_tmpl = env.get_template("lima.yaml.j2")
    return lima_tmpl.render(
        name=config.name,
        vm_type=vm_type,
        vcpus=config.vm.vcpus,
        mem_gb=mem_gb,
        provision_script=provision_script,
        port_forwards=port_forwards,
        extra_mounts=extra_mounts,
    )
