"""Lima VM provisioning — generate Lima YAML config and cloud-init scripts."""

from __future__ import annotations

import math
import platform
from pathlib import Path

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "lima"

# Default Lima user inside the VM
_LIMA_USER = "lima"


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


def generate_lima_config(config: object) -> str:
    """Generate a Lima YAML configuration string for *config*.

    Uses duck typing — *config* must expose:
      - config.name (str)
      - config.vm.vcpus (int)
      - config.vm.mem_mb (int)
      - config.container.ports (list[str])

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

    # Render provisioning script
    provision_tmpl = env.get_template("provision.sh.j2")
    provision_script = provision_tmpl.render(lima_user=_LIMA_USER)

    # Parse port forwards
    port_forwards = _parse_port_forwards(config.container.ports)

    # Render main Lima YAML
    lima_tmpl = env.get_template("lima.yaml.j2")
    return lima_tmpl.render(
        name=config.name,
        vm_type=vm_type,
        vcpus=config.vm.vcpus,
        mem_gb=mem_gb,
        provision_script=provision_script,
        port_forwards=port_forwards,
    )
