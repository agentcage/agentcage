# Lima VM Backend — Replace Firecracker with Lima

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Firecracker backend with a Lima-based VM backend that works on both Linux (QEMU/KVM) and macOS (Virtualization.framework), and make `vm` the only isolation mode on macOS.

**Architecture:** Lima manages Linux VMs via `limactl`. Inside each VM, the existing Podman + quadlet + systemd stack runs unchanged. The host-side code generates Lima YAML configs (cloud-init provisioned), and communicates with the VM via `lima exec`. On Linux, Lima uses QEMU/KVM. On macOS, Lima uses Apple's Virtualization.framework (`vmType: vz`). The `container` isolation mode is preserved for Linux/WSL2 users who want direct Podman without a VM.

**Tech Stack:** Lima (`limactl`), cloud-init, Jinja2 templates, existing Podman/quadlet stack inside VM

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `src/agentcage/lima/__init__.py` | Package init |
| `src/agentcage/lima/prerequisites.py` | Check `limactl` available, platform detection |
| `src/agentcage/lima/instance.py` | Lima instance lifecycle: create, start, stop, delete, exec, status |
| `src/agentcage/lima/provisioning.py` | Generate Lima YAML config + cloud-init scripts |
| `src/agentcage/backends/vm.py` | New `VmBackend` implementing `Backend` protocol via Lima |
| `src/agentcage/templates/lima/lima.yaml.j2` | Lima instance YAML template |
| `src/agentcage/templates/lima/provision.sh.j2` | Cloud-init provisioning script (install Podman, setup systemd) |
| `tests/test_lima_prerequisites.py` | Unit tests for prerequisite checks |
| `tests/test_lima_instance.py` | Unit tests for Lima instance management (mocked) |
| `tests/test_lima_provisioning.py` | Unit tests for YAML/cloud-init generation |
| `tests/test_vm_backend.py` | Unit tests for VmBackend |

### Modified files

| File | Changes |
|------|---------|
| `src/agentcage/config.py` | Replace `isolation: "firecracker"` with `"vm"`, replace `FirecrackerConfig` with `VmConfig` (vcpus, mem_mb) |
| `src/agentcage/backend.py` | Update docstrings (no functional changes) |
| `src/agentcage/backends/__init__.py` | `get_backend()`: add `"vm"` → `VmBackend`, remove `"firecracker"` |
| `src/agentcage/cli.py` | Replace all `firecracker` references: `_require_root` checks, log commands (Lima exec instead of journalctl), audit commands |
| `src/agentcage/quadlets.py` | No changes — quadlets run inside the VM as-is |
| `src/agentcage/systemd.py` | No changes — used by container backend and inside the VM |
| `pyproject.toml` | No new Python deps (Lima is an external binary) |

### Deleted files

| File | Reason |
|------|--------|
| `src/agentcage/backends/firecracker.py` | Replaced by `backends/vm.py` |
| `src/agentcage/firecracker/` (entire package) | All replaced by Lima: `binaries.py`, `kernel.py`, `network.py`, `prerequisites.py`, `rootfs.py`, `secrets.py`, `vmconfig.py` |
| `src/agentcage/templates/firecracker/` | Replaced by `templates/lima/` |
| `src/agentcage/data/firecracker/` | `vm-init.sh` and `Containerfile.vmbase` no longer needed — Lima cloud-init handles provisioning |
| `tests/test_firecracker_config.py` | Replaced by new VM config tests |
| `tests/test_prerequisites.py` | Replaced by `test_lima_prerequisites.py` |
| `tests/test_vmconfig.py` | No longer applicable |
| `tests/test_firecracker_rootfs.py` | No longer applicable |
| `tests/test_network.py` | TAP/bridge networking removed |

---

## Task 1: Lima prerequisites module

**Files:**
- Create: `src/agentcage/lima/__init__.py`
- Create: `src/agentcage/lima/prerequisites.py`
- Create: `tests/test_lima_prerequisites.py`

- [ ] **Step 1: Write failing tests for prerequisite checks**

```python
# tests/test_lima_prerequisites.py
"""Tests for Lima prerequisite checks."""
import platform
import shutil
from unittest.mock import patch

import pytest

from agentcage.lima.prerequisites import check_prerequisites, detect_platform


class TestDetectPlatform:
    def test_linux(self):
        with patch("platform.system", return_value="Linux"):
            assert detect_platform() == "linux"

    def test_macos(self):
        with patch("platform.system", return_value="Darwin"):
            assert detect_platform() == "macos"

    def test_unsupported(self):
        with patch("platform.system", return_value="Windows"):
            assert detect_platform() == "unsupported"


class TestCheckPrerequisites:
    def test_missing_limactl(self):
        with patch("shutil.which", return_value=None):
            issues = check_prerequisites()
            assert any("limactl" in i for i in issues)

    def test_limactl_available(self):
        with patch("shutil.which", return_value="/usr/bin/limactl"):
            with patch("platform.system", return_value="Linux"):
                issues = check_prerequisites()
                assert not any("limactl" in i for i in issues)

    def test_macos_no_container_mode_warning(self):
        """On macOS, container mode is not available — only vm."""
        with patch("platform.system", return_value="Darwin"):
            assert detect_platform() == "macos"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_lima_prerequisites.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agentcage.lima'`

- [ ] **Step 3: Implement prerequisites module**

```python
# src/agentcage/lima/__init__.py
"""Lima VM backend for agentcage."""

# src/agentcage/lima/prerequisites.py
"""Check prerequisites for the Lima VM backend."""
from __future__ import annotations

import platform
import shutil


def detect_platform() -> str:
    """Return 'linux', 'macos', or 'unsupported'."""
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Darwin":
        return "macos"
    return "unsupported"


def check_prerequisites() -> list[str]:
    """Return list of unmet prerequisites for the Lima VM backend."""
    issues: list[str] = []

    if not shutil.which("limactl"):
        issues.append(
            "limactl is not installed. "
            "Install Lima: https://lima-vm.io/docs/installation/"
        )

    plat = detect_platform()
    if plat == "unsupported":
        issues.append(
            f"Unsupported platform: {platform.system()}. "
            "Lima VM backend requires Linux or macOS."
        )

    return issues
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_lima_prerequisites.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentcage/lima/__init__.py src/agentcage/lima/prerequisites.py tests/test_lima_prerequisites.py
git commit -m "feat: add Lima prerequisites module with platform detection"
```

---

## Task 2: Lima instance management

**Files:**
- Create: `src/agentcage/lima/instance.py`
- Create: `tests/test_lima_instance.py`

- [ ] **Step 1: Write failing tests for instance lifecycle**

```python
# tests/test_lima_instance.py
"""Tests for Lima instance lifecycle management."""
from unittest.mock import patch, MagicMock
import subprocess

import pytest

from agentcage.lima.instance import LimaInstance


class TestLimaInstance:
    def test_instance_name(self):
        inst = LimaInstance("mycage")
        assert inst.name == "agentcage-mycage"

    def test_create_calls_limactl(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.create("/path/to/lima.yaml")
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "limactl"
            assert args[1] == "create"
            assert "--name=agentcage-mycage" in args

    def test_start_calls_limactl(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.start()
            args = mock_run.call_args[0][0]
            assert args[:3] == ["limactl", "start", "agentcage-mycage"]

    def test_stop_calls_limactl(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.stop()
            args = mock_run.call_args[0][0]
            assert args[:3] == ["limactl", "stop", "agentcage-mycage"]

    def test_delete_calls_limactl(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            inst.delete()
            args = mock_run.call_args[0][0]
            assert "delete" in args
            assert "--force" in args

    def test_exec_runs_command_in_vm(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok\n")
            result = inst.exec(["echo", "hello"])
            args = mock_run.call_args[0][0]
            assert args[0] == "limactl"
            assert args[1] == "shell"
            assert "agentcage-mycage" in args
            assert "echo" in args
            assert "hello" in args

    def test_is_running_active(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout='{"status":"Running"}\n'
            )
            assert inst.is_running() is True

    def test_is_running_stopped(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout='{"status":"Stopped"}\n'
            )
            assert inst.is_running() is False

    def test_is_running_not_found(self):
        inst = LimaInstance("mycage")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "limactl")
            assert inst.is_running() is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_lima_instance.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement instance module**

```python
# src/agentcage/lima/instance.py
"""Lima instance lifecycle management."""
from __future__ import annotations

import json
import subprocess


_LIMA_PREFIX = "agentcage-"


class LimaInstance:
    """Manage a single Lima VM instance for an agentcage cage."""

    def __init__(self, cage_name: str) -> None:
        self._cage_name = cage_name
        self.name = f"{_LIMA_PREFIX}{cage_name}"

    def create(self, config_path: str) -> None:
        """Create a Lima instance from a YAML config file."""
        subprocess.run(
            ["limactl", "create", f"--name={self.name}", config_path],
            check=True,
        )

    def start(self) -> None:
        """Start the Lima instance."""
        subprocess.run(
            ["limactl", "start", self.name],
            check=True,
        )

    def stop(self) -> None:
        """Stop the Lima instance."""
        subprocess.run(
            ["limactl", "stop", self.name],
            check=True,
        )

    def delete(self) -> None:
        """Delete the Lima instance and its disk."""
        subprocess.run(
            ["limactl", "delete", "--force", self.name],
            check=True,
        )

    def exec(
        self,
        cmd: list[str],
        *,
        check: bool = True,
        capture_output: bool = True,
        text: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run a command inside the VM."""
        return subprocess.run(
            ["limactl", "shell", self.name, "--", *cmd],
            check=check,
            capture_output=capture_output,
            text=text,
        )

    def is_running(self) -> bool:
        """Check if the Lima instance is running."""
        try:
            result = subprocess.run(
                ["limactl", "list", "--json", self.name],
                check=True,
                capture_output=True,
                text=True,
            )
            info = json.loads(result.stdout)
            return info.get("status") == "Running"
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return False

    def exists(self) -> bool:
        """Check if the Lima instance exists (any state)."""
        try:
            subprocess.run(
                ["limactl", "list", "--json", self.name],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_lima_instance.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentcage/lima/instance.py tests/test_lima_instance.py
git commit -m "feat: add Lima instance lifecycle management"
```

---

## Task 3: Lima provisioning — YAML config and cloud-init generation

**Files:**
- Create: `src/agentcage/lima/provisioning.py`
- Create: `src/agentcage/templates/lima/lima.yaml.j2`
- Create: `src/agentcage/templates/lima/provision.sh.j2`
- Create: `tests/test_lima_provisioning.py`

- [ ] **Step 1: Write failing tests for provisioning**

```python
# tests/test_lima_provisioning.py
"""Tests for Lima YAML config and cloud-init generation."""
import platform
import yaml
from unittest.mock import patch

import pytest

from agentcage.lima.provisioning import generate_lima_config
from agentcage.config import Config, ContainerConfig, VmConfig


class TestGenerateLimaConfig:
    def _make_config(self, **vm_overrides) -> Config:
        cfg = Config()
        cfg.name = "testcage"
        cfg.isolation = "vm"
        cfg.container.image = "ubuntu:latest"
        vm = VmConfig()
        for k, v in vm_overrides.items():
            setattr(vm, k, v)
        cfg.vm = vm
        return cfg

    def test_generates_valid_yaml(self):
        cfg = self._make_config()
        result = generate_lima_config(cfg)
        parsed = yaml.safe_load(result)
        assert isinstance(parsed, dict)

    def test_vmtype_linux(self):
        cfg = self._make_config()
        with patch("platform.system", return_value="Linux"):
            result = generate_lima_config(cfg)
        parsed = yaml.safe_load(result)
        assert parsed["vmType"] == "qemu"

    def test_vmtype_macos(self):
        cfg = self._make_config()
        with patch("platform.system", return_value="Darwin"):
            result = generate_lima_config(cfg)
        parsed = yaml.safe_load(result)
        assert parsed["vmType"] == "vz"

    def test_cpu_and_memory(self):
        cfg = self._make_config(vcpus=4, mem_mb=4096)
        result = generate_lima_config(cfg)
        parsed = yaml.safe_load(result)
        assert parsed["cpus"] == 4
        assert parsed["memory"] == "4GiB"

    def test_provision_script_included(self):
        cfg = self._make_config()
        result = generate_lima_config(cfg)
        parsed = yaml.safe_load(result)
        assert "provision" in parsed
        scripts = [p for p in parsed["provision"] if p.get("mode") == "system"]
        assert len(scripts) >= 1

    def test_port_forwards(self):
        cfg = self._make_config()
        cfg.container.ports = ["8080:80", "0.0.0.0:443:443"]
        result = generate_lima_config(cfg)
        parsed = yaml.safe_load(result)
        assert "portForwards" in parsed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_lima_provisioning.py -v`
Expected: FAIL

- [ ] **Step 3: Create Lima YAML template**

```yaml
# src/agentcage/templates/lima/lima.yaml.j2
# Lima VM config for agentcage cage: {{ name }}
# Auto-generated — do not edit manually.

vmType: {{ vm_type }}
{% if vm_type == "vz" %}
rosetta:
  enabled: false
mountType: virtiofs
{% endif %}

images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    arch: "x86_64"
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: "aarch64"

cpus: {{ vcpus }}
memory: "{{ mem_gb }}GiB"
disk: "20GiB"

containerd:
  system: false
  user: false

provision:
  - mode: system
    script: |
{{ provision_script | indent(6, first=true) }}

{% if port_forwards %}
portForwards:
{% for pf in port_forwards %}
  - guestPort: {{ pf.guest_port }}
    hostPort: {{ pf.host_port }}
{% if pf.host_bind != "0.0.0.0" %}
    hostIP: "{{ pf.host_bind }}"
{% endif %}
{% endfor %}
{% endif %}
```

- [ ] **Step 4: Create provisioning script template**

```bash
# src/agentcage/templates/lima/provision.sh.j2
#!/bin/bash
# Cloud-init provisioning for agentcage VM
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Install Podman
apt-get update -qq
apt-get install -y -qq podman fuse-overlayfs uidmap slirp4netns socat iptables

# Configure Podman for rootless
mkdir -p /etc/containers
cat > /etc/containers/storage.conf <<'STOR'
[storage]
driver = "overlay"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
STOR

# Enable lingering for the lima user so systemd user services persist
loginctl enable-linger {{ lima_user }}

echo "agentcage provisioning complete"
```

- [ ] **Step 5: Implement provisioning module**

```python
# src/agentcage/lima/provisioning.py
"""Generate Lima YAML config and cloud-init provisioning scripts."""
from __future__ import annotations

import math
import platform
from pathlib import Path

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.config import Config

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "lima"


def _vm_type() -> str:
    """Return the Lima vmType for the current platform."""
    if platform.system() == "Darwin":
        return "vz"
    return "qemu"


def _parse_port_forwards(ports: list[str]) -> list[dict]:
    """Convert agentcage port specs to Lima portForward entries."""
    forwards = []
    for spec in ports:
        parts = spec.split(":")
        if len(parts) == 3:
            host_bind, host_port, guest_port = parts
        elif len(parts) == 2:
            host_bind = "0.0.0.0"
            host_port, guest_port = parts
        else:
            continue
        forwards.append({
            "host_bind": host_bind,
            "host_port": int(host_port),
            "guest_port": int(guest_port),
        })
    return forwards


def generate_lima_config(config: Config) -> str:
    """Generate a Lima YAML config string for a cage."""
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Generate provisioning script
    prov_tmpl = env.get_template("provision.sh.j2")
    provision_script = prov_tmpl.render(
        lima_user="lima",  # Lima's default user
    )

    # Generate main YAML
    yaml_tmpl = env.get_template("lima.yaml.j2")
    vm = config.vm
    return yaml_tmpl.render(
        name=config.name,
        vm_type=_vm_type(),
        vcpus=vm.vcpus,
        mem_gb=math.ceil(vm.mem_mb / 1024),
        provision_script=provision_script,
        port_forwards=_parse_port_forwards(config.container.ports),
    )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_lima_provisioning.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/agentcage/lima/provisioning.py src/agentcage/templates/lima/ tests/test_lima_provisioning.py
git commit -m "feat: add Lima provisioning — YAML config and cloud-init generation"
```

---

## Task 4: Update config — replace `firecracker` with `vm`

**Files:**
- Modify: `src/agentcage/config.py`
- Modify: `tests/test_firecracker_config.py` → rename to `tests/test_config.py`

- [ ] **Step 1: Write failing test for new vm config**

```python
# In existing config test file, add/modify:
def test_isolation_vm():
    raw = {"name": "test", "isolation": "vm", "container": {"image": "ubuntu"},
           "vm": {"vcpus": 4, "mem_mb": 4096}}
    # write to tmp yaml, load, validate
    cfg = load_config(tmp_path)
    assert cfg.isolation == "vm"
    assert cfg.vm.vcpus == 4
    assert cfg.vm.mem_mb == 4096

def test_isolation_firecracker_rejected():
    """Old firecracker isolation value should fail validation."""
    cfg = Config(name="test", isolation="firecracker",
                 container=ContainerConfig(image="ubuntu"))
    with pytest.raises(ValueError, match="container.*vm"):
        validate_config(cfg)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_firecracker_config.py -v -k "vm or firecracker_rejected"`
Expected: FAIL

- [ ] **Step 3: Update config.py**

In `config.py`:
- Rename `FirecrackerConfig` → `VmConfig`, remove `kernel` and `firecracker_bin` fields (keep `vcpus`, `mem_mb`)
- In `Config`: rename `firecracker` field → `vm`, change `isolation` default doc
- In `load_config()`: parse `vm:` section (with `firecracker:` fallback for migration info)
- In `validate_config()`: accept `"container"` and `"vm"`, reject `"firecracker"` with helpful message

```python
@dataclass
class VmConfig:
    vcpus: int = 2
    mem_mb: int = 2048

@dataclass
class Config:
    ...
    isolation: str = "container"  # "container" | "vm"
    vm: VmConfig = field(default_factory=VmConfig)
    # Remove: firecracker field
```

- [ ] **Step 4: Run all config tests**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_firecracker_config.py tests/test_config.py -v`
Expected: PASS (after updating existing tests for renamed fields)

- [ ] **Step 5: Commit**

```bash
git add src/agentcage/config.py tests/
git commit -m "feat: replace FirecrackerConfig with VmConfig, isolation='vm'"
```

---

## Task 5: Implement VmBackend

**Files:**
- Create: `src/agentcage/backends/vm.py`
- Create: `tests/test_vm_backend.py`
- Modify: `src/agentcage/backends/__init__.py`

- [ ] **Step 1: Write failing tests for VmBackend**

```python
# tests/test_vm_backend.py
"""Tests for the Lima-based VM backend."""
from unittest.mock import patch, MagicMock
import pytest

from agentcage.backends.vm import VmBackend
from agentcage.config import Config, ContainerConfig, VmConfig


class TestVmBackend:
    def _make_config(self) -> Config:
        cfg = Config()
        cfg.name = "testcage"
        cfg.isolation = "vm"
        cfg.container = ContainerConfig(image="ubuntu:latest")
        cfg.vm = VmConfig(vcpus=2, mem_mb=2048)
        return cfg

    def test_check_prerequisites_no_lima(self):
        backend = VmBackend()
        with patch("shutil.which", return_value=None):
            issues = backend.check_prerequisites(self._make_config())
            assert any("limactl" in i for i in issues)

    def test_start_creates_and_starts_instance(self):
        backend = VmBackend()
        with patch.object(backend, "_instance") as mock_inst:
            mock_inst.return_value.is_running.return_value = False
            mock_inst.return_value.exists.return_value = True
            backend.start("testcage")
            mock_inst.return_value.start.assert_called_once()

    def test_stop_stops_instance(self):
        backend = VmBackend()
        with patch.object(backend, "_instance") as mock_inst:
            mock_inst.return_value.is_running.return_value = True
            backend.stop("testcage")
            mock_inst.return_value.stop.assert_called_once()

    def test_service_names(self):
        backend = VmBackend()
        assert backend.service_names("test") == ["cage"]

    def test_is_running(self):
        backend = VmBackend()
        with patch("agentcage.backends.vm.LimaInstance") as MockInst:
            MockInst.return_value.is_running.return_value = True
            assert backend.is_running("test", "cage") is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_vm_backend.py -v`
Expected: FAIL

- [ ] **Step 3: Implement VmBackend**

```python
# src/agentcage/backends/vm.py
"""VM backend — Lima-managed VMs with Podman containers inside."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import click

from agentcage.config import Config
from agentcage.lima.instance import LimaInstance
from agentcage.lima.prerequisites import check_prerequisites
from agentcage.lima.provisioning import generate_lima_config
from agentcage.podman import Podman
from agentcage.quadlets import generate_quadlets


class VmBackend:
    """Backend using Lima VMs with Podman + quadlets inside."""

    def __init__(self) -> None:
        self._podman = Podman()

    def _instance(self, name: str) -> LimaInstance:
        return LimaInstance(name)

    def check_prerequisites(self, config: Config) -> list[str]:
        return check_prerequisites()

    def build_artifacts(self, config: Config, deploy_name: str) -> None:
        # Images are built inside the VM during provisioning
        pass

    def generate_units(
        self,
        config: Config,
        config_host_path: str,
        patches_host_dir: str,
        deploy_name: str,
    ) -> dict[str, str]:
        """Generate Lima YAML config as the 'unit' for this backend."""
        lima_yaml = generate_lima_config(config)
        return {"lima.yaml": lima_yaml}

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/lima"))

    def install_units(self, units: dict[str, str]) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        for filename, content in units.items():
            (dest / filename).write_text(content)

    def start(self, name: str) -> None:
        inst = self._instance(name)
        if not inst.exists():
            # First start: create the instance from saved config
            config_path = self.unit_dir() / "lima.yaml"
            inst.create(str(config_path))
        if not inst.is_running():
            inst.start()
        click.echo(f"Started {name} (Lima VM)")

    def stop(self, name: str) -> None:
        inst = self._instance(name)
        if inst.is_running():
            inst.stop()

    def restart(self, name: str) -> None:
        inst = self._instance(name)
        if inst.is_running():
            inst.stop()
        inst.start()

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:
        removed: list[str] = []
        inst = self._instance(name)
        if inst.exists():
            inst.delete()
            removed.append(f"lima-instance:{inst.name}")
        # Remove local config
        config_path = self.unit_dir() / "lima.yaml"
        if config_path.exists():
            config_path.unlink()
            removed.append("lima.yaml")
        return removed

    def is_running(self, name: str, service: str) -> bool:
        return self._instance(name).is_running()

    def service_names(self, name: str) -> list[str]:
        return ["cage"]
```

- [ ] **Step 4: Update backends/__init__.py**

```python
# src/agentcage/backends/__init__.py
def get_backend(config: Config) -> Backend:
    isolation = getattr(config, "isolation", "container")
    if isolation == "vm":
        from agentcage.backends.vm import VmBackend
        return VmBackend()
    from agentcage.backends.container import ContainerBackend
    return ContainerBackend()
```

- [ ] **Step 5: Run tests**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_vm_backend.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentcage/backends/vm.py src/agentcage/backends/__init__.py tests/test_vm_backend.py
git commit -m "feat: add VmBackend using Lima for VM lifecycle"
```

---

## Task 6: Update CLI — remove Firecracker references, update logs/audit

**Files:**
- Modify: `src/agentcage/cli.py`

- [ ] **Step 1: Replace `_require_root` checks for firecracker**

Find all `if cfg.isolation == "firecracker": _require_root(...)` blocks and remove them. Lima doesn't require root.

- [ ] **Step 2: Update `cage_logs` — replace journalctl with `lima exec journalctl`**

For `vm` isolation, logs are read via:
```python
def _logs_vm(name, services, lines, no_follow, min_level=None):
    """Read logs from the Lima VM via lima exec."""
    inst = LimaInstance(name)
    # Inside the VM, journalctl works normally
    cmd = ["journalctl", "--user"]
    for svc in services:
        cmd += ["-u", f"{name}-{svc}"]
    cmd += ["-n", str(lines)]
    if not no_follow:
        cmd.append("-f")
    # Exec into the VM
    full_cmd = ["limactl", "shell", inst.name, "--"] + cmd
    if min_level is None:
        os.execvp("limactl", full_cmd)
    else:
        # Filter on Python side (same as container mode)
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
```

- [ ] **Step 3: Update `_build_audit_journal_cmd` for vm isolation**

Replace the `firecracker` branch with `vm`:
```python
if cfg.isolation == "vm":
    inst = LimaInstance(name)
    cmd = ["limactl", "shell", inst.name, "--",
           "journalctl", "--user", "-u", f"{name}-cage", "-o", "cat"]
```

- [ ] **Step 4: Update `cage_logs` dispatch**

```python
if cfg.isolation == "vm":
    _logs_vm(name, selected, lines, no_follow_effective, min_level)
else:
    _logs_container(name, selected, lines, no_follow_effective, min_level)
```

- [ ] **Step 5: Replace all remaining `"firecracker"` string literals in cli.py**

Search for `firecracker` in cli.py and update to `vm` where applicable. Update help text.

- [ ] **Step 6: Update `from agentcage import state, systemd` import**

Add `from agentcage.lima.instance import LimaInstance` where needed.

- [ ] **Step 7: Remove `_restart_cage` direct systemd calls**

The `_restart_cage` function (around line 2070) calls `systemd.daemon_reload()` and `systemd.stop_unit/start_unit` directly. For `vm` isolation, delegate to the backend instead.

- [ ] **Step 8: Run existing e2e test (container mode should still work)**

Run: `cd /home/luca/github/agentcage && bash tests/e2e_basic.sh`
Expected: Container mode still works

- [ ] **Step 9: Commit**

```bash
git add src/agentcage/cli.py
git commit -m "feat: update CLI for vm isolation — Lima exec for logs/audit, remove root requirement"
```

---

## Task 7: Delete Firecracker-specific code

**Files:**
- Delete: `src/agentcage/backends/firecracker.py`
- Delete: `src/agentcage/firecracker/` (entire package)
- Delete: `src/agentcage/templates/firecracker/`
- Delete: `src/agentcage/data/firecracker/`
- Delete: `tests/test_firecracker_config.py` (if not already renamed)
- Delete: `tests/test_prerequisites.py`
- Delete: `tests/test_vmconfig.py`
- Delete: `tests/test_firecracker_rootfs.py`
- Delete: `tests/test_network.py`

- [ ] **Step 1: Delete all firecracker files**

```bash
rm -rf src/agentcage/backends/firecracker.py
rm -rf src/agentcage/firecracker/
rm -rf src/agentcage/templates/firecracker/
rm -rf src/agentcage/data/firecracker/
rm -f tests/test_prerequisites.py tests/test_vmconfig.py tests/test_firecracker_rootfs.py tests/test_network.py
```

- [ ] **Step 2: Run all tests to verify nothing is broken**

Run: `cd /home/luca/github/agentcage && python -m pytest -v`
Expected: All tests pass (new Lima tests + remaining container tests)

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "chore: remove Firecracker backend and all associated code"
```

---

## Task 8: Platform-aware validation and auto-selection

**Files:**
- Modify: `src/agentcage/config.py`
- Modify: `src/agentcage/cli.py`
- Create: `tests/test_platform_validation.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_platform_validation.py
from unittest.mock import patch
import pytest
from agentcage.config import Config, ContainerConfig, VmConfig, validate_config


class TestPlatformValidation:
    def test_container_rejected_on_macos(self):
        cfg = Config(name="test", isolation="container",
                     container=ContainerConfig(image="ubuntu"))
        with patch("platform.system", return_value="Darwin"):
            with pytest.raises(ValueError, match="container.*macOS"):
                validate_config(cfg)

    def test_vm_accepted_on_macos(self):
        cfg = Config(name="test", isolation="vm",
                     container=ContainerConfig(image="ubuntu"),
                     vm=VmConfig())
        with patch("platform.system", return_value="Darwin"):
            warnings = validate_config(cfg)
            # Should not raise

    def test_container_accepted_on_linux(self):
        cfg = Config(name="test", isolation="container",
                     container=ContainerConfig(image="ubuntu"))
        with patch("platform.system", return_value="Linux"):
            warnings = validate_config(cfg)
            # Should not raise
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_platform_validation.py -v`

- [ ] **Step 3: Add platform validation to validate_config**

In `config.py`, add after the isolation field check:

```python
import platform

if config.isolation == "container" and platform.system() == "Darwin":
    raise ValueError(
        "container isolation is not supported on macOS. "
        "Use isolation: vm instead."
    )
```

- [ ] **Step 4: Run tests**

Run: `cd /home/luca/github/agentcage && python -m pytest tests/test_platform_validation.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentcage/config.py tests/test_platform_validation.py
git commit -m "feat: reject container isolation on macOS, require vm"
```

---

## Task 9: Integration test — Lima VM backend end-to-end

**Files:**
- Create: `tests/e2e_lima.sh`

- [ ] **Step 1: Write e2e test script**

```bash
#!/usr/bin/env bash
# End-to-end test for Lima VM backend.
# Requires: limactl, podman
set -euo pipefail

CAGE_NAME="e2e-lima-test"

cleanup() {
    agentcage cage destroy "$CAGE_NAME" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Creating test config ==="
cat > /tmp/e2e-lima-cage.yaml <<EOF
name: $CAGE_NAME
isolation: vm
vm:
  vcpus: 2
  mem_mb: 2048
container:
  image: docker.io/library/nginx:latest
  ports:
    - "18080:80"
domains:
  allow:
    - "*.docker.io"
    - "*.docker.com"
    - "production.cloudflare.docker.com"
EOF

echo "=== Creating cage ==="
agentcage cage create -c /tmp/e2e-lima-cage.yaml

echo "=== Checking cage is running ==="
agentcage cage list | grep "$CAGE_NAME" | grep -q "running"

echo "=== Waiting for nginx to come up ==="
for i in $(seq 1 30); do
    if curl -sf http://localhost:18080/ >/dev/null 2>&1; then
        echo "nginx is up"
        break
    fi
    sleep 2
done

echo "=== Checking logs ==="
agentcage cage logs "$CAGE_NAME" -n 5

echo "=== Stopping cage ==="
agentcage cage stop "$CAGE_NAME"

echo "=== Starting cage ==="
agentcage cage start "$CAGE_NAME"

echo "=== Destroying cage ==="
agentcage cage destroy "$CAGE_NAME"

echo "=== ALL TESTS PASSED ==="
```

- [ ] **Step 2: Run e2e test on a machine with Lima**

Run: `bash tests/e2e_lima.sh`
Expected: All steps pass

- [ ] **Step 3: Commit**

```bash
git add tests/e2e_lima.sh
git commit -m "test: add end-to-end test for Lima VM backend"
```

---

## Task 10: Update documentation

**Files:**
- Modify: `docs/configuration.md` — replace `firecracker` section with `vm`
- Modify: `docs/firecracker.md` → rename to `docs/vm.md`
- Modify: `docs/cli.md` — update isolation references
- Modify: `docs/architecture.md` — update diagram

- [ ] **Step 1: Update docs/configuration.md**

Replace the `firecracker:` config section with:
```markdown
### VM Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vcpus` | `int` | `2` | Number of virtual CPUs |
| `mem_mb` | `int` | `2048` | Memory in megabytes |
```

- [ ] **Step 2: Rename and update docs/firecracker.md → docs/vm.md**

Replace Firecracker-specific content with Lima-based VM backend docs.

- [ ] **Step 3: Update docs/cli.md**

Replace references to `firecracker` isolation, `sudo` requirements, etc.

- [ ] **Step 4: Commit**

```bash
git add docs/
git commit -m "docs: update documentation for Lima VM backend"
```
