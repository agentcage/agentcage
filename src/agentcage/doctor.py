"""Diagnostic checks for agentcage — ``agentcage doctor``."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import click

from agentcage.output import dim, green, red


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Result of a single diagnostic check."""
    level: str  # "pass", "warn", "error"
    message: str
    hint: str = ""


@dataclass
class Section:
    """A group of related checks with a heading."""
    title: str
    results: list[CheckResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------

def _detect_distro() -> str:
    """Detect the Linux distribution family from /etc/os-release."""
    try:
        text = Path("/etc/os-release").read_text()
    except OSError:
        return "unknown"

    kv: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            kv[key.strip()] = val.strip().strip('"')

    distro_id = kv.get("ID", "")
    id_like = kv.get("ID_LIKE", "")

    if distro_id in ("arch", "archarm") or "arch" in id_like:
        return "arch"
    if distro_id in ("debian", "ubuntu", "pop", "mint", "elementary", "zorin",
                      "kali", "raspbian") or "debian" in id_like or "ubuntu" in id_like:
        return "debian"
    if distro_id == "fedora" or "fedora" in id_like:
        return "fedora"
    if distro_id in ("rhel", "centos", "rocky", "alma", "ol") or "rhel" in id_like:
        return "rhel"
    if distro_id.startswith("opensuse") or distro_id == "sles" or "suse" in id_like:
        return "opensuse"

    return "unknown"


# ---------------------------------------------------------------------------
# Remediation hints
# ---------------------------------------------------------------------------

_INSTALL_PODMAN = {
    "arch":     "sudo pacman -S podman",
    "debian":   "sudo apt-get install -y podman",
    "fedora":   "sudo dnf install -y podman",
    "rhel":     "sudo dnf install -y podman",
    "opensuse": "sudo zypper install -y podman",
    "unknown":  "install podman for your distribution",
}

_INSTALL_LIMA = {
    "arch":     "install lima from AUR or via 'brew install lima'",
    "debian":   "sudo apt-get install -y lima",
    "fedora":   "sudo dnf install -y lima",
    "rhel":     "sudo dnf install -y lima",
    "opensuse": "sudo zypper install -y lima",
    "unknown":  "install lima from https://lima-vm.io",
}

_INSTALL_QEMU = {
    "arch":     "sudo pacman -S qemu-full",
    "debian":   "sudo apt-get install -y qemu-system-x86",
    "fedora":   "sudo dnf install -y qemu-system-x86-core",
    "rhel":     "sudo dnf install -y qemu-kvm",
    "opensuse": "sudo zypper install -y qemu-x86",
    "unknown":  "install qemu for your distribution",
}

_ENABLE_LINGER = "sudo loginctl enable-linger $USER"


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _python_version_info() -> tuple[int, int, int]:
    """Return (major, minor, micro) — split out for testability."""
    return sys.version_info[:3]  # type: ignore[return-value]


def check_python_version() -> CheckResult:
    """Check Python >= 3.12."""
    major, minor, micro = _python_version_info()
    ver = f"{major}.{minor}.{micro}"
    if (major, minor) >= (3, 12):
        return CheckResult("pass", f"Python {ver}")
    return CheckResult("error", f"Python {ver} (need >= 3.12)",
                       hint="install Python 3.12+ for your distribution")


def check_podman(distro: str) -> CheckResult:
    """Check podman is installed and report version."""
    try:
        r = subprocess.run(["podman", "--version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            ver = r.stdout.strip().replace("podman version ", "")
            return CheckResult("pass", f"Podman {ver}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return CheckResult("error", "Podman not found",
                       hint=_INSTALL_PODMAN.get(distro, _INSTALL_PODMAN["unknown"]))


def check_podman_rootless(distro: str) -> CheckResult:
    """Check podman is running in rootless mode."""
    try:
        r = subprocess.run(
            ["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            val = r.stdout.strip().lower()
            if val == "true":
                return CheckResult("pass", "Podman rootless mode")
            return CheckResult("warn", "Podman running as root (rootless recommended)",
                               hint="run podman as a regular user, not root")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return CheckResult("warn", "Could not verify Podman rootless mode")


def check_lima(distro: str) -> CheckResult:
    """Check lima is installed (optional)."""
    try:
        r = subprocess.run(["limactl", "--version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            ver = r.stdout.strip()
            # limactl --version may output "limactl version X.Y.Z"
            ver = ver.replace("limactl version ", "")
            return CheckResult("pass", f"Lima {ver}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return CheckResult("warn", "Lima not found (needed for VM mode)",
                       hint=_INSTALL_LIMA.get(distro, _INSTALL_LIMA["unknown"]))


def check_qemu(distro: str) -> CheckResult:
    """Check QEMU is installed (optional, Linux VM mode only)."""
    try:
        r = subprocess.run(["qemu-system-x86_64", "--version"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            # First line: "QEMU emulator version X.Y.Z ..."
            first = r.stdout.splitlines()[0] if r.stdout else ""
            return CheckResult("pass", f"QEMU ({first.strip()})")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return CheckResult("warn", "QEMU not found (needed for VM mode on Linux)",
                       hint=_INSTALL_QEMU.get(distro, _INSTALL_QEMU["unknown"]))


def check_systemd_linger() -> CheckResult:
    """Check systemd user linger is enabled."""
    user = os.environ.get("USER", "")
    if not user:
        return CheckResult("warn", "Could not determine current user for linger check")
    try:
        r = subprocess.run(
            ["loginctl", "show-user", user, "-p", "Linger"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and "yes" in r.stdout.lower():
            return CheckResult("pass", "systemd user linger enabled")
        return CheckResult("warn", "systemd user linger not enabled",
                           hint=_ENABLE_LINGER)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return CheckResult("warn", "loginctl not available (no systemd?)")


# ---------------------------------------------------------------------------
# System checks
# ---------------------------------------------------------------------------

def check_disk_space() -> CheckResult:
    """Check available disk space > 2 GB."""
    try:
        usage = shutil.disk_usage(os.path.expanduser("~"))
    except OSError as exc:
        return CheckResult("warn", f"Could not check disk space: {exc}")
    free_gb = usage.free / (1024 ** 3)
    if free_gb >= 2:
        return CheckResult("pass", f"{free_gb:.0f}GB disk available")
    return CheckResult("error", f"Only {free_gb:.1f}GB disk free (need >= 2GB)",
                       hint="free up disk space in your home directory")


def _check_secret_backend() -> CheckResult:
    """Report the detected secret storage backend."""
    from agentcage.secret_resolver import (
        detect_default_backend, _systemd_version,
    )

    backend = detect_default_backend()
    if backend == "systemd-creds":
        ver = _systemd_version()
        return CheckResult(
            "pass",
            f"systemd-creds (systemd {ver}, secrets encrypted at rest)",
            hint="Secrets encrypted with TPM2 or host key. "
                 "Note: encrypted blobs are bound to this machine's hardware.",
        )
    ver = _systemd_version()
    if ver >= 250 and shutil.which("systemd-creds"):
        return CheckResult(
            "warn",
            f"podman (systemd-creds installed but not usable, systemd {ver})",
            hint="Run 'sudo systemd-creds setup' to initialize the host key, "
                 "or use 'source: cmd:...' in cage.yaml for external secret managers.",
        )
    return CheckResult(
        "warn",
        "podman (secrets stored unencrypted)",
        hint="Install systemd 250+ for encrypted secret storage, "
             "or use 'source: cmd:...' in cage.yaml for external secret managers.",
    )


def check_cgroup_v2() -> CheckResult:
    """Check cgroup v2 is enabled."""
    try:
        if Path("/sys/fs/cgroup/cgroup.controllers").exists():
            return CheckResult("pass", "cgroup v2 enabled")
    except OSError as exc:
        return CheckResult("warn", f"Could not check cgroup version: {exc}")
    return CheckResult("warn", "cgroup v2 not detected",
                       hint="cgroup v2 is required for rootless containers; "
                            "check your kernel boot parameters")


# ---------------------------------------------------------------------------
# Network checks
# ---------------------------------------------------------------------------

def check_dns() -> CheckResult:
    """Check DNS resolution works."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo("example.com", 80)
        return CheckResult("pass", "DNS resolution working")
    except socket.gaierror:
        return CheckResult("error", "DNS resolution failed",
                           hint="check /etc/resolv.conf and network connectivity")
    except socket.timeout:
        return CheckResult("error", "DNS resolution timed out",
                           hint="check /etc/resolv.conf and network connectivity")
    except OSError as exc:
        return CheckResult("error", f"DNS check failed: {exc}",
                           hint="check /etc/resolv.conf and network connectivity")
    finally:
        socket.setdefaulttimeout(old_timeout)


def check_subnet_conflicts() -> CheckResult:
    """Check no conflicting 10.89.x.0/24 subnets from existing podman networks."""
    try:
        r = subprocess.run(
            ["podman", "network", "ls", "--format", "json"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return CheckResult("pass", "No subnet conflicts (could not query networks)")

        networks = json.loads(r.stdout) if r.stdout.strip() else []
        conflicts = []
        for net in networks:
            # Networks may have subnets in different formats
            subnets = net.get("subnets") or []
            for sub in subnets:
                gw = sub.get("gateway", "")
                subnet = sub.get("subnet", "")
                if "10.89." in gw or "10.89." in subnet:
                    name = net.get("name", "unknown")
                    conflicts.append(f"{name} ({subnet})")

        if conflicts:
            return CheckResult("warn",
                               f"Existing 10.89.x.0/24 subnets: {', '.join(conflicts)}",
                               hint="these may conflict with new cages; "
                                    "destroy unused cages to free subnets")
        return CheckResult("pass", "No subnet conflicts")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return CheckResult("pass", "No subnet conflicts (podman not available)")


def check_port(port: int) -> CheckResult:
    """Check if a common port is available."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
        return CheckResult("pass", f"Port {port} available")
    except OSError:
        # Try to find what is using it
        pid_info = ""
        try:
            r = subprocess.run(
                ["ss", "-tlnp", f"sport = :{port}"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines()[1:]:
                    if f":{port}" in line:
                        m = re.search(r"pid=(\d+)", line)
                        if m:
                            pid_info = f" (PID {m.group(1)})"
                        break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return CheckResult("warn", f"Port {port} in use{pid_info}")


# ---------------------------------------------------------------------------
# Cage health checks
# ---------------------------------------------------------------------------

def check_cages() -> list[CheckResult]:
    """Check health of existing cage deployments."""
    try:
        from agentcage import state  # noqa: F811 — deferred import to avoid circular deps
        from agentcage.backends.container import ContainerBackend  # noqa: F811
    except Exception as exc:
        return [CheckResult("warn", f"Could not load cage modules: {exc}")]

    results: list[CheckResult] = []
    try:
        deployments = state.list_deployments()
    except Exception as exc:
        return [CheckResult("warn", f"Could not list deployments: {exc}")]
    if not deployments:
        results.append(CheckResult("pass", "No cages configured"))
        return results

    for name in deployments:
        try:
            cfg = state.load_deployment_config(name)
        except Exception:
            results.append(CheckResult("warn", f"{name}: could not load config"))
            continue

        if cfg.isolation == "vm":
            # Check Lima VM status
            try:
                from agentcage.lima.instance import LimaInstance
                inst = LimaInstance(name)
                if inst.is_running():
                    results.append(CheckResult("pass", f"{name}: running (VM)"))
                elif inst.exists():
                    results.append(CheckResult("warn", f"{name}: VM exists but stopped"))
                else:
                    results.append(CheckResult("warn",
                                               f"{name}: state exists, no VM (orphaned)",
                                               hint=f"agentcage cage destroy {name}"))
            except Exception:
                results.append(CheckResult("warn", f"{name}: could not check VM status"))
        else:
            # Container mode: check if the main cage container is running
            try:
                backend = ContainerBackend()
                if backend.is_running(name, "cage"):
                    results.append(CheckResult("pass", f"{name}: running"))
                else:
                    results.append(CheckResult("warn",
                                               f"{name}: stopped (state exists, no container)",
                                               hint=f"agentcage cage start {name}"))
            except Exception:
                results.append(CheckResult("warn", f"{name}: could not check container status"))

    return results


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _warn(text: str) -> str:
    return click.style(text, fg="yellow")


def _print_section(section: Section) -> None:
    """Print a section heading and its check results."""
    click.echo()
    click.echo(f"  {click.style(section.title, bold=True)}")
    for r in section.results:
        if r.level == "pass":
            mark = green("\u2713")
        elif r.level == "warn":
            mark = _warn("\u26a0")
        else:
            mark = red("\u2717")
        click.echo(f"    {mark} {r.message}")
        if r.hint:
            click.echo(f"      {dim('\u2192')} {dim(r.hint)}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

_COMMON_PORTS = [8080, 3000, 18789]


def _safe_check(fn, *args, label: str = "check") -> CheckResult:
    """Run a check function, catching any unexpected exception."""
    try:
        return fn(*args)
    except Exception as exc:
        return CheckResult("warn", f"{label} crashed: {exc}")


def _safe_check_multi(fn, *args, label: str = "check") -> list[CheckResult]:
    """Run a check function that returns a list, catching any unexpected exception."""
    try:
        return fn(*args)
    except Exception as exc:
        return [CheckResult("warn", f"{label} crashed: {exc}")]


def run_doctor() -> list[CheckResult]:
    """Run all diagnostic checks, print results, and return all issues."""
    click.echo()
    click.echo(click.style("agentcage doctor", bold=True))

    distro = _detect_distro()
    all_results: list[CheckResult] = []

    # --- Prerequisites ---
    prereqs = Section("Prerequisites")
    prereqs.results.append(_safe_check(check_python_version, label="Python version"))
    prereqs.results.append(_safe_check(check_podman, distro, label="Podman"))
    # Only check rootless if podman was found
    if prereqs.results[-1].level == "pass":
        prereqs.results.append(_safe_check(check_podman_rootless, distro, label="Podman rootless"))
    prereqs.results.append(_safe_check(check_lima, distro, label="Lima"))
    prereqs.results.append(_safe_check(check_qemu, distro, label="QEMU"))
    prereqs.results.append(_safe_check(check_systemd_linger, label="systemd linger"))
    _print_section(prereqs)
    all_results.extend(prereqs.results)

    # --- System ---
    system = Section("System")
    system.results.append(_safe_check(check_cgroup_v2, label="cgroup v2"))
    system.results.append(_safe_check(check_disk_space, label="disk space"))
    _print_section(system)
    all_results.extend(system.results)

    # --- Secrets ---
    secrets_sec = Section("Secrets")
    secrets_sec.results.append(_safe_check(_check_secret_backend, label="secret backend"))
    _print_section(secrets_sec)
    all_results.extend(secrets_sec.results)

    # --- Network ---
    network = Section("Network")
    network.results.append(_safe_check(check_dns, label="DNS"))
    network.results.append(_safe_check(check_subnet_conflicts, label="subnet conflicts"))
    for port in _COMMON_PORTS:
        network.results.append(_safe_check(check_port, port, label=f"port {port}"))
    _print_section(network)
    all_results.extend(network.results)

    # --- Cages ---
    cages = Section("Cages")
    cages.results.extend(_safe_check_multi(check_cages, label="cage health"))
    _print_section(cages)
    all_results.extend(cages.results)

    # --- Summary ---
    errors = sum(1 for r in all_results if r.level == "error")
    warnings = sum(1 for r in all_results if r.level == "warn")
    parts = []
    if errors:
        parts.append(red(f"{errors} error{'s' if errors != 1 else ''}"))
    if warnings:
        parts.append(_warn(f"{warnings} warning{'s' if warnings != 1 else ''}"))
    if not parts:
        parts.append(green("all checks passed"))

    click.echo()
    click.echo(f"  {click.style('Summary:', bold=True)} {', '.join(parts)}")
    click.echo()

    return all_results
