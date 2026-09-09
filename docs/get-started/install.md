# Installing agentcage

agentcage is a Python 3.12+ command-line tool that drives an isolated container or microVM runtime on your host machine. It installs as an unprivileged, user-level utility — no root daemons, no background services, and no system-wide configuration.

---

## Prerequisites at a Glance

| Component | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Python** | 3.12+ | Python 3.12 and 3.13 are fully supported. |
| **Linux Runtime** | Podman 4.4+ (rootless), cgroups v2, systemd | `systemd` 250+ enables encrypted secret storage via `systemd-creds`. |
| **macOS (Apple Silicon, 26+)** | Apple `container` CLI | Default and fastest backend on modern Apple Silicon Macs (`brew install container`). |
| **macOS (Intel / Older)** | Lima 0.19+ | MicroVM isolation using Lima (`brew install lima`). |
| **Disk Space** | ≥ 2 GB free in `$HOME` | Used for base container images and per-cage persistent volumes. |

agentcage has minimal Python dependencies (`click`, `pyyaml`, `jinja2`). Heavy components (such as `mitmproxy` and `dnsmasq`) run inside the isolated egress container image, which agentcage builds automatically on first use.

---

## Quick Installation

### Option 1: The Automated Installer (Recommended)

The official installer script inspects your operating system, hardware architecture, and installed packages, then installs agentcage into `~/.local/bin` alongside necessary backend components:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
```

To review what the script will execute before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh -s -- --dry-run
```

Ensure `~/.local/bin` is in your shell `$PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

### Option 2: Package Managers (`uv`, `pipx`, `pip`)

If you manage Python CLI tools using modern package managers:

#### Using `uv` (Fastest)

```bash
uv tool install agentcage
```

#### Using `pipx` (Isolated virtual environment)

```bash
pipx install agentcage
```

#### Using standard `pip` in a virtual environment

```bash
python3 -m venv ~/.local/share/agentcage-venv
~/.local/share/agentcage-venv/bin/pip install agentcage
ln -s ~/.local/share/agentcage-venv/bin/agentcage ~/.local/bin/agentcage
```

#### Installing from Source

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
uv sync
# Or with standard pip:
pip install -e .
```

---

## Platform-Specific Setup

### 1. Linux Setup

On Linux, agentcage defaults to the `container` backend, running rootless Podman containers supervised by your systemd user session.

#### A. Rootless Podman
Install Podman through your distribution package manager:

```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y podman

# Fedora / RHEL
sudo dnf install -y podman

# Arch Linux
sudo pacman -S podman
```

Ensure subuids and subgids are allocated for your user:

```bash
# Verify your user has subordinate UID/GID ranges:
grep "^$USER:" /etc/subuid /etc/subgid

# If empty, add a 65,536-range allocation:
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$USER"
podman system migrate
```

#### B. systemd User Session & Lingering
agentcage registers systemd user quadlets (`.container` and `.network` units in `~/.config/containers/systemd/`). To allow background cages to continue running when you disconnect an SSH session or close your terminal:

```bash
loginctl enable-linger "$USER"
```

#### C. Encrypted Secret Storage (`systemd-creds`)
Linux systems with systemd 250+ automatically encrypt secrets stored via `agentcage secret set` using the host's TPM2 or credential key. If unavailable, agentcage falls back to standard user-permission encrypted files.

---

### 2. macOS Setup

On macOS, agentcage supports two backends: native Apple Container microVMs or Lima.

#### A. Apple Silicon with macOS 26+ (`apple-container`)
The `apple-container` backend is the default on Apple Silicon running macOS 26+. It runs two lightweight microVMs per cage using Apple's native virtualization framework:

```bash
brew install container
```

Verify that the Apple container service is running:

```bash
container list
```

#### B. Intel Macs or macOS < 26 (`vm` via Lima)
For Intel-based Macs or earlier versions of macOS, hardware virtualization is provided via **Lima**:

```bash
brew install lima
```

Verify Lima can launch microVMs:

```bash
limactl list
```

---

## Verifying the Installation

Run `agentcage doctor` to verify that your operating system, virtualization backends, network configuration, and permissions are properly configured:

```bash
agentcage doctor
```

Example successful output:

```text
=== System & Dependencies ===
[PASS] Python 3.12.3 (/home/user/.local/bin/python3)
[PASS] Platform: Linux 6.8.0-45-generic (x86_64)

=== Runtime & Isolation ===
[PASS] Backend: container (Linux rootless Podman)
[PASS] Podman 4.9.3 (rootless mode enabled)
[PASS] User subuid/subgid ranges allocated
[PASS] systemd user manager active (linger enabled)
[PASS] cgroups v2 unified hierarchy available

=== Security & Storage ===
[PASS] Secret storage: systemd-creds (encrypted at rest)
[PASS] Storage directory: ~/.config/agentcage/ (drwx------)

All checks passed! Your system is ready to run agentcage.
```

If any check fails, `agentcage doctor` outputs the exact command required to fix the issue.

---

## Upgrading agentcage

When upgrading agentcage, update the CLI binary and refresh existing cage container images:

```bash
# If installed via the one-liner or git:
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh

# If installed via uv:
uv tool upgrade agentcage

# If installed via pipx:
pipx upgrade agentcage
```

After upgrading, rebuild running persistent cages to pull updated proxy and supervisor layers:

```bash
agentcage cage update <name> --pull --no-cache
```

---

## Uninstalling agentcage

To cleanly remove agentcage and all associated sandbox state:

```bash
# 1. Stop and destroy all existing cages and scoped secrets
for cage in $(agentcage ls --quiet 2>/dev/null); do
  agentcage cage destroy "$cage" -y
done

# 2. Remove the CLI package
uv tool uninstall agentcage
# or: pipx uninstall agentcage

# 3. Clean up configuration and state directories
rm -rf ~/.config/agentcage ~/.local/share/agentcage
rm -rf ~/.config/containers/systemd/agentcage-* 2>/dev/null
```

---

## Next Steps

Now that agentcage is installed and verified, proceed to the **[Quickstart Tutorial](quickstart.md)** to run your first sandboxed agent session.
