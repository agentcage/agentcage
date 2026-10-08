# Installing agentcage

agentcage is a single command-line binary, built from source with Rust's `cargo`, that drives an isolated container or microVM runtime on your host machine. It installs as an unprivileged, user-level utility — no root daemons, no background services, and no system-wide configuration, and no runtime to install first.

---

## Prerequisites at a Glance

| Component | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Linux Runtime** | Podman 4.4+ (rootless), cgroups v2, systemd | `systemd` 250+ enables encrypted secret storage via `systemd-creds`. |
| **macOS (Apple Silicon, 26+)** | Apple `container` CLI | Default and fastest backend on modern Apple Silicon Macs (`brew install container`). |
| **macOS (Intel / Older)** | Lima 0.19+ | MicroVM isolation using Lima (`brew install lima`). |
| **Rust toolchain** | Rust 1.85+ and a C linker | Build-time only. The installer sets up a minimal toolchain with rustup if none is found. |
| **Disk Space** | ≥ 2 GB free in `$HOME` | Used for base container images and per-cage persistent volumes. |

agentcage has no runtime dependencies of its own: once built, the binary needs no interpreter and no Rust toolchain. Heavy components (such as `mitmproxy` and `dnsmasq`) run inside the isolated egress container image, which agentcage builds automatically on first use — that image carries its own Python, and it is the only Python in the product.

---

## Quick Installation

### Option 1: The Automated Installer (Recommended)

The official installer script inspects your operating system and installed packages, builds agentcage from source with `cargo`, and installs it into `~/.local/bin` alongside the necessary backend components:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
```

If no Rust toolchain is found, the installer sets up a minimal one with [rustup](https://rustup.rs) (into `~/.rustup` and `~/.cargo`, without editing your shell profile). An existing toolchain older than 1.85 is left alone and the installer stops and asks you to run `rustup update stable`. The build takes a few minutes.

To read the script before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh -o install.sh
less install.sh
sh install.sh --help
```

To pick what gets built, set `AGENTCAGE_VERSION=0.50.0` (a release tag; the default is the latest release) or `AGENTCAGE_REF=master` (a branch).

Ensure `~/.local/bin` is in your shell `$PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

### Option 2: `cargo install` from GitHub

With Rust 1.85+ already installed, build and install the CLI directly. It is not published to crates.io; `cargo` fetches it from the repository:

```bash
cargo install --locked --git https://github.com/agentcage/agentcage --tag v0.50.0 agentcage-cli
```

`agentcage-cli` is the package name; the binary it installs is `agentcage`, into `~/.cargo/bin`. `--locked` builds against the committed `Cargo.lock`, the same dependency versions CI tested. Use `--branch master` instead of `--tag` to track unreleased changes.

#### Building from a clone

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
cargo build --release --locked --bin agentcage
install -m 755 target/release/agentcage ~/.local/bin/agentcage
```

> **Why there is no prebuilt binary download.** The macOS release binaries
> are not notarized yet, and an un-notarized download triggers a Gatekeeper
> prompt. A binary built on your own machine is not quarantined, so building
> from source avoids that on every platform with one install path.

> **The Python package is not an install path.** `pip install agentcage`
> and `uv tool install agentcage` used to be how you got the CLI. They
> are not any more: the host CLI is the Rust binary above, and the
> `pyproject.toml` in this repository is dev/test-only — it installs no
> `agentcage` command, and it is not published to PyPI. If you have an
> old Python install, remove it (`uv tool uninstall agentcage`, or
> `pipx uninstall agentcage`) so it cannot shadow the binary on your
> `PATH`.

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

There is no Python check. There used to be one, and it was dropped
rather than ported: the host does not need an interpreter any more, so a
check for one would fail on exactly the machines this design exists to
support.

---

## Upgrading agentcage

When upgrading agentcage, update the CLI binary and refresh existing cage container images:

```bash
# If installed via the installer:
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh

# If installed via cargo install (--force replaces the existing build):
cargo install --locked --force --git https://github.com/agentcage/agentcage --tag v<version> agentcage-cli
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

# 2. Remove the CLI binary
rm -f ~/.local/bin/agentcage
# or, if installed via cargo install: cargo uninstall agentcage-cli

# 3. Clean up configuration and state directories
rm -rf ~/.config/agentcage ~/.local/share/agentcage
rm -rf ~/.config/containers/systemd/agentcage-* 2>/dev/null
```

---

## Next Steps

Now that agentcage is installed and verified, proceed to the **[Quickstart Tutorial](quickstart.md)** to run your first sandboxed agent session.
