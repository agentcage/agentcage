# Installing agentcage

agentcage is a single command-line binary, distributed as a prebuilt release binary (and buildable from source with Rust's `cargo`), that drives an isolated container or microVM runtime on your host machine. It installs as an unprivileged, user-level utility — no root daemons, no background services, and no system-wide configuration, and no runtime to install first.

---

## Prerequisites at a Glance

| Component | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Linux Runtime** | Podman 4.4+ (rootless), cgroups v2, systemd | `systemd` 250+ enables encrypted secret storage via `systemd-creds`. |
| **macOS (Apple Silicon, 26+)** | Apple `container` CLI | Default and fastest backend on modern Apple Silicon Macs (`brew install container`). |
| **macOS (Intel / Older)** | Lima 0.19+ | MicroVM isolation using Lima (`brew install lima`). |
| **Rust toolchain** | Rust 1.99+ and a C linker | Only needed with `--build` or another source install. The installer sets one up if needed. |
| **Disk Space** | ≥ 2 GB free in `$HOME` | Used for base container images and per-cage persistent volumes. |

agentcage has no runtime dependencies of its own: once built, the binary needs no interpreter and no Rust toolchain. The network-facing components (the `agentcage-egress` proxy and `dnsmasq`) run inside the isolated egress container image, which agentcage builds automatically on first use. That image is `alpine:3` plus a few utilities and the static `agentcage-egress` binary, which the host binary carries inside it for its own architecture. There is no interpreter anywhere in the product.

---

## Quick Installation

### Option 1: The Automated Installer (Recommended)

The official installer script inspects your operating system and installed packages, downloads the latest release's prebuilt `agentcage` binary for your platform, verifies it against its published SHA-256, and installs it into `~/.local/bin` alongside the necessary backend components:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
```

To build agentcage and the egress it embeds from source instead, pass `--build`:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh -s -- --build
```

If no Rust toolchain is found with `--build`, the installer sets up a minimal one with [rustup](https://rustup.rs) (into `~/.rustup` and `~/.cargo`, without editing your shell profile). An existing toolchain older than 1.99 is left alone and the installer stops and asks you to run `rustup update stable`. The build takes a few minutes.

The release's prebuilt `agentcage` binary already embeds the static linux-musl `agentcage-egress` for your architecture, so a default install needs no Rust toolchain and its `cage create` works out of the box. With `--build` (or for a branch via `AGENTCAGE_REF`, which has no release assets), agentcage builds both the host and its egress from source; the egress build needs the musl tooling described under [Building from a clone](#building-from-a-clone), and the installer stops with an error saying what is missing if it is unavailable.

To read the script before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh -o install.sh
less install.sh
sh install.sh --help
```

To pick a release, set `AGENTCAGE_VERSION=0.54.1` (the default is the latest release) or `AGENTCAGE_REF=master` (a branch, which is built from source).

Ensure `~/.local/bin` is in your shell `$PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

### Option 2: `cargo install` from GitHub

With Rust 1.99+ already installed, build and install the CLI directly. It is not published to crates.io; `cargo` fetches it from the repository:

```bash
cargo install --locked --git https://github.com/agentcage/agentcage --tag v0.54.1 agentcage-cli
```

`agentcage-cli` is the package name; the binary it installs is `agentcage`, into `~/.cargo/bin`. `--locked` builds against the committed `Cargo.lock`, the same dependency versions CI tested. Use `--branch master` instead of `--tag` to track unreleased changes.

> **The egress binary.** The host binary embeds the static linux-musl `agentcage-egress` it puts into each cage's egress image. A plain `cargo install` builds only the host. The result runs, but its first `cage create` stops with an error saying it was built without the egress binary. To get a complete binary, get an egress binary first (the release's `agentcage-egress` asset for your architecture, or one built from a clone as shown below) and point `AGENTCAGE_EGRESS_BIN` at it:
>
> ```bash
> AGENTCAGE_EGRESS_BIN=/path/to/agentcage-egress \
>   cargo install --locked --git https://github.com/agentcage/agentcage --tag v<version> agentcage-cli
> ```

#### Building from a clone

Build the egress for your machine's architecture first, then the host, which picks it up from `target/`:

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
rustup target add x86_64-unknown-linux-musl     # aarch64-unknown-linux-musl on arm64
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release --locked --target x86_64-unknown-linux-musl -p agentcage-egress
cargo build --release --locked --bin agentcage
install -m 755 target/release/agentcage ~/.local/bin/agentcage
```

The egress build needs a C compiler for the musl target (`musl-gcc`, from `musl-tools` on Debian/Ubuntu or `musl` on Arch and Fedora). On macOS the target is still Linux (`aarch64-unknown-linux-musl` on Apple Silicon, since that is what the VM runs), so you need a cross C toolchain for it.

> **Prebuilt macOS binaries.** The macOS release binaries are not notarized
> yet, but `curl` does not set the quarantine attribute, so the installer's
> default prebuilt download is not blocked by Gatekeeper. Use `--build` to
> compile from source instead.

> **The old Python package is not an install path.** `pip install agentcage`
> and `uv tool install agentcage` used to be how you got the CLI. They
> are not any more: agentcage is the Rust binary above. If you still have
> an old Python install, remove it (`uv tool uninstall agentcage`, or
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

`agentcage doctor` does not check for an interpreter: the host binary
needs none, so such a check would only fail on machines that are
otherwise ready.

---

## Upgrading agentcage

When upgrading agentcage, update the CLI binary and refresh existing cage container images:

```bash
# If installed via the installer:
agentcage update

# Or run the installer again, which also checks the prerequisites:
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh

# If installed via Homebrew:
brew upgrade agentcage

# If installed via cargo install (--force replaces the existing build):
cargo install --locked --force --git https://github.com/agentcage/agentcage --tag v<version> agentcage-cli
```

After upgrading, rebuild running persistent cages to pull updated proxy and supervisor layers:

```bash
agentcage cage update <name> --pull --no-cache
```

### Picking up base image security fixes

The shipped images build from floating base tags (`alpine:3` for the egress, `debian:stable-slim` for the scaffolds), so a rebuild is what brings in the distribution's security fixes. A plain `agentcage cage update <name>` checks for this: it asks the registry whether either image's base has a newer version, rebuilds only the image whose base moved, and restarts the cage only if the rebuilt image changed. Nothing is pulled when no base moved. Run it periodically, or from a timer, to keep cages current:

```bash
agentcage cage update <name>            # check the registry, rebuild and restart only if a base moved
agentcage cage update <name> --no-pull  # never contact the registry (offline, or to keep images fixed)
```

When the registry cannot be reached, `cage update` warns and leaves the cage as it is. A plain update does not pick up a newer version of software the Containerfile downloads itself (Claude Code, Codex, Pi): that still needs `--pull --no-cache`. On the apple-container backend there is no registry check; use `--pull --no-cache` there.

---

## Uninstalling agentcage

To cleanly remove agentcage and all associated sandbox state:

```bash
# 1. Remove the cages and their secrets. Each destroy prints a `Kept:`
#    block naming the data directory it leaves behind; step 3 removes
#    those under the default data root.
for cage in $(agentcage ls --quiet 2>/dev/null); do
  agentcage cage destroy "$cage" -y
done

# 2. Remove the CLI binary
rm -f ~/.local/bin/agentcage
# or, if installed via cargo install: cargo uninstall agentcage-cli

# 3. Clean up configuration and state directories. If a step-1 `Kept:`
#    block named a data directory outside this root, remove that too.
rm -rf ~/.config/agentcage "${XDG_DATA_HOME:-$HOME/.local/share}/agentcage"
rm -rf ~/.config/containers/systemd/agentcage-* 2>/dev/null
```

---

## Next Steps

Now that agentcage is installed and verified, proceed to the **[Quickstart Tutorial](quickstart.md)** to run your first sandboxed agent session.
