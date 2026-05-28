<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Install

Backend-specific setup steps for agentcage. This is a temporary staging page consolidating the install snippets that previously lived in `docs/vm.md` and `docs/apple-container.md`; a later pass will rewrite it as a proper quickstart.

<!-- WIP: this is a holding bay during the docs revamp. The one-line installer
in README.md is the canonical entry point; this page exists so that backend
prerequisites are not lost when vm.md and apple-container.md are deleted.
A future step will rewrite this into a full Diataxis "get started" tutorial. -->

## One-line installer

Installs agentcage plus the prerequisites for the default backend on the current platform.

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
```

## Container backend (Linux)

Prerequisites: rootless [Podman](https://podman.io/), Python 3.12+, [uv](https://docs.astral.sh/uv/).

| OS | Command |
|---|---|
| Arch Linux | `sudo pacman -S podman python uv` |
| Debian / Ubuntu 24.04+ | `sudo apt install podman python3 && curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Fedora | `sudo dnf install podman python3 uv` |

## VM backend (Linux and macOS)

Prerequisites: [Lima](https://lima-vm.io/), Python 3.12+, [uv](https://docs.astral.sh/uv/). QEMU is required on Linux for VM acceleration. Podman on the host is optional — only `agentcage secret set` uses it.

| OS | Command |
|---|---|
| macOS (any version) | `brew install lima python uv` |
| Arch Linux | `sudo pacman -S lima qemu-full python uv` |
| Debian / Ubuntu | `sudo apt install lima qemu-system python3 && curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Fedora | `sudo dnf install lima python3 uv` |

For other Linux distributions, see [lima-vm.io](https://lima-vm.io/docs/installation/).

## apple-container backend (macOS 26+ Apple Silicon)

Prerequisites: Apple's [`container`](https://github.com/apple/container) CLI, Python 3.12+, [uv](https://docs.astral.sh/uv/). On macOS 26+ Apple Silicon with `container` installed, this is the default backend when `isolation:` is omitted from `cage.yaml`.

```bash
# Install the latest .pkg from apple/container releases
PKG=$(curl -fsSL https://api.github.com/repos/apple/container/releases/latest \
      | grep -oE 'https://github.com/apple/container/releases/download/[^"]+\.pkg' | head -1)
curl -fsSLO "$PKG" && sudo installer -pkg "$(basename "$PKG")" -target /

# Start the apiserver and install the recommended kernel
container system start --enable-kernel-install

# Plus Python + uv
brew install python uv
```

`agentcage doctor` reports which prerequisite is missing if any of these are not met.

## Install agentcage

After the backend prerequisites are in place:

```bash
uv tool install agentcage                                       # from PyPI
uv tool install git+https://github.com/agentcage/agentcage.git  # from GitHub
```

## Related

- [Isolation modes](../explain/isolation-modes.md) — pick the backend that matches your threat model
- [Configuration reference](../reference/configuration.md) — `cage.yaml` settings
- [CLI reference](../reference/cli.md) — full command set
