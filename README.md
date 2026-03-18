<p align="center">
  <img src="docs/agentcage.png" alt="agentcage logo" width="250">
</p>

# agentcage

*Defense-in-depth proxy sandbox for AI agents.*

Don't let your agent phone home.

> :warning: **Warning:** This is an experimental project. It has not been audited by security professionals. Use it at your own risk. See [Security & Threat Model](docs/security.md) for details and known limitations.

> **Setup guides:** [OpenClaw](src/agentcage/scaffolds/openclaw/README.md) · [PicoClaw](src/agentcage/scaffolds/picoclaw/README.md) · [NanoClaw](src/agentcage/scaffolds/nanoclaw/README.md)

<p align="center">
  <a href="https://asciinema.org/a/838890"><img src="https://asciinema.org/a/838890.svg" alt="agentcage demo" width="700"></a>
</p>

## What is it?

agentcage is a CLI that generates hardened, sandboxed environments for AI agents. Your agent runs on an internal-only network with no internet gateway; the only way out is through an inspecting proxy that scans every HTTP request before forwarding it.

Most agent deployments hand the agent a [**lethal trifecta**](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): internet access, real secrets, and arbitrary code execution. Combined, they create an exfiltration risk that most setups have zero defense against. agentcage breaks that combination. See [Security & Threat Model](docs/security.md) for the full breakdown.

- **Network isolation** -- agent on internal-only network, no internet gateway
- **Inspecting proxy** -- pluggable inspector chain on every HTTP request, WebSocket frame, and DNS query
- **Secret injection** -- agent gets placeholders, proxy swaps in real values outbound and redacts inbound
- **Secret & payload scanning** -- regex secret detection, Shannon entropy, content-type mismatch, base64 blob scanning
- **DNS filtering** -- allowlist-based dnsmasq sidecar, placeholder IPs for unauthorized domains
- **Fail-closed by default** -- all hardening on out of the box; component failure stops traffic

Both container mode (rootless Podman) and VM mode (Lima KVM) are supported -- see [Security & Threat Model](docs/security.md#isolation-modes) for the comparison. For the full container topology and inspector chain, see [Architecture](docs/architecture.md).

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh

# Scaffold a config (or use --scaffold openclaw)
agentcage init myapp --image node:22-slim

# Create and start the cage
agentcage cage create -c cage.yaml

# Store secrets (cage must exist first)
agentcage secret set myapp ANTHROPIC_API_KEY
agentcage cage restart myapp

# Verify it's healthy
agentcage cage verify myapp
```

Run `agentcage init --list-scaffolds` to see available scaffolds. See [CLI Reference](docs/cli.md) for the full command set.

## Install

**One-line installer** (installs agentcage + prerequisites):

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
```

**Manual install:**

*Container mode* (Linux only) -- prerequisites: [Podman](https://podman.io/) (rootless), Python 3.12+, [uv](https://docs.astral.sh/uv/).

| OS | Command |
|---|---|
| Arch Linux | `sudo pacman -S podman python uv` |
| Debian / Ubuntu 24.04+ | `sudo apt install podman python3 && curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Fedora | `sudo dnf install podman python3 uv` |

*VM mode* (Linux and macOS) -- prerequisites: [Lima](https://lima-vm.io/), Python 3.12+, [uv](https://docs.astral.sh/uv/). QEMU also required on Linux.

| OS | Command |
|---|---|
| macOS | `brew install lima python uv` |
| Arch Linux | `sudo pacman -S qemu-full python uv` + [install Lima](https://lima-vm.io/docs/installation/) |
| Debian / Ubuntu | `sudo apt install qemu-system python3 && curl -LsSf https://astral.sh/uv/install.sh \| sh` + [install Lima](https://lima-vm.io/docs/installation/) |

On macOS, only VM mode is available. Podman is optional (only needed for `agentcage secret set`). See [VM Isolation](docs/vm.md) for details.

Then install agentcage:

```bash
uv tool install agentcage                                            # from PyPI
uv tool install git+https://github.com/agentcage/agentcage.git      # from GitHub
```

For development:

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
uv run agentcage --help
```

## Usage

```bash
# View logs
agentcage cage logs myapp             # agent logs
agentcage cage logs myapp -s proxy    # proxy inspection logs

# Audit inspection decisions
agentcage cage audit myapp --summary --since 24h

# Rotate a secret (auto-reloads the cage)
agentcage secret set myapp ANTHROPIC_API_KEY

# Update after code/config changes
agentcage cage update myapp -c cage.yaml

# Restart without rebuild
agentcage cage restart myapp

# Backup and restore
agentcage cage backup myapp --include-secrets -o backup.tar.gz
agentcage cage restore backup.tar.gz --name myapp-clone

# Tear it all down
agentcage cage destroy myapp
```

| Command / Group | Commands |
|---|---|
| `init` | *(top-level)* -- scaffold a config file |
| `cage` | `create`, `update`, `edit`, `list`, `destroy`, `verify`, `restart`, `logs`, `exec`, `audit`, `har`, `backup`, `restore` (aliases: `ls`/`ps`/`status` → `list`, `rm` → `destroy`, `reload` → `restart`) |
| `secret` | `set`, `list`, `rm` (alias: `ls` → `list`) |
| `domain` | `list`, `add`, `rm` (alias: `ls` → `list`) |
| `completions` | *(top-level)* -- print shell completion script (`bash`/`zsh`/`fish`) |

See [CLI Reference](docs/cli.md) for full documentation of all commands and options.

## Configuration

See the [Configuration Reference](docs/configuration.md) for all settings, defaults, and examples. Example configs: [`basic/cage.yaml`](examples/basic/). Deployment state is tracked per-cage in `~/.config/agentcage/deployments/<name>/`.

## Security

The agent has no internet gateway -- all traffic must pass through the proxy, which applies domain filtering, secret detection, payload inspection, and custom inspectors. For workloads requiring hardware-level isolation, VM mode adds a dedicated guest kernel per cage via Lima, eliminating container escape as an attack vector. See [Security & Threat Model](docs/security.md) for the full threat model, defense layers, and known limitations.

## License

MIT
