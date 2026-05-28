<p align="center">
  <img src="docs/agentcage.png" alt="agentcage logo" width="250">
</p>

# agentcage

*Defense-in-depth proxy sandbox for AI agents.*

Don't let your agent phone home.

> :warning: **Warning:** This is an experimental project. It has not been audited by security professionals. Use it at your own risk. See [Security model](docs/explain/security-model.md) for details and known limitations.

> **Coding agents:** [Claude Code](src/agentcage/scaffolds/claude-code/README.md) · [Codex](src/agentcage/scaffolds/codex/README.md) &nbsp;|&nbsp; **Agent platforms:** [OpenClaw](src/agentcage/scaffolds/openclaw/README.md)

<p align="center">
  <a href="https://asciinema.org/a/838890"><img src="https://asciinema.org/a/838890.svg" alt="agentcage demo" width="700"></a>
</p>

## What is it?

agentcage is a CLI that generates hardened, sandboxed environments for AI agents. Your agent runs on an internal-only network with no internet gateway; the only way out is through an inspecting proxy that scans every HTTP request before forwarding it.

Most agent deployments hand the agent a [**lethal trifecta**](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): internet access, real secrets, and arbitrary code execution. Combined, they create an exfiltration risk that most setups have zero defense against. agentcage breaks that combination. See [Security model](docs/explain/security-model.md) for the full breakdown.

- **Network isolation** -- agent on internal-only network, no internet gateway
- **Inspecting proxy** -- pluggable inspector chain on every HTTP request, WebSocket frame, and DNS query
- **Secret injection** -- agent gets placeholders, proxy swaps in real values outbound and redacts inbound
- **Secret & payload scanning** -- regex secret detection, Shannon entropy, content-type mismatch, base64 blob scanning
- **DNS filtering** -- allowlist-based dnsmasq sidecar, placeholder IPs for unauthorized domains
- **Fail-closed by default** -- all hardening on out of the box; component failure stops traffic

Three isolation backends are supported:

- **container** (Linux, default) — rootless Podman containers on the host
- **vm** (Linux + macOS) — a Lima VM per cage with hardware isolation via KVM
- **apple-container** (macOS 26+ Apple Silicon, new in 0.20) — a single Apple `container` microVM per cage with the egress filter (mitmproxy + dnsmasq + iptables) running inside, supervised by an in-microVM PID 1 that drops to uid 1000 / zero caps / NoNewPrivs before exec'ing the cage workload. ~10–20× faster than Lima and ~3× less RAM per cage; the default on macOS 26+ when Apple's `container` CLI is installed.

See [Security model](docs/explain/security-model.md#isolation-modes-and-the-threat-surface) for the threat-by-threat matrix and [Isolation modes](docs/explain/isolation-modes.md) for how each backend works and when to pick which. For the full container topology and inspector chain, see [Architecture](docs/explain/architecture.md).

## Quick Start

### Ephemeral session

The fastest way to sandbox a coding agent. One command builds the image, creates a temporary cage, and drops you into an interactive session. The cage is torn down when you exit; audit logs are preserved.

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh

# Run Claude Code in a sandbox
agentcage run claude-code

# Run OpenAI Codex in a sandbox
agentcage run codex

# Pass secrets and a project directory
agentcage run claude-code -s ANTHROPIC_API_KEY --project ~/myrepo
```

### Persistent interactive cage

Use this when you want the cage to survive across sessions -- for example, to keep auth tokens, run multiple `cage exec` sessions, or inspect traffic after the fact.

```bash
agentcage init myagent --scaffold claude-code
agentcage secret set myagent ANTHROPIC_API_KEY
agentcage cage create -c cage.yaml
agentcage cage exec myagent -- claude
```

### Always-on service cage

For agents that run continuously (API gateways, coding platforms, webhook receivers). systemd auto-restarts the container on failure and starts it on boot.

```bash
agentcage init myapp --scaffold openclaw
agentcage secret set myapp ANTHROPIC_API_KEY
agentcage cage create -c cage.yaml
agentcage cage verify myapp
```

### Custom image

```bash
agentcage init myapp --image node:22-slim
# Edit cage.yaml to configure domains, secrets, inspectors...
agentcage cage create -c cage.yaml
```

Run `agentcage init --list-scaffolds` to see available scaffolds. See [CLI Reference](docs/reference/cli.md) for the full command set.

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
| macOS (any version) | `brew install lima python uv` |
| Arch Linux | `sudo pacman -S qemu-full python uv` + [install Lima](https://lima-vm.io/docs/installation/) |
| Debian / Ubuntu | `sudo apt install qemu-system python3 && curl -LsSf https://astral.sh/uv/install.sh \| sh` + [install Lima](https://lima-vm.io/docs/installation/) |

*apple-container mode* (macOS 26+ Apple Silicon, recommended on that platform) -- prerequisites: Apple's [`container`](https://github.com/apple/container) CLI, Python 3.12+, [uv](https://docs.astral.sh/uv/).

```bash
# Install Apple container (from the latest GitHub release .pkg)
PKG=$(curl -fsSL https://api.github.com/repos/apple/container/releases/latest \
      | grep -oE 'https://github.com/apple/container/releases/download/[^"]+\.pkg' | head -1)
curl -fsSLO "$PKG" && sudo installer -pkg "$(basename "$PKG")" -target /
container system start --enable-kernel-install

# Plus Python + uv
brew install python uv
```

On macOS 26+ Apple Silicon hosts with `container` installed, `apple-container` is the **default** when `isolation:` is omitted from `cage.yaml`. Older macOS, Intel Macs, and macOS 26 hosts without `container` continue to default to `vm` (Lima). Podman is optional on macOS (only needed for `agentcage secret set` with the container backend). See [Isolation modes](docs/explain/isolation-modes.md) for details, security trade-offs, and limitations.

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
| `run` | *(top-level)* -- run a coding agent in a sandbox (`agentcage run claude-code`) |
| `init` | *(top-level)* -- scaffold a config file |
| `doctor` | *(top-level)* -- check system prerequisites |
| `update` | *(top-level)* -- self-update agentcage |
| `cage` | `create`, `update`, `list`, `show`, `verify`, `start`, `stop`, `restart`, `logs`, `exec`, `shell`, `audit`, `har`, `backup`, `restore`, `destroy`, `prune` (aliases: `ls`/`ps`/`status` → `list`, `describe`/`inspect` → `show`, `rm`/`delete` → `destroy`, `reload` → `restart`) |
| `secret` | `set`, `list`, `migrate`, `rm` (alias: `ls` → `list`) |
| `domain` | `list`, `add`, `rm` (alias: `ls` → `list`) |
| `scaffold` | `list`, `show`, `create`, `edit`, `delete`, `export` -- manage custom scaffolds |

See [CLI Reference](docs/reference/cli.md) for full documentation of all commands and options.

## Configuration

See the [Configuration Reference](docs/reference/configuration.md) for all settings, defaults, and examples. Example configs: [`basic/cage.yaml`](examples/basic/). Deployment state is tracked per-cage in `~/.config/agentcage/cages/<name>/`.

## Security

The agent has no internet gateway -- all traffic must pass through the proxy, which applies domain filtering, secret detection, payload inspection, and custom inspectors. For workloads requiring hardware-level isolation, VM mode adds a dedicated guest kernel per cage via Lima, eliminating container escape as an attack vector. See [Security model](docs/explain/security-model.md) for the full threat model, defense layers, and known limitations.

## License

MIT
