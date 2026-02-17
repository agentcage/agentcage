<p align="center">
  <img src="docs/agentcage.png" alt="agentcage logo" width="250">
</p>

# agentcage

*Defense-in-depth proxy sandbox for AI agents.*

Sandboxed container environments for AI agents, powered by rootless [Podman](https://podman.io/) and [mitmproxy](https://mitmproxy.org/).

> ⚠️ **Warning:** This is an experimental project. It has not been audited by security professionals. Use it at your own risk. See [Security & Threat Model](docs/security.md) for details and known limitations.

> **Setting up OpenClaw?** See the [OpenClaw guide](docs/openclaw.md) and [`openclaw/config.yaml`](examples/openclaw/).

## What is it?

agentcage is a CLI that generates hardened, sandboxed container environments for AI agents. It produces [systemd quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) files that deploy three containers on a rootless [Podman](https://podman.io/) network -- no root privileges required. Your agent runs on an internal-only network with no internet gateway; the only way out is through an inspecting [mitmproxy](https://mitmproxy.org/) that scans every HTTP request before forwarding it.

## Why is it needed?

Most AI agent deployments hand the agent a [**lethal trifecta**](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

1. **Internet access** -- the agent can reach any server on the internet.
2. **Credentials** -- API keys, tokens, and secrets are passed as environment variables or mounted files.
3. **Arbitrary code execution** -- the agent runs code it writes itself, or code suggested by a model.

Any one of these alone is manageable. Combined, they create an exfiltration risk: if the agent is compromised, misaligned, or simply makes a mistake, it can send your credentials, source code, or private data to any endpoint on the internet. Most current setups have zero defense against this -- the agent has the same network access as any other process on the machine.

agentcage breaks the trifecta by placing the agent behind a defense-in-depth proxy sandbox: network isolation, domain filtering, secret injection, credential scanning, payload analysis, and container hardening -- all fail-closed. See [Security & Threat Model](docs/security.md) for the full breakdown of each layer and known limitations.

## How does it work?

The agent container has no internet gateway. All HTTP traffic is routed via `HTTP_PROXY` / `HTTPS_PROXY` to a dual-homed mitmproxy container, which is the agent's only path to the outside world. A pluggable inspector chain evaluates every request -- enforcing domain allowlists, scanning for secret leaks, and optionally analyzing payloads -- before forwarding or blocking with a 403.

See [Architecture](docs/architecture.md) for the full container topology, inspector chain, startup order, and certificate sharing.

## Prerequisites

- [Podman](https://podman.io/) (rootless)
- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (Python package manager)

### Linux

**Arch Linux:**

```bash
sudo pacman -S podman python uv
```

**Debian / Ubuntu (24.04+):**

```bash
sudo apt install podman python3
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Fedora:**

```bash
sudo dnf install podman python3 uv
```

### macOS

```bash
brew install podman python uv
podman machine init
podman machine start
```

> **Note:** On macOS, Podman runs containers inside a Linux VM. `podman machine init` creates and `podman machine start` starts it.

## Install

```bash
uv tool install agentcage            # from PyPI (when published)
uv tool install git+https://github.com/agentcage/agentcage.git  # from GitHub
```

Or for development:

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
uv run agentcage --help
```

## Quick Start

```bash
# Edit config (set your allowed domains, image, etc.)
cp examples/basic/config.yaml config.yaml

# Store secrets first (they're required before cage creation)
agentcage secret set myapp ANTHROPIC_API_KEY

# Create the cage (builds images, generates quadlets, starts containers)
agentcage cage create -c config.yaml

# Verify everything is healthy
agentcage cage verify myapp
```

## CLI Reference

The CLI is organized into two command groups: **`cage`** (manage cages) and **`secret`** (manage cage-scoped secrets).

```
agentcage <group> <command> [options]
```

### `cage` -- Manage cages

| Command | Description |
|---|---|
| `cage create -c CONFIG` | Build images, generate quadlets, install, and start a new cage |
| `cage update NAME [-c CONFIG]` | Rebuild images and restart an existing cage |
| `cage list` | List all cages with status |
| `cage destroy NAME [-y]` | Stop containers, remove quadlets, state, and scoped secrets |
| `cage verify NAME` | Health checks (containers, certs, proxy, egress, rootless) |
| `cage reload NAME` | Restart containers without rebuilding images |

### `secret` -- Manage cage-scoped secrets

| Command | Description |
|---|---|
| `secret list NAME` | List secrets for a cage (with status if cage exists) |
| `secret set NAME KEY` | Set a secret (prompts for value or reads stdin) |
| `secret rm NAME KEY` | Remove a secret |

---

### `cage create`

```
agentcage cage create -c <config>
```

Creates a new cage from a config file. This single command:

1. Validates the config
2. Checks that all required secrets exist in Podman
3. Saves deployment state to `~/.config/agentcage/deployments/<name>/config.yaml`
4. Builds the proxy and DNS container images
5. Generates and installs 5 quadlet files into `~/.config/containers/systemd/`
6. Reloads systemd and starts the cage

The generated quadlet files are:

- `<name>-net.network` -- internal network with fixed subnet
- `<name>-certs.volume` -- shared certificate volume
- `<name>-dns.container` -- DNS sidecar (dnsmasq)
- `<name>-proxy.container` -- mitmproxy with inspector chain
- `<name>-cage.container` -- your agent container

Fails if any required secrets are missing. The error message tells you exactly which secrets to create:

```
error: missing secrets for cage 'myapp':
  ANTHROPIC_API_KEY
Create them with:
  agentcage secret set myapp ANTHROPIC_API_KEY
```

### `cage update`

```
agentcage cage update <name> [-c <config>]
```

Rebuild and restart an existing cage. Use this after changing code or config:

- **With `-c`**: Updates the stored config, then rebuilds and restarts.
- **Without `-c`**: Rebuilds from the previously stored config (useful when only the container image or proxy code has changed).

Stops the running services before rebuilding, then starts them again.

### `cage list`

```
agentcage cage list
```

Lists all known cages with their current status:

```
NAME                 STATUS
myapp                running (3/3)
testcage             stopped (0/3)
broken               degraded (2/3)
```

### `cage destroy`

```
agentcage cage destroy <name> [-y|--yes]
```

Tears down a cage completely:

1. Stops all containers (cage, proxy, DNS)
2. Removes quadlet files from `~/.config/containers/systemd/`
3. Removes the Podman network and certificate volume
4. Removes all scoped secrets (e.g., `myapp.ANTHROPIC_API_KEY`)
5. Removes deployment state from `~/.config/agentcage/deployments/<name>/`

User-defined named volumes and bind-mounted data are never removed. Pass `-y` to skip the confirmation prompt.

### `cage verify`

```
agentcage cage verify <name>
```

Runs health checks against a running cage:

- All 3 containers running (cage, proxy, DNS)
- CA certificate present in the shared volume
- `HTTP_PROXY` / `HTTPS_PROXY` set in the cage container
- Egress filtering working (blocked domain returns 403)
- Podman running rootless

Example output:

```
=== agentcage verify: myapp ===

-- Containers --
  [PASS] myapp-proxy is running
  [PASS] myapp-dns is running
  [PASS] myapp-cage is running

-- CA Certificate --
  [PASS] mitmproxy CA cert exists in shared volume

-- Proxy Configuration --
  [PASS] HTTP_PROXY is set
  [PASS] HTTPS_PROXY is set

-- Egress Filtering --
  [PASS] Blocked domain (evil-exfil-server.io) is denied (HTTP 403)

-- Podman --
  [PASS] Podman is running rootless

=== Results: 8 passed, 0 failed, 0 warnings ===
```

### `cage reload`

```
agentcage cage reload <name>
```

Restarts containers without rebuilding images. Useful after config-only changes (the config YAML is bind-mounted into the proxy container, so a restart picks it up).

### `secret set`

```
agentcage secret set <name> <key>
```

Sets a deployment-scoped secret. When run interactively, prompts for the value with hidden input. Also accepts piped input:

```bash
# Interactive (prompts for value)
agentcage secret set myapp ANTHROPIC_API_KEY

# Piped from a command
echo "sk-ant-abc123" | agentcage secret set myapp ANTHROPIC_API_KEY

# From a file
agentcage secret set myapp ANTHROPIC_API_KEY < /path/to/key.txt
```

Secrets are stored in Podman as `<name>.<key>` (e.g., `myapp.ANTHROPIC_API_KEY`) and mapped back to the original env var name via `target=` in the quadlet templates, so the container sees `ANTHROPIC_API_KEY` as expected.

If the cage is currently running, it is automatically reloaded after the secret is set.

### `secret list`

```
agentcage secret list <name>
```

Lists secrets for a cage. If the cage has deployment state, cross-references with the config to show expected secrets and their status:

```
NAME                           TYPE         STATUS
ANTHROPIC_API_KEY                 injection    ok
GITHUB_TOKEN                   direct       MISSING
```

Secret types:
- **injection** -- managed by the proxy's secret injection system (the cage sees a placeholder; the proxy swaps in the real value)
- **direct** -- passed directly to the cage container via `podman_secrets`

If no deployment state exists, lists all Podman secrets matching the `<name>.` prefix.

### `secret rm`

```
agentcage secret rm <name> <key>
```

Removes a secret from Podman. If the cage is currently running, it is automatically reloaded.

---

## Typical Workflow

```bash
# 1. Write your config
cp examples/basic/config.yaml config.yaml
vim config.yaml

# 2. Store secrets (before creating the cage)
agentcage secret set myapp ANTHROPIC_API_KEY
agentcage secret set myapp GITHUB_TOKEN

# 3. Create the cage
agentcage cage create -c config.yaml

# 4. Verify it's healthy
agentcage cage verify myapp

# 5. View logs
journalctl --user -u myapp-cage -f

# 6. Update after code/config changes
agentcage cage update myapp -c config.yaml

# 7. Rotate a secret (auto-reloads the cage)
agentcage secret set myapp ANTHROPIC_API_KEY

# 8. Restart without rebuild (config-only change)
agentcage cage reload myapp

# 9. Tear it all down
agentcage cage destroy myapp
```

### View logs

```bash
journalctl --user -u myapp-cage -f
journalctl --user -u myapp-proxy -f
journalctl --user -u myapp-dns -f
```

## Deployment State

agentcage tracks each cage in `~/.config/agentcage/deployments/<name>/config.yaml`. This stored config copy allows commands like `cage update` (without `-c`) and `cage reload` to operate without requiring the original config file. The state is removed when a cage is destroyed.

## Architecture

Three containers on an internal Podman network: the agent (no internet gateway), a dual-homed DNS sidecar, and a dual-homed mitmproxy that inspects and forwards all traffic. See [Architecture](docs/architecture.md) for the full topology, inspector chain, startup order, and certificate sharing.

## Configuration

See the [Configuration Reference](docs/configuration.md) for all settings, defaults, and examples. Example configs: [`basic/config.yaml`](examples/basic/) | [`openclaw/config.yaml`](examples/openclaw/)

## Security

The agent has no internet gateway -- all traffic must pass through the proxy, which applies domain filtering, secret detection, payload inspection, and custom inspectors. See [Security & Threat Model](docs/security.md) for the full threat model, defense layers, and known limitations.

## License

MIT
