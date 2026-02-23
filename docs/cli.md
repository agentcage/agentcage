# CLI Reference

The CLI has a top-level **`init`** command for scaffolding configs, and four command groups: **`cage`** (manage cages), **`secret`** (manage cage-scoped secrets), **`domain`** (manage cage domain allowlists), and **`firecracker`** (host setup for Firecracker mode).

```
agentcage init [NAME] [options]
agentcage <group> <command> [options]
```

## `init` -- Scaffold a config

```
agentcage init [NAME] [options]
```

Generates a starter `cage.yaml` for a new cage. With `--preset`, uses a curated template; without it, produces a generic scaffold you can edit.

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | path | `cage.yaml` | Output file path |
| `--image` | string | `node:22-slim` | Container image |
| `--isolation` | choice: `container`/`firecracker` | `container` | Isolation backend |
| `--force` | flag | | Overwrite existing file |
| `--preset` | string | | Use a preset template (e.g. `openclaw`, `picoclaw`) |
| `--list-presets` | flag | | List available presets and exit |

### Examples

```bash
# Generic scaffold
agentcage init myapp --image python:3.12-slim

# OpenClaw preset
agentcage init myclaw --preset openclaw

# List available presets
agentcage init --list-presets
```

---

## `cage` -- Manage cages

| Command | Description |
|---|---|
| `cage create -c CONFIG` | Build images, generate quadlets, install, and start a new cage |
| `cage update NAME [-c CONFIG]` | Rebuild images and restart an existing cage |
| `cage list` | List all cages with status |
| `cage destroy NAME [-y]` | Stop containers, remove quadlets, state, and scoped secrets |
| `cage verify NAME` | Health checks (containers, certs, proxy, egress, rootless) |
| `cage edit NAME` | Open stored config in `$EDITOR`, validate, and reload if running |
| `cage reload NAME` | Restart containers without rebuilding images |
| `cage logs NAME [OPTIONS]` | Follow journalctl logs for a cage |
| `cage audit NAME [OPTIONS]` | Query, filter, and summarize proxy audit logs |
| `cage har NAME [OPTIONS]` | Export captured HTTP traffic as HAR 1.2 JSON |

## `secret` -- Manage cage-scoped secrets

| Command | Description |
|---|---|
| `secret list NAME` | List secrets for a cage (with status if cage exists) |
| `secret set NAME KEY` | Set a secret (prompts for value or reads stdin) |
| `secret rm NAME KEY` | Remove a secret |

## `domain` -- Manage cage domain allowlists

| Command | Description |
|---|---|
| `domain list NAME` | List domains and filtering mode for a cage |
| `domain add NAME DOMAIN` | Add a domain to a cage's allowlist (auto-reloads if running) |
| `domain rm NAME DOMAIN` | Remove a domain from a cage's allowlist (auto-reloads if running) |

---

## `cage create`

```
agentcage cage create -c <config>
```

Creates a new cage from a config file. This single command:

1. Validates the config
2. Checks that all required secrets exist in Podman
3. Saves deployment state to `~/.config/agentcage/deployments/<name>/cage.yaml`
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

## `cage update`

```
agentcage cage update <name> [-c <config>]
```

Rebuild and restart an existing cage. Use this after changing code or config:

- **With `-c`**: Updates the stored config, then rebuilds and restarts.
- **Without `-c`**: Rebuilds from the previously stored config (useful when only the container image or proxy code has changed).

Stops the running services before rebuilding, then starts them again.

## `cage list`

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

## `cage destroy`

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

## `cage verify`

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

## `cage edit`

```
agentcage cage edit <name>
```

Opens the stored cage config (`~/.config/agentcage/cages/<name>/cage.yaml`) in `$EDITOR`. After saving, the config is validated and the proxy config is synced. If the cage is running, it is automatically reloaded.

For changes that require an image rebuild (e.g. `container.image`), use `cage update` instead.

**Example:**

```
agentcage cage edit myapp
# → opens $EDITOR with the cage config
# → validates on save, reloads if running
```

## `cage reload`

```
agentcage cage reload <name>
```

Restarts containers without rebuilding images. Useful after config-only changes (the config YAML is bind-mounted into the proxy container, so a restart picks it up).

## `cage logs`

```
agentcage cage logs <name> [options]
```

Follow journalctl logs for a cage.

### Options

| Flag | Type | Description |
|------|------|-------------|
| `-s, --service` | repeatable choice: `cage`/`proxy`/`dns` | Filter by service (default: all) |
| `-n, --lines` | int (default 50) | Number of lines to show |
| `--no-follow` | flag | Print logs and exit |
| `-l, --severity` | choice: `debug`/`info`/`warning`/`error`/`critical` | Minimum severity level to show |

## `cage audit`

```
agentcage cage audit <name> [options]
```

Query, filter, and summarize proxy audit logs. The proxy writes a structured JSON audit entry for every inspected request (blocked, flagged, or allowed). This command reads those entries from journalctl, applies filters, and presents them as a table, JSON lines, or an aggregated summary.

In container mode, audit entries are read from the `{name}-proxy` systemd unit. In Firecracker mode, they are read from the `{name}-cage` unit (where proxy logs appear with `[proxy:level]` prefixes).

### Options

| Flag | Type | Description |
|------|------|-------------|
| `-d, --decision` | repeatable choice: `blocked`/`flagged`/`allowed` | Filter by decision (OR within, AND with other filters) |
| `--host` | repeatable string | Filter by target host (substring match) |
| `--inspector` | repeatable string | Filter by inspector name |
| `--severity` | choice: `debug`/`info`/`warning`/`error`/`critical` | Minimum severity level |
| `--method` | repeatable string | Filter by HTTP method |
| `--since` | string | Time window: `1h`, `30m`, `7d`, or ISO date |
| `-n, --lines` | int (default 100) | Max entries to show (0 = unlimited) |
| `-f, --follow` | flag | Stream new entries in real time |
| `--json` | flag | Output as JSON lines (one per entry) |
| `--summary` | flag | Show aggregated statistics (incompatible with `--follow`) |
| `--no-color` | flag | Disable colored output |

### Examples

```bash
# Last 100 audit entries as a table
agentcage cage audit myapp

# Stream blocked and flagged entries as JSON (for alerting pipelines)
agentcage cage audit myapp -f --json -d blocked -d flagged

# Daily summary report
agentcage cage audit myapp --summary --since 24h

# Secret leak attempts
agentcage cage audit myapp -d blocked --inspector secrets

# Pipe to an alerting webhook
agentcage cage audit myapp -f --json -d blocked | ./alert-webhook.sh
```

## `cage har`

```
agentcage cage har <name> [options]
```

Export captured HTTP traffic as HAR 1.2 JSON. Requires `capture: enabled: true` in the cage config. The capture file records full decrypted request/response bodies with two perspectives per flow.

Two perspectives are available:

- **inbound** (default) — What the bot saw inside the cage. Secrets are replaced with placeholders. Safe to share with researchers.
- **outbound** — What went on the wire. Contains real API keys and tokens. Treat as sensitive.

Output is valid HAR 1.2 JSON, loadable in Chrome DevTools (Network > Import HAR).

### Options

| Flag | Type | Description |
|------|------|-------------|
| `--view` | choice: `inbound`/`outbound` | Perspective to export (default: `inbound`) |
| `-d, --decision` | repeatable choice: `blocked`/`flagged`/`allowed` | Filter by decision |
| `--host` | repeatable string | Filter by host (substring match) |
| `--method` | repeatable string | Filter by HTTP method |
| `--direction` | repeatable choice: `inbound`/`outbound` | Filter by traffic direction |
| `--since` | string | Time window: `1h`, `30m`, `7d`, or ISO date |
| `-n, --max-entries` | int (default 0) | Max entries (0 = unlimited) |
| `-o, --output` | path | Output file (default: stdout) |
| `--json-lines` | flag | Output raw capture JSONL instead of HAR |

### Examples

```bash
# Export everything the agent saw (inbound perspective)
agentcage cage har mycage -o agent-view.har

# Export only blocked requests as seen on the wire
agentcage cage har mycage --view outbound --decision blocked -o blocked.har

# Export last hour of traffic to anthropic
agentcage cage har mycage --host api.anthropic.com --since 1h -o anthropic.har

# Pipe raw capture data for custom processing
agentcage cage har mycage --json-lines | jq '.outbound.request.url'
```

---

## `secret set`

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

## `secret list`

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

## `secret rm`

```
agentcage secret rm <name> <key>
```

Removes a secret from Podman. If the cage is currently running, it is automatically reloaded.

## `domain list`

```
agentcage domain list <name>
```

Lists the domain filtering mode and all domains for a cage:

```
Mode: allowlist
api.anthropic.com
github.com
httpbin.org
```

Mode is one of:
- **allowlist** -- only listed domains are permitted (default)
- **blocklist** -- listed domains are blocked, all others permitted

## `domain add`

```
agentcage domain add <name> <domain>
```

Adds a domain to a cage's allowlist. Updates both the stored config and the proxy config on disk. If the cage is currently running, all containers are automatically restarted so the change takes effect immediately.

```bash
agentcage domain add myapp api.openai.com
# Added 'api.openai.com' to cage 'myapp'. Cage reloaded.
```

Subdomain matching is built in -- adding `anthropic.com` also allows `api.anthropic.com`. Duplicates are detected and skipped.

If no `domains` section exists in the stored config, one is created with mode `allowlist`.

## `domain rm`

```
agentcage domain rm <name> <domain>
```

Removes a domain from a cage's allowlist. Like `domain add`, updates stored config and proxy config, and auto-reloads the cage if running.

```bash
agentcage domain rm myapp api.openai.com
# Removed 'api.openai.com' from cage 'myapp'. Cage reloaded.
```

Fails if the domain is not in the list.

---

## `firecracker` -- Firecracker host setup

### `firecracker setup`

```
sudo agentcage firecracker setup
```

One-time host setup for Firecracker mode. Requires root. This command:

1. Downloads the guest kernel (if not already present)
2. Downloads the Firecracker binary (if not already present)
3. Checks all prerequisites (`/dev/kvm` access, `agentcage-nethelper`, etc.)
4. Creates the `agentcage-br0` network bridge (if not already present)

Run this once before creating your first Firecracker cage. If any step fails, the output tells you exactly what to fix.

```bash
sudo agentcage firecracker setup
# Kernel: /opt/agentcage/vmlinux
#   ok
# Firecracker: /opt/agentcage/firecracker
#   ok
#
# All prerequisites met.
#
# Network bridge (agentcage-br0) already exists.
```
