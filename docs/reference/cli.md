# CLI Reference Manual

The `agentcage` command-line interface manages sandboxes, secret storage, domain allowlists, traffic auditing, and runtime grants.

---

## Global Options & Aliases

```text
agentcage [OPTIONS] COMMAND [ARGS]...

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.
```

### Top-Level Aliases
For developer convenience, frequently used commands can be executed directly without the `cage` sub-group prefix:

| Alias | Full Command Target |
| :--- | :--- |
| `agentcage run ...` | `agentcage cage run ...` |
| `agentcage exec ...` | `agentcage cage exec ...` |
| `agentcage shell ...` | `agentcage cage shell ...` |
| `agentcage ls` / `agentcage ps` | `agentcage cage list` |
| `agentcage logs ...` | `agentcage cage logs ...` |
| `agentcage status [NAME]` | `agentcage cage status [NAME]` |
| `agentcage show NAME` / `describe` / `inspect` | `agentcage cage show NAME` |
| `agentcage edit NAME` / `config` | `agentcage cage edit NAME` |
| `agentcage start` / `stop` / `restart` / `reload` | `agentcage cage start/stop/restart ...` |
| `agentcage rm NAME` / `delete` | `agentcage cage destroy NAME` |
| `agentcage update NAME ...` | `agentcage cage update NAME ...` |

---

## 1. Initializing & Launching Workloads

### `agentcage init [NAME]`
Generates a new declarative `cage.yaml` configuration in the current directory:

```bash
agentcage init my-agent --scaffold claude-code
```

**Options**:
- `-o, --output PATH`: Target file path (default: `cage.yaml`).
- `--image TEXT`: Base container image (default: `node:22-slim`).
- `--isolation [container|vm|apple-container]`: Specify backend (default: auto-detected).
- `--scaffold TEXT`: Initialize from a scaffold template (e.g. `claude-code`, `pi`, `codex`, `openclaw`).
- `--list-scaffolds`: Print all available scaffolds and exit.
- `--force`: Overwrite existing target file without prompting.

---

### `agentcage run SCAFFOLD [EXTRA_ARGS]...`
Launches an ephemeral, one-shot sandboxed agent session. The cage and network are automatically destroyed upon process exit:

```bash
agentcage run claude-code -s ANTHROPIC_API_KEY
```

**Options**:
- `--project PATH`: Directory to bind mount to `/workspace` (default: current directory).
- `--name TEXT`: Custom cage name (default: auto-generated).
- `-s, --set-secret TEXT`: Secret to set (`KEY=VALUE` or `KEY` to prompt securely). Repeatable.
- `--isolation [container|vm|apple-container]`: Override isolation backend.
- `--as-root`: Run as root (UID 0) inside container instead of UID 1000 (debug only).
- `--no-cache`: Force clean image rebuild, ignoring Podman layer caches.
- `--pull`: Force re-pulling the base image from the remote registry.
- `--time`: Print wall-clock execution times for each setup phase.
- `-v, --verbose`: Display full image build output.

---

## 2. Managing Cage Lifecycles (`agentcage cage`)

### `agentcage cage create [CONFIG_PATH]`
Builds container images, generates systemd quadlets or microVM configs, and starts a persistent cage:

```bash
agentcage cage create -c ./cage.yaml -s ANTHROPIC_API_KEY
```

**Options**:
- `-c, --config PATH`: Path to `cage.yaml` (may also be provided positionally).
- `-s, --set-secret TEXT`: Supply required secrets (`KEY=VALUE` or `KEY` to prompt). Repeatable.
- `--no-cache`: Force full image rebuild.
- `--pull`: Always pull latest base image.
- `--time`: Print per-phase timing summaries.

---

### `agentcage cage update [NAME]`
Rebuilds and restarts an existing persistent cage to pick up configuration or image changes:

```bash
agentcage cage update my-agent --no-cache --pull
```

**Options**:
- `-c, --config PATH`: Path to updated `cage.yaml` (optional if `NAME` is provided).
- `--no-cache`: Ignore image layer cache.
- `--pull`: Re-pull base images.
- `--force`: Rebuild even if input files are unchanged.

---

### `agentcage cage list` (Aliases: `ls`, `ps`)
Lists all existing cages with status, isolation mode, backend, and scaffold metadata:

```bash
agentcage list
```

---

### `agentcage cage status [NAME]`
Displays system status: lists all cages when invoked without arguments; displays full status detail when invoked with `NAME` (mirrors `systemctl status`).

---

### `agentcage cage show NAME` (Aliases: `describe`, `inspect`)
Displays detailed configuration, network IP addresses, mounted volumes, active domain rules, and secret placeholders for a specific cage:

```bash
agentcage show my-agent
```

---

### `agentcage cage start | stop | restart NAME`
Controls container execution without rebuilding images:
- `start`: Starts a stopped cage service.
- `stop`: Pauses execution while preserving container state and IP bindings.
- `restart` (alias: `reload`): Restarts container processes without rebuilding.

---

### `agentcage cage destroy NAME` (Aliases: `rm`, `delete`)
Stops running containers, removes systemd quadlets, deletes state files, and purges scoped secrets:

```bash
agentcage rm my-agent -y
```

**Options**:
- `-y, --yes`: Skip confirmation prompt.
- `--keep-secrets`: Retain encrypted secrets on the host (useful when recreating the cage).

---

### `agentcage cage prune`
Removes all exited, stopped ephemeral or interactive cages:

```bash
agentcage cage prune -y
```

---

### `agentcage cage edit NAME` (Alias: `config`)
Opens the cage's stored `cage.yaml` in `$EDITOR` with automatic validation and atomic saving:
- Validates YAML schema before saving (rejected edits are saved to `cage.yaml.rejected`).
- Backs up previous working configuration to `cage.yaml.bak`.
- Auto-applies domain changes to `dnsmasq` via `SIGHUP` without restarting the cage.

---

## 3. Workload Interaction

### `agentcage cage exec NAME COMMAND...`
Runs a non-interactive command inside a cage container:

```bash
agentcage exec my-agent -- npm test
```

**Options**:
- `-s, --service [cage|egress]`: Target container (`cage` for agent workload, `egress` for proxy). Default: `cage`.
- `--as-root`: Execute command as root (UID 0) instead of UID 1000.

---

### `agentcage cage shell NAME`
Opens an interactive TTY shell inside the container:

```bash
agentcage shell my-agent
```

**Options**:
- `-s, --service [cage|egress]`: Target container (`cage` or `egress`). Default: `cage`.
- `--as-root`: Open shell as root (UID 0).

---

### `agentcage cage logs NAME`
Streams container logs from systemd `journalctl`:

```bash
agentcage logs my-agent -f --tail 100
```

**Options**:
- `-s, --service [cage|egress]`: Filter by container service (`cage` or `egress`).
- `-f, --follow`: Follow log stream in real time.
- `-n, --lines, --tail INTEGER`: Number of recent lines to display (default: 50).
- `--since TEXT`: Time filter (e.g. `"10 min ago"`, `"today"`, `"2026-09-08 12:00"`).
- `-l, --severity [debug|info|warning|error|critical]`: Minimum log severity level.

---

## 4. Egress Domains & Runtime Grants

### `agentcage domain add NAME DOMAIN...`
Adds one or more domains to a cage's permanent allowlist (triggers instant proxy reload):

```bash
agentcage domain add my-agent crates.io docs.rs --expires-in 2h
```

**Options**:
- `--passthrough`: Add to raw TLS passthrough list (bypasses MITM inspection).
- `--expires-in TEXT`: Set a TTL (e.g. `"30m"`, `"2h"`, `"1d"`). Once expired, traffic is blocked.

---

### `agentcage domain list NAME` (Alias: `ls`)
Lists all configured allowlisted, blocked, and passthrough domains:

```bash
agentcage domain list my-agent
```

---

### `agentcage domain rm NAME DOMAIN`
Removes a domain from the filter list:

```bash
agentcage domain rm my-agent crates.io
```

---

### `agentcage cage grants NAME COMMAND [ARGS]...`
Manages runtime domain access granted by the Policy API / Decider Agent:

- **`grants list <name>`**: Shows both static baseline and active dynamic runtime grants.
- **`grants promote <name> <domain>`**: Promotes a temporary runtime grant into permanent `cage.yaml`.
- **`grants revoke <name> <domain>`**: Immediately removes a temporary runtime grant.
- **`grants sync <name>`**: Reconciles expired grants and cleans up DNS zone configurations.

---

## 5. Secret Management (`agentcage secret`)

### `agentcage secret set NAME KEY`
Stores a secret encrypted on the host for a specific cage:

```bash
agentcage secret set my-agent ANTHROPIC_API_KEY
```

**Options**:
- `--declare`: Automatically add a `secret_injection` rule to `cage.yaml` if none exists.
- `--placeholder TEXT`: Provide an explicit placeholder string (implies `--declare`).
- `--inject-to TEXT`: Restrict substitution to specific domains (repeatable).

---

### `agentcage secret list NAME` (Alias: `ls`)
Lists all secrets configured for a cage, indicating whether values are stored and which placeholders they map to:

```bash
agentcage secret list my-agent
```

---

### `agentcage secret rm NAME KEY`
Deletes a stored secret:

```bash
agentcage secret rm my-agent ANTHROPIC_API_KEY
```

---

### `agentcage secret rotate-placeholders NAME [KEYS...]`
Generates fresh 128-bit entropic placeholders for all injection rules and updates `cage.yaml`:

```bash
agentcage secret rotate-placeholders my-agent
```

---

## 6. Traffic Auditing & Watcher

### `agentcage cage audit NAME`
Queries, filters, and summarizes structured proxy audit decisions:

```bash
# View summary statistics:
agentcage cage audit my-agent --summary --since 24h

# Stream only blocked requests:
agentcage cage audit my-agent -f -d blocked
```

**Options**:
- `-d, --decision [blocked|flagged|allowed]`: Filter by proxy decision (repeatable).
- `--host TEXT`: Filter by target host substring.
- `--inspector TEXT`: Filter by triggering inspector name.
- `--severity [debug|info|warning|error|critical]`: Minimum inspector severity.
- `--since TEXT`: Time window (`"30m"`, `"1h"`, `"7d"`, or ISO timestamp).
- `-f, --follow`: Stream events in real time.
- `--summary`: Output aggregated decision counts.
- `--json`: Output as raw JSON lines.

---

### `agentcage cage har NAME`
Exports captured HTTP transactions as standard HAR 1.2 JSON loadable into Chrome DevTools:

```bash
agentcage cage har my-agent --view inbound -o traffic.har
```

**Options**:
- `--view [inbound|outbound]`: Perspective to export:
  - `inbound` (default): Safe to share; contains only decoy placeholders.
  - `outbound`: Sensitive wire-view containing real injected credentials.
- `-d, --decision [blocked|flagged|allowed]`: Filter by decision.
- `-o, --output PATH`: Target file (default: stdout).
- `--json-lines`: Output raw JSONL capture format instead of HAR.

---

### `agentcage watcher status | findings NAME`
- **`watcher status <name>`**: Displays background traffic watcher scan intervals, backlog, and health.
- **`watcher findings <name>`**: Lists anomalies flagged by the Watcher (options: `-s, --severity`, `--json`).

---

## 7. Diagnostics & Backup

### `agentcage doctor`
Runs comprehensive diagnostic checks on host dependencies, virtualization backends, rootless Podman, systemd lingering, and secret stores.

---

### `agentcage cage backup NAME`
Creates a portable tarball backup of a cage's configuration, volume data, and metadata:

```bash
agentcage cage backup my-agent -o ./backup.tar.gz --include-secrets
```

---

### `agentcage cage restore TARBALL`
Restores or clones a cage from a backup tarball:

```bash
agentcage cage restore ./backup.tar.gz --name my-cloned-agent
```

---

## Next Steps

- **[Configuration Reference](configuration.md)** — Schema reference for `cage.yaml`.
- **[Policy API Reference](policy-api.md)** — In-cage HTTP endpoint reference.
- **[How-To Run Harnesses](../how-to/run-agent-harnesses.md)** — Recipes for Claude Code, Pi, and Codex.
