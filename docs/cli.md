# CLI Reference

The CLI has top-level **`run`**, **`init`**, and **`doctor`** commands, and four command groups: **`cage`**, **`secret`**, **`domain`**, and **`scaffold`**.

```
agentcage run SCAFFOLD [options]
agentcage init [NAME] [options]
agentcage <group> <command> [options]
```

## `init` -- Scaffold a config

```
agentcage init [NAME] [options]
```

Generates a starter `cage.yaml` for a new cage. With `--scaffold`, uses a curated template; without it, produces a generic scaffold you can edit.

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | path | `cage.yaml` | Output file path |
| `--image` | string | `node:22-slim` | Container image |
| `--isolation` | choice: `container`/`vm` | `container` | Isolation backend |
| `--force` | flag | | Overwrite existing file |
| `--scaffold` | string | | Use a scaffold template (e.g. `claude-code`, `codex`, `openclaw`) |
| `--list-scaffolds` | flag | | List available scaffolds and exit |
| `--port` | int | | Host port to publish (scaffold-specific) |

### Examples

```bash
# Generic scaffold
agentcage init myapp --image python:3.12-slim

# OpenClaw scaffold
agentcage init myclaw --scaffold openclaw

# Claude Code scaffold
agentcage init mycc --scaffold claude-code

# List available scaffolds
agentcage init --list-scaffolds
```

---

## `run` -- Run a coding agent in a sandbox

```
agentcage run SCAFFOLD [options] [-- EXTRA_ARGS...]
```

Creates a sandboxed cage from a scaffold, opens an interactive session, and stops the cage on exit. Auto-generates a unique cage name (e.g. `claude-code-bold-fox`). The cage state is preserved after exit for auditing — use `cage prune` to clean up.

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--project` | path | current directory | Project directory to mount as `/workspace` |
| `--name` | string | auto-generated | Override the auto-generated cage name |
| `-i, --interactive-domains` | flag | | Prompt to add blocked domains to the allowlist in real-time |
| `-s, --set-secret` | repeatable string | | Set a secret (`KEY=VALUE` or `KEY` to prompt). Passed to the cage at creation |
| `-v, --verbose` | flag | | Enable verbose output |
| `--isolation` | choice: `container`/`vm` | `container` | Isolation backend |

### Examples

```bash
# Run Claude Code in the current project
agentcage run claude-code

# Run Codex with a specific project
agentcage run codex --project /path/to/repo

# Run with a custom name
agentcage run claude-code --name my-session

# Run with interactive domain prompts
agentcage run claude-code -i
```

When `-i` is passed, each time the proxy blocks a request to an unlisted domain, you are prompted to add it to the allowlist:

```
[agentcage] blocked → api.stripe.com (domain)
  Add stripe.com to allowlist? [y/N] y
  ✓ stripe.com added
```

Subdomains are collapsed to their parent domain (e.g. `api.stripe.com` prompts for `stripe.com`). Each domain is prompted at most once per session.

---

## `cage` -- Manage cages

| Command | Description |
|---|---|
| `cage create -c CONFIG` | Build images, generate quadlets, install, and start a new cage |
| `cage update NAME [-c CONFIG]` | Rebuild images and restart an existing cage |
| `cage edit NAME` | Edit a cage's stored config in `$EDITOR` with validation, backup, and live-reload |
| `cage list` | List all cages with status |
| `cage destroy NAME [-y] [--keep-secrets]` | Stop containers, remove quadlets, state, and scoped secrets |
| `cage prune [-y]` | Remove all exited interactive and ephemeral cages |
| `cage show NAME` | Show cage configuration and status |
| `cage verify NAME` | Health checks (containers, certs, proxy, egress, rootless) |
| `cage stop NAME` | Stop a running cage without destroying it |
| `cage start NAME` | Start a stopped cage |
| `cage restart NAME` | Restart containers without rebuilding images |
| `cage logs NAME [OPTIONS]` | Show journalctl logs for a cage |
| `cage shell NAME` | Open an interactive shell in a cage container |
| `cage audit NAME [OPTIONS]` | Query, filter, and summarize proxy audit logs |
| `cage har NAME [OPTIONS]` | Export captured HTTP traffic as HAR 1.2 JSON |
| `cage backup NAME [OPTIONS]` | Create a backup tarball of a cage |
| `cage restore TARBALL [OPTIONS]` | Restore a cage from a backup tarball |

**Aliases:** `ls` → `list`, `ps` → `list`, `status` → `list`, `rm` → `destroy`, `delete` → `destroy`, `reload` → `restart`, `describe` → `show`, `inspect` → `show`, `config` → `edit`

## `secret` -- Manage cage-scoped secrets

| Command | Description |
|---|---|
| `secret list NAME` | List secrets for a cage (with status if cage exists) |
| `secret set NAME KEY` | Set a secret (prompts for value or reads stdin) |
| `secret rm NAME KEY` | Remove a secret |
| `secret migrate NAME` | Migrate a cage's secrets to a different storage backend |

**Aliases:** `ls` → `list`

## `domain` -- Manage cage domain filters

| Command | Description |
|---|---|
| `domain list NAME` | List domains and filtering mode for a cage |
| `domain add NAME DOMAIN` | Add a domain to a cage's filter list (auto-reloads if running) |
| `domain rm NAME DOMAIN` | Remove a domain from a cage's filter list (auto-reloads if running) |

**Aliases:** `ls` → `list`

---

## `cage create`

```
agentcage cage create -c <config>
```

Creates a new cage from a config file. Use `-s KEY=VALUE` (repeatable) to set secrets inline during creation. Pass `--no-cache` to force a full image rebuild (ignore podman's layer cache) or `--pull` to force a re-pull of the base image from the registry. This single command:

1. Validates the config
2. Checks that all required secrets exist in Podman
3. Saves deployment state to `~/.config/agentcage/cages/<name>/cage.yaml`
4. Builds the proxy and DNS container images
5. Generates and installs 5 quadlet files into `~/.config/containers/systemd/`
6. Reloads systemd and starts the cage

The generated quadlet files are:

- `<name>-net.network` -- internal network with fixed subnet
- `<name>-certs.volume` -- shared certificate volume
- `<name>-dns.container` -- DNS sidecar (dnsmasq)
- `<name>-proxy.container` -- mitmproxy with inspector chain
- `<name>-cage.container` -- your agent container
- `<name>-podman-storage.volume` -- *(nested containers only)* inner podman storage

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

### Options

| Option | Description |
|---|---|
| `--no-cache` | Force a full image rebuild, ignoring podman's layer cache. Use after pulling a fresh agentcage release that changed the `Containerfile` or its build context. |
| `--pull` | Force a re-pull of the base image from the registry (`--pull=always`). Invalidates the base-image cache, independent of `--no-cache`. Combine both for a fully clean rebuild. |

## `cage edit`

```
agentcage cage edit <name>
```

Opens the cage's stored `cage.yaml` in your `$EDITOR` (falls back to `vi`). On save:

1. Parses the edited YAML and runs the same `validate_config` checks that `cage create` runs. If parsing or validation fails, the edits are written to `cage.yaml.rejected` and the original `cage.yaml` is left untouched — exits non-zero.
2. Backs up the prior good config to `cage.yaml.bak`.
3. Writes the new config atomically (temp file + `rename`) so a crash mid-edit cannot corrupt cage state.
4. Shows a unified diff of what changed.
5. **Live-applies domain changes** by re-rendering the dnsmasq allowlist and `pkill -HUP dnsmasq` inside the dns sidecar — no cage restart, any interactive session inside the cage survives.
6. For changes the proxy can hot-reload (`inspectors`, `rate_limit`, `logging`, etc.), rewrites `proxy-config.yaml` — the mitmproxy addon picks it up on the next request via mtime polling.
7. For changes that need a service restart (`container.*`, `secrets`, etc.), tells you to run `agentcage cage restart NAME`.
8. For changes that need a full rebuild (`isolation`, `vm.*`), tells you to run `agentcage cage update NAME`.

This is safer than `$EDITOR ~/.config/agentcage/cages/NAME/cage.yaml` because a malformed YAML or invalid field there silently breaks the cage at the next `cage start` / `cage update`. With `cage edit`, the validation runs *before* the file is written.

Aliased as `cage config`.

## `cage list`

```
agentcage cage list
```

Lists all known cages with their current status:

```
NAME                 ISOLATION      VERSION      STATUS
myapp                container      0.8.0        running (3/3)
testcage             vm             0.7.1        stopped (0/3)
broken               container      0.8.0        degraded (2/3)
```

## `cage destroy`

```
agentcage cage destroy <name> [-y|--yes] [--keep-secrets]
```

Tears down a cage completely:

1. Stops all containers (cage, proxy, DNS)
2. Removes quadlet files from `~/.config/containers/systemd/`
3. Removes the Podman network and certificate volume
4. Removes all scoped secrets (e.g., `myapp.ANTHROPIC_API_KEY`) — unless `--keep-secrets` is passed
5. Removes deployment state from `~/.config/agentcage/cages/<name>/`

User-defined named volumes and bind-mounted data are never removed. Pass `-y` to skip the confirmation prompt. Pass `--keep-secrets` to preserve scoped secrets (useful when destroying and recreating a cage).

## `cage verify`

```
agentcage cage verify <name>
```

Runs health checks against a running cage:

- All 3 containers running (cage, proxy, DNS)
- CA certificate present in the shared volume
- `HTTP_PROXY` / `HTTPS_PROXY` set in the cage container
- Egress filtering working (blocked domain returns 403)
- Inner podman and Docker shim available (when `nested_containers: true`)
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

## `cage show`

```
agentcage cage show <name>
```

Show cage configuration and status. Displays name, isolation mode, image, version, service status, ports, domain mode, and secrets status.

**Aliases:** `cage describe`, `cage inspect`

## `cage stop`

```
agentcage cage stop <name>
```

Stop a running cage without destroying it. Services can be restarted with `cage start`.

## `cage start`

```
agentcage cage start <name>
```

Start a stopped cage.

## `cage restart`

```
agentcage cage restart <name>
```

Restarts containers without rebuilding images. Useful after config-only changes: `restart` (and `start`) regenerate `proxy-config.yaml` and `dns-allowlist.conf` from `cage.yaml` before bouncing services, so the running cage always reflects the current config on disk.

**Alias:** `cage reload`

## `cage logs`

```
agentcage cage logs <name> [options]
```

Show journalctl logs for a cage.

### Options

| Flag | Type | Description |
|------|------|-------------|
| `-s, --service` | repeatable choice: `cage`/`proxy`/`dns` | Filter by service (default: all) |
| `-n, --lines` | int (default 50) | Number of lines to show |
| `-f, --follow` | flag | Stream logs in real time |
| `-l, --severity` | choice: `debug`/`info`/`warning`/`error`/`critical` | Minimum severity level to show |

## `cage shell`

```
agentcage cage shell <name> [options]
```

Open an interactive shell in a cage container. Auto-detects bash, falling back to sh.

### Options

| Flag | Type | Description |
|------|------|-------------|
| `-s, --service` | choice: `cage`/`proxy`/`dns` | Container to shell into (default: `cage`) |

## `cage audit`

```
agentcage cage audit <name> [options]
```

Query, filter, and summarize proxy audit logs. The proxy writes a structured JSON audit entry for every inspected request (blocked, flagged, or allowed). This command reads those entries from journalctl, applies filters, and presents them as a table, JSON lines, or an aggregated summary.

Audit entries are read from the `{name}-proxy` systemd unit in container mode, or from the Lima VM's journal in VM mode.

### Options

| Flag | Type | Description |
|------|------|-------------|
| `-d, --decision` | repeatable choice: `blocked`/`flagged`/`allowed` | Filter by decision (OR within, AND with other filters) |
| `--host` | repeatable string | Filter by target host (substring match) |
| `--inspector` | repeatable string | Filter by inspector name |
| `--severity` | choice: `debug`/`info`/`warning`/`error`/`critical` | Minimum severity level |
| `--method` | repeatable string | Filter by HTTP method |
| `--since` | string | Time window: `1h`, `30m`, `7d`, or ISO date |
| `-n, --max-entries` | int (default 100) | Max entries to show (0 = unlimited) |
| `-f, --follow` | flag | Stream new entries in real time |
| `--json` | flag | Output as JSON lines (one per entry) |
| `--summary` | flag | Show aggregated statistics (incompatible with `--follow`) |
| `--direction` | repeatable choice: `inbound`/`outbound` | Filter by traffic direction |
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

## `cage backup`

```
agentcage cage backup <name> [options]
```

Create a compressed tarball containing a cage's config, named volumes, capture logs, and optionally secrets.

### Options

| Flag | Type | Description |
|------|------|-------------|
| `-o, --output` | path | Output path (default: `./{name}-backup-{timestamp}.tar.gz`) |
| `--include-secrets` | flag | Include secret values in the backup (handle with care) |

### Tarball layout

```
agentcage-backup/
  manifest.json            # format version, cage metadata, content flags
  config/
    cage.yaml
    metadata.json
    proxy-config.yaml
  secrets/                 # only present with --include-secrets
    API_KEY
    GITHUB_TOKEN
  volumes/                 # podman volume exports
    myapp-state.tar
  capture/
    capture.jsonl
```

### Examples

```bash
# Backup without secrets (default)
agentcage cage backup myapp

# Backup with secrets to a specific path
agentcage cage backup myapp --include-secrets -o /backups/myapp.tar.gz

# Inspect the tarball
tar tzf myapp-backup-20260223-143000.tar.gz
```

## `cage restore`

```
agentcage cage restore <tarball> [options]
```

Restore a cage from a backup tarball. Recreates config, secrets (if included), named volumes, and capture logs. Can restore to a different name for cloning.

### Options

| Flag | Type | Description |
|------|------|-------------|
| `--name` | string | Restore with a different name (for cloning) |
| `--force` | flag | Overwrite existing cage |
| `--no-start` | flag | Restore state without building or starting |

### Examples

```bash
# Restore to the original name
agentcage cage restore myapp-backup-20260223-143000.tar.gz

# Clone to a new name
agentcage cage restore myapp-backup.tar.gz --name myapp-clone

# Overwrite an existing cage
agentcage cage restore backup.tar.gz --force

# Restore config and secrets only, start later
agentcage cage restore backup.tar.gz --no-start
agentcage cage update myapp   # build and start when ready
```

### Notes

- If the backup does not include secrets (`--include-secrets` was not used during backup), you must set them manually before starting the cage.
- With `--no-start`, named volumes are not imported (they don't exist until the cage starts). They will be imported on the first start via `cage update`.
- When cloning with `--name`, the `name` field in `cage.yaml` is updated and secrets are scoped to the new name. Named volume names are not changed.

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

Lists secrets for a cage. If the cage has deployment state (i.e. the cage has been created with `cage create`), cross-references with the config to show expected secrets and their status:

```
NAME                           TYPE         STATUS
ANTHROPIC_API_KEY                 injection    ok
GITHUB_TOKEN                   direct       MISSING
```

Secret types:
- **injection** -- managed by the proxy's secret injection system (the cage sees a placeholder; the proxy swaps in the real value)
- **direct** -- passed directly to the cage container via `podman_secrets`

If no deployment state exists (e.g. before `cage create` has been run), the TYPE and STATUS columns are not shown. Only the secret names matching the `<name>.` prefix are listed.

## `secret rm`

```
agentcage secret rm <name> <key>
```

Removes a secret from Podman. If the cage is currently running, it is automatically reloaded.

## `secret migrate`

```
agentcage secret migrate <name> [--backend systemd-creds] [--remove-old|--keep-old]
```

Migrates a cage's secrets to a different storage backend. The `systemd-creds` backend re-encrypts each secret with a systemd-creds key so the plaintext no longer lives in the Podman secret store.

| Option | Description |
|---|---|
| `--backend systemd-creds` | Target backend for secret storage. |
| `--remove-old` / `--keep-old` | Remove (or keep) the old plaintext secrets in the Podman store after migration. |

The encrypting key's scope — `user` or `system` — follows the cage's `secrets.scope` config field (`auto` | `user` | `system`, default `auto`). `agentcage doctor` reports the scope a cage resolved to.

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

Adds a domain to a cage's filter list. Updates both the stored config and the proxy config on disk. If the cage is currently running, the proxy detects the config change and hot-reloads.

```bash
agentcage domain add myapp api.openai.com
# Added 'api.openai.com' to cage 'myapp'. Proxy updated.
```

Subdomain matching is built in -- adding `anthropic.com` also allows `api.anthropic.com`. Duplicates are detected and skipped.

If no `domains` section exists in the stored config, one is created with mode `allowlist`.

## `domain rm`

```
agentcage domain rm <name> <domain>
```

Removes a domain from a cage's filter list. Like `domain add`, updates stored config and proxy config, and hot-reloads the proxy if running.

```bash
agentcage domain rm myapp api.openai.com
# Removed 'api.openai.com' from cage 'myapp'. Proxy updated.
```

Fails if the domain is not in the list.


---

## Shell completion

agentcage uses Click's native completion. Add one of these to your shell profile to enable tab completion permanently:

```bash
# Bash (~/.bashrc)
eval "$(_AGENTCAGE_COMPLETE=bash_source agentcage)"

# Zsh (~/.zshrc)
eval "$(_AGENTCAGE_COMPLETE=zsh_source agentcage)"

# Fish (~/.config/fish/config.fish)
eval "$(_AGENTCAGE_COMPLETE=fish_source agentcage)"
```

---

## `doctor` -- Check system prerequisites

```
agentcage doctor
```

Checks that all required tools are installed and properly configured (Podman, systemd, Lima, etc.). Reports pass/fail for each prerequisite.

---

## `scaffold` -- Manage scaffold templates

| Command | Description |
|---|---|
| `scaffold list` | List available scaffolds (built-in, user, and project-local) |
| `scaffold show NAME` | Show scaffold details and config template |
| `scaffold create NAME` | Create a new user scaffold |
| `scaffold edit NAME` | Edit a user scaffold |
| `scaffold delete NAME` | Delete a user scaffold |
| `scaffold export NAME` | Export a scaffold as a directory |

Scaffolds are resolved in order: project-local (`.agentcage/scaffolds/`) → user (`~/.config/agentcage/scaffolds/`) → built-in.

**Aliases:** `ls` → `list`, `rm` → `delete`
