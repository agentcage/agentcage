<!-- owner: @luca  last-reviewed: 2026-09-03 -->
# CLI

Reference for every `agentcage` command, subcommand, and flag. Pair with [Configuration](configuration.md) for `cage.yaml` settings and the how-to pages for worked examples.

```bash
agentcage <command> [args] [options]
```

Top-level commands: `run` (alias of `cage run`), `init`, `doctor`. Command groups: `cage`, `secret`, `domain`, `scaffold`.

## init

Generate a starter `cage.yaml` for a new cage.

```bash
agentcage init [NAME] [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | path | `cage.yaml` | Output file path |
| `--image` | string | `node:22-slim` | Container image |
| `--isolation` | `container` \| `vm` | `container` | Isolation backend |
| `--force` | flag | | Overwrite existing file |
| `--scaffold` | string | | Use a scaffold template (e.g. `claude-code`, `codex`, `openclaw`) |
| `--list-scaffolds` | flag | | List available scaffolds and exit |
| `--port` | int | | Host port to publish (scaffold-specific) |

## run

Create a sandboxed cage from a scaffold, open an interactive session, and stop the cage on exit. The cage state is preserved after exit for auditing — use `cage prune` to clean up.

The canonical command is `agentcage cage run`; `agentcage run` is a top-level alias of it (like `agentcage exec` / `agentcage shell`). Both forms take the same arguments.

```bash
agentcage run SCAFFOLD [options] [-- EXTRA_ARGS...]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--project` | path | current directory | Project directory to mount as `/workspace` |
| `--name` | string | auto-generated | Override the auto-generated cage name |
| `-i, --interactive-domains` | flag | | Prompt to add blocked domains to the allowlist in real time |
| `-s, --set-secret` | repeatable | | Set a secret (`KEY=VALUE` or `KEY` to prompt) |
| `-v, --verbose` | flag | | Enable verbose output |
| `--isolation` | `container` \| `vm` | `container` | Isolation backend |
| `--no-cache` | flag | | Force a full image rebuild, ignoring podman's layer cache (all backends) |
| `--pull` | flag | | Force a re-pull of the base image from the registry (all backends) |

Like `cage create`, `run` fails with an actionable error (before starting the cage) if a required secret is missing — provide it with `-s KEY=VALUE` or a configured `source:`. Every scaffold-declared secret is mandatory; there is no "optional secret". To run an agent that authenticates without an API key (e.g. claude-code via interactive OAuth login), create a persistent cage with `agentcage init` and edit its config instead.

`--no-cache`/`--pull` behave consistently across the `container`, `vm`, and `apple-container` backends — they rebuild the scaffold/agent image, the shared egress image, and (on `vm`) the in-VM cage image.

## doctor

Check that all required tools are installed and properly configured (Podman, systemd, Lima, etc.).

```bash
agentcage doctor
```

## cage

Manage cages.

| Command | Description |
|---------|-------------|
| `cage create -c CONFIG` | Build images, generate quadlets, install, and start a new cage |
| `cage run SCAFFOLD` | Create a cage from a scaffold, open an interactive session, and stop on exit (top-level alias: `agentcage run` — see [run](#run)) |
| `cage update NAME [-c CONFIG]` | Rebuild images and restart an existing cage |
| `cage edit NAME` | Edit a cage's stored config in `$EDITOR` with validation and live-reload |
| `cage list` | List all cages with status |
| `cage destroy NAME` | Stop containers, remove quadlets, state, and scoped secrets |
| `cage prune` | Remove all exited interactive and ephemeral cages |
| `cage show NAME` | Show cage configuration and status |
| `cage status [NAME]` | `systemctl`-style: detail for one cage (with NAME) or list all (without) |
| `cage verify NAME` | Run health checks (containers, certs, proxy, egress, rootless) |
| `cage stop NAME` | Stop a running cage without destroying it |
| `cage start NAME` | Start a stopped cage |
| `cage restart NAME` | Restart containers without rebuilding images |
| `cage logs NAME` | Show journalctl logs for a cage |
| `cage shell NAME` | Open an interactive shell in a cage container |
| `cage audit NAME` | Query, filter, and summarize proxy audit logs |
| `cage har NAME` | Export captured HTTP traffic as HAR 1.2 JSON |
| `cage backup NAME` | Create a backup tarball of a cage |
| `cage restore TARBALL` | Restore a cage from a backup tarball |

Aliases: `ls`/`ps`/`status` → `list`, `rm`/`delete` → `destroy`, `reload` → `restart`, `describe`/`inspect` → `show`, `config` → `edit`, `update` → `update`.

> **Note**: `agentcage` also supports dropping the `cage` group prefix for all standard cage commands and these aliases (e.g. `agentcage run`, `agentcage ls`, `agentcage start`, `agentcage stop`, `agentcage update`, `agentcage logs` function as their `cage` equivalents).

### cage create

```bash
agentcage cage create <config>        # positional (docker/podman style)
agentcage cage create -c <config>     # or with -c
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `CONFIG` | path (positional) | | Path to `cage.yaml`. Alternative to `-c`. |
| `-c, --config` | path | | Path to `cage.yaml`. Give the config positionally **or** with `-c`, not both. |
| `-s, --set-secret` | repeatable | | Set a secret inline during creation (`KEY=VALUE`) |
| `--no-cache` | flag | | Force a full image rebuild, ignoring podman's layer cache |
| `--pull` | flag | | Force a re-pull of the base image from the registry |

The config is required — pass it positionally or with `-c`. Fails with an actionable error if any required secrets are missing.

### cage update

```bash
agentcage cage update <name> [-c <config>]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-c, --config` | path | stored config | Replace the stored config before rebuilding |
| `--no-cache` | flag | | Force a full image rebuild |
| `--pull` | flag | | Force a re-pull of the base image |

A cage's `cage.yaml` and `Containerfile` are **frozen at create time** — a scaffold is a one-shot generator, not a live dependency. Without `-c`, `cage update` rebuilds the **staged** Containerfile (the copy in the cage's state dir, shown as `Build:` in `cage show`), pulls fresh base images, and restarts. It never re-reads the scaffold and never mutates the stored config. To change config, edit the staged files and rerun, use `cage edit`, or pass a new config with `-c`.

### cage edit

```bash
agentcage cage edit <name>
```

Opens the stored `cage.yaml` in `$EDITOR` (falls back to `vi`). Validates on save, backs up the prior config to `cage.yaml.bak`, writes atomically, shows a diff, and hot-reloads domains, proxy inspectors, rate limits, and logging where possible. Service-restart or rebuild prompts appear for container or isolation changes. Aliased as `cage config`. See [Architecture — hot-reload](../explain/architecture.md#hot-reload-semantics) for the reload model.

### cage destroy

```bash
agentcage cage destroy <name> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y, --yes` | flag | | Skip the confirmation prompt |
| `--keep-secrets` | flag | | Preserve scoped secrets after teardown |

User-defined named volumes and bind-mounted data are never removed.

### cage list

Lists all known cages with name, isolation, version, and status (`running`/`stopped`/`degraded` plus running container count).

### cage verify

Runs health checks against a running cage: containers up, CA cert present, `HTTP(S)_PROXY` set, egress filtering blocks denied domains, nested-container support (when configured), and rootless Podman.

### cage show

Show cage configuration and status: name, isolation mode, image, `Build:` (the staged Containerfile path), version, service status, ports, domain mode, and secrets status. Aliases: `describe`, `inspect`.

### cage status

```bash
agentcage cage status [name]
```

`systemctl status`-style: with a `NAME`, shows that cage's detail (identical to `cage show`); with no argument, lists every cage (identical to `cage list`). Available top-level as `agentcage status`.

### cage stop / start / restart

Stop a running cage without destroying it, start a stopped cage, or restart containers without rebuilding. `restart` regenerates `proxy-config.yaml` and `dns-allowlist.conf` from `cage.yaml` before bouncing services. `restart` alias: `reload`.

### cage logs

```bash
agentcage cage logs <name> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-s, --service` | repeatable `cage`\|`egress` | all | Filter by service |
| `-n, --lines, --tail` | int | `50` | Number of lines to show (`--tail` is a docker/podman alias) |
| `-f, --follow` | flag | | Stream logs in real time |
| `--since` | string | | Show entries since a time, journalctl syntax (`10 min ago`, `today`, `2026-05-29 14:00`). Not supported on apple-container. |
| `-l, --severity` | `debug`\|`info`\|`warning`\|`error`\|`critical` | | Minimum severity level |

### cage shell

```bash
agentcage cage shell <name> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-s, --service` | `cage`\|`proxy`\|`dns` | `cage` | Container to shell into |

### cage audit

Query, filter, and summarize proxy audit logs from the `{name}-proxy` systemd unit (or the Lima VM journal in VM mode).

```bash
agentcage cage audit <name> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-d, --decision` | repeatable `blocked`\|`flagged`\|`allowed` | | Filter by decision (OR within, AND with other filters) |
| `--host` | repeatable string | | Filter by target host (substring match) |
| `--inspector` | repeatable string | | Filter by inspector name |
| `--severity` | `debug`\|`info`\|`warning`\|`error`\|`critical` | | Minimum severity level |
| `--method` | repeatable string | | Filter by HTTP method |
| `--direction` | repeatable `inbound`\|`outbound` | | Filter by traffic direction |
| `--since` | string | | Time window (`1h`, `30m`, `7d`, or ISO date) |
| `-n, --max-entries` | int | `100` | Max entries to show (`0` = unlimited) |
| `-f, --follow` | flag | | Stream new entries in real time |
| `--json` | flag | | Output as JSON lines |
| `--summary` | flag | | Show aggregated statistics (incompatible with `--follow`) |
| `--no-color` | flag | | Disable colored output |

### cage har

Export captured HTTP traffic as HAR 1.2 JSON. Requires `capture.enabled: true` in the cage config. Output is loadable in Chrome DevTools (Network > Import HAR).

```bash
agentcage cage har <name> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--view` | `inbound`\|`outbound` | `inbound` | Perspective to export (`outbound` contains real secrets) |
| `-d, --decision` | repeatable `blocked`\|`flagged`\|`allowed` | | Filter by decision |
| `--host` | repeatable string | | Filter by host (substring match) |
| `--method` | repeatable string | | Filter by HTTP method |
| `--direction` | repeatable `inbound`\|`outbound` | | Filter by traffic direction |
| `--since` | string | | Time window (`1h`, `30m`, `7d`, or ISO date) |
| `-n, --max-entries` | int | `0` | Max entries (`0` = unlimited) |
| `-o, --output` | path | stdout | Output file |
| `--json-lines` | flag | | Output raw capture JSONL instead of HAR |

### cage backup

```bash
agentcage cage backup <name> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | path | `./{name}-backup-{timestamp}.tar.gz` | Output path |
| `--include-secrets` | flag | | Include secret values in the backup |

### cage restore

```bash
agentcage cage restore <tarball> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--name` | string | original | Restore with a different name (for cloning) |
| `--force` | flag | | Overwrite existing cage |
| `--no-start` | flag | | Restore state without building or starting |

## secret

Manage cage-scoped secrets.

| Command | Description |
|---------|-------------|
| `secret list NAME` | List secrets for a cage (with status if cage exists) |
| `secret set NAME KEY [--declare] [--placeholder P] [--inject-to D]` | Set a secret (prompts for value or reads stdin). Applies live to a running cage — no restart. `--declare` adds a `secret_injection` rule for a brand-new KEY (entropic placeholder; `--inject-to` scopes it) |
| `secret rm NAME KEY` | Remove a secret |
| `secret rotate-placeholders NAME [KEY...]` | Mint fresh entropic placeholders for all (or named) `secret_injection` rules — retire a compromised placeholder or migrate a legacy static one. Restarts a running cage to apply |
| `secret migrate NAME` | Migrate a cage's secrets to a different storage backend |

Aliases: `ls` → `list`.

Secrets are stored in Podman as `<name>.<key>` (e.g. `myapp.ANTHROPIC_API_KEY`) and mapped back to the original env var name via `target=` in the quadlet templates. Setting or removing a secret auto-reloads a running cage.

### secret migrate

```bash
agentcage secret migrate <name> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--backend` | `systemd-creds` | | Target backend for secret storage |
| `--remove-old` | flag | | Remove old plaintext secrets from the Podman store |
| `--keep-old` | flag | | Keep old plaintext secrets in the Podman store |

The encrypting key's scope (`user` or `system`) follows the cage's `secrets.scope` config field. `agentcage doctor` reports the resolved scope.

## domain

Manage cage domain filters.

| Command | Description |
|---------|-------------|
| `domain list NAME` | List domains and filtering mode for a cage |
| `domain add NAME DOMAIN` | Add a domain to the filter list (hot-reloads if running) |
| `domain rm NAME DOMAIN` | Remove a domain from the filter list (hot-reloads if running) |

Aliases: `ls` → `list`.

Mode is `allowlist` (only listed domains permitted, default) or `blocklist` (listed domains blocked). Subdomain matching is built in — adding `anthropic.com` also allows `api.anthropic.com`.

## watcher

Read the traffic watcher's findings and scan status. The watcher itself runs **inside the egress** — there is no host daemon and no `watcher start`; enable it with the `watcher:` block in `cage.yaml` (see [the traffic watcher](../explain/traffic-watcher.md)).

| Command | Description |
|---------|-------------|
| `watcher findings NAME [-s SEV] [--host H] [-n N] [--json]` | Show recorded findings (most recent last; filter by severity/domain) |
| `watcher status NAME` | Show the watcher's configuration and last scan counters |

Aliases: `ls` → `findings`.

Findings also appear in the audit stream: `cage audit --inspector watcher` (each finding is a `watcher_finding` entry with `decision: flagged`). Revocations appear as `watcher_revoke` entries.

For the full workflow — configuring the watcher, provisioning its key, and acting on a finding — see [Run the traffic watcher](../how-to/run-the-traffic-watcher.md).

## scaffold

Manage scaffold templates. Resolved in order: project-local (`.agentcage/scaffolds/`), user (`~/.config/agentcage/scaffolds/`), built-in.

| Command | Description |
|---------|-------------|
| `scaffold list` | List available scaffolds |
| `scaffold show NAME` | Show scaffold details and config template |
| `scaffold create NAME` | Create a new user scaffold |
| `scaffold edit NAME` | Edit a user scaffold |
| `scaffold delete NAME` | Delete a user scaffold |
| `scaffold export NAME` | Export a scaffold as a directory |

Aliases: `ls` → `list`, `rm` → `delete`.

## Related

- [Configuration](configuration.md) — `cage.yaml` settings reference
- [Domains](domains.md) — filtering rules and modes
- [Capture](capture.md) — HAR export and traffic recording
- [Architecture](../explain/architecture.md) — hot-reload model and startup order
- [Secret injection](secret-injection.md) — injection vs direct secrets
