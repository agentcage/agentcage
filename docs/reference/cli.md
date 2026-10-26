# CLI Reference Manual

The `agentcage` command-line interface manages sandboxes, secret storage, domain allowlists, traffic auditing, and runtime grants.

---

## Global Options & Aliases

```text
agentcage [OPTIONS] COMMAND [ARGS]...

Options:
  --version   Show the version and exit.
  -h, --help  Show this message and exit.
  --no-color  Disable colored output.
  --quiet     Suppress progress output (spinners and banners).
```

### Automation-friendly globals

Both new global options are accepted before or after the subcommand
(`agentcage --quiet cage create` and `agentcage cage create --quiet` are
the same invocation).

- **`-h, --help`** — `-h` is an alias for `--help`, everywhere. `--help`
  remains the long form (the full command docstring); both spellings
  print it.
- **`--no-color`** — strip ANSI escapes from stdout and stderr even when
  they are terminals. `NO_COLOR` (any value, including an empty one) is
  honoured the same way. Without either, colour still follows the
  per-stream terminal check, so existing behaviour is unchanged. The
  per-command `cage audit --no-color` keeps working; it is now the same
  global flag.
- **`--quiet`** — silence progress output: the pre-deploy banner and the
  braille spinner. A `CI` environment (any non-empty value) does the
  same. `--quiet` never suppresses a command's own output, a table, a
  warning or an error, and progress is never written when the stream is
  not a terminal.

### JSON output

The read-only commands that do not depend on a cage's live backend write
one JSON document to stdout with `--json`. The envelope is stable:

```json
{
  "schema_version": 1,
  "command": "domain list",
  "ok": true,
  "data": {},
  "warnings": []
}
```

The keys and their order are the contract. `command` is the canonical
spelling (`domain list`, never `ls`), so either spelling of a command
produces the same document. `schema_version` is bumped only for a
breaking change to the envelope; new keys inside `data` are not a break.
Secret *values* are never emitted — `secret list` carries names, types,
`present` and the decoy placeholder label only. A failing command keeps
its existing stderr message and non-zero exit code. `ok` is `false` only
when a command still prints a document while reporting failure — today
that is `secret list --json` when a declared secret is missing, which
also exits 1; every other document has `ok: true`.

See [`agentcage paths`](#agentcage-paths---json) and
[`agentcage version`](#agentcage-version---json) for the
backend-independent ones, and the `domain list` / `secret list` entries
below.

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
- `--pull`: Always pull the base image (`--pull=always`). Without it, a build on the container and vm backends still pulls a base image the registry has a newer version of (`--pull=newer`), and uses the local one when the registry cannot be reached.
- `--time`: Print per-phase timing summaries.

---

### `agentcage cage update [NAME]`
Rebuilds and restarts an existing persistent cage to pick up configuration or image changes:

```bash
agentcage cage update my-agent --no-cache --pull
```

When the cage's inputs (its `cage.yaml`, units, Containerfile and build context, plugins and image identities) are unchanged and it is running, `cage update` asks the registry whether a base image has moved, without pulling anything (`podman manifest inspect`):

- the `FROM` images of the egress image (`docker.io/library/alpine:3`) and of the cage's Containerfile, after `ARG` substitution, skipping `localhost/` images, digest-pinned references, `scratch` and earlier build stages;
- or the cage's image itself, when the cage runs a registry image rather than building one.

A base has moved when the registry's manifest for the local platform has a different digest from the local image's. Only the image whose base moved is rebuilt (or re-pulled), and the build pulls the new base (`--pull=newer`). The cage then restarts only if a rebuilt image differs from the one the running container was started from; a rebuild that ends up identical leaves the cage running and prints `Image unchanged; not restarting`. If the registry cannot be reached (offline, an error, a rate limit), `cage update` prints one warning, treats the bases as unchanged and carries on. `--pull` and `--no-cache` skip the check and rebuild, and also restart only if an image changed. So does an update where the only thing that changed since the last one is an image identity, for example because another cage's update rebuilt the shared egress image or a base image was pulled: both images are rebuilt (mostly from cache) and the cage restarts only if one of them differs from what it runs. Any other changed input, or `--force`, rebuilds and restarts as before.

This means a plain `cage update` contacts the registry, and can restart a running cage whose inputs did not change when a base image has a newer version. Use `--no-pull` to avoid both.

On the **vm** backend the check runs inside the guest, and a rebuild builds the egress and cage images there together; the guest is restarted only if an image changed. On the **apple-container** backend there is no check: the `container` CLI cannot read a remote digest without pulling, so `cage update` pulls the cage image's upstream references as before (unless `--no-pull`), and the shared egress image is rebuilt only with `--pull` or `--no-cache`.

**Options**:
- `-c, --config PATH`: Path to updated `cage.yaml` (optional if `NAME` is provided).
- `--no-cache`: Ignore image layer cache.
- `--pull`: Re-pull base images (`--pull=always`) and rebuild even if nothing changed. A rebuild without it still pulls a newer base image when the registry has one (`--pull=newer`).
- `--no-pull`: Do not ask the registry whether a base image moved. Only changed inputs, `--force` or `--no-cache` rebuild. For offline use, or to keep the images fixed. Cannot be combined with `--pull`.
- `--force`: Rebuild and restart even if input files are unchanged.

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
Stops running containers, removes systemd quadlets, removes the deployment's state files, and purges scoped secrets:

```bash
agentcage rm my-agent -y
```

**Options**:
- `-y, --yes`: Skip confirmation prompt.
- `--keep-secrets`: Retain encrypted secrets on the host (useful when recreating the cage). The per-cage data directory below is kept either way.

**Retention**: `cage destroy` leaves the cage's data directory in place and prints a `Kept:` block naming it (the `data:` line) and what is still in it. It is `$XDG_DATA_HOME/agentcage/<name>/` when `XDG_DATA_HOME` is set, `~/.local/share/agentcage/<name>/` otherwise; use the path the block printed rather than rebuilding it. It normally holds `grants/`, `capture/`, `policy-audit.jsonl` and `timings/`, and it survives so that the policy audit log outlives the command that removed the cage. Two exceptions: `inspectors/` is staged deployment content and is removed with the deployment, and on `apple-container` the capture log lives under `~/.config/agentcage/apple-container/<name>/logs/` and is removed with that state tree, so `capture/` is not reported as kept. To remove the directory by hand once the cage is gone, use the path from the `Kept:` block:

```bash
rm -rf '<the path on the data: line>'
```

---

### `agentcage cage prune`
Removes all exited, stopped ephemeral or interactive cages:

```bash
agentcage cage prune -y
```

It takes `destroy`'s teardown and keeps the same thing: each removed cage's data directory, named by the `Kept:` block it prints (see **Retention** above).

---

### `agentcage cage edit NAME` (Alias: `config`)
Opens the cage's stored `cage.yaml` in `$EDITOR` with automatic validation and atomic saving:
- Validates YAML schema before saving (rejected edits are saved to `cage.yaml.rejected`).
- Backs up previous working configuration to `cage.yaml.bak`.
- Keeps the file's comments, quoting and layout: the operator's `cage.yaml` is written back byte-for-byte when the only change is theirs, and it is re-rendered only when `cage edit` itself adds a generated `secret_injection` placeholder.
- Auto-applies domain changes to `dnsmasq` via `SIGHUP` without restarting the cage.
- Ends by naming the command that applies each change it could not apply live:
  - **Live-applied**: proxy policy (`domains`, `inspectors`, `logging`, `capture`, `secret_injection`, `protocol_relays`, `agents`, …), which the egress reloads from `proxy-config.yaml` within about a second, and keys read on use (`exec_aliases`, `help`, `scaffold`).
  - **Needs restart** (`agentcage cage restart NAME`): `egress`, whose address-space limit is set when the egress starts.
  - **Needs update** (`agentcage cage update NAME`): everything rendered into the units: `container` (image, volumes, env, user, resources, …), `lifecycle`, `ports`, `dns_servers`, `secrets`, `apple_container_autostart`, and any other key. `cage restart` starts the units already installed and does not apply these; `cage update` re-renders them and notices the edit without `--force`.
  - **Needs rebuild**: `isolation` and `vm`.

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
- `--passthrough`: Add to the TLS passthrough list (the egress splices the connection without terminating TLS, so it is not inspected).
- `--expires-in TEXT`: Set a TTL (e.g. `"30m"`, `"2h"`, `"1d"`). Once expired, traffic is blocked.

---

### `agentcage domain list NAME` (Alias: `ls`)
Lists all configured allowlisted, blocked, and passthrough domains:

```bash
agentcage domain list my-agent
agentcage domain ls my-agent --json
```

**Options**:
- `--json`: Emit the JSON envelope instead of the text list. `data` holds
  `cage`, `mode` (`allowlist` or `blocklist`), `domains` (sorted, each
  `{domain, passthrough?, expires_at?}`), `passthrough` (every
  passthrough entry) and `passthrough_only` (entries in no other list).

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
agentcage secret ls my-agent --json
```

**Options**:
- `--json`: Emit the JSON envelope. `data` holds `cage` and `secrets`, an
  array of `{name, type, present, placeholder?}`. Values are never read or
  emitted; `placeholder` is the decoy token the cage injects instead of the
  secret. The exit code is unchanged: a declared-but-absent secret still
  exits 1, with `present: false` in the document.

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

Every record the egress audits is listed, not only HTTP and DNS decisions: protocol-relay commands and failures (`imap_command`, `smtp_data`, `relay_start_failed`, ...), Policy API requests (`policy_*`), watcher findings and revocations (`watcher_*`), blocked TCP bypasses and private-address peers, upstream failures (`upstream_error`, `decision: error`), flows the egress refused after an internal error (`internal_error`), and config edits it refused to apply (`config_reload_failed`). In the table, a record without an HTTP method shows its kind's family (`IMAP`, `SMTP`, `POLICY`, ...) in the METHOD column, the relay name in HOST when it has no host, the relay command in PATH, and its full `kind` at the start of REASON. `--summary` counts `policy_*` and `watcher_*` records separately from traffic and lists every kind it saw.

**Options**:
- `-d, --decision [blocked|flagged|allowed]`: Filter by proxy decision (repeatable). Records with no decision (for example a Policy API introspection read) never match.
- `--host TEXT`: Filter by target host substring. A Policy API record matches on its domain, a relay record on the relay's name.
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
  - `inbound` (default): The request as the cage sent it and the response as the cage received it.
  - `outbound`: The request and response as recorded on the wire side, after the egress redacted them.

  Both views hold every secret agentcage manages as its rule's placeholder: real values, tokens a secret `transform` minted, a server's echo of either, and a literal secret the cage sent itself (including in a blocked request). The injected credentials never appear in either view, so the two views now record the same content. Anything else is recorded as is in both: bodies, cookies, and any credential the agent holds itself, so review a capture before sharing it. Captures recorded by agentcage 0.50.0 or earlier can still hold real secrets: in the `outbound` view (a server's echo of an injected secret, a token a transform minted) and in the `inbound` view of a request blocked for carrying a literal secret.
- `-d, --decision [blocked|flagged|allowed]`: Filter by decision.
- `-o, --output PATH`: Target file (default: stdout).
- `--json-lines`: Output raw JSONL capture format instead of HAR.

---

### `agentcage watcher status | findings NAME`
- **`watcher status <name>`**: Displays background traffic watcher scan intervals, backlog, and health.
- **`watcher findings <name>`**: Lists anomalies flagged by the Watcher (options: `-s, --severity`, `--json`).

---

## 7. Diagnostics & Backup

### `agentcage paths [--json]`
Prints the directories this install resolves, for backup scripts, sandboxes and support bundles:

```bash
agentcage paths
agentcage paths --json
```

The rows are `home`, `config` (`$XDG_CONFIG_HOME/agentcage`), `data`
(`$XDG_DATA_HOME/agentcage`), `cache` (`<data>/assets`, the
extracted build contexts, where `<data>` is the `data` row above),
`runtime` (`$XDG_RUNTIME_DIR`), `apple-container`
(`~/.config/agentcage/apple-container`), `quadlets`
(`~/.config/containers/systemd`) and `user-units` (`~/.config/systemd/user`).
JSON `data` uses the same names with `apple_container` and `user_units`
as the machine keys. There is no separate XDG state root: per-cage state
lives under `config` and `data`. Nothing is created.

---

### `agentcage version [--json]`
Prints `agentcage, version <version>` (the same string as `agentcage --version`), or the JSON envelope with `data: {name, version}`:

```bash
agentcage version
agentcage version --json
```

---

### `agentcage completions <SHELL>` / `agentcage completions print --shell <SHELL>`
Writes a completion script for `bash`, `zsh` or `fish` to stdout:

```bash
agentcage completions bash > ~/.local/share/bash-completion/completions/agentcage
agentcage completions print --shell zsh
```

There is deliberately no `completions install`: installing would mean
guessing which of `.bashrc`, `.bash_profile`, `.zshrc` or
`~/.config/fish/config.fish` owns the user's shell, and agentcage does not
write to dotfiles. Where the script lands, and whether it is `eval`ed or
sourced, is the user's call.

---

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
