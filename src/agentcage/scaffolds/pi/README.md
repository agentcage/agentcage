# Pi Setup Guide

[Pi](https://pi.dev/docs/latest) is a minimal terminal coding harness — an extensible CLI for AI-assisted coding that supports multiple model providers and is also embeddable as a Node.js SDK. This guide shows how to run it inside an agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by the agentcage egress proxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](../../../../docs/reference/configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless) and the `agentcage` binary -- see [installation instructions](../../../../docs/get-started/install.md) for your platform
- An Anthropic API key (`ANTHROPIC_API_KEY`), an OpenAI API key (`OPENAI_API_KEY`), or a subscription you can `/login` into from inside the cage

## Quick start

There are two ways to run Pi in a cage: a one-command ephemeral session with `agentcage run`, or a persistent cage managed with `agentcage cage` commands.

### Ephemeral session (`agentcage run`)

The fastest way to get started. Builds the image, creates a temporary cage, drops you into an interactive Pi session, and tears down the cage when you exit.

```bash
# API key auth (Anthropic)
agentcage run pi -s ANTHROPIC_API_KEY

# OpenAI instead — also uncomment the OPENAI_API_KEY block in cage.yaml
agentcage run pi -s OPENAI_API_KEY

# With a specific project directory
agentcage run pi -s ANTHROPIC_API_KEY --project ~/myrepo
```

You'll be prompted to enter the API key value on first run. The cage is removed on exit; audit logs are preserved.

### Persistent interactive cage (`agentcage cage`)

Use this when you want the cage to survive across sessions -- for example, to keep `/login` credentials, run multiple `cage exec` sessions against the same cage, or inspect traffic after the fact.

#### 1. Scaffold the config

```bash
agentcage init myagent --scaffold pi
```

This creates `cage.yaml` with sensible defaults and auto-builds the `agentcage-scaffold-pi:latest` image. Review the config and adjust as needed.

#### 2. Authenticate

**Subscription — log in inside the cage:**

```bash
agentcage cage create -c cage.yaml
agentcage cage exec myagent -- pi
# then type /login at the Pi prompt
```

Follow the URL to authenticate. Credentials are saved under the `~/.pi` volume mount, so they persist across sessions.

**API key (Anthropic):**

```bash
agentcage secret set myagent ANTHROPIC_API_KEY
agentcage cage create -c cage.yaml
```

The scaffold uses `secret_injection` for the API key. Pi sends a generated placeholder token (e.g. `agentcage:secret:ANTHROPIC_API_KEY:9f3c1a7e8b204d56c1e0a4f7b2d8369a`) in API calls, and the proxy swaps it for the real value when forwarding to `anthropic.com`. No real secret enters the cage.

**API key (OpenAI):**

```bash
agentcage secret set myagent OPENAI_API_KEY
# uncomment the OPENAI_API_KEY block under secret_injection in cage.yaml
# uncomment the openai.com line under domains.allow
agentcage cage create -c cage.yaml
```

#### 3. Start a session

```bash
agentcage cage exec myagent -- pi
```

The cage uses `lifecycle: interactive`, so the container stays up (via `sleep infinity`) but systemd will not auto-restart it if stopped. You can open multiple concurrent `cage exec` sessions against the same cage.

#### 4. Verify

```bash
# Check containers are running
agentcage cage list

# View logs
agentcage cage logs myagent           # cage container
agentcage cage logs myagent -s egress  # egress proxy and DNS (traffic inspection)
agentcage cage logs myagent -s dns    # DNS sidecar
```

### Running as a service

To run Pi as a long-running service cage (e.g. for a headless agent embedded via Pi's SDK), change the lifecycle and command in `cage.yaml`:

```yaml
lifecycle: service

container:
  command: ["node", "/workspace/your-pi-sdk-entry.js"]
```

With `lifecycle: service`, systemd auto-restarts the container on failure and starts it on boot. Use `cage logs` to follow output instead of `cage exec`.

See [Pi SDK docs](https://pi.dev/docs/latest/sdk) for embedding the agent in a Node.js entrypoint. The scaffold image does not ship Node.js (see [Image](#image)), so an SDK entrypoint needs a Containerfile that adds Node.js 22.19 or newer and installs `@earendil-works/pi-coding-agent` from npm.

## Managing your cage

See [Troubleshooting](../../../../docs/how-to/troubleshooting.md) for diagnosing blocked requests, secret problems, and proxy restarts. See the [CLI reference](../../../../docs/reference/cli.md) for the full `cage` subcommand set.

## Configuration

### Image

The `Containerfile` builds on `debian:stable-slim`, the same base as the `debian` scaffold, and adds git, curl, an SSH client, `build-essential`, Python 3, ripgrep and fd. Pi itself comes from upstream's latest standalone Linux release (a single executable with the Bun runtime bundled), checked against the release's `SHA256SUMS` and installed under `/opt/pi`. To build a specific release, set the `PI_VERSION` build arg (e.g. `1.2.0`). `pi update` does not apply inside the image; rebuild it without the layer cache to pick up a new release.

The image has no Node.js or npm. Debian stable's `nodejs` is older than the 22.19 Pi requires, and the standalone build doesn't need it. If your agent runs `npm install` in the workspace, or you install Pi packages from npm (`pi install npm:...`), add Node.js to the `Containerfile`. The agent runs as `agent` (uid/gid 1000, home `/home/agent`). Images built before this release ran as `node` with home `/home/node`; the uid is unchanged, but mount targets move to `/home/agent/...`.

### Volumes

The scaffold mounts two paths from the host:

- `${PROJECT_DIR}:/workspace:rw` -- your project directory (set by `agentcage init`)
- `~/.pi:/home/agent/.pi:rw` -- Pi global config, auth, and session state

Remove the `~/.pi` mount to fully isolate the cage from host state. Git config and SSH known hosts mounts are commented out in `cage.yaml` -- uncomment them if you need git push.

### Sandbox brief (introspection)

The image bakes a short "you are running inside agentcage" brief into
`~/.pi/agent/AGENTS.md`, so Pi loads it as a global context file automatically
and knows up front that egress is proxied, secrets are placeholders, and a
failed `fetch` usually means the host isn't allowlisted. agentcage stages one
canonical `AGENTS.md` brief into the build context (it is not committed
per-scaffold); remove the `COPY AGENTS.md` line from the `Containerfile` to drop
it, or edit `src/agentcage/scaffolds/AGENTS.md` upstream to change it for every
scaffold at once. It's a plain, writable file Pi owns — not a read-only mount —
so Pi's own state/session writes still work. The agentcage version is also
available at `$AGENTCAGE_VERSION`.

### Policy API skill

The image also installs agentcage's standard `agentcage` skill into `~/.agents/skills/agentcage/` (a cross-agent skills location Pi discovers, and one a `~/.pi` bind mount cannot shadow).
It is an [Agent Skills](https://agentskills.io) package the agent loads on
demand when a request fails with a `403`: how to check `/v1/health`, reflect on
the effective allowlist with `GET https://agentcage.local/v1/allowlist`, request
a new egress domain with a justification the decider will accept
(`POST /v1/allowlist/requests`), and give a grant back
(`POST /v1/allowlist/removals`). The endpoints only answer when the cage enables
`agents.decider` (see [Policy API Reference](../../../../docs/reference/policy-api.md)); without it the skill tells
the agent to ask the operator. Like the brief, agentcage stages the one canonical
copy (`src/agentcage/scaffolds/skills/agentcage/`) into the build context for the
`COPY skills/agentcage` line; drop that line to leave it out.

### Secret injection

The scaffold pre-configures secret injection for the Anthropic API key. Two more rules ship commented out in `cage.yaml`:

- `OPENAI_API_KEY` — for Pi sessions targeting OpenAI models.
- `GITHUB_TOKEN` — GitHub push over HTTPS.

Uncomment the block you need and set the secret:

```bash
agentcage secret set myagent GITHUB_TOKEN
```

Injected secrets are swapped by the proxy on the wire — the real value never enters the cage, the cage env only ever holds the `{{PLACEHOLDER}}`.

### Domain allowlist

The scaffold organizes domains into tiers:

**AI provider** (Anthropic by default):
- `anthropic.com`, `claude.com`

**Pi update + auth**:
- `pi.dev`

**Package registries** (commented out):
- `npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org` — Pi is installed at image-build time, so the running cage doesn't need them. Uncomment if your agent runs `npm install` / `pip install` in the workspace (the image has no npm; see [Image](#image)).

**Code hosting** (commented out):
- `github.com`, `githubusercontent.com`

**Other providers** (commented out):
- `openai.com` — uncomment alongside the matching `secret_injection` rule

Subdomains are matched automatically -- adding `anthropic.com` also allows `api.anthropic.com`. Sibling domains are not matched.

## Troubleshooting

**`/login` fails inside the cage**: make sure `pi.dev` is in the domain allowlist (it is by default in this scaffold) — Pi resolves OAuth flows through `pi.dev`.

**Pi can reach the model provider but not its own update server**: `pi.dev` covers the update + auth endpoints. To suppress update checks entirely, set `PI_SKIP_VERSION_CHECK=1` in the cage env.
