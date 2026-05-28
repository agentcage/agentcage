# Pi Setup Guide

[Pi](https://pi.dev/docs/latest) is a minimal terminal coding harness — an extensible CLI for AI-assisted coding that supports multiple model providers and is also embeddable as a Node.js SDK. This guide shows how to run it inside an agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by mitmproxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](../../docs/reference/configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) -- see [installation instructions](../../README.md#install) for your platform
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

The scaffold uses `secret_injection` for the API key. Pi sends the placeholder `{{ANTHROPIC_API_KEY}}` in API calls, and the proxy swaps it for the real value when forwarding to `anthropic.com`. No real secret enters the cage.

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
agentcage cage logs myagent -s proxy  # mitmproxy (traffic inspection)
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

See [Pi SDK docs](https://pi.dev/docs/latest/sdk) for embedding the agent in a Node.js entrypoint.

## Managing your cage

See [Managing Your Cage](../../docs/cage-management.md) for common operations (edit, update, restart, audit, destroy) and troubleshooting.

## Configuration

### Volumes

The scaffold mounts two paths from the host:

- `${PROJECT_DIR}:/workspace:rw` -- your project directory (set by `agentcage init`)
- `~/.pi:/home/node/.pi:rw` -- Pi global config, auth, and session state

Remove the `~/.pi` mount to fully isolate the cage from host state. Git config and SSH known hosts mounts are commented out in `cage.yaml` -- uncomment them if you need git push.

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
- `npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org` — pi's deps are installed at image-build time, so the running cage doesn't need them. Uncomment if your agent runs `npm install` / `pip install` in the workspace.

**Code hosting** (commented out):
- `github.com`, `githubusercontent.com`

**Other providers** (commented out):
- `openai.com` — uncomment alongside the matching `secret_injection` rule

Subdomains are matched automatically -- adding `anthropic.com` also allows `api.anthropic.com`. Sibling domains are not matched.

## Troubleshooting

**`/login` fails inside the cage**: make sure `pi.dev` is in the domain allowlist (it is by default in this scaffold) — Pi resolves OAuth flows through `pi.dev`.

**Pi can reach the model provider but not its own update server**: `pi.dev` covers the update + auth endpoints. To suppress update checks entirely, set `PI_SKIP_VERSION_CHECK=1` in the cage env.
