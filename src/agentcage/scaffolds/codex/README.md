# Codex Setup Guide

[Codex](https://github.com/openai/codex) is OpenAI's CLI coding agent. This guide shows how to run it inside an agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by mitmproxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](../../docs/reference/configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) -- see [installation instructions](../../README.md#install) for your platform
- An OpenAI API key (`OPENAI_API_KEY`)

## Quick start

There are two ways to run Codex in a cage: a one-command ephemeral session with `agentcage run`, or a persistent cage managed with `agentcage cage` commands.

### Ephemeral session (`agentcage run`)

The fastest way to get started. Builds the image, creates a temporary cage, drops you into an interactive Codex session, and tears down the cage when you exit.

```bash
# API key auth
agentcage run codex -s OPENAI_API_KEY

# With a specific project directory
agentcage run codex -s OPENAI_API_KEY --project ~/myrepo
```

You'll be prompted to enter the API key value on first run. The cage is removed on exit; audit logs are preserved.

### Persistent interactive cage (`agentcage cage`)

Use this when you want the cage to survive across sessions -- for example, to run multiple `cage exec` sessions against the same cage or inspect traffic after the fact.

#### 1. Scaffold the config

```bash
agentcage init myagent --scaffold codex
```

This creates `cage.yaml` with sensible defaults and auto-builds the `agentcage-scaffold-codex:latest` image. Review the config and adjust as needed.

#### 2. Create the cage

```bash
agentcage cage create -c cage.yaml
```

This builds the proxy and DNS images, generates systemd quadlet files, and starts all three services (cage, proxy, dns).

#### 3. Set secrets

```bash
agentcage secret set myagent OPENAI_API_KEY
```

The scaffold uses `secret_injection` for the API key. Codex sends a generated placeholder token (e.g. `agentcage:secret:OPENAI_API_KEY:9f3c1a7e8b204d56c1e0a4f7b2d8369a`) in API calls, and the proxy swaps it for the real value when forwarding to `openai.com`. No real secret enters the cage.

#### 4. Start a session

```bash
agentcage cage exec myagent -- codex
```

The cage uses `lifecycle: interactive`, so the container stays up (via `sleep infinity`) but systemd will not auto-restart it if stopped. You can open multiple concurrent `cage exec` sessions against the same cage.

#### 5. Verify

```bash
# Check containers are running
agentcage cage list

# View logs
agentcage cage logs myagent           # cage container
agentcage cage logs myagent -s proxy  # mitmproxy (traffic inspection)
agentcage cage logs myagent -s dns    # DNS sidecar
```

### Running as a service

To run Codex as a long-running service cage (e.g. for a headless agent that processes tasks continuously), change the lifecycle and command in `cage.yaml`:

```yaml
lifecycle: service

container:
  command: ["codex", "--headless", "--prompt", "your task here"]
```

With `lifecycle: service`, systemd auto-restarts the container on failure and starts it on boot. Use `cage logs` to follow output instead of `cage exec`.

## Managing your cage

See [Troubleshoot](../../docs/how-to/troubleshoot.md) for diagnosing blocked requests, secret problems, and proxy restarts. See the [CLI reference](../../docs/reference/cli.md#cage) for the full `cage` subcommand set.

## Configuration

### Volumes

The scaffold mounts two paths from the host:

- `${PROJECT_DIR}:/workspace:rw` -- your project directory (set by `agentcage init`)
- `~/.codex:/home/node/.codex:rw` -- Codex settings and state

Remove the `~/.codex` mount to fully isolate the cage from host state. Git config and SSH known hosts mounts are commented out in `cage.yaml` -- uncomment them if you need git push.

### Sandbox brief (introspection)

The image bakes a short "you are running inside agentcage" brief into
`~/.codex/AGENTS.md`, so Codex reads it as global guidance automatically and
knows up front that egress is proxied, secrets are placeholders, and a failed
`fetch` usually means the host isn't allowlisted. The brief ships as
`AGENTS.md` next to the `Containerfile`; edit it (or remove the
`COPY AGENTS.md` line) and rebuild to change or drop it. It's a plain, writable
file Codex owns — not a read-only mount — so Codex's own config/auth writes
still work. The agentcage version is also available at `$AGENTCAGE_VERSION`.

### Secret injection

The scaffold pre-configures secret injection for the OpenAI API key. To enable GitHub push via HTTPS, uncomment the `GITHUB_TOKEN` block in `cage.yaml` and set the secret:

```bash
agentcage secret set myagent GITHUB_TOKEN
```

### Domain allowlist

The scaffold organizes domains into tiers:

**AI provider** (required):
- `openai.com`

**Package registries** (commented out):
- `npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org` — Codex's deps are installed at image-build time, so the running cage doesn't need them. Uncomment if your agent runs `npm install` / `pip install` in the workspace.

**Code hosting** (commented out):
- `github.com`, `githubusercontent.com`

Subdomains are matched automatically -- adding `openai.com` also allows `api.openai.com`. Sibling domains are not matched.

