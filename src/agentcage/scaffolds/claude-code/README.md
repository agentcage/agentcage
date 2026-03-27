# Claude Code Setup Guide

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) is Anthropic's official CLI for Claude -- an interactive coding agent that lives in your terminal. This guide shows how to run it inside an agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by mitmproxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](../../docs/configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) -- see [installation instructions](../../README.md#install) for your platform
- An Anthropic API key (`ANTHROPIC_API_KEY`) or a Claude subscription (Pro/Team/Enterprise)

## Quick start

There are two ways to run Claude Code in a cage: a one-command ephemeral session with `agentcage run`, or a persistent cage managed with `agentcage cage` commands.

### Ephemeral session (`agentcage run`)

The fastest way to get started. Builds the image, creates a temporary cage, drops you into an interactive Claude Code session, and tears down the cage when you exit.

```bash
# API key auth
agentcage run claude-code -s ANTHROPIC_API_KEY

# With a specific project directory
agentcage run claude-code -s ANTHROPIC_API_KEY --project ~/myrepo
```

You'll be prompted to enter the API key value on first run. The cage is removed on exit; audit logs are preserved.

### Persistent interactive cage (`agentcage cage`)

Use this when you want the cage to survive across sessions -- for example, to keep auth tokens, run multiple `cage exec` sessions against the same cage, or inspect traffic after the fact.

#### 1. Scaffold the config

```bash
agentcage init myagent --scaffold claude-code
```

This creates `cage.yaml` with sensible defaults and auto-builds the `agentcage-scaffold-claude-code:latest` image. Review the config and adjust as needed.

#### 2. Authenticate

**Subscription (Claude Pro/Team/Enterprise):**

```bash
agentcage cage create -c cage.yaml
agentcage cage exec myagent -- claude login
```

Follow the URL to authenticate. The token is saved in the `~/.claude` volume mount, so it persists across sessions.

**API key:**

```bash
agentcage secret set myagent ANTHROPIC_API_KEY
agentcage cage create -c cage.yaml
```

The scaffold uses `secret_injection` for the API key. Claude Code sends the placeholder `{{ANTHROPIC_API_KEY}}` in API calls, and the proxy swaps it for the real value when forwarding to `anthropic.com`. No real secret enters the cage.

#### 3. Start a session

```bash
agentcage cage exec myagent -- claude
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

To run Claude Code as a long-running service cage (e.g. for a headless agent that processes tasks continuously), change the lifecycle and command in `cage.yaml`:

```yaml
lifecycle: service

container:
  command: ["claude", "--headless", "--prompt", "your task here"]
```

With `lifecycle: service`, systemd auto-restarts the container on failure and starts it on boot. Use `cage logs` to follow output instead of `cage exec`.

## Managing your cage

```bash
# Edit the config in $EDITOR, validate, and reload if running
agentcage cage edit myagent

# Rebuild and restart (after config or image changes)
agentcage cage update myagent

# Restart without rebuilding
agentcage cage reload myagent

# View proxy audit logs
agentcage cage audit myagent

# Destroy the cage (stops containers, removes quadlets and state)
agentcage cage destroy myagent
```

## Configuration

### Volumes

The scaffold mounts three paths from the host:

- `${PROJECT_DIR}:/workspace:rw` -- your project directory (set by `agentcage init`)
- `~/.claude:/home/node/.claude:rw` -- Claude auth tokens and settings
- `~/.claude.json:/home/node/.claude.json:rw` -- Claude global config

Remove the `~/.claude` mounts to fully isolate the cage from host state. Git config and SSH known hosts mounts are commented out in `cage.yaml` -- uncomment them if you need git push.

### Secret injection

The scaffold pre-configures secret injection for the Anthropic API key. To enable GitHub push via HTTPS, uncomment the `GITHUB_TOKEN` block in `cage.yaml` and set the secret:

```bash
agentcage secret set myagent GITHUB_TOKEN
```

### Domain allowlist

The scaffold organizes domains into tiers:

**AI provider** (required):
- `anthropic.com`, `claude.com`

**Telemetry** (Claude Code hangs on startup if these are blocked):
- `datadoghq.com`, `githubusercontent.com`, `sentry.io`

**Package registries**:
- `npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org`

**Code hosting** (commented out):
- `github.com`, `githubusercontent.com`

Subdomains are matched automatically -- adding `anthropic.com` also allows `api.anthropic.com`. Sibling domains are not matched.

## Troubleshooting

**Claude Code hangs on startup**: The telemetry domains (`datadoghq.com`, `sentry.io`) must be in the allowlist. Claude Code blocks on telemetry init if these are unreachable.

**403 errors from the proxy**: A domain is not in your allowlist, or a secret pattern was detected in the request. Check proxy logs with `agentcage cage logs myagent -s proxy` -- the JSON log entries include a `reason` field explaining the block.

**Certificate errors**: The mitmproxy CA certificate is shared via a named volume. If the proxy container hasn't finished generating it before the cage starts, you may see TLS errors. Restart the cage: `agentcage cage reload myagent`.

**DNS resolution failures**: Verify the DNS sidecar is running: `agentcage cage list`. If you are using custom `dns_servers`, make sure those servers are reachable from the host.

**File permission errors in /workspace**: The scaffold uses `userns: "keep-id"` to map your host UID into the container. If you still see permission issues, check that the mounted directories are owned by your user on the host.
