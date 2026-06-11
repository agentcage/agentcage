# Claude Code Setup Guide

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) is Anthropic's official CLI for Claude -- an interactive coding agent that lives in your terminal. This guide shows how to run it inside an agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by mitmproxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](../../docs/reference/configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) -- see [installation instructions](../../README.md#install) for your platform
- An Anthropic API key (`ANTHROPIC_API_KEY`) or a Claude subscription (Pro/Team/Enterprise)

## Quick start

There are two ways to run Claude Code in a cage: a one-command ephemeral session with `agentcage run`, or a persistent cage managed with `agentcage cage` commands.

### Ephemeral session (`agentcage run`)

The fastest way to get started. Builds the image, creates a temporary cage, drops you into an interactive Claude Code session, and tears down the cage when you exit.

```bash
# Subscription — mint a token once on the host, then just run
claude setup-token
export CLAUDE_CODE_OAUTH_TOKEN=<token>
agentcage run claude-code

# API key
agentcage run claude-code -s ANTHROPIC_API_KEY

# With a specific project directory
agentcage run claude-code --project ~/myrepo
```

`agentcage run claude-code` checks for authentication before building the cage. If `CLAUDE_CODE_OAUTH_TOKEN` is set in your environment it is wired in automatically (no `-s` flag needed). If no auth is found at all — no token, no `-s` secret, and no `~/.claude/.credentials.json` from a previous in-cage `claude login` — it exits with setup instructions instead of dropping you into an unauthenticated session.

The cage is removed on exit; audit logs are preserved.

### Persistent interactive cage (`agentcage cage`)

Use this when you want the cage to survive across sessions -- for example, to keep auth tokens, run multiple `cage exec` sessions against the same cage, or inspect traffic after the fact.

#### 1. Scaffold the config

```bash
agentcage init myagent --scaffold claude-code
```

This creates `cage.yaml` with sensible defaults and auto-builds the `agentcage-scaffold-claude-code:latest` image. Review the config and adjust as needed.

#### 2. Authenticate

**Subscription — log in inside the cage:**

```bash
agentcage cage create -c cage.yaml
agentcage cage exec myagent -- claude login
```

Follow the URL to authenticate. The token is saved in the `~/.claude` volume mount, so it persists across sessions.

**Subscription — reuse your host login (no in-cage login):**

On macOS, `claude login` stores its credentials in the system Keychain, which a Linux cage cannot read. Instead, mint a long-lived OAuth token on the host and inject it:

```bash
claude setup-token                                  # on the host — mints a token
agentcage secret set myagent CLAUDE_CODE_OAUTH_TOKEN # paste the token
```

Then uncomment the `CLAUDE_CODE_OAUTH_TOKEN` block under `secret_injection` in `cage.yaml`, and remove the `ANTHROPIC_API_KEY` rule (Claude Code prefers the API key when both are set). Claude Code sends the generated placeholder token (run `agentcage secret list <cage>` to see it) as a bearer token, and the proxy swaps it for the real value en route to `anthropic.com` — the real token never enters the cage.

This is the best option for persistent and headless cages: the token is long-lived, so there is no per-session refresh that could collide with your host login.

**API key:**

```bash
agentcage secret set myagent ANTHROPIC_API_KEY
agentcage cage create -c cage.yaml
```

The scaffold uses `secret_injection` for the API key. Claude Code sends a generated placeholder token (e.g. `{{placeholder_anthropic_api_key_9f3a1c0b7d2e4a85}}`) in API calls, and the proxy swaps it for the real value when forwarding to `anthropic.com`. No real secret enters the cage.

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

See [Troubleshoot](../../docs/how-to/troubleshoot.md) for diagnosing blocked requests, secret problems, and proxy restarts. See the [CLI reference](../../docs/reference/cli.md#cage) for the full `cage` subcommand set.

## Configuration

### Volumes

The scaffold mounts two paths from the host:

- `${PROJECT_DIR}:/workspace:rw` -- your project directory (set by `agentcage init`)
- `~/.claude:/home/node/.claude:rw` -- Claude auth tokens and settings (credentials at `~/.claude/.credentials.json` live here)

`~/.claude.json` (Claude Code's global UX config — model choice, theme, etc.) is **not** mounted by default; uncomment the line in `cage.yaml` if you want host preferences to follow you into the cage. Git config and SSH known hosts mounts are commented out -- uncomment them if you need git push. Remove the `~/.claude` mount to fully isolate the cage from host state.

### Secret injection

The scaffold pre-configures secret injection for the Anthropic API key. Two more
rules ship commented out in `cage.yaml`:

- `CLAUDE_CODE_OAUTH_TOKEN` — subscription auth without an in-cage `claude login`
  (see [Authenticate](#2-authenticate) above).
- `GITHUB_TOKEN` — GitHub push over HTTPS.

Uncomment the block you need and set the secret:

```bash
agentcage secret set myagent GITHUB_TOKEN
```

Injected secrets are swapped by the proxy on the wire — the real value never
enters the cage, the cage env only ever holds the `{{PLACEHOLDER}}`.

### Domain allowlist

The scaffold organizes domains into tiers:

**AI provider** (required):
- `anthropic.com`, `claude.com`

**Telemetry** (commented out):
- `datadoghq.com`, `githubusercontent.com`, `sentry.io` — Claude Code may hang at the splash screen if telemetry is enabled AND these are blocked. Preferred fix: set `"telemetry": "disabled"` in `~/.claude/settings.json`. Fallback: uncomment these in `cage.yaml`.

**Package registries** (commented out):
- `npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org` — Claude Code's deps are installed at image-build time, so the running cage doesn't need them. Uncomment if your agent runs `npm install` / `pip install` in the workspace.

**Code hosting** (commented out):
- `github.com`, `githubusercontent.com`

Subdomains are matched automatically -- adding `anthropic.com` also allows `api.anthropic.com`. Sibling domains are not matched.

## Troubleshooting

**Claude Code hangs on startup**: telemetry is enabled and the telemetry domains are blocked. Either set `"telemetry": "disabled"` in `~/.claude/settings.json` (recommended for sandbox use) or uncomment the `datadoghq.com` / `githubusercontent.com` / `sentry.io` lines under `domains.allow` in `cage.yaml`.

