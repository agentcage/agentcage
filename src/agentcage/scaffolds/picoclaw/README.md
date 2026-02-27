# PicoClaw Setup Guide

[PicoClaw](https://github.com/sipeed/picoclaw) is an ultra-lightweight AI agent gateway (~10 MB image, ~10-20 MB RAM). This guide shows how to run it inside an agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by mitmproxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](../../docs/configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) -- see [installation instructions](../../README.md#install) for your platform
- An Anthropic API key (`ANTHROPIC_API_KEY`)

## Quick start

### 1. Scaffold the config

```bash
agentcage init myapp --scaffold picoclaw
```

This creates `cage.yaml` with sensible defaults and provisions `~/.picoclaw/config.json` with the Anthropic API key placeholder. The scaffold also auto-builds the `picoclaw:latest` image from source. Review the config and adjust as needed.

### 2. Set secrets

```bash
agentcage secret set myapp ANTHROPIC_API_KEY
```

The config uses `secret_injection` for the API key. The `config.json` contains the placeholder `{{ANTHROPIC_API_KEY}}`. PicoClaw sends this placeholder in API calls, and the proxy swaps it for the real value when forwarding to `anthropic.com`. No real secret enters the cage.

### 3. Create the cage

```bash
agentcage cage create -c cage.yaml
```

This builds the proxy and DNS images, generates systemd quadlet files, and starts all three services (cage, proxy, dns).

### 4. Verify

```bash
# Check containers are running
agentcage cage list

# View logs
agentcage cage logs myapp           # cage container
agentcage cage logs myapp -s proxy  # mitmproxy (traffic inspection)
agentcage cage logs myapp -s dns    # DNS sidecar
```

### 5. Connect

Open `http://localhost:18790` in your browser to access the PicoClaw web UI.

## Managing your cage

```bash
# Edit the config in $EDITOR, validate, and reload if running
agentcage cage edit myapp

# Rebuild and restart (after config or image changes)
agentcage cage update myapp

# Restart without rebuilding
agentcage cage reload myapp

# View proxy audit logs
agentcage cage audit myapp

# Destroy the cage (stops containers, removes quadlets and state)
agentcage cage destroy myapp
```

## Configuration

### Secret injection

The scaffold pre-configures secret injection for the Anthropic API key. To add more providers, uncomment the entries in `cage.yaml` and set the corresponding secrets:

```bash
agentcage secret set myapp OPENAI_API_KEY
agentcage secret set myapp OPENROUTER_API_KEY
```

Then add the placeholder to `~/.picoclaw/config.json` in the `model_list` entries.

### Domain allowlist

The scaffold organizes domains into tiers:

**AI providers** (Anthropic and OpenAI enabled by default):
- `anthropic.com`, `openai.com`
- `openrouter.ai`, `generativelanguage.googleapis.com`, `api.deepseek.com`, etc. (commented out)

**Web search** (commented out):
- `search.brave.com`, `duckduckgo.com`, `api.perplexity.ai`

**Skills registry** (commented out):
- `clawhub.ai`

**Messaging channels** (commented out):
- `api.telegram.org`, `discord.com`, `gateway.discord.gg`

Subdomains are matched automatically -- adding `anthropic.com` also allows `api.anthropic.com`. Sibling domains are not matched.

### Published ports

The scaffold exposes the gateway on `127.0.0.1:18790`. Webhook ports for LINE, WeCom, and other integrations are commented out in `cage.yaml` -- uncomment as needed.

## Custom config.json

The provisioned `~/.picoclaw/config.json` is a starting point. Edit it to add models, change defaults, or configure PicoClaw-specific settings:

```bash
$EDITOR ~/.picoclaw/config.json
agentcage cage reload myapp    # pick up changes (bind-mounted read-only)
```

## Troubleshooting

**403 errors from the proxy**: A domain is not in your allowlist, or a secret pattern was detected in the request. Check proxy logs with `agentcage cage logs myapp -s proxy` -- the JSON log entries include a `reason` field explaining the block.

**Certificate errors**: The mitmproxy CA certificate is shared via a named volume. If the proxy container hasn't finished generating it before the cage starts, you may see TLS errors. Restart the cage: `agentcage cage reload myapp`.

**DNS resolution failures**: Verify the DNS sidecar is running: `agentcage cage list`. If you are using custom `dns_servers`, make sure those servers are reachable from the host.

**PicoClaw web tools return errors**: PicoClaw's web tools (`web_fetch`, `web_search`) use `PICOCLAW_TOOLS_WEB_PROXY` to route through the proxy. This is pre-configured in the scaffold. If web tools fail, check that the target domains are in the allowlist.
