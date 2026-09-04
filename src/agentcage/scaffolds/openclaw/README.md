# OpenClaw Setup Guide

[OpenClaw](https://github.com/openclaw/openclaw) is an AI coding agent. This guide shows how to run it inside an agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by mitmproxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](../../docs/reference/configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) — see [installation instructions](../../README.md#install) for your platform
- An OpenClaw container image (`ghcr.io/openclaw/openclaw:latest` or custom-built)
- An Anthropic API key (`ANTHROPIC_API_KEY`)

## Quick start

### 1. Scaffold the config

```bash
agentcage init myapp --scaffold openclaw
```

This creates `cage.yaml` with sensible defaults: domain allowlist, secret injection, resource limits, and inline help. Review it and adjust as needed -- the comments explain each option.

### 2. Create the cage

```bash
agentcage cage create -c cage.yaml
```

This builds the proxy and DNS images, generates systemd quadlet files, and starts all three services (cage, proxy, dns). After startup, inline help is printed showing next steps.

### 3. Set secrets

```bash
# Anthropic API key (required)
agentcage secret set myapp ANTHROPIC_API_KEY

# Gateway password (required — used for browser auth)
agentcage secret set myapp OPENCLAW_GATEWAY_PASSWORD

# Brave Search API key (optional — for web_search tool)
# agentcage secret set myapp BRAVE_API_KEY
```

If you add `BRAVE_API_KEY`, uncomment the Brave entries in the `secret_injection` section and add `search.brave.com` to the domain allowlist in `cage.yaml`.

> **Secret injection:** The config uses `secret_injection` for API keys (Anthropic, Brave). The cage container never sees the real value -- it gets a generated placeholder token like `agentcage:secret:ANTHROPIC_API_KEY:9f3c1a7e8b204d56c1e0a4f7b2d8369a`, and the proxy swaps it for the real value when forwarding to the correct domain. The gateway password (`OPENCLAW_GATEWAY_PASSWORD`) stays in `podman_secrets` since it is used internally by the cage process, not in proxied HTTP requests. See [Secret injection](../../docs/reference/secret-injection.md) for details.

### 4. Connect and pair your browser

Open `http://localhost:18789` in your browser. Navigate to **Overview** and enter your gateway password in the **Password** field, then click **Connect**. The first connection triggers a device pairing request.

Approve the device from the command line:

```bash
# List pending device pairing requests
agentcage cage exec --as-root myapp -- openclaw devices list

# Approve a device
agentcage cage exec --as-root myapp -- openclaw devices approve <request-id>
```

After approval, click **Connect** again in the browser. The dashboard should show **Health: OK** and **STATUS: Connected**.

Subsequent connections from the same browser are automatic.

### 5. Verify

```bash
# Check containers are running
agentcage cage list

# Check health from inside the cage
agentcage cage exec --as-root myapp -- openclaw health

# View logs
agentcage cage logs myapp           # cage container
agentcage cage logs myapp -s proxy  # mitmproxy (traffic inspection)
agentcage cage logs myapp -s dns    # DNS sidecar
```

## Managing your cage

See [Troubleshoot](../../docs/how-to/troubleshoot.md) for diagnosing blocked requests, secret problems, and proxy restarts. See the [CLI reference](../../docs/reference/cli.md#cage) for the full `cage` subcommand set.

## Reverse proxy & device pairing

agentcage runs a reverse proxy (mitmproxy) in front of the cage container. When you connect a browser to OpenClaw through this proxy, there are two things to be aware of:

**Trusted proxies** — The OpenClaw scaffold auto-configures `trustedProxies` in `openclaw.json` on first start (writing `{"gateway": {"trustedProxies": ["10.89.0.11"]}}` into the state volume). No manual setup is needed. If you need to customize this, edit the file inside the container or provide your own `openclaw.json` in the state volume before starting the cage.

**Device pairing** — The first browser connection from a new device triggers a one-time pairing approval. Use `cage exec` to list pending requests and approve them:

```bash
agentcage cage exec --as-root myapp -- openclaw devices list
agentcage cage exec --as-root myapp -- openclaw devices approve <request-id>
```

The `openclaw` alias is expanded to `node openclaw.mjs` automatically via `exec_aliases` in the scaffold config.

## Secret detection defaults

agentcage ships with 19 built-in secret patterns and automatic domain exemptions. Out-of-the-box, your secrets are protected without any `allow_to_domains` configuration:

- **Anthropic keys** (`sk-ant-...`) are auto-allowed to `anthropic.com`
- **OpenAI keys** (`sk-proj-...`) are auto-allowed to `openai.com`
- **OpenRouter keys** (`sk-or-v1-...`) are auto-allowed to `openrouter.ai`
- **AWS keys**, **GitHub tokens**, **Stripe keys**, and 13 other patterns are similarly mapped

If a secret is detected going to any domain *other* than its mapped provider, the request is blocked. No configuration needed.

To extend the built-in mappings (e.g. for a custom API proxy):

```yaml
secrets:
  allow_to_domains:
    anthropic_key:
      - my-proxy.example.com    # overrides the built-in anthropic.com mapping
```

To disable built-in mappings entirely (require explicit config for every exemption):

```yaml
secrets:
  builtin_allow_to_domains: false
```

See [Secret detection](../../docs/reference/inspectors.md#secrets-inspector) for the full reference.

## Domain allowlist tiers

The scaffold config organizes domains into tiers. Enable what you need:

**Essential** (enabled by default):
- `anthropic.com` — AI provider API
- `npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org` — package registries
- `github.com`, `githubusercontent.com` — code hosting
- `cdn.jsdelivr.net`, `unpkg.com`, `esm.sh` — CDNs

**Web access** (commented out, uncomment as needed):
- `search.brave.com` — web search (requires `BRAVE_API_KEY`)
- `perplexity.ai` — AI search
- `firecrawl.dev` — web scraping (requires `FIRECRAWL_API_KEY`)

**AI/ML services**:
- `huggingface.co`, `hf.co` — model downloads
- `openai.com`, `openrouter.ai` — alternative AI providers

**Messaging**:
- `api.telegram.org`, `discord.com`, `slack.com` — bot integrations

Subdomains are matched automatically -- adding `anthropic.com` also allows `api.anthropic.com`, `docs.anthropic.com`, etc. However, sibling domains are not matched: adding `github.com` does **not** allow `githubusercontent.com` -- add it separately.

## Custom images

If you need extra tools or extensions in the container, build a custom image:

```dockerfile
FROM ghcr.io/openclaw/openclaw:latest
# install additional tools
RUN npm install -g some-extension
```

```bash
podman build -t localhost/openclaw-custom:latest -f Containerfile .
```

Then update `cage.yaml`:

```yaml
container:
  image: "localhost/openclaw-custom:latest"
```

Rebuild:

```bash
agentcage cage update myapp
```

## Troubleshooting

**Container fails to start / times out**: OpenClaw's Node.js gateway can take over 60 seconds to initialize. The scaffold config sets `timeout_start_sec: 120` to accommodate this. Check logs with `agentcage cage logs myapp`.

