# OpenClaw Setup Guide

[OpenClaw](https://github.com/openclaw/openclaw) is an AI coding agent. This guide shows how to run it inside a agentcage sandbox -- a rootless Podman container with no direct internet access where all HTTP traffic is inspected by mitmproxy for domain filtering, secret leak detection, and payload analysis.

For the full list of configuration options, see the [Configuration Reference](configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) — see [installation instructions](../README.md#prerequisites) for your platform
- An OpenClaw container image (`ghcr.io/openclaw/openclaw:latest` or custom-built)
- An Anthropic secret (`ANTHROPIC_API_KEY`)

## Setup

### 1. Copy the example config

```bash
cd /path/to/agentcage
cp examples/openclaw/config.yaml config.yaml
```

Review `config.yaml` and adjust the domain allowlist, resource limits, and image as needed. The config file comments explain each option.

### 2. Create Podman secrets

OpenClaw needs secrets injected via Podman:

```bash
# Anthropic secret (required)
echo -n "sk-ant-..." | podman secret create ANTHROPIC_API_KEY -

# Gateway password
echo -n "your-password-here" | podman secret create OPENCLAW_GATEWAY_PASSWORD -

# Brave Search secret (optional — for web_search tool)
# echo -n "BSA..." | podman secret create BRAVE_API_KEY -
```

Verify secrets are created:

```bash
podman secret ls
```

If you add `BRAVE_API_KEY`, uncomment the Brave entries in the `secret_injection` section and add `search.brave.com` to the domain allowlist in `config.yaml`.

> **Secret injection:** The example config uses `secret_injection` for secrets (Anthropic, Brave). This means the cage container never sees the real value -- it gets a placeholder like `{{ANTHROPIC_API_KEY}}`, and the proxy swaps it for the real value when forwarding to the correct domain. The gateway secret (`OPENCLAW_GATEWAY_PASSWORD`) stays in `podman_secrets` since it is used internally by the cage process, not in proxied HTTP requests. See [Secret injection](configuration.md#secret-injection-secret_injection) for details.

### 3. Create workspace directory

```bash
mkdir -p ~/openclaw-workspace
```

This is bind-mounted into the container at `/workspace`. Agent file operations happen here.

### 4. Generate quadlets and deploy

```bash
agentcage generate -c config.yaml
agentcage deploy ./openclaw-cage
```

### 5. Verify

```bash
# Check containers are running
podman ps --format "{{.Names}} {{.Status}}"

# Check OpenClaw is responding
curl -s http://127.0.0.1:18789/api/health

# View logs
journalctl --user -u openclaw-cage -f    # agent container
journalctl --user -u openclaw-proxy -f   # mitmproxy (traffic inspection)
journalctl --user -u openclaw-dns -f     # DNS sidecar
```

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

See [Secret detection](configuration.md#secret-detection-secrets) for the full reference.

## Domain allowlist tiers

The example config organizes domains into tiers. Enable what you need:

**Essential** (enabled by default in the example):
- `anthropic.com` — AI provider API
- `npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org` — package registries
- `github.com`, `githubusercontent.com` — code hosting

**Web access** (commented out, uncomment as needed):
- `search.brave.com` — web search (requires `BRAVE_API_KEY`)
- `perplexity.ai` — AI search
- `firecrawl.dev` — web scraping (requires `FIRECRAWL_API_KEY`)

**AI/ML services**:
- `huggingface.co`, `hf.co` — model downloads
- `openai.com`, `openrouter.ai` — alternative AI providers

**Messaging**:
- `api.telegram.org`, `discord.com` — bot integrations

## Customizing the domain allowlist

The example config allows the minimum set of domains OpenClaw needs: `anthropic.com` (API calls), package registries (npm, PyPI), and GitHub. Add domains as your agents need them:

```yaml
domains:
  mode: allowlist
  list:
    - anthropic.com
    - npmjs.org
    # ... existing entries ...
    - search.brave.com      # web search (requires BRAVE_API_KEY)
    - huggingface.co         # model downloads
    - cdn.jsdelivr.net       # CDN
```

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

Then update `config.yaml`:

```yaml
container:
  image: "localhost/openclaw-custom:latest"
```

Regenerate and restart:

```bash
agentcage generate -c config.yaml
agentcage deploy ./openclaw-cage
```

## Reverse proxy & device pairing

agentcage runs a reverse proxy (mitmproxy) in front of the cage container. When you connect a browser to OpenClaw through this proxy, there are two things to be aware of:

**Trusted proxies** — The proxy forwards `X-Forwarded-For` headers so OpenClaw can identify the real client IP. To make OpenClaw trust these headers, create a config file in the persistent state volume:

```bash
podman exec <name>-cage sh -c 'cat > /home/node/.openclaw/openclaw.json << EOF
{ "gateway": { "trustedProxies": ["10.89.0.11"] } }
EOF'
```

Then restart the cage (`systemctl --user restart <name>-cage`).

**Device pairing** — The first browser connection from a new device triggers a one-time pairing approval. To approve, check the cage logs for the pairing request and approve it:

```bash
# Find the pairing request ID in the logs
journalctl --user -u <name>-cage -f

# Approve the device
podman exec <name>-cage openclaw pairing approve <request-id>
```

Subsequent connections from the same browser are automatic.

## Troubleshooting

**Container fails to start / times out**: OpenClaw's Node.js gateway can take over 60 seconds to initialize. The example config sets `timeout_start_sec: 120` to accommodate this. Check logs with `journalctl --user -u openclaw-cage -f`.

**403 errors from the proxy**: A domain is not in your allowlist, or a secret pattern was detected in the request. Check proxy logs with `journalctl --user -u openclaw-proxy -f` -- the JSON log entries include a `reason` field explaining the block.

**Certificate errors**: The mitmproxy CA certificate is shared via a named volume (see [Certificate Sharing](architecture.md#certificate-sharing)). If the proxy container hasn't finished generating it before the cage starts, you may see TLS errors. The generated quadlet files include a start-up check that waits up to 30 seconds for the certificate. If it still fails, restart the cage: `systemctl --user restart openclaw-cage`.

**DNS resolution failures**: Verify the DNS sidecar is running: `podman ps --filter name=openclaw-dns`. If you are using custom `dns_servers` (e.g., Tailscale MagicDNS), make sure those servers are reachable from the host.
