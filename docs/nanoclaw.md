# NanoClaw Setup Guide

[NanoClaw](https://github.com/qwibitai/nanoclaw) is an AI agent framework that spawns Docker containers to run tasks. This guide shows how to run it inside an agentcage cage with nested container support -- the cage can run podman-in-podman, and a Docker CLI shim translates `docker` commands to `podman` automatically.

All HTTP traffic from the cage (and from inner agent containers) passes through agentcage's inspecting proxy for domain filtering, secret leak detection, and payload analysis. Inner agent containers are patched to use `--network host` so they inherit the cage's proxy, and proxy/cert environment variables are forwarded automatically.

For the full list of configuration options, see the [Configuration Reference](configuration.md).

## Architecture

```
Host podman:
  agentcage-nested        ← base image (podman + fuse-overlayfs)
  agentcage-nanoclaw      ← NanoClaw installed + patched (extends nested)
  nanoclaw-agent          ← agent image (claude-code + chromium)

Cage (runs agentcage-nanoclaw):
  NanoClaw orchestrator (node dist/index.js)
    └─ spawns inner containers (nanoclaw-agent:latest)
       └─ --network host → inherits cage proxy → API calls inspected
```

Three images are built on the host. The `nanoclaw-agent` image is automatically imported into the cage's inner podman during `cage create` / `cage update` via `podman save | podman exec podman load`.

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) -- see [installation instructions](../README.md#install) for your platform
- An Anthropic API key (`ANTHROPIC_API_KEY`)

## Quick start

### 1. Scaffold the config

```bash
agentcage init myapp --scaffold nanoclaw
```

This creates `cage.yaml` with nested container support enabled, Docker Hub registry domains in the allowlist, and Docker registry JWT token exemptions pre-configured. Review it and adjust as needed.

### 2. Build the images

Three images are required, built in order:

```bash
# Base image: node:22-slim + podman + fuse-overlayfs
agentcage build nested-base

# Cage image: NanoClaw installed + patched for agentcage
agentcage build nanoclaw

# Agent image: claude-code + chromium (what NanoClaw spawns per task)
agentcage build nanoclaw-agent
```

- `agentcage-nested` -- base image with podman-in-podman support
- `agentcage-nanoclaw` -- extends the base with NanoClaw cloned, built, and patched so inner containers use `--network host`, forward proxy/cert env vars, and mount `/certs` and `/agentcage` volumes
- `nanoclaw-agent` -- NanoClaw's agent container (claude-code, chromium, agent-runner)

### 3. Set secrets

```bash
agentcage secret set myapp ANTHROPIC_API_KEY
```

The config uses `secret_injection` for the API key. The cage image has a `.env` file containing the placeholder `{{ANTHROPIC_API_KEY}}`. NanoClaw reads this and passes it to agent containers via stdin. The proxy swaps the placeholder for the real value when forwarding to `anthropic.com`. No real secret ever enters the cage.

### 4. Create the cage

```bash
agentcage cage create -c cage.yaml
```

This builds the proxy and DNS images, generates systemd quadlet files, starts all services, and preloads the `nanoclaw-agent` image into the cage's inner podman.

### 5. Verify

```bash
agentcage cage verify myapp
```

For nested-container cages, verify includes two additional checks:

- **Inner podman available** -- confirms podman is installed and working inside the cage
- **Docker shim available** -- confirms the `docker` CLI shim is in place

You can also check that the agent image was preloaded:

```bash
agentcage cage exec myapp -- podman images
# Should show nanoclaw-agent:latest
```

### 6. Check NanoClaw is running

```bash
agentcage cage logs myapp
```

The cage runs `node dist/index.js` (NanoClaw's orchestrator). Check logs to confirm it started successfully.

## How it works

### Secret flow

```
.env file (baked in image):  ANTHROPIC_API_KEY={{ANTHROPIC_API_KEY}}
  → NanoClaw reads it → passes to agent container via stdin
  → claude-code uses placeholder in API calls
  → cage proxy replaces {{ANTHROPIC_API_KEY}} with real key → forwards to anthropic.com
```

No real secret ever enters the cage.

### Agent image preload

The `nanoclaw-agent` image is built on the host but must be available inside the cage's inner podman. During `cage create` and `cage update`, agentcage automatically runs:

```
podman save nanoclaw-agent:latest | podman exec -i <name>-cage podman load
```

This is idempotent -- `podman load` is safe to repeat.

### Proxy env var forwarding

The NanoClaw cage image patches `dist/container-runner.js` so that inner agent containers:

1. Run with `--network host` instead of `--network none`, so they can reach the Anthropic API through the cage's proxy
2. Inherit `HTTP_PROXY`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, and `NODE_OPTIONS` from the cage environment
3. Mount `/certs` (CA certificate) and `/agentcage` (patches) as read-only volumes

### Named volumes

Three named volumes persist NanoClaw state across cage rebuilds:

- `nanoclaw-<name>-store` -- NanoClaw's key-value store
- `nanoclaw-<name>-groups` -- agent group configurations
- `nanoclaw-<name>-data` -- general data directory

## How nested containers work

When `nested_containers: true` is set, agentcage configures the cage container to support podman-in-podman:

- **Capabilities** -- 16 Linux capabilities are added (SYS_ADMIN, SYS_CHROOT, MKNOD, SETUID, SETGID, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, NET_ADMIN, NET_BIND_SERVICE, NET_RAW, SETFCAP, SETPCAP, AUDIT_WRITE) instead of the default `DropCapability=ALL`. This is not `--privileged` -- only the required capabilities are granted.
- **User** -- The cage runs as `User=0` (root in the user namespace) so that setuid helpers (`newuidmap`/`newgidmap`) work for inner rootless podman.
- **NoNewPrivileges** -- Forced to `false` (required for setuid helpers).
- **Seccomp** -- Set to `unconfined` (required for podman's tar applier and mount operations).
- **Device** -- `/dev/fuse` is added for fuse-overlayfs.
- **Storage volume** -- A persistent named volume (`agentcage-podman-<name>`) is mounted at `/var/lib/containers` for inner podman's image and container storage.
- **Docker shim** -- A shell script at `/usr/local/bin/docker` that translates `docker` commands to `podman`.
- **Config files** -- Inner podman's `storage.conf`, `containers.conf`, and `registries.conf` are bind-mounted from agentcage's data directory.

Inner agent containers use `--network host` (patched), so all their traffic flows through the cage's proxy and is subject to domain filtering and secret detection.

See [Security trade-offs](#security-trade-offs) for what this means for your threat model.

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

# View logs
agentcage cage logs myapp           # cage container
agentcage cage logs myapp -s proxy  # mitmproxy (traffic inspection)

# Destroy the cage (stops containers, removes quadlets and state)
agentcage cage destroy myapp
```

## Domain allowlist

The NanoClaw scaffold organizes domains into tiers:

**Core AI providers** (enabled by default):
- `anthropic.com` -- Anthropic API

**Container registries** (enabled by default -- required for pulling inner images):
- `docker.io`, `registry-1.docker.io`, `auth.docker.io` -- Docker Hub
- `production.cloudflare.docker.com` -- Docker Hub CDN
- `r2.cloudflarestorage.com` -- Docker Hub blob storage (Cloudflare R2)

**Package registries** (enabled by default):
- `npmjs.org`, `npmjs.com` -- npm
- `pypi.org`, `files.pythonhosted.org` -- PyPI
- `nodejs.org` -- Node.js downloads

**Code hosting** (enabled by default):
- `github.com`, `githubusercontent.com`

**Additional providers** (commented out, uncomment as needed):
- `openai.com`, `openrouter.ai` -- alternative AI providers

> **Note:** Docker Hub's image pull flow involves multiple domains. All five Docker-related domains must be in the allowlist for image pulls to work. The scaffold pre-configures these.

## Docker registry JWT tokens

Docker Hub uses JWT bearer tokens for authentication. These tokens match agentcage's `azure_jwt` secret detection pattern, which would normally block them. The NanoClaw scaffold pre-configures an `allow_to_domains` exemption so JWT tokens can reach the Docker registry domains:

```yaml
inspectors:
  - name: secrets
    config:
      allow_to_domains:
        azure_jwt:
          - docker.io
          - registry-1.docker.io
          - auth.docker.io
```

If you use a different container registry (e.g. GitHub Container Registry), add its domains to both the domain allowlist and the `azure_jwt` exemption list.

## Security trade-offs

Nested container support requires elevated capabilities that weaken the default container hardening. When `nested_containers: true`:

- **SYS_ADMIN capability** significantly increases the container escape attack surface compared to the default `DropCapability=ALL`.
- **NoNewPrivileges=false** allows privilege escalation via setuid binaries inside the cage.
- **Seccomp unconfined** disables the seccomp filter, allowing all syscalls.
- **User=0** means processes run as root in the user namespace.

All agentcage network-level protections remain fully active:
- Proxy inspection, domain filtering, and secret detection apply to all cage traffic
- Inner agent containers use `--network host` and inherit the cage's proxy configuration
- The cage only sees API key placeholders -- the proxy replaces them on the wire

For production nested workloads with untrusted agents, consider using Firecracker mode (`isolation: firecracker`) for hardware-level isolation around the cage. Note that `nested_containers` is not currently supported with Firecracker isolation.

See [Security & Threat Model](security.md) for the full threat model and defense layers.

## Troubleshooting

**`agentcage build nested-base` fails**: The build requires several capabilities (`CAP_SETFCAP`, `CAP_SETUID`, `CAP_SETGID`, `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`). These are passed automatically. If the build still fails, check that rootless podman is working: `podman run --rm alpine echo hello`.

**`agentcage build nanoclaw` fails**: Requires `localhost/agentcage-nested` to be built first. The build clones the NanoClaw repository from GitHub and patches the compiled JavaScript. If the patch fails, the NanoClaw source may have changed -- check the error message for which pattern failed to match.

**`agentcage build nanoclaw-agent` fails**: Clones the NanoClaw repository and builds from `container/Dockerfile`. This installs claude-code, chromium, and the agent-runner. Requires internet access for npm and apt packages.

**Agent image not preloaded**: If `agentcage cage exec myapp -- podman images` doesn't show `nanoclaw-agent`, the preload may have failed. Check logs with `agentcage cage logs myapp`. You can manually preload with: `podman save localhost/nanoclaw-agent | podman exec -i myapp-cage podman load`.

**Inner `docker pull` fails with 403**: A domain is missing from the allowlist. Docker Hub uses multiple domains for image pulls. Check proxy logs: `agentcage cage logs myapp -s proxy`. The JSON log entries include a `reason` field explaining the block. Add any missing domains with `agentcage domain add myapp <domain>`.

**Inner `docker pull` blocked by secrets inspector**: Docker Hub JWT tokens trigger the `azure_jwt` pattern. Make sure the `allow_to_domains` exemption is configured for the Docker registry domains (the scaffold pre-configures this).

**`mkdir .pivot_root: permission denied` inside inner container**: The cage is missing required capabilities. Make sure `nested_containers: true` is set in the config -- this automatically configures all 16 required capabilities, seccomp=unconfined, and unmask=ALL.

**Container fails to start / times out**: NanoClaw can take time to initialize. The scaffold sets `timeout_start_sec: 120`. Increase this if needed. Check logs with `agentcage cage logs myapp`.

**Certificate errors in inner containers**: The patched container-runner forwards `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE` and mounts `/certs` into inner containers. If you still see certificate errors, check that the proxy's CA cert exists at `/certs/mitmproxy-ca-cert.pem` inside the cage.

**DNS resolution failures**: Verify the DNS sidecar is running: `agentcage cage list`. Inner containers with `--network host` use the cage's DNS configuration.
