# NanoClaw Setup Guide

[NanoClaw](https://github.com/nanoclaw/nanoclaw) is an AI agent framework that spawns Docker containers to run tasks. This guide shows how to run it inside an agentcage cage with nested container support -- the cage can run podman-in-podman, and a Docker CLI shim translates `docker` commands to `podman` automatically.

All HTTP traffic from the cage (and from any inner containers that opt into networking) passes through agentcage's inspecting proxy for domain filtering, secret leak detection, and payload analysis. Inner containers spawned by NanoClaw run with `--network none` by default, so they have no network access at all unless explicitly configured otherwise.

For the full list of configuration options, see the [Configuration Reference](configuration.md).

## Prerequisites

- [Podman](https://podman.io/) (rootless), Python 3.12+, and [uv](https://docs.astral.sh/uv/) -- see [installation instructions](../README.md#install) for your platform
- An Anthropic API key (`ANTHROPIC_API_KEY`)

## Quick start

### 1. Scaffold the config

```bash
agentcage init myapp --scaffold nanoclaw
```

This creates `cage.yaml` with nested container support enabled, Docker Hub registry domains in the allowlist, and Docker registry JWT token exemptions pre-configured. Review it and adjust as needed.

### 2. Build the base image

```bash
agentcage build nested-base
```

This builds `localhost/agentcage-nested`, a `node:22-slim` image with podman, fuse-overlayfs, crun, and uidmap pre-installed. The image is used as the cage container's base.

### 3. Set secrets

```bash
agentcage secret set myapp ANTHROPIC_API_KEY
```

The config uses `secret_injection` for the API key -- the cage container never sees the real value. It gets a placeholder (`{{ANTHROPIC_API_KEY}}`), and the proxy swaps it for the real value when forwarding to `anthropic.com`. See [Secret injection](configuration.md#secret-injection-secret_injection) for details.

### 4. Create the cage

```bash
agentcage cage create -c cage.yaml
```

This builds the proxy and DNS images, generates systemd quadlet files (6 for nested cages -- the standard 5 plus a storage volume for inner podman state), and starts all services.

### 5. Verify

```bash
agentcage cage verify myapp
```

For nested-container cages, verify includes two additional checks:

- **Inner podman available** -- confirms podman is installed and working inside the cage
- **Docker shim available** -- confirms the `docker` CLI shim is in place

Example output:

```
=== agentcage verify: myapp ===

-- Containers --
  [PASS] myapp-proxy is running
  [PASS] myapp-dns is running
  [PASS] myapp-cage is running

-- CA Certificate --
  [PASS] mitmproxy CA cert exists in shared volume

-- Proxy Configuration --
  [PASS] HTTP_PROXY is set
  [PASS] HTTPS_PROXY is set

-- Egress Filtering --
  [PASS] Blocked domain (evil-exfil-server.io) is denied (HTTP 403)

-- Nested Containers --
  [PASS] Inner podman available (podman version 4.3.1)
  [PASS] Docker shim available

-- Podman --
  [PASS] Podman is running rootless

=== Results: 10 passed, 0 failed, 0 warnings ===
```

### 6. Test inner containers

```bash
# Run a container inside the cage
agentcage cage exec myapp -- docker run --rm alpine echo hello

# Run with network access (uses the cage's proxy)
agentcage cage exec myapp -- docker run --rm --network host alpine wget -qO- https://httpbin.org/ip
```

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

Inner containers inherit the cage's network configuration:
- With `--network none` (NanoClaw's default): no network access at all
- With `--network host`: traffic goes through the cage's proxy, subject to all agentcage protections

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

## Custom base images

The default base image (`localhost/agentcage-nested`) is built from `node:22-slim`. To add tools or customize it:

```dockerfile
FROM localhost/agentcage-nested
# Install additional tools
RUN apt-get update && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*
```

```bash
podman build -t localhost/my-nanoclaw:latest -f Containerfile .
```

Then update `cage.yaml`:

```yaml
container:
  image: "localhost/my-nanoclaw:latest"
  nested_containers: true
```

Rebuild:

```bash
agentcage cage update myapp
```

> **Important:** Your custom image must have podman, fuse-overlayfs, crun, and uidmap installed. The easiest approach is to base it on `localhost/agentcage-nested` as shown above.

## Security trade-offs

Nested container support requires elevated capabilities that weaken the default container hardening. When `nested_containers: true`:

- **SYS_ADMIN capability** significantly increases the container escape attack surface compared to the default `DropCapability=ALL`.
- **NoNewPrivileges=false** allows privilege escalation via setuid binaries inside the cage.
- **Seccomp unconfined** disables the seccomp filter, allowing all syscalls.
- **User=0** means processes run as root in the user namespace.

All agentcage network-level protections remain fully active:
- Proxy inspection, domain filtering, and secret detection apply to all cage traffic
- Inner containers with `--network none` have no network access at all
- Inner containers with `--network host` inherit the cage's proxy configuration

For production nested workloads with untrusted agents, consider using Firecracker mode (`isolation: firecracker`) for hardware-level isolation around the cage. Note that `nested_containers` is not currently supported with Firecracker isolation.

See [Security & Threat Model](security.md) for the full threat model and defense layers.

## Troubleshooting

**`agentcage build nested-base` fails**: The build requires several capabilities (`CAP_SETFCAP`, `CAP_SETUID`, `CAP_SETGID`, `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`). These are passed automatically. If the build still fails, check that rootless podman is working: `podman run --rm alpine echo hello`.

**Inner `docker pull` fails with 403**: A domain is missing from the allowlist. Docker Hub uses multiple domains for image pulls. Check proxy logs: `agentcage cage logs myapp -s proxy`. The JSON log entries include a `reason` field explaining the block. Add any missing domains with `agentcage domain add myapp <domain>`.

**Inner `docker pull` blocked by secrets inspector**: Docker Hub JWT tokens trigger the `azure_jwt` pattern. Make sure the `allow_to_domains` exemption is configured for the Docker registry domains (the scaffold pre-configures this).

**`mkdir .pivot_root: permission denied` inside inner container**: The cage is missing required capabilities. Make sure `nested_containers: true` is set in the config -- this automatically configures all 16 required capabilities, seccomp=unconfined, and unmask=ALL.

**Container fails to start / times out**: NanoClaw can take time to initialize, especially when pulling inner container images. The scaffold sets `timeout_start_sec: 120`. Increase this if needed. Check logs with `agentcage cage logs myapp`.

**Certificate errors in inner containers**: Inner containers with `--network host` inherit the cage's proxy environment variables but not the CA certificate. Mount the certificate into inner containers or set `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` to point to `/certs/mitmproxy-ca-cert.pem`.

**DNS resolution failures**: Verify the DNS sidecar is running: `agentcage cage list`. Inner containers with `--network none` cannot resolve DNS -- this is by design.
