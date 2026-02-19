# Architecture

agentcage generates [systemd quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) files that define 3 containers, a Podman network, and a shared certificate volume. Together they form a proxy sandbox where all agent HTTP traffic is inspected before reaching the internet.

For configuration options, see the [Configuration Reference](configuration.md). For hardware-level VM isolation via Firecracker, see [Firecracker MicroVM Isolation](firecracker.md).

## Container Topology

```
  podman network: <name>-net (--internal, no internet gateway)
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐  │
  │  │ Agent         │    │ DNS sidecar   │    │ mitmproxy        │  │
  │  │ 10.89.0.2    │    │ (dnsmasq)     │    │ + inspector chain│  │
  │  │               │    │               │    │                  │  │
  │  │ HTTP_PROXY=  ─┼────┼───────────────┼───►│ forward :8080   ─┼──┼─► Internet
  │  │  10.89.0.11   │    │               │    │                  │  │
  │  │               │    │               │    │ reverse :port   ◄┼──┼── Host (published ports)
  │  │ resolv.conf  ─┼───►│ resolves via  │    │   ↕ inspects     │  │
  │  │               │    │ external net ─┼────┼──────────────────┼──┼─► Upstream DNS
  │  │               │    │               │    │                  │  │
  │  │ ONLY on       │    │ internal +    │    │ internal +       │  │
  │  │ internal net  │    │ external net  │    │ external net     │  │
  │  └──────────────┘    └───────────────┘    └──────────────────┘  │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
```

**Agent** -- The user's container (e.g. an AI coding agent), at fixed IP `10.89.0.2`. It is connected *only* to the internal network and has no internet gateway. `HTTP_PROXY` and `HTTPS_PROXY` environment variables force all outbound HTTP traffic through the proxy container. The agent cannot reach the internet by any other path. Published ports are not exposed on the agent container — they are served by the proxy.

**DNS sidecar (dnsmasq)** -- Dual-homed: connected to both the internal network (at `10.89.0.10`) and the default `podman` network. It handles DNS resolution for agents that resolve hostnames before proxying. In allowlist mode, non-allowlisted domains resolve to a placeholder IP (`198.51.100.1`, RFC 5737 TEST-NET-2) instead of failing, so SSRF guards that pre-resolve DNS continue to work. Upstream DNS servers default to `1.1.1.1` and `8.8.8.8` but are configurable via `dns_servers`.

**Proxy (mitmproxy + addon.py)** -- Dual-homed: connected to both networks. Runs the [inspector chain](#inspector-chain) against every request. Operates in two modes simultaneously when ports are published:

- **Forward proxy** (`:8080`) -- handles outbound traffic from the agent, forwarding allowed requests to the internet
- **Reverse proxy** (one listener per published port) -- handles inbound traffic from the host, forwarding to the agent at `10.89.0.2`

Both directions pass through the full inspector chain (domain filtering, secret detection, entropy analysis, etc.). When no ports are published, only the forward proxy mode is active.

## Network Isolation

The generated `.network` file uses Podman's `Internal=true` directive, which creates a network with no internet gateway. Only containers that are also connected to an external network (the DNS sidecar and proxy) can reach the internet.

The network uses a fixed subnet: `10.89.0.0/24` with the agent at `10.89.0.2`, the DNS sidecar at `10.89.0.10`, and the proxy at `10.89.0.11`. The cage's `/etc/resolv.conf` is bind-mounted (read-only) to point at the dnsmasq sidecar. If this subnet conflicts with your existing network, you will need to regenerate the quadlet files after editing the `.network` file.

## Inspector Chain

All HTTP traffic passes through a pluggable inspector chain implemented in `addon.py`. Each request is evaluated by inspectors in order, with a pre-computed `InspectionContext` (URL, headers, body, entropy, etc.) shared across the chain. The chain short-circuits on the first hard block -- remaining inspectors are skipped.

5 built-in inspectors are available:

| Inspector | Default | Purpose |
|-----------|---------|---------|
| `domain` | on | Domain allowlist/blocklist enforcement |
| `secrets` | on | Regex-based secret leak detection |
| `body-size` | on | Request body size limits |
| `entropy` | off | Shannon entropy analysis for encrypted/compressed payloads |
| `content-type` | off | Content-type mismatch and base64 blob detection |

Custom inspectors can be added via Python files that extend the `Inspector` base class. Inspectors can also implement `inspect_response()` to scan inbound responses after forwarding.

See the [Configuration Reference](configuration.md#inspectors) for the full inspector API, `InspectionContext` fields, and custom inspector examples.

## Secret Injection

Secret injection is an optional pre/post-processing step that runs **outside** the inspector chain. It modifies the flow in-place rather than observing it read-only like inspectors do.

The cage container never receives real secrets. Instead it gets placeholder tokens (e.g. `{{ANTHROPIC_API_KEY}}`), and the proxy swaps them transparently:

```
Outbound (cage → upstream):
  cage sends:     Authorization: Bearer {{ANTHROPIC_API_KEY}}
       ↓
  injector:       domain in inject_to? → replace placeholder with real value
       ↓
  inspector chain runs on the modified request (domain, secrets, entropy, etc.)
       ↓
  upstream receives real key

Inbound (upstream → cage):
  upstream responds with real key in body/headers
       ↓
  response inspector chain runs
       ↓
  injector:       redact real value → placeholder
       ↓
  cage receives placeholder only
```

If a placeholder is found heading to a domain not in the rule's `inject_to` list, the request is blocked before reaching the inspector chain.

See the [Configuration Reference](configuration.md#secret-injection-secret_injection) for setup and examples.

## Startup Order

The quadlet files encode a dependency chain via systemd `Requires=` and `After=` directives:

1. **DNS sidecar** starts first (no dependencies)
2. **Proxy** starts after DNS (`Requires=<name>-dns.service`)
3. **Cage** starts after proxy (`Requires=<name>-proxy.service`)

Before the cage container's main process starts, an `ExecStartPre` script polls for the mitmproxy CA certificate in the shared volume. It checks once per second for up to 30 seconds, failing the start if the cert never appears. This ensures the agent always has a valid CA cert before making HTTPS requests.

## Certificate Sharing

mitmproxy generates a CA certificate on first run, stored in a named Podman volume (`agentcage-certs-<name>`). This volume is:

- Mounted read-write in the proxy container at `/home/mitmproxy/.mitmproxy` (where mitmproxy writes the cert)
- Mounted **read-only** in the cage container at `/certs`

Two environment variables are set in the cage container so that common runtimes trust the CA:

- `NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem` -- Node.js
- `SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem` -- Python, curl, and other OpenSSL-based tools

## Node.js Fetch Patch

Node.js's built-in `fetch()` (powered by undici) ignores the `HTTP_PROXY` / `HTTPS_PROXY` environment variables. Without intervention, `fetch()` calls from Node.js agents bypass the proxy entirely -- and since the agent has no internet gateway, they fail with connection errors instead of being inspected.

agentcage solves this by injecting a loader script via `NODE_OPTIONS=--import /agentcage/proxy-fetch.mjs`. The script replaces `globalThis.fetch` with a wrapper that routes requests through an `EnvHttpProxyAgent` from the `undici` package, which reads the proxy env vars.

Non-Node.js applications (Python, Go, curl, etc.) natively respect `HTTP_PROXY` / `HTTPS_PROXY` and need no patching.

## Generated Files

The `generate` command produces 5 quadlet files in `<name>-quadlets/`:

| File | Role |
|------|------|
| `<name>-net.network` | Internal network with fixed subnet |
| `<name>-certs.volume` | Shared certificate volume |
| `<name>-dns.container` | DNS sidecar (dnsmasq) |
| `<name>-proxy.container` | mitmproxy with inspector chain |
| `<name>-cage.container` | Agent container with proxy env vars, cert mount, and fetch patch |
