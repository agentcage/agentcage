# Architecture

agentcage deploys a three-container topology — agent, DNS sidecar, and inspecting proxy — on an internal network with no internet gateway. In **container mode** (default), these containers run directly on the host via rootless Podman. In **VM mode**, the same topology runs inside a dedicated Lima VM with its own kernel, adding hardware-level isolation around the containers.

This document covers the shared architecture used by both modes. For backend-specific details — how VM and apple-container differ from container mode — see [Isolation modes](explain/isolation-modes.md). For configuration options, see the [Configuration Reference](reference/configuration.md).

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
  │  │               │    │               │    │ transparent:8443│  │
  │  │ default route─┼────┼───────────────┼───►│  ↕ iptables REDIR│  │
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

## Isolation Boundary

In container mode, the three containers above run directly on the host using rootless Podman. Network isolation is enforced by Podman's `--internal` network flag, and container hardening (read-only rootfs, dropped capabilities, no-new-privileges) reduces the attack surface. However, all containers share the host kernel.

In VM mode, the entire topology runs inside a Lima VM with a dedicated guest kernel. The VM itself becomes the isolation boundary — a container escape lands inside the VM, not on the host.

```
┌─────────────────────────────────────────────────────────────┐
│  Lima VM (dedicated kernel, KVM isolation)                  │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  Podman internal network (same topology as above)   │   │
│   │  Agent ──► DNS sidecar ──► Proxy ──► Internet       │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
└───────────────── Lima networking ──── Host ─────────────────┘
```

This is the **only** architectural difference between the modes. The inspector chain, secret injection, DNS filtering, and all other inspection logic are identical.

**Agent** -- The user's container (e.g. an AI coding agent), at fixed IP `10.89.0.2`. It is connected *only* to the internal network. A default route via the proxy container and iptables REDIRECT rules provide **transparent proxy interception**: outbound TCP traffic to ports listed in `ports.tcp.allow` (default `[80, 443]`) is intercepted by mitmproxy regardless of whether the application respects `HTTP_PROXY` environment variables. The proxy applies a default-deny `filter:FORWARD` policy, so any TCP/UDP destination port not listed in the cage's `ports` config is dropped at the proxy. `HTTP_PROXY` and `HTTPS_PROXY` are still set for proxy-aware applications. Published ports are not exposed on the agent container — they are served by the proxy.

**DNS sidecar (dnsmasq)** -- Dual-homed: connected to both the internal network (at `10.89.0.10`) and the default `podman` network. It handles DNS resolution for agents that resolve hostnames before proxying. In allowlist mode, non-allowlisted domains resolve to a placeholder IP (`198.51.100.1`, RFC 5737 TEST-NET-2) instead of failing, so SSRF guards that pre-resolve DNS continue to work. Upstream DNS servers default to `1.1.1.1` and `8.8.8.8` but are configurable via `dns_servers`.

**Proxy (mitmproxy + addon.py)** -- Dual-homed: connected to both networks. Runs the [inspector chain](#inspector-chain) against every request. Operates in multiple modes simultaneously:

- **Forward proxy** (`:8080`) -- handles outbound traffic from proxy-aware applications via `HTTP_PROXY`
- **Transparent proxy** (`:8443`) -- handles outbound TCP traffic redirected by iptables from the inspected port set (`ports.tcp.allow - ports.tcp.passthrough`, default `[80, 443]`), intercepting traffic from applications that don't use proxy env vars
- **Reverse proxy** (one listener per published port, when ports are configured) -- handles inbound traffic from the host, forwarding to the agent at `10.89.0.2`

All directions pass through the full inspector chain (domain filtering, secret detection, entropy analysis, etc.). The `NET_ADMIN` capability is granted to the proxy container to allow iptables REDIRECT rules and to enforce the default-deny `filter:FORWARD` policy.

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
| `content-type` | on | Content-type mismatch and base64 blob detection |
| `entropy` | off (opt-in) | Shannon entropy analysis for encrypted/compressed payloads |

Custom inspectors can be added via Python files that extend the `Inspector` base class. Inspectors can also implement `inspect_response()` to scan inbound responses after forwarding.

See the [Inspectors reference](reference/inspectors.md) for the full inspector API, `InspectionContext` fields, and custom inspector examples.

## Secret Injection

Secret injection is an optional pre/post-processing step that runs **outside** the inspector chain. It modifies the flow in-place rather than observing it read-only like inspectors do.

The cage container never receives real secrets. Instead it gets placeholder tokens (e.g. `{{ANTHROPIC_API_KEY}}`), and the proxy swaps them transparently:

```
Outbound (cage → upstream):
  cage sends:     Authorization: Bearer {{ANTHROPIC_API_KEY}}
       ↓
  policy check:   literal real value in request? → block (critical)
                  placeholder to unauthorized domain? → flag
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

Two policy checks run before injection:

1. **Literal value blocking** — If a real secret value appears anywhere in the request (URL, headers, or body), the request is blocked with severity `critical`. The cage should never know real values, so their presence indicates the agent learned the secret outside the placeholder system. This applies to all domains (including `inject_to` domains), except `redact_to` domains where redaction handles the substitution.
2. **Placeholder domain restriction** — If a placeholder is found heading to a domain not in the rule's `inject_to` list, the request is flagged.

See the [Secret injection reference](reference/secret-injection.md) for setup and examples.

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

## Transparent Proxy Interception

In container mode, outbound TCP traffic to the inspected port set is intercepted transparently at the network level, regardless of whether the application uses proxy environment variables:

1. **Default route** -- An `ExecStartPost` script uses `nsenter` to add a default route in the cage container's network namespace, pointing to the proxy container's IP. This gives the cage container a path to send packets to arbitrary IPs (which previously had no route on the internal network).

2. **iptables REDIRECT** -- The proxy container has `NET_ADMIN` capability and runs iptables rules that redirect TCP traffic on each inspected port (`ports.tcp.allow - ports.tcp.passthrough`, default `[80, 443]`) to mitmproxy's transparent listener on port 8443. Operators extend `ports.tcp.allow` to permit non-standard services (e.g. `8448` for a Matrix homeserver, `5432` for Postgres). See [Port policy](reference/ports.md) for the full discussion.

3. **mitmproxy transparent mode** -- mitmproxy runs with `--mode transparent@8443` alongside its regular forward proxy mode on port 8080. It uses `SO_ORIGINAL_DST` to determine the original destination of redirected connections — so any TLS-terminated TCP port works without per-port mitmproxy configuration.

4. **Default-deny `filter:FORWARD`** -- Anything not in `ports.tcp.allow`, `ports.tcp.passthrough`, or `ports.udp.allow` is dropped at the proxy. ICMP echo-request is always permitted for diagnostics. An `ip6tables -P FORWARD DROP` failsafe blocks IPv6 forwarding.

This means Go's custom `http.Transport`, Node.js `fetch()`, Rust's `reqwest`, and any other HTTP client that creates direct connections to inspected TCP ports will have their traffic intercepted and inspected — no runtime-specific patching required.

`HTTP_PROXY` / `HTTPS_PROXY` environment variables are still set for proxy-aware applications. UDP traffic on ports listed in `ports.udp.allow` is forwarded uninspected (mitmproxy is HTTP-only).

In VM mode, transparent interception is not yet implemented — applications must use `HTTP_PROXY` env vars.

## Nested Containers (Podman-in-Podman)

When `nested_containers: true` is set, the cage container is configured to run podman internally, enabling AI agent frameworks that spawn containers. A Docker CLI shim at `/usr/local/bin/docker` translates `docker` commands to `podman`.

The nested container topology adds a layer inside the cage:

```
┌─────────────────────────────────────────────────────────────────┐
│  Cage container (10.89.0.2)                                     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐       │
│  │  Inner containers (spawned by podman/docker shim)    │       │
│  │                                                      │       │
│  │  --network none  → no network access                 │       │
│  │  --network host  → inherits cage proxy → inspected   │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                 │
│  HTTP_PROXY → proxy → Internet (inspected)                      │
└─────────────────────────────────────────────────────────────────┘
```

Inner containers default to `--network none` (configured via `containers.conf`), giving them no network access. Inner containers that explicitly use `--network host` inherit the cage's proxy environment variables, so their traffic passes through the full inspector chain.

A persistent named volume (`agentcage-podman-<name>`) stores inner podman's image cache and container state at `/var/lib/containers`, so pulled images survive cage restarts.

## Generated Files

The `cage create` command produces 5 quadlet files in `<name>-quadlets/` (6 when `nested_containers` is enabled):

| File | Role |
|------|------|
| `<name>-net.network` | Internal network with fixed subnet |
| `<name>-certs.volume` | Shared certificate volume |
| `<name>-dns.container` | DNS sidecar (dnsmasq) |
| `<name>-proxy.container` | mitmproxy with inspector chain |
| `<name>-cage.container` | Agent container with proxy env vars, cert mount, and default route |
| `<name>-podman-storage.volume` | *(nested only)* Inner podman image/container storage |
