# System Architecture

agentcage decouples an untrusted AI coding agent workload from the host environment and open internet through a multi-service container or microVM architecture.

This document details the internal design of agentcage: network topology, packet filtering, DNS sinkholing, transparent TLS proxying, the Python proxy addon pipeline, systemd quadlet integration, and live-reload mechanisms.

---

## High-Level Topology

Every cage consists of two tightly coupled services running on a dedicated private network:

1. **Workload Sandbox (`<name>-cage`)**: Houses the agent binary (e.g. Claude Code, Pi, OpenAI Codex), development runtimes (Node, Python), and mounted workspace files. It runs as an unprivileged user (UID 1000) with no direct gateway to the internet.
2. **Egress Gateway (`<name>-egress`)**: Acts as the sole network gateway for the cage. It runs `tini` as PID 1 supervising two unprivileged processes:
   - `dnsmasq` (UID 201): Local DNS server enforcing domain allowlists and sinkholing unauthorized names.
   - `mitmdump` (UID 200): TLS-intercepting proxy running custom agentcage addons (`addon.py`), inspector chains, and the internal Policy API.

```
┌─────────────────────────── HOST MACHINE ───────────────────────────────────────────┐
│                                                                                    │
│  State & Configuration:                                                            │
│  ~/.config/agentcage/cages/<name>/                                                 │
│    ├── cage.yaml            (Declarative source of truth)                          │
│    ├── proxy-config.yaml    (Derived configuration for proxy addon)                │
│    ├── dns-allowlist.conf   (Generated dnsmasq zone directives)                    │
│    └── creds/*.cred         (Encrypted credentials via systemd-creds / Keychain)   │
│                                                                                    │
│  ~/.local/share/agentcage/<name>/                                                  │
│    ├── capture/capture.jsonl(Full HTTP payload capture)                            │
│    ├── audit.jsonl          (Structured L7 decision log)                           │
│    └── grants/              (Runtime domain overlay files)                         │
│                                                                                    │
│  ┌───────────── Private Bridge Network: <name>-net (Internal=true) ────────────┐   │
│  │                                                                             │   │
│  │   ┌──────────────────────────┐          ┌────────────────────────────────┐  │   │
│  │   │  WORKLOAD SANDBOX (cage) │          │  EGRESS GATEWAY (egress)       │  │   │
│  │   │  Static IP: 10.89.X.2    │          │  Static IP: 10.89.X.10         │  │   │
│  │   │                          │          │                                │  │   │
│  │   │  Agent Workload          │  DNS/53  │  tini (PID 1)                  │  │   │
│  │   │  • UID 1000 (workload)   │─────────▶│   ├── dnsmasq (UID 201)        │  │   │
│  │   │  • Capabilities: DROPPED │          │   │    allowlisted → upstream  │  │   │
│  │   │  • no_new_privileges     │          │   │    blocked → 198.51.100.1  │  │   │
│  │   │  • Read-only rootfs      │  TCP     │   │                            │  │   │
│  │   │  • Pivot masks on .git   │─────────▶│   └── mitmdump (UID 200)       │  │   │
│  │   │                          │          │        :8080 regular proxy     │  │   │
│  │   │  Decoy Placeholders:     │          │        :8443 transparent       │  │   │
│  │   │  agentcage:secret:KEY:…  │          │              (iptables REDIRECT│  │   │
│  │   │                          │          │                                │  │   │
│  │   │  Mounted CA Public Cert: │          │   addon.py                     │  │   │
│  │   │  /certs/ca-cert.pem      │          │   ├── Inspector Chain          │  │   │
│  │   └──────────────────────────┘          │   │   (domain, secrets, entropy│  │   │
│  │                │                        │   │    content-type, body-size)│  │   │
│  │                │ Default Gateway via    │   │   ├── Secret Wire Injector │  │   │
│  │                └──────▶ 10.89.X.10      │   │   ├── Response Redactor    │  │   │
│  │                                         │   │   ├── Policy API (:443)    │  │   │
│  │                                         │   │   ├── Traffic Watcher      │  │   │
│  │                                         │   │   └── Protocol Relays      │  │   │
│  │                                         └───────────────┬────────────────┘  │   │
│  └─────────────────────────────────────────────────────────│───────────────────┘   │
│                                                            │ iptables:             │
│                                                            │  FORWARD policy DROP  │
│                                                            │  IPv6 FORWARD DROP    │
└────────────────────────────────────────────────────────────│───────────────────────┘
                                                             ▼
                                                     INTERNET / UPSTREAM
                                                  (Allowlisted domains only)
```

---

## 1. Network Isolation & Routing

### A. The Internal Bridge (`Internal=true`)
On Linux and Lima, agentcage creates an isolated Podman bridge network configured with `Internal=true`. Podman does not attach a default NAT gateway or host bridge forwarding rules to this network. As a result, containers on this network have **no inherent route to the host or internet**.

### B. Gateway Routing
The workload container is provisioned with a default gateway pointing directly to the IP of the egress container (`10.89.X.10`). Because the workload container lacks `CAP_NET_ADMIN` and `CAP_NET_RAW`, it cannot alter its routing table or assign alias IP addresses.

### C. Default-Deny L4 Packet Filtering
The egress container manages kernel netfilter rules via `iptables`:
- **Default Policy**: Both `iptables -P FORWARD DROP` and `ip6tables -P FORWARD DROP` are set on container startup.
- **Port Allowlist**: Only TCP ports explicitly declared in `cage.yaml` (`ports.tcp.allow`, default `[80, 443]`) are permitted through the forwarding chain.
- **Protocol Blocking**: Raw UDP and ICMP traffic is blocked by default unless `ports.udp.allow` or `ports.icmp.allow` are enabled.
- **Transparent Redirection**: Outbound TCP traffic targeting ports 80 and 443 is redirected to the local proxy:
  ```bash
  iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-ports 8080
  iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-ports 8443
  ```

---

## 2. DNS Filtering & Sinkholing

DNS resolution inside the cage is handled by `dnsmasq` running inside the egress container.

### A. Upstream DNS vs. Sinkhole Resolution
- **Upstream Resolution**: For domains present in the allowlist (or active runtime grants), `dnsmasq` forwards queries to upstream resolvers (auto-detected from host `/etc/resolv.conf`, excluding local loopback stubs like `127.0.0.53`).
- **TEST-NET-2 Sinkholing**: For any domain not in the allowlist, `dnsmasq` responds with `198.51.100.1` (RFC 5737 TEST-NET-2 dummy IP).

### B. Why Sinkholing Instead of NXDOMAIN?
If an unapproved domain returned `NXDOMAIN`, agent HTTP clients would immediately fail with DNS lookup errors, obscuring whether the domain was invalid or blocked by policy. 

By resolving unapproved domains to `198.51.100.1`:
1. The agent client establishes a TCP connection to `198.51.100.1:443`.
2. The packet is redirected to `mitmdump`.
3. The proxy inspects the request and responds with a standard `403 Forbidden` containing structured explanation headers (`x-agentcage-decision: blocked`).
4. This ensures LLM agents recognize that access was denied by policy and allows them to request access via the Policy API.

### C. Anti-Evasion DNS Protections
The DNS engine rejects:
- **IP Literals**: Raw IP addresses are rejected; agents must reference hosts by name.
- **Encoded IP Wildcards**: Domains that embed private IP addresses (e.g., `169-254-169-254.nip.io` or `10.0.0.1.sslip.io`) are parsed and blocked via `_encoded_private_ip()`, preventing SSRF against cloud metadata or private LAN services.

---

## 3. Transparent TLS Interception

### A. Per-Cage Certificate Authority
During cage initialization (`agentcage cage create`), agentcage generates a dedicated 4096-bit RSA Certificate Authority (CA) specific to that cage:
- The private key stays inside the egress container filesystem and is never shared.
- The public certificate is mounted read-only into the workload container at `/certs/mitmproxy-ca-cert.pem`.
- Environment variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) point to this certificate, enabling Node.js, Python, curl, and git to verify intercepted TLS without certificate warnings.

### B. Strict SNI ↔ Host Matching
To prevent domain-fronting attacks (where an attacker supplies an allowlisted domain in TLS SNI but requests a malicious host in the HTTP `Host` header), the proxy enforces strict equality between TLS Server Name Indication and the L7 HTTP `Host` header. Any mismatch terminates the connection with a 403.

### C. DNS Rebinding Protection
Before connecting upstream, the proxy resolves the target domain and verifies that the peer IP address is globally routable. If a domain attempts to resolve to an RFC 1918 private address (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or loopback, the connection is aborted immediately.

---

## 4. The Proxy Addon Pipeline

The core L7 inspection logic lives in `src/agentcage/data/proxy/addon.py`, implemented as a custom mitmproxy addon.

```
Incoming Request (Redirected from iptables)
       │
       ▼
[ Strict SNI ↔ Host Check ] ──(Mismatch)──▶ [ 403 Forbidden ]
       │
       ▼
[ Token-Bucket Rate Limiter ] ──(Exceeded)──▶ [ 429 Too Many Requests ]
       │
       ▼
[ Peer IP Verification ] ──(Private IP)──▶ [ Abort / Block ]
       │
       ▼
[ Off-Loop Worker Thread: Inspector Chain ]
  ├── domain: verify allowlist & runtime grants
  ├── secrets: detect unredacted raw API keys
  ├── entropy: detect high-entropy binary blobs
  ├── content-type: check MIME consistency
  └── body-size: enforce maximum body limits
       │
       ▼
[ Secret Injection ]
  Replace `agentcage:secret:NAME:<hex>` ──▶ Real API Key (Outbound wire only)
       │
       ▼
[ Forward Upstream ] Over verified TLS
       │
       ▼
[ Inbound Response Redactor ]
  Replace real API Key in body/headers ──▶ `agentcage:secret:NAME:<hex>`
       │
       ▼
[ Write audit.jsonl & capture.jsonl ]
```

### A. Threaded Execution
Mitmproxy runs on an asynchronous Python `asyncio` event loop. To ensure heavyweight inspections (such as Shannon entropy computation and regex secret scanning) do not stall concurrent traffic, the inspector chain executes inside a dedicated `ThreadPoolExecutor`.

### B. Zero-Leak Secret Injection & Reverse Redaction
Real secrets are injected only on outbound wire requests:
1. The proxy matches the outbound domain against declared `inject_to` rules in `cage.yaml`.
2. Placeholders are swapped for real credentials exclusively within credential-bearing headers (`Authorization`, `x-api-key`, etc.) or configured body fields.
3. Inbound responses from the server are passed through a streaming regex replacer that replaces any echoed secret back into its placeholder before the response enters the workload container.

---

## 5. Systemd Quadlets & Supervisor Architecture

### A. Linux Quadlet Generation
On Linux, agentcage generates native systemd user quadlets under `~/.config/containers/systemd/`:
- `<name>-net.network`: Defines the bridge network with `Internal=true`.
- `<name>-egress.container`: Defines the egress proxy container, capabilities (`NET_ADMIN`), and volume mounts.
- `<name>-cage.container`: Defines the workload sandbox container, binding `/workspace` and dropping all privileges.

Systemd manages container lifecycles, health restarts (`Restart=on-failure`), dependency ordering (`After=<name>-egress.service`), and log aggregation in `journalctl`.

### B. macOS Supervision
- **Apple Container (`apple-container`)**: Runs two lightweight microVMs managed by a unified agentcage supervisor and launchd daemon.
- **Lima VM (`vm`)**: Runs a dedicated Lima virtual machine running rootless Podman and quadlets internally, isolating macOS hosts through hardware hypervisor boundaries.

---

## 6. Live-Reload Seams

agentcage allows operators and agents to modify policies without restarting running cages:

| Component | Modification Seam | Mechanism | Restart Required? |
| :--- | :--- | :--- | :--- |
| **Domain Allowlists** | `agentcage domain add/rm` | Rewrites `dns-allowlist.conf` and sends `SIGHUP` to `dnsmasq`. | **No** (Instant) |
| **Runtime Grants** | Policy API `POST /v1/allowlist/requests` | Writes timestamped JSON grant to `grants/` directory. Proxy reloads in-memory cache. | **No** (Sub-second) |
| **Secret Updates** | `agentcage secret set` | Stores updated secret on host and notifies proxy addon via IPC reload file. | **No** (Zero-restart) |
| **Inspector Config** | `agentcage cage edit` | Updates `proxy-config.yaml` and signals mitmproxy addon via flag file. | **No** (Hot reload) |
| **Image / Mounts** | `agentcage cage update` | Full container rebuild and quadlet regeneration. | **Yes** |

---

## Next Steps

- **[Isolation Backends](isolation-backends.md)** — Compare `container`, `apple-container`, and `vm`.
- **[Security Model](security-model.md)** — Review the 8-layer defense-in-depth model and residual risks.
- **[Policy API Architecture](policy-api.md)** — Explore autonomous decider agents and dynamic egress.
