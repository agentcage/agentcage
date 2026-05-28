# Security & Threat Model

agentcage is a defense-in-depth proxy sandbox designed to reduce the risk of data exfiltration from AI agent containers. It is not a silver bullet -- it raises the bar significantly for HTTP-based exfiltration while acknowledging limitations outside that scope.

For architecture details, see [Architecture](explain/architecture.md). For configuration options, see [Configuration Reference](reference/configuration.md).

## Threat Model

### Isolation modes and the threat surface

agentcage offers three isolation modes that affect the threat model differently:

**Container mode** (Linux default) — The agent runs in a rootless Podman container with hardened defaults (read-only rootfs, all capabilities dropped, no-new-privileges). Network isolation is enforced by Podman's internal network. This provides strong defense against HTTP-based exfiltration, but all containers share the host kernel. A container escape via a kernel or runtime CVE is out of scope for this mode.

**VM mode** — The same container topology runs inside a Lima VM with a dedicated guest kernel, isolated by KVM hardware virtualization. This brings "kernel or container escapes" **into scope** as a defended threat: an escape from the container lands inside the VM, not on the host. The host sees only the Lima VM process.

**apple-container mode** (macOS 26+ Apple Silicon default, new in 0.20) — Each cage runs in a single Apple `container` microVM with its own kernel (hypervisor boundary via Apple's Virtualization.framework). The supervisor inside the microVM stands up mitmproxy + dnsmasq + iptables, installs the proxy CA into the cage's trust store, then drops to uid 1000 / zero caps / NoNewPrivs before exec'ing the cage workload. Functionally equivalent to VM mode on every threat where it matters, with one documented trade-off: there is no second backstop network layer (Lima's `<cage>-net` is non-routed; Apple custom networks always have NAT). The cage's iptables — which the cage workload cannot mutate (CAP_NET_ADMIN dropped) — is the sole defense rather than the second layer.

| Threat | Container mode | VM mode | apple-container mode |
|---|---|---|---|
| HTTP/HTTPS exfiltration | Defended (proxy inspection) | Defended (same) | Defended (in-microVM proxy + addon allowlist) |
| Secret leakage | Defended (injection + scanning) | Defended (same) | **Partial** — egress filter + MITM in place; server-side `{{SECRET:...}}` injection deferred (v1 ships filter only) |
| Unauthorized API calls | Defended (domain filtering) | Defended (same) | Defended (mitmproxy addon 403s non-listed hosts) |
| DNS exfiltration | Partially defended (placeholder IPs) | Partially defended (same) | Partially defended (cage's only DNS path is local dnsmasq) |
| Container/runtime escape | **Out of scope** (shared kernel) | Defended (VM boundary) | Defended (microVM boundary) |
| Kernel exploit | **Out of scope** (shared kernel) | Defended (guest kernel) | Defended (microVM kernel) |
| Side-channel attacks | Out of scope | Out of scope | Out of scope |

### Isolation modes

| | Container mode | VM mode | apple-container mode |
|---|---|---|---|
| **Isolation** | Linux namespaces (rootless Podman) | Hardware virtualization (KVM via Lima) | Hardware virtualization (Virtualization.framework, Apple `container` per cage) |
| **Kernel** | Shared with host | Dedicated guest kernel per cage | Dedicated microVM kernel per cage |
| **Container escape risk** | Mitigated by hardening, not eliminated | Eliminated — escape lands in VM, not on host | Eliminated — escape lands in microVM, not on host |
| **Egress defense layers** | iptables-in-cage + non-routed `<cage>-net` (two) | iptables-in-cage + non-routed `<cage>-net` (two) | iptables-in-cage only (one; CAP_NET_ADMIN dropped so cage can't bypass) |
| **Root required** | No | No (Lima handles VM networking) | No (Apple's `container` is rootless) |
| **macOS support** | No (use VM or apple-container) | Yes (Lima supports macOS) | macOS 26+ Apple Silicon only |
| **User image constraint** | Any glibc-or-musl Linux | Any (built inside the VM) | Glibc-based (debian/ubuntu/etc) — mitmproxy bundle is glibc-only |
| **Boot overhead** | ~1s | ~15–30s | ~3–5s warm, ~25–30s cold |
| **Best for** | Development, CI on Linux | Production, untrusted agents, high-security | Fast iteration on macOS 26+; default macOS path |

Set `isolation: vm` or `isolation: apple-container` explicitly in your config to override the platform default. See [Isolation modes](explain/isolation-modes.md) for how each backend works and [Install](get-started/install.md) for setup.

### What agentcage prevents

The primary threat is an AI agent exfiltrating sensitive data -- secrets, source code, environment variables -- via HTTP requests. This covers both intentional exfiltration (a compromised or misaligned agent deliberately sending secrets to an attacker-controlled server) and accidental leakage (an agent including sensitive context in API calls it wasn't supposed to make).

### In scope

- **HTTP/HTTPS exfiltration** -- secrets or sensitive data sent in request bodies, headers, or URLs
- **Accidental secret leakage** -- secrets inadvertently included in outbound requests
- **Unauthorized API calls** -- requests to domains not on the allowlist
- **Encoded payload smuggling** -- base64-encoded or compressed data hiding exfiltrated content in seemingly normal requests
- **WebSocket exfiltration** -- secrets or high-entropy data sent via WebSocket frames after the initial handshake

### Out of scope

- **Non-HTTP protocols** -- TCP/UDP connections other than HTTP (blocked by network isolation, but not inspected)
- **DNS exfiltration** -- data encoded in subdomain labels of allowlisted domains (blocked for non-allowlisted domains; see Known Limitations)
- **Kernel or container escapes (container mode)** -- exploits that break out of the Podman container via kernel or runtime vulnerabilities. In VM mode, these are contained by the VM boundary (see Isolation modes above).
- **Side-channel attacks** -- timing-based or resource-usage-based data leakage
- **Multi-request evasion** -- splitting secrets across many small requests to avoid pattern matching
- **Confused deputy / prompt injection** -- an agent tricked into exfiltrating data through legitimate-looking requests to allowed domains

## Defense Layers

agentcage applies multiple overlapping defenses:

1. **Network isolation** -- The agent container is on a Podman `--internal` network with no internet gateway. The only path to the internet is through the mitmproxy container. Published ports are served by the proxy container via mitmproxy reverse mode, so both inbound and outbound HTTP traffic passes through the inspector chain. This is enforced at the network level and cannot be bypassed by the agent process. In VM mode, the network isolation has an additional layer: all container traffic is confined within the Lima VM's guest network stack.

2. **Domain filtering** -- An allowlist or blocklist controls which domains the agent can reach. Non-matching requests receive a 403 response with a JSON body explaining the block. Subdomains are matched automatically.

3. **DNS filtering** -- When using allowlist mode, the dnsmasq sidecar returns a placeholder IP (198.51.100.1, RFC 5737 TEST-NET-2) for non-allowlisted domains, preventing DNS resolution from reaching real infrastructure while keeping SSRF guards functional. DNS query logging is enabled by default for forensic analysis.

4. **Secret injection** -- When configured, the cage container never receives real secrets. It gets placeholder tokens (e.g. `{{ANTHROPIC_API_KEY}}`), and the proxy transparently injects real values on outbound requests and redacts them from inbound responses. Inspectors run on the pre-injection flow (with placeholders still in place), so real secret values are never exposed to the inspector chain. Two policy checks enforce this boundary: if a **literal real secret value** appears in any outbound request or WebSocket frame, the request is blocked (severity `critical`) — the agent should never know real values; if a **placeholder** is sent to a domain not in the rule's `inject_to` list, the request is flagged. See [Secret injection](reference/secret-injection.md).

   For credentials that must be exchanged in-process for a derived value before any HTTPS request (e.g. signing a JWT bearer assertion with a Google service-account private key), `secret_injection` rules can be configured with a `transform`. The proxy holds the underlying credential, mints the derived value at request time, and substitutes it on the wire. The cage never sees the long-lived credential. The literal-value block is *strengthened* for transform rules — the underlying secret is never expected to legitimately appear on the wire to anywhere, including the rule's own `inject_to` domains, so any appearance is blocked unconditionally. See [Transforms](reference/secret-injection.md#transforms).

   For non-HTTP protocols (IMAP, SMTP), the equivalent property is provided by [Protocol relays](reference/protocol-relays.md) — stateful in-proxy listeners that perform upstream auth on the cage's behalf. The cage connects to a localhost address inside the proxy container with no credentials; the relay holds the upstream password in its own memory only. Per-protocol policy enforces things the HTTP injection model handles by domain. IMAP: `readonly` blocks state-mutating commands; `folder_allowlist` restricts SELECT/EXAMINE/STATUS targets. SMTP: `recipient_allowlist` (addresses + domains) gates every `RCPT TO`, `sender_allowlist` gates `MAIL FROM`, and every `DATA` payload runs through the same inspector chain (`secrets`, `entropy`, `content-type`, `body-size`) used for HTTP — so a leaked API key in an outbound email body blocks the message before it reaches the upstream MTA.

5. **Secret detection** -- 19 regex patterns scan every request for common secret formats: OpenAI, Anthropic, AWS, GitHub, Google, Slack, Stripe, GitLab, Hugging Face, Databricks, Azure JWT, OpenRouter, Perplexity, Brave, Telegram, Discord, and Firecrawl tokens, plus private keys. Matches result in a hard block by default. Built-in `allow_to_domains` mappings automatically let each secret type reach its provider domain (e.g., an Anthropic key to `anthropic.com`) without manual configuration. Custom patterns can be added via `extra_patterns` config, including env-var-based literal matching.

6. **Payload inspection** -- Inspectors analyze request bodies for anomalies (default action: block):
   - **Entropy analysis** detects encrypted or compressed payloads that may hide exfiltrated data
   - **Content-type mismatch** detection catches text requests with suspiciously high entropy
   - **Base64 blob scanning** catches encoded data embedded in otherwise normal requests
   - **Body size limiting** rejects requests exceeding a configurable threshold (default 10 MiB)

7. **WebSocket inspection** -- After the initial HTTP upgrade handshake is approved, all subsequent WebSocket frames are inspected by the full inspector chain (secrets, entropy, content-type). Frames that trigger a block are dropped.

8. **Rate limiting** -- Per-host token-bucket rate limiter (enabled by default: 10 req/s, burst 50) prevents request flooding and timing-based evasion. Configure via `rate_limit.requests_per_second` and `rate_limit.burst`.

9. **Custom inspectors** -- User-defined Python inspectors can implement arbitrary detection logic, extending the chain with domain-specific rules. Custom inspector paths are validated against an allowed directory list to prevent arbitrary code loading.

10. **Audit logging** -- All inspection decisions (blocked, flagged, and allowed requests) are written as structured JSON lines to a persistent audit log file (`/var/log/agentcage/audit.jsonl` by default). Allowed request logging is disabled by default.

## Fail-Closed Design

If the proxy container goes down, the agent gets connection errors -- not unfiltered internet access. Since the agent has no internet gateway, a proxy failure means no connectivity at all.

The generated quadlet files use systemd `Restart=on-failure` so the proxy recovers automatically from transient failures.

## Container Hardening

The cage container is hardened by default: read-only root filesystem, all Linux capabilities dropped, no-new-privileges flag set. See the [Configuration Reference](reference/configuration.md#container-hardening) for details and how to adjust these settings.

The DNS sidecar runs as a non-root `dnsmasq` user with only `NET_BIND_SERVICE` capability (set via `setcap` at build time). The proxy container runs as the `mitmproxy` user and binds only to the internal network IP (not 0.0.0.0).

### Nested containers (`nested_containers: true`)

When nested container support is enabled, several hardening defaults are overridden to allow podman-in-podman:

| Default | With `nested_containers: true` |
|---|---|
| `DropCapability=ALL` | 16 capabilities added (SYS_ADMIN, SYS_CHROOT, etc.) |
| `NoNewPrivileges=true` | `false` (required for setuid helpers) |
| `User=1000:1000` | `User=0` (root in user namespace) |
| seccomp profile active | `seccomp=unconfined` |

These changes increase the container escape attack surface. All network-level protections (proxy inspection, domain filtering, secret detection, DNS filtering) remain fully active. Inner containers default to `--network none` with no network access.

`nested_containers` is only supported with `isolation: container`. For production nested workloads, consider running the cage on a dedicated host or VM to limit blast radius.

## Supply Chain Hardening

- **Container base images** are pinned to specific `sha256` digests in the Containerfiles, preventing silent upstream changes
- **Python dependencies** (pyyaml) are pinned to exact versions
- **Patch files** (nested container support) are re-copied from package data on every cage create, update, and reload
- **Custom inspector paths** are validated against an allowed directory list (default: `/etc/agentcage/inspectors/`)
- **Cage names** are validated against `^[a-z0-9][a-z0-9-]{0,62}$` to prevent shell injection in generated systemd units
- **Jinja2 templates** use `SandboxedEnvironment` to prevent template injection
- **Volume host paths** are validated to resolve within the user's home directory
- **Proxy config isolation** -- the proxy container receives a filtered config subset containing only proxy-relevant keys, not the full YAML

## OWASP Top 10 for Agentic Applications (2026)

| OWASP Risk | agentcage Coverage | Residual Gaps |
|---|---|---|
| **ASI01 Agent Goal Hijack** | Out of scope — agentcage inspects network traffic, not agent intent | Correctly scoped |
| **ASI02 Tool Misuse** | Strong — domain allowlist + WebSocket inspection + DNS filtering limit which services agents can reach | Multi-request evasion, DNS subdomain exfiltration, allowed-domain data smuggling |
| **ASI03 Identity/Privilege Abuse** | Strong — secret injection prevents agent from holding real secrets; inspectors see only placeholders | — |
| **ASI04 Supply Chain** | Strong — pinned image digests, pinned deps, lockfile integrity, patch file verification, inspector path validation | Agent can install arbitrary packages from allowlisted registries |
| **ASI05 Code Execution** | Strong — read-only root, dropped caps, no-new-privileges; custom inspector paths restricted to allowed directories | — |
| **ASI06 Memory Poisoning** | Not applicable — agentcage doesn't manage agent memory | Named volumes persist across sessions (design choice) |
| **ASI07 Inter-Agent Comms** | Not applicable — single-agent scope | — |
| **ASI08 Cascading Failures** | Strong — fail-closed on proxy down, systemd restart, per-host rate limiting | — |
| **ASI09 Human Trust** | Strong — persistent structured audit logging with all decisions logged by default | — |
| **ASI10 Rogue Agents** | Strong — network isolation + multi-layer inspection + DNS filtering + WebSocket inspection | Multi-request evasion, confused-deputy via allowed domains |

## Known Limitations

**Multi-request evasion** -- An agent could split a secret across many requests to avoid regex matching. The entropy and content-type inspectors help catch encoded exfiltration, but are not foolproof against sophisticated splitting strategies. The GTG-1002 campaign demonstrated that AI agents can autonomously develop multi-step exfiltration strategies where each individual request appears legitimate.

**Proxy-unaware applications** -- In container mode, transparent proxy interception (default route + iptables REDIRECT) captures outbound TCP traffic on the inspected port set (`ports.tcp.allow - ports.tcp.passthrough`, default `[80, 443]`) regardless of whether the application uses `HTTP_PROXY` env vars. This covers Go, Rust, Node.js `fetch()`, and any other runtime. Applications using ports outside the configured policy are dropped at the proxy's default-deny `filter:FORWARD` rule — the security guarantee holds (no unfiltered internet access; the cage cannot reach a port the operator hasn't permitted), but the error is a connection timeout rather than a 403 response. UDP traffic on `ports.udp.allow` ports is forwarded uninspected (mitmproxy is HTTP-only). See [Port policy](reference/ports.md) for the full discussion.

  In VM mode, transparent interception is not yet implemented, so proxy-unaware applications get connection errors for all ports. The same security guarantee applies — requests fail rather than bypass inspection.

**DNS-based exfiltration** -- In allowlist mode, dnsmasq returns a placeholder IP (198.51.100.1, RFC 5737 TEST-NET-2) for non-allowlisted domains, blocking direct DNS exfiltration. However, an agent with code execution can encode data in subdomain labels of *allowlisted* domains (e.g. `<encoded-data>.cdn.jsdelivr.net`). These queries are forwarded to the upstream resolver, which recursively resolves them — potentially reaching an attacker's authoritative nameserver if they control a subdomain delegation. Each DNS query can carry ~253 bytes; practical exfiltration rates of 10-50 KB/s are achievable. Mitigations include monitoring dnsmasq query logs for high-entropy subdomain labels and enabling rate limiting.

**Exfiltration through allowed domains** -- The domain allowlist prevents direct exfiltration to attacker infrastructure, but data can be smuggled through *allowed* endpoints. For example, an agent could embed secrets in GitHub issue titles, Brave Search query parameters, or npm package metadata. The secrets inspector detects known secret patterns in URLs, but custom-encoded data in URL paths and query parameters is not subject to entropy analysis (only request bodies are). Rate limiting and audit log monitoring help bound this channel.

**Published port limitations** -- Published ports (`container.ports` config option) are served through mitmproxy reverse mode, so HTTP traffic is inspected by the full inspector chain. However, non-HTTP protocols (raw TCP, WebSocket upgrade on non-standard ports) will fail at HTTP parsing. Container ports 8080 and 8443 cannot be published as they conflict with the forward proxy and transparent proxy listeners respectively. The same reserved-port check rejects `ports.tcp.allow` overlap with any inbound forward port — see [Port policy](reference/ports.md#reserved-ports).

**Supply chain poisoning** -- The agent can install arbitrary packages from allowlisted registries (npm, PyPI, etc.). A prompt injection could direct the agent to install a malicious package that runs code inside the container. Container hardening (read-only root, dropped caps, no-new-privileges) limits the impact but does not prevent data access within the agent's workspace. Consider pre-approved package lists for high-security deployments.

**Shared kernel (container mode only)** — In container mode, rootless Podman containers share the host kernel. A container escape CVE in the Linux kernel, runc, or crun would bypass all container-level protections and give the agent access to the host. This is the most significant limitation of container mode.

VM mode eliminates this limitation. Each cage runs in a dedicated Lima VM with its own guest kernel, isolated by KVM hardware virtualization (VT-x/AMD-V). A kernel exploit inside the VM affects only the guest kernel, not the host. A container escape inside the VM lands in the VM's userspace, not on the host. Set `isolation: vm` to use this mode. See [Isolation modes](explain/isolation-modes.md) for the comparison across backends.

## Traffic Capture and HAR Export

When `capture: enable_har: true` is set, the proxy records full decrypted request/response bodies to a JSONL file. This data is exported via `agentcage cage har`.

### OUTBOUND captures contain real secrets

The OUTBOUND perspective records what actually went on the wire, including real API keys, tokens, and session cookies after secret injection. OUTBOUND HAR files must be treated with the same access controls as the secrets themselves.

- The default `--view` is `inbound` (safe perspective with placeholders)
- The CLI prints a warning to stderr when exporting with `--view outbound`
- The capture volume has the same ownership/permissions as the podman user (not world-readable)

### INBOUND captures may contain sensitive content

Even INBOUND captures (with secrets replaced by placeholders) may contain PII, user queries, model responses, or other sensitive content in request/response bodies. Handle HAR files under the same data governance as the agent's operational data. The Okta breach (2023) is a cautionary reference — HAR files uploaded to support portals led to session hijacking of 134 customers.

### Disk exhaustion risk

With `min_action: all` and heavy traffic, the capture JSONL grows indefinitely. Mitigations:
- `max_body_size` truncates bodies (default 10 MB per body)
- `domains` filter limits which hosts are recorded
- `min_action: flag` or `min_action: block` reduces capture volume
- Periodically truncate or archive the capture file for long-running deployments

### Capture file integrity

The capture file is plain JSON lines on disk. An attacker with host access could modify entries. For forensic chain of custody, hash the file at export time (`sha256sum capture.jsonl`). Per-entry HMAC or signed HAR wrappers are a potential follow-up.

### Same trust boundary as podman secrets

The capture volume is accessible to the host user running podman. This is the same trust boundary as podman secrets — if an attacker has access to the host user's files, they already have access to the secrets.

## Secret Backend Trust Boundaries

The `source` field in `secret_injection` rules supports a `cmd:` scheme that executes shell commands to retrieve secrets. This runs with the privileges of the user invoking agentcage, the same trust boundary as Containerfile execution or volume mounts.

If a `cage.yaml` is sourced from an untrusted location (e.g. a public git repository), review all `source: "cmd:..."` entries before running `cage create`. A malicious config could execute arbitrary commands on the host.

The `env:` backend reads from the host's environment variables. No shell execution is involved.

The `systemd-creds:` backend encrypts secrets at rest with AES256-GCM, keyed by a combination of a TPM2 chip and a host-specific key. Encrypted blobs are bound to the machine's hardware. A motherboard swap, TPM reset, or BIOS update may render encrypted secrets unrecoverable. Use `agentcage cage backup --include-secrets` to create portable backups.

## Reporting Security Issues

Please report security vulnerabilities via email to **security@agentcage.ai**. Do not open a public GitHub issue for security vulnerabilities. See [SECURITY.md](../SECURITY.md) for details.
