# Security & Threat Model

agentcage is a defense-in-depth proxy sandbox designed to reduce the risk of data exfiltration from AI agent containers. It is not a silver bullet -- it raises the bar significantly for HTTP-based exfiltration while acknowledging limitations outside that scope.

For architecture details, see [Architecture](architecture.md). For configuration options, see [Configuration Reference](configuration.md).

## Threat Model

### What agentcage prevents

The primary threat is an AI agent exfiltrating sensitive data -- API keys, credentials, source code, environment variables -- via HTTP requests. This covers both intentional exfiltration (a compromised or misaligned agent deliberately sending secrets to an attacker-controlled server) and accidental leakage (an agent including sensitive context in API calls it wasn't supposed to make).

### In scope

- **HTTP/HTTPS exfiltration** -- secrets or sensitive data sent in request bodies, headers, or URLs
- **Accidental secret leakage** -- API keys or credentials inadvertently included in outbound requests
- **Unauthorized API calls** -- requests to domains not on the allowlist
- **Encoded payload smuggling** -- base64-encoded or compressed data hiding exfiltrated content in seemingly normal requests
- **WebSocket exfiltration** -- secrets or high-entropy data sent via WebSocket frames after the initial handshake

### Out of scope

- **Non-HTTP protocols** -- TCP/UDP connections other than HTTP (blocked by network isolation, but not inspected)
- **DNS exfiltration** -- data encoded in subdomain labels of allowlisted domains (blocked for non-allowlisted domains; see Known Limitations)
- **Kernel or container escapes** -- exploits that break out of the Podman container
- **Side-channel attacks** -- timing-based or resource-usage-based data leakage
- **Multi-request evasion** -- splitting secrets across many small requests to avoid pattern matching
- **Confused deputy / prompt injection** -- an agent tricked into exfiltrating data through legitimate-looking requests to allowed domains

## Defense Layers

agentcage applies multiple overlapping defenses:

1. **Network isolation** -- The agent container is on a Podman `--internal` network with no internet gateway. The only path to the internet is through the mitmproxy container. This is enforced at the network level and cannot be bypassed by the agent process.

2. **Domain filtering** -- An allowlist or blocklist controls which domains the agent can reach. Non-matching requests receive a 403 response with a JSON body explaining the block. Subdomains are matched automatically.

3. **DNS filtering** -- When using allowlist mode, the dnsmasq sidecar returns a placeholder IP (198.51.100.1, RFC 5737 TEST-NET-2) for non-allowlisted domains, preventing DNS resolution from reaching real infrastructure while keeping SSRF guards functional. DNS query logging is enabled by default for forensic analysis.

4. **Secret injection** -- When configured, the cage container never receives real API keys or credentials. It gets placeholder tokens (e.g. `{{ANTHROPIC_API_KEY}}`), and the proxy transparently injects real values on outbound requests and redacts them from inbound responses. Inspectors run on the pre-injection flow (with placeholders still in place), so real secret values are never exposed to the inspector chain. Domain restrictions ensure placeholders are only injected to authorized services; sending a placeholder to an unauthorized domain is blocked. See [Secret injection](configuration.md#secret-injection-secret_injection).

5. **Secret detection** -- 19 regex patterns scan every request for common credential formats: OpenAI, Anthropic, AWS, GitHub, Google, Slack, Stripe, GitLab, Hugging Face, Databricks, Azure JWT, OpenRouter, Perplexity, Brave, Telegram, Discord, and Firecrawl tokens, plus private keys. Matches result in a hard block by default. Built-in `allow_to_domains` mappings automatically let each secret type reach its provider domain (e.g., an Anthropic key to `anthropic.com`) without manual configuration. Custom patterns can be added via `extra_patterns` config, including env-var-based literal matching.

6. **Payload inspection** -- Inspectors analyze request bodies for anomalies (default action: block):
   - **Entropy analysis** detects encrypted or compressed payloads that may hide exfiltrated data
   - **Content-type mismatch** detection catches text requests with suspiciously high entropy
   - **Base64 blob scanning** catches encoded data embedded in otherwise normal requests
   - **Body size limiting** rejects requests exceeding a configurable threshold (default 10 MiB)

7. **WebSocket inspection** -- After the initial HTTP upgrade handshake is approved, all subsequent WebSocket frames are inspected by the full inspector chain (secrets, entropy, content-type). Frames that trigger a block are dropped.

8. **Rate limiting** -- Optional per-host token-bucket rate limiter prevents request flooding and timing-based evasion. Configure via `rate_limit.requests_per_second` and `rate_limit.burst`.

9. **Custom inspectors** -- User-defined Python inspectors can implement arbitrary detection logic, extending the chain with domain-specific rules. Custom inspector paths are validated against an allowed directory list to prevent arbitrary code loading.

10. **Audit logging** -- All inspection decisions (blocked, flagged, and allowed requests) are written as structured JSON lines to a persistent audit log file (`/var/log/agentcage/audit.jsonl` by default). Allowed request logging is enabled by default for forensic completeness.

## Fail-Closed Design

If the proxy container goes down, the agent gets connection errors -- not unfiltered internet access. Since the agent has no internet gateway, a proxy failure means no connectivity at all.

The generated quadlet files use systemd `Restart=on-failure` so the proxy recovers automatically from transient failures.

## Container Hardening

The cage container is hardened by default: read-only root filesystem, all Linux capabilities dropped, no-new-privileges flag set. See the [Configuration Reference](configuration.md#container-hardening) for details and how to adjust these settings.

The DNS sidecar runs as a non-root `dnsmasq` user with only `NET_BIND_SERVICE` capability (set via `setcap` at build time). The proxy container runs as the `mitmproxy` user and binds only to the internal network IP (not 0.0.0.0).

## Supply Chain Hardening

- **Container base images** are pinned to specific `sha256` digests in the Containerfiles, preventing silent upstream changes
- **Python dependencies** (pyyaml) are pinned to exact versions
- **Node.js patch dependencies** (undici) use `npm ci` with a committed lockfile containing integrity hashes
- **Patch files** are re-copied from package data and SHA-256 verified on every cage create, update, and reload
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
| **ASI03 Identity/Privilege Abuse** | Strong — secret injection prevents agent from holding real credentials; inspectors see only placeholders | — |
| **ASI04 Supply Chain** | Strong — pinned image digests, pinned deps, lockfile integrity, patch file verification, inspector path validation | Agent can install arbitrary packages from allowlisted registries |
| **ASI05 Code Execution** | Strong — read-only root, dropped caps, no-new-privileges; custom inspector paths restricted to allowed directories | — |
| **ASI06 Memory Poisoning** | Not applicable — agentcage doesn't manage agent memory | Named volumes persist across sessions (design choice) |
| **ASI07 Inter-Agent Comms** | Not applicable — single-agent scope | — |
| **ASI08 Cascading Failures** | Strong — fail-closed on proxy down, systemd restart, per-host rate limiting | — |
| **ASI09 Human Trust** | Strong — persistent structured audit logging with all decisions logged by default | — |
| **ASI10 Rogue Agents** | Strong — network isolation + multi-layer inspection + DNS filtering + WebSocket inspection | Multi-request evasion, confused-deputy via allowed domains |

## Known Limitations

**Multi-request evasion** -- An agent could split a secret across many requests to avoid regex matching. The entropy and content-type inspectors help catch encoded exfiltration, but are not foolproof against sophisticated splitting strategies. The GTG-1002 campaign demonstrated that AI agents can autonomously develop multi-step exfiltration strategies where each individual request appears legitimate.

**Proxy-unaware applications** -- Applications that don't read `HTTP_PROXY` / `HTTPS_PROXY` get connection errors (blocked by network isolation) rather than 403 responses from the proxy. This applies to:
  - Node.js `http.request()` / `https.request()` (agentcage patches `globalThis.fetch` automatically, but not the lower-level APIs)
  - Go's `net/http` (does respect `HTTP_PROXY` by default)
  - Rust's `reqwest` (requires explicit proxy configuration)
  - Python's `urllib3` (does respect `HTTP_PROXY`, but `socket` does not)
  - Any npm library (axios, got, node-fetch) that doesn't respect env vars

  In all cases, the requests *fail* (blocked by network isolation) rather than bypass inspection. The security guarantee holds — the agent cannot reach the internet — but the error messages are connection timeouts rather than informative 403 responses.

**DNS-based exfiltration** -- In allowlist mode, dnsmasq returns a placeholder IP (198.51.100.1, RFC 5737 TEST-NET-2) for non-allowlisted domains, blocking direct DNS exfiltration. However, an agent with code execution can encode data in subdomain labels of *allowlisted* domains (e.g. `<encoded-data>.cdn.jsdelivr.net`). These queries are forwarded to the upstream resolver, which recursively resolves them — potentially reaching an attacker's authoritative nameserver if they control a subdomain delegation. Each DNS query can carry ~253 bytes; practical exfiltration rates of 10-50 KB/s are achievable. Mitigations include monitoring dnsmasq query logs for high-entropy subdomain labels and enabling rate limiting.

**Exfiltration through allowed domains** -- The domain allowlist prevents direct exfiltration to attacker infrastructure, but data can be smuggled through *allowed* endpoints. For example, an agent could embed secrets in GitHub issue titles, Brave Search query parameters, or npm package metadata. The secrets inspector detects known credential patterns in URLs, but custom-encoded data in URL paths and query parameters is not subject to entropy analysis (only request bodies are). Rate limiting and audit log monitoring help bound this channel.

**MCP server exposure** -- If a caged agent runs an MCP server (exposed via the `ports` config option), the MCP server is accessible on the internal network. agentcage doesn't inspect intra-network traffic.

**Supply chain poisoning** -- The agent can install arbitrary packages from allowlisted registries (npm, PyPI, etc.). A prompt injection could direct the agent to install a malicious package that runs code inside the container. Container hardening (read-only root, dropped caps, no-new-privileges) limits the impact but does not prevent data access within the agent's workspace. Consider pre-approved package lists for high-security deployments.

**Shared kernel** -- Rootless Podman containers share the host kernel. A container escape CVE in the Linux kernel or runc/crun would bypass all protections.

## Reporting Security Issues

Please report security issues via [GitHub Issues](https://github.com/agentcage/agentcage/issues).
