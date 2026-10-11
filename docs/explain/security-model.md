# Security Model & Threat Analysis

agentcage is a defense-in-depth security harness designed for running untrusted, autonomous AI coding agents.

This document describes the threat model, the eight protective security layers, the fail-closed design, trust boundaries, and known residual risks.

---

## 1. Threat Model

### A. What We Assume About the Agent
We assume the agent process is **actively compromised or malicious**:
- **Prompt Injection**: The agent will read untrusted text (from GitHub issues, pull request diffs, scraped websites, or npm dependencies) containing indirect prompt injections attempting to hijack its execution.
- **Rogue Dependencies**: The agent will execute code that installs malicious packages containing obfuscated telemetry, credential stealers, or reverse shells.
- **Hallucinatory Operations**: The agent may hallucinate destructive commands or query sensitive internal network resources.

### B. What We Assume About the Host
- The operator's host operating system and kernel are trustworthy prior to running the agent.
- The host user running agentcage is unprivileged (rootless).
- Host directories outside explicit volume mounts are inaccessible to the sandbox.

### C. Adversaries in Scope
| Adversary Class | Motivation & Attack Vectors |
| :--- | :--- |
| **Credential Harvesters** | Exfiltrating environment variables (`ANTHROPIC_API_KEY`, `AWS_ACCESS_KEY_ID`), git credentials, or SSH keys. |
| **Data Exfiltrators** | Uploading proprietary source code or intellectual property to attacker-controlled C2 servers. |
| **LAN / Cloud Pivoters** | Probing RFC 1918 internal subnets, local development services, or cloud instance metadata (`169.254.169.254`). |
| **Persistent Host Compromisers**| Planting malicious git hooks (`.git/hooks/`) or agent configs (`.claude/`) that trigger host execution when the operator works outside the cage. |

### D. Explicitly Out of Scope
- Compromise of the host machine prior to launching agentcage.
- Operator explicitly disabling security controls (e.g. running with `--as-root`, allowlisting a bare top-level domain such as `com`, or enabling broad passthrough).
- Malicious source code intentionally committed to your repository that is later reviewed, approved, and executed directly on the host by the operator.

---

## 2. The Eight Defense-in-Depth Layers

agentcage enforces eight independent defensive rings between the agent workload and external resources:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. NETWORK LAYER       Internal=true private bridge; iptables FORWARD DROP  │
│ 2. DNS LAYER           dnsmasq allowlist; TEST-NET sinkhole (198.51.100.1)   │
│ 3. PROXY IDENTITY      Strict SNI ↔ Host equality; anti-DNS rebinding guard │
│ 4. L7 INSPECTORS       Domain, secrets regex, Shannon entropy, content-type │
│ 5. SECRETS LAYER       128-bit decoy placeholders; wire injection; redaction│
│ 6. CONFINEMENT LAYER   UID 1000; drop ALL capabilities; no-new-privileges   │
│ 7. FILESYSTEM LAYER    Read-only rootfs; tmpfs pivot masks on .git/hooks    │
│ 8. AGENTIC LAYER       In-egress Decider Agent; background Traffic Watcher  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Layer 1: Network Confinement
- **Internal Network**: Workload containers attach to an unrouted Podman network (`Internal=true`).
- **Default-Drop Forwarding**: The egress container enforces `iptables -P FORWARD DROP` and `ip6tables -P FORWARD DROP`.
- **Protocol Drops**: Raw UDP, ICMP, and unapproved TCP ports are dropped at the packet filter level. Ports in `ports.tcp.allow` (default: 80, 443) are redirected to the egress proxy, except those also in `ports.tcp.passthrough`, which are forwarded uninspected.
- **Forward-proxy ports**: The forward proxy (`HTTPS_PROXY`) only connects to the same inspected ports. A `CONNECT host:22` is refused with a `403`, so the proxy cannot be used to reach a port the packet filter drops.

### Layer 2: DNS Filtering & Sinkholing
- **Strict Allowlist**: `dnsmasq` answers queries only for domains matching `domains.allow` or active runtime grants.
- **RFC 5737 Sinkhole**: Unauthorized domains resolve to `198.51.100.1` (TEST-NET-2). This guarantees that HTTP clients connect to the local proxy and receive clear `403 Forbidden` policy responses rather than ambiguous connection timeouts.
- **SSRF & Wildcard Prevention**: An IP literal never matches a domain allowlist, and names that encode a private address for a wildcard DNS service (e.g. `169-254-169-254.nip.io`) can never be granted at runtime.

### Layer 3: Proxy Identity & Rebinding Guards
- **Strict SNI ↔ Host Matching**: The proxy terminates TLS and verifies that the TLS SNI extension matches the HTTP `Host` header, defeating domain-fronting evasion.
- **Anti-Rebinding Check**: A host that is reachable only through a runtime grant is resolved before the connect, and refused if any answer is not globally routable (RFC 1918, loopback, link-local, CGNAT, ULA, IPv4-mapped forms). The proxy then connects to exactly the addresses it checked, so the name cannot re-resolve in between, and the host stays refused. Baseline entries are the operator's and may name LAN hosts.
- **Passthrough Pinning**: A `domains.passthrough` name is spliced uninspected only when the connection's real destination is an address that name resolves to. Sending a passthrough SNI to any other address gets the connection intercepted and inspected like any other.
- **Token-Bucket Rate Limiter**: Per-host rate limiting prevents denial-of-service or rapid brute-force attacks against upstream APIs.

### Layer 4: L7 Content Inspectors
Every HTTP request (and every WebSocket message the cage sends) passes through a chain of inspectors, run on worker threads so a large body never stalls other connections. The built-ins inspect requests only; responses are inspected only by custom inspectors that ask for them.
- **`domain`**: Enforces the allowlist (baseline plus runtime grants, with expiry) or the blocklist. Not applied to inbound (reverse-proxied) traffic.
- **`secrets`**: Scans the URL, headers and body for 20 built-in credential patterns plus `extra_patterns`; flags by default.
- **`body-size`**: Caps request bodies at `max_request_body` (10 MiB by default).
- **`entropy`** (opt-in): Blocks (by default) high-entropy bodies, query parameters and path segments that look like encrypted or encoded exfiltration.
- **`content-type`** (on by default): Blocks (by default) bodies that claim a text type but carry high-entropy or long base64 content.
- **Custom inspectors**: WebAssembly components loaded with no capabilities and a CPU and memory budget; see [Custom Inspectors](../how-to/custom-inspectors.md).

### Layer 5: Zero-Leak Placeholder Secrets
Real credentials never enter the workload sandbox:
- **Decoy Tokens**: The sandbox environment variable contains an entropic decoy string:
  ```text
  agentcage:secret:ANTHROPIC_API_KEY:4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
  ```
- **Wire Injection**: The proxy replaces this placeholder with the real secret **only** on outbound requests targeting the authorized domain (`inject_to`) and inside credential-bearing headers (`Authorization`, `x-api-key`).
- **Response Redaction**: The proxy redacts any real secret value (or a token a transform minted) back to its placeholder in responses, WebSocket messages, the capture file and every audit record, including its percent-encoded, JSON-escaped and base64 forms. Streamed responses are redacted as they stream.
- **Literal-Value Blocking**: A request that carries a real secret value to a host outside that secret's `inject_to` is blocked before anything is forwarded.
- **Encrypted At-Rest Storage**: Real credentials on the host are encrypted using `systemd-creds` (Linux TPM2 / host key) or the macOS Keychain.

### Layer 6: Process Confinement
- **Unprivileged User**: The agent workload executes as an unprivileged user (UID 1000).
- **Dropped Capabilities**: All Linux kernel capabilities are dropped (`drop_capabilities: [ALL]`), including `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_SYS_ADMIN`.
- **No New Privileges**: `no_new_privileges: true` prevents privilege escalation via `setuid` binaries.
- **User Namespaces**: On Linux, rootless Podman maps container UID 0 to an unprivileged host subuid, preventing host root compromise even in the event of a container breakout.

### Layer 7: Filesystem Isolation & Pivot Masks
- **Read-Only Root Filesystem**: The container root filesystem is mounted read-only (`read_only: true`), preventing agents from installing persistent backdoors or modifying system binaries.
- **Host Pivot Masks**: When binding a project directory to `/workspace`, agentcage automatically places tmpfs overlays over:
  - `/workspace/.git/hooks/`: Prevents the agent from writing executable git hooks that execute on your host during your next `git commit`.
  - `/workspace/.claude/`: Prevents the agent from tampering with host-level agent configuration files or memory dumps.
- **Isolated State**: The agent cannot access `~/.ssh`, `~/.aws`, or host configuration directories.

### Layer 8: Autonomous Policy & Auditing
- **In-Egress Policy API**: The agent can introspect reachable domains at `https://agentcage.local/v1/allowlist` and request dynamic egress via `POST /v1/allowlist/requests`.
- **Decider Agent**: A dedicated in-egress LLM adjudicates domain requests against technical justifications and security rules.
- **Traffic Watcher**: An asynchronous background LLM agent scans recent audit and HAR capture logs. If it detects suspicious patterns or beaconing, it can autonomously revoke runtime grants.

---

## 3. Fail-Closed Design

The egress is built so that a failure narrows egress rather than widening it:

- **Internal errors block.** A flow the egress cannot process (a body whose `Content-Encoding` cannot be removed, an injection that cannot be applied) gets a JSON `502` and an `internal_error` audit record. It is never forwarded unfiltered.
- **A bad config never goes live.** A config edit that does not parse, or whose inspector chain or rate limit cannot be built, is refused: the last good config stays live and one `config_reload_failed` record is written. A config that fails at boot makes the egress refuse every request until a good version lands.
- **Broken plugins block.** A custom inspector that traps, runs out of fuel or memory, or returns a malformed verdict counts as a `block`.
- **The decider fails to deny.** Any error, timeout or malformed answer from the Policy API's LLM decider is a denial, never a grant. The traffic watcher records a failed scan instead of a verdict, and never revokes on a failure.
- **Upstream failures are explicit.** A failed upstream is a JSON `502` with an `upstream_error` record, and a response that fails mid-stream cuts the client connection rather than ending it cleanly.
- **Memory is bounded per flow, not per process.** Request bodies have a per-body limit (`413`) and all buffered bodies share one budget (`503` when exhausted), so a burst of large transfers fails those transfers instead of the whole egress.

---

## 4. Trust Boundaries

| Component | Trust Level | Justification |
| :--- | :--- | :--- |
| **Agent Workload** | **Untrusted** | Assumed to be under active adversarial manipulation or prompt injection. |
| **Egress Gateway** | **Trusted (Hardened)** | Runs minimal, unprivileged proxy and DNS daemons; owns the network boundary. |
| **Host CLI & State**| **Trusted** | Operator-controlled; holds encrypted secrets and controls quadlet generation. |
| **Policy Decider** | **Semi-Trusted** | Autonomous LLM gatekeeper; can only grant temporary access, subject to rate limits. |
| **Traffic Watcher**| **Constrained** | Narrowing-only: can revoke dynamic grants, but cannot add new grants or alter baseline config. |

---

## 5. Known Residual Risks & Limitations

Transparency is a fundamental tenet of security engineering. agentcage documents the following known residual risks:

1. **Abuse of Allowlisted Domains**: If an agent is granted access to a domain with arbitrary upload endpoints (e.g. `github.com` or `pastebin.com`), it could potentially exfiltrate non-credential data (such as source code) within legitimate HTTP calls. *Mitigation: Restrict allowlists to minimal API endpoints; enable the Traffic Watcher.*
2. **Shared Linux Kernel (`container` backend)**: The Linux `container` backend relies on user namespaces. While robust, it shares the host kernel. *Mitigation: Use the `apple-container` (macOS) or `vm` (Lima) backends when strict hardware virtualization boundaries are required.*
3. **TLS Passthrough Blindspots**: Declaring domains under `domains.passthrough` tunnels raw TCP without terminating TLS. The egress cannot inspect payloads, inject secrets or capture anything in passthrough streams. *Mitigation: Use passthrough only for certificate-pinned endpoints that fail under custom CAs.*
4. **HAR Captures**: `capture.jsonl` records full request and response bodies. Both of its views (`cage har --view inbound` and `--view outbound`) hold every secret agentcage manages as its placeholder, the injected credentials included, but everything else is recorded as is: cookies, session tokens and any credential the agent holds itself. Captures recorded by agentcage 0.50.0 or earlier can also hold real secrets, in the `outbound` view (a server's echo of an injected secret, a token a transform minted) and in a blocked request's `inbound` view. *Mitigation: Review a capture before sharing it, and treat captures from 0.50.0 or earlier as sensitive.*
5. **Elevated Debug Flags**: Running `agentcage run --as-root` or setting `nested_containers: true` relaxes user namespace protections. These flags should only be used in isolated CI environments.

---

## 6. Security Hardening Checklist

When configuring production cages:

- [ ] Ensure `domains.allow` contains only specific, fully qualified hostnames (an entry also covers every subdomain, so avoid broad suffixes like `com` or `co.uk`).
- [ ] Verify that `container.read_only: true` is enabled.
- [ ] Do not mount sensitive host directories (never mount `~/.ssh`, `~/.aws`, or Docker sockets).
- [ ] Store secrets with `agentcage secret set` rather than placing cleartext in `cage.yaml`.
- [ ] Run `agentcage doctor` to verify that unprivileged user namespaces and lingering are active.
- [ ] Enable the `agents.watcher` block in `cage.yaml` to monitor background traffic anomalies.

---

## Reporting Vulnerabilities

If you identify a security vulnerability in agentcage, please report it privately according to the procedure in **[SECURITY.md](../../SECURITY.md)**.
