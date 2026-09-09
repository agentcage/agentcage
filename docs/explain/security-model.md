# Security Model & Threat Analysis

agentcage is a defense-in-depth security harness designed for running untrusted, autonomous AI coding agents.

This document describes the threat model, the eight protective security layers, trust boundaries, fail-closed design principles, and known residual risks.

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
- Operator explicitly disabling security controls (e.g. running with `--as-root`, adding `*` wildcards to allowlists, or enabling broad passthrough).
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
- **Protocol Drops**: Raw UDP, ICMP, and unapproved TCP ports are dropped at the packet filter level. Only ports declared in `ports.tcp.allow` (default: 80, 443) are forwarded to the proxy.

### Layer 2: DNS Filtering & Sinkholing
- **Strict Allowlist**: `dnsmasq` answers queries only for domains matching `domains.allow` or active runtime grants.
- **RFC 5737 Sinkhole**: Unauthorized domains resolve to `198.51.100.1` (TEST-NET-2). This guarantees that HTTP clients connect to the local proxy and receive clear `403 Forbidden` policy responses rather than ambiguous connection timeouts.
- **SSRF & Wildcard Prevention**: The resolver strips IP literals and blocks wildcard DNS domains encoding private IP addresses (e.g., `169-254-169-254.nip.io`).

### Layer 3: Proxy Identity & Rebinding Guards
- **Strict SNI ↔ Host Matching**: The proxy terminates TLS and verifies that the TLS SNI extension matches the HTTP `Host` header, defeating domain-fronting evasion.
- **Anti-Rebinding Check**: Before connecting upstream, the proxy resolves the target hostname and asserts that the peer IP address is a public, globally routable address. Private RFC 1918 addresses, loopbacks, and link-local ranges are blocked immediately.
- **Token-Bucket Rate Limiter**: Per-host rate limiting prevents denial-of-service or rapid brute-force attacks against upstream APIs.

### Layer 4: L7 Content Inspectors
Every HTTP request and response passes through a chain of pre-configured inspectors running off the main event loop in worker threads:
- **`domain`**: Enforces static allowlists, blocklists, and dynamic runtime grant policies.
- **`secrets`**: Scans outbound payloads using regex signatures to detect raw API keys or tokens leaving the cage.
- **`entropy`**: Calculates Shannon entropy (0–8 bits/byte) on request bodies to detect encrypted or obfuscated binary exfiltration.
- **`content-type`**: Detects MIME mismatches (e.g. executable binaries disguised as `application/json`).
- **`body-size`**: Enforces strict request body caps (`capture.max_body_size`).

### Layer 5: Zero-Leak Placeholder Secrets
Real credentials never enter the workload sandbox:
- **Decoy Tokens**: The sandbox environment variable contains an entropic decoy string:
  ```text
  agentcage:secret:ANTHROPIC_API_KEY:4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
  ```
- **Wire Injection**: The proxy replaces this placeholder with the real secret **only** on outbound requests targeting the authorized domain (`inject_to`) and inside credential-bearing headers (`Authorization`, `x-api-key`).
- **Response Redaction**: The proxy scans inbound responses from the upstream server and redacts any echoed secret back to its placeholder before delivering it to the agent.
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

## 3. Trust Boundaries

| Component | Trust Level | Justification |
| :--- | :--- | :--- |
| **Agent Workload** | **Untrusted** | Assumed to be under active adversarial manipulation or prompt injection. |
| **Egress Gateway** | **Trusted (Hardened)** | Runs minimal, unprivileged proxy and DNS daemons; owns the network boundary. |
| **Host CLI & State**| **Trusted** | Operator-controlled; holds encrypted secrets and controls quadlet generation. |
| **Policy Decider** | **Semi-Trusted** | Autonomous LLM gatekeeper; can only grant temporary access, subject to rate limits. |
| **Traffic Watcher**| **Constrained** | Narrowing-only: can revoke dynamic grants, but cannot add new grants or alter baseline config. |

---

## 4. Known Residual Risks & Limitations

Transparency is a fundamental tenet of security engineering. agentcage documents the following known residual risks:

1. **Abuse of Allowlisted Domains**: If an agent is granted access to a domain with arbitrary upload endpoints (e.g. `github.com` or `pastebin.com`), it could potentially exfiltrate non-credential data (such as source code) within legitimate HTTP calls. *Mitigation: Restrict allowlists to minimal API endpoints; enable the Traffic Watcher.*
2. **Shared Linux Kernel (`container` backend)**: The Linux `container` backend relies on user namespaces. While robust, it shares the host kernel. *Mitigation: Use the `apple-container` (macOS) or `vm` (Lima) backends when strict hardware virtualization boundaries are required.*
3. **TLS Passthrough Blindspots**: Declaring domains under `domains.passthrough` tunnels raw TCP without terminating TLS. Mitmproxy cannot inspect payloads or inject secrets into passthrough streams. *Mitigation: Use passthrough only for certificate-pinned endpoints that fail under custom CAs.*
4. **Outbound HAR Captures**: Exporting HAR files with `--view outbound` contains real injected credentials on the wire. *Mitigation: Always use `--view inbound` (default) when sharing traffic captures.*
5. **Elevated Debug Flags**: Running `agentcage run --as-root` or setting `nested_containers: true` relaxes user namespace protections. These flags should only be used in isolated CI environments.

---

## 5. Security Hardening Checklist

When configuring production cages:

- [ ] Ensure `domains.allow` contains only specific, fully qualified hostnames (avoid wildcards like `*.com`).
- [ ] Verify that `container.read_only: true` is enabled.
- [ ] Do not mount sensitive host directories (never mount `~/.ssh`, `~/.aws`, or Docker sockets).
- [ ] Store secrets with `agentcage secret set` rather than placing cleartext in `cage.yaml`.
- [ ] Run `agentcage doctor` to verify that unprivileged user namespaces and lingering are active.
- [ ] Enable the `agents.watcher` block in `cage.yaml` to monitor background traffic anomalies.

---

## Reporting Vulnerabilities

If you identify a security vulnerability in agentcage, please report it privately according to the procedure in **[SECURITY.md](../../SECURITY.md)**.
