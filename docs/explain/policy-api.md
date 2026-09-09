# The Policy API & Autonomous Decider

When running autonomous coding agents inside a default-deny sandbox, agents frequently encounter legitimate egress needs that were not anticipated when drafting the initial allowlist (e.g. downloading documentation, accessing an API spec, or fetching a new package dependency).

Without dynamic controls, every blocked domain halts execution and requires manual human intervention to edit configuration files and restart containers.

The **Policy API** solves this by providing a secure, in-egress control plane at `https://agentcage.local` where sandboxed agents can introspect their reachable domains and request temporary access to new domains, adjudicated in real time by an autonomous **Decider Agent**.

---

## Architecture of the Control Plane

The Policy API runs entirely inside the egress proxy container (`mitmdump`):

```
┌───────────────────────── WORKLOAD SANDBOX (cage) ──────────────────────────┐
│                                                                            │
│  Agent Process                                                             │
│    │                                                                       │
│    ├─ 1. Introspect Allowlist:                                             │
│    │     GET https://agentcage.local/v1/allowlist                          │
│    │                                                                       │
│    └─ 2. Request Dynamic Domain:                                           │
│          POST https://agentcage.local/v1/allowlist/requests                │
│          {"domain": "crates.io", "reason": "Fetch serde dependency"}       │
│                                                                            │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ In-Cage TLS (using per-cage CA)
                                      ▼
┌────────────────────────── EGRESS GATEWAY (egress) ─────────────────────────┐
│                                                                            │
│  Policy API Controller (mitmdump addon at https://agentcage.local)         │
│                                                                            │
│  1. Hard Input Validation:                                                 │
│     • Strict FQDN validation (RFC 1035 regex)                              │
│     • Reject IP literals, single labels, and wildcards                     │
│     • Reject `never_grant` suffixes (metadata, localhost, internal TLDs)   │
│     • Rate limit: 2 requests/sec (burst 5)                                 │
│                                                                            │
│  2. Autonomous Decider Agent (LLM):                                        │
│     • Evaluates operator-provided cage context and agent justification     │
│     • Prompt-injection hardened cybersecurity evaluator persona            │
│     • Verdict: { "decision": "granted" | "denied", "reason": "..." }       │
│                                                                            │
│  3. Grant Activation Seam (Sub-second):                                    │
│     • Write grant file to host-mounted grants/ directory                   │
│     • Update proxy in-memory routing table                                 │
│     • Update dnsmasq zone configuration via SIGHUP                         │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. The Reserved Control Host (`agentcage.local`)

- **Dedicated Hostname**: The control plane is served at `https://agentcage.local`. This name is intercepted locally by `mitmdump` and is never forwarded to external networks.
- **Port**: Serves standard HTTPS on port 443 (and HTTP on port 80).
- **TLS Authentication**: Authenticates using the per-cage CA certificate already trusted by the workload container.

---

## 2. In-Cage Endpoints

Sandboxed agents interact with the Policy API using standard HTTP client libraries or `curl`:

### A. Introspect Effective Allowlist (`GET /v1/allowlist`)
Retrieves the complete set of currently reachable domains, distinguishing between the operator's static baseline and active dynamic grants:

```bash
curl -s https://agentcage.local/v1/allowlist | jq .
```

Response:
```json
{
  "mode": "allowlist",
  "static": [
    "api.anthropic.com",
    "github.com"
  ],
  "grants": [
    {
      "domain": "crates.io",
      "reason": "Fetch serde dependency",
      "created_at": "2026-09-08T10:15:00Z",
      "expires_at": "2026-09-08T12:15:00Z"
    }
  ]
}
```

### B. Request Dynamic Egress (`POST /v1/allowlist/requests`)
Requests temporary access to a specific fully qualified domain name:

```bash
curl -s -X POST https://agentcage.local/v1/allowlist/requests \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "docs.rs",
    "reason": "Need to read serde JSON serialization documentation."
  }' | jq .
```

Success Response:
```json
{
  "id": "req-9f2c8a1b",
  "domain": "docs.rs",
  "decision": "granted",
  "reason": "Legitimate documentation retrieval for declared project tasks.",
  "ttl_seconds": 7200,
  "expires_at": "2026-09-08T12:15:00Z"
}
```

Denial Response:
```json
{
  "id": "req-3b4c5d6e",
  "domain": "pastebin.com",
  "decision": "denied",
  "reason": "Arbitrary paste/upload service presents unacceptable data exfiltration risk."
}
```

---

## 3. The Autonomous Decider Agent

The Decider Agent is an in-egress LLM that acts as a cybersecurity evaluator, scrutinizing every domain request against the declared purpose of the cage.

### A. Configuration in `cage.yaml`
```yaml
agents:
  decider:
    enable: true
    provider: openrouter # anthropic | openai | openrouter
    model: z-ai/glm-5.3 # Or anthropic/claude-3-5-sonnet, etc.
    context: >
      This cage builds and tests a Rust CLI application.
      Approved tasks include downloading Rust crates and reading technical docs.
      Do not grant access to social media, webmail, or generic file drop sites.
```

### B. Evaluation Criteria
The Decider grants access only if **all three** conditions are met:
1. **Relevance**: The domain is technically necessary for the tasks declared in the operator's `context` prompt.
2. **Safety**: The domain is a reputable, dedicated service (e.g. package registries, API endpoints) rather than an arbitrary upload/paste service.
3. **No Over-Privilege**: The agent requested a specific hostname rather than an overbroad domain.

### C. Hard Gates & Prompt-Injection Hardening
Before the Decider Agent LLM ever sees a request, the input must pass strict programmatic validation:
- **FQDN Syntax**: Must match standard DNS naming rules; newlines, paths, or shell metacharacters are rejected at parse time.
- **`never_grant` Suffixes**: Suffixes matching cloud metadata (`169.254.169.254`, `metadata.google.internal`), localhost (`.local`, `.localhost`), or internal tailnets (`.ts.net`) are rejected outright without invoking the LLM.
- **Encoded IP Blocking**: Domain names that encode private IP addresses (e.g. `192-168-1-1.nip.io`) are detected and rejected.
- **Strict Delimiters**: The agent's justification string is encapsulated within cryptographic boundary tokens in the prompt, preventing indirect prompt injections from escaping their evaluation sandbox.

---

## 4. Grant Activation & Lifecycle

When a domain request is granted:
1. **Host-Side Overlay**: The proxy writes an atomic JSON grant file to `~/.local/share/agentcage/<name>/grants/`.
2. **In-Memory Proxy Cache**: The proxy addon updates its routing table immediately.
3. **DNS Activation**: The proxy appends the domain to `dns-allowlist.conf` and triggers a `SIGHUP` signal to `dnsmasq`. The domain becomes resolvable and reachable in **less than one second**.
4. **Time-To-Live (TTL)**: Grants have default TTLs (typically 2 hours). When a grant expires, the proxy blocks outbound traffic and prunes the DNS configuration.

---

## 5. Operator Controls

Operators maintain full visibility and control over dynamic grants from the host CLI:

```bash
# List all active dynamic grants and static baseline:
agentcage cage grants <name> list

# Promote a dynamic grant permanently into cage.yaml:
agentcage cage grants <name> promote crates.io

# Revoke a dynamic grant immediately:
agentcage cage grants <name> revoke crates.io

# Synchronize expired or decided grants:
agentcage cage grants <name> sync
```

---

## Next Steps

- **[Traffic Watcher](traffic-watcher.md)** — Learn how background auditing monitors and revokes grants.
- **[Policy API Reference](../reference/policy-api.md)** — Exhaustive HTTP schema and endpoint specification.
- **[Managing Egress How-To](../how-to/manage-egress-and-domains.md)** — Operator workflows for domain management.
