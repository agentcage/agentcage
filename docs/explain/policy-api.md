# The Policy API & Autonomous Decider

When an autonomous coding agent runs inside a default-deny sandbox, it regularly needs a domain nobody put on the allowlist: a documentation site, an API spec, a new package registry. Without a runtime path, every such block stops the agent until a human edits the config.

The **Policy API** is that path. It is a small control plane inside the egress, at `https://agentcage.local`, where the caged agent can see what it may reach and ask for a domain it may not. Each request is judged by the **decider**, an LLM agent the operator configures, after a set of hard checks that run in code.

---

## Architecture of the Control Plane

The Policy API is not a separate server. It is a virtual host the egress proxy (`agentcage-egress`) answers itself: when the cage sends a request whose TLS SNI and `Host` header are both the control host (or, for plain HTTP, whose `Host` is), the egress handles it in-process before any other step and never opens an upstream connection for it.

```
┌───────────────────────── WORKLOAD SANDBOX (cage) ──────────────────────────┐
│                                                                            │
│  Agent                                                                     │
│    ├─ GET  https://agentcage.local/v1/allowlist                            │
│    └─ POST https://agentcage.local/v1/allowlist/requests                   │
│         {"domain": "crates.io", "reason": "Fetch the serde crate"}         │
│                                                                            │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ TLS with the cage's own CA
                                      ▼
┌────────────────────────── EGRESS GATEWAY (egress) ─────────────────────────┐
│                                                                            │
│  agentcage-egress, control host agentcage.local                            │
│                                                                            │
│  1. Hard checks, in code, in this order:                                   │
│     body ≤ 8 KiB · JSON object · non-empty reason · allowlist mode ·       │
│     valid dotted hostname · already allowed? · never-grant floor ·         │
│     at most 32 live grants · rate limit (1 rps, burst 5)                   │
│                                                                            │
│  2. Decider (operator's LLM), one forced `decide` tool call:               │
│     {"decision": "grant" | "deny", "reason": "...", "ttl_seconds": N}      │
│     any error, timeout or malformed answer = deny                          │
│                                                                            │
│  3. Grant:                                                                 │
│     • domain inspector allows it at once (in memory)                       │
│     • grants.yaml persisted in the cage's grants directory                 │
│     • granted names published; the supervisor reloads dnsmasq (≤ 1 s)      │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. The Reserved Control Host (`agentcage.local`)

- **Name**: `agentcage.local` by default (`agents.decider.host`). The host keeps the name out of every domain list and adds it to the never-grant floor, so it can neither be allowlisted nor granted.
- **Transport**: HTTPS on port 443 with a certificate from the cage's own CA, which the cage already trusts. Plain HTTP on port 80 is answered the same way; there is no redirect.
- **Only when enabled**: the control host is served only while `agents.decider.enable` is `true`. Otherwise a request to it is an ordinary request, and the domain inspector blocks it.
- **Only from the cage**: the Policy API answers outbound requests only. Inbound (reverse-proxied) traffic can set any `Host` and SNI, so it is never treated as a control request.
- **No authentication**: only the caged agent can reach it.

---

## 2. In-Cage Endpoints

Full request and response schemas are in the **[Policy API Reference](../reference/policy-api.md)**.

### A. Introspect the effective allowlist (`GET /v1/allowlist`)

```bash
curl -s https://agentcage.local/v1/allowlist | jq .
```

```json
{
  "mode": "allowlist",
  "baseline": ["api.anthropic.com", "github.com"],
  "granted": [
    {
      "domain": "crates.io",
      "granted_at": "2026-09-08T10:15:00.123456+00:00",
      "expires_at": "",
      "reason": "Package registry for the project's Rust build.",
      "source": "decider:agent:openrouter"
    }
  ],
  "passthrough": [],
  "requestable": true,
  "context": "This cage builds and tests a Rust CLI application.",
  "version": "0.51.0"
}
```

`expires_at` is empty for a permanent grant. `context` is the operator's `agents.decider.context`, so the agent can see what the decider is told about the cage.

### B. Request a domain (`POST /v1/allowlist/requests`)

```bash
curl -s -X POST https://agentcage.local/v1/allowlist/requests \
  -H "Content-Type: application/json" \
  -d '{"domain": "docs.rs", "reason": "Read the serde_json API documentation."}' | jq .
```

Granted (`200`):

```json
{
  "id": "req_5f0c2a9e1b7d4c3a8e6f1d20",
  "status": "granted",
  "domain": "docs.rs",
  "reason": "Official Rust crate documentation host; low risk and fits the stated task.",
  "expires_at": "2026-09-08T11:15:00.123456+00:00",
  "ttl_seconds": 3600,
  "decided_by": "decider:agent:openrouter"
}
```

Denied by the decider (`403`):

```json
{
  "id": "req_3b4c5d6e7f8091a2b3c4d5e6",
  "status": "denied",
  "domain": "pastebin.com",
  "reason": "Paste sites are a data exfiltration sink. If you need a code sample, request the project's own documentation host instead.",
  "suggestion": "Paste sites are a data exfiltration sink. If you need a code sample, request the project's own documentation host instead.",
  "retryable": true,
  "decided_by": "decider:agent:openrouter"
}
```

A denial is a `403` with `status: "denied"`. `retryable` says whether asking again (with a better justification, or after waiting) can succeed; it is `false` only for never-grant domains. A domain that is already reachable gets `200` with `status: "already_allowed"` and the decider is not called.

### C. Give a grant back (`POST /v1/allowlist/removals`)

A cooperative agent can remove a runtime grant it no longer needs:

```bash
curl -s -X POST https://agentcage.local/v1/allowlist/removals \
  -H "Content-Type: application/json" \
  -d '{"domain": "docs.rs", "reason": "task finished"}'
```

Only live runtime grants can be removed this way; the operator's baseline cannot (`403`).

---

## 3. The Decider

The decider is an LLM agent, prompted as a security reviewer, that sees one request at a time: the domain, the agent's justification and the operator's context.

### A. Configuration in `cage.yaml`
```yaml
agents:
  decider:
    enable: true
    provider: openrouter # anthropic | openai | openrouter
    model: z-ai/glm-5.3
    api_key: env:OPENROUTER_API_KEY
    context: >
      This cage builds and tests a Rust CLI application.
      Approved tasks include downloading Rust crates and reading technical docs.
      Do not grant access to social media, webmail, or generic file drop sites.
```

Every key, default and limit is in the [Configuration Reference](../reference/configuration.md#5-agents-decider--watcher). The decider requires `domains` allowlist mode.

The decider's API key is an egress-only secret: the egress resolves it through its secret lookup (the staged secret file, then the egress environment), and the cage never sees it. The LLM call is made by the egress directly, not through its own proxy listeners, so the operator's model provider is neither inspected nor subject to the cage's allowlist.

### B. What it is told to grant
The prompt asks the model to grant only when the domain plausibly serves the stated task, the justification is specific, and the risk is low, and to deny outright: hostnames that encode an IP address, egress-bypass channels (DNS-over-HTTPS, tunnels, open proxies), exfiltration and C2 sinks (request bins, paste sites, file-transfer hosts, messaging bot APIs), and over-broad apexes (`amazonaws.com`, `workers.dev`, …). A denial's reason is written to be actionable, so the agent can make a better request. The operator's `context` is fenced into the prompt as trusted, advisory scope information; it cannot relax the criteria or the hard checks.

### C. Hard checks, before and after the model
These run in code and the model cannot influence them:
- **Syntax**: the domain must be a valid dotted hostname. IP literals, single labels, wildcards, paths, schemes and ports are refused (`400`).
- **Never-grant floor**: `internal`, `local`, `localhost`, `metadata.goog`, the control host itself, every subdomain of these, and any name that encodes a private address for a wildcard DNS service (`10-0-0-1.nip.io`, `192.168.1.1.sslip.io`) are refused without calling the model (`403`, `retryable: false`).
- **Capacity**: at most 32 live grants, counting decisions still in flight (`409`).
- **Rate limit**: one shared token bucket, 1 request per second with a burst of 5 by default (`agents.decider.rate_limit`), for requests and removals together (`429`). Reloading the config does not refill it.
- **Fail closed**: an unconfigured provider is a `503`; any error, timeout, missing tool call or malformed answer from the model is a denial. A `ttl_seconds` above 86400 is clamped to a day, and a negative one is a denial.

---

## 4. Grant Activation & Lifecycle

When the decider grants a domain:
1. **In memory**: the domain inspector allows it immediately.
2. **Overlay**: the egress persists the grant to `grants.yaml` in the cage's grants directory (`~/.local/share/agentcage/<name>/grants/` on the host), a YAML list of `{domain, granted_at, expires_at, reason, source}` written with a temp file and a rename. The egress reloads it at start-up, so a grant survives an egress restart.
3. **DNS**: the egress writes the list of granted names for the supervisor, which re-renders dnsmasq's servers file and sends it `SIGHUP`. The name resolves within about a second. See [Egress-local DNS apply](egress-local-dns-apply.md).
4. **Lifetime**: the decider chooses 600 seconds (one action), 3600 (one session) or 0 (permanent, the default). Every 30 seconds the egress drops expired grants, persists the overlay, re-publishes DNS and writes a `policy_grant_expired` record. An expired grant is blocked by the domain inspector at once, even before the sweep.

On a grant, the domain is still subject to everything else: SNI/Host matching, the inspectors, secret injection rules, the rate limit, and the peer guard, which refuses a grant-only host that resolves to a private address.

Every request, decision and removal is audited (`policy_request`, `policy_introspect`, `policy_removal`, `policy_grant_expired`) and shown by `agentcage cage audit`.

---

## 5. Operator Controls

```bash
# Baseline and live runtime grants:
agentcage cage grants <name> list

# Make a runtime grant permanent in cage.yaml:
agentcage cage grants <name> promote crates.io

# Remove a runtime grant now:
agentcage cage grants <name> revoke crates.io

# Apply the overlay to cage.yaml explicitly (domain list does this too):
agentcage cage grants <name> sync
```

The [traffic watcher](traffic-watcher.md) can also revoke runtime grants after the fact, when it finds them abused.

---

## Next Steps

- **[Traffic Watcher](traffic-watcher.md)** — Background auditing that can revoke grants.
- **[Policy API Reference](../reference/policy-api.md)** — Every endpoint, status code and response body.
- **[Managing Egress How-To](../how-to/manage-egress-and-domains.md)** — Operator workflows for domain management.
