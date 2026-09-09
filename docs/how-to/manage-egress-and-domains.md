# How-To: Manage Egress & Domains

agentcage operates on a strict **default-deny** network model. This guide explains how to manage domain allowlists, configure wildcards, grant temporary access, and handle blocked connections.

---

## 1. Static Domain Management (Operator CLI)

Operators can update domain allowlists for persistent cages without restarting containers.

### A. Add Domains to Allowlist
Add one or more domains to a cage:

```bash
agentcage domain add my-agent crates.io docs.rs
```
*agentcage appends the domains to `dns-allowlist.conf` and reloads `dnsmasq` via `SIGHUP`. The domains become reachable immediately.*

### B. List Configured Domains
Inspect all allowlisted, blocked, and passthrough domains:

```bash
agentcage domain list my-agent
```

### C. Remove a Domain
Revoke access to a domain:

```bash
agentcage domain rm my-agent crates.io
```

---

## 2. Using Time-Limited Grants (`--expires-in`)

For temporary tasks (such as running `npm install` from an unfamiliar registry), grant time-limited access that automatically expires:

```bash
agentcage domain add my-agent temp-registry.org --expires-in 2h
```

Supported duration formats:
- Minutes: `--expires-in 30m`
- Hours: `--expires-in 2h`
- Days: `--expires-in 1d`
- Bare seconds: `--expires-in 3600`

Once the TTL elapses:
1. The proxy immediately blocks outbound L7 traffic to `temp-registry.org`.
2. The next automated reconcile sweeps the expired entry from DNS and `cage.yaml`.

---

## 3. Wildcards & Domain Matching Rules

In `cage.yaml`:

```yaml
domains:
  mode: allowlist
  allow:
    - api.github.com         # Exact match only
    - "*.githubusercontent.com" # Matches all subdomains (raw.githubusercontent.com, etc.)
```

### Wildcard Best Practices
- **Do not allow top-level wildcards**: Never declare `*.com` or `*`. This breaks egress isolation entirely.
- **Specific subdomains preferred**: Prefer `api.anthropic.com` over `*.anthropic.com` to prevent agents from accessing employee portals or marketing sites.

---

## 4. Configuring TLS Passthrough

Some tools (such as certain package managers, corporate VPNs, or internal microservices) enforce **TLS certificate pinning** and reject the per-cage CA certificate.

To allow pinned connections without decrypting payloads:

```bash
agentcage domain add my-agent pinned-api.example.com --passthrough
```

Or declare in `cage.yaml`:

```yaml
domains:
  passthrough:
    - pinned-api.example.com
```

> **Warning**: In passthrough mode, the proxy acts as a transparent TCP tunnel. It cannot inspect request bodies, scan for exfiltration, or inject/redact secret placeholders. Use passthrough sparingly.

---

## 5. Troubleshooting Blocked Connections

When an agent attempts to access an unauthorized domain, two things happen:
1. **DNS**: The hostname resolves to `198.51.100.1` (RFC 5737 TEST-NET-2 sinkhole IP).
2. **HTTP**: Connecting to `198.51.100.1:443` is intercepted by the proxy, which returns `403 Forbidden` with diagnostic headers:
   ```text
   HTTP/1.1 403 Forbidden
   x-agentcage-decision: blocked
   x-agentcage-reason: domain 'unapproved.com' not in allowlist
   ```

### Diagnosing Blocked Hosts via Audit Logs
To see which hosts your agent is trying to reach:

```bash
agentcage cage audit my-agent -d blocked --since 1h
```

Output:
```text
2026-09-08 10:30:15 [BLOCKED] api.datadoghq.com (inspector: domain) - not in allowlist
2026-09-08 10:31:02 [BLOCKED] telemetry.example.com (inspector: domain) - not in allowlist
```

If the traffic is legitimate, add the required host:

```bash
agentcage domain add my-agent api.datadoghq.com
```

---

## 6. Managing Dynamic Policy API Grants

If the **Policy API** and **Decider Agent** are enabled in `cage.yaml`, the sandboxed agent can request access dynamically from inside the container:

```bash
# Agent runs this inside the cage:
curl -s -X POST https://agentcage.local/v1/allowlist/requests \
  -H "Content-Type: application/json" \
  -d '{"domain": "crates.io", "reason": "Fetch serde crate"}'
```

On your host machine, the operator can review and manage these dynamic grants:

```bash
# List all active runtime grants:
agentcage cage grants my-agent list

# Promote a temporary grant permanently into cage.yaml:
agentcage cage grants my-agent promote crates.io

# Revoke a runtime grant immediately:
agentcage cage grants my-agent revoke crates.io

# Clean up expired grants:
agentcage cage grants my-agent sync
```

---

## Next Steps

- **[Policy API Explanation](../explain/policy-api.md)** — Architectural details of the Decider Agent.
- **[Configuration Reference](../reference/configuration.md)** — Syntax for `domains` in `cage.yaml`.
- **[Troubleshooting Guide](troubleshooting.md)** — Diagnosing DNS and connection errors.
