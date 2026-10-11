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

## 3. Domain Matching Rules

Every entry matches the name itself **and every subdomain** of it. There is no wildcard syntax: `*.githubusercontent.com` is refused at `cage create`.

```yaml
domains:
  mode: allowlist
  allow:
    - api.github.com         # api.github.com and *.api.github.com
    - githubusercontent.com  # githubusercontent.com, raw.githubusercontent.com, ...
```

### Best Practices
- **Never allow a bare top-level domain** such as `com` or `co.uk`: it covers every name under it and breaks egress isolation.
- **Prefer specific hosts**: `api.anthropic.com` rather than `anthropic.com`, so the agent cannot reach employee portals or marketing sites under the same apex.

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

> **Warning**: In passthrough mode, the egress splices the TLS connection as raw TCP. It cannot inspect request bodies, scan for exfiltration, inject or redact secret placeholders, or capture anything. A passthrough name also covers its subdomains, and the splice happens only when the connection goes to an address that name actually resolves to. Use passthrough sparingly.

---

## 5. Troubleshooting Blocked Connections

When an agent attempts to access an unauthorized domain, two things happen:
1. **DNS**: The hostname resolves to `198.51.100.1` (RFC 5737 TEST-NET-2 sinkhole IP).
2. **HTTP**: Connecting to `198.51.100.1:443` is intercepted by the egress proxy, which reads the real name from the TLS SNI and returns a `403` with a JSON body:
   ```json
   {"blocked": true, "reason": "domain not in allowlist: unapproved.com", "host": "unapproved.com", "by": "agentcage"}
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
