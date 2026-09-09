# Policy API HTTP Specification

The **Policy API** is an internal REST service running inside the egress gateway at `https://agentcage.local`. It enables sandboxed agent workloads to introspect their network boundaries and request dynamic egress access.

---

## Service Overview

| Property | Value |
| :--- | :--- |
| **Base URL** | `https://agentcage.local` |
| **Protocol** | HTTPS (TLS terminated with per-cage CA) |
| **Port** | `443` (HTTP on `80` redirects to HTTPS) |
| **Authentication** | Per-cage internal network identity (no tokens required) |
| **Availability** | Available **only** inside the sandboxed workload container |
| **Rate Limit** | 2.0 requests/sec with burst capacity of 5 requests |

---

## Endpoint Specification

### 1. Health Check (`GET /v1/health`)
Verifies that the Policy API server and internal proxy addons are operational.

#### Request
```http
GET /v1/health HTTP/1.1
Host: agentcage.local
```

#### Response (`200 OK`)
```json
{
  "status": "ok",
  "decider_enabled": true,
  "watcher_enabled": true
}
```

---

### 2. Introspect Allowlist (`GET /v1/allowlist`)
Returns the complete set of reachable domains, separating the operator's static baseline from active dynamic grants.

#### Request
```http
GET /v1/allowlist HTTP/1.1
Host: agentcage.local
```

#### Response (`200 OK`)
```json
{
  "mode": "allowlist",
  "static": [
    "api.anthropic.com",
    "github.com",
    "registry.npmjs.org"
  ],
  "grants": [
    {
      "domain": "crates.io",
      "reason": "Download Rust crate dependencies",
      "created_at": "2026-09-08T10:15:00Z",
      "expires_at": "2026-09-08T12:15:00Z",
      "ttl_remaining_seconds": 7142
    }
  ]
}
```

---

### 3. Request Dynamic Egress (`POST /v1/allowlist/requests`)
Submits a dynamic access request for a specific domain. The request is evaluated programmatically against hard safety gates and passed to the in-egress Decider Agent.

#### Request
```http
POST /v1/allowlist/requests HTTP/1.1
Host: agentcage.local
Content-Type: application/json

{
  "domain": "docs.rs",
  "reason": "Need to read Rust crate API documentation for project compilation."
}
```

#### Request Fields
| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `domain` | string | **Yes** | Fully qualified domain name (FQDN). Must not contain wildcards, paths, or protocols. |
| `reason` | string | **Yes** | Technical justification explaining why this domain is necessary for the current task. |

#### Responses

##### `200 OK` — Access Granted
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
*The domain is instantly promoted to the active routing table and `dnsmasq`. It becomes reachable in < 1 second.*

##### `200 OK` — Access Denied by Decider
```json
{
  "id": "req-3b4c5d6e",
  "domain": "pastebin.com",
  "decision": "denied",
  "reason": "Arbitrary paste/upload service presents unacceptable data exfiltration risk."
}
```

##### `400 Bad Request` — Invalid Domain Syntax
```json
{
  "error": "invalid_domain",
  "message": "Domain '192.168.1.1' is an IP literal. IP addresses are rejected by policy."
}
```

##### `403 Forbidden` — Denied by Hard Security Policy (`never_grant`)
```json
{
  "error": "forbidden_domain",
  "message": "Domain '169.254.169.254.nip.io' matches forbidden metadata address space."
}
```

##### `429 Too Many Requests` — Rate Limit Exceeded
```json
{
  "error": "rate_limited",
  "message": "Exceeded request quota of 2 requests/sec. Please back off."
}
```

---

### 4. Voluntary Grant Removal (`POST /v1/allowlist/removals`)
Allows cooperative agents to give back a previously granted domain once its task (e.g. downloading a package) is complete.

#### Request
```http
POST /v1/allowlist/removals HTTP/1.1
Host: agentcage.local
Content-Type: application/json

{
  "domain": "docs.rs"
}
```

#### Response (`200 OK`)
```json
{
  "status": "revoked",
  "domain": "docs.rs"
}
```

---

## Domain Validation & Security Rules

All domain strings undergo strict programmatic validation before evaluation:

1. **RFC 1035 Syntax**:
   - Total length: 1–253 characters.
   - Label length: 1–63 characters consisting of `[a-z0-9-]` (cannot begin or end with hyphens).
   - TLD validation: Last label must be at least 2 characters.
2. **IP Literals Rejected**: Raw IPv4 or IPv6 addresses are rejected.
3. **`never_grant` Denylist**: Suffixes matching the following spaces are rejected unconditionally:
   - Cloud instance metadata: `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`
   - Local networks & loopbacks: `.local`, `.localhost`, `.internal`, `.lan`, `.home.arpa`
   - Private tailnets: `.ts.net`
4. **Encoded IP Block**: Domains utilizing wildcard DNS services to encode private IP addresses (e.g. `10-0-0-1.nip.io`, `192.168.1.1.sslip.io`) are stripped and blocked via `_encoded_private_ip()`.

---

## HTTP Status Code Summary

| Status Code | Meaning |
| :--- | :--- |
| `200 OK` | Request processed successfully (evaluates to `granted` or `denied`). |
| `400 Bad Request` | Missing fields, malformed JSON, or invalid domain syntax. |
| `403 Forbidden` | Target domain matches a `never_grant` protected suffix. |
| `404 Not Found` | Unrecognized API endpoint. |
| `429 Too Many Requests`| Exceeded rate limits (2 rps, burst 5). |
| `502 Bad Gateway` | Upstream LLM provider failed to respond to the Decider Agent. |
| `503 Service Unavailable`| Policy API or Decider Agent is disabled in `cage.yaml`. |

---

## Client Code Examples

### Python (using `requests` or `urllib`)
```python
import requests

def request_egress(domain: str, justification: str) -> bool:
    resp = requests.post(
        "https://agentcage.local/v1/allowlist/requests",
        json={"domain": domain, "reason": justification},
        timeout=15,
    )
    if resp.status_code == 200:
        data = resp.json()
        return data.get("decision") == "granted"
    return False

# Example usage:
if request_egress("crates.io", "Download serde serialization crate"):
    print("Access granted! Initiating download...")
```

### Shell (`curl`)
```bash
curl -s -X POST https://agentcage.local/v1/allowlist/requests \
  -H "Content-Type: application/json" \
  -d '{"domain": "crates.io", "reason": "Fetch crate dependencies"}'
```

---

## Next Steps

- **[Policy API Architecture](../explain/policy-api.md)** — Architectural deep-dive on the Decider Agent.
- **[Configuration Reference](configuration.md)** — How to configure `agents.decider` in `cage.yaml`.
