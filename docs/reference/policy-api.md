# Policy API HTTP Specification

The **Policy API** is a control plane the egress proxy serves to the caged agent at `https://agentcage.local`. It lets the agent read its effective allowlist, request a domain (decided by the operator's LLM decider), and give a runtime grant back. For the design and the trust model, see [The Policy API & Autonomous Decider](../explain/policy-api.md).

---

## Service Overview

| Property | Value |
| :--- | :--- |
| **Base URL** | `https://agentcage.local` (the host is `agents.decider.host`) |
| **Transport** | HTTPS on 443, signed by the cage's own CA; plain HTTP on 80 is answered the same way (no redirect) |
| **Served when** | `agents.decider.enable: true`, for outbound requests from the cage only |
| **Authentication** | None; only the caged agent can reach it |
| **Request bodies** | JSON objects, at most 8 KiB (larger: `413`). A UTF-8 BOM is accepted. |
| **Responses** | `Content-Type: application/json` |
| **Paths** | Compared exactly, query string included: `/v1/health?x=1` is a `404` |
| **Rate limit** | One token bucket shared by requests and removals: 1 request/second, burst 5 (`agents.decider.rate_limit`) |

---

## Endpoints

### 1. Health (`GET /v1/health`)

Not rate limited, not audited.

```json
{
  "status": "ok",
  "version": "0.51.0",
  "features": {"introspection": true, "request": true, "removal": true},
  "host": "agentcage.local"
}
```

---

### 2. Effective allowlist (`GET /v1/allowlist`)

Audited as `policy_introspect`.

```json
{
  "mode": "allowlist",
  "baseline": ["api.anthropic.com", "github.com", "registry.npmjs.org"],
  "granted": [
    {
      "domain": "crates.io",
      "granted_at": "2026-09-08T10:15:00.123456+00:00",
      "expires_at": "2026-09-08T11:15:00.123456+00:00",
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

| Field | Meaning |
| :-- | :-- |
| `mode` | `allowlist` or `blocklist` (`null` if neither). |
| `baseline` | The operator's domains (`domains.allow`). Each entry also covers its subdomains. |
| `granted` | Live runtime grants, as stored in `grants.yaml`. `expires_at` is `""` for a permanent grant. |
| `passthrough` | `domains.passthrough`, sorted. |
| `requestable` | Whether `POST /v1/allowlist/requests` is available. |
| `context` | The operator's `agents.decider.context`, or `""`. |
| `version` | The agentcage version. |

---

### 3. Request a domain (`POST /v1/allowlist/requests`)

```http
POST /v1/allowlist/requests HTTP/1.1
Host: agentcage.local
Content-Type: application/json

{"domain": "docs.rs", "reason": "Read the serde_json API documentation for the parser task."}
```

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `domain` | string | **Yes** | One hostname, lowercased, with a trailing dot removed. No wildcards, schemes, paths or ports. |
| `reason` | string | **Yes** | Why the task needs this domain. Must not be empty; cut to 1000 characters. The decider judges this text. |

The checks run in this order, and the first that applies decides the response:

| # | Check | Status | Body |
| :-- | :-- | :-- | :-- |
| 1 | Body is not a JSON object | `400` | `{"error": "invalid JSON body"}` |
| 2 | `reason` empty | `400` | `{"error": "a non-empty 'reason' justification is required"}` |
| 3 | `domains` not in allowlist mode | `400` | `{"error": "request endpoint requires allowlist mode"}` |
| 4 | Not a valid dotted hostname | `400` | `{"error": "invalid domain: '<domain>'"}` |
| 5 | Already allowed (baseline or live grant, unexpired) | `200` | `status: "already_allowed"`, no decider call |
| 6 | Never-grant floor | `403` | `status: "denied"`, `retryable: false` |
| 7 | 32 live grants (decisions in flight count) | `409` | `status: "denied"`, `retryable: true` |
| 8 | Rate limit | `429` | `status: "denied"`, `retryable: true` |
| 9 | Decider not configured (no provider, model or key) | `503` | `{"error": "llm provider not configured"}` |
| 10 | Decider denies, errors, times out or answers malformed | `403` | `status: "denied"`, `retryable: true` |
| 11 | Decider grants | `200` | `status: "granted"` |

An expired baseline entry or grant is not "already allowed": the request goes to the decider for a fresh decision.

#### `200` — granted
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
`ttl_seconds` is `0` and `expires_at` is `""` for a permanent grant. The decider picks 600, 3600 or 0 (the default); anything above 86400 is clamped to a day. The domain is allowed at once and resolves within about a second.

#### `200` — already allowed
```json
{"id": "req_…", "status": "already_allowed", "domain": "github.com", "reason": "already in baseline or granted"}
```

#### `403` — denied by the decider
```json
{
  "id": "req_3b4c5d6e7f8091a2b3c4d5e6",
  "status": "denied",
  "domain": "pastebin.com",
  "reason": "Paste sites are a data exfiltration sink. Request the project's own documentation host instead.",
  "suggestion": "Paste sites are a data exfiltration sink. Request the project's own documentation host instead.",
  "retryable": true,
  "decided_by": "decider:agent:openrouter"
}
```
`suggestion` repeats the decider's reason, which is written to tell the agent how to ask better. A provider failure is reported as a denial too, without the provider's error text.

#### `403` — never-grant floor
```json
{
  "id": "req_…",
  "status": "denied",
  "domain": "metadata.goog",
  "reason": "metadata.goog is on the operator's never_grant list and cannot be granted by the policy API",
  "suggestion": "request a different, non-internal domain; this one is permanently denied by policy",
  "retryable": false,
  "decided_by": "decider"
}
```

#### `409` — no room for another grant
```json
{
  "id": "req_…",
  "status": "denied",
  "domain": "new.example.net",
  "reason": "max_grants (32) reached; no room for another grant",
  "suggestion": "wait for an existing grant to expire, or ask the operator to remove one with `agentcage domain rm`, then re-request",
  "retryable": true,
  "decided_by": "decider"
}
```

#### `429` — rate limited
```json
{
  "id": "req_…",
  "status": "denied",
  "domain": "z.com",
  "reason": "request rate limit exceeded",
  "suggestion": "wait a few seconds and re-request the same domain",
  "retryable": true,
  "decided_by": "decider"
}
```

---

### 4. Give a grant back (`POST /v1/allowlist/removals`)

```http
POST /v1/allowlist/removals HTTP/1.1
Host: agentcage.local
Content-Type: application/json

{"domain": "docs.rs", "reason": "task finished"}
```

`reason` is optional. Removals share the request rate limit and are audited as `policy_removal`.

| Case | Status | Body |
| :-- | :-- | :-- |
| A live runtime grant | `200` | `{"id", "status": "removed", "domain", "reason"}`, plus `"still_allowed_by_baseline": true` when a baseline entry still covers the domain |
| A baseline entry (operator-owned) | `403` | `status: "denied"`, `retryable: false`, with a suggestion to ask the operator to run `agentcage domain rm` |
| Not a live grant | `404` | `status: "not_found"`, with a suggestion to use the exact domain from `GET /v1/allowlist` |
| Invalid hostname | `400` | `{"error": "invalid domain: '<domain>'"}` |
| Rate limited | `429` | `status: "denied"`, `retryable: true` |

A removal takes effect at once: the domain inspector stops allowing the name, the overlay is persisted and DNS is re-published.

---

### Other responses

| Case | Status | Body |
| :-- | :-- | :-- |
| Any request with a body over 8 KiB | `413` | `{"error": "request body too large"}` |
| Unknown path, or a known path with the wrong method | `404` | `{"error": "not found"}` |

---

## Domain Validation & the Never-Grant Floor

1. **Syntax**: a dotted hostname of at most 253 characters, labels of 1–63 characters from `[a-z0-9-]` that do not start or end with a hyphen. IP literals and single labels are refused.
2. **Never grant**: `internal`, `local`, `localhost`, `metadata.goog`, the control host (`agents.decider.host`), and every subdomain of these. This floor is fixed; it has no config key.
3. **Encoded private addresses**: names that encode a loopback, link-local (cloud metadata), private or CGNAT address for a wildcard DNS service (`10-0-0-1.nip.io`, `192.168.1.1.sslip.io`, `169-254-169-254.nip.io`, …) are on the floor too.

A granted host is also checked when the egress connects to it: if it resolves to an address that is not globally routable, the connection is refused and the host stays refused (`private_peer_blocked`).

---

## Status Code Summary

| Status | Meaning |
| :--- | :--- |
| `200` | Granted, already allowed, removed, or a read. |
| `400` | Not a JSON object, empty reason, not allowlist mode, or invalid domain. |
| `403` | Denied: by the decider, by the never-grant floor, or a removal of a baseline entry. |
| `404` | Unknown endpoint, or a removal of something that is not a live grant. |
| `409` | 32 live grants already. |
| `413` | Body over 8 KiB. |
| `429` | Rate limit (1 rps, burst 5 by default). |
| `503` | The decider has no provider, model or key configured. |

---

## Client Examples

### Shell (`curl`)
```bash
curl -s -X POST https://agentcage.local/v1/allowlist/requests \
  -H "Content-Type: application/json" \
  -d '{"domain": "crates.io", "reason": "Fetch the crate dependencies for cargo build"}'
```

### Python (`requests`)
```python
import requests

def request_egress(domain: str, justification: str) -> bool:
    resp = requests.post(
        "https://agentcage.local/v1/allowlist/requests",
        json={"domain": domain, "reason": justification},
        timeout=30,
    )
    status = resp.json().get("status")
    return status in ("granted", "already_allowed")
```

The decider call can take as long as `agents.decider.timeout_seconds` (15 s by default), so give the client a longer timeout than that.

---

## Next Steps

- **[Policy API Architecture](../explain/policy-api.md)** — The decider and the grant lifecycle.
- **[Configuration Reference](configuration.md)** — `agents.decider` keys and defaults.
