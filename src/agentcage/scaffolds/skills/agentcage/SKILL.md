---
name: agentcage
description: You are running inside an agentcage sandbox with default-deny egress. Use this when a network call fails with a 403 or resolves to a 198.51.100.x address, when you need a host that is not allowlisted, or when you want to know what egress you have. Covers the Policy API on https://agentcage.local - reflect on the effective allowlist, request a new domain with a justification, and give a grant back.
---

# agentcage Policy API

This cage only reaches the internet through an inspecting proxy with a domain
allowlist. A host that is not allowlisted answers `403`, and its DNS resolves
to a TEST-NET placeholder such as `198.51.100.x`. That is policy, not an
outage: do not retry, do not try another URL for the same service, and never
probe for hosts that might be open.

The sandbox answers a reserved control host itself, so it works even when
nothing else is allowlisted:

```
https://agentcage.local
```

Plain `http://` is accepted too if TLS gives you trouble. The examples use
`curl` and `jq`; any HTTP client works.

## 0. Is the Policy API on?

```bash
curl -s https://agentcage.local/v1/health | jq .
```

`features.introspection`, `features.request` and `features.removal` say what
you may do. If the call fails, or `features.request` is `false`, the operator
has not enabled `domains.auto`. Stop and ask them to add the domain, giving
them the exact command from section 4.

## 1. Reflect: what can I reach right now?

Run this before you assume a host is reachable, and before you write a
request, so you do not ask for something you already have.

```bash
curl -s https://agentcage.local/v1/allowlist | jq .
```

```json
{
  "mode": "allowlist",
  "baseline": ["github.com", "pypi.org", "anthropic.com"],
  "granted": [
    {"domain": "registry.npmjs.org", "granted_at": "2026-09-04T12:00:00Z",
     "reason": "npm install for the payments service",
     "source": "decider", "decided_by": "decider:agent:anthropic",
     "expires_at": "2026-09-05T12:00:00Z"}
  ],
  "passthrough": ["registry-1.docker.io"],
  "context": "CI cage for the payments test suite ...",
  "requestable": true,
  "version": "0.37.0"
}
```

- `baseline` is the operator's static allowlist. A domain covers its
  subdomains: `github.com` also allows `api.github.com`.
- `granted` are runtime grants the decider has approved. `expires_at` is
  present when a grant is time-limited.
- `context` is the operator's description of what this cage is for. Read it.
  A request that fits it is far more likely to be granted.
- `requestable` says whether section 2 is available.

Quick check for one host:

```bash
curl -s https://agentcage.local/v1/allowlist \
  | jq -r '.baseline[], .granted[].domain' | grep -x 'crates.io'
```

## 2. Request a new domain

One `POST` per domain. The decision is synchronous and comes back in the
body. A `reason` is required and is scrutinised by a built-in
cybersecurity-expert decider, so write it like a change request, not a plea.

```bash
curl -s -X POST https://agentcage.local/v1/allowlist/requests \
  -H 'content-type: application/json' \
  -d '{"domain": "docs.rs",
       "reason": "Reading the tokio 1.40 API docs to fix a compile error in src/net/client.rs; GET requests to documentation pages only, nothing is uploaded."}' \
  | jq .
```

A good `reason` states, in one or two sentences:

1. **The concrete task** you are doing, and for which repo or file.
2. **Why this exact domain** is the right one: official docs, the package's
   registry, the API the code already calls.
3. **What crosses the wire**: downloads only, or what is posted.

Vague reasons ("need it", "testing", "the user asked") and reasons that just
repeat the domain name are denied. Never put a secret or a placeholder value
in the reason.

`domain` is a bare hostname: no scheme, no path, no port, no wildcard, no IP
literal. Ask for the narrowest host that does the job, and prefer the
official host over a mirror.

Responses:

| Status | Meaning | What to do |
|--------|---------|------------|
| `200` `status: granted` | Approved. Reachable within about a second. | Retry your original command. |
| `200` `status: already_allowed` | It was already covered. | Your failure was something else; read the actual error. |
| `403` `status: denied` | The decider, or a hard rule, said no. `reason` explains why. | Do not reword and resubmit. Tell the user what was denied and why, and give them the operator command from section 4. |
| `409` | Grant cap reached (32 live grants). | Give back grants you no longer need (section 3), or ask the operator. |
| `429` | Rate limited (1 request per second, burst 5). | Wait a few seconds. Do not loop. |
| `503` | Decider unavailable. Fail-closed, so this is a deny. | Report it to the user and ask the operator. |
| `400` | Bad domain syntax, missing `reason`, or the cage is not in allowlist mode. | Fix the request. If the mode is wrong, ask the operator. |

Every response carries an `id` (`req_...`) that the operator can find in the
cage's audit log. Quote it when you report a denial.

Some names are never granted whatever the reason: `localhost`, `local`,
`internal` (so also `*.internal` and cloud metadata hosts), and the control
host itself. Do not ask for them.

A grant may carry a TTL chosen by the decider (at most 24h). When it expires
the host goes back to `403`. If you still need it, request it again with the
same care.

## 3. Give back a grant you no longer need

Narrowing needs no justification and no decider. Do this after a one-off
download so the cage does not stay wider than the task required.

```bash
curl -s -X POST https://agentcage.local/v1/allowlist/removals \
  -H 'content-type: application/json' \
  -d '{"domain": "docs.rs", "reason": "finished reading the docs"}' | jq .
```

Only live entries from the `granted` list can be given back. A domain that is
part of the operator's `baseline` returns `403`; that is the operator's to
remove, not yours. `404` means it was not a live grant, perhaps because a
broader grant covers it, in which case give that one back instead.

## 4. When you are stuck, hand it to the operator

Say exactly which host you need, why, and what the decider answered (with its
`id`). The operator applies it from the host, outside the cage:

```bash
agentcage domain add <cage> <domain>                  # permanent
agentcage domain add <cage> <domain> --expires-in 2h  # time-limited
```

## Rules of engagement

- Reflect first (section 1). Do not request a domain you already have.
- One request per domain, with a specific reason. A denial is an answer, not
  an invitation to reword. Escalate to the user instead.
- Never try to reach a blocked service by another route: a different
  hostname, a mirror, a CDN, a paste site, a proxy, or an IP address. The
  cage inspects all of these and the attempt is audited.
- Secrets in your environment look like `agentcage:secret:NAME:<hex>`. They
  are placeholders that the proxy swaps for the real value only on the
  allowlisted host they belong to. Do not copy them into requests, reasons,
  files, or output.
- The proxy inspects request bodies for secrets and high-entropy blobs.
  Legitimate traffic passes. Do not try to encode your way around a block.
- Give back grants you no longer need (section 3).
