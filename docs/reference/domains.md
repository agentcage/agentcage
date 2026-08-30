<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Domains

Hostname-level allow/block filtering for cage egress. Combine with [Ports](ports.md) for full coverage.

## Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `allow` | `list[string]` | `[]` | Allowlist mode — only these domains (and their subdomains) are reachable. |
| `block` | `list[string]` | `[]` | Blocklist mode — all domains except these are reachable. |
| `passthrough` | `list[string]` | `[]` | Domains that bypass TLS interception (no MITM). Still subject to DNS filtering. |

Rules:

- `allow:` present → allowlist mode (only listed domains reachable).
- `block:` present → blocklist mode (all except listed domains).
- Both `allow` + `block` → validation error.
- Neither → no filtering (all domains reachable).
- `passthrough:` → listed domains pass TLS through without interception.

Subdomains are matched automatically — adding `example.com` also matches `api.example.com`, `sub.api.example.com`, etc.

## Basic allowlist

```yaml
domains:
  allow:
    - api.anthropic.com
    - github.com        # also matches *.github.com
    - pypi.org
```

## TLS passthrough

Some protocols (WhatsApp/Noise Protocol, gRPC with certificate pinning) break under MITM interception. Use `passthrough` to let these connections through without TLS interception while still enforcing DNS-level domain filtering:

```yaml
domains:
  allow:
    - anthropic.com
    - whatsapp.com
    - whatsapp.net
  passthrough:
    - whatsapp.com
    - whatsapp.net
```

Passthrough domains are automatically added to the DNS allowlist for resolution. The proxy will not intercept or inspect TLS traffic to these domains — use this only for protocols that require it.

> **Security note:** Passthrough domains bypass all proxy inspection (secret detection, entropy analysis, content-type checks). Only add domains that genuinely require direct TLS connections.

## Blocklist mode

```yaml
domains:
  block:
    - evil.com
    - malware.example.org
```

## Related

- [Ports](ports.md) — TCP/UDP egress policy that pairs with domain filtering.
- [Inspectors](inspectors.md) — the `domain` inspector that enforces this allowlist on HTTP.
- [Protocol relays](protocol-relays.md) — drop relay upstream hosts from `allow` so only the relay can reach them.
- [Policy API](policy-api.md) — optional opt-in feature (configured under `domains.auto`) letting a caged agent introspect its allowlist and request new egress domains at runtime, gated by a built-in LLM decider. See the [design doc](../explain/policy-api.md).
