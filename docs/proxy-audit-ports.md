# `proxy.audit_ports`

`proxy.audit_ports` selects the TCP destination ports a cage's proxy container intercepts and audits via mitmdump. Ports outside this list still reach their destination — the proxy container forwards them at L3 — but they bypass `audit.jsonl`, the inspector chain, and the secret injector.

## How agentcage routes cage traffic

Each cage netns has a default route via the proxy container's IP. Inside the proxy container, an iptables PREROUTING REDIRECT diverts selected ports to mitmdump's transparent listener on `:8443`. Anything not matched by REDIRECT is forwarded by the proxy container's kernel routing out to the host network and onward to its real destination.

```
┌─ cage netns ─────────────────────────────────────────────────┐
│ default route via proxy IP                                    │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│ proxy netns                                                   │
│ iptables -t nat PREROUTING:                                   │
│   --dport <audit_port> -j REDIRECT --to-port 8443             │
└──────────┬───────────────────────────────────┬───────────────┘
           │ matched: redirected to mitmdump   │ not matched: forwarded
           ▼                                   ▼
   ┌────────────────┐                ┌────────────────────────┐
   │ mitmdump :8443 │                │ kernel L3 forward      │
   │ transparent    │                │ → upstream             │
   │ → AUDITED      │                │ → NOT AUDITED          │
   └────────────────┘                └────────────────────────┘
```

mitmdump's transparent mode uses `SO_ORIGINAL_DST` to recover the pre-REDIRECT destination, so any TLS-terminated port works without per-port mitmdump configuration — the mitmproxy CA cert (mounted into the cage at `/certs/mitmproxy-ca-cert.pem` and trusted via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`) handles the TLS substitution.

## Default

```yaml
proxy:
  audit_ports: [80, 443]   # default — applied if `proxy:` is omitted
```

This is the historical behavior. Cages that only talk HTTP/HTTPS on standard ports get full audit coverage with no extra configuration.

## When to extend

Any cage that talks to a service on a non-standard port. Common cases:

- **Matrix homeserver** on port 8448 (federation)
- **PostgreSQL** on 5432 (when the cage uses a TLS-wrapped connection)
- **MQTT/TLS** on 8883
- **Any internal service** the operator runs on a non-default port

```yaml
proxy:
  audit_ports: [80, 443, 8448]
```

The list is merged into a single `iptables` `ExecStartPost` line — startup is atomic, so partial-rule states are impossible.

## Reserved ports — rejected by `validate_config`

Three classes of port cannot appear in `audit_ports`:

| Port | Why |
|------|-----|
| `8443` | mitmdump's transparent listener. Redirecting `8443 → 8443` would loop. |
| `8080` | mitmdump's regular HTTP-proxy listener (the L7 path used by apps that honor `HTTP_PROXY`). Redirecting it would strip the L7 layer. |
| Any `protocol_relays[*].listen` port | The relay binds in-process inside the proxy container. Redirecting that port to mitmdump would intercept the connection before the relay handler sees it. |

Validation rejects these with descriptive errors so the misconfiguration surfaces at `agentcage cage create`, not after deploy.

## Disabling transparent capture

Setting `audit_ports: []` removes the iptables `ExecStartPost` entirely. The cage relies solely on the L7 path (apps that honor `HTTP_PROXY` send `CONNECT` requests to mitmdump on `:8080`). Validation emits a warning when this is detected.

This is appropriate for cages running only L7-aware tooling and explicitly opting out of L4 capture — for example, when transparent mode would interfere with a custom routing setup. For most cages, leave at least `[80, 443]`.

## Trade-offs

### Inspector noise on extended ports

If a port carries high-entropy traffic (E2E-encrypted protocols, binary streams), the `entropy` and `body-size` inspectors will flag every payload. Add per-host exemptions in the `inspectors:` block to suppress the noise without disabling the inspector globally:

```yaml
inspectors:
  - name: entropy
    config:
      host_exempt_content_types:
        homeserver.example: ["application/json"]
  - name: body-size
    config:
      host_max_bytes:
        homeserver.example: 33554432   # 32 MiB
```

### TLS interception scope

Adding a port means mitmdump terminates TLS for connections on that port. The cage's runtime must trust the mitmproxy CA. The default cage scaffold mounts the CA via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`; non-Node runtimes may need separate trust-store wiring (e.g. Chromium NSS DB; see `scaffolds/openclaw/entrypoint.sh` for the existing pattern).

### Defense in depth still holds

The cage's `domains.allow` enforces *which* hosts the cage can reach regardless of port — that check happens at DNS resolution and (for the L7 path) at `CONNECT`. Adding a port to `audit_ports` only adds *visibility* and *content inspection*; it doesn't widen the destination set.

## Worked example: jacque (Matrix bot)

```yaml
name: jacque
container:
  image: localhost/jacque-cage:latest
  env:
    HTTPS_PROXY: "http://10.89.5.11:8080"
    HTTP_PROXY: "http://10.89.5.11:8080"
    NODE_EXTRA_CA_CERTS: "/certs/mitmproxy-ca-cert.pem"

proxy:
  audit_ports: [80, 443, 8448]   # ← matrix homeserver on 8448

domains:
  allow:
    - anthropic.com
    - homeserver.example       # the matrix homeserver

inspectors:
  - name: entropy
    config:
      host_exempt_content_types:
        homeserver.example: ["application/json"]
  - name: body-size
    config:
      host_max_bytes:
        homeserver.example: 33554432
```

Without the `8448` entry, every `m.room.encrypted` event the bot sends would reach the homeserver but never appear in `audit.jsonl`. The bot's domain allowlist would still prevent it from talking to *other* hosts, but the visibility of its homeserver traffic — including the secret injector's literal-value check on each request — would be missing.

## Related

- L7 trust signal (`HTTP_PROXY` honoring): see runtime-specific docs. For openclaw cages, setting `OPENCLAW_PROXY_ACTIVE=1` opts the inner runtime into using `HTTP_PROXY` for requests its own SSRF guard otherwise pins to a direct dispatcher. That's a complementary lever — `audit_ports` covers L4 transparently regardless of inner-runtime cooperation.
- Secret injection: see `docs/configuration.md`. The injector runs against captured traffic, so it only sees ports listed in `audit_ports`.
- Inspector chain: see `docs/configuration.md`. Same scope.
