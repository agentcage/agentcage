# Port policy: `ports.allow` and `ports.passthrough`

The proxy container enforces a default-deny network policy on every cage. Cage→external traffic is dropped unless the destination port is explicitly listed in one of two fields, which mirror the shape of `domains.allow` / `domains.passthrough`:

- `ports.allow` — TCP+UDP destination ports the cage may reach. The superset of permitted egress ports.
- `ports.passthrough` — subset of allowed ports that bypass mitmdump inspection. Auto-merged into the effective allow set if the operator didn't list them in `allow`.

Inspected ports = `allow - passthrough`. There is no opt-out flag for the default-deny FORWARD policy. Every cage gets it on next `agentcage cage update`.

> **BREAKING change (Unreleased):** the default-deny `filter:FORWARD` policy is new. Pre-change, anything not in the audit list was silently L3-forwarded uninspected — the cage's `domains.allow` gated *which hosts* could be reached but said nothing about *which ports* could exit. An agent that resolved an allowed hostname could exfiltrate over any TCP or UDP port (NTP, custom binary protocols, QUIC) with the audit pipeline blind. The new default-deny posture closes that gap.
>
> **Migration impact:** cages that talk *only* on the default `ports.allow` (`[80, 443]`) keep working unchanged. Cages that depend on outbound on any other port — NTP for clock sync (`123/udp`), Postgres (`5432/tcp`), IMAP (`993/tcp`), QUIC/HTTP3 (`443/udp`), custom services — must add those ports to `ports.allow` (and to `ports.passthrough` if mitmdump's TLS interception isn't workable for them) or lose connectivity. DNS is unaffected: cages talk to the sidecar dns container directly on the same subnet and never traverse the proxy's FORWARD chain.

## How agentcage routes cage traffic

Each cage netns has a default route via the proxy container's IP. Inside the proxy netns, two iptables chains decide what happens to each packet:

```
┌─ cage netns ─────────────────────────────────────────────────┐
│ default route via proxy IP                                    │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│ proxy netns                                                   │
│                                                               │
│   nat:PREROUTING                                              │
│     -p tcp --dport <inspected_port> -j REDIRECT --to-port 8443│
│         (inspected = ports.allow - ports.passthrough)         │
│                                                               │
│   filter:FORWARD                                              │
│     -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT      │
│     -p tcp --dport <passthrough_port> -j ACCEPT               │
│     -p udp --dport <passthrough_port> -j ACCEPT               │
│   policy: DROP                                                │
└──┬─────────────────────────┬────────────────────────────┬────┘
   │ inspected               │ passthrough                 │ neither
   ▼                         ▼                             ▼
┌─────────────────┐  ┌──────────────────────┐  ┌────────────────────┐
│ mitmdump :8443  │  │ kernel L3 forward    │  │ DROP at FORWARD    │
│ transparent     │  │ → upstream            │  │ policy             │
│ → AUDITED       │  │ → NOT AUDITED         │  │ → BLOCKED          │
└─────────────────┘  └──────────────────────┘  └────────────────────┘
```

REDIRECTed traffic never reaches `filter:FORWARD` — REDIRECT rewrites the destination as local, so packets traverse `INPUT` to mitmdump. mitmdump uses `SO_ORIGINAL_DST` to recover the pre-REDIRECT destination, so any TLS-terminated port works without per-port mitmdump configuration; the mitmproxy CA cert (mounted into the cage at `/certs/mitmproxy-ca-cert.pem` and trusted via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`) handles the TLS substitution.

## Defaults

```yaml
ports:
  allow: [80, 443]      # default — applied if `ports:` is omitted
  passthrough: []       # default — every allowed port is inspected
```

Cages that only talk HTTP/HTTPS on standard ports get full audit coverage and zero configuration. Cages that need anything else must opt in port-by-port.

## When to extend `ports.allow`

Use `ports.allow` to permit destination ports the cage needs to reach. Adding a port without also listing it in `passthrough` means it's inspected — TCP traffic gets REDIRECTed to mitmdump's transparent listener, runs through `audit.jsonl`, the inspector chain, and the secret injector.

Inspected ports work best for TCP services where mitmdump's transparent TLS interception holds: the cage's runtime trusts the mitmproxy CA, and the upstream uses TLS that mitmproxy can substitute.

- **Matrix homeserver** on port `8448` (federation)
- **PostgreSQL** on `5432` (when wrapped in TLS)
- **MQTT/TLS** on `8883`
- **Any internal service** the operator runs on a non-default port over TLS the runtime will trust

```yaml
ports:
  allow: [80, 443, 8448]
```

The inspected list is rendered into a single `iptables` `ExecStartPost` line — startup is atomic, so partial-rule states are impossible.

## When to use `ports.passthrough`

Use `passthrough` for ports where mitmdump's TLS interception isn't workable but the cage still needs reachability. Passthrough entries are auto-merged into the effective allow set, so operators can list them in `passthrough` alone (with a warning surfaced at validation time, mirroring `domains.passthrough`). Common cases:

- **NTP** on `123/udp` — clock sync, required for TLS cert validation in long-running cages
- **IMAP/SMTPS** on `993/tcp`, `465/tcp` — when the cage uses a `protocol_relays` upstream that connects out
- **QUIC / HTTP3** on `443/udp` — UDP can't be MITM'd transparently
- **Custom binary protocols** that mutual-auth with hostnames mitmproxy can't impersonate

```yaml
ports:
  allow: [80, 443, 123, 993]    # explicit superset
  passthrough: [123, 993]       # NTP and IMAP bypass inspection
```

Each passthrough entry installs both a TCP and a UDP `iptables -A FORWARD … -j ACCEPT` rule. UDP coverage matters: NTP, QUIC, and custom UDP services would otherwise be silently dropped.

If a passthrough port isn't explicitly listed in `allow`, validation emits a warning ("ports.passthrough entry N is not in ports.allow and will be added automatically to the effective allow list") and the quadlet generator auto-merges it — same semantics as `domains.passthrough` not appearing in `domains.allow`.

## Reserved ports

Validation rejects four classes of port from the **inspected set** (= `allow - passthrough`). These are ports where a `nat:PREROUTING REDIRECT` would collide with a locally-bound listener inside the proxy container:

| Port | Why |
|------|-----|
| `8443` | mitmdump's transparent listener. Redirecting `8443 → 8443` would loop. |
| `8080` | mitmdump's regular HTTP-proxy listener (the L7 path used by apps that honor `HTTP_PROXY`). Redirecting it would strip the L7 layer. |
| Any `protocol_relays[*].listen` port | The relay binds in-process inside the proxy container. Redirecting that port to mitmdump would intercept the connection before the relay handler sees it. |
| Any `container.ports[*].container_port` inbound forward | mitmdump runs an extra reverse-mode listener on `0.0.0.0:<container_port>` for each inbound forward. PREROUTING REDIRECT fires before the netfilter INPUT decision, so an overlap silently steals inbound connections from the reverse listener. |

These ports are **only reserved against the inspected set**. They're fine in `passthrough` — passthrough entries don't get a REDIRECT rule, so they never collide with locally-bound listeners. If the cage needs to reach an external service on a reserved port, list the port in both `allow` and `passthrough`:

```yaml
ports:
  allow: [80, 443, 1143]
  passthrough: [1143]   # cage→external:1143 forwarded uninspected; doesn't conflict with the in-process IMAP relay on :1143
```

Per-entry rules apply to both lists: integers only (YAML strings, booleans, floats rejected), in range 1-65535, no duplicates.

## Disabling transparent capture

Setting `ports.allow: []` removes the `nat:PREROUTING` REDIRECTs entirely. The cage relies solely on the L7 path (apps that honor `HTTP_PROXY` send `CONNECT` requests to mitmdump on `:8080`). Validation emits a warning when this is detected.

If both `ports.allow: []` and `ports.passthrough: []`, the cage has zero outbound connectivity — `filter:FORWARD` policy DROP is unconditional, and only `ESTABLISHED,RELATED` (response packets to flows already accepted) traverses. Validation surfaces this as a warning so the posture is visible.

## Trade-offs

### Inspector noise on inspected ports

If an inspected port carries high-entropy traffic (E2E-encrypted protocols, binary streams), the `entropy` and `body-size` inspectors will flag every payload. Add per-host exemptions in the `inspectors:` block to suppress the noise without disabling the inspector globally:

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

Adding a port to the inspected set means mitmdump terminates TLS for connections on that port. The cage's runtime must trust the mitmproxy CA. The default cage scaffold mounts the CA via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`; non-Node runtimes may need separate trust-store wiring (e.g. Chromium NSS DB; see `scaffolds/openclaw/entrypoint.sh` for the existing pattern).

### `ports.passthrough` is a deliberate audit gap

Anything in `passthrough` flows uninspected. Use it sparingly — every entry is a port where the audit pipeline (inspector chain, secret injector, `audit.jsonl`) is intentionally blind. The cage's `domains.allow` still gates *which* hosts can be reached on those ports, but the *content* of the traffic is unobservable.

### IPv4 only

The default-deny rules apply to `iptables` (IPv4) only. Podman networks default to IPv4-only unless explicitly configured, but operators using IPv6 networking should add equivalent `ip6tables` rules out-of-band.

## Worked example: jacque (Matrix bot with NTP)

```yaml
name: jacque
container:
  image: localhost/jacque-cage:latest
  env:
    HTTPS_PROXY: "http://10.89.5.11:8080"
    HTTP_PROXY: "http://10.89.5.11:8080"
    NODE_EXTRA_CA_CERTS: "/certs/mitmproxy-ca-cert.pem"

ports:
  allow: [80, 443, 8448, 123]    # HTTP, HTTPS, matrix federation, NTP
  passthrough: [123]             # NTP bypasses inspection (UDP only)

domains:
  allow:
    - anthropic.com
    - homeserver.example
    - pool.ntp.org

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

Without the `8448` entry in `allow`, every `m.room.encrypted` event the bot sends would reach the homeserver but never appear in `audit.jsonl`. Without the `123` entry in both `allow` and `passthrough`, the cage's NTP client would silently fail every clock-sync attempt, drift, and eventually trigger TLS cert-validation failures across the audit path. The bot's domain allowlist still prevents it from talking to *other* hosts on either port.

## Related

- `domains.allow` / `domains.passthrough` use the same shape and semantics for hostnames. See [Configuration Reference — Domain filtering](configuration.md#domain-filtering-domains).
- L7 trust signal (`HTTP_PROXY` honoring): see runtime-specific docs. For openclaw cages, setting `OPENCLAW_PROXY_ACTIVE=1` opts the inner runtime into using `HTTP_PROXY` for requests its own SSRF guard otherwise pins to a direct dispatcher. Complementary to inspected ports, which cover L4 transparently regardless of inner-runtime cooperation.
- Secret injection: see `docs/configuration.md`. The injector runs against captured traffic, so it only sees the inspected set — never `passthrough`.
- Inspector chain: see `docs/configuration.md`. Same scope.
