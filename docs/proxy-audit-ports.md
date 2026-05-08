# Port policy: `ports.tcp` and `ports.udp`

The proxy container enforces a default-deny network policy on every cage. Cage→external traffic is dropped unless the destination port is explicitly listed in one of three fields, organized by transport protocol:

- `ports.tcp.allow` — TCP destination ports the cage may reach (audited via mitmdump unless also in `passthrough`).
- `ports.tcp.passthrough` — subset of TCP ports that bypass mitmdump inspection. Auto-merged into the effective TCP allow set if not listed in `tcp.allow`.
- `ports.udp.allow` — UDP destination ports the cage may reach. UDP is never inspected (mitmdump is HTTP-only) — every entry is forwarded uninspected.

Inspected TCP ports = `tcp.allow - tcp.passthrough`. Outbound ICMP echo-request is always permitted for diagnostics. IPv6 forwarding is dropped by an `ip6tables -P FORWARD DROP` failsafe. There is no opt-out flag for the default-deny posture; every cage gets it on next `agentcage cage update`.

> **BREAKING change (Unreleased):** the default-deny `filter:FORWARD` policy is new. Pre-change, anything not in the audit list was silently L3-forwarded uninspected — the cage's `domains.allow` gated *which hosts* could be reached but said nothing about *which ports* could exit. An agent that resolved an allowed hostname could exfiltrate over any TCP or UDP port (NTP, custom binary protocols, QUIC) with the audit pipeline blind. The new posture closes that gap.
>
> **Migration impact:** cages that talk *only* on the default `tcp.allow` (`[80, 443]`) keep working unchanged. Cages that depend on outbound on any other port — NTP for clock sync (`123/udp`), Postgres (`5432/tcp`), IMAP (`993/tcp`), QUIC/HTTP3 (`443/udp`), custom services — must add those ports to `tcp.allow`/`tcp.passthrough` (TCP) or `udp.allow` (UDP) or lose connectivity. DNS is unaffected: cages talk to the sidecar dns container directly on the same subnet and never traverse the proxy's FORWARD chain.

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
│     -p tcp --dport <inspected_tcp> -j REDIRECT --to-port 8443 │
│         (inspected_tcp = ports.tcp.allow - ports.tcp.passthrough)│
│                                                               │
│   filter:FORWARD                                              │
│     -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT      │
│     -p icmp --icmp-type echo-request -j ACCEPT                │
│     -p tcp --dport <tcp.passthrough> -j ACCEPT                │
│     -p udp --dport <udp.allow>       -j ACCEPT                │
│   policy: DROP                                                │
│                                                               │
│   ip6tables filter:FORWARD policy: DROP (failsafe)            │
└──┬─────────────────────────┬────────────────────────────┬────┘
   │ inspected_tcp           │ passthrough_tcp / udp.allow │ neither
   ▼                         ▼                             ▼
┌─────────────────┐  ┌──────────────────────┐  ┌────────────────────┐
│ mitmdump :8443  │  │ kernel L3 forward    │  │ DROP at FORWARD    │
│ transparent     │  │ → upstream            │  │ policy             │
│ → AUDITED       │  │ → NOT AUDITED         │  │ → BLOCKED          │
└─────────────────┘  └──────────────────────┘  └────────────────────┘
```

REDIRECTed traffic never reaches `filter:FORWARD` — REDIRECT rewrites the destination as local, so packets traverse `INPUT` to mitmdump. mitmdump uses `SO_ORIGINAL_DST` to recover the pre-REDIRECT destination, so any TLS-terminated TCP port works without per-port mitmdump configuration; the mitmproxy CA cert (mounted into the cage at `/certs/mitmproxy-ca-cert.pem` and trusted via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`) handles the TLS substitution.

## Defaults

```yaml
ports:
  tcp:
    allow: [80, 443]    # default — applied if `ports.tcp.allow` is omitted
    passthrough: []     # default — every allowed TCP port is inspected
  udp:
    allow: []           # default — UDP is opt-in only
```

Cages that only talk HTTP/HTTPS on standard ports get full audit coverage and zero configuration. Anything beyond that — NTP, QUIC/HTTP3, Matrix federation on 8448, internal services on custom ports — needs an explicit entry.

## When to extend `ports.tcp.allow`

Use `tcp.allow` to permit TCP destination ports the cage needs to reach. Adding a port without also listing it in `tcp.passthrough` means it's inspected — TCP traffic gets REDIRECTed to mitmdump's transparent listener and runs through `audit.jsonl`, the inspector chain, and the secret injector.

Inspected ports work best where mitmdump's transparent TLS interception holds: the cage's runtime trusts the mitmproxy CA, and the upstream uses TLS that mitmproxy can substitute.

- **Matrix homeserver** on port `8448` (federation)
- **PostgreSQL** on `5432` (when wrapped in TLS)
- **MQTT/TLS** on `8883`
- **Any internal service** the operator runs on a non-default port over TLS the runtime will trust

```yaml
ports:
  tcp:
    allow: [80, 443, 8448]
```

## When to use `ports.tcp.passthrough`

Use `tcp.passthrough` for TCP ports where mitmdump's TLS interception isn't workable but the cage still needs reachability. Passthrough entries are auto-merged into the effective allow set, so operators can list them in `passthrough` alone (with a validation warning, mirroring `domains.passthrough`).

- **IMAP/SMTPS** on `993/tcp`, `465/tcp` — when the cage uses a `protocol_relays` upstream that connects out
- **Custom binary protocols** that mutual-auth with hostnames mitmproxy can't impersonate
- **Pinned-cert clients** that won't accept the mitmproxy CA

```yaml
ports:
  tcp:
    allow: [80, 443, 5432]
    passthrough: [5432]    # postgres bypasses inspection
```

## When to extend `ports.udp.allow`

Every UDP service requires an explicit `udp.allow` entry. UDP is never inspected — mitmdump is HTTP-only, so there is no inspection-vs-passthrough distinction for UDP — but the default-deny `filter:FORWARD` policy will drop any UDP that isn't listed.

- **NTP** on `123` — clock sync, required for TLS cert validation in long-running cages
- **QUIC / HTTP3** on `443` — modern HTTP libraries auto-negotiate UDP/443 alongside TCP/443
- **Custom UDP protocols** — SNMP (`161`), syslog (`514`), STUN/TURN, etc.

```yaml
ports:
  udp:
    allow: [123, 443]    # NTP and HTTP/3
```

### TCP/443 audited + UDP/443 reachable

The independent TCP/UDP shape is what makes the headline HTTP/3 case work. Listing `443` in `tcp.allow` (and not in `tcp.passthrough`) inspects HTTP/2 traffic; listing `443` in `udp.allow` lets HTTP/3 reach upstream uninspected. The two protocols on the same port are governed independently:

```yaml
ports:
  tcp:
    allow: [80, 443]   # HTTP/1.1, HTTP/2 audited
  udp:
    allow: [443]       # HTTP/3 reachable, uninspected (mitmdump can't audit QUIC)
```

A cage that uses HTTP/3 will have audit entries for handshake fallbacks and for any TLS-over-TCP traffic, but the QUIC stream itself is invisible — that's an inherent limitation of mitmdump, not a posture choice. If `udp.allow: [443]` is omitted, modern HTTP libraries that try QUIC first will silently retry over TCP (a few hundred ms penalty per request) — which is sometimes the right call for a cage that should never use HTTP/3.

## Reserved ports

Validation rejects four classes of port from the **inspected TCP set** (= `tcp.allow - tcp.passthrough`). These are ports where a `nat:PREROUTING REDIRECT` would collide with a locally-bound listener inside the proxy container:

| Port | Why |
|------|-----|
| `8443` | mitmdump's transparent listener. Redirecting `8443 → 8443` would loop. |
| `8080` | mitmdump's regular HTTP-proxy listener (the L7 path used by apps that honor `HTTP_PROXY`). Redirecting it would strip the L7 layer. |
| Any `protocol_relays[*].listen` port | The relay binds in-process inside the proxy container. Redirecting that port to mitmdump would intercept the connection before the relay handler sees it. |
| Any `container.ports[*].container_port` inbound forward | mitmdump runs an extra reverse-mode listener on `0.0.0.0:<container_port>` for each inbound forward. PREROUTING REDIRECT fires before the netfilter INPUT decision, so an overlap silently steals inbound connections from the reverse listener. |

These ports are **only reserved against the inspected TCP set**. They're fine in `tcp.passthrough` (no REDIRECT, no collision) and fine in `udp.allow` (UDP can never collide with mitmdump's TCP listeners). If the cage needs to reach an external service on a reserved port, list the port in both `tcp.allow` and `tcp.passthrough`:

```yaml
ports:
  tcp:
    allow: [80, 443, 1143]
    passthrough: [1143]   # cage→external:1143 forwarded uninspected; doesn't conflict with the in-process IMAP relay on :1143
```

Per-entry rules apply to all three lists: integers only (YAML strings, booleans, floats rejected), in range 1-65535, no duplicates.

## ICMP and IPv6

**ICMP echo-request is always allowed** outbound. `ping` from inside the cage works for diagnostics; replies ride the `ESTABLISHED,RELATED` rule. There's no config knob to disable this — the rule is unconditional. Any other ICMP type (echo-reply for *new* unsolicited replies, unreachables generated by intermediate routers, redirects) is dropped by the default policy.

**IPv6 is uncovered.** The proxy installs an `ip6tables -P FORWARD DROP` failsafe so any IPv6 traffic the cage might attempt is dropped at the proxy. Today's podman networks are IPv4-only (`10.89.x.0/24`), so this is a latent-gap failsafe rather than active filtering. Future IPv6 support would require mirroring the v4 REDIRECT/FORWARD rules in `ip6tables`.

## Disabling transparent capture

Setting `ports.tcp.allow: []` removes the `nat:PREROUTING` REDIRECTs entirely. The cage relies solely on the L7 path (apps that honor `HTTP_PROXY` send `CONNECT` requests to mitmdump on `:8080`). Validation emits a warning when this is detected.

If `tcp.allow`, `tcp.passthrough`, and `udp.allow` are all empty, the cage has zero outbound TCP/UDP — `filter:FORWARD` policy DROP is unconditional. Only ICMP echo and `ESTABLISHED,RELATED` (response packets to flows already accepted) traverse. Validation surfaces this as a warning so the posture is visible.

## Trade-offs

### Inspector noise on inspected ports

If an inspected port carries high-entropy traffic (E2E-encrypted protocols, binary streams), the `entropy` and `body-size` inspectors will flag every payload. Add per-host exemptions in the `inspectors:` block:

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

Adding a port to the inspected TCP set means mitmdump terminates TLS for connections on that port. The cage's runtime must trust the mitmproxy CA. The default cage scaffold mounts the CA via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`; non-Node runtimes may need separate trust-store wiring (e.g. Chromium NSS DB; see `scaffolds/openclaw/entrypoint.sh` for the existing pattern).

### `tcp.passthrough` and `udp.allow` are deliberate audit gaps

Anything in `tcp.passthrough` or `udp.allow` flows uninspected. Use them sparingly — every entry is a port where the audit pipeline (inspector chain, secret injector, `audit.jsonl`) is intentionally blind. The cage's `domains.allow` still gates *which* hosts can be reached on those ports, but the *content* is unobservable.

## Worked example: jacque (Matrix bot)

```yaml
name: jacque
container:
  image: localhost/jacque-cage:latest
  env:
    HTTPS_PROXY: "http://10.89.5.11:8080"
    HTTP_PROXY: "http://10.89.5.11:8080"
    NODE_EXTRA_CA_CERTS: "/certs/mitmproxy-ca-cert.pem"

ports:
  tcp:
    allow: [80, 443, 8448]    # HTTP, HTTPS, Matrix federation — all audited
  udp:
    allow: [123]              # NTP for clock sync

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

Without `8448` in `tcp.allow`, every `m.room.encrypted` event the bot sends would reach the homeserver but never appear in `audit.jsonl`. Without `123` in `udp.allow`, the cage's NTP client would silently fail every clock-sync attempt, drift, and eventually trigger TLS cert-validation failures across the audit path. The bot's domain allowlist still prevents it from talking to *other* hosts on either port.

## Related

- `domains.allow` / `domains.passthrough` use the same allow/passthrough shape for hostnames. See [Configuration Reference — Domain filtering](configuration.md#domain-filtering-domains).
- L7 trust signal (`HTTP_PROXY` honoring): see runtime-specific docs. For openclaw cages, setting `OPENCLAW_PROXY_ACTIVE=1` opts the inner runtime into using `HTTP_PROXY` for requests its own SSRF guard otherwise pins to a direct dispatcher. Complementary to inspected ports, which cover L4 transparently regardless of inner-runtime cooperation.
- Secret injection: see `docs/configuration.md`. The injector runs against captured traffic, so it only sees the inspected TCP set — never `passthrough` or UDP.
- Inspector chain: see `docs/configuration.md`. Same scope.
