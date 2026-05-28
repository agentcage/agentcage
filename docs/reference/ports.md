<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Ports

The proxy container's default-deny `filter:FORWARD` policy and the `ports.tcp` / `ports.udp` allowlists that govern cage egress. Read this when extending a cage past HTTP/HTTPS.

`ports.tcp.allow` lists TCP destination ports the cage may reach (audited via mitmdump unless also in `passthrough`). `ports.tcp.passthrough` is the subset that bypasses mitmdump — auto-merged into the effective TCP allow set if not listed in `tcp.allow`. `ports.udp.allow` lists UDP destination ports; UDP is never inspected (mitmdump is HTTP-only).

Inspected TCP ports = `tcp.allow - tcp.passthrough`. Outbound ICMP echo-request is always permitted for diagnostics. IPv6 forwarding is dropped by an `ip6tables -P FORWARD DROP` failsafe. There is no opt-out flag for the default-deny posture; every cage gets it on next `agentcage cage update`.

*Since 0.15.0* — pre-0.15 anything not in the audit list was silently L3-forwarded uninspected, so an agent that resolved an allowed hostname could exfiltrate over any port (NTP, custom binary protocols, QUIC) with the audit pipeline blind. Cages that talk *only* on the default `tcp.allow` (`[80, 443]`) keep working unchanged. Cages that depend on outbound on any other port — NTP (`123/udp`), Postgres (`5432/tcp`), IMAP (`993/tcp`), QUIC/HTTP3 (`443/udp`) — must add those ports or lose connectivity. DNS is unaffected: cages talk to the sidecar dns container directly on the same subnet and never traverse the proxy's FORWARD chain.

## How agentcage routes cage traffic

Each cage netns has a default route via the proxy container's IP. Inside the proxy netns, two iptables chains decide what happens to each packet:

```
┌─ cage netns ─────────────────────────────────────────────────┐
│ default route via proxy IP                                    │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│ proxy netns                                                   │
│   nat:PREROUTING                                              │
│     -p tcp --dport <inspected_tcp> -j REDIRECT --to-port 8443 │
│         (inspected_tcp = tcp.allow - tcp.passthrough)         │
│   filter:FORWARD                                              │
│     -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT      │
│     -p icmp --icmp-type echo-request -j ACCEPT                │
│     -p tcp --dport <tcp.passthrough> -j ACCEPT                │
│     -p udp --dport <udp.allow>       -j ACCEPT                │
│   policy: DROP                                                │
│   ip6tables filter:FORWARD policy: DROP (failsafe)            │
└──┬─────────────────────────┬────────────────────────────┬────┘
   │ inspected_tcp           │ passthrough_tcp / udp.allow │ neither
   ▼                         ▼                             ▼
 mitmdump :8443        kernel L3 forward             DROP at FORWARD
 transparent → AUDITED → upstream → NOT AUDITED       policy → BLOCKED
```

REDIRECTed traffic never reaches `filter:FORWARD` — REDIRECT rewrites the destination as local, so packets traverse `INPUT` to mitmdump. mitmdump uses `SO_ORIGINAL_DST` to recover the pre-REDIRECT destination, so any TLS-terminated TCP port works without per-port configuration; the mitmproxy CA cert (mounted into the cage at `/certs/mitmproxy-ca-cert.pem` and trusted via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`) handles the TLS substitution.

## Defaults

```yaml
ports:
  tcp:
    allow: [80, 443]    # default — applied if ports.tcp.allow is omitted
    passthrough: []     # default — every allowed TCP port is inspected
  udp:
    allow: []           # default — UDP is opt-in only
```

Cages that only talk HTTP/HTTPS on standard ports get full audit coverage and zero configuration. Anything beyond that — NTP, QUIC/HTTP3, Matrix federation on 8448, internal services on custom ports — needs an explicit entry.

## When to extend `tcp.allow`

`tcp.allow` permits TCP destination ports. Adding a port without also listing it in `tcp.passthrough` means it's inspected — TCP traffic gets REDIRECTed to mitmdump's transparent listener and runs through `audit.jsonl`, the inspector chain, and the secret injector. Inspected ports work best where mitmdump's transparent TLS interception holds: the runtime trusts the mitmproxy CA and the upstream uses TLS that mitmproxy can substitute. Typical cases: Matrix homeserver federation (`8448`), PostgreSQL over TLS (`5432`), MQTT/TLS (`8883`), internal services on non-default ports.

```yaml
ports:
  tcp:
    allow: [80, 443, 8448]
```

## When to use `tcp.passthrough`

`tcp.passthrough` is for TCP ports where mitmdump's TLS interception isn't workable but the cage still needs reachability — IMAP/SMTPS (`993`, `465`) reached via a [protocol relay](protocol-relays.md), custom binary protocols, or pinned-cert clients that won't accept the mitmproxy CA. Passthrough entries are auto-merged into the effective allow set, so listing them in `passthrough` alone works (with a validation warning, mirroring `domains.passthrough`).

```yaml
ports:
  tcp:
    allow: [80, 443, 5432]
    passthrough: [5432]    # postgres bypasses inspection
```

## When to extend `udp.allow`

Every UDP service needs an explicit `udp.allow` entry. UDP is never inspected, so there's no inspection-vs-passthrough distinction — the default-deny `filter:FORWARD` policy drops any UDP that isn't listed. Typical: NTP (`123`) for clock sync, QUIC/HTTP3 (`443`), SNMP (`161`), syslog (`514`), STUN/TURN.

```yaml
ports:
  udp:
    allow: [123, 443]    # NTP and HTTP/3
```

### TCP/443 audited + UDP/443 reachable

The independent TCP/UDP shape makes the headline HTTP/3 case work. Listing `443` in `tcp.allow` (and not in `tcp.passthrough`) inspects HTTP/2; listing `443` in `udp.allow` lets HTTP/3 reach upstream uninspected. The two protocols on the same port are governed independently:

```yaml
ports:
  tcp:
    allow: [80, 443]   # HTTP/1.1, HTTP/2 audited
  udp:
    allow: [443]       # HTTP/3 reachable, uninspected (mitmdump can't audit QUIC)
```

A cage that uses HTTP/3 will have audit entries for handshake fallbacks and TLS-over-TCP, but the QUIC stream itself is invisible — an inherent mitmdump limitation. If `udp.allow: [443]` is omitted, modern HTTP libraries that try QUIC first will silently retry over TCP (a few hundred ms penalty per request).

## Reserved ports

Validation rejects four classes of port from the **inspected TCP set** (= `tcp.allow - tcp.passthrough`). These are ports where a `nat:PREROUTING REDIRECT` would collide with a locally-bound listener inside the proxy container:

| Port | Why |
|------|-----|
| `8443` | mitmdump's transparent listener. Redirecting `8443 → 8443` would loop. |
| `8080` | mitmdump's regular HTTP-proxy listener (the L7 path used by apps that honor `HTTP_PROXY`). Redirecting it would strip the L7 layer. |
| Any `protocol_relays[*].listen` port | The relay binds in-process inside the proxy container. Redirecting that port would intercept the connection before the relay handler sees it. |
| Any `container.ports[*].container_port` inbound forward | mitmdump runs a reverse-mode listener on `0.0.0.0:<container_port>` for each inbound forward. PREROUTING REDIRECT fires before the netfilter INPUT decision, so an overlap silently steals inbound connections. |

These ports are only reserved against the inspected TCP set. They're fine in `tcp.passthrough` (no REDIRECT, no collision) and fine in `udp.allow` (UDP can never collide with mitmdump's TCP listeners). If the cage needs to reach an external service on a reserved port, list the port in both `tcp.allow` and `tcp.passthrough`:

```yaml
ports:
  tcp:
    allow: [80, 443, 1143]
    passthrough: [1143]   # forwarded uninspected; doesn't conflict with in-process IMAP relay on :1143
```

Per-entry rules apply to all three lists: integers only (YAML strings, booleans, floats rejected), in range 1-65535, no duplicates.

## ICMP and IPv6

ICMP echo-request is always allowed outbound — `ping` from inside the cage works for diagnostics, and replies ride the `ESTABLISHED,RELATED` rule. There's no config knob; the rule is unconditional. Any other ICMP type (unsolicited echo-reply, unreachables, redirects) is dropped by the default policy.

IPv6 is uncovered. The proxy installs an `ip6tables -P FORWARD DROP` failsafe so any IPv6 traffic the cage attempts is dropped. Today's podman networks are IPv4-only (`10.89.x.0/24`), so this is a latent-gap failsafe rather than active filtering.

## Disabling transparent capture

Setting `ports.tcp.allow: []` removes the `nat:PREROUTING` REDIRECTs entirely. The cage relies solely on the L7 path (apps that honor `HTTP_PROXY` send `CONNECT` requests to mitmdump on `:8080`). Validation emits a warning when this is detected. If `tcp.allow`, `tcp.passthrough`, and `udp.allow` are all empty, the cage has zero outbound TCP/UDP — only ICMP echo and `ESTABLISHED,RELATED` traverse. Validation surfaces this as a warning so the posture is visible.

## Trade-offs

**Inspector noise on inspected ports.** If an inspected port carries high-entropy traffic (E2E-encrypted protocols, binary streams), the `entropy` and `body-size` inspectors will flag every payload. Add per-host exemptions in the `inspectors:` block:

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

**TLS interception scope.** Adding a port to the inspected TCP set means mitmdump terminates TLS on that port. The cage's runtime must trust the mitmproxy CA. The default scaffold mounts it via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`; non-Node runtimes may need separate trust-store wiring (e.g. Chromium NSS DB; see `scaffolds/openclaw/entrypoint.sh`).

**Deliberate audit gaps.** Anything in `tcp.passthrough` or `udp.allow` flows uninspected. Use them sparingly — every entry is a port where the audit pipeline is intentionally blind. The `domains.allow` list still gates which hosts can be reached on those ports, but the content is unobservable.

## Worked example: homeserver + NTP

```yaml
name: example-bot
container:
  image: localhost/example-bot:latest
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

Without `8448` in `tcp.allow`, every encrypted event reaches the homeserver but never appears in `audit.jsonl`. Without `123` in `udp.allow`, the NTP client silently fails, drift accumulates, and TLS cert-validation eventually breaks across the audit path. The domain allowlist still prevents the bot from talking to other hosts on either port.

## Related

- [Domains](domains.md) — same allow/passthrough shape, applied to hostnames instead of ports.
- [Secret injection](secret-injection.md) — runs against inspected TCP only; never `passthrough` or UDP.
- [Inspectors](inspectors.md) — chain that processes inspected TCP traffic.
- [Protocol relays](protocol-relays.md) — in-proxy listeners whose `listen` ports are reserved against the inspected set.
