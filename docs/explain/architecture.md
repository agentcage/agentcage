<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Architecture

agentcage runs each agent inside a small, opinionated topology: a cage container that holds the workload and a proxy container that holds everything the workload should not see. This page explains the shape, why it's shaped this way, and how a request flows from the agent out to the internet.

The container backend is the canonical model described here. The VM and apple-container backends preserve the same inspector chain and secret-injection model around a different trust boundary — see [Isolation modes](isolation-modes.md) for the per-backend differences.

## The cage and the proxy

A cage is two containers on a `--internal` podman network with no internet gateway, plus a dns sidecar bridging the gap. The agent sits on the internal network only; the dns sidecar and proxy are dual-homed so they can reach upstream.

```text
host
└── <name>-net (--internal, no gateway)
    ├── <name>-cage    workload, internal-only, default route to proxy
    ├── <name>-dns     dnsmasq, dual-homed
    └── <name>-proxy   mitmproxy + inspector chain, dual-homed
```

The split exists because the workload is the untrusted thing. The cage holds the agent process and nothing else of value — no real secrets, no internet gateway, no route to anywhere but the proxy. The proxy holds the egress filter, the secret values, the audit log, and the iptables policy. A compromise of the workload buys access to placeholders and an inspected pipe; the proxy is what your isolation boundary is meant to protect.

The cage gets a fixed IP on the internal subnet, a default route pointing at the proxy, and a read-only `/etc/resolv.conf` pinned to the dns sidecar. It runs read-only rootfs with all capabilities dropped and `no-new-privileges`. The proxy gets `NET_ADMIN` so it can install iptables rules and enforce the default-deny `FORWARD` policy.

## Egress flow

A request from the agent traverses three components before it reaches the internet: dns resolution at the sidecar, an iptables decision at the proxy, and (for inspected ports) the inspector chain inside mitmproxy.

```text
agent in cage
   | 1. resolve hostname
   v
dns sidecar (dnsmasq)
   |   allowlist hit  -> real upstream IP
   |   allowlist miss -> 198.51.100.1 (TEST-NET-2 placeholder)
   v
agent sends packet -> default route -> proxy netns
   |
   |-- nat:PREROUTING
   |     inspected TCP -> REDIRECT to mitmproxy :8443
   |     (inspected = ports.tcp.allow - ports.tcp.passthrough)
   |
   `-- filter:FORWARD (default DROP)
         passthrough TCP / allowed UDP -> L3 forward, uninspected
         anything else                 -> DROP
   |
   v
mitmproxy
   | recovers original dst via SO_ORIGINAL_DST
   | substitutes TLS with the mitmproxy CA (trusted in cage)
   | runs the inspector chain
   | injects secrets when destination matches an inject_to rule
   v
upstream
```

The dns placeholder for non-allowlisted domains exists because SSRF guards in popular HTTP clients pre-resolve hostnames and refuse to connect to non-public IPs. Returning a routable-looking TEST-NET-2 address lets the request reach the proxy, where the real policy decision happens.

REDIRECTed traffic is rewritten as locally-destined, so it traverses `INPUT` to mitmproxy and never hits `FORWARD`. That is how the inspected path coexists with default-deny: inspected ports leave the FORWARD chain entirely; passthrough ports are L3-forwarded uninspected; everything else is dropped.

Inbound traffic to a published port enters via mitmproxy in reverse-proxy mode, runs through the same inspector chain, and is forwarded to the cage. Published ports are not exposed on the cage container directly — the host only ever talks to the proxy.

## Inspector chain

Inspectors are the request-level policy layer. Each inspector receives a pre-computed `InspectionContext` (url, headers, body, entropy, parsed content-type) and returns allow, flag, or block. The chain runs in declared order and short-circuits on the first hard block — remaining inspectors are skipped, which keeps expensive checks off requests that are already going to fail.

The split between inspectors is not cosmetic. `domain` answers "is this destination on the allowlist", `secrets` answers "is the cage trying to leak a credential", `body-size` and `content-type` answer "does this look like exfiltration", `entropy` answers "is this an encrypted blob we cannot inspect". Each is independently configurable, independently disablable, and independently extensible. Custom inspectors plug in by extending the `Inspector` base class.

Inspectors can also implement `inspect_response()` to scan inbound responses, which is how content-type sniffing catches mismatches that only show up on the way back.

See the [inspectors reference](../reference/inspectors.md) for the built-in inspector list, configuration shape, and the custom-inspector API.

## Secret injection model

Secret injection runs outside the inspector chain — it modifies the flow in place rather than observing it. The conceptual move is to keep real secret values out of the cage entirely.

The cage gets a placeholder, e.g. `{{ANTHROPIC_API_KEY}}`. The agent uses the placeholder in headers, query strings, or bodies as if it were the real value. When the request reaches the proxy, a pre-inspection step checks two invariants:

1. **Literal value blocking.** If a real secret value appears anywhere in the request — url, headers, or body — the request is blocked with severity `critical`. The cage should never know the real value, so its presence indicates the agent learned the secret outside the placeholder system.
2. **Placeholder routing.** If a placeholder is heading to a domain not in that secret's `inject_to` list, the request is flagged.

If both checks pass, the injector substitutes the placeholder for the real value, the inspector chain runs against the substituted request, and the upstream sees a normal authenticated call. On the response path, the injector reverses the substitution — real values in the response body or headers are redacted back to placeholders before the cage receives them.

The trust property: an agent that exfiltrates everything it can see still only exfiltrates placeholders. The real value lives in the proxy's environment (or a host secret store), gets read once at proxy start, and never crosses the wire to the cage.

See the [secret injection reference](../reference/secret-injection.md) for setup, secret backends, and per-secret configuration fields.

## Generated files and startup order

`cage create` writes a small set of systemd-managed quadlet units to the cage's state directory, then `systemctl --user daemon-reload` picks them up. The dependency chain is encoded directly in the units:

```text
<name>-net.network         (no deps)
<name>-certs.volume        (no deps)
<name>-dns.container       Requires=<name>-net-network.service
<name>-proxy.container     Requires=<name>-dns.service, <name>-certs-volume.service
<name>-cage.container      Requires=<name>-proxy.service
```

The cage waits on the proxy for two reasons: the proxy generates the mitmproxy CA cert on first start and writes it to the shared certs volume, and the cage's `ExecStartPre` polls that volume for up to 30 seconds before exec'ing the workload. This guarantees the cage always boots with a valid CA cert mounted at `/certs/mitmproxy-ca-cert.pem` and trusted via `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE`.

An `ExecStartPost` on the cage uses `nsenter` to install the default route into the cage netns, pointing at the proxy. Without it, the cage has no route to anything but the internal subnet.

The port policy — which TCP ports get inspected, which get passthrough, which UDP ports are allowed at all — is enforced by iptables rules installed by the proxy at start. See the [ports reference](../reference/ports.md) for the rule layout and how to extend the allow set past the default `[80, 443]`.

### Hot-reload semantics

`cage edit` opens the stored `cage.yaml`, validates on save, and chooses the lightest-touch reload that still applies the change:

- **Hot-reload** (no service restart): domains, inspector config, rate limits, logging fields. Sent to the running proxy via SIGUSR1.
- **Service restart** (no rebuild): `ports`, `secret_injection`, command, env, restart policy. The proxy and cage are restarted; images are unchanged.
- **Image rebuild**: `container.image`, isolation backend, base-image-level changes. Same path as `cage update`.

The CLI prompts when a change escalates beyond hot-reload, so you can choose between staging the change and applying it immediately.

### Nested containers

With `nested_containers: true`, the cage runs podman internally so it can host agent frameworks that spawn containers; a docker-cli shim translates `docker` invocations to `podman`. Inner containers default to `--network none`; `--network host` is the only way they pick up the cage's proxy env vars and thus the inspector chain. Nested containers weaken the cage's hardening (added capabilities, writable container storage) — see the [configuration reference](../reference/configuration.md) for the trade-offs and exact settings.

## Related

- [Isolation modes](isolation-modes.md) — container, vm, and apple-container backend differences
- [Inspectors reference](../reference/inspectors.md) — built-in inspectors and custom-inspector API
- [Secret injection reference](../reference/secret-injection.md) — setup, backends, and transforms
- [Ports reference](../reference/ports.md) — port policy and iptables layout
- [Security model](security-model.md) — what each isolation mode defends against
