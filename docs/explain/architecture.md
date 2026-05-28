<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Architecture

agentcage runs each agent inside a small, opinionated topology: a cage container that holds the workload and an egress container that holds everything the workload should not see. This page explains the shape, why it's shaped this way, and how a request flows from the agent out to the internet.

The container backend is the canonical model described here. The VM and apple-container backends preserve the same inspector chain and secret-injection model around a different trust boundary — see [Isolation modes](isolation-modes.md) for the per-backend differences.

## The cage and the egress

A cage is two containers on an internal podman network with no gateway to the outside. The workload sits on the internal subnet only; a single egress sibling sits on both the internal subnet (cage-facing) and the host's default podman network (upstream-facing), so it is the only path out.

```text
host
└── <name>-net (Internal=true, no gateway)
    ├── <name>-cage     workload, internal-only, default route to egress
    └── <name>-egress   mitmproxy + dnsmasq + iptables, dual-homed
```

The split exists because the workload is the untrusted thing. The cage holds the agent process and nothing else of value — no real secrets, no internet gateway, no route to anywhere but the egress. The egress holds the secret values, the audit log, the iptables policy, the DNS allowlist, and the inspector chain. A compromise of the workload buys access to placeholders and an inspected pipe; the egress is what your isolation boundary is meant to protect.

mitmproxy and dnsmasq run side-by-side inside the egress container under a small supervisor, each as its own non-root uid (acproxy 200, acdns 201) with stripped bounding capabilities. The supervisor installs iptables rules in the egress's own network namespace, then signals readiness; the cage's `ExecStartPre` polls for the mitmproxy CA cert in a shared volume before exec'ing the workload, so the cage always boots with `/certs/mitmproxy-ca-cert.pem` mounted read-only and trusted via `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE`.

The cage gets a fixed IP on the internal subnet, `HTTP_PROXY` and `HTTPS_PROXY` env vars pointing at the egress, a default route installed post-start via `nsenter` so passthrough TCP still reaches the egress, and a read-only `/etc/resolv.conf` pointing at the egress's dnsmasq. The egress carries `NET_ADMIN`, `NET_BIND_SERVICE`, and `SETUID`/`SETGID`/`SETPCAP`/`KILL` because the supervisor needs to install iptables rules, bind privileged ports, drop to two unprivileged uids via `setpriv --bounding-set`, and signal both daemons during shutdown.

## Egress flow

A request from the agent traverses three components before it reaches the internet: DNS resolution at the egress's dnsmasq, an iptables decision in the egress's network namespace, and (for inspected ports) the inspector chain inside mitmproxy.

```text
agent in cage
   | 1. resolve hostname
   v
dnsmasq (inside egress, uid 201)
   |   allowlist hit  -> real upstream IP
   |   allowlist miss -> 198.51.100.1 (TEST-NET-2 sinkhole, A and AAAA)
   v
agent sends packet -> default route -> egress netns
   |
   |-- nat:PREROUTING
   |     inspected TCP -> REDIRECT to mitmproxy :8443
   |     (inspected = ports.tcp.allow - ports.tcp.passthrough,
   |      defaulting to [80, 443])
   |
   `-- filter:FORWARD (default DROP)
         established/related -> ACCEPT
         passthrough TCP / allowed UDP -> ACCEPT, uninspected
         anything else                 -> DROP
   |
   v
mitmproxy (inside egress, uid 200)
   | recovers original dst via SO_ORIGINAL_DST
   | substitutes TLS with the mitmproxy CA (trusted in cage)
   | runs the inspector chain
   | injects secrets when destination matches an inject_to rule
   v
upstream
```

The DNS sinkhole for non-allowlisted domains exists because SSRF guards in popular HTTP clients pre-resolve hostnames and refuse to connect to non-public IPs. dnsmasq's `address=/#/198.51.100.1` returns this RFC 5737 TEST-NET-2 address for any zone outside the allowlist, so the cage's connection still reaches the egress, where the real policy decision happens and iptables drops it on the `FORWARD` chain.

REDIRECTed traffic is rewritten as locally-destined, so it traverses `INPUT` to mitmproxy and never hits `FORWARD`. That is how the inspected path coexists with default-deny: inspected ports leave the `FORWARD` chain entirely; passthrough ports are L3-forwarded uninspected; everything else is dropped.

Inbound traffic to a published port enters the egress in mitmproxy reverse-proxy mode (one `--mode reverse:http://<ip_cage>:<port>@0.0.0.0:<port>` per forward), runs through the same inspector chain, and is forwarded to the cage. Published ports are bound on the egress container, not the cage — the host only ever talks to the egress.

## Inspector chain

Inspectors are the request-level policy layer. Each inspector receives a pre-computed `InspectionContext` (url, headers, body, entropy, parsed content-type) and returns allow, flag, or block. The chain runs in registry order and short-circuits on the first hard block — remaining inspectors are skipped, which keeps expensive checks off requests that are already going to fail.

The built-in chain runs in the order `domain`, `secrets`, `body-size`, `entropy`, `content-type`. Cheap, high-reject-rate checks come first so a blocked domain never pays the cost of body analysis. `domain` answers "is this destination on the allowlist", `secrets` answers "is the cage trying to leak a credential", `body-size` answers "is this payload an order of magnitude too large", `entropy` answers "is this an encrypted blob we cannot inspect", and `content-type` answers "does this body match its declared type". Each is independently configurable and independently disablable; `entropy` is opt-in (enable via the top-level `entropy:` mapping or by adding it to `inspectors:`).

Custom inspectors plug into the same chain by subclassing `Inspector` and pointing an `inspectors:` entry at the Python file. They share the `InspectionContext`, the same allow / flag / block contract, and the same short-circuit semantics. Inspectors can also implement `inspect_response()` to scan inbound responses, which is how content-type sniffing catches mismatches that only show up on the way back.

See the [inspectors reference](../reference/inspectors.md) for the built-in inspector list, configuration shape, and the custom-inspector API.

## Secret injection model

Secret injection runs alongside the inspector chain — it modifies the flow in place rather than observing it, but its policy checks plug into the same pre-inspection step. The conceptual move is to keep real secret values out of the cage entirely.

The cage gets a placeholder, e.g. `{{ANTHROPIC_API_KEY}}`. The agent uses the placeholder in headers, query strings, or bodies as if it were the real value. Before the inspector chain runs, a pre-inspection step checks two invariants:

1. **Literal value blocking.** If a real secret value appears in a request to a host outside that secret's `inject_to` list, the request is blocked with severity `critical`. The cage should never know the real value, so its presence indicates the agent learned the secret outside the placeholder system. (When the host IS in `inject_to`, the literal can appear legitimately after injection, so it is allowed.)
2. **Placeholder routing.** If a placeholder is heading to a domain not in that secret's `inject_to` list, the request is flagged. The placeholder is left in place; the request still goes through.

The inspector chain then runs against the request as the cage produced it — placeholders intact, so inspectors see no real secrets. Only after every inspector returns non-block does the injector substitute placeholders for real values; the upstream sees a normal authenticated call. On the response path, the injector reverses the substitution — real values in the response body or headers are redacted back to placeholders before the cage receives them.

The trust property: an agent that exfiltrates everything it can see still only exfiltrates placeholders. The real value lives in the egress's environment (sourced from systemd-creds or the host's podman secret store), is read once at egress start, and never crosses the wire to the cage.

See the [secret injection reference](../reference/secret-injection.md) for setup, secret backends, and per-secret configuration fields.

## Generated files and startup order

`cage create` writes a small set of systemd-managed quadlet units under `~/.config/containers/systemd/`, then a `daemon-reload` picks them up. The dependency chain is encoded directly in the units:

```text
<name>-net.network            (no deps)
<name>-certs.volume           (private mitmproxy state, RW into egress)
<name>-public-certs.volume    (public CA, RW into egress and RO into cage)
<name>-egress.container       Network=<name>-net + default podman network
<name>-cage.container         Requires=<name>-egress.service
```

The cert volumes are split deliberately so the cage never has visibility into mitmproxy's private key. The egress's supervisor generates the CA on first start, installs only the public cert into the public-certs volume, and the cage's `ExecStartPre` polls the egress for that cert for up to 30 seconds before exec'ing the workload. The cage sees `/certs/mitmproxy-ca-cert.pem` (read-only); the private key never leaves the egress.

A second `ExecStartPost` on the cage uses `nsenter` against the cage's pid to install a default route into the cage netns, pointing at the egress. Without it, the cage has no route to anything but the internal subnet — and `HTTP_PROXY` alone would miss any non-HTTP-aware client.

The port policy — which TCP ports get inspected, which get passthrough, which UDP ports are allowed at all — is enforced by iptables rules the egress's supervisor installs at start, driven by env vars rendered into the quadlet. See the [ports reference](../reference/ports.md) for the rule layout and how to extend the allow set past the default `[80, 443]`.

### Hot-reload semantics

`cage edit` opens the stored `cage.yaml`, validates on save, classifies the diff, and chooses the lightest-touch reload that still applies the change:

- **Live reload** (no service restart): `domains`, `inspectors`, `secret_injection`, `rate_limit`, `logging`, `capture`, `protocol_relays`, `max_request_body`, `entropy`, `content_type`. Domain edits rewrite the dnsmasq allowlist and SIGHUP dnsmasq via its pidfile; the rest are picked up by the mitmproxy addon's mtime poll on `/etc/agentcage/config.yaml`.
- **Service restart** (no rebuild): anything else — for example `container.env`, `container.command`, `ports`, `container.volumes`. `cage edit` writes the new YAML and tells you to run `agentcage cage restart NAME`.
- **Image rebuild**: `isolation` and `vm`. These need `agentcage cage update` (or destroy + create) because the backend or VM shape itself changed.

`cage edit` prints exactly which keys fell into which bucket and the command needed to apply each restart-or-rebuild slice. The cage process itself is untouched on live reloads, so an interactive shell inside the cage survives a `domain add` or an inspector tweak.

### Nested containers

With `nested_containers: true`, the cage runs podman internally so it can host agent frameworks that spawn containers; a docker-cli shim translates `docker` invocations to `podman`. Inner containers default to `--network none`; `--network host` is the only way they pick up the cage's proxy env vars and thus the inspector chain. Nested containers weaken the cage's hardening (added capabilities, writable container storage) — see the [configuration reference](../reference/configuration.md) for the trade-offs and exact settings.

## Related

- [Isolation modes](isolation-modes.md) — container, vm, and apple-container backend differences
- [Inspectors reference](../reference/inspectors.md) — built-in inspectors and custom-inspector API
- [Secret injection reference](../reference/secret-injection.md) — setup, backends, and transforms
- [Ports reference](../reference/ports.md) — port policy and iptables layout
- [Security model](security-model.md) — what each isolation mode defends against
