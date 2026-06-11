<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Architecture

agentcage runs each agent inside a small, opinionated topology: a cage container that holds the workload and an egress container that holds everything the workload should not see. This page explains the shape, why it's shaped this way, and how a request flows from the agent out to the internet.

The container backend is the canonical model described here. The VM and apple-container backends preserve the same inspector chain and secret-injection model around a different trust boundary — see [Isolation modes](isolation-modes.md) for the per-backend differences.

## The cage and the egress

A cage is two containers on an internal podman network with no gateway to the outside. The workload sits on the internal network only; the egress sibling is dual-homed onto both the internal network and the host's default network, so it is the only path out.

```text
host
└── internal network (no gateway)
    ├── cage     workload, internal-only, default route to egress
    └── egress   proxy + DNS + firewall, dual-homed
```

The split exists because the workload is the untrusted thing. The cage holds the agent process and nothing else of value — no real secrets, no internet gateway, no route to anywhere but the egress. The egress holds the secret values, the audit log, the firewall policy, the DNS allowlist, and the inspector chain. A compromise of the workload buys access to placeholders and an inspected pipe; the egress is what your isolation boundary is meant to protect.

The egress runs a TLS-intercepting HTTP proxy and a DNS resolver. The cage boots with `HTTP_PROXY` and `HTTPS_PROXY` set to the egress, DNS pointed at the egress, and the proxy's CA installed as a trusted root. Apps that don't honor `HTTP_PROXY` are still caught — the egress transparently intercepts traffic on inspected ports.

## Egress flow

A request from the cage hits the egress's DNS, then its firewall, then — for inspected ports — its proxy. The DNS resolver returns real upstream IPs for allowlisted zones and a sinkhole IP (RFC 5737 TEST-NET-2) for everything else. The firewall is default-deny: inspected ports go to the proxy, passthrough ports are forwarded uninspected, and anything else is dropped. The proxy terminates TLS, runs the inspector chain, and injects secrets.

The DNS sinkhole exists because SSRF guards in popular HTTP clients pre-resolve hostnames and refuse to connect to non-public IPs. A sinkhole IP lets the connection reach the egress, where the real policy decision happens. You'll see TEST-NET-2 addresses in cage logs for names outside the allowlist — that's why.

Default-deny is what makes the port allowlist meaningful: any TCP port not explicitly inspected or passed through is dropped. See the [ports reference](../reference/ports.md) for extending the allow set past the default `[80, 443]`.

Inbound traffic to a published port enters the egress, runs through the same inspector chain, and is forwarded to the cage. The host only ever talks to the egress.

## Inspector chain

Inspectors are the request-level policy layer. Each inspector receives a request and returns allow, flag, or block. The chain runs in registry order and short-circuits on the first hard block, so cheap, high-reject-rate checks come first and a blocked domain never pays the cost of body analysis.

The built-in chain answers, in order: is this destination on the allowlist (`domain`), is the cage trying to leak a credential (`secrets`), is this payload an order of magnitude too large (`body-size`), is this an encrypted blob we cannot inspect (`entropy`, opt-in), and does this body match its declared type (`content-type`). Each is independently configurable and disablable.

Custom inspectors plug into the same chain with the same allow / flag / block contract and can also scan inbound responses. See the [inspectors reference](../reference/inspectors.md) for the built-in list, configuration, and the custom-inspector API.

## Secret injection model

Secret injection keeps real secret values out of the cage entirely.

The cage gets a placeholder — a generated decoy token like `{{placeholder_anthropic_api_key_9f3a1c0b7d2e4a85}}` (entropic so real outbound content never collides with it; see [Secret injection](../reference/secret-injection.md#placeholder-entropy)). The agent uses the placeholder in headers, query strings, or bodies as if it were the real value. Before the inspector chain runs, the proxy checks two invariants:

1. **Literal value blocking.** If a real secret value appears in a request to a host outside that secret's `inject_to` list, the request is blocked. The cage should never know the real value, so its presence indicates the agent learned the secret outside the placeholder system.
2. **Placeholder routing.** If a placeholder is heading to a domain not in that secret's `inject_to` list, the request is flagged but still goes through.

Inspectors then run with placeholders intact, so they see no real secrets. Only after every inspector returns non-block does the proxy substitute placeholders for real values; the upstream sees a normal authenticated call. On the response path, real values are redacted back to placeholders before the cage receives them.

The trust property: an agent that exfiltrates everything it can see still only exfiltrates placeholders. Real values live in the egress and never cross the wire to the cage.

See the [secret injection reference](../reference/secret-injection.md) for setup, secret backends, and per-secret configuration fields.

## Startup order

The egress comes up first. The cage waits for the egress to be ready — specifically, for the proxy CA cert to be available — before starting the workload. On slow boots you may see the cage hold in a "starting" state for a few seconds while this handshake completes. Once running, the cage has a default route to the egress and trusts the egress's CA, so HTTP and HTTPS traffic both flow through the inspector chain.

### Hot-reload semantics

`cage edit` opens the stored `cage.yaml`, validates on save, classifies the diff, and chooses the lightest-touch reload that still applies the change:

- **Live reload** (no service restart): `domains`, `inspectors`, `secret_injection`, `rate_limit`, `logging`, `capture`, `protocol_relays`, `max_request_body`, `entropy`, `content_type`. The cage process is untouched, so an interactive shell inside the cage survives the reload.
- **Service restart** (no rebuild): anything else — for example `container.env`, `container.command`, `ports`, `container.volumes`. `cage edit` tells you to run `cage restart NAME`.
- **Image rebuild**: `isolation` and `vm`. These need `cage update` because the backend or VM shape itself changed.

`cage edit` prints which keys fell into which bucket and the command needed to apply each slice. See the [CLI reference](../reference/cli.md) for the full behavior of `cage edit`, `cage restart`, and `cage update`.

### Nested containers

With `nested_containers: true`, the cage runs podman internally so it can host agent frameworks that spawn containers; a docker-cli shim translates `docker` invocations to `podman`. Inner containers default to `--network none`; `--network host` is the only way they pick up the cage's proxy env vars and thus the inspector chain. Nested containers weaken the cage's hardening — see the [configuration reference](../reference/configuration.md) for the trade-offs.

## Related

- [Isolation modes](isolation-modes.md) — container, vm, and apple-container backend differences
- [Inspectors reference](../reference/inspectors.md) — built-in inspectors and custom-inspector API
- [Secret injection reference](../reference/secret-injection.md) — setup, backends, and transforms
- [Ports reference](../reference/ports.md) — port policy and how to extend the allow set
- [Security model](security-model.md) — what each isolation mode defends against
