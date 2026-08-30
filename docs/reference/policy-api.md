<!-- owner: @luca  last-reviewed: 2026-08-29 -->
# Policy API

An **opt-in** control plane that lets a caged agent introspect its effective
domain allowlist and request new egress domains at runtime, gated by a
**decider** — a built-in LLM cybersecurity-expert agent that adjudicates each
request. Read this when enabling the `domains.auto:` config section or
operating grants.

The feature is **off by default** — an omitted `domains.auto:` block (or
`auto.enable: false`) adds zero new surface and the control hostname is not
even resolved. When enabled it works under full **default-deny**: the whole
point is to let the agent ask for *more* access, so it must function when
nothing is yet allowlisted.

Auto-management lives under `domains.auto` so that all domain egress policy
— static `allow`/`block`/`passthrough`, `expires`, and runtime
auto-management — shares one namespace.

The full design rationale lives in the [design doc](../explain/policy-api.md);
this page documents the implemented behavior.

## Control hostname

Introspection and requests are served by the egress proxy itself on a reserved
control hostname — default `agentcage.local`, configurable via
`domains.auto.host`. The cage reaches it like any other host:

- **DNS** — `agentcage.local` resolves via the dnsmasq sinkhole: the global
  `address=/#/<ip_egress>` catch-all already sends every unresolved name to
  the egress, so the control host needs no dedicated record (works on all
  backends). The cage resolves it to the egress and connects normally.
- **TLS** — the egress CA already mints a certificate for any SNI, and the
  cage trusts that CA via the `/certs` mount, so `https://agentcage.local`
  works with no extra certificate plumbing. HTTP is accepted too.
- **Interception** — the addon recognizes the control host by SNI/Host and
  short-circuits in `request()` **before** the SNI/Host-equality check, the
  rate limiter, the secret-injection policy, and the inspector chain. It
  synthesizes an `http.Response` locally and **never opens an upstream
  connection**. `agentcage.local` is therefore unreachable as a real upstream
  and cannot be forwarded.

> **Why this works under default-deny.** The egress sinkhole plus the
> iptables REDIRECT already routes any non-allowlisted connection into
> mitmproxy, where the addon recognizes the control host by SNI/Host and
> answers locally instead of forwarding upstream. Short-circuiting before
> the SNI check is safe: the control host is a synthetic local endpoint, not
> a real upstream, so SNI/Host equality is trivially satisfied (the cage
> sets both to `agentcage.local`) and there is nothing to impersonate. A
> request whose SNI is `agentcage.local` but whose Host header differs is
> rejected with `404` by the control handler.

## Endpoints

All under `https://agentcage.local` (HTTP accepted too). Anything else on the
control host → `404`. There is no wildcarding and no proxying. When
`auto.enable` is true, **both** the introspection and request endpoints are
on — there are no separate `introspection:`/`request:` enable flags.

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/v1/allowlist` | Introspection. Returns the effective domain policy. |
| `POST` | `/v1/allowlist/requests` | Request a new domain. Invokes the decider (synchronous — the decision is in the response body). |
| `POST` | `/v1/allowlist/removals` | Give back a live runtime grant the agent no longer needs. No decider — a removal only narrows. |
| `GET`  | `/v1/health` | Liveness + feature flags. |

**Backend support:** identical on all three backends. A grant is applied
entirely inside the egress container — the addon publishes the granted zone
list and the supervisor re-renders dnsmasq's servers-file and SIGHUPs it from
the liveness loop it already runs — so there is no host-side watcher, no
systemd unit and no launchd plist. See
[Egress-local DNS apply](../explain/egress-local-dns-apply.md).

On vm cages the grants overlay still lives VM-LOCAL
(`~/.config/agentcage-vm/cages/<name>/grants/` inside the guest, like the
other hot-reloaded config files) so the in-guest addon writes it with no
Lima-mount staleness; the host reads it over `limactl shell` when it
reconciles the durable baseline.
| `GET`  | `/v1/health` | Liveness + feature flags (which endpoints are enabled). |

### `GET /v1/allowlist`

```json
{
  "mode": "allowlist",
  "baseline": ["anthropic.com", "github.com", "pypi.org"],
  "granted": [
    {"domain": "registry.npmjs.org", "granted_at": "2026-06-01T12:00:00Z",
     "reason": "npm install requested",
     "source": "decider", "decided_by": "decider:agent:openrouter"}
  ],
  "passthrough": ["whatsapp.com"],
  "requestable": true,
  "version": "0.33.0"
}
```

- `baseline` — the operator's static `domains.allow` from `config.yaml`.
- `granted` — domains admitted by the decider and promoted into the baseline
  and reconciled into the baseline (empty when auto-management is disabled). An entry
  carries `expires_at` when it is time-limited: the decider may attach a
  `ttl_seconds` to a grant it judges transient (clamped to 24h), and
  `agentcage domain add --expires-in` sets one explicitly. A grant with no
  TTL is permanent until `agentcage domain rm`.
- `requestable` — whether `POST /v1/allowlist/requests` is enabled, so the
  agent knows before trying.

### `POST /v1/allowlist/requests`

Request body:

```json
{"domain": "registry.npmjs.org", "reason": "need to run npm install"}
```

The `reason` field is **required** and must be non-empty — it is the
justification the decider scrutinizes.

Synchronous decision → `200`:

```json
{
  "id": "req_01HZ...",
  "status": "granted",
  "domain": "registry.npmjs.org",
  "reason": "package install looks benign",
  "decided_by": "decider:agent:openrouter"
}
```

Errors:

| Status | Meaning |
|--------|---------|
| `200` | Granted, or already reachable (`status: already_allowed`). |
| `400` | Bad domain syntax, not in allowlist mode, or missing `reason` justification. |
| `403` | Denied — by the decider, or structurally (`never_grant`, not in allowlist mode). The body carries `status: denied` with an actionable `reason`. |
| `409` | Grant cap reached (`max_grants`). |
| `429` | Request rate limit exceeded. |
| `503` | Decider unavailable (fail-closed = deny; see below). |

Every response carries an `id` (`req_<hex>`) that correlates it with the
`policy_request` line in `audit.jsonl`.

### `POST /v1/allowlist/removals`

Self-service narrowing — the agent gives back a runtime grant it no longer
needs. The mirror image of the request endpoint in trust terms: a removal
only ever **shrinks** the agent's own egress, so **no decider is involved
and no justification is required** (an optional `reason` is recorded in
`audit.jsonl`).

Request body:

```json
{"domain": "registry.npmjs.org", "reason": "one-off install finished"}
```

Scope is **live runtime grants only** — the exact domains in the
introspection response's `granted` list. A grant the host reconcile has
already promoted into the operator's static baseline is indistinguishable
from a domain the operator added by hand, and the egress never edits the
baseline (the same immutability invariant that routes promotion through
the host-side `domain add` machinery), so those return `403` naming
`agentcage domain rm` as the operator command.

Removal takes effect the same two-step way a grant does, in reverse: the
domain leaves the in-memory L7 allow set immediately, and the shrunk zone
list is republished so the supervisor drops it from dnsmasq within ~1s.
The overlay entry is deleted, so the removal survives an egress restart
and the next reconcile has nothing to promote. Removal is not a ban — the
agent can re-request the domain later and the decider adjudicates fresh.

| Status | Meaning |
|--------|---------|
| `200` | Removed (`status: removed`). Carries `still_allowed_by_baseline: true` when the domain also suffix-matches the static baseline, so the agent knows the narrowing was partial. |
| `400` | Bad domain syntax. |
| `403` | The domain matches the operator baseline (possibly a promoted grant) — not the agent's to retract. |
| `404` | Not a live runtime grant (`status: not_found`). |
| `429` | Rate limited (shares the request endpoint's per-cage bucket). |

Audited as `policy_removal` lines in `audit.jsonl`. Enabled together with
the request endpoint by `auto.enable` (the `/v1/health` features object
reports `removal`).

## Config schema

Auto-management nests under `domains.auto`. Full form:

```yaml
domains:
  allow: [anthropic.com, github.com]
  expires: {npmjs.org: "2026-08-29T19:00:00+00:00"}   # from `domain add --expires-in`
  auto:                       # auto-manage this allowlist (opt-in, default off)
    enable: true              # master switch; off = no control host
    host: agentcage.local     # reserved synthetic control host (default)
    context: |                # optional: tell the decider what this cage is FOR
      CI cage for the payments-reconciliation test suite. Talks to staging
      APIs (api.stripe.com) and installs deps from npm/pypi. Advisory only.
    decider:                  # the agent that decides each request
      kind: agent             # "agent" = built-in LLM cybersecurity expert (v1 only)
      provider: openrouter    # anthropic | openai | openrouter
      model: anthropic/claude-sonnet-4-5
      api_key: env:OPENROUTER_API_KEY   # secret_injection.source syntax; egress-only
      timeout_seconds: 15
      # base_url: https://openrouter.ai  # optional override
    rate_limit: {requests_per_second: 1, burst: 5}
```

Minimal form:

```yaml
domains:
  allow: [anthropic.com]
  auto:
    enable: true
    decider: {kind: agent, provider: openrouter, model: anthropic/claude-sonnet-4-5, api_key: env:OPENROUTER_API_KEY}
```

### Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `domains.auto.enable` | `bool` | `false` | Master switch. Off → no control host, zero new surface. |
| `domains.auto.host` | `string` | `agentcage.local` | Reserved synthetic control hostname. |
| `domains.auto.decider.kind` | `string` | — | The decider actor. v1 ships `agent` only; `webhook` is reserved / not yet implemented. |
| `domains.auto.decider.provider` | `string` | — | LLM provider: `anthropic`, `openai`, or `openrouter`. |
| `domains.auto.decider.model` | `string` | — | Model identifier (e.g. `anthropic/claude-sonnet-4-5`). |
| `domains.auto.decider.api_key` | `string` | — | **Required** for `kind: agent`. The decider's own API key. Uses the `secret_injection.source` scheme (`env:NAME` / `systemd-creds:NAME` / `cmd:...`); egress-only. |
| `domains.auto.decider.timeout_seconds` | `int` | `15` | Per-decision timeout. |
| `domains.auto.decider.base_url` | `string` | provider default | Optional API base override (proxy/gateway/local server). |
| `domains.auto.context` | `string` | `""` (off) | Optional free-text describing this cage's purpose and scope. Appended to the decider's system prompt as **trusted operator context** (advisory only — it never overrides `never_grant`, domain syntax, or rate limits) so decisions can account for what the cage is for. Capped at **4096 chars** (measured after strip) because it rides in every decider call's system prompt and through `proxy-config.yaml` — a huge blob is a prompt-bloat/abuse surface; an over-long value is rejected at `cage create`/`update` with the length in the message. Empty/whitespace-only = feature off. The caged agent can read it via `GET /v1/allowlist` (the `context` field) to write justifications that match the cage's stated scope. Hot-reloads via `cage update` with no restart (the egress addon rebuilds the decider on `proxy-config.yaml` mtime change). |
| `domains.auto.rate_limit` | `{requests_per_second, burst}` | `{1, 5}` | Per-cage request rate limit, independent of the per-host HTTP rate limit. |

When `auto.enable` is true, both the introspection and request endpoints are
on; there are no separate `introspection:` or `request:` enable flags, and no
`grant:` block — grant behavior uses fixed safe defaults (see below).

### The decider

The decider is the agent that adjudicates each domain request. v1 ships
**`kind: agent` only** — the built-in LLM decider, a senior cybersecurity
expert that adjudicates each request (Claude Code "auto" mode for egress).
`kind: webhook` is **reserved / not yet implemented**.

For `kind: agent`, the egress calls the LLM provider directly over raw HTTPS
— **no SDK**, to keep the egress image lean:

- `anthropic` — `/v1/messages` (API key via the `x-api-key` header).
- `openai` — `/v1/chat/completions` (OpenAI chat-completions wire format).
- `openrouter` — same OpenAI chat-completions format, with OpenRouter's
  model-routing (`anthropic/claude-sonnet-4-5`, etc.).

Set an optional `base_url` to point at a proxy/gateway or a local
OpenAI-compatible server.

#### `api_key` — the decider's credential

The decider's API key is **`api_key`** (not `auth_source`/`source`), declared
with the same `*_source` scheme as `secret_injection.source`
(`env:NAME` / `systemd-creds:NAME` / `cmd:...`). It is **required** for
`kind: agent`, and it is an **egress-only secret**: the quadlet renderer
strips it from the cage environment and stages it into the proxy's tmpfs
secret files, exactly like a relay credential. The real value lives only in
the egress and never reaches the cage environment or cage traffic.

#### How the decider decides

The agent must justify the request: the `POST` body requires a non-empty
`reason`, and the decider treats it as an **adversarial claim to be
scrutinized**. The system prompt casts the model as a senior cybersecurity
expert acting as the autonomous-approval gate (mirroring Claude Code "auto"
mode): it grants only when the justification explains a specific, plausible
task and the domain is a well-known, legitimate, low-risk service for that
task; it denies look-alikes, paste/file-share/anonymizer domains, and vague
justifications. The decision is forced through a `decide` tool call
(decision/reason); a response with no usable tool call is treated as **deny**
(fail-closed). The decider's `reason` is an actionable explanation returned
to the agent and written to `audit.jsonl` as the risk-assessment rationale.

### Fail-closed vs fail-open

The decider is **fail-closed by default**: a decider error, timeout, or
unparseable model response denies the request. The decider is **always**
fail-closed — a decider error NEVER grants (the caged agent cannot expand its
own egress without a positive decision). The decider
has its own timeout (default 15s) and is rate-limited per cage (default
1 req/s, burst 5), independently of the egress's per-host HTTP rate limit, to
bound LLM cost and abuse of the request endpoint.

### Grant defaults (fixed, not configurable)

There is **no `grant:` block** — v1 uses fixed safe defaults that are not
operator-configurable:

- Grants default to **permanent** (`ttl_seconds: 0`), but the decider may
  return a `ttl_seconds` on a grant it judges transient — the system prompt
  asks it to. Any decider-supplied TTL is **clamped to 24h** and recorded in
  `domains.expires`, and the addon's own in-egress sweeper prunes the entry
  when it expires (re-publishing the zone list); the baseline's
  `domains.expires` entry is tidied by the next reconcile. To time-limit a
  domain yourself, use `agentcage domain add --expires-in 30m`.
- **Max 32 concurrent** grants per cage.
- A **`never_grant`** set — `internal`, `local`, `localhost`, and the control
  host itself — is **always** unioned in; the decider cannot override or
  widen it. These use label-suffix matching (so `internal` matches
  `*.internal` and `metadata.google.internal`), the same rules as
  `DomainInspector`. IP-literal domains are rejected by the request endpoint
  by syntax.
- **Requires allowlist mode.** The request endpoint refuses to run in
  blocklist mode (introspection still works).

## How grants take effect

A `grant` decision takes effect in two steps, both immediate:

1. **L7 — immediate.** The addon calls `DomainInspector.grant(domain)`,
   which adds the domain to its in-memory `domain_set` (allowlist mode). The
   very next request to that domain passes the domain inspector — no restart,
   no SIGHUP, no upstream reconnect.
2. **DNS — immediate.** The addon publishes the granted zone to
   `/home/acproxy/dns/granted`; the egress supervisor re-renders dnsmasq's
   servers-file (baseline + granted zones) and SIGHUPs it, so the name
   resolves. The addon cannot signal dnsmasq itself — different uid, no
   `CAP_KILL` — which is why the supervisor does this half.

**Durability** is separate and lazy. The grant is persisted to the overlay,
which the addon reloads (and re-publishes) at startup, so it survives an
egress restart. Writing it into the operator's `cage.yaml` baseline — so it
shows in `domain list` and survives `cage destroy`/recreate — happens on the
next reconcile: `agentcage cage grants <name> sync`, which `domain list` also
runs implicitly. Grants only ever *widen* the allow set.

> **Grants are additive-only.** A grant only ever *widens* the allow set. It
> never bypasses the SNI/Host-equality check, the `secrets`/`entropy`/
> `content-type`/`body-size` inspectors, the rate limits, or the TCP-bypass
> kill. Granted traffic is still fully inspected.

## Promoting & revoking grants

Reconciling promotes each grant into the static `cage.yaml` baseline via the
existing `domain add` live-reload path, so there is no manual `promote` step —
grants are durable by default. A grant is permanent unless the decider
attached a `ttl_seconds` (see above); the addon's own sweeper drops it at
expiry and re-publishes the zone list, and the next reconcile tidies the
baseline.

- **Remove a granted domain:** `agentcage domain rm <domain>` — drops it from
  the baseline and live-reloads it away. The **agent** can also give back a
  grant it no longer needs via `POST /v1/allowlist/removals` — but only
  while it is still a live runtime grant (not yet promoted into the
  baseline); see the endpoint section above.
- **Time-limit a domain:** `agentcage domain add <domain> --expires-in 30m` —
  records an expiry in `domains.expires`; the domain is removed automatically
  when it expires.
- **How grants apply:** granted DNS is applied automatically in-egress — the
  addon publishes the zone and raises a reload flag; the egress supervisor's
  1 s liveness loop re-renders dnsmasq's servers-file (baseline + granted)
  and SIGHUPs it, so the name resolves within ~1 s (see
  [Egress-local DNS apply](../explain/egress-local-dns-apply.md)).
  `agentcage cage grants <name> sync` (also run implicitly by
  `agentcage domain list`) promotes decided grants into the static baseline
  when you want them permanent. Expired grants are pruned automatically by
  the in-egress sweeper (30 s poll); expired baseline entries are tidied by
  the next reconcile. There is no `grants watch` subcommand and no host-side
  watcher.

The egress itself never writes `config.yaml` directly for a grant — promotion
goes through the host-side `domain add` machinery, so the operator's static
policy is changed through the same battle-tested path as a manual
`domain add`.

## Audit

Two audit streams record policy activity:

- **`audit.jsonl`** (egress, per-cage) carries `policy_request` entries —
  each request and the decider's decision, with the domain, the decision, the
  decider's `reason`, and `decided_by`. `decided_by` is
  `decider:agent:<provider>` (e.g. `decider:agent:openrouter`) for grants,
  and `decider` for structural denials (syntax, `never_grant`, not allowlist
  mode, already granted, rate-limited).
- **`policy-audit.jsonl`** (per-cage, *outside* the grants bind mount) carries
  the lifecycle events: `policy_grant_applied` (a grant was promoted into the
  baseline), `policy_grant_removed` (a domain removed via `agentcage domain rm`),
  and `domain_allow_expired` (a time-limited domain expired). It lives at
  `~/.local/share/agentcage/<name>/policy-audit.jsonl` — a sibling of the
  `grants/` subdirectory, deliberately NOT inside the grants dir (that dir is
  writable by the egress container — group-shared with the operator via the
  podman user-namespace mapping and bind-mounted RW — so a file inside it
  would be forgeable/truncatable by the caged container).

  > **Grants-dir permissions differ by backend.** On **container** the dir is
  > `0770`, group-shared with the egress via the podman subgid mapping. On
  > **apple-container** there is no equivalent host-side mapping, so the dir
  > is `0777`; on a shared macOS host another local account could plant
  > `grants.yaml` entries the reconcile then promotes. On **vm** the overlay
  > is VM-local (inside the guest) and the host-side dir stays operator-owned,
  > which avoids the problem entirely.

These are the forensic record for every egress widening.

## Threat model

This feature intentionally lets the cage expand its own egress, gated by the
decider. The safeguards:

- **Opt-in, off by default.** No `domains.auto:` section (or `enable: false`)
  → zero new surface; the control host is not even resolved.
- **The decider is the gate.** The egress never grants without a positive
  grant from the decider; decider failure defaults to **deny**.
- **Additive-only.** Grants only widen the allowlist; they never bypass the
  SNI/Host check, the secret/entropy/content-type/body-size inspectors, rate
  limits, or the TCP-bypass kill.
- **Control host is synthetic and non-forwardable.** The addon answers
  locally and never opens an upstream; `agentcage.local` is in the fixed
  `never_grant` set, so the cage can't grant it to itself or reach a "real"
  upstream of the same name.
- **No SSRF via the request endpoint.** Only the documented paths exist;
  everything else `404`s. The `domain` field is validated as a syntactically
  valid public hostname (no IP literals, no `*.local`) and is refused when it
  hits the fixed `never_grant` set.

  Names that *encode* an address are refused too. Wildcard-DNS services
  (`nip.io`, `sslip.io`, `xip.io`, `traefik.me`, …) turn
  `169-254-169-254.nip.io` into 169.254.169.254 — the cloud metadata endpoint
  — through a name that is syntactically public and carries none of the
  `never_grant` suffixes. The request endpoint decodes the leading labels and
  refuses any embedded loopback, link-local, private or CGNAT address, on both
  the addon and the host-side reconcile path. Matching the encoded *address*
  rather than a list of services covers future clones. A name encoding a
  globally-routable address is allowed through to the decider — it is no more
  dangerous than naming that host directly.

  > This is defense in depth, not the only line. The decider reliably denies
  > these on its own (verified by red-teaming a live cage), but that made a
  > metadata bypass contingent on model judgement; the structural check makes
  > it contingent on nothing.

- **Granted domains are checked against the address they resolve to.** Every
  check above reasons about the *name*, and DNS answers the name — the answer
  can change after the grant (rebinding), or be internal from the start with
  nothing odd about the name at all (`localtest.me` is a real public domain
  whose A record is `127.0.0.1`). Before the egress opens an upstream
  connection for a **granted** host it resolves the name and refuses if *any*
  answer is loopback, link-local, private or CGNAT — every answer, since a
  rebinding payload commonly returns a public address alongside the internal
  one.

  This runs at mitmproxy's `server_connect` hook, which is the only point
  that can abort: mitmproxy reads `connection.error` there and skips
  connecting, but proceeds unconditionally after `server_connected`, so a
  verdict reached later cannot stop the request already in flight. A host
  caught rebinding between the lookup and the connect is refused at L7 on its
  next request.

  Scoped to **grant-derived** hosts only. A baseline domain is the operator's
  own choice — an internal artifact mirror on `10.x` in `domains.allow` is a
  legitimate configuration — and inbound port-forwarding connects to the
  cage's private address by design. Neither is affected. Blocks are audited
  as `private_peer_blocked`.
- **Bounded blast radius.** Max 32 concurrent grants, per-cage request rate
  limit, full audit logging, and permanent grants that are explicitly
  removable via `agentcage domain rm`.
- **Secret hygiene.** The decider's `api_key` is an egress-only secret
  (staged into the proxy's tmpfs, never cage-visible) declared via the
  `secret_injection.source` scheme.
- **Baseline immutability from the egress.** The egress cannot rewrite
  `config.yaml` directly; grants are promoted through the host-side
  `domain add` machinery, so the operator's static policy is never silently
  changed by the egress.

**Residual risk:** a grant widens egress to a new host. If the decider is
mis-prompted or the model is compromised, the cage gains access it shouldn't.
Mitigated by the fixed `never_grant` set, the adversarial-claim system prompt,
audit logging, and explicit removal via `agentcage domain rm`.

## Related

- [Domains](domains.md) — the static allow/block policy this feature extends at runtime; auto-management nests under `domains.auto`.
- [Inspectors](inspectors.md) — granted traffic still runs through the full inspector chain.
- [Secret injection](secret-injection.md) — the `source` scheme reused for the decider's `api_key` (injection substitutes into cage traffic; `api_key` is egress-only).
- [Protocol relays](protocol-relays.md) — the `*_source` credential scheme reused here.
- [Policy API design](../explain/policy-api.md) — full design rationale and implementation plan.
