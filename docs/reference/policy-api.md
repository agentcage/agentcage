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

- **DNS** — dnsmasq gains `address=/agentcage.local/<ip_egress>` (rendered at
  deploy time, all backends), so the cage resolves the control host to the
  egress and connects normally.
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
| `POST` | `/v1/allowlist/requests` | Request a new domain. Invokes the decider. |
| `GET`  | `/v1/allowlist/requests/{id}` | Poll a request's status. |
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
  by the grants watcher (empty when auto-management is disabled). Entries are
  permanent; an `expires_at` field appears only for domains time-limited via
  `agentcage domain add --expires-in`.
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
| `400` | Bad domain syntax, not in allowlist mode, or missing `reason` justification. |
| `409` | Domain already granted. |
| `429` | Request rate limit exceeded. |
| `503` | Decider unavailable (fail-closed by default = deny; see below). |

## Config schema

Auto-management nests under `domains.auto`. Full form:

```yaml
domains:
  allow: [anthropic.com, github.com]
  expires: {npmjs.org: "2026-08-29T19:00:00+00:00"}   # from `domain add --expires-in`
  auto:                       # auto-manage this allowlist (opt-in, default off)
    enable: true              # master switch; off = no control host
    host: agentcage.local     # reserved synthetic control host (default)
    decider:                  # the agent that decides each request
      kind: agent             # "agent" = built-in LLM cybersecurity expert (v1 only)
      provider: openrouter    # anthropic | openai | openrouter
      model: anthropic/claude-sonnet-4-5
      api_key: env:OPENROUTER_API_KEY   # secret_injection.source syntax; egress-only
      timeout_seconds: 15
      # base_url: https://openrouter.ai  # optional override
    fail_open: false           # deny on decider error (default)
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
| `domains.auto.fail_open` | `bool` | `false` | `true` = grant on decider error/timeout (risky). Default denies. |
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
unparseable model response denies the request. Setting `fail_open: true`
grants on error instead — this is **risky** and not recommended. The decider
has its own timeout (default 15s) and is rate-limited per cage (default
1 req/s, burst 5), independently of the egress's per-host HTTP rate limit, to
bound LLM cost and abuse of the request endpoint.

### Grant defaults (fixed, not configurable)

There is **no `grant:` block** — v1 uses fixed safe defaults that are not
operator-configurable:

- Grants are **permanent** (`ttl_seconds: 0`). To time-limit a domain, use
  `agentcage domain add --expires-in 30m` (recorded in `domains.expires`).
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

On a `grant` decision, the **auto-started grants watcher** promotes the
domain into the static baseline via the literal `domain add` chain:

1. **L7 — immediate.** The addon calls `DomainInspector.grant(domain)`,
   which adds the domain to its in-memory `domain_set` (allowlist mode). The
   very next request to that domain passes the domain inspector — no restart,
   no SIGHUP, no upstream reconnect.
2. **Baseline — permanent.** The grants watcher (which auto-starts whenever
   `auto.enable` is true) runs the same logic as `agentcage domain add`:
   `save_raw_config` → `save_proxy_config` → `save_dns_allowlist` → SIGHUP
   dnsmasq, and the addon hot-reloads on `config.yaml`'s mtime. The domain is
   now baked into the operator's `cage.yaml` baseline — immediately reachable
   and permanent, surviving `cage destroy`/`recreate`.

Because the watcher auto-starts, there is no manual `watch` step and no
separate overlay file to manage. Grants only ever *widen* the allow set.

> **Grants are additive-only.** A grant only ever *widens* the allow set. It
> never bypasses the SNI/Host-equality check, the `secrets`/`entropy`/
> `content-type`/`body-size` inspectors, the rate limits, or the TCP-bypass
> kill. Granted traffic is still fully inspected.

## Promoting & revoking grants

Grants are **permanent** — the auto-started watcher promotes each grant into
the static `cage.yaml` baseline via the existing `domain add` live-reload
path, so there is no manual `promote` step. The `cage grants promote`/`revoke`
commands were removed; grants are durable by default.

- **Remove a granted domain:** `agentcage domain rm <domain>` — drops it from
  the baseline and live-reloads it away.
- **Time-limit a domain:** `agentcage domain add <domain> --expires-in 30m` —
  records an expiry in `domains.expires`; the domain is removed automatically
  when it expires.
- **Debug the watcher:** `agentcage cage grants <name> watch` still exists for
  debugging the auto-promotion flow (there is no manual `watch` to start; the
  watcher starts itself when `auto.enable` is true).

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
- **`policy-audit.jsonl`** (per-cage) carries the lifecycle events:
  `policy_grant_applied` (a grant was promoted into the baseline),
  `policy_grant_removed` (a domain removed via `agentcage domain rm`), and
  `domain_allow_expired` (a time-limited domain expired).

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
  valid public hostname (no IP literals, no `*.local`, no link-local/
  metadata ranges — enforced via the fixed `never_grant` set plus a syntax
  check).
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
