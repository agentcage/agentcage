<!-- owner: @luca  last-reviewed: 2026-06-01 -->
# Policy API

An **opt-in** control plane that lets a caged agent introspect its effective
domain allowlist and request new egress domains at runtime, gated by an
operator-configured decision hook. Read this when enabling the `policy_api:`
config section or operating the `agentcage cage grants` CLI.

The feature is **off by default** — an omitted `policy_api:` block adds zero
new surface and the control hostname is not even resolved. When enabled it
works under full **default-deny**: the whole point is to let the agent ask
for *more* access, so it must function when nothing is yet allowlisted.

The full design rationale lives in the [design doc](../explain/policy-api.md);
this page documents the implemented behavior.

## Control hostname

Introspection and requests are served by the egress proxy itself on a reserved
control hostname — default `agentcage.local`, configurable via
`policy_api.host`. The cage reaches it like any other host:

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
control host → `404`. There is no wildcarding and no proxying.

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/v1/allowlist` | Introspection. Returns the effective domain policy. |
| `POST` | `/v1/allowlist/requests` | Request a new domain. Triggers the decision hook. |
| `GET`  | `/v1/allowlist/requests/{id}` | Poll a request's status (async hooks). |
| `GET`  | `/v1/health` | Liveness + feature flags (which endpoints are enabled). |

### `GET /v1/allowlist`

```json
{
  "mode": "allowlist",
  "baseline": ["anthropic.com", "github.com", "pypi.org"],
  "granted": [
    {"domain": "registry.npmjs.org", "granted_at": "2026-06-01T12:00:00Z",
     "expires_at": "2026-06-01T13:00:00Z", "reason": "npm install requested",
     "source": "policy-hook"}
  ],
  "passthrough": ["whatsapp.com"],
  "requestable": true,
  "version": "0.33.0"
}
```

- `baseline` — the operator's static `domains.allow` from `config.yaml`.
- `granted` — runtime overlay entries (empty when the request endpoint is
  disabled). Each carries `expires_at` if the grant has a TTL.
- `requestable` — whether `POST /v1/allowlist/requests` is enabled, so the
  agent knows before trying.

### `POST /v1/allowlist/requests`

Request body:

```json
{"domain": "registry.npmjs.org", "reason": "need to run npm install"}
```

Synchronous decision (default) → `200`:

```json
{
  "id": "req_01HZ...",
  "status": "granted",
  "domain": "registry.npmjs.org",
  "reason": "package install looks benign",
  "expires_at": "2026-06-01T13:00:00Z",
  "decided_by": "policy-hook:webhook"
}
```

A hook that returns `202` with a handle (async mode) → `202` with
`status: "pending"`; the agent polls `GET /v1/allowlist/requests/{id}` until
`granted` or `denied`. The addon retains pending requests in memory for a
configurable TTL (default 5 min).

Errors:

| Status | Meaning |
|--------|---------|
| `400` | Bad domain syntax, not in allowlist mode, or missing `reason` justification. |
| `409` | Domain already granted. |
| `429` | Request rate limit exceeded. |
| `503` | Decision hook unavailable (fail-closed by default = deny; see below). |

## Config schema

```yaml
policy_api:
  enable: true                       # master switch; off = no control host
  host: agentcage.local              # reserved control hostname (default)

  introspection:
    enable: true                     # GET /v1/allowlist (default: follows enable)

  request:
    enable: true                     # POST /v1/allowlist/requests
    decision:
      provider: webhook              # "webhook" | "llm"
      webhook:
        url: https://approver.example.com/agentcage
        # relay-auth *_source scheme, NOT secret_injection. See below.
        auth_source: "systemd-creds:POLICY_HOOK_TOKEN"
        timeout_seconds: 10
        async: false                 # true → 202 + poll
      # llm:                          # alternative provider (built-in)
      #   provider: openrouter         # "anthropic" | "openai" | "openrouter"
      #   model: anthropic/claude-sonnet-4-5
      #   auth_source: "systemd-creds:POLICY_LLM_KEY"   # REQUIRED, separate key
      #   base_url: ""                 # optional API base override
      #   timeout_seconds: 15
      fail_open: false               # true = grant on hook error (risky)
      rate_limit: {requests_per_second: 1, burst: 5}
    grant:
      ttl_seconds: 3600              # 0 = no expiry
      max_grants: 32                 # cap total overlay size
      never_grant:                   # hard-deny list; label-suffix matched
        - agentcage.local            #   (so `internal` matches *.internal,
        - 169.254.169.254            #    not a glob). IP literals are
        - internal                   #    redundant (the request endpoint
                                     #    rejects IP-literal domains by
                                     #    syntax) but allowed.
      require_allowlist_mode: true   # refuse to run in blocklist mode (default)
```

### Decision-hook authentication

The hook credential uses **`auth_source`** with the relay-auth `*_source`
scheme (`env:NAME` / `cmd:...` / `systemd-creds:NAME`), **not**
`secret_injection`. This follows the [protocol-relay](protocol-relays.md)
credential precedent: the hook token is an **egress-only secret** that must
never appear in cage traffic, so piggy-backing on a `secret_injection` rule
(which exists to substitute placeholders *into* cage traffic) would be the
wrong abstraction. The quadlet renderer stages `auth_source` credentials into
the proxy's tmpfs secret files exactly like a relay credential — the real
value lives only in the egress and never reaches the cage environment.

### `never_grant` matching

`never_grant` uses **label-suffix matching** (the same rules as
`DomainInspector`), not globs. So `internal` matches `*.internal` (and
`metadata.google.internal`); write `internal`, not `*.internal`. A small
built-in set — `internal`, `local`, `localhost`, and the control host itself
— is **always** unioned in at validation time; operator entries only ever
*widen* this. IP literals are redundant because the request endpoint rejects
IP-literal domains by syntax, but they are accepted for belt-and-braces.

## Decision hook providers

### `webhook` (recommended, primary)

The egress `POST`s a JSON decision request to an operator-controlled URL,
authenticating with `Authorization: Bearer <token>` resolved from
`auth_source`:

```json
{
  "cage": "myagent",
  "domain": "registry.npmjs.org",
  "reason": "need to run npm install",
  "baseline": ["anthropic.com", "github.com"],
  "granted": ["api.openai.com"],
  "ts": "2026-06-01T12:00:00Z"
}
```

Expected response:

```json
{"decision": "grant", "reason": "...", "ttl_seconds": 3600}
```

or `{"decision": "deny", "reason": "..."}`. The operator's service does
whatever it wants — an LLM call, a static rule, a human approval queue, a
Slack prompt. This keeps the policy logic **outside** the egress trust
boundary and fully under operator control.

### `llm` (built-in, cybersecurity-expert adjudicator)

The egress calls an LLM provider directly over HTTPS — **no SDK**, to keep
the egress image lean. Three providers are supported:

- `anthropic` — `/v1/messages` (API key via the `x-api-key` header).
- `openai` — `/v1/chat/completions` (OpenAI chat-completions wire format).
- `openrouter` — same OpenAI chat-completions format, with OpenRouter's
  model-routing (`anthropic/claude-sonnet-4-5`, etc.).

Set an optional `base_url` to point at a proxy/gateway or a local
OpenAI-compatible server.

**The evaluator's API key is a SEPARATE, required credential** from the
webhook `auth_source`: a cage using the `llm` provider has no webhook, so
its key must not be confused with one. It is an egress-only secret (staged
into the proxy's tmpfs secret files, never cage-visible) and declared via
`auth_source` with the same `*_source` scheme.

**The agent must justify the request.** The `POST` body requires a non-empty
`reason`; the evaluator treats it as an adversarial claim to be scrutinized.
The system prompt casts the model as a **senior cybersecurity expert** acting
as the autonomous-approval gate (mirroring Claude Code "auto" mode): it grants
only when the justification explains a specific, plausible task and the domain
is a well-known, legitimate, low-risk service for that task; it denies
look-alikes, paste/file-share/anonymizer domains, and vague justifications.
The decision is forced through a `decide` tool call (decision/reason/
ttl_seconds); a response with no usable tool call is treated as **deny**
(fail-closed). The evaluator's `reason` is written to `audit.jsonl` as the
risk-assessment rationale.

This is a larger trust surface than the webhook (the egress makes model calls
and interprets their output as policy) but requires no external service. Use
it when you want a single cage to self-serve with a capable model as the
reviewer; prefer `webhook` when policy logic must stay fully under operator
control.

### Fail-closed vs fail-open

Both providers are **fail-closed by default**: a hook error, timeout, or
unparseable model response denies the request. Setting `fail_open: true`
grants on error instead — this is **risky** and not recommended. Each
provider also has its own timeout (webhook default 10s, llm default 15s) and
is rate-limited per cage (default 1 req/s, burst 5), independently of the
egress's per-host HTTP rate limit, to bound LLM cost and abuse of the request
endpoint.

## How grants take effect

A grant applies at **two layers**, in sequence:

1. **L7 — immediate.** The addon calls `DomainInspector.grant(domain)`,
   which adds the domain to its in-memory `domain_set` (allowlist mode). The
   very next request to that domain passes the domain inspector — no
   restart, no SIGHUP, no upstream reconnect.
2. **DNS — ~1s latency.** The egress supervisor watches the grants overlay
   file, regenerates dnsmasq's per-zone forwarders for the granted domain,
   and SIGHUPs dnsmasq. This is what makes the granted domain actually
   **resolve**: mitmproxy resolves its upstreams through the same dnsmasq,
   so without this step the granted domain would sinkhole and return `502`.
   The latency comes from the supervisor's monitor loop and is roughly one
   second — grants are **not** instant for DNS.

The grant is appended to a **grants overlay** file (`/var/lib/agentcage/
grants.yaml`) on a writable per-cage volume. On egress start and on every
config hot-reload (`_maybe_reload`), the addon replays non-expired grants
into the inspector *after* `configure()`, so hot-reloads of `config.yaml`
never wipe runtime grants. An optional background sweeper drops expired
grants from memory and the overlay.

> **Grants are additive-only.** A grant only ever *widens* the allow set. It
> never bypasses the SNI/Host-equality check, the `secrets`/`entropy`/
> `content-type`/`body-size` inspectors, the rate limits, or the TCP-bypass
> kill. Granted traffic is still fully inspected.

## Promoting & revoking grants

A grant in the overlay takes effect immediately and survives an egress
restart, but a `cage destroy`/`recreate` loses it. To make a grant permanent,
the operator promotes it into the static `cage.yaml` baseline via the
existing `domain add` live-reload path:

```bash
agentcage cage grants <name> list              # show overlay grants
agentcage cage grants <name> promote <domain>  # bake into baseline, drop overlay entry
agentcage cage grants <name> revoke <domain>   # drop the overlay entry
```

- `promote` runs the same logic as `domain add`
  (`save_raw_config` → `save_proxy_config` → `save_dns_allowlist` → SIGHUP
  dnsmasq), then removes the now-redundant overlay entry. This deliberately
  reuses the battle-tested `domain add` machinery rather than a second write
  path.
- `revoke` drops the overlay entry; the addon hot-reloads it away on the next
  request (the overlay file's mtime triggers the addon's reload, mirroring
  how `config.yaml` hot-reloads work).

The egress itself never writes `config.yaml` (it is bind-mounted `:ro`), so
the operator's static policy is never silently changed — promotion is an
explicit operator action. Every request and decision is written to
`audit.jsonl` with `kind: "policy_request"`, the domain, the decision, the
reason, and `decided_by`, which is the forensic record.

## Threat model

This feature intentionally lets the cage expand its own egress, gated by an
external decision. The safeguards:

- **Opt-in, off by default.** No `policy_api:` section → zero new surface;
  the control host is not even resolved.
- **Decision hook is the gate.** The egress never grants without a positive
  grant from the hook; hook failure defaults to **deny**.
- **Additive-only overlay.** Grants only widen the allowlist; they never
  bypass the SNI/Host check, the secret/entropy/content-type/body-size
  inspectors, rate limits, or the TCP-bypass kill.
- **Control host is synthetic and non-forwardable.** The addon answers
  locally and never opens an upstream; `agentcage.local` is in `never_grant`
  by default, so the cage can't grant it to itself or reach a "real"
  upstream of the same name.
- **No SSRF via the request endpoint.** Only the documented paths exist;
  everything else `404`s. The `domain` field is validated as a syntactically
  valid public hostname (no IP literals, no `*.local`, no link-local/
  metadata ranges — enforced via `never_grant` plus a syntax check).
- **Bounded blast radius.** `max_grants`, per-cage request rate limit, TTL
  expiry, and full audit logging. The grants overlay is per-cage, not shared.
- **Secret hygiene.** The hook auth secret flows through the `auth_source`
  relay-auth mechanism — the real value lives only in the egress, never in
  the cage env.
- **Baseline immutability.** The egress cannot rewrite `config.yaml`; the
  operator's static policy is never silently changed. Promotion is an
  explicit operator action.

**Residual risk:** a grant widens egress to a new host. If the hook is
compromised or mis-prompted (the `llm` provider), the cage gains access it
shouldn't. Mitigated by `never_grant`, TTLs, audit logging, and the
recommendation to prefer the `webhook` provider (which keeps policy logic
outside the egress trust boundary).

## Related

- [Domains](domains.md) — the static allow/block policy this feature extends at runtime.
- [Inspectors](inspectors.md) — granted traffic still runs through the full inspector chain.
- [Secret injection](secret-injection.md) — the contrast for `auth_source` (injection substitutes into cage traffic; `auth_source` is egress-only).
- [Protocol relays](protocol-relays.md) — the `*_source` credential scheme reused here.
- [Policy API design](../explain/policy-api.md) — full design rationale and implementation plan.
