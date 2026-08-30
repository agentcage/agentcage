<!-- design proposal — not yet implemented -->
# Policy API: allowlist introspection + on-demand domain requests

Status: **Proposal**. Owner: @luca. Related: [Domains](../reference/domains.md),
[Inspectors](../reference/inspectors.md), [Security model](security-model.md),
[Architecture](architecture.md).

## TL;DR

Two new **opt-in** capabilities for a cage, both served by the egress proxy on a
reserved control hostname so they work even under full default-deny:

1. **Introspection** — the agent can `GET` the effective domain allow/block
   policy (baseline + decider-granted domains).
2. **Request** — the agent can `POST` a request to add a domain. The egress
   invokes a **decider** — a built-in LLM cybersecurity-expert agent
   (`kind: agent`) — that scrutinizes the request's justification as an
   adversarial claim and grants or denies. On grant, an auto-started grants
   watcher promotes the domain into the static `cage.yaml` baseline via the
   existing `agentcage domain add` chain, so it is immediately reachable and
   permanent.

The egress never self-authorizes without the decider, and the feature is
disabled by default with zero behavior change when off. Auto-management nests
under `domains.auto`, so all domain egress policy (static
`allow`/`block`/`passthrough`, `expires`, and runtime auto-management) shares
one namespace.

---

## 1. Background & constraints

The relevant facts of the current architecture (verified in code):

- The **egress container** runs `mitmdump` with `data/proxy/addon.py`
  (`Agentcage` addon). It sits on two networks: the cage-net (mitmproxy
  listens on `ip_egress:8080` regular + `:8443` transparent) and the default
  `podman` network, which it uses for its **own** outbound to the internet.
  The cage's only path out is through this proxy.
- **`/etc/agentcage/config.yaml` is bind-mounted `:ro`** into the egress. The
  addon polls its mtime on every request (`_maybe_reload`) and reconfigures
  inspectors in place — no restart needed.
- `DomainInspector` holds `mode` + `domain_set` in memory and is
  **fail-closed default-deny** when no policy is configured.
- A **strict SNI ↔ Host-header equality check** runs at the top of `request()`
  before any host rewrite, so audit identity and allowlist decisions always
  reference one hostname.
- **Audit** goes to stderr + `/var/log/agentcage/audit.jsonl` (writable in the
  egress); **capture** is a host-mounted writable volume.
- The egress mints TLS certs for any SNI using its own CA, which the cage
  trusts via the `/certs` mount — so a reserved HTTPS hostname "just works".
- The cage resolves DNS via the egress's dnsmasq. Passthrough domains are
  already injected into the DNS allowlist at render time.
- **Host-side runtime mutation already exists**: `agentcage domain add/rm`
  rewrites `cage.yaml` (`state.save_raw_config`), re-renders
  `proxy-config.yaml` (`state.save_proxy_config`), rewrites the dnsmasq
  allowlist (`state.save_dns_allowlist`), SIGHUPs dnsmasq via its pidfile, and
  relies on the addon's mtime hot-reload. This is live, no cage restart, and
  works across all three backends (container / vm / apple-container).

The last point is the foundation: **granting a domain is already a solved
host-side operation.** This design adds (a) an in-cage way to *observe* the
policy and (b) an in-cage way to *request* a change, gated by the decider,
with the egress applying the grant immediately (L7) and an auto-started
grants watcher promoting it into the static baseline via the existing
`domain add` machinery for durability and operator visibility.

## 2. Goals / non-goals

Goals:

- Agent can discover the effective allowlist without trial-and-error `fetch`
  (today it only learns by getting 403s).
- Agent can request a new domain; the built-in decider (an LLM
  cybersecurity-expert agent) grants or denies.
- Granted domains take effect immediately and are promoted into the static
  baseline (permanent, survive `cage destroy`/`recreate`).
- Both features are **opt-in** and **off by default**; no change for existing
  cages.
- Works under default-deny (the whole point is to ask for more access).
- Works across all three isolation backends.
- Fully audited; operator can see grants and remove them via
  `agentcage domain rm`.

Non-goals (explicitly out of scope for v1):

- Requesting changes to **ports**, **blocklist** entries, **secrets**, or
  **passthrough**. v1 is allowlist-additive only. (Introspection may *show*
  these; requests cannot change them.)
- Human-in-the-loop approval UI. The decider *may* eventually delegate to a
  human (a future `kind: webhook` could do anything), but agentcage itself
  ships no approval UI.
- Granting in **blocklist** mode. A grant is meaningless there (blocklist
  allows everything except listed). v1 requires allowlist mode; blocklist mode
  disables the request endpoint (introspection still works).
- Mutating any policy other than the domain allowlist.

## 3. Design

### 3.1 Control hostname

A reserved hostname, default `agentcage.local`, served entirely by the egress:

- **DNS**: `agentcage.local` resolves via the dnsmasq sinkhole: the global
  `address=/#/<ip_egress>` catch-all already sends every unresolved name to
  the egress, so the control host needs no dedicated record. The cage
  resolves it to the egress and connects normally. Configurable via
  `domains.auto.host`.
- **TLS**: the egress CA already mints a cert for any SNI, and the cage trusts
  that CA, so `https://agentcage.local` works with no extra cert plumbing.
- **Interception**: the addon short-circuits in `request()` **before** the
  SNI check, the rate limiter, the secret-injection policy check, and the
  inspector chain whenever `flow.request.host` (after pretty-host rewrite)
  equals the control host **and** the feature is enabled **and** the flow is
  an egress-path flow (reverse-mode *inbound* flows — published
  `container.ports` listeners — never reach the control host, because their
  Host/SNI are client-controlled and the control plane is reserved for the
  caged agent). It synthesizes an
  `http.Response` and never opens an upstream connection. `agentcage.local`
  is therefore unreachable as a real upstream and cannot be forwarded.

Short-circuiting before the SNI check is intentional and safe: the control
host is a synthetic local endpoint, not a real upstream, so SNI/Host equality
is trivially satisfied (the cage sets both to `agentcage.local`) and there is
no upstream to impersonate. A request whose SNI is `agentcage.local` but whose
Host header differs is rejected with 404 by the control handler (treat
mismatched Host as "not a control path").

### 3.2 Endpoints

All under `https://agentcage.local` (HTTP too is accepted; the cage may use
either).

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/v1/allowlist` | Introspection. Returns the effective domain policy. |
| `POST` | `/v1/allowlist/requests` | Request a new domain. Invokes the decider. |
| `GET`  | `/v1/allowlist/requests/{id}` | Poll a request's status. |
| `GET`  | `/v1/health` | Liveness + feature flags (which endpoints are enabled). |

Anything else on the control host → `404`. No wildcarding, no proxying.

#### `GET /v1/allowlist` response

```json
{
  "mode": "allowlist",
  "baseline": ["anthropic.com", "github.com", "pypi.org"],
  "granted": [
    {"domain": "registry.npmjs.org", "granted_at": "2026-06-01T12:00:00Z",
     "expires_at": "2026-06-01T13:00:00Z", "reason": "npm install requested",
     "source": "decider", "decided_by": "decider:agent:openrouter"}
  ],
  "passthrough": ["whatsapp.com"],
  "requestable": true,
  "version": "0.33.0"
}
```

- `baseline` = the operator's static `domains.allow` from `config.yaml`.
- `granted` = domains admitted by the decider and promoted into the baseline
  by the grants watcher (empty when auto-management is disabled). Entries are
  permanent; an `expires_at` field appears only for domains time-limited via
  `agentcage domain add --expires-in`.
- `requestable` = whether `POST /v1/allowlist/requests` is enabled (so the
  agent knows before trying).

#### `POST /v1/allowlist/requests` request/response

Request body:

```json
{"domain": "registry.npmjs.org", "reason": "need to run npm install"}
```

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

Errors: `400` bad domain syntax / not allowlist mode / missing `reason`;
`409` already granted; `429` request rate limit; `503` decider unavailable
(configurable fail-open vs fail-closed; **default fail-closed** = deny).

### 3.3 The decider (built-in LLM cybersecurity-expert agent)

The decider is invoked **by the egress** (it has its own internet outbound on
the podman network, and already handles real secret values as the secret
injector). The decider is configured as a `decider:` block under
`domains.auto`, with a `kind`. **v1 ships `kind: agent` only** — the built-in
LLM decider, a senior cybersecurity expert that adjudicates each request
(Claude Code "auto" mode for egress). `kind: webhook` is **reserved / not
yet implemented** — the design below describes the `agent` decider.

#### `kind: agent` — the built-in LLM decider

The egress calls the LLM provider directly over raw HTTPS — **no SDK**, to
keep the egress image lean. Three providers:

- `anthropic` — `/v1/messages` (API key via the `x-api-key` header).
- `openai` — `/v1/chat/completions` (OpenAI chat-completions wire format).
- `openrouter` — same OpenAI chat-completions format, with OpenRouter's
  model-routing (`anthropic/claude-sonnet-4-5`, etc.).

Config gives `provider`, `model`, an `api_key` (the decider's own key,
declared with the `secret_injection.source` scheme — `env:NAME` /
`systemd-creds:NAME` / `cmd:...`; **egress-only**, stripped from the cage env
and staged to the proxy tmpfs), a `timeout_seconds` (default 15), and an
optional `base_url` override.

The agent must justify the request: the `POST` body requires a non-empty
`reason`, and the decider treats it as an **adversarial claim to be
scrutinized**. The system prompt casts the model as a senior cybersecurity
expert acting as the autonomous-approval gate: it grants only when the
justification explains a specific, plausible task and the domain is a
well-known, legitimate, low-risk service for that task; it denies
look-alikes, paste/file-share/anonymizer domains, and vague justifications.
The decision is forced through a `decide` tool call (decision/reason); a
response with no usable tool call is treated as **deny** (fail-closed). The
decider's `reason` is returned to the agent and written to `audit.jsonl` as
the risk-assessment rationale.

#### Operator context — telling the decider what the cage is FOR

By default the decider has no idea *why* the cage exists, so it can only
judge a domain request against the domain's own reputation and the shape of
the agent's (adversarial) justification. An operator who knows the cage's
purpose can supply a free-text `context` under `domains.auto`; it is appended
to the decider's system prompt as **trusted operator context** — authored by
the cage's operator (not the caged agent), so it is the one free-text allowed
in the constant system prompt the way the decision rules are. The decider is
told to use it to judge whether a requested domain fits the cage's stated
function, and explicitly that it **does NOT override the hard rules** above it
(`never_grant`, domain syntax, rate limits always apply). It is advisory only.

The context is capped at **4096 chars** (measured after stripping
whitespace) because it rides in every decider call's system prompt and
through `proxy-config.yaml` — a huge blob is a prompt-bloat/abuse surface;
`cage create`/`update` reject an over-long value with the length in the
message. Empty/whitespace-only leaves the feature off (the bare core prompt).
The caged agent can read the context via `GET /v1/allowlist` (the `context`
field) so it can write justifications that match the cage's stated scope.

```yaml
domains:
  auto:
    enable: true
    context: |
      CI cage for the payments-reconciliation test suite. Talks to staging
      APIs (api.stripe.com), publishes test coverage to codecov.io, and
      installs dependencies from npm/pypi. Nothing else should be needed.
```

The context hot-reloads via `cage update` with no restart: the egress addon
rebuilds the decider (`_init_domain_requests`) whenever `proxy-config.yaml`'s
mtime changes, so editing `context:` and running `cage update` takes effect
on the next domain request. **Known trade-off — adversarial tailoring:** the
caged agent can READ the context (via `GET /v1/allowlist`) and may shape its
justification wording to match it. This is deliberate — the decider still
independently verifies domain legitimacy and exfiltration risk, and the
hard gates (never_grant, syntax, rate limits) are enforced in code outside
the model — but write the context as scope description, not secrets or
grantable-domain lists you wouldn't want the agent quoting back.

The decider:

- Has a timeout (default 15s) and retry policy.
- Is **fail-closed by default**: a decider error or timeout → deny. Operator
- Is rate-limited per cage (default 1 req/s burst 5) independently of the
  egress's existing per-host HTTP rate limit, to bound LLM cost/abuse.

### 3.4 Applying a grant (immediate + permanent promotion)

On `grant`:

1. **Live effect (L7)**: the addon calls `DomainInspector.grant(domain)`
   which adds the domain to the in-memory `domain_set` (allowlist mode). The
   very next request to that domain passes the domain inspector. No restart,
   no SIGHUP, no upstream reconnect.
2. **Permanent promotion (baseline)**: the **auto-started grants watcher**
   (started whenever `auto.enable` is true) runs the literal `domain add`
   chain (`save_raw_config` → `save_proxy_config` → `save_dns_allowlist` →
   SIGHUP dnsmasq), baking the domain into the operator's `cage.yaml`
   baseline. The addon hot-reloads on `config.yaml`'s mtime. The grant is
   immediately reachable and permanent — it survives `cage destroy`/
   `recreate`. There is no separate overlay file and no manual `watch` step.
3. **Audit**: every request + decision is written to the egress
   `audit.jsonl` as `policy_request`, with the domain, the decision, the
   decider's `reason`, and `decided_by` (`decider:agent:<provider>` for
   grants, `decider` for structural denials). The per-cage
   `policy-audit.jsonl` (host-side, outside the grants bind mount — see §3.4)
   carries `policy_grant_applied`, `policy_grant_removed`, and
   `domain_allow_expired`.

Grants are **additive only**:

- The egress **never** writes `config.yaml` directly for a grant; promotion
  goes through the host-side `domain add` machinery, so the baseline is
  always changed through the operator-visible path.
- Introspection reports `baseline` and `granted` as distinct lists.
- Grants only ever *expand* the allow set. They cannot weaken the SNI/Host
  check, secret inspection, entropy, content-type, or body-size inspectors —
  those still run on traffic to granted domains.

### 3.5 Revoking & time-limiting grants (host-side)

Grants are **permanent** — the auto-started watcher promotes each grant into
`cage.yaml` via the existing `domain add` live-reload path, so there is no
manual `promote` step and no separate overlay to manage. The
`cage grants promote`/`revoke` commands were removed.

- **Remove a granted domain:** `agentcage domain rm <domain>` — drops it from
  the baseline and live-reloads it away.
- **Time-limit a domain:** `agentcage domain add <domain> --expires-in 30m` —
  records an expiry in `domains.expires`; the domain is removed automatically
  when it expires (`domain_allow_expired` in `policy-audit.jsonl`).
- **Debug the watcher:** `agentcage cage grants <name> watch` still exists for
  debugging the auto-promotion flow. There is no manual `watch` to start — the
  watcher starts itself when `auto.enable` is true.

This deliberately reuses the battle-tested `domain add`/`domain rm` machinery
rather than inventing a second write path.

### 3.6 Opt-in configuration

Auto-management nests under `domains.auto`, disabled by default. Full form:

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

Validation (`config.validate_config`):

- `domains.auto.enable` gates everything. When true, **both** endpoints are
  on — there are no separate `introspection:`/`request:` enable flags.
- Auto-management requires allowlist mode (`domains.allow` present); the
  request endpoint refuses to run in blocklist mode.
- `decider.kind` must be `agent` in v1 (`webhook` is reserved / not yet
  implemented).
- `decider.api_key` is **required** for `kind: agent`, declared with the
  `secret_injection.source` scheme (`env:` / `systemd-creds:` / `cmd:`). It
  is egress-only: stripped from the cage env, staged to the proxy tmpfs.
  Validated at create/update.
- There is **no `grant:` block**. Grants use fixed safe defaults: permanent
  (`ttl_seconds: 0`), max 32 concurrent, a `never_grant` set of
  `internal`/`local`/`localhost` + the control host (always unioned, the
  decider can't override), and a require-allowlist-mode invariant. These are
  NOT operator-configurable in v1.
- `max_grants >= 0` (fixed at 32), `ttl_seconds >= 0` (fixed at 0).

## 4. Threat model & security

This feature intentionally lets the cage expand its own egress, gated by the
decider. The safeguards:

1. **Opt-in, off by default.** No `domains.auto:` section (or `enable: false`)
   → zero new surface; the control host isn't even resolved.
2. **The decider is the gate.** The egress never grants without a positive
   grant from the decider. Decider failure defaults to **deny**.
3. **Additive-only.** Grants can only *widen* the allowlist; they
   never bypass the SNI/Host check, secret/entropy/content-type/body-size
   inspectors, rate limits, or the TCP-bypass kill. Granted traffic is still
   fully inspected.
4. **Control host is synthetic and non-forwardable.** The addon answers it
   locally and never opens an upstream. `agentcage.local` is in the fixed
   `never_grant` set, so the cage can't grant it to itself and can't reach a
   "real" agentcage.local upstream.
5. **No SSRF via the request endpoint.** Only the two documented paths exist;
   everything else 404s. The `domain` field is validated as a syntactically
   valid public hostname (no IP literals, no `*.local`, no link-local/metadata
   ranges — enforced via the fixed `never_grant` set + syntax check).
6. **Bounded blast radius.** Max 32 concurrent grants, per-cage request rate
   limit, full audit logging, and permanent grants that are explicitly
   removable via `agentcage domain rm`. The grant lifecycle is per-cage, not
   shared.
7. **Secret hygiene.** The decider's `api_key` flows through the
   `secret_injection.source` mechanism as an egress-only secret — the real
   value lives only in the egress, never in the cage env.
8. **Trust-boundary note (documented, not hidden).** With `kind: agent`, the
   egress makes model calls over raw HTTPS and interprets their output as
   policy. v1 ships the agent decider only; `kind: webhook` (which would keep
   policy logic outside the egress) is reserved / not yet implemented.
9. **Baseline immutability from the egress.** The egress cannot rewrite
   `config.yaml` directly; grants are promoted through the host-side
   `domain add` machinery, so the operator's static policy is never silently
   changed by the egress.

Residual risks (acknowledged):

- A grant widens egress to a new host. If the decider is mis-prompted or the
  model is compromised, the cage gains access it shouldn't. Mitigated by the
  fixed `never_grant` set, the adversarial-claim system prompt, audit, and
  explicit removal via `agentcage domain rm`.
- The egress gains a new outbound destination (the LLM provider API).
  This is egress-egress, not subject to the cage allowlist, and is pinned in
  config + audited.

## 5. Implementation plan

Sequenced so each milestone is independently shippable and reviewable. M1–M2
are safe and reversible; M3 adds the policy mutation; M4–M6 are hardening +
parity.

### M1 — Config schema + validation + docs (no runtime effect)
- `config.py`: add `DomainAutoConfig`, `DeciderConfig` (`kind: agent` only in
  v1; `webhook` reserved). Parse under `domains.auto:`. Wire into `Config`.
  No `IntrospectionConfig`/`RequestConfig`/`GrantConfig` — both endpoints are
  on when `enable` is true, and grant behavior is fixed safe defaults.
- `validate_config`: implement all rules in §3.6 (allowlist-mode requirement,
  `decider.kind == agent`, required `api_key` with a valid `*_source`
  scheme, numeric bounds).
- `docs/explain/policy-api.md` (this doc) + a section in
  `docs/reference/domains.md` pointing here.
- Tests: config parse/validate (positive + every rejection), backward-compat
  (omitted section = defaults, no warnings).

### M2 — Control host + introspection endpoint (read-only, safe)
- dnsmasq render (`services.py` / `quadlets.py`): emit
  `address=/<host>/<ip_egress>` when `domains.auto.enable` (all backends).
- `addon.py`: in `request()`, short-circuit on the control host *before* the
  SNI check / rate limit / inspector chain when enabled. Implement
  `GET /v1/allowlist` (serialize `DomainInspector` state) and `GET /v1/health`.
  Expose `DomainInspector.snapshot()` returning `{mode, baseline, granted,
  passthrough}`.
- `egress.container.j2` / apple-container egress: no new mounts needed for
  introspection-only (reads in-memory state).
- Tests: addon unit tests (control host answered, never forwarded, 404 on
  unknown paths, SNI/Host mismatch on control host → 404); e2e that a
  default-denied cage can `GET /v1/allowlist`.

### M3 — Request endpoint + decider + grants watcher
- `addon.py`: `POST /v1/allowlist/requests` handler:
  - validate domain (syntax + fixed `never_grant` + allowlist mode + not
    already granted) and require a non-empty `reason`;
  - enforce request rate limit;
  - build decision context, invoke the `kind: agent` decider (raw HTTPS to
    the LLM provider — `anthropic` `/v1/messages`, `openai`/`openrouter`
    `/v1/chat/completions`, no SDK);
  - on `grant`: `DomainInspector.grant(domain)` (immediate L7), hand off to
    the grants watcher for permanent promotion, audit, return response. On
    `deny`: audit, return.
- `DomainInspector`: add `grant(domain)` / `revoke(domain)` /
  `effective_set()`; make `configure()` not clobber grants (replay after).
- Grants watcher: auto-started when `domains.auto.enable`, runs the literal
  `domain add` chain to bake grants into `cage.yaml` (permanent). No overlay
  file and no TTL sweeper — grants are permanent; time-limiting is
  `agentcage domain add --expires-in`.
- `egress.container.j2` + apple-container: stage the decider `api_key` into
  the proxy tmpfs (egress-only), pass `AGENTCAGE_DOMAIN_AUTO_*` env where
  helpful.
- Audit: egress `audit.jsonl` `policy_request` (the decision) + per-cage
  `policy-audit.jsonl` (a sibling of `grants/`, outside the RW bind mount)
  `policy_grant_applied`/`policy_grant_removed`/`domain_allow_expired`.
- Tests: agent decider (grant/deny/timeout/fail-closed/malformed), grants
  promoted via `domain add` chain, `never_grant` enforcement, request rate
  limit, missing-`reason` rejection; e2e grant → immediate access to new host.

### M4 — Agent decider hardening
- `kind: agent` decider: prompt templating, structured `decide` tool-call
  response parsing (decision/reason). API key via `api_key` (`*_source`
  scheme, read from staged secret files).
- Hardening: response schema validation, strict parse → deny on ambiguity,
  prompt-injection-resistant system prompt (adversarial-claim framing),
  per-provider timeout/retry.
- Tests: mocked provider endpoints (grant/deny/malformed/unavailable),
  secret-resolution from staged files.

### M5 — Host-side grants management
- CLI: `agentcage cage grants <name> list` (show promoted grants) and
  `agentcage cage grants <name> watch` (debug the auto-promotion flow).
  `promote`/`revoke` were removed — grants are permanent; removal is
  `agentcage domain rm <domain>`, time-limiting is
  `agentcage domain add <domain> --expires-in`.
- `cage show` / `domain list` show granted domains alongside baseline.
- AGENTS.md brief: templated addition telling the agent the control
  endpoints exist (only rendered when `domains.auto.enable`), so it knows to
  query/request instead of guessing.
- Tests: grant → baseline updated + still live; `domain rm` removal;
  `--expires-in` expiry; show output.

### M6 — Apple-container parity + hardening + security review
- Verify the apple-container egress supervisor wires the control-host DNS
  and uid mapping (mirror of container backend's acproxy handling).
- Fuzz the control endpoint (unknown methods, huge bodies, weird Host
  headers, concurrent requests), confirm no path reaches a real upstream.
- Threat-model review pass against §4; add tests for each safeguard.
- Docs: full reference page `docs/reference/policy-api.md`, config example
  in scaffolds (commented out), changelog.

## 6. Files touched (summary)

| Area | Files |
|------|-------|
| Config | `src/agentcage/config.py` (new dataclasses + parse + validate under `domains.auto`) |
| Proxy addon | `src/agentcage/data/proxy/addon.py` (control host, endpoints, decider caller, grants watcher handoff), `inspectors/domain.py` (`grant`/`revoke`/`snapshot`, replay-safe `configure`) |
| Rendering | `src/agentcage/quadlets.py`, `src/agentcage/services.py`, `templates/egress.container.j2`, `data/containers/supervisor-egress.sh` (control-host DNS, decider `api_key` staging, env) |
| Apple-container | `src/agentcage/data/apple-container/*`, `backends/apple_container.py` (`reload_domains`-style parity for grants + control host) |
| CLI | `src/agentcage/cli.py` (`cage grants` group: `list`/`watch`; removal via `domain rm`) |
| Brief | `src/agentcage/scaffolds/AGENTS.md` (templated control-endpoint notice) |
| Docs | `docs/explain/policy-api.md`, `docs/reference/policy-api.md`, `docs/reference/domains.md` |
| Tests | `tests/` (config, addon control endpoints, decider, grants promotion, removal, e2e) |

## 7. Alternatives considered

- **Egress writes `config.yaml` directly.** Rejected: the file is `:ro` by
  design and the egress is unprivileged; letting it rewrite operator policy
  inverts the trust model. Promoting grants through the host-side
  `domain add` machinery preserves the operator-as-source-of-truth invariant.
- **Host-side daemon owns all decisions + application.** Cleanest trust
  boundary but adds an always-on component and a new IPC channel (egress→host
  request queue) for v1. Deferred (a future `kind: webhook` could delegate).
  The egress-calls-decider model reuses the egress's existing outbound and
  secret handling with no new daemon.
- **In-memory-only grants (no promotion).** Rejected: grants lost on every
  egress restart (which happens on `cage restart`, host reboot, OOM kill) —
  the agent would re-request constantly. The auto-started watcher promotes
  each grant into `cage.yaml` via `domain add`, keeping grants durable and
  operator-visible.
- **Make the control host a magic IP (e.g. 169.254.169.254).** Rejected: a
  hostname is debuggable (`curl https://agentcage.local/v1/allowlist`),
  composes with the existing dnsmasq allowlist machinery, and avoids
  colliding with metadata-service semantics. The fixed `never_grant` set
  still blocks link-local/metadata IPs by pattern.
- **Operator-configurable `grant:` block.** Rejected for v1: fixed safe
  defaults (permanent, max 32, fixed `never_grant`, require-allowlist-mode)
  keep the trust surface minimal and reviewable. Operator time-limiting is
  served by `agentcage domain add --expires-in`.
- **Generalize to ports/secrets/blocklist.** Explicitly deferred (§2) to
  keep v1's trust surface minimal and reviewable.
