<!-- design proposal — not yet implemented -->
# Policy API: allowlist introspection + on-demand domain requests

Status: **Proposal**. Owner: @luca. Related: [Domains](../reference/domains.md),
[Inspectors](../reference/inspectors.md), [Security model](security-model.md),
[Architecture](architecture.md).

## TL;DR

Two new **opt-in** capabilities for a cage, both served by the egress proxy on a
reserved control hostname so they work even under full default-deny:

1. **Introspection** — the agent can `GET` the effective domain allow/block
   policy (baseline + runtime-granted overlay).
2. **Request** — the agent can `POST` a request to add a domain. The egress
   invokes an operator-configured **decision hook** (a webhook, or a built-in
   LLM call) that grants or denies. On grant, the domain is added to a live
   in-memory overlay that takes effect immediately and is persisted so it
   survives egress restart; the operator can promote it into the static
   `cage.yaml` baseline via the existing `agentcage domain add` path.

The egress never self-authorizes without the decision hook, never writes the
operator's `cage.yaml`, and the feature is disabled by default with zero
behavior change when off.

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
policy and (b) an in-cage way to *request* a change, gated by external logic,
with the egress applying grants to a live overlay for immediate effect and the
host promotion path reusing the existing `domain add` machinery for durability
and operator visibility.

## 2. Goals / non-goals

Goals:

- Agent can discover the effective allowlist without trial-and-error `fetch`
  (today it only learns by getting 403s).
- Agent can request a new domain; an external, operator-controlled decision
  (LLM or otherwise) grants or denies.
- Granted domains take effect immediately and survive egress restart.
- Both features are **opt-in** and **off by default**; no change for existing
  cages.
- Works under default-deny (the whole point is to ask for more access).
- Works across all three isolation backends.
- Fully audited; operator can see, promote, and revoke grants.

Non-goals (explicitly out of scope for v1):

- Requesting changes to **ports**, **blocklist** entries, **secrets**, or
  **passthrough**. v1 is allowlist-additive only. (Introspection may *show*
  these; requests cannot change them.)
- Human-in-the-loop approval UI. The decision hook *may* delegate to a human
  (a webhook can do anything), but agentcage itself ships no approval UI.
- Granting in **blocklist** mode. A grant is meaningless there (blocklist
  allows everything except listed). v1 requires allowlist mode; blocklist mode
  disables the request endpoint (introspection still works).
- Mutating any policy other than the domain allowlist.

## 3. Design

### 3.1 Control hostname

A reserved hostname, default `agentcage.local`, served entirely by the egress:

- **DNS**: dnsmasq gains `address=/agentcage.local/<ip_egress>` (rendered at
  deploy time; `ip_egress` is already known to `quadlets.py`). The cage
  resolves it to the egress and connects normally. Configurable via
  `policy_api.host`.
- **TLS**: the egress CA already mints a cert for any SNI, and the cage trusts
  that CA, so `https://agentcage.local` works with no extra cert plumbing.
- **Interception**: the addon short-circuits in `request()` **before** the
  SNI check, the rate limiter, the secret-injection policy check, and the
  inspector chain whenever `flow.request.host` (after pretty-host rewrite)
  equals the control host **and** the feature is enabled. It synthesizes an
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
| `POST` | `/v1/allowlist/requests` | Request a new domain. Triggers the decision hook. |
| `GET`  | `/v1/allowlist/requests/{id}` | Poll a request's status (async hooks). |
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
     "source": "policy-hook"}
  ],
  "passthrough": ["whatsapp.com"],
  "requestable": true,
  "version": "0.33.0"
}
```

- `baseline` = the operator's static `domains.allow` from `config.yaml`.
- `granted` = runtime overlay entries (empty when the request endpoint is
  disabled). Each carries `expires_at` if the grant has a TTL.
- `requestable` = whether `POST /v1/allowlist/requests` is enabled (so the
  agent knows before trying).

#### `POST /v1/allowlist/requests` request/response

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

Async hook (operator's webhook returns `202` with a handle) → `202` with
`status: "pending"`; the agent polls `GET /v1/allowlist/requests/{id}` until
`granted`/`denied`. The addon retains pending requests in memory for a
configurable TTL (default 5 min).

Errors: `400` bad domain syntax / not allowlist mode; `409` already granted;
`429` request rate limit; `503` decision hook unavailable (configurable
fail-open vs fail-closed; **default fail-closed** = deny).

### 3.3 Decision hook ("external logic / LLM call")

The hook is invoked **by the egress** (it has its own internet outbound on
the podman network, and already handles real secret values as the secret
injector). Two providers, selected by config:

#### Provider `webhook` (recommended, primary)

The egress `POST`s a JSON decision request to an operator-controlled URL:

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
Slack prompt. This keeps the LLM/external logic **outside** the egress trust
boundary and fully under operator control. Auth via an injected secret
(`Authorization: Bearer <secret>`, referencing a `secret_injection` env name
the egress already holds).

#### Provider `llm` (built-in, optional convenience)

The egress calls an LLM provider directly. Config gives `provider`
(`anthropic` | `openai`), `model`, an API key referenced by `secret_injection`
env name, a `prompt` template (with `{domain}`, `{reason}`, `{baseline}`,
`{granted}` placeholders), and a response parser (structured tool call →
grant/deny + reason + ttl). Reuses the egress's existing ability to hold real
secret values. Provided so a single cage can self-serve without an external
service, but documented as a larger trust surface (the egress makes model
calls and parses their output as policy).

Both providers:

- Have a timeout (default 10s) and retry policy.
- Are **fail-closed by default**: a hook error or timeout → deny. Operator
  can set `fail_open: true` to grant on error (not recommended; documented as
  risky).
- Are rate-limited per cage (default 1 req/s burst 5) independently of the
  egress's existing per-host HTTP rate limit, to bound LLM cost/abuse.

### 3.4 Applying a grant (live overlay + persistence)

On `grant`:

1. **Live effect**: the addon calls `DomainInspector.grant(domain)` which
   adds the domain to the in-memory `domain_set` (allowlist mode). The very
   next request to that domain passes the domain inspector. No restart, no
   SIGHUP, no upstream reconnect.
2. **Persistence**: the grant is appended to a **grants overlay** file on a
   writable volume (`/var/lib/agentcage/grants.yaml`, mounted from the host
   per-cage deploy dir). On egress start and on every `_maybe_reload`, the
   addon replays non-expired grants into the inspector **after** `configure()`
   so hot-reloads of `config.yaml` never wipe runtime grants.
3. **Expiry**: an optional background sweeper (a single `asyncio` task
   started in `running()`) drops expired grants from memory and the overlay.
4. **Audit**: every request + decision is written to `audit.jsonl` with
   `kind: "policy_request"`, the domain, the decision, the reason, and
   `decided_by`. This is the forensic record.

The grants overlay is **additive only** and clearly separated from the
operator's `config.yaml` baseline:

- The egress **never** writes `config.yaml` (it's `:ro`). The baseline is
  always the operator's.
- Introspection reports `baseline` and `granted` as distinct lists.
- Grants only ever *expand* the allow set. They cannot weaken the SNI/Host
  check, secret inspection, entropy, content-type, or body-size inspectors —
  those still run on traffic to granted domains.

### 3.5 Promotion to the static baseline (optional, host-side)

A grant in the overlay takes effect immediately and survives egress restart,
but a `cage destroy`/`recreate` loses it. To make a grant permanent, the
operator promotes it into `cage.yaml` via the **existing** path:

- New CLI: `agentcage cage grants <name> list` / `promote <domain>` /
  `revoke <domain>`. `promote` reads the overlay, runs the same logic as
  `domain add` (`save_raw_config` → `save_proxy_config` → `save_dns_allowlist`
  → SIGHUP dnsmasq), and removes the now-redundant overlay entry.
- Optional lightweight **host watcher** (`agentcage cage grants --watch`, or
  a systemd user unit) that auto-promotes grants after a configurable delay.
  v1 ships the on-demand CLI; the watcher is a documented follow-up so we
  don't add an always-on component before the UX is proven.

This deliberately reuses the battle-tested `domain add` machinery rather than
inventing a second write path.

### 3.6 Opt-in configuration

New top-level config section, disabled by default:

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
        auth_secret: POLICY_HOOK_TOKEN   # env name from secret_injection
        timeout_seconds: 10
        async: false                # true → 202 + poll
      # llm:                          # alternative provider
      #   provider: anthropic
      #   model: claude-sonnet-4-5
      #   auth_secret: ANTHROPIC_API_KEY
      #   timeout_seconds: 15
      fail_open: false               # true = grant on hook error (risky)
      rate_limit: {requests_per_second: 1, burst: 5}
    grant:
      ttl_seconds: 3600              # 0 = no expiry
      max_grants: 32                 # cap total overlay size
      never_grant:                   # hard deny list (always denied)
        - agentcage.local
        - 169.254.169.254
        - "*.internal"
      require_allowlist_mode: true   # refuse to run in blocklist mode (default)
```

Validation (`config.validate_config`):

- `policy_api.enable` gates everything. Both sub-`enable` flags default to
  the master.
- `request.enable` requires allowlist mode (`domains.mode == "allowlist"`)
  unless `require_allowlist_mode: false` (warned as risky).
- `never_grant` must include the control host and link-local/metadata ranges
  by default; operator additions are unioned.
- `webhook.url` must be an absolute `https` URL (or `http` to a loopback).
- `auth_secret` must reference a name present in `secret_injection` (the
  egress can only use secrets it already holds). Validated at create/update.
- `max_grants >= 0`, `ttl_seconds >= 0`.

## 4. Threat model & security

This feature intentionally lets the cage expand its own egress, gated by an
external decision. The safeguards:

1. **Opt-in, off by default.** No config section → zero new surface; the
   control host isn't even resolved.
2. **Decision hook is the gate.** The egress never grants without a positive
   grant from the hook. Hook failure defaults to **deny**.
3. **Additive-only overlay.** Grants can only *widen* the allowlist; they
   never bypass the SNI/Host check, secret/entropy/content-type/body-size
   inspectors, rate limits, or the TCP-bypass kill. Granted traffic is still
   fully inspected.
4. **Control host is synthetic and non-forwardable.** The addon answers it
   locally and never opens an upstream. `agentcage.local` is in `never_grant`
   by default, so the cage can't grant it to itself and can't reach a "real"
   agentcage.local upstream.
5. **No SSRF via the request endpoint.** Only the two documented paths exist;
   everything else 404s. The `domain` field is validated as a syntactically
   valid public hostname (no IP literals, no `*.local`, no link-local/metadata
   ranges — enforced via `never_grant` + syntax check).
6. **Bounded blast radius.** `max_grants`, per-cage request rate limit, TTL
   expiry, and full audit logging. The grants overlay is per-cage, not shared.
7. **Secret hygiene.** The hook auth secret flows through the existing
   `secret_injection` mechanism — the real value lives only in the egress,
   never in the cage env.
8. **Trust-boundary note (documented, not hidden).** With the `llm` provider,
   the egress makes model calls and interprets their output as policy. With
   the `webhook` provider, policy logic stays with the operator. The docs
   recommend `webhook` for production and flag `llm` as a larger surface.
9. **Baseline immutability.** The egress cannot rewrite `config.yaml`; the
   operator's static policy is never silently changed. Promotion is an
   explicit operator action.

Residual risks (acknowledged):

- A grant widens egress to a new host. If the hook is compromised or
  mis-prompted (LLM provider), the cage gains access it shouldn't. Mitigated
  by `never_grant`, TTLs, audit, and recommending the webhook provider.
- The egress gains a new outbound destination (the webhook URL / LLM API).
  This is egress-egress, not subject to the cage allowlist, and is pinned in
  config + audited.

## 5. Implementation plan

Sequenced so each milestone is independently shippable and reviewable. M1–M2
are safe and reversible; M3 adds the policy mutation; M4–M6 are hardening +
parity.

### M1 — Config schema + validation + docs (no runtime effect)
- `config.py`: add `PolicyApiConfig`, `IntrospectionConfig`, `RequestConfig`,
  `DecisionConfig` (`webhook`/`llm` variants), `GrantConfig`. Parse under
  `policy_api:`. Wire into `Config`.
- `validate_config`: implement all rules in §3.6 (allowlist-mode requirement,
  `never_grant` defaults incl. control host + metadata ranges, secret ref
  existence, URL shape, numeric bounds).
- `docs/explain/policy-api.md` (this doc) + a section in
  `docs/reference/domains.md` pointing here.
- Tests: config parse/validate (positive + every rejection), backward-compat
  (omitted section = defaults, no warnings).

### M2 — Control host + introspection endpoint (read-only, safe)
- dnsmasq render (`services.py` / `quadlets.py`): emit
  `address=/<host>/<ip_egress>` when `policy_api.enable` (all backends).
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

### M3 — Request endpoint + decision hook + grants overlay
- `addon.py`: `POST /v1/allowlist/requests` handler:
  - validate domain (syntax + `never_grant` + allowlist mode + not already
    granted);
  - enforce request rate limit;
  - build decision context, invoke provider (`webhook` via the egress's own
    outbound HTTP client; `llm` via provider SDK call);
  - on `grant`: `DomainInspector.grant(domain)`, append to overlay, audit,
    return response. On `deny`: audit, return. On async `202`: stash
    pending, expose poll endpoint.
- `DomainInspector`: add `grant(domain)` / `revoke(domain)` /
  `effective_set()`; make `configure()` not clobber grants (replay after).
- Grants overlay file (`/var/lib/agentcage/grants.yaml`) on a new writable
  per-cage volume; load + replay on `load()` and `_maybe_reload()`; atomic
  write (temp + rename).
- TTL expiry sweeper: `asyncio` task started in `running()`, cancelled in
  `done()`.
- `egress.container.j2` + apple-container: mount the grants volume (writable
  by `acproxy` uid 200), pass `AGENTCAGE_POLICY_API_*` env where helpful.
- Audit entries `kind: policy_request` with full context.
- Tests: webhook provider (grant/deny/timeout/fail-closed/async), grants
  replay across simulated reload, TTL expiry, `max_grants` cap, `never_grant`
  enforcement, request rate limit; e2e grant → immediate access to new host.

### M4 — Built-in LLM provider
- `llm` provider: Anthropic + OpenAI clients, prompt templating, structured
  tool-call response parsing (grant/deny/reason/ttl). API key via
  `secret_injection` env name (read from staged secret files, same path the
  injector uses).
- Hardening: response schema validation, strict parse → deny on ambiguity,
  prompt-injection-resistant system prompt, per-provider timeout/retry.
- Tests: mocked provider endpoints (grant/deny/malformed/unavailable),
  secret-resolution from staged files.

### M5 — Host-side grants management + promotion
- CLI `agentcage cage grants <name> list|promote|revoke`:
  - `list`: read overlay (host-side file) → table.
  - `promote <domain>`: run the existing `domain add` logic
    (`save_raw_config` → `save_proxy_config` → `save_dns_allowlist` →
    `_update_dns_quadlet`), then remove the overlay entry.
  - `revoke <domain>`: remove from overlay and signal egress (overlay file
    mtime → addon hot-reload drops it; or an explicit dnsmasq-style signal).
- `cage show` / `domain list` show granted overlay alongside baseline.
- AGENTS.md brief: templated addition telling the agent the control
  endpoints exist (only rendered when `policy_api.enable`), so it knows to
  query/request instead of guessing.
- Tests: promote → baseline updated + overlay cleared + still live; revoke;
  show output.

### M6 — Apple-container parity + hardening + security review
- Verify the apple-container egress supervisor wires the control-host DNS,
  grants volume, and uid mapping (mirror of container backend's acproxy
  handling).
- Fuzz the control endpoint (unknown methods, huge bodies, weird Host
  headers, concurrent requests), confirm no path reaches a real upstream.
- Threat-model review pass against §4; add tests for each safeguard.
- Docs: full reference page `docs/reference/policy-api.md`, config example
  in scaffolds (commented out), changelog.

## 6. Files touched (summary)

| Area | Files |
|------|-------|
| Config | `src/agentcage/config.py` (new dataclasses + parse + validate) |
| Proxy addon | `src/agentcage/data/proxy/addon.py` (control host, endpoints, hook caller, grants overlay, sweeper), `inspectors/domain.py` (`grant`/`revoke`/`snapshot`, replay-safe `configure`) |
| Rendering | `src/agentcage/quadlets.py`, `src/agentcage/services.py`, `templates/egress.container.j2`, `data/containers/supervisor-egress.sh` (control-host DNS, grants volume, env) |
| Apple-container | `src/agentcage/data/apple-container/*`, `backends/apple_container.py` (`reload_domains`-style parity for grants + control host) |
| CLI | `src/agentcage/cli.py` (`cage grants` group; introspection in `show`/`domain list`) |
| Brief | `src/agentcage/scaffolds/AGENTS.md` (templated control-endpoint notice) |
| Docs | `docs/explain/policy-api.md`, `docs/reference/policy-api.md`, `docs/reference/domains.md` |
| Tests | `tests/` (config, addon control endpoints, hook providers, grants replay, promotion, e2e) |

## 7. Alternatives considered

- **Egress writes `config.yaml` directly.** Rejected: the file is `:ro` by
  design and the egress is unprivileged; letting it rewrite operator policy
  inverts the trust model. The overlay + optional host promotion preserves
  the operator-as-source-of-truth invariant.
- **Host-side daemon owns all decisions + application.** Cleanest trust
  boundary but adds an always-on component and a new IPC channel (egress→host
  request queue) for v1. Deferred (§3.5 watcher). The egress-calls-hook model
  reuses the egress's existing outbound and secret handling with no new
  daemon.
- **In-memory-only grants (no persistence).** Rejected: grants lost on every
  egress restart (which happens on `cage restart`, host reboot, OOM kill) —
  the agent would re-request constantly. The overlay file is cheap and
  keeps grants durable without touching `config.yaml`.
- **Make the control host a magic IP (e.g. 169.254.169.254).** Rejected: a
  hostname is debuggable (`curl https://agentcage.local/v1/allowlist`),
  composes with the existing dnsmasq allowlist machinery, and avoids
  colliding with metadata-service semantics. The `never_grant` default still
  blocks link-local/metadata IPs by pattern.
- **Generalize to ports/secrets/blocklist.** Explicitly deferred (§2) to
  keep v1's trust surface minimal and reviewable.
