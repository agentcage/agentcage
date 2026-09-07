# Plan: restructure cage.yaml — `agents.decider` + `agents.watcher`

Repo: `/workspace/agentcage` (Python, `src/agentcage/`). Target release: 0.40.0 (single release, no hybrid).

## 1. Context & motivation

Two LLM agents run **inside the egress** on the operator's behalf, but the cage.yaml
schema hides that fact:

- the **decider** (adjudicates domain requests before a grant) lives 4 levels deep
  under static egress policy: `domains.auto.decider.{provider,...}`
- the **watcher** (after-the-fact traffic auditor, can only narrow) sits at
  top-level `watcher:`

Problems: two spellings for one shared concept (`AgentDeciderConfig` is rendered
flat as `decider:` for the decider but nested as `agent:` for the watcher); the
"this costs money and holds an egress-only API key" signal is buried inside the
block `domain add/rm/list` edits; internal code pays for it with getattr
gymnastics (`services.py:44–60`, `quadlets.py:195–213`).

## 2. Design decisions

- **D1.** New top-level `agents:` namespace: `agents.decider` (absorbs
  `domains.auto`) + `agents.watcher` (absorbs top-level `watcher:`). Role-named
  roster, not feature-named (`policy` rejected: overloads "policy" — ports policy,
  restart policy, Policy API — and breaks when a `webhook` decider kind ships).
- **D2.** LLM client fields **flat** in each block: `provider`, `model`,
  `api_key`, `timeout_seconds`, `base_url`. Kills the `decider.agent` vs
  `watcher.agent` asymmetry; both agents use the same shared dataclass.
- **D3.** Drop `decider.kind` from the operator surface. v1 only implements
  `kind: agent`; under `agents:` the block *is* the agent. Reintroduce a
  discriminator only when webhook ships.
- **D4.** `domains:` becomes purely static operator policy: `allow`, `block`,
  `passthrough`, `expires`. `domains.auto` is removed from the schema.
- **D5.** Unchanged semantics: `enable` master switches, `agentcage.local`
  control host, `rate_limit: {requests_per_second, burst}` nested shape, per-agent
  `context` channels + 4096 caps, fixed grant defaults (`_AUTO_*` constants),
  CLI nouns (`agentcage watcher status|findings`, `domain add/rm`), fail-closed
  decider/watcher behavior.
- **D6.** Compat: `domains.auto:` and top-level `watcher:` still **parse** for
  ≥2 minor releases, normalized into `Config.agents` in-memory, with a
  deprecation warning via the existing warnings channel (config.py:1512
  warnings-returning validator, surfaced by `cage create`/`update`). Configs
  containing **both** the old and the new form of the same agent are rejected
  as ambiguous.
- **D7.** Egress wire format (`proxy-config.yaml`) renamed **in the same
  release** — no hybrid translation layer. `proxy-config.yaml` is regenerated
  state derived from the raw config (`state.save_proxy_config`), not operator
  state. Single choke-point normalization (S4) makes both cage.yaml rewrites and
  proxy-config renders emit the new form.
- **D8.** Single atomic PR/release: schema + parse + validate + normalization +
  wire format + egress readers + secret/DNS plumbing + `cage edit` + docs +
  tests together. Half-released hybrids (new cage.yaml key, old egress key) are
  exactly the two-names-one-concept trap this restructure removes.

## 3. Target schema

```yaml
# agents: LLM agents agentcage runs inside the EGRESS on the operator's
# behalf. Each is opt-in, costs money, and holds an egress-only API key.
# decider guards the front door (before a grant); watcher guards the house
# (after the traffic; can only narrow).
agents:
  decider:
    enable: true
    host: agentcage.local          # reserved control host (unchanged default)
    context: "CI cage for the payments suite; talks to staging APIs"
    rate_limit: {requests_per_second: 1, burst: 5}
    provider: openrouter           # flat LLM fields — same grammar as watcher
    model: anthropic/claude-sonnet-4-5
    api_key: env:OPENROUTER_API_KEY
    timeout_seconds: 15
    # base_url: https://openrouter.ai
  watcher:
    enable: true
    interval_seconds: 900
    window_seconds: 3600
    max_flows: 200
    auto_revoke: true
    dedup_samples: true
    max_digest_tokens: 8000
    context: "same purpose-description channel as the decider's"
    provider: openrouter
    model: anthropic/claude-sonnet-4-5
    api_key: env:WATCHER_LLM_KEY
    timeout_seconds: 30

domains:                           # purely static, operator-authored policy
  allow: [anthropic.com, github.com]
  passthrough: []
  expires: {}
```

## 4. Implementation steps

### S1 — Dataclasses (`src/agentcage/config.py`)

- Rename `AgentDeciderConfig` (~:612) → `LlmAgentConfig` (fields unchanged:
  provider/model/api_key/timeout_seconds/base_url).
- `DomainsAutoConfig` (~:646) → `DeciderAgentConfig`: enable, host, context,
  rate_limit_rps, rate_limit_burst + flat LLM fields. `DeciderConfig` (kind
  wrapper) is deleted.
- `WatcherConfig` (~:672) → `WatcherAgentConfig`: existing watcher fields minus
  the `agent` sub-block, plus flat LLM fields.
- New `AgentsConfig`: `decider` + `watcher` fields with default factories.
- `Config.agents: AgentsConfig` (~:744 area); remove `Config.watcher` (~:762);
  `DomainConfig` (~:331) drops its `auto` field.

### S2 — Parsing (`src/agentcage/config.py` ~:1160–1300)

- Parse `agents.decider` / `agents.watcher` with the existing strictness rules
  carried over verbatim: bool-type traps (`enable`, `auto_revoke`,
  `dedup_samples` — a quoted `"false"` must be rejected), explicit-`0`
  preservation for rate-limit and numeric knobs, non-string `context` rejected
  (never str()-coerced into the system prompt), numeric coercion errors
  carrying the block name.
- Compat path: `raw["domains"]["auto"]` and `raw["watcher"]` parsed by the same
  parameterized code, normalized into `Config.agents`; set a deprecation flag on
  Config (consumed by the warnings validator → `cage create`/`update` output).
- New rejection: `agents.decider` **and** `domains.auto` both present (or
  `agents.watcher` and `watcher`) → `ValueError("ambiguous: both the new
  agents.* form and the legacy form are set; keep one")`.
- **New strictness (not carried over):** the decider's `enable` is parsed by
  truthiness today (config.py:1168, no `isinstance(..., bool)` guard — a quoted
  `"false"` silently enables it); the watcher has the guard (:1252–1261). Add
  the bool-type check to `agents.decider.enable` so both agents match.
- `kind:` handling: reject `kind: webhook` **before** normalization with the
  existing "not implemented" message; a `kind: agent` (or absent) is dropped
  silently.

### S3 — Validation (`src/agentcage/config.py` ~:2133+)

- Rewrite message prefixes `domains.auto.*` → `agents.decider.*`, `watcher.*` →
  `agents.watcher.*`. Invariants unchanged: allowlist-mode requirement for both
  agents, provider enum, model/api_key required when enabled, context 4096
  caps, the >5M tokens/day watcher spend warning, never-grant set incl. control
  host, host-not-in-baseline rule.

### S4 — Raw-config normalization (`src/agentcage/state.py:81` `load_raw_config`)

- After `yaml.safe_load`, if legacy keys are present and `agents` is absent:
  rewrite the raw dict in-memory to the new form (move block, flatten LLM
  fields, drop `kind`). This is the single choke point: every downstream
  consumer — `save_raw_config` (the `domain add`/`rm` rewrite chain) and
  `save_proxy_config` (:375, renders from raw ∩ `_PROXY_KEYS`) — then emits the
  new form, so old keys evaporate from real cages on the next config-touching
  command.
- **`cage edit` bypasses this choke point today** (cli.py:1903 hands the raw
  file text to the editor, :1963/:2008 writes `edited_raw` back directly — it
  never goes through `load_raw_config`→`save_raw_config`). Left alone, an
  old-form file (a) is never migrated by `cage edit`, and (b)
  `_classify_changes(original_raw /*normalized*/, edited_raw /*old-form*/)`
  reports spurious `agents`/`watcher`/`domains` churn on a no-op edit. Fix:
  `original_text = _yaml_dump(state.load_raw_config(name))` so the editor sees
  the normalized form, the diff compares like with like, and the first
  `cage edit` migrates the file.
- Reject-both-forms check (S2) must run against the **pre-normalization** raw
  dict, before the rewrite.
- `cli.py:4631 _host_never_grant(raw)` reads `raw["domains"]["auto"]["host"]`
  from the **post-normalization** dict (callers: `domain_add` :4413→4861,
  grants reconcile :5253→5272). Untouched it silently falls back to the
  default host, so host-side and egress-side (`effective_never_grant`,
  config.py:664) never-grant sets diverge for any operator with a custom
  control host. Read `raw["agents"]["decider"]["host"]` — or better, derive
  from the typed `Config` for a single source of truth.

### S5 — Egress wire format

- `state._PROXY_KEYS` (:185): replace `"watcher"` with `"agents"`; keep
  `"domains"` (post-normalization it is static-only — the `auto` subkey never
  survives to the render).
- **`data/proxy/addon.py:201–202` — the decider construction GATE:**
  `pa_cfg = (self.cfg.get("domains") or {}).get("auto") or {}` → `if not
  pa_cfg: self.domain_requests = None`. Updating only `PolicyApi.__init__`
  below leaves the decider silently never constructed (fail-closed: every
  request denied, while the watcher works — the S10 manual check would not
  catch it). Change to `(self.cfg.get("agents") or {}).get("decider")`; update
  the log string at :219–220.
- `data/proxy/policy_api.py:276`: `self.cfg` ←
  `(proxy_cfg.get("agents") or {}).get("decider") or {}`; update downstream
  reads of the decider's LLM fields to the flat spelling. **Crucial:** at
  :322–323, `decider = self.cfg.get("decider") or {}` and
  `decider.get("kind", "agent")` must both be dropped — the decider fields
  sit flat under the block itself now, and `kind` is removed per D3.
- `data/proxy/watcher.py:739`: `self.cfg` ←
  `(proxy_cfg or {}).get("agents", {}).get("watcher") or {}`; flat LLM reads.
- `data/proxy/addon.py:276`: `w_cfg = self.cfg.get("agents", {}).get("watcher")`
  (and the `_init_watcher` rebuild path).
- **Version-skew note (see R1):** the egress readers ship inside the built
  egress image (`data/containers/Containerfile.egress`). An old running egress +
  new proxy-config.yaml reads neither `watcher` nor `domains.auto` → both
  agents simply appear disabled. Fail direction is **closed** (decider denies,
  watcher stops scanning) — an availability gap, not a security hole. Document
  "run `cage update` (rebuilds egress) after upgrading" in the migration note
  rather than rendering dual keys.

### S6 — Secret, DNS & volume plumbing (uniform agent loop)

**Verification step, not a curated list:** run
`grep -rn "\.watcher\b\|domains\.auto\|\.auto\b\|decider\.agent\|\.agent\.api_key" src/ --include="*.py" --include="*.j2"`
and clear every non-comment hit. The first draft of this plan missed the six
sites marked ★ below; all six silently disable a load-bearing path.

- ★ `quadlets.py:1065–1067` `domains_auto_enabled=` Jinja var (consumed by
  `templates/egress.container.j2:50,217`) gates the **grants-overlay bind
  mount** into the egress on container+vm. After S1 it computes `False` →
  findings/revocations/state land in the ephemeral layer → the silent
  all-clear the 0.36.0 fix exists to prevent. Recompute as
  `agents_enabled = decider.enable or watcher.enable or bool(domains.expires)`
  and rename the template var.
- ★ `backends/apple_container.py:1396–1398` writes metadata flags
  `domains_auto` / `has_expiring_domains` / `watcher_enabled` from the removed
  fields; read back at :1709–1710 to gate the same grants bind-mount on the
  apple backend. Rewrite from `config.agents.*`. (Metadata is regenerated on
  every create/update and read at start within one agentcage version → no
  cross-version skew; renaming the keys is safe.)
- ★ `backends/vm.py:984–995, 1043` VM secret staging binds
  `config.domains.auto` / `config.watcher` and reads `.decider.agent.api_key`
  / `.agent.api_key`. Untouched → neither key staged → egress dies at start
  (`no such secret`) on every `vm` cage. Read `config.agents.*.api_key`.
- ★ `secret_resolver.py:204–222` container-backend secret materialization,
  same shape (`auto.decider.agent.api_key`, `watcher.agent.api_key`) → same
  `no such secret` egress death on Linux. Read `cfg.agents.*.api_key`; update
  the `"domains.auto decider"` label strings.
- ★ `cli.py:3687–3690` `secret list` → `_collect_agent_key` does
  `getattr(getattr(src, "agent", None), "api_key", "")` — the `.agent`
  indirection no longer exists after flattening; the key would be labelled
  `orphan` (inviting `secret rm`). Read flat `.api_key`; keep the
  `decider`/`watcher` `stype` labels at :3716–3718.
- ★ `cli.py:5572+` `watcher status` reads `cfg.watcher` and
  `w.agent.provider/.model` → `cfg.agents.watcher` flat.

- `services.py:44–60` (`expected_secrets`): iterate
  `(cfg.agents.decider, cfg.agents.watcher)` — both flat, the getattr
  gymnastics (`agent` vs `decider.agent` shape-probing) is deleted.
- `quadlets.py:195–213` (`_llm_provider_dns_hosts`): same uniform loop; flat
  `.provider`/`.base_url`.
- `quadlets.py:879` decider `api_key` `Secret=` staging: read
  `cfg.agents.decider.api_key`.
- `backends/apple_container.py:1341–1382`: `_watcher = config.agents.watcher`,
  flat `api_key`; `watcher_api_key_source` metadata key — regenerated per
  create/update, single consumer in this backend → rename or keep freely (see
  ★ above for the three sibling flags that actually matter). Update the
  operator-facing warning string at :2152
  (`domains.auto.decider.agent.api_key` → `agents.decider.api_key`).

### S7 — `cage edit` classification (`src/agentcage/cli.py`)

- `_classify_changes` (:1841): live-bucket set `("domains", "watcher")` →
  `("domains", "agents")`.
- The `if "watcher" in live` block (:2027+): becomes `if "agents" in live` —
  same actions (quadlet/unit refresh for the watcher's `Secret=` + grants
  volume; `_update_dns_quadlet` for provider-host changes on either agent).
  Rationale preserved from the 0.36.0 fix: those two things are decided at
  unit-generation time.

### S8 — Docs (same PR)

- `docs/reference/configuration.md`: drop the top-level `watcher` row and
  "watcher settings" section; add an `agents` section (roster framing, decider
  + watcher tables with flat LLM fields, cost note, migration pointer).
- New `docs/reference/agents.md` (roster, credential scheme, cost model);
  linked from configuration.md, domains.md, policy-api.md.
- `docs/reference/domains.md`: remove `auto` mentions; Related → agents page.
- `docs/explain/policy-api.md` (§3.4/§3.6 YAML blocks at ~:253/:346/:364) and
  `docs/reference/policy-api.md`: `domains.auto` → `agents.decider`.
- `docs/explain/traffic-watcher.md`, `docs/how-to/run-the-traffic-watcher.md`:
  `watcher:` → `agents.watcher:`. `docs/reference/cli.md:305` ("enable it with
  the `watcher:` block").
- `CHANGELOG.md`: **Changed** entry + explicit migration note (old keys still
  parse; next config-touching command rewrites the file; `cage update` needed
  to rebuild the egress image). Add the migration note to
  `docs/how-to/upgrade-agentcage.md` as well (the existing home for post-upgrade
  steps; already documents the apple `cage update` requirement).

### S9 — Tests

- Fixture updates: `tests/test_policy_api_config.py`, `test_policy_api_ttl.py`,
  `test_policy_api_persist.py`, `test_policy_api_control.py`,
  `test_cage_cli.py`, `test_secret_resolver.py`, `test_addon_tcp_bypass.py`,
  `test_cli_aliases.py`, `test_egress_dns_apply.py`, **`test_quadlets.py:362–418`
  (asserts `domains_auto_enabled`), `test_apple_container.py:4255–4310`
  (asserts `meta["domains_auto"]`/`meta["watcher_enabled"]`), `test_watcher.py`
  (note :442 `assert "watcher" in _PROXY_KEYS` fails outright on the flip),
  `test_state.py:117,169` (`test_filters_keys` and
  `test_domains_auto_context_passes_through_verbatim` assert on old keys),
  `test_policy_api_fixes.py` (fixtures using `DeciderConfig`)**.
- New tests:
  - **highest value:** `addon._init_domain_requests` constructs `PolicyApi`
    from a new-form proxy-config (`agents.decider.enable: true`, no
    `domains.auto`) — catches the S5 gate; nothing in S10 would;
  - egress quadlet / apple metadata gate the grants bind-mount on
    `agents.decider.enable` and `agents.watcher.enable` (each alone);
  - VM (`vm.py`) and container (`secret_resolver.py`) secret staging resolve
    both agents' keys under the new form;
  - `_host_never_grant` honours a custom `agents.decider.host`;
  - `cage edit` no-op on an old-form file classifies nothing and writes
    new-form;
  - `secret list` labels both agents' keys `decider`/`watcher`, never `orphan`;
  - quoted `enable: "false"` on `agents.decider` is rejected;
  - old-form cage.yaml parses to a `Config` identical to the new form;
  - both-forms-present → ambiguous-config error;
  - `load_raw_config` normalizes old → new raw; `save_raw_config` round-trip
    migrates the on-disk file;
  - flat LLM field parse + rejection traps (quoted booleans, explicit 0);
  - `save_proxy_config` emits the `agents` key and no `watcher`/`domains.auto`;
  - egress-side readers (`policy_api`, `watcher`, `addon`) consume
    `agents.*`.
- Separate follow-up PR: `/workspace/agentcage-skill` tests reference
    `domains.auto` (cross-repo, avoids a mixed checkout PR).

### S10 — Verification

- `uv run pytest` (full suite) green.
- Manual: old cage.yaml → `cage create` warns + works; `domain add` rewrites the
  file to the new form; watcher findings still flow to `agentcage watcher
  findings`; `secret set <cage> WATCHER_LLM_KEY` classified as the watcher's key
  (not orphan); `cage edit` on an agents change refreshes units without restart.

## 5. Sequencing (commits inside the single PR)

1. S1–S3 dataclasses + parse + validate (new form primary, legacy accepted).
2. S4 + S5 normalization + wire flip (`_PROXY_KEYS`, egress readers).
3. S6 + S7 uniform secret/DNS loops + `cage edit` buckets.
4. S8 + S9 docs + fixtures + new tests + CHANGELOG.

## 6. Risks & open questions

- **R1 — Egress image version skew (S5):** old egress image + new
  proxy-config.yaml = both agents silently off until `cage update` rebuilds the
  egress. Fail-closed for the decider (no false grants), but the watcher's
  silent-off produces a *detection* gap (a false-all-clear) that looks like
  monitoring (`watcher status` reads the host-side config and reports
  "enabled" while a stale egress isn't scanning — the exact 0.36.0 hazard).
  Reviewers differed on mitigation: gpt-astra suggested a CLI warning on
  legacy normalization; fable-5.1 pushed for a bounded dual-render.
  **Resolution (strengthened):** take fable-5.1's bounded dual-render for
  0.40.0 — `save_proxy_config` renders **both** `agents.*` and the legacy
  `watcher`/`domains.auto` keys into `proxy-config.yaml` for this single
  release, scheduled for deletion in 0.41.0. This prevents the "permanent
  hybrid" by giving it a hard deadline, keeps old egress images scanning until
  `cage update`, and the CLI warning remains as belt-and-suspenders so
  operators know the sunset is coming.
- **R2 — `load_raw_config` normalization blast radius:** every caller now sees
  new-form raw. Audit all callers (grep `load_raw_config`): `_classify_changes`
  diffs both-normalized; proxy render wants new keys; anything else reading
  `raw["watcher"]` or `raw["domains"]["auto"]` directly must be updated in the
  same PR (grep-verified: `policy_api.py` reads the rendered proxy-config, not
  raw; `cli.py` reads via `_classify_changes`).
- **R3 — `kind: webhook` removal:** already rejected today (config.py:2178),
  so not a compat break. Rejection must happen **pre-normalization** (S2) —
  once `kind` is dropped there is nowhere to emit the message.
- **R4 — apple-container metadata (resolved):** the guest-side
  `cage-init.sh` is a static COPY in `Containerfile.wrapper.j2:102` (not
  regenerated per create) and does **not** read metadata keys; the only
  consumer is host-side `apple_container.py:2070–2072` which regenerates on
  every create/update within the same version → zero cross-version skew, so
  renaming is fully safe. The load-bearing part is the three sibling flags at
  :1396–1398 (S6 ★).
- **R5 — deprecation-warning channel:** warnings-returning validator exists
  (config.py:1512) but parse-time errors are raised; the deprecation is
  informational only — pick the channel that `cage create`/`update` already
  prints without breaking tests that assert on stderr.
- **R6 — `agents` namespace collision:** future in-cage workload config might
  want the name. Mitigation: header comment ("egress-side agents run by
  agentcage on the operator's behalf") + docs/reference/agents.md framing.
