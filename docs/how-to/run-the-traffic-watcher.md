<!-- owner: @luca  last-reviewed: 2026-09-04 -->
# Run the traffic watcher

How to enable the traffic watcher on a cage, read what it finds, and act on it. Read this when per-request checks aren't enough and you want the shape of a cage's traffic over time reviewed for exfiltration, beaconing, credential relays, and inbound prompt injection.

*Since 0.36.0*

The watcher is off by default: a cage with no `watcher:` block imports nothing, starts no task, and stages no credential. For why it runs inside the egress and what it may and may not touch, read [the traffic watcher](../explain/traffic-watcher.md).

## Decide how much authority to give it

Start with `auto_revoke: false` on a cage you haven't watched before, then turn it on once the findings earn your trust. With `false` the watcher revokes nothing but still records every revocation it would have made as a finding, so you see the analysis and apply it yourself. With `true` it applies those revocations to runtime grants directly.

The watcher requires allowlist mode. In blocklist mode the static baseline is the *block* list, so the analysis would invert and a recommended removal would widen egress instead of narrowing it; `cage create` and `cage update` reject that combination.

Autonomous revocation only bites when [`domains.auto`](../reference/policy-api.md) is enabled, because runtime grants are the only thing the watcher may narrow. On a cage without auto-managed domains, every revocation the model asks for is recorded as a finding instead, and your static allowlist is untouched either way.

## Configure the watcher

Add a `watcher:` block with `agentcage cage edit mycage`:

```yaml
watcher:
  enable: true
  auto_revoke: false
  context: "runs the nightly dependency audit against api.example.com"
  agent:
    provider: anthropic
    model: claude-sonnet-4-5
    api_key: env:WATCHER_LLM_KEY
```

Fill in `context`. It's the one trusted free-text the model receives, and it's what lets the model tell a cage doing its job from a cage being abused. Everything the watcher reads out of cage traffic is framed as untrusted evidence, so `context` is your only channel for stating intent.

Every setting, type, and default is in the [configuration reference](../reference/configuration.md#watcher-settings).

## Provide the API key

Declare the key as `env:NAME` or `systemd-creds:NAME`. Those are the two egress-only schemes; `cmd:` is rejected because the egress container has no shell.

Either export the variable before you create, start, or update the cage:

```bash
export WATCHER_LLM_KEY=sk-your-key
agentcage cage update mycage
```

Or store it once in the cage's secret store, which survives restarts and applies to a running cage without a rebuild:

```bash
agentcage secret set mycage WATCHER_LLM_KEY
```

Reusing the decider's key is fine. Point both `watcher.agent.api_key` and `domains.auto.decider.agent.api_key` at the same variable name.

## Record bodies for deeper analysis

Turn on HAR capture when you want the watcher to see request bodies and to keep evidence across an egress restart:

```yaml
capture:
  enable_har: true
```

Without it the watcher still works from its in-memory audit ring: decisions, hosts, methods, inspector triggers, secret names, and the decider's own grant record. That ring holds no bodies and resets when the egress restarts, so post-restart coverage starts from "since start" until the capture file fills in the history. The perspective model and the body-size caps are in the [capture reference](../reference/capture.md).

## Apply it to a running cage

`agentcage cage edit mycage` applies a watcher change live. It rewrites the proxy config, republishes the egress DNS so the model's provider host resolves, and the egress adopts the new block on its next config poll. No restart.

That poll runs on the cage's next request, so a completely idle cage won't start scanning until it makes one. Two other changes need more than a live edit:

- A key name the cage has never staged. Run `agentcage secret set mycage WATCHER_LLM_KEY` or `agentcage cage update mycage` so the credential reaches the egress.
- Turning on `capture.enable_har`. That adds a volume mount, so run `agentcage cage update mycage`.

## Confirm it's scanning

Run `agentcage watcher status mycage`:

```text
Traffic watcher for cage 'mycage': enabled
  scan interval:   300s
  lookback window: 3600s
  auto-revoke:    no (findings only)
  agent:          anthropic / claude-sonnet-4-5
  last scan:      2026-09-03T09:12:04+00:00
  scans run:      7
  flows in last window: 41
  findings total: 2
```

Nothing appears until the first interval elapses, and a scan is skipped entirely when the window had no traffic — a quiet cage costs nothing. If `scans run` stays at zero well past `interval_seconds`, check the credential first.

## Keep the model bill down

The digest is bounded independently of how much traffic the cage makes, so cost tracks the number of scans and the model you pick, not capture volume. Two things dominate:

- **The model.** At measured OpenRouter prices a frontier model runs roughly twenty times a fast one for the same digest. Start on a fast model and escalate only if its findings are too shallow.
- **`interval_seconds`.** Cost is linear in scan count. A quiet window is free: the watcher skips the call entirely when no traffic arrived.

The defaults hold a cage to about 885,000 input tokens a day, roughly $47 a month on a frontier-priced model and $2.50 on a fast one. `max_digest_tokens` is the hard ceiling and the only setting that bounds spend whatever the traffic does; `max_flows` bounds how many samples are sent, not how large they are. Check `digest size` in `agentcage watcher status` for what you are actually sending.

Repeated flow shapes are collapsed before the digest is sent, so a poller hitting one endpoint forty times costs one sample carrying `repeated: 40` rather than forty. Distinct request bodies survive the collapse, because that is where exfiltration evidence lives. Turn it off with `dedup_samples: false` if you want every sample verbatim.

## Read the findings

Run `agentcage watcher findings mycage` for the summary table, and add `--json` for the detail and recommendation fields:

```bash
agentcage watcher findings mycage --severity high --severity critical
agentcage watcher findings mycage --host api.example.com --json
```

The same records are in the audit stream, next to the inspector findings that caused them:

```bash
agentcage cage audit mycage --inspector watcher
agentcage cage audit mycage --decision flagged
```

Findings carry the model's severity vocabulary of `info`, `low`, `medium`, `high`, and `critical`. The audit tooling ranks that alongside the inspector ladder, so `agentcage cage audit mycage --severity warning` surfaces a `medium` finding and worse.

## Act on a finding

Revocations are already applied when `auto_revoke` is on. With it off they arrive as findings titled "revocation recommended", which you apply with `agentcage cage grants revoke`. Either way, what needs you is everything the egress is barred from doing. The watcher never edits your static allowlist: a baseline removal arrives as a finding with a recommendation, and you apply it.

```bash
agentcage domain rm mycage api.example.com
```

Check the `still_allowed_by_baseline` flag on a `watcher_revoke` audit entry before assuming traffic stopped. When it's `true` the runtime grant is gone but a static entry still matches the domain, so the cage keeps reaching it until you remove that entry too.

A revocation is not a ban. The caged agent can request the same domain again and the decider adjudicates fresh, so a domain you want gone for good belongs out of the baseline — and, if the decider keeps granting it back, named in `domains.auto.context` as something this cage has no business reaching.

## What the caged agent sees

A revoked domain starts failing mid-session, with no notification that a watcher decided it. The grant leaves the L7 allow set immediately and the egress republishes DNS within about a second, so the next request to that host is blocked exactly like any other non-allowlisted domain.

An agent that hits a sudden block on a host that worked moments ago has three sound moves:

- Read the effective policy with `GET /v1/allowlist` on the control host, to confirm the grant is gone instead of inferring it from an error.
- Request the domain again with `POST /v1/allowlist/requests`, with a justification that accounts for what the traffic actually looked like. The decider adjudicates fresh and may refuse.
- Stop and report to the operator. A grant that a traffic auditor revoked is a signal about the work, not a transient error to retry around.

The agent has no read access to findings and no endpoint to appeal or suppress one. Findings are operator-facing by design — the cage is the subject of the audit, not its audience. The endpoint contracts are in the [Policy API reference](../reference/policy-api.md).

## When a scan fails

A failed scan revokes nothing and records a finding titled `watcher scan failed`. The watcher is fail-closed on every model outcome: an error, a timeout, a missing tool call, or a verdict that breaks the output contract is a recorded failure, never an all-clear and never license to revoke.

The window isn't lost. Drained audit entries go back on the ring and the capture cursor doesn't advance, so the next tick re-analyzes the same window plus whatever arrived since. The failure finding is throttled to the first failure and every tenth after it, so a dead provider can't flood the file. `agentcage watcher status mycage` marks the last scan `[FAILED]` and counts consecutive failures.

## Turn it off

Set `enable: false`, or delete the block, with `agentcage cage edit mycage`. The scan loop stops on the next config poll and the credential stops being staged on the next start. Findings already written stay on the grants volume, so `agentcage watcher findings mycage` keeps rendering the history.

## Related

- [The traffic watcher](../explain/traffic-watcher.md) — why it runs in the egress, the trust model, the invariants.
- [Policy API](../reference/policy-api.md) — runtime grants, the decider, and the endpoints a caged agent calls.
- [Configuration](../reference/configuration.md#watcher-settings) — every `watcher:` setting.
- [Capture](../reference/capture.md) — HAR recording and the inbound and outbound perspectives.
- [Troubleshoot](troubleshoot.md) — blocked requests, missing secrets, stuck cages.
