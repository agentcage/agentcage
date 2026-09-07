<!-- owner: @luca  last-reviewed: 2026-09-07 -->
# Egress agents

`agents:` groups the LLM agents **agentcage runs inside the egress** on the
operator's behalf. It does not configure the caged workload. Every entry is
independently opt-in, can incur model costs, and uses an egress-only API key.
`domains:` remains the static allow/block/passthrough/expiry policy.

| Agent | Responsibility | Authority |
|-------|----------------|-----------|
| `agents.decider` | Adjudicate runtime domain requests through the [Policy API](policy-api.md). | Grant access subject to hard-coded domain, grant-count, and rate-limit checks; model errors deny. Requires allowlist mode. |
| `agents.watcher` | Review traffic after the fact and report suspicious patterns. | Revoke runtime grants, never add grants or edit the static baseline. Set `auto_revoke: false` for findings only. Blocklist mode is rejected; an omitted domains block is permitted. |

## Example

```yaml
domains:
  allow: [github.com]

agents:
  decider:
    enable: true
    context: "Build and test this repository; fetch dependencies when needed."
    provider: openrouter
    model: anthropic/claude-sonnet-4-5
    api_key: env:POLICY_LLM_KEY
  watcher:
    enable: true
    auto_revoke: false
    provider: openrouter
    model: anthropic/claude-sonnet-4-5
    api_key: env:WATCHER_LLM_KEY
```

Provider/model/key/timeout/completion-budget/base-URL settings are **flat** on
both blocks. Nested `agent:` / `decider:` wrappers and the `kind:` discriminator
are unsupported.
Omitting a block or setting `enable: false` disables that agent; presence alone
does not enable it. Enable switches must be actual YAML booleans.

## Shared LLM settings

| Setting | Default | Meaning |
|---------|---------|---------|
| `provider` | Required when enabled | `anthropic`, `openai`, or `openrouter`. |
| `model` | Required when enabled | Provider model identifier. |
| `api_key` | Required when enabled | `env:NAME` or `systemd-creds:NAME`; `cmd:` is rejected. |
| `timeout_seconds` | Decider: `15`; watcher: `30` | Positive finite LLM-call timeout. |
| `max_tokens` | `8192` | Completion budget, including reasoning; minimum `1024`. |
| `base_url` | Provider default | HTTPS-only endpoint override. OpenRouter's default is `https://openrouter.ai/api/v1`. |
| `context` | `""` | Per-agent trusted operator context, at most 4096 characters after stripping whitespace. It never overrides hard security checks. |

Keys are staged only into the egress and removed from the cage environment and
its direct secret declarations. Both agents may reference the same key name.
See the [full settings tables](configuration.md#agents-settings) for the
role-specific limits and the [watcher setup guide](../how-to/run-the-traffic-watcher.md)
for credential provisioning and cost controls.

## Migration from the old format

**Breaking change in 0.40:** `domains.auto` and top-level `watcher` are rejected,
even when empty, null, or disabled, and even if canonical blocks are also
present. There is no automatic migration or deprecation window. The `kind`
field (including `kind: agent`) and nested `agent:` / `decider:` wrappers are
unsupported under either agent.

Convert every existing config **manually**, preserving the values:

| Before (rejected) | After |
|-------------------|-------|
| `domains.auto` settings such as `enable`, `host`, `context`, `rate_limit` | The same settings under `agents.decider` |
| LLM fields under `domains.auto.decider` | Flat fields under `agents.decider` |
| Top-level `watcher` settings such as `enable`, `interval_seconds`, `auto_revoke` | The same settings under `agents.watcher` |
| LLM fields under `watcher.agent` | Flat fields under `agents.watcher` |
| `kind: agent` | Remove the field; no discriminator replaces it |

Move `provider`, `model`, `api_key`, `timeout_seconds`, `max_tokens`, and `base_url`
out of the old wrappers, then delete those wrappers and the old blocks. Leave
static `domains` policy untouched. To keep an agent disabled, omit its canonical
block or set its `enable: false`; do not leave an old disabled block behind.
The [example above](#example) shows the resulting YAML.

Edit the stored `cage.yaml` directly and run `agentcage cage update <name>`, or
prepare a complete converted config and replace the stored file with
`agentcage cage update <name> -c <converted.yaml>`. The latter accepts a converted
replacement even when the stored config still uses the rejected schema; it does
not transform that old config. Update any source copies used for future updates
too. Do not rely on `cage edit` or another config-saving command to convert it.

**Rebuild/update the egress along with the config.** Generated `proxy-config.yaml`
contains only canonical agent keys, with no legacy shadows. Old egress images
cannot read them; pushing the new config live before rebuilding can stop watcher
monitoring. This is not a live schema upgrade: stop affected cages before the
upgrade, then convert and rebuild before resuming workloads. See the
[upgrade procedure](../how-to/upgrade-agentcage.md#upgrading-to-040-the-agents-namespace).
