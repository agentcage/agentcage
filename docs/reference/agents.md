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
both blocks. There is no nested `agent:` block or `kind:` discriminator.
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

Since 0.40:

- `domains.auto` becomes `agents.decider`; LLM fields move out of its nested
  `decider:` block, and `kind: agent` is removed.
- Top-level `watcher` becomes `agents.watcher`; LLM fields move out of `agent:`.

Legacy input remains supported with warnings. Only one spelling per role is
allowed, even when a block is empty, null, or disabled. Different roles may be
migrated independently. An unimplemented legacy `kind: webhook` is still
rejected, never silently converted to an LLM agent.

Reads normalize in memory; saves write canonical YAML. `cage edit` shows the
migrated form but does not write it if you cancel or return unchanged text.
During the 0.40 transition, generated proxy configuration also includes the old
wire keys for older egress images. They are derived from the canonical settings
on every render (including disable/removal) and never persisted to `cage.yaml`.
Update the cage before their scheduled removal in 0.41; see
[upgrading agentcage](../how-to/upgrade-agentcage.md#upgrading-to-040-the-agents-namespace).
