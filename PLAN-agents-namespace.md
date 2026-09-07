# Plan: explicit egress agents in cage.yaml

## Scope and decision

Use `agents.decider` and `agents.watcher` for the LLM agents agentcage runs
inside the egress on the operator's behalf. Each is independently opt-in,
incurs model-call costs, and holds an egress-only API key. These settings do
not configure the caged workload.

**This is an intentional breaking schema change.** Per the updated requirement,
there is no legacy YAML migration, alias support, deprecation period, or
compatibility wire output. This decision supersedes the original migration
proposal and its temporary dual-render transition.

## Schema

```yaml
domains:
  allow: [github.com]

agents:
  decider:
    enable: true
    host: agentcage.local
    context: "Build and test this repository; fetch dependencies when needed."
    rate_limit: {requests_per_second: 1, burst: 5}
    provider: openrouter
    model: anthropic/claude-sonnet-4-5
    api_key: env:POLICY_LLM_KEY
    timeout_seconds: 15
    max_tokens: 8192
  watcher:
    enable: true
    interval_seconds: 900
    window_seconds: 3600
    max_flows: 200
    auto_revoke: false
    dedup_samples: true
    max_digest_tokens: 8000
    provider: openrouter
    model: anthropic/claude-sonnet-4-5
    api_key: env:WATCHER_LLM_KEY
    timeout_seconds: 30
    max_tokens: 8192
```

- `domains:` contains only static allow/block/passthrough/expiry policy.
- Both agents have flat LLM client fields from a shared `LlmAgentConfig`.
- The decider adjudicates domain requests before access is granted.
- The watcher reviews traffic after the fact and can only revoke runtime
  grants or recommend operator actions, never widen access.
- No per-agent `kind`, `agent`, or nested `decider` implementation wrapper.
- The control hostname, endpoints, grant semantics, and CLI nouns are unchanged.

## Implementation

1. **Typed configuration** (`config.py`)
   - `Config.agents` contains `DeciderAgentConfig` and `WatcherAgentConfig`.
   - Remove `DomainConfig.auto`, `Config.watcher`, and the old wrapper classes.
   - Keep shared flat provider/model/key/timeout/budget/base-URL fields.
   - Remove normalization functions and migration-notice state.

2. **Strict input validation** (`config.py`, `state.py`)
   - Reject `domains.auto` and top-level `watcher` with actionable errors naming
     their replacements, including empty, null, disabled, or mixed old/new input.
   - Reject `kind` and nested LLM wrappers; never silently discard them.
   - Reject malformed agent mappings and non-boolean enable/revocation flags.
   - Preserve prompt context bounds, HTTPS/key-source requirements, rate limits,
     timeout/completion-budget checks, watcher spend warnings and trust rules.
   - Validate before persisting or generating proxy configuration. Reads and
     saves never transform the input schema.

3. **Canonical wire format** (`state.py`, `data/proxy/`)
   - `_PROXY_KEYS` includes `agents`, not a standalone `watcher`.
   - Generate only the canonical shape; remove legacy wire shadows entirely.
   - Update both the addon construction gates and the PolicyApi/Watcher readers.
   - Preserve watcher runtime-ref/key refresh when an unchanged block reloads.

4. **Backend wiring** (`services.py`, `secret_resolver.py`, `quadlets.py`, backends)
   - Resolve/stage both flat API keys without exposing them to the cage.
   - Add provider DNS hosts without adding cage HTTP permissions.
   - Gate the grants/findings volume on either agent or expiring domain entries.
   - Use canonical Apple metadata flags; no old `domains_auto` fallback.
   - Preserve private config-file permissions during atomic saves.

5. **CLI** (`cli.py`)
   - Update secret classification, watcher status, custom-control-host
     never-grant checks, and live-change classification to `agents.*`.
   - `cage edit` displays stored text as-is and rejects unsupported edited YAML
     before saving. Cancellation/no-op editing leaves the file untouched.
   - Explicit `cage update -c <converted.yaml>` can replace an unsupported stored
     file. Previous raw data is read only to preserve secret placeholders;
     old operational settings are not validated as new, applied, or translated.
   - No migration notices participate in update fingerprints.

6. **Documentation and tests**
   - Document the breaking change and manual conversion in the config reference,
     egress-agents reference, Policy API/watcher guides, and Unreleased changelog.
   - Keep shipped scaffold guidance on canonical keys.
   - Test rejection at parser/raw-state/save/render boundaries without rewriting
     old files, canonical-only proxy output, lifecycle gates, credentials on all
     backends, custom control hosts, editor behavior and explicit replacement.
   - Retain security regressions and unrelated domain-syntax coverage.

## Upgrade requirement

Old egress images cannot consume this wire format. Operators must manually
convert the config and update/rebuild the deployment together. Stop the cage
before replacing its config, then use `cage update` with the converted file.
Do not push the new schema live to an old egress and assume that monitoring
continues. Verify cage health and fresh watcher scan state afterward.

## Verification

Run the unit suite and changed YAML examples. Container-image integration tests
require working container tooling and registry access; report these separately
when the execution sandbox blocks them. Do not conflate configured watcher
`enable: true` with proof of a running scan loop.
