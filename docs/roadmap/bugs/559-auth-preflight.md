# the claude scaffold promises OAuth autowiring, but `run` still requires an API key

| | |
| :--- | :--- |
| **Issue** | [#559](https://github.com/agentcage/agentcage/issues/559) |
| **Status** | Fixed — closed by #590 |
| **Priority** | P0 |
| **Area** | Authentication / docs |
| **Affected** | v0.53.1 |
| **Fix** | [#565](https://github.com/agentcage/agentcage/issues/565) plus an immediate docs correction |

## Progress (2026-10-28)

Closed by [#590](https://github.com/agentcage/agentcage/pull/590) (merged 2026-10-28). `scaffold.yaml` gains `auth:`, a
list of `{secret, from_env}` alternatives; `run` needs one of them, takes the
one given with `-s` (two is an error) or else an exported one marked
`from_env`, and renders the template with `{{ auth }}` so only that rule
exists. An environment value is stored as `-s KEY=VALUE` would be, so the cage
sees only the placeholder. claude-code lists `CLAUDE_CODE_OAUTH_TOKEN`
(`from_env`) then `ANTHROPIC_API_KEY`; an exported API key still needs `-s`.
The scaffold README, `run --help` and the references now describe this.

Not covered: an e2e run against podman with a real token (the tests stop at
`run --dry-run`), and the missing-auth hint only appears on the container
backend, the one with a secret pre-flight. The rest of
[#565](https://github.com/agentcage/agentcage/issues/565) (`agentcage auth`,
cage-owned login volumes) is still open.

## Summary

The claude-code scaffold represents three auth paths: API key, a
`CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`, and an in-cage
`claude login`. The scaffold template always declares an
`ANTHROPIC_API_KEY` `secret_injection` rule. `run` requires every declared
rule, so a user who only has an OAuth token cannot run the scaffold without
inventing an API key or editing the generated config.

The scaffold README still promises the opposite:

> `agentcage run claude-code` checks for authentication before building the
> cage. If `CLAUDE_CODE_OAUTH_TOKEN` is set in your environment it is wired in
> automatically (no `-s` flag needed).

That preflight existed in the Python implementation and was deliberately
removed with host credential mounts in commit `33c22b81`. The removal was
reasonable for security; the documentation and the mandatory injection rule
were not updated.

## Evidence

- `src/agentcage/scaffolds/claude-code/cage.yaml.j2` always emits the
  `ANTHROPIC_API_KEY` rule.
- `rust/agentcage-cli/src/cli/run.rs:58-66` documents “there is no optional
  secret” and points OAuth users to a persistent cage.
- `rust/agentcage-cli/src/cli/run.rs:303-315` fails when any expected secret
  is missing.
- `src/agentcage/scaffolds/claude-code/README.md:33` promises the removed
  autowiring.
- Commit `33c22b81` removed `_preflight_claude_code_auth` and host mounts.

## Expected vs actual

**Expected:** exporting `CLAUDE_CODE_OAUTH_TOKEN` and running
`agentcage run claude-code` starts an authenticated session without an
`ANTHROPIC_API_KEY`.

**Actual:** the command reports a missing `ANTHROPIC_API_KEY` before it builds.
The user must either supply a key, edit the config, or switch to a persistent
cage with a hand-edited OAuth rule.

## Impact

- Subscription users, a large part of the target audience, hit a dead end on
  the advertised one-command path.
- The failure message suggests `-s ANTHROPIC_API_KEY=VALUE`, which nudges
  users toward putting a secret in shell history.
- It makes the scaffold look broken even though the underlying design is
  capable of OAuth injection.

## Proposed fix

1. Immediately correct the scaffold README and `run --help` text so they do
   not promise autowiring.
2. Implement the generic auth strategy model in
   [#565](https://github.com/agentcage/agentcage/issues/565): render only the
   selected strategy’s rule, detect the environment token, add the rule on
   demand, and stage the value through the secret store.
3. For in-cage login, use a cage-owned named volume rather than a host home
   mount.

## Acceptance criteria

- [x] `CLAUDE_CODE_OAUTH_TOKEN=... agentcage run claude-code` works without
      `ANTHROPIC_API_KEY` and without the real token entering the cage.
- [x] `agentcage run claude-code -s ANTHROPIC_API_KEY` still works.
- [x] A missing-auth error lists the available strategies and exact commands.
      *Container backend only; vm and apple-container have no secret pre-flight.*
- [x] The docs and help text no longer claim a preflight that does not exist.
- [ ] A test covers both auth paths and the missing-auth path.
      *Partly: both auth paths are covered through `run --dry-run`; the missing-auth hint is unit-tested only.*

## Tests

- e2e: run claude scaffold with an OAuth token only; assert the session
  starts and the placeholder, not the token, is in the cage environment.
- e2e: run with no auth; assert the error contains all supported options.
- docs: assert the scaffold README no longer promises autowiring unless the
  implementation exists.

## Related

- [#565](https://github.com/agentcage/agentcage/issues/565)
- [#558](https://github.com/agentcage/agentcage/issues/558)
