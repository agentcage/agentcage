# Scaffold auth strategies and `agentcage auth`

| | |
| :--- | :--- |
| **Issue** | [#565](https://github.com/agentcage/agentcage/issues/565) |
| **Status** | Proposed |
| **Priority** | P0 |
| **Phase** | 1 |
| **Depends on** | [#564](https://github.com/agentcage/agentcage/issues/564) |
| **Related** | [#559](https://github.com/agentcage/agentcage/issues/559) |

## Problem

Authentication is agent-specific and currently encoded as “every
`secret_injection` rule is mandatory”. That works for API keys and fails for
subscription OAuth, in-cage login and host credential import. The old
claude-specific preflight was removed with host mounts, leaving documentation
and behaviour out of sync.

## Proposal

Make authentication a first-class, declarative part of a scaffold, and add a
host command to inspect/import auth methods.

### Scaffold metadata

```yaml
auth:
  strategies:
    - id: api_key
      env: ANTHROPIC_API_KEY
      secret: ANTHROPIC_API_KEY
      inject_to: [anthropic.com]
    - id: oauth
      env: CLAUDE_CODE_OAUTH_TOKEN
      secret: CLAUDE_CODE_OAUTH_TOKEN
      inject_to: [anthropic.com]
      import:
        command: ["claude", "setup-token"]
        help: "Mint a long-lived subscription token on the host."
    - id: login
      command: ["claude", "login"]
      state_volume: claude-state
      help: "Log in inside the cage; the token stays in the cage-owned volume."
```

`run` selects one strategy:

1. Explicit `-s KEY` / `--auth <id>`.
2. The scaffold’s preferred order, skipping strategies whose secret is absent.
3. If none is available, an actionable error listing host commands and the
   cage-scoped login option.

### CLI

```text
agentcage auth list <scaffold>
agentcage auth check <scaffold>
agentcage auth import <scaffold> --strategy claude-oauth
agentcage auth use <name> <strategy>
```

`import` runs the provider’s host command, reads its output without printing
it, stores it via the encrypted secret backend, and declares the injection
rule. It must never accept a secret value in argv.

### Cage-owned login volume

For `/login` strategies, create a named volume for the agent’s state directory
(for example `/home/agent/.claude`, `/home/agent/.pi`). This preserves the
session across `cage restart` and `cage update` without mounting the host home
directory. The volume is destroyed by `destroy`; `--rm` policy follows
[#564](https://github.com/agentcage/agentcage/issues/564).

## Security notes

- Host credential imports are explicit and audited; no automatic copying of
  `~/.claude`, `~/.codex` or `~/.pi` into the cage.
- An injected OAuth token remains outside the cage; an in-cage login token is
  usable by everything in the cage. The UI must state that difference.
- Vendor terms for OAuth tokens used outside the vendor CLI are the
  operator’s responsibility; document it once.
- `auth check` prints presence/expiry metadata, never values.

## Implementation

- Extend scaffold parsing in `agentcage-core`/`agentcage-cli/src/scaffold.rs`.
- Render only the selected strategy into `secret_injection`; `expected_secrets`
  must reflect the choice, not every alternative.
- Add `cli/auth.rs` and a `secrets` adapter for import.
- Extend `run`’s preflight, replacing the removed claude-specific code with a
  generic loop over strategies.
- Add a named-volume helper for state directories; no host bind mount.
- Update scaffold templates and READMEs; claude-code is the first migration.

## Acceptance criteria

- [ ] `run claude-code` works with only `CLAUDE_CODE_OAUTH_TOKEN` set.
- [ ] `run claude-code -s ANTHROPIC_API_KEY` still works.
- [ ] `agentcage auth import` stores encrypted and never prints the value.
- [ ] An in-cage login survives `cage update` when a cage-owned volume is used.
- [ ] Missing-auth output lists every supported path with a copy-paste command.
- [ ] The real token never appears in the cage env, audit, capture or JSON.

## Tests

- e2e auth matrix: API key, OAuth env, host import mock, in-cage login, none.
- Unit: strategy selection and rule rendering.
- Secret redaction corpus for each strategy.
- State test: named volume survives update, not destroy.

## Risks

- Vendor CLI output formats change; isolate parsing behind a small adapter.
- A login volume changes `cage backup` content; define whether it is included.
- Multiple strategies at once could widen injection; render one.
