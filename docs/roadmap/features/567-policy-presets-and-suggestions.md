# Policy presets, domain suggestions and explanations

| | |
| :--- | :--- |
| **Issue** | [#567](https://github.com/agentcage/agentcage/issues/567) |
| **Status** | Proposed |
| **Priority** | P0 |
| **Phase** | 1 |
| **Depends on** | [#566](https://github.com/agentcage/agentcage/issues/566) |
| **Related** | [#568](https://github.com/agentcage/agentcage/issues/568), [#572](https://github.com/agentcage/agentcage/issues/572) |

## Problem

Default-deny is the right default, but the product gives users almost no help
operating it. Scaffolds comment out package registries, blocked hosts produce
only a generic 403, and there is no way to turn an audit trail into a proposed
allowlist. Users must be policy experts before the first `npm install`.

## Proposal

### Policy profiles

Named, explicit presets:

| Profile | Contents |
| :--- | :--- |
| `strict` | Agent API only; current default-deny. |
| `balanced` | Agent API + common package registries + code hosting, listed explicitly. |
| `dev` | Balanced + common local development services; still audited. |

Presets resolve at write time into explicit `domains.allow` entries. There is
no hidden runtime expansion.

### Service catalog

Domain bundles for `anthropic`, `openai`, `github`, `node`, `python`, `rust`,
`docker`, `debian`, `ubuntu`, `arch`, with comments explaining each entry and
the redirect/telemetry hosts that often accompany it.

```console
agentcage domain add NAME --preset node
agentcage domain add NAME --preset node --expires-in 2h
```

### Suggestions

- `agentcage cage audit NAME --suggest`: group blocked hosts by count and
  propose `domain add` commands.
- `agentcage domain suggest NAME`: same, from the audit data directory.
- `agentcage run --learn`: opt-in session that records blocked hosts and
  proposes an allowlist at exit. It **never** edits `cage.yaml`; the user
  applies the proposal with a second command.

### Explain and test

- `agentcage domain test NAME HOST`: resolve the host through the cage and
  report DNS/L7 decisions and the matching rule.
- `agentcage domain explain NAME HOST`: show which allow/block/passthrough
  entry matches, whether a grant applies, and which inspectors would run.

### Denial remediation

When a request is blocked for domain policy, the 403 body should include a
machine-readable `suggestion` and the operator command to add the host, while
respecting the existing Policy API information boundary. An agent with the
skill installed should be told to request a grant rather than retry.

## Implementation

- Store presets as data (for example `src/agentcage/data/presets/*.yaml`),
  embedded by `agentcage-assets`.
- Reuse the domain matcher for `test`/`explain`; do not reimplement suffix
  matching.
- `--suggest` reads audit records, groups by host, excludes never-grant and
  already-allowed entries, and caps output.
- `--learn` must be clearly marked as a policy-widening mode and must not be
  available with `strict` without an explicit flag.
- 403 remediation should reuse the existing control-host/skill wording so the
  agent and operator see one story.

## Acceptance criteria

- [ ] `init --policy balanced` writes explicit domains, not a preset reference.
- [ ] `domain add --preset node` is deterministic and documented.
- [ ] `audit --suggest` produces actionable commands and never changes files.
- [ ] `--learn` produces a proposal only; a subsequent `domain add` is
      required.
- [ ] `domain explain` names the matching rule and decision.
- [ ] A blocked request carries a remediation hint without exposing
      operator-only internals.

## Tests

- Golden test for each preset.
- Audit fixture → suggestion output.
- Domain matcher property tests for test/explain.
- e2e: blocked host, suggest, add, retry succeeds.

## Risks

- Presets can become stale or too broad; review them like policy.
- Suggestions can reveal internal hostnames in logs; redact sensitive targets.
- `--learn` could be mistaken for safe default; mark it experimental and
  opt-in.
