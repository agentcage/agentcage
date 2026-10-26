# scaffold READMEs document a `-s dns` log service the CLI rejects

| | |
| :--- | :--- |
| **Issue** | [#560](https://github.com/agentcage/agentcage/issues/560) |
| **Status** | Confirmed |
| **Priority** | P1 |
| **Area** | CLI documentation |
| **Affected** | v0.53.1 |
| **Fix** | Documentation fix plus a docs test |

## Summary

Four scaffold READMEs tell the user to view DNS logs with:

```console
agentcage cage logs myagent -s dns    # DNS sidecar
```

`agentcage cage logs --service` accepts only `cage` and `egress`
(`rust/agentcage-cli/src/cli/args.rs:42`). DNS runs inside the egress
service in the current architecture, so `-s egress` is the correct command.

## Evidence

- `src/agentcage/scaffolds/claude-code/README.md`
- `src/agentcage/scaffolds/codex/README.md`
- `src/agentcage/scaffolds/pi/README.md`
- `src/agentcage/scaffolds/openclaw/README.md`
- `rust/agentcage-cli/src/cli/args.rs` — `SERVICES = ["cage", "egress"]`.

## Expected vs actual

**Expected:** the documented command works.

**Actual:** the command exits with a usage error because `dns` is not a valid
service value.

## Impact

Low severity, but it is a visible documentation defect in the first README a
new user reads, and it sends them to a command that cannot work.

## Proposed fix

- Replace every `-s dns` example with `-s egress` and a note that DNS is part
  of the egress service.
- Add a narrow docs test that extracts documented `--service` values and
  checks them against the CLI’s allowed set.

## Acceptance criteria

- [ ] No live documentation names `-s dns` or a `dns` service.
- [ ] The docs test fails if a new service value is documented without being
      added to the CLI.

## Tests

- `cargo xtask check-docs` (or equivalent) extracts `--service <value>`
  examples from fenced code blocks and validates them.

## Related

- [#580](https://github.com/agentcage/agentcage/issues/580)
