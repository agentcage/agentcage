# CLI automation contract

| | |
| :--- | :--- |
| **Issue** | [#569](https://github.com/agentcage/agentcage/issues/569) |
| **Status** | Partly done — #585, #586 |
| **Priority** | P0 |
| **Phase** | 0 |
| **Depends on** | — |
| **Related** | [#570](https://github.com/agentcage/agentcage/issues/570), [#561](https://github.com/agentcage/agentcage/issues/561) |

## Progress (2026-10-28)

Shipped in [#585](https://github.com/agentcage/agentcage/pull/585) and
[#586](https://github.com/agentcage/agentcage/pull/586): `-h`, global
`--no-color` (and `NO_COLOR`) and `--quiet`, no spinners or banners off a TTY
or under `CI`, `agentcage paths` and `agentcage version`, and `--json` under one
envelope on `cage list`, `cage show`, `cage status`, `doctor`, `domain list`,
`secret list`, `paths` and `version`.

Different from the proposal: `--json` was added instead of
`--format table|json|yaml`, and `completions install` was declined on purpose
(see `rust/agentcage-cli/src/cli/completions.rs`).

Still open: JSON for `cage verify`, `cage stats` and `cage update --check`;
documented schemas; a test that machine output never contains a secret value.

## Problem

The CLI is a faithful click-compatible port, not a modern automation surface:
`-h` is deliberately absent; JSON exists only on `audit`, `har` and watcher
commands; there is no global quiet, color or format policy; human output is
byte-pinned by conformance fixtures. Scripts, CI, dashboards and support tools
must scrape tables.

## Proposal

### Common flags

```text
-h, --help
    --format table|json|yaml
    --quiet
    --no-color
    --no-banner
    --json            (alias for --format json on read commands)
```

- `NO_COLOR` and `CLICOLOR` are honoured; `--color=auto|always|never` is the
  explicit form.
- Spinners and banners are disabled when stdout/stderr is not a TTY or `CI` is
  set.
- `--quiet` suppresses progress and human detail but never suppresses errors
  or the final JSON.

### Stable machine output

One envelope for every read command:

```json
{
  "schema_version": 1,
  "command": "cage list",
  "ok": true,
  "data": {},
  "warnings": []
}
```

Commands: `cage list`, `cage status`, `cage show`, `doctor`, `cage verify`,
`domain list`, `secret list`, `cage audit`, `cage har`, `watcher status`,
`watcher findings`, `cage stats`, `cage update --check`.

- Add `schema_version` and document the fields.
- Secret values never appear; names and masked placeholders are allowed.
- Human output is no longer normative. Conformance tests pin JSON schemas,
  exit codes and a small set of semantic facts.

### Convenience

- `agentcage paths`: human and JSON output of config, state, data, cache and
  runtime roots.
- `agentcage completions install`: write/install completion files for
  bash/zsh/fish with a documented rc snippet.
- `agentcage version --json`.
- `agentcage cage update --check` for scripts (no rebuild).

## Implementation

- Centralize formatting in `rust/agentcage-cli/src/output.rs` or a new
  `format.rs`; avoid per-command `println!` for machine output.
- Add a `Serialize`-like adapter rather than a new dependency if the pinned
  JSON module is sufficient.
- Keep `--format table` as the default; JSON must be opt-in.
- Make exit codes consistent: 0 success, 1 operational failure, 2 usage,
  distinct code for “up to date” versus “update available” where documented.
- Move the byte-pinned human fixtures to JSON/semantic fixtures in the same
  migration; do not break aliases.

## Acceptance criteria

- [x] `agentcage -h` works and prints the long help.
- [ ] Every read command has `--format json` with a documented schema.
      *Partly: `--json` on most read commands; not `cage verify`, `cage stats` or `cage update --check`.*
- [x] `--quiet` and `--no-color` work globally; `NO_COLOR` is honoured.
- [x] CI/non-TTY runs produce no spinner or banner.
- [x] `agentcage paths --format json` is usable by scripts.
- [ ] `completions install` works for the three supported shells.
      *Declined: there is no `install` subcommand by design.*
- [ ] Machine output never contains a secret value.

## Tests

- JSON schema validation per command.
- Golden smoke tests for table output (not every byte).
- `NO_COLOR` / non-TTY output tests.
- Integration: `jq` reads list/status/doctor output.
- Completion script parse test for each shell.

## Risks

- Schema churn; version it and add fields additively.
- Changing human output breaks pinned fixtures; update them intentionally.
- `--quiet` semantics can hide important warnings; keep warnings on stderr.
