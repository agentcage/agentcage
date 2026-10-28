# Diagnostics, support bundles and actionable status

| | |
| :--- | :--- |
| **Issue** | [#570](https://github.com/agentcage/agentcage/issues/570) |
| **Status** | Partly done — #586 |
| **Priority** | P0 |
| **Phase** | 0 |
| **Depends on** | [#569](https://github.com/agentcage/agentcage/issues/569) |
| **Related** | [#561](https://github.com/agentcage/agentcage/issues/561) |

## Progress (2026-10-28)

Shipped in [#586](https://github.com/agentcage/agentcage/pull/586), with fixes
in `fff9fa0`: `doctor --json` (schema v1, stable check ids), `fix:` lines under
every `cage verify` failure, and the enriched `cage show`/`status` with
`--json`.

Still open: `doctor --verbose`, `doctor --fix`, `doctor --config`, the
`support` bundle, JSON for `verify`, and the deployed egress version and update
availability in `show`.

## Problem

`doctor` is a strong host check, but it is text-only, has no repair path and
does not produce a safe artifact to attach to a bug report. `verify` reports
failures without naming the fix. `show`/`status` are too thin to debug a
degraded cage.

## Proposal

### `doctor`

- `doctor --json` with the same checks and machine-readable results.
- `doctor --verbose` with the full command/output behind each check.
- `doctor --fix` for safe, user-level repairs:
  - enable systemd user linger;
  - start/enable the podman socket if that is the chosen mode;
  - create missing config/state/data directories;
  - install completions;
  - repair a stale `agentcage` state lock.
- Never install OS packages or change firewall/network settings automatically;
  print the distro-specific command instead.
- `doctor --config cage.yaml`: static config/back-end readiness check without
  deploying.

### `support`

`agentcage support -o support.tar.gz` gathers:

- `agentcage version --json`, OS/kernel/backend versions;
- `doctor --json`;
- selected `cage list/status` and unit states;
- recent audit/capture tails (redacted);
- a redacted copy of the selected `cage.yaml` and generated units;
- a manifest with file sizes and hashes.

It must never include secret values, Authorization headers, cookies,
request/response bodies by default, or host environment. `--include-capture`
must be explicit and warn.

### `verify` remediation

Each failed check prints a `fix:` line with the exact command, or a docs link
when the fix is host-specific. The JSON form carries `remediation`.

### `show`/`status`

Enrich with network addresses, volumes and flags, domain names/expiry, secret
names and masked placeholders, ports, data directory, recent blocked count,
watcher state, deployed egress version and update availability.

## Implementation

- Refactor doctor checks to return structured results before rendering text.
- Add a redaction pass for support files; test it against canary secrets.
- `verify` already has pass/fail/warn; add a remediation field at the point
  each check is created.
- For `show`, reuse parsed config, raw domain config, secrets metadata and
  backend service status; do not query the network.
- `--fix` runs through `CommandRunner`; every action is printed before it is
  performed.

## Acceptance criteria

- [x] `doctor --json` is consumable by a script and matches the text checks.
- [ ] `doctor --fix` is idempotent and reviews each action.
- [ ] `support` contains no secret value, header credential or body by default.
- [x] Every `verify` failure has a remediation command or docs link.
- [x] `show --json` includes the documented fields (see [#561](https://github.com/agentcage/agentcage/issues/561)).
- [x] `show` never prints a real secret.

## Tests

- Doctor golden JSON across the existing 38 host cases.
- Support-bundle canary test: plant secrets in config/env/audit, assert none
  appear.
- `verify` remediation golden cases.
- `show` output/schema test with a multi-resource cage.

## Risks

- `--fix` touching systemd/podman can surprise; require confirmation and keep
  it user-scope.
- Support bundles can leak hostnames; offer `--redact-hosts`.
- Doctor JSON becomes a public contract; version it.
