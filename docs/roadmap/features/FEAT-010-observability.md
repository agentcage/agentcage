# FEAT-010: Live observability: TUI, events, stats and reports

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P1 |
| **Phase** | 3 |
| **Depends on** | [FEAT-006](FEAT-006-cli-automation.md), [FEAT-001](FEAT-001-session-lifecycle.md) |
| **Related** | [BUG-004](../bugs/BUG-004-show-output.md) |

## Problem

Audit and HAR are excellent after the fact, but there is no live “what is
happening now?” view, no metrics and no reviewer-friendly artifact. Operators
must run several commands and tail files to understand a degraded or noisy
cage.

## Proposal

### `agentcage top`

A read-only TUI over local state:

- cages with service health, lifecycle, backend, uptime;
- requests/s, allowed/blocked/flagged counts;
- top hosts and top blocked hosts;
- active grants and expiry;
- watcher findings;
- recent events;
- selected cage details (ports, volumes, policy counts, data dir).

Read-only in v1; destructive actions remain explicit commands.

### Events and stats

```text
agentcage cage events NAME [--format json]
agentcage cage stats NAME [--format json]
```

`stats` covers CPU/memory/disk, network bytes, request counts and capture size.
`events` streams existing audit/watcher records; it does not add a new source
of truth.

### Optional OpenTelemetry

Opt-in export of lifecycle and decision events (no bodies, no headers) to an
OTLP endpoint. Off by default; document the privacy implications.

### Reports and retention

- `cage report NAME --format md|html|json`: self-contained reviewer artifact.
- `cage har --open`: open the HAR in the default browser/DevTools.
- `cage audit prune --older-than 30d` with dry-run; never deletes the active
  capture or the grants overlay.

## Implementation

- TUI: start with `ratatui`/`crossterm` or a minimal ANSI renderer; keep it a
  separate module and ensure it degrades when not a TTY.
- Poll local files with a short refresh; no daemon and no new listener.
- `stats` reads cgroup/podman stats/backend equivalents.
- OTel behind a feature flag; use the existing audit schema for attributes.
- HTML report: one file, embedded CSS, placeholders only.

## Acceptance criteria

- [ ] `agentcage top` works with zero, one and several cages and never blocks
      the rest of the CLI.
- [ ] `events --format json` is a stable stream and includes an event id.
- [ ] `stats --format json` reports the documented fields.
- [ ] OTel is off by default and carries no body/header data.
- [ ] Retention removes old files only and refuses to remove an active capture.
- [ ] Report is self-contained and contains no real secret value.

## Tests

- Snapshot/ANSI tests for the TUI with a fake terminal.
- Stats JSON schema test.
- Retention tests with active/old files.
- Report redaction canary.
- OTel disabled-by-default test.

## Risks

- Terminal portability; keep a `--no-tui`/plain mode.
- Metrics can expose hostnames; redact by default.
- TUI can become a second CLI; keep it read-only.
