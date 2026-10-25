# Honest, flexible session lifecycle

| | |
| :--- | :--- |
| **Issue** | [#564](https://github.com/agentcage/agentcage/issues/564) |
| **Status** | Proposed |
| **Priority** | P0 |
| **Phase** | 0 |
| **Depends on** | [#558](https://github.com/agentcage/agentcage/issues/558) |
| **Related** | [#571](https://github.com/agentcage/agentcage/issues/571), [#573](https://github.com/agentcage/agentcage/issues/573) |

## Problem

`run` is the entry point most users see first, but its lifecycle is neither
what the docs say nor what users expect from an “ephemeral” command. The cage
is stopped, not removed; volumes, secrets and deployment state remain. There
is also no way to detach, resume or inspect a session before deciding what to
keep.

## Proposal

Make the semantics explicit and give the operator control:

| Command | Behaviour |
| :--- | :--- |
| `run` | Run; on exit stop and **keep** deployment, volumes, secrets and audit. Print a `Kept:` summary and the removal command. |
| `run --rm` | Run; on exit destroy the deployment, scoped secrets and cage-owned volumes. Keep the audit/HAR data directory unless `--purge-data` is also passed. |
| `run --detach` | Start the session in the background; print the cage name and attach command. |
| `attach NAME` | Reattach to a running or stopped session. |
| `run --resume NAME` | Reuse an existing stopped cage instead of failing on the name. |
| `run --dry-run` | Render the config and print the plan; do not build, pull, bind ports or write state. |
| `prune` | Remove stopped interactive/ephemeral cages, with `--dry-run`, `--older-than`, and the same `Kept:` inventory. |

Naming: `--rm` mirrors the familiar container UX; `--keep` is the explicit
form of the default. The default preserves evidence for the watcher and HAR
features. True incineration requires both `--rm` and `--purge-data`.

## Interface

```console
$ agentcage run claude-code
...
Cage 'claude-bold-fox' stopped.
Kept:
  data: /home/me/.local/share/agentcage/claude-bold-fox
  volumes: claude-bold-fox-state
  secrets: ANTHROPIC_API_KEY
Remove with: agentcage destroy claude-bold-fox

$ agentcage run claude-code --rm
# no stopped cage remains

$ agentcage run claude-code --detach --name review
review
$ agentcage attach review
$ agentcage prune --older-than 7d --dry-run
```

## Implementation

- Reuse the existing stop/destroy paths. Do not add a second teardown
  implementation: `run` should call the same lifecycle service as `cage
  destroy` and `prune`.
- Centralize the “what was kept” calculation and rendering so `run`, `stop`,
  `prune` and `destroy` cannot drift.
- Add the flags in `rust/agentcage-cli/src/cli/run.rs`; keep the orchestration
  in `agentcage-cli/src/run.rs`.
- For `--detach`, reuse the terminal/session machinery but skip the
  foreground attach; persist enough metadata for `attach` to find the cage and
  service.
- `--dry-run` must go through render + validate + plan but stop before
  `save_deployment`, image build, port binding and secret staging.
- `prune --older-than` uses the stopped-at timestamp in deployment metadata,
  not the directory mtime.
- The `run` exit summary should be generated from audit/capture files and
  include duration, decision counts, top blocked hosts, grants, watcher
  findings and artifact paths.

## Acceptance criteria

- [ ] Default `run` prints exactly what was kept and the one-line removal
      command.
- [ ] `run --rm` removes deployment, scoped secrets and cage-owned volumes,
      and leaves the audit data directory unless `--purge-data` is passed.
- [ ] `run --dry-run` writes nothing and performs no build/network pull.
- [ ] `--detach` returns a usable cage name; `attach` reconnects.
- [ ] `run --resume` works on a stopped cage and preserves its audit history.
- [ ] `prune --dry-run` lists exactly what would be removed; running/service
      cages are never candidates.
- [ ] The docs and scaffold READMEs match the implemented lifecycle.

## Tests

- e2e: default run → stopped cage, data dir present, summary contains
  `Kept:`.
- e2e: `--rm` → deployment, scoped secrets and volumes gone.
- e2e: `--dry-run` → no state dir, no podman build, no port bind.
- e2e: detach/attach with a long-running command.
- e2e: `prune --older-than` with fabricated stopped-at timestamps.
- Unit: kept-inventory renderer.

## Risks

- Detach/attach across `container`, `vm` and `apple-container` has different
  terminal semantics; ship the flag only on backends that pass the e2e test.
- Destroying on `--rm` while an audit writer is still flushing must be
  ordered and tested.
- Users may expect `--rm` to remove the audit trail; the help text must state
  what survives.
