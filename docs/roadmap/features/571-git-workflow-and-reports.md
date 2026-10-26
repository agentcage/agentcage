# Git worktrees, review commands and session reports

| | |
| :--- | :--- |
| **Issue** | [#571](https://github.com/agentcage/agentcage/issues/571) |
| **Status** | Proposed |
| **Priority** | P1 |
| **Phase** | 2 |
| **Depends on** | [#564](https://github.com/agentcage/agentcage/issues/564) |
| **Related** | [#574](https://github.com/agentcage/agentcage/issues/574), [#573](https://github.com/agentcage/agentcage/issues/573) |

## Problem

agentcage mounts the host working tree directly. Pivot masks protect
`.git/hooks` and project `.claude`, but an agent can still modify or delete
uncommitted work, and two agents cannot safely work on one repository. There
is no diff/review flow and no report of what happened.

## Proposal

### Workspace modes

| Mode | Behaviour |
| :--- | :--- |
| `direct` | Current behaviour: bind-mount the project at `/workspace`. |
| `worktree` | Create `agentcage/<cage>` from a base ref and mount that worktree. Host checkout untouched. |
| `clone` | Clone the project into a cage-private directory (host Git not needed at runtime). |
| `mountless` | No host workspace; clone inside the cage and push/fetch explicitly. |

Default remains `direct`; `run --worktree` is recommended in the setup wizard
and docs for parallel or unattended work.

### Review commands

```text
agentcage cage diff NAME [--base REF]
agentcage cage apply NAME [--check]
agentcage cage merge NAME [--delete]
agentcage cage checkout NAME
agentcage cage log NAME
agentcage report NAME [--format md|html|json] [-o FILE]
```

- `diff` compares the worktree/branch to its base.
- `apply` writes a patch to the host checkout as staged or unstaged changes,
  refusing if the host checkout is dirty. It never force-overwrites.
- `merge` merges the branch into the current branch.
- `checkout` checks out the branch locally.
- `log` shows the command/file history where available.
- `report` includes duration, changed files/diff stat, commands, allowed and
  blocked hosts, grants, watcher findings, artifact paths and the cleanup
  command. It uses placeholder-safe capture views.

### Unattended mode

Scaffold metadata declares `unattended_args` (for example
`--dangerously-skip-permissions`, `--full-auto`, etc.). `run --yolo` exposes
them with a warning and recommends `--worktree` plus `--rm`.

## Implementation

- Add `worktree.rs` in `agentcage-cli`, using `git worktree add` through the
  `CommandRunner` seam so argv is testable.
- Store branch/worktree metadata in deployment state; cleanup is a lifecycle
  operation, not an ad-hoc `rm -rf`.
- Path constraints: the worktree must be under a backend-mountable path
  (prefer `$XDG_DATA_HOME/agentcage/worktrees/<cage>`); verify Apple and VM
  mount behaviour before enabling those backends.
- `apply` should generate a patch from the branch and use `git apply --index`
  only after checking `git status --porcelain` is empty.
- Report generation reads existing audit/capture; no new logging channel.
- `--yolo` is per-scaffold data, not agent-specific CLI code.

## Acceptance criteria

- [ ] Two agents can run against one repo with independent worktrees and no
      shared working-tree writes.
- [ ] `diff`/`apply` round-trip a known patch; `apply` refuses a dirty host.
- [ ] `merge` produces the expected merge commit (or conflict) without
  force.
- [ ] `destroy`/`prune` remove or report worktrees predictably.
- [ ] `report` contains no real secret value.
- [ ] `--yolo` fails closed for scaffolds that do not declare unattended args.

## Tests

- Real-Git integration tests: clean/dirty apply, conflicts, submodules/LFS
  skips, unborn HEAD.
- e2e: two worktree cages modifying different files.
- Report redaction canary.
- Backend mount tests for container, VM, Apple.

## Risks

- Worktree support across VM/Apple is the hard part; ship per backend only
  after e2e passes.
- `apply` can destroy uncommitted host work if the dirty check is wrong; test
  every porcelain state.
- Reports can leak captured data; default to metadata and placeholders.
