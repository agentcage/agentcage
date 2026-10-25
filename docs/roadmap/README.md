# agentcage Improvement Plan (2026–2027)

> **Status:** Proposed. This is a discussion document, not a release schedule
> or a guarantee. Each bug and feature suggestion has its own numbered page so
> that it can be reviewed, prioritised and implemented independently.

**Last updated:** 2026-10-25
**Applies to:** v0.54 through v1.0
**Scope:** usability, workflow, diagnostics, integration and distribution.
The egress and policy engine remains the centre of the product; this plan
does not propose relaxing it.

---

## How to read this plan

- **[Bugs](bugs/)** are confirmed contradictions between documented and actual
  behaviour, or user-visible defects. Each has evidence, impact and a proposed
  fix.
- **[Features](features/)** are new capabilities or product work. Each has a
  problem statement, proposed interface, implementation notes, acceptance
  criteria, dependencies and risks.
- **P0** means “do this before adding new surface”: first-run truth, auth and
  the ability to operate the CLI.
- **P1** means “make it a daily driver”: Git workflow, approvals, visibility,
  integrations.
- **P2** means “strategic depth”: platform, MCP/API, filesystem policy, team
  governance.

The numbering is stable. New entries take the next number; do not renumber an
entry after it has been linked from a PR or an issue.

---

## 1. Summary

agentcage has an unusually strong security core: default-deny egress, DNS
sinkholing, TLS inspection, zero-leak secret injection, a Policy API with an
LLM decider, a traffic watcher, HAR capture and three isolation backends.
The engineering process around it is also strong: golden fixtures, e2e tests,
fuzzing, a redteam harness and detailed documentation.

The bottleneck is now the **last mile**:

- `agentcage run` does not behave the way its documentation says it does.
- Subscription/OAuth authentication is harder than it should be.
- The CLI is not script-friendly and says little when something is wrong.
- There is no first-run wizard, policy preset or suggested allowlist.
- There is no Git-native workflow, so running agents in parallel is unsafe.
- Human approvals, notifications, MCP, editor access and an API/SDK are missing.

This plan treats those as product work, not optional polish. The target is a
tool that a developer can install, authenticate, run and review in one sitting,
while preserving the security properties that make agentcage worth using.

### Goals

1. **First success in under three minutes:** install → authenticate → run a
   real agent → see a useful result, with no manual policy editing.
2. **Honest lifecycle:** what `run`, `prune` and `destroy` keep is exactly what
   the documentation says, and cleanup is one command.
3. **A daily workflow:** isolated Git worktrees, reviewable diffs, resumable
   sessions and a post-session report.
4. **A usable policy plane:** presets, suggestions, explanations, human
   approvals and notifications, without weakening default-deny.
5. **A stable automation surface:** machine-readable output, a local API/SDK,
   CI support and MCP integration.
6. **Distribution:** self-update, package managers, notarized macOS builds,
   WSL2 support and a predictable release channel.

### Non-goals

- Becoming a cloud sandbox provider, a browser/desktop sandbox, or a GPU
  rental platform.
- Replacing Docker, Kubernetes, E2B, Daytona or Container Use. Integrate with
  them where that is cheaper than rebuilding them.
- Adding broad “open network” defaults. Any widening of policy must be an
  explicit, auditable choice.
- A large configuration surface without safe defaults.

---

## 2. Bugs

| ID | Priority | Area | Summary | Fix |
| :--- | :--- | :--- | :--- | :--- |
| [BUG-001](bugs/BUG-001-run-lifecycle.md) | P0 | Session lifecycle | `run` stops and keeps state while docs say it is removed or torn down. | [FEAT-001](features/FEAT-001-session-lifecycle.md) + docs fix |
| [BUG-002](bugs/BUG-002-auth-preflight.md) | P0 | Auth / docs | The claude scaffold promises OAuth autowiring, but `run` still requires `ANTHROPIC_API_KEY`. | [FEAT-002](features/FEAT-002-auth-strategies.md) + docs fix |
| [BUG-003](bugs/BUG-003-dns-log-service.md) | P1 | Docs / CLI | Scaffold READMEs document `-s dns`, which the CLI rejects. | Remove the line; docs test |
| [BUG-004](bugs/BUG-004-show-output.md) | P1 | CLI / docs | `cage show` prints a summary while its reference promises addresses, volumes, rules and placeholders. | [FEAT-007](features/FEAT-007-diagnostics-and-support.md) or docs fix |
| [BUG-005](bugs/BUG-005-readme-version-install.md) | P0 | Docs / release | README pins v0.50.0 and says the installer builds from source; current releases install a prebuilt binary. | Docs + release checklist |
| [BUG-006](bugs/BUG-006-grant-baseline-wording.md) | P2 | Docs / agent brief | The cage `AGENTS.md` says a granted domain is promoted into the baseline; it is a runtime grant. | Wording fix |

---

## 3. Features

| ID | Priority | Phase | Feature | Depends on |
| :--- | :--- | :--- | :--- | :--- |
| [FEAT-001](features/FEAT-001-session-lifecycle.md) | P0 | 0 | Honest, flexible `run` lifecycle: `--rm`, `--keep`, detach/attach, dry-run, prune filters | BUG-001 |
| [FEAT-002](features/FEAT-002-auth-strategies.md) | P0 | 1 | Scaffold auth strategies and `agentcage auth` | FEAT-001 |
| [FEAT-003](features/FEAT-003-guided-setup.md) | P0 | 1 | Guided first-run setup | FEAT-002 |
| [FEAT-004](features/FEAT-004-policy-presets-and-suggestions.md) | P0 | 1 | Policy presets, domain suggestions, `domain test/explain` | FEAT-003 |
| [FEAT-005](features/FEAT-005-plan-lint-config.md) | P1 | 1 | `plan`, `lint`, config schema, `extends`, devcontainer import | FEAT-003 |
| [FEAT-006](features/FEAT-006-cli-automation.md) | P0 | 0 | CLI automation contract: `-h`, format, quiet, color, paths, completions | — |
| [FEAT-007](features/FEAT-007-diagnostics-and-support.md) | P0 | 0 | Diagnostics, support bundle, actionable verify and enriched show/status | FEAT-006 |
| [FEAT-008](features/FEAT-008-git-workflow-and-reports.md) | P1 | 2 | Git worktrees/clones, diff/apply/merge, session reports, `--yolo` mapping | FEAT-001 |
| [FEAT-009](features/FEAT-009-approvals-and-notifications.md) | P1 | 3 | Human/hybrid decider, approval queue, notifications, 403 remediation | FEAT-006 |
| [FEAT-010](features/FEAT-010-observability.md) | P1 | 3 | Live TUI, events, stats, optional OTel, retention, HTML reports | FEAT-006, FEAT-001 |
| [FEAT-011](features/FEAT-011-workspace-access.md) | P1 | 4 | Dynamic ports, `cp`, `open`, SSH/editor access | FEAT-001, FEAT-006 |
| [FEAT-012](features/FEAT-012-mcp-gateway.md) | P1 | 4 | MCP gateway and MCP server for cage control | Security spike |
| [FEAT-013](features/FEAT-013-api-sdk-ci.md) | P2 | 5 | Local API, Python/TS SDK, GitHub Action | FEAT-006 |
| [FEAT-014](features/FEAT-014-filesystem-and-socket-policy.md) | P2 | 5 | Filesystem/socket policy, credential transforms, format-preserving placeholders | Threat-model update |
| [FEAT-015](features/FEAT-015-packaging-and-platform.md) | P1 | 0/5 | Self-update, Homebrew/AUR, notarization, WSL2, Nix/devcontainer | #413/#414 |
| [FEAT-016](features/FEAT-016-scaffold-registry-supply-chain.md) | P2 | 5 | OCI scaffold registry, signatures, SBOMs, prebuilt images and caches | FEAT-015 |
| [FEAT-017](features/FEAT-017-docs-conformance-and-selftest.md) | P0/P1 | 0/4 | Docs conformance and security self-test | Bugs fixed |
| [FEAT-018](features/FEAT-018-team-governance.md) | P2 | 5 | Signed audit, SIEM export, signed policy bundles | FEAT-013 |
| [FEAT-019](features/FEAT-019-standalone-gateway-and-fleet.md) | P2 | 5+ | Standalone egress gateway, remote host, fleet/warm pools | FEAT-008, FEAT-013 |

---

## 4. Phases

Estimates assume one experienced Rust engineer; workstreams can run in
parallel where dependencies allow. They are planning aids, not deadlines.

| Phase | Target | Scope | Outcome |
| :--- | :--- | :--- | :--- |
| **0. Truth and quick wins** | v0.54 | BUG-001..005, FEAT-001, FEAT-006, FEAT-007, FEAT-017 (docs) | `run` tells the truth; `-h`/JSON/quiet exist; docs no longer lie. |
| **1. First run** | v0.55 | FEAT-002..005 | A new user can install, authenticate and run without editing policy. |
| **2. Daily driver** | v0.56 | FEAT-008 | Parallel agents are safe and reviewable. |
| **3. Control and visibility** | v0.57 | FEAT-009, FEAT-010 | Operators can see and steer a running cage. |
| **4. Integration** | v0.58 | FEAT-011, FEAT-012, FEAT-017 (selftest) | agentcage fits the editor/CI loop. |
| **5. Platform** | v0.59–v1.0 | FEAT-013..016, FEAT-018, FEAT-019 | A credible 1.0 with stable contracts and distribution. |

FEAT-015 (packaging) starts immediately and runs alongside phases 0–5. It is
the only workstream whose critical path includes external accounts and
package-manager repositories.

---

## 5. Principles

- **Security first, convenience explicit.** A preset may widen policy only
  when the operator selects it, and the widening must be visible in
  `cage.yaml`, `cage plan` and the audit log.
- **Default-deny stays the default.** “Balanced” is a named profile, not a
  silent fallback.
- **One concern per PR.** Keep the review culture as the plan grows.
- **Machine-readable before pretty.** Add a versioned JSON contract for
  automation; human output can then improve without breaking conformance
  fixtures.
- **Local-first and open.** No account, no cloud dependency for the core
  experience.
- **Integrate rather than replace.** Use Git, OCI, MCP and OpenAPI where they
  already fit.
- **No silent widening, no silent deletion.** Every policy change and every
  cleanup action is printed and auditable.
- **Behaviour is documented and tested.** A documented promise should have a
  test that fails when the promise becomes false.

---

## 6. Release gates

Every phase must pass:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --locked`
- `cargo doc` with the strict rustdoc settings
- `cargo xtask check-invariants`
- docs conformance
- the relevant e2e phases
- for security-adjacent work: the redteam/self-test subset and a threat-model
  review.

A feature is not “done” because the code exists. It is done when:

1. the documented user path works on all supported backends;
2. there is an e2e or integration test for it;
3. the error path has a remediation message;
4. the changelog and docs are updated;
5. the security impact has been reviewed.

---

## 7. Decisions needed

| Decision | Recommendation | Owner |
| :--- | :--- | :--- |
| `run` default lifecycle | Keep-and-audit by default; `--rm` for true ephemeral. See [FEAT-001](features/FEAT-001-session-lifecycle.md). | Product |
| Interactive auth state | Allow a cage-owned login volume; do not mount the host home. See [FEAT-002](features/FEAT-002-auth-strategies.md). | Security + product |
| Worktree default | Opt-in for compatibility; recommend it in first-run profiles. See [FEAT-008](features/FEAT-008-git-workflow-and-reports.md). | Product |
| Approval transport | Host-side pending queue; the egress returns a retryable pending response. See [FEAT-009](features/FEAT-009-approvals-and-notifications.md). | Security |
| MCP gateway location | Host-managed gateway with tool allowlists; design spike before code. See [FEAT-012](features/FEAT-012-mcp-gateway.md). | Security |
| Windows scope | WSL2 first; native Windows is a separate project. See [FEAT-015](features/FEAT-015-packaging-and-platform.md). | Platform |
| v1.0 scope | Worktree, auth, packages and docs conformance are hard requirements; MCP/API/SDK may ship after 1.0. | Product |

---

## 8. Compatibility rules

- **Additive first.** New flags, commands, config keys and JSON output are
  introduced before any existing behaviour changes.
- **`run` default.** Keep the audit-preserving default (`--keep`) and add
  `--rm`; do not silently destroy volumes or secrets users may rely on. The
  documentation is corrected in the same release.
- **Aliases.** Keep existing top-level aliases. Deprecate a command with a
  warning for at least one minor release before removing it.
- **Config.** New keys are optional and default to current behaviour. Warnings
  are added before errors. A config written by v0.53 must continue to load.
- **State.** Existing deployments must survive an upgrade in place; run the
  state-compat fixture on every change. No migration step for phases 0–2.
- **JSON.** Add `schema_version` to every machine output. Human text may
  change; JSON fields follow the deprecation policy.
- **Security.** No new default that widens network, filesystem or credential
  access. `plan` and `doctor` must show when a non-default profile is active.

---

## 9. Success metrics

| Metric | Target |
| :--- | :--- |
| Install → first successful agent prompt | < 3 minutes on a supported host. |
| Supported auth paths that work on first try | 100% (API key, OAuth, host import, in-cage login where offered). |
| Documented behaviours with a conformance test | 100% of the promises in phases 0–2. |
| Blocked requests with a remediation hint | > 90% of domain/secret/body-size blocks. |
| Stopped `run` cages older than 7 days | 0 unless explicitly kept. |
| Fresh-install pass rate | Linux, macOS, WSL2 in CI. |
| Time from release to package-manager availability | < 1 week for stable releases. |
| Secret values in logs, argv, JSON or support bundles | 0 by test. |
| Parallel-agent adoption | Worktree used for a meaningful share of `run` sessions once shipped. |

---

## 10. Adding an entry

1. Pick the next unused number in `bugs/` or `features/`; do not renumber.
2. Copy the shape of an existing page.
3. Include status, priority, area, evidence, proposal, acceptance criteria and
   tests.
4. Add a row to the relevant table above.
5. Link the entry from the PR or issue that implements it.

This plan is intentionally reviewable in slices. A feature page can be
accepted while the implementation is still blocked on a decision, and a bug
page can be fixed without waiting for the larger workstream.
