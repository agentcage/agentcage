# agentcage Improvement Plan (2026–2027)

> **Status:** Working plan, **not meant to be merged.** It lives on the
> `docs/product-roadmap-draft` branch and its draft PR, where it can be
> discussed and kept current without becoming part of the published docs.
> It is not a release schedule or a guarantee. Each bug and feature has its
> own GitHub issue, which is the tracker; the page named after that issue
> holds the plan and is updated as work ships.

**Last updated:** 2026-10-28
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
- **Status** is ✅ done, 🟡 partly done or ⬜ open. A page that has shipped work
  has a **Progress** section naming the PRs, and its acceptance criteria are
  ticked where they are met.

Issue numbers are stable. Open an issue first, then use its number as the page
filename; do not renumber an entry after it has been linked from a PR or an
issue.

---

## Progress (2026-10-28)

Most of phase 0 shipped on 2026-10-26, after this plan was written, and is in
the `[Unreleased]` section of the changelog (not yet in a release):

| PR | What shipped | Items |
| :--- | :--- | :--- |
| [#583](https://github.com/agentcage/agentcage/pull/583) | Lifecycle, install and logging docs corrected; `cargo xtask check-docs` | #558, #560, #562, #563, #580 (part) |
| [#584](https://github.com/agentcage/agentcage/pull/584) | `run --rm/--keep/--dry-run`, `Kept:` block, `prune --dry-run/--older-than` | #558, #564 (part) |
| [#585](https://github.com/agentcage/agentcage/pull/585) | `-h`, `--no-color`, `--quiet`, `--json` read output, `paths`, `version` | #569 (part) |
| [#586](https://github.com/agentcage/agentcage/pull/586) | `doctor --json`, enriched `cage show/status`, `verify` `fix:` lines | #561, #570 (part) |
| [#556](https://github.com/agentcage/agentcage/pull/556) | `agentcage update` self-update | #578 (part) |

**Phase 0 left to do:** the [#559](https://github.com/agentcage/agentcage/issues/559)
docs correction (the claude-code scaffold README still promises OAuth
autowiring); `--detach`/`attach`/`--resume` ([#564](https://github.com/agentcage/agentcage/issues/564));
JSON for `verify` and documented schemas ([#569](https://github.com/agentcage/agentcage/issues/569));
`doctor --fix` and the support bundle ([#570](https://github.com/agentcage/agentcage/issues/570)).

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

| Issue | Status | Priority | Area | Summary | Fix |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [#558](https://github.com/agentcage/agentcage/issues/558) ([plan](bugs/558-run-lifecycle.md)) | ✅ | P0 | Session lifecycle | `run` stops and keeps state while docs say it is removed or torn down. | [#564](https://github.com/agentcage/agentcage/issues/564) ([plan](features/564-session-lifecycle.md)) + docs fix |
| [#559](https://github.com/agentcage/agentcage/issues/559) ([plan](bugs/559-auth-preflight.md)) | ⬜ | P0 | Auth / docs | The claude scaffold promises OAuth autowiring, but `run` still requires `ANTHROPIC_API_KEY`. | [#565](https://github.com/agentcage/agentcage/issues/565) ([plan](features/565-auth-strategies.md)) + docs fix |
| [#560](https://github.com/agentcage/agentcage/issues/560) ([plan](bugs/560-dns-log-service.md)) | ✅ | P1 | Docs / CLI | Scaffold READMEs document `-s dns`, which the CLI rejects. | Replace with `-s egress`; docs test |
| [#561](https://github.com/agentcage/agentcage/issues/561) ([plan](bugs/561-show-output.md)) | ✅ | P1 | CLI / docs | `cage show` prints a summary while its reference promises addresses, volumes, rules and placeholders. | [#570](https://github.com/agentcage/agentcage/issues/570) ([plan](features/570-diagnostics-and-support.md)) or docs fix; `--json` uses the [#569](https://github.com/agentcage/agentcage/issues/569) ([plan](features/569-cli-automation.md)) envelope |
| [#562](https://github.com/agentcage/agentcage/issues/562) ([plan](bugs/562-readme-version-install.md)) | ✅ | P0 | Docs / release | README pins v0.50.0 and says the installer builds from source; current releases install a prebuilt binary. | Docs + release checklist |
| [#563](https://github.com/agentcage/agentcage/issues/563) ([plan](bugs/563-grant-baseline-wording.md)) | ✅ | P2 | Docs / agent brief | The cage `AGENTS.md` says a granted domain is promoted into the baseline; it is a runtime grant. | Wording fix |

---

## 3. Features

| Issue | Status | Priority | Phase | Feature | Depends on |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [#564](https://github.com/agentcage/agentcage/issues/564) ([plan](features/564-session-lifecycle.md)) | 🟡 | P0 | 0 | Honest, flexible `run` lifecycle: `--rm`, `--keep`, detach/attach, dry-run, prune filters | [#558](https://github.com/agentcage/agentcage/issues/558) |
| [#565](https://github.com/agentcage/agentcage/issues/565) ([plan](features/565-auth-strategies.md)) | ⬜ | P0 | 1 | Scaffold auth strategies and `agentcage auth` | [#564](https://github.com/agentcage/agentcage/issues/564) |
| [#566](https://github.com/agentcage/agentcage/issues/566) ([plan](features/566-guided-setup.md)) | ⬜ | P0 | 1 | Guided first-run setup | [#565](https://github.com/agentcage/agentcage/issues/565) |
| [#567](https://github.com/agentcage/agentcage/issues/567) ([plan](features/567-policy-presets-and-suggestions.md)) | ⬜ | P0 | 1 | Policy presets, domain suggestions, `domain test/explain` | [#566](https://github.com/agentcage/agentcage/issues/566) |
| [#568](https://github.com/agentcage/agentcage/issues/568) ([plan](features/568-plan-lint-config.md)) | ⬜ | P1 | 1 | `plan`, `lint`, config schema, `extends`, devcontainer import | [#566](https://github.com/agentcage/agentcage/issues/566) |
| [#569](https://github.com/agentcage/agentcage/issues/569) ([plan](features/569-cli-automation.md)) | 🟡 | P0 | 0 | CLI automation contract: `-h`, format, quiet, color, paths, completions | — |
| [#570](https://github.com/agentcage/agentcage/issues/570) ([plan](features/570-diagnostics-and-support.md)) | 🟡 | P0 | 0 | Diagnostics, support bundle, actionable verify and enriched show/status | [#569](https://github.com/agentcage/agentcage/issues/569) |
| [#571](https://github.com/agentcage/agentcage/issues/571) ([plan](features/571-git-workflow-and-reports.md)) | ⬜ | P1 | 2 | Git worktrees/clones, diff/apply/merge, session reports, `--yolo` mapping | [#564](https://github.com/agentcage/agentcage/issues/564) |
| [#572](https://github.com/agentcage/agentcage/issues/572) ([plan](features/572-approvals-and-notifications.md)) | ⬜ | P1 | 3 | Human/hybrid decider, approval queue, notifications, 403 remediation | [#569](https://github.com/agentcage/agentcage/issues/569) |
| [#573](https://github.com/agentcage/agentcage/issues/573) ([plan](features/573-observability.md)) | ⬜ | P1 | 3 | Live TUI, events, stats, optional OTel, retention, HTML reports | [#569](https://github.com/agentcage/agentcage/issues/569), [#564](https://github.com/agentcage/agentcage/issues/564) |
| [#574](https://github.com/agentcage/agentcage/issues/574) ([plan](features/574-workspace-access.md)) | ⬜ | P1 | 4 | Dynamic ports, `cp`, `open`, SSH/editor access | [#564](https://github.com/agentcage/agentcage/issues/564), [#569](https://github.com/agentcage/agentcage/issues/569) |
| [#575](https://github.com/agentcage/agentcage/issues/575) ([plan](features/575-mcp-gateway.md)) | ⬜ | P1 | 4 | MCP gateway and MCP server for cage control | Security spike |
| [#576](https://github.com/agentcage/agentcage/issues/576) ([plan](features/576-api-sdk-ci.md)) | ⬜ | P2 | 5 | Local API, Python/TS SDK, GitHub Action | [#569](https://github.com/agentcage/agentcage/issues/569) |
| [#577](https://github.com/agentcage/agentcage/issues/577) ([plan](features/577-filesystem-and-socket-policy.md)) | ⬜ | P2 | 5 | Filesystem/socket policy, credential transforms, format-preserving placeholders | Threat-model update |
| [#578](https://github.com/agentcage/agentcage/issues/578) ([plan](features/578-packaging-and-platform.md)) | 🟡 | P1 | 0/5 | Self-update, Homebrew/AUR, notarization, WSL2, Nix/devcontainer | #413/#414 |
| [#579](https://github.com/agentcage/agentcage/issues/579) ([plan](features/579-scaffold-registry-supply-chain.md)) | ⬜ | P2 | 5 | OCI scaffold registry, signatures, SBOMs, prebuilt images and caches | [#578](https://github.com/agentcage/agentcage/issues/578) |
| [#580](https://github.com/agentcage/agentcage/issues/580) ([plan](features/580-docs-conformance-and-selftest.md)) | 🟡 | P0/P1 | 0/4 | Docs conformance and security self-test | Bugs fixed |
| [#581](https://github.com/agentcage/agentcage/issues/581) ([plan](features/581-team-governance.md)) | ⬜ | P2 | 5 | Signed audit, SIEM export, signed policy bundles | [#576](https://github.com/agentcage/agentcage/issues/576) |
| [#582](https://github.com/agentcage/agentcage/issues/582) ([plan](features/582-standalone-gateway-and-fleet.md)) | ⬜ | P2 | 5+ | Standalone egress gateway, remote host, fleet/warm pools | [#571](https://github.com/agentcage/agentcage/issues/571), [#576](https://github.com/agentcage/agentcage/issues/576) |

---

## 4. Phases

Estimates assume one experienced Rust engineer; workstreams can run in
parallel where dependencies allow. They are planning aids, not deadlines.

| Phase | Target | Scope | Outcome |
| :--- | :--- | :--- | :--- |
| **0. Truth and quick wins** 🟡 | v0.54 | #558, #560–#563, #564, #569, #570, #580 (docs) | `run` tells the truth; `-h`/JSON/quiet exist; docs no longer lie. Mostly shipped; see [Progress](#progress-2026-10-28). |
| **1. First run** | v0.55 | #559, #565–#568 | A new user can install, authenticate and run without editing policy. |
| **2. Daily driver** | v0.56 | #571 | Parallel agents are safe and reviewable. |
| **3. Control and visibility** | v0.57 | #572, #573 | Operators can see and steer a running cage. |
| **4. Integration** | v0.58 | #574, #575, #580 (selftest) | agentcage fits the editor/CI loop. |
| **5. Platform** | v0.59–v1.0 | #576–#579, #581, #582 | A credible 1.0 with stable contracts and distribution. |

[#578](https://github.com/agentcage/agentcage/issues/578) (packaging) starts immediately and runs alongside phases 0–5. It is
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
| `run` default lifecycle | Keep-and-audit by default; `--rm` for true ephemeral. See [#564](https://github.com/agentcage/agentcage/issues/564) ([plan](features/564-session-lifecycle.md)). | Product |
| Interactive auth state | Allow a cage-owned login volume; do not mount the host home. See [#565](https://github.com/agentcage/agentcage/issues/565) ([plan](features/565-auth-strategies.md)). | Security + product |
| Worktree default | Opt-in for compatibility; recommend it in first-run profiles. See [#571](https://github.com/agentcage/agentcage/issues/571) ([plan](features/571-git-workflow-and-reports.md)). | Product |
| Approval transport | Host-side pending queue; the egress returns a retryable pending response. See [#572](https://github.com/agentcage/agentcage/issues/572) ([plan](features/572-approvals-and-notifications.md)). | Security |
| MCP gateway location | Host-managed gateway with tool allowlists; design spike before code. See [#575](https://github.com/agentcage/agentcage/issues/575) ([plan](features/575-mcp-gateway.md)). | Security |
| Windows scope | WSL2 first; native Windows is a separate project. See [#578](https://github.com/agentcage/agentcage/issues/578) ([plan](features/578-packaging-and-platform.md)). | Platform |
| v1.0 scope | Worktree, auth, packages and docs conformance are hard requirements; MCP/API/SDK may ship after 1.0. | Product |

---

## 8. Compatibility rules

- **Additive first.** New flags, commands, config keys and JSON output are
  introduced before any existing behaviour changes.
- **`run` default.** Keep the audit-preserving default (`--keep`) and add
  `--rm`; do not silently destroy volumes or secrets users may rely on. The
  documentation is corrected in the same release.
- **Aliases.** Keep existing top-level aliases. Deprecate a command with a
  warning for at least one minor release before removing it. *Already broken
  once:* [#556](https://github.com/agentcage/agentcage/pull/556) turned
  `agentcage update NAME` (an alias for `cage update`) into an exit-2 error
  with no warning release. Either record that as an accepted exception or add
  a warning shim before v0.54 ships.
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

1. Open a GitHub issue with a descriptive title and the right labels.
2. Create a page under `bugs/<issue>-slug.md` or `features/<issue>-slug.md`.
3. Copy the shape of an existing page and include status, priority, area,
   evidence, proposal, acceptance criteria and tests.
4. Link the issue from the page and add a row to the relevant table above.
5. Do not renumber an entry after it has been linked.

## 11. Updating an entry

When a PR ships part of an item:

1. Set the page's **Status** (`Partly done — #PR`, `Fixed — closed by #PR`).
2. Add or update its **Progress** section: what shipped, what is still open,
   and anything that shipped differently from the proposal.
3. Tick the acceptance criteria that are met; add a one-line note under any
   that are partly met or deliberately declined.
4. Update the status column above and the [Progress](#progress-2026-10-28)
   table.

This plan is intentionally reviewable in slices. A feature page can be
accepted while the implementation is still blocked on a decision, and a bug
page can be fixed without waiting for the larger workstream.
