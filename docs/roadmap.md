# agentcage Improvement Plan (2026–2027)

> **Status:** Proposed. This is a discussion document, not a release schedule or a
> guarantee. It records the gap between the security engine and the
> day-to-day product, and proposes an order in which to close it.

**Last updated:** 2026-10-25
**Applies to:** v0.54 through v1.0
**Scope:** usability, workflow, diagnostics, integration and distribution.
The egress and policy engine remains the centre of the product; this plan
does not propose relaxing it.

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

This plan treats those as product work, not as optional polish. The target is
a tool that a developer can install, authenticate, run and review in one
sitting, while preserving the security properties that make agentcage worth
using.

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

## 2. Where we are

### 2.1 Strengths to preserve

- **Defence in depth:** private network, DNS sinkhole, L4 filtering, TLS
  interception, SNI/Host equality, private-address guards and per-cage CAs.
- **Credential confinement:** real values never enter the workload; decoy
  placeholders are swapped on the wire and redacted inbound.
- **Autonomous controls:** the Policy API, decider and watcher are a genuine
  differentiator among local agent sandboxes.
- **Forensics:** structured audit records, dual-perspective HAR export and
  timestamped capture.
- **Backend coverage:** `container`, `apple-container` and `vm` behind one
  config.
- **Engineering discipline:** tests, golden fixtures, fuzzing, release
  automation and a maintained changelog.

### 2.2 Gaps found in the current product

| Area | Current state | User impact |
| :--- | :--- | :--- |
| Session lifecycle | `run` stops the cage and keeps deployment, volumes and secrets; docs say it is removed/torn down. | Surprise disk/subnet/secret accumulation; wrong security assumptions. |
| Auth | `run` requires every `secret_injection` rule, so the claude scaffold needs `ANTHROPIC_API_KEY` even when an OAuth token is available. The old preflight was removed; scaffold docs still promise it. | Subscription users hit a dead end on the first command. |
| CLI | No `-h`; JSON only on `audit`, `har` and watcher commands; no global quiet/no-color. | Hard to script, test, dashboard or support. |
| Onboarding | No wizard or presets; package registries are commented out; no suggested allowlist. | The first `npm install` or `pip install` is a policy debugging session. |
| Status | `cage show` prints seven summary lines, despite the CLI reference promising addresses, volumes, rules and placeholders. | Operators cannot see what is actually deployed. |
| Git workflow | The host working tree is mounted directly; no worktrees, diff/apply or review flow. | Parallel agents are unsafe; uncommitted work is at risk. |
| Approvals | The Policy API is LLM-only; no pending queue, desktop notification or webhook. | Headless/remote agents stop silently; watcher findings are easy to miss. |
| Integration | No MCP gateway, dynamic ports, `cp`, editor/SSH access or public API/SDK. | agentcage is not part of the daily editor/CI/orchestration loop. |
| Filesystem policy | Only fixed pivot masks for `.git/hooks` and `.claude`; no general read/write denylist or Unix-socket policy. | `.env`, SSH material or host sockets can remain reachable through mounts. |
| Distribution | No Homebrew/AUR, no notarized macOS binary, no Windows/WSL path, self-update still proposed. | Installation is a project of its own. |
| Docs | README still pins v0.50.0 and says the installer builds from source; scaffold READMEs name `-s dns`, which the CLI rejects. | Documentation is no longer a reliable contract. |

The evidence for these entries is in the current code, CLI output and docs;
the table is the short version for reviewers. Existing issues that belong to
this work include #413, #414, #416, #418, #422, #464, #467, #513, #543, #544
and #545.

### 2.3 Competitive context

| Project | Pattern worth borrowing |
| :--- | :--- |
| **Docker Sandboxes (`sbx`)** | First-run network presets, broad agent support, direct/clone/worktree/mountless modes, dynamic ports, `cp`, SSH/editor integrations, MCP gateway, `secret set --command`, structured diagnostics, kits and cloud. |
| **Anthropic Sandbox Runtime (`srt`)** | Filesystem allow/deny rules, Unix-socket policy, an `ask` callback, per-command allowlists, live config updates and model-facing denial reasons. |
| **Container Use** | One branch/container per agent, command history, `diff`/`apply`/`merge`/`checkout`, live `watch`, MCP. |
| **Microsandbox** | SDKs, snapshot/fork, detached sandboxes, MCP, cross-platform support. |
| **nono** | Composable profiles, tool-scoped credentials, L7 method/path rules, signed skills/hooks, tamper-evident audit and rollback. |
| **ai-jail** | Developer-friendly defaults: agent state, toolchain caches, private home, worktrees, `--dry-run` and a status bar. |
| **OpenSandbox / Kubernetes agent-sandbox** | Declarative templates, warm pools/claims, pause/resume, SDK/API/MCP and credential vaults. |

The market has split into OS sandboxes, container/VM runtimes and workflow
layers. agentcage should own the **policy and audit plane** and add just enough
workflow to be a daily driver. It should not try to match every runtime
feature.

### 2.4 The central decision

For the next two quarters, **do not add major new egress features** unless a
security fix requires one. Put the effort into the surface around the engine:

1. Make the advertised behaviours true.
2. Make the first session easy.
3. Make the daily loop safe and reviewable.
4. Make the policy plane visible and controllable.
5. Make it installable everywhere the target user works.

---

## 3. Principles

- **Security first, convenience explicit.** A preset may widen policy only
  when the operator selects it, and the widening must be visible in
  `cage.yaml`, `cage plan` and the audit log.
- **Default-deny stays the default.** “Balanced” is a named profile, not a
  silent fallback.
- **One concern per PR.** This is already the project’s review culture; keep
  it as the plan grows.
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

## 4. Workstreams

The work below is ordered by dependency, not by importance. Each workstream
contains a problem statement, deliverables, proposed interface, implementation
notes and acceptance criteria.

### A. Honest, flexible sessions

**Problem.** `run` stops the cage but keeps the deployment, quadlets, named
volumes and podman secrets (`rust/agentcage-cli/src/run.rs:28-34`,
`rust/agentcage-cli/src/cli/run.rs:468-478`). The README, quickstart, CLI
reference and every scaffold README say the cage is removed, torn down or
destroyed. Users therefore accumulate stopped cages and may believe secrets
and volumes were deleted.

**Deliverables**

- `agentcage run --rm`: destroy the deployment, volumes and secrets on exit.
- `agentcage run --keep`: default; print exactly what was kept and the one
  command that removes it.
- `agentcage run --detach` and `agentcage attach NAME`: leave a session
  running and reattach later.
- `agentcage run --resume NAME`: reuse a stopped cage instead of erroring on
  the name collision.
- `agentcage prune --dry-run`, `--older-than`, `--filter status=stopped`.
- `agentcage run --dry-run`: print the rendered config, image, mounts,
  allowlist, secrets required and commands that would run; do not build.
- A session summary at exit: duration, allowed/blocked counts, grants,
  watcher findings, audit/HAR paths, workspace state and the cleanup command.
- A clear separation between “ephemeral session” and “persistent cage” in
  help text and docs.

**Proposed interface**

```console
agentcage run claude-code                 # stopped and kept; prints Kept:
agentcage run claude-code --rm            # destroyed on exit
agentcage run claude-code --detach        # returns a cage name
agentcage attach claude-bold-fox
agentcage prune --older-than 7d --dry-run
```

**Implementation notes**

- `run` already has a stop path; add the destroy path through the existing
  `destroy_cage`/backend APIs rather than a second teardown implementation.
- Put the “what survives” inventory in one place and print it from both
  `run` and `destroy`/`prune`.
- `--detach` must keep the session watchdog and audit writer alive; the
  existing backend `stop` is not enough.
- `prune` must never remove a running cage or a `service` cage (it already
  filters lifecycle; keep that invariant).
- The default should preserve the audit trail. Destroying evidence on every
  exit would undermine the watcher and HAR features.

**Acceptance criteria**

- After a default `run`, `cage list` shows a stopped cage and the exit text
  names the path and cleanup command.
- `run --rm` leaves no deployment, named volume or scoped secret.
- `run --dry-run` writes nothing and performs no build/network pull.
- `prune --dry-run` lists exactly what would be removed and changes nothing.
- Docs and scaffold READMEs match the chosen semantics; a regression test
  fails when they drift.

**Estimate:** 3–5 engineer-days.
**Depends on:** none.
**Risks:** deciding the default semantics; detach/attach lifecycle on VM and
Apple backends.

---

### B. Authentication that matches how agents are actually used

**Problem.** `run` requires every `secret_injection` rule. The claude scaffold
always declares `ANTHROPIC_API_KEY`, so `agentcage run claude-code` fails
without a key even when `CLAUDE_CODE_OAUTH_TOKEN` is set. The scaffold README
still promises autowiring (`src/agentcage/scaffolds/claude-code/README.md:33`),
but the Python preflight was removed together with host credential mounts in
commit `33c22b81`, for good security reasons. The result is a first-command
dead end for subscription users.

**Deliverables**

- A generic auth strategy model in `scaffold.yaml`; no agent-specific code in
  the CLI core.
- `agentcage auth` commands to inspect, import and remove auth methods.
- OAuth token import from the environment, a host command, or the vendor CLI
  (for example `claude setup-token`), stored encrypted and injected as a
  secret.
- A cage-owned named volume for interactive `/login` state so it survives
  `cage update` without exposing the host home directory.
- `run` selection logic: API key, OAuth token, host CLI import, or interactive
  login; print the available choices when none is present.
- `--login` for the interactive path, with a clear explanation that the
  agent’s own token lives in the cage-owned volume.
- No secret values in argv, environment dumps or logs.

**Proposed scaffold metadata**

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
        help: "Mint a long-lived Claude subscription token on the host."
    - id: login
      command: ["claude", "login"]
      state_volume: claude-state
      help: "Log in inside the cage; the token stays in the cage-owned volume."
```

**Implementation notes**

- Parse and validate `auth` in `agentcage-core`; scaffolds are data and must
  remain declarative.
- `run` renders only the selected strategy into `secret_injection`, rather than
  leaving every alternative rule mandatory.
- `agentcage auth import` must use the existing secret store and never print
  the value. `--from-command` should execute on the host (as `source: cmd:`
  already does) and report only success.
- A named volume is cage-scoped, not a host bind mount. It preserves login
  across image rebuilds without re-exposing `~/.claude`, `~/.codex` or
  `~/.pi`.
- The docs must state the trade-off: an in-cage login token is usable by
  everything in the cage; an injected token remains outside it.

**Acceptance criteria**

- `agentcage run claude-code` with an exported OAuth token starts without
  `-s ANTHROPIC_API_KEY` and does not put the real token in the cage.
- `agentcage run claude-code -s ANTHROPIC_API_KEY` still works.
- `agentcage auth import claude` stores the value encrypted and declares the
  right rule.
- An in-cage login survives `cage restart` and `cage update`.
- Missing-auth output lists the exact next command for each supported path.

**Estimate:** 5–8 engineer-days.
**Depends on:** A (session lifecycle for interactive login).
**Risks:** vendor token terms; OAuth callback UX; avoiding a regression in the
zero-leak model.

---

### C. First-run setup, policy presets and planning

**Problem.** The current quickstart assumes the user already understands
default-deny, domain matching, secret injection and scaffolds. The generated
configs comment out package registries, so the first real task is blocked.
There is no way to see the effective policy before deploying.

**Deliverables**

- `agentcage setup`: an interactive first-run flow that detects the host,
  backend, available agents and auth source; chooses a policy profile; offers
  to install completions; and runs a smoke test.
- `agentcage init` wizard with `--no-interactive` for scripts.
- Named policy profiles:
  - `strict`: current default-deny, agent API only.
  - `balanced`: agent API plus common package registries and code hosting,
    explicitly listed in `cage.yaml`.
  - `dev`: balanced plus common local development services, still audited.
- Service-domain presets: `anthropic`, `openai`, `github`, `node`, `python`,
  `rust`, `docker`, `debian`, `ubuntu`, `arch`.
- `agentcage domain add --preset node` writes the explicit domains (no hidden
  runtime expansion).
- `agentcage plan -c cage.yaml`: a read-only plan showing images, mounts,
  ports, required secrets, effective allowlist, passthrough, resource limits
  and security warnings.
- `agentcage cage lint`: static checks for bare TLDs, broad passthrough,
  `--as-root`, writable rootfs, `container.env` with `$VAR`, missing
  `inject_to`, unencrypted secret storage and open ports.
- `agentcage domain suggest --from-audit`: propose allowlist entries from
  blocked hosts, with counts and sample paths.
- An opt-in `agentcage run --learn` session that records blocked hosts and
  proposes a tighter allowlist afterward. It must never edit `cage.yaml`
  automatically.

**Implementation notes**

- Presets are data, embedded like scaffolds (`src/agentcage/data/presets/` or
  an equivalent); no policy logic in the CLI.
- Resolve presets at write time so the stored `cage.yaml` is the complete,
  auditable policy.
- `plan` should reuse the validation and rendering path but stop before any
  build, pull, port bind or service start.
- `lint` is a distinct, non-fatal command; `cage create` keeps its existing
  warnings for compatibility.
- The first-run chooser must have a default; `strict` is the safe default,
  `balanced` is the recommended path for a first successful agent session.

**Acceptance criteria**

- A new user can run `agentcage setup`, choose an agent and policy, and get a
  working session without editing YAML.
- `domain add --preset node` produces the same explicit entries every time.
- `plan` performs zero writes and zero network pulls.
- `lint` flags the documented risky patterns with actionable messages.
- `--learn` never changes policy without a second explicit command.

**Estimate:** 7–10 engineer-days.
**Depends on:** B (setup needs auth choices).
**Risks:** preset sprawl; making “balanced” too broad; policy drift between
preset contents and scaffold defaults.

---

### D. CLI operability and diagnostics

**Problem.** The CLI is a faithful click-compatible port, not a modern
automation surface. `-h` is deliberately absent, JSON exists only on a few
commands, and output is byte-pinned by conformance fixtures. Automation and
support are harder than they need to be.

**Deliverables**

- `-h` as an alias for `--help`; keep `--help` as the long form.
- A global output policy: `--format table|json|yaml`, `--quiet`, `--no-color`,
  `--no-banner`, and `NO_COLOR` support.
- Versioned JSON schemas for `list`, `status`, `show`, `doctor`, `verify`,
  `domain list`, `secret list`, `audit`, `har`, `watcher status` and
  `watcher findings`.
- `doctor --json`, `doctor --verbose`, `doctor --fix` for safe, user-level
  repairs (linger, podman socket, missing state directories, completions).
- `agentcage support`: a redacted tar containing doctor output, versions,
  selected config, recent audit/capture tails and unit status, with secret
  values and sensitive headers removed.
- Enriched `cage show`/`status`: network addresses, volumes, ports, domain
  names (not just counts), secret names and placeholder masking, data
  directory, recent blocked count, watcher state and update availability.
- `verify` output with the exact remediation command per failure.
- `agentcage paths` to print config, state, data, cache and runtime roots.
- `agentcage completions install` for bash/zsh/fish.
- CI detection: no spinner/banner when `CI` is set or stdout is not a TTY.
- `cage update --check` and `agentcage version --json`.

**Implementation notes**

- Separate human output from machine output. The conformance corpus should pin
  the JSON schema and exit codes; it should not pin human prose forever.
- Put JSON serializers in one module so every command has the same envelope:
  `{schema_version, command, ok, data, warnings}`.
- Never put secret values in JSON. Secret names and placeholder labels are
  allowed.
- A support bundle must be safe by default; provide `--include-capture` only
  with a warning.

**Acceptance criteria**

- Every read command has a documented JSON schema and a test that validates
  its output.
- `agentcage doctor --json` is consumable by a script without scraping.
- `agentcage support` contains no real secret value in a test fixture.
- `cage show` includes the information the CLI reference promises.
- `verify` failures name a command that can fix each one.

**Estimate:** 5–7 engineer-days.
**Depends on:** none.
**Risks:** schema churn; output conformance fixtures need a deliberate
migration path.

---

### E. Git-native workflow and session reports

**Problem.** agentcage mounts the host working tree directly. The pivot masks
protect `.git/hooks` and project `.claude`, but the agent can still modify or
delete uncommitted work, and there is no clean way to run two agents on one
repository. Comparable workflow projects solve this with branches and
worktrees.

**Deliverables**

- `agentcage run --worktree [--base REF]`: create a branch
  `agentcage/<cage-name>` and a worktree under the data directory; mount that
  worktree at `/workspace`; preserve the host checkout.
- `agentcage run --clone`: clone the project into a cage-private directory.
- `agentcage run --mountless`: no host workspace; repo cloned inside the cage.
- `agentcage cage diff NAME`: diff the worktree against its base.
- `agentcage cage apply NAME`: apply changes as staged/unstaged edits to the
  host checkout, refusing if the host checkout is dirty.
- `agentcage cage merge NAME`: merge the agent branch into the current branch.
- `agentcage cage checkout NAME`: print or check out the branch.
- `agentcage cage log NAME`: command/file history if available.
- `agentcage report NAME --format md|html|json`: session report with diff
  stat, changed files, commands, allowed/blocked hosts, grants, watcher
  findings and artifact paths.
- Scaffold metadata for unattended mode (`unattended_args`), exposed as
  `run --yolo` with a warning; recommend it together with `--worktree`.

**Proposed workflow**

```console
agentcage run claude-code --worktree --yolo
# ... agent works in agentcage/claude-bold-fox ...
agentcage cage diff claude-bold-fox
agentcage cage apply claude-bold-fox
agentcage report claude-bold-fox -o report.md
```

**Implementation notes**

- Create the worktree on the host with `git worktree add`; run Git through the
  existing `CommandRunner` seam so tests can record argv.
- Worktrees must live under a path the selected backend can mount. Use the
  state/data directory under `$HOME` first; verify VM staged-copy and Apple
  bind-mount behaviour before claiming support.
- `apply` must never overwrite a dirty host file. It should stage a patch and
  let the user review it.
- The branch and worktree are part of the cage metadata so `destroy` and
  `prune` can clean them up predictably. `--keep-worktree` preserves them for
  review after `--rm`.
- The report must use placeholder-safe capture views, never real secrets.

**Acceptance criteria**

- Two agents can run against the same repository with independent worktrees
  and no shared working-tree writes.
- `diff` and `apply` round-trip a known patch.
- `apply` refuses a dirty host checkout and says why.
- `destroy` cleans up the worktree or prints exactly what it kept.
- A session report contains no real secret value.

**Estimate:** 10–15 engineer-days.
**Depends on:** A (session lifecycle and cleanup).
**Risks:** backend mount differences; worktree path permissions on macOS and
Lima; Git edge cases (submodules, LFS, unborn HEAD).

---

### F. Policy UX, human approvals and notifications

**Problem.** The Policy API is an LLM decider with no human fallback. When the
decider is disabled, unavailable or uncertain, the agent is simply blocked.
There is no pending queue and no notification channel. Watcher findings are
only visible if the operator runs a CLI command.

**Deliverables**

- `agents.decider.mode: llm | human | hybrid`.
- A pending-approval store under the cage data directory.
- `agentcage approvals list|approve|deny` with domain, justification, context,
  requesting process metadata and expiry.
- Notification channels: desktop, generic webhook, Slack/Discord/ntfy (via
  webhook), with secret-safe payloads.
- `agentcage watch` / `cage watch`: a live stream of blocked, flagged, granted
  and watcher-finding events.
- A `403` response body and `X-Agentcage-*` headers that tell the agent what
  to do next (ask the Policy API, ask the operator, use a specific command).
- `agentcage domain test NAME HOST` and `domain explain`: show which rule
  matches, which inspector would run and why a request is blocked.
- Per-domain notes in `cage.yaml` so teams can record why an exception
  exists.

**Implementation notes**

- Human mode must fail closed and time out. A pending request should expire
  with an audit record, not linger forever.
- Approval must be authenticated on the host side; never accept an approval
  from inside the cage.
- The decider and human queue share the same validation and audit path.
- Notifications must never include request bodies or secret values, only
  host, justification and identifiers.
- `403` remediation must not leak operator-only commands to a hostile agent
  beyond what the Policy API already exposes.

**Acceptance criteria**

- In human mode, an agent request becomes a pending approval; the agent gets a
  clear retryable response; the operator can approve or deny; the result is
  audited.
- Timeout denies the request and records why.
- A watcher finding can trigger a notification without exposing secrets.
- `domain explain` answers “why is this blocked?” with the matching rule.

**Estimate:** 7–10 engineer-days.
**Depends on:** D (CLI/JSON), existing Policy API.
**Risks:** approval fatigue; notification spam; prompt-injected justification
text reaching the operator.

---

### G. Observability and live status

**Problem.** Audit and HAR are strong, but only after the fact and only through
CLI queries. There is no live dashboard, no metrics, no “what is happening
right now?” view and no easy report for a reviewer.

**Deliverables**

- `agentcage top`: a read-only TUI showing cages, service health, request
  rate, allowed/blocked counts, top hosts, active grants, watcher findings and
  recent events.
- `agentcage cage events NAME --format json`: a stream suitable for a local
  UI or CI log.
- `agentcage cage stats NAME`: CPU, memory, disk, network bytes, request
  counts and capture size.
- Optional OpenTelemetry export for audit decisions and lifecycle events
  (off by default; no body content).
- `cage har --open` / `cage report` HTML output for reviewers.
- Desktop/webhook notifications on watcher findings and blocked bursts.
- Retention controls for audit/capture (`cage audit prune --older-than`).

**Implementation notes**

- Start with a local TUI over the existing files; no daemon and no new network
  listener.
- Metrics must be opt-in and redact host/path details by default.
- The TUI is read-only in v1; destructive actions stay in explicit commands.
- HTML reports should be a single self-contained file with placeholders, so
  they are safe to attach to an issue.

**Acceptance criteria**

- `agentcage top` runs on a host with no cages and with several cages; it
  never blocks the CLI.
- `stats --format json` has a stable schema.
- `report` produces a self-contained HTML/Markdown file with no real secret
  values.
- Retention removes old files but never the active capture.

**Estimate:** 8–12 engineer-days.
**Depends on:** D (JSON contract), A (session summary).
**Risks:** terminal/TUI portability; metrics revealing sensitive hostnames.

---

### H. Integration surface: ports, files, editor, MCP and API

**Problem.** agentcage is absent from the places where agents are actually
used: editors, dev servers, CI and orchestrators. Docker Sandboxes shows how
much adoption comes from these integrations.

**Deliverables**

- `agentcage ports NAME list|publish|unpublish` for dynamic host forwarding.
- `agentcage cp SRC DST` for host↔cage file transfer, with backend support and
  clear ownership/permission semantics.
- `agentcage open NAME PORT` to open a published service in the browser.
- `agentcage ssh NAME` / `agentcage code NAME` for editor and remote-terminal
  access; key-based, cage-scoped, disabled by default.
- **MCP gateway**: `agentcage mcp add|ls|rm|load`; host-managed servers,
  OAuth/credential injection, per-tool allowlists and audit. A design spike
  must decide whether stdio servers run on the host or in a dedicated
  sidecar; the gateway must not give the cage raw host access.
- **Local API/SDK**: `agentcage serve` on a Unix socket or loopback with a
  bearer token; endpoints for create/run/exec/stream/stop/destroy; Python and
  TypeScript clients; OpenAPI schema.
- **GitHub Action**: install a pinned release, create a cage, run an agent or
  test command, upload audit/HAR, destroy with `--rm`.
- `agentcage mcp serve`: expose cage lifecycle and audit queries as MCP tools
  to host agents, so orchestrators can use agentcage as their sandbox layer.

**Implementation notes**

- Ports should use the existing inbound reverse-proxy path where available;
  VM and Apple backends may need backend-specific forwarding.
- `cp` should use backend-native copy where possible and preserve modes; do
  not copy secret mounts.
- SSH should use a dedicated key and a gateway process; never expose the host
  SSH agent or host keys. The listener must be loopback-only by default.
- MCP is a security boundary. It needs a threat model before code: host
  servers, OAuth storage, tool-level policy, prompt-injection in tool
  descriptions, and audit.
- The API is local-only by default. Remote access is out of scope for v1.
- Ship `--format json` before the API so the API is not the first stable
  contract.

**Acceptance criteria**

- A dev server started in a cage can be reached on a chosen host port and is
  listed by `ports`; unpublish closes it.
- `cp` round-trips a file without leaking secrets or changing ownership.
- VS Code/SSH access is opt-in and can be revoked by `destroy`.
- MCP gateway spike produces a design document and a working single-server
  prototype before it is merged as a feature.
- The SDK can create a cage, run a command and destroy it in an integration
  test.

**Estimate:** 15–25 engineer-days for the first slice (ports/cp/SSH), plus
15–25 for MCP/API.
**Depends on:** D, A.
**Risks:** MCP host-access model; SSH key management; API auth and lifecycle
races.

---

### I. Isolation depth: filesystem, sockets and credential transforms

**Problem.** The network story is mature; the filesystem story is not. The
only path rules are hard-coded pivot masks. SRT, ai-jail and nono already offer
general read/write denylists and tool-scoped credentials. For a security
product, that is a visible gap.

**Deliverables**

- `container.filesystem` policy:

  ```yaml
  container:
    filesystem:
      deny_read: ["~/.ssh", "**/.env"]
      deny_write: [".git", "**/secrets/**"]
      allow_write: ["/workspace", "/tmp"]
  ```

- Unix-socket policy: `container.sockets.allow` / `deny`, with default-deny
  for host sockets and explicit support for MCP/agent sockets.
- Enforcement strategy per backend:
  - Linux: Landlock for path rules where the kernel supports it; mount masks
    as a fallback.
  - macOS Apple container: mount masks and/or a Seatbelt-style wrapper where
    available.
  - VM: same policy inside the guest.
- Defaults that protect common credential paths (`.env`, `.ssh`, cloud
  config) while keeping `/workspace` writable.
- Credential transforms beyond `google-jwt-bearer`: GitHub App installation
  tokens, AWS SigV4, generic OAuth2 refresh-token exchange.
- Format-preserving placeholders (safe prefix/suffix from the real value) for
  tools that validate key shape, while keeping the decoy unguessable.
- Signed policy bundles: optional, verifiable team policy overlay.

**Implementation notes**

- Landlock is unprivileged but requires kernel support and seccomp
  compatibility. The feature must degrade with a clear warning, not silently
  drop the rule.
- Path rules are most useful inside mounts; the host directory itself is not
  accessible otherwise. Start with project-mounted paths.
- Credential transforms must keep real values outside the cage and redact
  minted tokens exactly like stored secrets.
- Format-preserving placeholders need a redaction and injection corpus before
  release; they are security-sensitive.
- This work needs a threat model update and a redteam pass.

**Acceptance criteria**

- A denied path returns a clear error inside the cage and is absent from
  `cage show` as an allowed path.
- The fallback path is explicit in `plan` and `doctor`.
- A GitHub App token can be minted and injected without the private key
  entering the cage.
- New placeholder formats survive the existing redaction corpus.

**Estimate:** 10–20 engineer-days.
**Depends on:** design spike; existing egress transform machinery.
**Risks:** kernel heterogeneity; security regressions; performance overhead
on large workspaces.

---

### J. Packaging, platform and release engineering

**Problem.** The project is pre-1.0, effectively single-maintainer, and not
available through the package managers most users rely on. There is no
notarized macOS binary and no Windows/WSL story.

**Deliverables**

- Self-update (`agentcage update [VERSION] --check`) with checksum
  verification and refusal to overwrite package-managed installs. The draft
  in #556 is the starting point.
- Homebrew tap (#414) and AUR package; generated artifacts from the existing
  scripts.
- macOS signing/notarization (#413) once the Apple Developer account is
  available.
- WSL2 support: detect WSL, install/run rootless Podman inside it, document
  the backend, and include it in `doctor` and CI.
- Nix flake and a devcontainer feature.
- Prebuilt, digest-pinned scaffold images and a documented local build path;
  shared toolchain caches where safe.
- Stable and edge release channels; `agentcage update --check` warns about
  security-relevant egress changes.
- `cage update --check` and a `doctor` warning when a deployed cage runs an
  older egress build than the host.

**Implementation notes**

- Do not let the installer silently choose a package-managed path. The
  existing self-update design already refuses Homebrew/system paths; keep it.
- Release assets should be signed and accompanied by SBOMs. Scaffold base
  images should be pinned by digest where upstream supports it; floating
  bases need an explicit `# update-from:` policy.
- CI should exercise fresh installs on Ubuntu, Arch, macOS and WSL2.
- The stable channel should favour security fixes; edge can track master.

**Acceptance criteria**

- A fresh VM on each supported platform installs from the documented method
  and passes `doctor`.
- `agentcage update --check` returns a meaningful exit code and never
  replaces a package-managed binary.
- A deployed cage warns when its egress is older than the host.
- WSL2 is a documented, tested backend path, even if native Windows remains
  unsupported.

**Estimate:** 10–15 engineer-days plus external dependencies.
**Depends on:** #413/#414; release process.
**Risks:** Apple enrollment; package-manager policy; Windows scope creep.

---

### K. Documentation, community and quality process

**Problem.** Documentation is extensive but no longer a reliable contract.
README still pins v0.50.0 and describes source builds; scaffold READMEs name a
`-s dns` service that the CLI does not accept; `cage show` overpromises. The
project also needs contributors to grow beyond a single maintainer.

**Deliverables**

- A docs conformance check (`cargo xtask check-docs`) that verifies documented
  commands/options exist and that key promises have tests.
- Fix the known drift in this PR’s follow-up: README version/build text,
  cleanup claims, auth claims, `-s dns`, `cage show` description.
- A “current behaviour” test for each scaffold promise: auth, cleanup,
  `run --help` secrets text, logs service names.
- A public roadmap (this document) with status labels: proposed, accepted,
  in progress, shipped, dropped.
- `good first issue` labels and contributor-sized workstreams; design notes
  for worktree, MCP and filesystem policy.
- A release checklist that includes docs, migration notes and package-manager
  artifacts.
- A built-in `agentcage selftest`: non-destructive probes for blocked egress,
  secret redaction, DNS rebinding and host-pivot protection, suitable for CI
  and fresh installs.

**Implementation notes**

- `check-docs` can start narrow: extract fenced `agentcage ...` commands and
  verify command/option existence; separately assert the handful of
  behavioural promises above.
- Do not make human output untestable to satisfy docs tests. Test the
  machine JSON and a small set of semantic facts.
- Use the redteam harness as the basis for `selftest`, but keep the shipped
  probes canary-only and non-destructive.
- Add a “docs changed?” checkbox to the PR template if one exists.

**Acceptance criteria**

- CI fails when a documented command or option disappears.
- The known drift items are fixed and covered by tests.
- `agentcage selftest` passes on a fresh supported host and fails when an
  egress rule is deliberately broken.
- New contributors can pick up a scoped issue without reading the full port
  history.

**Estimate:** 5–8 engineer-days plus ongoing maintenance.
**Depends on:** A–D for the behaviour tests.
**Risks:** docs tests becoming brittle; over-fitting to exact prose.

---

## 5. Phases and releases

Estimates assume one experienced Rust engineer; workstreams can run in
parallel where dependencies allow. They are planning aids, not deadlines.

| Phase | Target | Workstreams | Outcome |
| :--- | :--- | :--- | :--- |
| **0. Truth and quick wins** | v0.54 | A (lifecycle), D (CLI hygiene), K (docs fixes) | `run` tells the truth, `-h`/JSON/quiet exist, docs no longer lie. |
| **1. First run** | v0.55 | B (auth), C (setup/presets/plan) | A new user can install, authenticate and run without editing policy. |
| **2. Daily driver** | v0.56 | E (worktree/report), A (detach/attach) | Parallel agents are safe and reviewable. |
| **3. Control and visibility** | v0.57 | F (approvals/notifications), G (top/report/metrics) | Operators can see and steer a running cage. |
| **4. Integration** | v0.58 | H (ports/cp/SSH), C (config schema), early MCP spike | agentcage fits the editor/CI loop. |
| **5. Platform** | v0.59–v1.0 | H (MCP/API/SDK), I (filesystem/credentials), J (packaging/WSL2) | A credible 1.0 product with stable contracts and distribution. |

### Release gates

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

A phase is not “done” because the feature exists. It is done when:

1. the documented user path works on all supported backends;
2. there is an e2e or integration test for it;
3. the error path has a remediation message;
4. the changelog and docs are updated;
5. the security impact has been reviewed.

---

## 6. Backlog and dependencies

| ID | Deliverable | Phase | Depends on | Acceptance |
| :--- | :--- | :--- | :--- | :--- |
| A1 | `run` lifecycle flags and honest summary | 0 | — | `--rm` removes; default prints Kept; docs test. |
| A2 | `detach`/`attach`/`resume` | 2 | A1 | Reattach to a live session. |
| B1 | Scaffold auth strategies and `run` selection | 1 | A1 | OAuth-only Claude run works. |
| B2 | `agentcage auth import` / `auth list` | 1 | B1 | Encrypted import, no argv secret. |
| B3 | Cage-owned login volume | 1 | B1 | Login survives update. |
| C1 | `agentcage setup` and init wizard | 1 | B1 | First run without YAML editing. |
| C2 | Policy presets and `domain add --preset` | 1 | C1 | Explicit config output. |
| C3 | `plan` / `lint` | 1 | C1 | No writes, actionable warnings. |
| C4 | `domain suggest` / `--learn` | 2 | C2 | Proposals only, never auto-write. |
| D1 | `-h`, global format/quiet/no-color | 0 | — | All read commands JSON. |
| D2 | `doctor --json/--fix`, `support` bundle | 0 | D1 | Redacted bundle. |
| D3 | Enriched `show`/`status`, verify hints | 0 | D1 | Documented fields present. |
| E1 | `run --worktree/--clone/--mountless` | 2 | A1 | Parallel agents isolated. |
| E2 | `cage diff/apply/merge/checkout/log` | 2 | E1 | Patch round-trip; dirty guard. |
| E3 | Session report / `--yolo` mapping | 2 | E1 | Report has no secrets. |
| F1 | Human/hybrid decider and approvals | 3 | D1 | Approve/deny audited; timeout. |
| F2 | Notifications and 403 remediation | 3 | F1 | Safe payloads. |
| F3 | `domain test/explain` | 3 | D1 | Rule match explained. |
| G1 | `agentcage top` and events/stats | 3 | D1 | Read-only, stable JSON. |
| G2 | Report HTML and retention | 3 | G1 | Self-contained, redacted. |
| H1 | Ports/cp/SSH/editor | 4 | A1, D1 | Port forwarding and `cp` round-trip. |
| H2 | MCP gateway spike | 4 | security design | Design doc + one-server prototype. |
| H3 | Local API/SDK and GitHub Action | 5 | D1 | SDK integration test. |
| I1 | Filesystem/socket policy | 5 | threat model | Deny works; fallback clear. |
| I2 | Credential transforms/placeholders | 5 | I1 design | GitHub App/AWS/OAuth cases. |
| J1 | Self-update and package managers | 0/5 | #413/#414 | Fresh-VM install pass. |
| J2 | WSL2 support | 5 | J1 | Doctor + docs + CI. |
| K1 | Docs conformance and drift fixes | 0 | — | CI fails on doc drift. |
| K2 | `agentcage selftest` | 4/5 | redteam | Probes pass/fail correctly. |

---

## 7. Compatibility and migration

- **Additive first.** New flags, commands, config keys and JSON output are
  introduced before any existing behaviour changes.
- **`run` default.** Keep the audit-preserving default (`--keep`) and add
  `--rm`; do not silently destroy volumes or secrets that users may rely on.
  The documentation must be corrected in the same release.
- **Aliases.** Keep existing top-level aliases. Deprecate a command with a
  warning for at least one minor release before removing it; the draft
  self-update change that removes the `update` alias should be revisited.
- **Config.** New keys are optional and default to current behaviour. Warnings
  are added before errors. A config written by v0.53 must continue to load.
- **State.** Existing deployments must survive an upgrade in place; run the
  state-compat fixture on every change. No migration step should be required
  for the work in phases 0–2.
- **JSON.** Add `schema_version` to every machine output. Human text may
  change; JSON fields follow the deprecation policy.
- **Security.** No new default that widens network, filesystem or credential
  access. `plan` and `doctor` must show when a non-default profile is active.

---

## 8. Decisions needed

These are the choices that should be settled before implementation, not
discovered during review:

1. **`run` default lifecycle:** keep-and-audit (recommended) vs destroy-on-exit.
2. **Interactive auth trade-off:** allow in-cage `/login` state in a
   cage-owned volume, or require host-minted tokens only.
3. **Worktree default:** opt-in (recommended for compatibility) vs default for
   `run`.
4. **Approval transport:** host-only queue vs egress-side pending queue;
   recommendation is host-side storage with the egress exposing a retryable
   pending response.
5. **MCP gateway location:** host broker vs egress sidecar. Security review is
   required before code.
6. **Windows scope:** WSL2-first is recommended; native Windows is a separate
   project.
7. **v1.0 scope:** worktree, auth, packages and docs conformance are hard
   requirements; MCP/API/SDK may ship after 1.0 behind stable interfaces.

---

## 9. Risks and mitigations

| Risk | Mitigation |
| :--- | :--- |
| Maintainer bandwidth | Slice work into independent PRs; publish the roadmap; label contributor-sized issues; avoid simultaneous large rewrites. |
| Security regression in new features | Threat-model worktree, approvals, MCP and filesystem policy; run redteam/self-test in CI; default off for risky features. |
| Docs and behaviour drift | `check-docs` plus semantic behaviour tests; update docs in the same PR. |
| Output compatibility | Versioned JSON contract; keep human output non-normative. |
| Backend divergence | Add backend-specific e2e cases for worktree, ports, `cp`, filesystem policy and auth volumes. |
| Package-manager constraints | Follow each ecosystem’s upgrade policy; self-update refuses managed installs. |
| Approval fatigue | Include context and risk, batch notifications, set short expiry; human mode is opt-in. |
| MCP host access | Start with a host-managed gateway and tool allowlists; never give the cage a raw host socket. |
| Scope creep | The non-goals list is part of the plan; new proposals must name the security or usability gap they close. |

---

## 10. First 30 days

The first milestone should be deliberately small and shippable:

1. **Fix the truth:** update README, quickstart, CLI reference and scaffold
   READMEs for `run` lifecycle, auth, `-s dns` and README version/build text;
   add a docs conformance test for the four promises.
2. **Add the quick wins:** `-h`, `run --rm`, `run --dry-run`,
   `prune --dry-run`, `--json` for read commands, `doctor --json`, `support`.
3. **Design auth:** write the scaffold `auth:` schema and the `agentcage auth`
   flow; implement the OAuth-token path for claude-code first.
4. **Design the wizard:** choose the profile/domain-preset data model and the
   `plan`/`lint` output; do not build a broad UI before the data is stable.
5. **Write design notes:** worktree lifecycle, human approvals and MCP
   gateway, each with a threat model and acceptance tests.

That is enough to make the product feel different without touching the
security engine.

---

## Appendix: patterns to borrow, and not borrow

### Borrow

- Docker: first-run presets, `--rm`, `cp`, ports, SSH, `diagnose --format`,
  secret import from a host command, MCP gateway, kits.
- SRT: filesystem/socket policy, ask callback, per-command allowlists,
  actionable denial reasons.
- Container Use: branch per agent, diff/apply/merge/checkout, watch.
- Microsandbox: SDKs, snapshots, detached sessions, MCP.
- nono: profiles, tool-scoped credentials, signed policy/skills, audit
  integrity, rollback.
- ai-jail: toolchain caches, private home, worktree, dry-run, status line.
- Kubernetes agent-sandbox / OpenSandbox: templates, warm pools, declarative
  lifecycle, SDK/API.

### Do not borrow

- Cloud regions, GPU pools, browser desktops and general-purpose orchestration.
  Those are different products; integrate with them instead.
- “Open by default” network profiles. Widening must always be explicit.
- A large pile of config knobs without safe defaults and tests.
- Vendor-specific agent logic in the CLI core. Keep agents as data.

---

## Appendix: success metrics

| Metric | Target |
| :--- | :--- |
| Install → first successful agent prompt | < 3 minutes on a supported host. |
| Supported auth paths that work on first try | 100% (API key, OAuth, host import, in-cage login where offered). |
| Documented behaviours with a conformance test | 100% of the promises in this plan’s phase 0–2. |
| Blocked requests with a remediation hint | > 90% of domain/secret/body-size blocks. |
| Stopped `run` cages older than 7 days | 0 unless explicitly kept. |
| Fresh-install pass rate | Linux, macOS, WSL2 in CI. |
| Time from release to package-manager availability | < 1 week for stable releases. |
| Secret values in logs, argv, JSON or support bundles | 0 by test. |
| Parallel-agent adoption | Worktree used for a meaningful share of `run` sessions once shipped. |
