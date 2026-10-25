# FEAT-003: Guided first-run setup

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P0 |
| **Phase** | 1 |
| **Depends on** | [FEAT-002](FEAT-002-auth-strategies.md) |
| **Related** | [FEAT-004](FEAT-004-policy-presets-and-suggestions.md), [FEAT-007](FEAT-007-diagnostics-and-support.md) |

## Problem

The first-run path assumes the user already understands backends, scaffolds,
default-deny domains, secret injection and `cage.yaml`. There is no interactive
setup, no backend recommendation, no auth discovery and no smoke test. A new
user often learns the model by hitting a 403.

## Proposal

Add `agentcage setup`, an interactive flow with a non-interactive mode:

```console
$ agentcage setup
Checking host...
  ✓ rootless Podman 6.1.4
  ✓ systemd linger
  ✓ systemd-creds (user)
  ✓ 147 GB free

Backend: container (recommended)
Agent: claude-code
Auth: OAuth token found in environment (use it, import it, or log in later)
Policy: balanced (recommended for first run) / strict / custom
Project: /home/me/project
Workspace: direct / worktree (recommended for parallel work)

Ready:
  cage.yaml at /home/me/project/cage.yaml
  policy: balanced (12 domains)
  auth: CLAUDE_CODE_OAUTH_TOKEN
Run now? [Y/n]
```

`agentcage setup --no-interactive --agent claude-code --policy strict
--auth env` is the scripted form.

### Responsibilities

- Run the same checks as `doctor`, but present them as decisions, not a wall
  of output.
- Detect installed agents and host auth sources; do not copy credentials
  without consent.
- Choose a backend from the host probe.
- Write a `cage.yaml` with explicit domains from a preset.
- Offer shell completions and a first `agentcage run` (or `cage create`).
- Print the exact next commands and where the config was written.
- Never install host packages without an explicit `--fix`/confirmation; link
  to the install guide instead.

## Implementation

- New `cli/setup.rs` with a small prompt abstraction that tests can fake.
- Reuse `doctor` host probes and `doctor --fix` for safe user-level repairs.
- Reuse the init renderer; setup is a guided front end, not a second config
  generator.
- On non-TTY stdin, `setup` must fail with a clear `--no-interactive` hint
  rather than hang.
- Write the config atomically; do not leave a half-written file on Ctrl-C.

## Acceptance criteria

- [ ] A fresh supported host can complete setup and run an agent without
      editing YAML.
- [ ] `--no-interactive` works in CI and never prompts.
- [ ] The selected policy and auth method are visible in the generated
      `cage.yaml`.
- [ ] Ctrl-C leaves no partial config or cage.
- [ ] `doctor` and `setup` share the same host checks.

## Tests

- Golden transcript tests with a fake host (no root/Podman required).
- Non-TTY test: no hang, clear error.
- e2e: setup with strict profile on the container backend, then run a trivial
  command.

## Risks

- Interactive prompts are hard to test; keep parsing and rendering separate.
- Auto-detection can be wrong; always show the choice and allow override.
