# TODOS

Deferred work that's been explicitly considered and punted, with context
so future readers know why. Each entry names the trigger (PR / incident /
plan), the motivation, and where to start.

## Phase 8 / openclaw regression canary

### T1. HAR-capture openclaw's organic outbound to verify placeholder usage end-to-end

**What.** Add an assertion to `tests/e2e/phase8_openclaw.sh` that captures
an outbound request openclaw organically makes (not one we triggered with
`curl`), then grep the HAR entry for the placeholder appearing in its
`Authorization` header.

**Why.** Phase 8's 8.8a/b/c close the proxy side of secret injection:

- 8.8a proves the cage's environment contains the literal placeholder.
- 8.8b proves the proxy substitutes when the placeholder is sent to an
  injected domain.
- 8.8c proves substitution is domain-scoped.

What they do NOT prove: that openclaw's own client code actually routes
secrets through the placeholder path. If a future openclaw build reads
`ANTHROPIC_API_KEY` from env and does its own substitution (or, worse,
expects the real key in env), every current assertion still passes while
the injection silently no-ops in production.

**Pros.** Closes the proxy-vs-openclaw gap. Catches a whole class of
regression that our current tests cannot see.

**Cons.** Requires investigating whether openclaw issues any outbound
request on boot without a user prompt. If it doesn't, the assertion is
untestable as a pure "boot and check" — we'd need to script a minimal
openclaw action that forces a hit on an injected domain, which involves
scripting the gateway's approval flow.

**Context.** Phase 8 landed in PR e2e/phase8-openclaw-canary. The plan
reviewer flagged this as the one real gap in the phase's coverage;
user chose to defer to TODO rather than expand scope in the landing PR.

**Where to start.**

1. Enable `capture.enable_har: true` in the test cage's `cage.yaml`
   (sed it into place during phase 8 setup, same way memory/cpus are
   already patched).
2. Boot the cage and observe what, if anything, openclaw sends outbound
   with no user interaction (`agentcage cage har e2e-openclaw` after
   `wait_ready`).
3. If organic outbound exists: add assertion 8.11 that greps the HAR
   for `{{ANTHROPIC_API_KEY}}` in an outbound request's body/headers.
4. If no organic outbound: investigate whether openclaw has a
   non-interactive CLI flag (`openclaw ping`, `--self-test`, etc.)
   that issues one.

**Depends on.** Phase 8 (this TODO is a follow-up to the initial
canary landing).
