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

## Protocol relays / SMTP

### S1. Run inspector chain in a thread executor

**What.** Wrap `_run_inspectors` in `loop.run_in_executor(None, ...)` so the
asyncio loop stays responsive while body inspection runs.

**Why.** Today the inspector chain runs synchronously on the event loop. For
a 5MB DATA payload going through 19 secret patterns + entropy + content-type
checks, that's an estimated 50-300ms of CPU work. While it runs, every other
client session, the IMAP relay, and any HTTP requests through mitmproxy
all wait. Same gap exists for HTTP inspectors today.

**Pros.** Loop stays responsive under multi-cage load. Latency on unrelated
HTTP traffic stops correlating with email sends.

**Cons.** Inspectors must be thread-safe (mostly are; verify). Adds a
thread-pool dep on the inspector chain. Doubles the testable surface
(sync + async paths).

**Context.** Surfaced by /plan-eng-review on PR #86 (C1). Decision was
defer because v1 load profile is single-cage occasional email. Revisit
when measured contention shows up. The fix should cover BOTH the SMTP
relay's `_run_inspectors` AND the HTTP inspector chain in `addon.py` —
they have the same concurrency shape.

**Where to start.** `src/agentcage/data/proxy/relays/smtp.py:_run_inspectors`
+ `src/agentcage/data/proxy/addon.py:request` + `addon.py:websocket_message`.
Make a shared helper that wraps the chain in an executor.

**Depends on.** Nothing. Self-contained refactor.

### S2. Audit log accuracy when upstream rejects RCPTs

**What.** Make `_UpstreamSmtp.deliver` return `(upstream_status, accepted,
rejected)` instead of just status. Audit `smtp_data` allowed entry records
the accepted set + a separate `recipients_rejected_upstream` field.

**Why.** Today the cage sends 5 RCPTs, all pass our recipient_allowlist,
upstream rejects 2 of them. We forward to the 3 accepted ones. The audit
log entry records `recipients: [all 5]` and `decision: allowed`. Forensics
can't tell who actually got the message.

**Pros.** Audit log becomes truthful. Forensic queries answer "did jacque
actually email Bob?" correctly.

**Cons.** Minor breaking change to the audit JSON shape (downstream
consumers add a field). About 30 LOC + a test using the fake upstream's
`reject_rcpts` set.

**Context.** Surfaced by /plan-eng-review on PR #86 (C3). Decision was
defer because audit accuracy matters less than security gaps.

**Where to start.** `src/agentcage/data/proxy/relays/smtp.py:_UpstreamSmtp.deliver`
+ the call site at `_smtp_session`. Test with the existing
`FakeSmtpRecorder.reject_rcpts` mechanism.

**Depends on.** Nothing.

### S3. AUTH PLAIN without inline base64 (RFC 4954 continuation form)

**What.** Handle `AUTH PLAIN\r\n` (no inline token) by sending `334\r\n`
continuation, reading the base64 line, then forging `235`. Mirrors the
existing AUTH LOGIN handling.

**Why.** RFC 4954 lets clients send the auth token either inline
(`AUTH PLAIN <base64>`) or via continuation (`AUTH PLAIN\r\n` then `334`
then `<base64>`). Today we only handle the inline form. A spec-strict
client that uses continuation gets `502 not implemented` from the relay.

**Pros.** Correctness against RFC. Wider client compatibility.

**Cons.** ~10 LOC + a test. Almost no clients use the continuation form
in practice — `python-smtplib`, mailx, himalaya, etc. all send inline.

**Context.** Surfaced by /plan-eng-review on PR #86 (C2 follow-up).
Defer because it's not currently breaking any real client.

**Where to start.** `src/agentcage/data/proxy/relays/smtp.py:_smtp_session`
in the AUTH branch around the `arg.upper().startswith("LOGIN")` check.

**Depends on.** Nothing.
