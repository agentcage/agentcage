# Phase 8 — OpenClaw Scaffold Regression Canary

Companion doc to `phase8_openclaw.sh`. Reading this should tell you
exactly what the phase proves, what it **doesn't** prove, and which
failure modes could slip through silently.

## What the phase verifies, assertion by assertion

Columns: **Asserts** = the fact the test proves. **Gap** = what the
test shape *cannot* catch.

### Setup (8.0)

| Step | Asserts | Gap |
|---|---|---|
| Log base image digest | `ghcr.io/openclaw/openclaw:latest` is present locally before cage build — failure triage knows which upstream sha ran | Doesn't record the digest on PASS runs (only visible in log) |
| `agentcage init --scaffold openclaw --port P` | Scaffold renderer produces a valid `cage.yaml` | Doesn't diff against a known-good rendering — a template change that silently drops a field is invisible |
| `sed`/`python3` patches to cage.yaml | CI-only resource trim (memory 4g, cpus 2.0, timeout 300s) + test-shape tweaks (`inject_to: httpbin.org`, add `httpbin.org`/`postman-echo.com` to allowlist) | Patches are idempotent; a template change that reshapes the inject block could leave the sed no-op'd and the phase would still "pass" setup |
| `agentcage cage create -s K=V ...` | Scaffold Containerfile builds; quadlets install; container starts under user systemd | Doesn't distinguish "build passed but slow" from "build crashed and systemd swallowed stderr" — a dump_cage_diagnostics is issued on wait_ready failure but not on create failure |
| `wait_ready BASE 300s` | Host-side port :19180 returns HTTP 200 at least once | 200 could come from the reverse proxy's error page if openclaw never bound internally — `wait_ready` polls `/` with no body check |

### Assertions

| # | What it asserts | What it does NOT assert |
|---|---|---|
| **8.1** Gateway serves OpenClaw Control UI | GET `/` contains the literal string `OpenClaw Control` in the response body — rules out reverse-proxy error pages and other servers on the port | Doesn't load the JS bundle, doesn't follow any API route, doesn't test authenticated paths. If openclaw ships a redesign that renames the app title, 8.1 false-fails. If openclaw ships a UI that loads but the backend is broken, 8.1 false-passes. |
| **8.2** `openclaw health` via exec_alias | Exec_aliases config wires `openclaw` → `node openclaw.mjs`; the CLI runs inside the cage; at least one agent is configured (`Agents:` appears in output) | "Agents:" is a loose match — the health command could fail its internal checks and still print the agent list. Doesn't verify heartbeat, session store, or any downstream dependency. |
| **8.3** tini is PID 1 | Scaffold's `ENTRYPOINT ["tini", "--"]` was applied and the container started under tini (`/proc/1/comm == tini`) | Doesn't prove tini is correctly forwarding signals — only that it's present. If tini were compiled with bad defaults (e.g., ignoring SIGUSR1), this passes. That's what 8.4 is for. |
| **8.4** Self-restart survives SIGUSR1 | SIGUSR1 sent to `openclaw-gateway` causes: (a) the gateway to exit, (b) the supervisor's `node openclaw.mjs gateway` command to end, (c) the `while true; do ... done` loop in `entrypoint.sh` to respawn with a new PID, (d) the container stays alive through the cycle, (e) the gateway responds 200 again within 60s | Only tests ONE restart cycle. Won't catch file-descriptor leaks, growing memory, or zombie-process accumulation across many restarts. The 30s poll after the signal is optimistic — on a saturated CI runner a slow restart could time out and false-fail. Doesn't verify state preservation across the restart (e.g. devices still paired). |
| **8.5** `openclaw.json` has SSRF opt-out | Entrypoint wrote the config file with `.browser.ssrfPolicy.dangerouslyAllowPrivateNetwork == true` (jq-parsed, so key renames fail loudly) | Only verifies the config FILE, not the RUNTIME. If openclaw ≥ a future version renames `ssrfPolicy` → `ssrf` or ignores the key, 8.5 passes while the browser tool is still broken. Doesn't launch an actual browser. |
| **8.6** `controlUi.allowedOrigins` includes gateway URL | Entrypoint templated the port correctly into both `http://localhost:$PORT` and `http://127.0.0.1:$PORT` | Doesn't prove device pairing actually succeeds with those origins. If the allowedOrigins key is renamed upstream, 8.6 fails loudly — which is the correct behaviour. |
| **8.7** Matrix extension workspace workaround | `/app/node_modules/openclaw` is a symlink AND its target `package.json` is resolvable — proves the Containerfile layer that creates the symlink ran | Doesn't verify matrix-js-sdk actually loads at runtime, or that `import`s from the matrix extension resolve. A regression that breaks extension loading for a different reason (e.g. peer-dep mismatch) wouldn't be caught here. |
| **8.8a** Cage env has literal placeholder | `ANTHROPIC_API_KEY` in the cage environment equals the literal string `{{ANTHROPIC_API_KEY}}` — proves secret_injection's placeholder substitution is wired and the real key does not leak into the cage | The placeholder format is hardcoded in the test. If agentcage ever changes placeholder syntax (e.g. `${X}`), the test silently passes the wrong thing while the injection contract has moved. |
| **8.8b** Proxy logs `secrets_injected` on injected domain | Audit log records `secrets_injected: [ANTHROPIC_API_KEY]` for the flow to `httpbin.org` (in `inject_to`) — proves inject rules fire on matched domains | Follows phase 3's audit-log pattern: only proves the proxy ATTEMPTED injection, not that the real value landed on the wire. A bug where the audit log fires but the mutation doesn't persist is NOT caught here. The trigger is a `curl` from inside the cage, not openclaw's own outbound — see T1 in TODOS.md. |
| **8.8c** Substitution is domain-scoped | Audit log does NOT record `secrets_injected` for the flow to `postman-echo.com` (allowlisted but NOT in `inject_to`) — proves the `inject_to` list is honored | Absence proof via polling is weaker than presence — a race that misses the log entry would false-pass. Doesn't test path-scoped or method-scoped injection (not features today, but future-proofing is absent). |
| **8.9** Domain allowlist blocks unlisted host | `curl https://forbidden.example.com` through the proxy returns 403 or 502 | Doesn't test subdomain-matching edge cases (e.g. `evil.httpbin.org` when only `httpbin.org` is allowed); doesn't assert a proper audit entry for the block event. |
| **8.10** Nested rootless podman smoke | `podman run --rm busybox echo ok` works inside the cage — proves the scaffold's subuid/subgid/`fuse-overlayfs`/`slirp4netns`/storage.conf layer is functional *when the environment supports it*. Probes `podman ps` first and `e2e_skip`s if unavailable (GHA ubuntu-24.04 uncertainty) | `busybox echo` is the smallest possible nested workload. Doesn't test CNI networking inside, doesn't test volume mounts, doesn't test running a real agent inside. The skip path could mask a regression on CI permanently — if GHA never runs 8.10, we won't notice the day scaffolds/openclaw/Containerfile drops `fuse-overlayfs`. |

## Meta-gaps: things phase 8 does not cover at all

These aren't per-assertion weaknesses — they're whole classes of
regression that this phase is blind to.

1. **Authenticated gateway use.** 8.1 tests the UI loads unauth. 8.2
   tests the internal CLI. Nothing proves the `OPENCLAW_GATEWAY_PASSWORD`
   actually authenticates an API request. If openclaw switched to
   token-only auth and ignored the password secret, all 12 assertions
   still pass.

2. **Openclaw's own outbound requests.** Captured as TODO T1. The
   current 8.8a/b/c prove the proxy side end-to-end but trigger the
   flows with `curl` inside the cage. Openclaw's own client code is
   never exercised.

3. **Anthropic API shape compatibility.** If openclaw bumps its
   Anthropic SDK and the SDK changes header/URL conventions, none of
   the phase 8 assertions fire. We're testing the scaffold wrapper,
   not the agent's business logic.

4. **Chromium / Playwright browser tool.** 8.5 tests that the SSRF
   *config* permits the browser. 8.10 runs busybox, not Chromium. If
   openclaw's browser tool breaks (new Chromium version incompatible
   with the Playwright the image ships, missing libs), no assertion
   fires.

5. **mitmproxy CA chain / TLS trust.** The entrypoint installs the
   mitm CA into `/usr/local/share/ca-certificates` and the NSS DB at
   `/home/node/.pki`. If a future openclaw image pre-installs a
   hardened CA store that rejects our cert, HTTPS through the proxy
   breaks silently. 8.8b/c drive HTTPS curls, so a TLS break would
   actually fail them — but the failure mode (curl error) looks the
   same as an upstream outage, which makes triage ambiguous.

6. **State persistence across restart.** 8.4 verifies restart
   mechanically works. It does NOT verify that `/home/node/.openclaw`
   state (approved devices, session store, agent config) survives.

7. **Memory / file-descriptor leaks under sustained load.**
   Out-of-scope for a smoke test.

8. **Non-default scaffold options.** Scaffold supports VM isolation,
   custom ports, HAR capture (`capture.enable_har`), additional
   providers (Brave, Firecrawl, OpenAI, OpenRouter). Phase 8 covers
   only the default config path. A regression specific to a non-default
   branch is invisible.

9. **Other `openclaw` subcommands.** Scaffold help lists `openclaw
   status`, `openclaw devices list/approve`. Only `openclaw health`
   is exercised.

10. **Reverse-proxy header plumbing (commit a795100).** 8.6 covers
    the `controlUi.allowedOrigins` half. The matching `X-Forwarded-For`
    / `Host` / `Origin` rewriting in the agentcage proxy isn't asserted
    — device pairing could still fail even with 8.6 passing.

11. **Cage stop/start cycle from the host.** SIGUSR1 is an *internal*
    restart. `agentcage cage stop` + `cage start` exercises the
    systemd/quadlet lifecycle instead and isn't covered by phase 8.

12. **Scaffold build reproducibility.** We build once. Layer caching
    bugs that only surface on a second build with a stale cache aren't
    caught.

13. **Read-only root filesystem edge case.** `entrypoint.sh` has a
    fallback path for when `/home/node/.pki` isn't writable (emits a
    warning instead of exiting under `set -e`). Phase 8 uses the
    standard scaffold which mounts a `.pki` tmpfs, so the warning path
    is never exercised. A regression that breaks the fallback only
    surfaces for users with custom cage.yaml.

## Assumptions that could break silently

Things phase 8's logic *assumes* about the environment — if any of
these stop holding, assertions could pass for the wrong reason.

- **setproctitle renames survive.** 8.4 relies on `pgrep -f '^openclaw$'`
  matching exactly the supervisor's cmdline. If openclaw stops renaming
  argv[0] and instead runs as `node openclaw.mjs gateway`, the pgrep
  returns empty and 8.4 bails with "could not find openclaw supervisor"
  — which is a *correct* failure, but the test's error message will
  mislead.
- **httpbin.org and postman-echo.com are reachable.** External echo
  services are transient dependencies. Outages cause false-fails on
  8.8b/c (the `--retry 3` on curl mitigates briefly). The audit-log
  signal still works even if the echo body is garbled, but a complete
  service outage blocks the proxy logs from ever being written for
  that flow.
- **openclaw writes `/home/node/.openclaw/openclaw.json` once at
  first boot.** 8.5/8.6 read the file the entrypoint produces. If
  openclaw starts managing its own config (deletes + rewrites on each
  boot), the entrypoint's initial write could be overwritten and 8.5/8.6
  would fail — which is likely the correct behaviour, but the debug
  story would be "why does the file not match what the entrypoint
  wrote?" rather than "openclaw has a new config system."
- **`agentcage cage audit` shows the last N entries across all
  flows.** 8.8b/c poll the audit output for specific flow attributes.
  If the audit format changes (JSON key renames, line batching), the
  greps break. jq-parsing the audit would be more resilient — tracked
  informally as a future hardening.

## How to strengthen phase 8 without expanding scope

These are cheap local tightenings that would close some gaps without
adding new test cases:

- **8.1**: add a second assertion that GET `/favicon.svg` returns
  `image/svg+xml` — proves more than just HTML text matching.
- **8.4**: also assert `systemctl --user show -p NRestarts --value
  e2e-openclaw-cage.service == 0` to prove systemd never saw the
  container die (strongest witness that tini kept PID 1 alive).
- **8.5/8.6**: assert the same keys via a live probe against the
  browser tool / a device-pairing request, not just file contents.
  (Higher effort — likely T2.)
- **8.8a**: read the placeholder syntax from the rendered cage.yaml
  rather than hardcoding — protects against a placeholder format change.
- **8.10**: when the probe succeeds, record the nested container's
  podman info in the log — so we can tell if the skip path is firing
  on CI when it shouldn't.

## Related tests

- Phase 1-6: cage lifecycle, secrets, domains, hardening
  — all use the basic `node:22-slim` agent, so none exercise openclaw.
- Phase 7: VM mode — openclaw isn't tested in VM mode anywhere.
- `tests/conftest.py::openclaw_yaml`: pytest fixture for config-
  parsing unit tests. Renders a bare `ghcr.io/openclaw/openclaw:latest`
  directly, bypassing the scaffold Containerfile. Catches YAML-schema
  regressions but not scaffold build regressions.

## TODOs this phase surfaced

- **T1** (tracked in `TODOS.md`): HAR-capture openclaw's organic
  outbound to prove the scaffold ACTUALLY uses the placeholder in
  its own traffic, not just that our test curl does. Addresses the
  biggest remaining gap.
