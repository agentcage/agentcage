<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Troubleshoot

Diagnose and fix a misbehaving cage. Replace `myapp` with your cage name. Most recipes lean on `cage verify`, `cage logs`, and `cage audit`.

## The cage won't start

Run health checks first — `cage verify` calls out missing containers, broken cert volumes, and unset proxy env vars in one pass.

```bash
agentcage cage verify myapp
```

If verify reports the egress down or restarting, pull its logs:

```bash
agentcage cage logs myapp -s egress -n 200
```

Common failure shapes:

- **`iptables: Permission denied`** — the egress is missing capabilities its supervisor needs. Reinstall with `agentcage cage update myapp` against the current agentcage release.
- **Stuck on `wait for ca cert`** — the mitmproxy CA volume is empty. Destroy and recreate the cage.
- **Cage container exits immediately on `apple-container`** — the image's CMD ran to completion. Set `container.command:` in `cage.yaml` to a long-running process, or use a scaffold that does.
- **`cage … was created with v0.21…`** — the cage carries the legacy 3-service shape. Destroy and recreate it. `cage destroy` and `cage list` still work without the upgrade.

## Outbound requests are being blocked

Start at the audit log — every block carries a reason and the inspector that decided it.

```bash
agentcage cage audit myapp --decision blocked --since 1h
```

Three patterns cover most cases:

- **`domain not in allowlist`** — `agentcage domain add myapp example.com`. Subdomains match automatically; the change hot-reloads.
- **`port not in ports.tcp.allow`** — the cage tried a port outside the inspected set (default `[80, 443]`). Add the port to `ports.tcp.allow` or `ports.tcp.passthrough` in `cage.yaml`, then `cage update myapp`.
- **Reason from the `secrets` inspector** — a real secret value or pattern (e.g. `sk-ant-…`) appeared on the wire. On HTTP egress the secrets inspector defaults to `flag` (logged, not blocked), so this shows up as a *blocked* decision only when you've set `secrets: { action: block }`, or on an SMTP relay (which blocks by default). See the next section.

For a single host you suspect is wrong:

```bash
agentcage cage audit myapp --host api.example.com --since 24h
```

## Secrets aren't reaching the cage

List, then set or rotate:

```bash
agentcage secret list myapp
agentcage secret set myapp ANTHROPIC_API_KEY
```

`secret set` prompts for the value (or reads stdin). The running cage hot-reloads.

If a secret is set but the cage still sees the placeholder upstream, two paths can look alike. `secret_injection` rules keep the real value in the proxy; bare `container.podman_secrets` entries inject the real value as an env variable. Mixing the two for the same key is a common cause of confusion. See [Secret injection](../reference/secret-injection.md).

Editing the proxy-side behavior of a `secret_injection` rule (transforms, `inject_to`, `allow_to_domains`) hot-reloads — no cage restart needed. Adding a brand-new rule that introduces a new env name in the cage workload still needs `cage update`. See [Hot-reload semantics](../explain/architecture.md#hot-reload-semantics).

## A request is blocked when it shouldn't be

Find the audit entry and match the `inspector` field to the fix:

```bash
agentcage cage audit myapp --decision blocked --host api.example.com --since 1h
```

- **`domain`** — destination not on the allowlist. `domain add` it.
- **`secrets`** — a known secret pattern matched (only blocks when `secrets.action` is `block` — the HTTP default is `flag` — or on an SMTP relay). Add the destination to that secret's `allow_to_domains` in `cage.yaml`, or move the secret to `secret_injection` with `inject_to: ["api.example.com"]` if you actively want it injected for this host.
- **`body-size`** — body exceeded `max_request_body` (default 10 MB). Raise the cap in `cage.yaml`.
- **`entropy` / `content-type`** — the body tripped an exfiltration heuristic. Tune the inspector or scope it to specific content types. See [Inspectors](../reference/inspectors.md).

After editing `cage.yaml`, `cage edit` picks the lightest-touch reload. For raw `domains` changes, prefer `domain add` / `domain rm` — they hot-reload without touching the proxy.

## The proxy keeps restarting

The egress uses `Restart=on-failure`. Catch the failure window with `agentcage cage logs myapp -s egress -f`, then match the cause:

- **Bad CA trust on first boot** — the cage workload polls for the CA cert and times out. Wait 30 seconds; if the loop persists, destroy and recreate.
- **Port conflict on the host** — a published port became busy after `cage create`. Pick a new host port in `cage.yaml` and `cage update myapp`.
- **Custom inspector raising at import** — a syntax error crashes the proxy on every restart. Fix the file and `cage restart myapp`.

## Reading audit logs

Stream live, aggregate, or filter:

```bash
agentcage cage audit myapp -f
agentcage cage audit myapp --since 24h --summary
agentcage cage audit myapp --decision blocked --inspector secrets --since 7d
```

Full filter set in [CLI — cage audit](../reference/cli.md#cage-audit).

## Backend-specific quirks

Full list in [Isolation modes](../explain/isolation-modes.md#known-limitations).

- **apple-container — most `cage.yaml` edits need `cage update`.** `domain add` / `domain rm` are the exception (they hot-reload). Command, env, ports, and secret-injection changes need an explicit `cage update`.
- **apple-container — `apt-get update` prints HTTP→HTTPS warnings.** Cosmetic; exit code is 0 and the fetches succeed via mitmproxy's TLS interception.
- **vm — first cold start takes 15-30s.** Lima boots a guest kernel before any container starts. Subsequent starts are sub-second.
- **container — file permission errors in `/workspace`.** Scaffolds that set `userns: keep-id` map your host UID into the container. Confirm the mounted directory is owned by your user.

## Getting help

Open an issue at <https://github.com/agentcage/agentcage/issues> with `cage verify` output, the last 100 lines of `cage logs`, `uname -a`, `agentcage --version`, and a minimal `cage.yaml` that reproduces the issue (redact sensitive hostnames and secrets).

Security vulnerabilities go to **security@agentcage.ai**, not the public tracker. See [Security model](../explain/security-model.md#reporting-security-issues).

## Related

- [CLI](../reference/cli.md) — every flag mentioned here
- [Inspectors](../reference/inspectors.md) — what each inspector blocks and how to tune it
- [Isolation modes](../explain/isolation-modes.md) — full backend quirk list
- [Back up and restore](back-up-and-restore.md) — when things are unrecoverable
- [Upgrade agentcage](upgrade-agentcage.md) — version-bump troubleshooting
