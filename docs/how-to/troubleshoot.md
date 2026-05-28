<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Troubleshoot

Diagnose and fix a misbehaving cage. Read this when a cage refuses to start, requests are blocked unexpectedly, or you need to triage what the proxy is doing.

Replace `myapp` with your cage name. Most recipes here lean on `cage verify`, `cage logs`, and `cage audit` — three commands that answer most questions before you have to read systemd journals by hand.

## The cage won't start

Run health checks first — `cage verify` calls out missing containers, broken cert volumes, and unset proxy env vars in one pass.

```bash
agentcage cage verify myapp
```

If verify reports the egress service down or restarting, pull its logs:

```bash
agentcage cage logs myapp -s egress -n 200
```

Common failure shapes:

- **Egress exited with `iptables: Permission denied`** — the rootless Podman setup is missing required capabilities (SETUID/SETGID/SETPCAP/KILL). Reinstall the cage with `cage update myapp` against a current agentcage; the templates were tightened in 0.22.0.
- **Egress stuck on `wait for ca cert`** — the mitmproxy CA volume is empty. Destroy and recreate the cage; the shared volume is repopulated on first run.
- **Cage container exits immediately on `apple-container`** — the image's CMD ran to completion. Set `container.command:` in `cage.yaml` to a long-running process, or use a scaffold that does.
- **`cage … was created with v0.21…` from any command** — the cage carries legacy `-proxy` / `-dns` containers. Destroy and recreate it. `cage destroy` and `cage list` still work without the upgrade.

If you cannot tell which container died, list everything for the cage:

```bash
agentcage cage list
agentcage cage logs myapp -n 500
```

## Outbound requests are being blocked

Start at the audit log — every block carries a reason and the inspector that decided it.

```bash
agentcage cage audit myapp --decision blocked --since 1h
```

The output shows host, inspector, severity, and reason for each block. Three patterns cover most cases:

- **Reason: `domain not in allowlist`** — add the host with `agentcage domain add myapp example.com`. Subdomains are matched automatically. The change hot-reloads.
- **Reason: `port not in ports.tcp.allow`** — the cage tried to reach a port outside the inspected set (default `[80, 443]`). Edit `cage.yaml`, add the port to `ports.tcp.allow` or `ports.tcp.passthrough`, then `cage update myapp`. The default-deny `filter:FORWARD` chain is the cause; this default landed in 0.15.0.
- **Reason: from the `secrets` inspector** — a real secret value or a pattern matching one (e.g. `sk-ant-…`) appeared on the wire. The block is intentional; see "A request is blocked when it shouldn't be".

For a single host you suspect is wrong:

```bash
agentcage cage audit myapp --host api.example.com --since 24h
```

## Secrets aren't reaching the cage

List what the cage knows about:

```bash
agentcage secret list myapp
```

Each row shows the secret name and its status. Missing entries do not get injected. To set or rotate a value:

```bash
agentcage secret set myapp ANTHROPIC_API_KEY
```

The CLI prompts for the value (or reads stdin). The running cage hot-reloads — no restart is needed.

If a secret is set but the cage still sees the placeholder upstream, check which path the secret takes. `secret_injection` rules keep the real value in the proxy and never expose it to the cage container; bare `container.podman_secrets` entries inject the real value as a plain environment variable. Mixing the two for the same key is a common cause of confusion. See [Secret injection](../reference/secret-injection.md).

If you change `secret_injection` rules in `cage.yaml`, the proxy needs a service restart to pick up the new mapping:

```bash
agentcage cage restart myapp
```

## A request is blocked when it shouldn't be

Find the audit entry, identify the inspector, then choose between exempting the destination, adjusting the inspector, or accepting the block as correct.

```bash
agentcage cage audit myapp --decision blocked --host api.example.com --since 1h
```

The `inspector` field names the policy that fired. Match it to the right fix:

- **`domain`** — destination is not on the allowlist. `domain add` it.
- **`secrets`** — a known secret pattern matched. Add the destination to that secret's `allow_to_domains` in `cage.yaml`, or, if the secret is real and you actively want it injected for this host, move it into `secret_injection` with `inject_to: ["api.example.com"]`.
- **`body-size`** — body exceeded `max_request_body` (default 10 MiB). Raise the cap in `cage.yaml`.
- **`entropy` / `content-type`** — the request body tripped an exfiltration heuristic. Tune the inspector or scope it to specific content types. See [Inspectors](../reference/inspectors.md).

After editing `cage.yaml`, `cage edit` picks the lightest-touch reload. For raw `domains` changes, prefer `domain add` / `domain rm` — they hot-reload without touching the proxy.

## The proxy keeps restarting

The egress service uses `Restart=on-failure`, so a misconfigured cage loops every few seconds. Catch the failure window:

```bash
agentcage cage logs myapp -s egress -f
```

Common loop causes:

- **Bad CA trust on first boot** — the cage workload writes to `/certs` before the egress has populated it. Wait 30 seconds; `cage create` adds an `ExecStartPre` that polls for the CA. If the loop persists, destroy and recreate.
- **Port conflict on the host** — published ports collide with another process. `cage create` rejects conflicts up front, but a port can become busy after the cage is created. Pick a new host port in `cage.yaml` and `cage update myapp`.
- **Custom inspector raising at import** — a syntax error in `/etc/agentcage/inspectors/*.py` crashes the proxy on every restart. Fix the file and `cage restart myapp`.

## Reading audit logs

Stream new decisions live:

```bash
agentcage cage audit myapp -f
```

Aggregate the last day:

```bash
agentcage cage audit myapp --since 24h --summary
```

Combine filters to scope an investigation:

```bash
agentcage cage audit myapp --decision blocked --inspector secrets --since 7d
```

The full filter set — `--decision`, `--host`, `--inspector`, `--method`, `--direction`, `--severity`, `--since`, `--json` — is documented in [CLI](../reference/cli.md#cage-audit).

## Backend-specific quirks

Most quirks are minor side-effects of the isolation boundary. Full list in [Isolation modes](../explain/isolation-modes.md#known-limitations).

- **apple-container — `cage logs -s proxy` or `-s dns` fails** — the proxy and DNS run as supervised processes inside the egress sibling. Use `-s egress` instead.
- **apple-container — `cage update` is needed for most `cage.yaml` edits** — the allowlist, command, env, and secret-injection rules are baked into the wrapper image at build. `domain add` / `domain rm` auto-rebuild; everything else needs an explicit `cage update`.
- **apple-container — `apt-get update` prints HTTP→HTTPS warnings** — cosmetic. Exit code is 0; the fetches succeed via mitmproxy's TLS interception.
- **vm — first cold start takes 15-30s** — Lima boots a guest kernel before any container starts. Subsequent starts are sub-second.
- **container — file permission errors in `/workspace`** — the scaffold uses `userns: keep-id` to map your host UID into the container. Confirm the mounted directory is owned by your user on the host.

## Getting help

Open an issue at <https://github.com/agentcage/agentcage/issues> with:

- The output of `agentcage cage verify myapp`.
- The last 100 lines of `agentcage cage logs myapp` (redact any real hostnames if sensitive).
- `uname -a` and `agentcage --version`.
- A minimal `cage.yaml` that reproduces the issue (strip real domains and secrets).

Security vulnerabilities go to **security@agentcage.ai**, not the public tracker. See [Security model](../explain/security-model.md#reporting-security-issues).

## Related

- [CLI](../reference/cli.md) — every flag mentioned here
- [Inspectors](../reference/inspectors.md) — what each inspector blocks and how to tune it
- [Isolation modes](../explain/isolation-modes.md) — full backend quirk list
- [Back up and restore](back-up-and-restore.md) — when things are unrecoverable
- [Upgrade agentcage](upgrade-agentcage.md) — version-bump troubleshooting
