<!-- owner: @luca  last-reviewed: 2026-08-31 -->
# Web interface

`agentcage web` serves a read-only dashboard for cage visibility —
processes, secrets, the domain allowlist, and proxy traffic — plus a
versioned JSON API backing it. There is no web framework and no new
dependency: the server is Python's stdlib `http.server`, and the
dashboard is one static HTML file.

The web interface is a **view, never a capability**: every panel it
serves has a CLI twin (see the parity table below), so nothing becomes
inspectable-only-in-a-browser. Where the data is richer than a table, the
CLI takes `--json`.

```bash
agentcage web                    # http://127.0.0.1:7635
agentcage web --port 8080        # different port
agentcage web --host 0.0.0.0     # share on the network (warns — see below)
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--host` | string | `127.0.0.1` | Interface to bind. Keep it on loopback unless you mean to share it |
| `--port` | int | `7635` | Port to serve on |
| `--no-browser` | flag | | Don't open a browser tab on start |

## Panels

The dashboard's landing page lists every cage (status, lifecycle,
isolation, secrets, domains); clicking one shows its detail: per-service
runtime status, expected secrets, the domain allowlist with passthrough
and expiry, runtime Policy API grants, DNS decisions, recent traffic
decisions, captured HTTP flows (inbound view) with a HAR download, and
service logs. Views auto-refresh every 5 s; traffic and logs can be
tailed live (SSE) with the `live` toggle — the web twin of `cage audit
-f` / `cage logs -f`. A `doctor` page mirrors `agentcage doctor`.

| Panel | Endpoint | CLI twin |
|-------|----------|----------|
| Manifest | `GET /api/v1/manifest` | — |
| Overview | `GET /api/v1/overview` | `agentcage overview [--json]` |
| Doctor | `GET /api/v1/doctor` | `agentcage doctor` |
| Cage detail | `GET /api/v1/cages/{name}` | `agentcage cage show NAME` |
| Secrets | `GET /api/v1/cages/{name}/secrets` | `agentcage secret list NAME` |
| Allowlist | `GET /api/v1/cages/{name}/allowlist` | `agentcage domain list NAME` + `agentcage cage grants list NAME` |
| Traffic | `GET /api/v1/cages/{name}/traffic` | `agentcage cage audit NAME [--summary]` |
| Traffic (live) | `GET /api/v1/cages/{name}/traffic/stream` (SSE) | `agentcage cage audit NAME -f --json` |
| DNS | `GET /api/v1/cages/{name}/dns` | `agentcage cage audit NAME --method DNS [--summary]` |
| Capture | `GET /api/v1/cages/{name}/capture` | `agentcage cage har NAME [--json-lines]` |
| HAR export | `GET /api/v1/cages/{name}/capture/har` | `agentcage cage har NAME` |
| Logs | `GET /api/v1/cages/{name}/logs` | `agentcage cage logs NAME` |
| Logs (live) | `GET /api/v1/cages/{name}/logs/stream` (SSE) | `agentcage cage logs NAME -f` |

`traffic` accepts `?limit=`, `?decision=` (repeatable), `?host=`
(repeatable), `?method=` (repeatable), and `?since=` (`1h`, `30m`, `7d`,
ISO date) — the same filters `cage audit` takes. `logs` accepts
`?service=` (repeatable) and `?lines=`. `capture` accepts `?limit=`;
the HAR download accepts `?limit=` (capped at 5000 entries). The DNS
panel is the audit stream's `method: DNS` slice — the egress's dnsmasq
wrapper emits one audit entry per DNS decision (allowed lookups and
sinkholed non-allowlisted lookups).

### Capture views stay inbound

Capture entries record both perspectives of every flow: **inbound**
(what the cage saw — placeholders, redacted secrets) and **outbound**
(the wire — real injected secrets). The web interface serves the
inbound perspective only, in both the capture panel and the HAR
download; the wire view is `agentcage cage har --view outbound` and it
stays in the CLI, warning and all.

### Live streams (SSE)

`/traffic/stream` and `/logs/stream` speak Server-Sent Events: one
`data: {json}` frame per entry/line, a `: heartbeat` comment every 15 s
so idle cages keep the connection alive and dead clients are detected
within one interval, and `event: error` frames if the reader fails
mid-stream. Providers resolve before the stream opens, so an unknown
cage or a missing reader is still a clean JSON error. Closing the
browser tab terminates the backend reader subprocess — streams are
one reader per connection, exactly like a `cage audit -f` per terminal.

Errors are JSON: `404` unknown cage/panel, `400` bad query parameter,
`409` legacy pre-v0.22 cage, `503` a reader failed or timed out. A cage
whose *panel* can't be read (no podman on PATH, VM down) degrades to an
inline `detail`/`error` field rather than failing the page.

## Security posture

- **Read-only.** The server accepts GET only; everything else is a 405.
  Changes go through the CLI, where they are reviewed, audited commands.
- **Secret values never cross the boundary.** Panels carry names and
  presence booleans only — the same surface `secret list` has. The
  capture/HAR panels go further and serve the **inbound perspective
  only** (what the cage saw: placeholders, redacted secrets); the wire
  view is `cage har --view outbound` and stays in the CLI.
- **Loopback by default.** The API exposes cage inventory (names,
  domains, traffic metadata); serving on a non-loopback `--host` prints
  a warning before the first request.
- **No caching, no sniffing.** API responses carry
  `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
- **Validated inputs.** Cage names are checked against the same charset
  the CLI enforces at create time before any filesystem use; reader
  subprocesses run with timeouts.

## Extending

A panel is a provider function in
`src/agentcage/web/providers.py` registered in `PANELS` with its route
and CLI twin. The server serves whatever is registered; `GET
/api/v1/manifest` advertises the list and the dashboard renders from
it. To add one: write the provider (read-only, JSON-able dict, no
secret values), register it, and — if the capability is new — add the
CLI command that renders the same data. The `cage_traffic` provider is
the worked example: it reuses `audit.py`'s filter and summary machinery
so the web numbers can never drift from `cage audit`'s.

Tests live in `tests/test_web.py` and pin the parity contract from
three sides: the provider data layer, the HTTP surface, and the CLI
commands.

## Related

- [CLI](cli.md) — the command reference
- [Inspectors](inspectors.md) — what produces the traffic decisions
- [Policy API](policy-api.md) — where runtime grants come from
