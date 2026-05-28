<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Capture

Opt-in HAR recording of full request/response bodies (decrypted) for forensic analysis. Disabled by default. Read this when investigating a flagged flow or building a regression fixture.

Each captured flow contains two perspectives:

- **INBOUND** — what the bot sees inside the cage (placeholders, redacted secrets). Safe to share.
- **OUTBOUND** — what goes on the wire (real injected secrets, raw server responses). Treat as sensitive.

## Settings

Settings under `capture:`.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_har` | `bool` | `false` | Enable HAR traffic capture. Creates a volume mount for the capture file. |
| `max_body_size` | `int` | `10485760` (10 MB) | Truncate bodies larger than this. Truncated entries are marked with `bodyTruncated: true`. |
| `min_action` | `string` | `"all"` | Minimum inspector action to trigger capture: `"all"` (capture everything), `"flag"` (flagged + blocked only), `"block"` (blocked only). |
| `domains` | `list[string]` | `[]` | Domain allowlist — only capture flows to matching domains. Empty = capture all. Subdomains are matched automatically. |
| `exclude_domains` | `list[string]` | `[]` | Domain blocklist — skip flows to matching domains. |

## Example

```yaml
capture:
  enable_har: true
  max_body_size: 10485760     # 10MB (default)
  min_action: all             # capture everything
  domains: []                 # all domains
  exclude_domains: []         # no exclusions
```

## Capture only flagged/blocked traffic to specific domains

```yaml
capture:
  enable_har: true
  min_action: flag            # skip allowed requests
  domains:
    - anthropic.com           # only capture anthropic traffic
  max_body_size: 1048576      # 1MB — keep capture file small
```

## Storage considerations

- Each simple API call generates ~1-5 KB of capture data.
- Large request/response bodies (file uploads, model outputs) can be much larger — use `max_body_size` to cap per-body size.
- The capture file grows indefinitely. For long-running cages, use `min_action: flag` or `domains` to limit what's recorded.
- Export with `agentcage cage har --since 1h` to get time-bounded snapshots.

## Exporting captured traffic

Use `agentcage cage har` to export captured traffic as HAR 1.2 JSON:

```bash
# Inbound perspective (safe to share)
agentcage cage har mycage -o agent-view.har

# Outbound perspective (contains real secrets)
agentcage cage har mycage --view outbound -o wire-view.har

# Only blocked requests from last hour
agentcage cage har mycage --decision blocked --since 1h
```

See [CLI Reference — cage har](../cli.md#cage-har) for full options.

## Related

- [Inspectors](inspectors.md) — `min_action` keys off inspector decisions.
- [Domains](domains.md) — `domains` / `exclude_domains` use the same matching rules.
- [Secret injection](secret-injection.md) — outbound captures contain real secrets; treat as sensitive.
