# `cage show` does not provide the detail its reference promises

| | |
| :--- | :--- |
| **Issue** | [#561](https://github.com/agentcage/agentcage/issues/561) |
| **Status** | Confirmed |
| **Priority** | P1 |
| **Area** | CLI output / documentation |
| **Affected** | v0.53.1 |
| **Fix** | [#570](https://github.com/agentcage/agentcage/issues/570) or a docs correction; `--json` follows the [#569](https://github.com/agentcage/agentcage/issues/569) envelope |

## Summary

The CLI reference says `agentcage cage show NAME`:

> Displays detailed configuration, network IP addresses, mounted volumes,
> active domain rules, and secret placeholders for a specific cage.

The actual command prints name, isolation, image, build path, version, status,
port specs, a domain count, a passthrough count and a secret count. It does not
print network addresses, volume mounts, domain names, rule details or
placeholder names.

## Evidence

- `docs/reference/cli.md` — `cage show` section.
- `rust/agentcage-cli/src/cli/cage/lifecycle.rs:160-235` — the actual fields.
- Sample output:

  ```text
  Name:       redteam
  Isolation:  container
  Image:      localhost/agentcage-scaffold-redteam:latest
  Build:      /home/.../Containerfile
  Version:    0.52.2
  Status:     degraded (1/2)
  Domains:    allowlist (2 domains)
  Secrets:    1/1
  ```

The same function backs `cage status NAME`, so both commands share the gap.

## Impact

- Operators cannot answer “what is actually mounted / reachable / injected?”
  from the CLI.
- `show` is the natural place to debug a degraded cage, but it omits the
  service-level detail needed for that.
- The reference overpromises, which is worse than a deliberately minimal show.

## Proposed fix

Either:

1. **Enrich the output** with network addresses, volumes and mount flags,
   named domain rules and expiry, secret names and masked placeholder names,
   ports, data directory, recent blocked count and watcher state; add
   `--json` with the same data. `cage show --json` is not an independent JSON
   design: it emits the envelope owned by
   [#569](https://github.com/agentcage/agentcage/issues/569)
   ([plan](../features/569-cli-automation.md)) — `schema_version`, `command`,
   `ok`, `data`, `warnings` — with the fields above under `data`. This is the
   recommended path.
2. **Correct the reference** to describe the summary and point to `cage audit`,
   `domain list`, `secret list` and `cage logs` for detail.

Option 1 is preferable because the information already exists in the parsed
config and deployment state.

## Acceptance criteria

- [ ] `cage show` displays every field the reference promises, or the
      reference no longer promises them.
- [ ] `cage show --json` exposes the same fields with a stable schema, inside
      the [#569](https://github.com/agentcage/agentcage/issues/569) envelope.
      The envelope is a prerequisite, not this issue’s design.
- [ ] Secret values are never printed; only key names and masked placeholders.
- [ ] A test pins the documented field list.

## Tests

- Unit/golden output test for a cage with multiple volumes, domains, ports and
  secrets.
- JSON schema test.
- Docs test asserting the reference fields exist in the output schema.

## Related

- [#570](https://github.com/agentcage/agentcage/issues/570)
- [#569](https://github.com/agentcage/agentcage/issues/569) — owns the JSON
  envelope and the shared `--json`/`--format` flags that `cage show` uses.
- [#562](https://github.com/agentcage/agentcage/issues/562)
