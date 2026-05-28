<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Upgrade agentcage

Bump agentcage on a host with running cages, propagate the upgrade to each cage, and recover if it goes wrong. Read this when a new release lands and you want to ship it without surprising your operators.

The agentcage binary and the cages it manages are upgraded separately. Bumping the binary does not silently rebuild your cages; until you run `cage update`, each cage keeps the templates and patches it was created with.

## Before you upgrade

Confirm every cage is healthy on the current version:

```bash
agentcage cage list
agentcage cage verify myapp
```

Take a backup of each cage you cannot afford to lose. See [Back up and restore](back-up-and-restore.md).

```bash
agentcage cage backup myapp --output ./pre-upgrade/myapp-$(date +%F).tar.gz
```

Read the `CHANGELOG.md` entries between your current version and the target. Look specifically for:

- Lines starting with `### Security` — these often tighten defaults and may change observable behavior.
- Lines mentioning `cage.yaml` field changes or new validation.
- Lines mentioning podman, Lima, or Apple `container` minimum versions.

## Upgrade agentcage itself

If you installed via `uv tool`:

```bash
uv tool upgrade agentcage
agentcage --version
```

If you installed via the curl script:

```bash
curl -sSf https://install.agentcage.ai | sh
```

Pin to a specific version when rolling out across hosts:

```bash
uv tool install agentcage==0.22.12
```

After the upgrade, `agentcage doctor` verifies host-side prerequisites (Podman, systemd, Lima, Apple `container`) are still compatible.

```bash
agentcage doctor
```

## Update running cages

Cages created before the upgrade keep their old generated quadlets and wrapper images until you explicitly update them.

`cage update` rebuilds the image and regenerates quadlets — the fully redeploy path:

```bash
agentcage cage update myapp
```

`cage restart` bounces containers without rebuilding — fine when only runtime state is stale:

```bash
agentcage cage restart myapp
```

Which one to pick:

- New agentcage version with template or patch changes → `cage update`.
- `cage.yaml` field that hot-reloads (domains, inspectors, rate limits, logging) → use `cage edit` or `domain add` / `domain rm`; the proxy is signaled in place.
- `cage.yaml` field that requires a service restart (`ports`, `secret_injection`, command, env, restart policy) → `cage restart` after editing.
- `cage.yaml` field that requires a rebuild (`container.image`, `isolation`) → `cage update`.

See [Architecture — hot-reload semantics](../explain/architecture.md#hot-reload-semantics) for the full reload model.

To roll out a binary upgrade across every cage on a host:

```bash
for cage in $(agentcage cage list --names); do
  agentcage cage backup "$cage" --output ./pre-upgrade/
  agentcage cage update "$cage"
  agentcage cage verify "$cage"
done
```

## Common breaking-change patterns

Recent releases that changed observable behavior:

- **0.22.0 — three-service shape collapsed to two.** The legacy `<cage>-proxy` and `<cage>-dns` containers were unified into a single `<cage>-egress` container. Cages created on 0.21.x are detected and rejected by every command except `cage list` and `cage destroy`. Recovery is `cage destroy && cage create` — there is no in-place migration. `cage logs -s proxy/-s dns` are gone; use `-s egress`.
- **0.21.19 — `container` and `vm` exec sessions drop to uid 1000 by default.** Previously inherited the image's USER (root on most bases). Pass `--as-root` to keep root for operator debug.
- **0.15.0 — default-deny `filter:FORWARD` policy.** Pre-0.15, only ports 80 and 443 were inspected; every other port silently L3-forwarded. Post-0.15, every other port is dropped unless listed in `ports.tcp.allow`, `ports.tcp.passthrough`, or `ports.udp.allow`. Cages that depend on outbound NTP (`123/udp`), Postgres (`5432/tcp`), IMAP (`993/tcp`), Matrix federation (`8448/tcp`), or QUIC (`443/udp`) need those ports added.

The `CHANGELOG.md` `### Security` and `### Changed` sections are the canonical record. When in doubt, run `cage verify` after each cage update — degradation surfaces there.

## Rolling back

If the upgrade leaves a cage broken and you cannot fix forward, restore from backup and pin the old agentcage:

```bash
agentcage cage destroy myapp -y
uv tool install agentcage==0.22.6
agentcage cage restore ./pre-upgrade/myapp-2026-05-28.tar.gz
agentcage cage verify myapp
```

Pinning blocks accidental re-upgrade. Once you understand the breakage, unpin with another `uv tool install agentcage==<newer>`.

Yanked releases are documented in the changelog with `(yanked, see X.Y.Z)`. Avoid those — install the successor.

## Apple-container specific notes

On `apple-container`, the cage's allowlist, command, env, secret-injection rules, capture config, and autostart are baked into the wrapper image at build time. After an agentcage upgrade that touches the supervisor or the wrapper Containerfile, `cage update` is mandatory for the changes to take effect — `cage restart` reuses the existing image.

`domain add` and `domain rm` are the exceptions; both trigger an automatic wrapper rebuild on apple-container (Apple's layer cache makes this 1-2s on warm systems) so the new allowlist is live without a separate command.

See [Isolation modes — apple-container](../explain/isolation-modes.md#known-limitations) for the full list of fields that need `cage update` versus those that hot-reload.

## OS or backend upgrades

Backend tooling updates independently of agentcage. Each has its own constraints:

- **podman major version on Linux.** The container backend's hardened rootless setup is sensitive to changes in `containers.conf` defaults — agentcage 0.22.0 dropped the runtime chown after `default_capabilities = []` started breaking the supervisor. After a podman major bump, run `cage verify` on every cage; if egress fails to start, `cage update` regenerates quadlets that match the new podman.
- **Lima version bumps.** Lima manages the per-cage VM in `vm` mode. Lima upgrades occasionally change VM image defaults; agentcage's provision script handles the common ones. If a cage fails to come up after a Lima upgrade, destroy and recreate it — the VM is recreated from the captured `cage.yaml`.
- **Apple `container` CLI upgrades.** macOS 26.x ships the `container` CLI as part of the OS. Major bumps occasionally tighten apiserver behavior (race-on-create has been seen in the wild); when `cage create` returns before the supervisor reaches stage 90, give it 5-10 seconds and re-check rather than assuming a config error.

For all three, `agentcage doctor` is the first stop after the host-side upgrade.

## Related

- [CHANGELOG](../../CHANGELOG.md) — release-by-release behavior changes
- [Back up and restore](back-up-and-restore.md) — pre-upgrade backup and rollback
- [Architecture — hot-reload semantics](../explain/architecture.md#hot-reload-semantics) — which field changes reload how
- [Isolation modes](../explain/isolation-modes.md) — backend-specific upgrade quirks
- [Troubleshoot](troubleshoot.md) — diagnose a cage that breaks after upgrade
