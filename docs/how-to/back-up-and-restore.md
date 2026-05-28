<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Back up and restore

Capture and recover the full state of a cage — image, config, scaffold files, audit data, and optionally secrets. Read this when preparing for an upgrade, migrating a cage, or building a disaster-recovery routine.

A backup is a single tarball. Restore reconstructs the cage state, rebuilds the image (unless deferred), and starts it. Replace `myapp` with your cage name.

## What gets backed up

`cage backup` captures everything agentcage needs to reconstruct the cage:

- The stored `cage.yaml` and any per-cage scaffold files.
- `metadata.json`, including the cage's network octet so the rebuild lands on the same subnet.
- The audit log and, when capture is enabled, the HAR capture file.
- The list of expected secret names, so the restore host knows what to re-set.
- On the `container` backend, `cage.yaml`-declared named volumes are exported and re-imported.

With `--include-secrets`, the backup also contains real secret values from the Podman secret store. On `apple-container` the flag is rejected — there's no host-side Podman store to serialize from on that backend (secrets are provided via `cage create --set-secret` and staged into a per-cage dir at start; they aren't reconciled into a portable form). The manifest still records the expected env names.

Not included:

- Bind-mounted host directories. Back them up with your normal data tooling.
- Named volumes on `vm` and `apple-container` (no host-side `podman volume export` path).
- The container image when it's a pull from a public registry. Restore re-pulls it. Locally built scaffold images are rebuilt from the captured scaffold files.

## Take a backup

```bash
agentcage cage backup myapp
agentcage cage backup myapp --output /var/backups/agentcage/myapp-2026-05-28.tar.gz
```

Without `--output`, the tarball lands in the current directory as `myapp-backup-<timestamp>.tar.gz`.

To include secrets (`container` and `vm` only):

```bash
agentcage cage backup myapp --include-secrets --output ./myapp-with-secrets.tar.gz
```

Treat any backup with `--include-secrets` as secret material itself. File permissions on the tarball are the only access control; store it where you would store the underlying API keys.

## Restore on the same host

```bash
agentcage cage restore myapp-backup-2026-05-28.tar.gz
```

The command reconstructs the cage state, rebuilds the image, and starts the cage. Flags:

- `--force` — overwrite an existing cage with the same name.
- `--name myapp-staging` — restore as a clone. Rewrites the `name:` field in the restored `cage.yaml`. The clone gets a fresh subnet allocation; the original is unaffected.
- `--no-start` — lay down the cage state on disk without building the image or starting containers. Run `cage update myapp` when you are ready.

## Restore on a different host

Three things move with the cage; one is host-specific.

- **The image** is rebuilt from the scaffold files captured in the backup. The destination host needs network access to whatever base images the scaffold pulls.
- **The mitmproxy CA** is regenerated on first start. The cage workload trusts the new CA via `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE`; nothing needs to follow it across hosts.
- **Secret values** do not travel by default. Either run the original backup with `--include-secrets`, or re-set each secret on the destination host with `secret set`. The restore output lists the expected names.

Host-specific: `systemd-creds`-backed secrets are bound to the source host's TPM2 or host key and cannot be transplanted. Re-set them on the destination — its `systemd-creds` encrypts with its own key. See [Secret injection](../reference/secret-injection.md#secret-backends).

On `apple-container`, restore prints a warning listing the expected env names; set them with `secret set` (or export them before `cage start`) before traffic flows.

## Backup discipline

Take a backup before any destructive operation:

- Before `agentcage cage destroy` — the only way back is the tarball.
- Before `agentcage cage update` against a substantial `cage.yaml` change.
- Before bumping agentcage itself. See [Upgrade agentcage](upgrade-agentcage.md).

For service-lifecycle cages, schedule a periodic backup:

```bash
0 3 * * * agentcage cage backup myapp --output /var/backups/agentcage/myapp-$(date +\%F).tar.gz
```

Keep at least one off-host copy — the default location is the host's filesystem, and a host failure wipes both the cage and the backup unless you ship the tarball elsewhere. Rotate older copies (`find /var/backups/agentcage -mtime +30 -delete`).

## Restore drills

An untested backup is not a backup. Once a quarter, restore the most recent backup under a clone name and confirm:

```bash
agentcage cage restore myapp-backup-latest.tar.gz --name myapp-drill
agentcage cage verify myapp-drill
agentcage cage audit myapp-drill --since 1h
agentcage cage destroy myapp-drill -y
```

`cage verify` exercises every health check the cage was designed to pass. If it reports degradation, the backup either captured a broken state or the restore path drifted from `cage create`.

For cages with `secret_injection` rules, the drill should include re-setting one secret and confirming the cage reaches the upstream — secret restoration is the most common silent-failure path.

## Related

- [CLI — cage backup](../reference/cli.md#cage-backup) — flag reference
- [Secret injection](../reference/secret-injection.md) — backends and migration
- [Isolation modes](../explain/isolation-modes.md) — backup behavior per backend
- [Security model](../explain/security-model.md) — capture file handling and trust boundaries
- [Upgrade agentcage](upgrade-agentcage.md) — when to back up during a version bump
