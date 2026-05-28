<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Back up and restore

Capture and recover the full state of a cage — image, config, scaffold files, audit data, and optionally secrets. Read this when preparing for an upgrade, migrating a cage, or building a disaster-recovery routine.

A backup is a single tarball. Restore reconstructs the cage state, rebuilds the image (unless deferred), and starts it. Replace `myapp` with your cage name.

## What gets backed up

`cage backup` captures everything agentcage needs to reconstruct the cage:

- The stored `cage.yaml` and any per-cage scaffold files.
- The persisted `metadata.json`, including the cage's network octet so the rebuild lands on the same subnet.
- The cage's audit log (`audit.jsonl`) and, when capture is enabled, the HAR capture file.
- The list of expected secret names, so the restore host knows what to re-set.

With `--include-secrets`, the backup also contains the real secret values from the Podman secret store. On `apple-container`, this flag is **rejected** — secret values are env-passed at `cage start` from `os.environ` and are no longer accessible to agentcage at backup time. The manifest still records the expected env names.

Not included:

- User-defined named volumes and bind-mounted host directories. These hold workload data outside agentcage's lifecycle. Back them up with your normal data tooling.
- The container image itself when the image is a pull from a public registry. Restore re-pulls it. Locally built scaffold images are rebuilt from the captured scaffold files.

## Take a backup

```bash
agentcage cage backup myapp
```

The tarball lands in the current directory as `myapp-backup-<timestamp>.tar.gz`. Override the path with `--output`:

```bash
agentcage cage backup myapp --output /var/backups/agentcage/myapp-2026-05-28.tar.gz
```

To include secrets (Linux backends only):

```bash
agentcage cage backup myapp --include-secrets --output ./myapp-with-secrets.tar.gz
```

Treat any backup with `--include-secrets` as secret material itself. File permissions on the tarball are the only access control; store it where you would store the underlying API keys.

## Restore on the same host

To recover a cage you destroyed or that has gone unrecoverable:

```bash
agentcage cage restore myapp-backup-2026-05-28.tar.gz
```

The command reconstructs the cage state, rebuilds the image, and starts the cage. If a cage with the same name already exists, restore refuses unless you pass `--force`:

```bash
agentcage cage restore myapp-backup-2026-05-28.tar.gz --force
```

To restore as a clone — for testing changes against a copy of production data — give it a new name:

```bash
agentcage cage restore myapp-backup-2026-05-28.tar.gz --name myapp-staging
```

`--name` rewrites the `name:` field in the restored `cage.yaml`. The new cage gets a fresh subnet allocation; the original is unaffected.

If you need to inspect the restored state before anything runs, defer the build:

```bash
agentcage cage restore myapp-backup-2026-05-28.tar.gz --no-start
```

The cage state is laid down on disk but the image is not built and no containers start. Run `cage update myapp` when you are ready.

## Restore on a different host

Three things move with the cage; one is host-specific.

- **The image** is rebuilt from the scaffold files captured in the backup. The destination host needs network access to whatever base images the scaffold pulls.
- **The mitmproxy CA** is regenerated on first start. The cage workload trusts the new CA via `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE`; nothing needs to follow it across hosts.
- **Secret values** do not travel by default. Either run the original backup with `--include-secrets` (and treat the tarball accordingly), or re-set each secret on the destination host with `secret set`. The restore output lists the expected names.

Host-specific: `systemd-creds`-backed secrets are bound to the source host's TPM or host key. They cannot be transplanted. Re-set them on the destination host; the destination's `systemd-creds` encrypts them with its own key. See [Secret injection](../reference/secret-injection.md#secret-backends).

On `apple-container`, restoring a cage whose backup recorded expected env names prints a warning listing them; set them with `secret set` (or export them before `cage start`) before traffic flows.

## Backup discipline

Take a backup before any destructive operation:

- Before `agentcage cage destroy` — the only way back is the tarball.
- Before `agentcage cage update` against a substantial `cage.yaml` change — the prior config goes into `cage.yaml.bak` automatically, but a full backup also captures audit data.
- Before bumping agentcage itself. See [Upgrade agentcage](upgrade-agentcage.md).

For service-lifecycle cages, schedule a periodic backup. A simple cron job:

```bash
0 3 * * * agentcage cage backup myapp --output /var/backups/agentcage/myapp-$(date +\%F).tar.gz
```

Keep at least one off-host copy. The default location is the host's filesystem; a host failure wipes both the cage and the backup unless you ship the tarball elsewhere.

Rotate backups so older copies are pruned. The cage's audit log grows over time, and so do its backups. A `find /var/backups/agentcage -mtime +30 -delete` next to the cron line bounds the footprint.

## Restore drills

An untested backup is not a backup. Once a quarter, restore the most recent backup under a clone name and confirm:

```bash
agentcage cage restore myapp-backup-latest.tar.gz --name myapp-drill
agentcage cage verify myapp-drill
agentcage cage audit myapp-drill --since 1h
agentcage cage destroy myapp-drill -y
```

`cage verify` exercises every health check the cage was designed to pass. If it reports degradation, the backup either captured a broken state or the restore path drifted from `cage create`. Either is a problem worth knowing about while you still have the running original.

For cages with `secret_injection` rules, the drill should include re-setting one secret and confirming the cage reaches the upstream — secret restoration is the most common silent-failure path.

## `--include-secrets` on apple-container

On the `apple-container` backend, `cage backup --include-secrets` is rejected with a clear message. Secret values are passed to the egress sibling via `os.environ` at `cage start` and bind-mounted as 0600 files at `/home/acproxy/secrets/<env-name>`. By the time backup runs, agentcage has no path to re-read those values from its own process. The backup manifest records the expected env names so the restore host operator knows what to set.

This is a backend property, not a configuration toggle. To get secret material into a portable backup, take the backup on `container` or `vm`, or maintain the secret values out of band (a password manager, `systemd-creds` on the destination host, a `cmd:` source pointing at your secret store). See [Isolation modes — apple-container](../explain/isolation-modes.md#known-limitations).

## Related

- [CLI — cage backup](../reference/cli.md#cage-backup) — flag reference
- [Secret injection](../reference/secret-injection.md) — backends and migration
- [Isolation modes](../explain/isolation-modes.md) — backup behavior per backend
- [Security model](../explain/security-model.md) — capture file handling and trust boundaries
- [Upgrade agentcage](upgrade-agentcage.md) — when to back up during a version bump
