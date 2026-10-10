# How-To: Backup & Restore Cages

agentcage provides built-in commands to create portable, self-contained backup tarballs of your sandboxes. You can use backups for disaster recovery, migrating cages between machines, or cloning environments for testing.

---

## What a Backup Contains

`agentcage cage backup` writes a gzipped tar with one top-level directory, `agentcage-backup/`, holding:

- **`manifest.json`**: the backup's format version, the agentcage version that wrote it, the cage's name and isolation backend, a timestamp, the names of the secrets the cage's config expects, the named volumes in the archive, and whether secret values and a build context are included.
- **`config/`**: the cage's state directory: `cage.yaml`, `metadata.json` (including the cage's network slot), the generated `proxy-config.yaml` and `dns-allowlist.conf` (for reading only, since a restore regenerates both from `cage.yaml`), and the build context when the cage builds its own image: the `Containerfile` and everything it copies in. Left out:
  - credential material: `creds` and `pending_secrets.json`.
  - `cage-env/`, the placeholder environment a deploy regenerates.
  - `secret_keys.json`, the index of which secrets the at-rest store holds. Restored onto another host it would claim secrets that aren't there.
  - `fingerprint.json`, which describes the source host's build. Restored, it would make `cage update` report "already up to date" and skip the rebuild the restored cage needs.
  - `cage.yaml.bak`, `cage.yaml.rejected` and build noise (`.git`, `node_modules`, `__pycache__`, `*.pyc`, `*.deleted.*`).

  A restore skips these names even when a hand-made archive includes them.
- **`volumes/`** (`container` only): one `<name>.tar` for each `container.named_volumes` entry that exists, from `podman volume export`. A `vm` cage's named volumes live in its Lima guest and aren't backed up. `apple-container` has no named volumes.
- **`capture/capture.jsonl`**: the capture log, when it isn't empty. An `apple-container` backup also carries **`audit/audit.jsonl`**.
- **`secrets/`** (only with `--include-secrets`, not on `apple-container`): one file per stored secret, holding its **plaintext value**. Without the flag no values travel, and the restore lists the secrets you have to set again.

A backup never contains the cage's CA. The restored cage's egress generates a new one, as every new cage's does. `cage restore` imports only the volumes listed in the backup's `manifest.json`. It refuses an archive that lists a name podman doesn't accept as a volume name (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`) or that carries a volume agentcage manages (`agentcage-certs-*`, `agentcage-public-certs-*`, `agentcage-podman-*`), since `cage backup` never writes either.

---

## 1. Creating a Backup

Create a timestamped backup archive of a running or stopped cage:

```bash
agentcage cage backup my-agent
```
By default, this writes `./my-agent-backup-YYYYMMDD-HHMMSS.tar.gz`.

### Specifying an Output Path
```bash
agentcage cage backup my-agent -o ~/backups/my-agent.tar.gz
```

### Including Secret Values
By default, secret values are excluded from backups to prevent accidental credential leakage. To include the stored values (as plaintext, in `secrets/`):

```bash
agentcage cage backup my-agent -o ~/backups/my-agent-full.tar.gz --include-secrets
```

> **Warning**: Backups containing secret values should be handled with extreme care. Store the resulting tarball in an encrypted vault.

---

## 2. Restoring a Cage

Restore a cage from an existing backup archive:

```bash
agentcage cage restore ~/backups/my-agent.tar.gz
```

This restores the secrets the archive carries and the cage's configuration, regenerates `proxy-config.yaml` and `dns-allowlist.conf`, and builds and starts the cage. On `container` it then stops the cage, imports the named volumes and starts it again. The capture log is restored too.

### Restoring Under a Different Name (Cloning)
To duplicate an existing cage configuration and volume state under a new name:

```bash
agentcage cage restore ~/backups/my-agent.tar.gz --name my-cloned-agent
```

Only the cage's `name:` changes. Named volumes keep the names written in the archived `cage.yaml`: the openclaw scaffold, for example, names them `my-agent-workspace` and `my-agent-state`. Two cages mounting one volume would share its data, so on `container` a restore under a new name refuses, before it changes anything, when a volume the clone would import or mount already exists in podman or another cage mounts it. This covers the `container.named_volumes` keys and any `container.volumes` entry whose source is a bare volume name. The error lists each volume and what holds it. To go ahead, pick one:

- **Restore under the archive's own name** instead, after `agentcage cage destroy my-agent` or with `--force` to replace it, if you don't need the original any more.
- **Give the clone volumes of its own.** Unpack the archive. Rename each volume in `config/cage.yaml` (`container.named_volumes`, `container.volumes`). For a volume the archive carries, also rename its entry in `manifest.json`'s `named_volumes` and its `volumes/<name>.tar`. Then pack the archive again and restore it.
- **Remove a leftover volume** that nothing needs: `podman volume rm <name>`. `cage destroy` keeps a cage's named volumes, so one can outlive its cage. The restore counts it as taken because it still holds that cage's data, and `podman volume import` merges into an existing volume instead of replacing it.

On a host where none of the volumes exist and no cage mounts them, the clone gets them, created and filled from the archive. Keep in mind they still carry the original's name: a cage created later under that name would mount them. Restoring the same archive again with `--force` over a clone made this way works, since those volumes are the clone's own, as long as no other cage mounts them. A restore under the archive's own name isn't checked, because the volumes are that cage's own. `vm` and `apple-container` clones aren't checked either: a `vm` cage's volumes live in its own Lima guest, and `apple-container` has none.

### Restoring Without Starting
To restore the cage without building or starting it:

```bash
agentcage cage restore ~/backups/my-agent.tar.gz --no-start
```

This restores the secrets, the configuration and the capture log, and on `container` it also creates the named volumes and imports their data, so nothing is lost by not starting. No image is built and no units are installed. Run `agentcage cage update my-agent` to build and start the cage. It mounts the volumes that are already filled.

On `vm` and `apple-container`, a restore never imports named volumes, whether it starts the cage or not. `cage backup` doesn't write any for these backends. If a hand-made archive lists one, the restore warns and leaves the data in the archive, at `agentcage-backup/volumes/<name>.tar`.

### Overwriting an Existing Cage
If a cage with the same name already exists on the host:

```bash
agentcage cage restore ~/backups/my-agent.tar.gz --force
```

---

## 3. Disaster Recovery & Migration Checklist

When moving a cage to a new machine:

1. Create a full backup on the source host:
   ```bash
   agentcage cage backup my-agent --include-secrets -o my-agent-export.tar.gz
   ```
2. Copy the archive to the target host via `scp`:
   ```bash
   scp my-agent-export.tar.gz user@target-host:~/
   ```
3. On the target host, verify prerequisites:
   ```bash
   agentcage doctor
   ```
4. Restore the cage:
   ```bash
   agentcage cage restore ~/my-agent-export.tar.gz
   ```
5. Verify cage status:
   ```bash
   agentcage status my-agent
   agentcage cage verify my-agent
   ```

---

## Next Steps

- **[CLI Reference](../reference/cli.md)** — Full command syntax for `backup` and `restore`.
- **[Configuration Reference](../reference/configuration.md)** — Understand volume and state configuration.
