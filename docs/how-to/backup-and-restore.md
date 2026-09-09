# How-To: Backup & Restore Cages

agentcage provides built-in commands to create portable, self-contained backup tarballs of your sandboxes. You can use backups for disaster recovery, migrating cages between machines, or cloning environments for testing.

---

## What a Backup Contains

When you create a backup archive using `agentcage cage backup`, agentcage packages:

- **Configuration**: The stored declarative `cage.yaml` source of truth.
- **Metadata**: State records, created timestamps, active scaffold name, and isolation backend settings (`metadata.json`).
- **Fingerprints**: Build layer cache hashes and container IDs (`fingerprint.json`).
- **Volumes**: Persistent Podman named volume data (tarred from the container storage layer).
- **Secrets (Optional)**: If `--include-secrets` is specified, encrypted credentials stored on the host are included in the archive.

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

### Including Encrypted Secrets
By default, secret values are excluded from backups to prevent accidental credential leakage. To include stored secrets:

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

This unpacks configuration and state files, registers systemd quadlets (or microVM configs), restores named volume contents, and starts the cage.

### Restoring Under a Different Name (Cloning)
To duplicate an existing cage configuration and volume state under a new name:

```bash
agentcage cage restore ~/backups/my-agent.tar.gz --name my-cloned-agent
```

### Restoring Without Starting
To restore files and quadlets without automatically starting the containers:

```bash
agentcage cage restore ~/backups/my-agent.tar.gz --no-start
```

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
