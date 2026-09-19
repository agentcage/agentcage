# `state-compat` fixtures — 0.40.1

A byte-frozen snapshot of the on-disk state that **agentcage 0.40.1
(Python)** writes for a deployed cage.

## Why

The host CLI is being rewritten in Rust (`RUST-PORT-PLAN.md` §2.7). At cutover
every existing user has cages that the Python CLI deployed, and the Rust binary
must read that state **in place, on first run, with no migration step**.

None of this state carries a schema version — `metadata.json` is a bare
`json.dumps(dict)`, and there is no `state_version` field anywhere in
`src/agentcage/state.py`. There is nothing to branch on. So the Rust readers
have to accept *exactly* what the Python writers produce, and this directory is
the definition of "exactly".

The Python tests in `tests/test_state_compat.py` load every file here through
the real Python readers and assert concrete values. Those same assertions are
what the Rust implementation will be held to.

## This is generated. Do not hand-edit.

    uv run python scripts/gen-state-fixtures.py

The generator drives the real code paths — `state.save_deployment`,
`state.fill_placeholders`, `state.save_proxy_config`, `state.save_grants`,
`secret_store.*`, `quadlets.generate_quadlets`, and the actual `cage backup`
click command — inside a throwaway XDG sandbox, then scrubs and copies the
result here. Re-running it on a clean tree produces a byte-identical tree.

`--check` regenerates into a temporary directory and reports every difference
file by file — added, removed, and changed with a unified diff; for the backup
tarball it compares decompressed members rather than the gzip stream. That is
how CI (and you) can prove the committed fixture still matches the code, and a
CI log alone is enough to diagnose a drift.

One trap worth knowing about: git cannot store an empty directory. If the
generator ever emits one it survives in the author's working tree, is silently
dropped by `git add`, and then makes `--check` fail on every fresh checkout
while passing locally. The generator refuses to write such a tree, and
`tests/test_state_compat.py` additionally asserts that every fixture file is
tracked by git.

## Adding a new generation

**Never overwrite this directory.** Bump the package version and run the
generator again; it writes `tests/fixtures/state-compat/<new-version>/`. Keeping
several generations is the point — the Rust reader has to cope with state
written by any version a user might be upgrading from.

## Layout

| Path | Corresponds to |
| :-- | :-- |
| `xdg-config/agentcage/cages/<name>/` | `$XDG_CONFIG_HOME/agentcage/cages/<name>/` |
| `xdg-config/agentcage/apple-container/<name>/` | `~/.config/agentcage/apple-container/<name>/` |
| `xdg-config/containers/systemd/` | `~/.config/containers/systemd/` (quadlets) |
| `xdg-data/agentcage/<name>/` | `$XDG_DATA_HOME/agentcage/<name>/` |
| `xdg-data/agentcage/patches/` | shared resolv.conf + nested-podman patch dir |
| `backup/<name>-backup.tar.gz` | output of `agentcage cage backup --include-secrets` |

Three cages are captured:

- **`acme-agent`** — multiple domains, secrets from more than one source, a
  protocol relay, capture, grants, `creds/`, a fingerprint, rendered quadlets
  and a backup tarball.
- **`plain-cage`** — everything defaulted, so the *absence* of a file is
  captured too.
- **`mac-agent`** — the macOS shape. Note where its runtime state lives:
  `~/.config/agentcage/apple-container/<name>/logs/` holds the addon's
  `audit.jsonl`, `capture.jsonl`, `dnsmasq.log` and `ready` marker. That is a
  third state root, separate from both XDG trees.

Two things about `audit.jsonl` are easy to get wrong and are captured here
deliberately. There is **no** host-side `audit.jsonl` for a container or vm
cage — the addon writes its audit trail to stderr and the host reads it back
out of `journalctl`. And the grants overlay is **`grants.yaml`**, a YAML list,
not JSON.

## Frozen values

Determinism is a hard requirement, so everything that varies per run is pinned:

- **Clock** — every `datetime.now()` returns `2026-03-14T15:09:26+00:00`.
- **Paths** — the generator's sandbox is rewritten to `/home/agentcage-fixture`, and
  `$XDG_RUNTIME_DIR` to `/run/user/1000`. No path from the generating machine
  appears anywhere in this tree; the generator asserts that before writing.
- **UID/GID** — rewritten to `1000`.
- **Placeholder entropy** — `config.generate_placeholder` mints
  `agentcage:secret:<ENV>:<hex>` from `secrets.token_hex(16)`; the entropy
  source is frozen so the minted token is fixed.
- **Subnet octet** — pinned to `137` rather than hash-derived.
- **Tarball metadata** — the gzip header mtime/filename and each tar member's
  mtime, uid/gid, uname/gname and mode are normalized after `cage backup`
  runs, and member text goes through the same path scrub as everything else.
  Member names, order, types and contents are what `cage backup` emitted.
  Mode is normalized because it is not a stable part of the format: `tar.add`
  copies each state file's mode, which is whatever the producing host's umask
  made it, so `umask 077` and `umask 022` produce different archive bytes for
  identical state.
- **File modes are not part of this fixture.** git records only the
  executable bit, so a file that is 0600 on a real host (`pending_secrets.json`,
  `creds/*.cred`) comes back from a checkout as 0644. The at-rest mode is a
  real property of those writers and is asserted in their own tests; it cannot
  be carried here, so the regeneration check ignores modes.

## Secrets

There are none. Every secret-shaped value is an obviously-fake
`TEST-NOT-A-REAL-SECRET-####` string and every certificate is
`TEST-NOT-A-REAL-CERTIFICATE-####`.

`xdg-config/agentcage/cages/acme-agent/creds/*.cred` is the one thing that is
*not* generated by running the real encryptor: `systemd-creds` encryption is
host-bound (host key / TPM2 / per-user key), so a blob produced here could not
be decrypted in CI or on any other machine, and re-encrypting would not
reproduce byte-identically anyway. A single real-shaped blob is frozen into the
generator instead. **Assert its presence, filename and shape — never its
contents.** The plaintext behind it was `TEST-NOT-A-REAL-SECRET-0001`.
