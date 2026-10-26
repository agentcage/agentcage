# Dynamic ports, file transfer and editor access

| | |
| :--- | :--- |
| **Issue** | [#574](https://github.com/agentcage/agentcage/issues/574) |
| **Status** | Proposed |
| **Priority** | P1 |
| **Phase** | 4 |
| **Depends on** | [#564](https://github.com/agentcage/agentcage/issues/564), [#569](https://github.com/agentcage/agentcage/issues/569) |
| **Related** | [#571](https://github.com/agentcage/agentcage/issues/571) |

## Problem

An agent often starts a dev server, writes a file outside the workspace or
needs to be edited in a real editor. agentcage currently requires a restart
for port changes and has no file-transfer or editor path. This is a major
daily-workflow gap.

## Proposal

### Ports

```text
agentcage ports NAME list
agentcage ports NAME publish 3000[:8080]
agentcage ports NAME unpublish 8080
agentcage open NAME 3000
```

- Reuse the existing inbound reverse-proxy path for the container backend.
- VM/Apple backends may use backend-native forwarding; expose only loopback
  by default.
- `list` shows host→cage mappings in `ls` and `status`.
- Ports can be declared in `cage.yaml` and added at runtime where the backend
  permits; otherwise the command says a restart is required.

### Files

```text
agentcage cp SRC DST
agentcage cp NAME:/path ./local
agentcage cp ./local NAME:/path
```

- Backend-native copy where available; preserve modes.
- Never copy secret mounts or the CA private key.
- Refuse to overwrite a directory without `--force`.

### Editor and SSH

```text
agentcage ssh NAME [--print-config]
agentcage code NAME PATH
```

- Key-based, cage-scoped SSH endpoint, loopback-only by default.
- `ssh --print-config` emits an SSH config block for VS Code/Cursor remote
  development.
- Do not expose the host SSH agent, host keys or `/run/user` sockets.
- `destroy` removes the key and config.

## Implementation

- Port service: extend backend trait with `publish_port`/`unpublish_port`
  where supported; otherwise return a precise “requires restart” error.
- `cp`: use `podman cp`, `container cp`, or `limactl` equivalents; run through
  `CommandRunner`.
- SSH: start a minimal `sshd`/dropbear sidecar inside the cage with a generated
  per-cage key; mount a read-only authorized_keys file. Prefer a dedicated
  sidecar over modifying the workload image.
- Editor integration is just SSH config plus instructions; no proprietary
  extension required in v1.

## Acceptance criteria

- [ ] A dev server started in a cage is reachable on the chosen host port and
      listed by `ports`; unpublish closes it.
- [ ] `cp` round-trips a file in both directions without exposing secrets.
- [ ] SSH is opt-in, loopback-only by default and revoked by `destroy`.
- [ ] `code` prints/opens a working remote path where the editor supports it.
- [ ] Unsupported backends return a remediation, not a generic failure.

## Tests

- e2e port publish/unpublish on container; backend-gated VM/Apple tests.
- `cp` file/dir/owner/mode tests in both directions.
- SSH key lifecycle and loopback binding tests.
- Secret-mount copy refusal test.

## Risks

- SSH is a new attack surface; gate behind explicit opt-in and threat model.
- Port forwarding on VM/Apple may expose more than expected; bind loopback.
- `cp` can copy sensitive workspace data; document it.
