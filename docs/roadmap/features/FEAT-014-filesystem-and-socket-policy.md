# FEAT-014: Filesystem, socket and sensitive-file policy

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P2 |
| **Phase** | 5 |
| **Depends on** | Threat-model update |
| **Related** | [FEAT-012](FEAT-012-mcp-gateway.md), [FEAT-018](FEAT-018-team-governance.md) |

## Problem

The network story is mature; the filesystem story is not. The only path rules
are hard-coded pivot masks for `.git/hooks` and `.claude`. There is no general
read/write denylist, no Unix-socket policy and no credential broker beyond the
Google JWT transform. SRT, ai-jail and nono already offer parts of this.

## Proposal

### Filesystem policy

```yaml
container:
  filesystem:
    deny_read: ["/workspace/.env", "**/secrets/**"]
    deny_write: [".git", "**/secrets/**", ".env"]
    allow_write: ["/workspace", "/tmp"]
```

- Path rules apply inside the cage, after mounts are resolved.
- Deny wins over allow for write; read uses an explicit exception model.
- Defaults protect common sensitive files while keeping `/workspace` writable.
- `agentcage cage plan` and `doctor` show which rules are enforced by the
  backend and which are advisory.
- Provider credential directories are covered by preset rules; the examples
  above stay project-scoped so they work identically on every backend.

### Backend enforcement

| Backend | Strategy |
| :--- | :--- |
| Linux container | Landlock where the kernel supports it; mount masks as fallback. |
| Apple container | Mount masks and/or a Seatbelt-style wrapper where available. |
| VM | Same policy inside the guest. |

A backend that cannot enforce a rule must fail closed for `deny_write` or
clearly warn for `deny_read`; never silently drop it.

### Unix sockets

```yaml
container:
  sockets:
    allow: ["/run/agent.sock"]
    deny: ["/var/run/docker.sock"]
```

Default-deny for host sockets; explicit allow for MCP/agent sockets.

### Credential broker

Extend the existing `transform` machinery:

- GitHub App installation tokens (private key stays outside the cage);
- AWS SigV4 signing;
- generic OAuth2 refresh-token exchange;
- optional format-preserving placeholders for tools that validate key shape.

Minted tokens are redacted exactly like stored secrets.

## Implementation

- Landlock needs a helper invoked before the workload; do not rely on shell
  wrappers inside the image. Start with project-mounted paths.
- Landlock support depends on kernel and seccomp; detect and report.
- Socket policy may need seccomp/BPF; scope v1 to explicit bind mounts and
  socket files, not all abstract sockets.
- Credential transforms must be tested against the existing redaction and
  capture corpus.
- Format-preserving placeholders require a security review and a large
  redaction test matrix.

## Acceptance criteria

- [ ] A denied read/write path fails with a clear error inside the cage.
- [ ] The fallback backend behaviour is explicit in `plan` and `doctor`.
- [ ] A host socket cannot be reached unless explicitly allowed.
- [ ] A GitHub App token is minted and injected without the private key
      entering the cage.
- [ ] Minted tokens and new placeholder formats survive the redaction corpus.

## Tests

- Landlock integration tests on a supported kernel (skip with a reason
  elsewhere).
- Mount-mask tests for Apple/VM.
- Socket allow/deny tests.
- Credential transform and redaction matrix.
- Redteam pass focused on filesystem/socket bypasses.

## Risks

- Kernel heterogeneity; a rule that silently does nothing is a security bug.
- Performance on large worktrees; benchmark before defaulting.
- New placeholder formats can regress redaction; require fuzzing.
EOF