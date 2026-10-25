# FEAT-019: Standalone egress gateway, remote hosts and fleets

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P2 |
| **Phase** | 5+ |
| **Depends on** | [FEAT-008](FEAT-008-git-workflow-and-reports.md), [FEAT-013](FEAT-013-api-sdk-ci.md) |
| **Related** | [FEAT-012](FEAT-012-mcp-gateway.md), [FEAT-015](FEAT-015-packaging-and-platform.md) |

## Problem

The strongest part of agentcage is the egress policy plane, but it is coupled
to the full cage topology. Teams that already use Docker, E2B, a remote dev
box or a CI runner cannot reuse it. Users who want to run several agents on a
beefy remote machine have no supported path.

## Proposal

### Standalone egress gateway

```text
agentcage gateway --config proxy.yaml --listen 127.0.0.1:8080
```

- Runs the egress proxy without a cage, for a workload where the operator
  controls the network namespace.
- Use cases: Docker sandbox, remote CI job, a process wrapped with SRT-like
  filesystem isolation, an existing VM.
- Exposes the domain inspector, secret injection, capture and audit; the DNS
  sinkhole/iptables guarantees remain cage-specific and must be documented as
  such.
- Explicitly not a replacement for the full cage when the workload can bypass
  the proxy.

### Remote host

- `agentcage remote add NAME ssh://host` and `run --remote NAME`.
- The CLI orchestrates a cage on the remote host; the egress stays with the
  cage.
- SSH transport only; no inbound control port by default.
- `remote doctor` and version compatibility checks.

### Fleet and warm pools

- `agentcage fleet` to create N worktree cages from one template for parallel
  tasks.
- `fleet status`, `fleet collect` (diffs/reports), `fleet destroy`.
- Optional warm pool of pre-created cages on a remote host, with a claim API.
- Keep this local-first; Kubernetes/agent-sandbox integration can come later
  via the API/SDK.

## Implementation

- Gateway: extract the egress binary’s proxy startup from the supervisor;
  add a config-only mode. Need a clear security warning and a test that shows
  direct egress is still possible.
- Remote: use SSH multiplexing and a remote `agentcage` binary; never copy
  private keys. The local CLI drives the same lifecycle contract as local.
- Fleet: build on FEAT-008 worktrees and FEAT-013 API; don’t invent a second
  orchestration model.
- Warm pool: only after the API and cleanup semantics are stable.

## Acceptance criteria

- [ ] `gateway` enforces domain/secret policy for a proxy-configured workload
      and documents what it cannot enforce.
- [ ] `remote` runs a cage on a remote host with version/doctor checks.
- [ ] `fleet` creates independent worktrees and reports their status.
- [ ] `fleet collect` produces diffs/reports without sharing secrets.
- [ ] Warm pool is opt-in and has a defined cleanup policy.

## Tests

- Gateway policy test with a bypass attempt documented and detected.
- Remote lifecycle e2e against a disposable VM.
- Fleet worktree isolation and collect tests.
- Warm pool claim/cleanup tests.

## Risks

- The gateway can create a false sense of security if used without network
  enforcement; name it clearly and document the limits.
- Remote support multiplies platform combinations; start with Linux-to-Linux.
- Fleet orchestration can become a separate product; keep it thin and built on
  existing primitives.
EOF