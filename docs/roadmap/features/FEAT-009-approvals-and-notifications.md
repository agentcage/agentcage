# FEAT-009: Human approvals, notifications and policy explanations

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P1 |
| **Phase** | 3 |
| **Depends on** | [FEAT-006](FEAT-006-cli-automation.md) |
| **Related** | [FEAT-004](FEAT-004-policy-presets-and-suggestions.md), [FEAT-018](FEAT-018-team-governance.md) |

## Problem

The Policy API is LLM-decider-only. If the decider is disabled, unavailable or
uncertain, the agent is simply blocked. There is no pending queue, no desktop
or webhook notification, and watcher findings are easy to miss unless the
operator is watching a terminal.

## Proposal

### Decider modes

```yaml
agents:
  decider:
    mode: llm | human | hybrid
    # hybrid: ask the model; if uncertain or unavailable, queue for a human
    approval_timeout_seconds: 300
```

- `llm`: current behaviour.
- `human`: every request becomes a pending approval; the agent receives a
  retryable response with a request id.
- `hybrid`: run the decider; on deny/uncertainty/error, enqueue for a human
  when the policy allows it.

### Approvals

```text
agentcage approvals list [--json]
agentcage approvals show ID
agentcage approvals approve ID [--ttl 1h]
agentcage approvals deny ID --reason TEXT
```

Pending requests include domain, cage, justification, requesting process
metadata (if available), risk context, timestamp and expiry. The store lives
under the cage data directory, not inside the cage.

### Notifications

- Desktop notification on new pending request, block burst, or watcher
  finding.
- Generic webhook plus Slack/Discord/ntfy-compatible payloads.
- `agentcage watch`: a live event stream (human and JSON).
- Payloads contain host, reason, request id and severity only; never bodies,
  headers or secret values.

### Policy explanations

- `domain test NAME HOST` and `domain explain NAME HOST` (shared with
  FEAT-004).
- 403 responses include a machine-readable `suggestion` and a request id.

## Implementation

- Add `mode` to the decider config; validate human mode only when a local
  operator channel exists.
- The egress writes pending requests through the same grants/audit volumes so
  the host CLI can read them on all backends.
- Human mode returns `202`/`409`-style pending status with a request id; the
  agent retries after approval or receives a final deny on timeout.
- Approval/deny is a host-side operation; never accept it from the cage.
- Use one notification module with per-channel adapters; store webhook URLs as
  secrets.
- Timeouts write a `policy_approval_expired` audit record.

## Acceptance criteria

- [ ] Human mode queues a request; the agent can retry after approval; denial
      and timeout are clear and audited.
- [ ] Hybrid mode falls back to a human only when configured.
- [ ] `approvals list/show/approve/deny` work on all backends.
- [ ] Notifications never include a secret or body.
- [ ] A watcher finding can trigger a notification without exposing traffic.
- [ ] 403 remediation points to the correct path (Policy API or operator).

## Tests

- e2e: human approval grant/deny/timeout.
- Hybrid fallback with a mocked decider error.
- Notification payload golden/redaction tests.
- Backend store tests for the pending queue.

## Risks

- Approval fatigue and prompt-injected justifications; show risk context and
  short expiry.
- Webhook credentials are secrets; never echo them.
- Host queue availability while a VM is stopped; document degraded mode.
