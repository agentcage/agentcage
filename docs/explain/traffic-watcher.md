# The Traffic Watcher & Background Auditing

The inspectors in the request path judge one request at a time, in milliseconds. Some threats only show in the aggregate: **slow exfiltration** spread over many small requests, **beaconing** to a command-and-control host, a **multi-step pivot** after a prompt injection.

The **traffic watcher** is an LLM auditor that runs inside the egress, re-reads the cage's recent traffic every interval, records what looks suspicious, and can **revoke runtime grants** it finds abused. It is opt-in.

---

## Architecture & Scan Loop

The watcher runs on its own thread in the egress process (`agentcage-egress`), so a slow model provider never holds up proxied traffic.

```
┌──────────────────────────── EVIDENCE ─────────────────────────────────┐
│                                                                        │
│  audit ring     every audit record the egress writes, allowed          │
│                 requests included (even with allowed_requests off)     │
│  capture.jsonl  tailed by byte offset; the placeholder view only       │
│                                                                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │  every interval_seconds × U(0.5, 1.5)
                                    │  (never less than 60 s)
                                    ▼
┌────────────────────────────── ONE SCAN ────────────────────────────────┐
│                                                                        │
│  1. Collect: drain the ring, read new capture lines                    │
│     no traffic since the last scan → no model call                     │
│  2. Digest: per-host aggregates, deduplicated samples, short body      │
│     excerpts, evasion indicators; trimmed to max_digest_tokens         │
│  3. Review: one forced tool call to the watcher's LLM                  │
│  4. Apply: findings → audit + findings.jsonl;                          │
│     revocations → runtime grants removed (if auto_revoke)              │
│     failure → evidence pushed back, retried next scan                  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Enabling the Watcher in `cage.yaml`

```yaml
agents:
  watcher:
    enable: true
    provider: openrouter # anthropic | openai | openrouter
    model: z-ai/glm-5.3
    api_key: env:OPENROUTER_API_KEY
    interval_seconds: 900 # one scan per 15 minutes at most (default)
    window_seconds: 3600 # look-back for a scan that starts from scratch (default)
    max_flows: 200 # capture samples per digest (default)
    max_digest_tokens: 8000 # prompt ceiling per scan (default)
    auto_revoke: true # revoke condemned runtime grants (default)
    dedup_samples: true # collapse repeated flow shapes (default)
    context: >
      This cage runs a Python backend's unit test suite.
      Expected traffic: GitHub API calls and PyPI package downloads.
      Flag requests that carry serialized source code or unusual uploads.
```

Every key's accepted values are in the [Configuration Reference](../reference/configuration.md#5-agents-decider--watcher). The watcher requires `domains` allowlist mode.

`max_digest_tokens` is the setting that caps spend whatever the traffic volume. Each scan's prompt is trimmed to fit it; about one scan in twenty is a "full-fidelity" scan with four times the budget, so a cage cannot learn which traffic always falls outside the trimmed digest.

---

## 2. Evidence & Secret Hygiene

The watcher reads two sources:
1. **The audit ring**: every record the egress audits, kept in memory (the most recent 5000), including allowed requests that `logging.allowed_requests: false` keeps out of the log. It carries the host, method, path, decision and inspector verdicts of every request, plus relay, Policy API and other records.
2. **`capture.jsonl`** (when `capture.enable_har` is on): tailed by byte offset across rotations and truncations. Only short excerpts of request and response bodies reach the digest.

`window_seconds` applies only when the watcher has to start reading the capture from scratch: the first scan after the egress starts, or after the file was rotated or truncated. Later scans read only what is new since the last one.

### Secret hygiene
The digest never carries a real secret value. Body excerpts come only from the capture's placeholder view, the values of sensitive headers (`Authorization`, cookies, API-key headers) are replaced by name, and the capture itself holds placeholders only. Everything in the digest is treated as untrusted data; the operator's `context` is the only trusted free text in the prompt.

### Fail closed
An error, a timeout, a missing tool call or a malformed verdict is a **recorded failed scan**, never an all-clear and never a revocation. The evidence of a failed scan is not lost: the drained audit records go back to the front of the ring and the capture offset is not advanced, so the next scan sees the same window plus anything newer. Repeated failures produce a finding on the first failure and every tenth after it.

Each scan draws its own random seed for the choices that shape the digest (excerpt windows, tie-breaks, which samples survive the budget), so a cage cannot shape its traffic to sit just past a fixed boundary. The seed is recorded in `state.json`.

---

## 3. Autonomous Revocation (Narrowing Only)

- **What it can do**: revoke a runtime grant (a domain the [Policy API](policy-api.md) granted) when its analysis finds the grant abused. The domain is blocked at once and removed from DNS, and a `watcher_revoke` record is written. With `auto_revoke: false` the revocation is recorded as a finding for you to apply instead.
- **What it cannot do**: grant anything, widen an allowlist, or edit the operator's baseline. A baseline domain it distrusts becomes a recommendation finding, not a removal. The never-grant floor is never touched.

---

## 4. Findings

Each finding is written twice: as a `watcher_finding` audit record (with `decision: flagged` and an inspector entry named `watcher`, so `cage audit --inspector watcher` and `--decision flagged` find it), and as a line in `findings.jsonl` in the cage's grants directory (`~/.local/share/agentcage/<name>/grants/watcher/`), rotated to `findings.jsonl.1` at 16 MiB.

```json
{
  "kind": "watcher_finding",
  "ts": "2026-09-08T10:24:12.513402+00:00",
  "decision": "flagged",
  "method": "",
  "direction": "",
  "host": "api.example.com",
  "url": "",
  "path": "",
  "port": 0,
  "reason": "",
  "severity": "high",
  "title": "Repeated base64 uploads to a granted API",
  "detail": "Every 60 s a POST of ~4 KB of base64 to /v1/events, unrelated to the stated task.",
  "recommendation": "Revoke the grant and review the workspace for an injected script.",
  "decided_by": "watcher:agent:openrouter",
  "inspectors": [{"name": "watcher", "severity": "high", "reason": "Repeated base64 uploads to a granted API"}]
}
```

Severities are `info`, `low`, `medium`, `high` and `critical`. The scan state (last scan, scans run, findings total, failures, capture backlog, digest size, seed) is in `state.json` beside it.

---

## 5. Operator Commands

```bash
# Configuration and the last scan's state:
agentcage watcher status <name>

# Recorded findings (most recent 50 by default):
agentcage watcher findings <name>
agentcage watcher findings <name> -s high -s critical
agentcage watcher findings <name> --host example.com -n 0
agentcage watcher findings <name> --json
```

`watcher status` shows the scan interval, look-back window, auto-revoke setting and agent, then the scan state: last scan, scans run, flows in the last window, findings total, digest size against its budget and the capture backlog. Neither command triggers a scan or changes a grant.

---

## Next Steps

- **[System Architecture](architecture.md)** — The egress and its request pipeline.
- **[Configuration Reference](../reference/configuration.md)** — `agents.watcher` keys and defaults.
- **[Managing Egress How-To](../how-to/manage-egress-and-domains.md)** — Managing and promoting domain grants.
