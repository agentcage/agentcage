# The Traffic Watcher & Background Auditing

In a defense-in-depth architecture, synchronous inline inspectors (`domain`, `secrets`, `entropy`, `content-type`) evaluate individual HTTP flows in the hot request path. To keep latency negligible, inline inspectors must make instantaneous decisions on single requests.

However, sophisticated security threats — such as **slow-and-low data exfiltration**, **C2 beaconing**, and **multi-step prompt injection pivots** — span multiple requests across minutes or hours.

The **Traffic Watcher** is an asynchronous, background LLM auditor that periodically re-examines recent network traffic, detects anomalous behavior, flags suspicious flows, and can **autonomously revoke compromised runtime grants**.

---

## Architecture & Scan Loop

The Watcher runs on an independent background timer inside the egress container:

```
┌─────────────────────────── TRAFFIC CAPTURE ───────────────────────────┐
│                                                                        │
│  L7 Proxy Flow  ──▶  audit.jsonl   (Decisions, hosts, inspector flags) │
│                 ──▶  capture.jsonl (Full HTTP bodies, inbound view)    │
│                                                                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         Every `interval_seconds` (e.g. 300s)
                                    │
                                    ▼
┌────────────────────────── THE WATCHER ENGINE ──────────────────────────┐
│                                                                        │
│  1. Window Digest Generator:                                           │
│     • Extracts traffic from the last `window_seconds` (e.g. 600s)       │
│     • Deduplicates repeated polling endpoints (`dedup_samples: true`)   │
│     • Truncates large bodies to respect `max_digest_tokens`            │
│     • Enforces strict secret hygiene (never leaks real keys)           │
│                                                                        │
│  2. Autonomous LLM Auditor:                                            │
│     • Evaluates digest against declared cage purpose                   │
│     • Analyzes traffic shape, frequency, and payload entropy           │
│     • Scans for exfiltration or C2 beaconing signatures                │
│                                                                        │
│  3. Actions & Enforcement:                                             │
│     • Record structured findings to `findings.jsonl`                   │
│     • Autonomous Revocation: if `auto_revoke: true` is enabled and a   │
│       dynamic grant is implicated in suspicious traffic, the grant     │
│       is immediately revoked and purged from DNS.                      │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Enabling the Watcher in `cage.yaml`

Configure the watcher within the `agents.watcher` block:

```yaml
agents:
  watcher:
    enable: true
    interval_seconds: 300 # Run scan every 5 minutes
    window_seconds: 600 # Inspect the last 10 minutes of traffic
    max_flows: 100 # Maximum flows to analyze per scan
    auto_revoke: true # Autonomously revoke suspicious runtime grants
    dedup_samples: true # Collapse repeated polling requests
    max_digest_tokens: 8000 # Hard ceiling on LLM prompt size
    provider: openrouter
    model: z-ai/glm-5.3
    context: >
      This cage is running a Python backend unit test suite.
      Approved traffic includes GitHub API calls and PyPI package downloads.
      Flag any requests containing serialized source code or unusual uploads.
```

---

## 2. Evidence Sources & Secret Hygiene

The Watcher synthesizes evidence from two local log files:
1. `audit.jsonl`: Contains metadata for every request: timestamp, target host, HTTP method, status code, decision (`allowed`, `blocked`, `flagged`), and triggering inspector names.
2. `capture.jsonl`: Contains full request and response bodies.

### Secret Hygiene Guarantee
The Watcher reads exclusively from the **inbound perspective** of captured traffic. It only ever sees decoy placeholders (`agentcage:secret:NAME:<hex>`), never real decrypted API keys. Real credentials can never be leaked to the Watcher's LLM model.

---

## 3. Autonomous Revocation (Narrowing Only)

The Watcher operates under a strict principle of **least authority**:
- **What it CAN do**: If the Watcher determines that a domain granted through the Policy API is being abused (e.g. an agent requested access to an API but is now uploading base64 data to it), the Watcher can **autonomously revoke the runtime grant**. The domain is immediately blocked at the proxy and removed from `dnsmasq`.
- **What it CANNOT do**: The Watcher **can never grant access** to new domains, widen existing allowlists, or modify the operator's static `cage.yaml` configuration. Its authority is strictly **narrowing-only**.

---

## 4. Operator Commands

Operators can monitor the Watcher's health and review findings using the CLI:

### A. Check Watcher Status
Displays scan intervals, the last execution timestamp, and backlog status:

```bash
agentcage watcher status <name>
```

Example output:
```text
=== Traffic Watcher: my-agent ===
Status:           Active (running)
Interval:         Every 300s (last scan: 42s ago)
Window:           Last 600s of traffic
Auto-Revoke:      Enabled
Last Scan Result: Clean (0 findings across 24 flows)
Backlog:          0 pending events
```

### B. Inspect Recorded Findings
Lists anomalies flagged by the Watcher:

```bash
# View recent findings:
agentcage watcher findings <name>

# Filter by minimum severity:
agentcage watcher findings <name> -s high

# Stream raw findings as JSON lines:
agentcage watcher findings <name> --json
```

Example finding entry:
```json
{
  "timestamp": "2026-09-08T10:24:12Z",
  "severity": "high",
  "category": "exfiltration",
  "domain": "api.example.com",
  "description": "High entropy POST payload (7.8 bits/byte) sent to unverified endpoint.",
  "action_taken": "grant_revoked"
}
```

---

## Next Steps

- **[System Architecture](architecture.md)** — Understand the full dual-container design.
- **[Configuration Reference](../reference/configuration.md)** — Complete configuration schema for `agents.watcher`.
- **[Auditing How-To](../how-to/manage-egress-and-domains.md)** — Managing and promoting domain grants.
