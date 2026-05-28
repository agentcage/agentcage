<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Documentation

The operator's map of agentcage. Find your task; follow the link.

## Get started

- [Install](get-started/install.md) — backend prerequisites for Linux, macOS, and Apple Silicon.
- Need to sandbox a coding agent right now? Run `agentcage run claude-code` (see the [README Quick Start](../README.md#quick-start)).

## Sandbox an agent

- [Claude Code](../src/agentcage/scaffolds/claude-code/README.md) — Anthropic's CLI agent.
- [Codex](../src/agentcage/scaffolds/codex/README.md) — OpenAI's CLI agent.
- [Pi](../src/agentcage/scaffolds/pi/README.md) — minimal terminal coding harness.
- [OpenClaw](../src/agentcage/scaffolds/openclaw/README.md) — full agent platform.

## Control what the agent can do

- [Domains](reference/domains.md) — allowlist, blocklist, TLS passthrough.
- [Ports](reference/ports.md) — TCP/UDP policy and the default-deny FORWARD chain.
- [Secret injection](reference/secret-injection.md) — keep real credentials out of the cage.
- [Protocol relays](reference/protocol-relays.md) — IMAP/SMTP credential brokers.
- [Inspectors](reference/inspectors.md) — built-in checks and the custom inspector API.
- [Configuration](reference/configuration.md) — every other `cage.yaml` setting.
- [Capture](reference/capture.md) — HAR recording, inbound vs outbound perspectives.

## Operate a cage

- [Deploy to a server](how-to/deploy-to-server.md) — systemd-service pattern under a dedicated user.
- [Troubleshoot](how-to/troubleshoot.md) — stuck cages, blocked requests, missing secrets.
- [Upgrade agentcage](how-to/upgrade-agentcage.md) — bump the binary, update running cages.
- [Back up and restore](how-to/back-up-and-restore.md) — snapshotting, restore drills.
- [CLI reference](reference/cli.md) — full command set.

## Extend agentcage

- [Write a custom inspector](how-to/write-a-custom-inspector.md) — end-to-end walkthrough.

## Understand how it works

- [Architecture](explain/architecture.md) — topology, egress flow, inspector chain.
- [Isolation modes](explain/isolation-modes.md) — container vs vm vs apple-container, when to use which.
- [Security model](explain/security-model.md) — threat model, defense layers, known limitations.

## Past audits

- [Security review (Feb 2026)](audits/2026-02-security-review.md) — frozen snapshot, not always-current.
