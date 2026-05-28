# Documentation

## Core

- [Architecture](explain/architecture.md) — container topology, inspector chain, secret injection, network isolation
- [Security model](explain/security-model.md) — threat model, defense layers, isolation modes, known limitations
- [Configuration Reference](reference/configuration.md) — all settings, defaults, and examples
- [CLI Reference](reference/cli.md) — full command set and options
- [Port Policy](reference/ports.md) — `ports.tcp` / `ports.udp` allowlists, the default-deny FORWARD chain, worked examples

## Isolation

- [Isolation modes](explain/isolation-modes.md) — when to use container vs vm vs apple-container, how each one works, and the canonical comparison
- [Install](get-started/install.md) — backend-specific setup steps

## Setup Guides

- [Claude Code](../src/agentcage/scaffolds/claude-code/README.md) — Anthropic's CLI coding agent
- [Codex](../src/agentcage/scaffolds/codex/README.md) — OpenAI's CLI coding agent
- [OpenClaw](../src/agentcage/scaffolds/openclaw/README.md) — full-featured AI coding agent
- [Managing Your Cage](cage-management.md) — common operations and troubleshooting
