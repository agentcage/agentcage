# Documentation

## Core

- [Architecture](architecture.md) — container topology, inspector chain, secret injection, network isolation
- [Security & Threat Model](security.md) — threat model, defense layers, isolation modes, known limitations
- [Configuration Reference](configuration.md) — all settings, defaults, and examples
- [CLI Reference](cli.md) — full command set and options
- [Port Policy](proxy-audit-ports.md) — `ports.tcp` / `ports.udp` allowlists, the default-deny FORWARD chain, worked examples

## Isolation

- [Lima VM Isolation](vm.md) — KVM-based hardware isolation via Lima
- [Apple Container Isolation](apple-container.md) — Apple `container` microVM per cage, macOS 26+ Apple Silicon (default on that platform)

## Setup Guides

- [Claude Code](../src/agentcage/scaffolds/claude-code/README.md) — Anthropic's CLI coding agent
- [Codex](../src/agentcage/scaffolds/codex/README.md) — OpenAI's CLI coding agent
- [OpenClaw](../src/agentcage/scaffolds/openclaw/README.md) — full-featured AI coding agent
- [Managing Your Cage](cage-management.md) — common operations and troubleshooting
