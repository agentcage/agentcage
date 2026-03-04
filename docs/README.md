# Documentation

## Core

- [Architecture](architecture.md) — container topology, inspector chain, secret injection, network isolation
- [Security & Threat Model](security.md) — threat model, defense layers, isolation modes, known limitations
- [Configuration Reference](configuration.md) — all settings, defaults, and examples
- [CLI Reference](cli.md) — full command set and options

## Features

- [Traffic Capture & HAR Export](configuration.md#traffic-capture-capture) — record and export decrypted request/response bodies for forensic analysis
- [Inspector Chain](architecture.md#inspector-chain) — pluggable inspection pipeline for domain filtering, secret detection, entropy analysis

## Isolation

- [Firecracker MicroVM Isolation](firecracker.md) — KVM-based hardware isolation setup and details

## Setup Guides

- [OpenClaw](../src/agentcage/scaffolds/openclaw/README.md) — full-featured AI coding agent
- [PicoClaw](../src/agentcage/scaffolds/picoclaw/README.md) — ultra-lightweight agent gateway
- [NanoClaw](../src/agentcage/scaffolds/nanoclaw/README.md) — nested container agent framework
