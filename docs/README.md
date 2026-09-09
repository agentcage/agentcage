# agentcage Documentation

Welcome to the **agentcage** technical documentation. agentcage is a defense-in-depth isolation sandbox designed to safely run autonomous AI coding agents (such as Claude Code, Pi, OpenAI Codex, and OpenClaw) with default-deny network egress, zero-leak placeholder secret injection, transparent TLS inspection, and autonomous policy controls.

This documentation is organized according to the **Diátaxis framework**, structured into four distinct quadrants based on your goals:

- **[Get Started](#1-get-started)**: Step-by-step onboarding for first-time operators.
- **[Explanations & Architecture](#2-architecture--explanations)**: Deep dives into internal mechanisms, security models, and design trade-offs.
- **[Reference Manuals](#3-reference-manuals)**: Exhaustive technical specifications for configuration, CLI commands, APIs, and schemas.
- **[How-To Guides](#4-how-to-guides)**: Practical, task-oriented operational recipes for common workflows.

---

## Recommended Learning Path

If you are new to agentcage, we suggest reading in this order:

1. **[Installation](get-started/install.md)** — Set up host prerequisites and install the CLI.
2. **[Quickstart Tutorial](get-started/quickstart.md)** — Launch your first sandboxed agent and observe network enforcement.
3. **[Architecture](explain/architecture.md)** — Understand the dual-container topology and packet routing.
4. **[Security Model](explain/security-model.md)** — Review threat boundaries, defenses, and residual risks.
5. **[Configuration Reference](reference/configuration.md)** — Learn every key in `cage.yaml`.

---

## Documentation Index

### 1. Get Started

| Guide | Description |
| :--- | :--- |
| **[Installation](get-started/install.md)** | Platform prerequisites (Linux rootless Podman vs. macOS Apple Container / Lima), installation methods, environment verification with `agentcage doctor`, upgrading, and uninstalling. |
| **[Quickstart Tutorial](get-started/quickstart.md)** | Hands-on walkthrough from scratch: running ephemeral agent sessions (`agentcage run`), building persistent cages (`agentcage init` / `cage create`), and observing blocked vs. allowed traffic. |

### 2. Architecture & Explanations

| Document | Description |
| :--- | :--- |
| **[System Architecture](explain/architecture.md)** | Technical breakdown of the dual-container topology (`<name>-cage` and `<name>-egress`), private bridge networking, iptables redirection, DNS sinkholing, per-cage CA injection, and request lifecycles. |
| **[Isolation Backends](explain/isolation-backends.md)** | Deep comparative analysis of the three isolation engines: `container` (Linux rootless Podman + quadlets), `apple-container` (macOS 26+ native microVMs), and `vm` (Lima hardware virtualization). |
| **[Security Model](explain/security-model.md)** | Comprehensive 8-layer defense-in-depth security model: threat assumptions, trust boundaries, capabilities dropping, read-only rootfs, pivot protection masks, and honest documentation of residual risks. |
| **[Policy API & Dynamic Egress](explain/policy-api.md)** | How sandboxed agents introspect allowlists and request dynamic domain access at `https://agentcage.local`, the role of the autonomous LLM Decider Agent, token budgeting, and baseline synchronization. |
| **[Traffic Watcher & Forensics](explain/traffic-watcher.md)** | Asynchronous background traffic auditing: how the Watcher agent detects exfiltration patterns and beaconing, autonomous grant revocation, structured audit trails, and dual-perspective HAR captures. |

### 3. Reference Manuals

| Manual | Description |
| :--- | :--- |
| **[Configuration Reference (`cage.yaml`)](reference/configuration.md)** | Exhaustive, field-by-field reference for every YAML configuration setting: container parameters, volumes, domain policies, secret injection rules, agent blocks, ports, logging, and capture limits. |
| **[CLI Reference Manual](reference/cli.md)** | Complete manual of all CLI commands, subcommands, flags, options, and ergonomic top-level aliases (`run`, `exec`, `shell`, `ls`, `ps`, `logs`, `status`, `show`, `edit`, `rm`, `update`). |
| **[Policy API Specification](reference/policy-api.md)** | Full HTTP/REST API specification for internal endpoints served on `https://agentcage.local` (`/v1/allowlist`, `/v1/allowlist/requests`, `/v1/allowlist/removals`), schemas, status codes, and security checks. |
| **[Scaffolds Reference](reference/scaffolds.md)** | Catalog of pre-configured agent templates (`claude-code`, `codex`, `pi`, `openclaw`, `ubuntu`, `debian`, `arch`, `busybox`), scaffold resolution order, and authoring custom scaffolds. |
| **[Secrets Management Reference](reference/secrets.md)** | Complete specification of secret lifecycles: encrypted storage backends (`systemd-creds` / Keychain), 128-bit entropic decoy tokens (`agentcage:secret:NAME:<hex>`), wire injection, and rotation. |

### 4. How-To Guides

| Recipe | Description |
| :--- | :--- |
| **[Run Agent Harnesses](how-to/run-agent-harnesses.md)** | Recipes and configuration examples for running popular coding harnesses inside agentcage: Anthropic Claude Code, OpenAI Codex, Pi.dev, OpenClaw, and custom LLM scripts. |
| **[Manage Egress & Domains](how-to/manage-egress-and-domains.md)** | Practical management of domain allowlists, wildcards, time-limited grants (`--expires-in`), handling 403 errors and TEST-NET IPs, and reviewing or promoting dynamic Policy API grants. |
| **[Troubleshooting & Diagnostics](how-to/troubleshooting.md)** | Diagnostic workflows for common operational problems: running `agentcage doctor`, interpreting audit logs, fixing DNS and certificate trust issues, terminal restoration, and permissions. |
| **[Backup & Restore](how-to/backup-and-restore.md)** | Procedures for creating portable tarball backups of cage state, volumes, and configurations (`agentcage cage backup`), and restoring or cloning cages (`agentcage cage restore`). |
| **[Custom Inspectors & Relays](how-to/custom-inspectors.md)** | Guide to authoring custom Python L7 traffic inspection filters (`Inspector` class) and configuring hardened protocol relays for non-HTTP services (such as IMAP and SMTP). |

---

## Getting Help & Contributing

- **Security Vulnerabilities**: Report security issues privately per [SECURITY.md](../SECURITY.md).
- **Contributing**: Development guidelines, testing instructions, and pull request workflows are documented in [CONTRIBUTING.md](../CONTRIBUTING.md).
- **Project License**: agentcage is open-source software licensed under the [MIT License](../LICENSE).
