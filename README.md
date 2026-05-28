<p align="center">
  <img src="docs/agentcage.png" alt="agentcage logo" width="250">
</p>

# agentcage

*Defense-in-depth proxy sandbox for AI agents.*

Don't let your agent phone home.

> :warning: **Warning:** This is an experimental project. It has not been audited by security professionals. Use it at your own risk. See [Security model](docs/explain/security-model.md) for details and known limitations.

> **Coding agents:** [Claude Code](src/agentcage/scaffolds/claude-code/README.md) · [Codex](src/agentcage/scaffolds/codex/README.md) · [Pi](src/agentcage/scaffolds/pi/README.md) &nbsp;|&nbsp; **Agent platforms:** [OpenClaw](src/agentcage/scaffolds/openclaw/README.md)

<p align="center">
  <a href="https://asciinema.org/a/838890"><img src="https://asciinema.org/a/838890.svg" alt="agentcage demo" width="700"></a>
</p>

## What is it?

agentcage is a CLI that generates hardened, sandboxed environments for AI agents. Your agent runs on an internal-only network with no internet gateway; the only way out is through an inspecting proxy that scans every HTTP request before forwarding it.

Most agent deployments hand the agent a [**lethal trifecta**](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): internet access, real secrets, and arbitrary code execution. Combined, they create an exfiltration risk that most setups have zero defense against. agentcage breaks that combination. See [Security model](docs/explain/security-model.md) for the full breakdown.

- **Network isolation** -- agent on internal-only network, no internet gateway
- **Inspecting proxy** -- pluggable inspector chain on every HTTP request, WebSocket frame, and DNS query
- **Secret injection** -- agent gets placeholders, proxy swaps in real values outbound and redacts inbound
- **Secret & payload scanning** -- regex secret detection, Shannon entropy, content-type mismatch, base64 blob scanning
- **DNS filtering** -- allowlist-based dnsmasq sidecar, placeholder IPs for unauthorized domains
- **Fail-closed by default** -- all hardening on out of the box; component failure stops traffic

Three isolation backends are supported:

- **container** (Linux, default) — rootless Podman containers on the host
- **vm** (Linux + macOS) — a Lima VM per cage with hardware isolation via KVM
- **apple-container** (macOS 26+ Apple Silicon, new in 0.20) — a single Apple `container` microVM per cage with the egress filter (mitmproxy + dnsmasq + iptables) running inside, supervised by an in-microVM PID 1 that drops to uid 1000 / zero caps / NoNewPrivs before exec'ing the cage workload. ~10–20× faster than Lima and ~3× less RAM per cage; the default on macOS 26+ when Apple's `container` CLI is installed.

See [Security model](docs/explain/security-model.md#isolation-modes-and-the-threat-surface) for the threat-by-threat matrix and [Isolation modes](docs/explain/isolation-modes.md) for how each backend works and when to pick which. For the full container topology and inspector chain, see [Architecture](docs/explain/architecture.md).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
```

The installer detects your platform and installs the right backend (Podman on Linux, Apple `container` on macOS 26+ Apple Silicon, Lima elsewhere). For manual setup per backend, see [Install](docs/get-started/install.md).

## Quick Start

### Ephemeral session

One command builds the image, creates a temporary cage, and drops you into an interactive session. The cage is torn down when you exit; audit logs are preserved.

```bash
# Run Claude Code in a sandbox
agentcage run claude-code

# Run OpenAI Codex in a sandbox
agentcage run codex

# Pass secrets and a project directory
agentcage run claude-code -s ANTHROPIC_API_KEY --project ~/myrepo
```

### Persistent cage

Survives across sessions — keep auth tokens, run multiple `cage exec` sessions, or let it run continuously as a background service (systemd auto-restarts on failure and starts on boot).

```bash
agentcage init myapp --scaffold claude-code
agentcage secret set myapp ANTHROPIC_API_KEY
agentcage cage create -c cage.yaml
agentcage cage exec myapp -- claude     # interactive
agentcage cage verify myapp             # or just check it's running
```

### Custom image

```bash
agentcage init myapp --image node:22-slim
# Edit cage.yaml to configure domains, secrets, inspectors...
agentcage cage create -c cage.yaml
```

Run `agentcage init --list-scaffolds` to see available scaffolds. See [CLI Reference](docs/reference/cli.md) for the full command set.

## Day-to-day

```bash
agentcage cage list                              # what's running
agentcage cage logs myapp                        # agent logs
agentcage cage audit myapp --summary --since 24h # inspection decisions
agentcage secret set myapp ANTHROPIC_API_KEY     # rotate a secret
agentcage cage update myapp -c cage.yaml         # apply config changes
agentcage cage destroy myapp                     # tear it down
```

See [CLI reference](docs/reference/cli.md) for the full command set and [Operate a cage](docs/README.md#operate-a-cage) for the how-tos.

## Documentation

The [docs map](docs/README.md) lays out the tree by task: control egress, operate a cage, extend with a custom inspector, understand the architecture and security model.

## License

MIT
