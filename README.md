<p align="center">
  <img src="docs/agentcage.png" alt="agentcage logo" width="240">
</p>

# agentcage

<p align="center">
  <strong>Defense-in-depth security sandbox for autonomous AI agents.</strong>
</p>

<p align="center">
  Default-deny network egress • Zero-leak placeholder secret injection • TLS inspection proxy • Autonomous Policy API & Traffic Watcher • Multi-backend isolation (Linux rootless Podman, macOS Apple Container, Lima VM)
</p>

---

agentcage runs an AI coding agent — **Claude Code**, **OpenAI Codex**, **Pi**, **OpenClaw**, or any custom agent workload — inside an isolated sandbox whose **only route to the outside world is an inspecting proxy you control**.

The agent gets a working internet connection restricted to approved domains, cryptographically random decoy tokens instead of your real API keys, and zero ability to access the open internet, probe internal networks, or pivot back to your host machine.

```bash
agentcage run claude-code -s ANTHROPIC_API_KEY
```

That single command builds an unprivileged container, allocates a private internal network, launches an egress proxy with a DNS filter and TLS-inspecting inspector chain, stores your real API key encrypted on the host, hands the agent a fake placeholder token, mounts your current repository at `/workspace` with host-pivot protection masks, and drops you into an interactive Claude Code session.

---

## Why agentcage?

Autonomous AI coding agents read untrusted input from the web, execute shell commands, install dependencies, and manipulate files. Running an agent directly on your machine or inside a naive container hands it what security researchers term the [**lethal trifecta**](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): access to private credentials, arbitrary code execution, and unrestricted network egress.

Standard containerization alone does **not** protect you:

1. **Unrestricted Egress**: A standard container can dial any IP on the internet. A prompt-injected agent or malicious dependency can trivially exfiltrate your entire repository or open a reverse shell to an attacker's C2 server.
2. **Exposed Credentials**: Environment variables like `ANTHROPIC_API_KEY` or `GITHUB_TOKEN` are readable by every process in the container, any installed npm/pip package, and any prompt injection that executes `env` or `curl`.
3. **Internal Network Probing**: Containers can reach RFC 1918 private subnets, your local LAN services, and cloud metadata endpoints (`169.254.169.254`), exposing internal databases and cloud IAM credentials.
4. **Host Pivoting via Workspace Mounts**: A rogue agent can silently drop a malicious hook into `/workspace/.git/hooks/` or a malicious configuration into `/workspace/.claude/` that executes arbitrary code on your host upon your next manual commit.

**agentcage eliminates each of these attack surfaces:**

| Attack Surface | Naive Setup / Container | agentcage Defense |
|---|---|---|
| **Outbound Data Exfiltration** | Allowed to any IP / host | **Default-deny egress**. All non-HTTP traffic is dropped. Only allowlisted domains resolve or connect. |
| **Credential Theft** | Real keys sit in memory/env | **Zero-leak placeholders**. Real keys stay on host. Proxy injects credentials on the wire and redacts responses. |
| **LAN / Metadata Probing** | Can probe `192.168.x.x` & `169.254.169.254` | **Blocked**. Private IPs, loopbacks, and wildcard DNS tricks (`*.nip.io` IP-encoding) are structurally rejected. |
| **Host Pivoting via Mounts** | Can write malicious git hooks to host | **Pivot masks**. Writable project mounts automatically hide `.git/hooks/` and `.claude/` via tmpfs overlays. |
| **Silent Policy Violations** | Unaudited and uninspected | **Deep inspection & watcher**. Real-time entropy / secret / payload scanning, structured audit logs, and HAR exports. |

---

## System Architecture

Every cage consists of a workload sandbox and an egress gateway container operating on an isolated, internal-only bridge network (`Internal=true`), orchestrated by systemd user quadlets (Linux) or microVM supervisors (macOS):

```
┌─────────────────────────── HOST MACHINE ───────────────────────────────────────────┐
│                                                                                    │
│  agentcage CLI (create, run, exec, domain, secret, watcher, doctor)                │
│  State & Encrypted Secrets: ~/.config/agentcage/ (systemd-creds / Apple Keychain)  │
│                                                                                    │
│  ┌───────────── Private Network: <name>-net (10.89.X.0/24, Internal=true) ─────┐   │
│  │                                                                             │   │
│  │   ┌──────────────────────────┐          ┌────────────────────────────────┐  │   │
│  │   │  WORKLOAD SANDBOX (cage) │          │  EGRESS GATEWAY (egress)       │  │   │
│  │   │  10.89.X.2               │          │  10.89.X.10                    │  │   │
│  │   │                          │          │                                │  │   │
│  │   │  Coding Agent Process    │          │  dnsmasq (DNS Filter)          │  │   │
│  │   │  • UID 1000 (workload)   │  DNS/53  │  • Allowlisted zones → upstream│  │   │
│  │   │  • All capabilities drop │─────────▶│  • Blocked zones → 198.51.100.1│  │   │
│  │   │  • No-new-privileges     │          │    (TEST-NET-2 sinkhole)       │  │   │
│  │   │  • Read-only rootfs      │  TCP     │                                │  │   │
│  │   │  • Pivot masks on .git   │─────────▶│  mitmdump (Inspecting Proxy)   │  │   │
│  │   │                          │          │  • :8080 HTTP proxy            │  │   │
│  │   │  Decoy Placeholders:     │          │  • :8443 transparent (iptables)│  │   │
│  │   │  agentcage:secret:KEY:…  │          │                                │  │   │
│  │   │                          │          │  Proxy Addon & Controls:       │  │   │
│  │   │  Trusted Per-Cage CA:    │          │  • Inspector Chain             │  │   │
│  │   │  /certs/ca-cert.pem      │          │    (domain, secrets, entropy,  │  │   │
│  │   └──────────────────────────┘          │     content-type, body-size)   │  │   │
│  │                │                        │  • Wire Secret Injector        │  │   │
│  │                │ Default route via      │  • Inbound Response Redactor   │  │   │
│  │                └──────▶ 10.89.X.10      │  • Policy API (agentcage.local)│  │   │
│  │                                         │  • Traffic Watcher Agent       │  │   │
│  │                                         │  • Protocol Relays (IMAP/SMTP) │  │   │
│  │                                         └───────────────┬────────────────┘  │   │
│  └─────────────────────────────────────────────────────────│───────────────────┘   │
│                                                            │ iptables:             │
│                                                            │  FORWARD policy DROP  │
│                                                            │  IPv6 FORWARD DROP    │
└────────────────────────────────────────────────────────────│───────────────────────┘
                                                             ▼
                                                     INTERNET / APIs
                                                (allowlisted domains only)
```

### Outbound Request Lifecycle

When an agent performs an HTTPS call (e.g. `GET https://api.anthropic.com/v1/messages`):

1. **DNS Resolution**: The agent queries `dnsmasq`. If `anthropic.com` is in the allowlist, it forwards upstream and returns the real A/AAAA record. If not, it resolves to `198.51.100.1` (RFC 5737 TEST-NET-2 sinkhole) so unauthorized destinations fail immediately with clear policy errors instead of silent timeouts.
2. **Transparent Interception**: TCP port 443 is redirected by kernel `iptables PREROUTING` into the local `mitmdump` proxy on port 8443.
3. **Identity & Anti-Rebinding Checks**: The proxy enforces strict SNI ↔ Host equality and verifies that the resolved peer IP is a globally routable public address (blocking DNS rebinding to internal subnets).
4. **Inspector Chain**: Offloaded to worker threads to keep latency minimal:
   - `domain`: Verifies destination against permanent allowlists and active runtime grants.
   - `secrets`: Scans payloads with regex patterns; detects raw credentials leaving the sandbox.
   - `entropy`: Computes Shannon entropy (0–8 bits/byte) to catch encrypted or obfuscated exfiltration payloads.
   - `content-type`: Flags base64 blobs disguised inside JSON or plain text.
   - `body-size`: Enforces strict request body limits.
5. **Wire Secret Injection**: Decoy placeholders (`agentcage:secret:ANTHROPIC_API_KEY:<hex>`) are substituted with the real secret on the wire — **only** for matching allowlisted domains and credential-bearing headers (`Authorization`, `x-api-key`, etc.).
6. **Upstream Request**: Sent to upstream servers over verified TLS.
7. **Inbound Redaction**: The proxy scans the server response; any echoed real secret is redacted back to its placeholder before reaching the cage.
8. **Forensic Logging**: Decisions are written to `audit.jsonl` and full HTTP transactions are recorded in `capture.jsonl` (exportable as HAR 1.2).

---

## Key Features

- **Strict Default-Deny Egress**: Private container network (`Internal=true`). L4 `iptables` drop all forwarding by default; IPv6 is disabled outright. Non-HTTP protocols (TCP/UDP/ICMP) are dropped unless explicitly permitted in `cage.yaml`.
- **Zero-Leak Secret Injection**: The sandboxed agent never touches your real API keys. Decoy entropic tokens are swapped on the wire outbound and redacted inbound. An agent tricked into printing its environment only leaks harmless placeholders.
- **Encrypted At-Rest Storage**: Real secrets are encrypted at rest using `systemd-creds` on Linux and the macOS Keychain on Darwin.
- **Autonomous Policy API**: Sandboxed agents can query `https://agentcage.local/v1/allowlist` to discover reachable domains and `POST /v1/allowlist/requests` to request dynamic domain access with a justification. An in-egress LLM **Decider Agent** scrutinizes the justification and grants temporary runtime access without operator intervention.
- **Autonomous Traffic Watcher**: An opt-in background LLM agent re-examines audit logs and capture windows to detect subtle exfiltration, beaconing, or injection patterns, and can autonomously revoke compromised runtime grants in real time.
- **Host Pivot Protection**: Project mounts hide `.git/hooks/` and `.claude/` via tmpfs masks (`notmpcopyup` and `tmpcopyup`), preventing agents from planting malicious git hooks that execute on your host machine.
- **Dual-Perspective HAR Forensics**: Export complete network traffic via `agentcage cage har` loadable into Chrome DevTools — choosing either the **inbound** view (safe to share, placeholders only) or **outbound** view (wire-level debugging with real injected values).
- **First-Class Scaffolds**: Pre-packaged, hardened templates for popular coding agents (Claude Code, Pi, OpenAI Codex, OpenClaw, and minimal base distros).

---

## Backend Support Matrix

agentcage automatically selects the optimal isolation backend for your host machine:

| Feature | `container` | `apple-container` | `vm` |
|---|---|---|---|
| **Host OS** | Linux | macOS 26+ (Apple Silicon) | macOS (Intel / older), Linux |
| **Runtime Engine** | Rootless Podman + systemd quadlets | Apple `container` microVMs | Dedicated Lima microVM + Podman |
| **Default On** | Linux | macOS 26+ ASi with Apple `container` | Other macOS environments |
| **Isolation Strength** | Linux namespaces + cgroups v2 | Hardware virtualization (Apple VZ) | Hardware virtualization (QEMU / VZ) |
| **Startup Speed** | Sub-second (fastest) | Fast (~1–2s) | Moderate (~10–15s VM boot) |
| **Host Volume Mounts** | Full host bind mounts (`rw`/`ro`) | Full bind mounts under `$HOME` | Staged copies / sshfs |
| **Read-Only Rootfs** | Supported (`read_only: true`) | Always RW (warned) | Supported |
| **Pivot Masks (`.git/hooks`)**| Supported via tmpfs | Emulated via tmpcopyup | Supported via tmpfs |
| **Encrypted Secret Store** | `systemd-creds` (TPM2 / host key) | macOS Keychain | macOS Keychain / `systemd-creds` |
| **Named Volumes** | Supported | Not supported | Supported |
| **Published Host Ports** | Supported (reverse mitmproxy) | Reached via direct vmnet IP | Supported |
| **Policy API & Watcher** | Supported | Supported | Supported |
| **HAR 1.2 Capture** | Supported | Supported | Supported |

---

## 30-Second Quickstart

### 1. Install agentcage

Using the official one-line installer:

```bash
curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
```

Or install via Python package managers (`uv` or `pip`):

```bash
uv tool install agentcage
# or
pip install agentcage
```

Verify your host environment:

```bash
agentcage doctor
```

### 2. Ephemeral Session (One-Command Run)

Run an interactive coding agent in a temporary, sandboxed cage with your repository mounted. The cage is automatically torn down when the session exits:

```bash
# Run Claude Code in the current project directory (prompts for key securely)
agentcage run claude-code -s ANTHROPIC_API_KEY

# Run OpenAI Codex with an explicit project directory
agentcage run codex --project ~/code/my-repo -s OPENAI_API_KEY

# Run Pi terminal harness with a specific isolation backend
agentcage run pi --project . --isolation vm -s OPENAI_API_KEY
```

### 3. Persistent Cage

For continuous background agents, services, or multi-session workflows:

```bash
# 1. Generate a commented cage.yaml configuration
agentcage init my-cage --scaffold claude-code

# 2. Store your API key encrypted on the host
agentcage secret set my-cage ANTHROPIC_API_KEY

# 3. Build, generate quadlets, and start the cage
agentcage cage create -c cage.yaml

# 4. Attach an interactive shell or exec commands
agentcage cage exec my-cage -- claude
agentcage cage shell my-cage

# 5. Monitor and audit live traffic
agentcage cage logs my-cage -f
agentcage cage audit my-cage --follow --decision blocked
```

---

## CLI Cheat Sheet & Aliases

agentcage provides top-level aliases for all common operations (`agentcage run`, `agentcage exec`, `agentcage ls`, etc.):

```text
CAGE LIFECYCLE
  agentcage init [NAME] [--scaffold NAME]     Scaffold a new cage.yaml
  agentcage run <scaffold> -s KEY [--project] Launch ephemeral agent session (auto-cleanup)
  agentcage cage create -c cage.yaml          Build, install, and start persistent cage
  agentcage cage update NAME [--no-cache]     Rebuild images and restart cage
  agentcage start | stop | restart NAME       Control cage lifecycle (skips rebuild)
  agentcage destroy NAME [-y] [--keep-secrets]Stop containers, remove quadlets and state
  agentcage prune [-y]                        Remove exited interactive/ephemeral cages
  agentcage verify NAME                       Run runtime health diagnostics

WORKLOAD INTERACTION
  agentcage exec NAME -- CMD                  Execute a command inside the cage container
  agentcage exec NAME -s egress -- CMD        Execute a command inside the egress proxy
  agentcage shell NAME [--as-root]            Open an interactive shell in the cage
  agentcage logs NAME -f [-s egress]          Stream systemd journalctl container logs

EGRESS DOMAINS & GRANTS
  agentcage domain list NAME                  List allowlisted, blocked, and passthrough domains
  agentcage domain add NAME DOMAIN...         Add domains to filter (--expires-in 2h)
  agentcage domain rm NAME DOMAIN             Remove a domain from the filter list
  agentcage cage grants NAME list             List active runtime Policy API grants
  agentcage cage grants NAME promote DOMAIN   Promote dynamic grant into static cage.yaml
  agentcage cage grants NAME revoke DOMAIN    Immediately drop dynamic runtime grant
  agentcage cage grants NAME sync             Reconcile expired or accepted grants

SECRET MANAGEMENT
  agentcage secret set NAME KEY [--declare]   Store secret encrypted on host
  agentcage secret list NAME                  List stored secrets and injection bindings
  agentcage secret rm NAME KEY                Remove a stored secret
  agentcage secret rotate-placeholders NAME   Mint fresh random 128-bit decoy placeholders

FORENSICS & WATCHER
  agentcage cage audit NAME --summary         View aggregated proxy inspection statistics
  agentcage cage audit NAME -f -d blocked     Stream blocked traffic decisions in real time
  agentcage cage har NAME -o audit.har        Export HTTP flows as HAR 1.2 (inbound/outbound)
  agentcage watcher status NAME               Inspect background traffic watcher state
  agentcage watcher findings NAME             Review suspicious flow findings and revocations

CONFIG & MAINTENANCE
  agentcage edit NAME                         Open cage.yaml in $EDITOR with live validation
  agentcage doctor                            Check host dependencies and backend health
  agentcage scaffold list | show | create     Manage built-in and custom scaffolds
  agentcage cage backup NAME -o backup.tar.gz Backup cage configuration and state
  agentcage cage restore BACKUP.tar.gz        Restore or clone cage from backup archive
```

---

## Built-In Scaffolds

Scaffolds package container definitions, volume mounts, and network policies tailored to specific agent harnesses:

| Scaffold | Alias | Lifecycle | Description |
|---|---|---|---|
| `claude-code` | `claude` | interactive | Anthropic Claude Code CLI. Pre-configures `anthropic.com` allowlist, injects `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN`, and masks `.git/hooks` and `.claude/`. |
| `codex` | — | interactive | OpenAI Codex CLI. Allowlists `api.openai.com`, injects `OPENAI_API_KEY`. |
| `pi` | — | interactive | Pi.dev autonomous terminal coding harness. Pre-configured for Anthropic/OpenAI keys or in-cage OAuth login. |
| `openclaw` | — | service | Autonomous agent harness with browser automation and local web gateway (`127.0.0.1:18789`). Supports nested containers and named volume caching. |
| `ubuntu` | — | interactive | Clean Ubuntu Linux environment with package management. |
| `debian` | — | interactive | Minimal Debian base sandbox. |
| `arch` | — | interactive | Minimal Arch Linux sandbox with `pacman`. |
| `busybox` | — | interactive | Ultra-lightweight container for testing egress rules and scripts. |

Custom scaffolds can be created, edited, and shared across your team using `agentcage scaffold create my-scaffold --from claude-code`.

---

## Configuration Quick Reference (`cage.yaml`)

agentcage configurations use standard YAML (`cage.yaml`):

```yaml
name: my-agent
isolation: container         # container | apple-container | vm (default: auto)
lifecycle: service           # service | interactive | ephemeral

container:
  image: node:22-slim
  command: ["bash"]
  user: 1000:1000
  read_only: true
  drop_capabilities: [ALL]
  no_new_privileges: true
  volumes:
    - ".:/workspace:rw"
  tmpfs:
    - "/tmp:rw,noexec,nosuid,size=512m"

domains:
  mode: allowlist
  allow:
    - api.anthropic.com
    - github.com
    - registry.npmjs.org
  passthrough: []            # Raw TCP TLS passthrough (bypasses MITM inspection)

secrets:
  backend: auto              # systemd-creds (Linux) or keychain (macOS)

secret_injection:
  - env: ANTHROPIC_API_KEY
    inject_to:
      - api.anthropic.com
    inject_headers: true
    inject_body: false

agents:
  decider:
    enable: true             # In-egress autonomous LLM decider for Policy API
  watcher:
    enable: true             # Background LLM auditor for traffic anomaly detection
    interval_seconds: 300
    auto_revoke: true

capture:
  enable_har: true
  max_body_size: 1048576     # 1 MB body capture limit
```

Full configuration reference: [docs/reference/configuration.md](docs/reference/configuration.md).

---

## Documentation Index

Explore the complete technical documentation in [`docs/`](docs/README.md):

* **[Get Started](docs/get-started/install.md)**: Detailed installation guides, distribution packages, prerequisites, and a step-by-step [Quickstart Tutorial](docs/get-started/quickstart.md).
* **[Architecture & Concepts](docs/explain/architecture.md)**: Deep dive into network namespaces, [Isolation Backends](docs/explain/isolation-backends.md), the 8-layer [Security Model](docs/explain/security-model.md), the [Policy API](docs/explain/policy-api.md), and the [Traffic Watcher](docs/explain/traffic-watcher.md).
* **[Reference Manuals](docs/reference/configuration.md)**: Complete specifications for [`cage.yaml`](docs/reference/configuration.md), the [CLI Manual](docs/reference/cli.md), the [Policy API HTTP Spec](docs/reference/policy-api.md), [Scaffolds](docs/reference/scaffolds.md), and [Secrets Management](docs/reference/secrets.md).
* **[How-To Guides](docs/how-to/run-agent-harnesses.md)**: Practical operational recipes for [Running Agent Harnesses](docs/how-to/run-agent-harnesses.md), [Managing Egress & Domains](docs/how-to/manage-egress-and-domains.md), [Troubleshooting & Diagnostics](docs/how-to/troubleshooting.md), [Backup & Restore](docs/how-to/backup-and-restore.md), and [Custom Inspectors](docs/how-to/custom-inspectors.md).

---

## Security & Disclosure

agentcage is an active defense-in-depth security harness. While it drastically reduces the threat surface of autonomous code execution, security is a continuous discipline. Always review project mounts, domain allowlists, and passthrough grants.

If you discover a security vulnerability in agentcage, please report it privately according to our [Security Policy](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE).
