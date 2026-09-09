# How-To: Run Agent Harnesses

agentcage provides pre-configured scaffolds for leading AI coding agents. This guide provides recipes and best practices for running Claude Code, Pi, OpenAI Codex, and OpenClaw inside hardened sandboxes.

---

## 1. Running Anthropic Claude Code

The `claude-code` scaffold (aliased as `claude`) packages Anthropic's Claude Code CLI.

### Quick Ephemeral Session
To run a one-shot session in your current repository:

```bash
cd ~/code/my-project
agentcage run claude-code -s ANTHROPIC_API_KEY
```

### Authentication Options
Claude Code supports two authentication paths:

#### Option A: Direct API Key (Recommended)
Pass `-s ANTHROPIC_API_KEY` when starting the session:
```bash
agentcage run claude-code -s ANTHROPIC_API_KEY
```

#### Option B: Web OAuth Login
If you authenticate via your Anthropic console web login:
1. Create a persistent cage:
   ```bash
   agentcage init my-claude --scaffold claude-code
   agentcage cage create -c cage.yaml
   ```
2. Open an interactive shell and run the login flow:
   ```bash
   agentcage cage exec my-claude -- claude /login
   ```
   *The OAuth flow authenticates through `claude.ai` and `anthropic.com`, which are allowlisted by default.*

### Protective Controls Applied
- **Allowlist**: Pre-configured for `api.anthropic.com`, `claude.ai`, `statsig.anthropic.com`, and package registries (`npmjs.org`, `github.com`).
- **Pivot Protection**: Automatically masks `/workspace/.git/hooks/` and `/workspace/.claude/` using tmpfs overlays. Claude Code cannot plant malicious git hooks on your host.

---

## 2. Running Pi.dev Terminal Coding Agent

The `pi` scaffold packages the Pi.dev autonomous coding harness.

### Quick Ephemeral Session
Run Pi on your current repository:

```bash
agentcage run pi --project . -s OPENAI_API_KEY
# Or with an Anthropic key:
agentcage run pi --project . -s ANTHROPIC_API_KEY
```

### Passing Extra Flags to Pi
To forward CLI arguments directly to the agent binary, append `--` followed by your flags:

```bash
agentcage run pi --project . -s OPENAI_API_KEY -- -m gpt-5.6-sol --thinking high
```

---

## 3. Running OpenAI Codex CLI

The `codex` scaffold runs OpenAI's Codex agent in an interactive terminal.

### Quick Ephemeral Session
```bash
agentcage run codex --project ~/code/my-repo -s OPENAI_API_KEY
```

### Pre-Configured Policies
- **Allowlist**: Permits `api.openai.com`, `cdn.openai.com`, and standard package registries.
- **Secret Substitution**: Swaps `OPENAI_API_KEY` placeholders only on outbound requests to OpenAI endpoints.

---

## 4. Running OpenClaw (Browser Automation & Web UI)

OpenClaw is a autonomous agent platform featuring headless browser automation and a local web dashboard.

### Creating a Persistent OpenClaw Service
Because OpenClaw operates as a continuous background daemon with a local web UI, run it as a persistent service:

```bash
# 1. Initialize OpenClaw configuration
agentcage init openclaw-agent --scaffold openclaw

# 2. Store your LLM API keys
agentcage secret set openclaw-agent ANTHROPIC_API_KEY
agentcage secret set openclaw-agent OPENAI_API_KEY

# 3. Build and launch the cage
agentcage cage create -c cage.yaml
```

### Accessing the Web Dashboard
OpenClaw publishes its web interface locally to port `18789`:
- Open `http://127.0.0.1:18789` in your host browser.
- Inbound traffic passes through agentcage's reverse gateway into the sandboxed container.

### Running Nested Containers
OpenClaw supports running nested Docker/Podman containers for software builds:
- The scaffold pre-configures `container.nested_containers: true` and mounts a dedicated named volume for inner image caches.

---

## 5. Running Custom Agent Scripts

To run custom Python, Node.js, or Go agent scripts inside a hardened sandbox:

```bash
# 1. Initialize a clean base sandbox
agentcage init custom-runner --image python:3.12-slim

# 2. Configure domains in cage.yaml:
# domains:
#   allow:
#     - api.anthropic.com
#     - api.github.com

# 3. Create the cage
agentcage cage create -c cage.yaml -s MY_API_KEY

# 4. Execute your script inside the sandbox
agentcage exec custom-runner -- python /workspace/agent_script.py
```

---

## Next Steps

- **[Manage Egress & Domains](manage-egress-and-domains.md)** — Add or remove domain access for your agent.
- **[Troubleshooting Guide](troubleshooting.md)** — Debugging common agent connection issues.
