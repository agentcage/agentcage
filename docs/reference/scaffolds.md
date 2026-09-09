# Scaffolds Reference

A **scaffold** is a reusable template that packages a base container image, runtime dependencies, environment configurations, and network policies for a specific coding agent or base distribution.

Scaffolds power both one-shot ephemeral sessions (`agentcage run <scaffold>`) and declarative cage initialization (`agentcage init --scaffold <scaffold>`).

---

## Catalog of Built-In Scaffolds

agentcage includes hardened, pre-configured scaffolds for leading AI agent harnesses and base Linux distributions:

| Scaffold | Alias | Default Lifecycle | Description |
| :--- | :--- | :--- | :--- |
| **`claude-code`** | `claude` | `interactive` | Anthropic's Claude Code CLI. Pre-configures `anthropic.com` and `claude.com` allowlists, injects `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`, and masks `.git/hooks` and `.claude/`. |
| **`codex`** | — | `interactive` | OpenAI Codex CLI. Allowlists `api.openai.com` and injects `OPENAI_API_KEY`. |
| **`pi`** | — | `interactive` | Pi.dev autonomous terminal coding agent harness. Supports Anthropic/OpenAI keys or in-cage `/login`. |
| **`openclaw`** | — | `service` | Full-featured OpenClaw agent with browser automation and local web gateway (`127.0.0.1:18789`). Supports nested rootless containers and named volume caches. |
| **`ubuntu`** | — | `interactive` | Minimal Ubuntu Linux development environment with `apt` package management. |
| **`debian`** | — | `interactive` | Minimal Debian Linux base container. |
| **`arch`** | — | `interactive` | Minimal Arch Linux environment with `pacman`. |
| **`busybox`** | — | `interactive` | Minimal 5 MB container for rapid egress testing and script validation. |

---

## Anatomy of a Scaffold

Each scaffold is a self-contained directory containing three files:

```text
my-scaffold/
├── scaffold.yaml      # Scaffold metadata, declared secrets, and defaults
├── Containerfile      # OCI container image build definition
└── cage.yaml.j2       # Jinja2 template rendered into the final cage.yaml
```

### 1. `scaffold.yaml` (Metadata & Secret Declarations)
Defines the scaffold's parameters and required credentials:

```yaml
name: my-scaffold
description: "Custom Node.js agent scaffold with GitHub CLI"
aliases: ["node-agent"]
lifecycle: interactive

# Every secret declared here is mandatory when running `agentcage run`
secrets:
  - env: API_KEY
    description: "Production API access key"
  - env: GITHUB_TOKEN
    description: "GitHub personal access token"

# Default domains required for basic functionality
domains:
  allow:
    - api.github.com
    - registry.npmjs.org
```

### 2. `Containerfile` (Build Definition)
Specifies the workload container build layers:

```dockerfile
FROM node:22-slim

# Install system dependencies
RUN apt-get update && apt-get install -y git curl jq && rm -rf /var/lib/apt/lists/*

# Run as unprivileged UID 1000
USER 1000:1000
WORKDIR /workspace

CMD ["bash"]
```

### 3. `cage.yaml.j2` (Jinja2 Configuration Template)
Renders into `cage.yaml` when running `agentcage init`:

```yaml
name: {{ name }}
isolation: {{ isolation }}
lifecycle: {{ lifecycle }}

container:
  image: {{ image }}
  user: 1000:1000
  read_only: true
  drop_capabilities: [ALL]
  volumes:
    - ".:/workspace:rw"

domains:
  mode: allowlist
  allow:
    {% for domain in domains.allow %}
    - {{ domain }}
    {% endfor %}

secret_injection:
  {% for secret in secrets %}
  - env: {{ secret.env }}
    inject_headers: true
  {% endfor %}
```

---

## Scaffold Resolution Hierarchy

When you request a scaffold by name (e.g. `agentcage run my-scaffold`), agentcage searches directories in this strict order:

1. **Project Scaffolds (`<git-root>/.agentcage/scaffolds/<name>/`)**: Scaffolds checked into your repository. This allows teams to version-control project-specific agent environments.
2. **User Scaffolds (`~/.config/agentcage/scaffolds/<name>/`)**: Personal custom scaffolds stored in your user profile.
3. **Built-In Scaffolds**: Pre-packaged templates distributed with the agentcage package.

*A project-level scaffold overrides a user scaffold of the same name, which in turn overrides a built-in scaffold.*

---

## Authoring & Managing Custom Scaffolds

The `agentcage scaffold` command group provides tools for creating, editing, and managing custom scaffolds:

### 1. List Available Scaffolds
Lists all discovered scaffolds across project, user, and built-in paths:

```bash
agentcage scaffold list
```

### 2. Fork an Existing Scaffold
Create a new custom scaffold by cloning an existing template:

```bash
agentcage scaffold create my-custom-agent --from claude-code
```
This copies the scaffold files into `~/.config/agentcage/scaffolds/my-custom-agent/`.

### 3. Edit a Scaffold
Opens the scaffold template files in `$EDITOR`:

```bash
agentcage scaffold edit my-custom-agent
```

### 4. Inspect a Scaffold Manifest
Shows declared secrets, default domains, and metadata:

```bash
agentcage scaffold show my-custom-agent
```

### 5. Export a Scaffold
Exports a built-in or user scaffold to an arbitrary directory (e.g. to commit into a repository):

```bash
agentcage scaffold export claude-code -o ./.agentcage/scaffolds/claude-code
```

### 6. Delete a Custom Scaffold
Removes a custom scaffold from your user directory:

```bash
agentcage scaffold delete my-custom-agent -y
```

---

## Next Steps

- **[Run Agent Harnesses How-To](../how-to/run-agent-harnesses.md)** — Practical guides for running Claude Code, Pi, and Codex.
- **[Configuration Reference](configuration.md)** — Learn how `cage.yaml.j2` renders configuration keys.
