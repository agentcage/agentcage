"""Shared fixtures for agentcage tests."""

import textwrap

import pytest


@pytest.fixture
def minimal_yaml(tmp_path):
    """Write a minimal valid config and return its path."""
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent("""\
        name: test
        container:
          image: localhost/test:latest
    """))
    return str(p)


@pytest.fixture
def full_yaml(tmp_path):
    """Write a config with all fields populated and return its path."""
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent("""\
        name: myapp
        container:
          image: "node:22-slim"
          command: ["node", "/app/agent.js"]
          volumes:
            - "./agent:/app:ro"
          env:
            ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"
            STATIC_VAR: "hello"
          named_volumes:
            myapp-data: "/data:rw"
          tmpfs:
            - "/tmp:rw,noexec,nosuid,size=64M"
          ports:
            - "127.0.0.1:3000:3000"
          podman_secrets:
            - MY_API_KEY
            - INJECTED_KEY
          user: ""
          memory: "4g"
          cpus: "2.0"
          read_only: false
          drop_capabilities: []
          add_capabilities:
            - NET_BIND_SERVICE
          no_new_privileges: false
          security_label_disable: false
          restart: "no"
          restart_sec: 0
          timeout_start_sec: 300
          timeout_stop_sec: 60
        secret_injection:
          - env: INJECTED_KEY
            placeholder: "{{INJECTED_KEY}}"
            inject_to:
              - api.example.com
        dns_servers:
          - 100.100.100.100
          - 1.1.1.1
    """))
    return str(p)


@pytest.fixture
def openclaw_yaml(tmp_path):
    """Write an openclaw-style config and return its path."""
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent("""\
        name: openclaw
        container:
          image: "ghcr.io/openclaw/openclaw:latest"
          command:
            - "sh"
            - "-c"
            - "test -f /home/node/.openclaw/openclaw.json || printf '{} ' > /home/node/.openclaw/openclaw.json; exec node openclaw.mjs gateway --allow-unconfigured --bind lan --auth password"
          volumes:
            - "${HOME}/openclaw-workspace:/workspace:rw"
          named_volumes:
            openclaw-state: "/home/node/.openclaw:rw"
          tmpfs:
            - "/tmp:rw,noexec,nosuid,size=64M"
            - "/home/node/.npm:rw,size=128M"
            - "/scratch:rw,exec,nosuid,size=256M"
          ports:
            - "127.0.0.1:18789:18789"
          env:
            OPENCLAW_DISABLE_BONJOUR: "1"
          podman_secrets:
            - OPENCLAW_GATEWAY_PASSWORD
          memory: "4g"
          cpus: "2.0"
          timeout_start_sec: 120
        secret_injection:
          - env: ANTHROPIC_API_KEY
            placeholder: "{{ANTHROPIC_API_KEY}}"
            inject_to:
              - anthropic.com
        domains:
          allow:
            - anthropic.com
            - npmjs.org
            - github.com
        exec_aliases:
          openclaw: ["node", "openclaw.mjs"]
        help: |
          Open http://localhost:18789 in your browser.
    """))
    return str(p)
