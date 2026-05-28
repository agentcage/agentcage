# Basic example

A minimal agentcage cage that sandboxes a Node.js agent behind the inspecting proxy. No secrets needed -- uses httpbin.org to demonstrate proxy behavior.

The agent runs an HTTP server on port 3000 with endpoints you can curl from the host.

## Usage

```bash
cd /path/to/agentcage

# Create and start the cage
AGENT_DIR=$(pwd)/examples/basic/agent agentcage cage create -c examples/basic/cage.yaml

# Wait a few seconds for startup, then interact with the agent
curl http://localhost:3000/

# Tear down when done
agentcage cage destroy basic
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check with proxy env info and endpoint list |
| `/fetch?url=<url>` | GET | Proxy a fetch to the given URL (demonstrates domain filtering) |
| `/check-secret` | POST | Forward POST body to httpbin.org/post (demonstrates secret detection) |

## What it demonstrates

1. **Allowed request** -- `curl localhost:3000/fetch?url=https://httpbin.org/get` succeeds (HTTP 200)
2. **Blocked request** -- `curl localhost:3000/fetch?url=https://evil.com/exfil` is denied (HTTP 403, domain not in allowlist)
3. **Secret leak detection** -- `curl -X POST -d 'sk-ant-FAKE01-abc' localhost:3000/check-secret` is blocked (HTTP 403, secret detected)
4. **Clean POST** -- `curl -X POST -d '{"data":"safe"}' localhost:3000/check-secret` succeeds (HTTP 200)

## E2E test

```bash
bash tests/e2e/run.sh
```

See [Configuration Reference](../../docs/reference/configuration.md) for all settings.
