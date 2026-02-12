# Basic example

A minimal lobstercage cage that sandboxes a Node.js agent behind the inspecting proxy. No API keys or secrets needed -- uses httpbin.org to demonstrate proxy behavior.

## Usage

```bash
cd /path/to/lobstercage

# Create and start the cage
AGENT_DIR=$(pwd)/examples/basic/agent lobstercage cage create -c examples/basic/config.yaml

# View the agent output
journalctl --user -u basic-cage -e

# Tear down when done
lobstercage cage destroy basic
```

## What it demonstrates

1. **Allowed request** -- GET to httpbin.org succeeds (HTTP 200)
2. **Blocked request** -- GET to evil.com is denied (HTTP 403, domain not in allowlist)
3. **Secret leak detection** -- POST containing a fake API key is blocked (HTTP 403, secret detected)
4. **Clean POST** -- POST with harmless data to an allowed domain succeeds (HTTP 200)

See [Configuration Reference](../../docs/configuration.md) for all settings.
