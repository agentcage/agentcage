# debian

Minimal Debian cage — no AI agent, only `ca-certificates` added on top of the base image so `apt` trusts the agentcage MITM proxy, package mirrors pre-allowlisted so `apt-get` works out of the box.

Image: `docker.io/library/debian:stable-slim` (~75 MB; includes bash, coreutils, apt).

## Quick start

```bash
agentcage init mycage --scaffold debian
agentcage cage create -c cage.yaml
agentcage cage exec mycage -- bash
```

Or one-shot:

```bash
agentcage run debian
```

## What you get

- The cage's startup command installs the agentcage MITM proxy CA into Debian's system trust store (`update-ca-certificates`) so apt trusts the intercepted TLS to the mirrors. Then `sleep infinity` keeps the container alive; you drop in via `cage exec`.
- `${PROJECT_DIR}:/workspace:rw` is the only volume mount.
- Domain allowlist pre-allows `deb.debian.org` and `security.debian.org`. Everything else is blocked by the proxy until you add it under `domains.allow` in `cage.yaml`.
- Cage runs as root with the minimum `add_capabilities` for `apt` to install packages (`CHOWN`, `FOWNER`, `DAC_OVERRIDE`, `SETUID`, `SETGID`).
- `apt-get update && apt-get install -y curl` works out of the box.
- No secrets pre-injected. A commented-out `GITHUB_TOKEN` block is left in `cage.yaml` as a starting point.

## Use cases

- Testing agentcage on Debian (the upstream of many derivatives, including the node:22-slim image the coding-agent scaffolds use).
- Confirming that blocked domains return 403 and allowed domains return 200.
- Testing apt-based package install flows under the proxy.
