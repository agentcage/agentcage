# debian

Minimal Debian cage — no AI agent, no extra tools, no outbound network by default.

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

- `sleep infinity` keeps the container alive; you drop in via `cage exec`.
- `${PROJECT_DIR}:/workspace:rw` is the only volume mount.
- Domain allowlist is empty — every outbound request is blocked by the proxy. Add hosts under `domains.allow` in `cage.yaml` to test specific paths.
- No tools beyond Debian's slim base. To `apt-get install` you'll need to allowlist `deb.debian.org` and `security.debian.org`.
- No secrets pre-injected. A commented-out `GITHUB_TOKEN` block is left in `cage.yaml` as a starting point.

## Use cases

- Testing agentcage on Debian (the upstream of many derivatives, including the node:22-slim image the coding-agent scaffolds use).
- Confirming that blocked domains return 403 and allowed domains return 200.
- Testing apt-based package install flows under the proxy.
