# alpine

Minimal Alpine Linux cage for testing agentcage primitives — no AI agent, no extra tools, no outbound network by default.

Image: `docker.io/library/alpine:latest` (~7 MB, includes `sh`, `apk`, busybox userland).

## Quick start

```bash
agentcage init mycage --scaffold alpine
agentcage cage create -c cage.yaml
agentcage cage exec mycage -- sh
```

Or one-shot:

```bash
agentcage run alpine
```

## What you get

- `sleep infinity` keeps the container alive; you drop in via `cage exec`.
- `${PROJECT_DIR}:/workspace:rw` is the only volume mount.
- Domain allowlist is empty — every outbound request is blocked by the proxy. Add hosts under `domains.allow` in `cage.yaml` to test specific paths.
- No tools beyond Alpine's base. Need `curl`? `apk add --no-cache curl` (you'll need to allowlist `dl-cdn.alpinelinux.org` first).
- No secrets pre-injected. A commented-out `GITHUB_TOKEN` block is left in `cage.yaml` as a starting point.

## Use cases

- Smoke-testing agentcage's proxy / DNS / network policy.
- Confirming that blocked domains return 403 and allowed domains return 200.
- Testing apk-based package install flows under the proxy.
