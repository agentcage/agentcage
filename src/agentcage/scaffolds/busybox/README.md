# busybox

Minimal busybox cage for testing agentcage primitives — no AI agent, no extra tools, no outbound network by default.

Image: `docker.io/library/busybox:latest` (single static binary, ~5 MB).

## Quick start

```bash
agentcage init mycage --scaffold busybox
agentcage cage create -c cage.yaml
agentcage cage exec mycage -- sh
```

Or one-shot:

```bash
agentcage run busybox
```

## What you get

- `sleep infinity` keeps the container alive; you drop in via `cage exec`.
- `${PROJECT_DIR}:/workspace:rw` is the only volume mount.
- Domain allowlist is empty — every outbound request is blocked by the proxy. Add hosts under `domains.allow` in `cage.yaml` to test specific paths.
- No secrets pre-injected. A commented-out `GITHUB_TOKEN` block is left in `cage.yaml` as a starting point.

## Use cases

- Smoke-testing agentcage's proxy / DNS / network policy without the noise of a coding agent.
- Confirming that blocked domains return 403 and allowed domains return 200.
- Quick disposable shells for experimenting with cage features.
