# alpine

Minimal Alpine Linux cage — no AI agent, no extra tools beyond Alpine's base, package mirror pre-allowlisted so `apk` works out of the box.

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
- Domain allowlist pre-allows `alpinelinux.org` (subdomains included → `dl-cdn.alpinelinux.org` works). Everything else is blocked by the proxy until you add it under `domains.allow` in `cage.yaml`.
- Cage runs as root with the minimum `add_capabilities` for `apk` to install packages (`CHOWN`, `FOWNER`, `DAC_OVERRIDE`, `SETUID`, `SETGID`).
- `apk update && apk add curl` works out of the box.
- No secrets pre-injected. A commented-out `GITHUB_TOKEN` block is left in `cage.yaml` as a starting point.

## Use cases

- Smoke-testing agentcage's proxy / DNS / network policy.
- Confirming that blocked domains return 403 and allowed domains return 200.
- Testing apk-based package install flows under the proxy.
