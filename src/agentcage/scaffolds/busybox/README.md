# busybox

Minimal busybox cage — no AI agent, no extra tools, no outbound network by default.

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

## Limitations

**No package manager.** `busybox:latest` ships only the busybox static binary — no `apk`, `apt`, `pacman`, or `opkg`. You cannot install additional tools at runtime. If you need to test package installs or pull in something like `curl`, use the [debian scaffold](../debian/README.md) instead (`apt`-based, still small).

## Use cases

- Smoke-testing agentcage's proxy / DNS / network policy without the noise of a coding agent or even a package manager.
- Confirming that blocked domains return 403 and allowed domains return 200, using busybox's built-in `wget`.
- The absolute floor for "what's the smallest cage I can spin up to poke at agentcage".
