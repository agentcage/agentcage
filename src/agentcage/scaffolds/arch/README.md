# arch

Minimal Arch Linux cage — no AI agent, no extra tools, no outbound network by default.

Image: `docker.io/library/archlinux:latest` (~150 MB, includes bash, coreutils, pacman).

## Quick start

```bash
agentcage init mycage --scaffold arch
agentcage cage create -c cage.yaml
agentcage cage exec mycage -- bash
```

Or one-shot:

```bash
agentcage run arch
```

## What you get

- `sleep infinity` keeps the container alive; you drop in via `cage exec`.
- `${PROJECT_DIR}:/workspace:rw` is the only volume mount.
- Domain allowlist is empty — every outbound request is blocked by the proxy. Add hosts under `domains.allow` in `cage.yaml` to test specific paths.
- No tools beyond what archlinux:latest ships. To `pacman -Syu` you'll need to allowlist the mirror hosts (`geo.mirror.pkgbuild.com` or whatever your `/etc/pacman.d/mirrorlist` resolves to).
- No secrets pre-injected. A commented-out `GITHUB_TOKEN` block is left in `cage.yaml` as a starting point.

## Use cases

- Testing agentcage behavior on a larger, more "real" Linux base than alpine/busybox.
- Confirming that blocked domains return 403 and allowed domains return 200.
- Testing pacman-based package install flows under the proxy.
