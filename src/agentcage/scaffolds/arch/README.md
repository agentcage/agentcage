# arch

Minimal Arch Linux cage — no AI agent, no extra tools beyond what archlinux:latest ships, package mirrors pre-allowlisted so `pacman` works out of the box.

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

- The cage's startup command installs the agentcage MITM proxy CA into Arch's system trust store (`trust extract-compat`) so pacman trusts the intercepted TLS to the mirrors. Then `sleep infinity` keeps the container alive; you drop in via `cage exec`.
- `${PROJECT_DIR}:/workspace:rw` is the only volume mount.
- Domain allowlist pre-allows `pkgbuild.com` (covers `fastly.mirror.pkgbuild.com` and `geo.mirror.pkgbuild.com` via subdomain matching) and `archlinux.org`. Everything else is blocked by the proxy until you add it under `domains.allow` in `cage.yaml`.
- Cage runs as root with the minimum `add_capabilities` for `pacman` to install packages (`CHOWN`, `FOWNER`, `DAC_OVERRIDE`, `SETUID`, `SETGID`).
- `pacman -Sy && pacman -S curl` works out of the box.
- No secrets pre-injected. A commented-out `GITHUB_TOKEN` block is left in `cage.yaml` as a starting point.

## Use cases

- Testing agentcage behavior on a larger, more "real" Linux base than alpine/busybox.
- Confirming that blocked domains return 403 and allowed domains return 200.
- Testing pacman-based package install flows under the proxy.
