# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-05-03

### Fixed
- e2e Phase 8: `8.4 self-restart SIGUSR1` rewritten for openclaw 2026.5+. The upstream change collapses the supervisor + `openclaw-gateway` worker into a single `openclaw` process and switches to in-process restart in containers (deliberate — `restart mode: in-process restart (container: use in-process restart to keep PID 1 alive)`), so the previous PID-delta witness can no longer fire. The new test sends SIGUSR1 to `^openclaw$`, asserts openclaw logs `received SIGUSR1; restarting` (proves the signal was authorized via `commands.restart`, which defaults to true), and probes the gateway readiness endpoint to confirm recovery.

### Removed
- `agentcage completions <shell>` wrapper command. Click ships native shell completion via the `_AGENTCAGE_COMPLETE=<shell>_source agentcage` env-var protocol; the wrapper added zero capability over upstream and created a maintenance surface that could drift from Click. See [Shell completion](docs/cli.md#shell-completion) in the CLI reference for the env-var pattern.
- `agentcage cage edit` — trivial `click.edit()` wrapper. Use `$EDITOR <path>` (path visible via `cage show`) followed by `agentcage cage update <name>` instead.

## [0.10.6] - 2026-04-26

### Changed
- `agentcage domain add` now accepts multiple domains in a single invocation (e.g. `agentcage domain add my-cage foo.com bar.com baz.com`). Config is written and the cage is reloaded exactly once for the whole batch, replacing the previous one-reload-per-domain behavior. Single-domain calls are unchanged.

## [0.10.5] - 2026-04-21

### Fixed
- openclaw scaffold: default `openclaw.json` now sets `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: true`. openclaw's browser plugin refuses every navigation when `HTTP_PROXY`/`HTTPS_PROXY` is set (error: `Navigation blocked: strict browser SSRF policy cannot be enforced while env proxy variables are set`). In agentcage, egress is already policed by the mitm proxy + domain allowlist + inspectors, so this guard is redundant and purely blocks the browser tool. Opting out restores browser-tool functionality; the cage's own egress controls remain authoritative.

## [0.10.4] - 2026-04-20

### Added
- `cage update` auto-bumps scaffold-declared untagged base image tags on every run, tracking upstream instead of freezing on the tag current at `cage create`. Scaffold.yaml's `build_args` is authoritative: untagged = auto-bump, explicit tag = respect the author's pin. Offline updates preserve the existing pin (regression-critical).
- `infer_scaffold_from_image()` discovers the scaffold name for pre-existing cages from the `localhost/agentcage-scaffold-<NAME>:...` image naming convention, so legacy cages benefit without manual migration. New cages get the scaffold persisted to `metadata.json` on create.
- `resolve_build_args()` in `agentcage.registry` centralizes tag resolution previously duplicated across `cli.py` update, `services.py` build, and `init.py` scaffold setup.

### Changed
- `cage update` preserves existing metadata instead of overwriting — `scaffold` and `network_octet` survive updates.
- openclaw scaffold compatibility with `ghcr.io/openclaw/openclaw:2026.4.15+` base images: skip the `npm install --omit=dev` step when runtime deps are already hoisted (new upstream layout); add `/app/node_modules/openclaw -> /app` symlink so the bundled matrix extension's `openclaw/plugin-sdk/...` self-references resolve.
- openclaw scaffold `entrypoint.sh` degrades gracefully when `/home/node/.pki` isn't writable: the mitmproxy CA install is best-effort and a stderr warning is emitted so operators can see TLS inspection for browser traffic is degraded.
- `_SCAFFOLD_IMAGES` hardcoded dict removed; scaffold.yaml is now the single source of truth for scaffold → upstream-image mapping.
- `render_config()` and `run_scaffold_setup()` no longer thread an `image_tag` through call sites — tag resolution happens inside `run_scaffold_setup` via the shared helper.

### Fixed
- Suppress the noisy `warning: could not resolve latest tag for localhost/...` that fired on every `cage update` for scaffold-built local image refs that never exist in a real registry.

## [0.10.3] - 2026-03-27

### Improved
- E2E test reliability: parallelize test phases, add local mock httpbin server, and fail-fast on first error

## [0.10.2] - 2026-03-22

### Fixed
- OpenClaw container no longer crashes on SIGUSR1-based self-restart: tini is now PID 1 with a restart loop in `entrypoint.sh`, so config changes via the web UI don't kill the container
- `cage update` automatically refreshes scaffold build files (Containerfile, entrypoint.sh) and updates the container command — existing cages pick up fixes with just `agentcage cage update <name>`
- `cage create`, `cage update -c`, and `agentcage init` now copy all build context files alongside the Containerfile, not just the Containerfile itself

## [0.10.1] - 2026-03-21

### Added
- `agentcage doctor` command: diagnose system health, check prerequisites, and provide distro-aware remediation hints
- Custom scaffolds: `agentcage scaffold create/list/show/edit/delete/export` for user-defined cage templates
- Three-tier scaffold resolution: project-local → user → built-in
- `agentcage update` command: self-update the CLI from PyPI
- `-i/--interactive-domains` flag on `agentcage run`: approve blocked domains interactively at runtime

### Fixed
- Stabilize flaky E2E tests (4.3 domain hot-reload, 5.2 subnet isolation) with exponential backoff and proxy readiness checks
- `_version_tuple` crash on pre-release version strings
- `scaffold edit` now opens the config file instead of the directory

## [0.10.0] - 2026-03-21

### Added
- Coding agent scaffolds: pre-built templates for common agent frameworks
- `agentcage run` command: one-shot cage creation, build, and execution
- Polished `agentcage run` CLI output: box-drawn banner, spinner during builds, ✓/✗ status lines, compact info summary
- `agentcage run -v/--verbose` flag to show full build output
- `agentcage run` VM isolation support (`--isolation vm`)
- Version banner on `agentcage` and `agentcage --help`

### Fixed
- Build scaffold images inside VM instead of host Podman when using VM isolation

## [0.9.2] - 2026-03-20

### Added
- Modular E2E test suite (`tests/e2e/`) with 7 phases covering container and VM modes
- E2E CI workflow — container tests (phases 1-6) run on every PR via GitHub Actions

### Fixed
- `domain add`/`domain rm` crash: DNS quadlet regenerated with wrong subnet IP when hash collision shifted the octet at deploy time
- HAR capture `Permission denied` in rootless Podman — capture directory ownership now set via `ExecStartPre` with virtiofs fallback
- VM mount isolation: replaced blanket `~` mount with targeted read-only/read-write mounts; `~/.ssh`, `~/.gnupg`, `~/.aws` no longer accessible inside VMs
- `cage destroy` no longer deletes the shared config directory
- Shell-quote filenames in VM quadlet deployment commands
- Journal access uses group-based permissions instead of world-readable

### Security
- Lima VM template no longer exposes host SSH keys, GPG keys, or AWS credentials
- Config directory (`~/.config/agentcage`) mounted read-only in VMs
- Volumes targeting sensitive directories (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`) are rejected with a clear error
- Default port binding changed from `0.0.0.0` to `127.0.0.1`
- Narrow `net.ipv4.ip_unprivileged_port_start` sysctl from 0 to 80
- Validate container image references in config (reject `latest` with registry, block `docker.io/library` prefix typos)
- Pin Ubuntu cloud image digests in Lima template
- Restrict permissions on `pending_secrets.json`

## [0.9.1] - 2026-03-18

### Added
- `cage create --set-secret KEY=VALUE` — set secrets during creation, no separate restart needed
- `VmPodman` — secret commands route through the VM's Podman for VM-mode cages

### Changed
- Secret commands (`set`, `list`, `rm`) now require the cage to exist first
- Removed `agentcage build` CLI group
- Install script: macOS skips Podman and Podman machine (uses Lima instead)
- Scaffold guides updated: create cage first, then set secrets

### Fixed
- Shell injection in `_bridge_secrets` (piped via stdin)
- Command injection in `os.system()` (`shlex.quote`)
- Heredoc injection in quadlet transfer (base64 encoding)
- `cage exec/shell` checks `isatty()` in all code paths
- Host Podman calls guarded for VM mode
- VmConfig defaults aligned between dataclass and `load_config()`

## [0.9.0] - 2026-03-18

### Added
- **Lima VM backend** — new `isolation: vm` mode using Lima to manage Linux VMs with Podman + quadlets inside. Works on both Linux (QEMU/KVM) and macOS (Apple Virtualization.framework).
- **macOS support** — agentcage now runs on macOS via the VM backend. Only `limactl` is required on the host; Podman runs inside the VM.
- `cage exec` and `cage shell` work for VM-mode cages via `limactl shell` + `podman exec`
- `cage logs` and `cage audit` work for VM-mode cages via `limactl shell` + `journalctl`
- Lima prerequisites check for QEMU and `/dev/kvm` on Linux
- Secret bridging from host Podman store into VM's Podman store
- End-to-end test for Lima VM backend (`tests/e2e_lima.sh`)

### Changed
- **BREAKING**: `isolation: firecracker` is removed. Existing configs are silently migrated to `isolation: vm`. The `agentcage firecracker setup` command is removed.
- VM defaults: 4 vCPUs, 4 GiB RAM (previously 2/2 GiB for Firecracker)
- `Sysctl=net.ipv4.ip_unprivileged_port_start=0` added to proxy container for low-port binding in reverse proxy mode
- Host Podman is optional for VM mode — only needed for `agentcage secret set`

### Removed
- Firecracker backend and all associated code (binaries, kernel, network, rootfs, secrets, vmconfig)
- `agentcage firecracker setup` CLI command
- TAP/bridge networking, `agentcage-nethelper`, root/sudo requirement for VM isolation

### Fixed
- `cage shell` now checks `isatty()` before passing `-it` flags (fixes piped commands)

## [0.8.1] - 2026-03-14

### Added
- **`cage stop` / `cage start`** — stop and start cages without destroying them
- **`cage show`** — inspect cage config and status (aliases: `describe`, `inspect`)
- **`cage shell`** — open an interactive shell in a cage container (auto-detects bash/sh)
- `delete` alias for `cage destroy` (kubectl compatibility)
- `--json-lines` hidden alias on `cage audit`, `--json` hidden alias on `cage har` for cross-command consistency
- `-n/--max-entries` on `cage audit` (replaces `--lines`; `--lines` kept as hidden alias)

### Changed
- **`cage logs` no longer follows by default** — use `-f/--follow` to stream logs in real time (matches systemctl/kubectl/podman behavior). `--no-follow` is kept as a hidden no-op for backward compatibility
- `domain` group help text changed from "allowlists" to "filters" (the group handles both allow and block modes)
- `cage audit` primary option renamed from `--lines` to `--max-entries` (consistent with `cage har`)
- Secret and domain commands now show `NAME` instead of `CAGE_NAME` in `--help` output

## [0.8.0] - 2026-03-14

### Added
- **`container.build` config** — `cage create` and `cage update` now automatically rebuild the main container image from a local Containerfile when `container.build.containerfile` is set, with `args` for `--build-arg` pass-through and automatic latest-tag resolution for untagged remote image refs
- Containerfile is copied to the state directory so `cage update` (without `-c`) can rebuild from the stored file

### Changed
- Scaffold container images renamed from `agentcage-{name}` to `agentcage-scaffold-{name}` for clarity
- Update Firecracker binary from v1.14.2 to v1.15.0

## [0.7.1] - 2026-03-06

### Fixed
- `brave_api_key` pattern used wrong prefix (`BSA` instead of `BSAI`), causing false positives on base64 text in POST bodies to `api.anthropic.com`
- `perplexity_key` pattern used hex charset instead of alphanumeric and wrong length (64→48), missing real keys
- `openai_key` pattern now requires `T3BlbkFJ` marker present in all real OpenAI keys
- `anthropic_key` pattern now requires `sk-ant-api03-` or `sk-ant-admin01-` prefix
- `huggingface_token` tightened to alphabetic-only, exact 34 chars
- `github_token` tightened to Base62 (no underscores), exact 36 chars
- `github_pat` tightened to exact structure per GitHub docs
- `aws_access_key` tightened to Base32 charset (`[A-Z2-7]`)
- `firecrawl_key` tightened to hex-only, exact 32 chars
- `telegram_bot_token` widened bot ID range to support older bots
- `discord_bot_token` added `O` prefix, tightened part 1 length

## [0.7.0] - 2026-03-06

### Added
- OpenClaw scaffold now supports nested containers and headless Chrome out of the box
- New `Containerfile` in openclaw scaffold layers podman, Chromium runtime deps, and NSS tools onto the upstream openclaw base image
- `build_image()` accepts `build_args` for passing `--build-arg` to podman builds
- Scaffold build system supports `containerfile` key (alternative to `git`) for local image builds
- Domain allowlist includes container registries (Docker Hub, GHCR), Playwright/Chrome CDNs, and OS package repos
- mitmproxy CA certificate is imported into both the system CA store and Chrome's NSS database at startup
- Secrets inspector with Docker registry JWT auth token exemption

### Changed
- OpenClaw scaffold resources bumped to 8 GB RAM / 4 CPUs with larger tmpfs mounts
- `render_config()` returns `(content, image_tag)` tuple to share resolved tag with build step

## [0.6.4] - 2026-03-04

### Changed
- Update Firecracker binary from v1.14.1 to v1.14.2
- Remove obsolete Node.js/undici check from update-deps script (proxy-fetch patches were removed in 0.6.3)

## [0.6.3] - 2026-03-04

### Fixed
- `cage create` no longer emits a spurious "Failed to restart" warning for the storage volume service when `nested_containers` is not enabled (#21)
- `secret set` no longer leaks the podman secret ID to stdout (#20)
- `cage har` error message now shows the exact config snippet needed to enable capture instead of a vague hint (#19)

### Added
- Commented-out `capture:` config block in all scaffold templates (openclaw, picoclaw, nanoclaw) for discoverability
- Documentation index (`docs/README.md`) with links to all docs and setup guides

### Changed
- Updated tagline to "Don't let your agent phone home."

## [0.6.2] - 2026-03-02

### Fixed
- Fix 502 Bad Gateway on inbound reverse-proxy requests — the transparent-mode host rewrite was overwriting the configured upstream destination with the client's Host header, causing mitmproxy to connect to itself

## [0.6.1] - 2026-03-01

### Fixed
- `cage verify` no longer reports a false egress `[FAIL]` on images without curl or node — adds python3 `urllib` as a third fallback and reports `[WARN]` when no HTTP client is available (#16)

## [0.6.0] - 2026-02-27

### Added
- **TLS passthrough** (`domains.passthrough`) — listed domains bypass mitmproxy TLS interception, allowing protocols that break under MITM (WhatsApp/Noise Protocol, gRPC with cert pinning) to connect directly while still enforcing DNS-level domain filtering
  - Passthrough domains auto-added to DNS allowlist for resolution
  - mitmproxy `ignore_hosts` set via `running()` hook with port-aware regex (`host:port` matching)
  - Hot-reload: passthrough changes picked up via config file mtime check
- `domain add --passthrough` / `domain rm --passthrough` CLI flags for managing passthrough domains
- PicoClaw setup guide

### Changed
- **Domain config redesign** — `domains:` section now uses explicit `allow:` / `block:` / `passthrough:` keys instead of `mode:` + `list:`. The old format is still accepted for backward compatibility
  - `allow:` → allowlist mode (replaces `mode: allowlist` + `list:`)
  - `block:` → blocklist mode (replaces `mode: blocklist` + `list:`)
  - Both `allow` + `block` → validation error
  - All examples, scaffolds, and templates migrated to new format
  - `domain list` shows `[passthrough]` markers
  - `domain add`/`rm` auto-migrates legacy `mode`+`list` configs on write
- Domain inspector accepts both new (`allow`/`block`) and legacy (`mode`/`list`) config keys

## [0.5.0] - 2026-02-27

### Added
- **Transparent HTTP/HTTPS proxy interception** — all outbound port 80/443 traffic from the cage is now intercepted at the network level via iptables REDIRECT rules, regardless of whether the application uses `HTTP_PROXY` env vars. This covers Go, Rust, Node.js `fetch()`, and any other runtime without per-language patching.
  - Default route added to the cage's network namespace via `nsenter` (ExecStartPost)
  - iptables PREROUTING rules redirect ports 80/443 to mitmproxy's transparent listener on port 8443
  - mitmproxy runs with `--mode transparent@8443` alongside the regular forward proxy on port 8080
  - Proxy container gets `NET_ADMIN` capability and `iptables` package
- Port 8443 conflict check — container port 8443 is now rejected (conflicts with transparent proxy)
- `flow.request.pretty_host` normalization in addon.py — transparent mode flows now resolve to the real hostname (from Host header / TLS SNI) instead of the raw destination IP

### Removed
- **Node.js proxy-fetch.mjs patch** — replaced by network-level transparent interception; `NODE_OPTIONS`, `proxy-fetch.mjs`, `package.json`, `package-lock.json`, and `node_modules/undici` are no longer needed
- `_file_sha256()` helper in CLI (only used by removed patch verification)
- `npm ci` step during cage create/update (undici dependency installation)

### Changed
- Proxy container image now installs `iptables` via apt-get (Debian-based mitmproxy image)
- Proxy image build requires additional capabilities (`CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`) for apt-get in rootless builds
- Firecracker mode: removed `NODE_OPTIONS` env var from VM startup script (transparent proxy for firecracker is a future task)

## [0.4.1] - 2026-02-26

### Added
- **Generic scaffold metadata** — scaffolds can now declare `build`, `provision`, and `next_steps` in a `scaffold.yaml` file, replacing hardcoded per-scaffold logic in the CLI
  - `build`: auto-clone and build container images (with `cap_add` support) during `agentcage init`
  - `provision`: copy config files from the scaffold directory to the user's home
  - `next_steps`: templated post-init instructions shown to the user
- PicoClaw scaffold now auto-builds the image and provisions `~/.picoclaw/config.json` during init

### Fixed
- `~` in volume host paths (e.g. `~/.picoclaw/config.json:/app/config.json`) was not expanded, causing podman to create a named volume instead of a bind mount
- `podman.build_image()` now accepts `containerfile=None` to auto-detect Dockerfile/Containerfile

## [0.4.0] - 2026-02-26

### Added
- **Nested container support (podman-in-podman)** — `container.nested_containers: true` enables running podman/docker inside a cage, for AI agent frameworks (like NanoClaw) that spawn their own containers
  - Minimal capability elevation (SYS_ADMIN, MKNOD, SETUID, SETGID) instead of `--privileged`
  - Docker CLI shim translates `docker` commands to `podman` inside the cage
  - Inner containers inherit cage network isolation (proxy + DNS filtering still apply)
  - Persistent storage volume for inner podman state
  - Rejects `firecracker` + `nested_containers` combination (not supported)
- `agentcage build nested-base` command — builds `localhost/agentcage-nested` base image with podman, fuse-overlayfs, crun, uidmap, and slirp4netns
- NanoClaw scaffold (`--scaffold nanoclaw`) — pre-configured for AI agent frameworks that spawn Docker containers, with ANTHROPIC_API_KEY injection and Docker registry domains
- Self-contained scaffold directory (`scaffolds/nanoclaw/`) with `build.sh`, `build-agent.sh`, `preload-agent.sh`, Containerfile, and README — decouples NanoClaw from the core CLI
- Scaffold discovery from `scaffolds/*/cage.yaml.j2` in addition to `templates/presets/`
- Nested container verification in `cage verify` — checks inner podman and docker shim availability

### Removed
- `agentcage build nanoclaw` and `agentcage build nanoclaw-agent` CLI subcommands — replaced by scaffold scripts
- Auto-preload of `nanoclaw-agent` during `cage create` / `cage update` — use `preload-agent.sh` instead

## [0.3.19] - 2026-02-26

### Fixed
- OpenClaw scaffold: configure `gateway.controlUi.allowedOrigins` so the gateway starts without errors on newer OpenClaw versions that require explicit origin config for non-loopback binds
- Add LAN access instructions (0.0.0.0 binding) to the scaffold template comments

## [0.3.18] - 2026-02-25

### Fixed
- Reverse proxy forwarded `X-Forwarded-Proto: http` and rewrote `Origin` with `http://` even when the browser connected via HTTPS, causing 502 errors in upstream apps (e.g. OpenClaw WebSocket upgrades and origin validation)

## [0.3.17] - 2026-02-25

### Fixed
- `cage update` no longer fails with "port already in use" when the running cage's own ports are bound
- Port conflict suggestion now suggests port+1 (e.g. 18790) instead of port+10000 (e.g. 28789)
- OpenClaw scaffold: restrict permissions on `.openclaw/` (mode 700) and `openclaw.json` (mode 600) to prevent world-readable config
- Stale `--list-presets` references in install script and README (renamed to `--list-scaffolds` in v0.3.14)

## [0.3.16] - 2026-02-25

### Fixed
- Scaffold templates (`--scaffold openclaw/picoclaw`) rendered port as `None` when `--port` was not specified
- Firecracker rootfs build failed with "permission denied" when `SUDO_USER` differs from `SUDO_UID` user

### Added
- Ports documentation in configuration reference with format table and examples

## [0.3.15] - 2026-02-25

### Added
- Hot-reload proxy config — `domain add/rm` no longer restarts cage services; the proxy detects config file changes via mtime and reloads inspectors in-place

### Changed
- Renamed `cage reload` to `cage restart` (`reload` kept as alias)
- `domain add/rm` prints "Proxy updated." instead of restarting the cage

### Fixed
- Proxy container startup failure under rootless Podman when cert volume was inaccessible due to `/home/mitmproxy` being root-owned mode 700 in the upstream mitmproxy image

## [0.3.14] - 2026-02-25

### Added
- `--port` option on `agentcage init` — set the host port for scaffold templates (e.g. `--scaffold openclaw --port 28789`)
- Port conflict detection in `cage create` and `cage update` — checks host ports with `socket.bind()` before building, with clear error messages and suggested alternatives
- Port format and range (1–65535) validation in config validation

### Changed
- Renamed `--preset` / `--list-presets` CLI flags to `--scaffold` / `--list-scaffolds`
- Renamed "preset" to "scaffold" in all user-facing text, docs, and template comments

### Fixed
- `cage create` no longer fails with a cryptic rootlessport error when a host port is already in use — the conflict is detected early with actionable guidance
- Incomplete cleanup when `cage create` fails after quadlet install
- Build-failure orphan state, `--keep-secrets` flag on `cage destroy`

## [0.3.13] - 2026-02-23

### Added
- `cage backup` command — create a compressed tarball of a cage's config, named volumes, capture logs, and optionally secrets (`--include-secrets`)
- `cage restore` command — restore a cage from a backup tarball, with support for cloning to a different name (`--name`), overwriting (`--force`), and deferred start (`--no-start`)

## [0.3.12] - 2026-02-23

### Added
- `cage exec` command — run commands inside cage containers with alias expansion (`agentcage cage exec <name> -- <command>`)
- `exec_aliases` config field — define shorthand commands expanded by `cage exec` (e.g. `openclaw` → `node openclaw.mjs`)
- `help` config field — inline guidance printed after `cage create` and `cage update`
- `systemd_exec` Jinja filter for proper quoting of `Exec=` arguments containing spaces
- OpenClaw preset: auto-configures `trustedProxies` in `openclaw.json` on first start
- OpenClaw preset: `exec_aliases` and `help` fields for streamlined device pairing workflow

### Fixed
- Reverse-proxy WebSocket frames were blocked by the domain inspector — the proxy now correctly identifies reverse-proxy WebSocket flows and skips domain checks, fixing "domain not in allowlist" errors for inbound WebSocket connections (e.g. OpenClaw Control UI)

## [0.3.11] - 2026-02-23

### Added
- CLI command aliases: `cage ls`/`ps`/`status` → `list`, `cage rm` → `destroy`, `secret ls` → `list`, `domain ls` → `list`
- `agentcage completions <shell>` command for bash/zsh/fish tab completion
- `cage edit` command to open stored config in `$EDITOR`, validate, and reload if running
- `AGENTCAGE_VERSION` env var injected into cage containers

### Changed
- Config file convention renamed from `config.yaml` to `cage.yaml`

## [0.3.10] - 2026-02-21

### Fixed
- Reverse proxy now preserves the browser's original `Host` header (`keep_host_header=true`), eliminating the need to whitelist internal container IPs in OpenClaw
- Reverse proxy now sends `X-Forwarded-For` and `X-Forwarded-Proto` headers so upstream apps (e.g. OpenClaw `gateway.trustedProxies`) can identify real client IPs
- Removed unused `OPENCLAW_GATEWAY_TOKEN` from OpenClaw preset, CLI output, and docs

### Added
- Documentation for reverse proxy trusted proxies configuration and device pairing workflow (`docs/openclaw.md`)

## [0.3.9] - 2026-02-21

### Added
- HAR capture support for full request/response forensics (`capture.enable_har` config option)

### Fixed
- Firecracker socat port-forward retries now scale with `timeout_start_sec` instead of hardcoded 90, preventing premature timeout for large images

## [0.3.8] - 2026-02-21

### Fixed
- Literal secret values sent to authorized `inject_to` domains are no longer blocked — the policy check now recognizes that post-injection requests legitimately contain real values for their target domain (HTTP and WebSocket)
- Proxy image builds now use `--no-cache` to ensure code changes are always picked up on deploy

### Changed
- Audit table direction column shows `INBOUND`/`OUTBOUND` (was `in`/`out`) with header `DIRECTION` (was `DIR`)
- Audit entries include `port`, `path`, `source` (inbound IP), `secrets_injected`, and `secrets_redacted` fields
- Secret inject/redact methods now return lists of secret names acted on, surfaced in audit logs

## [0.3.7] - 2026-02-21

### Added
- `agentcage init` command with `--preset` support for scaffolding config files
- PicoClaw preset (`--preset picoclaw`) — ultra-lightweight Go-based AI assistant with config.json volume mount, minimal resources (256 MB / 0.5 CPU), and domain allowlist for AI providers and messaging channels
- OpenClaw preset (`--preset openclaw`) — moved from static `examples/openclaw/` to Jinja2 template with cage name substitution
- Generic init scaffold for custom setups (`agentcage init <name>` without `--preset`)
- `--list-presets` flag to discover available presets

## [0.3.6] - 2026-02-21

### Fixed
- Install script: `sudo agentcage firecracker setup` fails on Ubuntu because sudo resets PATH — now uses the full binary path
- Install script: PATH warning after install was never shown because the script's own PATH exports made the check always pass
- Install script: removed nonexistent `init` subcommand suggestion, added correct `agentcage init` and `--list-presets` examples

## [0.3.5] - 2026-02-21

### Security
- WebSocket frames now undergo secret injection (outbound) and redaction (inbound), closing a gap where the cage could learn real secret values from WebSocket responses
- Outbound requests and WebSocket frames containing literal secret values are now blocked, preventing exfiltration when the agent learns a real secret value outside the placeholder system

## [0.3.4] - 2026-02-20

### Added
- `cage audit` CLI command — query, filter, and summarize proxy audit logs with support for real-time streaming and JSON output for alerting pipelines

### Changed
- Unified severity levels across `cage logs` and `cage audit` — both now use `--severity` with values `debug`, `info`, `warning`, `error`, `critical`
- Inspector severity values renamed: `medium` → `warning`, `high` → `error` (aligns with standard logging levels)
- Config `logging.level` and per-service overrides now accept `warning` instead of `warn` (and add `critical`)

### Removed
- `cage logs --level` flag (replaced by `--severity`)
- Inspector severity values `low` and `medium` (replaced by `warning`; `high` replaced by `error`)

## [0.3.3] - 2026-02-20

### Fixed
- Secret placeholder policy violations are now flagged instead of blocked — the placeholder is left in place (preventing secret leakage) while the request continues through downstream inspectors

## [0.3.1] - 2026-02-20

### Fixed
- DNS resolution fails on Ubuntu 24.04 and other systemd-resolved hosts — loopback nameservers (127.0.0.53) are now filtered from `/etc/resolv.conf` and real upstream servers are read from `/run/systemd/resolve/resolv.conf` instead (#5)

## [0.3.0] - 2026-02-20

### Security
- Entropy inspector now checks URL path segments for high-entropy data, closing an exfiltration channel that bypassed body inspection
- Rate limiting enabled by default (10 req/s, burst 50) — previously disabled unless explicitly configured
- All secret detection regex patterns now have upper-bounded quantifiers to prevent ReDoS on crafted inputs

## [0.2.0] - 2026-02-20

### Added
- **Firecracker microVM isolation** — run the same three-container topology inside a dedicated microVM with its own Linux kernel, providing hardware-level isolation via KVM (`isolation: firecracker`)
- `firecracker setup` CLI command to download and verify Firecracker binaries and kernel
- Auto-download of Firecracker binary and kernel with SHA-256 checksum verification
- File-based secret store and secrets drive for Firecracker VMs
- Persistent data drive for Firecracker VMs (survives cage updates)
- Graceful VM shutdown via SendCtrlAltDel with trap-based container cleanup
- VM restart support with automatic Podman storage reset
- **Inbound port inspection** — ports exposed via `ports:` config are now routed through the mitmproxy inspector chain in both container and Firecracker modes
- Socat-based port forwarding for Firecracker VMs (replaces iptables DNAT)
- Dependency update script and bumped pinned dependencies

### Changed
- Extracted `Backend` protocol; CLI now dispatches to `ContainerBackend` or `FirecrackerBackend` based on `isolation` config
- Firecracker commands require `sudo` directly (removed `agentcage-nethelper` setuid binary)
- Reverse proxy binds to `0.0.0.0` and skips domain inspector for inbound flows

### Fixed
- Secrets and startup failures in Firecracker VMs
- Firecracker networking: dual-homed TAP, INPUT firewall rules for VM-to-host connectivity
- Firecracker image loading, gzip handling, UID mapping, and port forwarding
- E2E tests use real user's HOME when running via sudo

### Docs
- Firecracker MicroVM isolation guide (`docs/firecracker.md`)
- Updated architecture, security, and README to cover both isolation modes and threat model differences

## [0.1.2] - 2026-02-17

### Fixed
- Cage DNS resolution: bind-mount resolv.conf pointing to dnsmasq instead of relying on `DNS=` directive (which was overridden by aardvark-dns) and `ExecStartPost` (which failed on read-only containers)
- SSRF guard compatibility: dnsmasq returns placeholder IP (198.51.100.1, RFC 5737 TEST-NET-2) for non-allowlisted domains instead of NXDOMAIN, so DNS-pinned SSRF guards no longer crash

### Changed
- Proxy container resolves DNS via upstream servers directly instead of through dnsmasq
- Cage `HTTP_PROXY` uses proxy static IP (10.89.0.11) instead of container name
- `dns_servers` defaults to host DNS servers (from `/etc/resolv.conf`) when omitted from config

### Removed
- `dns.lookup` / `dns/promises.lookup` patches from proxy-fetch.mjs (no longer needed since DNS always resolves)

## [0.1.0] - 2026-02-17

### Added

- CLI with `cage create`, `cage update`, `cage destroy`, `cage list`, `cage verify`, `cage reload`, and `cage logs` commands
- Secret management with `secret set`, `secret list`, and `secret rm` commands
- Domain management with `domain add`, `domain list`, and `domain rm` commands
- Network isolation via rootless Podman with `--internal` network (no internet gateway for the agent)
- Domain allowlist/blocklist filtering at both proxy and DNS layers
- Secret injection — the cage never sees real secrets; the proxy swaps placeholders transparently
- 19 built-in secret detection patterns (OpenAI, Anthropic, AWS, GitHub, Google, Slack, Stripe, and more)
- Built-in `allow_to_domains` mappings so standard secrets reach their provider domains without configuration
- Shannon entropy analysis for detecting encrypted/compressed exfiltration payloads
- Content-type mismatch and base64 blob detection
- Per-host token-bucket rate limiting
- WebSocket frame inspection (secrets, entropy)
- Custom inspector support via Python files
- Structured JSON audit logging
- Container hardening defaults (read-only root, dropped capabilities, no-new-privileges)
- Node.js `fetch()` proxy patch via `--import` loader
- Supply chain hardening (pinned image digests, lockfile integrity, patch file SHA-256 verification)
- systemd quadlet generation with proper dependency ordering
- OpenClaw example configuration and setup guide

[0.8.1]: https://github.com/agentcage/agentcage/releases/tag/v0.8.1
[0.8.0]: https://github.com/agentcage/agentcage/releases/tag/v0.8.0
[0.7.1]: https://github.com/agentcage/agentcage/releases/tag/v0.7.1
[0.7.0]: https://github.com/agentcage/agentcage/releases/tag/v0.7.0
[0.6.4]: https://github.com/agentcage/agentcage/releases/tag/v0.6.4
[0.6.3]: https://github.com/agentcage/agentcage/releases/tag/v0.6.3
[0.6.2]: https://github.com/agentcage/agentcage/releases/tag/v0.6.2
[0.6.1]: https://github.com/agentcage/agentcage/releases/tag/v0.6.1
[0.6.0]: https://github.com/agentcage/agentcage/releases/tag/v0.6.0
[0.5.0]: https://github.com/agentcage/agentcage/releases/tag/v0.5.0
[0.4.1]: https://github.com/agentcage/agentcage/releases/tag/v0.4.1
[0.4.0]: https://github.com/agentcage/agentcage/releases/tag/v0.4.0
[0.3.19]: https://github.com/agentcage/agentcage/releases/tag/v0.3.19
[0.3.18]: https://github.com/agentcage/agentcage/releases/tag/v0.3.18
[0.3.17]: https://github.com/agentcage/agentcage/releases/tag/v0.3.17
[0.3.16]: https://github.com/agentcage/agentcage/releases/tag/v0.3.16
[0.3.15]: https://github.com/agentcage/agentcage/releases/tag/v0.3.15
[0.3.14]: https://github.com/agentcage/agentcage/releases/tag/v0.3.14
[0.3.13]: https://github.com/agentcage/agentcage/releases/tag/v0.3.13
[0.3.12]: https://github.com/agentcage/agentcage/releases/tag/v0.3.12
[0.3.11]: https://github.com/agentcage/agentcage/releases/tag/v0.3.11
[0.3.10]: https://github.com/agentcage/agentcage/releases/tag/v0.3.10
[0.3.9]: https://github.com/agentcage/agentcage/releases/tag/v0.3.9
[0.3.8]: https://github.com/agentcage/agentcage/releases/tag/v0.3.8
[0.3.7]: https://github.com/agentcage/agentcage/releases/tag/v0.3.7
[0.3.6]: https://github.com/agentcage/agentcage/releases/tag/v0.3.6
[0.3.5]: https://github.com/agentcage/agentcage/releases/tag/v0.3.5
[0.3.4]: https://github.com/agentcage/agentcage/releases/tag/v0.3.4
[0.3.3]: https://github.com/agentcage/agentcage/releases/tag/v0.3.3
[0.3.1]: https://github.com/agentcage/agentcage/releases/tag/v0.3.1
[0.3.0]: https://github.com/agentcage/agentcage/releases/tag/v0.3.0
[0.2.0]: https://github.com/agentcage/agentcage/releases/tag/v0.2.0
[0.1.2]: https://github.com/agentcage/agentcage/releases/tag/v0.1.2
[0.1.0]: https://github.com/agentcage/agentcage/releases/tag/v0.1.0
