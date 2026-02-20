# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-02-20

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

[0.4.0]: https://github.com/agentcage/agentcage/releases/tag/v0.4.0
[0.3.3]: https://github.com/agentcage/agentcage/releases/tag/v0.3.3
[0.3.1]: https://github.com/agentcage/agentcage/releases/tag/v0.3.1
[0.3.0]: https://github.com/agentcage/agentcage/releases/tag/v0.3.0
[0.2.0]: https://github.com/agentcage/agentcage/releases/tag/v0.2.0
[0.1.2]: https://github.com/agentcage/agentcage/releases/tag/v0.1.2
[0.1.0]: https://github.com/agentcage/agentcage/releases/tag/v0.1.0
