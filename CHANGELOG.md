# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.2]: https://github.com/agentcage/agentcage/releases/tag/v0.1.2
[0.1.0]: https://github.com/agentcage/agentcage/releases/tag/v0.1.0
