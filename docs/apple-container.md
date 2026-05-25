# Apple Container Isolation

`apple-container` isolation uses Apple's [`container`](https://github.com/apple/container) CLI on macOS 26+ Apple Silicon. Each cage runs in a single Apple `container` microVM (one kernel per cage, hypervisor boundary via Apple's Virtualization.framework). A small POSIX-sh supervisor takes PID 1 inside the microVM, stands up an in-microVM egress filter (mitmproxy + dnsmasq + iptables), then drops privileges before exec'ing the cage workload.

Introduced in **0.20**, reached functional parity with `container` / `vm` in **0.21** for everything users actually exercise (init → create → exec → audit / har / verify → backup / restore → secret-injection → domain-management → autostart → config validation). On macOS 26+ Apple Silicon hosts where the `container` CLI is installed, this is the **default** when `isolation:` is omitted from `cage.yaml`. Lima remains the default everywhere else.

## Why apple-container

Versus Lima on the same host:

- **~10–20× faster cage create** warm (~5s vs ~60s+ Lima warm). Apple microVMs boot in well under a second; Lima has to bring up a full Ubuntu cloud image.
- **~3× less RAM per cage.** A single microVM with one kernel vs Lima's full guest OS.
- **Same hypervisor boundary** — both use Virtualization.framework. The host-side trust boundary is identical.

Trade-offs:

- **macOS 26+ Apple Silicon only.** Older macOS, Intel Macs, and Linux all stay on Lima/container.
- **User cage image must be glibc-based** (debian, ubuntu, slim variants, distroless w/ apt). The bundled mitmproxy is a PyInstaller binary built against glibc; alpine/musl bases fail at wrapper-build time with a clear actionable error (see [Known gaps](#known-gaps-with-workarounds)).
- **One defense layer instead of two** for egress (see [Security model](#security-model) below).

## Architecture

Per cage, one Apple `container` microVM runs:

```
microVM (one kernel, isolated from host via Apple Virtualization.framework)
│
├── PID 1: /opt/agentcage/supervisor (POSIX sh, runs as root inside the µVM)
│   │
│   ├── stage 10  remount /proc with hidepid=2
│   ├── stage 20  parse cage CMD from /etc/agentcage/cage-cmd.json (jq @sh)
│   ├── stage 30  start dnsmasq (uid 201) → :53 forwarding to 1.1.1.1/8.8.8.8
│   ├── stage 40  start mitmproxy (uid 200) → transparent on :8080 with
│   │             /opt/agentcage/allowlist_addon.py
│   ├── stage 50  poll mitmproxy CA file AND listening socket (fail loud)
│   ├── stage 60  install proxy CA via update-ca-certificates;
│   │             mirror CA into /certs/ for cage.yaml command compatibility
│   ├── stage 70  point /etc/resolv.conf at 127.0.0.1
│   ├── stage 80  iptables: DROP OUTPUT, REDIRECT 80/443 → :8080 (excludes
│   │             uids 200/201 to avoid proxy/dns self-loop), allow lo:{8080,53},
│   │             allow uid 200/201 egress, kill IPv6
│   └── stage 90  capsh --no-new-privs --drop=all
│                 --user=$(getent passwd 1000 | cut -d: -f1)
│                 → exec the cage workload
│
├── dnsmasq      (uid 201) — only DNS path the cage has; filter-AAAA strips
│                            IPv6 records so clients don't waste time on
│                            unreachable AAAA addresses
├── mitmproxy    (uid 200) — egress filter + allowlist + {{SECRET}} injection +
│                            JSON audit log + capture.jsonl
└── cage workload (uid 1000 or image USER) — exactly zero capabilities,
                                              NoNewPrivs set, hidepid hides
                                              other UIDs' PIDs
```

The per-cage wrapper image (built by `AppleContainerBackend.build_artifacts` via `container build`) layers the supervisor + addons + dnsmasq + mitmproxy bundle (SHA256-pinned, fetched from `downloads.mitmproxy.org`) onto the user's cage image with an explicit `USER root` so the apt install step works even when the user image sets a non-root USER. The microVM also bind-mounts `~/.config/agentcage/apple-container/<cage>/logs/` to `/var/log/agentcage/` so `cage audit` and `cage har` can read proxy logs and capture JSONL from the host.

## Prerequisites

- macOS 26 or later
- Apple Silicon (arm64) — Intel Macs are not supported
- Apple's `container` CLI installed and apiserver started:

```bash
# Install the latest .pkg from apple/container releases
PKG=$(curl -fsSL https://api.github.com/repos/apple/container/releases/latest \
      | grep -oE 'https://github.com/apple/container/releases/download/[^"]+\.pkg' | head -1)
curl -fsSLO "$PKG" && sudo installer -pkg "$(basename "$PKG")" -target /

# Start the apiserver and let it install the recommended kernel
container system start --enable-kernel-install
```

`agentcage doctor` will tell you which prerequisite is missing if any of these aren't met.

## Usage

Once `container` is installed and the apiserver is running, agentcage uses it by default:

```bash
# isolation: defaults to apple-container on macOS 26+ ASi
agentcage run claude-code

# Or be explicit
agentcage init my-cage --isolation apple-container
```

To opt back into Lima on a macOS 26+ host, set `isolation: vm` explicitly in `cage.yaml`.

All cage subcommands work the same way they do on container / vm:

| Command | Behavior on apple-container |
|---|---|
| `cage create / start / stop / restart / destroy` | Routes through `container` CLI; per-cage state in `~/.config/agentcage/apple-container/<cage>/` |
| `cage exec / shell` | `container exec [-it] <cage> <cmd>` — see [`cage exec` runs as root](#cage-exec-runs-as-root-not-uid-1000) below |
| `cage logs` | `container logs [-f] <cage>` — combined supervisor / proxy / dns / workload stream |
| `cage audit` | Tails `<state>/<cage>/logs/audit.jsonl` (bind-mounted from the microVM); same filter machinery as container / vm. `--since` is post-parse only (see [Quirks](#quirks-worth-knowing)) |
| `cage har` | Reads `<state>/<cage>/logs/capture.jsonl` and renders HAR 1.2 JSON |
| `cage verify` | Service-status + CA / DNS routing / egress filtering probes via `container exec` |
| `cage backup / restore` | Backup tarball with config + capture + audit; secrets NOT serialized (see [secret backup](#cage-backup---include-secrets-rejected)) |
| `cage update` | Rebuilds the wrapper image and restarts the cage |
| `domain add / rm` | Auto-rebuilds the wrapper (allowlist is baked in at build time) and restarts the cage; change takes immediate effect |
| `secret list / set / rm` | Exits with a clear message — secrets are env-passed on apple-container, not stored in a secret store (see [secrets model](#secrets-are-env-passed-not-stored)) |

## Security model

The cage **workload** (PID 1 = whatever your `cage.yaml` `command` evaluates to) runs with:

| Property | Value | Verifiable in `/proc/1/status` |
|---|---|---|
| UID | image's uid-1000 user (`ubuntu`, `node`, `claude`, or auto-created `cage`) | `Uid: 1000 1000 1000 1000` |
| Capability sets | all empty | `CapInh/Prm/Eff/Bnd: 0000000000000000` |
| `NoNewPrivs` | set | `NoNewPrivs: 1` |
| `/proc` visibility | only own UID's PIDs | `hidepid=2` mount option |

Cage-side escape attempts that are blocked end-to-end (verified on macOS 26.3.2 + ASi from inside the workload's process tree):

- `iptables -F` → "Permission denied" (workload has no `CAP_NET_ADMIN`)
- `mount` syscall → denied (no `CAP_SYS_ADMIN`)
- TCP to non-80/443 port → DROPped by iptables
- UDP DNS to upstream (8.8.8.8) → DROPped by iptables; only path is dnsmasq on 127.0.0.1
- Connect to arbitrary loopback port (not 53 or 8080) → DROPped by iptables
- IPv6 fallback → killed at ip6tables + sysctl `disable_ipv6=1`
- TLS with `Host: evil.com` spoofed on connection to allowlisted host → 403 from proxy (addon uses SNI/dst, not Host header)
- Bypass via raw IP literal → 403 from proxy (allowlist applies to all hosts)

**`container exec` enters the cage as the image's default `USER` (typically root), NOT as the workload uid.** The supervisor's privilege drop applies only to the workload process tree. The CAP_NET_ADMIN / CAP_SYS_ADMIN the supervisor needed during stages 10-80 are still present in the cage's capability set, just not in the workload's. So an interactive `cage exec ubuntu02 -- bash` session CAN `iptables -F` and bypass the egress filter. This is by design — operator debug sessions need full visibility. The threat model treats the *workload* (the AI agent code) as untrusted, not the interactive operator.

The single defense-in-depth layer that's missing vs Lima: if iptables in the cage netns is somehow flushed (would require a supervisor bug or kernel CVE — the workload itself cannot do this), Lima's `<cage>-net` is a non-routed podman network so the cage still can't reach the internet. Apple custom networks always have NAT, so apple-container has no equivalent backstop. We compensate with shellcheck + stage-marker CI on the supervisor (`.github/workflows/supervisor.yml`) and manual macOS verification on supervisor changes.

## Known gaps with workarounds

Each item below is something an operator might reasonably expect to "just work" but doesn't — listed with the technical reason and a concrete workaround. All tracked in [#120](https://github.com/agentcage/agentcage/issues/120).

### Alpine / musl user images not supported

**Symptom.** `cage create` against `docker.io/library/alpine:*` fails with `exit 78` and a multi-line message:

```
agentcage apple-container does not yet support alpine/musl user images.
Status: the official mitmproxy PyInstaller bundle is glibc-only, and the
pip-install fallback fails because mitmproxy-rs requires cargo edition2024
(rustc >= 1.88) which alpine ships only in edge — too unstable for a
per-cage build dependency.
```

**Why.** The supervisor includes the mitmproxy CLI as a self-contained PyInstaller bundle, which is glibc-linked. The obvious fallback — `pip install mitmproxy` inside the wrapper at build time — fails because `mitmproxy-rs` (a Rust dep) requires `cargo edition2024` which lands in Rust 1.88. Alpine 3.22 ships only 1.87; only `alpine:edge` has 1.88, and edge moves too fast to be a stable per-cage build dependency.

**Workarounds.**

- Use a debian/ubuntu base image (the supported path).
- Switch the cage to `isolation: vm`. Lima runs the proxy / dns in separate Lima containers, so the user image's libc doesn't matter.

**Proper fix path (deferred).** A multi-stage builder image (alpine:edge with rust 1.88+ compiles mitmproxy-rs + mitmproxy-linux from source; COPY artifacts into the runtime alpine wrapper). Avoids the rust toolchain bloat in the runtime image. Tracked in #120.

### `cage exec --service proxy|dns` rejected

**Symptom.**

```
$ agentcage cage exec ubuntu02 -s proxy -- ls
error: 'cage exec --service proxy' is not yet supported on the
apple-container backend; only --service cage is addressable (proxy
and dnsmasq run inside the same microVM)
```

**Why.** On `container` / `vm` backends, proxy and dnsmasq are separate containers with their own names (`<cage>-proxy`, `<cage>-dns`). On apple-container, both run as supervised processes (uid 200 and 201) inside the single per-cage microVM — there's no separate addressable target.

**Workarounds.**

- `cage logs <cage>` shows the combined supervisor / proxy / dnsmasq / workload stream (the supervisor multiplexes them into the microVM's stdout/stderr).
- `cage exec <cage> -- ps aux` lists the proxy + dnsmasq processes; you can target them with `kill -USR1 <pid>` etc. via a regular `cage exec`.
- For mitmproxy state, `cage exec <cage> -- cat /var/log/agentcage/proxy.log` works.

**Proper fix path (deferred).** Would need a routing layer in the supervisor that listens on a control socket and proxies exec requests to the right component's namespace. Architectural, not a small patch.

### `secret_injection.transform` accepted but not applied

**Symptom.** Setting `transform: google-jwt-bearer` (or any other transform) on a `secret_injection` rule passes `validate_config` but the proxy substitutes the literal env-var value, not the transform output. `validate_config` emits a warning:

```
warning: secret_injection['MY_SA_JWT'].transform ='google-jwt-bearer':
silently has no effect on apple-container (server-side
{{SECRET:...}} placeholder substitution is not wired yet — the
cage sees the raw env-passed value). See issue #120.
```

**Why.** Transforms are part of the container backend's `SecretInjector`. The apple-container addon does direct string substitution only.

**Workaround.** Pre-compute the transformed value host-side and pass it as the env var:

```bash
# Instead of relying on transform: google-jwt-bearer:
export GOOGLE_BEARER_TOKEN=$(gcloud auth print-access-token)
agentcage cage start mycage  # the cage sees GOOGLE_BEARER_TOKEN directly
```

### `cage backup --include-secrets` rejected

**Symptom.**

```
$ agentcage cage backup ubuntu02 --include-secrets
error: --include-secrets is not supported on apple-container
(secrets are env-passed at start from the host environment, not
stored in a secret store; the backup manifest records the expected
env names so you can re-set them on the restore host)
```

**Why.** On container / vm backends, secrets live in the host's podman secret store and backup pulls them out. On apple-container, secrets are env-passed at start from `os.environ` (PR #151) — by the time `cage backup` runs, the values aren't anywhere agentcage can re-read them.

**Workaround.** `cage backup` (no `--include-secrets`) records the expected env names in the manifest. On restore, the CLI prints them so you can re-export host-side before `cage start`:

```
Secrets are env-passed at start on apple-container — set these on the
host environment before `cage start`:
  export AGENTCAGE_TEST_SECRET=<value>
```

**Proper fix path (deferred).** macOS Keychain integration. The operator's Keychain would hold the real values; backup serializes Keychain entries; restore re-stores them in the destination's Keychain. Tracked in #120.

### Full runtime supervisor CI is partial

**Symptom.** `.github/workflows/supervisor.yml` runs shellcheck on supervisor.sh and asserts every documented stage marker is present. It does NOT actually boot supervisor.sh in a privileged Linux container and verify `hidepid=2`, the per-component uids, the empty cap sets, etc.

**Why.** Real runtime testing of supervisor.sh requires CAP_SYS_ADMIN + CAP_NET_ADMIN inside a Linux container (so the supervisor can remount /proc + apply iptables). That means docker-in-docker on GitHub Actions, which complicates the CI image and requires careful permission scoping.

**Workaround.** Manual macOS verification is the current "real" test (`cage verify ubuntu02` runs CA / DNS / egress probes; bug regressions in supervisor would surface as cage exits). The maintainer rebuilds + tests on every supervisor.sh change.

**Proper fix path (deferred).** Add a `tests/apple_container_supervisor/` package with a runner that builds a stub user image, runs the wrapper with `--cap-add CAP_SYS_ADMIN`, asserts /proc/<workload-pid>/status fields. Tracked in #120.

## Quirks worth knowing

Behaviors that are correct-by-design but surprising the first time you hit them.

### `cage exec` runs as root, not uid 1000

```
$ agentcage cage exec ubuntu02 -- id
uid=0(root) gid=0(root) groups=0(root)
```

The supervisor's `capsh --user=...` privilege drop applies to the **workload process tree** (PID 1 = your `cage.yaml` `command`). `container exec` enters via Apple's runtime, which respects the image's default `USER` (root on debian/ubuntu/node bases).

The egress filter accommodates this: the NAT REDIRECT rule excludes uid 200 (mitmproxy) and uid 201 (dnsmasq) instead of explicitly matching uid 1000, so root-from-`cage exec` ALSO flows through the proxy + allowlist. Allowlist behavior is identical regardless of which uid initiated the request.

Caveat: root via `cage exec` retains the container's CAP_NET_ADMIN. So `cage exec ... -- iptables -F` would work and bypass the egress filter. The threat model treats the operator's interactive sessions as trusted; only the workload is sandboxed.

### virtiofs locks file ownership to the host user

Files written by uid 200 (mitmproxy) or uid 201 (dnsmasq) inside the cage show up as the host user (e.g. `m1`) on the macOS side. Apple's virtiofs bind mount maps all guest uids to the host file's owner uid; the guest can't chown the mountpoint.

This is why supervisor.sh stage 30 / 40 use `chown ... 2>/dev/null || true` for `/var/log/agentcage` — the chown fails on the bind mount, but the host-side `chmod 1777` (set by `AppleContainerBackend.start()`) means any uid in the cage can still write files there. Sticky bit means each new file is owned by its creator host-side.

### dnsmasq strips AAAA records

`getent ahosts <name>` from inside the cage returns IPv4 only:

```
$ agentcage cage exec ubuntu02 -- getent ahosts archive.ubuntu.com
172.66.152.176  STREAM archive.ubuntu.com
104.20.28.246   STREAM
```

This is `filter-AAAA` in `dnsmasq.conf`. Without it, dnsmasq returns AAAA records from upstream; curl/apt try IPv6 first; the cage has no IPv6 (killed at netfilter + sysctl); the connection fails instantly with `Cannot assign requested address`; curl falls back to v4. Correct behavior but slow + noisy in client logs. Stripping at the resolver keeps everything single-stack.

### `cage update` is needed for most cage.yaml edits

`domain add / rm` is the only cage.yaml-modifying command that auto-rebuilds the wrapper image. If you hand-edit cage.yaml to change `secret_injection`, `apple_container_autostart`, `container.command`, `container.cpus`, etc., run `agentcage cage update <name>` to bake the changes into the wrapper.

Why: most cage.yaml fields are baked into the wrapper image at build time (allowlist, command, env, secret-injection rules, autostart flag). The running cage holds the OLD image; only a rebuild + restart picks up edits.

### `cage audit --since` is post-parse on apple-container

```
$ agentcage cage audit ubuntu02 --since 1h
```

On container / vm backends, `--since` is passed to `journalctl --since` so the journal cursor advances to the right point. On apple-container, the audit data is a plain JSONL file tailed with `tail -n 10000`; there's no time index. The CLI applies the time filter in Python after parsing, so the command works correctly but doesn't skip rows on disk. For large audit files this is slightly slower than on container / vm.

### `apt-get update` emits HTTP→HTTPS warnings

```
W: Failed to fetch http://archive.ubuntu.com/...  Unable to connect to archive.ubuntu.com:http:
...
Get:10 http://archive.ubuntu.com/ubuntu resolute/main arm64 Packages [1860 kB]
```

apt tries HTTP first; the upstream redirects to HTTPS; mitmproxy handles the TLS interception correctly; the HTTPS fetches all succeed. The `Failed to fetch http://...` lines are cosmetic — `apt-get update` returns 0 and the package lists are fresh.

### Phase 8.2 OpenClaw is a known CI flake

`E2E OpenClaw (Phase 8) > 8.2 openclaw health via exec alias` intermittently fails on every PR's CI run, including on master itself. Not specific to apple-container. Admin-merge precedent is established when all other checks (3.12/3.13/3.14 unit, E2E Container 1-6, shellcheck on supervisor) pass.

### v0.20.3 and v0.20.4 are dead tags

`v0.20.4` was published to PyPI by accident from a stale checkout; the wheel had `version = "0.20.4"` but missing the actual fixes. **PyPI 0.20.4 has been yanked.** `v0.20.3` was tagged but the publish workflow was cancelled before reaching PyPI, so no PyPI version exists at 0.20.3. Both tags exist on GitHub for traceability — install `0.20.5` or later (currently `0.21.0`).

## Troubleshooting

**`agentcage doctor` reports "Apple container unavailable"** — check `container system status`. If "not running": `container system start --enable-kernel-install`. If "not installed": install the `.pkg` from apple/container releases.

**Cage create fails with `exit 78`** — your cage image isn't glibc-based. The error message lists the workarounds (use debian/ubuntu base, or switch to `isolation: vm`). See [Alpine / musl user images not supported](#alpine--musl-user-images-not-supported).

**Cage create fails with `exit 79`** — your cage image has a system user at uid 200 or 201 that collides with the apple-container `acproxy` / `acdns` users. File an issue with the base image name.

**Cage create fails with `User [cage] not known`** — pre-0.20.4 supervisor bug; upgrade agentcage.

**`cage run ubuntu` exits immediately** — pre-0.20.4 cage.yaml-command-ignored bug; upgrade agentcage.

**`cage audit` shows no entries** — the cage may not have made any HTTP(S) requests yet (the addon writes audit.jsonl per request). Generate traffic with `cage exec <cage> -- curl https://example.com` and re-run. If still empty, check `cage logs <cage>` for supervisor stage errors and verify the audit file exists at `~/.config/agentcage/apple-container/<cage>/logs/audit.jsonl`.

**Cage runs but every outbound HTTP times out** — check `container logs <cage>` for the supervisor's stages. If stage 50 says "mitmproxy listener never came up", inspect `cage exec <cage> -- tail /var/log/agentcage/proxy.log` for mitmproxy errors. If stage 80 (iptables) errored, the container probably didn't get `--cap-add CAP_NET_ADMIN` — check that you're on a fresh-enough agentcage build (0.21.0+).

**Cage starts but the workload immediately exits** — your `cage.yaml` `command` returned non-zero. Apple's `container run -d` exits when the command exits. Check `cage logs <cage>` for the workload's last output. Wrap one-shot commands in `... ; exec sleep infinity` if you want the cage to stay up for `cage exec`.

**`agentcage cage destroy <cage>` leaves an image behind** — `container image delete localhost/agentcage-apple-<cage>:latest` to clean it up. Logged as a destroy warning; not destructive.

**`launchctl list io.agentcage.<cage>` says "Could not find service"** — on macOS 26 with autostart enabled, the plist is loaded into a domain `launchctl list <label>` doesn't always introspect. Check that the plist file exists at `~/Library/LaunchAgents/io.agentcage.<cage>.plist`; if it does, autostart is wired (the plist is reloaded at each login via the LaunchAgents directory's automatic discovery).

## Secrets are env-passed, not stored

| | container / vm | apple-container |
|---|---|---|
| Where secrets live at rest | host podman secret store | host environment (`os.environ`) |
| Set via | `agentcage secret set <cage> KEY` | `export KEY=value` in the shell that runs `cage start` |
| Listed by | `agentcage secret list <cage>` | (none — exits unsupported) |
| Persisted after host reboot | yes (podman secret store survives) | no (env vars are per-shell) |
| Injected as | env vars on the cage container OR `{{SECRET:...}}` placeholder substitution by the proxy | env vars on the cage microVM + `{{ENV_NAME}}` placeholder substitution by the proxy addon (PR #151) |

On apple-container, `secret list / set / rm` exit with `not yet implemented` — they have no work to do. The flow is:

1. `cage.yaml` declares the rule: `secret_injection: [{env: API_KEY, placeholder: "{{API_KEY}}", inject_to: [api.example.com]}]`
2. Operator exports the value: `export API_KEY=sk-real-key`
3. `agentcage cage start <cage>` reads `API_KEY` from `os.environ`, forwards via `container run -e API_KEY=sk-real-key`
4. Inside the cage, the mitmproxy addon resolves the env var at startup and substitutes `{{API_KEY}}` → `sk-real-key` in outbound request headers/bodies whose host matches `inject_to`
5. The cage workload only ever sees the placeholder, never the real value
