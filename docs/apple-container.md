# Apple Container Isolation

`apple-container` isolation uses Apple's [`container`](https://github.com/apple/container) CLI on macOS 26+ Apple Silicon. Each cage runs in **two sibling Apple `container` microVMs** (one kernel per VM, hypervisor boundary via Apple's Virtualization.framework). One VM holds the egress filter (mitmproxy + dnsmasq); the other holds the cage workload. The cage VM has its default route pointed at the egress sibling, so all cage egress traffic flows through the proxy.

Introduced in **0.20** as a single-microVM model and reached parity with `container` / `vm` in **0.21**. **0.21.20** refactored to the 2-microVM model (PR #196 / #197) so the workload-threat invariants match container/vm: secrets cleartext lives only in the egress VM; the cage VM has no mitmproxy / dnsmasq / iptables / jq.

On macOS 26+ Apple Silicon hosts where the `container` CLI is installed, this is the **default** when `isolation:` is omitted from `cage.yaml`. Lima remains the default everywhere else.

## Why apple-container

Versus Lima on the same host:

- **~10–20× faster cage create** warm (~5s vs ~60s+ Lima warm). Apple microVMs boot in well under a second; Lima has to bring up a full Ubuntu cloud image.
- **~3× less RAM per cage.** Two thin microVMs (single kernel each) vs Lima's full guest OS.
- **Same hypervisor boundary** — both use Virtualization.framework. The host-side trust boundary is identical.

Trade-offs:

- **macOS 26+ Apple Silicon only.** Older macOS, Intel Macs, and Linux all stay on Lima/container.
- **User cage image needs `iproute2` + `libcap2-bin` + `iputils-ping` + `ca-certificates`** — the slim wrapper installs these on debian/ubuntu/alpine bases via apt-get / apk; distroless images may need the user to layer them in.
- **Per-cage CAP_NET_ADMIN residual** on the cage VM (see [Known residual](#known-residual-route-bypass-via-as-root)).

## Architecture (PR 3 onwards — 2-microVM model)

```
Apple `container` network (per-cage, e.g. <cage>-net)
│
├── <cage>-egress  ──── built from shared agentcage-egress image (one per host)
│   ├── PID 1: tini → /opt/agentcage/supervisor-egress (POSIX sh)
│   ├── step A   iptables: PREROUTING REDIRECT 80/443 → :8443 (transparent),
│   │            FORWARD default DROP, allow ESTABLISHED + ICMP echo
│   ├── step B/C dnsmasq (uid 201, CapBnd=0)   — recursive resolver scoped
│   │            to allowlisted apex zones; sinks A/AAAA for unlisted zones
│   ├── step D/E mitmproxy (uid 200, CapBnd=0) — transparent on :8443;
│   │            allowlist + {{SECRET}} injection + audit + capture
│   ├── step F   touch /var/log/agentcage/ready (host polls before cage start)
│   ├── bind: <state>/<cage>/secrets       → /home/acproxy/secrets:ro
│   ├── bind: <state>/<cage>/egress-config → /etc/agentcage/{config,dnsmasq,dns-allowlist}.conf:ro
│   ├── bind: <state>/<cage>/certs         → /home/acproxy/.mitmproxy
│   └── bind: <state>/<cage>/logs          → /var/log/agentcage  (cage audit / har)
│
└── <cage>        ──── built from per-cage agentcage-apple-<cage>:latest
    │                  (slim wrapper: FROM user_image + cage-init.sh +
    │                   cage-cmd.sh; no mitmproxy/dnsmasq/iptables/jq)
    ├── PID 1: /opt/agentcage/cage-init.sh (POSIX sh, runs as root briefly)
    │   ├── stage A   ping <egress-ip> until ARP-reachable (≤15s grace)
    │   ├── stage B   ip route replace default via <egress-ip>
    │   ├── stage C   install /certs/mitmproxy-ca-cert.pem → trust store
    │   └── stage D   capsh --no-new-privs --drop=all --user=$(getent passwd 1000)
    │                 → exec /opt/agentcage/cage-cmd.sh (the user's argv,
    │                   shell-escaped at build time via Python's shlex.quote)
    ├── env: AGENTCAGE_EGRESS_IP=<sibling-ip>  (resolved by backend at start)
    ├── env: -e KEY={{KEY}} per secret_injection rule  (placeholders only;
    │        cleartext lives only in the egress sibling's bind mount)
    └── bind: <state>/<cage>/certs            → /certs (read by cage-init)
```

**Workload-threat invariants** verified end-to-end:

- `cage exec -- ls /home/acproxy/secrets` → `No such file or directory` (different microVM; the secrets bind isn't in the cage's namespace).
- `cage exec -- iptables -L` → command not found (no iptables in the slim wrapper).
- `cage exec -- /usr/sbin/dnsmasq` → command not found.
- Workload (uid 1000) has empty `CapEff/CapPrm` and `NoNewPrivs=1` set by `capsh --no-new-privs --drop=all` in cage-init's stage D.

The shared `agentcage-egress` image is built once per host (tagged with the agentcage version, e.g. `localhost/agentcage-egress:0.21.20`) so sibling cages share a single ~120MB mitmproxy bundle install. Per-cage builds only need to add the ~30-line wrapper on top of the user's image.

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
| `cage exec / shell` | `container exec [-it] -u 1000 <cage> <cmd>` — runs as the cage workload's uid 1000 user by default (matches the workload's capability set: no CAP_NET_ADMIN / CAP_DAC_OVERRIDE). Pass `--as-root` for the operator-debug path. See [`cage exec` default-drop](#cage-exec-defaults-to-uid-1000-not-root) below |
| `cage logs` | `container logs [-f] <cage>` — combined supervisor / proxy / dns / workload stream |
| `cage audit` | Tails `<state>/<cage>/logs/audit.jsonl` (bind-mounted from the microVM); same filter machinery as container / vm. `--since` is post-parse only (see [Quirks](#quirks-worth-knowing)) |
| `cage har` | Reads `<state>/<cage>/logs/capture.jsonl` and renders HAR 1.2 JSON; full request/response bodies captured when `capture.enable_har: true` (see [HAR body capture](#har-body-capture--wired-was-a-gap-pre-0212)) |
| `cage verify` | Service-status + CA / DNS routing / egress filtering probes via `container exec` |
| `cage backup / restore` | Backup tarball with config + capture + audit; secrets NOT serialized (see [secret backup](#cage-backup---include-secrets-rejected)) |
| `cage update` | Rebuilds the wrapper image and restarts the cage |
| `domain add / rm` | Auto-rebuilds the wrapper (allowlist is baked in at build time) and restarts the cage; change takes immediate effect |
| `secret list / set / rm` | Exits with a clear message — secrets are env-passed on apple-container, not stored in a secret store (see [secrets model](#secrets-are-env-passed-not-stored)) |
| `inspectors:` chain in cage.yaml | Runs end-to-end via the bundled `inspectors` registry; flagged/blocked entries land in `cage audit --inspector <name>` (see [Inspector chain — wired](#inspector-chain--wired)) |

## Security model

The cage **workload** (PID 1 = whatever your `cage.yaml` `command` evaluates to) runs with:

| Property | Value | Verifiable in `/proc/1/status` |
|---|---|---|
| UID | image's uid-1000 user (`ubuntu`, `node`, `claude`, or auto-created `cage`) | `Uid: 1000 1000 1000 1000` |
| Capability sets | all empty | `CapEff/CapPrm/CapInh: 0000000000000000` |
| `NoNewPrivs` | set | `NoNewPrivs: 1` |

Cage-side escape attempts that are blocked end-to-end:

- `iptables -L` → command not found (no iptables binary in the slim wrapper)
- `cat /home/acproxy/secrets/*` → ENOENT (secrets bind-mount is in the egress sibling VM, not the cage's namespace)
- TLS with `Host: evil.com` spoofed on connection to allowlisted host → 403 from proxy (addon uses SNI/dst, not Host header)
- Bypass via raw IP literal → 403 from proxy (allowlist applies to all hosts)
- DNS exfil via non-A record type → REFUSED by dnsmasq (per-zone recursion scoping)
- IPv6 fallback → no AAAA records reach the cage (`filter-AAAA` in dnsmasq.conf)

**`cage exec` / `agentcage run` default to uid 1000.** The CLI passes `-u 1000:1000` to `container exec` so interactive sessions run as the cage workload's user, matching `container` and `vm` backends. Pass `--as-root` for the operator-debug path.

**Threat-model parity with container / vm (PR 3, 0.21.20+).** With the 2-microVM split, the workload-threat invariants now match container/vm:

| Threat | container/vm | apple-container (0.21.19) | apple-container (0.21.20+, 2-microVM) |
|---|---|---|---|
| Workload (uid 1000) reads injected secrets | ❌ different container | ❌ different uid (re-stage) | ❌ different microVM |
| Workload modifies iptables | ❌ no NET_ADMIN | ❌ no NET_ADMIN | ❌ no iptables binary |
| Workload reads dnsmasq config | ❌ different container | ❌ root-only file | ❌ different microVM |
| `--as-root` reads secrets | ❌ different container | ⚠️ same VM (CAP_DAC_OVERRIDE) | ❌ different microVM |
| `--as-root` flushes iptables | ❌ no NET_ADMIN | ⚠️ same VM (CAP_NET_ADMIN re-acquired) | ❌ no iptables binary |

### Known residual: route bypass via --as-root

The cage microVM is created with `--cap-add CAP_NET_ADMIN` because `cage-init.sh` needs it to set the default route to the egress sibling at startup. Per the spike on Apple's runtime, `container exec --user 0 <cage>` re-acquires `CAP_NET_ADMIN` in the bounding set even after `capsh --drop=all` dropped it for the workload — Apple's runtime reconstructs `CapBnd` from `configuration.capAdd` on every exec.

An operator with `--as-root` can therefore `ip route replace default via <host-bridge-ip>` to bypass the egress sibling. They **cannot** read cleartext secrets (they're in a different microVM's filesystem) and **cannot** flush iptables (no binary in the wrapper) — but they can route around the egress filter for that exec session.

This affects the **`--as-root` operator threat** only, not the workload threat. The structural fix is macOS host pf rules pinning egress to the per-cage Apple network's egress interface, planned for v0.23. Tracked in [#196](https://github.com/agentcage/agentcage/issues/196).

If your threat model requires hardening `--as-root` operator sessions against egress bypass on apple-container, use `isolation: vm` (Lima) — there, the cage workload's container has `DropCapability=ALL`, so `podman exec --user 0 <cage>` enters a process with no CAP_NET_ADMIN in CapBnd at all.

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

### `protocol_relays:` — wired (was a gap pre-0.21.x)

**Status.** Fixed. `protocol_relays:` entries (IMAP, SMTP) now spawn real TCP listeners inside the apple-container microVM. The in-cage mitmproxy addon's `running()` hook reads the cage's relay list from `/etc/agentcage/protocol_relays.json` (baked in at wrapper-build time), dispatches each entry's `type` through the same `data/proxy/relays` registry the container backend uses, and starts a listener on the configured `listen:` address. Pre-0.21.1 the config parsed cleanly but silently spawned nothing — outbound SMTP / IMAP from the cage would just hang. Audit events from the relay (`smtp_data`, `imap_command`, `smtp_command`, ...) land in the same `audit.jsonl` as HTTP allow/block decisions, so `cage audit` surfaces them under one timeline.

**Credential handling.** Relay credentials (`auth.user_source: env:SMTP_USER`, etc.) take the same hardened path `secret_injection:` does on 0.21.1+: the backend writes each value into the per-cage secrets bind mount (`<state>/<cage>/secrets/<env>`, mode 0600), supervisor stage 35 re-stages into `/home/acproxy/secrets/<env>` (chown 200:200 mode 0400) for mitmproxy, then `umount`s the host bind so the cage workload cannot read it. The addon reads each relay-secret file in its `running()` hook and sets `os.environ[<env>]` for the relay's own `_resolve_credential` to pick up. Crucially, relay credentials are **NOT** passed as `-e` flags to `container run` — they live only in the mitmproxy process's env, so `container inspect <cage>` and the cage workload's `/proc/self/environ` never carry them.

**Loopback access.** Cage workloads reach the relay over loopback on whatever port the cage author chose in `listen:`. Supervisor stage 80 reads `protocol_relays.json` and adds a per-port `iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport <port> -j ACCEPT` rule — without it the default-DROP filter chain would silently kill cage→relay connections.

**Inspector chain (caveat).** The apple-container relay path currently runs with `inspectors=None` — relay-level policy (`recipient_allowlist`, `sender_allowlist`, `max_message_bytes`, rate limits) still applies, but the body inspector chain (`secrets`, `entropy`, `content-type`) does not run on SMTP `DATA` payloads. Full inspector-chain parity is the next item under #120; the container backend already wires it (`src/agentcage/data/proxy/addon.py:_start_protocol_relays`).

**Example.**

```yaml
# cage.yaml — outbound SMTP through a hardened relay
name: mail-cage
isolation: apple-container
container:
  image: ubuntu:24.04
domains:
  allow:
    - smtp.example.net   # only the upstream MTA is reachable
protocol_relays:
  - name: primary-smtp
    type: smtp
    listen: 127.0.0.1:2525
    upstream:
      host: smtp.example.net
      port: 587
      tls: true
    auth:
      type: smtp-plain
      user_source: env:SMTP_USER
      password_source: env:SMTP_PASS
    policy:
      sender_allowlist: ["bot@local"]
      recipient_allowlist:
        domains: ["example.com"]
      max_message_bytes: 1048576
      send_rate_limit: "20/hour"
```

`SMTP_USER` / `SMTP_PASS` must be set in the host environment at `cage start` time — the backend writes them into the secrets bind mount and the cage workload never sees them.

### `secret_injection.transform` — wired (was a gap pre-0.21.x)

**Status.** Fixed. `transform: google-jwt-bearer` (and any future entry in `KNOWN_TRANSFORMS`) now runs end-to-end on apple-container: the in-cage mitmproxy addon loads the same `data/proxy/transforms` registry the container backend uses, mints a derived value at request time (e.g. a short-lived OAuth bearer from a service-account JWT), and substitutes that — not the raw env-passed credential — into the outbound request. The "silently has no effect on apple-container" warning no longer fires for known transforms.

**Fail-closed contract.** If the transform fails to initialize (bad SA key) or to mint at request time (Google rejects the assertion, network error, rate limit), the addon leaves the placeholder in place and logs the failure. The upstream sees `Bearer {{TOKEN}}` literally and 401s — the raw credential never leaks as a fallback.

**Audit.** The per-request audit entry includes `"secret_transforms": {"<env>": "<transform_name>"}` whenever a transform ran, so the operator can distinguish raw-env substitution from derived-value substitution in `cage audit`.

**Example.**

```yaml
# cage.yaml
secret_injection:
  - env: GCP_SA_KEY            # SA JSON, full key — never leaves the proxy
    placeholder: "{{GCP_BEARER}}"
    transform: google-jwt-bearer
    transform_config:
      scopes:
        - https://www.googleapis.com/auth/calendar.readonly
    inject_to:
      - www.googleapis.com
```

Cage agent sends `Authorization: Bearer {{GCP_BEARER}}`; the proxy substitutes a freshly minted (cached until expiry) `ya29.<...>` access token.

### HAR body capture — wired (was a gap pre-0.21.2)

**Status.** Fixed. `cage har <cage>` now exports request and response **bodies** alongside headers when `capture.enable_har: true` is set in `cage.yaml`. Pre-this-PR the apple-container mitmproxy addon wrote a headers-only capture record and HAR exports showed `content.size: 0` for every entry — debugging an actual payload meant exec'ing into the cage. Now the in-cage addon stages inbound + outbound snapshots through the same shared `CaptureWriter` the `container` backend uses, so both backends produce identical HAR 1.2 JSON.

**Body-size cap + binary skip.** `capture.max_body_size` (default 10 MB) caps each captured body; oversized bodies record `bodySize` faithfully and set `bodyTruncated: true`. Binary bodies (anything that fails UTF-8 decode — images, archives, gzip) are base64-encoded with `bodyEncoding: "base64"`; the HAR consumer can render or skip them. Same encoder used by the `container` backend, no behavioral drift.

**Filtering.** `capture.domains` and `capture.exclude_domains` (lists of hosts) gate which flows hit `capture.jsonl`, evaluated by `CaptureWriter.should_capture()`. Use `domains: [api.example.com]` to capture only one upstream's traffic when debugging.

**Inbound vs outbound view.** `cage har --view inbound` (default) renders what the cage actually saw — secret placeholders intact, response bytes post-redaction. `--view outbound` renders the wire view — real injected secrets in the request, raw server response. The CLI prints a warning when you pick the outbound view because that JSON contains live credentials. Both perspectives are recorded in every entry; the flag chooses which one to materialize into HAR.

**Example.**

```yaml
# cage.yaml
capture:
  enable_har: true
  max_body_size: 10485760     # 10 MB; override per-cage if you expect larger payloads
  domains:
    - httpbin.org             # scope: only capture httpbin traffic
```

```bash
# Inside the cage:
curl -d 'name=test&value=hello' https://httpbin.org/post

# On the host:
agentcage cage har <cage> -o /tmp/cage.har
# /tmp/cage.har now contains:
#   .log.entries[0].request.postData.text  == "name=test&value=hello"
#   .log.entries[0].response.content.text  == '{"form":{"name":"test","value":"hello"},...}'
#   .log.entries[0].response.content.size  > 0
```

Open in Chrome DevTools → Network → Import HAR to inspect the payload exactly as the cage saw it.

**Rebuild required.** Capture config is baked into the wrapper image at build time (same shape as `secret_injection`), so `cage update <cage>` is required after toggling `capture.enable_har` or changing `capture.domains` / `capture.max_body_size`. Hot-reload is not wired.

### Inspector chain — wired

**Status.** Fixed. The cage.yaml top-level `inspectors:` list now runs end-to-end on apple-container. The in-cage mitmproxy addon imports the same `data/proxy/inspectors` registry the container backend uses (`content-type`, `body-size`, `entropy`, `secrets`, `domain`), dispatches each configured entry through it, and runs the chain on every outbound HTTP(S) request — after the host-allowlist gate but BEFORE secret injection (so inspectors see placeholders, never real secret values).

**Behavior.** Matches the container backend byte-for-byte:

- **Block.** First inspector returning `action: "block"` short-circuits the chain. The proxy itself responds 403 with `{"blocked": true, "reason": ..., "host": ..., "by": "agentcage"}` — same JSON shape as the allowlist 403. No upstream connection is opened.
- **Flag.** `action: "flag"` results travel through to the audit entry but the request is forwarded. Audit `decision` becomes `flagged` (instead of `allowed`) and `reason` carries the inspector's message.
- **Audit shape.** Every audit entry includes `inspectors: [{"name", "action", "reason", "severity"}, ...]` so `cage audit --inspector <name>` and `--severity warning|error|critical` filters work identically across backends.

**Example.**

```yaml
# cage.yaml
inspectors:
  - name: content-type
    config:
      action: block
      entropy_ceiling: 6.5
  - name: body-size
    config:
      max_bytes: 1048576
```

The `content-type` inspector flags requests whose body entropy is too high for the declared content type (a common exfil indicator); `body-size` rejects any request body over 1 MiB.

**Limitations.**

- Custom Python inspectors (`path: /etc/agentcage/my_inspector.py`) are NOT yet staged into the wrapper image — `validate_config` warns at parse time. Built-in inspectors only for now; tracked in #120.
- Unknown built-in names (typos) also warn at parse time, so a misspelled inspector entry surfaces immediately instead of silently no-op'ing.

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

### `cage exec` defaults to uid 1000, not root

```
$ agentcage cage exec ubuntu02 -- id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
```

The CLI passes `-u 1000` to `container exec` by default, so the exec session runs with the same uid as the cage workload (PID 1 after the supervisor's stage-90 privilege drop). The workload's empty cap set applies: no `CAP_NET_ADMIN` (can't `iptables -F` and bypass the egress filter), no `CAP_DAC_OVERRIDE` (can't read `/home/acproxy/secrets/*` past mode 0400).

For operator-debug scenarios that genuinely need root (running `apt-get install` to add a package, inspecting iptables rules, reading dnsmasq's own log files owned by uid 201), use `--as-root`:

```
$ agentcage cage exec ubuntu02 --as-root -- apt-get install -y htop
$ agentcage cage shell ubuntu02 --as-root
```

Threat model: the cage workload (the AI agent code) is untrusted and runs as uid 1000 with empty caps + hidepid + NoNewPrivs. Interactive operator sessions are trusted, but the default-drop keeps the agent code from masquerading as root through a `cage exec` invocation — for example, a malicious cage workload that somehow tricks the operator into running `agentcage cage exec <cage> -- malicious-binary` no longer gets root + CAP_NET_ADMIN automatically; the operator must explicitly type `--as-root` for that.

**Egress filter scope.** The NAT REDIRECT rule excludes uid 200 (mitmproxy) and uid 201 (dnsmasq) instead of explicitly matching uid 1000, so requests from BOTH the workload (uid 1000) AND root-via-`cage exec --as-root` flow through the proxy + allowlist. Allowlist behavior is identical regardless of which uid initiated the request — only the cap set (which lets you re-write rules) differs.

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

## Secret delivery model

| | container / vm | apple-container (0.21.1+) |
|---|---|---|
| Where secrets live at rest | host podman secret store | host environment (`os.environ`) at `cage start` time |
| Set via | `agentcage secret set <cage> KEY` | `export KEY=value` in the shell that runs `cage start` |
| Listed by | `agentcage secret list <cage>` | (none — exits unsupported) |
| Persisted after host reboot | yes (podman secret store survives) | no (env vars are per-shell) |
| How the real value reaches the proxy | mounted into proxy container at `/run/secrets/<name>` (podman secret bind) | host-side file at `<state>/<cage>/secrets/<env>` (mode 0600), bind-mounted into the microVM as `:ro`, re-staged by supervisor to `/home/acproxy/secrets/<env>` (chown 200:200 mode 0400) |
| What the cage workload sees in its env | placeholder | placeholder (`-e API_KEY={{API_KEY}}`) |
| What the cage workload sees on disk | nothing (proxy holds the secret) | nothing — host bind mount is `umount`ed by supervisor stage 35 after re-staging |

### End-to-end flow

1. `cage.yaml` declares the rule: `secret_injection: [{env: API_KEY, placeholder: "{{API_KEY}}", inject_to: [api.example.com]}]`
2. Operator exports the value: `export API_KEY=sk-real-key`
3. `agentcage cage start <cage>`:
   - reads `API_KEY` from `os.environ`
   - writes the value to `<state>/<cage>/secrets/API_KEY` (mode 0600 on host)
   - passes `--volume <state>/<cage>/secrets:/run/agentcage/secrets:ro` and `-e API_KEY={{API_KEY}}` to `container run` (NOT the cleartext value)
4. Supervisor stage 35 (in-cage, as root): copies `/run/agentcage/secrets/*` → `/home/acproxy/secrets/*` with chown 200:200 mode 0400, then `umount /run/agentcage/secrets` so the workload can't read the host-side bind mount
5. Mitmproxy addon (uid 200) reads `/home/acproxy/secrets/API_KEY` at startup
6. Cage workload (uid 1000) reads `os.environ["API_KEY"]` → gets `{{API_KEY}}` (the placeholder)
7. Cage makes an outbound request to api.example.com with `Authorization: Bearer {{API_KEY}}`
8. Mitmproxy intercepts, substitutes `{{API_KEY}}` → `sk-real-key` on the wire (PR #151) — `secrets_injected` audit entry records the env name
9. On the response, mitmproxy redacts the real value back to `{{API_KEY}}` (PR #156) — `secrets_redacted` audit entry records it; the cage never sees the bytes even if the upstream echoes them

### What's NOT exposed (verified)

| Surface | What's visible | Why |
|---|---|---|
| Host `ps -ef` | placeholder, never the real value | the `container run` argv only carries `-e KEY={{KEY}}`; value goes via bind-mounted file |
| `container inspect <cage>` | placeholder | container env config is `KEY={{KEY}}` |
| Cage workload's `/proc/self/environ` | placeholder | cage workload's env is exactly what `-e` set: placeholder |
| Cage workload reading `/run/agentcage/secrets/` | `No such file or directory` | supervisor umount'd after re-staging |
| Cage workload reading `/home/acproxy/secrets/` | `Permission denied` | dir is acproxy-only-readable (mode 0700, owned uid 200), workload runs as uid 1000 |

The only places the cleartext value lives are: the host shell environment of whoever ran `cage start` (the operator's responsibility), the per-cage secrets dir on the host (mode 0600 owned by the host user), and inside the mitmproxy process's memory while it's running.

### Caveats

- **`cage exec` defaults to uid 1000** (the cage workload's user) on 0.21.2+. The exec session inherits the workload's empty cap set so it cannot read `/home/acproxy/secrets/*` past mode 0400, nor flush the egress filter. For operator-debug needs that require root, pass `--as-root` explicitly. Pre-0.21.2, `cage exec` defaulted to root — that was the documented quirk and is now closed.
- **Backward compat.** If you run a fresh agentcage 0.21.1+ against a cage last started under 0.21.0 (unit JSON predates `secret_env_placeholders`), `start()` falls back to the old `-e NAME=value` cleartext-env delivery so the cage keeps starting without a `cage update`. Run `cage update <name>` to migrate to the hardened model.
