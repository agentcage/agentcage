<!-- owner: @luca  last-reviewed: 2026-08-30 -->
# Egress-local DNS apply

Design note for removing the host-side grants **watcher** — the systemd user
unit on Linux and the launchd plist on macOS — and applying a granted
domain's DNS inside the egress container instead.

Read this alongside [Policy API](../reference/policy-api.md), which describes
the feature this changes the plumbing of. Nothing about *who decides* a grant
changes; only *who applies* it.

## The problem

A grant needs two things to become real:

1. **L7** — the domain must pass `DomainInspector`. The addon already does
   this synchronously, in-memory, the instant the decider says yes.
2. **DNS** — dnsmasq must be willing to forward the zone, or the cage cannot
   resolve the name at all.

Only (2) was remote. The addon (`acproxy`, uid 200, `--bounding-set=-all`)
cannot signal dnsmasq (`acdns`, uid 201) — it has no `CAP_KILL` — so applying
DNS was delegated to a host process, and the host learned about grants by
**polling a file**:

- container: a `<name>-grants.service` systemd user unit, 1 Hz.
- apple-container: an `io.agentcage.<name>.grants.plist` launchd agent, 1 Hz.
- vm: the same, but each tick is a `limactl shell` SSH round-trip, 5 s.

That is ~86,400 wakeups per day per cage (~17,280 SSH hops on vm) to observe a
file that changes a handful of times in a cage's life. It also made the
feature's correctness depend on per-OS service supervision, which is where the
bugs were: a plist with no `PATH` could not find `limactl` and failed every
tick while reporting healthy to `launchctl`.

The deeper observation is that **the host was never the right place for this**.
The egress already *is* the enforcement domain — mitmproxy and dnsmasq both run
there. Anyone who can execute code in that container already owns policy
enforcement completely. Routing a DNS update through the host bought no
security; it bought latency, an OS-specific supervisor, and a polling loop.

## The design

The addon publishes the granted zone list; the supervisor renders and reloads.

```
addon (uid 200)                    supervisor (root, PID 1)         dnsmasq (uid 201)
  |                                   |                                |
  | decider says grant                |                                |
  | dom.grant()  ── L7 live now       |                                |
  | _persist_grants()                 |                                |
  |    ├─ grants.yaml   (durability)  |                                |
  |    └─ dns/granted   (apply)  ───► | step G loop notices mtime      |
  |                                   | re-render servers-file         |
  |                                   | kill -HUP ───────────────────► | re-reads
  |                                   |                                | servers-file
```

Three properties make this sound.

**The supervisor's loop already exists.** Step G is a required liveness poll —
it `kill -0`s both children every second and exits so the runtime can restart
the container when one dies. Adding a `stat` of one file to an iteration that
already runs and already sleeps 1 s introduces *no new wakeups, no new process,
and no new service*. This is the difference between "polling" and "noticing":
the wakeup is already paid for.

**The addon can only name a zone, never route it.** It writes newline-delimited
**domain names** to `/home/acproxy/dns/granted`, not `server=` directives. The
supervisor decides the upstream for each zone using exactly the logic it
already applies to the baseline. A compromised addon therefore cannot point a
zone at a resolver it controls — the worst it can do is name a domain, which is
precisely the authority it already has (it is the component that decides
grants).

**The baseline is never mutated.** `/etc/agentcage/dns-allowlist.conf` stays a
read-only bind mount. The rendered servers-file is always
`baseline-lines + granted-lines`, regenerated from the baseline every time, so
a grant is strictly additive and cannot delete or repoint an operator zone.

### Why `--servers-file` and not the config file

dnsmasq does **not** re-read its main config on `SIGHUP`. It does re-read the
file named by `--servers-file`, which is exactly why the existing host path
worked. Both supervisor branches already start dnsmasq with a *writable
runtime* servers-file (`/run/agentcage/dns-allowlist.egress.conf`) when a
default-route gateway is derivable, so the seam already exists; this change
makes that runtime file unconditional so there is a single path to re-render.

### Permissions

`/home/acproxy` is chowned to `acproxy` in an image layer, so the addon can
create `dns/granted` with no runtime `chown` — the supervisor deliberately
avoids `chown` at runtime because hardened rootless podman
(`default_capabilities = []`) drops `CAP_CHOWN`. The file is written
temp+rename so the supervisor never observes a partial list.

## What happens on the host

The host keeps exactly one job: writing the durable `domains.allow` baseline in
the operator's `cage.yaml`, which lives behind a **read-only** Lima/bind mount
and must stay authoritative across a guest compromise. That job has no deadline
anymore, so it needs no daemon:

- `agentcage cage grants <name> sync` applies the overlay explicitly.
- The same reconcile runs implicitly from `agentcage domain list`, which is
  where the lag would otherwise be visible — so what the operator reads is
  always the truth, and they never have to know `sync` exists. It is a no-op
  when nothing is pending.

Deliberately NOT hooked into `cage status`: reconciling writes `cage.yaml` and
drives the live-reload chain, and a read-only status command should not have
that side effect.

Enforcement durability does not depend on this. The overlay (`grants.yaml`) is
the addon's own persistence: it reloads it at startup and re-publishes the DNS
list, so a granted domain survives an egress restart whether or not the host
has reconciled yet.

## Trade-offs

**An expired *baseline* entry stays resolvable until the next reconcile.** Only
entries from `agentcage domain add --expires-in` are affected (decider TTLs are
swept by the addon itself, which re-publishes on expiry). The L7 inspector
blocks an expired domain immediately and unconditionally, so the window is
cosmetic — DNS resolution is not egress. This is already the behavior between
watcher ticks today; it just widens from ≤1 s to "until the operator runs a
command".

**`domain list` may lag `cage.yaml`.** It reconciles first, so what the operator
sees is correct; the file on disk is what converges lazily.

**The cage can trigger supervisor work.** A grant causes a re-render. This is
bounded by the policy API's existing per-cage rate limit (1 rps, burst 5) and
by `max_grants` (32), so the amplification ceiling is a few file writes.

## What this removes

- `quadlets._grants_service_unit` and the `<name>-grants.service` unit.
- `watcher.install_grants_watcher_plist` / `uninstall_grants_watcher` and the
  `io.agentcage.<name>.grants.plist` launchd agent.
- `cli._ensure_grants_watcher` and every backend's install/enable/stop/uninstall
  call site.
- The `grants watch` polling loop (`--once` survives as `grants sync`).

Net: one fewer long-lived process per cage, no per-OS service supervision in
the feature's correctness path, and no `PATH`/`limactl`/GUI-domain class of bug.
