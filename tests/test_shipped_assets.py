"""Static checks on files that ship in the images and scaffolds.

Everything here reads a file agentcage ships — the egress image's
``supervisor-egress.sh`` and ``Containerfile.egress``, the apple-container
``cage-init.sh``, the scaffold ``Containerfile``s, the canonical scaffold
brief (``scaffolds/AGENTS.md``) and skill (``scaffolds/skills/agentcage``),
the ``scaffold.yaml`` metadata and ``cage.yaml.j2`` templates, and
``templates/egress.container.j2`` — and asserts on its text, its YAML, or (for
``cage-init.sh``'s seeding stages) its behaviour when run under ``sh``.

These tests were rescued from host-test files deleted together with the
Python host CLI (``test_egress_dns_apply.py``, ``test_dns_live_reload.py``,
``test_apple_container.py``, ``test_scaffold_introspection.py``,
``test_scaffolds.py``, ``test_custom_scaffolds.py``, ``test_defaults_host.py``).
The files they guard did not go away with the CLI, so neither should the
guards. Test names and docstrings are kept so failures stay greppable against
history. None of them imports host code: where an original reached its
assertion through a small host helper (a path constant, ``list_scaffolds``,
``load_scaffold_meta``, a verbatim copy into a build context), a minimal
equivalent is inlined here instead.

The rendered-scaffold checks at the end read
``tests/fixtures/scaffold-configs/<name>/cage.yaml`` rather than rendering
``cage.yaml.j2`` (jinja2 is no longer a test dependency). Those fixtures are
what the shipped templates render to for a cage named ``demo``, and
``rust/agentcage-cli/src/scaffold.rs::every_scaffold_renders_byte_identically_to_the_python``
pins the Rust renderer to them byte for byte — so asserting on a fixture is
asserting on the shipped template's output. Their generator was deleted with
the Python CLI, so these semantic checks are what keeps a hand-edited fixture
honest.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO_ROOT / "src" / "agentcage"
DATA_DIR = PACKAGE_DIR / "data"
SUPERVISOR = (DATA_DIR / "containers" / "supervisor-egress.sh").read_text()
CONTAINERFILE = (DATA_DIR / "containers" / "Containerfile.egress").read_text()
CAGE_INIT = DATA_DIR / "apple-container" / "cage-init.sh"


def _read_src(*parts):
    return PACKAGE_DIR.joinpath(*parts).read_text()


def _read_data_file(*parts):
    return DATA_DIR.joinpath(*parts).read_text()


# ── supervisor-egress.sh ──────────────────────────────────────────────────


class TestSupervisorAppliesGrants:
    """The supervisor renders + reloads from its existing liveness loop."""

    def test_monitor_loop_watches_the_published_list(self):
        # The whole point: no new process, no new service. The check rides
        # the loop that already polls both children for liveness.
        assert 'while kill -0 "$DNSMASQ_PID"' in SUPERVISOR
        assert 'if [ -f "$GRANTS_RELOAD" ]; then' in SUPERVISOR

    def test_reload_signal_is_posix(self):
        """`-nt` is a bash/dash extension, not POSIX (shellcheck SC3013).

        The script is `#!/bin/sh` and CI lints it as POSIX sh. A `stat`
        comparison would also work but forks a process every second inside
        the loop whose entire appeal is that it costs nothing.
        """
        assert "-nt" not in SUPERVISOR.replace("`-nt`", "")

    def test_flag_is_cleared_before_rendering(self):
        """A grant decided mid-render must not be swallowed."""
        i = SUPERVISOR.index('if [ -f "$GRANTS_RELOAD" ]; then')
        clear = SUPERVISOR.index('rm -f "$GRANTS_RELOAD"', i)
        render = SUPERVISOR.index("_render_servers_file", i)
        assert clear < render
        # ...and a failed render puts it back so the next tick retries.
        assert ': > "$GRANTS_RELOAD"' in SUPERVISOR

    def test_sighup_targets_the_pidfile_not_the_wrapper(self):
        """Regression: SIGHUPing $DNSMASQ_PID kills the whole egress.

        dnsmasq runs under dns-audit.sh, so $DNSMASQ_PID is that WRAPPER's
        pid — and SIGHUP is fatal to a plain shell. Signalling it kills the
        wrapper, the liveness poll sees a dead child, and the container
        exits. Observed against a live cage before the fix.
        """
        assert '_hup_pid=$(cat "$DNSMASQ_PID_FILE"' in SUPERVISOR
        assert 'kill -HUP "$_hup_pid"' in SUPERVISOR
        assert 'kill -HUP "$DNSMASQ_PID"' not in SUPERVISOR

    def test_render_is_atomic(self):
        # dnsmasq must never read a half-written servers-file, and the
        # `-nt` gate must flip exactly once per completed render.
        assert '_sf_tmp="${SERVERS_OUT}.tmp"' in SUPERVISOR
        assert 'mv -f "$_sf_tmp" "$SERVERS_OUT"' in SUPERVISOR

    def test_baseline_is_read_only_and_rebuilt_each_render(self):
        # A grant is strictly additive: the rendered file is always
        # baseline-then-grants, regenerated from the read-only bind mount,
        # so a grant can never delete or repoint an operator zone.
        assert "SERVERS_BASE=/etc/agentcage/dns-allowlist.conf" in SUPERVISOR
        assert "SERVERS_OUT=/run/agentcage/dns-allowlist.egress.conf" in SUPERVISOR
        base_i = SUPERVISOR.index('cat "$SERVERS_BASE" >> "$_sf_tmp"')
        grants_i = SUPERVISOR.index('if [ -s "$GRANTED_DOMAINS" ]')
        assert base_i < grants_i, "baseline must be emitted before grants"

    def test_supervisor_chooses_the_upstream_not_the_addon(self):
        """The addon names a zone; the supervisor routes it.

        The published file holds bare domain names. If the addon could emit
        `server=` directives it could point a zone at a resolver it
        controls, which is strictly more authority than deciding grants.
        """
        assert "printf 'server=/%s/%s\\n' \"$_sf_dom\" \"$_sf_up\"" in SUPERVISOR
        # ...and the shell re-validates the name as a second gate.
        assert "grep -E '^[a-z0-9]" in SUPERVISOR

    def test_granted_upstreams_do_not_come_from_the_baseline(self):
        """Under full default-deny the baseline is EMPTY.

        Scraping upstreams out of the rendered baseline would mean a grant
        could never resolve on exactly the cage the feature exists for.
        """
        assert "AGENTCAGE_DNS_UPSTREAMS" in SUPERVISOR

    def test_runtime_servers_file_is_always_rendered(self):
        # Both branches must end up on the writable /run path; pointing
        # dnsmasq at the read-only bind mount would make a grant
        # unappliable without a restart.
        assert SUPERVISOR.count("_render_servers_file") >= 4
        assert '--servers-file="$SERVERS_OUT"' in SUPERVISOR


class TestSupervisorEgressScript:
    """DNS forwarding, resolver, mitmdump and log-file invariants of the
    egress supervisor (container, vm and apple-container egress alike)."""

    def test_supervisor_container_path_forwards_to_default_route_gateway(self):
        """The container/vm egress dnsmasq forwards allowlisted zones to the
        runtime DEFAULT-ROUTE gateway (host-tracking, like the apple vmnet
        gateway) IN ADDITION to the baked cfg.dns_servers, with --all-servers so
        a degraded gateway falls back instantly. Derived from the default route
        (NOT eth0-subnet .1): the Linux egress is dual-homed and <name>-net is
        internal."""
        s = _read_src("data", "containers", "supervisor-egress.sh")
        assert "ip route 2>/dev/null | awk '/^default/{print $3; exit}'" in s
        # The gateway rewrite now lives in _render_servers_file (so the same
        # recipe can be re-run when the addon publishes a grant), parameterised
        # over $SERVERS_BASE rather than the literal bind-mount path. Same
        # behavior: gateway-rewritten lines first, baked resolver lines kept.
        assert 'sed "s#/[^/]*\\$#/$_SF_GW#" \\\n        "$SERVERS_BASE"' in s \
            or 'sed "s#/[^/]*\\$#/$_SF_GW#" "$SERVERS_BASE"' in s
        assert 'SERVERS_BASE=/etc/agentcage/dns-allowlist.conf' in s
        assert '_SF_STYLE=prepend' in s
        assert "/run/agentcage/dns-allowlist.egress.conf" in s
        assert '_all_servers="--all-servers"' in s
        assert "$_all_servers" in s
        # --all-servers is UNCONDITIONAL (not gated on deriving a gateway): dnsmasq
        # must prefer a positive answer over a public resolver's NXDOMAIN so a
        # split-horizon apex resolves, and mitmproxy now resolves through this
        # dnsmasq, so the correctness must hold even when no gateway is derived.
        assert '_all_servers=""' not in s

    def test_supervisor_points_mitmproxy_resolver_at_local_dnsmasq(self):
        """mitmproxy re-resolves the upstream SNI/Host, so its OWN resolver
        (/etc/resolv.conf) must track the host AND resolve split-horizon names.
        The supervisor rebuilds it each start to point at the egress's local
        dnsmasq (the cage-facing DNS_LISTEN_IP), which forwards to the
        default-route gateway + baked dns_servers in parallel (--all-servers) and
        prefers a positive answer — so a public resolver's NXDOMAIN can't shadow a
        split-horizon apex and a dead gateway adds no latency. A flat resolv.conf
        of upstream nameservers cannot: glibc getaddrinfo queries them
        sequentially and stops at the first definitive answer (NXDOMAIN included).
        Requires the rw resolv bind."""
        s = _read_src("data", "containers", "supervisor-egress.sh")
        # resolv.conf is a single nameserver pointing at the local dnsmasq
        # (loopback when DNS_LISTEN_IP is the 0.0.0.0 wildcard).
        assert '_resolver_ip="$DNS_LISTEN_IP"' in s
        assert 'echo "nameserver $_resolver_ip"' in s
        assert "> /etc/resolv.conf" in s
        # Regression guard (split-DNS): mitmproxy's resolv.conf must NOT be rebuilt
        # as a flat list of upstream nameservers again. The old code wrote
        # `nameserver $_gw` + the dns_servers piped through `sort -u`; the sort
        # reordered the operator's deliberate dns_servers order (a public
        # NXDOMAIN-ing resolver could sort ahead of a split-horizon one) and broke
        # MagicDNS-homed cages.
        assert 'echo "nameserver $_gw"' not in s
        assert "dns-allowlist.conf | sort" not in s
        # egress.container.j2 must mount resolv.conf rw so the supervisor can rewrite it
        j2 = _read_src("templates", "egress.container.j2")
        assert "resolv-egress-{{ name }}.conf:/etc/resolv.conf:rw,Z" in j2
        assert ":/etc/resolv.conf:ro,Z" not in j2

    def test_egress_supervisor_keeps_lazy_connection_strategy(self):
        """The mitmdump launch line must still carry --set connection_strategy=lazy.
        PR 3 moved this to the egress sibling's supervisor (PR 1's
        supervisor-egress.sh) — same string, different file."""
        egress_supervisor = (
            Path(__file__).parent.parent
            / "src" / "agentcage" / "data" / "containers" / "supervisor-egress.sh"
        ).read_text()
        assert "connection_strategy=lazy" in egress_supervisor

    def test_egress_supervisor_precreates_logs_at_0640(self):
        """Regression for #186: the egress supervisor must pre-create the four
        proxy log files (audit.jsonl, capture.jsonl, proxy.log, dnsmasq.log)
        at mode 0640 owned by their service user before the daemons start.

        On the apple-container backend the host per-cage logs_dir is
        bind-mounted into the egress microVM and virtiofs *identity-maps*
        host owner → guest owner, so files the daemons create at the default
        0644 are readable (and dnsmasq.log writable) by the cage workload
        (uid 1000, "others"). A malicious workload could then forge/truncate
        the audit trail. Pre-creating at 0640 owned by acproxy/acdns denies
        "others" any access via the identity mapping.

        Static check on the script — the load-bearing piece is that the
        files are created up-front at a restrictive mode (install -m 0640,
        no chmod-after-create race) and chowned to the right service user.
        """
        egress_supervisor = (
            Path(__file__).parent.parent
            / "src" / "agentcage" / "data" / "containers" / "supervisor-egress.sh"
        ).read_text()

        # The helper must create files at 0640 up front (install -m 0640
        # creates at 0600 then fchmods to 0640 — the intermediate 0600 grants
        # "others" nothing, so no world-readable window).
        assert "install -m 0640" in egress_supervisor, (
            "supervisor must create log files with `install -m 0640` (no race)"
        )

        # The create path must run under setpriv as the service user with
        # --clear-groups, so a future edit that drops setpriv and creates as
        # root-then-chown (re-introducing the CAP_FOWNER/chown dependency)
        # is caught.
        assert "setpriv --reuid=" in egress_supervisor \
            and "--clear-groups" in egress_supervisor, (
            "supervisor must create/tighten logs under `setpriv --clear-groups` "
            "as the service user (no root-then-chown, no CAP_FOWNER dep) (#186)"
        )

        # Each of the four log files must be pre-created and owned by its
        # service user (acproxy for the mitmproxy-owned logs, acdns for
        # dnsmasq). Assert the exact _ensure_log calls so a future edit can't
        # silently drop one or point it at the wrong owner.
        expected = [
            ("/var/log/agentcage/dnsmasq.log", "acdns"),
            ("/var/log/agentcage/audit.jsonl", "acproxy"),
            ("/var/log/agentcage/capture.jsonl", "acproxy"),
            ("/var/log/agentcage/proxy.log", "acproxy"),
        ]
        for path, user in expected:
            call = f"_ensure_log {path} {user}"
            assert call in egress_supervisor, (
                f"supervisor missing `_ensure_log {path} {user}` (#186)"
            )

        # Ordering: each _ensure_log call must appear BEFORE the daemon that
        # writes the file is launched, so a future edit that moves creation
        # to AFTER the daemon starts (reopening the create-race where the
        # daemon creates at its umask 0644) is caught. Assert RELATIVE
        # ordering (ensure_log before launch line), not absolute line nums.
        lines = egress_supervisor.splitlines()
        # dnsmasq.log ensure must precede the first dnsmasq launch line.
        dns_ensure_idx = next(
            i for i, ln in enumerate(lines)
            if "_ensure_log /var/log/agentcage/dnsmasq.log acdns" in ln
        )
        dns_launch_idx = next(
            i for i, ln in enumerate(lines)
            if "/usr/sbin/dnsmasq" in ln or "/opt/agentcage/dns-audit.sh" in ln
        )
        assert dns_ensure_idx < dns_launch_idx, (
            "_ensure_log dnsmasq.log must run BEFORE the dnsmasq launch line "
            "(else the daemon creates the file at its umask 0644) (#186)"
        )
        # The three acproxy ensure calls must precede the mitmdump launch line.
        acproxy_ensure_idx = next(
            i for i, ln in enumerate(lines)
            if "_ensure_log /var/log/agentcage/proxy.log acproxy" in ln
        )
        mitm_launch_idx = next(
            i for i, ln in enumerate(lines) if "mitmdump" in ln
        )
        assert acproxy_ensure_idx < mitm_launch_idx, (
            "_ensure_log acproxy logs must run BEFORE the mitmdump launch line "
            "(else the daemon creates the files at its umask 0644) (#186)"
        )

        # Failure must NOT be silent: the helper must surface a loud `log`
        # warning on failure (no `|| true` swallowing the error), so a degraded
        # audit-integrity control is observable to the operator/CI.
        assert "|| log \"warn: _ensure_log" in egress_supervisor, (
            "_ensure_log must emit a loud log warning on failure instead of "
            "silently `|| true`-ing (silent degradation re-opens #186)"
        )

        # Defense-in-depth: no line creating one of these four log files may
        # leave it world-readable. The pre-creation must be 0640, never 0644
        # / 0664 / 0666. (The 1777 logs *directory* is intentional and out
        # of scope — the sticky bit prevents cross-uid deletion; what matters
        # is the FILE modes, not the dir mode.)
        log_basenames = ("audit.jsonl", "capture.jsonl", "proxy.log", "dnsmasq.log")
        for line in egress_supervisor.splitlines():
            if not any(b in line for b in log_basenames):
                continue
            # A chmod/create that grants any perms to "others" on one of
            # these files would re-open the #186 hole.
            assert "0644" not in line, (
                f"supervisor creates a world-readable log file (#186): {line!r}"
            )
            assert "0664" not in line, (
                f"supervisor creates a group+world-writable log file (#186): {line!r}"
            )
            assert "0666" not in line, (
                f"supervisor creates a world-writable log file (#186): {line!r}"
            )

    def test_egress_dnsmasq_listens_explicitly_and_forwards_to_gateway(self):
        """apple-container egress dnsmasq must bind an explicit listen address
        and forward allowlisted zones to the vmnet gateway.

        The bind-mounted conf says ``listen-address=0.0.0.0``; a wildcard
        listener in this microVM shape opens the :53 socket but does not answer
        the cage sibling's queries (the container/vm path already documents
        this). The supervisor must strip the conf's listen-address and pass an
        explicit ``--listen-address`` (the egress eth0 IP) so the cage can
        resolve THROUGH the egress, and re-point the per-zone forwarders at the
        host-tracking vmnet gateway (<subnet>.1) instead of the host-resolver IP
        baked at ``cage update`` time — so DNS follows host network changes with
        no restart."""
        script = _read_data_file("containers", "supervisor-egress.sh")
        assert '--listen-address="${_eth0_ip}"' in script
        assert "grep -vE '^(server=/|listen-address=)'" in script
        assert 'print $1"."$2"."$3".1"' in script  # derive <subnet>.1 gateway
        assert "/run/agentcage/dns-allowlist.egress.conf" in script


# ── Containerfile.egress ──────────────────────────────────────────────────


class TestPublishDirIsPreChowned:
    def test_image_creates_an_acproxy_owned_dir(self):
        """No runtime chown: hardened rootless podman drops CAP_CHOWN.

        Same reason /home/acdns is pre-chowned in an image layer.
        """
        assert "mkdir -p /home/acproxy/dns" in CONTAINERFILE
        assert "chown acproxy:acproxy /home/acproxy/dns" in CONTAINERFILE


# ── apple-container/cage-init.sh ──────────────────────────────────────────


class TestCageInit:
    """PID 1 of the apple-container cage microVM.

    ``stage_build_context`` copies this file verbatim into the wrapper build
    context, so its text is what boots in the cage VM."""

    def test_cage_init_resolves_cage_user_dynamically(self):
        """The cage-init script (PID 1 of the cage VM in the 2-microVM model)
        must look up the uid-1000 user's name from /etc/passwd at runtime —
        capsh's --user= takes a name, and the name varies by base image
        (ubuntu / node / claude / cage)."""
        from pathlib import Path
        script = (
            Path(__file__).resolve().parent.parent
            / "src" / "agentcage" / "data" / "apple-container" / "cage-init.sh"
        )
        text = script.read_text()
        assert "getent passwd 1000" in text
        assert "--user=" in text
        assert "${CAGE_USER}" in text

    def test_stage_build_context_writes_cage_init(self):
        """The slim build context only stages cage-init.sh. Every per-cage
        proxy/dns config file (cage-cmd.json, allowlist.txt, dnsmasq.conf,
        secret_injection.json, transforms.tar.gz, etc.) moved out of the
        wrapper image — they're rendered host-side by build_artifacts and
        bind-mounted into the egress sibling at runtime.

        The staging half (only cage-init.sh is written) is host code; what
        is checked here is the staged file, which is a verbatim copy of the
        shipped ``data/apple-container/cage-init.sh``."""
        cage_init = CAGE_INIT.read_text()
        # cage-init runs as PID 1 of the cage VM and sets up the route to
        # the egress sibling. Sanity-check key strings.
        assert "AGENTCAGE_EGRESS_IP" in cage_init
        assert "ip route replace default via" in cage_init
        assert "capsh" in cage_init
        # Stage D must export HOME/USER/LOGNAME for the dropped-uid workload
        # before exec'ing capsh. capsh switches uid but does NOT update env,
        # so without these the workload inherits root's HOME=/root and any
        # tool that touches ~/.config or ~/.cache fails EACCES — claude-code
        # 2.1.x silently exits 0 from `claude -p` on that path. 0.22.4
        # regression guard.
        assert 'export HOME="${CAGE_HOME}"' in cage_init
        assert 'export USER="${CAGE_USER}"' in cage_init
        assert 'export LOGNAME="${CAGE_USER}"' in cage_init
        assert 'CAGE_HOME=$(getent passwd 1000 | cut -d: -f6)' in cage_init
        # Stage B' installs three OUTPUT-chain DROP rules:
        #   * DROP cage→apple-host-gateway TCP   — closes the macOS host's
        #                                         sshd (:22) and Apple
        #                                         Remote Desktop (:5900)
        #                                         exposure on the vmnet
        #                                         gateway IP, outside the
        #                                         egress proxy's filter.
        #   * DROP cage→apple-host-gateway UDP   — no legitimate cage
        #                                         process talks to the
        #                                         host gateway anymore;
        #                                         DNS goes to the in-cage
        #                                         dnsmasq on loopback.
        #   * DROP UDP :53 NOT from acdns        — the in-cage dnsmasq
        #                                         scoping is decorative
        #                                         if a uid-1000 workload
        #                                         can `dig @1.1.1.1 evil`
        #                                         to any external resolver.
        #                                         Only the dnsmasq uid
        #                                         (acdns, 201) may emit
        #                                         UDP :53.
        assert "_apple_host_gw=" in cage_init
        assert 'iptables -A OUTPUT -d "${_apple_host_gw}" -p tcp -j DROP' in cage_init
        assert (
            'iptables -A OUTPUT -d "${_apple_host_gw}" -p udp -j DROP'
            in cage_init
        )
        # Loopback :53 must be ACCEPTed BEFORE the uid-owner DROP so the
        # workload's `getent` / `gethostbyname` lookups (uid 1000 → 127.0.0.1)
        # reach the local dnsmasq. Without this, the uid-owner rule swallows
        # them too and the cage has no working DNS at all.
        _accept_lo_udp53 = "iptables -A OUTPUT -o lo -p udp --dport 53 -j ACCEPT"
        _drop_non_acdns_udp53 = (
            "iptables -A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 201 -j DROP"
        )
        assert _accept_lo_udp53 in cage_init
        assert _drop_non_acdns_udp53 in cage_init
        assert cage_init.index(_accept_lo_udp53) < cage_init.index(_drop_non_acdns_udp53), (
            "loopback :53 ACCEPT must come BEFORE the uid-owner DROP — iptables "
            "is order-sensitive; first match wins."
        )
        # The previous `! --dport 53` exception on the host-gateway UDP
        # drop MUST NOT survive — it would re-open the cage→host-gateway
        # :53 direct-DNS path now that the in-cage dnsmasq exists.
        assert (
            'iptables -A OUTPUT -d "${_apple_host_gw}" -p udp ! --dport 53 -j DROP'
            not in cage_init
        )
        # stage A' launches a local dnsmasq scoped to the cage's
        # `domains.allow` apexes and points /etc/resolv.conf at 127.0.0.1.
        # apple-container requires macOS 26+ (checked by the host's prerequisites),
        # where inter-microVM UDP IS delivered — so the cage forwards the
        # allowlisted apexes to the EGRESS sibling (AGENTCAGE_EGRESS_IP),
        # keeping the egress the single chokepoint for ALL egress traffic, DNS
        # included. (The pre-macOS-26 claim that "vmnet drops inter-microVM UDP
        # so the cage must self-resolve" no longer holds — verified empirically
        # against apple/container on macOS 26.)
        assert "stage A': starting local dnsmasq" in cage_init
        # It reads the bind-mounted conf as the SOURCE, strips the baked
        # `server=` upstreams (host-resolver IP, used by the egress only), and
        # serves a runtime conf + servers-file whose per-zone forwarders point
        # at the egress — so a host network change is followed transparently
        # (the egress chases the host-tracking vmnet gateway).
        assert "/etc/agentcage/dnsmasq.conf" in cage_init
        assert "grep -v '^server=/'" in cage_init
        assert "/run/agentcage/dns-allowlist.cage.conf" in cage_init
        assert 'up="${AGENTCAGE_EGRESS_IP}"' in cage_init
        # Conf says `listen-address=0.0.0.0`; `--except-interface=eth0`
        # whittles that down to just lo. Direct `--listen-address=127.0.0.1`
        # on the cmdline would conflict because dnsmasq treats listen-
        # address values as additive (duplicate → EADDRINUSE).
        assert "--bind-interfaces" in cage_init
        assert "--except-interface=eth0" in cage_init
        assert "--user=acdns" in cage_init
        assert "nameserver 127.0.0.1" in cage_init

    def test_start_routes_np_file_to_exact_target_without_tmpfs(self):
        """The cage-init.sh half of np file routing: a single-file ``np``
        source is copied to its exact target, creating the parent first.

        The argv half (no ``--tmpfs`` over the target, the lowerdir bind and
        ``AGENTCAGE_NONPERSISTENT_COPIES``) is host code, covered by
        ``rust/agentcage-cli/src/apple/run_argv.rs::a_non_directory_np_source_gets_no_tmpfs``."""
        init_script = (
            Path(__file__).parents[1]
            / "src/agentcage/data/apple-container/cage-init.sh"
        ).read_text()
        assert 'np_parent=$(dirname "${target}")' in init_script
        assert 'mkdir -p "${np_parent}"' in init_script
        assert 'cp -f "${lower}" "${target}"' in init_script


def _stage_c_prime_script():
    """Return cage-init.sh's seeding stages as a standalone POSIX-sh script.

    The shared seed helper plus stages C' (``np`` binds) and C'' (copy-up
    tmpfs masks, #328) are the only parts of cage-init that can be exercised
    off-VM: they are pure filesystem work driven by
    AGENTCAGE_NONPERSISTENT_COPIES / AGENTCAGE_TMPFS_COPYUP. Slicing them out
    (rather than asserting on source text) lets the tests below run the real
    control flow — which branch chowns what — against a temp dir. Each stage
    is inert when its env var is unset, so one slice serves both.
    """
    text = (
        Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container" / "cage-init.sh"
    ).read_text()
    start = text.index("#-- Seeding helper (stages C' and C'')")
    end = text.index("#-- Stage D.", start)
    return "set -eu\nlog() { printf '%s\\n' \"$*\" >&2; }\n" + text[start:end]


def _run_stage_c_prime(tmp_path, copies, copyup=()):
    """Run stages C'/C'' with a recording `chown` stub; return its arg lines.

    chown(1) to uid 1000 needs root, which the test suite is not. The stub
    keeps the assertions about *which paths are handed to the cage user*
    honest without needing privileges, and keeps the on-disk seeding real.

    *copies* drives stage C' (``np`` binds), *copyup* stage C'' (copy-up
    tmpfs masks, #328); both are ``(lower, target)`` pairs.
    """
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    log = tmp_path / "chown.log"
    stub = bindir / "chown"
    stub.write_text(f'#!/bin/sh\nprintf \'%s\\n\' "$*" >> {log}\n')
    stub.chmod(0o755)

    script = tmp_path / "stage_c_prime.sh"
    script.write_text(_stage_c_prime_script())
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["AGENTCAGE_NONPERSISTENT_COPIES"] = "\n".join(
        f"{lower}\t{target}" for lower, target in copies
    )
    env["AGENTCAGE_TMPFS_COPYUP"] = "\n".join(
        f"{lower}\t{target}" for lower, target in copyup
    )
    proc = subprocess.run(
        ["sh", str(script)], env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return log.read_text().splitlines() if log.exists() else []


class TestCageInitSeeding:
    """cage-init.sh stages C' (``np`` binds) and C'' (copy-up tmpfs masks),
    run off-VM under ``sh`` with a recording ``chown`` stub."""

    def test_cage_init_hands_np_directory_seed_to_the_cage_user(self, tmp_path):
        """REGRESSION (#311): `tar xp` replays the host source's root-owned 0755
        modes into the tmpfs, so the uid-1000 workload could not write to an `np`
        mount at all — `echo x > /mnt/xfer/test2` returned EACCES, defeating the
        documented "writable in the cage; changes discarded" contract. The seeded
        tree must be chowned to uid 1000."""
        lower = tmp_path / "lower"
        (lower / "sub").mkdir(parents=True)
        (lower / "sub" / "f.txt").write_text("hi")
        target = tmp_path / "target"

        chowns = _run_stage_c_prime(tmp_path, [(lower, target)])

        assert (target / "sub" / "f.txt").read_text() == "hi"
        assert chowns == [f"-Rh 1000:1000 {target}"]
        # The read-only host bind is the operator's real data — never chowned
        # through, not even via -R on a path that contains it.
        assert not any(str(lower) in line for line in chowns)

    def test_cage_init_np_directory_chown_does_not_follow_symlinks(self, tmp_path):
        """The seeded tree is a verbatim copy of a host directory, so it can
        contain a symlink to an absolute path outside the mount (/etc/shadow).
        chown must carry -h so it retargets the link, not the referent."""
        assert "chown -Rh 1000:1000" in _stage_c_prime_script()

    def test_cage_init_hands_np_file_seed_and_invented_parent_to_the_cage_user(self, tmp_path):
        """A single-file np source is copied to its exact target. The copy must be
        owned by uid 1000, and so must a parent directory this stage invents —
        otherwise the root-owned 0755 parent blocks the write-temp-then-rename
        save path that config writers use."""
        lower = tmp_path / "settings.json"
        lower.write_text("{}")
        target = tmp_path / "cage" / "config" / "settings.json"

        chowns = _run_stage_c_prime(tmp_path, [(lower, target)])

        assert target.read_text() == "{}"
        assert chowns == [
            f"1000:1000 {target.parent}",
            f"-h 1000:1000 {target}",
        ]

    def test_cage_init_np_file_seed_leaves_a_preexisting_parent_alone(self, tmp_path):
        """A parent that already exists belongs to the image (e.g.
        /home/node/.config or /etc) — seeding one file into it must not rewrite
        that directory's ownership."""
        lower = tmp_path / "settings.json"
        lower.write_text("{}")
        target = tmp_path / "existing" / "settings.json"
        target.parent.mkdir()

        chowns = _run_stage_c_prime(tmp_path, [(lower, target)])

        assert chowns == [f"-h 1000:1000 {target}"]

    def test_stage_c_double_prime_seeds_and_hands_the_copy_to_the_cage_user(
        self, tmp_path,
    ):
        """The in-guest half: stage C'' replays the read-only lower into the
        tmpfs and chowns it to uid 1000, so the agent can edit its throwaway
        copy instead of hitting the Permission denied #328 measured."""
        lower = tmp_path / "lower"
        (lower / "commands").mkdir(parents=True)
        (lower / "settings.json").write_text('{"host":"settings"}')
        target = tmp_path / "target"

        chowns = _run_stage_c_prime(tmp_path, [], copyup=[(lower, target)])

        assert (target / "settings.json").read_text() == '{"host":"settings"}'
        assert (target / "commands").is_dir()
        assert chowns == [f"-Rh 1000:1000 {target}"]
        # The read-only lower is never chowned.
        assert not any(str(lower) in line for line in chowns)

    def test_stage_c_double_prime_is_inert_without_the_env(self, tmp_path):
        assert _run_stage_c_prime(tmp_path, []) == []


# ── scaffolds/AGENTS.md and scaffolds/skills/agentcage ────────────────────


# scaffold name -> (agent memory file the COPY targets, home dir chowned to node)
SCAFFOLD_WIRING = {
    "claude-code": ("/home/node/.claude/CLAUDE.md", "/home/node/.claude"),
    "codex": ("/home/node/.codex/AGENTS.md", "/home/node/.codex"),
    "pi": ("/home/node/.pi/agent/AGENTS.md", "/home/node/.pi"),
}

# scaffold name -> (agent skills dir the skill COPY targets, dir chowned to node)
SKILL_WIRING = {
    "claude-code": ("/home/node/.claude/skills/agentcage", "/home/node/.claude"),
    "codex": ("/home/node/.codex/skills/agentcage", "/home/node/.codex"),
    "pi": ("/home/node/.agents/skills/agentcage", "/home/node/.agents"),
}


def _scaffolds_dir() -> Path:
    return PACKAGE_DIR / "scaffolds"


CANONICAL_BRIEF = _scaffolds_dir() / "AGENTS.md"
CANONICAL_SKILL_DIR = _scaffolds_dir() / "skills" / "agentcage"


class TestScaffoldBrief:
    """Scaffolds bake a 'you are sandboxed' brief into each agent's memory file.

    There is a SINGLE canonical brief (``scaffolds/AGENTS.md``); scaffolds
    ``COPY AGENTS.md`` into the agent's memory file but don't each ship a
    copy — agentcage stages the canonical brief into the build context at
    build time."""

    def test_single_canonical_brief_exists(self):
        assert CANONICAL_BRIEF == _scaffolds_dir() / "AGENTS.md"
        assert CANONICAL_BRIEF.is_file()

    def test_no_per_scaffold_brief_copies(self):
        # DRY: the brief is NOT duplicated into each scaffold dir.
        for name in SCAFFOLD_WIRING:
            assert not (_scaffolds_dir() / name / "AGENTS.md").exists()

    def test_canonical_brief_content(self):
        brief = CANONICAL_BRIEF.read_text()
        assert brief.startswith("# You are running inside agentcage")
        low = brief.lower()
        assert "proxy" in low
        assert "placeholder" in low
        assert "agentcage_version" in low
        # Short — it lands in the agent's context window.
        assert len(brief.splitlines()) < 60

    # ── per-scaffold Containerfile wiring ────────────────────────────────────────

    @pytest.mark.parametrize("scaffold,mem_path,home_dir",
                             [(n, m, h) for n, (m, h) in sorted(SCAFFOLD_WIRING.items())])
    def test_containerfile_copies_brief_into_agent_memory_writable(
        self, scaffold, mem_path, home_dir,
    ):
        cf = (_scaffolds_dir() / scaffold / "Containerfile").read_text()
        # Plain COPY into the agent's own memory file, before USER node, with the
        # home dir chowned back to node so the file stays writable and the agent's
        # own state writes (auth, settings, history) still work.
        assert f"COPY AGENTS.md {mem_path}" in cf
        assert f"chown -R node:node {home_dir}" in cf
        assert cf.index("COPY AGENTS.md") < cf.index("USER node")
        # Real file, not a shell-redirect / @import indirection.
        assert f"> {mem_path}" not in cf


class TestScaffoldSkill:
    """The canonical ``agentcage`` Agent Skill and its per-scaffold wiring."""

    def test_single_canonical_skill_exists(self):
        assert CANONICAL_SKILL_DIR == _scaffolds_dir() / "skills" / "agentcage"
        assert (CANONICAL_SKILL_DIR / "SKILL.md").is_file()
        # The build-context path the scaffold Containerfiles COPY from.
        assert CANONICAL_SKILL_DIR.relative_to(_scaffolds_dir()).as_posix() == "skills/agentcage"

    def test_no_per_scaffold_skill_copies(self):
        for name in SKILL_WIRING:
            assert not (_scaffolds_dir() / name / "skills").exists()

    def test_canonical_skill_frontmatter_and_content(self):
        text = (CANONICAL_SKILL_DIR / "SKILL.md").read_text()
        # Agent Skills standard: YAML frontmatter with name (== directory name)
        # and a non-empty description; that is all Pi/Claude Code/Codex need to
        # discover it.
        assert text.startswith("---\n")
        fm = text.split("---\n", 2)[1]
        assert "name: agentcage\n" in fm
        desc = [l for l in fm.splitlines() if l.startswith("description:")]
        assert desc and len(desc[0]) > len("description: ") + 40
        assert len(desc[0]) <= len("description: ") + 1024
        body = text.lower()
        # The three endpoints the skill exists to teach, plus health.
        for needle in ("/v1/health", "get", "/v1/allowlist",
                       "post", "/v1/allowlist/requests", "/v1/allowlist/removals",
                       "agentcage.local", "reason", "403", "placeholder"):
            assert needle in body, needle

    # ── per-scaffold Containerfile skill wiring ──────────────────────────────────

    @pytest.mark.parametrize("scaffold,skill_path,home_dir",
                             [(n, p, h) for n, (p, h) in sorted(SKILL_WIRING.items())])
    def test_containerfile_copies_skill_into_agent_skills_dir(
        self, scaffold, skill_path, home_dir,
    ):
        cf = (_scaffolds_dir() / scaffold / "Containerfile").read_text()
        copy_line = f"COPY skills/agentcage {skill_path}"
        assert copy_line in cf
        # Owned by node afterwards, and before USER node like the brief.
        assert cf.index(copy_line) < cf.index(f"chown -R node:node {home_dir}")
        assert cf.index(copy_line) < cf.index("USER node")


# ── scaffolds/<name>/scaffold.yaml ────────────────────────────────────────


def list_scaffolds() -> list[str]:
    """The built-in half of the deleted ``agentcage.init.list_scaffolds``:
    every shipped scaffold directory that carries a ``cage.yaml.j2``."""
    return sorted(
        d.name for d in _scaffolds_dir().iterdir()
        if d.is_dir() and (d / "cage.yaml.j2").exists()
    )


def load_scaffold_meta(scaffold: str) -> dict | None:
    """The built-in half of the deleted ``agentcage.init.load_scaffold_meta``:
    a shipped scaffold's ``scaffold.yaml``, or None."""
    meta_file = _scaffolds_dir() / scaffold / "scaffold.yaml"
    if not meta_file.is_file():
        return None
    return yaml.safe_load(meta_file.read_text()) or {}


class TestListScaffolds:
    """Verify list_scaffolds() returns all available scaffold names."""

    def test_includes_known_scaffolds(self):
        """The scaffolds/ directory should contain at least the shipped scaffolds."""
        scaffolds = list_scaffolds()
        assert "openclaw" in scaffolds
        assert "claude-code" in scaffolds
        assert "codex" in scaffolds


class TestScaffoldMeta:
    """Verify scaffold.yaml metadata files are loadable."""

    def test_openclaw_has_build_entry(self):
        meta = load_scaffold_meta("openclaw")
        assert meta is not None
        assert "build" in meta
        assert len(meta["build"]) > 0

    def test_claude_code_scaffold_meta(self):
        meta = load_scaffold_meta("claude-code")
        assert meta is not None
        assert "build" in meta
        assert meta["build"][0]["image"] == "localhost/agentcage-scaffold-claude-code:latest"

    def test_codex_scaffold_meta(self):
        meta = load_scaffold_meta("codex")
        assert meta is not None
        assert "build" in meta
        assert meta["build"][0]["image"] == "localhost/agentcage-scaffold-codex:latest"


class TestScaffoldMetadataFields:

    def test_all_builtins_have_description(self):
        for name in ["claude-code", "codex", "openclaw"]:
            meta = load_scaffold_meta(name)
            assert meta is not None, f"{name} has no scaffold.yaml"
            assert "description" in meta, f"{name} missing description"
            assert meta["description"], f"{name} has empty description"

    def test_all_builtins_have_lifecycle(self):
        for name in ["claude-code", "codex", "openclaw"]:
            meta = load_scaffold_meta(name)
            assert meta is not None
            assert "lifecycle" in meta, f"{name} missing lifecycle"
            assert meta["lifecycle"] in ("interactive", "service"), \
                f"{name} has invalid lifecycle: {meta['lifecycle']}"


# ── scaffolds/<name>/cage.yaml.j2 (raw template text) ─────────────────────


class TestScaffoldTemplates:
    """Raw-text checks on scaffold ``cage.yaml.j2`` templates."""

    def test_ubuntu_scaffold_ca_install_tolerates_eacces(self):
        """REGRESSION: the ubuntu scaffold's `command` runs `cp` into a root-only
        directory. On the container backend the cage runs as root so it works;
        on apple-container the supervisor forces the cage workload to uid 1000,
        which can't write to /usr/local/share/ca-certificates. Without the
        `|| true` swallow the cp's EACCES would propagate, the cage CMD would
        exit non-zero, and the container would stop before `sleep infinity` —
        making `agentcage run ubuntu` look like an instant exit."""
        from pathlib import Path
        scaffold = (
            Path(__file__).resolve().parent.parent
            / "src" / "agentcage" / "scaffolds" / "ubuntu" / "cage.yaml.j2"
        )
        content = scaffold.read_text()
        # The whole cp+update-ca-certificates pair must be guarded by `|| true`
        # so a permission error doesn't kill the cage on apple-container.
        assert "|| true" in content
        # `exec sleep infinity` must still be reachable after the guard.
        assert "exec sleep infinity" in content


# ── scaffolds/<name>/cage.yaml.j2 (rendered, via the pinned fixtures) ─────


SCAFFOLD_CONFIGS = REPO_ROOT / "tests" / "fixtures" / "scaffold-configs"


def _rendered_text(scaffold: str) -> str:
    """``cage.yaml.j2`` of *scaffold* rendered for a cage named ``demo``.

    Read from the fixture the Rust renderer is pinned to (see the module
    docstring) instead of rendering through the deleted host code."""
    return (SCAFFOLD_CONFIGS / scaffold / "cage.yaml").read_text()


class TestScaffoldRendering:
    """Verify scaffold templates render to valid YAML."""

    def test_openclaw_renders_valid_yaml(self):
        cfg_text = _rendered_text("openclaw")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "demo"
        assert "container" in parsed
        assert "image" in parsed["container"]


class TestCodingAgentScaffolds:
    """Verify claude-code and codex scaffolds render and validate correctly."""

    def test_claude_code_renders_valid_yaml(self):
        cfg_text = _rendered_text("claude-code")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "demo"
        assert parsed["lifecycle"] == "interactive"
        assert parsed["scaffold"] == "claude-code"
        assert "container" in parsed
        assert parsed["container"]["command"] == ["sleep", "infinity"]

    def test_codex_renders_valid_yaml(self):
        cfg_text = _rendered_text("codex")
        parsed = yaml.safe_load(cfg_text)
        assert parsed["name"] == "demo"
        assert parsed["lifecycle"] == "interactive"
        assert parsed["scaffold"] == "codex"
        assert "container" in parsed

    def test_claude_code_has_anthropic_domain(self):
        cfg_text = _rendered_text("claude-code")
        parsed = yaml.safe_load(cfg_text)
        domains = parsed.get("domains", {}).get("allow", [])
        assert "anthropic.com" in domains

    def test_codex_has_openai_domain(self):
        cfg_text = _rendered_text("codex")
        parsed = yaml.safe_load(cfg_text)
        domains = parsed.get("domains", {}).get("allow", [])
        assert "openai.com" in domains

    def test_claude_code_has_exec_alias(self):
        cfg_text = _rendered_text("claude-code")
        parsed = yaml.safe_load(cfg_text)
        assert "exec_aliases" in parsed
        assert "claude" in parsed["exec_aliases"]

    def test_codex_has_exec_alias(self):
        cfg_text = _rendered_text("codex")
        parsed = yaml.safe_load(cfg_text)
        assert "exec_aliases" in parsed
        assert "codex" in parsed["exec_aliases"]

    def test_claude_code_has_secret_injection(self):
        cfg_text = _rendered_text("claude-code")
        parsed = yaml.safe_load(cfg_text)
        secrets = parsed.get("secret_injection", [])
        assert any(s["env"] == "ANTHROPIC_API_KEY" for s in secrets)

    def test_claude_code_oauth_token_rule_present_but_inactive(self):
        """The CLAUDE_CODE_OAUTH_TOKEN injection rule ships commented out —
        present as guidance, but not active (an active rule would make
        `cage create` demand the secret). The placeholder renders as a
        concrete entropic token even inside the comment, so uncommenting
        the rule yields a ready-to-use config."""
        cfg_text = _rendered_text("claude-code")
        assert "#- env: CLAUDE_CODE_OAUTH_TOKEN" in cfg_text
        assert re.search(
            r"agentcage:secret:CLAUDE_CODE_OAUTH_TOKEN:[0-9a-f]{32}",
            cfg_text,
        )
        parsed = yaml.safe_load(cfg_text)
        active = [s["env"] for s in parsed.get("secret_injection", [])]
        assert active == ["ANTHROPIC_API_KEY"]

    def test_claude_code_has_help_text(self):
        cfg_text = _rendered_text("claude-code")
        parsed = yaml.safe_load(cfg_text)
        assert parsed.get("help", "") != ""


class TestWorkspaceExecutableConfigMasks:
    """Regression guards for the workspace executable-config tmpfs masks
    (#170, #173).

    Every scaffold that bind-mounts ``${PROJECT_DIR}:/workspace:rw`` exposes
    the host's ``.git/hooks/`` (a cage→host git-hook pivot, #170) and the
    claude-code scaffold additionally exposes the project-local
    ``.claude/settings.json`` (a cage→cage hooks-injection chain, #173) to
    cage writes. The fix is a ``tmpfs:`` entry per affected scaffold that
    overlays the bind-mounted path with an empty, transient tmpfs.

    ``openclaw`` is intentionally exempt: it mounts ``/workspace`` from a
    Podman named volume (``{{ name }}-workspace``), not a host bind-mount,
    so there is no host ``.git``/``.claude`` tree for a caged agent to reach
    or pivot to.
    """

    # Scaffolds that bind-mount ${PROJECT_DIR}:/workspace:rw — must mask
    # the host's .git/hooks/ (#170). openclaw uses a named volume, not a
    # bind-mount, so it is excluded.
    _WORKSPACE_BINDMOUNT_SCAFFOLDS = [
        "arch",
        "busybox",
        "claude-code",
        "codex",
        "debian",
        "pi",
        "ubuntu",
    ]

    @pytest.mark.parametrize("scaffold", _WORKSPACE_BINDMOUNT_SCAFFOLDS)
    def test_git_hooks_mask_present(self, scaffold):
        """Every workspace-bind-mount scaffold must tmpfs-mask
        /workspace/.git/hooks/ so a caged agent can't plant a git hook that
        the next host-side `git commit` runs as the host user (#170)."""
        cfg_text = _rendered_text(scaffold)
        assert "${PROJECT_DIR}:/workspace:rw" in cfg_text, (
            f"{scaffold} no longer bind-mounts ${{PROJECT_DIR}}:/workspace:rw — "
            "update the mask set if the mount shape changed"
        )
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        masks = [e for e in tmpfs if e.split(":", 1)[0] == "/workspace/.git/hooks/"]
        assert masks, (
            f"{scaffold} mounts the workspace RW but is missing the "
            "/workspace/.git/hooks/ tmpfs mask (#170)"
        )
        # The mask must be noexec so even transient cage-written binaries land
        # on a non-executable mount.
        assert "noexec" in masks[0], (
            f"{scaffold} .git/hooks mask is missing noexec: {masks[0]!r}"
        )

    def test_claude_code_dotclaude_mask_present(self):
        """The claude-code scaffold must tmpfs-mask /workspace/.claude/ so a
        caged agent can't plant a malicious .claude/settings.json `hooks`
        block that Claude Code in another cage honors on launch (#173)."""
        cfg_text = _rendered_text("claude-code")
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        masks = [e for e in tmpfs if e.split(":", 1)[0] == "/workspace/.claude/"]
        assert masks, (
            "claude-code is missing the /workspace/.claude/ tmpfs mask (#173)"
        )
        assert "noexec" in masks[0], (
            f"claude-code .claude mask is missing noexec: {masks[0]!r}"
        )

    def test_openclaw_exempt_from_git_hooks_mask(self):
        """openclaw mounts /workspace from a Podman named volume, not a host
        bind-mount, so there is no host .git/hooks/ to pivot to. It must NOT
        gain the bind-mount-driven .git/hooks mask — and must not accidentally
        start bind-mounting ${PROJECT_DIR} either."""
        cfg_text = _rendered_text("openclaw")
        assert "${PROJECT_DIR}:/workspace" not in cfg_text, (
            "openclaw now bind-mounts ${PROJECT_DIR}:/workspace — re-evaluate "
            "whether it needs the #170/.git/hooks mask"
        )
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        assert not any(
            e.split(":", 1)[0] == "/workspace/.git/hooks/" for e in tmpfs
        ), "openclaw (named-volume workspace) gained a spurious .git/hooks mask"

    @pytest.mark.parametrize("scaffold", ["codex", "pi"])
    def test_other_agent_scaffolds_no_dotclaude_mask(self, scaffold):
        """codex/pi don't read a project-level executable-config file the way
        Claude Code reads .claude/settings.json `hooks`, so they get the
        .git/hooks mask only — not the .claude/ mask. This pins that decision:
        if a codex/pi project-local executable-config surface is later
        identified, add the analogous mask here rather than blanket-masking."""
        cfg_text = _rendered_text(scaffold)
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        assert not any(
            "/workspace/.claude/" in e for e in tmpfs
        ), f"{scaffold} should not carry the claude-code .claude/ mask"

    def test_claude_code_home_dotclaude_not_masked(self):
        """The claude-code scaffold masks the PROJECT-level
        ``/workspace/.claude/`` (#173) but must NOT mask the cage's own
        HOME ``~/.claude`` (``/home/node/.claude``). The home tree holds
        ``CLAUDE.md``, login credentials (``.credentials.json`` from an
        in-cage ``claude login``), and in-cage settings — masking it would
        break ``claude login`` / credential persistence. This pins the core
        distinction so a future mask-list edit can't silently widen the
        project-level mask onto the cage home."""
        cfg_text = _rendered_text("claude-code")
        tmpfs = yaml.safe_load(cfg_text)["container"]["tmpfs"]
        assert not any(
            e.split(":", 1)[0] == "/home/node/.claude"
            or e.split(":", 1)[0] == "/home/node/.claude/"
            for e in tmpfs
        ), (
            "claude-code tmpfs must not mask the cage HOME ~/.claude "
            "(/home/node/.claude) — only the project-level "
            "/workspace/.claude/. Masking HOME breaks claude login/creds."
        )


class TestBuildConfig:
    """Verify BuildConfig is correctly parsed from YAML."""

    def test_openclaw_scaffold_has_build_section(self):
        """The rendered openclaw scaffold should include a build section."""
        build = yaml.safe_load(_rendered_text("openclaw"))["container"]["build"]
        assert build["containerfile"] == "Containerfile"
        assert "BASE_IMAGE" in build["args"]
