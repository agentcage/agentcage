"""Unit tests for the apple-container backend (offline; mocks subprocess)."""

from __future__ import annotations

import importlib.util
import json
import platform
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentcage.apple_container import cli as ac_cli
from agentcage.apple_container import prerequisites as ac_prereq
from agentcage.apple_container import scaffold as ac_scaffold
from agentcage.apple_container import wrapper as ac_wrapper
from agentcage.backends.apple_container import AppleContainerBackend
from agentcage.config import Config, default_isolation, validate_config


# The addon file ships inside the wheel as a data file (it runs
# *inside* the cage's mitmproxy process, not in the host Python).
# To unit-test ``AllowlistAddon`` from the host, we load it by
# absolute path; conftest.py already stubs ``mitmproxy`` so the
# import succeeds without the real proxy bundle being installed.



# ---------------------------------------------------------------------------
# prerequisites
# ---------------------------------------------------------------------------

def test_prereqs_non_darwin_blocks():
    with patch.object(platform, "system", return_value="Linux"):
        issues = ac_prereq.check_prerequisites()
    assert issues
    assert "macOS" in issues[0]


def test_prereqs_wrong_arch_flagged():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="x86_64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "x86_64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_cli, "system_running", return_value=True):
        issues = ac_prereq.check_prerequisites()
    assert any("Apple Silicon" in s for s in issues)


def test_prereqs_macos_too_old_flagged():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("15.6.1", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_cli, "system_running", return_value=True):
        issues = ac_prereq.check_prerequisites()
    assert any("macOS 26+" in s for s in issues)


def test_prereqs_cli_missing_flagged():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value=None):
        issues = ac_prereq.check_prerequisites()
    assert any("'container' CLI not found" in s for s in issues)


def test_prereqs_apiserver_stopped_distinct_from_missing():
    """We want different hints for 'not installed' vs 'installed but stopped'."""
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_cli, "system_running", return_value=False):
        issues = ac_prereq.check_prerequisites()
    assert any("apiserver is not running" in s for s in issues)


def test_start_auto_starts_apiserver_when_down(tmp_path, monkeypatch):
    """The apiserver doesn't survive a reboot. Rather than make the user
    run `container system start` by hand, start() brings it up itself
    (mirroring the Lima backend's VM auto-start) and then proceeds."""
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
        },
    )
    # Down on the first probe, up after `system start` runs.
    states = iter([False, True, True, True, True])
    monkeypatch.setattr(ac_cli, "system_running", lambda: next(states))

    backend.start("demo", quiet=True)

    assert ["system", "start", "--enable-kernel-install"] in captured


def test_start_errors_when_apiserver_wont_start(tmp_path, monkeypatch):
    """If the daemon stays down even after we try to start it, raise an
    actionable error — never the misleading 'wrapped image not found'."""
    backend = AppleContainerBackend()
    monkeypatch.setattr(backend, "unit_dir", lambda: tmp_path)
    (tmp_path / "pi01.json").write_text(json.dumps({"autostart": False}))

    with patch.object(ac_cli, "system_running", return_value=False), \
         patch.object(ac_cli, "run") as run, \
         patch.object(ac_cli, "image_inspect") as image_inspect:
        with pytest.raises(RuntimeError) as excinfo:
            backend.start("pi01", quiet=True)

    assert "apiserver is not running" in str(excinfo.value)
    assert "container system start" in str(excinfo.value)
    # We attempted the auto-start before giving up.
    assert ["system", "start", "--enable-kernel-install"] in [
        c.args[0] for c in run.call_args_list
    ]
    # Bailed before ever probing images.
    image_inspect.assert_not_called()


def test_ensure_ready_starts_apiserver_when_down():
    """ensure_ready() is the recoverable-substrate step the CLI runs before
    build/start: a downed apiserver gets `container system start`."""
    backend = AppleContainerBackend()
    states = iter([False, True])  # down, then up after start
    with patch.object(ac_cli, "system_running", side_effect=lambda: next(states)), \
         patch.object(ac_cli, "run") as run:
        backend.ensure_ready(quiet=True)
    assert ["system", "start", "--enable-kernel-install"] in [
        c.args[0] for c in run.call_args_list
    ]


def test_ensure_ready_noop_when_apiserver_already_running():
    """If the daemon is already up, ensure_ready() must not touch it."""
    backend = AppleContainerBackend()
    with patch.object(ac_cli, "system_running", return_value=True), \
         patch.object(ac_cli, "run") as run:
        backend.ensure_ready(quiet=True)
    run.assert_not_called()


def test_ensure_ready_swallows_missing_cli():
    """When the `container` CLI isn't installed, ensure_ready() has nothing
    to recover and must not raise — check_prerequisites() reports the
    missing CLI with an install hint instead."""
    backend = AppleContainerBackend()
    with patch.object(ac_cli, "system_running", return_value=False), \
         patch.object(ac_cli, "run", side_effect=FileNotFoundError):
        backend.ensure_ready(quiet=True)  # no exception


def test_ensure_backend_ready_gate_recovers_then_passes():
    """The CLI gate auto-recovers the substrate, then proceeds when no
    prerequisites are unmet — returning the backend for reuse."""
    from agentcage import cli
    backend = MagicMock()
    backend.check_prerequisites.return_value = []
    cfg = Config(name="t", isolation="apple-container")
    with patch.object(cli, "get_backend", return_value=backend):
        result = cli._ensure_backend_ready(cfg)
    backend.ensure_ready.assert_called_once()
    assert result is backend


def test_ensure_backend_ready_gate_aborts_on_unmet_prereqs():
    """Whatever ensure_ready() couldn't fix (reported by check_prerequisites)
    aborts the command with a non-zero exit and the issue text — this is the
    path that turns a downed-and-unstartable apiserver into an actionable
    message instead of the misleading 'image not found'."""
    from agentcage import cli
    backend = MagicMock()
    backend.check_prerequisites.return_value = [
        "Apple container apiserver is not running — run 'container system start'",
    ]
    cfg = Config(name="t", isolation="apple-container")
    with patch.object(cli, "get_backend", return_value=backend):
        with pytest.raises(SystemExit) as excinfo:
            cli._ensure_backend_ready(cfg)
    assert excinfo.value.code == 1


# ---------------------------------------------------------------------------
# config validation
# ---------------------------------------------------------------------------

def test_apple_container_isolation_value_accepted():
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "alpine:3.20"
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"):
        validate_config(cfg)  # should not raise


def test_apple_container_isolation_rejects_linux():
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "alpine:3.20"
    with patch.object(platform, "system", return_value="Linux"):
        with pytest.raises(ValueError, match="requires macOS"):
            validate_config(cfg)


def test_apple_container_isolation_rejects_intel():
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "alpine:3.20"
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="x86_64"):
        with pytest.raises(ValueError, match="Apple Silicon"):
            validate_config(cfg)


def test_default_isolation_linux_is_container():
    with patch.object(platform, "system", return_value="Linux"):
        assert default_isolation() == "container"


def test_default_isolation_intel_mac_is_vm():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="x86_64"):
        assert default_isolation() == "vm"


def test_default_isolation_old_macos_is_vm():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("15.6.1", ("", "", ""), "arm64")):
        assert default_isolation() == "vm"


def test_default_isolation_macos_26_without_container_cli_is_vm():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value=None):
        assert default_isolation() == "vm"


def test_default_isolation_macos_26_with_container_cli_is_apple_container():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.3.2", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"):
        assert default_isolation() == "apple-container"


def test_unknown_isolation_rejected():
    cfg = Config(name="t", isolation="banana")
    cfg.container.image = "alpine:3.20"
    with pytest.raises(ValueError, match="isolation must be"):
        validate_config(cfg)


# ---------------------------------------------------------------------------
# wrapper rendering
# ---------------------------------------------------------------------------

def test_render_wrapper_embeds_user_image():
    """PR 3 (2-microVM model): the wrapper template embeds the user image
    + bakes the shlex-quoted user CMD into a one-shot script. No more
    COPY of supervisor.sh / cage-cmd.json / dnsmasq.conf etc."""
    out = ac_wrapper.render_wrapper_containerfile(
        "docker.io/library/alpine:3.20",
        user_cmd=["sh", "-c", "echo hi"],
    )
    assert "FROM docker.io/library/alpine:3.20" in out
    # The user CMD is shlex-escaped and baked into cage-cmd.sh by a RUN
    # heredoc — no jq, no JSON parse at runtime.
    assert "/opt/agentcage/cage-cmd.sh" in out
    assert 'ENTRYPOINT ["/opt/agentcage/cage-init.sh"]' in out
    # The legacy supervisor entrypoint must be GONE — slim wrapper now.
    assert "/opt/agentcage/supervisor" not in out


def test_render_wrapper_shell_escapes_user_cmd():
    """User CMD is shell-escaped via Python's shlex.quote() at template
    render time and baked into a one-shot script via a RUN heredoc.

    This closes the I2 argv-injection risk from the eng review on the
    prior runtime-jq approach: every metacharacter (whitespace, $VAR,
    ;, ` etc.) is escaped host-side before reaching the cage VM, and
    nothing inside the cage interprets it except `sh -c "exec ..."`."""
    out = ac_wrapper.render_wrapper_containerfile(
        "alpine:3.20",
        user_cmd=["sh", "-c", "echo $FOO && wait"],
    )
    # The shlex.quote'd form of `echo $FOO && wait` is a single-quoted
    # string. We just check that the user's literal CMD substring is
    # NOT present in raw form (which would mean shell metacharacters
    # leaked unescaped) — and that the quoted form IS present.
    assert "exec sh -c 'echo $FOO && wait'" in out


def test_stage_build_context_writes_cage_init(tmp_path):
    """The slim build context only stages cage-init.sh. Every per-cage
    proxy/dns config file (cage-cmd.json, allowlist.txt, dnsmasq.conf,
    secret_injection.json, transforms.tar.gz, etc.) moved out of the
    wrapper image — they're rendered host-side by build_artifacts and
    bind-mounted into the egress sibling at runtime."""
    ac_wrapper.stage_build_context(tmp_path, ["sh", "-c", "echo hi"])
    assert (tmp_path / "cage-init.sh").exists()
    cage_init = (tmp_path / "cage-init.sh").read_text()
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
    # apple-container requires macOS 26+ (apple_container/prerequisites.py),
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
    # Legacy files must NOT be staged.
    assert not (tmp_path / "supervisor.sh").exists()
    assert not (tmp_path / "allowlist_addon.py").exists()
    assert not (tmp_path / "transforms.tar.gz").exists()
    assert not (tmp_path / "secret_injection.json").exists()
    assert not (tmp_path / "cage-cmd.json").exists()


def test_render_dnsmasq_conf_per_zone_recursion():
    """`render_dnsmasq_conf` produces the same dnsmasq.conf shape as the
    legacy single-VM build (per-zone server=/apex/upstream forwarders +
    address=/#/sinkhole), just rendered host-side instead of into the
    wrapper image. The egress sibling bind-mounts the result."""
    conf = ac_wrapper.render_dnsmasq_conf(["a.com"])
    assert "server=/a.com/1.1.1.1" in conf
    assert "address=/#/198.51.100.1" in conf


# ── DNS non-A-record exfil regression (CTF-derived) ──────────────────
# CTF discovery on 0.21.x: dnsmasq's `address=/#/<sinkhole>` only
# intercepts A and AAAA. Any other RR type (TXT/MX/NS/SRV/CNAME) for
# any hostname falls through to the default upstream (`server=<ip>`
# without a domain prefix) and reaches a real recursive resolver — an
# attacker who owns a delegated subdomain can encode bytes in DNS labels
# and exfil fully out-of-band, never touching mitmproxy. These tests
# pin the bypass SHAPE, not just the absence of a substring.

def test_apple_dnsmasq_no_blanket_default_upstream():
    """No `server=<ip>` line without a domain scope. A blanket default
    upstream lets dnsmasq recursively answer ANY non-A query — TXT, MX,
    NS, SRV, CNAME — for ANY hostname, regardless of allowlist.

    PR 3 moved this rendering from `stage_build_context` (build-time
    into the wrapper image) to `render_dnsmasq_conf` (host-side, then
    bind-mounted into the egress sibling). The shape invariants are
    unchanged — the test just calls the renderer directly now."""
    import re
    conf = ac_wrapper.render_dnsmasq_conf(
        ["a.com", "b.org"], dns_servers=["1.1.1.1", "8.8.8.8"],
    )
    for line in conf.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        # Per-zone forwarders are `server=/<domain>/<ip>` and ARE allowed.
        # Blanket `server=<ip>` (no leading slash) leaks non-A queries.
        assert not re.match(r"^\s*server=[^/]", stripped), (
            f"blanket default-upstream `server=<ip>` line leaks non-A "
            f"queries to upstream: {stripped!r}"
        )


def test_apple_dnsmasq_recursion_scoped_to_allowlist():
    """Recursion must be scoped per-allowlisted-apex × per-upstream."""
    conf = ac_wrapper.render_dnsmasq_conf(
        ["api.anthropic.com", "github.com"],
        dns_servers=["1.1.1.1", "8.8.8.8"],
    )
    for domain in ("api.anthropic.com", "github.com"):
        for upstream in ("1.1.1.1", "8.8.8.8"):
            assert f"server=/{domain}/{upstream}" in conf, (
                f"missing per-zone forwarder server=/{domain}/{upstream}"
            )


def test_apple_dnsmasq_empty_allowlist_has_no_upstream():
    """Empty allowlist → no upstream forwarders at all."""
    import re
    conf = ac_wrapper.render_dnsmasq_conf([])
    for line in conf.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        assert not re.match(r"^\s*server=", stripped), (
            f"empty allowlist should yield no upstream forwarders, got: "
            f"{stripped!r}"
        )
    assert "address=/#/198.51.100.1" in conf


def test_apple_dnsmasq_sinkhole_present_with_allowlist():
    """The `address=/#/<sinkhole>` line must remain even when the
    allowlist is populated — sinks A/AAAA for non-allowlisted zones."""
    conf = ac_wrapper.render_dnsmasq_conf(["a.com"])
    assert "address=/#/198.51.100.1" in conf


def test_apple_dnsmasq_no_resolv_preserved():
    """`no-resolv` MUST be set so dnsmasq never reads /etc/resolv.conf."""
    conf = ac_wrapper.render_dnsmasq_conf(["a.com"])
    assert any(
        ln.strip() == "no-resolv"
        for ln in conf.splitlines()
    ), "no-resolv missing — dnsmasq would silently fall back to /etc/resolv.conf"


# Tests that previously verified the wrapper build context staged
# `secret_injection.json`, `transforms.tar.gz`, etc. were removed when PR
# 3 moved all proxy/dns/secret config out of the wrapper image. The
# equivalent invariants are now tested by:
#   * tests/test_egress_image.py (the agentcage-egress image carries the
#     proxy code).
#   * The host-side render tests below (proxy-config.yaml shape).
#     the addon's behaviour, importing from
#     file is retained as a test fixture; it is no longer baked into any
#     image).





def test_generate_units_persists_autostart_flag():
    """`apple_container_autostart: true` in cage.yaml flows into the unit
    JSON's `autostart` field. `start()` reads this to decide whether to
    install a launchd plist."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.apple_container_autostart = True

    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["autostart"] is True


def test_generate_units_autostart_default_false():
    """Autostart is opt-in. Cages that don't set the flag get
    `autostart: false` in the unit JSON; `start()` skips the plist."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["autostart"] is False


def test_launchd_plist_path_is_under_user_launchagents():
    """plist file goes under ~/Library/LaunchAgents — user-scope so no
    sudo, runs at the user's login session."""
    p = AppleContainerBackend()._launchd_plist_path("demo")
    assert str(p).endswith("/Library/LaunchAgents/io.agentcage.demo.plist")


def test_install_launchd_plist_writes_well_formed_xml(tmp_path, monkeypatch):
    """`_install_launchd_plist` writes a valid Apple plist XML with the
    expected ProgramArguments shape and the cage name in the Label."""
    backend = AppleContainerBackend()
    monkeypatch.setattr(backend, "_launchd_plist_path",
                        lambda name: tmp_path / f"io.agentcage.{name}.plist")
    monkeypatch.setattr(backend, "_state_dir",
                        lambda name: tmp_path / f"state-{name}")
    with patch.object(ac_cli, "container_binary",
                       return_value="/usr/local/bin/container"), \
         patch("subprocess.run",
               return_value=type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()):
        backend._install_launchd_plist("demo")

    plist_text = (tmp_path / "io.agentcage.demo.plist").read_text()
    assert "<key>Label</key>" in plist_text
    assert "<string>io.agentcage.demo</string>" in plist_text
    assert "<string>/usr/local/bin/container</string>" in plist_text
    assert "<string>start</string>" in plist_text
    assert "<string>demo</string>" in plist_text
    # Well-formedness: round-trip via plistlib.
    import plistlib
    parsed = plistlib.loads(plist_text.encode())
    assert parsed["Label"] == "io.agentcage.demo"
    assert parsed["RunAtLoad"] is True
    assert parsed["ProgramArguments"][-1] == "demo"


def test_install_launchd_plist_calls_bootstrap_in_gui_domain(tmp_path, monkeypatch):
    """The whole point of this fix: `launchctl bootstrap gui/<uid>` is
    the modern API. Pre-fix the install path called `launchctl load -w`
    which is deprecated since macOS 10.10 and silently no-ops in many
    contexts — the symptom was the plist file existing but
    `launchctl list` showing nothing. Issue: F2 in torture-mac findings."""
    backend = AppleContainerBackend()
    monkeypatch.setattr(backend, "_launchd_plist_path",
                        lambda name: tmp_path / f"io.agentcage.{name}.plist")
    monkeypatch.setattr(backend, "_state_dir",
                        lambda name: tmp_path / f"state-{name}")
    monkeypatch.setattr("os.getuid", lambda: 501)
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "container_binary",
                       return_value="/usr/local/bin/container"), \
         patch("subprocess.run", side_effect=fake_run):
        backend._install_launchd_plist("demo")

    # bootout (pre-bootstrap) targets the modern domain/label form.
    bootouts = [c for c in calls if c[:2] == ["launchctl", "bootout"]]
    assert any("gui/501/io.agentcage.demo" in " ".join(c) for c in bootouts), \
        f"expected `bootout gui/501/io.agentcage.demo`, got {bootouts}"
    # bootstrap is the post-write load step.
    bootstraps = [c for c in calls if c[:2] == ["launchctl", "bootstrap"]]
    assert len(bootstraps) == 1, f"expected exactly 1 bootstrap call, got {bootstraps}"
    assert "gui/501" in bootstraps[0], f"expected gui/501 domain in {bootstraps[0]}"
    assert str(tmp_path / "io.agentcage.demo.plist") in bootstraps[0]


def test_install_launchd_plist_falls_back_to_load_when_bootstrap_fails(
    tmp_path, monkeypatch,
):
    """If `launchctl bootstrap` fails (very old macOS, no GUI session,
    permissions oddity), fall back to the legacy `launchctl load -w`
    path so the operator never gets worse behavior than before the fix.
    Only when BOTH fail do we warn loudly."""
    backend = AppleContainerBackend()
    monkeypatch.setattr(backend, "_launchd_plist_path",
                        lambda name: tmp_path / f"io.agentcage.{name}.plist")
    monkeypatch.setattr(backend, "_state_dir",
                        lambda name: tmp_path / f"state-{name}")
    monkeypatch.setattr("os.getuid", lambda: 501)
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        # bootstrap fails; subsequent unload+load succeed.
        if argv[:2] == ["launchctl", "bootstrap"]:
            return type("CP", (), {"returncode": 1, "stdout": "",
                                   "stderr": "Bootstrap failed: 5: Input/output error"})()
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "container_binary",
                       return_value="/usr/local/bin/container"), \
         patch("subprocess.run", side_effect=fake_run):
        backend._install_launchd_plist("demo")

    # bootstrap was tried...
    assert any(c[:2] == ["launchctl", "bootstrap"] for c in calls)
    # ...and then `load -w` ran as fallback.
    loads = [c for c in calls if c[:3] == ["launchctl", "load", "-w"]]
    assert len(loads) == 1, f"expected exactly 1 fallback load -w, got {loads}"


def test_uninstall_launchd_plist_calls_bootout(tmp_path, monkeypatch):
    """Mirror of install: uninstall must use `launchctl bootout
    gui/<uid>/<label>` for services we installed via bootstrap. Legacy
    `unload` also tried as a belt for any plists from the fallback path."""
    backend = AppleContainerBackend()
    plist_path = tmp_path / "io.agentcage.demo.plist"
    plist_path.write_text("<plist/>")
    monkeypatch.setattr(backend, "_launchd_plist_path", lambda name: plist_path)
    monkeypatch.setattr("os.getuid", lambda: 501)
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch("subprocess.run", side_effect=fake_run):
        backend._uninstall_launchd_plist("demo")

    assert any(c[:2] == ["launchctl", "bootout"]
               and "gui/501/io.agentcage.demo" in " ".join(c)
               for c in calls), f"missing bootout in {calls}"
    # plist file removed.
    assert not plist_path.exists()


# ── 2-microVM start() helpers ────────────────────────────────
# PR 3 split start() into two `container run` calls: <name>-egress (egress
# image, holds secrets bind-mount) and <name> (slim wrapper, holds the
# placeholder env). The helpers below set up the minimum scaffolding
# (unit JSON + egress_config_dir + mocked egress IP lookup) so tests can
# focus on the assertion they care about.

def _setup_start_test(tmp_path, monkeypatch, *, unit_meta):
    """Common scaffolding for backend.start() tests.

    Returns (backend, unit_dir, logs_dir, secrets_dir, captured_runs).
    `captured_runs` is a list of argv lists in call order. The mocked
    network-IP lookup returns "192.168.64.5" so cage-init has something
    to set as the default route.
    """
    import agentcage.state as _state
    monkeypatch.setattr(_state, "_DEPLOYMENTS_DIR", tmp_path / "cages")

    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    # On Linux CI the macOS keychain is unavailable; the stage tests seed a
    # pending_secrets.json, so default the unit to the plaintext backend
    # (ApplePlaintextStore reads that file).
    unit_meta.setdefault("secrets_backend", "plaintext")
    (unit_dir / "demo.json").write_text(json.dumps(unit_meta))

    logs_dir = tmp_path / "logs"
    secrets_dir = tmp_path / "secrets"
    egress_cfg = tmp_path / "egress-config"
    egress_cfg.mkdir(parents=True, exist_ok=True)
    (egress_cfg / "proxy-config.yaml").write_text("name: demo\n")
    (egress_cfg / "dnsmasq.conf").write_text("# stub\n")
    (egress_cfg / "dns-allowlist.conf").write_text("\n")
    certs_dir = tmp_path / "certs"
    public_certs_dir = tmp_path / "public-certs"

    captured: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        captured.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(backend, "unit_dir", lambda: unit_dir)
    monkeypatch.setattr(backend, "logs_dir", lambda _n: logs_dir)
    monkeypatch.setattr(backend, "secrets_dir", lambda _n: secrets_dir)
    # The post-boot secret wipe is tested separately; keep staged files in
    # place so the staging assertions below can inspect them.
    monkeypatch.setattr(backend, "_wipe_staged_secrets", lambda _n: None)
    monkeypatch.setattr(backend, "egress_config_dir", lambda _n: egress_cfg)
    monkeypatch.setattr(backend, "certs_dir", lambda _n: certs_dir)
    monkeypatch.setattr(
        backend, "public_certs_dir", lambda _n: public_certs_dir,
    )
    # start() guards on the apiserver being up before probing images.
    monkeypatch.setattr(ac_cli, "system_running", lambda: True)
    monkeypatch.setattr(
        ac_cli, "image_inspect", lambda _img: {"config": {}},
    )
    monkeypatch.setattr(ac_cli, "inspect", lambda _name: None)
    monkeypatch.setattr(ac_cli, "run", fake_run)
    monkeypatch.setattr(
        backend, "_wait_supervisor_ready", lambda *a, **k: None,
    )
    monkeypatch.setattr(
        backend, "_container_ip", lambda _n: "192.168.64.5",
    )
    return backend, captured


def _cage_run_argv(captured: list[list[str]]) -> list[str]:
    """Extract the `container run` argv for the cage VM (the slim wrapper).

    There are two `run` calls per start(): egress (named <name>-egress)
    and cage (named <name>). The cage call carries the wrapper image tag
    `localhost/agentcage-apple-<name>:latest` as its last positional
    argument.
    """
    for argv in captured:
        if argv and argv[0] == "run" and any("agentcage-apple-" in a for a in argv):
            return argv
    raise AssertionError(f"no cage `run` argv in {captured!r}")


def _egress_run_argv(captured: list[list[str]]) -> list[str]:
    """Extract the egress sibling's run argv (image = agentcage-egress)."""
    for argv in captured:
        if argv and argv[0] == "run" and any("agentcage-egress" in a for a in argv):
            return argv
    raise AssertionError(f"no egress `run` argv in {captured!r}")


def test_start_argv_uses_file_delivery_when_placeholders_known(
    tmp_path, monkeypatch,
):
    """0.21.1+ hardened path: when the unit JSON carries
    ``secret_env_placeholders``, start() writes the resolved value to
    ``<secrets_dir>/<env-name>`` (mode 0600) and passes
    ``-e <env>={{<env>}}`` (the placeholder, NOT the cleartext value) to
    `container run`. PR 3 moves the bind-mount target from
    /run/agentcage/secrets:ro (in the cage VM) to /home/acproxy/secrets:ro
    (in the egress sibling) — the cage VM never sees the cleartext
    secrets at all."""
    import agentcage.state as _state

    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo",
            "user_image": "x",
            "cpus": "",
            "memory": "",
            "lifecycle": "interactive",
            "secret_envs": ["API_KEY", "MISSING_KEY"],
            "secret_env_placeholders": {
                "API_KEY": "{{API_KEY}}",
                "MISSING_KEY": "{{MISSING_KEY}}",
            },
        },
    )
    deploy_dir = _state.deployment_dir("demo")
    deploy_dir.mkdir(parents=True, exist_ok=True)
    (deploy_dir / "pending_secrets.json").write_text(
        json.dumps([["API_KEY", "sk-real-1234"]])
    )
    monkeypatch.setenv("API_KEY", "from-host-env-DO-NOT-USE")
    monkeypatch.setenv("MISSING_KEY", "from-host-env-DO-NOT-USE")

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    egress_argv = _egress_run_argv(captured)
    secrets_dir = tmp_path / "secrets"

    # The cage VM's env carries the placeholder, NEVER the raw value.
    assert "API_KEY={{API_KEY}}" in cage_argv
    assert "sk-real-1234" not in " ".join(cage_argv)
    # The secrets bind-mount is on the EGRESS sibling at /home/acproxy/secrets.
    assert any(
        a == f"{secrets_dir}:/home/acproxy/secrets:ro" for a in egress_argv
    )
    # And the cage VM has NO secrets bind — the cleartext is in a
    # different microVM's namespace entirely.
    assert all("secrets" not in a or ":/certs" in a for a in cage_argv)
    # The secret file exists on the host, mode 0600, real value.
    secret_file = secrets_dir / "API_KEY"
    assert secret_file.is_file()
    assert secret_file.read_text() == "sk-real-1234"
    assert oct(secret_file.stat().st_mode & 0o777) == "0o600"
    # Missing key skipped.
    assert not (secrets_dir / "MISSING_KEY").exists()
    assert "MISSING_KEY=" not in " ".join(cage_argv)
    # Host env never leaks anywhere.
    assert "from-host-env-DO-NOT-USE" not in " ".join(cage_argv)
    assert "from-host-env-DO-NOT-USE" not in " ".join(egress_argv)
    assert oct(secrets_dir.stat().st_mode & 0o777) == "0o700"


def test_start_argv_injects_proxy_ca_env_vars(tmp_path, monkeypatch):
    """Apple-container's cage VM must get SSL_CERT_FILE and NODE_EXTRA_CA_CERTS
    pointing at /certs/mitmproxy-ca-cert.pem so HTTPS clients trust the
    egress MITM CA without waiting for cage-init.sh stage C to finish the
    update-ca-certificates dance. Mirrors cage.container.j2 lines 14-15
    on the container backend. Regression guard: the 0.22.0 3→2-service
    unification dropped these env vars and claude-code 2.1.x silently
    exited 0 from `-p` when its HTTPS calls failed cert verification.
    """
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
        },
    )

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    assert "SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem" in cage_argv
    assert "NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem" in cage_argv


def test_start_cage_mounts_certs_read_only(tmp_path, monkeypatch):
    """CTF (#275, 0.25.4): the public-cert dir must be bound at /certs
    read-only. The uid-1000 workload is told to TRUST this CA via
    SSL_CERT_FILE / NODE_EXTRA_CA_CERTS; a writable virtiofs mount let it
    tamper with, replace, or persist host-backed files under /certs,
    violating the cage->egress trust boundary. Mirrors the quadlet
    backend's `:/certs:ro,Z` (cage.container.j2)."""
    public_certs_dir = tmp_path / "public-certs"
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
        },
    )

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    # The cage sees /certs read-only — never a writable bind.
    assert f"{public_certs_dir}:/certs:ro" in cage_argv
    assert f"{public_certs_dir}:/certs" not in cage_argv
    certs_binds = [a for a in cage_argv if a.endswith((":/certs", ":/certs:ro"))]
    assert certs_binds == [f"{public_certs_dir}:/certs:ro"]


def test_start_cage_binds_dnsmasq_conf_for_local_resolver(tmp_path, monkeypatch):
    """CTF F2 (0.22.6): the cage's local dnsmasq (cage-init.sh stage A')
    reads the same dnsmasq.conf the egress sibling does, bind-mounted
    from the host's egress-config dir. macOS vmnet drops inter-microVM
    UDP (verified against apple/container source), so the cage cannot
    reach the egress's dnsmasq on .2:53; the only fix is a local
    resolver scoped to the same config. Without these binds the cage's
    dnsmasq has nothing to load and falls back to the apple gateway
    (the F2 exfil channel)."""
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
        },
    )

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    egress_cfg = tmp_path / "egress-config"

    assert (
        f"{egress_cfg}/dnsmasq.conf:/etc/agentcage/dnsmasq.conf:ro"
        in cage_argv
    )
    assert (
        f"{egress_cfg}/dns-allowlist.conf:/etc/agentcage/dns-allowlist.conf:ro"
        in cage_argv
    )
    # The env var that cage-init.sh interpolates into the dnsmasq
    # --servers-file flag — without it the cage's dnsmasq would not
    # know the per-cage upstream forwarders.
    assert (
        "AGENTCAGE_DNS_SERVERS_FILE=/etc/agentcage/dns-allowlist.conf"
        in cage_argv
    )


def test_start_cage_bind_excludes_ca_private_key(tmp_path, monkeypatch):
    """CTF F1 (0.22.5): the cage's /certs bind-mount MUST come from
    ``public_certs_dir``, not ``certs_dir``. ``certs_dir`` is mitmproxy's
    full ~/.mitmproxy/ — it contains ``mitmproxy-ca.pem`` (the CA
    *private* key) which a uid-1000 cage workload could read and use to
    mint a forged trusted cert for any allowlisted host, defeating the
    egress's trust-store guard. 0.22.6 regression guard.
    """
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
        },
    )

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    egress_argv = _egress_run_argv(captured)
    certs_dir = str(tmp_path / "certs")
    public_certs_dir = str(tmp_path / "public-certs")

    # Cage's /certs MUST come from public_certs_dir (and be read-only;
    # see test_start_cage_mounts_certs_read_only / #275).
    assert f"{public_certs_dir}:/certs:ro" in cage_argv
    # Cage MUST NOT mount certs_dir anywhere (any guest path) — that
    # would re-introduce the CA-private-key leak. Anchor on the host
    # path so an empty certs_dir name (unlikely tmp_path collision)
    # doesn't false-match.
    for a in cage_argv:
        assert not (
            a.startswith(certs_dir + ":") and not a.startswith(public_certs_dir + ":")
        ), f"cage argv leaks certs_dir mount: {a!r}"

    # Egress still gets the full mitmproxy dir (needs the private key
    # to mint per-host certs).
    assert f"{certs_dir}:/home/acproxy/.mitmproxy" in egress_argv
    # Egress also gets the public-cert dir so supervisor-egress.sh's
    # Step E can copy the cert there for the cage to pick up.
    assert f"{public_certs_dir}:/home/acproxy/public-certs" in egress_argv


def test_start_secrets_bind_only_to_egress(tmp_path, monkeypatch):
    """Threat-model invariant for PR 3: the secrets bind-mount appears
    on the egress sibling's argv and NEVER on the cage VM's argv. This
    is the load-bearing change — `cage exec --user 0 <cage>` cannot
    read /home/acproxy/secrets because the mount isn't in its namespace."""
    import agentcage.state as _state

    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
            "secret_envs": ["API_KEY"],
            "secret_env_placeholders": {"API_KEY": "{{API_KEY}}"},
        },
    )
    deploy_dir = _state.deployment_dir("demo")
    deploy_dir.mkdir(parents=True, exist_ok=True)
    (deploy_dir / "pending_secrets.json").write_text(
        json.dumps([["API_KEY", "sk-secret"]])
    )

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    egress_argv = _egress_run_argv(captured)
    secrets_dir = str(tmp_path / "secrets")

    # Bind appears on egress run argv.
    assert any(
        a.startswith(f"{secrets_dir}:") and "secrets" in a
        for a in egress_argv
    ), f"missing secrets bind on egress argv: {egress_argv}"
    # And NOT on cage run argv (other than the /certs bind, which is a
    # different host dir).
    for a in cage_argv:
        if a.startswith(secrets_dir):
            raise AssertionError(
                f"secrets bind leaked into cage VM argv: {a!r}"
            )


def test_start_argv_drops_stale_secrets_from_prior_starts(
    tmp_path, monkeypatch,
):
    """start() removes pre-existing files in <secrets_dir> so a rule
    that's been removed from cage.yaml doesn't linger in the bind mount
    after `cage update`."""
    import agentcage.state as _state

    backend, _captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
            "secret_envs": ["NEW_KEY"],
            "secret_env_placeholders": {"NEW_KEY": "{{NEW_KEY}}"},
        },
    )
    deploy_dir = _state.deployment_dir("demo")
    deploy_dir.mkdir(parents=True, exist_ok=True)
    (deploy_dir / "pending_secrets.json").write_text(
        json.dumps([["NEW_KEY", "new-value"]])
    )

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "OLD_KEY").write_text("old-stale-value")

    backend.start("demo", quiet=True)

    assert not (secrets_dir / "OLD_KEY").exists()
    assert (secrets_dir / "NEW_KEY").read_text() == "new-value"


def test_start_argv_pre_021_1_unit_json_refuses_cleartext_fallback(
    tmp_path, monkeypatch,
):
    """Pre-0.21.1 unit JSON (no ``secret_env_placeholders``) MUST NOT
    fall back to cleartext -e. Operator gets a warning + skip."""
    import agentcage.state as _state

    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
            "secret_envs": ["API_KEY"],
            # no secret_env_placeholders — pre-0.21.1 shape
        },
    )
    deploy_dir = _state.deployment_dir("demo")
    deploy_dir.mkdir(parents=True, exist_ok=True)
    (deploy_dir / "pending_secrets.json").write_text(
        json.dumps([["API_KEY", "sk-real-1234"]])
    )
    monkeypatch.setenv("API_KEY", "sk-real-1234")

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    egress_argv = _egress_run_argv(captured)
    # Value MUST NOT appear anywhere on either container run argv.
    assert "sk-real-1234" not in " ".join(cage_argv)
    assert "sk-real-1234" not in " ".join(egress_argv)
    assert "API_KEY=sk-real-1234" not in cage_argv
    # No secret file written (placeholder map missing → refuse fallback).
    secrets_dir = tmp_path / "secrets"
    assert not (secrets_dir / "API_KEY").exists()


def test_generate_units_persists_secret_env_placeholders():
    """generate_units writes the env→placeholder map for start() to use."""
    from agentcage.config import SecretInjectionRule
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.secret_injection = [
        SecretInjectionRule(env="API_KEY", placeholder="{{API_KEY}}"),
        SecretInjectionRule(env="DB_URL", placeholder="{{DATABASE_URL}}"),
    ]
    units = AppleContainerBackend().generate_units(cfg, "/cfg", "/p", "deploy")
    meta = json.loads(units["deploy.json"])
    assert meta["secret_env_placeholders"] == {
        "API_KEY": "{{API_KEY}}",
        "DB_URL": "{{DATABASE_URL}}",
    }
    # secret_envs still present for backward compat.
    assert meta["secret_envs"] == ["API_KEY", "DB_URL"]


# supervisor.sh secret-restaging tests removed in PR 3 — the file is
# gone (the cage VM has no supervisor; the egress sibling has its own
# supervisor-egress.sh which reads secrets from a bind-mounted dir
# directly, no re-staging needed). The corresponding invariant for the
# 2-VM model — secrets bind-mount lives ONLY in the egress VM, NOT in
# the cage VM — is enforced by test_start_secrets_bind_only_to_egress
# below.


def test_start_argv_ignores_host_env_when_pending_secrets_missing(
    tmp_path, monkeypatch,
):
    """Regression for the implicit-env-secret leak: host env is never
    used as an implicit secret source — only --set-secret values are
    honored.

    NOTE(PR3): the cage VM still carries the placeholder env even when
    the value isn't provided (so cage code that reads
    ``os.environ['API_KEY']`` always gets ``{{API_KEY}}``, never an
    unset key). The mitmproxy addon then sees the placeholder string in
    the request and emits a warning. This differs from the legacy
    single-VM model which conditionally added the -e flag, but the
    invariant `cleartext never leaks` is preserved either way."""
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
            "secret_envs": ["API_KEY"],
            "secret_env_placeholders": {"API_KEY": "{{API_KEY}}"},
        },
    )
    monkeypatch.setenv("API_KEY", "from-host-env-DO-NOT-USE")

    backend.start("demo", quiet=True)

    cage_argv = _cage_run_argv(captured)
    egress_argv = _egress_run_argv(captured)
    secrets_dir = tmp_path / "secrets"

    # Host-env value MUST NOT leak anywhere.
    assert "from-host-env-DO-NOT-USE" not in " ".join(cage_argv)
    assert "from-host-env-DO-NOT-USE" not in " ".join(egress_argv)
    # No secret file written (no value was provided).
    assert not (secrets_dir / "API_KEY").exists()


# Legacy in-cage iptables NAT REDIRECT tests removed in PR 3 — the cage
# VM has no iptables/uid-owner rules anymore. The equivalent invariant
# (cage egress flows through the proxy regardless of which uid issued
# the request) is now enforced by the egress sibling's PREROUTING
# REDIRECT (see tests/test_egress_image.py::test_iptables_rules_applied).


def test_dnsmasq_strips_aaaa_records():
    """REGRESSION: dnsmasq must `filter-AAAA` so clients don't waste time
    trying IPv6 addresses they can never reach. Same invariant as the
    legacy single-VM model, just rendered host-side now."""
    conf = ac_wrapper.render_dnsmasq_conf(["a.com"])
    assert "filter-AAAA" in conf


def test_cage_init_resolves_cage_user_dynamically():
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


def test_ubuntu_scaffold_ca_install_tolerates_eacces():
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


def test_user_cmd_missing_image_raises():
    with patch.object(ac_cli, "image_inspect", return_value=None):
        with pytest.raises(ValueError, match="cannot inspect"):
            ac_wrapper._user_cmd("missing:tag")


def test_user_cmd_no_entrypoint_or_cmd_raises():
    with patch.object(ac_cli, "image_inspect", return_value={"config": {}}):
        with pytest.raises(ValueError, match="neither ENTRYPOINT nor CMD"):
            ac_wrapper._user_cmd("empty:tag")


def test_user_cmd_combines_entrypoint_and_cmd():
    inspect = {"config": {"entrypoint": ["mitmdump", "-s"], "cmd": ["/app/addon.py"]}}
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["mitmdump", "-s", "/app/addon.py"]


def test_user_cmd_handles_apple_variants_schema():
    """Apple's actual `image inspect` nests config under variants[i].config.config."""
    inspect = {
        "name": "img:tag",
        "variants": [
            {
                "platform": {"os": "linux", "architecture": "arm64"},
                "config": {"config": {"Cmd": ["sh", "-c", "echo hi"]}},
            }
        ],
    }
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["sh", "-c", "echo hi"]


def test_user_cmd_prefers_arm64_variant():
    inspect = {
        "variants": [
            {"platform": {"architecture": "amd64"},
             "config": {"config": {"Cmd": ["x86only"]}}},
            {"platform": {"architecture": "arm64"},
             "config": {"config": {"Cmd": ["arm64only"]}}},
        ],
    }
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["arm64only"]


def test_user_cmd_handles_capitalized_keys():
    """Apple's inspect schema may use 'Config' / 'Cmd' (OCI-style)."""
    inspect = {"Config": {"Cmd": ["node", "server.js"]}}
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["node", "server.js"]


# ---------------------------------------------------------------------------
# cli helpers
# ---------------------------------------------------------------------------

def test_inspect_returns_first_when_list():
    fake_cp = type("CP", (), {"returncode": 0, "stdout": '[{"a": 1}]'})()
    with patch.object(ac_cli, "run", return_value=fake_cp):
        result = ac_cli.inspect("x")
    assert result == {"a": 1}


def test_inspect_returns_none_on_nonzero_exit():
    fake_cp = type("CP", (), {"returncode": 1, "stdout": ""})()
    with patch.object(ac_cli, "run", return_value=fake_cp):
        assert ac_cli.inspect("x") is None


# ---------------------------------------------------------------------------
# build_artifacts: cage.yaml command precedence + ordering
# ---------------------------------------------------------------------------


def _ok_run(*args, **kwargs):  # noqa: ARG001
    """Fake subprocess.CompletedProcess-ish for ac_cli.run that always succeeds."""
    return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()


def test_build_artifacts_prefers_cage_yaml_command():
    """cage.yaml `container.command:` wins over the user image's OCI CMD.

    Regression test for the bug where the apple-container backend silently
    ignored cage.yaml `command:` and exec'd the base image's CMD (e.g.
    ubuntu → `/bin/bash`), causing `agentcage run ubuntu` to exit instantly.
    """
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/ubuntu:24.04"
    cfg.container.command = ["sh", "-c", "exec sleep infinity"]

    with patch.object(ac_cli, "run", side_effect=_ok_run) as run_mock, \
         patch.object(ac_cli, "image_inspect", return_value={"config": {"Cmd": ["/bin/bash"]}}), \
         patch.object(ac_wrapper, "_user_cmd", return_value=["/bin/bash"]) as user_cmd_mock, \
         patch.object(ac_wrapper, "build_wrapper", return_value="img") as build_mock:
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    # When cage.yaml sets command, we must NOT fall through to image inspect.
    user_cmd_mock.assert_not_called()
    # And the wrapper build must receive the cage.yaml command verbatim.
    assert build_mock.call_count == 1
    kwargs = build_mock.call_args.kwargs
    assert kwargs["user_cmd"] == ["sh", "-c", "exec sleep infinity"]
    # The image is already present locally (image_inspect truthy), so we must
    # NOT pull it — pulling an already-local image is wasted, doomed work.
    assert not any(
        call.args and call.args[0][:2] == ["image", "pull"]
        for call in run_mock.call_args_list
    )


def test_build_artifacts_falls_back_to_user_cmd_when_unset():
    """No cage.yaml command → inspect the user image's OCI CMD as before."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/alpine:3.20"
    # command is the default empty list — falsy.
    assert cfg.container.command == []

    with patch.object(ac_cli, "run", side_effect=_ok_run), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {"Cmd": ["/bin/sh"]}}), \
         patch.object(ac_wrapper, "_user_cmd", return_value=["/bin/sh"]) as user_cmd_mock, \
         patch.object(ac_wrapper, "build_wrapper", return_value="img") as build_mock:
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    user_cmd_mock.assert_called_once_with("docker.io/library/alpine:3.20")
    assert build_mock.call_args.kwargs["user_cmd"] == ["/bin/sh"]


def test_build_artifacts_orders_scaffold_before_wrapper_no_pull_for_local(tmp_path):
    """The cage image (built from its staged Containerfile) builds BEFORE the
    wrapper (the wrapper's `FROM <user_image>` references that tag), and a
    locally-present `localhost/` image is NOT pulled — pulling a local-only
    ref is guaranteed to fail and is pure wasted work.
    """
    (tmp_path / "Containerfile").write_text("FROM scratch\n")
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/agentcage-scaffold-ubuntu:latest"
    cfg.container.build.containerfile = "Containerfile"
    cfg.scaffold = "ubuntu"

    calls: list[str] = []

    def staged_side_effect(*args, **kwargs):  # noqa: ARG001
        calls.append("scaffold")

    def run_side_effect(argv, **kwargs):  # noqa: ARG001
        if argv[:2] == ["image", "pull"]:
            calls.append("pull")
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    def build_wrapper_side_effect(*args, **kwargs):  # noqa: ARG001
        calls.append("wrapper")
        return "img"

    with patch.object(ac_scaffold, "build_image_from_staged", side_effect=staged_side_effect), \
         patch("agentcage.state.deployment_dir", return_value=tmp_path), \
         patch.object(ac_cli, "run", side_effect=run_side_effect), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {"Cmd": ["/bin/bash"]}}), \
         patch.object(ac_wrapper, "_user_cmd", return_value=["/bin/bash"]), \
         patch.object(ac_wrapper, "build_wrapper", side_effect=build_wrapper_side_effect):
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    assert "pull" not in calls  # local image present → never pulled
    assert calls.index("scaffold") < calls.index("wrapper")


def test_build_artifacts_localhost_image_missing_raises_clear_error():
    """A `localhost/` image that isn't in the local store must fail fast with
    an actionable message and must NOT attempt a (doomed) registry pull.

    Regression: a mistyped/unbuilt scaffold tag previously fell through to
    `container image pull localhost/...`, which can never resolve in a
    registry — surfacing as a cryptic 'Connection refused' after a multi-
    second timeout instead of 'this local image was not built'.
    """
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/agentcage-scaffold-alpine-typo:latest"

    with patch.object(ac_cli, "run", side_effect=_ok_run) as run_mock, \
         patch.object(ac_cli, "image_inspect", return_value=None), \
         patch.object(ac_wrapper, "build_wrapper", new=MagicMock()):
        with pytest.raises(RuntimeError, match="local-only.*not present|not present.*local"):
            AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    # No registry pull was attempted for the local-only ref.
    assert not any(
        call.args and call.args[0][:2] == ["image", "pull"]
        for call in run_mock.call_args_list
    )


def test_build_artifacts_pulls_remote_image_when_absent():
    """A genuinely-remote image that is absent locally IS pulled (the only
    case where a registry pull is warranted)."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/debian:stable-slim"
    cfg.container.command = ["sleep", "infinity"]

    with patch.object(ac_cli, "run", side_effect=_ok_run) as run_mock, \
         patch.object(ac_cli, "image_inspect", return_value=None), \
         patch.object(ac_wrapper, "build_wrapper", return_value="img"):
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    assert any(
        call.args and call.args[0][:3]
        == ["image", "pull", "docker.io/library/debian:stable-slim"]
        for call in run_mock.call_args_list
    )


def test_build_artifacts_remote_pull_fails_and_absent_raises():
    """A remote image whose pull fails AND that isn't local → clear error."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/does-not-exist:latest"
    cfg.container.command = ["sleep", "infinity"]

    def fail_pull(argv, **kwargs):  # noqa: ARG001
        rc = 1 if argv[:2] == ["image", "pull"] else 0
        return type("CP", (), {"returncode": rc, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "run", side_effect=fail_pull), \
         patch.object(ac_cli, "image_inspect", return_value=None), \
         patch.object(ac_wrapper, "build_wrapper", new=MagicMock()):
        with pytest.raises(RuntimeError, match="failed to pull user image"):
            AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)


def test_build_artifacts_no_cmd_anywhere_raises_helpful_error():
    """If neither cage.yaml nor the image declare a CMD, fail with a clear hint."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/scratch:latest"

    with patch.object(ac_cli, "run", side_effect=_ok_run), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(
             ac_wrapper, "_user_cmd",
             side_effect=ValueError("image has neither ENTRYPOINT nor CMD"),
         ), \
         patch.object(ac_wrapper, "build_wrapper", new=MagicMock()):
        with pytest.raises(RuntimeError, match="cannot determine cage entrypoint"):
            AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)


# ---------------------------------------------------------------------------
# generate_units / start: container.cpus + container.memory precedence
# ---------------------------------------------------------------------------


def test_generate_units_prefers_container_cpus_memory_over_vm():
    """REGRESSION: cage.yaml's `container.cpus` / `container.memory` (the
    per-cage cap users actually write) must win over `vm.vcpus` /
    `vm.mem_mb` on apple-container. Pre-fix, the backend read only the
    vm.* fields and silently dropped container.* — meaning a Mac user
    who wrote `container: { memory: 2g, cpus: 1.5 }` got Apple's default
    resource allocation, not the cap they asked for."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.container.cpus = "1.5"
    cfg.container.memory = "2g"
    cfg.vm.vcpus = 8       # set but should be overridden
    cfg.vm.mem_mb = 16384  # set but should be overridden

    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["cpus"] == "1.5"
    assert meta["memory"] == "2g"


def test_generate_units_falls_back_to_vm_when_container_unset():
    """vm.vcpus / vm.mem_mb are the fallback when cage.yaml doesn't set
    container.*. Backward compatibility: existing cages that only had
    the vm section keep working."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.container.cpus = ""
    cfg.container.memory = ""
    cfg.vm.vcpus = 4
    cfg.vm.mem_mb = 4096

    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["cpus"] == "4"
    assert meta["memory"] == "4096m"


def test_start_argv_includes_normalized_cpus_memory(tmp_path, monkeypatch):
    """The cage VM's `container run` argv carries normalized --cpus
    (integer; Apple rejects fractions) and --memory (uppercase suffix).
    The egress sibling gets a fixed 512M and no --cpus (it's small)."""
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "1.5", "memory": "2g",
            "lifecycle": "interactive",
        },
    )
    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    assert cage_argv[cage_argv.index("--cpus") + 1] == "2"
    assert cage_argv[cage_argv.index("--memory") + 1] == "2G"


def test_normalize_cpus_ceils_fractions():
    from agentcage.backends.apple_container import _normalize_cpus
    assert _normalize_cpus("0.5") == "1"
    assert _normalize_cpus("1.0") == "1"
    assert _normalize_cpus("1.1") == "2"
    assert _normalize_cpus("4") == "4"
    assert _normalize_cpus("not-a-number") == "not-a-number"  # pass through


def test_normalize_memory_uppercases_suffix():
    from agentcage.backends.apple_container import _normalize_memory
    assert _normalize_memory("512m") == "512M"
    assert _normalize_memory("2g") == "2G"
    assert _normalize_memory("1024M") == "1024M"  # already uppercase
    assert _normalize_memory("2Gi") == "2GI"      # uppercase the i too
    assert _normalize_memory("512") == "512"      # no suffix, pass through
    assert _normalize_memory("garbage") == "garbage"  # doesn't match → pass through


def test_start_creates_logs_dir_and_bind_mounts_it(tmp_path, monkeypatch):
    """`start()` must create the per-cage logs dir on the host and pass
    --volume <host_logs>:/var/log/agentcage to the EGRESS sibling
    (where the addon writes audit.jsonl + capture.jsonl + dnsmasq.log).
    The cage VM does not get this bind in the 2-microVM model — there's
    nothing inside the cage that writes to /var/log/agentcage."""
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": "", "memory": "", "lifecycle": "interactive",
        },
    )
    backend.start("demo", quiet=True)
    logs_dir = tmp_path / "logs"
    assert logs_dir.is_dir()
    egress_argv = _egress_run_argv(captured)
    assert f"{logs_dir}:/var/log/agentcage" in egress_argv


def test_logs_dir_lives_under_per_cage_state_dir():
    """logs_dir(name) is `<state-dir>/<name>/logs/` so destroy_resources's
    recursive rmtree of _state_dir(name) sweeps it up automatically."""
    backend = AppleContainerBackend()
    logs = backend.logs_dir("demo")
    state = backend._state_dir("demo")
    assert logs.parent == state
    assert logs.name == "logs"


def test_start_argv_backward_compat_pre_0_20_6_mem_mb(tmp_path, monkeypatch):
    """Pre-0.20.6 unit JSON used integer `mem_mb` (no `memory` string).
    Cages created before this PR must keep starting on a fresh agentcage."""
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x",
            "cpus": 4, "mem_mb": 4096,  # old shape
            "lifecycle": "interactive",
        },
    )
    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    assert cage_argv[cage_argv.index("--memory") + 1] == "4096M"


def test_start_waits_for_supervisor_ready_marker(tmp_path, monkeypatch):
    """`start()` must block until the EGRESS sibling's supervisor signals
    readiness via ``logs_dir(name)/ready`` (PR 3: this marker is now
    touched by supervisor-egress.sh inside the egress sibling, not by
    the cage VM). Without this wait the cage VM starts before the
    egress's mitmproxy is listening — same race the legacy single-VM
    model had at issue #168."""
    monkeypatch.setattr(AppleContainerBackend, "_READY_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(AppleContainerBackend, "_READY_TIMEOUT_S", 1.0)
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
        },
    )
    # Override the auto-mocked _wait_supervisor_ready so it runs against
    # the real poll loop, then have fake_run touch the marker when the
    # egress `container run` is invoked.
    monkeypatch.delattr(backend, "_wait_supervisor_ready", raising=False)
    logs_dir = tmp_path / "logs"

    def fake_run_touches_ready(argv, **_kwargs):
        captured.append(list(argv))
        if argv and argv[0] == "run" and any("agentcage-egress" in a for a in argv):
            logs_dir.mkdir(parents=True, exist_ok=True)
            (logs_dir / "ready").touch()
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(ac_cli, "run", fake_run_touches_ready)
    # inspect returns running so the dead-cage detector doesn't fire.
    monkeypatch.setattr(
        ac_cli, "inspect", lambda _n: {"status": "running"},
    )
    backend.start("demo", quiet=True)


def test_start_clears_stale_ready_marker_before_run(tmp_path, monkeypatch):
    """A leftover marker from a prior cage lifetime must NOT be honored:
    `start()` deletes it BEFORE the egress `container run`, then re-polls."""
    monkeypatch.setattr(AppleContainerBackend, "_READY_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(AppleContainerBackend, "_READY_TIMEOUT_S", 0.5)
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
        },
    )
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    stale = logs_dir / "ready"
    stale.touch()
    monkeypatch.delattr(backend, "_wait_supervisor_ready", raising=False)

    deleted = {"happened": False}

    def fake_run(argv, **_kwargs):
        captured.append(list(argv))
        if argv and argv[0] == "run" and any("agentcage-egress" in a for a in argv):
            deleted["happened"] = not stale.exists()
            stale.touch()
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(ac_cli, "run", fake_run)
    monkeypatch.setattr(
        ac_cli, "inspect", lambda _n: {"status": "running"},
    )
    backend.start("demo", quiet=True)
    assert deleted["happened"], \
        "start() must unlink stale ready marker BEFORE the egress run"


def test_start_raises_when_supervisor_dies_before_ready(tmp_path, monkeypatch):
    """If the egress sibling exits before signaling ready, `start()`
    must raise immediately with a pointer to `container logs`."""
    monkeypatch.setattr(AppleContainerBackend, "_READY_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(AppleContainerBackend, "_READY_TIMEOUT_S", 1.0)
    backend, _captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
        },
    )
    monkeypatch.delattr(backend, "_wait_supervisor_ready", raising=False)
    # No marker ever touched; inspect reports egress as exited.
    monkeypatch.setattr(
        ac_cli, "inspect", lambda _n: {"status": "exited"},
    )
    with pytest.raises(RuntimeError, match="exited before becoming ready"):
        backend.start("demo", quiet=True)


@pytest.mark.parametrize(
    "data, expected",
    [
        # Pre-1.0 schema: top-level string.
        ({"status": "running"}, "running"),
        ({"status": "stopped"}, "stopped"),
        ({"Status": "running"}, "running"),
        # container 1.0.0 schema: state nested under the status object,
        # alongside networks / startedDate.
        ({"status": {"state": "running", "networks": []}}, "running"),
        ({"status": {"state": "stopped"}}, "stopped"),
        ({"status": {"State": "running"}}, "running"),
        # Degenerate / absent.
        ({}, None),
        (None, None),
        ({"status": {}}, None),
    ],
)
def test_container_state_handles_both_inspect_schemas(data, expected):
    """`container_state` normalizes both the pre-1.0 top-level string
    `status` and the 1.0+ nested `status.state` schema. Regression for the
    1.0.0 breaking change that made every cage look stopped."""
    assert ac_cli.container_state(data) == expected


def test_wait_supervisor_ready_accepts_container_1_0_running_status(
    tmp_path, monkeypatch
):
    """Regression: with container 1.0's nested `status` object, a *running*
    egress must NOT trip the death-detector. Pre-fix, `status` was a dict
    that never equalled "running", so the wait raised a spurious
    "exited before becoming ready" on the first poll."""
    monkeypatch.setattr(AppleContainerBackend, "_READY_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(AppleContainerBackend, "_READY_TIMEOUT_S", 1.0)
    backend = AppleContainerBackend()
    marker = tmp_path / "ready"

    # Egress reports the new nested-running schema; marker appears after a
    # couple of polls (mirrors the supervisor finishing steps A-F).
    calls = {"n": 0}

    def fake_inspect(_name):
        calls["n"] += 1
        if calls["n"] >= 2:
            marker.touch()
        return {"status": {"state": "running", "networks": [],
                           "startedDate": "2026-06-22T11:02:42Z"}}

    monkeypatch.setattr(ac_cli, "inspect", fake_inspect)
    # Must return cleanly (no RuntimeError).
    backend._wait_supervisor_ready("demo", marker)


def test_wait_supervisor_ready_detects_death_with_nested_status(
    tmp_path, monkeypatch
):
    """A genuinely-dead egress under the 1.0 nested schema
    (`status.state == "stopped"`) must still raise."""
    monkeypatch.setattr(AppleContainerBackend, "_READY_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(AppleContainerBackend, "_READY_TIMEOUT_S", 1.0)
    backend = AppleContainerBackend()
    marker = tmp_path / "ready"  # never created
    monkeypatch.setattr(
        ac_cli, "inspect",
        lambda _n: {"status": {"state": "stopped"}},
    )
    with pytest.raises(RuntimeError, match="exited before becoming ready"):
        backend._wait_supervisor_ready("demo", marker)


@pytest.mark.parametrize(
    "data, expected_ips",
    [
        # Pre-1.0: networks at top level.
        ({"networks": [{"ipv4Address": "192.168.64.5/24"}]}, ["192.168.64.5/24"]),
        # container 1.0.0: networks nested under status.
        (
            {"status": {"state": "running",
                        "networks": [{"ipv4Address": "192.168.67.2/24"}]}},
            ["192.168.67.2/24"],
        ),
        ({"status": {"networks": []}}, []),
        ({}, []),
        (None, []),
    ],
)
def test_container_networks_handles_both_inspect_schemas(data, expected_ips):
    """`container_networks` finds the network list whether it sits at the
    top level (pre-1.0) or nested under `status` (1.0+)."""
    nets = ac_cli.container_networks(data)
    assert [n["ipv4Address"] for n in nets] == expected_ips


def test_container_ip_reads_nested_container_1_0_networks(monkeypatch):
    """Regression: `_container_ip` must find the egress gateway IP under the
    1.0 nested `status.networks` schema. Pre-fix it read top-level
    `networks` (absent in 1.0), so `start()` raised "could not resolve IP"
    even though the egress had an address."""
    backend = AppleContainerBackend()
    monkeypatch.setattr(
        ac_cli, "inspect",
        lambda _n: {"status": {"state": "running", "networks": [
            {"ipv4Address": "192.168.67.2/24",
             "ipv4Gateway": "192.168.67.1"}]}},
    )
    assert backend._container_ip("demo-egress") == "192.168.67.2"


def test_is_running_reads_nested_container_1_0_state(monkeypatch):
    """`is_running` must read `status.state` under the 1.0 schema; pre-fix
    it compared the whole dict to "running" and always returned False."""
    backend = AppleContainerBackend()
    monkeypatch.setattr(
        ac_cli, "inspect",
        lambda _n: {"status": {"state": "running", "networks": []}},
    )
    assert backend.is_running("demo", "egress") is True
    monkeypatch.setattr(
        ac_cli, "inspect",
        lambda _n: {"status": {"state": "stopped"}},
    )
    assert backend.is_running("demo", "egress") is False


# test_supervisor_touches_ready_marker_before_capsh removed in PR 3:
# supervisor.sh is gone. The ready-marker invariant moved to the egress
# image's supervisor-egress.sh (tested in tests/test_egress_image.py).


def test_start_passes_user_volumes_as_container_run_args(tmp_path, monkeypatch):
    """`container.volumes` entries flow through `start()` as
    `--volume host:cage[:mode]` on the CAGE VM's run argv. The egress
    sibling does not get user volumes — its bind set is fixed
    (config / certs / logs / secrets)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    rw_host = tmp_path / "rw-src"
    rw_host.mkdir()
    ro_host = tmp_path / "ro-src"
    ro_host.mkdir()
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
            "volumes": [
                f"{rw_host}:/workspace:rw",
                f"{ro_host}:/readonly:ro",
            ],
        },
    )
    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    assert f"{rw_host}:/workspace:rw" in cage_argv
    assert f"{ro_host}:/readonly:ro" in cage_argv
    # User volumes should NOT appear on the egress sibling.
    egress_argv = _egress_run_argv(captured)
    assert f"{rw_host}:/workspace:rw" not in egress_argv
    assert f"{ro_host}:/readonly:ro" not in egress_argv


def test_user_volume_argv_skips_unresolved_var():
    """`$VAR` that didn't expand → skip + warn, not crash. Mirrors quadlets.py."""
    out = AppleContainerBackend._user_volume_argv(["$UNSET_VAR/foo:/cage:rw"])
    assert out == []


def test_user_volume_argv_skips_path_outside_home(tmp_path, monkeypatch):
    """Host path outside $HOME → skip + warn. Prevents `/etc:/...` style bind-ins."""
    monkeypatch.setenv("HOME", str(tmp_path))
    out = AppleContainerBackend._user_volume_argv(["/etc:/cage:rw"])
    assert out == []


def test_user_volume_argv_skips_missing_separator():
    """Entry without `:` (no cage path) → skip + warn, not silently pass through."""
    out = AppleContainerBackend._user_volume_argv(["/just/a/path"])
    assert out == []


def test_user_volume_argv_accepts_home_relative_paths(tmp_path, monkeypatch):
    """`~/path:/cage` expands to an absolute host path under $HOME and is accepted."""
    monkeypatch.setenv("HOME", str(tmp_path))
    target = tmp_path / "work"
    target.mkdir()
    out = AppleContainerBackend._user_volume_argv(["~/work:/cage:rw"])
    assert out == [f"{target}:/cage:rw"]


def test_unit_json_persists_user_volumes(tmp_path, monkeypatch):
    """`generate_units` must include `volumes` in the unit JSON so a
    subsequent `start()` (which only reads the unit JSON, not the
    cage.yaml) can re-emit them as --volume args. The persisted value is
    the EXPANDED, absolute host path — `~`/`$VAR` are resolved at
    create/update time, not lazily at start() — so the mount survives a
    restart that has no PROJECT_DIR/HOME-dependent env (see
    test_unit_json_bakes_env_var_so_mount_survives_restart)."""
    from agentcage.config import Config, ContainerConfig
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "foo").mkdir()
    cfg = Config(
        name="demo",
        isolation="apple-container",
        container=ContainerConfig(
            image="localhost/test:latest",
            volumes=["~/foo:/workspace:rw"],
        ),
    )
    backend = AppleContainerBackend()
    out = backend.generate_units(cfg, "/tmp/proxy-config.yaml", "/tmp/patches", "demo")
    parsed = json.loads(out["demo.json"])
    # `~` expanded to the absolute home path, not persisted verbatim.
    assert parsed["volumes"] == [f"{tmp_path}/foo:/workspace:rw"]


def test_unit_json_persists_inline_np_volume_flag(tmp_path, monkeypatch):
    """The start path needs the inline np marker to route this bind through
    apple-container's lowerdir+tmpfs implementation."""
    from agentcage.config import Config, ContainerConfig
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "foo").mkdir()
    cfg = Config(
        name="demo",
        isolation="apple-container",
        container=ContainerConfig(
            image="localhost/test:latest",
            volumes=["~/foo:/workspace:rw,np"],
        ),
    )
    out = AppleContainerBackend().generate_units(
        cfg, "/tmp/proxy-config.yaml", "/tmp/patches", "demo"
    )
    assert json.loads(out["demo.json"])["volumes"] == [
        f"{tmp_path}/foo:/workspace:rw,np"
    ]


def test_start_routes_only_np_directory_via_tmpfs(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    np_host = tmp_path / "np-src"
    np_host.mkdir()
    persistent_host = tmp_path / "persistent-src"
    persistent_host.mkdir()
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
            "volumes": [
                f"{np_host}:/workspace:rw,np",
                f"{persistent_host}:/cache:rw",
            ],
        },
    )

    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    assert f"{np_host}:/run/agentcage/mounts/vol-0/lower:ro" in cage_argv
    tmpfs_index = cage_argv.index("--tmpfs")
    assert cage_argv[tmpfs_index + 1] == "/workspace"
    assert f"{persistent_host}:/cache:rw" in cage_argv
    assert (
        "AGENTCAGE_NONPERSISTENT_COPIES="
        "/run/agentcage/mounts/vol-0/lower\t/workspace"
    ) in cage_argv


@pytest.mark.parametrize("options", ["rw", "rw,np"])
def test_start_revalidates_unsafe_unit_metadata_volumes(
    tmp_path, monkeypatch, options,
):
    """start() must re-apply the $HOME/unresolved-$VAR guards to unit metadata.

    generate_units already drops unsafe entries, so this is defense-in-depth
    against hand-edited or tampered unit JSON. Regression guard: routing np
    binds must not bypass _user_volume_argv."""
    monkeypatch.delenv("AGENTCAGE_NOPE", raising=False)
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
            "volumes": [
                f"/etc:/cage-etc:{options}",
                f"${{AGENTCAGE_NOPE}}/x:/cage-unset:{options}",
            ],
        },
    )

    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    mounted = [
        cage_argv[i + 1] for i, arg in enumerate(cage_argv[:-1])
        if arg == "--volume"
    ]
    assert not any("/cage-etc" in entry for entry in mounted)
    assert not any("/cage-unset" in entry for entry in mounted)
    # Neither entry may reach the np lowerdir/tmpfs routing either.
    assert not any("/run/agentcage/mounts/" in entry for entry in mounted)
    assert "--tmpfs" not in cage_argv
    assert not any(
        arg.startswith("AGENTCAGE_NONPERSISTENT_COPIES=") for arg in cage_argv
    )


def test_start_routes_np_file_to_exact_target_without_tmpfs(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    host_file = tmp_path / "settings.json"
    host_file.write_text("{}")
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
            "volumes": [f"{host_file}:/home/node/.config/settings.json:rw,np"],
        },
    )

    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    assert f"{host_file}:/run/agentcage/mounts/vol-0/lower:ro" in cage_argv
    assert "/home/node/.config/settings.json" not in [
        cage_argv[i + 1] for i, arg in enumerate(cage_argv[:-1])
        if arg == "--tmpfs"
    ]
    assert (
        "AGENTCAGE_NONPERSISTENT_COPIES="
        "/run/agentcage/mounts/vol-0/lower\t/home/node/.config/settings.json"
    ) in cage_argv

    init_script = (
        Path(__file__).parents[1]
        / "src/agentcage/data/apple-container/cage-init.sh"
    ).read_text()
    assert 'mkdir -p "$(dirname "${target}")"' in init_script
    assert 'cp -f "${lower}" "${target}"' in init_script


def test_unit_json_bakes_env_var_so_mount_survives_restart(tmp_path, monkeypatch):
    """Regression: the scaffold workspace mount is `${PROJECT_DIR}:/workspace`
    and PROJECT_DIR only exists in the `agentcage run` process env. Pre-fix,
    generate_units persisted the literal `${PROJECT_DIR}` and start() expanded
    it lazily — so a restart/launchd-autostart/reboot (no PROJECT_DIR set)
    silently dropped the workspace via _user_volume_argv's unresolved-`$`
    guard. generate_units must bake the ABSOLUTE path so it survives a
    PROJECT_DIR-less start()."""
    from agentcage.config import Config, ContainerConfig
    monkeypatch.setenv("HOME", str(tmp_path))
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setenv("PROJECT_DIR", str(proj))
    cfg = Config(
        name="demo",
        isolation="apple-container",
        container=ContainerConfig(
            image="localhost/test:latest",
            volumes=["${PROJECT_DIR}:/workspace:rw"],
        ),
    )
    backend = AppleContainerBackend()
    out = backend.generate_units(cfg, "/tmp/proxy-config.yaml", "/tmp/patches", "demo")
    baked = json.loads(out["demo.json"])["volumes"]
    # Baked to the absolute project path — no literal `${PROJECT_DIR}` left.
    assert baked == [f"{proj}:/workspace:rw"]
    assert not any("$" in v for v in baked)
    # Simulate a restart: PROJECT_DIR no longer in the environment. start()
    # re-runs _user_volume_argv on the baked metadata; the mount must remain.
    monkeypatch.delenv("PROJECT_DIR")
    assert AppleContainerBackend._user_volume_argv(baked) == [f"{proj}:/workspace:rw"]


def test_generate_units_drops_unresolvable_volume_at_create_time(tmp_path, monkeypatch):
    """Validation gate: a volume whose host path can't be resolved (unset
    var) or escapes $HOME is dropped at generate_units time (with a stderr
    warning from _user_volume_argv) rather than silently failing later. The
    unit JSON only ever carries mountable, $HOME-contained absolute paths."""
    from agentcage.config import Config, ContainerConfig
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AGENTCAGE_NOPE", raising=False)
    cfg = Config(
        name="demo",
        isolation="apple-container",
        container=ContainerConfig(
            image="localhost/test:latest",
            volumes=[
                "${AGENTCAGE_NOPE}/x:/cage:rw",  # unresolved var → dropped
                "/etc:/cage-etc:ro",             # outside $HOME → dropped
            ],
        ),
    )
    backend = AppleContainerBackend()
    out = backend.generate_units(cfg, "/tmp/proxy-config.yaml", "/tmp/patches", "demo")
    assert json.loads(out["demo.json"])["volumes"] == []


def test_start_passes_user_env_as_container_run_args(tmp_path, monkeypatch):
    """`container.env:` entries flow through `start()` as `-e KEY=VAL`
    on the cage VM's argv. The egress sibling does NOT inherit user env
    (it only carries the fixed AGENTCAGE_CONFIG / AGENTCAGE_AUDIT_LOG /
    AGENTCAGE_CAPTURE for the addon)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": 1,
            "memory": "1G", "lifecycle": "interactive",
            "env": {"TORTURE_T7": "hello-from-mac", "DEPLOY_ENV": "ctf"},
        },
    )
    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    assert "TORTURE_T7=hello-from-mac" in cage_argv
    assert "DEPLOY_ENV=ctf" in cage_argv
    # User env MUST NOT leak to the egress sibling.
    egress_argv = _egress_run_argv(captured)
    assert "TORTURE_T7=hello-from-mac" not in egress_argv
    assert "DEPLOY_ENV=ctf" not in egress_argv


def test_unit_json_persists_user_env_with_var_expansion(monkeypatch):
    """`generate_units` must persist `container.env` into the unit JSON,
    expanding $VAR in values host-side (matching container backend's
    quadlets.py:338 behavior). A subsequent `start()` only reads the
    unit JSON, not the cage.yaml — so the expansion has to happen at
    generate-units time."""
    from agentcage.config import Config, ContainerConfig
    monkeypatch.setenv("DEPLOY_HOST", "ctf-mac")
    cfg = Config(
        name="demo",
        isolation="apple-container",
        container=ContainerConfig(
            image="localhost/test:latest",
            env={"GREETING": "hello", "DEPLOY_ON": "$DEPLOY_HOST"},
        ),
    )
    backend = AppleContainerBackend()
    out = backend.generate_units(cfg, "/tmp/proxy-config.yaml", "/tmp/patches", "demo")
    parsed = json.loads(out["demo.json"])
    assert parsed["env"] == {"GREETING": "hello", "DEPLOY_ON": "ctf-mac"}


def test_unit_json_empty_env_when_container_env_unset():
    """Backward compat: cages with no `container.env:` get an empty
    dict, not a None / missing key — so `meta.get('env') or {}` always
    iterates cleanly."""
    from agentcage.config import Config, ContainerConfig
    cfg = Config(
        name="demo",
        isolation="apple-container",
        container=ContainerConfig(image="localhost/test:latest"),
    )
    backend = AppleContainerBackend()
    out = backend.generate_units(cfg, "/tmp/proxy-config.yaml", "/tmp/patches", "demo")
    parsed = json.loads(out["demo.json"])
    assert parsed["env"] == {}


def test_run_streaming_pauses_active_spinner():
    """``ac_cli.run(capture_output=False)`` must wrap subprocess.run in
    ``output.pause_active_spinner()`` so Apple's CLI progress doesn't fight
    our braille spinner for the same terminal line.
    """
    from agentcage import output as ac_output

    events: list[str] = []

    fake_spinner = type(
        "FakeSpinner", (), {
            "pause": lambda self: events.append("pause"),
            "resume": lambda self: events.append("resume"),
        },
    )()

    def fake_subprocess_run(*_args, **_kwargs):
        events.append("subprocess.run")
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_output, "_active", fake_spinner), \
         patch("agentcage.apple_container.cli.subprocess.run", side_effect=fake_subprocess_run):
        ac_cli.run(["image", "pull", "alpine"], check=False, capture_output=False)

    # pause must happen before the subprocess starts, resume after it returns.
    assert events == ["pause", "subprocess.run", "resume"]


def test_run_capturing_does_not_pause_active_spinner():
    """The capturing path is silent on stderr -- no need to pause the spinner."""
    from agentcage import output as ac_output

    events: list[str] = []

    fake_spinner = type(
        "FakeSpinner", (), {
            "pause": lambda self: events.append("pause"),
            "resume": lambda self: events.append("resume"),
        },
    )()

    def fake_subprocess_run(*_args, **_kwargs):
        events.append("subprocess.run")
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_output, "_active", fake_spinner), \
         patch("agentcage.apple_container.cli.subprocess.run", side_effect=fake_subprocess_run):
        ac_cli.run(["inspect", "x"], check=False, capture_output=True)

    assert events == ["subprocess.run"]


# ---------------------------------------------------------------------------
#
# These exercise the addon's response() hook end-to-end with a mocked
# mitmproxy HTTPFlow. The conftest.py stub of `mitmproxy` lets the addon
# module import cleanly on the host; we never spin up real mitmproxy.
# ---------------------------------------------------------------------------



def _make_response_flow(*, host, body, status=200, resp_headers=None,
                        method="GET", path="/headers"):
    """Build a minimal mock mitmproxy HTTPFlow with a response attached.

    ``body`` may be ``str`` (text body) or ``bytes`` (binary). For text
    bodies we set ``flow.response.get_text`` to return it; the addon's
    redactor calls ``set_text`` to mutate, which writes back into
    ``flow.response.text``.
    """
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.pretty_url = f"https://{host}{path}"
    flow.request.path = path
    flow.request.port = 443
    flow.request.method = method
    flow.request.headers = {}

    flow.response = MagicMock()
    flow.response.status_code = status
    flow.response.reason = "OK"
    flow.response.headers = dict(resp_headers or {})
    flow.response.content = body.encode() if isinstance(body, str) else body

    if isinstance(body, str):
        # Stash text in a closure so set_text() updates what get_text()
        # returns on subsequent calls — matches mitmproxy's behaviour.
        state = {"text": body}
        flow.response.get_text.side_effect = lambda strict=True: state["text"]
        def _set_text(new):
            state["text"] = new
            flow.response.content = new.encode()
        flow.response.set_text.side_effect = _set_text
    else:
        # Binary body — mimic mitmproxy raising on undecodable bytes.
        flow.response.get_text.side_effect = UnicodeDecodeError(
            "utf-8", body, 0, 1, "binary body",
        )
    return flow






# ---------------------------------------------------------------------------
#
# ``_maybe_inject`` substitutes the real secret value into both request
# headers and request body so the upstream sees a working key. Without
# a symmetric ``_maybe_redact_request`` running BEFORE the capture
# writer serializes the flow, those real-value bytes land on disk in
# ``capture.jsonl`` — which is bind-mounted into the cage rootfs at
# mode 0644 (cage-readable). A cage workload can ``grep sk- /var/log/
# agentcage/capture.jsonl`` and recover the live ``ANTHROPIC_API_KEY``,
# defeating the whole placeholder-injection trust model. The proxy held
# the raw key precisely so the cage wouldn't see it; capture brought it
# right back.
#
# These tests cover the addon's new ``_maybe_redact_request`` method
# directly and end-to-end through the request→response capture pipeline.
# ---------------------------------------------------------------------------


def _make_request_redact_flow(*, host, headers=None, body=""):
    """Mock flow shaped for ``_maybe_redact_request``.

    Provides the get_text/set_text pair that backs body editing, and a
    headers dict whose ``items()`` returns a list (the addon calls it
    with no kwargs — matching the inject path).
    """
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.client_conn.sni = host

    class _Headers(dict):
        def items(self, multi=False):  # noqa: ARG002
            return list(super().items())

    flow.request.headers = _Headers(dict(headers or {}))

    state = {"text": body}
    flow.request.get_text.side_effect = lambda strict=True: state["text"]

    def _set_text(new):
        state["text"] = new
        flow.request.content = new.encode()

    flow.request.set_text.side_effect = _set_text
    flow.request.content = body.encode() if isinstance(body, str) else body
    return flow









# ---------------------------------------------------------------------------
#
# Regression coverage for the CTF finding: with mitmproxy running in
# transparent mode and ``--set keep_host_header=true`` on, the addon
# previously gated the allowlist + secret injection on
# ``flow.request.pretty_host`` — which reads the (attacker-controlled)
# HTTP Host header. A cage could open a TCP connection to any IP, send
# ``Host: api.anthropic.com``, and the addon would (a) allowlist the
# request and (b) inject the real ``ANTHROPIC_API_KEY`` into a request
# bound for the attacker's IP. These tests assert the addon now blocks
# any Host-header spoof and refuses to inject secrets on the spoof.
# ---------------------------------------------------------------------------


def _make_request_flow(
    *,
    pretty_host,
    sni=None,
    original_dst_host=None,
    method="GET",
    path="/",
    port=443,
    headers=None,
):
    """Build a mock HTTPFlow for the addon's ``request()`` hook.

    Sets ``flow.client_conn.sni`` and ``flow.request.host`` explicitly
    so the addon's authoritative-host resolution sees real strings (not
    MagicMock children). ``pretty_host`` is what the addon reads via
    ``flow.request.pretty_host`` — i.e. the HTTP Host header the cage
    sent. The mismatch case (pretty_host=api.anthropic.com but
    sni=example.com) is the exact CTF attack signature.
    """
    flow = MagicMock()
    flow.request.pretty_host = pretty_host
    flow.request.pretty_url = f"https://{pretty_host}{path}"
    flow.request.path = path
    flow.request.port = port
    flow.request.method = method
    flow.request.host = original_dst_host if original_dst_host else ""
    flow.request.content = b""
    flow.request.get_text = lambda strict=False: ""

    class _Headers(dict):
        def items(self, multi=False):  # noqa: ARG002
            return list(super().items())

        def get(self, key, default=""):
            for k, v in super().items():
                if k.lower() == key.lower():
                    return v
            return default

    flow.request.headers = _Headers(dict(headers or {}))
    flow.request.set_text = lambda _t: None

    # Critical: set sni to a real str (or None), not a MagicMock auto-attr.
    flow.client_conn.sni = sni
    flow.response = None
    return flow







# ---------------------------------------------------------------------------
# protocol_relays (PR #160): SMTP/IMAP listeners on apple-container
# ---------------------------------------------------------------------------


def _smtp_relay_entry(name="primary-smtp", port=2525):
    return {
        "name": name,
        "type": "smtp",
        "listen": f"127.0.0.1:{port}",
        "upstream": {
            "host": "smtp.example.net",
            "port": 587,
            "tls": True,
        },
        "auth": {
            "type": "smtp-plain",
            "user_source": "env:AGENTCAGE_SMTP_USER",
            "password_source": "env:AGENTCAGE_SMTP_PASSWORD",
        },
        "policy": {
            "sender_allowlist": ["sender@local"],
            "recipient_allowlist": {"domains": ["example.com"]},
        },
    }


# Build-context staging tests for protocol_relays + transforms + capture
# + inspectors were removed in PR 3 — those config files are no longer
# baked into the wrapper image; they ship inside the agentcage-egress
# image (PR 1) and the per-cage proxy-config.yaml is bind-mounted from
# the host (rendered by AppleContainerBackend._render_egress_config).
#
# The high-value end-to-end invariants the deleted tests covered are
# preserved by:
#   * tests/test_egress_image.py (egress image carries the addon code)
#   * tests/test_addon.py / test_addon_relays.py / test_addon_capture_redaction.py
#     (Python-level unit tests of the addon code)
#   * test_backend_protocol_relay_envs_collected_into_unit_json below
#     (the unit JSON still drives credential staging at start time).


def test_backend_protocol_relay_envs_collected_into_unit_json(monkeypatch):
    """``generate_units`` must capture every relay credential env name
    so ``start()`` knows to read+stage the value into the per-cage
    secrets dir. Crucially, these env names are NOT placed in
    ``secret_envs`` — that list drives the ``-e PLACEHOLDER`` flag
    set, and relay credentials must stay off the cage workload's env
    block.
    """
    from agentcage.config import (
        ProtocolRelay, RelayAuth, RelayPolicy,
        RelayRecipientAllowlist, RelayUpstream,
    )
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/test:latest"
    cfg.protocol_relays = [
        ProtocolRelay(
            name="primary",
            type="smtp",
            listen="127.0.0.1:2525",
            upstream=RelayUpstream(host="smtp.example.net", port=587),
            auth=RelayAuth(
                type="smtp-plain",
                user_source="env:SMTP_USER",
                password_source="env:SMTP_PASS",
            ),
            policy=RelayPolicy(
                recipient_allowlist=RelayRecipientAllowlist(),
            ),
        ),
    ]
    cfg.domains.allow = ["smtp.example.net"]

    units = AppleContainerBackend().generate_units(
        cfg, "/dev/null", "/dev/null", "t",
    )
    meta = json.loads(units["t.json"])
    assert sorted(meta["relay_secret_envs"]) == ["SMTP_PASS", "SMTP_USER"]
    # Relay creds must NOT appear in secret_envs — start() uses that
    # list to set `-e ENV={{PLACEHOLDER}}` on the cage workload, which
    # is exactly what we DON'T want for relay credentials.
    assert "SMTP_USER" not in meta["secret_envs"]
    assert "SMTP_PASS" not in meta["secret_envs"]




def test_validate_config_protocol_relays_on_apple_container_no_warning():
    """A cage.yaml with ``protocol_relays:`` on apple-container must NOT
    trigger any silent-drop warning — relays are wired now. (We never
    had an explicit warning for this, but the test pins the contract
    in case someone adds one later.)

    Construct the Config directly so the test runs on any host (the
    platform-gated isolation acceptance is exercised elsewhere).
    """
    from agentcage.config import (
        ProtocolRelay, RelayAuth, RelayPolicy,
        RelayRecipientAllowlist, RelayUpstream,
    )
    # Patch the platform check so validate_config accepts
    # isolation="apple-container" off-Mac.
    with patch.object(platform, "system", return_value="Darwin"), \
            patch.object(platform, "machine", return_value="arm64"), \
            patch.object(
                platform, "mac_ver",
                return_value=("26.0", ("", "", ""), ""),
            ):
        cfg = Config(name="relays-cage", isolation="apple-container")
        cfg.container.image = "ubuntu:24.04"
        cfg.domains.allow = ["smtp.example.net"]
        cfg.ports.tcp.passthrough = [2525]
        cfg.protocol_relays = [
            ProtocolRelay(
                name="primary",
                type="smtp",
                listen="127.0.0.1:2525",
                upstream=RelayUpstream(
                    host="smtp.example.net", port=587, tls=True,
                ),
                auth=RelayAuth(
                    type="smtp-plain",
                    user_source="env:SMTP_USER",
                    password_source="env:SMTP_PASS",
                ),
                policy=RelayPolicy(
                    recipient_allowlist=RelayRecipientAllowlist(
                        domains=["example.com"],
                    ),
                ),
            ),
        ]
        warnings = validate_config(cfg)
    relay_warnings = [w for w in warnings if "protocol_relays" in w]
    assert relay_warnings == []


# ---------------------------------------------------------------------------
#
# When ``capture.enable_har: true`` is set in cage.yaml, the addon stages
# inbound + outbound request/response snapshots (request body + response
# body, subject to ``max_body_size`` + binary-skip) and writes them as
# nested ``{inbound, outbound}`` entries to capture.jsonl. ``cage har``
# then renders these as HAR 1.2 with non-zero ``content.size`` and
# ``request.postData.text``. Pre-this-PR the addon wrote a headers-only
# capture record and HAR exports showed ``content.size=0`` everywhere.
# ---------------------------------------------------------------------------



class _FakeHeaders(dict):
    """dict subclass with ``items(multi=...)`` to mimic mitmproxy.Headers.

    The CaptureWriter snapshot helpers call ``headers.items(multi=True)``
    to walk repeated header values, and ``headers.get("content-type")``
    expects case-insensitive lookup. A plain dict gets neither right.
    """

    def items(self, multi=False):  # noqa: ARG002
        return list(super().items())

    def get(self, key, default=None):  # type: ignore[override]
        # Case-insensitive lookup — mimics mitmproxy.Headers semantics.
        kl = key.lower()
        for k, v in super().items():
            if k.lower() == kl:
                return v
        return default


def _make_flow_with_bodies(*, host, req_body, resp_body, method="POST",
                           path="/post", status=200,
                           req_content_type="application/x-www-form-urlencoded",
                           resp_content_type="application/json"):
    """Mock HTTPFlow with both request AND response body bytes attached.

    The CaptureWriter snapshot helpers read ``flow.request.content`` and
    ``flow.response.content`` directly (not via get_text), so we just set
    the bytes attribute.
    """
    flow = MagicMock()
    flow.id = "test-flow-id"
    flow.request.pretty_host = host
    flow.request.pretty_url = f"https://{host}{path}"
    flow.request.url = f"https://{host}{path}"
    flow.request.path = path
    flow.request.port = 443
    flow.request.method = method
    flow.request.http_version = "HTTP/1.1"
    flow.request.headers = _FakeHeaders({"Content-Type": req_content_type})
    flow.request.content = (
        req_body.encode() if isinstance(req_body, str) else req_body
    )

    flow.response = MagicMock()
    flow.response.status_code = status
    flow.response.reason = "OK"
    flow.response.http_version = "HTTP/1.1"
    flow.response.headers = _FakeHeaders({"Content-Type": resp_content_type})
    flow.response.content = (
        resp_body.encode() if isinstance(resp_body, str) else resp_body
    )
    # Redaction path calls get_text(strict=False) — for the no-secret
    # tests we return the body verbatim (no substring will match anything).
    if isinstance(resp_body, bytes):
        flow.response.get_text.side_effect = UnicodeDecodeError(
            "utf-8", resp_body, 0, 1, "binary body",
        )
    else:
        flow.response.get_text.side_effect = lambda strict=True: resp_body
    return flow


# capture / inspectors / secret_injection build-context staging tests
# removed in PR 3 (2-microVM refactor). The wrapper image no longer
# carries these files — they ship in the agentcage-egress image and the
# per-cage host-side rendered proxy-config.yaml.






def test_capture_warning_no_longer_fires_for_enable_har():
    """Pre-this-PR: ``validate_config`` warned that ``capture.enable_har:
    true`` was silently dropped on apple-container. Post-PR, body capture
    actually works — the warning must NOT fire so operators aren't told
    a working feature is broken.
    """
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/debian:12-slim"
    cfg.capture.enable_har = True
    # Patch the platform probes so validate_config's macOS-only guard
    # doesn't reject the test on a Linux CI host.
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"):
        warnings = validate_config(cfg)
    for w in warnings:
        assert "capture.enable_har" not in w, (
            "validate_config still warns about capture.enable_har on "
            "apple-container — should be removed now that HAR body "
            "capture works end-to-end."
        )
# ---------------------------------------------------------------------------
# inspector chain — wire the cage.yaml ``inspectors:`` list end-to-end
# ---------------------------------------------------------------------------


# inspectors build-context staging tests removed in PR 3 — see comment
# above about the wrapper image no longer carrying proxy/dns config.


def test_load_config_parses_inspectors(tmp_path):
    """cage.yaml ``inspectors:`` list survives load_config as a list of
    raw dicts on Config.inspectors. The container backend's addon
    already reads YAML directly; we keep the same opaque-dict shape so
    behavior is byte-for-byte identical across backends."""
    from agentcage.config import load_config
    p = tmp_path / "cage.yaml"
    p.write_text(
        "name: t\n"
        "container:\n  image: localhost/test:latest\n"
        "inspectors:\n"
        "  - name: content-type\n"
        "    config:\n"
        "      action: block\n"
    )
    cfg = load_config(str(p))
    assert cfg.inspectors == [
        {"name": "content-type", "config": {"action": "block"}}
    ]


def test_validate_config_accepts_builtin_inspector_on_apple_container():
    """A built-in inspector entry on apple-container must NOT trigger a
    'silently has no effect' warning — the chain runs end-to-end now."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.inspectors = [{"name": "content-type", "config": {}}]
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"):
        warnings = validate_config(cfg)
    joined = " ".join(warnings)
    # Built-in inspector → no warning at all.
    assert "inspectors" not in joined or "content-type" not in joined


def test_validate_config_warns_for_unknown_inspector_on_apple_container():
    """An unknown built-in name is almost always a typo and would silently
    no-op in the cage. Surface it at parse time."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.inspectors = [{"name": "nonexistent-inspector", "config": {}}]
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"):
        warnings = validate_config(cfg)
    assert any(
        "nonexistent-inspector" in w and "not a known built-in" in w
        for w in warnings
    ), warnings


def test_validate_config_warns_for_path_inspector_on_apple_container():
    """Custom-Python-file inspectors (``path: /etc/...``) are not yet
    staged into the wrapper image — warn so the operator knows it'll
    silently no-op until that gap is closed."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.inspectors = [
        {"name": "my-check", "path": "/etc/agentcage/my_inspector.py"}
    ]
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"):
        warnings = validate_config(cfg)
    assert any(
        "custom Python file inspectors" in w for w in warnings
    ), warnings


def _make_request_flow_for_inspector(*, host, method="POST",
                                      headers=None, body=""):
    """Build a minimal mock HTTPFlow for the inspector-chain request hook.

    Different shape from _make_response_flow because the inspector chain
    runs before the response hook fires; we need the request side fully
    populated (body, content-type, etc.) so InspectionContext can be built.
    """
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.pretty_url = f"https://{host}/api/x"
    flow.request.path = "/api/x"
    flow.request.port = 443
    flow.request.method = method
    flow.request.content = body.encode() if isinstance(body, str) else body
    hdrs = dict(headers or {})

    class _Headers(dict):
        def items(self, multi=False):  # noqa: ARG002
            return list(super().items())

        def get(self, key, default=""):
            for k, v in super().items():
                if k.lower() == key.lower():
                    return v
            return default

    flow.request.headers = _Headers(hdrs)
    flow.request.get_text = lambda strict=False: (
        body if isinstance(body, str) else body.decode("utf-8", "replace")
    )
    flow.response = None

    def _make_response(status, content, resp_headers):
        resp = MagicMock()
        resp.status_code = status
        resp.content = content
        resp.headers = resp_headers
        return resp

    # The addon does `http.Response.make(...)` to synthesize the 403.
    # conftest.py stubs `mitmproxy.http` as a MagicMock so `Response.make`
    # is already a MagicMock; we wire it to a real object so we can
    # assert on the returned body/status.
    return flow





# ---------------------------------------------------------------------------
#
# Regression coverage for the CTF finding that mitmproxy in transparent
# mode bridges raw TCP (and non-HTTP TLS) through unmodified — bypassing
# the ``request``/``response`` hooks that enforce the allowlist and
# secret-injection policy. The fix adds a ``tcp_start`` hook that kills
# any flow reaching the TCP layer.
#
# The container backend has the same class of bug and is covered in
# ``tests/test_addon_tcp_bypass.py``. Both backends share the same
# threat model and must fail closed on identical attack shapes.
# ---------------------------------------------------------------------------


def _make_tcp_flow(*, sni=None, server_address=None, server_peername=None):
    """Build a mock TCP flow for the apple-container addon's ``tcp_start``.

    ``sni`` is the TLS SNI the cage committed to (None for plain TCP).
    ``server_address`` is what mitmproxy resolves from SO_ORIGINAL_DST
    in transparent mode (the cage's TCP destination IP:port).
    """
    flow = MagicMock()
    flow.client_conn.sni = sni
    flow.server_conn.address = server_address
    flow.server_conn.peername = server_peername
    flow.server_conn.error = None
    flow.killable = True
    flow.live = True
    return flow







def test_egress_supervisor_keeps_lazy_connection_strategy():
    """The mitmdump launch line must still carry --set connection_strategy=lazy.
    PR 3 moved this to the egress sibling's supervisor (PR 1's
    supervisor-egress.sh) — same string, different file."""
    egress_supervisor = (
        Path(__file__).parent.parent
        / "src" / "agentcage" / "data" / "containers" / "supervisor-egress.sh"
    ).read_text()
    assert "connection_strategy=lazy" in egress_supervisor


# ---------------------------------------------------------------------------
# reload_domains: live SIGHUP allowlist reload (no cage rebuild/restart)
# ---------------------------------------------------------------------------


def test_reload_domains_sighups_dnsmasq_without_restart(tmp_path, monkeypatch):
    """A domain change on a running apple-container cage re-renders the
    bind-mounted egress config in place and SIGHUPs dnsmasq — it must NOT
    rebuild the image or stop/start the cage (so an interactive session
    survives)."""
    backend = AppleContainerBackend()
    egress_dir = tmp_path / "egress"
    egress_dir.mkdir()
    allow = egress_dir / "dns-allowlist.conf"
    allow.write_text("server=/old.example/1.1.1.1\n")

    monkeypatch.setattr(backend, "egress_config_dir", lambda name: egress_dir)
    monkeypatch.setattr(
        backend, "_render_egress_config",
        lambda cfg, name: allow.write_text("server=/new.example/1.1.1.1\n"),
    )
    monkeypatch.setattr(backend, "is_running", lambda name, svc: True)

    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    cfg = Config(name="demo", isolation="apple-container")
    cfg.container.image = "x"
    with patch.object(ac_cli, "run", side_effect=fake_run), \
         patch.object(backend, "stop") as stop_mock, \
         patch.object(backend, "build_artifacts") as build_mock, \
         patch.object(backend, "start") as start_mock:
        backend.reload_domains(cfg, "demo")

    # Validated the allowlist inside the egress, then SIGHUP'd dnsmasq in
    # BOTH the egress and the cage (the cage-local resolver is the one the
    # workload actually queries).
    assert any(
        a[:2] == ["exec", "demo-egress"] and "dnsmasq" in a and "--test" in a
        for a in calls
    )
    assert any(
        a[:2] == ["exec", "demo-egress"] and "kill -HUP" in " ".join(a)
        for a in calls
    )
    assert any(
        a[:2] == ["exec", "demo"] and "/run/agentcage/dnsmasq.pid" in " ".join(a)
        for a in calls
    )
    # No rebuild, no cage restart.
    stop_mock.assert_not_called()
    build_mock.assert_not_called()
    start_mock.assert_not_called()


def test_reload_domains_reverts_on_invalid_allowlist(tmp_path, monkeypatch):
    """If `dnsmasq --test` rejects the rewritten allowlist, revert the file
    and raise — never SIGHUP a broken config (which dnsmasq would ignore,
    silently serving stale rules)."""
    backend = AppleContainerBackend()
    egress_dir = tmp_path / "egress"
    egress_dir.mkdir()
    allow = egress_dir / "dns-allowlist.conf"
    allow.write_text("server=/old.example/1.1.1.1\n")

    monkeypatch.setattr(backend, "egress_config_dir", lambda name: egress_dir)
    monkeypatch.setattr(
        backend, "_render_egress_config",
        lambda cfg, name: allow.write_text("this is not valid dnsmasq syntax\n"),
    )
    monkeypatch.setattr(backend, "is_running", lambda name, svc: True)

    sighup_seen = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        if "--test" in argv:
            return type("CP", (), {"returncode": 2, "stdout": "", "stderr": "bad allowlist"})()
        if "kill" in " ".join(argv):
            sighup_seen.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    cfg = Config(name="demo", isolation="apple-container")
    with patch.object(ac_cli, "run", side_effect=fake_run):
        with pytest.raises(RuntimeError, match="rejected the new allowlist"):
            backend.reload_domains(cfg, "demo")

    # File reverted to its previous contents; no SIGHUP sent.
    assert allow.read_text() == "server=/old.example/1.1.1.1\n"
    assert sighup_seen == []


def test_reload_domains_no_signal_when_egress_stopped(tmp_path, monkeypatch):
    """When the egress isn't running, re-rendering the files is enough — the
    next start() reads them; we must not exec into a stopped microVM."""
    backend = AppleContainerBackend()
    egress_dir = tmp_path / "egress"
    egress_dir.mkdir()
    (egress_dir / "dns-allowlist.conf").write_text("server=/old.example/1.1.1.1\n")

    rendered: list[int] = []
    monkeypatch.setattr(backend, "egress_config_dir", lambda name: egress_dir)
    monkeypatch.setattr(backend, "_render_egress_config",
                        lambda cfg, name: rendered.append(1))
    monkeypatch.setattr(backend, "is_running", lambda name, svc: False)

    cfg = Config(name="demo", isolation="apple-container")
    with patch.object(ac_cli, "run") as run_mock:
        backend.reload_domains(cfg, "demo")

    assert rendered == [1]          # re-rendered the files
    run_mock.assert_not_called()    # but did not exec into the stopped egress


# ---------------------------------------------------------------------------
# --no-cache / --pull propagation (cage create/update flags)
# ---------------------------------------------------------------------------


def test_egress_build_no_cache_forces_rebuild_even_when_present():
    """`_build_egress_image_if_missing(no_cache=True)` must rebuild with
    --no-cache even though the version-tagged egress image already exists —
    the whole point of --no-cache is to not reuse the cached image."""
    backend = AppleContainerBackend()
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "run", side_effect=fake_run), \
         patch.object(ac_cli, "image_inspect", return_value={"present": True}):
        backend._build_egress_image_if_missing(quiet=True, no_cache=True, pull=True)

    builds = [a for a in calls if a[:1] == ["build"]]
    assert builds, "egress must rebuild when --no-cache/--pull is set"
    assert "--no-cache" in builds[0]
    assert "--pull" in builds[0]


def test_egress_build_skips_when_present_and_not_forced():
    """Without the flags, a present egress image is still skipped (default)."""
    backend = AppleContainerBackend()
    with patch.object(ac_cli, "run") as run_mock, \
         patch.object(ac_cli, "image_inspect", return_value={"present": True}):
        backend._build_egress_image_if_missing(quiet=True)
    run_mock.assert_not_called()


def test_build_image_from_staged_passes_flags_and_build_args(tmp_path):
    """`build_image_from_staged(no_cache=True, pull=True)` forwards both flags
    and the (resolved) build args to `container build`, building the cage's
    own staged Containerfile."""
    cf = tmp_path / "Containerfile"
    cf.write_text("FROM scratch\n")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "run", side_effect=fake_run), \
         patch("agentcage.registry.resolve_build_args",
               return_value=({"BASE_IMAGE": "x:1"}, [])):
        ac_scaffold.build_image_from_staged(
            "localhost/agentcage-scaffold-debian:latest", cf, tmp_path,
            {"BASE_IMAGE": "x"}, quiet=True, no_cache=True, pull=True,
        )

    builds = [a for a in calls if a[:1] == ["build"]]
    assert builds, "image must be built from the staged Containerfile"
    assert "--no-cache" in builds[0]
    assert "--pull" in builds[0]
    assert "-f" in builds[0] and str(cf) in builds[0]
    assert "--build-arg" in builds[0] and "BASE_IMAGE=x:1" in builds[0]
    assert builds[0][-1] == str(tmp_path)  # context dir


def test_build_image_from_staged_drops_pull_for_localhost_base(tmp_path):
    """`--pull` is suppressed when a `FROM` references a `localhost/` base:
    it has no registry source, and `container build --pull` applies globally,
    so BuildKit would fail with ECONNREFUSED trying to fetch it. `--no-cache`
    is still forwarded to force the rebuild."""
    cf = tmp_path / "Containerfile"
    cf.write_text("FROM localhost/agentcage-truelayer-base:latest\nRUN true\n")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "run", side_effect=fake_run), \
         patch("agentcage.registry.resolve_build_args", return_value=({}, [])):
        ac_scaffold.build_image_from_staged(
            "localhost/agentcage-truelayer-pi:latest", cf, tmp_path,
            None, quiet=True, no_cache=True, pull=True,
        )

    builds = [a for a in calls if a[:1] == ["build"]]
    assert builds, "image must be built from the staged Containerfile"
    assert "--no-cache" in builds[0]
    assert "--pull" not in builds[0]


def test_build_image_from_staged_keeps_pull_for_remote_base(tmp_path):
    """`--pull` is honored when every `FROM` is a genuinely-remote ref
    (a real registry pull the operator asked for)."""
    cf = tmp_path / "Containerfile"
    cf.write_text("FROM docker.io/library/debian:bookworm\nRUN true\n")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "run", side_effect=fake_run), \
         patch("agentcage.registry.resolve_build_args", return_value=({}, [])):
        ac_scaffold.build_image_from_staged(
            "localhost/agentcage-scaffold-debian:latest", cf, tmp_path,
            None, quiet=True, no_cache=False, pull=True,
        )

    builds = [a for a in calls if a[:1] == ["build"]]
    assert builds
    assert "--pull" in builds[0]


def test_base_image_refs_ignores_multistage_aliases(tmp_path):
    """A `FROM <alias>` that references an earlier `FROM ... AS <alias>` stage
    is not a base ref; `--platform` flags and `scratch` are also excluded."""
    cf = tmp_path / "Containerfile"
    cf.write_text(
        "FROM --platform=linux/arm64 docker.io/library/debian:bookworm AS build\n"
        "RUN true\n"
        "FROM build\n"
        "FROM scratch\n"
    )
    assert ac_scaffold._base_image_refs(cf) == ["docker.io/library/debian:bookworm"]


def test_build_artifacts_threads_no_cache_and_pull_to_all_builders(tmp_path):
    """`build_artifacts(no_cache=True, pull=True)` propagates both flags to
    the egress build, the staged-Containerfile build, and the wrapper build
    (no-cache)."""
    (tmp_path / "Containerfile").write_text("FROM scratch\n")
    backend = AppleContainerBackend()
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/agentcage-scaffold-debian:latest"
    cfg.container.build.containerfile = "Containerfile"
    cfg.container.command = ["sh", "-c", "sleep infinity"]
    cfg.scaffold = "debian"

    with patch.object(backend, "_build_egress_image_if_missing") as egress, \
         patch.object(ac_scaffold, "build_image_from_staged") as staged, \
         patch("agentcage.state.deployment_dir", return_value=tmp_path), \
         patch.object(ac_cli, "image_inspect", return_value={"present": True}), \
         patch.object(backend, "_render_egress_config"), \
         patch.object(ac_wrapper, "build_wrapper") as wrapper:
        backend.build_artifacts(cfg, "t", quiet=True, no_cache=True, pull=True)

    assert egress.call_args.kwargs.get("no_cache") is True
    assert egress.call_args.kwargs.get("pull") is True
    assert staged.call_args.kwargs.get("no_cache") is True
    assert staged.call_args.kwargs.get("pull") is True
    assert wrapper.call_args.kwargs.get("no_cache") is True


def test_build_artifacts_pull_forces_repull_of_cached_remote_image():
    """`--pull` re-pulls a genuinely-remote image even when it's already
    cached locally (operator asked for the latest)."""
    backend = AppleContainerBackend()
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/debian:stable-slim"
    cfg.container.command = ["sh"]

    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(backend, "_build_egress_image_if_missing"), \
         patch.object(ac_cli, "run", side_effect=fake_run), \
         patch.object(ac_cli, "image_inspect", return_value={"present": True}), \
         patch.object(backend, "_render_egress_config"), \
         patch.object(ac_wrapper, "build_wrapper"):
        backend.build_artifacts(cfg, "t", quiet=True, pull=True)

    assert any(a[:2] == ["image", "pull"] for a in calls), \
        "--pull must re-pull a cached remote image"


def test_build_artifacts_pull_does_not_pull_localhost_ref():
    """`--pull` never pulls a `localhost/` ref (no registry source); a
    present localhost image is used as-is."""
    backend = AppleContainerBackend()
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/agentcage-scaffold-debian:latest"
    cfg.container.command = ["sh"]

    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(backend, "_build_egress_image_if_missing"), \
         patch.object(ac_cli, "run", side_effect=fake_run), \
         patch.object(ac_cli, "image_inspect", return_value={"present": True}), \
         patch.object(backend, "_render_egress_config"), \
         patch.object(ac_wrapper, "build_wrapper"):
        backend.build_artifacts(cfg, "t", quiet=True, pull=True)

    assert not any(a[:2] == ["image", "pull"] for a in calls)


def test_wipe_staged_secrets_empties_the_bind_dir(tmp_path, monkeypatch):
    """The transient post-boot wipe removes staged cleartext files while
    leaving the bind-mount dir in place (re-staged on the next start)."""
    from agentcage.backends.apple_container import AppleContainerBackend
    backend = AppleContainerBackend()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "API_KEY").write_text("sk-secret")
    (secrets_dir / "GH_TOKEN").write_text("ghp-x")
    monkeypatch.setattr(backend, "secrets_dir", lambda _n: secrets_dir)

    backend._wipe_staged_secrets("demo")

    assert secrets_dir.is_dir()
    assert list(secrets_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# start() re-renders DNS config from the current host resolver
# ---------------------------------------------------------------------------
class _HaltStart(Exception):
    """Sentinel raised from a stubbed step to halt start() right after the
    re-render, so the test needn't mock the whole egress bring-up."""


def _prime_start(backend, tmp_path):
    """Stub out everything start() touches BEFORE _stage_secrets so the
    method runs from entry through the DNS re-render, then halts.

    Returns the sentinel config that ``state.load_deployment_config`` is
    patched to return, so the caller can assert it was threaded into
    ``_render_egress_config``.
    """
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({"autostart": False}))
    for sub in ("egress-cfg", "logs", "certs", "pub"):
        (tmp_path / sub).mkdir()

    backend.unit_dir = MagicMock(return_value=unit_dir)
    backend.egress_config_dir = MagicMock(return_value=tmp_path / "egress-cfg")
    backend.logs_dir = MagicMock(return_value=tmp_path / "logs")
    backend.certs_dir = MagicMock(return_value=tmp_path / "certs")
    backend.public_certs_dir = MagicMock(return_value=tmp_path / "pub")
    # start() now gates on the apiserver being up (ensure_ready +
    # ac_cli.system_running) before doing any work; stub the readiness
    # bring-up here and patch system_running True in the caller.
    backend.ensure_ready = MagicMock()
    # Halt right after the network-create step that follows the re-render.
    backend._stage_secrets = MagicMock(side_effect=_HaltStart)

    cfg_sentinel = MagicMock(name="loaded-config")
    return cfg_sentinel


def test_start_rerenders_egress_dns_config_from_current_host(tmp_path):
    """Regression: 'cage cannot connect to the network after restarting'.

    The bind-mounted dnsmasq.conf / dns-allowlist.conf pin the cage's DNS
    upstream to the host resolver detected at the last create/update. On a
    dev laptop that changed networks (or rebooted on a different LAN) since
    then, a plain restart used to come back forwarding DNS to a dead
    resolver IP. start() must re-render those (bind-mounted, no-rebuild)
    files from the host's CURRENT resolver."""
    backend = AppleContainerBackend()
    cfg_sentinel = _prime_start(backend, tmp_path)
    backend._render_egress_config = MagicMock(name="_render_egress_config")

    with patch.object(ac_cli, "system_running", return_value=True), \
         patch.object(ac_cli, "image_inspect", return_value=object()), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", return_value=MagicMock(returncode=0)), \
         patch("agentcage.state.load_deployment_config",
               return_value=cfg_sentinel):
        with pytest.raises(_HaltStart):
            backend.start("demo")

    backend._render_egress_config.assert_called_once_with(cfg_sentinel, "demo")


def test_start_tolerates_undetectable_host_resolver(tmp_path):
    """The re-render is best-effort: if the host resolver can't be detected
    at start time (_host_dns_servers raises), start() must NOT abort — it
    keeps the previously-rendered config and continues, matching the
    pre-fix behaviour of starting with whatever was on disk."""
    backend = AppleContainerBackend()
    cfg_sentinel = _prime_start(backend, tmp_path)
    backend._render_egress_config = MagicMock(
        side_effect=RuntimeError("could not detect usable DNS servers")
    )

    with patch.object(ac_cli, "system_running", return_value=True), \
         patch.object(ac_cli, "image_inspect", return_value=object()), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", return_value=MagicMock(returncode=0)), \
         patch("agentcage.state.load_deployment_config",
               return_value=cfg_sentinel):
        # Reaching the halt sentinel proves the render failure was swallowed
        # rather than propagated out of start().
        with pytest.raises(_HaltStart):
            backend.start("demo")


# ---------------------------------------------------------------------------
# DNS routes through the egress to the host-tracking vmnet gateway
# ---------------------------------------------------------------------------
def _read_data_file(*parts):
    from pathlib import Path
    return (Path(__file__).resolve().parent.parent
            / "src" / "agentcage" / "data").joinpath(*parts).read_text()


def test_egress_dnsmasq_listens_explicitly_and_forwards_to_gateway():
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


def test_reload_domains_regenerates_runtime_servers_before_sighup():
    """Live `domain add/rm` must regenerate the runtime servers-file the
    dnsmasq instances actually serve (/run/agentcage/dns-allowlist.{cage,
    egress}.conf), re-pointing apexes at each VM's default-route upstream,
    BEFORE the SIGHUP — otherwise the new apex lands only in the
    bind-mounted file and the served set is stale."""
    import inspect
    src = inspect.getsource(AppleContainerBackend.reload_domains)
    # both instances re-point at their default route (cage→egress,
    # egress→gateway) and rewrite the served runtime file before SIGHUP
    assert "/run/agentcage/dns-allowlist.egress.conf" in src
    assert "/run/agentcage/dns-allowlist.cage.conf" in src
    assert 'ip route' in src and '/^default/' in src
    assert "kill -HUP" in src


def test_start_injects_agentcage_version_env(tmp_path, monkeypatch):
    """The cage VM gets AGENTCAGE_VERSION so an agent can detect it's
    sandboxed (parity with the container/vm backends' cage.container.j2)."""
    backend, captured = _setup_start_test(
        tmp_path, monkeypatch,
        unit_meta={
            "name": "demo", "user_image": "x", "cpus": "", "memory": "",
            "lifecycle": "interactive",
        },
    )
    backend.start("demo", quiet=True)
    cage_argv = _cage_run_argv(captured)
    assert any(a.startswith("AGENTCAGE_VERSION=") for a in cage_argv)
