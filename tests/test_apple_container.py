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


# ── allowlist_addon import helper ────────────────────────────
# The addon file ships inside the wheel as a data file (it runs
# *inside* the cage's mitmproxy process, not in the host Python).
# To unit-test ``AllowlistAddon`` from the host, we load it by
# absolute path; conftest.py already stubs ``mitmproxy`` so the
# import succeeds without the real proxy bundle being installed.

_ADDON_PATH = (
    Path(__file__).parent.parent
    / "src" / "agentcage" / "data" / "apple-container" / "allowlist_addon.py"
)


def _load_addon_module():
    spec = importlib.util.spec_from_file_location(
        "_test_allowlist_addon", _ADDON_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


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
    # CTF F1 (0.22.6): stage B' must install iptables rules that DROP
    # cage→apple-host-gateway TCP and non-DNS UDP. Without this the cage
    # can reach the macOS host's sshd (:22) and Apple Remote Desktop
    # (:5900) directly via the vmnet gateway, OUTSIDE the egress proxy.
    assert "_apple_host_gw=" in cage_init
    assert 'iptables -A OUTPUT -d "${_apple_host_gw}" -p tcp -j DROP' in cage_init
    assert (
        'iptables -A OUTPUT -d "${_apple_host_gw}" -p udp ! --dport 53 -j DROP'
        in cage_init
    )
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
#   * `test_allowlist_addon_*` further down — Python-level unit tests of
#     the addon's behaviour, importing from
#     src/agentcage/data/apple-container/allowlist_addon.py directly (the
#     file is retained as a test fixture; it is no longer baked into any
#     image).


def test_allowlist_addon_runs_transform_at_request_time(monkeypatch, tmp_path):
    """End-to-end addon test: a rule with ``transform`` set must inject
    the transform's return value into the outbound request — NOT the
    raw env-passed credential. This is the load-bearing assertion for
    the whole feature.

    Uses a fake transform registered in-process so we don't need
    cryptography or network access.
    """
    # Write a rule list with a transform; point the addon at it.
    rules = [{
        "env": "SECRET_INPUT",
        "placeholder": "{{TOKEN}}",
        "inject_to": ["api.example.com"],
        "transform": "_test_marker",
        "transform_config": {"marker": "transformed-output-marker"},
    }]
    rule_file = tmp_path / "secret_injection.json"
    rule_file.write_text(json.dumps(rules))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")

    # Set the raw env input that the cage agent would normally send;
    # the test asserts the upstream sees the TRANSFORMED value instead.
    monkeypatch.setenv("SECRET_INPUT", "raw-input-value")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    # Import the addon AFTER setting the env so module-level path constants
    # resolve to tmp_path. The addon is read from data/apple-container/.
    import importlib
    import sys
    addon_dir = (
        # tests/  -> repo root -> src/agentcage/data/apple-container/
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    transforms_src = (
        addon_dir.parent / "proxy" / "transforms"
    )
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(transforms_src.parent))

    # Register a no-op transform that returns the configured marker so
    # we don't need cryptography / network. This is the SAME registry the
    # addon uses; the registration must happen before AllowlistAddon's
    # __init__ runs (which is where transforms are bound).
    import transforms as _t  # noqa: WPS433  (test-only)
    importlib.reload(_t)

    class _MarkerTransform:
        def __init__(self, secret: str, config: dict) -> None:
            self._marker = config["marker"]
            self._secret = secret

        def get_value(self) -> str:
            return self._marker

    _t.register("_test_marker", _MarkerTransform)

    # Point the addon's module-level paths at our tmp files BEFORE import.
    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rule_file)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")

    addon = allowlist_addon.AllowlistAddon()

    # Sanity: rule was resolved AND a transform_fn was bound.
    assert len(addon._resolved_secrets) == 1
    resolved = addon._resolved_secrets[0]
    assert resolved["transform"] == "_test_marker"
    assert resolved["transform_fn"] is not None
    # The raw env value is still cached on the resolved rule (so the
    # original injection path stays available for non-transform rules)
    # — but it MUST NOT be the value sent on the wire.
    assert resolved["value"] == "raw-input-value"

    # Build a fake flow with the placeholder in the Authorization header.
    fake_flow = MagicMock()
    fake_flow.request.pretty_host = "api.example.com"
    fake_flow.request.headers = {"Authorization": "Bearer {{TOKEN}}"}

    # `headers` needs the in-place mutation pattern the real addon uses.
    class _Headers(dict):
        def items(self):
            return list(super().items())

    fake_flow.request.headers = _Headers(
        {"Authorization": "Bearer {{TOKEN}}"}
    )
    fake_flow.request.get_text = lambda strict=False: ""
    fake_flow.request.set_text = lambda _t: None

    injected, transforms_map = addon._maybe_inject(fake_flow)

    # The transform's marker — NOT the raw env value — landed in the header.
    assert (
        fake_flow.request.headers["Authorization"]
        == "Bearer transformed-output-marker"
    )
    assert "raw-input-value" not in fake_flow.request.headers["Authorization"]
    assert injected == ["SECRET_INPUT"]
    assert transforms_map == {"SECRET_INPUT": "_test_marker"}


def test_allowlist_addon_skips_rule_on_transform_init_failure(
    monkeypatch, tmp_path,
):
    """A transform that raises during ``__init__`` must drop the rule at
    startup (with a warning) — NOT crash the whole addon and NOT fall
    back to substituting the raw env-passed credential. Failing closed
    is the safety-critical contract."""
    rules = [{
        "env": "SECRET_INPUT",
        "placeholder": "{{TOKEN}}",
        "inject_to": ["api.example.com"],
        "transform": "_test_broken_init",
        "transform_config": {},
    }]
    rule_file = tmp_path / "secret_injection.json"
    rule_file.write_text(json.dumps(rules))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")
    monkeypatch.setenv("SECRET_INPUT", "raw-input-value")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    import importlib
    import sys
    addon_dir = (
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    transforms_src = addon_dir.parent / "proxy" / "transforms"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(transforms_src.parent))

    import transforms as _t
    importlib.reload(_t)

    class _BrokenInit:
        def __init__(self, *_a, **_kw):
            raise RuntimeError("intentional test failure")

        def get_value(self) -> str:  # pragma: no cover
            return "unreachable"

    _t.register("_test_broken_init", _BrokenInit)

    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rule_file)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")
    addon = allowlist_addon.AllowlistAddon()

    # Rule dropped, NOT substituted with raw value.
    assert addon._resolved_secrets == []


def test_allowlist_addon_skips_request_on_transform_runtime_failure(
    monkeypatch, tmp_path,
):
    """If the transform raises at substitution time, the placeholder is
    left in place — the upstream request fails closed with an auth error
    rather than smuggling the raw credential through. No fallback to the
    raw env value (which is the point of having a transform in the first
    place)."""
    rules = [{
        "env": "SECRET_INPUT",
        "placeholder": "{{TOKEN}}",
        "inject_to": ["api.example.com"],
        "transform": "_test_runtime_fail",
        "transform_config": {},
    }]
    rule_file = tmp_path / "secret_injection.json"
    rule_file.write_text(json.dumps(rules))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")
    monkeypatch.setenv("SECRET_INPUT", "raw-input-value")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    import importlib
    import sys
    addon_dir = (
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    transforms_src = addon_dir.parent / "proxy" / "transforms"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(transforms_src.parent))

    import transforms as _t
    importlib.reload(_t)

    class _RuntimeFail:
        def __init__(self, *_a, **_kw):
            pass

        def get_value(self) -> str:
            raise RuntimeError("mint failed")

    _t.register("_test_runtime_fail", _RuntimeFail)

    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rule_file)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")
    addon = allowlist_addon.AllowlistAddon()

    class _Headers(dict):
        def items(self):
            return list(super().items())

    fake_flow = MagicMock()
    fake_flow.request.pretty_host = "api.example.com"
    fake_flow.request.headers = _Headers(
        {"Authorization": "Bearer {{TOKEN}}"}
    )
    fake_flow.request.get_text = lambda strict=False: ""
    fake_flow.request.set_text = lambda _t: None

    injected, transforms_map = addon._maybe_inject(fake_flow)

    # Header UNCHANGED — placeholder stays, raw value never leaks.
    assert (
        fake_flow.request.headers["Authorization"] == "Bearer {{TOKEN}}"
    )
    assert "raw-input-value" not in fake_flow.request.headers["Authorization"]
    assert injected == []
    assert transforms_map == {}


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
    monkeypatch.setattr(backend, "egress_config_dir", lambda _n: egress_cfg)
    monkeypatch.setattr(backend, "certs_dir", lambda _n: certs_dir)
    monkeypatch.setattr(
        backend, "public_certs_dir", lambda _n: public_certs_dir,
    )
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

    # Cage's /certs MUST come from public_certs_dir.
    assert f"{public_certs_dir}:/certs" in cage_argv
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
    # `image pull` must still have run.
    assert any(
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


def test_build_artifacts_orders_scaffold_then_pull_then_wrapper():
    """Scaffold images must build BEFORE pull, and pull BEFORE wrapper build.

    The wrapper's `FROM <user_image>` references a scaffold-produced tag, so
    flipping these would leave the wrapper build referencing a tag that
    doesn't yet exist.
    """
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/agentcage-ubuntu:latest"
    cfg.scaffold = "ubuntu"

    calls: list[str] = []

    def scaffold_side_effect(scaffold, *, quiet=False):  # noqa: ARG001
        calls.append("scaffold")

    def run_side_effect(argv, **kwargs):  # noqa: ARG001
        if argv[:2] == ["image", "pull"]:
            calls.append("pull")
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    def build_wrapper_side_effect(*args, **kwargs):  # noqa: ARG001
        calls.append("wrapper")
        return "img"

    with patch.object(ac_scaffold, "build_scaffold_images", side_effect=scaffold_side_effect), \
         patch.object(ac_cli, "run", side_effect=run_side_effect), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {"Cmd": ["/bin/bash"]}}), \
         patch.object(ac_wrapper, "_user_cmd", return_value=["/bin/bash"]), \
         patch.object(ac_wrapper, "build_wrapper", side_effect=build_wrapper_side_effect):
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    # Only the first occurrence of each matters; pull can be called more than
    # once depending on internal retries, but the ordering invariant is fixed.
    first_idx = {step: calls.index(step) for step in ("scaffold", "pull", "wrapper")}
    assert first_idx["scaffold"] < first_idx["pull"] < first_idx["wrapper"]


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
    cage.yaml) can re-emit them as --volume args. Was missing pre-fix."""
    from agentcage.config import Config, ContainerConfig
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
    assert parsed["volumes"] == ["~/foo:/workspace:rw"]


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
# allowlist_addon: response-side {{SECRET}} redaction
#
# These exercise the addon's response() hook end-to-end with a mocked
# mitmproxy HTTPFlow. The conftest.py stub of `mitmproxy` lets the addon
# module import cleanly on the host; we never spin up real mitmproxy.
# ---------------------------------------------------------------------------


def _build_addon(monkeypatch, tmp_path, *, secret_value="redact-test-xyz",
                 inject_to=("httpbin.org",), allowlist=("httpbin.org",)):
    """Construct an AllowlistAddon wired to a one-rule config in tmp_path.

    Returns ``(module, addon)``. Audit + capture logs are redirected
    into tmp_path so tests can assert on the JSONL output.
    """
    addon_mod = _load_addon_module()
    # Resolve secret via env so the addon's startup-time os.environ lookup
    # picks it up (the same way `agentcage cage create -e ...` works in prod).
    monkeypatch.setenv("AGENTCAGE_REDACT_SECRET", secret_value)
    rules = [{
        "env": "AGENTCAGE_REDACT_SECRET",
        "placeholder": "{{AGENTCAGE_REDACT_SECRET}}",
        "inject_to": list(inject_to),
    }]
    allow_path = tmp_path / "allowlist.txt"
    allow_path.write_text("\n".join(allowlist) + "\n")
    si_path = tmp_path / "secret_injection.json"
    si_path.write_text(json.dumps(rules))
    monkeypatch.setattr(addon_mod, "ALLOWLIST_PATH", str(allow_path))
    monkeypatch.setattr(addon_mod, "SECRET_INJECTION_PATH", str(si_path))
    monkeypatch.setattr(addon_mod, "AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(addon_mod, "CAPTURE_PATH", str(tmp_path / "capture.jsonl"))
    return addon_mod, addon_mod.AllowlistAddon()


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


def test_response_redaction_happy_path(tmp_path, monkeypatch):
    """End-to-end: a response body that echoes the real secret value gets
    rewritten back to ``{{AGENTCAGE_REDACT_SECRET}}``. The audit JSONL
    records the env name under ``secrets_redacted``.

    Mirrors the live-Mac smoke test against httpbin/headers — the upstream
    sees the real key, the cage sees the placeholder."""
    addon_mod, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_response_flow(
        host="httpbin.org",
        # Shape mimics httpbin /headers JSON output.
        body='{"headers": {"X-Echo": "redact-test-xyz"}}',
    )

    addon.response(flow)

    # Body has the placeholder, not the real value.
    assert "redact-test-xyz" not in flow.response.content.decode()
    assert "{{AGENTCAGE_REDACT_SECRET}}" in flow.response.content.decode()

    # Audit log records the redaction.
    audit_lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    inbound = [json.loads(l) for l in audit_lines
               if json.loads(l).get("direction") == "inbound"]
    assert len(inbound) == 1
    assert inbound[0]["secrets_redacted"] == ["AGENTCAGE_REDACT_SECRET"]
    assert inbound[0]["host"] == "httpbin.org"
    assert inbound[0]["reason"] == "secret-redaction"


def test_response_redaction_in_response_headers(tmp_path, monkeypatch):
    """Headers (not just body) get redacted. Some upstreams echo bearer
    tokens into custom response headers; the cage must never see them."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_response_flow(
        host="httpbin.org",
        body="ok",
        resp_headers={"X-Reflected-Auth": "Bearer redact-test-xyz"},
    )

    addon.response(flow)

    assert flow.response.headers["X-Reflected-Auth"] == (
        "Bearer {{AGENTCAGE_REDACT_SECRET}}"
    )


def test_response_redaction_scoped_to_inject_to_host(tmp_path, monkeypatch):
    """Defense-in-depth: a response from a host NOT in ``inject_to`` is
    NOT redacted even when its body coincidentally contains the secret
    value as a substring. Otherwise unrelated allowlisted upstreams could
    have legitimate text mangled (e.g. a UUID that happened to match)."""
    addon_mod, addon = _build_addon(
        monkeypatch, tmp_path,
        inject_to=("httpbin.org",),
        allowlist=("httpbin.org", "example.com"),
    )
    flow = _make_response_flow(
        host="example.com",  # allowlisted but not in inject_to
        body="here is a coincidence: redact-test-xyz appears in this body",
    )

    addon.response(flow)

    # Real value still present — scope guard worked.
    assert "redact-test-xyz" in flow.response.content.decode()
    assert "{{AGENTCAGE_REDACT_SECRET}}" not in flow.response.content.decode()

    # No inbound audit entry emitted (nothing was redacted).
    audit_path = tmp_path / "audit.jsonl"
    if audit_path.exists():
        for line in audit_path.read_text().splitlines():
            assert json.loads(line).get("direction") != "inbound"


def test_response_redaction_skips_binary_body(tmp_path, monkeypatch):
    """Binary responses (images, archives) pass through unchanged — the
    addon catches ``UnicodeDecodeError`` from ``get_text(strict=False)``
    and never touches the body bytes. Headers are still scanned."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    binary = bytes([0xff, 0xd8, 0xff]) + b"redact-test-xyz" + bytes([0x00, 0xfe])
    flow = _make_response_flow(
        host="httpbin.org",
        body=binary,
        resp_headers={"X-Trace": "echo redact-test-xyz back"},
    )

    addon.response(flow)

    # Body untouched.
    assert flow.response.content == binary
    # Header still got redacted.
    assert flow.response.headers["X-Trace"] == "echo {{AGENTCAGE_REDACT_SECRET}} back"


# ---------------------------------------------------------------------------
# allowlist_addon: REQUEST-side redaction (capture-leak fix)
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


def test_maybe_redact_request_replaces_value_in_headers(tmp_path, monkeypatch):
    """The new request-side redactor scrubs the raw secret out of the
    Authorization header before the capture writer reads it."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_request_redact_flow(
        host="httpbin.org",
        headers={"Authorization": "Bearer redact-test-xyz"},
    )

    redacted = addon._maybe_redact_request(flow)

    assert redacted == ["AGENTCAGE_REDACT_SECRET"]
    assert flow.request.headers["Authorization"] == (
        "Bearer {{AGENTCAGE_REDACT_SECRET}}"
    )


def test_maybe_redact_request_replaces_value_in_body(tmp_path, monkeypatch):
    """Body-bearing requests (POST JSON, etc) also get the real value
    swapped back to the placeholder."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_request_redact_flow(
        host="httpbin.org",
        body='{"x-api-key": "redact-test-xyz"}',
    )

    redacted = addon._maybe_redact_request(flow)

    assert redacted == ["AGENTCAGE_REDACT_SECRET"]
    assert flow.request.content == (
        b'{"x-api-key": "{{AGENTCAGE_REDACT_SECRET}}"}'
    )


def test_maybe_redact_request_scoped_to_inject_to_host(tmp_path, monkeypatch):
    """Mirror of response-side scoping: a request to a host outside the
    rule's ``inject_to`` is NOT scanned. Otherwise unrelated allowlisted
    upstreams would have legitimate text mangled (e.g. UUIDs that
    happen to match a secret value as substring). This also matches the
    inject path's host gate — symmetry is the whole point."""
    _, addon = _build_addon(
        monkeypatch, tmp_path,
        inject_to=("httpbin.org",),
        allowlist=("httpbin.org", "example.com"),
    )
    flow = _make_request_redact_flow(
        host="example.com",  # allowlisted but NOT in inject_to
        body="coincidence: redact-test-xyz appears here",
    )

    redacted = addon._maybe_redact_request(flow)

    assert redacted == []
    assert b"redact-test-xyz" in flow.request.content


def test_maybe_redact_request_skips_binary_body(tmp_path, monkeypatch):
    """Binary request bodies (uploads, etc) pass through unchanged —
    same defensive try/except shape as ``_maybe_inject`` and
    ``_maybe_redact``. Headers still scanned."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    binary = bytes([0xff, 0xd8]) + b"redact-test-xyz" + bytes([0x00])
    flow = _make_request_redact_flow(
        host="httpbin.org",
        headers={"X-Trace": "Bearer redact-test-xyz"},
    )
    # Override get_text to raise — mimics mitmproxy on undecodable bytes.
    flow.request.get_text.side_effect = UnicodeDecodeError(
        "utf-8", binary, 0, 1, "binary body",
    )
    flow.request.content = binary

    redacted = addon._maybe_redact_request(flow)

    # Body untouched (binary skip), but header still got scrubbed.
    assert flow.request.content == binary
    assert flow.request.headers["X-Trace"] == (
        "Bearer {{AGENTCAGE_REDACT_SECRET}}"
    )
    assert redacted == ["AGENTCAGE_REDACT_SECRET"]


def test_maybe_redact_request_keyed_on_authoritative_host(tmp_path, monkeypatch):
    """Symmetric to the inject path: the host used for ``inject_to``
    matching is the SNI (authoritative), NOT the attacker-controlled
    Host header. A spoof that sneaks past the addon's request hook
    shouldn't be able to trick the request-side redactor either."""
    _, addon = _build_addon(
        monkeypatch, tmp_path,
        inject_to=("httpbin.org",),
        allowlist=("httpbin.org",),
    )
    flow = _make_request_redact_flow(
        host="example.com",  # cage-claimed Host header
        body="value: redact-test-xyz",
    )
    # SNI says the bytes actually went to httpbin.org — the authoritative
    # host. Redaction should fire (matches inject_to=httpbin.org).
    flow.client_conn.sni = "httpbin.org"

    redacted = addon._maybe_redact_request(flow)

    assert redacted == ["AGENTCAGE_REDACT_SECRET"]
    assert flow.request.content == b"value: {{AGENTCAGE_REDACT_SECRET}}"


def test_capture_jsonl_never_contains_real_secret_value(tmp_path, monkeypatch):
    """End-to-end: the load-bearing assertion. Run the addon's full
    request→response pipeline with capture enabled and a body that
    contains the placeholder. The upstream will see the substituted
    real value (inject_request worked), but the on-disk capture.jsonl
    must NOT contain the real value — only the placeholder.

    Uses a clearly-synthetic ``sk-ant-api03-FAKE-...`` value so no
    real-key shape can possibly leak into the test fixture."""
    fake_real = "sk-ant-api03-FAKE-TEST-VALUE-FOR-REDACTION-1234567890"
    _, addon = _build_addon_with_capture(
        monkeypatch, tmp_path,
        capture_cfg={
            "enable_har": True,
            "max_body_size": 10485760,
            "domains": ["api.anthropic.com"],
        },
        allowlist=("api.anthropic.com",),
    )
    # Wire a rule so _maybe_inject substitutes on outbound and
    # _maybe_redact_request restores placeholder pre-capture.
    monkeypatch.setenv("AGENTCAGE_LEAK_SECRET", fake_real)
    addon._resolved_secrets = [{
        "env": "AGENTCAGE_LEAK_SECRET",
        "placeholder": "{{AGENTCAGE_LEAK_SECRET}}",
        "value": fake_real,
        "inject_to": ["api.anthropic.com"],
        "transform": "",
        "transform_fn": None,
    }]

    req_body = (
        '{"model": "claude", "x-api-key": "{{AGENTCAGE_LEAK_SECRET}}"}'
    )
    flow = _make_flow_with_bodies(
        host="api.anthropic.com",
        req_body=req_body,
        resp_body='{"ok": true}',
        path="/v1/messages",
        req_content_type="application/json",
    )
    # Mock get_text/set_text on the request side so _maybe_inject and
    # _maybe_redact_request can mutate the body in place.
    req_state = {"text": req_body}
    flow.request.get_text.side_effect = lambda strict=True: req_state["text"]

    def _set_req_text(new):
        req_state["text"] = new
        flow.request.content = new.encode()

    flow.request.set_text.side_effect = _set_req_text
    # SNI matches authoritative host so the addon's inject + redact
    # both fire for this rule.
    flow.client_conn.sni = "api.anthropic.com"

    addon.request(flow)
    # Sanity: the upstream actually received the substituted value —
    # this is what the existing inject path was designed for. We only
    # care that the capture file below does NOT carry these bytes.
    assert fake_real in flow.request.content.decode()

    addon.response(flow)

    cap_text = (tmp_path / "capture.jsonl").read_text()
    assert fake_real not in cap_text, (
        f"real-key bytes leaked into capture.jsonl: {cap_text!r}"
    )
    # Both the inbound (cage-visible) and outbound (wire) snapshots
    # should now show the placeholder.
    cap_entry = json.loads(cap_text.splitlines()[0])
    assert "{{AGENTCAGE_LEAK_SECRET}}" in cap_entry["inbound"]["request"]["body"]
    assert "{{AGENTCAGE_LEAK_SECRET}}" in cap_entry["outbound"]["request"]["body"]


def test_capture_jsonl_legacy_path_never_contains_real_value(
    tmp_path, monkeypatch,
):
    """The legacy headers-only capture path (capture.enable_har: false,
    or no capture config) is the fallback that ships pre-this-PR. It
    serializes ``flow.request.headers.items()`` AFTER ``_maybe_inject``
    has run. Without the new ``_maybe_redact_request`` running first,
    real secret bytes from injected headers land in the legacy
    capture.jsonl too. Symmetric coverage to the rich HAR path above."""
    fake_real = "sk-ant-api03-FAKE-TEST-VALUE-FOR-REDACTION-1234567890"
    _, addon = _build_addon(
        monkeypatch, tmp_path,
        secret_value=fake_real,
        inject_to=("api.anthropic.com",),
        allowlist=("api.anthropic.com",),
    )
    # legacy path: no CaptureWriter — addon writes lean entries via
    # self._capture_fh. Confirm we're on that path.
    assert addon._capture_writer is None
    assert addon._capture_fh is not None

    # Build a request flow that carries the placeholder in the header.
    flow = _make_request_flow(
        pretty_host="api.anthropic.com",
        sni="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        headers={
            "x-api-key": "{{AGENTCAGE_REDACT_SECRET}}",
            "Content-Type": "application/json",
        },
    )
    addon.request(flow)
    # Sanity: inject worked — header now has the real bytes on the wire.
    assert flow.request.headers["x-api-key"] == fake_real

    # Attach a response so the legacy capture path fires.
    resp = MagicMock()
    resp.status_code = 200
    resp.reason = "OK"
    resp.headers = {}
    resp.content = b'{"ok": true}'
    resp.get_text.side_effect = lambda strict=True: '{"ok": true}'
    flow.response = resp

    addon.response(flow)

    cap_text = (tmp_path / "capture.jsonl").read_text()
    assert fake_real not in cap_text, (
        f"real-key bytes leaked into legacy capture.jsonl: {cap_text!r}"
    )
    assert "{{AGENTCAGE_REDACT_SECRET}}" in cap_text


# ---------------------------------------------------------------------------
# allowlist_addon: Host-header spoofing bypass (CTF F1)
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


def test_request_blocks_host_header_spoof_against_sni(tmp_path, monkeypatch):
    """CTF F1 regression — the exact CTF scenario.

    Cage opens a TLS connection with SNI ``example.com`` (the real
    destination — example.com's IP responds to the TCP/TLS handshake)
    but sends ``Host: api.anthropic.com`` in the HTTP request hoping to
    smuggle the API key out. The addon must:

      1. 403 the request with reason ``host-header-spoof`` from the
         proxy itself (no upstream traffic).
      2. Emit an audit entry with ``decision=blocked``,
         ``host_mismatch=true``, and ``authoritative_host`` recording
         the SNI we actually gated on.
      3. Refuse to inject any secret_injection rule's value even if
         the spoofed Host matches a rule's ``inject_to``.
    """
    # Allowlist BOTH so we prove the block is on Host/SNI mismatch,
    # not on a missing allowlist entry.
    addon_mod, addon = _build_addon(
        monkeypatch, tmp_path,
        secret_value="sk-real-ANTHROPIC-key",
        inject_to=("api.anthropic.com",),
        allowlist=("api.anthropic.com", "example.com"),
    )

    flow = _make_request_flow(
        pretty_host="api.anthropic.com",  # spoofed Host header
        sni="example.com",                # authoritative — real dst
        headers={
            "Host": "api.anthropic.com",
            "Authorization": "Bearer {{AGENTCAGE_REDACT_SECRET}}",
        },
    )

    addon.request(flow)

    # 1. Addon synthesized a 403 (the mitmproxy.http stub records the
    #    Response.make call; we assert via flow.response being set).
    assert flow.response is not None
    # The conftest stubs mitmproxy.http as a MagicMock, so flow.response
    # is the MagicMock-returned object from Response.make. The audit log
    # is the source of truth for the decision.

    # 2. Audit log has a blocked entry with host_mismatch.
    audit_lines = [
        json.loads(l)
        for l in (tmp_path / "audit.jsonl").read_text().splitlines()
    ]
    blocks = [e for e in audit_lines if e.get("decision") == "blocked"]
    assert len(blocks) == 1
    blocked = blocks[0]
    assert blocked["host_mismatch"] is True
    assert blocked["authoritative_host"] == "example.com"
    assert "host-header-spoof" in blocked["reason"]
    assert "api.anthropic.com" in blocked["reason"]

    # 3. The Authorization header was NOT rewritten — the real secret
    #    never landed on the wire. (The addon must short-circuit before
    #    _maybe_inject runs.)
    assert (
        flow.request.headers["Authorization"]
        == "Bearer {{AGENTCAGE_REDACT_SECRET}}"
    )
    assert "sk-real-ANTHROPIC-key" not in flow.request.headers["Authorization"]
    assert blocked.get("secrets_injected", []) == []


def test_request_blocks_host_spoof_with_no_sni_uses_original_dst(
    tmp_path, monkeypatch,
):
    """Plain-HTTP variant: no TLS, no SNI — authoritative host falls
    back to the SO_ORIGINAL_DST IP (``flow.request.host`` in transparent
    mode). A Host header claiming a real domain over a TCP connection
    bound for an attacker IP is still blocked because IP != domain."""
    addon_mod, addon = _build_addon(
        monkeypatch, tmp_path,
        secret_value="sk-real",
        inject_to=("api.anthropic.com",),
        allowlist=("api.anthropic.com",),
    )

    flow = _make_request_flow(
        pretty_host="api.anthropic.com",
        sni=None,                       # plain HTTP
        original_dst_host="93.184.216.34",  # example.com's IP
        headers={"Host": "api.anthropic.com"},
    )

    addon.request(flow)

    blocks = [
        json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()
        if json.loads(l).get("decision") == "blocked"
    ]
    assert len(blocks) == 1
    assert blocks[0]["host_mismatch"] is True
    assert blocks[0]["authoritative_host"] == "93.184.216.34"


def test_request_allows_when_host_header_matches_sni(tmp_path, monkeypatch):
    """Happy path: a well-behaved cage that sets ``Host`` to match SNI
    is allowed through and gets the secret injected normally. Verifies
    the spoof gate doesn't break legitimate traffic."""
    addon_mod, addon = _build_addon(
        monkeypatch, tmp_path,
        secret_value="sk-real-value",
        inject_to=("api.anthropic.com",),
        allowlist=("api.anthropic.com",),
    )

    flow = _make_request_flow(
        pretty_host="api.anthropic.com",
        sni="api.anthropic.com",
        headers={
            "Host": "api.anthropic.com",
            "Authorization": "Bearer {{AGENTCAGE_REDACT_SECRET}}",
        },
    )

    addon.request(flow)

    entries = [
        json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()
    ]
    assert any(e.get("decision") == "allowed" for e in entries)
    allowed = [e for e in entries if e.get("decision") == "allowed"][0]
    assert allowed["secrets_injected"] == ["AGENTCAGE_REDACT_SECRET"]
    # Secret landed on the outbound request.
    assert (
        flow.request.headers["Authorization"] == "Bearer sk-real-value"
    )


def test_request_allows_subdomain_host_under_wildcard_sni(
    tmp_path, monkeypatch,
):
    """Some real upstreams route to a subdomain via virtual host while
    the TLS handshake uses the apex domain (wildcard cert). Allow Host
    to be a subdomain of the SNI so we don't break that pattern."""
    addon_mod, addon = _build_addon(
        monkeypatch, tmp_path,
        secret_value="sk-real",
        inject_to=("anthropic.com",),
        allowlist=("anthropic.com",),
    )

    flow = _make_request_flow(
        pretty_host="api.anthropic.com",
        sni="anthropic.com",
        headers={"Host": "api.anthropic.com"},
    )

    addon.request(flow)

    entries = [
        json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()
    ]
    assert any(e.get("decision") == "allowed" for e in entries)
    assert not any(e.get("decision") == "blocked" for e in entries)


def test_maybe_inject_keyed_on_authoritative_host_not_header(
    tmp_path, monkeypatch,
):
    """Defense-in-depth: even if a caller bypasses ``request()`` and
    calls ``_maybe_inject`` directly with a spoofed Host header,
    injection is keyed on the authoritative host (SNI / original-dst).
    The spoofed Host claiming ``api.anthropic.com`` over an
    SNI=``example.com`` connection MUST NOT cause the Anthropic key to
    be substituted."""
    addon_mod, addon = _build_addon(
        monkeypatch, tmp_path,
        secret_value="sk-real-ANTHROPIC-key",
        inject_to=("api.anthropic.com",),
        allowlist=("api.anthropic.com", "example.com"),
    )

    flow = _make_request_flow(
        pretty_host="api.anthropic.com",
        sni="example.com",
        headers={"Authorization": "Bearer {{AGENTCAGE_REDACT_SECRET}}"},
    )

    injected, _ = addon._maybe_inject(flow)

    assert injected == []
    assert (
        flow.request.headers["Authorization"]
        == "Bearer {{AGENTCAGE_REDACT_SECRET}}"
    )


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


def test_addon_running_hook_spawns_relay(monkeypatch, tmp_path):
    """End-to-end addon test: a protocol_relays entry in the JSON file
    causes the addon's ``running()`` hook to dispatch through the
    relays registry, instantiate the relay class, and schedule
    ``start()`` on the asyncio loop. The relay's credential env vars
    are seeded from the secrets dir before instantiation so the
    relay's ``_resolve_credential`` succeeds.

    Uses a fake relay registered in-process so we don't need a real
    SMTP listener or network. The wiring is the load-bearing part —
    the SMTP state machine is already covered in
    tests/test_protocol_relays_smtp.py.
    """
    import asyncio
    import importlib
    import os
    import sys

    addon_dir = (
        Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    proxy_dir = addon_dir.parent / "proxy"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(proxy_dir))

    # Pre-stage the relay credential in the secrets dir the addon
    # reads from. The supervisor stage 35 normally does this from the
    # host bind mount; for unit testing we just write the file.
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "AGENTCAGE_RELAY_USER").write_text("relay-user")
    (secrets_dir / "AGENTCAGE_RELAY_PASS").write_text("relay-pass")

    relays_cfg = [{
        "name": "test-relay",
        # We use type "smtp" so structural validation passes, then
        # swap the registry below to return a fake class. Using a made-up
        # type here would be rejected by validate_relay_entry before
        # the registry is even consulted.
        "type": "smtp",
        "listen": "127.0.0.1:25000",
        "upstream": {"host": "smtp.example.net", "port": 587, "tls": True},
        "auth": {
            "type": "smtp-plain",
            "user_source": "env:AGENTCAGE_RELAY_USER",
            "password_source": "env:AGENTCAGE_RELAY_PASS",
        },
        "policy": {
            "recipient_allowlist": {"domains": ["example.com"]},
        },
    }]
    relays_path = tmp_path / "protocol_relays.json"
    relays_path.write_text(json.dumps(relays_cfg))
    (tmp_path / "allowlist.txt").write_text("smtp.example.net\n")
    (tmp_path / "secret_injection.json").write_text("[]")

    # Register a fake relay class on the shared registry so the addon's
    # ``_get_relay`` lookup resolves without us needing a real SMTP
    # listener. The fake records the kwargs it was called with and
    # exposes start/stop coroutines.
    import relays as _r  # noqa: WPS433  (test-only)
    importlib.reload(_r)

    constructed: list[dict] = []

    class _FakeRelay:
        def __init__(self, entry, *, audit_log, log_allowed, inspectors):
            constructed.append({
                "entry": entry,
                "audit_log": audit_log,
                "log_allowed": log_allowed,
                "inspectors": inspectors,
            })
            self.started = False
            self.stopped = False

        async def start(self):
            self.started = True

        async def stop(self):
            self.stopped = True

    # Swap the smtp slot in the registry for our fake. The addon's
    # ``_get_relay("smtp")`` looks up ``_REGISTRY["smtp"]`` first, so an
    # explicit register() of the same name short-circuits ``_lazy_load``.
    _r.register("smtp", _FakeRelay)

    # Point the addon's module-level paths at our tmp files BEFORE import.
    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRETS_DIR = str(secrets_dir)
    allowlist_addon.SECRET_INJECTION_PATH = str(
        tmp_path / "secret_injection.json"
    )
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")
    allowlist_addon.PROTOCOL_RELAYS_PATH = str(relays_path)
    allowlist_addon.AUDIT_LOG_PATH = str(tmp_path / "audit.jsonl")
    allowlist_addon.CAPTURE_PATH = str(tmp_path / "capture.jsonl")

    addon = allowlist_addon.AllowlistAddon()
    # Relay entries are loaded at __init__ but listeners are deferred
    # to ``running()`` (need the mitmproxy asyncio loop).
    assert len(addon._relay_entries) == 1
    assert addon._relays == []

    # Drive the running() hook on a real loop and let the start task run.
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        addon.running()
        # One tick to let the scheduled task progress.
        loop.run_until_complete(asyncio.sleep(0))
    finally:
        loop.run_until_complete(addon.done())
        loop.close()
        asyncio.set_event_loop(None)

    assert len(constructed) == 1
    record = constructed[0]
    # The relay constructor was called with the entry from the JSON
    # plus our addon's audit sink — so SMTP audit records land in the
    # same audit.jsonl as HTTP allow/block decisions.
    assert record["entry"]["name"] == "test-relay"
    assert callable(record["audit_log"])
    # ``inspectors=None`` is the v1 wiring; tracked in #120.
    assert record["inspectors"] is None
    # Credentials must have been seeded into os.environ before
    # construction — that's the apple-container-specific glue that
    # lets the relay's own ``_resolve_credential("env:VAR")`` work
    # against the bind-mounted secrets file.
    assert os.environ.get("AGENTCAGE_RELAY_USER") == "relay-user"
    assert os.environ.get("AGENTCAGE_RELAY_PASS") == "relay-pass"
    # The relay was started and then stopped (done() drains).
    assert len(addon._relays) == 1
    relay_obj = addon._relays[0]
    assert relay_obj.started is True
    assert relay_obj.stopped is True


def test_addon_running_hook_no_relays_is_noop(monkeypatch, tmp_path):
    """A cage with no ``protocol_relays:`` must not touch the relays
    package at all — keeps existing apple-container cages from paying
    the cost of an unnecessary import and avoids spurious failures on
    import errors when no relay was ever configured."""
    addon_mod = _load_addon_module()
    monkeypatch.setattr(
        addon_mod, "PROTOCOL_RELAYS_PATH", str(tmp_path / "no-such-file.json"),
    )
    monkeypatch.setattr(
        addon_mod, "ALLOWLIST_PATH", str(tmp_path / "allowlist.txt"),
    )
    monkeypatch.setattr(
        addon_mod, "SECRET_INJECTION_PATH",
        str(tmp_path / "secret_injection.json"),
    )
    (tmp_path / "allowlist.txt").write_text("a.com\n")
    (tmp_path / "secret_injection.json").write_text("[]")
    addon = addon_mod.AllowlistAddon()
    assert addon._relay_entries == []
    addon.running()  # should be a no-op
    assert addon._relays == []


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
# allowlist_addon: HAR body capture
#
# When ``capture.enable_har: true`` is set in cage.yaml, the addon stages
# inbound + outbound request/response snapshots (request body + response
# body, subject to ``max_body_size`` + binary-skip) and writes them as
# nested ``{inbound, outbound}`` entries to capture.jsonl. ``cage har``
# then renders these as HAR 1.2 with non-zero ``content.size`` and
# ``request.postData.text``. Pre-this-PR the addon wrote a headers-only
# capture record and HAR exports showed ``content.size=0`` everywhere.
# ---------------------------------------------------------------------------


def _build_addon_with_capture(monkeypatch, tmp_path, *, capture_cfg=None,
                              allowlist=("httpbin.org",)):
    """Like _build_addon but lets the test pass an explicit capture config.

    Stages the shared CaptureWriter (data/proxy/capture.py) on sys.path so
    the addon's lazy ``from capture import CaptureWriter`` import resolves.
    Returns ``(module, addon)``.
    """
    capture_src = (
        Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "proxy"
    )
    monkeypatch.syspath_prepend(str(capture_src))

    addon_mod = _load_addon_module()
    # No secret_injection rules — keep the test focused on the capture
    # path (the secret-injection path has its own tests above).
    allow_path = tmp_path / "allowlist.txt"
    allow_path.write_text("\n".join(allowlist) + "\n")
    si_path = tmp_path / "secret_injection.json"
    si_path.write_text("[]")
    cap_path = tmp_path / "capture_config.json"
    cap_path.write_text(json.dumps(capture_cfg or {}))
    monkeypatch.setattr(addon_mod, "ALLOWLIST_PATH", str(allow_path))
    monkeypatch.setattr(addon_mod, "SECRET_INJECTION_PATH", str(si_path))
    monkeypatch.setattr(addon_mod, "CAPTURE_CONFIG_PATH", str(cap_path))
    monkeypatch.setattr(addon_mod, "AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(addon_mod, "CAPTURE_PATH", str(tmp_path / "capture.jsonl"))
    return addon_mod, addon_mod.AllowlistAddon()


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


def test_addon_disabled_falls_back_to_headers_only(tmp_path, monkeypatch):
    """``enable_har: false`` (or absent) → no CaptureWriter, no _cap_pending
    use, and the legacy headers-only capture entry is what hits disk.
    This is the pre-PR shape so existing cages keep working without an
    opt-in.
    """
    _, addon = _build_addon_with_capture(
        monkeypatch, tmp_path, capture_cfg={"enable_har": False},
    )
    assert addon._capture_writer is None
    assert addon._capture_fh is not None

    flow = _make_flow_with_bodies(
        host="httpbin.org",
        req_body="name=test&value=hello",
        resp_body='{"form": {"name": "test", "value": "hello"}}',
    )
    addon.request(flow)
    addon.response(flow)

    cap_lines = (tmp_path / "capture.jsonl").read_text().splitlines()
    assert len(cap_lines) == 1
    entry = json.loads(cap_lines[0])
    # Legacy flat shape — no `inbound`/`outbound` nesting, no body bytes.
    assert "inbound" not in entry
    assert "outbound" not in entry
    assert "body" not in entry.get("request", {})


def test_addon_text_body_captured_for_har_export(tmp_path, monkeypatch):
    """End-to-end: when capture is enabled, the addon emits a nested
    ``{inbound, outbound}`` entry whose request + response carry the full
    body bytes. ``capture_to_har`` then produces a HAR with non-zero
    ``content.size`` and ``request.postData.text`` — the exact gap this
    PR closes."""
    _, addon = _build_addon_with_capture(
        monkeypatch, tmp_path,
        capture_cfg={
            "enable_har": True,
            "max_body_size": 10485760,
            "domains": ["httpbin.org"],
        },
    )
    assert addon._capture_writer is not None

    req_body = "name=test&value=hello"
    resp_body = '{"form": {"name": "test", "value": "hello"}}'
    flow = _make_flow_with_bodies(
        host="httpbin.org", req_body=req_body, resp_body=resp_body,
    )
    addon.request(flow)
    addon.response(flow)

    cap_lines = (tmp_path / "capture.jsonl").read_text().splitlines()
    assert len(cap_lines) == 1
    entry = json.loads(cap_lines[0])

    # Shape: nested perspectives, both with body bytes verbatim.
    assert "inbound" in entry and "outbound" in entry
    in_req = entry["inbound"]["request"]
    in_resp = entry["inbound"]["response"]
    assert in_req["body"] == req_body
    assert in_req["bodySize"] == len(req_body.encode())
    assert in_resp["body"] == resp_body
    assert in_resp["bodySize"] == len(resp_body.encode())
    assert in_resp["mimeType"] == "application/json"

    # capture_to_har produces a HAR with non-zero content.size
    from agentcage.har import capture_to_har
    har = capture_to_har([entry], view="inbound")
    har_entry = har["log"]["entries"][0]
    assert har_entry["request"]["postData"]["text"] == req_body
    assert har_entry["response"]["content"]["text"] == resp_body
    assert har_entry["response"]["content"]["size"] == len(resp_body.encode())


def test_addon_binary_response_records_size_but_no_text(tmp_path, monkeypatch):
    """Binary bodies (images, archives) skip the body text but still
    record ``bodySize`` so the HAR export shows the right transfer size.
    The CaptureWriter base64-encodes binary; either way, the cage
    operator sees the size and can tell what slipped through.
    """
    _, addon = _build_addon_with_capture(
        monkeypatch, tmp_path,
        capture_cfg={
            "enable_har": True,
            "max_body_size": 10485760,
            "domains": ["httpbin.org"],
        },
    )

    # JPEG-ish magic bytes + payload that can't be decoded as UTF-8.
    binary = bytes([0xff, 0xd8, 0xff, 0xe0]) + b"\x00" * 100 + bytes([0xff])
    flow = _make_flow_with_bodies(
        host="httpbin.org",
        req_body=b"\x89PNG\r\n",
        resp_body=binary,
        req_content_type="image/png",
        resp_content_type="image/jpeg",
    )
    addon.request(flow)
    addon.response(flow)

    cap_lines = (tmp_path / "capture.jsonl").read_text().splitlines()
    assert len(cap_lines) == 1
    entry = json.loads(cap_lines[0])

    in_resp = entry["inbound"]["response"]
    # Size recorded faithfully — operator can see the JPEG was 105 bytes.
    assert in_resp["bodySize"] == len(binary)
    # Body field is the base64-encoded payload (NOT decoded text); the
    # encoding marker tells HAR consumers how to render it.
    assert in_resp["bodyEncoding"] == "base64"
    # No raw bytes leaked as text — would have failed UTF-8 anyway.
    import base64 as _b64
    assert _b64.b64decode(in_resp["body"]) == binary


def test_addon_capture_respects_domain_filter(tmp_path, monkeypatch):
    """``capture.domains`` is an allow-list — a request to a host not in
    the list is skipped at capture time even if the cage's outer
    ``domains.allow`` permitted it. Lets operators audit a specific
    upstream without flooding capture.jsonl with everything else."""
    _, addon = _build_addon_with_capture(
        monkeypatch, tmp_path,
        capture_cfg={
            "enable_har": True,
            "max_body_size": 10485760,
            "domains": ["httpbin.org"],
        },
        allowlist=("httpbin.org", "example.com"),
    )

    # Request to example.com — not in capture.domains.
    flow = _make_flow_with_bodies(
        host="example.com",
        req_body="x=1",
        resp_body="ok",
        path="/probe",
    )
    addon.request(flow)
    addon.response(flow)

    cap_path = tmp_path / "capture.jsonl"
    # Either the file doesn't exist yet or it's empty — the writer's
    # should_capture() short-circuits before write_entry().
    if cap_path.exists():
        assert cap_path.read_text().strip() == ""


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


def test_inspector_chain_runs_at_request_time(monkeypatch, tmp_path):
    """End-to-end: an inspector that returns a ``block`` result causes
    the addon to emit a 403 from the proxy itself (no upstream traffic).
    The audit entry includes the ``inspectors:`` list so ``cage audit
    --inspector <name>`` filtering works.

    Uses a fake inspector registered in-process so we don't depend on
    any specific built-in's heuristics — keeps the test deterministic."""
    rules_path = tmp_path / "secret_injection.json"
    rules_path.write_text("[]")
    inspectors_path = tmp_path / "inspectors.json"
    inspectors_path.write_text(json.dumps([
        {"name": "_test_blocker", "config": {"why": "test policy"}},
    ]))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    import importlib
    import sys
    addon_dir = (
        Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    inspectors_src_parent = addon_dir.parent / "proxy"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(inspectors_src_parent))

    # Pre-register a fake inspector by patching the registry the addon
    # uses. We patch the lazy builder so the registry returns our fake
    # under the configured name.
    from inspectors.base import Inspector, InspectionResult

    class _TestBlocker(Inspector):
        name = "_test_blocker"

        def configure(self, config):
            self._why = config.get("why", "blocked by test")

        def inspect_request(self, ctx_obj):
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=self._why,
                severity="error",
            )

    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rules_path)
    allowlist_addon.INSPECTORS_PATH = str(inspectors_path)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")
    monkeypatch.setattr(
        allowlist_addon, "_builtin_inspectors_map",
        lambda: {"_test_blocker": _TestBlocker},
    )

    addon = allowlist_addon.AllowlistAddon()
    assert len(addon.inspectors) == 1
    assert addon.inspectors[0].name == "_test_blocker"

    # Wire http.Response.make so the addon can synthesize a 403 — the
    # mitmproxy.http stub in conftest is a MagicMock, so .make() returns
    # a MagicMock by default which is fine for the audit assertions.
    captured_resp = {}

    def _fake_make(status, content, headers):
        captured_resp["status"] = status
        captured_resp["content"] = content
        captured_resp["headers"] = headers
        return MagicMock(status_code=status, content=content, headers=headers)

    allowlist_addon.http.Response.make.side_effect = _fake_make

    flow = _make_request_flow_for_inspector(
        host="api.example.com",
        method="POST",
        headers={"Content-Type": "application/json"},
        body='{"hello": "world"}',
    )
    addon.request(flow)

    # 403 synthesized, NOT a passthrough.
    assert captured_resp["status"] == 403
    body = json.loads(captured_resp["content"].decode())
    assert body["blocked"] is True
    assert body["by"] == "agentcage"
    assert body["reason"] == "test policy"

    # Audit entry has inspectors[].name == "_test_blocker" so the CLI's
    # --inspector filter matches it.
    audit_lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    blocked_lines = [
        json.loads(line) for line in audit_lines
        if json.loads(line).get("decision") == "blocked"
    ]
    assert blocked_lines, "expected a blocked audit entry"
    entry = blocked_lines[0]
    assert entry["inspectors"] == [
        {
            "name": "_test_blocker",
            "action": "block",
            "reason": "test policy",
            "severity": "error",
        }
    ]
    assert entry["reason"] == "test policy"
    assert entry["host"] == "api.example.com"


def test_inspector_chain_flag_does_not_block(monkeypatch, tmp_path):
    """A ``flag`` result records the inspector hit in the audit entry
    but does NOT 403 the request — same semantics as the container
    backend. Decision becomes ``flagged`` instead of ``allowed``."""
    rules_path = tmp_path / "secret_injection.json"
    rules_path.write_text("[]")
    inspectors_path = tmp_path / "inspectors.json"
    inspectors_path.write_text(json.dumps([
        {"name": "_test_flagger", "config": {}}
    ]))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    import importlib
    import sys
    addon_dir = (
        Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    inspectors_src_parent = addon_dir.parent / "proxy"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(inspectors_src_parent))

    from inspectors.base import Inspector, InspectionResult

    class _TestFlagger(Inspector):
        name = "_test_flagger"

        def inspect_request(self, ctx_obj):
            return InspectionResult(
                inspector=self.name,
                action="flag",
                reason="suspicious but allowed",
                severity="warning",
            )

    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rules_path)
    allowlist_addon.INSPECTORS_PATH = str(inspectors_path)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")
    monkeypatch.setattr(
        allowlist_addon, "_builtin_inspectors_map",
        lambda: {"_test_flagger": _TestFlagger},
    )

    addon = allowlist_addon.AllowlistAddon()

    flow = _make_request_flow_for_inspector(
        host="api.example.com",
        method="GET",
        headers={"Content-Type": "application/json"},
        body="",
    )
    addon.request(flow)

    # No 403 — flow.response stays None.
    assert flow.response is None
    audit_lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    entry = json.loads(audit_lines[-1])
    assert entry["decision"] == "flagged"
    assert entry["inspectors"] == [
        {
            "name": "_test_flagger",
            "action": "flag",
            "reason": "suspicious but allowed",
            "severity": "warning",
        }
    ]


def test_inspector_chain_empty_config_is_passthrough(monkeypatch, tmp_path):
    """An empty inspectors.json (the common case for legacy cages) must
    leave the request hook behaving exactly as it did pre-PR — no
    chain runs, audit entry has empty ``inspectors:`` array."""
    rules_path = tmp_path / "secret_injection.json"
    rules_path.write_text("[]")
    inspectors_path = tmp_path / "inspectors.json"
    inspectors_path.write_text("[]")
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    import importlib
    import sys
    addon_dir = (
        Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    inspectors_src_parent = addon_dir.parent / "proxy"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(inspectors_src_parent))

    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rules_path)
    allowlist_addon.INSPECTORS_PATH = str(inspectors_path)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")

    addon = allowlist_addon.AllowlistAddon()
    assert addon.inspectors == []

    flow = _make_request_flow_for_inspector(
        host="api.example.com",
        method="GET",
        headers={},
        body="",
    )
    addon.request(flow)
    assert flow.response is None
    entry = json.loads(
        (tmp_path / "audit.jsonl").read_text().splitlines()[-1]
    )
    assert entry["decision"] == "allowed"
    assert entry["inspectors"] == []


# ---------------------------------------------------------------------------
# allowlist_addon: Non-HTTP TCP bypass guard
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


def test_tcp_start_blocks_raw_tcp_to_ip(tmp_path, monkeypatch):
    """The exact CTF case: cage opens a raw TCP socket to ``1.1.1.1:443``
    and writes non-HTTP bytes. mitmproxy's ``next_layer`` falls back to
    ``TCPLayer`` (rawtcp=True by default); without ``tcp_start`` the
    bytes bridge straight to upstream. The addon must kill the flow
    before any byte leaves the cage."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_tcp_flow(
        sni=None,
        server_address=("1.1.1.1", 443),
    )

    addon.tcp_start(flow)

    # Belt 1: server_conn.error → mitmproxy's open_connection aborts
    # before the upstream socket is opened.
    assert flow.server_conn.error
    assert "non-http TCP bypass" in flow.server_conn.error

    # Belt 2: flow.kill() called for canonical killed state.
    flow.kill.assert_called_once_with()

    # Audit line landed in audit.jsonl with the right shape.
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["kind"] == "tcp_bypass_blocked"
    assert entry["decision"] == "blocked"
    assert entry["direction"] == "outbound"
    assert entry["source"] == "apple-container"
    assert "1.1.1.1:443" in entry["host"]
    assert "non-http TCP bypass" in entry["reason"]


def test_tcp_start_blocks_non_http_tls_with_sni(tmp_path, monkeypatch):
    """TLS variant: cage opens TLS with a real SNI (e.g. SMTPS at
    smtp.example.com) but the inner bytes are not HTTP. mitmproxy
    decrypts then falls back to ``TCPLayer``; the addon must still
    kill the flow because the L7 hooks would never run on those bytes.
    The audit entry records SNI (more useful than the original-dst IP)
    so operators know which destination the cage tried to reach."""
    _, addon = _build_addon(
        monkeypatch, tmp_path,
        # SNI happens to be allowlisted at the HTTP layer — irrelevant
        # to the TCP guard, which is HTTP-only-policy by design.
        allowlist=("smtp.example.com",),
        inject_to=("smtp.example.com",),
    )
    flow = _make_tcp_flow(
        sni="smtp.example.com",
        server_address=("203.0.113.5", 465),  # SMTPS
    )

    addon.tcp_start(flow)

    assert flow.server_conn.error
    flow.kill.assert_called_once_with()
    entry = json.loads(
        (tmp_path / "audit.jsonl").read_text().splitlines()[0]
    )
    # SNI wins over original-dst IP for the audit host field.
    assert entry["host"] == "smtp.example.com"


def test_tcp_start_handles_unknown_destination(tmp_path, monkeypatch):
    """Defensive: a flow with neither SNI nor a server address must
    still be killed and audited — the addon must never raise out of a
    mitmproxy hook (would tear down the proxy and fail the cage open)."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_tcp_flow(
        sni=None,
        server_address=None,
        server_peername=None,
    )

    addon.tcp_start(flow)  # must not raise

    assert flow.server_conn.error
    flow.kill.assert_called_once_with()
    entry = json.loads(
        (tmp_path / "audit.jsonl").read_text().splitlines()[0]
    )
    assert entry["host"] == "<unknown>"


def test_tcp_start_already_killed_flow_does_not_double_kill(
    tmp_path, monkeypatch,
):
    """If a higher-priority addon already killed the flow,
    ``flow.kill()`` would raise ``ControlException``. The addon must
    gate on ``flow.killable`` (and tolerate kill() raising regardless)
    so a kill race doesn't tear down the proxy."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_tcp_flow(server_address=("1.2.3.4", 443))
    flow.killable = False  # already killed by something else

    addon.tcp_start(flow)  # must not raise

    flow.kill.assert_not_called()
    # The audit line still lands so the operator sees the attempt.
    assert (tmp_path / "audit.jsonl").read_text().strip()


def test_tcp_start_accepts_bytes_sni(tmp_path, monkeypatch):
    """mitmproxy types ``sni`` as ``str | None``, but historically some
    paths handed back ``bytes``. The TCP-guard helper must normalize the
    same way ``_authoritative_host`` does so a bytes SNI doesn't fall
    through to the original-dst IP."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_tcp_flow(
        sni=b"smtp.example.com",
        server_address=("203.0.113.5", 465),
    )

    addon.tcp_start(flow)

    entry = json.loads(
        (tmp_path / "audit.jsonl").read_text().splitlines()[0]
    )
    assert entry["host"] == "smtp.example.com"


def test_egress_supervisor_keeps_lazy_connection_strategy():
    """The mitmdump launch line must still carry --set connection_strategy=lazy.
    PR 3 moved this to the egress sibling's supervisor (PR 1's
    supervisor-egress.sh) — same string, different file."""
    egress_supervisor = (
        Path(__file__).parent.parent
        / "src" / "agentcage" / "data" / "containers" / "supervisor-egress.sh"
    ).read_text()
    assert "connection_strategy=lazy" in egress_supervisor
