"""Tests for the apple-container egress port-policy wiring.

The apple-container backend runs an ``{name}-egress`` microVM whose
``supervisor-egress.sh`` builds its iptables filter from three env vars
(``INSPECTED_TCP_PORTS`` / ``PASSTHROUGH_TCP_PORTS`` / ``ALLOW_UDP_PORTS``).
Pre-fix, ``start()`` hardcoded only ``ALLOW_UDP_PORTS=53`` and silently
dropped a cage.yaml's ``ports.*`` policy.

These tests cover the argv/env construction only (no live Apple runtime,
which doesn't exist on Linux CI):
  - ``generate_units()`` persists the three int lists into metadata.json
    via the shared ``_effective_port_policy``.
  - ``start()`` reads them back and emits the three ``-e`` flags on the
    egress ``container run`` argv, with 53 always unioned into the UDP set.
"""

from __future__ import annotations

import json
import textwrap
from unittest.mock import patch

from agentcage.backends.apple_container import AppleContainerBackend
from agentcage.config import load_config


def _config(tmp_path, body: str):
    p = tmp_path / "cage.yaml"
    p.write_text(textwrap.dedent(body))
    return load_config(str(p))


# ── generate_units(): Config → metadata port lists ──────────


class TestGenerateUnitsPortPolicy:
    def test_default_policy_persisted(self, tmp_path):
        """A cage with no ``ports:`` override persists the default policy:
        inspected=[80,443], no passthrough, no UDP."""
        cfg = _config(tmp_path, """\
            name: demo
            container:
              image: test:latest
        """)
        units = AppleContainerBackend().generate_units(
            cfg, "/c.yaml", "/patches", "demo",
        )
        meta = json.loads(units["demo.json"])
        assert meta["inspected_tcp_ports"] == [80, 443]
        assert meta["passthrough_tcp_ports"] == []
        assert meta["allow_udp_ports"] == []

    def test_custom_policy_persisted(self, tmp_path):
        """Operator ports.tcp.allow/passthrough/udp.allow flow into
        metadata. Inspected = allow MINUS passthrough (shared
        _effective_port_policy semantics)."""
        cfg = _config(tmp_path, """\
            name: demo
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 8000, 22]
                passthrough: [22]
              udp:
                allow: [123, 5353]
        """)
        units = AppleContainerBackend().generate_units(
            cfg, "/c.yaml", "/patches", "demo",
        )
        meta = json.loads(units["demo.json"])
        assert meta["inspected_tcp_ports"] == [80, 443, 8000]
        assert meta["passthrough_tcp_ports"] == [22]
        assert meta["allow_udp_ports"] == [123, 5353]


# ── start(): metadata → egress run argv env ─────────────────


def _start_with_meta(tmp_path, meta_extra: dict) -> list[str]:
    """Drive AppleContainerBackend.start() far enough to capture the
    egress ``container run`` argv, with all the live-runtime side effects
    stubbed out. Returns the egress argv (the first ``run -d`` invocation).
    """
    backend = AppleContainerBackend()

    base_meta = {
        "name": "demo",
        "user_image": "test:latest",
        "cpus": "",
        "memory": "",
        "lifecycle": "service",
        "secret_envs": [],
        "secret_env_placeholders": {},
        "relay_secret_envs": [],
        "autostart": False,
        "volumes": [],
        "env": {},
    }
    base_meta.update(meta_extra)

    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps(base_meta))

    state_dir = tmp_path / "state"
    egress_cfg = state_dir / "egress-config"
    egress_cfg.mkdir(parents=True)
    # The three files start() binds in must exist for the egress_cfg_dir
    # guard to pass.
    for fn in ("proxy-config.yaml", "dnsmasq.conf", "dns-allowlist.conf"):
        (egress_cfg / fn).touch()

    captured: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        captured.append(list(argv))

        class _R:
            returncode = 0
        return _R()

    with patch.object(AppleContainerBackend, "unit_dir", return_value=unit_dir), \
         patch.object(AppleContainerBackend, "egress_config_dir", return_value=egress_cfg), \
         patch.object(AppleContainerBackend, "logs_dir", return_value=state_dir / "logs"), \
         patch.object(AppleContainerBackend, "certs_dir", return_value=state_dir / "certs"), \
         patch.object(AppleContainerBackend, "public_certs_dir", return_value=state_dir / "pub"), \
         patch.object(AppleContainerBackend, "secrets_dir", return_value=state_dir / "secrets"), \
         patch.object(AppleContainerBackend, "_stage_secrets", return_value=set()), \
         patch.object(AppleContainerBackend, "_wait_supervisor_ready"), \
         patch.object(AppleContainerBackend, "_container_ip", return_value="10.0.0.2"), \
         patch("agentcage.backends.apple_container.ac_cli.run", side_effect=fake_run), \
         patch("agentcage.backends.apple_container.ac_cli.inspect", return_value=None), \
         patch("agentcage.backends.apple_container.ac_cli.image_inspect", return_value={"ok": 1}), \
         patch("agentcage.backends.apple_container.ac_wrapper.wrapped_image_name",
               return_value="wrapped:demo"), \
         patch("agentcage.backends.apple_container._egress_image_name",
               return_value="egress:latest"):
        backend.start("demo", quiet=True)

    # The egress run is the first `run -d --name demo-egress ...` call.
    for argv in captured:
        if argv[:4] == ["run", "-d", "--name", "demo-egress"]:
            return argv
    raise AssertionError(f"egress run argv not found in {captured!r}")


def _env_value(argv: list[str], key: str) -> str | None:
    """Return the value of a ``-e KEY=VAL`` pair in argv (or None)."""
    for i, tok in enumerate(argv):
        if tok == "-e" and i + 1 < len(argv) and argv[i + 1].startswith(f"{key}="):
            return argv[i + 1].split("=", 1)[1]
    return None


class TestStartEgressArgvPortEnv:
    def test_default_policy_env(self, tmp_path):
        argv = _start_with_meta(tmp_path, {
            "inspected_tcp_ports": [80, 443],
            "passthrough_tcp_ports": [],
            "allow_udp_ports": [],
        })
        # INSPECTED set explicitly even at the default — the supervisor
        # only falls back to "80 443" when the var is UNSET.
        assert _env_value(argv, "INSPECTED_TCP_PORTS") == "80 443"
        assert _env_value(argv, "PASSTHROUGH_TCP_PORTS") == ""
        # 53 is unioned in even when config.udp.allow is empty.
        assert _env_value(argv, "ALLOW_UDP_PORTS") == "53"

    def test_custom_policy_env_honored(self, tmp_path):
        argv = _start_with_meta(tmp_path, {
            "inspected_tcp_ports": [80, 443, 8000],
            "passthrough_tcp_ports": [22],
            "allow_udp_ports": [123, 5353],
        })
        assert _env_value(argv, "INSPECTED_TCP_PORTS") == "80 443 8000"
        assert _env_value(argv, "PASSTHROUGH_TCP_PORTS") == "22"
        # config UDP ports preserved AND 53 appended.
        udp = _env_value(argv, "ALLOW_UDP_PORTS").split()
        assert udp == ["123", "5353", "53"]

    def test_dns_53_always_present(self, tmp_path):
        """CTF F2: 53 must survive even when the operator narrows the
        inspected set and lists no UDP ports — dropping it breaks all
        in-cage DNS (dnsmasq upstream forwarding)."""
        argv = _start_with_meta(tmp_path, {
            "inspected_tcp_ports": [443],
            "passthrough_tcp_ports": [],
            "allow_udp_ports": [],
        })
        assert "53" in _env_value(argv, "ALLOW_UDP_PORTS").split()

    def test_53_not_duplicated_when_already_present(self, tmp_path):
        """If the operator explicitly lists 53 in udp.allow, it appears
        exactly once (no duplicate from the union)."""
        argv = _start_with_meta(tmp_path, {
            "inspected_tcp_ports": [80, 443],
            "passthrough_tcp_ports": [],
            "allow_udp_ports": [53, 123],
        })
        udp = _env_value(argv, "ALLOW_UDP_PORTS").split()
        assert udp.count("53") == 1
        assert udp == ["53", "123"]

    def test_legacy_metadata_without_port_lists(self, tmp_path):
        """A cage last created before this fix has no *_ports keys in
        metadata.json. start() must not crash: inspected/passthrough fall
        back to empty, and 53 is still emitted so DNS keeps working."""
        argv = _start_with_meta(tmp_path, {})
        assert _env_value(argv, "INSPECTED_TCP_PORTS") == ""
        assert _env_value(argv, "PASSTHROUGH_TCP_PORTS") == ""
        assert _env_value(argv, "ALLOW_UDP_PORTS") == "53"
