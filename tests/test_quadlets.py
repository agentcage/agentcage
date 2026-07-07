"""Tests for quadlet generation."""

import os
import textwrap

import pytest

from agentcage.config import load_config
from agentcage.quadlets import generate_quadlets, _systemd_exec_join, cage_network_addrs, collect_used_octets, _passthrough_regex, _effective_dns_allowlist


class TestQuadletFileNames:
    def test_generates_five_files(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/path/to/config.yaml", "/path/to/patches")
        # v0.22 shape: net.network + certs.volume (private, egress-only) +
        # public-certs.volume (cage-visible) + cage + egress. The split
        # between certs.volume and public-certs.volume closes CTF F6/F9 —
        # the cage MUST NOT see mitmproxy's private key.
        assert len(files) == 5

    def test_file_names(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/path/to/config.yaml", "/path/to/patches")
        assert set(files.keys()) == {
            "test-net.network",
            "test-certs.volume",
            "test-public-certs.volume",
            "test-egress.container",
            "test-cage.container",
        }


class TestNetworkQuadlet:
    def test_network_content(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-net.network"]
        assert "NetworkName=test-net" in content
        assert "Internal=true" in content
        assert f"Subnet={addrs['subnet']}" in content


class TestVolumeQuadlet:
    def test_volume_content(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-certs.volume"]
        assert "VolumeName=agentcage-certs-test" in content

    def test_public_certs_volume_content(self, minimal_yaml):
        """Public-cert-only volume that the cage mounts at /certs:ro.
        Lives separately from agentcage-certs-<name> so the cage cannot
        see mitmproxy's private key + .p12 bundles (CTF F6 + F9)."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-public-certs.volume"]
        assert "VolumeName=agentcage-public-certs-test" in content


class TestEgressQuadlet:
    """The v0.22 2-service shape collapses the legacy proxy + dns
    quadlets into a single ``<name>-egress.container``. Most of the
    runtime behavior (iptables FORWARD chain, dnsmasq --servers-file
    wiring, mitmproxy listener) now lives inside the egress image's
    supervisor and is covered by ``test_egress_image.py``. These tests
    pin the quadlet-level surface area: image tag, capabilities, bind
    mounts, secrets, published ports.
    """

    def test_egress_basics(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "ContainerName=test-egress" in content
        # Image tag includes the version pin so a `cage update` after a
        # release picks up the new egress image.
        assert "Image=localhost/agentcage-egress:" in content
        assert f"Network=test-net.network:ip={addrs['ip_egress']}" in content

    def test_egress_capabilities(self, minimal_yaml):
        """The egress container is the only one allowed to mutate
        iptables / bind low ports. NET_ADMIN drives FORWARD chain setup
        (router shape between cage netns and host bridge);
        NET_BIND_SERVICE covers dnsmasq's :53 listener; SETUID/SETGID/
        SETPCAP/KILL cover the supervisor's setpriv drop chain and
        cross-uid kill -0 monitoring (needed under hardened
        `default_capabilities = []` podman configs)."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "AddCapability=NET_ADMIN" in content
        assert "AddCapability=NET_BIND_SERVICE" in content
        assert "AddCapability=SETUID" in content
        assert "AddCapability=SETGID" in content
        assert "AddCapability=SETPCAP" in content
        assert "AddCapability=KILL" in content

    def test_egress_chowns_private_certs_but_not_public_certs(self, minimal_yaml):
        """The private certs volume (/home/acproxy/.mitmproxy) is written by
        mitmproxy AS acproxy, so the egress chowns its mountpoint to 200:200.
        The public-certs volume is the opposite: written ONLY by the uid-0
        supervisor (Step E ``install``s the public CA cert into it) and mounted
        ``:ro`` by the cage, so its mountpoint must stay root-owned.

        REGRESSION GUARD: #211 added an ExecStartPre that chowned the
        public-certs mountpoint to 200:200. On hardened hosts
        (``default_capabilities = []``) the supervisor runs as uid 0 without
        CAP_DAC_OVERRIDE/CAP_FOWNER; once it no longer owned the dir, ``install``
        could not unlink+rewrite the existing cert on restart — ``install:
        cannot remove ...: Permission denied`` crashed the egress (and with it
        the cage) on every start after the first.
        """
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        # Private certs volume IS chowned to acproxy.
        assert "podman volume inspect agentcage-certs-test --format" in content
        assert '200:200 "$mp"' in content
        # Public-certs volume mountpoint must NOT be chowned (no inspect+chown
        # ExecStartPre targeting it).
        assert "agentcage-public-certs-test --format" not in content

    def test_egress_port_policy_default(self, minimal_yaml):
        """A cage with no `ports:` override gets the default policy —
        tcp.allow=[80,443], no passthrough, no UDP. The supervisor reads
        these via Environment= entries and REDIRECTs inspected ports to
        :8443 / ACCEPTs passthrough+UDP in FORWARD."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert 'Environment="INSPECTED_TCP_PORTS=80 443"' in content
        assert 'Environment="PASSTHROUGH_TCP_PORTS="' in content
        assert 'Environment="ALLOW_UDP_PORTS="' in content
        # ICMP is off by default — the supervisor installs no echo-request rule.
        assert 'Environment="ALLOW_ICMP=0"' in content

    def test_egress_icmp_allow_opt_in(self, tmp_path):
        """ports.icmp.allow: true emits ALLOW_ICMP=1 so the supervisor
        installs the FORWARD echo-request ACCEPT rule."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              icmp:
                allow: true
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert 'Environment="ALLOW_ICMP=1"' in content

    def test_egress_port_policy_custom(self, tmp_path):
        """Operator-supplied ports.tcp.allow / passthrough / udp.allow
        flow through to the supervisor's env. Inspected = allow MINUS
        passthrough; passthrough lands verbatim; UDP lands verbatim.

        REGRESSION GUARD: the initial v0.22 cutover passed these lists
        to the template renderer but the template never emitted them,
        and the supervisor fell back to hard-coded "80 443" — any
        operator with a custom port policy silently lost the rules.
        """
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 8000, 22]
                passthrough: [22]
              udp:
                allow: [123, 5353]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        # Inspected = allow - passthrough.
        assert 'Environment="INSPECTED_TCP_PORTS=80 443 8000"' in content
        assert 'Environment="PASSTHROUGH_TCP_PORTS=22"' in content
        assert 'Environment="ALLOW_UDP_PORTS=123 5353"' in content

    def test_egress_regular_bind_is_cage_net_ip(self, minimal_yaml):
        """mitmproxy's regular forward proxy binds to the egress's
        cage-net IP only, NOT 0.0.0.0. The egress is on two networks
        (cage-net + default podman), and a 0.0.0.0 bind would expose
        the proxy to every other rootless container on the host's
        default podman network — they could use it as an open HTTP
        proxy with this cage's allowlist + injected secrets.

        REGRESSION GUARD: the initial v0.22 cutover used
        ``--mode regular@:8080`` (no IP). A second container on the
        ``podman`` network could ``curl --proxy <egress-podman-ip>:8080``
        and get 200 OK back through the cage's mitmproxy.
        """
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert (
            f'Environment="AGENTCAGE_REGULAR_BIND={addrs["ip_egress"]}:8080"'
            in content
        )

    def test_egress_port_policy_empty_intentional(self, tmp_path):
        """Empty tcp.allow is a valid configuration (cage doesn't speak
        HTTP). The Environment= entry is emitted as empty, signaling the
        supervisor to install zero PREROUTING REDIRECT rules. The
        supervisor's `${VAR-default}` fallback fires only when the env
        var is genuinely unset (smoke-test path)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: []
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert 'Environment="INSPECTED_TCP_PORTS="' in content

    def test_egress_certs_volume(self, minimal_yaml):
        """mitmproxy writes its CA to ~/.mitmproxy inside the container;
        the cage trust-install path reads it back out of the named
        volume. uid 200 (acproxy) inside the egress image."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "Volume=test-certs.volume:/home/acproxy/.mitmproxy:Z" in content

    def test_egress_public_certs_volume(self, minimal_yaml):
        """Egress mounts the public-certs volume RW so supervisor-egress.sh
        Step E can publish mitmproxy-ca-cert.pem there. The cage mounts the
        SAME volume read-only at /certs. The mountpoint is intentionally NOT
        chowned to acproxy — see
        test_egress_chowns_private_certs_but_not_public_certs for why."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "Volume=test-public-certs.volume:/home/acproxy/public-certs:Z" in content

    def test_egress_config_bind(self, minimal_yaml):
        """The proxy-config bind source is the host path passed to
        generate_quadlets; the mitmproxy addon mtime-polls this file."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "Volume=/c.yaml:/etc/agentcage/config.yaml:ro,Z" in content

    def test_egress_dns_allowlist_bind(self, tmp_path):
        """In allowlist mode the egress quadlet bind-mounts the
        dns-allowlist sidecar file at /etc/agentcage/dns-allowlist.conf
        (the path supervisor-egress.sh hands to dnsmasq via
        --servers-file). Open-DNS / blocklist mode omits the mount."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="test")
        content = files["test-egress.container"]
        # Read-only bind, target is the path the supervisor wires into
        # `--servers-file=...`.
        assert "/etc/agentcage/dns-allowlist.conf:ro,Z" in content

    def test_egress_resolv_conf_bind_not_dns_directive(self, tmp_path):
        """The egress must NOT use the podman `DNS=` directive for its own
        upstream resolution (that race is real: podman injects aardvark as
        the FIRST nameserver ahead of `DNS=` entries). Instead, the egress's
        /etc/resolv.conf is a bind-mounted file (resolv-egress-<name>.conf,
        seeded with config.dns_servers by services.write_resolv_files).

        The bind is now **rw** so supervisor-egress.sh can REWRITE it each
        start to point mitmproxy's resolver at the egress's local dnsmasq
        (which forwards to the default-route gateway + dns_servers in parallel
        via --all-servers). mitmproxy re-resolves the upstream, so its
        resolver must track host network changes AND resolve split-horizon
        names — routing through dnsmasq gives both, where a flat list of
        upstream nameservers cannot (glibc getaddrinfo stops at the first
        NXDOMAIN).
        """
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            dns_servers:
              - 1.1.1.1
              - 8.8.8.8
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="test")
        content = files["test-egress.container"]
        # resolv.conf is bind-mounted rw (supervisor rewrites it to point at
        # the local dnsmasq).
        assert (
            "Volume=/patches/resolv-egress-test.conf:/etc/resolv.conf:rw,Z"
            in content
        )
        # The racy `DNS=` directive must NOT appear — that's the whole
        # point. Match on the line-start form so we never reintroduce it.
        assert "\nDNS=" not in content

    def test_egress_no_dns_allowlist_bind_in_blocklist_mode(self, tmp_path):
        """Blocklist / open-DNS mode does not produce an allowlist file,
        so the bind mount stays off."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              block:
                - evil.com
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="test")
        content = files["test-egress.container"]
        assert "dns-allowlist.conf" not in content

    def test_egress_capture_volume_when_enabled(self, tmp_path):
        """`capture.enable_har: true` bind-mounts the per-cage capture
        directory at /var/log/agentcage/capture so the mitmproxy addon
        can persist flow JSONL across container restarts."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            capture:
              enable_har: true
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="test")
        content = files["test-egress.container"]
        assert ":/var/log/agentcage/capture:Z" in content
        assert (
            'Environment="AGENTCAGE_CAPTURE='
            '/var/log/agentcage/capture/capture.jsonl"'
        ) in content

    def test_egress_no_capture_volume_by_default(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "/var/log/agentcage/capture" not in content
        assert "AGENTCAGE_CAPTURE" not in content

    def test_egress_secrets_unprefixed(self, tmp_path):
        """secret_injection entries without a deploy_name land on the
        egress container's Secret= directives so the proxy can resolve
        the {{PLACEHOLDER}} -> real value substitution at request time."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
              - env: OTHER_KEY
                placeholder: "{{OTHER_KEY}}"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "Secret=API_KEY,type=env" in content
        assert "Secret=OTHER_KEY,type=env" in content

    def test_egress_secrets_prefixed_by_deploy_name(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="myapp")
        content = files["test-egress.container"]
        assert "Secret=myapp.API_KEY,type=env,target=API_KEY" in content
        assert "Secret=API_KEY,type=env\n" not in content

    def test_egress_relay_secrets_reach_egress(self, tmp_path):
        """protocol_relays credentials must reach the egress container's
        env so the relay can resolve them at startup. They are stripped
        from the cage's podman_secrets/env (cage must not see them)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              podman_secrets:
                - MIGADU_USER
                - MIGADU_PASSWORD
            protocol_relays:
              - name: migadu-imap
                type: imap
                listen: "127.0.0.1:1143"
                upstream:
                  host: imap.migadu.com
                  port: 993
                auth:
                  type: imap-login
                  user_source: "podman:MIGADU_USER"
                  password_source: "podman:MIGADU_PASSWORD"
        """))
        cfg = load_config(str(p))
        # Stripped from cage.
        assert "MIGADU_USER" not in cfg.container.podman_secrets
        assert "MIGADU_PASSWORD" not in cfg.container.podman_secrets
        # But surfaced for the egress container.
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp"
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.MIGADU_USER,type=env,target=MIGADU_USER" in content
        assert "Secret=myapp.MIGADU_PASSWORD,type=env,target=MIGADU_PASSWORD" in content
        # Cage container must NOT receive them.
        cage_content = files["test-cage.container"]
        assert "MIGADU_USER" not in cage_content
        assert "MIGADU_PASSWORD" not in cage_content

    def test_egress_publish_port_when_inbound_forward(self, tmp_path):
        """Inbound published ports land on the egress quadlet (the
        container the host's port reaches first); mitmproxy --mode
        reverse:... is wired up by the supervisor based on the same
        proxy-config the cage's ports.allow drives."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "127.0.0.1:3000:3000"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "PublishPort=127.0.0.1:3000:3000" in content
        # Cage gets no published port — it's behind the egress container.
        cage_content = files["test-cage.container"]
        assert "PublishPort=" not in cage_content

    def test_egress_no_publish_port_without_forward(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-egress.container"]
        assert "PublishPort=" not in content

    def test_egress_creds_decrypt_user_scope(self, tmp_path):
        """secrets.scope: user → systemd-creds decrypt picks up `--user`
        in the ExecStartPre. This is the per-user encryption key, not
        the host-wide one — important so the quadlet runs under
        `systemctl --user` without a polkit prompt at start time."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secrets:
              scope: user
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
                source: "systemd-creds:"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="myapp")
        content = files["test-egress.container"]
        assert "systemd-creds --user decrypt" in content

    def test_egress_creds_decrypt_system_scope(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secrets:
              scope: system
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
                source: "systemd-creds:"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="myapp")
        content = files["test-egress.container"]
        decrypt_line = next(
            ln for ln in content.splitlines() if "systemd-creds" in ln and "decrypt" in ln
        )
        assert "systemd-creds decrypt" in decrypt_line
        assert "--user" not in decrypt_line

    def test_egress_creds_decrypt_passes_name(self, tmp_path):
        """systemd-creds decrypt validates the name embedded in the
        .cred against an expected name. With output going to stdout it
        cannot derive that name from the input path, so the decrypt
        must pass --name explicitly (matching what `agentcage secret
        set` encrypts each .cred with)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
                source: "systemd-creds:"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="myapp")
        content = files["test-egress.container"]
        decrypt_line = next(
            ln for ln in content.splitlines() if "systemd-creds" in ln and "decrypt" in ln
        )
        assert '--name "API_KEY"' in decrypt_line


class TestStoreAwareSecretEmission:
    """Issue #262: `secret rm` removes the podman store entry but the
    declared secret_injection rule stays in cage.yaml — blindly rendering
    `Secret=<cage>.<KEY>` makes the next egress boot fail with
    `no secret with name or ID ...` → start-limit-hit. With
    ``store_secrets`` passed (the env-name set actually present in the
    store), generation must skip store-backed references whose entry is
    absent — unless a pre-start channel materializes them (`.cred` blob /
    `systemd-creds:` decrypt ExecStartPre, or `env:`/`cmd:` resolution on
    the start path). ``store_secrets=None`` keeps legacy emit-all."""

    def _cfg(self, tmp_path, body: str):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent(body))
        return load_config(str(p))

    def test_missing_store_entry_drops_secret_line(self, tmp_path):
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
            store_secrets=set(),
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.API_KEY" not in content

    def test_present_store_entry_keeps_secret_line(self, tmp_path):
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
              - env: GONE_KEY
                placeholder: "{{GONE_KEY}}"
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
            store_secrets={"API_KEY"},
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.API_KEY,type=env,target=API_KEY" in content
        assert "Secret=myapp.GONE_KEY" not in content

    def test_none_store_keeps_legacy_emit_all(self, tmp_path):
        """Store state unknown (VM guest stopped, store unqueryable) →
        emit everything, exactly as before the fix."""
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.API_KEY,type=env,target=API_KEY" in content

    def test_env_and_cmd_sources_survive_empty_store(self, tmp_path):
        """env:/cmd: sources are resolved into the store by the start
        path's resolve_and_populate before units launch — their Secret=
        lines must stay even when the store is empty at generation."""
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: ENV_KEY
                placeholder: "{{ENV_KEY}}"
                source: "env:MY_VAR"
              - env: CMD_KEY
                placeholder: "{{CMD_KEY}}"
                source: "cmd:echo hi"
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
            store_secrets=set(),
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.ENV_KEY,type=env,target=ENV_KEY" in content
        assert "Secret=myapp.CMD_KEY,type=env,target=CMD_KEY" in content

    def test_systemd_creds_source_survives_empty_store(self, tmp_path):
        """systemd-creds: rules get a decrypt ExecStartPre that creates
        the store entry before the container starts — keep the line."""
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
                source: "systemd-creds:"
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
            store_secrets=set(),
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.API_KEY,type=env,target=API_KEY" in content
        assert "systemd-creds" in content and "decrypt" in content

    def test_cred_blob_survives_empty_store(self, tmp_path, patch_state_dirs):
        """A .cred blob (auto-encrypted `secret set` on a systemd-creds
        host) is materialized by the decrypt ExecStartPre — keep the
        line even without an explicit source: and an empty store."""
        state = patch_state_dirs
        creds_dir = state.deployment_dir("myapp") / "creds"
        creds_dir.mkdir(parents=True)
        (creds_dir / "API_KEY.cred").write_bytes(b"blob")
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: API_KEY
                placeholder: "{{API_KEY}}"
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
            store_secrets=set(),
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.API_KEY,type=env,target=API_KEY" in content

    def test_relay_credentials_gated_by_store(self, tmp_path):
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            protocol_relays:
              - name: migadu-imap
                type: imap
                listen: "127.0.0.1:1143"
                upstream:
                  host: imap.migadu.com
                  port: 993
                auth:
                  type: imap-login
                  user_source: "podman:MIGADU_USER"
                  password_source: "podman:MIGADU_PASSWORD"
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
            store_secrets={"MIGADU_USER"},
        )
        content = files["test-egress.container"]
        assert "Secret=myapp.MIGADU_USER,type=env,target=MIGADU_USER" in content
        assert "Secret=myapp.MIGADU_PASSWORD" not in content

    def test_cage_podman_secrets_gated_by_store(self, tmp_path):
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
              podman_secrets:
                - KEEP_ME
                - RM_ME
        """)
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp",
            store_secrets={"KEEP_ME"},
        )
        content = files["test-cage.container"]
        assert "Secret=myapp.KEEP_ME,type=env,target=KEEP_ME" in content
        assert "Secret=myapp.RM_ME" not in content

    def test_rm_then_set_round_trip(self, tmp_path):
        """The converge cycle: rm drops the line, the next set re-adds
        it — units always track store reality."""
        cfg = self._cfg(tmp_path, """\
            name: test
            container:
              image: test:latest
            secret_injection:
              - env: BRAND_KEY
                placeholder: "{{BRAND_KEY}}"
        """)
        after_rm = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="optest",
            store_secrets=set(),
        )["test-egress.container"]
        assert "Secret=optest.BRAND_KEY" not in after_rm
        after_set = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="optest",
            store_secrets={"BRAND_KEY"},
        )["test-egress.container"]
        assert "Secret=optest.BRAND_KEY,type=env,target=BRAND_KEY" in after_set


class TestVmLocalEgressConfigPaths:
    """VM backend: the egress quadlet must bind-mount a VM-local copy of
    proxy-config.yaml and dns-allowlist.conf — NOT the host path under
    ``~/.config/agentcage`` that Lima's reverse-sshfs caches past the
    point where dnsmasq SIGHUP / proxy mtime-poll would re-read it.

    The bind source uses the systemd ``%h`` home-directory specifier so
    podman-quadlet expands it to an absolute path. A bare ``~/...`` would
    be treated as a named volume by podman and rejected as an invalid
    name."""

    def test_quadlets_do_not_emit_unexpanded_tilde_volume(self, tmp_path):
        """Regression: ``Volume=~/...`` reaches podman-quadlet as a
        named-volume reference, not a bind mount, and fails the
        ``[a-zA-Z0-9_.-]*`` name validator at service start time."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
            domains:
              allow:
                - example.com
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/host/c.yaml", "/host/patches", "test")
        for fname, content in files.items():
            for line in content.splitlines():
                if line.startswith("Volume=~"):
                    raise AssertionError(
                        f"{fname} emits an unexpanded ~ Volume= source: "
                        f"{line!r}"
                    )

    def test_egress_quadlet_uses_vm_local_allowlist_path(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
            domains:
              allow:
                - example.com
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/host/c.yaml", "/host/patches", "test")
        content = files["test-egress.container"]
        # VM-local path is the bind source — NOT the host
        # ~/.config/agentcage cache path.
        assert "%h/.config/agentcage-vm/cages/test/dns-allowlist.conf" in content
        assert "~/.config/agentcage/cages/test/dns-allowlist.conf" not in content

    def test_egress_quadlet_uses_vm_local_config_path(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/host/c.yaml", "/host/patches", "test")
        content = files["test-egress.container"]
        # The proxy config bind source is VM-local; the host path passed
        # to generate_quadlets is ignored for the volume mount.
        assert "%h/.config/agentcage-vm/cages/test/proxy-config.yaml:/etc/agentcage/config.yaml" in content
        assert "/host/c.yaml:/etc/agentcage/config.yaml" not in content

    def test_container_backend_still_uses_host_path(self, tmp_path):
        """Regression guard: the container backend (no Lima sshfs) must
        keep mounting the authoritative host paths directly. We only
        sidestep the cache for VM cages."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - example.com
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/host/c.yaml", "/host/patches", "test")
        # Host paths used directly — NOT the agentcage-vm tree.
        assert "/host/c.yaml:/etc/agentcage/config.yaml" in files["test-egress.container"]
        assert "agentcage-vm" not in files["test-egress.container"]


class TestCageQuadlet:
    def test_cage_basics(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/home/patches")
        content = files["test-cage.container"]
        assert "ContainerName=test-cage" in content
        assert "Image=localhost/test:latest" in content
        # v0.22: the cage now depends on the single egress service (was
        # proxy + dns).
        assert "Requires=test-egress.service" in content
        assert "After=test-egress.service" in content
        assert f'Environment="HTTP_PROXY=http://{addrs["ip_egress"]}:8080"' in content
        assert f'Environment="HTTPS_PROXY=http://{addrs["ip_egress"]}:8080"' in content
        assert f'Environment="http_proxy=http://{addrs["ip_egress"]}:8080"' in content
        assert f'Environment="https_proxy=http://{addrs["ip_egress"]}:8080"' in content
        assert 'Environment="NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem"' in content
        assert 'Environment="SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem"' in content
        assert 'NODE_OPTIONS' not in content
        assert 'Environment="AGENTCAGE_VERSION=' in content
        # The cage MUST mount the public-certs volume (public cert only),
        # NOT the certs volume (which holds mitmproxy's private key,
        # .p12 bundles, etc.). CTF F6/F9 — agentcage 0.22.0 leaked the
        # full keypair into /certs and only file mode + uid mismatch
        # blocked reads.
        assert "Volume=test-public-certs.volume:/certs:ro,Z" in content
        assert "Volume=test-certs.volume:/certs:ro,Z" not in content
        # The broad `<patches_host_dir>:/agentcage` bind was removed — it
        # leaked every sibling cage's resolv-<name>.conf to this cage.
        assert "Volume=/home/patches:/agentcage:ro,Z" not in content
        assert "nsenter" in content
        assert f"ip route replace default via {addrs['ip_egress']}" in content

    def test_cage_no_broad_patches_mount(self, minimal_yaml):
        """Regression guard for the resolv-leak finding: the cage quadlet
        must NOT bind-mount the entire patches_host_dir at /agentcage.
        That directory holds per-cage resolv-<name>.conf for every cage
        on the host, so a broad RO mount let any cage enumerate its
        siblings' names + DNS sidecar IPs."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/home/patches")
        content = files["test-cage.container"]

        # No volume directive may map `<patches_host_dir>` (or its expansion)
        # to a bare `/agentcage` target. The narrower per-file mounts under
        # `/agentcage/<...>` (e.g. nested/docker → /usr/local/bin/docker)
        # are fine — only the top-level directory bind is forbidden.
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped.startswith("Volume="):
                continue
            spec = stripped[len("Volume="):]
            # Parse `source:target[:opts]` — the target is the second field.
            parts = spec.split(":")
            if len(parts) < 2:
                continue
            target = parts[1]
            assert target != "/agentcage", (
                f"broad /agentcage mount reintroduced: {line!r}"
            )

    def test_cage_resolv_conf_still_mounted(self, minimal_yaml):
        """The cage's own resolv.conf must still arrive via a direct
        bind at /etc/resolv.conf — independent of the broad /agentcage
        mount that we removed."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/home/patches")
        content = files["test-cage.container"]
        assert (
            "Volume=/home/patches/resolv-test.conf:/etc/resolv.conf:ro,Z"
            in content
        )

    def test_cage_defaults_hardening(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "User=1000:1000" in content
        assert "ReadOnly=true" in content
        assert "SecurityLabelDisable=true" in content
        assert "NoNewPrivileges=true" in content
        assert "DropCapability=ALL" in content

    def test_cage_cert_wait(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "ExecStartPre=" in content
        assert "mitmproxy-ca-cert.pem" in content

    def test_cage_resolv_conf_bind_mount(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Volume=/patches/resolv-test.conf:/etc/resolv.conf:ro,Z" in content

    def test_cage_no_dns_directive(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "\nDNS=" not in content

    def test_cage_service_section(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Restart=on-failure" in content
        assert "RestartSec=10" in content
        assert "TimeoutStartSec=120" in content
        assert "TimeoutStopSec=30" in content

    def test_cage_full_config(self, full_yaml, tmp_path, monkeypatch):
        # The fixture's volume "./agent" is a relative path — make it
        # resolvable and inside the (mocked) home so it is not skipped.
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)
        (tmp_path / "agent").mkdir()
        cfg = load_config(full_yaml)
        addrs = cage_network_addrs("myapp")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["myapp-cage.container"]
        # v0.22: published ports land on the egress quadlet (was proxy).
        egress_content = files["myapp-egress.container"]
        # Image
        assert "Image=node:22-slim" in content
        # Command
        assert "Exec=node /app/agent.js" in content
        # Volumes (env vars expanded)
        assert "Volume=./agent:/app:ro" in content
        # Named volumes
        assert "Volume=myapp-data:/data:rw" in content
        # Tmpfs
        assert "Tmpfs=/tmp:rw,noexec,nosuid,size=64M" in content
        # Ports — should be on egress, not cage
        assert "PublishPort=" not in content
        assert "PublishPort=127.0.0.1:3000:3000" in egress_content
        # Cage has static IP
        assert f"ip={addrs['ip_cage']}" in content
        # Podman secrets (INJECTED_KEY removed, MY_API_KEY kept)
        assert "Secret=MY_API_KEY,type=env" in content
        # Cage placeholders are delivered via EnvironmentFile (re-read by
        # podman at every container creation, so `cage restart` picks up
        # placeholder changes), not baked Environment= lines.
        assert 'Environment="INJECTED_KEY=' not in content
        assert "EnvironmentFile=" in content
        assert "/cage-env/placeholders.env" in content
        assert ":/run/agentcage/env:ro,Z" in content
        # User env
        assert 'Environment="STATIC_VAR=hello"' in content
        # User is empty → no User= line
        assert "\nUser=" not in content
        # Security disabled
        assert "ReadOnly=true" not in content
        assert "SecurityLabelDisable=true" not in content
        assert "NoNewPrivileges=true" not in content
        assert "DropCapability=" not in content
        # Added capability
        assert "AddCapability=NET_BIND_SERVICE" in content
        # Resource limits
        assert "PodmanArgs=--memory=4g" in content
        assert "PodmanArgs=--cpus=2.0" in content
        # Service section
        assert "Restart=no" in content
        assert "RestartSec=0" in content
        assert "TimeoutStartSec=300" in content
        assert "TimeoutStopSec=60" in content

    def test_cage_openclaw(self, openclaw_yaml):
        cfg = load_config(openclaw_yaml)
        files = generate_quadlets(cfg, "/etc/agentcage/config.yaml", "/patches")
        content = files["openclaw-cage.container"]
        assert "Image=ghcr.io/openclaw/openclaw:latest" in content
        assert "Exec=/usr/local/bin/entrypoint.sh" in content
        assert "Secret=OPENCLAW_GATEWAY_PASSWORD,type=env" in content
        assert 'Environment="ANTHROPIC_API_KEY=' not in content
        assert "EnvironmentFile=" in content
        assert "/cage-env/placeholders.env" in content
        assert 'Environment="OPENCLAW_DISABLE_BONJOUR=1"' in content
        assert "Volume=openclaw-state:/home/node/.openclaw:rw" in content
        assert "PodmanArgs=--memory=4g" in content
        assert "PodmanArgs=--cpus=2.0" in content

    def test_cage_secrets_prefixed(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              podman_secrets:
                - MY_TOKEN
                - MY_PASSWORD
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="prod")
        content = files["test-cage.container"]
        assert "Secret=prod.MY_TOKEN,type=env,target=MY_TOKEN" in content
        assert "Secret=prod.MY_PASSWORD,type=env,target=MY_PASSWORD" in content

    def test_cage_secrets_unprefixed_without_deploy_name(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              podman_secrets:
                - MY_TOKEN
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Secret=MY_TOKEN,type=env" in content
        assert "target=" not in content

    def test_cage_env_var_expansion(self, tmp_path, monkeypatch):
        # Treat tmp_path as home so the volume passes the within-home check;
        # the host path must exist or it would (correctly) be skipped.
        monkeypatch.setenv("HOME", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        monkeypatch.setenv("MY_TEST_DIR", str(tmp_path))
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              volumes:
                - "${MY_TEST_DIR}/data:/app:ro"
              env:
                DATA_DIR: "${MY_TEST_DIR}/data"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert f"Volume={data_dir}:/app:ro" in content
        assert f'Environment="DATA_DIR={tmp_path}/data"' in content

    def test_cage_skips_nonexistent_volume(self, tmp_path, monkeypatch):
        """A volume whose host path does not exist is skipped, not emitted —
        podman cannot bind-mount a missing source (it fails the container
        with `statfs ...: no such file or directory`)."""
        monkeypatch.setenv("HOME", str(tmp_path))
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              volumes:
                - "~/.claude:/home/node/.claude:rw"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "/home/node/.claude" not in content

    def test_cage_stages_file_volume_on_vm(self, tmp_path, monkeypatch):
        """On the VM backend a file-source volume is staged into the
        cage's data dir (which Lima mounts) and bind-mounted from there —
        Lima virtiofs cannot share a single file directly."""
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".claude.json").write_text('{"seed": true}')
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
              volumes:
                - "~/.claude.json:/home/node/.claude.json:rw"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches", "test")
        content = files["test-cage.container"]

        # The staged copy exists and carries the host file's content.
        staged = tmp_path / ".local/share/agentcage/test/seed/.claude.json"
        assert staged.is_file()
        assert staged.read_text() == '{"seed": true}'
        # The quadlet bind-mounts the staged copy, not the bare ~/.claude.json.
        assert "/agentcage/test/seed/.claude.json:/home/node/.claude.json:rw" in content
        assert f"{tmp_path}/.claude.json:" not in content

    def test_cage_keeps_file_volume_on_container(self, tmp_path, monkeypatch):
        """Container mode bind-mounts a single file directly — podman
        supports it, so a file-source volume must be preserved."""
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".claude.json").write_text("{}")
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              volumes:
                - "~/.claude.json:/home/node/.claude.json:rw"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "/home/node/.claude.json" in content

    def test_cage_volume_outside_home_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              volumes:
                - "/etc/shadow:/data:ro"
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="outside the home directory"):
            generate_quadlets(cfg, "/c.yaml", "/patches")

    def test_cage_has_static_ip(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert f"Network=test-net.network:ip={addrs['ip_cage']}" in content

    def test_port_8080_conflict_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "127.0.0.1:8080:8080"
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="container port 8080 conflicts"):
            generate_quadlets(cfg, "/c.yaml", "/patches")

    def test_port_8443_conflict_rejected(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "127.0.0.1:8443:8443"
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="container port 8443 conflicts"):
            generate_quadlets(cfg, "/c.yaml", "/patches")


class TestPublishPortsOnEgress:
    """In the v0.22 shape inbound published ports land on the egress
    container's quadlet (the only one with PublishPort directives —
    the cage sits behind it on the per-cage podman network). The
    mitmproxy --mode reverse:... wiring previously baked into the
    proxy quadlet's Exec= line is now derived by the supervisor from
    proxy-config.yaml at runtime, so the quadlet-level assertion shifts
    to PublishPort presence rather than the regular/transparent/reverse
    mitmdump argument string."""

    def test_publish_port_lands_on_egress(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "127.0.0.1:3000:3000"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        egress = files["test-egress.container"]
        cage = files["test-cage.container"]
        assert "PublishPort=127.0.0.1:3000:3000" in egress
        # Cage never gets PublishPort — it's behind the egress container.
        assert "PublishPort=" not in cage

    def test_no_publish_ports_without_inbound_forwards(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        egress = files["test-egress.container"]
        assert "PublishPort=" not in egress

    def test_multiple_publish_ports_all_on_egress(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "127.0.0.1:3000:3000"
                - "0.0.0.0:9090:9090"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        egress = files["test-egress.container"]
        cage = files["test-cage.container"]
        # Both PublishPorts on egress.
        assert "PublishPort=127.0.0.1:3000:3000" in egress
        assert "PublishPort=0.0.0.0:9090:9090" in egress
        # Cage has no PublishPort
        assert "PublishPort=" not in cage


class TestCageNetworkAddrs:
    def test_returns_all_keys(self):
        addrs = cage_network_addrs("test")
        assert "subnet" in addrs
        assert "ip_cage" in addrs
        # v0.22: single ip_egress for the combined mitmproxy+dnsmasq
        # container (was separate ip_proxy + ip_dns).
        assert "ip_egress" in addrs
        assert "ip_proxy" not in addrs
        assert "ip_dns" not in addrs

    def test_deterministic(self):
        assert cage_network_addrs("foo") == cage_network_addrs("foo")

    def test_different_names_different_subnets(self):
        a = cage_network_addrs("cage-alpha")
        b = cage_network_addrs("cage-beta")
        assert a["subnet"] != b["subnet"]

    def test_octet_in_valid_range(self):
        for name in ("a", "z", "test", "my-cage-99", "x" * 63):
            addrs = cage_network_addrs(name)
            octet = int(addrs["subnet"].split(".")[2])
            assert 1 <= octet <= 254

    def test_no_collision_with_empty_used(self):
        """When used_octets is empty, result matches default behavior."""
        assert cage_network_addrs("test", used_octets=set()) == cage_network_addrs("test")

    def test_no_collision_with_unrelated_used(self):
        """When used_octets doesn't contain the hash octet, result is unchanged."""
        base = cage_network_addrs("test")
        base_octet = int(base["subnet"].split(".")[2])
        # Pick a different octet to mark as used
        other = (base_octet % 254) + 1
        assert cage_network_addrs("test", used_octets={other}) == base

    def test_collision_resolved(self):
        """When the hash-based octet is taken, it increments to the next free one."""
        base = cage_network_addrs("test")
        base_octet = int(base["subnet"].split(".")[2])
        resolved = cage_network_addrs("test", used_octets={base_octet})
        resolved_octet = int(resolved["subnet"].split(".")[2])
        assert resolved_octet != base_octet
        assert 1 <= resolved_octet <= 254
        expected = (base_octet % 254) + 1
        assert resolved_octet == expected

    def test_multiple_collisions(self):
        """When several consecutive octets are taken, it skips them all."""
        base = cage_network_addrs("test")
        base_octet = int(base["subnet"].split(".")[2])
        # Block the base octet and the next 4
        used = set()
        o = base_octet
        for _ in range(5):
            used.add(o)
            o = (o % 254) + 1
        resolved = cage_network_addrs("test", used_octets=used)
        resolved_octet = int(resolved["subnet"].split(".")[2])
        assert resolved_octet not in used
        assert 1 <= resolved_octet <= 254
        assert resolved_octet == o  # first free after the blocked range

    def test_all_slots_taken_raises(self):
        """When all 254 slots are used, a RuntimeError is raised."""
        all_octets = set(range(1, 255))
        with pytest.raises(RuntimeError, match="All 254 subnet slots"):
            cage_network_addrs("test", used_octets=all_octets)

    def test_collision_wraps_around(self):
        """Collision resolution wraps from 254 back to 1."""
        # Find a name that hashes to 254
        base = cage_network_addrs("test")
        base_octet = int(base["subnet"].split(".")[2])
        # Block from base_octet through 254
        used = set(range(base_octet, 255))
        resolved = cage_network_addrs("test", used_octets=used)
        resolved_octet = int(resolved["subnet"].split(".")[2])
        assert resolved_octet not in used
        assert 1 <= resolved_octet <= 254


class TestCollectUsedOctets:
    def test_no_deployments(self, monkeypatch):
        """Returns empty set when no cages are deployed."""
        monkeypatch.setattr("agentcage.state.list_deployments", lambda: [])
        assert collect_used_octets() == set()

    def test_collects_from_metadata(self, monkeypatch):
        """Reads actual octet from metadata when available."""
        metadata = {
            "alpha": {"network_octet": 42},
            "beta": {"network_octet": 99},
        }
        monkeypatch.setattr("agentcage.state.list_deployments", lambda: ["alpha", "beta"])
        monkeypatch.setattr("agentcage.state.load_metadata", lambda n: metadata[n])

        used = collect_used_octets()
        assert used == {42, 99}

    def test_fallback_to_hash_without_metadata(self, monkeypatch, tmp_path):
        """Falls back to hash-based octet for legacy deployments without metadata."""
        configs = {}
        for cage_name in ("alpha", "beta"):
            p = tmp_path / f"{cage_name}.yaml"
            p.write_text(f"name: {cage_name}\ncontainer:\n  image: test:latest\n")
            from agentcage.config import load_config
            configs[cage_name] = load_config(str(p))

        monkeypatch.setattr("agentcage.state.list_deployments", lambda: ["alpha", "beta"])
        monkeypatch.setattr("agentcage.state.load_metadata", lambda n: {})
        monkeypatch.setattr("agentcage.state.load_deployment_config", lambda n: configs[n])

        used = collect_used_octets()
        expected = set()
        for cage_name in ("alpha", "beta"):
            octet = int(cage_network_addrs(cage_name)["subnet"].split(".")[2])
            expected.add(octet)
        assert used == expected

    def test_metadata_takes_precedence_over_hash(self, monkeypatch, tmp_path):
        """When metadata has network_octet, config is not loaded at all."""
        monkeypatch.setattr("agentcage.state.list_deployments", lambda: ["cage1"])
        monkeypatch.setattr("agentcage.state.load_metadata", lambda n: {"network_octet": 200})

        def _should_not_be_called(name):
            raise AssertionError("load_deployment_config should not be called when metadata has octet")

        monkeypatch.setattr("agentcage.state.load_deployment_config", _should_not_be_called)

        used = collect_used_octets()
        assert used == {200}

    def test_excludes_named_cage(self, monkeypatch):
        """The exclude parameter omits the specified cage."""
        monkeypatch.setattr("agentcage.state.list_deployments", lambda: ["only"])
        monkeypatch.setattr("agentcage.state.load_metadata", lambda n: {"network_octet": 50})

        assert collect_used_octets(exclude="only") == set()

    def test_skips_broken_config(self, monkeypatch):
        """Gracefully skips cages with unloadable configs."""
        def _fail(name):
            raise FileNotFoundError("gone")

        monkeypatch.setattr("agentcage.state.list_deployments", lambda: ["broken"])
        monkeypatch.setattr("agentcage.state.load_metadata", lambda n: {})
        monkeypatch.setattr("agentcage.state.load_deployment_config", _fail)

        assert collect_used_octets() == set()


class TestSystemdExecFilter:
    def test_simple_args(self):
        assert _systemd_exec_join(["node", "app.js"]) == "node app.js"

    def test_arg_with_spaces_quoted(self):
        result = _systemd_exec_join(["sh", "-c", "echo hello world"])
        assert result == 'sh -c "echo hello world"'

    def test_arg_with_double_quotes_escaped(self):
        result = _systemd_exec_join(["sh", "-c", 'echo "hi"'])
        assert result == r'sh -c "echo \"hi\""'

    def test_arg_with_backslash_escaped(self):
        result = _systemd_exec_join(["echo", "a\\b"])
        assert result == r'echo "a\\b"'

    def test_empty_list(self):
        assert _systemd_exec_join([]) == ""

    def test_arg_with_dollar_quoted(self):
        result = _systemd_exec_join(["sh", "-c", "echo $HOME"])
        assert result == 'sh -c "echo $HOME"'

    def test_backward_compatible_simple_command(self):
        """Simple commands without spaces produce identical output to join(' ')."""
        args = ["node", "openclaw.mjs", "gateway", "--bind", "lan"]
        assert _systemd_exec_join(args) == " ".join(args)


class TestPassthroughRegex:
    def test_single_domain(self):
        regex = _passthrough_regex(["whatsapp.com"])
        assert regex == r"^(.+\.)?whatsapp\.com(:\d+)?$"

    def test_multiple_domains(self):
        regex = _passthrough_regex(["whatsapp.com", "signal.org"])
        assert r"^(.+\.)?whatsapp\.com(:\d+)?$" in regex
        assert r"^(.+\.)?signal\.org(:\d+)?$" in regex
        assert "|" in regex

    def test_empty_list(self):
        assert _passthrough_regex([]) == ""

    def test_domain_with_dots_escaped(self):
        regex = _passthrough_regex(["web.whatsapp.com"])
        assert r"web\.whatsapp\.com" in regex


class TestEffectiveDnsAllowlist:
    def test_merges_passthrough(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - anthropic.com
              passthrough:
                - whatsapp.com
        """))
        cfg = load_config(str(p))
        merged = _effective_dns_allowlist(cfg)
        assert "anthropic.com" in merged
        assert "whatsapp.com" in merged

    def test_no_duplicates(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - whatsapp.com
                - anthropic.com
              passthrough:
                - whatsapp.com
        """))
        cfg = load_config(str(p))
        merged = _effective_dns_allowlist(cfg)
        assert merged.count("whatsapp.com") == 1

    def test_empty_for_non_allowlist(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              block:
                - evil.com
              passthrough:
                - whatsapp.com
        """))
        cfg = load_config(str(p))
        assert _effective_dns_allowlist(cfg) == []


class TestPassthroughSidecarFiles:
    """In the v0.22 shape mitmproxy's --ignore-hosts and dnsmasq's
    --servers-file flags are wired by the supervisor inside the egress
    image, not baked into the quadlet command line. The remaining
    quadlet-visible artifact for passthrough is the dns-allowlist.conf
    sidecar that the supervisor mounts in. These tests pin the sidecar
    content rather than the (now image-side) command-line shape."""

    def test_dns_includes_passthrough_domains(self, tmp_path, patch_state_dirs):
        """Passthrough domains must resolve via real DNS (not the
        sinkhole), so they are merged into the dns-allowlist.conf
        sidecar alongside normal allow entries."""
        state = patch_state_dirs
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - anthropic.com
              passthrough:
                - whatsapp.com
            dns_servers:
              - 100.100.100.100
        """))
        state.save_deployment("test", str(p))
        body = open(state.save_dns_allowlist("test")).read()
        assert "server=/whatsapp.com/100.100.100.100" in body
        assert "server=/anthropic.com/100.100.100.100" in body

    def test_backward_compat_mode_list_sidecar(self, tmp_path, patch_state_dirs):
        """Old ``mode: allowlist`` + ``list:`` format still produces
        the right sidecar file. The quadlet itself is now stable across
        allowlist edits (no --servers-file flag baked in — see the
        supervisor inside Containerfile.egress)."""
        state = patch_state_dirs
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              mode: allowlist
              list:
                - api.anthropic.com
            dns_servers:
              - 100.100.100.100
        """))
        state.save_deployment("test", str(p))
        body = open(state.save_dns_allowlist("test")).read()
        assert "server=/api.anthropic.com/100.100.100.100" in body
