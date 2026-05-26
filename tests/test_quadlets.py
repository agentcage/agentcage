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
        assert len(files) == 5

    def test_file_names(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/path/to/config.yaml", "/path/to/patches")
        assert set(files.keys()) == {
            "test-net.network",
            "test-certs.volume",
            "test-dns.container",
            "test-proxy.container",
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


class TestDnsQuadlet:
    def test_dns_default_no_log_queries(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "ContainerName=test-dns" in content
        assert "Image=localhost/agentcage-dns" in content
        assert f"Network=test-net.network:ip={addrs['ip_dns']}" in content
        assert "--log-queries" not in content

    def test_dns_custom_servers(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            dns_servers:
              - 100.100.100.100
              - 1.1.1.1
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "--server 100.100.100.100 --server 1.1.1.1" in content
        assert "--log-queries" not in content


    def test_dns_log_queries_enabled(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            dns_servers:
              - 100.100.100.100
            logging:
              dns_queries: true
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "--log-queries" in content
        assert "Exec=dnsmasq --no-daemon --log-queries --no-resolv --server 100.100.100.100" in content

    def test_dns_log_queries_no_servers(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            logging:
              dns_queries: true
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "Exec=dnsmasq --no-daemon --log-queries --no-resolv" in content


    def test_dns_allowlist_filtering(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
                - github.com
            dns_servers:
              - 100.100.100.100
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        # Sinkhole stays in the quadlet; per-domain forwarders now live in
        # the dns-allowlist.conf sidecar file referenced by --servers-file.
        assert "--address=/#/198.51.100.1" in content
        assert "--servers-file=/etc/dnsmasq-allow.conf" in content
        assert "/etc/dnsmasq-allow.conf:ro,Z" in content
        # The per-domain lines must NOT be baked into the quadlet — that's
        # what we're moving away from so domain edits don't churn systemd.
        assert "--server=/api.anthropic.com/" not in content
        assert "--server=/github.com/" not in content

    def test_proxy_cage_local_resolves_to_proxy_ip(self, tmp_path):
        """proxy.cage.local is the canonical hostname for cage-internal
        traffic that should land on the proxy container directly (e.g.
        the protocol_relays IMAP listener). dnsmasq must hand back the
        proxy's network IP for it instead of falling through to the
        198.51.100.1 placeholder."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - example.com
            dns_servers:
              - 100.100.100.100
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        # Default cage prefix is 10.89.0; proxy is .11
        import re
        assert re.search(r"--address=/proxy\.cage\.local/10\.89\.\d+\.11", content), content

    def test_proxy_cage_local_works_without_allowlist(self, tmp_path):
        """Even with no domains.allow set (open-DNS mode), proxy.cage.local
        must still resolve to the proxy IP."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            dns_servers:
              - 100.100.100.100
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        import re
        assert re.search(r"--address=/proxy\.cage\.local/10\.89\.\d+\.11", content), content

    def test_dns_allowlist_forwards_to_all_servers(self, tmp_path, patch_state_dirs):
        """Each allowlisted domain × upstream pair should appear in the
        dns-allowlist.conf sidecar file (and therefore reach dnsmasq via
        --servers-file). The quadlet itself stays stable across domain edits."""
        state = patch_state_dirs
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - github.com
                - pypi.org
            dns_servers:
              - 100.100.100.100
              - 1.1.1.1
              - 8.8.8.8
        """))
        state.save_deployment("test", str(p))
        body = open(state.save_dns_allowlist("test")).read()
        for domain in ("github.com", "pypi.org"):
            for server in ("100.100.100.100", "1.1.1.1", "8.8.8.8"):
                assert f"server=/{domain}/{server}" in body

    def test_dns_allowlist_uses_wrapper(self, tmp_path):
        """When allowlist is active, dnsmasq is wrapped with dns-audit.sh."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
            dns_servers:
              - 100.100.100.100
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "Exec=/usr/local/bin/dns-audit.sh" in content
        assert "-- dnsmasq" in content
        assert "--log-queries" in content
        # --log-allowed should NOT be present when dns_queries is false (default)
        assert "--log-allowed" not in content

    def test_dns_allowlist_log_allowed(self, tmp_path):
        """When allowlist + dns_queries logging, --log-allowed flag is added."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
            dns_servers:
              - 100.100.100.100
            logging:
              dns_queries: true
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "Exec=/usr/local/bin/dns-audit.sh --log-allowed --" in content
        assert "--log-queries" in content

    def test_dns_no_allowlist_no_wrapper(self, minimal_yaml):
        """Without allowlist, dnsmasq runs directly (no wrapper)."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "dns-audit.sh" not in content
        assert "Exec=dnsmasq --no-daemon" in content

    # ── DNS non-A-record exfil regression (CTF-derived) ──────────────
    # On 0.21.x dnsmasq was passed both `--server <ip>` (blanket
    # default upstream) AND `--address=/#/<sinkhole>` (catch-all). The
    # `--address` rule only intercepts A and AAAA queries — any other
    # RR type (TXT/MX/NS/SRV/CNAME) fell through to the blanket
    # `--server` upstream and reached a real recursive resolver. An
    # attacker who owns a delegated subdomain encoded bytes in the
    # query labels and exfilled out-of-band, never touching mitmproxy.
    # These tests pin the bypass SHAPE so the fix can't silently regress.

    def test_dns_allowlist_no_blanket_default_upstream(self, tmp_path):
        """In allowlist mode the quadlet must NOT pass a blanket
        `--server <ip>` (no domain scope). That argument tells dnsmasq
        "use this upstream for any query you don't otherwise handle",
        which is exactly the non-A-record bypass — TXT/MX/NS/SRV/CNAME
        for any hostname recurses to upstream regardless of the
        allowlist. Per-zone forwarders live in dns-allowlist.conf as
        `server=/<apex>/<upstream>` and are still allowed (they scope
        recursion to the allowlist)."""
        import re
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
                - github.com
            dns_servers:
              - 1.1.1.1
              - 8.8.8.8
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        # The bypass shape: `--server <ip>` with NO leading `=/...` after
        # `--server`. Per-zone forwarders are `--server=/<apex>/<ip>` —
        # those are exactly what closes the bypass and stay allowed.
        # `--servers-file=...` is also legitimate (it points at the per-
        # zone allowlist file).
        assert not re.search(r"--server\s+\d", content), (
            "blanket `--server <ip>` upstream present in DNS quadlet — "
            "non-A queries will bypass the allowlist via DNS tunneling. "
            f"quadlet:\n{content}"
        )

    def test_dns_allowlist_sinkhole_present(self, tmp_path):
        """Defense in depth: even with per-zone forwarder scoping, the
        A/AAAA catch-all sinkhole stays. A regression here would let
        A/AAAA queries for non-allowlisted zones leak out."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
            dns_servers:
              - 1.1.1.1
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        assert "--address=/#/198.51.100.1" in files["test-dns.container"]

    def test_dns_allowlist_servers_file_present(self, tmp_path):
        """The per-zone forwarder allowlist lives in dns-allowlist.conf
        and is loaded via `--servers-file`. Without it dnsmasq has no
        way to recurse for allowlisted zones — the cage couldn't
        resolve `api.anthropic.com` at all."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
            dns_servers:
              - 1.1.1.1
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "--servers-file=/etc/dnsmasq-allow.conf" in content
        # And the file is bind-mounted in read-only.
        assert "/etc/dnsmasq-allow.conf:ro,Z" in content

    def test_dns_allowlist_no_resolv_preserved(self, tmp_path):
        """`--no-resolv` must stay. Without it dnsmasq silently reads
        /etc/resolv.conf as an implicit default upstream, reopening
        the bypass via a different path."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - api.anthropic.com
            dns_servers:
              - 1.1.1.1
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        assert "--no-resolv" in files["test-dns.container"]

    def test_dns_blocklist_mode_keeps_open_resolver(self, tmp_path):
        """The fix is scoped to allowlist mode. In blocklist / open-DNS
        mode the cage explicitly wants open resolution — dnsmasq must
        keep its blanket forwarders. (HTTP egress is still filtered by
        mitmproxy; DNS is not the gate.)"""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              block:
                - evil.com
            dns_servers:
              - 1.1.1.1
              - 8.8.8.8
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        # Blanket forwarders intentional here.
        assert "--server 1.1.1.1 --server 8.8.8.8" in content
        # No allowlist sidecar mount in blocklist mode.
        assert "--servers-file=/etc/dnsmasq-allow.conf" not in content

    def test_dns_no_allowlist_filtering_in_blocklist_mode(self, tmp_path):
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
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        # Blocklist mode should NOT apply DNS filtering
        assert "--address=/#/198.51.100.1" not in content


class TestVmLocalConfigPaths:
    """VM backend: proxy + dns quadlets must bind-mount a VM-local copy
    of proxy-config.yaml and dns-allowlist.conf — NOT the host path
    under ``~/.config/agentcage`` that Lima's reverse-sshfs caches past
    the point where dnsmasq SIGHUP / proxy mtime-poll would re-read it."""

    def test_dns_quadlet_uses_vm_local_allowlist_path(self, tmp_path):
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
        content = files["test-dns.container"]
        # VM-local path is the bind source — NOT the host
        # ~/.config/agentcage cache path.
        assert "~/.config/agentcage-vm/cages/test/dns-allowlist.conf" in content
        assert "~/.config/agentcage/cages/test/dns-allowlist.conf" not in content

    def test_proxy_quadlet_uses_vm_local_config_path(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            isolation: vm
            container:
              image: test:latest
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/host/c.yaml", "/host/patches", "test")
        content = files["test-proxy.container"]
        # The proxy config bind source is VM-local; the host path passed
        # to generate_quadlets is ignored for the volume mount.
        assert "~/.config/agentcage-vm/cages/test/proxy-config.yaml:/etc/agentcage/config.yaml" in content
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
        assert "/host/c.yaml:/etc/agentcage/config.yaml" in files["test-proxy.container"]
        assert "agentcage-vm" not in files["test-proxy.container"]
        assert "agentcage-vm" not in files["test-dns.container"]

    def test_render_dns_quadlet_vm_uses_vm_local_path(self, tmp_path):
        """``render_dns_quadlet`` is the entry point used by
        ``_ensure_dns_quadlet_current`` — it must also produce the
        VM-local bind source for vm cages so the migration check
        rewrites pre-upgrade quadlets to the new shape."""
        from agentcage.quadlets import render_dns_quadlet
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
        rendered = render_dns_quadlet(cfg)
        assert "~/.config/agentcage-vm/cages/test/dns-allowlist.conf" in rendered


class TestProxyQuadlet:
    def test_proxy_basics(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/home/user/config.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "ContainerName=test-proxy" in content
        assert "Image=localhost/agentcage-proxy" in content
        assert "Requires=test-dns.service" in content
        assert "After=test-dns.service" in content
        assert "Volume=/home/user/config.yaml:/etc/agentcage/config.yaml:ro,Z" in content
        assert "Volume=test-certs.volume:/home/mitmproxy/.mitmproxy:Z" in content
        assert "AddCapability=NET_ADMIN" in content
        assert "--mode transparent@8443" in content
        assert "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8443" in content
        assert "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443" in content

    def test_proxy_secrets(self, tmp_path):
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
        content = files["test-proxy.container"]
        assert "Secret=API_KEY,type=env" in content
        assert "Secret=OTHER_KEY,type=env" in content

    def test_proxy_secrets_prefixed(self, tmp_path):
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
        files = generate_quadlets(cfg, "/c.yaml", "/patches", deploy_name="myapp")
        content = files["test-proxy.container"]
        assert "Secret=myapp.API_KEY,type=env,target=API_KEY" in content
        assert "Secret=myapp.OTHER_KEY,type=env,target=OTHER_KEY" in content
        assert "Secret=API_KEY,type=env\n" not in content

    def test_proxy_gets_relay_secrets(self, tmp_path):
        """protocol_relays credentials must reach the proxy container's
        env so the relay can resolve them at startup. They are stripped
        from the cage's podman_secrets/env (cage must not see them) but
        still need a Secret= directive on the proxy."""
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
        # But surfaced for proxy.
        files = generate_quadlets(
            cfg, "/c.yaml", "/patches", deploy_name="myapp"
        )
        content = files["test-proxy.container"]
        assert "Secret=myapp.MIGADU_USER,type=env,target=MIGADU_USER" in content
        assert "Secret=myapp.MIGADU_PASSWORD,type=env,target=MIGADU_PASSWORD" in content
        # Cage container must NOT receive them.
        cage_content = files["test-cage.container"]
        assert "MIGADU_USER" not in cage_content
        assert "MIGADU_PASSWORD" not in cage_content

    def test_proxy_creds_user_scope_emits_user_flag(self, tmp_path):
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
        content = files["test-proxy.container"]
        assert "systemd-creds --user decrypt" in content

    def test_proxy_creds_system_scope_omits_user_flag(self, tmp_path):
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
        content = files["test-proxy.container"]
        decrypt_line = next(
            ln for ln in content.splitlines() if "systemd-creds" in ln and "decrypt" in ln
        )
        assert "systemd-creds decrypt" in decrypt_line
        assert "--user" not in decrypt_line

    def test_proxy_creds_decrypt_passes_name(self, tmp_path):
        # systemd-creds decrypt validates the name embedded in the .cred
        # against an expected name. With output going to stdout it cannot
        # derive that name from the input path, so the decrypt must pass
        # --name explicitly — matching the `--name <ENV>` that
        # `agentcage secret set` encrypts each .cred with. Without it the
        # proxy's ExecStartPre fails ("Name in credential doesn't match
        # expectations") and the whole cage cannot start.
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
        content = files["test-proxy.container"]
        decrypt_line = next(
            ln for ln in content.splitlines() if "systemd-creds" in ln and "decrypt" in ln
        )
        assert '--name "API_KEY"' in decrypt_line

    def test_proxy_default_flags(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "Exec=mitmdump" in content
        assert "--set flow_detail=0" in content
        assert "--quiet" not in content
        assert "-v" not in content
        assert 'Environment="PYTHONUNBUFFERED=1"' in content

    def test_proxy_no_flow_detail_when_logging(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            logging:
              proxy_connections: true
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "Exec=mitmdump" in content
        assert "--quiet" not in content
        assert "flow_detail" not in content

    def test_proxy_resolv_conf_uses_upstream_dns(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            dns_servers:
              - 100.100.100.100
              - 1.1.1.1
        """))
        cfg = load_config(str(p))
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "ExecStartPost=" in content
        assert "nameserver 100.100.100.100" in content
        assert "nameserver 1.1.1.1" in content
        # Proxy should NOT use dnsmasq
        assert f"nameserver {addrs['ip_dns']}" not in content

    def test_proxy_inspected_tcp_default(self, minimal_yaml):
        """Default ports.tcp.allow ([80, 443]) with empty passthrough
        means the inspected TCP set is [80, 443]. Both get
        nat:PREROUTING REDIRECTs to mitmdump's transparent listener."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "--dport 80 -j REDIRECT --to-port 8443" in content
        assert "--dport 443 -j REDIRECT --to-port 8443" in content
        # Non-default ports must not appear unless requested.
        assert "--dport 8448" not in content

    def test_proxy_inspected_tcp_custom(self, tmp_path):
        """Custom tcp.allow list emits one REDIRECT rule per inspected
        port (= tcp.allow - tcp.passthrough), single &&-chain."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 8448]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        for port in (80, 443, 8448):
            assert f"--dport {port} -j REDIRECT --to-port 8443" in content
        iptables_lines = [
            line for line in content.splitlines()
            if "iptables -t nat -A PREROUTING" in line
        ]
        assert len(iptables_lines) == 1
        assert iptables_lines[0].count("iptables -t nat -A PREROUTING") == 3

    def test_proxy_inspected_tcp_single(self, tmp_path):
        """Single inspected TCP port emits one rule with no trailing &&."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [443]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        iptables_lines = [
            line for line in content.splitlines()
            if "iptables -t nat -A PREROUTING" in line
        ]
        assert len(iptables_lines) == 1
        assert "--dport 443 -j REDIRECT --to-port 8443" in iptables_lines[0]
        assert "--dport 80" not in iptables_lines[0]
        assert not iptables_lines[0].rstrip().endswith("&&\"")

    def test_proxy_no_inspected_tcp_omits_redirect(self, tmp_path):
        """When inspected TCP (tcp.allow - tcp.passthrough) is empty,
        the nat:PREROUTING ExecStartPost is omitted entirely."""
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
        content = files["test-proxy.container"]
        assert "iptables -t nat -A PREROUTING" not in content

    def test_proxy_tcp_passthrough_subtracts_from_inspected(self, tmp_path):
        """Putting a port in BOTH tcp.allow and tcp.passthrough means
        it's allowed but bypasses inspection — no REDIRECT, just a
        FORWARD ACCEPT for TCP."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 5432]
                passthrough: [5432]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "--dport 80 -j REDIRECT --to-port 8443" in content
        assert "--dport 443 -j REDIRECT --to-port 8443" in content
        assert "--dport 5432 -j REDIRECT --to-port 8443" not in content
        assert "iptables -A FORWARD -p tcp --dport 5432 -j ACCEPT" in content
        # No automatic UDP rule for tcp.passthrough — UDP requires
        # explicit udp.allow listing.
        assert "iptables -A FORWARD -p udp --dport 5432 -j ACCEPT" not in content

    def test_proxy_tcp_passthrough_auto_merges_into_allow(self, tmp_path):
        """If a tcp.passthrough port isn't explicitly in tcp.allow, the
        FORWARD ACCEPT still gets installed (auto-merge)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443]
                passthrough: [5432]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "iptables -A FORWARD -p tcp --dport 5432 -j ACCEPT" in content
        assert "--dport 5432 -j REDIRECT --to-port 8443" not in content

    def test_proxy_udp_allow_renders_forward_accept(self, tmp_path):
        """Each udp.allow port emits exactly one filter:FORWARD UDP
        ACCEPT (no REDIRECT, no TCP rule)."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              udp:
                allow: [123, 443]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "iptables -A FORWARD -p udp --dport 123 -j ACCEPT" in content
        assert "iptables -A FORWARD -p udp --dport 443 -j ACCEPT" in content
        # No REDIRECT for UDP entries — mitmdump can't audit UDP.
        assert "--dport 123 -j REDIRECT" not in content
        # No automatic TCP rule for udp.allow — TCP entries live in
        # tcp.allow / tcp.passthrough.
        assert "iptables -A FORWARD -p tcp --dport 123 -j ACCEPT" not in content

    def test_proxy_quic_alongside_tcp_inspection(self, tmp_path):
        """The headline case: TCP/443 is REDIRECTed (HTTP/2 audited),
        UDP/443 is FORWARD-ACCEPTed (HTTP/3 reachable, uninspected).
        Same port, two protocols, governed independently."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443]
              udp:
                allow: [443]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "-p tcp --dport 443 -j REDIRECT --to-port 8443" in content
        assert "iptables -A FORWARD -p udp --dport 443 -j ACCEPT" in content

    def test_proxy_forward_default_deny_always_installed(self, minimal_yaml):
        """The filter:FORWARD policy DROP, ESTABLISHED,RELATED ACCEPT,
        and ICMP echo-request ACCEPT are installed for every cage —
        there is no opt-out flag. With the default config (no
        passthrough, no UDP), only TCP/{80,443} (REDIRECTed at
        PREROUTING) plus echo + replies reach upstream."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert (
            "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED "
            "-j ACCEPT" in content
        )
        assert (
            "iptables -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT"
            in content
        )
        assert "iptables -P FORWARD DROP" in content
        assert "iptables -A FORWARD -p tcp --dport" not in content
        assert "iptables -A FORWARD -p udp --dport" not in content

    def test_proxy_ipv6_forward_drop_failsafe(self, minimal_yaml):
        """Always install ip6tables -P FORWARD DROP — IPv6 is not
        currently inspected and podman networks are IPv4-only, so this
        is a latent-gap failsafe rather than active filtering."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "ip6tables -P FORWARD DROP" in content

    def test_proxy_forward_atomic_chain(self, tmp_path):
        """The FORWARD ExecStartPost is a single &&-chained shell
        command so partial-rule states are impossible. Critically,
        `-P FORWARD DROP` runs FIRST: if any subsequent ACCEPT rule
        fails, packets matching the failed rule fall through to the
        DROP policy (fail-closed) instead of leaving the kernel
        default ACCEPT in place (fail-open). Default-deny is the
        headline of this feature; the failure mode must match."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            ports:
              tcp:
                allow: [80, 443, 5432]
                passthrough: [5432]
              udp:
                allow: [123]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        forward_lines = [
            line for line in content.splitlines()
            if "iptables -A FORWARD" in line or "iptables -P FORWARD" in line
        ]
        # All FORWARD-related rules live on a single ExecStartPost line.
        assert len(forward_lines) == 1
        line = forward_lines[0]
        # DROP first → ESTABLISHED,RELATED → ICMP echo → per-port ACCEPTs.
        drop_pos = line.find("-P FORWARD DROP")
        est_pos = line.find("ESTABLISHED,RELATED")
        icmp_pos = line.find("icmp-type echo-request")
        tcp_pos = line.find("--dport 5432")
        udp_pos = line.find("--dport 123")
        assert 0 < drop_pos < est_pos < icmp_pos < tcp_pos
        assert 0 < icmp_pos < udp_pos

    def test_proxy_jacque_worked_example_renders(self, tmp_path):
        """The jacque worked example from docs/proxy-audit-ports.md is
        the headline use case. Pin the rendered iptables rules so doc
        updates don't silently regress the example: TCP/{80,443,8448}
        REDIRECTed, UDP/123 (NTP) FORWARD-ACCEPTed, default-deny, ICMP
        echo always-on."""
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: jacque
            container:
              image: localhost/jacque-cage:latest
            ports:
              tcp:
                allow: [80, 443, 8448]
              udp:
                allow: [123]
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["jacque-proxy.container"]
        for port in (80, 443, 8448):
            assert (
                f"iptables -t nat -A PREROUTING -p tcp --dport {port} "
                f"-j REDIRECT --to-port 8443" in content
            )
        # NTP allowed but uninspected.
        assert "iptables -A FORWARD -p udp --dport 123 -j ACCEPT" in content
        # Audited TCP ports never get FORWARD ACCEPT (they're REDIRECTed
        # at PREROUTING and never traverse FORWARD).
        for port in (80, 443, 8448):
            assert (
                f"iptables -A FORWARD -p tcp --dport {port} -j ACCEPT"
                not in content
            )
        # Default-deny + ICMP echo always installed.
        assert "iptables -P FORWARD DROP" in content
        assert (
            "iptables -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT"
            in content
        )
        # IPv6 failsafe.
        assert "ip6tables -P FORWARD DROP" in content

    def test_proxy_inspected_tcp_not_re_accepted(self, minimal_yaml):
        """Inspected TCP ports are REDIRECTed at nat:PREROUTING and
        never traverse filter:FORWARD, so they should NOT have explicit
        ACCEPT rules in FORWARD."""
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "iptables -A FORWARD -p tcp --dport 80 -j ACCEPT" not in content
        assert "iptables -A FORWARD -p tcp --dport 443 -j ACCEPT" not in content


class TestCageQuadlet:
    def test_cage_basics(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/home/patches")
        content = files["test-cage.container"]
        assert "ContainerName=test-cage" in content
        assert "Image=localhost/test:latest" in content
        assert "Requires=test-proxy.service" in content
        assert "After=test-proxy.service" in content
        assert f'Environment="HTTP_PROXY=http://{addrs["ip_proxy"]}:8080"' in content
        assert f'Environment="HTTPS_PROXY=http://{addrs["ip_proxy"]}:8080"' in content
        assert f'Environment="http_proxy=http://{addrs["ip_proxy"]}:8080"' in content
        assert f'Environment="https_proxy=http://{addrs["ip_proxy"]}:8080"' in content
        assert 'Environment="NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem"' in content
        assert 'Environment="SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem"' in content
        assert 'NODE_OPTIONS' not in content
        assert 'Environment="AGENTCAGE_VERSION=' in content
        assert "Volume=test-certs.volume:/certs:ro,Z" in content
        # The broad `<patches_host_dir>:/agentcage` bind was removed — it
        # leaked every sibling cage's resolv-<name>.conf to this cage.
        assert "Volume=/home/patches:/agentcage:ro,Z" not in content
        assert "nsenter" in content
        assert f"ip route replace default via {addrs['ip_proxy']}" in content

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
        proxy_content = files["myapp-proxy.container"]
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
        # Ports — should be on proxy, not cage
        assert "PublishPort=" not in content
        assert "PublishPort=127.0.0.1:3000:3000" in proxy_content
        # Cage has static IP
        assert f"ip={addrs['ip_cage']}" in content
        # Podman secrets (INJECTED_KEY removed, MY_API_KEY kept)
        assert "Secret=MY_API_KEY,type=env" in content
        # Cage placeholder for injected secret
        assert 'Environment="INJECTED_KEY={{INJECTED_KEY}}"' in content
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
        assert 'Environment="ANTHROPIC_API_KEY={{ANTHROPIC_API_KEY}}"' in content
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


class TestProxyReverseMode:
    def test_proxy_reverse_mode_with_ports(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
              ports:
                - "127.0.0.1:3000:3000"
        """))
        cfg = load_config(str(p))
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        assert f"--mode regular@{addrs['ip_proxy']}:8080" in proxy
        assert "--mode transparent@8443" in proxy
        assert f"--mode reverse:http://{addrs['ip_cage']}:3000@0.0.0.0:3000" in proxy
        assert "--set keep_host_header=true" in proxy
        assert "PublishPort=127.0.0.1:3000:3000" in proxy

    def test_proxy_no_reverse_without_ports(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        assert f"--mode regular@{addrs['ip_proxy']}:8080" in proxy
        assert "--mode transparent@8443" in proxy
        assert "keep_host_header" not in proxy
        assert "PublishPort=" not in proxy

    def test_proxy_multiple_reverse_ports(self, tmp_path):
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
        addrs = cage_network_addrs("test")
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        cage = files["test-cage.container"]
        # Proxy has both reverse modes and both PublishPorts
        assert f"--mode reverse:http://{addrs['ip_cage']}:3000@0.0.0.0:3000" in proxy
        assert f"--mode reverse:http://{addrs['ip_cage']}:9090@0.0.0.0:9090" in proxy
        assert "PublishPort=127.0.0.1:3000:3000" in proxy
        assert "PublishPort=0.0.0.0:9090:9090" in proxy
        assert "--set keep_host_header=true" in proxy
        # Cage has no PublishPort
        assert "PublishPort=" not in cage


class TestCageNetworkAddrs:
    def test_returns_all_keys(self):
        addrs = cage_network_addrs("test")
        assert "subnet" in addrs
        assert "ip_cage" in addrs
        assert "ip_dns" in addrs
        assert "ip_proxy" in addrs

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


class TestPassthroughQuadlets:
    def test_proxy_ignore_hosts_present(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              allow:
                - anthropic.com
                - whatsapp.com
              passthrough:
                - whatsapp.com
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        assert "--ignore-hosts" in proxy
        assert "whatsapp" in proxy

    def test_proxy_no_ignore_hosts_without_passthrough(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        assert "--ignore-hosts" not in proxy

    def test_dns_includes_passthrough_domains(self, tmp_path, patch_state_dirs):
        """Passthrough domains must resolve via real DNS (not the sinkhole),
        so they are merged into the dns-allowlist.conf sidecar alongside
        normal allow entries."""
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

    def test_backward_compat_mode_list_quadlets(self, tmp_path, patch_state_dirs):
        """Old ``mode: allowlist`` + ``list:`` format still produces the right
        sidecar file and a quadlet with the sinkhole + servers-file flag."""
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

        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        dns = files["test-dns.container"]
        assert "--address=/#/198.51.100.1" in dns
        assert "--servers-file=/etc/dnsmasq-allow.conf" in dns
