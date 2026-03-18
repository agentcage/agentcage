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
        # Should return placeholder IP for non-allowlisted and allow only listed ones
        assert "--address=/#/198.51.100.1" in content
        assert "--server=/api.anthropic.com/100.100.100.100" in content
        assert "--server=/github.com/100.100.100.100" in content

    def test_dns_allowlist_forwards_to_all_servers(self, tmp_path):
        """Each allowlisted domain should be forwarded to every DNS server."""
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
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "--address=/#/198.51.100.1" in content
        # Each domain forwarded to ALL three servers
        for domain in ("github.com", "pypi.org"):
            for server in ("100.100.100.100", "1.1.1.1", "8.8.8.8"):
                assert f"--server=/{domain}/{server}" in content

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
        assert "iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8443" in content
        assert "iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8443" in content

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
        assert "Volume=/home/patches:/agentcage:ro,Z" in content
        assert "nsenter" in content
        assert f"ip route add default via {addrs['ip_proxy']}" in content

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

    def test_cage_full_config(self, full_yaml):
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
        # Shell wrapper command — sh -c arg is quoted by systemd_exec filter
        assert 'Exec=sh -c "' in content
        assert "exec node openclaw.mjs gateway" in content
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
        home = os.path.expanduser("~")
        monkeypatch.setenv("MY_TEST_DIR", home)
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
        assert f"Volume={home}/data:/app:ro" in content
        assert f'Environment="DATA_DIR={home}/data"' in content

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

    def test_dns_includes_passthrough_domains(self, tmp_path):
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
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        dns = files["test-dns.container"]
        assert "--server=/whatsapp.com/100.100.100.100" in dns
        assert "--server=/anthropic.com/100.100.100.100" in dns

    def test_backward_compat_mode_list_quadlets(self, tmp_path):
        """Old mode+list format still generates correct quadlets."""
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
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        dns = files["test-dns.container"]
        assert "--server=/api.anthropic.com/100.100.100.100" in dns
        assert "--address=/#/198.51.100.1" in dns
