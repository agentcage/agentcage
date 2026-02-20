"""Tests for quadlet generation."""

import os
import textwrap

import pytest

from agentcage.config import load_config
from agentcage.quadlets import generate_quadlets


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
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-net.network"]
        assert "NetworkName=test-net" in content
        assert "Internal=true" in content
        assert "Subnet=10.89.0.0/24" in content


class TestVolumeQuadlet:
    def test_volume_content(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-certs.volume"]
        assert "VolumeName=agentcage-certs-test" in content


class TestDnsQuadlet:
    def test_dns_default_no_log_queries(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-dns.container"]
        assert "ContainerName=test-dns" in content
        assert "Image=localhost/agentcage-dns" in content
        assert "Network=test-net.network:ip=10.89.0.10" in content
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
              mode: allowlist
              list:
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
              mode: allowlist
              list:
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

    def test_dns_no_allowlist_filtering_in_blocklist_mode(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: test:latest
            domains:
              mode: blocklist
              list:
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
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-proxy.container"]
        assert "ExecStartPost=" in content
        assert "nameserver 100.100.100.100" in content
        assert "nameserver 1.1.1.1" in content
        # Proxy should NOT use dnsmasq
        assert "nameserver 10.89.0.10" not in content


class TestCageQuadlet:
    def test_cage_basics(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/home/patches")
        content = files["test-cage.container"]
        assert "ContainerName=test-cage" in content
        assert "Image=localhost/test:latest" in content
        assert "Requires=test-proxy.service" in content
        assert "After=test-proxy.service" in content
        assert 'Environment="HTTP_PROXY=http://10.89.0.11:8080"' in content
        assert 'Environment="HTTPS_PROXY=http://10.89.0.11:8080"' in content
        assert 'Environment="http_proxy=http://10.89.0.11:8080"' in content
        assert 'Environment="https_proxy=http://10.89.0.11:8080"' in content
        assert 'Environment="NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem"' in content
        assert 'Environment="SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem"' in content
        assert 'Environment="NODE_OPTIONS=--import /agentcage/proxy-fetch.mjs"' in content
        assert "Volume=test-certs.volume:/certs:ro,Z" in content
        assert "Volume=/home/patches:/agentcage:ro,Z" in content

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
        assert "Volume=/patches/resolv.conf:/etc/resolv.conf:ro,Z" in content

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
        assert "ip=10.89.0.2" in content
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
        assert "Exec=node openclaw.mjs gateway --allow-unconfigured --bind lan --auth password" in content
        assert "Secret=OPENCLAW_GATEWAY_TOKEN,type=env" in content
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
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        content = files["test-cage.container"]
        assert "Network=test-net.network:ip=10.89.0.2" in content

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
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        assert "--mode regular@10.89.0.11:8080" in proxy
        assert "--mode reverse:http://10.89.0.2:3000@0.0.0.0:3000" in proxy
        assert "PublishPort=127.0.0.1:3000:3000" in proxy

    def test_proxy_no_reverse_without_ports(self, minimal_yaml):
        cfg = load_config(minimal_yaml)
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        assert "--listen-port 8080" in proxy
        assert "--mode" not in proxy
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
        files = generate_quadlets(cfg, "/c.yaml", "/patches")
        proxy = files["test-proxy.container"]
        cage = files["test-cage.container"]
        # Proxy has both reverse modes and both PublishPorts
        assert "--mode reverse:http://10.89.0.2:3000@0.0.0.0:3000" in proxy
        assert "--mode reverse:http://10.89.0.2:9090@0.0.0.0:9090" in proxy
        assert "PublishPort=127.0.0.1:3000:3000" in proxy
        assert "PublishPort=0.0.0.0:9090:9090" in proxy
        # Cage has no PublishPort
        assert "PublishPort=" not in cage
