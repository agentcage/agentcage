"""Tests for Firecracker rootfs — startup script and data drive."""

from __future__ import annotations

import os
import textwrap

import pytest

from agentcage.config import (
    Config, ContainerConfig, FirecrackerConfig,
    SecretInjectionRule, DomainConfig, LoggingConfig,
)
from agentcage.firecracker.rootfs import (
    _generate_startup_script, _shell_quote,
    ensure_data_drive, data_drive_path,
)


def _make_config(**overrides) -> Config:
    """Build a Config with sensible defaults, applying overrides."""
    cc_kwargs = {
        "image": "localhost/test:latest",
        "command": ["node", "app.js"],
    }
    cc_overrides = overrides.pop("container", {})
    cc_kwargs.update(cc_overrides)

    kwargs: dict = {
        "name": "testcage",
        "isolation": "firecracker",
        "container": ContainerConfig(**cc_kwargs),
        "firecracker": FirecrackerConfig(kernel="/opt/vmlinux", vcpus=2, mem_mb=2048),
        "dns_servers": ["1.1.1.1", "8.8.8.8"],
        "domains": DomainConfig(),
        "logging": LoggingConfig(),
        "secret_injection": [],
    }
    kwargs.update(overrides)
    return Config(**kwargs)


class TestShellQuote:
    def test_simple_string(self):
        assert _shell_quote("hello") == "hello"

    def test_string_with_equals(self):
        assert _shell_quote("KEY=value") == "KEY=value"

    def test_string_with_spaces(self):
        assert _shell_quote("hello world") == "'hello world'"

    def test_empty_string(self):
        assert _shell_quote("") == "''"

    def test_string_with_single_quote(self):
        result = _shell_quote("it's")
        assert "it" in result and "s" in result

    def test_path_with_slashes(self):
        assert _shell_quote("/tmp:rw,noexec") == "/tmp:rw,noexec"


class TestGenerateStartupScript:
    def test_basic_structure(self):
        cfg = _make_config()
        script = _generate_startup_script(cfg, "testcage")
        assert "#!/bin/bash" in script
        assert "CAGE_NAME=" in script
        assert "podman run" in script

    def test_contains_agent_image(self):
        cfg = _make_config()
        script = _generate_startup_script(cfg, "testcage")
        assert "localhost/test:latest" in script

    def test_contains_agent_command(self):
        cfg = _make_config()
        script = _generate_startup_script(cfg, "testcage")
        assert "node app.js" in script

    def test_env_vars_in_script(self):
        cfg = _make_config(container={"env": {"FOO": "bar", "BAZ": "qux"}})
        script = _generate_startup_script(cfg, "testcage")
        assert "FOO=bar" in script
        assert "BAZ=qux" in script

    def test_tmpfs_in_script(self):
        cfg = _make_config(container={"tmpfs": ["/tmp:rw,noexec,nosuid,size=64M"]})
        script = _generate_startup_script(cfg, "testcage")
        assert "--tmpfs /tmp:rw,noexec,nosuid,size=64M" in script

    def test_named_volumes_setup(self):
        cfg = _make_config(container={
            "named_volumes": {"mydata": "/data:rw"},
        })
        script = _generate_startup_script(cfg, "testcage")
        assert "mkdir -p /mnt/data/mydata" in script
        assert "podman volume create" in script
        assert "-v mydata:/data:rw" in script

    def test_cage_no_published_ports(self):
        """Cage container should NOT have -p flags — ports go through proxy."""
        cfg = _make_config(container={"ports": ["127.0.0.1:8080:8080"]})
        script = _generate_startup_script(cfg, "testcage")
        # Extract cage podman run command
        cage_run_start = script.index("starting cage container")
        cage_run = script[cage_run_start:script.index("\n\necho \"start-cage: all", cage_run_start)]
        assert " -p " not in cage_run

    def test_capabilities_drop(self):
        cfg = _make_config(container={"drop_capabilities": ["ALL"]})
        script = _generate_startup_script(cfg, "testcage")
        assert "--cap-drop ALL" in script

    def test_capabilities_add(self):
        cfg = _make_config(container={
            "drop_capabilities": [],
            "add_capabilities": ["NET_BIND_SERVICE"],
        })
        script = _generate_startup_script(cfg, "testcage")
        assert "--cap-add NET_BIND_SERVICE" in script

    def test_resource_limits(self):
        cfg = _make_config(container={"memory": "4g", "cpus": "2.0"})
        script = _generate_startup_script(cfg, "testcage")
        assert "--memory 4g" in script
        assert "--cpus 2.0" in script

    def test_no_resource_limits_when_empty(self):
        cfg = _make_config(container={"memory": "", "cpus": ""})
        script = _generate_startup_script(cfg, "testcage")
        assert "--memory" not in script
        assert "--cpus" not in script

    def test_user(self):
        cfg = _make_config(container={"user": "1000:1000"})
        script = _generate_startup_script(cfg, "testcage")
        assert "-u 1000:1000" in script

    def test_no_user_when_empty(self):
        cfg = _make_config(container={"user": ""})
        script = _generate_startup_script(cfg, "testcage")
        # Should not have a -u flag with empty value
        assert "\n    -u " not in script

    def test_read_only(self):
        cfg = _make_config(container={"read_only": True})
        script = _generate_startup_script(cfg, "testcage")
        assert "--read-only" in script

    def test_no_read_only(self):
        cfg = _make_config(container={"read_only": False})
        script = _generate_startup_script(cfg, "testcage")
        assert "--read-only" not in script

    def test_no_new_privileges(self):
        cfg = _make_config(container={"no_new_privileges": True})
        script = _generate_startup_script(cfg, "testcage")
        assert "--security-opt no-new-privileges" in script

    def test_security_label_disable(self):
        cfg = _make_config(container={"security_label_disable": True})
        script = _generate_startup_script(cfg, "testcage")
        assert "--security-opt label=disable" in script

    def test_podman_secrets(self):
        cfg = _make_config(container={"podman_secrets": ["MY_TOKEN", "MY_KEY"]})
        script = _generate_startup_script(cfg, "testcage")
        assert "--secret MY_TOKEN,type=env,target=MY_TOKEN" in script
        assert "--secret MY_KEY,type=env,target=MY_KEY" in script

    def test_secret_injection_placeholder(self):
        cfg = _make_config(
            secret_injection=[
                SecretInjectionRule(
                    env="API_KEY",
                    placeholder="{{API_KEY}}",
                    inject_to=["api.example.com"],
                ),
            ],
        )
        script = _generate_startup_script(cfg, "testcage")
        # Cage should see the placeholder
        assert "API_KEY={{API_KEY}}" in script

    def test_secret_injection_on_proxy(self):
        cfg = _make_config(
            secret_injection=[
                SecretInjectionRule(
                    env="API_KEY",
                    placeholder="{{API_KEY}}",
                    inject_to=["api.example.com"],
                ),
            ],
        )
        script = _generate_startup_script(cfg, "testcage")
        # Proxy should get the real secret
        assert "--secret API_KEY,type=env,target=API_KEY" in script

    def test_port_forward_socat(self):
        """Ports should use socat forwarding to the proxy container."""
        cfg = _make_config(container={"ports": ["127.0.0.1:3000:3000", "8080:8080"]})
        script = _generate_startup_script(cfg, "testcage")
        assert "socat TCP-LISTEN:3000,bind=0.0.0.0,fork,reuseaddr TCP:10.89.0.11:3000 &" in script
        assert "socat TCP-LISTEN:8080,bind=0.0.0.0,fork,reuseaddr TCP:10.89.0.11:8080 &" in script

    def test_no_port_forward_without_ports(self):
        cfg = _make_config(container={"ports": []})
        script = _generate_startup_script(cfg, "testcage")
        assert "socat TCP-LISTEN" not in script
        # The external network MASQUERADE should still be there
        assert "POSTROUTING -s 10.90.0.0/24" in script

    def test_host_volumes_warning(self):
        cfg = _make_config(container={"volumes": ["./data:/data:rw"]})
        script = _generate_startup_script(cfg, "testcage")
        assert "WARNING: host volume mount not supported" in script
        assert "./data:/data:rw" in script

    def test_dns_servers_from_config(self):
        cfg = _make_config(dns_servers=["100.100.100.100", "1.1.1.1"])
        script = _generate_startup_script(cfg, "testcage")
        assert "--server 100.100.100.100" in script
        assert "--server 1.1.1.1" in script

    def test_dns_servers_fallback(self):
        cfg = _make_config(dns_servers=[])
        script = _generate_startup_script(cfg, "testcage")
        assert "--server 1.1.1.1" in script
        assert "--server 8.8.8.8" in script

    def test_domain_allowlist(self):
        cfg = _make_config(
            dns_servers=["1.1.1.1"],
            domains=DomainConfig(mode="allowlist", list=["example.com"]),
        )
        script = _generate_startup_script(cfg, "testcage")
        assert "--address=/#/198.51.100.1" in script
        assert "--server=/example.com/1.1.1.1" in script

    def test_proxy_quiet_mode(self):
        cfg = _make_config(logging=LoggingConfig(allowed_requests=False))
        script = _generate_startup_script(cfg, "testcage")
        assert "--quiet" in script

    def test_proxy_verbose_mode(self):
        cfg = _make_config(logging=LoggingConfig(allowed_requests=True))
        script = _generate_startup_script(cfg, "testcage")
        assert "--quiet" not in script

    def test_proxy_reverse_mode_in_script(self):
        """Proxy should use multi-mode with reverse listeners for each port."""
        cfg = _make_config(container={"ports": ["127.0.0.1:3000:3000", "9090:9090"]})
        script = _generate_startup_script(cfg, "testcage")
        assert "--mode regular@10.89.0.11:8080" in script
        assert "--mode reverse:http://10.89.0.2:3000@0.0.0.0:3000" in script
        assert "--mode reverse:http://10.89.0.2:9090@0.0.0.0:9090" in script

    def test_proxy_no_reverse_without_ports(self):
        """Without ports, proxy should use simple --listen-port form."""
        cfg = _make_config(container={"ports": []})
        script = _generate_startup_script(cfg, "testcage")
        assert "--listen-port 8080" in script
        assert "--mode" not in script

    def test_full_config_script(self):
        """Integration test: a realistic config should produce a valid-looking script."""
        cfg = _make_config(
            container={
                "image": "localhost/openclaw:latest",
                "command": ["node", "gateway.js"],
                "volumes": ["/host/path:/container:ro"],
                "named_volumes": {"state": "/home/node/.state:rw"},
                "tmpfs": ["/tmp:rw,noexec,size=1G"],
                "ports": ["127.0.0.1:18789:18789"],
                "env": {"DISABLE_BONJOUR": "1"},
                "podman_secrets": ["TOKEN"],
                "memory": "8g",
                "cpus": "4.0",
                "user": "1000:1000",
                "read_only": True,
                "drop_capabilities": ["ALL"],
                "add_capabilities": ["NET_BIND_SERVICE"],
                "no_new_privileges": True,
                "security_label_disable": True,
            },
            secret_injection=[
                SecretInjectionRule(env="API_KEY", placeholder="{{API_KEY}}"),
            ],
            dns_servers=["100.100.100.100"],
        )
        script = _generate_startup_script(cfg, "testcage")
        # Should contain all the key elements
        assert "localhost/openclaw:latest" in script
        # Proxy should have reverse mode for port 18789
        assert "--mode reverse:http://10.89.0.2:18789@0.0.0.0:18789" in script
        # socat forwards to proxy, not cage
        assert "socat TCP-LISTEN:18789,bind=0.0.0.0,fork,reuseaddr TCP:10.89.0.11:18789 &" in script
        assert "--memory 8g" in script
        assert "--cap-drop ALL" in script
        assert "--cap-add NET_BIND_SERVICE" in script
        assert "--secret TOKEN,type=env,target=TOKEN" in script
        assert "API_KEY={{API_KEY}}" in script
        assert "WARNING: host volume mount" in script
        assert "mkdir -p /mnt/data/state" in script


class TestEnsureDataDrive:
    def test_creates_data_drive(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        path = ensure_data_drive("testdrive", size_mb=4)
        assert os.path.isfile(path)
        assert path.endswith("data.ext4")

    def test_preserves_existing_drive(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        path1 = ensure_data_drive("testdrive", size_mb=4)
        # Write a marker to verify it's not overwritten
        size1 = os.path.getsize(path1)
        path2 = ensure_data_drive("testdrive", size_mb=8)
        assert path1 == path2
        # Size should be same as original (4MB), not 8MB
        assert os.path.getsize(path2) == size1

    def test_data_drive_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        path = data_drive_path("myagent")
        assert "myagent" in path
        assert path.endswith("data.ext4")
