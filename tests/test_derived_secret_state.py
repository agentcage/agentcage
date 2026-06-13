"""Derived secret-state files (zero-restart groundwork, phase 1).

Covers state.save_placeholders_env / cage_env_dir / runtime_secrets_dir,
the save_proxy_config lockstep, VM-local placeholder paths in quadlet
rendering, and the egress boot-time staging lines.
"""

import os
import textwrap
from unittest.mock import MagicMock

import pytest

from agentcage.config import load_config


def _seed(state, name, body):
    d = state.deployment_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    (d / "cage.yaml").write_text(textwrap.dedent(body))


CFG = """\
    name: {name}
    container:
      image: localhost/test:latest
    dns_servers: ["1.1.1.1"]
    secret_injection:
      - env: KEY_A
        placeholder: "agentcage:secret:KEY_A:0123456789abcdef0123456789abcdef"
      - env: KEY_B
        placeholder: "agentcage:secret:KEY_B:fedcba9876543210fedcba9876543210"
      - env: NOT_FILLED
"""


class TestSavePlaceholdersEnv:

    def test_writes_env_lines_skipping_unfilled(self, patch_state_dirs):
        state = patch_state_dirs
        _seed(state, "c1", CFG.format(name="c1"))
        path = state.save_placeholders_env("c1")
        content = open(path).read()
        assert "KEY_A=agentcage:secret:KEY_A:0123456789abcdef0123456789abcdef\n" in content
        assert "KEY_B=agentcage:secret:KEY_B:fedcba9876543210fedcba9876543210\n" in content
        assert "NOT_FILLED" not in content

    def test_rewrite_in_place_keeps_inode(self, patch_state_dirs):
        """Bind mounts track the inode — the file must be rewritten in
        place, never replaced via rename."""
        state = patch_state_dirs
        _seed(state, "c2", CFG.format(name="c2"))
        path = state.save_placeholders_env("c2")
        inode = os.stat(path).st_ino
        state.save_placeholders_env("c2")
        assert os.stat(path).st_ino == inode

    def test_no_rules_writes_empty_file(self, patch_state_dirs):
        state = patch_state_dirs
        _seed(state, "c3", """\
            name: c3
            container:
              image: localhost/test:latest
        """)
        path = state.save_placeholders_env("c3")
        assert open(path).read() == ""

    def test_save_proxy_config_refreshes_placeholders_env(
        self, patch_state_dirs,
    ):
        """The two cage.yaml-derived files regenerate together — every
        deploy/restart path that calls save_proxy_config gets a fresh
        placeholders.env for free."""
        state = patch_state_dirs
        _seed(state, "c4", CFG.format(name="c4"))
        state.save_proxy_config("c4")
        assert state.placeholders_env_path("c4").is_file()
        assert "KEY_A=" in state.placeholders_env_path("c4").read_text()


class TestRuntimeSecretsDir:

    def test_honors_xdg_runtime_dir(self, tmp_path, monkeypatch):
        from agentcage import state
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
        d = state.runtime_secrets_dir("mycage")
        assert d == tmp_path / "run" / "agentcage" / "mycage" / "secrets"
        assert d.is_dir()
        assert (d.stat().st_mode & 0o777) == 0o700
        assert (d.parent.stat().st_mode & 0o777) == 0o700


class TestVmLocalPlaceholderPaths:

    def test_vm_quadlet_mounts_vm_local_cage_env(self, tmp_path, patch_state_dirs):
        from agentcage.quadlets import generate_quadlets
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: vmtest
            isolation: vm
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
                placeholder: "agentcage:secret:MY_KEY:0123456789abcdef0123456789abcdef"
        """))
        cfg = load_config(str(p))
        units = generate_quadlets(
            cfg, str(tmp_path / "proxy-config.yaml"), str(tmp_path), "vmtest",
        )
        cage_unit = units["vmtest-cage.container"]
        # %h expands inside the VM; the path is the VM-local copy pushed
        # by backends.vm.push_config_files (reverse-sshfs caching would
        # hide host-side rewrites of the host path).
        assert (
            "EnvironmentFile=%h/.config/agentcage-vm/cages/vmtest"
            "/cage-env/placeholders.env" in cage_unit
        )
        assert (
            "Volume=%h/.config/agentcage-vm/cages/vmtest/cage-env"
            ":/run/agentcage/env:ro,Z" in cage_unit
        )

    def test_push_config_files_pushes_placeholders_env(self, patch_state_dirs):
        from agentcage.backends.vm import push_config_files
        state = patch_state_dirs
        _seed(state, "vmpush", CFG.format(name="vmpush"))
        state.save_proxy_config("vmpush")
        state.save_dns_allowlist("vmpush")

        inst = MagicMock()
        inst.exec.return_value = MagicMock(stdout="/home/user\n")
        push_config_files("vmpush", inst)

        cmds = [" ".join(c.args[0]) for c in inst.exec.call_args_list]
        assert any("cage-env/placeholders.env" in c for c in cmds), cmds
        assert any(
            "mkdir -p" in c and "cage-env" in c for c in cmds
        ), cmds


class TestEgressStaging:

    def test_staging_lines_per_secret_with_deploy_prefix(
        self, tmp_path, patch_state_dirs,
    ):
        from agentcage.quadlets import generate_quadlets
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: stagetest
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: KEY_A
                placeholder: "agentcage:secret:KEY_A:0123456789abcdef0123456789abcdef"
              - env: KEY_B
                placeholder: "agentcage:secret:KEY_B:fedcba9876543210fedcba9876543210"
        """))
        cfg = load_config(str(p))
        units = generate_quadlets(
            cfg, str(tmp_path / "proxy-config.yaml"), str(tmp_path),
            "stagetest",
        )
        egress = units["stagetest-egress.container"]
        # tmpfs staging dir mounted RO at the injector's file-fallback path
        assert (
            "Volume=%t/agentcage/stagetest/secrets"
            ":/home/acproxy/secrets:ro,Z" in egress
        )
        # one non-fatal staging line per declared secret, deploy-prefixed
        assert '"stagetest.KEY_A"' in egress
        assert '"stagetest.KEY_B"' in egress
        assert egress.count("podman secret inspect --showsecret") == 2
        # mkdir is fatal (mount source must exist); staging lines are not
        assert (
            "ExecStartPre=/bin/bash -c 'umask 077; mkdir -p"
            ' "%t/agentcage/stagetest/secrets"' in egress
        )
        assert "ExecStartPre=-/bin/bash -c 'umask 077; f=" in egress
        # On inspect failure the staged file is removed, never left empty:
        # an empty file is a tombstone to the injector, which on pre-4.7
        # podman (no --showsecret) would disable every rule instead of
        # falling back to the env channel. printf's format must be %%s in
        # the unit text — bare %s is a systemd specifier (user shell) and
        # would be expanded before the shell ever runs.
        assert egress.count('then printf %%s "$v" > "$f"; else rm -f "$f"; fi') == 2
        assert 'printf %s' not in egress
        # acproxy (uid 200) must be able to read the 0600 files
        assert 'chown -R 200:200" "%t/agentcage/stagetest/secrets"' in egress \
            or "chown -R 200:200" in egress

    def test_no_secrets_no_staging(self, tmp_path, patch_state_dirs):
        from agentcage.quadlets import generate_quadlets
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: nostage
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
        """))
        cfg = load_config(str(p))
        units = generate_quadlets(
            cfg, str(tmp_path / "proxy-config.yaml"), str(tmp_path), "nostage",
        )
        egress = units["nostage-egress.container"]
        assert "/home/acproxy/secrets" not in egress
        assert "--showsecret" not in egress
