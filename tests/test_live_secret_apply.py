"""Live secret apply (zero-restart, phase 2).

Covers the injector's staged-file-first precedence (including the
empty-file tombstone), services.cage_has_live_secret_channel feature
detection, services.stage_secret_value, and the secret set/rm CLI flow
choosing live-apply over restart.
"""

import textwrap
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def injector(monkeypatch, tmp_path):
    """A SecretInjector whose staged-secrets dir points at tmp_path."""
    from agentcage.data.proxy import secret_injector as si
    monkeypatch.setattr(si, "_SECRETS_DIR", tmp_path)
    return si.SecretInjector(), tmp_path


RULE = {"env": "MY_KEY", "placeholder": "{{placeholder_my_key_0123456789abcdef}}"}


class TestInjectorFilePrecedence:

    def test_staged_file_wins_over_env(self, injector, monkeypatch):
        """The process env is frozen at container creation — a live value
        change can only arrive via the staged file, so the file must win."""
        inj, secrets_dir = injector
        monkeypatch.setenv("MY_KEY", "stale-env-value")
        (secrets_dir / "MY_KEY").write_text("fresh-staged-value\n")
        inj.configure([RULE])
        assert len(inj.rules) == 1
        assert inj.rules[0].real_value == "fresh-staged-value"

    def test_missing_file_falls_back_to_env(self, injector, monkeypatch):
        inj, _ = injector
        monkeypatch.setenv("MY_KEY", "env-value")
        inj.configure([RULE])
        assert len(inj.rules) == 1
        assert inj.rules[0].real_value == "env-value"

    def test_empty_file_is_tombstone_not_env_fallback(
        self, injector, monkeypatch,
    ):
        """`secret rm` stages an empty file. Falling back to the stale env
        value would keep injecting a removed secret."""
        inj, secrets_dir = injector
        monkeypatch.setenv("MY_KEY", "stale-env-value")
        (secrets_dir / "MY_KEY").write_text("")
        inj.configure([RULE])
        assert inj.rules == []

    def test_reconfigure_picks_up_new_file_content(self, injector, monkeypatch):
        """configure() runs on every proxy-config mtime bump — a re-staged
        value must be re-read, not cached."""
        inj, secrets_dir = injector
        monkeypatch.delenv("MY_KEY", raising=False)
        (secrets_dir / "MY_KEY").write_text("v1\n")
        inj.configure([RULE])
        assert inj.rules[0].real_value == "v1"
        (secrets_dir / "MY_KEY").write_text("v2\n")
        inj.configure([RULE])
        assert inj.rules[0].real_value == "v2"


class TestLiveChannelDetection:

    def _cfg(self, isolation="container"):
        cfg = MagicMock()
        cfg.isolation = isolation
        return cfg

    def test_detects_staging_mount_in_unit(self, tmp_path):
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg()
        backend = MagicMock()
        backend.unit_dir.return_value = tmp_path
        (tmp_path / "c1-egress.container").write_text(
            "Volume=%t/agentcage/c1/secrets:/home/acproxy/secrets:ro,Z\n"
        )
        with patch("agentcage.services.get_backend", return_value=backend):
            assert cage_has_live_secret_channel("c1", cfg) is True

    def test_pre_feature_unit_lacks_channel(self, tmp_path):
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg()
        backend = MagicMock()
        backend.unit_dir.return_value = tmp_path
        (tmp_path / "c1-egress.container").write_text(
            "Secret=c1.MY_KEY,type=env\n"
        )
        with patch("agentcage.services.get_backend", return_value=backend):
            assert cage_has_live_secret_channel("c1", cfg) is False

    def test_missing_unit_means_no_channel(self, tmp_path):
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg()
        backend = MagicMock()
        backend.unit_dir.return_value = tmp_path
        with patch("agentcage.services.get_backend", return_value=backend):
            assert cage_has_live_secret_channel("c1", cfg) is False

    def test_apple_container_not_live(self, tmp_path):
        from agentcage.services import cage_has_live_secret_channel
        assert cage_has_live_secret_channel(
            "c1", self._cfg("apple-container"),
        ) is False

    def test_vm_quadlets_subdir_layout(self, tmp_path):
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg("vm")
        backend = MagicMock()
        backend.unit_dir.return_value = tmp_path
        (tmp_path / "quadlets").mkdir()
        (tmp_path / "quadlets" / "c1-egress.container").write_text(
            "Volume=%t/agentcage/c1/secrets:/home/acproxy/secrets:ro,Z\n"
        )
        with patch("agentcage.services.get_backend", return_value=backend):
            assert cage_has_live_secret_channel("c1", cfg) is True


class TestStageSecretValue:

    def test_container_backend_writes_via_podman_unshare(
        self, tmp_path, monkeypatch,
    ):
        from agentcage import services
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        cfg = MagicMock()
        cfg.isolation = "container"
        with patch("subprocess.run") as run:
            run.return_value = MagicMock(returncode=0)
            services.stage_secret_value(cfg, "c1", "MY_KEY", "v1")
        argv = run.call_args.args[0]
        assert argv[:2] == ["podman", "unshare"]
        assert str(tmp_path / "agentcage" / "c1" / "secrets" / "MY_KEY") \
            in argv
        assert run.call_args.kwargs["input"] == b"v1"
        # The value must travel via stdin, never argv (visible in /proc).
        assert "v1" not in " ".join(argv)

    def test_container_staging_does_no_host_fs_ops(
        self, tmp_path, monkeypatch,
    ):
        """Regression (#260 CI): after the egress's first start the staging
        dir is owned by the acproxy subuid (quadlet `podman unshare chown
        -R 200:200`), so any host-side mkdir/chmod EPERMs — every
        filesystem operation must happen inside `podman unshare`."""
        from agentcage import services
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        cfg = MagicMock()
        cfg.isolation = "container"
        with patch("subprocess.run") as run:
            run.return_value = MagicMock(returncode=0)
            services.stage_secret_value(cfg, "c1", "MY_KEY", "v1")
        assert list(tmp_path.iterdir()) == []

    def test_vm_backend_writes_via_guest_exec(self, monkeypatch):
        from agentcage import services
        cfg = MagicMock()
        cfg.isolation = "vm"
        inst = MagicMock()
        inst.exec.return_value = MagicMock(stdout="/run/user/1000\n")
        with patch("agentcage.lima.instance.LimaInstance", return_value=inst):
            services.stage_secret_value(cfg, "c1", "MY_KEY", "v1")
        write_call = inst.exec.call_args_list[-1]
        argv = write_call.args[0]
        assert argv[:2] == ["podman", "unshare"]
        assert "/run/user/1000/agentcage/c1/secrets/MY_KEY" in argv
        assert write_call.kwargs["input"] == "v1"
        assert "v1" not in " ".join(argv)


class TestSecretSetLiveFlow:

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.services.stage_secret_value")
    @patch("agentcage.services.cage_has_live_secret_channel", return_value=True)
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.get_backend")
    def test_set_applies_live_without_restart(
        self, mock_backend, _podman, _store, _channel, mock_stage,
        mock_restart, patch_state_dirs,
    ):
        from click.testing import CliRunner
        from agentcage.cli import main
        state = patch_state_dirs
        d = state.deployment_dir("c1")
        d.mkdir(parents=True, exist_ok=True)
        (d / "cage.yaml").write_text(textwrap.dedent("""\
            name: c1
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
            secret_injection:
              - env: MY_KEY
                placeholder: "{{placeholder_my_key_0123456789abcdef}}"
        """))
        meta = state.load_metadata("c1")
        meta["agentcage_version"] = "0.22.22"
        state.save_metadata("c1", meta)
        mock_backend.return_value.is_running.return_value = True

        result = CliRunner().invoke(
            main, ["secret", "set", "c1", "MY_KEY"], input="new-value\n",
        )
        assert result.exit_code == 0, result.output
        mock_stage.assert_called_once()
        assert mock_stage.call_args.args[1:] == ("c1", "MY_KEY", "new-value")
        mock_restart.assert_not_called()
        assert "without a restart" in result.output
        # The mtime bump that triggers the proxy's hot reload happened.
        assert (d / "proxy-config.yaml").is_file()

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.services.stage_secret_value",
           side_effect=RuntimeError("boom"))
    @patch("agentcage.services.cage_has_live_secret_channel", return_value=True)
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.get_backend")
    def test_set_falls_back_to_restart_on_staging_failure(
        self, mock_backend, _podman, _store, _channel, _stage,
        mock_restart, patch_state_dirs,
    ):
        from click.testing import CliRunner
        from agentcage.cli import main
        state = patch_state_dirs
        d = state.deployment_dir("c1")
        d.mkdir(parents=True, exist_ok=True)
        (d / "cage.yaml").write_text(textwrap.dedent("""\
            name: c1
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
        """))
        meta = state.load_metadata("c1")
        meta["agentcage_version"] = "0.22.22"
        state.save_metadata("c1", meta)
        mock_backend.return_value.is_running.return_value = True

        result = CliRunner().invoke(
            main, ["secret", "set", "c1", "MY_KEY"], input="new-value\n",
        )
        assert result.exit_code == 0, result.output
        mock_restart.assert_called_once()
        assert "falling back to restart" in result.output

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.services.stage_secret_value")
    @patch("agentcage.services.cage_has_live_secret_channel",
           return_value=False)
    @patch("agentcage.cli._store_secret")
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.get_backend")
    def test_set_restarts_pre_feature_cage(
        self, mock_backend, _podman, _store, _channel, mock_stage,
        mock_restart, patch_state_dirs,
    ):
        from click.testing import CliRunner
        from agentcage.cli import main
        state = patch_state_dirs
        d = state.deployment_dir("c1")
        d.mkdir(parents=True, exist_ok=True)
        (d / "cage.yaml").write_text(textwrap.dedent("""\
            name: c1
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
        """))
        meta = state.load_metadata("c1")
        meta["agentcage_version"] = "0.22.22"
        state.save_metadata("c1", meta)
        mock_backend.return_value.is_running.return_value = True

        result = CliRunner().invoke(
            main, ["secret", "set", "c1", "MY_KEY"], input="new-value\n",
        )
        assert result.exit_code == 0, result.output
        mock_stage.assert_not_called()
        mock_restart.assert_called_once()

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.services.stage_secret_value")
    @patch("agentcage.services.cage_has_live_secret_channel", return_value=True)
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.get_backend")
    def test_rm_stages_tombstone(
        self, mock_backend, mock_podman, _channel, mock_stage,
        mock_restart, patch_state_dirs,
    ):
        from click.testing import CliRunner
        from agentcage.cli import main
        state = patch_state_dirs
        d = state.deployment_dir("c1")
        d.mkdir(parents=True, exist_ok=True)
        (d / "cage.yaml").write_text(textwrap.dedent("""\
            name: c1
            container:
              image: localhost/test:latest
            dns_servers: ["1.1.1.1"]
        """))
        meta = state.load_metadata("c1")
        meta["agentcage_version"] = "0.22.22"
        state.save_metadata("c1", meta)
        mock_backend.return_value.is_running.return_value = True
        mock_podman.return_value.secret_exists.return_value = True

        result = CliRunner().invoke(main, ["secret", "rm", "c1", "MY_KEY"])
        assert result.exit_code == 0, result.output
        assert mock_stage.call_args.args[1:] == ("c1", "MY_KEY", "")
        mock_restart.assert_not_called()


class TestAddonReloadReconfiguresInjector:
    """Regression (#261 CI, e2e 3.4e): the injector is NOT part of the
    inspector chain (inspectors must see placeholders; injection happens
    after them), so the reload loop over self.inspectors never reached it.
    Rules declared after start never loaded, and re-staged values were
    never re-read — the entire live-update mechanism depends on
    _maybe_reload reconfiguring the injector."""

    def _write_cfg(self, path, rules):
        import yaml
        path.write_text(yaml.safe_dump({"secret_injection": rules}))

    def test_reload_picks_up_new_rule_and_restaged_value(
        self, tmp_path, monkeypatch,
    ):
        import os
        # The addon does `from secret_injector import SecretInjector` (the
        # proxy dir is on sys.path inside the container and in conftest) —
        # patch THAT module instance, not the package-path twin.
        from agentcage.data.proxy import addon as addon_mod
        import secret_injector as si

        secrets_dir = tmp_path / "staged"
        secrets_dir.mkdir()
        monkeypatch.setattr(si, "_SECRETS_DIR", secrets_dir)
        cfg_path = tmp_path / "config.yaml"
        rule_a = {"env": "KEY_A",
                  "placeholder": "{{placeholder_key_a_0123456789abcdef}}"}
        self._write_cfg(cfg_path, [rule_a])
        (secrets_dir / "KEY_A").write_text("a-v1\n")
        monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))

        addon = addon_mod.Agentcage()
        addon.load(loader=None)
        assert [r.name for r in addon.injector.rules] == ["KEY_A"]
        assert addon.injector.rules[0].real_value == "a-v1"

        # Live update: new rule declared + value staged + existing value
        # re-staged; the config rewrite bumps the mtime.
        rule_b = {"env": "KEY_B",
                  "placeholder": "{{placeholder_key_b_fedcba9876543210}}"}
        (secrets_dir / "KEY_A").write_text("a-v2\n")
        (secrets_dir / "KEY_B").write_text("b-v1\n")
        self._write_cfg(cfg_path, [rule_a, rule_b])
        os.utime(cfg_path, (0, os.stat(cfg_path).st_mtime + 5))

        addon._maybe_reload()
        by_name = {r.name: r.real_value for r in addon.injector.rules}
        assert by_name == {"KEY_A": "a-v2", "KEY_B": "b-v1"}

    def test_reload_with_rules_removed_clears_injector(
        self, tmp_path, monkeypatch,
    ):
        import os
        # The addon does `from secret_injector import SecretInjector` (the
        # proxy dir is on sys.path inside the container and in conftest) —
        # patch THAT module instance, not the package-path twin.
        from agentcage.data.proxy import addon as addon_mod
        import secret_injector as si

        secrets_dir = tmp_path / "staged"
        secrets_dir.mkdir()
        monkeypatch.setattr(si, "_SECRETS_DIR", secrets_dir)
        cfg_path = tmp_path / "config.yaml"
        rule = {"env": "KEY_A",
                "placeholder": "{{placeholder_key_a_0123456789abcdef}}"}
        self._write_cfg(cfg_path, [rule])
        (secrets_dir / "KEY_A").write_text("a-v1\n")
        monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))

        addon = addon_mod.Agentcage()
        addon.load(loader=None)
        assert len(addon.injector.rules) == 1

        self._write_cfg(cfg_path, [])
        os.utime(cfg_path, (0, os.stat(cfg_path).st_mtime + 5))
        addon._maybe_reload()
        assert addon.injector.rules == []
