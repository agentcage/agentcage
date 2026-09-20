"""Live secret apply (zero-restart, phase 2) — host side.

Covers ``services.cage_has_live_secret_channel`` feature detection,
``services.stage_secret_value``, and the ``secret set`` / ``secret rm`` CLI flow
choosing live-apply over restart.

Boundary note (RUST-PORT-PLAN.md §2.4): the injector half — the staged-file
precedence and the addon's reload path, both inside the egress container — stays
Python and lives in ``tests/test_live_secret_apply_proxy.py``.
"""

import textwrap
from unittest.mock import MagicMock, patch



class TestLiveChannelDetection:

    def _cfg(self, isolation="container"):
        cfg = MagicMock()
        cfg.isolation = isolation
        return cfg

    def test_detects_staging_mount_on_running_egress(self):
        """Detection inspects the RUNNING container, not the installed
        unit files — units may have been converged after the container
        started, and a live-staged value can only reach a proxy whose
        container actually has the mount."""
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg()
        podman = MagicMock()
        podman.container_inspect.return_value = {
            "Mounts": [{"Destination": "/home/acproxy/secrets"}],
        }
        with patch("agentcage.services.Podman", return_value=podman):
            assert cage_has_live_secret_channel("c1", cfg) is True
        podman.container_inspect.assert_called_once_with("c1-egress")

    def test_pre_feature_container_lacks_channel(self):
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg()
        podman = MagicMock()
        podman.container_inspect.return_value = {
            "Mounts": [{"Destination": "/etc/agentcage/config.yaml"}],
        }
        with patch("agentcage.services.Podman", return_value=podman):
            assert cage_has_live_secret_channel("c1", cfg) is False

    def test_inspect_failure_means_no_channel(self):
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg()
        podman = MagicMock()
        podman.container_inspect.side_effect = RuntimeError("no container")
        with patch("agentcage.services.Podman", return_value=podman):
            assert cage_has_live_secret_channel("c1", cfg) is False

    def test_apple_container_not_live(self):
        from agentcage.services import cage_has_live_secret_channel
        assert cage_has_live_secret_channel(
            "c1", self._cfg("apple-container"),
        ) is False

    def test_vm_uses_guest_podman(self):
        from agentcage.services import cage_has_live_secret_channel
        cfg = self._cfg("vm")
        podman = MagicMock()
        podman.container_inspect.return_value = {
            "Mounts": [{"Destination": "/home/acproxy/secrets"}],
        }
        with patch("agentcage.lima.podman.VmPodman", return_value=podman):
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
                placeholder: "agentcage:secret:MY_KEY:0123456789abcdef0123456789abcdef"
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

    @patch("agentcage.cli._restart_cage")
    @patch("agentcage.services.stage_secret_value")
    @patch("agentcage.services.cage_has_live_secret_channel", return_value=True)
    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.get_backend")
    def test_rm_removes_cred_blob_without_store_entry(
        self, mock_backend, mock_podman, _channel, mock_stage,
        mock_restart, patch_state_dirs,
    ):
        """systemd-creds-backed secret set live on a running cage: the
        podman store entry doesn't exist yet (it only materializes at the
        egress decrypt ExecStartPre). `secret rm` must still succeed,
        delete the .cred blob — a lingering blob resurrects the secret on
        the next egress start — and stage the tombstone."""
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
        cred = d / "creds" / "MY_KEY.cred"
        cred.parent.mkdir(parents=True, exist_ok=True)
        cred.write_bytes(b"encrypted-blob")
        mock_backend.return_value.is_running.return_value = True
        mock_podman.return_value.secret_exists.return_value = False

        result = CliRunner().invoke(main, ["secret", "rm", "c1", "MY_KEY"])
        assert result.exit_code == 0, result.output
        assert not cred.exists()
        mock_podman.return_value.secret_remove.assert_not_called()
        assert mock_stage.call_args.args[1:] == ("c1", "MY_KEY", "")
        mock_restart.assert_not_called()

    @patch("agentcage.cli._podman_for_cage")
    @patch("agentcage.cli.get_backend")
    def test_rm_nonexistent_secret_still_errors(
        self, mock_backend, mock_podman, patch_state_dirs,
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
        mock_podman.return_value.secret_exists.return_value = False

        result = CliRunner().invoke(main, ["secret", "rm", "c1", "NOPE"])
        assert result.exit_code == 1
        assert "does not exist" in result.output
