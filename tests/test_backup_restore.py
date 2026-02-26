"""Tests for cage backup and cage restore CLI commands."""

from __future__ import annotations

import json
import os
import tarfile
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from click.testing import CliRunner

from agentcage.cli import main


def _runner():
    return CliRunner()


def _mock_config(isolation="container", named_volumes=None,
                 secret_injection=None, podman_secrets=None):
    cfg = MagicMock()
    cfg.isolation = isolation
    cfg.name = "test"
    cfg.container.named_volumes = named_volumes or {}
    cfg.container.podman_secrets = podman_secrets or []
    cfg.secret_injection = secret_injection or []
    return cfg


def _build_backup_tarball(tmp_path, *, manifest_overrides=None,
                          include_secrets=False, include_capture=False,
                          include_volumes=None, cage_yaml=None):
    """Build a minimal backup tarball for testing restore."""
    staging = tmp_path / "staging"
    staging.mkdir()

    # Manifest
    manifest = {
        "format_version": 1,
        "agentcage_version": "0.1.0",
        "cage_name": "test",
        "isolation": "container",
        "timestamp": "2026-02-23T14:30:00+00:00",
        "has_secrets": False,
        "has_capture": include_capture,
        "named_volumes": list(include_volumes or []),
        "secret_keys": [],
        "has_data_drive": False,
        "secrets_included": include_secrets,
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)

    (staging / "manifest.json").write_text(json.dumps(manifest))

    # Config
    config_dir = staging / "config"
    config_dir.mkdir()
    yaml_content = cage_yaml or textwrap.dedent("""\
        name: test
        container:
          image: localhost/test:latest
    """)
    (config_dir / "cage.yaml").write_text(yaml_content)

    # Secrets
    if include_secrets:
        secrets_dir = staging / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "API_KEY").write_text("secret-value-1")
        (secrets_dir / "OTHER_KEY").write_text("secret-value-2")

    # Capture
    if include_capture:
        cap_dir = staging / "capture"
        cap_dir.mkdir()
        (cap_dir / "capture.jsonl").write_text('{"test": true}\n')

    # Volumes
    if include_volumes:
        vol_dir = staging / "volumes"
        vol_dir.mkdir()
        for vol_name in include_volumes:
            # Create a minimal tar with a dummy file
            vol_tar_path = vol_dir / f"{vol_name}.tar"
            with tarfile.open(str(vol_tar_path), "w") as vt:
                import io
                data = b"volume-data"
                info = tarfile.TarInfo(name="data.txt")
                info.size = len(data)
                vt.addfile(info, io.BytesIO(data))

    # Build tarball
    tarball_path = tmp_path / "backup.tar.gz"
    with tarfile.open(str(tarball_path), "w:gz") as tar:
        for item in staging.iterdir():
            tar.add(str(item), arcname=f"agentcage-backup/{item.name}")

    return str(tarball_path)


# ── TestPodmanVolume ──────────────────────────────────────


class TestPodmanVolume:
    @patch("agentcage.podman.subprocess.run")
    def test_volume_exists_true(self, mock_run):
        from agentcage.podman import Podman
        mock_run.return_value = MagicMock(returncode=0)
        assert Podman().volume_exists("test-vol") is True
        cmd = mock_run.call_args[0][0]
        assert cmd[-2:] == ["volume", "exists"] or "exists" in cmd

    @patch("agentcage.podman.subprocess.run")
    def test_volume_exists_false(self, mock_run):
        from agentcage.podman import Podman
        mock_run.return_value = MagicMock(returncode=1)
        assert Podman().volume_exists("no-vol") is False

    @patch("builtins.open", create=True)
    @patch("agentcage.podman.subprocess.run")
    def test_volume_export(self, mock_run, mock_open):
        from agentcage.podman import Podman
        Podman().volume_export("test-vol", "/tmp/out.tar")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "volume" in cmd
        assert "export" in cmd
        assert "test-vol" in cmd

    @patch("agentcage.podman.subprocess.run")
    def test_volume_create(self, mock_run):
        from agentcage.podman import Podman
        Podman().volume_create("new-vol")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "volume" in cmd
        assert "create" in cmd
        assert "new-vol" in cmd

    @patch("builtins.open", create=True)
    @patch("agentcage.podman.subprocess.run")
    def test_volume_import(self, mock_run, mock_open):
        from agentcage.podman import Podman
        Podman().volume_import("test-vol", "/tmp/in.tar")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "volume" in cmd
        assert "import" in cmd
        assert "test-vol" in cmd


# ── TestCageBackup ────────────────────────────────────────


class TestCageBackup:
    @patch("agentcage.cli.state")
    def test_backup_nonexistent_cage(self, mock_state):
        mock_state.deployment_exists.return_value = False
        result = _runner().invoke(main, ["cage", "backup", "nope"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_creates_tarball(self, mock_state, MockPodman, tmp_path):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config()
        mock_state.load_deployment_config.return_value = cfg

        # Set up config path
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "cage.yaml").write_text("name: test\n")
        mock_state.stored_config_path.return_value = str(config_dir / "cage.yaml")

        # Empty capture
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        podman = MockPodman.return_value
        podman.secret_list.return_value = []

        out = str(tmp_path / "out.tar.gz")
        result = _runner().invoke(main, ["cage", "backup", "test", "-o", out])
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out)

        # Verify tarball structure
        with tarfile.open(out, "r:gz") as tar:
            names = tar.getnames()
            assert "agentcage-backup/manifest.json" in names
            assert "agentcage-backup/config" in names
            # No secrets dir when not included
            assert not any("secrets" in n for n in names)

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_default_output_name(self, mock_state, MockPodman, tmp_path):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config()
        mock_state.load_deployment_config.return_value = cfg

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "cage.yaml").write_text("name: test\n")
        mock_state.stored_config_path.return_value = str(config_dir / "cage.yaml")
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        podman = MockPodman.return_value
        podman.secret_list.return_value = []

        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = _runner().invoke(main, ["cage", "backup", "test"])
        finally:
            os.chdir(old_cwd)
        assert result.exit_code == 0, result.output
        assert "test-backup-" in result.output
        assert ".tar.gz" in result.output

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_without_secrets_prints_note(self, mock_state, MockPodman, tmp_path):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config()
        mock_state.load_deployment_config.return_value = cfg

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "cage.yaml").write_text("name: test\n")
        mock_state.stored_config_path.return_value = str(config_dir / "cage.yaml")
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        podman = MockPodman.return_value
        podman.secret_list.return_value = []

        out = str(tmp_path / "out.tar.gz")
        result = _runner().invoke(main, ["cage", "backup", "test", "-o", out])
        assert result.exit_code == 0
        assert "not included" in result.output.lower()

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_with_include_secrets(self, mock_state, MockPodman, tmp_path):
        mock_state.deployment_exists.return_value = True
        inj = MagicMock()
        inj.env = "API_KEY"
        cfg = _mock_config(secret_injection=[inj])
        mock_state.load_deployment_config.return_value = cfg

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "cage.yaml").write_text("name: test\n")
        mock_state.stored_config_path.return_value = str(config_dir / "cage.yaml")
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        podman = MockPodman.return_value
        podman.secret_list.return_value = [{"Name": "test.API_KEY"}]
        podman.secret_read.return_value = "sk-12345"

        out = str(tmp_path / "out.tar.gz")
        result = _runner().invoke(
            main, ["cage", "backup", "test", "--include-secrets", "-o", out]
        )
        assert result.exit_code == 0, result.output
        assert "included" in result.output.lower()

        # Verify secrets dir is in tarball
        with tarfile.open(out, "r:gz") as tar:
            names = tar.getnames()
            assert any("secrets/API_KEY" in n for n in names)

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_skips_missing_volume(self, mock_state, MockPodman, tmp_path):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config(named_volumes={"test-vol": "/data:rw"})
        mock_state.load_deployment_config.return_value = cfg

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "cage.yaml").write_text("name: test\n")
        mock_state.stored_config_path.return_value = str(config_dir / "cage.yaml")
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        podman = MockPodman.return_value
        podman.secret_list.return_value = []
        podman.volume_exists.return_value = False

        out = str(tmp_path / "out.tar.gz")
        result = _runner().invoke(main, ["cage", "backup", "test", "-o", out])
        assert result.exit_code == 0, result.output
        assert "does not exist" in result.output.lower()

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_includes_capture(self, mock_state, MockPodman, tmp_path):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config()
        mock_state.load_deployment_config.return_value = cfg

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "cage.yaml").write_text("name: test\n")
        mock_state.stored_config_path.return_value = str(config_dir / "cage.yaml")

        cap_file = tmp_path / "capture.jsonl"
        cap_file.write_text('{"entry": 1}\n')
        mock_state.capture_file.return_value = cap_file

        podman = MockPodman.return_value
        podman.secret_list.return_value = []

        out = str(tmp_path / "out.tar.gz")
        result = _runner().invoke(main, ["cage", "backup", "test", "-o", out])
        assert result.exit_code == 0, result.output

        with tarfile.open(out, "r:gz") as tar:
            names = tar.getnames()
            assert any("capture/capture.jsonl" in n for n in names)

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_no_capture(self, mock_state, MockPodman, tmp_path):
        mock_state.deployment_exists.return_value = True
        cfg = _mock_config()
        mock_state.load_deployment_config.return_value = cfg

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "cage.yaml").write_text("name: test\n")
        mock_state.stored_config_path.return_value = str(config_dir / "cage.yaml")

        # Non-existent capture file
        mock_state.capture_file.return_value = tmp_path / "no-capture.jsonl"

        podman = MockPodman.return_value
        podman.secret_list.return_value = []

        out = str(tmp_path / "out.tar.gz")
        result = _runner().invoke(main, ["cage", "backup", "test", "-o", out])
        assert result.exit_code == 0, result.output
        assert "Capture: no" in result.output


# ── TestCageRestore ───────────────────────────────────────


class TestCageRestore:
    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_restore_basic(self, mock_state, MockPodman, mock_build, tmp_path):
        tarball = _build_backup_tarball(
            tmp_path,
            include_secrets=True,
            manifest_overrides={
                "secret_keys": ["API_KEY", "OTHER_KEY"],
                "secrets_included": True,
            },
        )
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(
            tmp_path / "deploy" / "cage.yaml"
        )
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()

        podman = MockPodman.return_value
        podman.secret_exists.return_value = False

        mock_state.load_deployment_config.return_value = _mock_config()
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(main, ["cage", "restore", tarball])
        assert result.exit_code == 0, result.output
        assert "restored" in result.output.lower()
        mock_build.assert_called_once()

        # Verify secrets were created
        assert podman.secret_create.call_count == 2

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_restore_with_rename(self, mock_state, MockPodman, mock_build, tmp_path):
        tarball = _build_backup_tarball(tmp_path)
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(
            tmp_path / "deploy" / "cage.yaml"
        )
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()

        podman = MockPodman.return_value
        mock_state.load_deployment_config.return_value = _mock_config()
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(
            main, ["cage", "restore", tarball, "--name", "clone01"]
        )
        assert result.exit_code == 0, result.output
        assert "clone01" in result.output

        # Verify save_deployment was called with the new name
        mock_state.save_deployment.assert_called_once()
        call_args = mock_state.save_deployment.call_args
        assert call_args[0][0] == "clone01"

    @patch("agentcage.cli.state")
    def test_restore_existing_without_force(self, mock_state, tmp_path):
        tarball = _build_backup_tarball(tmp_path)
        mock_state.deployment_exists.return_value = True

        result = _runner().invoke(main, ["cage", "restore", tarball])
        assert result.exit_code != 0
        assert "already exists" in result.output

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_restore_existing_with_force(self, mock_state, MockPodman,
                                         mock_get_backend, mock_build, tmp_path):
        tarball = _build_backup_tarball(tmp_path)

        # First call: exists (for force check), then False after destroy
        mock_state.deployment_exists.side_effect = [True, True, False]
        mock_state.stored_config_path.return_value = str(
            tmp_path / "deploy" / "cage.yaml"
        )
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()

        existing_cfg = _mock_config()
        # load_deployment_config called for existing cage then for restored
        mock_state.load_deployment_config.side_effect = [existing_cfg, _mock_config()]

        podman = MockPodman.return_value
        backend = mock_get_backend.return_value
        backend.destroy_resources.return_value = []
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(
            main, ["cage", "restore", tarball, "--force"]
        )
        assert result.exit_code == 0, result.output
        assert "Destroying" in result.output
        mock_build.assert_called_once()

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_restore_no_start(self, mock_state, MockPodman, tmp_path):
        tarball = _build_backup_tarball(tmp_path)
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(
            tmp_path / "deploy" / "cage.yaml"
        )
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()

        podman = MockPodman.return_value
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(
            main, ["cage", "restore", tarball, "--no-start"]
        )
        assert result.exit_code == 0, result.output
        assert "cage update" in result.output.lower()

    @patch("agentcage.cli.state")
    def test_restore_invalid_format_version(self, mock_state, tmp_path):
        tarball = _build_backup_tarball(
            tmp_path, manifest_overrides={"format_version": 99}
        )
        mock_state.deployment_exists.return_value = False

        result = _runner().invoke(main, ["cage", "restore", tarball])
        assert result.exit_code != 0
        assert "unsupported" in result.output.lower()

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_restore_missing_optional_files(self, mock_state, MockPodman,
                                            mock_build, tmp_path):
        """Restore with only manifest + cage.yaml succeeds."""
        tarball = _build_backup_tarball(tmp_path)
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(
            tmp_path / "deploy" / "cage.yaml"
        )
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()

        podman = MockPodman.return_value
        mock_state.load_deployment_config.return_value = _mock_config()
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(main, ["cage", "restore", tarball])
        assert result.exit_code == 0, result.output

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_restore_without_secrets_warns(self, mock_state, MockPodman,
                                           mock_build, tmp_path):
        tarball = _build_backup_tarball(
            tmp_path,
            manifest_overrides={
                "secret_keys": ["API_KEY", "TOKEN"],
                "secrets_included": False,
            },
        )
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(
            tmp_path / "deploy" / "cage.yaml"
        )
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()

        podman = MockPodman.return_value
        podman.secret_exists.return_value = False

        cfg = _mock_config()
        cfg.secret_injection = []
        cfg.container.podman_secrets = []
        mock_state.load_deployment_config.return_value = cfg
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(main, ["cage", "restore", tarball])
        assert result.exit_code == 0, result.output
        assert "agentcage secret set" in result.output
