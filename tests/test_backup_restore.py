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


# ── TestBackupBuildContext ────────────────────────────────

_CAGE_YAML_BUILD = textwrap.dedent("""\
    name: test
    container:
      build:
        containerfile: Containerfile
""")

_CAGE_YAML_NO_BUILD = textwrap.dedent("""\
    name: test
    container:
      image: localhost/test:latest
""")


def _fake_state_dir(root: Path, *, cage_yaml: str, containerfile: bool = True):
    """A cage state dir shaped like the real thing (generated files and all)."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "cage.yaml").write_text(cage_yaml)
    (root / "metadata.json").write_text('{"scaffold": "test"}')
    (root / "proxy-config.yaml").write_text("listen: 8080\n")
    # Generated siblings every state dir has.
    (root / "dns-allowlist.conf").write_text("server=/example.com/1.1.1.1\n")
    (root / "fingerprint.json").write_text('{"version": 1, "fingerprint": "x"}')
    (root / "secret_keys.json").write_text('["API_KEY"]')
    if containerfile:
        (root / "Containerfile").write_text("FROM scratch\nCOPY skills /skills\n")
        skills = root / "skills"
        skills.mkdir()
        (skills / "tool.py").write_text("print('hi')\n")
    return root


def _tar_names(path):
    with tarfile.open(path, "r:gz") as tar:
        return set(tar.getnames())


def _tar_manifest(path):
    with tarfile.open(path, "r:gz") as tar:
        return json.loads(tar.extractfile("agentcage-backup/manifest.json").read())


def _backup(mock_state, MockPodman, tmp_path, src_dir, out_name="out.tar.gz"):
    """Run `cage backup test` against *src_dir* as the cage's state dir."""
    mock_state.deployment_exists.return_value = True
    mock_state.load_deployment_config.return_value = _mock_config()
    mock_state.stored_config_path.return_value = str(src_dir / "cage.yaml")
    mock_state.capture_file.return_value = tmp_path / "no-capture.jsonl"
    podman = MockPodman.return_value
    podman.secret_list.return_value = []
    out = str(tmp_path / out_name)
    result = _runner().invoke(main, ["cage", "backup", "test", "-o", out])
    return result, out


class TestBackupBuildContext:
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_omits_secret_index_and_fingerprint(
        self, mock_state, MockPodman, tmp_path,
    ):
        """secret_keys.json would make a clean host believe every keychain
        secret is present; fingerprint.json would make `cage update` skip
        the rebuild. Neither may travel."""
        src = _fake_state_dir(tmp_path / "state", cage_yaml=_CAGE_YAML_BUILD)
        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output

        names = _tar_names(out)
        assert "agentcage-backup/config/secret_keys.json" not in names
        assert "agentcage-backup/config/fingerprint.json" not in names
        # ... while the build context itself is carried.
        assert "agentcage-backup/config/Containerfile" in names
        assert "agentcage-backup/config/skills/tool.py" in names

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_omits_credential_material(
        self, mock_state, MockPodman, tmp_path,
    ):
        src = _fake_state_dir(tmp_path / "state", cage_yaml=_CAGE_YAML_BUILD)
        (src / "creds").mkdir()
        (src / "creds" / "token").write_text("sekrit")
        (src / "pending_secrets.json").write_text('{"API_KEY": "sk-1"}')
        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output
        names = _tar_names(out)
        assert not any("creds" in n for n in names)
        assert not any("pending_secrets" in n for n in names)

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_build_context_included_true_when_containerfile_carried(
        self, mock_state, MockPodman, tmp_path,
    ):
        src = _fake_state_dir(tmp_path / "state", cage_yaml=_CAGE_YAML_BUILD)
        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output
        assert _tar_manifest(out)["build_context_included"] is True

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_build_context_included_false_without_build_step(
        self, mock_state, MockPodman, tmp_path,
    ):
        """A cage with no build step has no context to carry, even though
        its state dir always holds extra generated files."""
        src = _fake_state_dir(
            tmp_path / "state", cage_yaml=_CAGE_YAML_NO_BUILD,
            containerfile=False,
        )
        (src / "AGENTS.md").write_text("# agents\n")
        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output
        assert _tar_manifest(out)["build_context_included"] is False
        # The extra files still travel — only the flag is about the build.
        assert "agentcage-backup/config/AGENTS.md" in _tar_names(out)

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_build_context_included_false_when_containerfile_missing(
        self, mock_state, MockPodman, tmp_path,
    ):
        src = _fake_state_dir(
            tmp_path / "state", cage_yaml=_CAGE_YAML_BUILD, containerfile=False,
        )
        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output
        assert _tar_manifest(out)["build_context_included"] is False

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_ignores_top_level_noise(
        self, mock_state, MockPodman, tmp_path,
    ):
        src = _fake_state_dir(tmp_path / "state", cage_yaml=_CAGE_YAML_BUILD)
        pycache = src / "__pycache__"
        pycache.mkdir()
        (pycache / "junk.pyc").write_text("x")
        (src / "Containerfile.deleted.20260101-000000").write_text("old")
        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output
        names = _tar_names(out)
        assert not any("__pycache__" in n for n in names)
        assert not any(".deleted." in n for n in names)

    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_backup_preserves_symlinks_without_dereferencing(
        self, mock_state, MockPodman, tmp_path,
    ):
        """A dangling link used to raise shutil.Error mid-backup, and a link
        to a sensitive host path was dereferenced into the tarball."""
        secret_host_file = tmp_path / "id_rsa"
        secret_host_file.write_text("PRIVATE KEY")
        src = _fake_state_dir(tmp_path / "state", cage_yaml=_CAGE_YAML_BUILD)
        (src / "skills" / "alias.py").symlink_to("tool.py")
        (src / "dangling").symlink_to("nowhere.txt")
        (src / "host-link").symlink_to(secret_host_file)

        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output

        with tarfile.open(out, "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}
        assert members["agentcage-backup/config/skills/alias.py"].issym()
        assert members["agentcage-backup/config/dangling"].issym()
        host_link = members["agentcage-backup/config/host-link"]
        assert host_link.issym() and host_link.size == 0
        assert host_link.linkname == str(secret_host_file)


# ── TestRestoreBuildContext ───────────────────────────────


class TestRestoreBuildContext:
    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_build_context_round_trips(self, mock_state, MockPodman,
                                       mock_build, tmp_path):
        src = _fake_state_dir(tmp_path / "state", cage_yaml=_CAGE_YAML_BUILD)
        (src / "skills" / "alias.py").symlink_to("tool.py")
        result, out = _backup(mock_state, MockPodman, tmp_path, src)
        assert result.exit_code == 0, result.output

        deploy = tmp_path / "deploy"
        deploy.mkdir()
        mock_state.reset_mock()
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(deploy / "cage.yaml")
        mock_state.load_deployment_config.return_value = _mock_config()
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(main, ["cage", "restore", out, "--no-start"])
        assert result.exit_code == 0, result.output

        assert (deploy / "Containerfile").is_file()
        assert (deploy / "skills" / "tool.py").is_file()
        assert (deploy / "skills" / "alias.py").is_symlink()
        # Excluded state must not reappear via the build-context reinstall.
        assert not (deploy / "secret_keys.json").exists()
        assert not (deploy / "fingerprint.json").exists()

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_restore_drops_excluded_entries_from_old_tarball(
        self, mock_state, MockPodman, mock_build, tmp_path,
    ):
        """Even if a tarball carries them, the secret name index and the
        source host's fingerprint must not land in the restored cage."""
        staging = tmp_path / "staging"
        config_dir = staging / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "cage.yaml").write_text(_CAGE_YAML_NO_BUILD)
        (config_dir / "secret_keys.json").write_text('["API_KEY"]')
        (config_dir / "fingerprint.json").write_text('{"version": 1}')
        (staging / "manifest.json").write_text(json.dumps({
            "format_version": 1, "cage_name": "test", "isolation": "container",
            "secret_keys": [], "secrets_included": False, "named_volumes": [],
        }))
        tarball = str(tmp_path / "old.tar.gz")
        with tarfile.open(tarball, "w:gz") as tar:
            for item in staging.iterdir():
                tar.add(str(item), arcname=f"agentcage-backup/{item.name}")

        deploy = tmp_path / "deploy"
        deploy.mkdir()
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(deploy / "cage.yaml")
        mock_state.load_deployment_config.return_value = _mock_config()
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(
            main, ["cage", "restore", tarball, "--no-start"]
        )
        assert result.exit_code == 0, result.output
        assert not (deploy / "secret_keys.json").exists()
        assert not (deploy / "fingerprint.json").exists()

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_force_restore_of_contextless_tarball_keeps_existing_cage(
        self, mock_state, MockPodman, mock_get_backend, tmp_path,
    ):
        """The preflight must run before anything destructive: a tarball
        taken before build contexts were included cannot rebuild the cage,
        and aborting after the destroy would leave nothing behind."""
        tarball = _build_backup_tarball(
            tmp_path,
            cage_yaml=_CAGE_YAML_BUILD,
            include_secrets=True,
            manifest_overrides={
                "secret_keys": ["API_KEY", "OTHER_KEY"],
                "secrets_included": True,
            },
        )
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config()
        podman = MockPodman.return_value
        backend = mock_get_backend.return_value

        result = _runner().invoke(main, ["cage", "restore", tarball, "--force"])
        assert result.exit_code == 1, result.output
        assert "cannot rebuild the cage" in result.output
        assert "Destroying" not in result.output
        backend.stop.assert_not_called()
        backend.destroy_resources.assert_not_called()
        mock_state.remove_deployment.assert_not_called()
        mock_state.save_deployment.assert_not_called()
        # ... and no orphaned `<cage>.KEY` podman secrets either.
        podman.secret_create.assert_not_called()

    @patch("agentcage.backends.apple_container.AppleContainerBackend")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_force_restore_contextless_apple_keeps_existing_cage(
        self, mock_state, mock_get_backend, mock_ac, tmp_path,
    ):
        tarball = _build_backup_tarball(
            tmp_path,
            cage_yaml=_CAGE_YAML_BUILD,
            manifest_overrides={"isolation": "apple-container"},
        )
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config(
            isolation="apple-container"
        )
        backend = mock_get_backend.return_value

        result = _runner().invoke(main, ["cage", "restore", tarball, "--force"])
        assert result.exit_code == 1, result.output
        assert "cannot rebuild the cage" in result.output
        backend.destroy_resources.assert_not_called()
        mock_ac.return_value.destroy_resources.assert_not_called()
        mock_state.remove_deployment.assert_not_called()

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_absolute_containerfile_does_not_pass_preflight(
        self, mock_state, MockPodman, mock_get_backend, tmp_path,
    ):
        """An absolute path is resolved against the host, not joined onto the
        backup dir — it must not be reported as carried by the tarball."""
        missing = tmp_path / "elsewhere" / "Containerfile"
        tarball = _build_backup_tarball(
            tmp_path,
            cage_yaml=textwrap.dedent(f"""\
                name: test
                container:
                  build:
                    containerfile: {missing}
            """),
        )
        mock_state.deployment_exists.return_value = True
        mock_state.load_deployment_config.return_value = _mock_config()
        backend = mock_get_backend.return_value

        result = _runner().invoke(main, ["cage", "restore", tarball, "--force"])
        assert result.exit_code == 1, result.output
        assert "absolute path" in result.output
        backend.destroy_resources.assert_not_called()

    @patch("agentcage.cli._build_and_deploy")
    @patch("agentcage.cli.Podman")
    @patch("agentcage.cli.state")
    def test_absolute_containerfile_present_on_host_is_accepted(
        self, mock_state, MockPodman, mock_build, tmp_path,
    ):
        host_cf = tmp_path / "elsewhere" / "Containerfile"
        host_cf.parent.mkdir()
        host_cf.write_text("FROM scratch\n")
        tarball = _build_backup_tarball(
            tmp_path,
            cage_yaml=textwrap.dedent(f"""\
                name: test
                container:
                  build:
                    containerfile: {host_cf}
            """),
        )
        deploy = tmp_path / "deploy"
        deploy.mkdir()
        mock_state.deployment_exists.return_value = False
        mock_state.stored_config_path.return_value = str(deploy / "cage.yaml")
        mock_state.load_deployment_config.return_value = _mock_config()
        mock_state.capture_file.return_value = tmp_path / "capture.jsonl"

        result = _runner().invoke(
            main, ["cage", "restore", tarball, "--no-start"]
        )
        assert result.exit_code == 0, result.output

    def test_carried_containerfile_rejects_escaping_paths(self, tmp_path):
        from agentcage.cli import _carried_containerfile

        config = tmp_path / "config"
        config.mkdir()
        (config / "Containerfile").write_text("FROM scratch\n")
        outside = tmp_path / "Containerfile"
        outside.write_text("FROM scratch\n")

        assert _carried_containerfile(config, "Containerfile") is not None
        assert _carried_containerfile(config, "../Containerfile") is None
        assert _carried_containerfile(config, str(outside)) is None
        assert _carried_containerfile(config, "") is None
        assert _carried_containerfile(config, "nope") is None
