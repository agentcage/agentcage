"""Tests for scaffold-related CLI commands and cage list/prune/destroy integration."""

from __future__ import annotations

import textwrap
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agentcage.cli import main
from tests.markers import REQUIRES_PODMAN


def _runner():
    return CliRunner()


class TestInitListScaffolds:
    """Test 'agentcage init --list-scaffolds'."""

    def test_list_scaffolds_shows_available(self):
        result = _runner().invoke(main, ["init", "--list-scaffolds"])
        assert result.exit_code == 0
        assert "openclaw" in result.output
        assert "claude-code" in result.output
        assert "codex" in result.output

    def test_list_scaffolds_header(self):
        result = _runner().invoke(main, ["init", "--list-scaffolds"])
        assert "Available scaffolds" in result.output


class TestInitWithScaffold:
    """Test 'agentcage init <name> --scaffold <scaffold>'."""

    def test_invalid_scaffold_rejected(self):
        result = _runner().invoke(main, ["init", "test", "--scaffold", "nonexistent"])
        assert result.exit_code != 0
        assert "unknown scaffold" in result.output

    @REQUIRES_PODMAN
    @patch("agentcage.registry.resolve_latest_tag", return_value="2026.2.24")
    def test_openclaw_scaffold_creates_file(self, mock_resolve, tmp_path):
        dest = tmp_path / "cage.yaml"
        result = _runner().invoke(main, [
            "init", "my-oc", "--scaffold", "openclaw", "-o", str(dest),
        ])
        assert result.exit_code == 0
        assert dest.exists()
        content = dest.read_text()
        assert "my-oc" in content

    def test_init_invalid_name_rejected(self):
        result = _runner().invoke(main, ["init", "INVALID_NAME"])
        assert result.exit_code != 0
        assert "must be" in result.output

    def test_init_requires_name(self):
        result = _runner().invoke(main, ["init"])
        assert result.exit_code != 0


class TestInitScaffoldStagingConflicts:
    """``init`` must not leave a config and a Containerfile that disagree.

    ``init --scaffold X`` writes a config naming
    ``localhost/agentcage-scaffold-X`` and ``containerfile: Containerfile``,
    then stages the scaffold's build context beside it with
    ``clobber=False``. An existing foreign Containerfile therefore used to
    survive, and ``cage create`` would build *it* under the scaffold's tag
    — surfacing as an unrelated failure in the wrapper build, or as no
    failure at all and a cage running the wrong image.

    ``--isolation vm`` throughout, so ``run_scaffold_setup`` skips the host
    podman build loop; the refusal itself happens before that anyway.
    """

    BUSYBOX = "FROM docker.io/library/busybox:latest\n"

    def _scaffold_containerfile(self, scaffold: str) -> str:
        from agentcage.init import resolve_scaffold
        return (resolve_scaffold(scaffold) / "Containerfile").read_text()

    def _init(self, tmp_path, *extra, scaffold="claude-code"):
        return _runner().invoke(main, [
            "init", "probe", "--scaffold", scaffold,
            "--isolation", "vm", "-o", str(tmp_path / "cage.yaml"),
            *extra,
        ])

    def test_foreign_containerfile_is_not_silently_kept(self, tmp_path):
        """The bug, mechanically: a Containerfile that is not the
        scaffold's must not survive unremarked."""
        (tmp_path / "Containerfile").write_text(self.BUSYBOX)

        result = self._init(tmp_path)

        assert result.exit_code != 0
        assert "Containerfile" in result.output
        assert "--force" in result.output
        # Untouched, and no config written beside it: a refusal that had
        # already written the config would be the same trap.
        assert (tmp_path / "Containerfile").read_text() == self.BUSYBOX
        assert not (tmp_path / "cage.yaml").exists()

    def test_a_projects_own_agents_md_is_not_silently_overwritten(self, tmp_path):
        """The same hole in the other direction. ``stage_scaffold_assets``
        refreshes unconditionally, so a repo that keeps its own root
        ``AGENTS.md`` (this one does) had it replaced with the canonical
        sandbox brief and was told nothing."""
        (tmp_path / "AGENTS.md").write_text("# my project brief\n")

        result = self._init(tmp_path)

        assert result.exit_code != 0
        assert "AGENTS.md" in result.output
        assert (tmp_path / "AGENTS.md").read_text() == "# my project brief\n"

    def test_a_copyed_sibling_is_a_build_input_too(self, tmp_path):
        """openclaw's Containerfile ``COPY``s ``entrypoint.sh``, so a
        foreign one decides what the cage runs just as surely as the
        Containerfile does."""
        (tmp_path / "entrypoint.sh").write_text("#!/bin/sh\necho pwned\n")

        result = self._init(tmp_path, scaffold="openclaw")

        assert result.exit_code != 0
        assert "entrypoint.sh" in result.output

    def test_a_projects_readme_is_not_a_conflict(self, tmp_path):
        """A scaffold's ``README.md`` is staged for the operator to read;
        the build never opens it. Refusing on it would break ``init`` in
        every existing project, so it stays the operator's and stays
        quiet."""
        (tmp_path / "README.md").write_text("# my readme\n")

        result = self._init(tmp_path)

        assert result.exit_code == 0, result.output
        assert (tmp_path / "README.md").read_text() == "# my readme\n"
        assert (tmp_path / "cage.yaml").exists()

    def test_force_actually_replaces_the_build_inputs(self, tmp_path):
        """``--force`` is already documented as "Overwrite existing file".
        A force that refused nothing but then kept the stale Containerfile
        would be the original bug with a prompt in front of it."""
        (tmp_path / "Containerfile").write_text(self.BUSYBOX)
        (tmp_path / "README.md").write_text("# my readme\n")

        result = self._init(tmp_path, "--force")

        assert result.exit_code == 0, result.output
        assert (tmp_path / "Containerfile").read_text() == \
            self._scaffold_containerfile("claude-code")
        # Still scoped to build inputs: --force is not licence to replace
        # a project README nothing ever warned about.
        assert (tmp_path / "README.md").read_text() == "# my readme\n"

    def test_rerunning_over_its_own_staging_does_not_refuse(self, tmp_path):
        """Idempotence. The second run sees its own staged Containerfile
        and brief, which match the scaffold's, so there is no conflict —
        otherwise the check would make ``init`` a one-shot."""
        first = self._init(tmp_path)
        assert first.exit_code == 0, first.output
        (tmp_path / "cage.yaml").unlink()

        second = self._init(tmp_path)

        assert second.exit_code == 0, second.output


class TestCageListColumns:
    """Test that cage list shows the expected columns."""

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_name_column(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        cfg = MagicMock()
        cfg.isolation = "container"
        cfg.lifecycle = "service"
        cfg.scaffold = ""
        cfg.container.nested_containers = False
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "proxy", "dns"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "NAME" in result.output
        assert "myapp" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_isolation_column(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        cfg = MagicMock()
        cfg.isolation = "container"
        cfg.lifecycle = "service"
        cfg.scaffold = ""
        cfg.container.nested_containers = False
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {}
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = True
        result = _runner().invoke(main, ["cage", "list"])
        assert "ISOLATION" in result.output
        assert "container" in result.output

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_list_shows_lifecycle_column(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["myapp"]
        cfg = MagicMock()
        cfg.isolation = "container"
        cfg.lifecycle = "interactive"
        cfg.scaffold = "claude-code"
        cfg.container.nested_containers = False
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {
            "lifecycle": "interactive",
            "scaffold": "claude-code",
            "agentcage_version": "0.22.0",
        }
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage"]
        backend.is_running.return_value = False
        result = _runner().invoke(main, ["cage", "list"])
        assert "LIFECYCLE" in result.output
        assert "interactive" in result.output
        assert "claude-code" in result.output
        assert "exited" in result.output

    @patch("agentcage.cli.state")
    def test_list_empty(self, mock_state):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "list"])
        assert result.exit_code == 0
        assert "No" in result.output


class TestCageDestroyCommand:
    """Test cage destroy CLI command."""

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_aborts_without_confirmation(self, mock_destroy):
        result = _runner().invoke(main, ["cage", "destroy", "test"], input="n\n")
        assert result.exit_code != 0
        mock_destroy.assert_not_called()

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_with_yes_flag(self, mock_destroy):
        mock_destroy.return_value = ["state:test"]
        result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0

    @patch("agentcage.cli._destroy_cage")
    def test_destroy_nothing_to_remove(self, mock_destroy):
        mock_destroy.return_value = []
        result = _runner().invoke(main, ["cage", "destroy", "test", "-y"])
        assert result.exit_code == 0
        assert "Nothing to remove" in result.output


class TestCagePrune:
    """Test cage prune CLI command."""

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_prune_nothing(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = []
        result = _runner().invoke(main, ["cage", "prune"])
        assert result.exit_code == 0
        assert "Nothing to prune" in result.output

    @patch("agentcage.cli._destroy_cage")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_prune_removes_exited_interactive(self, mock_state, mock_get_backend, mock_destroy):
        mock_state.list_deployments.return_value = ["cc-bold-fox", "my-openclaw"]

        # cc-bold-fox: interactive, stopped
        cc_cfg = MagicMock()
        cc_cfg.lifecycle = "interactive"
        cc_cfg.scaffold = "claude-code"

        # my-openclaw: service, running
        oc_cfg = MagicMock()
        oc_cfg.lifecycle = "service"
        oc_cfg.scaffold = "openclaw"

        mock_state.load_deployment_config.side_effect = lambda n: {
            "cc-bold-fox": cc_cfg, "my-openclaw": oc_cfg
        }[n]
        mock_state.load_metadata.side_effect = lambda n: {
            "cc-bold-fox": {"lifecycle": "interactive", "agentcage_version": "0.22.0"},
            "my-openclaw": {"lifecycle": "service", "agentcage_version": "0.22.0"},
        }[n]

        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "egress"]
        # cc-bold-fox stopped, my-openclaw running
        def is_running(name, svc):
            return name == "my-openclaw"
        backend.is_running.side_effect = is_running

        mock_destroy.return_value = []
        result = _runner().invoke(main, ["cage", "prune", "-y"])
        assert result.exit_code == 0
        # Only cc-bold-fox should be pruned
        mock_destroy.assert_called_once()
        assert "cc-bold-fox" in mock_destroy.call_args[0]

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_prune_skips_running_interactive(self, mock_state, mock_get_backend):
        mock_state.list_deployments.return_value = ["cc-running"]
        cfg = MagicMock()
        cfg.lifecycle = "interactive"
        mock_state.load_deployment_config.return_value = cfg
        mock_state.load_metadata.return_value = {
            "lifecycle": "interactive",
            "agentcage_version": "0.22.0",
        }
        backend = mock_get_backend.return_value
        backend.service_names.return_value = ["cage", "egress"]
        backend.is_running.return_value = True  # all running
        result = _runner().invoke(main, ["cage", "prune"])
        assert "Nothing to prune" in result.output


class TestRunCommand:
    """Test agentcage run CLI command basics."""

    def test_run_help(self):
        result = _runner().invoke(main, ["run", "--help"])
        assert result.exit_code == 0
        assert "scaffold" in result.output.lower() or "SCAFFOLD" in result.output

    def test_cage_run_help(self):
        """`run` is canonically `cage run`; the subcommand resolves and
        carries the same SCAFFOLD argument as the top-level alias."""
        result = _runner().invoke(main, ["cage", "run", "--help"])
        assert result.exit_code == 0
        assert "scaffold" in result.output.lower() or "SCAFFOLD" in result.output

    def test_run_is_alias_of_cage_run(self):
        """Top-level `run` and `cage run` resolve to the same command."""
        from agentcage.cli import cage, main as main_grp
        top = main_grp.get_command(None, "run")
        sub = cage.get_command(None, "run")
        assert top is not None and top is sub

    def test_run_listed_in_top_level_aliases(self):
        result = _runner().invoke(main, ["--help"])
        assert "run → cage run" in result.output

    def test_cage_help_shows_prune(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "prune" in result.output


class TestCageHelp:
    """Verify cage help includes expected subcommands."""

    def test_cage_help_shows_list(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "list" in result.output

    def test_cage_help_shows_destroy(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "destroy" in result.output

    def test_cage_help_shows_create(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "create" in result.output

    def test_cage_help_shows_verify(self):
        result = _runner().invoke(main, ["cage", "--help"])
        assert "verify" in result.output
