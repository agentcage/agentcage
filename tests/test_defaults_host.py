"""Host-side halves of the ported-defaults tests.

Split out of ``tests/test_defaults.py`` (RUST-PORT-PLAN.md §2.4): BuildConfig
parsing and the click CLI are host code and become Rust; the addon's inspector
auto-loading stays Python and stays in the original file. Test names are
unchanged so failures stay greppable against history.
"""

import textwrap




# ── BuildConfig parsing ────────────────────────────────────


class TestBuildConfig:
    """Verify BuildConfig is correctly parsed from YAML."""

    def test_build_section_parsed(self, tmp_path):
        from agentcage.config import load_config
        cfg_file = tmp_path / "cage.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            name: test-build
            container:
              image: "localhost/myimage:latest"
              build:
                containerfile: "Containerfile"
                args:
                  BASE_IMAGE: "ghcr.io/example/image:v1"
                  EXTRA: "value"
            domains:
              allow:
                - example.com
        """))
        cfg = load_config(str(cfg_file))
        assert cfg.container.build.containerfile == "Containerfile"
        assert cfg.container.build.args == {
            "BASE_IMAGE": "ghcr.io/example/image:v1",
            "EXTRA": "value",
        }

    def test_build_defaults_to_empty(self, tmp_path):
        from agentcage.config import load_config
        cfg_file = tmp_path / "cage.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            name: test-no-build
            container:
              image: "node:22-slim"
            domains:
              allow:
                - example.com
        """))
        cfg = load_config(str(cfg_file))
        assert cfg.container.build.containerfile == ""
        assert cfg.container.build.args == {}

    def test_openclaw_scaffold_has_build_section(self, tmp_path):
        """The rendered openclaw scaffold should include a build section."""
        from agentcage.init import render_config
        from agentcage.config import load_config
        cfg_text = render_config("test-oc-build", scaffold="openclaw")
        cfg_file = tmp_path / "cage.yaml"
        cfg_file.write_text(cfg_text)
        cfg = load_config(str(cfg_file))
        assert cfg.container.build.containerfile == "Containerfile"
        assert "BASE_IMAGE" in cfg.container.build.args


# ── CLI: verify and deploy arg parsing ────────────────────


class TestCLI:
    """Test Python CLI argument parsing via click.testing.CliRunner."""

    def _run(self, args):
        from click.testing import CliRunner
        from agentcage.cli import main
        return CliRunner().invoke(main, args, catch_exceptions=False)

    def test_verify_requires_name(self):
        result = self._run(["cage", "verify"])
        assert result.exit_code != 0

    def test_verify_help(self):
        result = self._run(["cage", "verify", "--help"])
        assert result.exit_code == 0
        assert "healthy" in result.output

    def test_main_help_shows_groups(self):
        result = self._run(["--help"])
        assert result.exit_code == 0
        assert "cage" in result.output
        assert "secret" in result.output

    def test_cage_help_shows_subcommands(self):
        result = self._run(["cage", "--help"])
        assert result.exit_code == 0
        assert "create" in result.output
        assert "update" in result.output
        assert "destroy" in result.output
        assert "verify" in result.output
        assert "list" in result.output
        assert "restart" in result.output

    def test_secret_help_shows_subcommands(self):
        result = self._run(["secret", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "set" in result.output
        assert "rm" in result.output
