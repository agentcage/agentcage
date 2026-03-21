"""Tests for lifecycle config field and its effects on quadlet generation.

These tests specify the expected behavior of the lifecycle feature:
- Config.lifecycle field with values "service", "interactive", "ephemeral"
- validate_config() rejects invalid lifecycle values
- Quadlet generation maps lifecycle to Restart and WantedBy settings
"""

import textwrap

import pytest

from agentcage.config import Config, ContainerConfig, load_config, validate_config

_has_lifecycle = hasattr(Config, "lifecycle")
_skip_reason = "lifecycle field not yet implemented on Config"


@pytest.mark.skipif(not _has_lifecycle, reason=_skip_reason)
class TestLifecycleConfigParsing:
    """Verify lifecycle field is parsed from YAML config."""

    def test_lifecycle_defaults_to_service(self, tmp_path):
        """When lifecycle is omitted, it defaults to 'service'."""
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.lifecycle == "service"

    def test_lifecycle_service(self, tmp_path):
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            lifecycle: service
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.lifecycle == "service"

    def test_lifecycle_interactive(self, tmp_path):
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            lifecycle: interactive
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.lifecycle == "interactive"

    def test_lifecycle_ephemeral(self, tmp_path):
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            lifecycle: ephemeral
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.lifecycle == "ephemeral"


@pytest.mark.skipif(not _has_lifecycle, reason=_skip_reason)
class TestLifecycleValidation:
    """Verify validate_config rejects invalid lifecycle values."""

    def test_invalid_lifecycle_raises(self, tmp_path):
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            lifecycle: invalid
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        with pytest.raises(ValueError, match="lifecycle"):
            validate_config(cfg)

    def test_valid_lifecycles_pass_validation(self, tmp_path):
        for lifecycle in ("service", "interactive", "ephemeral"):
            p = tmp_path / "cage.yaml"
            p.write_text(textwrap.dedent(f"""\
                name: test
                lifecycle: {lifecycle}
                container:
                  image: localhost/test:latest
            """))
            cfg = load_config(str(p))
            # Should not raise
            validate_config(cfg)


@pytest.mark.skipif(not _has_lifecycle, reason=_skip_reason)
class TestLifecycleQuadletMapping:
    """Verify lifecycle affects Restart and WantedBy in generated quadlets."""

    def _generate(self, tmp_path, lifecycle):
        from agentcage.quadlets import generate_quadlets
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent(f"""\
            name: test
            lifecycle: {lifecycle}
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        return generate_quadlets(cfg, str(p), "/patches")

    def test_service_lifecycle_has_restart_on_failure(self, tmp_path):
        files = self._generate(tmp_path, "service")
        cage = files["test-cage.container"]
        assert "Restart=on-failure" in cage

    def test_service_lifecycle_has_wantedby(self, tmp_path):
        files = self._generate(tmp_path, "service")
        cage = files["test-cage.container"]
        assert "WantedBy=default.target" in cage

    def test_interactive_lifecycle_has_restart_no(self, tmp_path):
        files = self._generate(tmp_path, "interactive")
        cage = files["test-cage.container"]
        assert "Restart=no" in cage

    def test_interactive_lifecycle_no_wantedby(self, tmp_path):
        files = self._generate(tmp_path, "interactive")
        cage = files["test-cage.container"]
        assert "WantedBy" not in cage

    def test_ephemeral_lifecycle_has_restart_no(self, tmp_path):
        files = self._generate(tmp_path, "ephemeral")
        cage = files["test-cage.container"]
        assert "Restart=no" in cage

    def test_ephemeral_lifecycle_no_wantedby(self, tmp_path):
        files = self._generate(tmp_path, "ephemeral")
        cage = files["test-cage.container"]
        assert "WantedBy" not in cage


class TestExistingRestartConfig:
    """Verify the existing restart config field works correctly with quadlets.

    These tests verify current behavior which lifecycle will build upon.
    """

    def test_default_restart_is_on_failure(self, tmp_path):
        """Default restart policy is on-failure."""
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        assert cfg.container.restart == "on-failure"

    def test_restart_no_in_config(self, tmp_path):
        """Setting restart: no disables automatic restarts."""
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
              restart: "no"
        """))
        cfg = load_config(str(p))
        assert cfg.container.restart == "no"

    def test_restart_appears_in_quadlet(self, tmp_path):
        """Restart policy is propagated to the cage quadlet."""
        from agentcage.quadlets import generate_quadlets
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
              restart: "no"
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, str(p), "/patches")
        cage = files["test-cage.container"]
        assert "Restart=no" in cage

    def test_wantedby_present_by_default(self, tmp_path):
        """By default, WantedBy=default.target enables auto-start."""
        from agentcage.quadlets import generate_quadlets
        p = tmp_path / "cage.yaml"
        p.write_text(textwrap.dedent("""\
            name: test
            container:
              image: localhost/test:latest
        """))
        cfg = load_config(str(p))
        files = generate_quadlets(cfg, str(p), "/patches")
        cage = files["test-cage.container"]
        assert "WantedBy=default.target" in cage
