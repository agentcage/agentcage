"""Live secret apply (zero-restart, phase 2) — egress side.

Split out of ``tests/test_live_secret_apply.py`` (RUST-PORT-PLAN.md §2.4):
``secret_injector`` and ``addon`` run inside the egress container and stay
Python. Covers the injector's staged-file-first precedence (including the
empty-file tombstone) and the addon reload that reconfigures it. Test names are
unchanged so failures stay greppable against history.
"""

import pytest


@pytest.fixture
def injector(monkeypatch, tmp_path):
    """A SecretInjector whose staged-secrets dir points at tmp_path."""
    from agentcage.data.proxy import secret_injector as si
    monkeypatch.setattr(si, "_SECRETS_DIR", tmp_path)
    return si.SecretInjector(), tmp_path


RULE = {"env": "MY_KEY", "placeholder": "agentcage:secret:MY_KEY:0123456789abcdef0123456789abcdef"}


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
                  "placeholder": "agentcage:secret:KEY_A:0123456789abcdef0123456789abcdef"}
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
                  "placeholder": "agentcage:secret:KEY_B:fedcba9876543210fedcba9876543210"}
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
                "placeholder": "agentcage:secret:KEY_A:0123456789abcdef0123456789abcdef"}
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
