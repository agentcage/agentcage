"""Hot-reload must not reset ``inspectors:``-section configs (2026-09-01).

Regression: ``_maybe_reload`` reconfigured built-in inspectors from the
LEGACY key map only, so a builtin configured via the explicit
``inspectors:`` section was silently reset to defaults on every
proxy-config mtime bump. For a cage whose content-type
``host_exempt_content_types`` lives in that section, the first
``domain add``/``domain rm`` or domains.auto grant after egress start
wiped the exemptions in place, and multipart uploads started 403ing on
body entropy — hit in production as "ElevenLabs audio transcription
failed (HTTP 403): content-type mismatch ... body entropy is 7.80".

Reload now re-applies the ``inspectors:`` section after the legacy map
(same precedence as initial load), and ``_load_custom_inspectors`` is
reload-safe: reconfigure-in-place, never a duplicate append.
"""

import os
import textwrap

import pytest
import yaml


ELEVENLABS_EXEMPT = {
    "host_exempt_content_types": {"elevenlabs.io": ["multipart/form-data"]}
}


def _write_cfg(path, extra=None, domains=("a.com",)):
    cfg = {
        "domains": {"allow": list(domains)},
        "inspectors": [
            {"name": "content-type", "config": dict(ELEVENLABS_EXEMPT)},
        ],
    }
    if extra:
        cfg.update(extra)
    path.write_text(yaml.safe_dump(cfg))


def _bump_mtime(path):
    os.utime(path, (0, os.stat(path).st_mtime + 5))


def _make_addon(tmp_path, monkeypatch, extra=None):
    from agentcage.data.proxy import addon as addon_mod

    cfg_path = tmp_path / "config.yaml"
    _write_cfg(cfg_path, extra=extra)
    monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))
    addon = addon_mod.Agentcage()
    addon.load(loader=None)
    return addon, cfg_path


def _content_type_inspector(addon):
    matches = [i for i in addon.inspectors if i.name == "content-type"]
    assert len(matches) == 1, f"expected exactly one, got {len(matches)}"
    return matches[0]


class TestReloadKeepsInspectorSectionConfig:
    def test_exemptions_survive_reload(self, tmp_path, monkeypatch):
        """THE production regression: a domain change bumps the config
        mtime; the content-type exemptions must survive the reload."""
        addon, cfg_path = _make_addon(tmp_path, monkeypatch)
        ct = _content_type_inspector(addon)
        assert ct.host_exempt_content_types == {
            "elevenlabs.io": ["multipart/form-data"]}

        # The realistic trigger: a domain add rewrites the config file.
        _write_cfg(cfg_path, domains=("a.com", "b.com"))
        _bump_mtime(cfg_path)
        addon._maybe_reload()

        ct = _content_type_inspector(addon)
        assert ct.host_exempt_content_types == {
            "elevenlabs.io": ["multipart/form-data"]}, (
            "hot reload reset the inspectors:-section config to defaults")

    def test_reload_applies_changed_section_config(self, tmp_path,
                                                   monkeypatch):
        """The section is live config: an EDITED exemption list must be
        picked up by the reload, not just preserved from initial load."""
        addon, cfg_path = _make_addon(tmp_path, monkeypatch)

        cfg = {
            "domains": {"allow": ["a.com"]},
            "inspectors": [
                {"name": "content-type",
                 "config": {"host_exempt_content_types": {
                     "example.org": ["multipart/form-data"]}}},
            ],
        }
        cfg_path.write_text(yaml.safe_dump(cfg))
        _bump_mtime(cfg_path)
        addon._maybe_reload()

        ct = _content_type_inspector(addon)
        assert ct.host_exempt_content_types == {
            "example.org": ["multipart/form-data"]}

    def test_no_duplicate_inspectors_after_reloads(self, tmp_path,
                                                   monkeypatch):
        addon, cfg_path = _make_addon(tmp_path, monkeypatch)
        names_before = sorted(i.name for i in addon.inspectors)
        for n in range(3):
            _write_cfg(cfg_path, domains=("a.com", f"x{n}.com"))
            _bump_mtime(cfg_path)
            addon._maybe_reload()
        assert sorted(i.name for i in addon.inspectors) == names_before

    def test_section_wins_over_legacy_key_on_reload(self, tmp_path,
                                                    monkeypatch):
        """Initial-load precedence is legacy first, explicit section wins.
        The reload must keep that ordering, not invert it."""
        extra = {"content_type": {"entropy_ceiling": 7.0}}
        addon, cfg_path = _make_addon(tmp_path, monkeypatch, extra=extra)
        cfg = {
            "domains": {"allow": ["a.com"]},
            "content_type": {"entropy_ceiling": 7.0},
            "inspectors": [
                {"name": "content-type",
                 "config": {"entropy_ceiling": 8.0}},
            ],
        }
        cfg_path.write_text(yaml.safe_dump(cfg))
        _bump_mtime(cfg_path)
        addon._maybe_reload()
        assert _content_type_inspector(addon).entropy_ceiling == 8.0


class TestPathInspectorNotDuplicatedOnReload:
    def test_path_entry_reconfigured_in_place(self, tmp_path, monkeypatch):
        insp_dir = tmp_path / "inspectors"
        insp_dir.mkdir()
        (insp_dir / "my_check.py").write_text(textwrap.dedent("""\
            from inspectors.base import Inspector

            class MyCheck(Inspector):
                name = "my-check"

                def configure(self, config):
                    self.marker = config.get("marker", "")

                def inspect_request(self, ctx):
                    return None
        """))
        monkeypatch.setenv("AGENTCAGE_INSPECTOR_DIRS", str(insp_dir))

        from agentcage.data.proxy import addon as addon_mod
        cfg_path = tmp_path / "config.yaml"

        def _cfg(marker, domains):
            return yaml.safe_dump({
                "domains": {"allow": list(domains)},
                "inspectors": [
                    {"name": "my-check",
                     "path": str(insp_dir / "my_check.py"),
                     "config": {"marker": marker}},
                ],
            })

        cfg_path.write_text(_cfg("v1", ["a.com"]))
        monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))
        addon = addon_mod.Agentcage()
        addon.load(loader=None)
        assert [i.name for i in addon.inspectors].count("my-check") == 1

        cfg_path.write_text(_cfg("v2", ["a.com", "b.com"]))
        _bump_mtime(cfg_path)
        addon._maybe_reload()

        mine = [i for i in addon.inspectors if i.name == "my-check"]
        assert len(mine) == 1, "path-based inspector duplicated on reload"
        assert mine[0].marker == "v2"
