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

Reload now builds the chain exactly as initial load does (legacy keys
first, the ``inspectors:`` section wins) through ``_load_inspectors``,
reconfiguring kept inspectors in place, never appending a duplicate.
"""

import base64
import copy
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


# ── Reload reconciles the chain to what a fresh load builds ──
#
# The reload used to reconfigure only the inspectors already loaded and
# re-apply the ``inspectors:`` section on top, so it could grow the
# chain (a section entry) but never shrink it, and a built-in enabled
# through a legacy top-level key was never added: ``content_type:
# false``, ``max_request_body: 0`` or dropping ``entropy:`` left the
# inspector running with its old config, ``entropy: {}`` or a non-zero
# ``max_request_body`` after a zero did nothing, and an entry removed
# from ``inspectors:`` kept running, until an egress restart. The
# reload now builds the chain a fresh load would and swaps it in whole.


_MY_CHECK_SRC = textwrap.dedent("""\
    from inspectors.base import Inspector


    class MyCheck(Inspector):
        name = "my-check"

        def configure(self, config):
            self.marker = config.get("marker", "")

        def inspect_request(self, ctx):
            return None
""")


@pytest.fixture
def my_check(tmp_path, monkeypatch):
    """A custom inspector file the ``inspectors:`` section can load."""
    d = tmp_path / "inspectors"
    d.mkdir()
    path = d / "my_check.py"
    path.write_text(_MY_CHECK_SRC)
    monkeypatch.setenv("AGENTCAGE_INSPECTOR_DIRS", str(d))
    return str(path)


def _load_cfg(tmp_path, monkeypatch, cfg, name="config.yaml"):
    from agentcage.data.proxy import addon as addon_mod

    cfg_path = tmp_path / name
    cfg_path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))
    addon = addon_mod.Agentcage()
    addon.load(loader=None)
    return addon, cfg_path


def _reload_cfg(addon, cfg_path, cfg, monkeypatch):
    from agentcage.data.proxy import addon as addon_mod

    cfg_path.write_text(yaml.safe_dump(cfg))
    _bump_mtime(cfg_path)
    # The reload reads CONFIG_PATH, which a later _load_cfg may repoint.
    monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))
    addon._maybe_reload()


def _names(addon):
    return [i.name for i in addon.inspectors]


def _fingerprint(addon):
    """The chain as a comparable value: each inspector's class, name and
    configured attributes (a snapshot: ``configure()`` rebinds them), in
    chain order."""
    return [(type(i).__name__, i.name, dict(vars(i)))
            for i in addon.inspectors]


def _ctx(body: bytes, *, content_type="text/plain", host="example.com"):
    from inspectors.base import InspectionContext
    from inspectors.util import shannon_entropy

    return InspectionContext(
        url=f"https://{host}/", host=host, method="POST",
        headers=[("content-type", content_type)],
        content_type=content_type, body_bytes=body,
        body_text=body.decode("latin-1"), body_size=len(body),
        body_entropy=shannon_entropy(body),
    )


def _verdicts(addon, body: bytes, **kw):
    from inspectors._chain import run_inspector_chain_sync

    return [(r.inspector, r.action) for r in
            run_inspector_chain_sync(addon.inspectors, _ctx(body, **kw))]


_BASE = {"domains": {"allow": ["example.com"]}}
# Random bytes, base64-encoded: what the content-type inspector refuses
# in a text/plain body.
_B64_BODY = base64.b64encode(bytes(range(256)) * 3)


class TestReloadDisablesBuiltins:
    @pytest.mark.parametrize("before,after,gone", [
        ({"content_type": {}}, {"content_type": False}, "content-type"),
        ({"max_request_body": 100}, {"max_request_body": 0}, "body-size"),
        ({"entropy": {}}, {}, "entropy"),
    ], ids=["content_type-false", "max_request_body-0", "entropy-removed"])
    def test_legacy_disable_drops_the_inspector(self, tmp_path, monkeypatch,
                                                before, after, gone):
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch,
                                    {**_BASE, **before})
        assert gone in _names(addon)

        _reload_cfg(addon, cfg_path, {**_BASE, **after}, monkeypatch)
        assert gone not in _names(addon), (
            f"{gone} disabled by a legacy key kept running after reload")

    def test_disabled_body_size_no_longer_blocks(self, tmp_path,
                                                 monkeypatch):
        addon, cfg_path = _load_cfg(
            tmp_path, monkeypatch, {**_BASE, "max_request_body": 100})
        assert ("body-size", "block") in _verdicts(addon, b"x" * 200)

        _reload_cfg(addon, cfg_path, {**_BASE, "max_request_body": 0},
                    monkeypatch)
        assert _verdicts(addon, b"x" * 200) == []


class TestReloadEnablesBuiltinsViaLegacyKeys:
    @pytest.mark.parametrize("before,after,added", [
        ({"content_type": False}, {}, "content-type"),
        ({"max_request_body": 0}, {"max_request_body": 100}, "body-size"),
        ({}, {"entropy": {}}, "entropy"),
    ], ids=["content_type-on", "max_request_body-N", "entropy-dict"])
    def test_legacy_enable_adds_the_inspector(self, tmp_path, monkeypatch,
                                              before, after, added):
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch,
                                    {**_BASE, **before})
        assert added not in _names(addon)

        _reload_cfg(addon, cfg_path, {**_BASE, **after}, monkeypatch)
        assert added in _names(addon), (
            f"{added} enabled by a legacy key was not added on reload")

    def test_enabled_content_type_blocks(self, tmp_path, monkeypatch):
        addon, cfg_path = _load_cfg(
            tmp_path, monkeypatch, {**_BASE, "content_type": False})
        assert _verdicts(addon, _B64_BODY) == []

        _reload_cfg(addon, cfg_path, {**_BASE, "content_type": {}},
                    monkeypatch)
        assert ("content-type", "block") in _verdicts(addon, _B64_BODY)


class TestReloadRemovesSectionEntries:
    def test_builtin_removed_from_section_is_dropped(self, tmp_path,
                                                     monkeypatch):
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, {
            **_BASE, "inspectors": [{"name": "entropy", "config": {}}]})
        assert "entropy" in _names(addon)

        _reload_cfg(addon, cfg_path, {**_BASE, "inspectors": []},
                    monkeypatch)
        assert "entropy" not in _names(addon)

    def test_path_inspector_removed_from_section_is_dropped(
            self, tmp_path, monkeypatch, my_check):
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, {
            **_BASE,
            "inspectors": [{"name": "my-check", "path": my_check}]})
        assert "my-check" in _names(addon)

        _reload_cfg(addon, cfg_path, dict(_BASE), monkeypatch)
        assert "my-check" not in _names(addon)

    def test_section_config_removed_falls_back_to_legacy(self, tmp_path,
                                                          monkeypatch):
        """A built-in that is also legacy-enabled stays, but with the
        legacy config once its section entry is gone — as at boot."""
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, {
            **_BASE, "content_type": {"entropy_ceiling": 7.0},
            "inspectors": [{"name": "content-type",
                            "config": {"entropy_ceiling": 8.0}}]})
        assert _content_type_inspector(addon).entropy_ceiling == 8.0

        _reload_cfg(addon, cfg_path, {
            **_BASE, "content_type": {"entropy_ceiling": 7.0}}, monkeypatch)
        assert _content_type_inspector(addon).entropy_ceiling == 7.0


class TestReloadKeepsLiveInstances:
    def test_kept_inspectors_are_the_same_objects(self, tmp_path,
                                                  monkeypatch, my_check):
        """An inspector that stays is reconfigured in place, never
        rebuilt: the domain inspector's live grants (and the Policy API
        holding it) and a custom inspector's state survive."""
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, {
            **_BASE, "inspectors": [{"name": "my-check", "path": my_check,
                                     "config": {"marker": "v1"}}]})
        before = {i.name: i for i in addon.inspectors}
        before["domain"].granted = {"granted.example"}
        before["my-check"].runtime_state = 42

        _reload_cfg(addon, cfg_path, {
            "domains": {"allow": ["example.com", "b.example"]},
            "entropy": {},
            "inspectors": [{"name": "my-check", "path": my_check,
                            "config": {"marker": "v2"}}]}, monkeypatch)
        after = {i.name: i for i in addon.inspectors}
        for name in ("domain", "secrets", "body-size", "content-type",
                     "my-check"):
            assert after[name] is before[name], name
        assert after["domain"].granted == {"granted.example"}
        assert "b.example" in after["domain"]._baseline
        assert after["my-check"].runtime_state == 42
        assert after["my-check"].marker == "v2"

    def test_path_inspector_file_is_not_reimported(self, tmp_path,
                                                   monkeypatch, my_check):
        from agentcage.data.proxy import addon as addon_mod

        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, {
            **_BASE, "inspectors": [{"name": "my-check", "path": my_check}]})
        calls = []
        real = addon_mod.load_inspector_from_file
        monkeypatch.setattr(addon_mod, "load_inspector_from_file",
                            lambda *a, **k: calls.append(a) or real(*a, **k))
        _reload_cfg(addon, cfg_path, {
            **_BASE, "entropy": {},
            "inspectors": [{"name": "my-check", "path": my_check,
                            "config": {"marker": "v2"}}]}, monkeypatch)
        assert calls == []
        assert "my-check" in _names(addon)

    def test_chain_is_swapped_not_mutated(self, tmp_path, monkeypatch):
        """A request chain running in the executor holds the chain it
        started with; the reload must hand over a new one, not grow or
        shrink that one under it."""
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, {
            **_BASE, "content_type": False})
        running = addon.inspectors
        snapshot = list(running)

        _reload_cfg(addon, cfg_path, {
            **_BASE, "inspectors": [{"name": "entropy", "config": {}}]},
            monkeypatch)
        assert list(running) == snapshot
        assert "entropy" in _names(addon)
        assert addon.inspectors is not running

    def test_a_failing_new_inspector_leaves_the_chain_alone(
            self, tmp_path, monkeypatch, my_check):
        """A path that cannot be imported aborts the reload before
        anything live is touched: same chain, same configs."""
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, {
            **_BASE, "content_type": {"entropy_ceiling": 7.0}})
        running = addon.inspectors
        before = _fingerprint(addon)
        outside = tmp_path / "elsewhere.py"
        outside.write_text(_MY_CHECK_SRC)

        cfg_path.write_text(yaml.safe_dump({
            **_BASE, "content_type": {"entropy_ceiling": 8.0}, "entropy": {},
            "inspectors": [{"name": "x", "path": str(outside)}]}))
        _bump_mtime(cfg_path)
        addon._reload_check()  # logs, never raises
        assert addon.inspectors is running
        assert _fingerprint(addon) == before


# A spread of configs covering every way a built-in is enabled,
# disabled or configured, plus a custom path inspector. Every ordered
# pair is reloaded A -> B (and back) and compared against fresh loads.
_CHAIN_CONFIGS = {
    "bare": {},
    "legacy-all-on": {"entropy": {"threshold": 7.5},
                      "max_request_body": 1000,
                      "content_type": {"entropy_ceiling": 6.0},
                      "secrets": {"action": "block"}},
    "legacy-all-off": {"content_type": False, "max_request_body": 0,
                       "entropy": False},
    "section-builtins": {"inspectors": [
        {"name": "entropy", "config": {"threshold": 6.5}},
        {"name": "body-size", "config": {"max_bytes": 50}},
    ]},
    "section-overrides-legacy": {
        "content_type": {"entropy_ceiling": 7.0},
        "max_request_body": 0,
        "inspectors": [
            {"name": "content-type", "config": {"entropy_ceiling": 8.0}},
            {"name": "secrets", "config": {"action": "flag"}},
            {"name": "body-size", "config": {"max_bytes": 10}},
        ]},
    "custom": {"content_type": False, "inspectors": [
        {"name": "my-check", "path": "{my_check}",
         "config": {"marker": "m"}},
        {"name": "entropy", "config": {}},
    ]},
    "custom-first": {"inspectors": [
        {"name": "my-check", "path": "{my_check}"},
        {"name": "content-type", "config": {"action": "flag"}},
    ]},
}


def _materialise(cfg, my_check):
    out = copy.deepcopy(cfg)
    for entry in out.get("inspectors", []):
        if entry.get("path") == "{my_check}":
            entry["path"] = my_check
    return {**_BASE, **out}


class TestReloadEqualsFreshLoad:
    @pytest.mark.parametrize("before,after", [
        (a, b) for a in _CHAIN_CONFIGS for b in _CHAIN_CONFIGS if a != b
    ])
    def test_reload_builds_the_chain_a_restart_would(
            self, tmp_path, monkeypatch, my_check, before, after):
        cfg_a = _materialise(_CHAIN_CONFIGS[before], my_check)
        cfg_b = _materialise(_CHAIN_CONFIGS[after], my_check)
        addon, cfg_path = _load_cfg(tmp_path, monkeypatch, cfg_a)
        _reload_cfg(addon, cfg_path, cfg_b, monkeypatch)
        reloaded = _fingerprint(addon)
        relay_chain = [i.name for i in addon._build_relay_inspectors()]

        fresh, _ = _load_cfg(tmp_path, monkeypatch, cfg_b, name="b.yaml")
        assert reloaded == _fingerprint(fresh)
        assert relay_chain == [
            i.name for i in fresh._build_relay_inspectors()]

        # And back again: the round trip lands on A's chain.
        _reload_cfg(addon, cfg_path, cfg_a, monkeypatch)
        fresh_a, _ = _load_cfg(tmp_path, monkeypatch, cfg_a, name="a.yaml")
        assert _fingerprint(addon) == _fingerprint(fresh_a)
