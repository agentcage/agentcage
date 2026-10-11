"""A WebAssembly custom inspector on the Python egress fails closed.

The host stages ``.wasm`` plugins (``inspectors: [{name, path: x.wasm}]``)
for the Rust egress, which loads them. This egress has no WebAssembly
runtime: it must neither crash on such an entry (``load_inspector_from_file``
cannot import a ``.wasm`` file) nor skip it, which would run the cage
without an inspector its operator relies on. It blocks instead, with a
reason that says why.
"""

import os

import yaml


def _make_addon(tmp_path, monkeypatch, inspectors):
    from agentcage.data.proxy import addon as addon_mod

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "domains": {"allow": ["a.com"]},
        "inspectors": inspectors,
    }))
    monkeypatch.setattr(addon_mod, "CONFIG_PATH", str(cfg_path))
    addon = addon_mod.Agentcage()
    addon.load(loader=None)
    return addon, cfg_path


def _ctx():
    from agentcage.data.proxy.inspectors.base import InspectionContext

    return InspectionContext(
        url="https://a.com/", host="a.com", method="GET", headers=[],
        content_type="", body_bytes=None, body_text=None, body_size=0)


def test_a_wasm_plugin_loads_as_a_blocking_stand_in(tmp_path, monkeypatch):
    addon, _ = _make_addon(tmp_path, monkeypatch, [
        {"name": "dlp", "path": "dlp_regex_inspector.wasm",
         "config": {"patterns": []}},
    ])
    plugin = [i for i in addon.inspectors if i.name == "dlp"]
    assert len(plugin) == 1
    # Last in the chain, after the built-ins.
    assert addon.inspectors[-1] is plugin[0]
    result = plugin[0].inspect_request(_ctx())
    assert result.action == "block"
    assert result.severity == "error"
    assert result.inspector == "dlp"
    assert result.reason == (
        "inspector dlp failed: WebAssembly inspectors are not supported "
        "by this egress")
    assert plugin[0].inspect_response(_ctx()) is None


def test_reload_keeps_one_stand_in(tmp_path, monkeypatch):
    entries = [{"name": "dlp", "path": "dlp.wasm"}]
    addon, cfg_path = _make_addon(tmp_path, monkeypatch, entries)
    before = [i for i in addon.inspectors if i.name == "dlp"]
    cfg_path.write_text(yaml.safe_dump({
        "domains": {"allow": ["a.com", "b.com"]}, "inspectors": entries}))
    os.utime(cfg_path, (0, os.stat(cfg_path).st_mtime + 5))
    addon._maybe_reload()
    after = [i for i in addon.inspectors if i.name == "dlp"]
    assert len(after) == 1
    assert after[0] is before[0]
