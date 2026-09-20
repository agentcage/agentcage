"""Host-side ``agentcage.state``: load_grants decoding and the atomic writers.

Split out of ``tests/test_policy_api_persist.py`` (RUST-PORT-PLAN.md §2.4).
These assert the *host* half of the grants overlay — ``state.load_grants``
mirroring the in-container ``_load_overlay``, and the save_* writers not
littering or writing through a symlinked temp — while the egress half stayed
behind with ``policy_api``. Test names are unchanged so failures stay greppable
against history.

Note the twin relationship the first class describes: the non-UTF8 tolerance
here mirrors ``policy_api._load_overlay``. That is a §2.2 behaviour contract;
PR A4 gives it a language-neutral fixture.
"""

from __future__ import annotations

import os



class TestHostLoadGrantsDecode:
    """``state.load_grants`` must not let ``UnicodeDecodeError`` escape — a
    non-UTF8 overlay file (corruption / a half-written swap) must read back
    as an empty list, mirroring the in-container twin ``_load_overlay``.
    Otherwise the 1Hz host watcher loop and the ``cage grants`` CLI crash."""

    def _patch_state(self, monkeypatch, tmp_path):
        from agentcage import state as host_state
        monkeypatch.setattr(
            host_state, "_DATA_DIR", tmp_path / "data" / "agentcage")
        return host_state

    def test_non_utf8_overlay_returns_empty(self, tmp_path, monkeypatch):
        host_state = self._patch_state(monkeypatch, tmp_path)
        name = "c"
        gf = host_state.grants_file(name)
        gf.parent.mkdir(parents=True, exist_ok=True)
        gf.write_bytes(b"\xff\xfe\x00bad")
        assert host_state.load_grants(name) == []

    def test_missing_file_returns_empty(self, tmp_path, monkeypatch):
        host_state = self._patch_state(monkeypatch, tmp_path)
        assert host_state.load_grants("nope") == []


class TestHostAtomicWriters:
    """``save_raw_config`` / ``save_metadata`` / ``save_grants`` must be
    atomic (temp + rename) so the 1Hz grants watcher and concurrent ``cage
    update`` / ``domain add`` never observe a half-written file. After a
    save: content round-trips and no ``*.tmp`` leftover remains in the
    directory. A pre-planted leftover temp (simulating a crashed writer, or
    a concurrent writer's in-flight temp at a colliding numeric PID) is
    NOT unlinked — the writer retries ONCE with a counter-suffixed name
    and the planted temp survives (Fix 1: unlinking a concurrent writer's
    in-flight temp would make its later rename fail — a lost write)."""

    def _patch_state(self, monkeypatch, tmp_path):
        from agentcage import state as host_state
        config_dir = tmp_path / "config" / "agentcage"
        monkeypatch.setattr(host_state, "_CONFIG_DIR", config_dir)
        monkeypatch.setattr(
            host_state, "_DEPLOYMENTS_DIR", config_dir / "cages")
        monkeypatch.setattr(
            host_state, "_DATA_DIR", tmp_path / "data" / "agentcage")
        return host_state

    def test_save_raw_config_round_trips_no_tmp(self, tmp_path, monkeypatch):
        host_state = self._patch_state(monkeypatch, tmp_path)
        raw = {"name": "c", "domains": {"allow": ["api.example.com"]}}
        host_state.save_raw_config("c", raw)
        d = host_state.deployment_dir("c")
        assert host_state.load_raw_config("c") == raw
        assert not list(d.glob("*.tmp")), "leftover temp file after save"

    def test_save_raw_config_does_not_unlink_leftover_tmp(self, tmp_path, monkeypatch):
        """Fix 1: a planted stale temp at the exact PID-suffixed path the
        helper would use is NOT unlinked by a subsequent save — the writer
        retries once with a counter-suffixed name (``cage.yaml.<pid>.1.tmp``)
        and the planted temp survives (unlinking it could delete a
        concurrent writer's in-flight temp). The save succeeds via the
        counter-suffixed name."""
        host_state = self._patch_state(monkeypatch, tmp_path)
        d = host_state.deployment_dir("c")
        d.mkdir(parents=True, exist_ok=True)
        # Plant a leftover temp at the exact path the helper would use.
        leftover = d / f"cage.yaml.{os.getpid()}.tmp"
        leftover.write_text("stale")
        host_state.save_raw_config("c", {"name": "c"})
        # The planted temp still exists (never unlinked).
        assert leftover.exists(), "planted temp was unlinked (Fix 1 regression)"
        assert leftover.read_text() == "stale", "planted temp was modified"
        # The save succeeded via the counter-suffixed name (now renamed to
        # cage.yaml); no counter-suffixed temp lingers.
        assert host_state.load_raw_config("c") == {"name": "c"}
        assert not list(d.glob("*.1.tmp")), \
            "counter-suffixed temp not renamed (published)"
        # The only ``*.tmp`` present is the planted one.
        assert [f.name for f in d.glob("*.tmp")] == [leftover.name]

    def test_save_raw_config_no_tmp_litter_on_normal_save(self, tmp_path, monkeypatch):
        """Fix 1 (b): a normal save (no collision) leaves no ``*.tmp`` litter
        — the single base temp is renamed to the target."""
        host_state = self._patch_state(monkeypatch, tmp_path)
        host_state.save_raw_config("c", {"name": "c"})
        d = host_state.deployment_dir("c")
        assert host_state.load_raw_config("c") == {"name": "c"}
        assert not list(d.glob("*.tmp")), "leftover temp file after save"

    def test_save_raw_config_does_not_write_through_symlink_temp(self, tmp_path, monkeypatch):
        """Fix 1: a planted symlink at the temp path must NOT be written
        through (O_EXCL). The writer does NOT unlink it (Fix 1) — it retries
        with a counter-suffixed name; the symlink survives, the outside
        target is untouched, and the save succeeds."""
        host_state = self._patch_state(monkeypatch, tmp_path)
        d = host_state.deployment_dir("c")
        d.mkdir(parents=True, exist_ok=True)
        target = tmp_path / "evil"
        target.write_text("secret")
        symlink_tmp = d / f"cage.yaml.{os.getpid()}.tmp"
        os.symlink(target, symlink_tmp)
        host_state.save_raw_config("c", {"name": "c"})
        assert host_state.load_raw_config("c") == {"name": "c"}
        # The symlink target was NOT overwritten with the YAML.
        assert target.read_text() == "secret"
        # The symlink still exists (never unlinked) — only the counter-
        # suffixed temp was created and renamed to cage.yaml.
        assert symlink_tmp.is_symlink(), "planted symlink was unlinked (Fix 1 regression)"
        assert not list(d.glob("*.1.tmp")), "counter-suffixed temp not published"

    def test_save_grants_does_not_unlink_leftover_tmp(self, tmp_path, monkeypatch):
        """Fix 1: a planted stale temp at the grants PID-suffixed path is
        NOT unlinked by ``save_grants`` — the writer retries once with a
        counter-suffixed name and the planted temp survives; the save
        succeeds via the counter-suffixed name."""
        host_state = self._patch_state(monkeypatch, tmp_path)
        gd = host_state.grants_dir("c")
        gd.mkdir(parents=True, exist_ok=True)
        gf = host_state.grants_file("c")
        leftover = gd / f"{gf.name}.{os.getpid()}.tmp"
        leftover.write_text("stale")
        entries = [{"domain": "x.com", "reason": "r"}]
        host_state.save_grants("c", entries)
        assert leftover.exists(), "planted temp was unlinked (Fix 1 regression)"
        assert leftover.read_text() == "stale"
        loaded = host_state.load_grants("c")
        assert loaded and loaded[0]["domain"] == "x.com"
        assert not list(gd.glob("*.1.tmp")), "counter-suffixed temp not published"
        assert [f.name for f in gd.glob("*.tmp")] == [leftover.name]

    def test_save_grants_no_tmp_litter_on_normal_save(self, tmp_path, monkeypatch):
        """Fix 1 (b): a normal ``save_grants`` leaves no ``*.tmp`` litter."""
        host_state = self._patch_state(monkeypatch, tmp_path)
        entries = [{"domain": "x.com", "reason": "r"}]
        host_state.save_grants("c", entries)
        gd = host_state.grants_dir("c")
        loaded = host_state.load_grants("c")
        assert loaded and loaded[0]["domain"] == "x.com"
        assert not list(gd.glob("*.tmp")), "leftover temp file after save"

    def test_save_metadata_round_trips_no_tmp(self, tmp_path, monkeypatch):
        host_state = self._patch_state(monkeypatch, tmp_path)
        meta = {"version": 1, "ports": {"icmp": {"allow": True}}}
        host_state.save_metadata("c", meta)
        d = host_state.deployment_dir("c")
        assert host_state.load_metadata("c") == meta
        assert not list(d.glob("*.tmp")), "leftover temp file after save"

    def test_save_grants_round_trips_no_tmp(self, tmp_path, monkeypatch):
        host_state = self._patch_state(monkeypatch, tmp_path)
        entries = [{"domain": "x.com", "reason": "r"}]
        host_state.save_grants("c", entries)
        gd = host_state.grants_dir("c")
        loaded = host_state.load_grants("c")
        assert loaded and loaded[0]["domain"] == "x.com"
        assert not list(gd.glob("*.tmp")), "leftover temp file after save"
