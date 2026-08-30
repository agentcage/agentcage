"""Integration tests for the ``PolicyApi`` overlay persist + revoke path.

These cover the bug found in review: ``_persist_grants`` must NOT drop a
freshly-decided grant (the B1 failure mode — reconcile unconditionally
discards in-memory grants absent from the on-disk overlay, which doesn't
yet contain the just-decided domain) AND a host-side revoke must eventually
be honored (the I1 race — an external rewrite of the overlay removing a
domain is picked up by the sweeper's mtime-gated poll, not by a reconcile
inside persist).

Exercises ``PolicyApi._apply_grant`` -> ``_persist_grants`` -> overlay file
and the ``maybe_reload_overlay`` sweeper poll, against a real temp grants
dir so the on-disk file is genuine.
"""

from __future__ import annotations

import os
import sys
import time
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

# ── Stub mitmproxy before importing the addon's policy_api module ────────
_mitmproxy = types.ModuleType("mitmproxy")
_mitmproxy.__path__ = []
_mitmproxy.ctx = MagicMock()
_mitmproxy.http = MagicMock()
_proxy = types.ModuleType("mitmproxy.proxy")
_proxy.__path__ = []
_mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
sys.modules.setdefault("mitmproxy", _mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mitmproxy.http)
sys.modules.setdefault("mitmproxy.proxy", _proxy)
_proxy.mode_specs = _mode_specs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "src" / "agentcage" / "data" / "proxy"))

from inspectors.domain import DomainInspector  # noqa: E402
from policy_api import PolicyApi  # noqa: E402


def _make_pa(tmp_path, monkeypatch):
    """Build a PolicyApi with a real temp grants dir (so the overlay file
    is genuine, not mocked)."""
    monkeypatch.setenv("AGENTCAGE_GRANTS_DIR", str(tmp_path))
    dom = DomainInspector()
    dom.configure({"allow": ["a.com"]})
    cfg = {"domains": {"allow": ["a.com"], "auto": {
        "enable": True,
        "decider": {"kind": "agent", "provider": "openrouter",
                    "model": "m", "api_key": "env:K"},
    }}}
    pa = PolicyApi(cfg, dom, lambda e: None, MagicMock())
    return pa, dom, tmp_path / "grants.yaml"


class TestPersistFreshGrant:
    def test_fresh_grant_is_persisted(self, tmp_path, monkeypatch):
        """_apply_grant -> _persist_grants writes the just-decided domain to
        the overlay. Regression guard for the B1-class bug where an
        unconditional reconcile-before-write dropped the fresh grant."""
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("x.com", "reason", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        data = yaml.safe_load(overlay.read_text())
        assert data and any(e["domain"] == "x.com" for e in data), \
            "fresh grant was dropped before persist (B1 regression)"
        assert dom.is_granted("x.com")

    def test_fresh_grant_lives_in_memory_and_overlay(self, tmp_path, monkeypatch):
        """The in-memory set and the on-disk overlay agree after a grant."""
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("y.com", "r", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert dom.is_granted("y.com")
        data = yaml.safe_load(overlay.read_text())
        assert len(data) == 1 and data[0]["domain"] == "y.com"


class TestPersistHonorsRevoke:
    def test_host_revoke_drops_entry_via_sweeper(self, tmp_path, monkeypatch):
        """A host-side rewrite of the overlay (removing a domain) + mtime
        bump is honored when the sweeper's mtime-gated poll runs
        (``maybe_reload_overlay``): the addon reconciles, drops the revoked
        domain from memory, and a subsequent persist writes an overlay without
        it. ``_persist_grants`` itself does NOT reconcile (that would drop a
        fresh grant); external changes land via the periodic poll."""
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("x.com", "r", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert dom.is_granted("x.com")
        # Host revokes x.com: rewrite the overlay empty, bump mtime forward.
        overlay.write_text("[]\n")
        ft = time.time() + 100
        os.utime(overlay, (ft, ft))
        # The sweeper poll (mtime-gated) picks up the external change.
        assert pa.maybe_reload_overlay() is True
        assert not dom.is_granted("x.com"), "revoke not honored by sweeper poll"
        pa._persist_grants()
        data = yaml.safe_load(overlay.read_text())
        assert not any(e["domain"] == "x.com" for e in (data or [])), \
            "revoked entry re-persisted"

    def test_fresh_grant_survives_unrelated_revoke(self, tmp_path, monkeypatch):
        """A fresh grant for a new domain is NOT dropped by a prior external
        revoke of a *different* domain. The addon writes its full in-memory
        set; the revoked domain is gone (sweeper handled it), the fresh one
        persists."""
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("x.com", "r", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        # Revoke x.com externally + let the sweeper pick it up.
        overlay.write_text("[]\n")
        ft = time.time() + 100
        os.utime(overlay, (ft, ft))
        pa.maybe_reload_overlay()
        assert not dom.is_granted("x.com")
        # New grant for a different domain — must persist.
        pa._apply_grant("z.com", "r2", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert not dom.is_granted("x.com"), "revoked x.com resurrected"
        assert dom.is_granted("z.com"), "fresh z.com lost"
        data = yaml.safe_load(overlay.read_text())
        domains = {e["domain"] for e in (data or [])}
        assert "z.com" in domains and "x.com" not in domains


class TestGrantReconcilesBeforePersist:
    """_apply_grant reconciles from the overlay BEFORE adding the fresh
    grant — so a host-side revoke that hit disk cannot be resurrected by
    the very next addon grant (the 5th-review HIGH finding: a resurrected
    entry would be promoted into the baseline by the host watcher —
    permanently, since promotion is not idempotent w.r.t. revoke)."""

    def test_grant_picks_up_pending_revoke_first(self, tmp_path, monkeypatch):
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("x.com", "r", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert dom.is_granted("x.com")
        # Host revokes x.com: overlay rewritten without it, mtime bumped.
        # NO sweeper tick runs — the next _apply_grant itself must see it.
        overlay.write_text("[]\n")
        ft = time.time() + 100
        os.utime(overlay, (ft, ft))
        # A new grant arrives before the sweeper's 30s poll would fire.
        pa._apply_grant("z.com", "r2", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert not dom.is_granted("x.com"), \
            "revoked x.com resurrected by the next grant's persist"
        assert dom.is_granted("z.com")
        data = yaml.safe_load(overlay.read_text())
        domains = {e["domain"] for e in (data or [])}
        assert "z.com" in domains and "x.com" not in domains, \
            "resurrected x.com written to overlay — watcher would promote it"

    def test_grant_without_external_change_is_untouched(self, tmp_path, monkeypatch):
        """The reconcile-before-grant is mtime-gated: with no external
        change it must not drop the in-memory grants (B1 stays fixed)."""
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        pa._apply_grant("x.com", "r", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        pa._apply_grant("y.com", "r2", ttl_override=0,
                        decided_by="decider:agent:openrouter")
        assert dom.is_granted("x.com") and dom.is_granted("y.com")
        data = yaml.safe_load(overlay.read_text())
        domains = {e["domain"] for e in (data or [])}
        assert domains == {"x.com", "y.com"}


class TestNegativeTtlDenied:
    """A negative ttl_seconds from the decider is out-of-contract output —
    the grant must be DENIED (fail-closed), not collapsed to a permanent
    grant by ``_expires_at``."""

    def test_negative_ttl_denies(self, tmp_path, monkeypatch):
        import asyncio
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        # Configure the LLM path (white-box: pretend the api_key resolved).
        pa._llm_provider = "openrouter"
        pa._llm_model = "m"
        pa._llm_secret = "sk-test"
        # The decider misbehaves: grants with a NEGATIVE ttl.
        pa._llm_call_sync = lambda domain, reason, timeout: {
            "decision": "grant", "reason": "r", "ttl_seconds": -5,
        }
        flow = MagicMock()
        asyncio.run(pa._decide_llm(flow, "neg.com", "need it"))
        # The response is a MagicMock (stubbed mitmproxy), so assert via the
        # durable side effects: no grant in memory, no overlay entry.
        assert not dom.is_granted("neg.com"), \
            "negative ttl_seconds must never produce a grant"
        assert not overlay.exists() or \
            not any(e["domain"] == "neg.com"
                    for e in (yaml.safe_load(overlay.read_text()) or [])), \
            "negative-ttl grant must not reach the overlay"

    def test_positive_ttl_still_grants(self, tmp_path, monkeypatch):
        import asyncio
        pa, dom, overlay = _make_pa(tmp_path, monkeypatch)
        pa._llm_provider = "openrouter"
        pa._llm_model = "m"
        pa._llm_secret = "sk-test"
        pa._llm_call_sync = lambda domain, reason, timeout: {
            "decision": "grant", "reason": "r", "ttl_seconds": 60,
        }
        flow = MagicMock()
        asyncio.run(pa._decide_llm(flow, "pos.com", "need it"))
        assert dom.is_granted("pos.com")
        data = yaml.safe_load(overlay.read_text())
        assert any(e["domain"] == "pos.com" for e in (data or []))


# ── Host-side state.py: load_grants / atomic writers ────────────────


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
    directory; a pre-planted leftover temp (simulating a crashed writer)
    is cleared and the save still succeeds."""

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

    def test_save_raw_config_clears_leftover_tmp(self, tmp_path, monkeypatch):
        host_state = self._patch_state(monkeypatch, tmp_path)
        d = host_state.deployment_dir("c")
        d.mkdir(parents=True, exist_ok=True)
        # Plant a leftover temp from a hypothetical previous crash.
        leftover = d / f"cage.yaml.{os.getpid()}.tmp"
        leftover.write_text("stale")
        host_state.save_raw_config("c", {"name": "c"})
        assert host_state.load_raw_config("c") == {"name": "c"}
        assert not leftover.exists(), "leftover temp not cleared"
        assert not list(d.glob("*.tmp"))

    def test_save_raw_config_replaces_symlink_temp(self, tmp_path, monkeypatch):
        host_state = self._patch_state(monkeypatch, tmp_path)
        d = host_state.deployment_dir("c")
        d.mkdir(parents=True, exist_ok=True)
        # A planted symlink at the temp path must NOT be written through
        # (O_EXCL); the writer unlinks it and retries.
        target = tmp_path / "evil"
        target.write_text("secret")
        symlink_tmp = d / f"cage.yaml.{os.getpid()}.tmp"
        os.symlink(target, symlink_tmp)
        host_state.save_raw_config("c", {"name": "c"})
        assert host_state.load_raw_config("c") == {"name": "c"}
        # The symlink target was NOT overwritten with the YAML.
        assert target.read_text() == "secret"
        assert not list(d.glob("*.tmp"))

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
