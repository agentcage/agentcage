"""Regression tests for grant TTL preservation on promotion.

Both promote paths — the watcher's `_tick` step 2 (``cage grants watch
--once``) and the operator's ``cage grants promote`` — must copy a grant's
``expires_at`` from the overlay entry into the baseline's
``domains.expires`` map. Without that, the overlay entry (the only place
the TTL lived) is deleted on promotion one tick later, silently turning a
short-lived ``ttl_seconds`` grant into a permanent baseline entry:
step-0 pruning reads ``domains.expires`` (now empty for that domain) and
step-1 pruning only sees entries still in the overlay (already removed).

Found cross-confirmed by two reviewers (Sol + K3) in the 4th review pass.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from click.testing import CliRunner

from agentcage.cli import main
from agentcage.config import load_config, valid_domain, validate_config


def _runner():
    return CliRunner()


def _raw():
    return {
        "name": "basic",
        "container": {"image": "node:22-slim",
                      "command": ["node", "/app/agent.js"]},
        "domains": {"allow": ["anthropic.com"]},
    }


def _overlay_entries():
    # A decided grant with a TTL (the decider returned ttl_seconds=600).
    # expires_at is far-future so the watcher's step-1 expiry check doesn't
    # classify it expired before promotion (the test targets step 2).
    return [{
        "domain": "x.com",
        "reason": "docs lookup",
        "source": "decider:agent:openrouter",
        "granted_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2030-01-01T00:10:00+00:00",
    }]


class TestWatchPromotesTtl:
    """``cage grants watch --once`` must preserve the grant's TTL."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_watch_promote_writes_domains_expires(
        self, mock_state, mock_apply
    ):
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = _overlay_entries()
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        # The baseline change was persisted with the domain added...
        saved = mock_apply.call_args[0][1]
        assert "x.com" in saved["domains"]["allow"]
        # ...AND its TTL preserved in domains.expires.
        expires = saved["domains"]["expires"]
        assert expires["x.com"] == "2030-01-01T00:10:00+00:00"

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_watch_promote_permanent_grant_no_expires_entry(
        self, mock_state, mock_apply
    ):
        """A permanent grant (no expires_at) must NOT grow domains.expires."""
        entries = _overlay_entries()
        del entries[0]["expires_at"]
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = entries
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        assert "x.com" in saved["domains"]["allow"]
        assert "expires" not in saved["domains"] or \
            "x.com" not in saved["domains"]["expires"]


class TestManualPromotePreservesTtl:
    """``cage grants promote <domain>`` must preserve the grant's TTL."""

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_promote_writes_domains_expires(
        self, mock_state, mock_apply, mock_backend
    ):
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = _overlay_entries()
        mock_state.load_deployment_config.return_value = _make_cfg()
        mock_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "promote", "x.com"]
        )
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        assert "x.com" in saved["domains"]["allow"]
        assert saved["domains"]["expires"]["x.com"] == \
            "2030-01-01T00:10:00+00:00"

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_promote_permanent_grant_no_expires_entry(
        self, mock_state, mock_apply, mock_backend
    ):
        entries = _overlay_entries()
        del entries[0]["expires_at"]
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = entries
        mock_state.load_deployment_config.return_value = _make_cfg()
        mock_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "promote", "x.com"]
        )
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        assert "x.com" in saved["domains"]["allow"]
        assert "expires" not in saved["domains"] or \
            "x.com" not in saved["domains"]["expires"]


# ── Fix: un-normalized domain appended to domains.allow (MEDIUM) ────────


class TestPromoteNormalizesDomain:
    """Both promote paths validated the LOWERCASED form (``dl = d.lower()``)
    but appended the RAW original — so an uppercase (or, pre-Fix-2,
    newline-bearing) overlay entry landed in cage.yaml, which
    ``validate_config`` then REJECTED (the regex is lowercase-only), making
    the cage's own config unparseable. The appended value must be the
    CANONICAL form: lowercased, trailing dots stripped, newline-free by
    construction."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_watch_promotes_uppercase_as_lowercase(self, mock_state, mock_apply):
        """An overlay entry whose ``domain`` is uppercase (the overlay is
        host-writable, so casing is not guaranteed) promotes into
        ``domains.allow`` as the lowercase canonical form."""
        # Use the REAL validator so the test also confirms the lowered form
        # is genuinely valid (not just that the append happened).
        mock_state.valid_domain.side_effect = valid_domain
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = [{
            "domain": "API.Example.com",
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "",
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"])
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        allow = saved["domains"]["allow"]
        # The appended value is the canonical lowercase form, NOT the raw
        # uppercase overlay value.
        assert "api.example.com" in allow
        assert "API.Example.com" not in allow

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_manual_promote_uppercase_as_lowercase(
        self, mock_state, mock_apply, mock_backend
    ):
        """``grants promote API.Example.com`` stores the canonical lowercase
        form in the baseline (the operator's raw argument is not appended
        verbatim)."""
        mock_state.valid_domain.side_effect = valid_domain
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = [{
            "domain": "api.example.com",
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "",
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()
        mock_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "promote", "API.Example.com"])
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        allow = saved["domains"]["allow"]
        assert "api.example.com" in allow
        assert "API.Example.com" not in allow

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_watch_rejects_newline_bearing_overlay_entry(
        self, mock_state, mock_apply
    ):
        """An overlay entry whose ``domain`` ends with a newline is rejected
        (the addon's request path would have rejected it at grant time, but
        the overlay is host-writable so the watcher must too): not promoted,
        not removed from the overlay, and audited once as
        ``policy_grant_rejected``."""
        mock_state.valid_domain.side_effect = valid_domain
        malicious = "evil.com\n"
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = [{
            "domain": malicious,
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:10:00+00:00",  # future → pending
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"])
        assert result.exit_code == 0, result.output

        # Not promoted, not removed.
        mock_apply.assert_not_called()
        mock_state.save_grants.assert_not_called()
        audits = [c.args[1]
                  for c in mock_state.append_policy_audit.call_args_list]
        rejected = [a for a in audits
                    if a.get("kind") == "policy_grant_rejected"]
        assert len(rejected) == 1
        assert rejected[0]["reason"] == "invalid domain syntax"


class TestPromoteRoundTripValidates:
    """Round-trip guard for the regression the finding describes: after a
    promote of a mixed-case entry, the resulting cage.yaml's ``domains.allow``
    must pass its OWN ``validate_config`` — pre-fix an uppercase entry landed
    in the file and the cage's config became unparseable."""

    @staticmethod
    def _round_trip_validate(saved_raw, tmp_path):
        """Dump the saved raw config to a file and load+validate it."""
        import yaml
        # load_config requires ``dns_servers`` (autodetect fails in CI); the
        # watcher's raw fixture omits it, so ensure it is present.
        raw = dict(saved_raw)
        raw.setdefault("dns_servers", ["1.1.1.1"])
        p = tmp_path / "round-trip.yaml"
        p.write_text(yaml.safe_dump(raw))
        cfg = load_config(str(p))
        validate_config(cfg)  # must not raise
        return cfg

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_watch_promote_yields_self_validating_config(
        self, mock_state, mock_apply, tmp_path
    ):
        mock_state.valid_domain.side_effect = valid_domain
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = [{
            "domain": "API.Example.com",
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "",
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"])
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        cfg = self._round_trip_validate(saved, tmp_path)
        assert cfg.domains.allow == ["anthropic.com", "api.example.com"]

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_manual_promote_yields_self_validating_config(
        self, mock_state, mock_apply, mock_backend, tmp_path
    ):
        mock_state.valid_domain.side_effect = valid_domain
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = [{
            "domain": "api.example.com",
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "",
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()
        mock_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "promote", "API.Example.com"])
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        cfg = self._round_trip_validate(saved, tmp_path)
        assert cfg.domains.allow == ["anthropic.com", "api.example.com"]


def _make_cfg():
    """A minimal deployment config for get_backend().is_running lookups."""
    cfg = MagicMock()
    cfg.name = "basic"
    cfg.backend = "container"
    # is_running is only used for the "DNS and proxy updated." message —
    # return False to skip backend interaction entirely.
    cfg.is_running = MagicMock(return_value=False)
    return cfg


class TestWatchRemovesPromotedEntries:
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_watch_removes_promoted_from_overlay(
        self, mock_state, mock_apply
    ):
        """After promotion, the overlay entry is removed (it lives in the
        baseline now) — and its TTL moved to domains.expires, not lost."""
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = _overlay_entries()
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        # save_grants called with the promoted entry removed...
        saved_overlay = mock_state.save_grants.call_args[0][1]
        assert saved_overlay == []
        # ...but its expires_at survived into the baseline.
        saved_raw = mock_apply.call_args[0][1]
        assert saved_raw["domains"]["expires"]["x.com"] == \
            "2030-01-01T00:10:00+00:00"


class TestWatchExpiredOverlayNotInBaseline:
    """Step 1 must persist the overlay even when an expired entry's domain
    is NOT in the baseline allow list — otherwise the entry reloads next
    tick and re-audits (policy_grant_removed) every tick forever, never
    converging."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_expired_overlay_not_in_baseline_is_persisted(
        self, mock_state, mock_apply
    ):
        # The expired domain "x.com" is NOT in domains.allow.
        mock_state.load_raw_config.return_value = {
            "name": "basic",
            "container": {"image": "node:22-slim",
                          "command": ["node", "/app/agent.js"]},
            "domains": {"allow": ["anthropic.com"]},
        }
        mock_state.load_grants.return_value = [{
            "domain": "x.com",
            "reason": "docs lookup",
            "source": "decider:agent:openrouter",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2000-01-01T00:00:00+00:00",  # past → expired
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        # The overlay is re-saved WITHOUT the expired entry (step-3
        # persistence fired because `changed` was set for any expired
        # entry, not only when the baseline was edited)...
        saved_overlay = mock_state.save_grants.call_args[0][1]
        assert saved_overlay == []
        # ...and _apply_baseline_change was NOT called (nothing was
        # removed from the baseline — the domain wasn't in domains.allow).
        mock_apply.assert_not_called()


class TestWatchStaleExpiresNotInAllow:
    """Step 0 must persist the shrunk ``domains.expires`` map even when the
    expired domain is NOT in ``domains.allow`` — otherwise the stale entry
    is popped in memory only, never persisted, and re-audited every tick
    forever."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_stale_expires_persisted_without_baseline_change(
        self, mock_state, mock_apply
    ):
        raw = {
            "name": "basic",
            "container": {"image": "node:22-slim",
                          "command": ["node", "/app/agent.js"]},
            "domains": {
                "allow": ["anthropic.com"],
                "expires": {"stale.com": "2000-01-01T00:00:00+00:00"},
            },
        }
        mock_state.load_raw_config.return_value = raw
        mock_state.load_grants.return_value = []
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        # The stale expires entry was popped and the shrunk config
        # persisted via save_raw_config (the persist-without-baseline-edit
        # path), so it won't reappear next tick.
        saved_raw = mock_state.save_raw_config.call_args[0][1]
        expires = saved_raw["domains"].get("expires", {})
        assert "stale.com" not in expires
        # _apply_baseline_change NOT called (removed_any was False — the
        # domain wasn't in the allow list, so no real baseline edit).
        mock_apply.assert_not_called()


class TestWatchBlocklistModeSkipsPromotion:
    """Step 2 must NOT promote grants in blocklist mode. A grant only widens
    the allow set; appending a granted domain to the BLOCK list is the
    exact opposite. Mirrors ``grants_promote``'s refusal: "cannot promote
    into a blocklist-mode cage"."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_blocklist_mode_skips_promotion(
        self, mock_state, mock_apply
    ):
        # Blocklist mode: domains.block present, domains.allow absent.
        mock_state.load_raw_config.return_value = {
            "name": "basic",
            "container": {"image": "node:22-slim",
                          "command": ["node", "/app/agent.js"]},
            "domains": {"block": ["evil.com"]},
        }
        mock_state.load_grants.return_value = [{
            "domain": "x.com",
            "reason": "docs lookup",
            "source": "decider:agent:openrouter",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:10:00+00:00",  # future → pending
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        # Promotion skipped: no baseline change, no overlay rewrite —
        # the entry stays pending (step 1 still drops expired ones).
        mock_apply.assert_not_called()
        mock_state.save_grants.assert_not_called()


class TestEnsureGrantsWatcherBackendGate:
    """_ensure_grants_watcher must never write a systemd unit at the
    apple-container launchd .plist path — the apple backend installs its
    own plist. VM cages now get a real host-side watcher: launchd plist
    on macOS hosts, the same systemd user unit as the container backend
    on Linux hosts (with a 5s poll interval — each tick is a limactl SSH
    round-trip)."""

    @patch("agentcage.cli.get_backend")
    def test_apple_delegates_to_install_plist(self, mock_backend):
        backend = MagicMock()
        # grants_unit_path returns a .plist path — the trap: writing the
        # systemd unit there would corrupt it.
        from pathlib import Path
        backend.grants_unit_path.return_value = Path(
            "/tmp/io.agentcage.x.grants.plist")
        install = backend._install_grants_plist
        mock_backend.return_value = backend

        from agentcage.cli import _ensure_grants_watcher
        cfg = MagicMock()
        cfg.isolation = "apple-container"
        _ensure_grants_watcher("x", cfg)

        install.assert_called_once_with("x")
        # And the systemd-unit write path was never taken: the plist path
        # must still not exist (no unit string written into it).
        assert not Path("/tmp/io.agentcage.x.grants.plist").exists()

    @patch("agentcage.cli.get_backend")
    def test_vm_linux_writes_unit_with_5s_interval(self, mock_backend, tmp_path):
        # Linux host (qemu Lima): the watcher is the SAME systemd user
        # unit the container backend installs — host-side path, 5s
        # interval (limactl round-trips make 1 Hz chatty).
        backend = MagicMock()
        unit = tmp_path / "x-grants.service"
        backend.grants_unit_path.return_value = unit
        del backend._install_grants_plist
        mock_backend.return_value = backend

        from agentcage.cli import _ensure_grants_watcher
        import agentcage.systemd as _systemd
        cfg = MagicMock()
        cfg.isolation = "vm"
        with patch.object(_systemd, "start_unit") as mock_start, \
             patch.object(_systemd, "enable_unit") as mock_enable:
            _ensure_grants_watcher("x", cfg)

        assert unit.exists()
        assert "--interval 5" in unit.read_text()
        mock_start.assert_called_once_with("x-grants.service")
        mock_enable.assert_called_once_with("x-grants.service")

    @patch("agentcage.cli.get_backend")
    def test_vm_darwin_installs_plist(self, mock_backend, tmp_path, monkeypatch):
        # macOS host (Lima/vz): launchd plist via the shared installer in
        # agentcage.watcher (same one the apple-container backend uses),
        # 5s interval.
        backend = MagicMock()
        backend.grants_unit_path.return_value = tmp_path / "x-grants.service"
        del backend._install_grants_plist
        mock_backend.return_value = backend

        from agentcage import watcher as _watcher
        calls = {}

        def _fake_install(name, *, log_dir, interval=1, plist_path=None):
            calls["name"] = name
            calls["interval"] = interval

        monkeypatch.setattr(_watcher, "install_grants_watcher_plist",
                            _fake_install)
        monkeypatch.setattr("agentcage.cli.sys.platform", "darwin")

        from agentcage.cli import _ensure_grants_watcher
        import agentcage.systemd as _systemd
        cfg = MagicMock()
        cfg.isolation = "vm"
        with patch.object(_systemd, "start_unit") as mock_start:
            _ensure_grants_watcher("x", cfg)

        assert calls == {"name": "x", "interval": 5}
        mock_start.assert_not_called()  # launchd, not systemd
        assert not (tmp_path / "x-grants.service").exists()

    @patch("agentcage.cli.get_backend")
    def test_container_backend_still_writes_unit(self, mock_backend, tmp_path):
        backend = MagicMock()
        unit = tmp_path / "x-grants.service"
        backend.grants_unit_path.return_value = unit
        # No _install_grants_plist on the container backend.
        del backend._install_grants_plist
        mock_backend.return_value = backend

        from agentcage.cli import _ensure_grants_watcher
        import agentcage.systemd as _systemd
        cfg = MagicMock()
        cfg.isolation = "container"
        with patch.object(_systemd, "start_unit") as mock_start, \
             patch.object(_systemd, "enable_unit") as mock_enable:
            _ensure_grants_watcher("x", cfg)

        assert unit.exists()
        assert "[Unit]" in unit.read_text()
        mock_start.assert_called_once_with("x-grants.service")
        # Fix 4: the native .service must be ENABLED so it survives a
        # host reboot (quadlet units are generator-activated; this native
        # unit is not — without enable it stays dead after reboot while
        # the egress and cage come up).
        mock_enable.assert_called_once_with("x-grants.service")


# ── Fix 1: watcher _tick lost-update race (merge-on-write) ───────────────


class TestTickMergeOnWrite:
    """Lost-update race: a grant the egress addon persisted DURING the
    watcher's step-2 podman-exec window (after the top-of-``_tick``
    snapshot but before the step-3 save) must survive the tick's overlay
    write. The snapshot is stale by the time step 3 runs; the fix
    re-reads the on-disk overlay at write time and drops only this tick's
    intentional removals (``removed_domains``)."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_fresh_grant_survives_tick(self, mock_state, mock_apply):
        mock_state.valid_domain.return_value = True
        snapshot = [{
            "domain": "old.com",
            "reason": "r",
            "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:10:00+00:00",  # future → pending
        }]
        fresh = {
            "domain": "fresh.com",
            "reason": "addon wrote this during step 2",
            "source": "decider",
            "granted_at": "2026-01-01T00:00:01+00:00",
            "expires_at": "2030-01-01T00:10:00+00:00",
        }
        # 1st load_grants = top-of-_tick snapshot; 2nd = step-3 re-read,
        # by which point the addon has persisted `fresh`.
        mock_state.load_grants.side_effect = [
            list(snapshot), snapshot + [fresh],
        ]
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        # old.com was promoted → removed from the overlay; fresh.com was
        # written by the addon AFTER the snapshot and MUST survive the
        # merge-on-write (it is not in any removal set).
        saved = mock_state.save_grants.call_args[0][1]
        saved_domains = {
            str(e.get("domain", "")).rstrip(".").lower() for e in saved
        }
        assert "fresh.com" in saved_domains
        assert "old.com" not in saved_domains

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_revoke_merges_on_write(self, mock_state, mock_apply):
        """grants_revoke must drop ONLY the revoked domain — a grant the
        addon persisted between the load and the save survives (Fix 1)."""
        mock_state.valid_domain.return_value = True
        revoke_target = [{
            "domain": "evil.com",
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "",
        }]
        fresh = {
            "domain": "fresh.com",
            "reason": "addon wrote this",
            "source": "decider",
            "granted_at": "2026-01-01T00:00:01+00:00",
            "expires_at": "",
        }
        # 1st load_grants (presence check) = [evil]; 2nd (merge re-read)
        # = [evil, fresh] — the addon persisted fresh in between.
        mock_state.load_grants.side_effect = [
            list(revoke_target), revoke_target + [fresh],
        ]
        mock_state.load_raw_config.return_value = _raw()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "revoke", "evil.com"]
        )
        assert result.exit_code == 0, result.output

        saved = mock_state.save_grants.call_args[0][1]
        saved_domains = {
            str(e.get("domain", "")).rstrip(".").lower() for e in saved
        }
        assert "evil.com" not in saved_domains
        assert "fresh.com" in saved_domains  # survived the merge


# ── Fix 3: no domain-syntax validation on promote (dnsmasq injection) ────


class TestTickRejectsInvalidDomain:
    """An overlay entry with invalid domain syntax (a dnsmasq directive
    injection payload like ``foo.com/\\nserver=/#``) must NOT be promoted,
    must NOT be removed from the overlay (the operator can still see the
    rejected grant), and must be audited exactly once per run."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_invalid_domain_not_promoted_and_audited_once(
        self, mock_state, mock_apply
    ):
        mock_state.valid_domain.return_value = False  # every domain invalid
        malicious = "foo.com/\nserver=/#"
        mock_state.load_grants.return_value = [{
            "domain": malicious,
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:10:00+00:00",  # future → pending
        }]
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        # Not promoted: no baseline change at all.
        mock_apply.assert_not_called()
        # Not removed: nothing written — the entry stays on disk.
        mock_state.save_grants.assert_not_called()
        # Audited once with the rejection kind/reason.
        audits = [c.args[1]
                  for c in mock_state.append_policy_audit.call_args_list]
        rejected = [a for a in audits
                    if a.get("kind") == "policy_grant_rejected"]
        assert len(rejected) == 1
        assert rejected[0]["reason"] == "invalid domain syntax"

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_never_grant_domain_not_promoted(self, mock_state, mock_apply):
        """An overlay entry matching the never_grant floor (internal /
        localhost / control host) must be rejected + audited, never
        promoted — mirroring the addon's PolicyApi._is_never_grant."""
        mock_state.valid_domain.return_value = True  # syntax OK
        mock_state.load_grants.return_value = [{
            "domain": "metadata.google.internal",
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:10:00+00:00",
        }]
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "watch", "--once"]
        )
        assert result.exit_code == 0, result.output

        mock_apply.assert_not_called()
        mock_state.save_grants.assert_not_called()
        audits = [c.args[1]
                  for c in mock_state.append_policy_audit.call_args_list]
        rejected = [a for a in audits
                    if a.get("kind") == "policy_grant_rejected"]
        assert len(rejected) == 1
        assert rejected[0]["reason"] == "never_grant"


# ── Fix 3 (manual promote): refuse invalid / not-in-overlay ──────────────


class TestPromoteRefuses:
    """``grants promote`` must refuse (not silently ``domain add``) when
    the domain is not a runtime grant, and refuse invalid-syntax overlay
    domains — mirroring ``grants_revoke``'s refusal pattern."""

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_promote_refuses_domain_not_in_overlay(
        self, mock_state, mock_apply, mock_backend
    ):
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = []  # no runtime grant
        mock_state.load_deployment_config.return_value = _make_cfg()
        mock_state.valid_domain.return_value = True
        mock_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "promote", "evil.com"]
        )
        assert result.exit_code != 0
        assert "is not a runtime grant" in result.output
        assert "domain add" in result.output
        mock_apply.assert_not_called()
        mock_state.save_grants.assert_not_called()

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_promote_refuses_invalid_domain_syntax(
        self, mock_state, mock_apply, mock_backend
    ):
        mock_state.load_raw_config.return_value = _raw()
        malicious = "foo.com/\nserver=/#"
        mock_state.load_grants.return_value = [{
            "domain": malicious,
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "",
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()
        mock_state.valid_domain.return_value = False
        mock_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "promote", malicious]
        )
        assert result.exit_code != 0
        assert "invalid domain" in result.output
        mock_apply.assert_not_called()
        mock_state.save_grants.assert_not_called()

    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_promote_refuses_never_grant(self, mock_state, mock_apply,
                                         mock_backend):
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_grants.return_value = [{
            "domain": "agentcage.local",  # the control host
            "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "",
        }]
        mock_state.load_deployment_config.return_value = _make_cfg()
        mock_state.valid_domain.return_value = True
        mock_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "promote", "agentcage.local"]
        )
        assert result.exit_code != 0
        assert "never_grant" in result.output
        mock_apply.assert_not_called()
        mock_state.save_grants.assert_not_called()


# ── Fix 2: whole-tick exception isolation in the watch loop ──────────────


class TestSafeTickIsolation:
    """A ``_tick`` that raises must NOT kill the continuous watch loop
    (Fix 2). ``_safe_tick`` wraps the tick in ``try/except Exception``,
    logging a warning and continuing; ``KeyboardInterrupt`` (a
    ``BaseException``) still propagates."""

    def test_safe_tick_swallows_exception(self, capsys):
        from agentcage.cli import _safe_tick

        def boom():
            raise RuntimeError("kaboom")

        _safe_tick(boom, "x")  # must NOT propagate
        err = capsys.readouterr().err
        assert "kaboom" in err
        assert "x" in err  # the cage name is in the warning

    def test_safe_tick_runs_normal_tick(self):
        from agentcage.cli import _safe_tick
        called = []
        _safe_tick(lambda: called.append(1), "x")
        assert called == [1]

    def test_safe_tick_lets_keyboardinterrupt_propagate(self):
        from agentcage.cli import _safe_tick

        def kb():
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            _safe_tick(kb, "x")


# ── VM backend: isolation-aware overlay IO ──────────────────────────────


class TestVmOverlayDispatch:
    """_load_grants_overlay / _save_grants_overlay must route VM cages
    through the limactl channel (backends.vm.pull_grants/push_grants) and
    everything else through the host-side state file. A manual grants
    command on an unreachable VM errors instead of treating the overlay
    as empty."""

    def test_load_dispatches_vm(self):
        from agentcage.cli import _load_grants_overlay
        cfg = MagicMock()
        cfg.isolation = "vm"
        with patch("agentcage.lima.instance.LimaInstance") as mock_li, \
             patch("agentcage.backends.vm.pull_grants",
                   return_value=[{"domain": "a.com"}]) as mock_pull:
            assert _load_grants_overlay("x", cfg) == [{"domain": "a.com"}]
        mock_pull.assert_called_once_with("x", mock_li.return_value)

    def test_load_dispatches_container(self):
        from agentcage.cli import _load_grants_overlay
        cfg = MagicMock()
        cfg.isolation = "container"
        with patch("agentcage.cli.state") as mock_state:
            mock_state.load_grants.return_value = []
            assert _load_grants_overlay("x", cfg) == []
            mock_state.load_grants.assert_called_once_with("x")

    def test_save_dispatches_vm(self):
        from agentcage.cli import _save_grants_overlay
        cfg = MagicMock()
        cfg.isolation = "vm"
        with patch("agentcage.lima.instance.LimaInstance") as mock_li, \
             patch("agentcage.backends.vm.push_grants") as mock_push:
            _save_grants_overlay("x", cfg, [])
        mock_push.assert_called_once_with("x", [], mock_li.return_value)

    @patch("agentcage.cli.state")
    def test_grants_list_errors_when_vm_unreachable(self, mock_state):
        mock_state.load_raw_config.return_value = _raw()
        mock_state.load_deployment_config.return_value = _make_cfg()
        cfg = _make_cfg()
        mock_state.load_deployment_config.return_value = cfg
        with patch("agentcage.cli._load_grants_overlay", return_value=None):
            result = _runner().invoke(
                main, ["cage", "grants", "basic", "list"])
        assert result.exit_code != 0
        assert "could not reach the VM" in result.output

    @patch("agentcage.cli.state")
    @patch("agentcage.cli._apply_baseline_change")
    def test_watch_tick_skips_quietly_when_vm_down(
            self, mock_apply, mock_state):
        """A stopped VM is a quiet no-op tick — not an error, not an
        empty-overlay promotion storm. The watcher keeps running and picks
        the overlay up again once the cage starts."""
        mock_state.load_raw_config.return_value = _raw()
        cfg = _make_cfg()
        cfg.isolation = "vm"
        mock_state.load_deployment_config.return_value = cfg
        with patch("agentcage.lima.instance.LimaInstance") as mock_li, \
             patch("agentcage.cli._load_grants_overlay", return_value=None) as lo:
            mock_li.return_value.is_running.return_value = False
            result = _runner().invoke(
                main, ["cage", "grants", "basic", "watch", "--once"])
        assert result.exit_code == 0
        lo.assert_not_called()  # is_running gate short-circuits the pull
        mock_apply.assert_not_called()

    @patch("agentcage.cli.state")
    @patch("agentcage.cli._apply_baseline_change")
    def test_watch_tick_promotes_from_vm_overlay(
            self, mock_apply, mock_state):
        """End-to-end VM tick: pull the guest-local overlay, promote into
        the baseline, push the shrunk overlay back through the same
        channel."""
        from agentcage.cli import _save_grants_overlay
        mock_state.load_raw_config.return_value = _raw()
        cfg = _make_cfg()
        cfg.isolation = "vm"
        mock_state.load_deployment_config.return_value = cfg
        overlay = _overlay_entries()
        saved = {}

        def _save(name, cfg_, entries):
            saved["entries"] = entries

        with patch("agentcage.lima.instance.LimaInstance") as mock_li, \
             patch("agentcage.cli._load_grants_overlay",
                   side_effect=[overlay, overlay]) as lo, \
             patch("agentcage.cli._save_grants_overlay",
                   side_effect=_save) as sv:
            mock_li.return_value.is_running.return_value = True
            result = _runner().invoke(
                main, ["cage", "grants", "basic", "watch", "--once"])
        assert result.exit_code == 0, result.output
        assert lo.call_count == 2  # tick snapshot + merge re-read
        sv.assert_called_once()
        # The promoted domain is gone from the pushed overlay.
        assert all(e["domain"] != overlay[0]["domain"]
                   for e in saved["entries"])
