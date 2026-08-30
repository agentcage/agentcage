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

from click.testing import CliRunner

from agentcage.cli import main


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
    own plist. And it must warn (not silently no-op) on the vm backend,
    where the watcher is unsupported in v1."""

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
    def test_vm_warns_and_skips(self, mock_backend, capsys):
        backend = MagicMock(spec=[])
        mock_backend.return_value = backend

        from agentcage.cli import _ensure_grants_watcher
        cfg = MagicMock()
        cfg.isolation = "vm"
        _ensure_grants_watcher("x", cfg)

        out = capsys.readouterr().err
        assert "not supported on the vm backend" in out

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
        with patch.object(_systemd, "start_unit") as mock_start:
            _ensure_grants_watcher("x", cfg)

        assert unit.exists()
        assert "[Unit]" in unit.read_text()
        mock_start.assert_called_once_with("x-grants.service")
