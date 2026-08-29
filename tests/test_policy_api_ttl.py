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
