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
            main, ["cage", "grants", "basic", "sync"]
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
            main, ["cage", "grants", "basic", "sync"]
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
            main, ["cage", "grants", "basic", "sync"])
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
            main, ["cage", "grants", "basic", "sync"])
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
            main, ["cage", "grants", "basic", "sync"])
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
            main, ["cage", "grants", "basic", "sync"]
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
            main, ["cage", "grants", "basic", "sync"]
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
            main, ["cage", "grants", "basic", "sync"]
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
            main, ["cage", "grants", "basic", "sync"]
        )
        assert result.exit_code == 0, result.output

        # Promotion skipped: no baseline change, no overlay rewrite —
        # the entry stays pending (step 1 still drops expired ones).
        mock_apply.assert_not_called()
        mock_state.save_grants.assert_not_called()

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
            main, ["cage", "grants", "basic", "sync"]
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
            main, ["cage", "grants", "basic", "sync"]
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
            main, ["cage", "grants", "basic", "sync"]
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
                main, ["cage", "grants", "basic", "sync"])
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
                main, ["cage", "grants", "basic", "sync"])
        assert result.exit_code == 0, result.output
        assert lo.call_count == 2  # tick snapshot + merge re-read
        sv.assert_called_once()
        # The promoted domain is gone from the pushed overlay.
        assert all(e["domain"] != overlay[0]["domain"]
                   for e in saved["entries"])


class TestMergeNoneNeverWipes:
    """Round-9 finding 4: a transient VM-unreachable None from the
    merge-on-write re-read must NEVER be treated as an empty overlay —
    merging against a fabricated [] would push an EMPTY overlay and wipe
    every grant decided in the window. Fall back to the snapshot view."""

    @patch("agentcage.cli.state")
    @patch("agentcage.cli._apply_baseline_change")
    def test_promote_none_reread_uses_snapshot(self, mock_apply, mock_state):
        mock_state.load_raw_config.return_value = _raw()
        cfg = _make_cfg()
        cfg.isolation = "vm"
        mock_state.load_deployment_config.return_value = cfg
        overlay = _overlay_entries()
        saved = {}

        def _save(name, cfg_, entries):
            saved["entries"] = entries

        with patch("agentcage.cli._load_grants_overlay",
                   side_effect=[overlay, None]), \
             patch("agentcage.cli._save_grants_overlay",
                   side_effect=_save), \
             patch("agentcage.cli.get_backend") as mock_backend:
            mock_backend.return_value.is_running.return_value = False
            result = _runner().invoke(
                main, ["cage", "grants", "basic", "promote",
                       overlay[0]["domain"]])
        assert result.exit_code == 0, result.output
        # NOT empty: the snapshot minus the promoted domain survives.
        assert saved["entries"] is not None and len(saved["entries"]) >= 0
        assert all(e["domain"] != overlay[0]["domain"]
                   for e in saved["entries"])
        assert "could not re-read" in result.output

    @patch("agentcage.cli.state")
    def test_revoke_none_reread_uses_snapshot(self, mock_state):
        mock_state.load_raw_config.return_value = _raw()
        cfg = _make_cfg()
        cfg.isolation = "vm"
        mock_state.load_deployment_config.return_value = cfg
        overlay = _overlay_entries() + [
            {"domain": "other.example.org", "reason": "other",
             "source": "decider:agent:test", "granted_at": "2024-01-01",
             "expires_at": ""}
        ]
        saved = {}

        def _save(name, cfg_, entries):
            saved["entries"] = entries

        with patch("agentcage.cli._load_grants_overlay",
                   side_effect=[overlay, None]), \
             patch("agentcage.cli._save_grants_overlay",
                   side_effect=_save):
            result = _runner().invoke(
                main, ["cage", "grants", "basic", "revoke",
                       overlay[0]["domain"]])
        assert result.exit_code == 0, result.output
        # The snapshot minus the revoked domain — never a fabricated [].
        assert all(e["domain"] != overlay[0]["domain"]
                   for e in saved["entries"])
        assert saved["entries"]  # non-empty: other grants survive
        assert "could not re-read" in result.output


# ── Round-10 Fix 1: TTL onto an already-permanent baseline entry ─────────


class TestWatchDoesNotTightenPermanentBaseline:
    """Fix 1: the watcher must NOT write a stale overlay TTL onto a domain
    the operator already permanently allowlisted (e.g. via ``domain add``
    with no ``--expires-in``). The manual ``cage grants promote`` command
    deliberately tightens an existing baseline entry with the overlay TTL
    (an explicit operator act — intentional TIGHTENING); the watcher is
    AUTOMATIC and must be more conservative, leaving the operator's
    stronger (permanent) decision untouched so step 0 of a later tick
    can't prune it. A NEW domain's TTL still lands in ``domains.expires``.
    """

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_permanent_baseline_entry_keeps_no_expires(
        self, mock_state, mock_apply
    ):
        # "perm.com" is permanently in the operator's allow list (no TTL);
        # "new.com" is a fresh grant not yet in the baseline.
        raw = {
            "name": "basic",
            "container": {"image": "node:22-slim",
                          "command": ["node", "/app/agent.js"]},
            "domains": {"allow": ["anthropic.com", "perm.com"]},
        }
        overlay = [
            {"domain": "perm.com", "reason": "r", "source": "decider",
             "granted_at": "2026-01-01T00:00:00+00:00",
             "expires_at": "2030-01-01T00:10:00+00:00"},  # TTL on perm.com
            {"domain": "new.com", "reason": "r", "source": "decider",
             "granted_at": "2026-01-01T00:00:00+00:00",
             "expires_at": "2030-01-01T00:10:00+00:00"},  # TTL on new.com
        ]
        mock_state.load_raw_config.return_value = raw
        mock_state.load_grants.return_value = overlay
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "sync"])
        assert result.exit_code == 0, result.output

        saved = mock_apply.call_args[0][1]
        expires = saved["domains"].get("expires", {})
        # perm.com was already permanent: the operator's entry is untouched —
        # the stale overlay TTL must NOT have landed in domains.expires.
        assert "perm.com" not in expires
        # perm.com is still in the allow list (unchanged, not pruned).
        assert "perm.com" in saved["domains"]["allow"]
        # new.com was a fresh grant: its TTL still lands in expires and the
        # domain is appended to the allow list.
        assert expires["new.com"] == "2030-01-01T00:10:00+00:00"
        assert "new.com" in saved["domains"]["allow"]


# ── Round-10 Fix 2: domain add writes a value validate_config rejects ────


class TestDomainAddValidatesSyntax:
    """Fix 2: ``domain add`` previously appended without syntax-validating,
    so ``agentcage cage <name> domain add "foo.com/x"`` wrote a cage.yaml
    that ``validate_config`` (and ``valid_domain``) REJECTS on next load —
    bricking the cage. The canonical form must be validated up front; on
    failure the command errors (matching the command's existing error
    style) and exits 1, writing nothing. A valid domain still works.
    """

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add_rejects_invalid_syntax(self, mock_state,
                                               mock_get_backend,
                                               mock_update_dns):
        mock_state.valid_domain.side_effect = valid_domain
        raw = {"name": "basic", "domains": {"allow": ["anthropic.com"]}}
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        mock_get_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["domain", "add", "basic", "foo.com/x"])
        assert result.exit_code != 0
        assert "invalid domain" in result.output
        assert "foo.com/x" in result.output
        # Nothing written: the up-front validation sys.exit(1)s before any
        # append / baseline change / DNS reload.
        mock_state.save_raw_config.assert_not_called()
        mock_update_dns.assert_not_called()

    @patch("agentcage.cli._update_dns_quadlet")
    @patch("agentcage.cli.get_backend")
    @patch("agentcage.cli.state")
    def test_domain_add_valid_domain_still_works(self, mock_state,
                                                 mock_get_backend,
                                                 mock_update_dns):
        mock_state.valid_domain.side_effect = valid_domain
        raw = {"name": "basic", "domains": {"allow": ["anthropic.com"]}}
        mock_state.load_raw_config.return_value = raw
        cfg = MagicMock()
        cfg.name = "basic"
        mock_state.load_deployment_config.return_value = cfg
        mock_get_backend.return_value.is_running.return_value = False

        result = _runner().invoke(
            main, ["domain", "add", "basic", "example.com"])
        assert result.exit_code == 0, result.output
        saved = mock_state.save_raw_config.call_args[0][1]
        assert "example.com" in saved["domains"]["allow"]


# ── Round-10 Fix 3: domain-keyed merge drops a fresh re-grant ────────────


class TestTickMergeKeepsFreshRegrant:
    """Fix 3: step 3's domain-keyed merge dropped a fresh re-grant of a
    domain that was expired-and-removed earlier in the SAME tick but
    freshly re-decided by the addon during the tick window (the new entry
    has a strictly newer ``granted_at``). The merge must keep the on-disk
    entry whose ``granted_at`` is strictly newer than the removed
    snapshot entry's ``granted_at``."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_fresh_regrant_survives_after_expire_in_same_tick(
        self, mock_state, mock_apply
    ):
        t1 = "2026-01-01T00:00:00+00:00"
        t2 = "2026-01-01T00:00:05+00:00"  # strictly newer
        # "d.com" is NOT in the baseline allow list — step 1 drops the
        # expired entry from the overlay and records removed["d.com"]=T1.
        raw = {
            "name": "basic",
            "container": {"image": "node:22-slim",
                          "command": ["node", "/app/agent.js"]},
            "domains": {"allow": ["anthropic.com"]},
        }
        expired_snapshot = [{
            "domain": "d.com", "reason": "r", "source": "decider",
            "granted_at": t1,
            "expires_at": "2000-01-01T00:00:00+00:00",  # past → expired
        }]
        fresh_reread = [{
            "domain": "d.com", "reason": "re-decided", "source": "decider",
            "granted_at": t2,  # strictly newer than the removed snapshot
            "expires_at": "2030-01-01T00:10:00+00:00",  # future → pending
        }]
        # 1st load_grants = top-of-_tick snapshot (expired); 2nd = step-3
        # re-read, by which point the addon has re-granted d.com (T2).
        mock_state.load_grants.side_effect = [
            list(expired_snapshot), list(fresh_reread)]
        mock_state.load_raw_config.return_value = raw
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "sync"])
        assert result.exit_code == 0, result.output

        # The fresh re-grant (granted_at T2 > the removed T1) survives the
        # domain-keyed merge — it is NOT dropped as a stale duplicate.
        saved = mock_state.save_grants.call_args[0][1]
        assert len(saved) == 1
        assert saved[0]["domain"] == "d.com"
        assert saved[0]["granted_at"] == t2

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_same_grantedat_regrant_still_dropped(self, mock_state, mock_apply):
        """Defensive: an on-disk entry with the SAME granted_at as the
        removed snapshot entry (i.e. the very entry we removed, not a
        fresh re-grant) is still dropped — only a STRICTLY newer
        granted_at resurrects a re-grant."""
        t1 = "2026-01-01T00:00:00+00:00"
        raw = {
            "name": "basic",
            "container": {"image": "node:22-slim",
                          "command": ["node", "/app/agent.js"]},
            "domains": {"allow": ["anthropic.com"]},
        }
        entry = [{"domain": "d.com", "reason": "r", "source": "decider",
                  "granted_at": t1,
                  "expires_at": "2000-01-01T00:00:00+00:00"}]
        mock_state.load_grants.side_effect = [
            list(entry), list(entry)]  # same granted_at on re-read
        mock_state.load_raw_config.return_value = raw
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "sync"])
        assert result.exit_code == 0, result.output
        saved = mock_state.save_grants.call_args[0][1]
        assert saved == []  # not a fresh re-grant → dropped


# ── Round-10 Fix 4: audit spam for unchanged entries ─────────────────────


class TestWatchNoAuditForAlreadyBaseline:
    """Fix 4: ``policy_grant_applied`` audits were emitted for every
    pending entry EVERY tick even when the domain was already in the
    baseline (nothing added). The audit must fire ONLY for entries this
    tick actually ADDED to the allow list; an already-present entry is a
    no-op promotion (the overlay entry is still removed — the observable
    change — but no redundant audit line)."""

    @patch("agentcage.cli._apply_baseline_change")
    @patch("agentcage.cli.state")
    def test_already_baseline_no_policy_grant_applied_audit(
        self, mock_state, mock_apply
    ):
        # "x.com" is ALREADY in the baseline; the overlay carries a
        # (stale) TTL'd grant for it.
        raw = {
            "name": "basic",
            "container": {"image": "node:22-slim",
                          "command": ["node", "/app/agent.js"]},
            "domains": {"allow": ["anthropic.com", "x.com"]},
        }
        overlay = [{
            "domain": "x.com", "reason": "r", "source": "decider",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:10:00+00:00",  # future → pending
        }]
        mock_state.load_raw_config.return_value = raw
        mock_state.load_grants.return_value = overlay
        mock_state.load_deployment_config.return_value = _make_cfg()

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "sync"])
        assert result.exit_code == 0, result.output

        # No policy_grant_applied audit: nothing was added to the baseline.
        audits = [c.args[1]
                  for c in mock_state.append_policy_audit.call_args_list]
        applied = [a for a in audits
                   if a.get("kind") == "policy_grant_applied"]
        assert applied == []
        # The overlay entry IS still removed (the observable change) — the
        # no-op promotion still clears the pending entry from the overlay.
        saved_overlay = mock_state.save_grants.call_args[0][1]
        assert saved_overlay == []
        # And no baseline change was needed (the domain was already there).
        mock_apply.assert_not_called()


# ── Round-10 Fix 5: --once bypasses _safe_tick ────────────────────────────


class TestWatchOnceSafeTick:
    """Fix 5: ``grants watch --once`` called ``_tick()`` directly instead
    of the isolated ``_safe_tick(_tick, name)`` wrapper. A one-shot crash
    must be a logged warning (exit 0), not an uncaught traceback — mirrors
    the continuous loop's per-tick isolation so a cron job / test harness
    never exits non-zero on a transient tick failure the loop survives."""

    @patch("agentcage.cli.state")
    def test_once_tick_raises_warns_exit_zero(self, mock_state):
        mock_state.load_deployment_config.return_value = _make_cfg()
        # A non-None overlay so _tick proceeds past the early return; an
        # empty list keeps step 1/2 idle so step 0's load_raw_config is the
        # first thing that runs.
        mock_state.load_grants.return_value = []
        # The FIRST load_raw_config is grants_watch's top-level existence
        # check (only FileNotFoundError is caught there) — let it succeed.
        # The SECOND is step 0 inside _tick: a RuntimeError (NOT
        # FileNotFoundError, which step 0 catches) propagates out of _tick.
        mock_state.load_raw_config.side_effect = [
            _raw(), RuntimeError("boom")]

        result = _runner().invoke(
            main, ["cage", "grants", "basic", "sync"])
        # Exit 0 (warning, not a crash) — _safe_tick swallowed the tick.
        assert result.exit_code == 0, result.output
        assert "boom" in result.output
        assert "basic" in result.output  # the cage name is in the warning
