"""Domain allowlist / blocklist inspector."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from inspectors.base import Inspector, InspectionContext, InspectionResult


class DomainInspector(Inspector):
    """Blocks or allows requests based on the target domain.

    Holds two layers of allow state:

    * ``_baseline`` — the operator's static ``domains.allow`` from
      ``config.yaml``. Rebuilt by :meth:`configure` on every hot-reload.
    * ``granted`` — runtime overlay entries added by the Policy API request
      endpoint (see docs/explain/policy-api.md). :meth:`configure` NEVER
      clears ``granted``, so a ``config.yaml`` mtime hot-reload reapplies
      the baseline on top of live grants without dropping them. Grants are
      additive only: they widen the allow set and never weaken the SNI/Host
      check, secret/entropy/content-type/body-size inspectors, or rate
      limits — those still run on traffic to granted domains.
    """

    name = "domain"

    def __init__(self) -> None:
        # ``mode`` is read by callers; keep it as a plain attribute.
        self.mode: str = ""
        self._baseline: set[str] = set()
        # granted[domain_lower] = {granted_at, expires_at, reason, source}
        self.granted: dict[str, dict] = {}

    # ── Configuration (hot-reload safe) ──────────────────────

    def configure(self, config: dict) -> None:
        # New format: allow/block keys
        if "allow" in config:
            self.mode = "allowlist"
            self._baseline = {d.lower() for d in config.get("allow", [])}
        elif "block" in config:
            self.mode = "blocklist"
            self._baseline = {d.lower() for d in config.get("block", [])}
        else:
            # Backward compat: mode + list
            self.mode = config.get("mode")  # "allowlist" | "blocklist" | None
            self._baseline = {d.lower() for d in config.get("list", [])}
        # NOTE: intentionally do NOT touch self.granted here. Hot-reload of
        # config.yaml rebuilds the baseline; live grants survive and remain
        # effective (replayed on top). The addon's _maybe_reload calls
        # configure() then re-persists/loads the overlay.

    @property
    def domain_set(self) -> set[str]:
        """Effective allow set: baseline ∪ granted (allowlist mode)."""
        if self.mode == "allowlist":
            return self._baseline | set(self.granted)
        # In blocklist mode grants are no-ops (everything not blocked is
        # already reachable); return the baseline so _matches behaves.
        return self._baseline

    # ── Matching ────────────────────────────────────────────

    def _matches(self, host: str) -> bool:
        parts = host.lower().split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self.domain_set:
                return True
        return False

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if self.mode not in ("allowlist", "blocklist"):
            # Fail closed. A cage with no recognizable domain policy — an
            # omitted or empty `domains:` section yields mode=None/"" — must
            # default-deny rather than silently allow every host (the L7
            # fail-open hole). The operator is warned loudly at create time;
            # see config.validate_config.
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=f"no domain allowlist configured (default-deny): {ctx.host}",
                severity="error",
            )
        matched = self._matches(ctx.host)
        if self.mode == "allowlist" and not matched:
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=f"domain not in allowlist: {ctx.host}",
                severity="error",
            )
        if self.mode == "blocklist" and matched:
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=f"domain in blocklist: {ctx.host}",
                severity="error",
            )
        return None

    # ── Policy API: runtime grants ──────────────────────────

    def grant(
        self,
        domain: str,
        *,
        expires_at: str = "",
        reason: str = "",
        source: str = "policy-hook",
    ) -> None:
        """Add *domain* to the live allow overlay (allowlist mode only).

        Takes effect immediately for the next request — at the L7 domain
        inspector. (DNS-layer reachability for the granted zone is applied
        separately by the egress supervisor, which watches the grants
        overlay file and SIGHUPs dnsmasq — the addon process lacks the
        privileges to signal dnsmasq itself. See docs/explain/policy-api.md
        §3.4 and the supervisor bridge in supervisor-egress.sh.)
        """
        if self.mode != "allowlist":
            return
        d = domain.lower().rstrip(".")
        if not d:
            return
        self.granted[d] = {
            "domain": d,
            "granted_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at or "",
            "reason": reason or "",
            "source": source or "policy-hook",
        }

    def revoke(self, domain: str) -> bool:
        """Remove *domain* from the live overlay. Returns True if present."""
        return self.granted.pop(domain.lower().rstrip("."), None) is not None

    def is_granted(self, domain: str) -> bool:
        return domain.lower().rstrip(".") in self.granted

    def drop_expired(self, now_iso: str = "") -> list[str]:
        """Remove & return domains whose ``expires_at`` has passed.

        ``now_iso`` is injected (rather than read from the clock) so tests
        are deterministic and the addon's sweeper can pass the same
        timestamp it logs.
        """
        if not now_iso:
            now_iso = datetime.now(timezone.utc).isoformat()
        expired: list[str] = []
        for d, meta in list(self.granted.items()):
            exp = meta.get("expires_at") or ""
            if exp and exp <= now_iso:
                self.granted.pop(d, None)
                expired.append(d)
        return expired

    def granted_entries(self) -> list[dict]:
        """Snapshot of overlay entries (sorted by domain for stable output)."""
        return [self.granted[d] for d in sorted(self.granted)]

    def baseline_list(self) -> list[str]:
        """Sorted baseline allow/block list (operator's static policy)."""
        return sorted(self._baseline)

    def snapshot(self) -> dict:
        """Effective policy for the introspection endpoint."""
        return {
            "mode": self.mode,
            "baseline": self.baseline_list(),
            "granted": self.granted_entries(),
        }