"""Domain allowlist / blocklist inspector."""

from __future__ import annotations

from typing import Optional

from inspectors.base import Inspector, InspectionContext, InspectionResult


class DomainInspector(Inspector):
    """Blocks or allows requests based on the target domain."""

    name = "domain"

    def configure(self, config: dict) -> None:
        # New format: allow/block keys
        if "allow" in config:
            self.mode = "allowlist"
            self.domain_set: set[str] = {d.lower() for d in config.get("allow", [])}
        elif "block" in config:
            self.mode = "blocklist"
            self.domain_set = {d.lower() for d in config.get("block", [])}
        else:
            # Backward compat: mode + list
            self.mode = config.get("mode")  # "allowlist" | "blocklist" | None
            self.domain_set = {d.lower() for d in config.get("list", [])}

    def _matches(self, host: str) -> bool:
        parts = host.lower().split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self.domain_set:
                return True
        return False

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if not self.mode:
            return None
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
