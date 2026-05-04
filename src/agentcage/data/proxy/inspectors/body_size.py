"""Request body size inspector."""

from __future__ import annotations

from typing import Optional

from inspectors.base import Inspector, InspectionContext, InspectionResult


class BodySizeInspector(Inspector):
    """Blocks requests whose body exceeds a configured limit.

    Config keys:
        max_bytes        (int)              Global cap. 0 disables.
        host_max_bytes   (dict[str, int])   Per-host overrides. Keys are
                                            hostnames (subdomain suffix
                                            matching supported), values
                                            are byte limits. When a host
                                            matches, its override replaces
                                            the global cap for that
                                            request — the override can be
                                            larger or smaller than the
                                            global. Most-specific (longest)
                                            match wins so a tight subdomain
                                            limit isn't widened by a looser
                                            apex-domain entry.
    """

    name = "body-size"

    def configure(self, config: dict) -> None:
        self.max_bytes: int = config.get("max_bytes", 0)
        self.host_max_bytes: dict[str, int] = {
            h.lower(): int(v) for h, v in config.get("host_max_bytes", {}).items()
        }

    def _limit_for_host(self, host: str) -> int:
        """Resolve the byte limit for a host.

        Picks the most-specific (longest) matching entry in
        ``host_max_bytes``. Suffix matching means a `paperless.example.com`
        request matches a `paperless.example.com` entry exactly and also
        any `example.com` entry, and the longer key wins. Falls back to
        ``max_bytes`` when nothing matches.
        """
        if not self.host_max_bytes:
            return self.max_bytes
        host = host.lower()
        best_match_len = -1
        best_limit = self.max_bytes
        for h, limit in self.host_max_bytes.items():
            if host == h or host.endswith("." + h):
                if len(h) > best_match_len:
                    best_match_len = len(h)
                    best_limit = limit
        return best_limit

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        limit = self._limit_for_host(ctx.host)
        if not limit:
            return None
        if ctx.body_size > limit:
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=f"body too large: {ctx.body_size} > {limit}",
                severity="warning",
                metadata={
                    "body_size": ctx.body_size,
                    "max_bytes": limit,
                    "host": ctx.host,
                },
            )
        return None
