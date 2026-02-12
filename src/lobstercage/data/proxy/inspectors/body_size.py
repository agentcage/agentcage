"""Request body size inspector."""

from __future__ import annotations

from typing import Optional

from inspectors.base import Inspector, InspectionContext, InspectionResult


class BodySizeInspector(Inspector):
    """Blocks requests whose body exceeds a configured limit."""

    name = "body-size"

    def configure(self, config: dict) -> None:
        self.max_bytes = config.get("max_bytes", 0)

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if not self.max_bytes:
            return None
        if ctx.body_size > self.max_bytes:
            return InspectionResult(
                inspector=self.name,
                action="block",
                reason=f"body too large: {ctx.body_size} > {self.max_bytes}",
                severity="medium",
                metadata={
                    "body_size": ctx.body_size,
                    "max_bytes": self.max_bytes,
                },
            )
        return None
