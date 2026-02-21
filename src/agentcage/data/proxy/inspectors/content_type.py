"""Content-type mismatch inspector.

Detects requests where the declared Content-Type does not match the
actual body characteristics — a common indicator of data exfiltration
disguised as normal API traffic.
"""

from __future__ import annotations

import re
from typing import Optional

from inspectors.base import Inspector, InspectionContext, InspectionResult

# Entropy ranges for "text-like" content types.  If the actual body
# entropy falls far outside these ranges the body is probably not
# what the Content-Type claims.
_TEXT_CT_PREFIXES = (
    "application/json",
    "application/xml",
    "text/",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
)

# Base64: almost exclusively [A-Za-z0-9+/=\s]
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\-_\s]{64,}$", re.MULTILINE)


class ContentTypeInspector(Inspector):
    """Flags requests where the body doesn't match the Content-Type.

    Config keys:
        entropy_ceiling  (float) Max expected entropy for text content
                                 types. Default 6.5.
        detect_base64    (bool)  Flag large Base64 blobs in text bodies.
                                 Default true.
        base64_min_len   (int)   Minimum Base64 match length to trigger.
                                 Default 256.
        action           (str)   "block" or "flag". Default "block".
    """

    name = "content-type"

    def configure(self, config: dict) -> None:
        self.entropy_ceiling: float = config.get("entropy_ceiling", 6.5)
        self.detect_base64: bool = config.get("detect_base64", True)
        self.base64_min_len: int = config.get("base64_min_len", 256)
        self.action: str = config.get("action", "block")

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if not ctx.body_text or not ctx.content_type:
            return None

        is_text_ct = any(
            ctx.content_type.startswith(p) for p in _TEXT_CT_PREFIXES
        )
        if not is_text_ct:
            return None

        # Check 1: entropy too high for a text content-type
        if ctx.body_entropy is not None and ctx.body_entropy > self.entropy_ceiling:
            return InspectionResult(
                inspector=self.name,
                action=self.action,
                reason=(
                    f"content-type mismatch: {ctx.content_type} declared "
                    f"but body entropy is {ctx.body_entropy:.2f} "
                    f"(expected <{self.entropy_ceiling})"
                ),
                severity="error",
                metadata={
                    "content_type": ctx.content_type,
                    "entropy": ctx.body_entropy,
                    "ceiling": self.entropy_ceiling,
                },
            )

        # Check 2: large Base64 blobs in text bodies
        if self.detect_base64:
            match = _BASE64_RE.search(ctx.body_text)
            if match and len(match.group()) >= self.base64_min_len:
                return InspectionResult(
                    inspector=self.name,
                    action=self.action,
                    reason=(
                        f"large base64 blob ({len(match.group())} chars) "
                        f"in {ctx.content_type} body"
                    ),
                    severity="warning",
                    metadata={
                        "content_type": ctx.content_type,
                        "base64_length": len(match.group()),
                    },
                )

        return None
