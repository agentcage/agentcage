"""Base classes and protocols for agentcage inspectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InspectionResult:
    """Returned by an inspector when it has something to report."""

    inspector: str
    action: str = "block"  # "block" or "flag"
    reason: str = ""
    severity: str = "medium"  # "info", "low", "medium", "high", "critical"
    score: float = 0.0  # for anomaly-scoring mode
    metadata: dict = field(default_factory=dict)


@dataclass
class InspectionContext:
    """Pre-computed request data passed to every inspector."""

    url: str
    host: str
    method: str
    headers: dict[str, str]
    content_type: str
    body_bytes: Optional[bytes]
    body_text: Optional[str]
    body_size: int
    body_entropy: Optional[float] = None  # computed once by orchestrator
    prior_results: list[InspectionResult] = field(default_factory=list)


class Inspector:
    """Base class for all inspectors.

    Subclass this and override ``inspect_request`` (and optionally
    ``inspect_response``) to build a custom inspector.

    Lifecycle:
        1. ``__init__`` is called with no arguments.
        2. ``configure(config)`` is called with the inspector-specific
           config dict from the YAML file.
        3. ``inspect_request(ctx)`` is called for every HTTP request.
           Return an ``InspectionResult`` to flag or block, or ``None``
           to abstain.

    Example (save as ``my_inspector.py``)::

        from inspectors.base import Inspector, InspectionResult, InspectionContext

        class MyInspector(Inspector):
            name = "my-check"

            def configure(self, config: dict) -> None:
                self.forbidden = config.get("forbidden_word", "EXFIL")

            def inspect_request(self, ctx: InspectionContext):
                if ctx.body_text and self.forbidden in ctx.body_text:
                    return InspectionResult(
                        inspector=self.name,
                        action="block",
                        reason=f"body contains forbidden word: {self.forbidden}",
                    )

    Then reference it in config.yaml::

        inspectors:
          - name: my-check
            path: /etc/agentcage/my_inspector.py
            config:
              forbidden_word: "EXFIL"
    """

    name: str = "base"

    def configure(self, config: dict) -> None:
        """Called once with the inspector's config section."""

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        """Inspect an outbound request. Return None to abstain."""
        return None

    def inspect_response(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        """Inspect an inbound response. Return None to abstain."""
        return None
