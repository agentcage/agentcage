"""Shannon entropy inspector for detecting encrypted or compressed payloads."""

from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qs, urlparse

from inspectors.base import Inspector, InspectionContext, InspectionResult
from inspectors.util import shannon_entropy


class EntropyInspector(Inspector):
    """Flags or blocks requests with high-entropy bodies.

    Encrypted and compressed data have entropy close to 8.0 bits/byte.
    Normal text/JSON/HTML sits around 3.5–5.5.  A body with entropy
    above the configured threshold is likely encrypted, compressed,
    or otherwise obfuscated — a strong indicator of data exfiltration
    when sent *outbound* from a sandboxed agent.

    Reference thresholds:
        Plain text / HTML / JSON : 3.5 – 5.5
        Source code              : 4.5 – 5.5
        Base64                   : ~6.0
        Compressed (gzip/zstd)   : 7.5 – 8.0
        Encrypted (AES/ChaCha)   : 7.9 – 8.0

    Config keys:
        threshold      (float)  Minimum entropy to trigger. Default 7.0.
        min_body_bytes (int)    Bodies smaller than this are skipped
                                (entropy is unreliable on tiny samples).
                                Default 256.
        action         (str)    "block" or "flag". Default "block".
        exempt_content_types (list[str])  Content-type prefixes to skip
                                globally (e.g. "image/", "application/gzip").
        host_exempt_content_types (dict[str, list[str]])
                                Per-host content-type exemptions. Keys are
                                hostnames (subdomain matching supported),
                                values are lists of content-type prefixes.
                                E.g. {"matrix.example.com": ["audio/", "video/"]}.
        check_url_params (bool)  Also check entropy of URL query parameter
                                values. Default true.
        url_threshold    (float)  Entropy threshold for URL params. Lower
                                than body threshold because URL-safe
                                encodings (base64 ~5.8, hex ~4.0) cap the
                                achievable entropy. Default 5.5.
        url_min_value_bytes (int)  Minimum query param value length to check.
                                Default 64.
    """

    name = "entropy"

    def configure(self, config: dict) -> None:
        self.threshold: float = config.get("threshold", 7.0)
        self.min_body_bytes: int = config.get("min_body_bytes", 256)
        self.action: str = config.get("action", "block")
        self.exempt_content_types: list[str] = config.get(
            "exempt_content_types",
            ["image/", "application/gzip", "application/zip"],
        )
        self.host_exempt_content_types: dict[str, list[str]] = {
            h.lower(): prefixes
            for h, prefixes in config.get("host_exempt_content_types", {}).items()
        }
        self.check_url_params: bool = config.get("check_url_params", True)
        self.url_threshold: float = config.get("url_threshold", 5.5)
        self.url_min_value_bytes: int = config.get("url_min_value_bytes", 64)

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        result = self._check_body(ctx)
        if result is not None:
            return result
        return self._check_url_params(ctx)

    def _check_body(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if ctx.body_entropy is None:
            return None
        if ctx.body_size < self.min_body_bytes:
            return None
        # Skip content types that are expected to be high-entropy
        for prefix in self.exempt_content_types:
            if ctx.content_type.startswith(prefix):
                return None

        # Per-host content-type exemptions
        host = ctx.host.lower()
        for h, prefixes in self.host_exempt_content_types.items():
            if host == h or host.endswith("." + h):
                for prefix in prefixes:
                    if ctx.content_type.startswith(prefix):
                        return None

        if ctx.body_entropy >= self.threshold:
            return InspectionResult(
                inspector=self.name,
                action=self.action,
                reason=(
                    f"high entropy body: {ctx.body_entropy:.2f} "
                    f"(threshold {self.threshold})"
                ),
                severity="high",
                score=ctx.body_entropy,
                metadata={
                    "entropy": ctx.body_entropy,
                    "threshold": self.threshold,
                    "body_size": ctx.body_size,
                    "content_type": ctx.content_type,
                },
            )
        return None

    def _check_url_params(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if not self.check_url_params:
            return None
        parsed = urlparse(ctx.url)
        if not parsed.query:
            return None
        for key, values in parse_qs(parsed.query, keep_blank_values=False).items():
            for val in values:
                val_bytes = val.encode("utf-8", errors="replace")
                if len(val_bytes) < self.url_min_value_bytes:
                    continue
                ent = shannon_entropy(val_bytes)
                if ent >= self.url_threshold:
                    return InspectionResult(
                        inspector=self.name,
                        action=self.action,
                        reason=(
                            f"high entropy URL param '{key}': {ent:.2f} "
                            f"(threshold {self.url_threshold})"
                        ),
                        severity="high",
                        score=ent,
                        metadata={
                            "entropy": ent,
                            "url_threshold": self.url_threshold,
                            "param": key,
                            "param_length": len(val_bytes),
                        },
                    )
        return None
