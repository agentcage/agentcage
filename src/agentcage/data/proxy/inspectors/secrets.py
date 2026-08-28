"""Secret / credential leak detection inspector."""

from __future__ import annotations

import os
import re
from typing import Optional

from inspectors.base import Inspector, InspectionContext, InspectionResult

BUILTIN_SECRETS = {
    "openai_key": re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,250}T3BlbkFJ[A-Za-z0-9_-]{20,250}"),
    "anthropic_key": re.compile(r"sk-ant-(?:api|admin)\d+-[a-zA-Z0-9_-]{20,250}"),
    "aws_access_key": re.compile(r"AKIA[A-Z2-7]{16}"),
    "github_token": re.compile(r"gh[ps]_[A-Za-z0-9]{36}"),
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth_access_token": re.compile(r"ya29\.[A-Za-z0-9_-]{50,}"),
    "slack_token": re.compile(r"xox[bpors]-[0-9]{10,20}-[a-zA-Z0-9-]{1,255}"),
    "stripe_key": re.compile(r"[sr]k_(live|test)_[0-9a-zA-Z]{24,255}"),
    "private_key": re.compile(r"-----BEGIN[ A-Z]{0,20}PRIVATE KEY-----"),
    "gitlab_token": re.compile(r"glpat-[A-Za-z0-9\-_]{20,255}"),
    "huggingface_token": re.compile(r"hf_[a-zA-Z]{34}"),
    "databricks_token": re.compile(r"dapi[0-9a-f]{32}"),
    "azure_jwt": re.compile(r"eyJ[A-Za-z0-9_-]{50,4096}\.eyJ[A-Za-z0-9_-]{50,4096}"),
    "openrouter_key": re.compile(r"sk-or-v1-[a-f0-9]{64}"),
    "perplexity_key": re.compile(r"pplx-[a-zA-Z0-9]{48}"),
    # Brave Search API keys are 32 chars total: ``BSA`` family prefix
    # (``BSAI`` for v2 issued keys) plus 28 URL-safe alphanumeric chars.
    # The negative lookbehind/lookahead require the candidate to be
    # delimited by non-base64-alphabet characters — without them the
    # pattern collides with random ``BSAI...`` substrings that occur
    # inside base64-encoded image payloads (observed at ~40% hit rate
    # per ~2 MB JPEG in real cages, hard-blocking Anthropic vision API
    # calls).  Real keys appear as JSON values, URL params, header
    # values, or env vars — all of which are bounded by non-alphabet
    # characters, so the boundary is preserved.
    "brave_api_key": re.compile(
        r"(?<![A-Za-z0-9_-])BSAI[a-zA-Z0-9_-]{28}(?![A-Za-z0-9_-])"
    ),
    "telegram_bot_token": re.compile(r"[0-9]{5,16}:[A-Za-z0-9_-]{35}"),
    "discord_bot_token": re.compile(r"[MNO][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,255}"),
    "firecrawl_key": re.compile(r"fc-[a-f0-9]{32}"),
}

# Content-type prefixes whose bodies are opaque/binary and where ASCII
# regex matching against base64-ish or random bytes produces meaningless
# false positives (e.g. ``BSAI...`` randomly appearing inside a JPEG
# base64-encoded for the Anthropic vision API).  URL and headers are
# still scanned for these requests; only ``body_text`` is skipped.
BINARY_BODY_CONTENT_TYPE_PREFIXES = (
    "image/",
    "audio/",
    "video/",
    "application/octet-stream",
    "application/pdf",
)


def _is_binary_body_content_type(content_type: str) -> bool:
    """Return True when the request body is opaque binary and body-text
    regex scanning is not meaningful."""
    if not content_type:
        return False
    ct = content_type.split(";", 1)[0].strip().lower()
    return any(ct.startswith(p) for p in BINARY_BODY_CONTENT_TYPE_PREFIXES)


BUILTIN_ALLOW_TO_DOMAINS = {
    "openai_key": ["openai.com"],
    "anthropic_key": ["anthropic.com"],
    "aws_access_key": ["amazonaws.com"],
    "github_token": ["github.com", "githubusercontent.com"],
    "github_pat": ["github.com", "githubusercontent.com"],
    "google_api_key": ["googleapis.com", "google.com"],
    "google_oauth_access_token": ["googleapis.com", "google.com"],
    "slack_token": ["slack.com"],
    "stripe_key": ["stripe.com"],
    "gitlab_token": ["gitlab.com"],
    "huggingface_token": ["huggingface.co", "hf.co"],
    "databricks_token": ["databricks.com"],
    "openrouter_key": ["openrouter.ai"],
    "perplexity_key": ["perplexity.ai"],
    "brave_api_key": ["search.brave.com"],
    "telegram_bot_token": ["api.telegram.org"],
    "discord_bot_token": ["discord.com"],
    "firecrawl_key": ["firecrawl.dev", "api.firecrawl.dev"],
}


class SecretsInspector(Inspector):
    """Detects known secret/credential patterns in request data."""

    name = "secrets"

    def configure(self, config: dict) -> None:
        self.enabled = config.get("enabled", True)
        # "flag" (default on HTTP egress) records the detection in the
        # audit log and lets the request through; "block" returns a hard
        # 403.  Any other value falls back to the "flag" default.
        # ``action_explicit`` lets the relay chain tell an operator-chosen
        # action apart from the default so it can apply its own
        # block-by-default only when unset.
        self.action_explicit = "action" in config
        self.action = "block" if config.get("action") == "block" else "flag"
        # Build ``patterns`` and ``allow_to_domains`` in locals and rebind
        # the attributes exactly once at the end.  ``inspect_request`` reads
        # ``self.patterns`` / ``self.allow_to_domains`` from a worker thread
        # (the inspector chain runs on a ``ThreadPoolExecutor`` via
        # ``run_inspector_chain``), while ``configure()`` may fire
        # concurrently from ``_maybe_reload`` on the loop thread during a
        # config hot-reload.  Mutating the live attribute in place after the
        # initial ``self.patterns = dict(BUILTIN_SECRETS)`` rebind lets a
        # worker grab the freshly-rebound dict and start ``.items()``
        # iteration while ``configure`` is still inserting ``extra_patterns``
        # — raising ``RuntimeError: dictionary changed size during
        # iteration``.  Building in a local and rebinding atomically means
        # ``inspect_*`` only ever observes a fully-built, immutable-to-it
        # dict (CPython attribute rebind is atomic under the GIL).
        patterns: dict[str, re.Pattern] = {}
        allow_to_domains: dict[str, list[str]] = {}
        if self.enabled:
            patterns = dict(BUILTIN_SECRETS)
            for p in config.get("extra_patterns", []):
                env_name = p.get("env")
                if env_name:
                    value = os.environ.get(env_name, "")
                    if not value:
                        continue
                    patterns[p["name"]] = re.compile(re.escape(value))
                else:
                    patterns[p["name"]] = re.compile(p["pattern"])
            # Merge built-in allow_to_domains (user config wins)
            if config.get("builtin_allow_to_domains", True):
                allow_to_domains = {
                    k: [d.lower() for d in v]
                    for k, v in BUILTIN_ALLOW_TO_DOMAINS.items()
                }
                for pat_name, domains in (
                    config.get("allow_to_domains") or {}
                ).items():
                    allow_to_domains[pat_name] = [d.lower() for d in domains]
            else:
                for pat_name, domains in (
                    config.get("allow_to_domains") or {}
                ).items():
                    allow_to_domains[pat_name] = [
                        d.lower() for d in domains
                    ]
        self.patterns = patterns
        self.allow_to_domains = allow_to_domains

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if not self.enabled:
            return None
        targets = [ctx.url] + [v for _, v in ctx.headers]
        # Skip body text scanning when the body is opaque binary
        # (image/audio/video/octet-stream/pdf): regex matching against
        # base64-encoded image bytes or other random data produces
        # false positives that hard-block legitimate uploads.  URL and
        # headers are still scanned so a leaked secret in those still
        # gets caught even on a binary-body request.
        if ctx.body_text and not _is_binary_body_content_type(ctx.content_type):
            targets.append(ctx.body_text)
        host = ctx.host.lower()
        for pat_name, pat in self.patterns.items():
            for t in targets:
                if pat.search(t):
                    # Allow secret to its legitimate API domain
                    allowed = self.allow_to_domains.get(pat_name, [])
                    if any(
                        host == d or host.endswith("." + d)
                        for d in allowed
                    ):
                        continue
                    return InspectionResult(
                        inspector=self.name,
                        action=self.action,
                        reason=f"secret detected: {pat_name}",
                        severity="critical",
                        metadata={"pattern": pat_name},
                    )
        return None
