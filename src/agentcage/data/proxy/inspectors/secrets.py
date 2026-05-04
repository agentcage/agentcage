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
    "brave_api_key": re.compile(r"BSAI[a-zA-Z0-9_-]{20,255}"),
    "telegram_bot_token": re.compile(r"[0-9]{5,16}:[A-Za-z0-9_-]{35}"),
    "discord_bot_token": re.compile(r"[MNO][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,255}"),
    "firecrawl_key": re.compile(r"fc-[a-f0-9]{32}"),
}

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
        self.patterns: dict[str, re.Pattern] = {}
        self.allow_to_domains: dict[str, list[str]] = {}
        if self.enabled:
            self.patterns = dict(BUILTIN_SECRETS)
            for p in config.get("extra_patterns", []):
                env_name = p.get("env")
                if env_name:
                    value = os.environ.get(env_name, "")
                    if not value:
                        continue
                    self.patterns[p["name"]] = re.compile(re.escape(value))
                else:
                    self.patterns[p["name"]] = re.compile(p["pattern"])
            # Merge built-in allow_to_domains (user config wins)
            if config.get("builtin_allow_to_domains", True):
                merged: dict[str, list[str]] = {
                    k: [d.lower() for d in v]
                    for k, v in BUILTIN_ALLOW_TO_DOMAINS.items()
                }
                for pat_name, domains in (
                    config.get("allow_to_domains") or {}
                ).items():
                    merged[pat_name] = [d.lower() for d in domains]
                self.allow_to_domains = merged
            else:
                for pat_name, domains in (
                    config.get("allow_to_domains") or {}
                ).items():
                    self.allow_to_domains[pat_name] = [
                        d.lower() for d in domains
                    ]

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        if not self.enabled:
            return None
        targets = [ctx.url] + [v for _, v in ctx.headers]
        if ctx.body_text:
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
                        action="block",
                        reason=f"secret detected: {pat_name}",
                        severity="critical",
                        metadata={"pattern": pat_name},
                    )
        return None
