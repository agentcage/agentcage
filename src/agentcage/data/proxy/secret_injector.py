"""Secret injection — swap placeholders for real values on outbound requests,
redact real values back to placeholders on inbound responses.

This runs *before* inspectors on requests and *after* inspectors on responses,
modifying the flow in-place.  It is deliberately separate from the read-only
inspector chain.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from mitmproxy import http

from inspectors.base import InspectionResult

log = logging.getLogger("agentcage.secret_injector")


@dataclass
class InjectionRule:
    name: str  # e.g. "ANTHROPIC_API_KEY"
    placeholder: str  # e.g. "{{ANTHROPIC_API_KEY}}"
    real_value: str  # loaded from os.environ at startup
    inject_to: list[str] = field(default_factory=list)  # domain restrictions


class SecretInjector:
    """Transparent secret injection / redaction for mitmproxy flows."""

    def __init__(self) -> None:
        self.rules: list[InjectionRule] = []
        self.redact_to: list[str] = []

    def configure(self, config: list[dict] | dict) -> None:
        """Build injection rules from the ``secret_injection`` config.

        Accepts either a plain list of rules (backwards compat) or a dict
        with ``rules`` and optional ``redact_to`` keys.

        Each rule entry has keys: ``env``, ``placeholder``, and optionally
        ``inject_to`` (list of domains).
        """
        if isinstance(config, dict):
            rules_list = config.get("rules", [])
            self.redact_to = [d.lower() for d in config.get("redact_to", [])]
        else:
            rules_list = config
            self.redact_to = []

        self.rules = []
        for entry in rules_list:
            env_name = entry.get("env", "")
            placeholder = entry.get("placeholder", "")
            inject_to = [d.lower() for d in entry.get("inject_to", [])]

            real_value = os.environ.get(env_name, "")
            if not real_value:
                log.warning(
                    "secret_injection: env var %s not set, skipping rule", env_name
                )
                continue

            self.rules.append(
                InjectionRule(
                    name=env_name,
                    placeholder=placeholder,
                    real_value=real_value,
                    inject_to=inject_to,
                )
            )

    def _find_placeholder(self, flow: http.HTTPFlow, rule: InjectionRule) -> bool:
        """Check if a rule's placeholder is present in the flow."""
        ph = rule.placeholder
        if ph in flow.request.url:
            return True
        for v in flow.request.headers.values():
            if ph in v:
                return True
        if flow.request.content and ph.encode() in flow.request.content:
            return True
        return False

    def check_injection_policy(
        self, flow: http.HTTPFlow
    ) -> Optional[InspectionResult]:
        """Check domain restrictions without modifying the flow.

        Returns an ``InspectionResult`` (flag) if a placeholder is found
        heading to an unauthorized domain.  Returns ``None`` if ok.
        """
        if not self.rules:
            return None

        host = flow.request.host.lower()

        if self.redact_to and self._domain_matches(host, self.redact_to):
            return None

        for rule in self.rules:
            if not self._find_placeholder(flow, rule):
                continue
            if rule.inject_to and not self._domain_matches(host, rule.inject_to):
                return InspectionResult(
                    inspector="secret-injector",
                    action="flag",
                    reason=(
                        f"placeholder {rule.name} sent to unauthorized "
                        f"domain {host}"
                    ),
                    severity="high",
                )
        return None

    def inject_request(self, flow: http.HTTPFlow) -> None:
        """Replace placeholders with real values in the outbound request.

        If the host matches ``redact_to``, outbound redaction is performed
        instead (real values → placeholders).

        Rules whose ``inject_to`` list does not match the request host are
        skipped, leaving the placeholder in place.
        """
        if not self.rules:
            return

        host = flow.request.host.lower()

        # Redact-to domains: replace real values with placeholders
        if self.redact_to and self._domain_matches(host, self.redact_to):
            self._redact_request(flow)
            return

        for rule in self.rules:
            if not self._find_placeholder(flow, rule):
                continue

            # Skip injection if domain not authorized for this rule
            if rule.inject_to and not self._domain_matches(host, rule.inject_to):
                continue

            # Replace placeholder → real value
            ph = rule.placeholder
            real = rule.real_value
            ph_bytes = ph.encode()
            real_bytes = real.encode()

            flow.request.url = flow.request.url.replace(ph, real)

            # Headers — rebuild to handle replacement
            for k in list(flow.request.headers.keys()):
                v = flow.request.headers[k]
                if ph in v:
                    flow.request.headers[k] = v.replace(ph, real)

            if flow.request.content and ph_bytes in flow.request.content:
                flow.request.content = flow.request.content.replace(
                    ph_bytes, real_bytes
                )

    def _redact_request(self, flow: http.HTTPFlow) -> None:
        """Replace real secret values with placeholders in the outbound request.

        Used for ``redact_to`` domains — the inverse of injection.
        Processes rules sorted by real-value length descending to prevent
        partial matches when one value is a substring of another.
        """
        sorted_rules = sorted(
            self.rules, key=lambda r: len(r.real_value), reverse=True
        )

        for rule in sorted_rules:
            real = rule.real_value
            real_bytes = real.encode()
            ph = rule.placeholder
            ph_bytes = ph.encode()

            # Redact URL
            flow.request.url = flow.request.url.replace(real, ph)

            # Redact headers
            for k in list(flow.request.headers.keys()):
                v = flow.request.headers[k]
                if real in v:
                    flow.request.headers[k] = v.replace(real, ph)

            # Redact body
            if flow.request.content and real_bytes in flow.request.content:
                flow.request.content = flow.request.content.replace(
                    real_bytes, ph_bytes
                )

    def redact_response(self, flow: http.HTTPFlow) -> None:
        """Replace real secret values with placeholders in the response.

        Processes rules sorted by real-value length descending to prevent
        partial matches when one value is a substring of another.
        """
        if not self.rules or not flow.response:
            return

        # Sort longest real value first to avoid partial-match issues
        sorted_rules = sorted(
            self.rules, key=lambda r: len(r.real_value), reverse=True
        )

        for rule in sorted_rules:
            real = rule.real_value
            real_bytes = real.encode()
            ph = rule.placeholder
            ph_bytes = ph.encode()

            # Redact response headers
            for k in list(flow.response.headers.keys()):
                v = flow.response.headers[k]
                if real in v:
                    flow.response.headers[k] = v.replace(real, ph)

            # Redact response body
            if flow.response.content and real_bytes in flow.response.content:
                flow.response.content = flow.response.content.replace(
                    real_bytes, ph_bytes
                )

    @staticmethod
    def _domain_matches(host: str, domains: list[str]) -> bool:
        """Suffix match — same logic as DomainInspector._matches."""
        parts = host.lower().split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in domains:
                return True
        return False
