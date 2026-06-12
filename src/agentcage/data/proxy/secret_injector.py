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
from pathlib import Path
from typing import Any, Callable, Optional

from mitmproxy import http

from inspectors.base import InspectionResult

log = logging.getLogger("agentcage.secret_injector")

# File-delivery fallback for backends that don't inject secrets as env vars.
# The container/podman backend uses Quadlet `Secret=type=env,target=KEY` so
# secrets land in os.environ. The apple-container backend can't — apple's
# `container` CLI has no quadlet-style env-secret primitive and we
# deliberately don't pass cleartext via `-e KEY=VAL` (would show in
# `container inspect` and process listings). Instead the backend bind-mounts
# a 0600 secrets dir into the egress sibling at /home/acproxy/secrets.
# This module reads from there when env lookup misses. Path is overridable
# via AGENTCAGE_SECRETS_DIR so tests don't need to write to /home.
_SECRETS_DIR = Path(
    os.environ.get("AGENTCAGE_SECRETS_DIR", "/home/acproxy/secrets")
)

# Strict (default) injection confines secret substitution to the "auth
# channel": a placeholder is swapped for its real value only when it appears
# in a *credential-bearing request header*, never in the URL/query string,
# the request body, or a WebSocket frame (those keep the placeholder unless
# the rule sets ``inject_body: true``). Keeping secrets out of bodies is the
# PR #251 goal — bodies get logged and echoed downstream; the auth header
# does not.
#
# Rather than enumerate specific vendor header names, we recognize a header
# as credential-bearing when its name contains one of these keyword stems
# (case-insensitive substring match). Almost every API's auth header does:
#   authorization, x-api-key, api-key, apikey, x-goog-api-key, private-token,
#   x-auth-token, x-auth-key, x-subscription-token, ocp-apim-subscription-key,
#   dd-api-key, circle-token, x-algolia-api-key, fastly-key, x-figma-token,
#   x-postmark-server-token, x-shopify-access-token, … all match.
# (Surveyed against ~70 popular APIs; the only credential header found that
# lacks any of these stems is Honeycomb's ``x-honeycomb-team`` — add headers
# like that per-rule via ``inject_headers``.)
#
# This is safe because the match only ever has an effect when a rule's unique
# ``{{PLACEHOLDER}}`` literally appears in the header — the cage only puts the
# placeholder where its HTTP client sends the credential — so a broad match
# can't inject a secret somewhere the agent didn't already place it. APIs that
# carry the key in the URL query string (Google ``?key=``, SerpAPI
# ``?api_key=``, Firebase ``?auth=``) or the request body (Plaid) are outside
# the header channel and need ``inject_body: true``.
AUTH_HEADER_KEYWORDS: tuple[str, ...] = ("auth", "key", "token")


@dataclass
class InjectionRule:
    name: str  # e.g. "ANTHROPIC_API_KEY"
    placeholder: str  # e.g. "{{ANTHROPIC_API_KEY}}"
    real_value: str  # loaded from os.environ at startup
    inject_to: list[str] = field(default_factory=list)  # domain restrictions
    # When set, ``transform_fn`` is called at substitution time to
    # produce a derived value (e.g. a freshly minted access token) in
    # place of ``real_value``. ``real_value`` still holds the underlying
    # high-privilege credential so the literal-match defense-in-depth
    # block can detect raw key bytes leaking into outbound traffic.
    transform: str = ""
    transform_fn: Optional[Callable[[], str]] = None
    # Strict by default: only inject into credential-bearing headers — those
    # whose name matches the ``AUTH_HEADER_KEYWORDS`` heuristic or is listed in
    # ``inject_headers``. When True, also inject into the request URL, every
    # header, the body, and WebSocket frames (the legacy, looser behavior).
    inject_body: bool = False
    # Extra request headers this rule treats as credential-bearing under the
    # strict default — for auth headers whose name doesn't match the keyword
    # heuristic (e.g. ``x-honeycomb-team``). Matched case-insensitively.
    inject_headers: list[str] = field(default_factory=list)

    def is_auth_header(self, name: str) -> bool:
        """Whether ``name`` is a credential-bearing header this rule injects
        into under the strict default. True when the (case-insensitive) header
        name contains one of ``AUTH_HEADER_KEYWORDS`` or exactly matches an
        ``inject_headers`` entry."""
        n = name.lower()
        if any(kw in n for kw in AUTH_HEADER_KEYWORDS):
            return True
        return any(n == extra.lower() for extra in self.inject_headers)


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
            if not placeholder:
                # A rule whose placeholder was never generated (the CLI
                # fills omitted placeholders at declare time). An empty
                # placeholder must never reach matching: `"" in text` is
                # always True and `text.replace("", v)` corrupts content.
                log.warning(
                    "secret_injection: rule %s has no placeholder, "
                    "skipping", env_name,
                )
                continue
            inject_to = [d.lower() for d in entry.get("inject_to", [])]

            # Value resolution — staged file first, env fallback.
            #
            # The bind-mounted secrets dir (/home/acproxy/secrets, staged by
            # the egress ExecStartPre and re-written live by `agentcage
            # secret set`) is authoritative WHEN the file exists: the
            # process env is frozen at container creation, so only the file
            # can carry a value change without a container restart. An
            # EXISTING-but-EMPTY file is a tombstone (`secret rm` / failed
            # staging of a deleted store entry): the rule is skipped rather
            # than falling back to a stale env value. Only a MISSING file
            # falls back to the env channel (pre-staging cages, podman <
            # 4.7 where --showsecret is unavailable).
            real_value = ""
            staged = False
            secret_file = _SECRETS_DIR / env_name
            try:
                if secret_file.is_file():
                    staged = True
                    real_value = secret_file.read_text().rstrip("\n")
            except OSError as e:
                log.warning(
                    "secret_injection: failed reading %s: %s",
                    secret_file, e,
                )
            if not staged:
                real_value = os.environ.get(env_name, "")
            if not real_value:
                log.warning(
                    "secret_injection: no value for %s (%s), skipping rule",
                    env_name,
                    "staged file is empty" if staged else "env var not set",
                )
                continue

            inject_body = bool(entry.get("inject_body", False))
            inject_headers = [
                str(h).strip() for h in (entry.get("inject_headers") or [])
            ]

            transform_name = entry.get("transform", "") or ""
            transform_fn: Optional[Callable[[], str]] = None
            if transform_name:
                transform_config = entry.get("transform_config") or {}
                try:
                    transform_fn = self._build_transform(
                        transform_name, real_value, transform_config
                    )
                except Exception as e:
                    log.error(
                        "secret_injection: transform %s for %s failed to "
                        "initialize: %s — skipping rule",
                        transform_name, env_name, e,
                    )
                    continue

            self.rules.append(
                InjectionRule(
                    name=env_name,
                    placeholder=placeholder,
                    real_value=real_value,
                    inject_to=inject_to,
                    transform=transform_name,
                    transform_fn=transform_fn,
                    inject_body=inject_body,
                    inject_headers=inject_headers,
                )
            )

    @staticmethod
    def _build_transform(
        name: str, secret: str, config: dict[str, Any]
    ) -> Callable[[], str]:
        """Look up a transform class and return its bound ``get_value``."""
        # Lazy import — keeps mitmproxy's addon load fast and avoids
        # pulling cryptography unless a transform actually uses it.
        from transforms import get as _get

        cls = _get(name)
        instance = cls(secret, config)
        return instance.get_value

    def _find_real_value(self, flow: http.HTTPFlow, rule: InjectionRule) -> bool:
        """Check if a rule's real secret value is present in the flow."""
        rv = rule.real_value
        if rv in flow.request.url:
            return True
        for v in flow.request.headers.values():
            if rv in v:
                return True
        if flow.request.content and rv.encode() in flow.request.content:
            return True
        return False

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

        # Block literal real values heading to unauthorized domains.
        # If the host is in the rule's inject_to list the value will
        # legitimately appear after injection, so we allow it — UNLESS
        # the rule has a transform, in which case the cage agent should
        # never have produced the raw secret bytes in the first place
        # (the proxy mints derived values; the raw credential never
        # legitimately appears on the wire to anywhere).
        for rule in self.rules:
            if self._find_real_value(flow, rule):
                if (
                    not rule.transform_fn
                    and rule.inject_to
                    and self._domain_matches(host, rule.inject_to)
                ):
                    continue
                return InspectionResult(
                    inspector="secret-injector",
                    action="block",
                    reason=(
                        f"literal secret value {rule.name} found in "
                        f"outbound request to {host}"
                    ),
                    severity="critical",
                )

        # Flag placeholders heading to unauthorized domains
        for rule in self.rules:
            if not self._find_placeholder(flow, rule):
                continue
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                return InspectionResult(
                    inspector="secret-injector",
                    action="flag",
                    reason=(
                        f"placeholder {rule.name} sent to unauthorized "
                        f"domain {host}"
                    ),
                    severity="error",
                )
        return None

    def inject_request(self, flow: http.HTTPFlow) -> list[str]:
        """Replace placeholders with real values in the outbound request.

        If the host matches ``redact_to``, outbound redaction is performed
        instead (real values → placeholders).

        Rules whose ``inject_to`` list does not match the request host are
        skipped, leaving the placeholder in place.

        Returns a list of secret names that were injected (or redacted for
        ``redact_to`` domains).
        """
        if not self.rules:
            return []

        host = flow.request.host.lower()

        # Redact-to domains: replace real values with placeholders
        if self.redact_to and self._domain_matches(host, self.redact_to):
            return self._redact_request(flow)

        names: list[str] = []
        for rule in self.rules:
            if not self._find_placeholder(flow, rule):
                continue

            # Skip injection if no authorized domains or domain not authorized
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                continue

            # Resolve substitution value: transform produces a derived
            # value at request time; otherwise use the static real_value.
            if rule.transform_fn is not None:
                try:
                    value = rule.transform_fn()
                except Exception as e:
                    log.error(
                        "secret_injection: transform %s (%s) failed: %s "
                        "— leaving placeholder in place",
                        rule.transform, rule.name, e,
                    )
                    continue
            else:
                value = rule.real_value

            ph = rule.placeholder
            ph_bytes = ph.encode()
            value_bytes = value.encode()

            injected = False

            if rule.inject_body:
                # Legacy/loose mode: inject into URL, all headers, and body.
                if ph in flow.request.url:
                    flow.request.url = flow.request.url.replace(ph, value)
                    injected = True

                for k in list(flow.request.headers.keys()):
                    v = flow.request.headers[k]
                    if ph in v:
                        flow.request.headers[k] = v.replace(ph, value)
                        injected = True

                if flow.request.content and ph_bytes in flow.request.content:
                    flow.request.content = flow.request.content.replace(
                        ph_bytes, value_bytes
                    )
                    injected = True
            else:
                # Strict mode (default): only inject into credential-bearing
                # headers — those whose name contains "auth", "key", or
                # "token" (Authorization, x-api-key, *-token, …), plus any
                # explicit ``inject_headers``. Placeholders anywhere else —
                # the URL, the body, or a non-credential header — are left
                # untouched.
                for k in list(flow.request.headers.keys()):
                    if not rule.is_auth_header(k):
                        continue
                    v = flow.request.headers[k]
                    if ph in v:
                        flow.request.headers[k] = v.replace(ph, value)
                        injected = True

            if injected:
                names.append(rule.name)
        return names

    def _redact_request(self, flow: http.HTTPFlow) -> list[str]:
        """Replace real secret values with placeholders in the outbound request.

        Used for ``redact_to`` domains — the inverse of injection.
        Processes rules sorted by real-value length descending to prevent
        partial matches when one value is a substring of another.

        Returns a list of secret names that were redacted.
        """
        sorted_rules = sorted(
            self.rules, key=lambda r: len(r.real_value), reverse=True
        )

        names: list[str] = []
        for rule in sorted_rules:
            real = rule.real_value
            real_bytes = real.encode()
            ph = rule.placeholder
            ph_bytes = ph.encode()

            found = False

            # Redact URL
            if real in flow.request.url:
                flow.request.url = flow.request.url.replace(real, ph)
                found = True

            # Redact headers
            for k in list(flow.request.headers.keys()):
                v = flow.request.headers[k]
                if real in v:
                    flow.request.headers[k] = v.replace(real, ph)
                    found = True

            # Redact body
            if flow.request.content and real_bytes in flow.request.content:
                flow.request.content = flow.request.content.replace(
                    real_bytes, ph_bytes
                )
                found = True

            if found:
                names.append(rule.name)
        return names

    def redact_request(self, flow: http.HTTPFlow) -> list[str]:
        """Replace real secret values with placeholders in the outbound
        REQUEST after it has been forwarded upstream — so the capture
        writer never serializes raw secret bytes to ``capture.jsonl``.

        This is the request-side mirror of ``redact_response``. It must
        run AFTER ``inject_request`` has put the real secrets on the wire
        (mitmproxy forwards on ``request`` hook return) and BEFORE any
        capture serialization reads ``flow.request.url`` /
        ``flow.request.headers`` / ``flow.request.content``. The capture
        file is bind-mounted into the cage at mode 0644; without this
        step the OUTBOUND request snapshot (by design "what went out
        on the wire") would land the raw ``ANTHROPIC_API_KEY`` on disk
        where the cage workload can read it.

        Distinct from the ``redact_to`` path: ``_redact_request`` runs
        at injection time for explicitly tagged ``redact_to`` domains
        (the cage agent shouldn't see its own secret echoed back from
        a non-trusted upstream). ``redact_request`` runs for EVERY rule
        on EVERY domain after the upstream send, purely to scrub the
        in-memory flow before disk serialization. Rules are processed
        longest real-value first to avoid partial-match issues.

        Returns the list of secret names that were redacted.
        """
        if not self.rules:
            return []

        sorted_rules = sorted(
            self.rules, key=lambda r: len(r.real_value), reverse=True
        )

        names: list[str] = []
        for rule in sorted_rules:
            real = rule.real_value
            real_bytes = real.encode()
            ph = rule.placeholder
            ph_bytes = ph.encode()

            found = False

            # Redact URL (rules that injected into query strings).
            if real in flow.request.url:
                flow.request.url = flow.request.url.replace(real, ph)
                found = True

            # Redact headers.
            for k in list(flow.request.headers.keys()):
                v = flow.request.headers[k]
                if real in v:
                    flow.request.headers[k] = v.replace(real, ph)
                    found = True

            # Redact body — only when the bytes are actually present;
            # avoid touching ``flow.request.content`` otherwise so we
            # don't churn binary bodies that legitimately contain no
            # secret material.
            if flow.request.content and real_bytes in flow.request.content:
                flow.request.content = flow.request.content.replace(
                    real_bytes, ph_bytes
                )
                found = True

            if found:
                names.append(rule.name)
        return names

    def redact_response(self, flow: http.HTTPFlow) -> list[str]:
        """Replace real secret values with placeholders in the response.

        Processes rules sorted by real-value length descending to prevent
        partial matches when one value is a substring of another.

        Returns a list of secret names that were redacted.
        """
        if not self.rules or not flow.response:
            return []

        # Sort longest real value first to avoid partial-match issues
        sorted_rules = sorted(
            self.rules, key=lambda r: len(r.real_value), reverse=True
        )

        names: list[str] = []
        for rule in sorted_rules:
            real = rule.real_value
            real_bytes = real.encode()
            ph = rule.placeholder
            ph_bytes = ph.encode()

            found = False

            # Redact response headers
            for k in list(flow.response.headers.keys()):
                v = flow.response.headers[k]
                if real in v:
                    flow.response.headers[k] = v.replace(real, ph)
                    found = True

            # Redact response body
            if flow.response.content and real_bytes in flow.response.content:
                flow.response.content = flow.response.content.replace(
                    real_bytes, ph_bytes
                )
                found = True

            if found:
                names.append(rule.name)
        return names

    # ── WebSocket (raw bytes) methods ───────────────────────

    def check_ws_injection_policy(
        self, content: bytes, host: str
    ) -> Optional[InspectionResult]:
        """Check domain restrictions for a WebSocket frame payload.

        Like ``check_injection_policy`` but operates on raw bytes + host
        instead of an ``http.HTTPFlow``.
        """
        if not self.rules:
            return None

        host = host.lower()

        if self.redact_to and self._domain_matches(host, self.redact_to):
            return None

        # Block literal real values heading to unauthorized domains.
        # Transform rules block raw secret bytes everywhere — see the
        # equivalent comment in check_injection_policy.
        for rule in self.rules:
            if rule.real_value.encode() in content:
                if (
                    not rule.transform_fn
                    and rule.inject_to
                    and self._domain_matches(host, rule.inject_to)
                ):
                    continue
                return InspectionResult(
                    inspector="secret-injector",
                    action="block",
                    reason=(
                        f"literal secret value {rule.name} found in "
                        f"outbound WebSocket frame to {host}"
                    ),
                    severity="critical",
                )

        # Flag placeholders heading to unauthorized domains
        for rule in self.rules:
            if rule.placeholder.encode() not in content:
                continue
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                return InspectionResult(
                    inspector="secret-injector",
                    action="flag",
                    reason=(
                        f"placeholder {rule.name} sent to unauthorized "
                        f"domain {host}"
                    ),
                    severity="error",
                )
        return None

    def inject_ws_content(
        self, content: bytes, host: str
    ) -> tuple[bytes, list[str]]:
        """Replace placeholders with real values in outbound WebSocket content.

        If the host matches ``redact_to``, outbound redaction is performed
        instead (real values → placeholders).

        Returns ``(content, names)`` where *names* lists the secrets acted on.
        """
        if not self.rules:
            return content, []

        host = host.lower()

        if self.redact_to and self._domain_matches(host, self.redact_to):
            return self._redact_ws_content(content)

        names: list[str] = []
        for rule in self.rules:
            # Strict mode only injects into credential-bearing request
            # headers, which have no equivalent in a raw WebSocket frame —
            # leave the placeholder in place unless the rule opted into body
            # injection (inject_body).
            if not rule.inject_body:
                continue
            ph_bytes = rule.placeholder.encode()
            if ph_bytes not in content:
                continue
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                continue
            if rule.transform_fn is not None:
                try:
                    value = rule.transform_fn()
                except Exception as e:
                    log.error(
                        "secret_injection: transform %s (%s) failed on "
                        "WebSocket content: %s — leaving placeholder",
                        rule.transform, rule.name, e,
                    )
                    continue
                content = content.replace(ph_bytes, value.encode())
            else:
                content = content.replace(ph_bytes, rule.real_value.encode())
            names.append(rule.name)

        return content, names

    def redact_ws_content(self, content: bytes) -> tuple[bytes, list[str]]:
        """Replace real secret values with placeholders in WebSocket content.

        Processes rules sorted by real-value length descending to prevent
        partial matches when one value is a substring of another.

        Returns ``(content, names)`` where *names* lists the secrets redacted.
        """
        if not self.rules:
            return content, []

        sorted_rules = sorted(
            self.rules, key=lambda r: len(r.real_value), reverse=True
        )

        names: list[str] = []
        for rule in sorted_rules:
            real_bytes = rule.real_value.encode()
            if real_bytes in content:
                content = content.replace(real_bytes, rule.placeholder.encode())
                names.append(rule.name)

        return content, names

    def _redact_ws_content(
        self, content: bytes
    ) -> tuple[bytes, list[str]]:
        """Private helper — redact real values in outbound WS content.

        Used by ``inject_ws_content`` for ``redact_to`` domains.
        """
        return self.redact_ws_content(content)

    @staticmethod
    def _domain_matches(host: str, domains: list[str]) -> bool:
        """Suffix match — same logic as DomainInspector._matches."""
        parts = host.lower().split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in domains:
                return True
        return False
