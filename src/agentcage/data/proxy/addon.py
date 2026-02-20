"""agentcage — mitmproxy traffic inspection with pluggable inspectors."""

import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import yaml
from mitmproxy import ctx, http
from mitmproxy.proxy.mode_specs import ReverseMode

from inspectors.base import InspectionContext, InspectionResult, Inspector
from inspectors.body_size import BodySizeInspector
from inspectors.content_type import ContentTypeInspector
from inspectors.domain import DomainInspector
from inspectors.entropy import EntropyInspector
from inspectors.secrets import SecretsInspector
from inspectors.util import load_inspector_from_file, shannon_entropy
from secret_injector import SecretInjector

CONFIG_PATH = os.environ.get("AGENTCAGE_CONFIG", "/etc/agentcage/config.yaml")


# ── Built-in inspector registry ──────────────────────────
# Order matters: domain runs first to short-circuit blocked domains before
# expensive body analysis (secrets, entropy, content-type).  If you add
# inspectors, keep cheap / high-reject-rate checks early in the chain.

_BUILTIN_INSPECTORS: dict[str, type[Inspector]] = {
    "domain": DomainInspector,
    "secrets": SecretsInspector,
    "body-size": BodySizeInspector,
    "entropy": EntropyInspector,
    "content-type": ContentTypeInspector,
}


# ── Orchestrator ─────────────────────────────────────────


class Agentcage:
    """mitmproxy addon that delegates inspection to a chain of inspectors."""

    def load(self, loader) -> None:
        with open(CONFIG_PATH) as f:
            self.cfg = yaml.safe_load(f) or {}
        logging_cfg = self.cfg.get("logging") or {}
        if "allowed_requests" in logging_cfg:
            self.log_allowed = bool(logging_cfg["allowed_requests"])
        else:
            self.log_allowed = bool(self.cfg.get("log_allowed", True))
        self.inspectors: list[Inspector] = []
        self.injector = SecretInjector()

        injection_cfg = self.cfg.get("secret_injection", [])
        if injection_cfg:
            self.injector.configure(injection_cfg)
            if self.injector.redact_to:
                ctx.log.info(
                    f"agentcage: redact_to domains={self.injector.redact_to}"
                )

        # Rate limiting — token bucket per host
        rl_cfg = self.cfg.get("rate_limit") or {}
        self._rl_rate: float = float(rl_cfg.get("requests_per_second", 10))
        self._rl_burst: int = int(rl_cfg.get("burst", 50))
        self._rl_buckets: dict[str, list] = defaultdict(
            lambda: [self._rl_burst, time.monotonic()]
        )  # {host: [tokens, last_time]}

        self._load_builtin_inspectors()
        self._load_custom_inspectors()

        # Audit log file — structured JSON lines for forensic analysis
        audit_path = os.environ.get(
            "AGENTCAGE_AUDIT_LOG", "/var/log/agentcage/audit.jsonl"
        )
        self._audit_file = None
        if audit_path:
            try:
                os.makedirs(os.path.dirname(audit_path), exist_ok=True)
                self._audit_file = open(audit_path, "a")
            except OSError as e:
                ctx.log.warn(f"agentcage: cannot open audit log {audit_path}: {e}")

        names = [i.name for i in self.inspectors]
        ctx.log.info(
            f"agentcage loaded: inspectors={names}, "
            f"injection_rules={len(self.injector.rules)}"
        )

    # ── Inspector loading ────────────────────────────────

    def _load_builtin_inspectors(self) -> None:
        """Load built-in inspectors from legacy and new config styles."""
        # Backwards-compatible: map old top-level config keys to
        # built-in inspector configs so existing config files keep working.
        legacy_map = self._build_legacy_config()
        for builtin_name, cls in _BUILTIN_INSPECTORS.items():
            cfg_section = legacy_map.get(builtin_name)
            if cfg_section is None:
                continue
            inspector = cls()
            inspector.configure(cfg_section)
            self.inspectors.append(inspector)

    def _build_legacy_config(self) -> dict[str, Optional[dict]]:
        """Translate old top-level YAML keys into per-inspector configs."""
        out: dict[str, Optional[dict]] = {}

        # domain — always load (inspector checks mode internally)
        out["domain"] = self.cfg.get("domains", {})

        # secrets — always load (inspector checks enabled internally)
        out["secrets"] = self.cfg.get("secrets", {})

        # body-size — only if max_request_body is set
        max_body = self.cfg.get("max_request_body", 10485760)
        if max_body:
            out["body-size"] = {"max_bytes": max_body}

        # entropy — on by default in flag mode; disable with entropy: false
        entropy_cfg = self.cfg.get("entropy", {})
        if entropy_cfg is not False:
            out["entropy"] = entropy_cfg if isinstance(entropy_cfg, dict) else {}

        # content-type — on by default in flag mode; disable with content_type: false
        ct_cfg = self.cfg.get("content_type", {})
        if ct_cfg is not False:
            out["content-type"] = ct_cfg if isinstance(ct_cfg, dict) else {}

        return out

    def _load_custom_inspectors(self) -> None:
        """Load inspectors declared in the ``inspectors:`` config section.

        Each entry can be:
        - A built-in by name::

              inspectors:
                - name: entropy
                  config:
                    threshold: 7.5

        - A custom Python file::

              inspectors:
                - name: my-check
                  path: /etc/agentcage/my_inspector.py
                  config:
                    key: value
        """
        for entry in self.cfg.get("inspectors", []):
            name = entry.get("name", "")
            path = entry.get("path")
            cfg = entry.get("config", {})

            # Skip if this built-in was already loaded via legacy config
            if not path and name in _BUILTIN_INSPECTORS:
                already = any(i.name == name for i in self.inspectors)
                if already:
                    # Re-configure with the explicit config section
                    for i in self.inspectors:
                        if i.name == name:
                            i.configure(cfg)
                            break
                    continue
                inspector = _BUILTIN_INSPECTORS[name]()
            elif path:
                inspector = load_inspector_from_file(path)
            else:
                ctx.log.warn(f"skipping unknown inspector: {name}")
                continue

            inspector.configure(cfg)
            self.inspectors.append(inspector)

    # ── Request handling ─────────────────────────────────

    def _check_rate_limit(self, host: str) -> bool:
        """Token-bucket rate limiter per host. Returns True if allowed."""
        if not self._rl_rate:
            return True
        bucket = self._rl_buckets[host]
        now = time.monotonic()
        elapsed = now - bucket[1]
        bucket[1] = now
        bucket[0] = min(self._rl_burst, bucket[0] + elapsed * self._rl_rate)
        if bucket[0] >= 1:
            bucket[0] -= 1
            return True
        return False

    def request(self, flow: http.HTTPFlow) -> None:
        # Rate limiting
        if not self._check_rate_limit(flow.request.host):
            flow.response = http.Response.make(
                429,
                json.dumps(
                    {"blocked": True, "reason": "rate limit exceeded",
                     "host": flow.request.host, "by": "agentcage"}
                ).encode(),
                {"Content-Type": "application/json"},
            )
            flow.metadata["agentcage_blocked"] = True
            self._log(flow, "blocked", "rate limit exceeded", [])
            return

        # Check for placeholder-to-unauthorized-domain violations first
        # (this does NOT modify the flow — only checks domain restrictions)
        inject_result = self.injector.check_injection_policy(flow)
        if inject_result and inject_result.action == "block":
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {"blocked": True, "reason": inject_result.reason,
                     "host": flow.request.host, "by": "agentcage"}
                ).encode(),
                {"Content-Type": "application/json"},
            )
            flow.metadata["agentcage_blocked"] = True
            self._log(flow, "blocked", inject_result.reason, [inject_result])
            return

        # Build context BEFORE injection so inspectors see placeholders,
        # not real secret values
        ctx_obj = self._build_context(flow)
        results: list[InspectionResult] = []

        # Reverse proxy flows are inbound traffic (host → cage via proxy).
        # Skip domain filtering (the "domain" is the internal cage IP, not
        # an external target) but still run all other inspectors.
        is_reverse = isinstance(
            getattr(flow.client_conn, "proxy_mode", None), ReverseMode
        )

        for inspector in self.inspectors:
            if is_reverse and isinstance(inspector, DomainInspector):
                continue
            result = inspector.inspect_request(ctx_obj)
            if result is not None:
                results.append(result)
                ctx_obj.prior_results.append(result)
                if result.action == "block":
                    break  # short-circuit on hard block

        blocked = [r for r in results if r.action == "block"]
        if blocked:
            reason = blocked[0].reason
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {"blocked": True, "reason": reason,
                     "host": flow.request.host, "by": "agentcage"}
                ).encode(),
                {"Content-Type": "application/json"},
            )
            flow.metadata["agentcage_blocked"] = True
            self._log(flow, "blocked", reason, results)
        else:
            # Inject real secrets only AFTER inspectors have approved
            self.injector.inject_request(flow)
            flagged = [r for r in results if r.action == "flag"]
            if flagged:
                reasons = "; ".join(r.reason for r in flagged)
                self._log(flow, "flagged", reasons, results)
            else:
                self._log(flow, "allowed", None, results)

    def response(self, flow: http.HTTPFlow) -> None:
        # Only run response inspectors if the request wasn't blocked
        if flow.metadata.get("agentcage_blocked"):
            return

        ctx_obj = self._build_context(flow, response=True)
        results: list[InspectionResult] = []

        for inspector in self.inspectors:
            result = inspector.inspect_response(ctx_obj)
            if result is not None:
                results.append(result)
                ctx_obj.prior_results.append(result)
                if result.action == "block":
                    break

        blocked = [r for r in results if r.action == "block"]
        if blocked:
            reason = blocked[0].reason
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {"blocked": True, "reason": reason,
                     "host": flow.request.host, "by": "agentcage"}
                ).encode(),
                {"Content-Type": "application/json"},
            )
            self._log(flow, "blocked", reason, results)

        # Redact real secrets from response before it reaches the cage
        self.injector.redact_response(flow)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Inspect WebSocket frame payloads for secrets and high entropy."""
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        content = msg.content
        if not content:
            return

        body_bytes = content if isinstance(content, bytes) else content.encode()
        body_text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        body_ent = shannon_entropy(body_bytes)

        ws_ctx = InspectionContext(
            url=flow.request.url,
            host=flow.request.host,
            method="WEBSOCKET",
            headers=dict(flow.request.headers),
            content_type="application/x-websocket-frame",
            body_bytes=body_bytes,
            body_text=body_text,
            body_size=len(body_bytes),
            body_entropy=body_ent,
        )

        results: list[InspectionResult] = []
        for inspector in self.inspectors:
            result = inspector.inspect_request(ws_ctx)
            if result is not None:
                results.append(result)
                ws_ctx.prior_results.append(result)
                if result.action == "block":
                    break

        blocked = [r for r in results if r.action == "block"]
        if blocked:
            reason = blocked[0].reason
            msg.drop()
            self._log(flow, "blocked", f"websocket: {reason}", results)
        else:
            flagged = [r for r in results if r.action == "flag"]
            if flagged:
                reasons = "; ".join(r.reason for r in flagged)
                self._log(flow, "flagged", f"websocket: {reasons}", results)
            elif self.log_allowed:
                self._log(flow, "allowed", "websocket", results)

    # ── Context building ─────────────────────────────────

    def _build_context(
        self, flow: http.HTTPFlow, response: bool = False
    ) -> InspectionContext:
        if response and flow.response:
            body_bytes = flow.response.content
            body_text = flow.response.get_text(strict=False)
            content_type = flow.response.headers.get("content-type", "")
            headers = dict(flow.response.headers)
        else:
            body_bytes = flow.request.content
            body_text = flow.request.get_text(strict=False)
            content_type = flow.request.headers.get("content-type", "")
            headers = dict(flow.request.headers)

        body_size = len(body_bytes) if body_bytes else 0
        body_ent = shannon_entropy(body_bytes) if body_bytes else None

        return InspectionContext(
            url=flow.request.url,
            host=flow.request.host,
            method=flow.request.method,
            headers=headers,
            content_type=content_type,
            body_bytes=body_bytes,
            body_text=body_text,
            body_size=body_size,
            body_entropy=body_ent,
        )

    # ── Logging ──────────────────────────────────────────

    def _log(
        self,
        flow: http.HTTPFlow,
        decision: str,
        reason: Optional[str],
        results: list[InspectionResult],
    ) -> None:
        if decision == "allowed" and not self.log_allowed:
            return
        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "host": flow.request.host,
            "url": flow.request.url,
            "decision": decision,
            "reason": reason or "",
        }
        if results:
            entry["inspectors"] = [
                {
                    "name": r.inspector,
                    "action": r.action,
                    "reason": r.reason,
                    "severity": r.severity,
                }
                for r in results
            ]
        line = json.dumps(entry)
        ctx.log.info(line)
        if self._audit_file:
            try:
                self._audit_file.write(line + "\n")
                self._audit_file.flush()
            except OSError:
                pass


addons = [Agentcage()]
