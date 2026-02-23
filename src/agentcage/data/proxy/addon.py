"""agentcage — mitmproxy traffic inspection with pluggable inspectors."""

import json
import os
import sys
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
CAPTURE_PATH = os.environ.get("AGENTCAGE_CAPTURE", "")


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

        # Capture JSONL — full request/response bodies for HAR export
        self._capture = None
        cap_cfg = self.cfg.get("capture") or {}
        if cap_cfg.get("enable_har") and CAPTURE_PATH:
            try:
                from capture import CaptureWriter
                self._capture = CaptureWriter(cap_cfg, CAPTURE_PATH)
                ctx.log.info(f"agentcage: capture enabled → {CAPTURE_PATH}")
            except Exception as e:
                ctx.log.warn(f"agentcage: cannot init capture: {e}")

        # Per-flow capture staging — stores partial snapshots between hooks
        self._cap_pending: dict[str, dict] = {}

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

        # Reverse proxy flows are inbound traffic (host → cage via proxy).
        # Detect early so direction is available for all subsequent logging.
        is_reverse = isinstance(
            getattr(flow.client_conn, "proxy_mode", None), ReverseMode
        )
        direction = "inbound" if is_reverse else "outbound"

        # Check for placeholder-to-unauthorized-domain violations first
        # (this does NOT modify the flow — only checks domain restrictions)
        inject_result = self.injector.check_injection_policy(flow)

        # Build context BEFORE injection so inspectors see placeholders,
        # not real secret values
        ctx_obj = self._build_context(flow)
        results: list[InspectionResult] = []

        # Policy violations are flagged (not blocked) so the request still
        # goes through with the placeholder left in place.
        if inject_result is not None:
            results.append(inject_result)
            ctx_obj.prior_results.append(inject_result)

        client_ip = ""
        if is_reverse:
            # Standard forwarding headers so the upstream app can identify
            # the real client (e.g. OpenClaw gateway.trustedProxies).
            try:
                client_ip = flow.client_conn.address[0]
            except (AttributeError, IndexError, TypeError):
                pass
            if client_ip:
                flow.request.headers["x-forwarded-for"] = client_ip
            flow.request.headers["x-forwarded-proto"] = "http"

            # Rewrite Origin to match the (now-preserved) Host header so
            # origin-checking middleware doesn't see a mismatch.
            host_hdr = flow.request.host_header or f"{flow.request.host}:{flow.request.port}"
            if flow.request.headers.get("origin"):
                flow.request.headers["origin"] = f"http://{host_hdr}"

        for inspector in self.inspectors:
            if is_reverse and isinstance(inspector, DomainInspector):
                continue
            result = inspector.inspect_request(ctx_obj)
            if result is not None:
                results.append(result)
                ctx_obj.prior_results.append(result)
                if result.action == "block":
                    break  # short-circuit on hard block

        # Source IP for inbound requests (extracted above for X-Forwarded-For)
        source = client_ip

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
            self._log(flow, "blocked", reason, results, direction=direction, source=source)

            # Capture blocked flow — both perspectives see the same request
            if self._capture and self._capture.should_capture("blocked", flow.request.host):
                inbound_req = self._capture.snapshot_request(flow)
                inbound_resp = self._capture.snapshot_response(flow)
                self._capture.write_entry(
                    flow_id=flow.id, direction=direction, decision="blocked",
                    host=flow.request.host, method=flow.request.method,
                    path=flow.request.path,
                    inspectors=[{"name": r.inspector, "action": r.action,
                                 "reason": r.reason, "severity": r.severity}
                                for r in results],
                    inbound_req=inbound_req, inbound_resp=inbound_resp,
                    outbound_req=inbound_req, outbound_resp=inbound_resp,
                )
        else:
            # ── SNAPSHOT request for INBOUND (placeholders still present) ──
            cap_inbound_req = None
            if self._capture:
                cap_inbound_req = self._capture.snapshot_request(flow)

            # Inject real secrets only AFTER inspectors have approved
            injected = self.injector.inject_request(flow)

            # ── SNAPSHOT request for OUTBOUND (real secrets on the wire) ──
            cap_outbound_req = None
            if self._capture:
                cap_outbound_req = self._capture.snapshot_request(flow)

            flagged = [r for r in results if r.action == "flag"]
            if flagged:
                reasons = "; ".join(r.reason for r in flagged)
                self._log(flow, "flagged", reasons, results, direction=direction, source=source, secrets_injected=injected)
            else:
                self._log(flow, "allowed", None, results, direction=direction, source=source, secrets_injected=injected)

            # Stage partial capture for completion in response()
            if self._capture and cap_inbound_req is not None:
                decision = "flagged" if flagged else "allowed"
                self._cap_pending[flow.id] = {
                    "direction": direction,
                    "decision": decision,
                    "host": flow.request.host,
                    "method": flow.request.method,
                    "path": flow.request.path,
                    "inspectors": [{"name": r.inspector, "action": r.action,
                                    "reason": r.reason, "severity": r.severity}
                                   for r in results],
                    "inbound_req": cap_inbound_req,
                    "outbound_req": cap_outbound_req,
                }

    def response(self, flow: http.HTTPFlow) -> None:
        # Only run response inspectors if the request wasn't blocked
        if flow.metadata.get("agentcage_blocked"):
            self._cap_pending.pop(flow.id, None)
            return

        is_reverse = isinstance(
            getattr(flow.client_conn, "proxy_mode", None), ReverseMode
        )
        direction = "inbound" if is_reverse else "outbound"

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
            redacted = self.injector.redact_response(flow)
            self._log(flow, "blocked", reason, results, direction=direction, secrets_redacted=redacted)

            # Write capture for response-blocked flow
            pending = self._cap_pending.pop(flow.id, None)
            if self._capture and pending:
                resp_snap = self._capture.snapshot_response(flow)
                self._capture.write_entry(
                    flow_id=flow.id,
                    direction=pending["direction"],
                    decision="blocked",
                    host=pending["host"],
                    method=pending["method"],
                    path=pending["path"],
                    inspectors=pending["inspectors"] + [
                        {"name": r.inspector, "action": r.action,
                         "reason": r.reason, "severity": r.severity}
                        for r in results
                    ],
                    inbound_req=pending["inbound_req"],
                    inbound_resp=resp_snap,
                    outbound_req=pending["outbound_req"],
                    outbound_resp=resp_snap,
                )
        else:
            # ── SNAPSHOT response for OUTBOUND (real secrets from server) ──
            cap_outbound_resp = None
            if self._capture and flow.id in self._cap_pending:
                cap_outbound_resp = self._capture.snapshot_response(flow)

            # Redact real secrets from response before it reaches the cage
            self.injector.redact_response(flow)

            # ── SNAPSHOT response for INBOUND (secrets replaced with placeholders) ──
            # Write complete capture entry
            pending = self._cap_pending.pop(flow.id, None)
            if self._capture and pending and cap_outbound_resp is not None:
                if self._capture.should_capture(pending["decision"], pending["host"]):
                    cap_inbound_resp = self._capture.snapshot_response(flow)
                    ws_msgs = self._capture.pop_ws_messages(flow.id)
                    self._capture.write_entry(
                        flow_id=flow.id,
                        direction=pending["direction"],
                        decision=pending["decision"],
                        host=pending["host"],
                        method=pending["method"],
                        path=pending["path"],
                        inspectors=pending["inspectors"],
                        inbound_req=pending["inbound_req"],
                        inbound_resp=cap_inbound_resp,
                        outbound_req=pending["outbound_req"],
                        outbound_resp=cap_outbound_resp,
                        ws_messages=ws_msgs or None,
                    )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Inspect, inject, and redact WebSocket frame payloads."""
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        content = msg.content
        if not content:
            return

        # Buffer WS frame for capture before any mutation
        if self._capture and flow.id in self._cap_pending:
            ws_type = "send" if msg.from_client else "receive"
            ws_data = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
            self._capture.add_ws_message(flow.id, {
                "type": ws_type,
                "ts": datetime.now(timezone.utc).isoformat(),
                "opcode": 1 if isinstance(content, str) else 2,
                "data": ws_data,
            })

        body_bytes = content if isinstance(content, bytes) else content.encode()
        body_text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        body_ent = shannon_entropy(body_bytes)
        host = flow.request.host

        ws_ctx = InspectionContext(
            url=flow.request.url,
            host=host,
            method="WEBSOCKET",
            headers=list(flow.request.headers.items(multi=True)),
            content_type="application/x-websocket-frame",
            body_bytes=body_bytes,
            body_text=body_text,
            body_size=len(body_bytes),
            body_entropy=body_ent,
        )

        results: list[InspectionResult] = []

        # Reverse proxy flows invert direction: from_client means
        # browser→proxy→cage (inbound), not cage→remote (outbound).
        is_reverse = isinstance(
            getattr(flow.client_conn, "proxy_mode", None), ReverseMode
        )
        is_outbound = msg.from_client if not is_reverse else not msg.from_client

        if is_outbound:
            # ── Outbound (cage → remote) ──────────────────
            inject_result = self.injector.check_ws_injection_policy(
                body_bytes, host
            )
            if inject_result is not None:
                results.append(inject_result)
                ws_ctx.prior_results.append(inject_result)

            for inspector in self.inspectors:
                if is_reverse and isinstance(inspector, DomainInspector):
                    continue
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
                self._log(flow, "blocked", f"websocket: {reason}", results, direction="outbound")
            else:
                content, injected = self.injector.inject_ws_content(
                    body_bytes, host
                )
                msg.content = content
                flagged = [r for r in results if r.action == "flag"]
                if flagged:
                    reasons = "; ".join(r.reason for r in flagged)
                    self._log(
                        flow, "flagged", f"websocket: {reasons}", results, direction="outbound", secrets_injected=injected
                    )
                elif self.log_allowed:
                    self._log(flow, "allowed", "websocket", results, direction="outbound", secrets_injected=injected)
        else:
            # ── Inbound (remote → cage) ───────────────────
            for inspector in self.inspectors:
                if is_reverse and isinstance(inspector, DomainInspector):
                    continue
                result = inspector.inspect_response(ws_ctx)
                if result is not None:
                    results.append(result)
                    ws_ctx.prior_results.append(result)
                    if result.action == "block":
                        break

            blocked = [r for r in results if r.action == "block"]
            if blocked:
                reason = blocked[0].reason
                msg.drop()
                self._log(flow, "blocked", f"websocket: {reason}", results, direction="inbound")
            else:
                if self.log_allowed:
                    self._log(flow, "allowed", "websocket", results, direction="inbound")

            # Redact real secrets before content reaches the cage
            content, _redacted = self.injector.redact_ws_content(body_bytes)
            msg.content = content

    # ── Context building ─────────────────────────────────

    def _build_context(
        self, flow: http.HTTPFlow, response: bool = False
    ) -> InspectionContext:
        if response and flow.response:
            body_bytes = flow.response.content
            body_text = flow.response.get_text(strict=False)
            content_type = flow.response.headers.get("content-type", "")
            headers = list(flow.response.headers.items(multi=True))
        else:
            body_bytes = flow.request.content
            body_text = flow.request.get_text(strict=False)
            content_type = flow.request.headers.get("content-type", "")
            headers = list(flow.request.headers.items(multi=True))

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
        *,
        direction: str = "outbound",
        source: str = "",
        secrets_injected: list[str] | None = None,
        secrets_redacted: list[str] | None = None,
    ) -> None:
        if decision == "allowed" and not self.log_allowed:
            return
        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "direction": direction,
            "method": flow.request.method,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "url": flow.request.url,
            "decision": decision,
            "reason": reason or "",
        }
        if source:
            entry["source"] = source
        if secrets_injected:
            entry["secrets_injected"] = secrets_injected
        if secrets_redacted:
            entry["secrets_redacted"] = secrets_redacted
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
        # Write directly to stderr so output appears regardless of
        # mitmproxy's termlog_verbosity / -v / --quiet settings.
        print(line, file=sys.stderr, flush=True)
        if self._audit_file:
            try:
                self._audit_file.write(line + "\n")
                self._audit_file.flush()
            except OSError:
                pass


addons = [Agentcage()]
