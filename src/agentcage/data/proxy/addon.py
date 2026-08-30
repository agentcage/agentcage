"""agentcage — mitmproxy traffic inspection with pluggable inspectors."""

import asyncio
import dataclasses
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

# Hard cap for the in-container audit log. The caged agent can reach the
# control endpoints (introspection is unauthenticated by design), and
# every request writes a record — without a cap that is an unbounded
# disk-fill vector against the egress container.
_AUDIT_CAP_BYTES = 16 * 1024 * 1024

from inspectors._chain import run_inspector_chain
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


class _RelaySecretsInspector:
    """Relay-channel view of the shared :class:`SecretsInspector`.

    Protocol relays (SMTP) keep blocking leaked secrets by default even
    though HTTP egress now defaults to ``flag`` — an email body is a
    deliberate, operator-invisible exfil channel. This wrapper delegates
    all detection to the live shared instance (so hot-reloaded config and
    config supplied via the ``inspectors:`` list are both honoured) and
    only rewrites a default ``flag`` verdict to ``block``. When the
    operator set ``action`` explicitly, their choice is passed through
    unchanged so it applies everywhere.
    """

    name = "secrets"

    def __init__(self, inner: SecretsInspector) -> None:
        self._inner = inner

    def _adjust(
        self, result: Optional[InspectionResult]
    ) -> Optional[InspectionResult]:
        if result is None or self._inner.action_explicit:
            return result
        return dataclasses.replace(result, action="block")

    def inspect_request(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        return self._adjust(self._inner.inspect_request(ctx))

    def inspect_response(
        self, ctx: InspectionContext
    ) -> Optional[InspectionResult]:
        return self._adjust(self._inner.inspect_response(ctx))


# ── Orchestrator ─────────────────────────────────────────


class Agentcage:
    """mitmproxy addon that delegates inspection to a chain of inspectors."""

    def load(self, loader) -> None:
        with open(CONFIG_PATH) as f:
            self.cfg = yaml.safe_load(f) or {}
        self._config_mtime = os.stat(CONFIG_PATH).st_mtime
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

        # domains.auto — opt-in auto-managed allowlist (introspection + on-demand requests).
        # Constructed only when ``policy_api.enable`` is set in the proxy
        # config; absent → None → zero new surface (the control host is not
        # even resolved). See docs/explain/policy-api.md and
        # data/proxy/policy_api.py.
        self.domain_requests = None
        self._policy_sweeper: Optional[asyncio.Task] = None
        self._running = False
        self._init_domain_requests()

        # Audit log file — structured JSON lines for forensic analysis
        audit_path = os.environ.get(
            "AGENTCAGE_AUDIT_LOG", "/var/log/agentcage/audit.jsonl"
        )
        self._audit_file = None
        self._audit_capped = False
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

    def _init_domain_requests(self) -> None:
        """Build (or rebuild) the Policy API controller from the live config.

        Rebuild on hot-reload is safe: grants live in the ``DomainInspector``
        overlay + the persisted grants file, and ``PolicyApi`` replays the
        overlay on construction, so a rebuild never drops a live grant.

        Also owns the sweeper task lifecycle: a rebuild cancels the old
        task (it polls the OLD controller object) and starts a new one, so
        ENABLING domains.auto on a live cage actually starts the TTL
        sweeper and DISABLING it stops the stale one — without this, a
        hot-enabled feature would leave grants permanently unswept and
        host overlay changes unreconciled.
        """
        if self._policy_sweeper is not None:
            self._policy_sweeper.cancel()
            self._policy_sweeper = None
        pa_cfg = (self.cfg.get("domains") or {}).get("auto") or {}
        if not pa_cfg or not pa_cfg.get("enable"):
            self.domain_requests = None
            return
        dom = next((i for i in self.inspectors
                    if isinstance(i, DomainInspector)), None)
        if dom is None:
            ctx.log.warn(
                "agentcage: domains.auto enabled but no domain inspector "
                "loaded; control endpoints disabled"
            )
            self.domain_requests = None
            return
        try:
            from policy_api import PolicyApi
            self.domain_requests = PolicyApi(
                self.cfg, dom, self._audit_write, ctx.log
            )
            ctx.log.info(
                f"agentcage: domains.auto enabled (host={self.domain_requests.host}, "
                f"introspection={self.domain_requests.introspection_enabled}, "
                f"request={self.domain_requests.request_enabled})"
            )
        except Exception as e:
            ctx.log.warn(f"agentcage: domains.auto init failed: {e}")
            self.domain_requests = None
            return
        # Start the sweeper immediately when the proxy is already running
        # (hot-reload path); at load time running() starts it once the loop
        # is live.
        if self._running:
            self._start_policy_sweeper()

    def running(self) -> None:
        """Called after the proxy is fully started — apply TLS passthrough
        and start any non-HTTP protocol relay listeners."""
        self._running = True
        self._apply_passthrough()
        self._start_protocol_relays()
        self._start_policy_sweeper()

    def _start_policy_sweeper(self) -> None:
        """Start the Policy API grant-TTL sweeper as an asyncio task."""
        if self.domain_requests is None:
            return
        try:
            self._policy_sweeper = asyncio.get_event_loop().create_task(
                self.domain_requests.sweeper_loop()
            )
        except RuntimeError:
            # No running loop (e.g. some test contexts) — sweeper is
            # best-effort; expiry is also reconciled on overlay reload.
            self._policy_sweeper = None

    async def done(self) -> None:
        """Drain protocol relays cleanly on shutdown.

        ``ImapRelay.stop()`` cancels in-flight client sessions so long-
        lived IDLE connections receive a ``* BYE`` close instead of a
        TCP reset. Without this hook the careful shutdown logic in the
        relay is never invoked; mitmproxy just tears down the loop.
        """
        self._running = False
        relays = list(getattr(self, "_relays", []) or [])
        if relays:
            await asyncio.gather(
                *[r.stop() for r in relays], return_exceptions=True
            )
        if getattr(self, "_policy_sweeper", None) is not None:
            self._policy_sweeper.cancel()
            try:
                await self._policy_sweeper
            except asyncio.CancelledError:
                pass

    def _audit_write(self, entry: dict) -> None:
        """Write a structured JSON line to the audit pipeline.

        Same sink as ``_log()``: stderr (always) and ``audit.jsonl``
        (when configured). Used by protocol relays so per-decision
        records land in the same place HTTP decisions do.

        Hard-capped at ``_AUDIT_CAP_BYTES`` (16 MB): the caged agent can
        reach the control endpoints (introspection is unauthenticated and
        un-rate-limited by design), and every call writes an audit record
        — without a cap that is an unbounded disk-fill vector against
        the egress container. Past the cap, records still go to stderr
        (journald's own rotation applies) but the file is left alone; the
        operator can rotate or truncate it.
        """
        if "ts" not in entry:
            entry["ts"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(entry)
        print(line, file=sys.stderr, flush=True)
        if self._audit_file:
            try:
                if not self._audit_capped:
                    import os as _os
                    try:
                        if self._audit_file.tell() > _AUDIT_CAP_BYTES:
                            self._audit_capped = True
                            ctx.log.warn(
                                "agentcage: audit log at cap "
                                f"({_AUDIT_CAP_BYTES} bytes); file writes "
                                "suspended (stderr only) — rotate the file "
                                "to resume"
                            )
                    except OSError:
                        pass
                if not self._audit_capped:
                    self._audit_file.write(line + "\n")
                    self._audit_file.flush()
            except OSError:
                pass

    def _start_protocol_relays(self) -> None:
        """Boot ``protocol_relays`` listeners (IMAP, etc.) on the same
        asyncio loop mitmproxy is using. Relays are housed in this
        process — same systemd-creds mount, same audit pipeline — to
        avoid expanding the trust boundary across more containers.
        """
        relay_cfg = self.cfg.get("protocol_relays") or []
        if not relay_cfg:
            return

        from relays import get as _get_relay
        from relays._validate import validate_relay_entry

        relay_inspectors = self._build_relay_inspectors()

        self._relays: list = []
        loop = asyncio.get_event_loop()
        for entry in relay_cfg:
            rname = entry.get("name", "?") if isinstance(entry, dict) else "?"
            try:
                validate_relay_entry(entry)
            except ValueError as e:
                ctx.log.warn(f"agentcage: relay {rname} invalid config: {e}")
                self._audit_write({
                    "kind": "relay_config_invalid",
                    "relay": rname,
                    "error": str(e),
                })
                continue
            rtype = entry["type"]
            try:
                cls = _get_relay(rtype)
            except KeyError as e:
                ctx.log.warn(f"agentcage: unknown protocol_relays type: {e}")
                continue
            try:
                relay = cls(
                    entry,
                    audit_log=self._audit_write,
                    log_allowed=self.log_allowed,
                    inspectors=relay_inspectors,
                )
            except Exception as e:
                ctx.log.warn(
                    f"agentcage: relay {rname} init failed: {e}"
                )
                self._audit_write({
                    "kind": "relay_init_failed",
                    "relay": rname,
                    "error": str(e),
                })
                continue
            try:
                task = loop.create_task(relay.start())
            except Exception as e:
                ctx.log.warn(
                    f"agentcage: relay {rname} start scheduling failed: {e}"
                )
                self._audit_write({
                    "kind": "relay_start_failed",
                    "relay": rname,
                    "error": str(e),
                })
                continue
            task.add_done_callback(
                lambda t, name=rname: self._on_relay_start_done(t, name)
            )
            self._relays.append(relay)
            ctx.log.info(
                f"agentcage: scheduled relay {entry.get('name')} "
                f"({rtype})"
            )

    def _build_relay_inspectors(self) -> list:
        """Build the inspector chain handed to protocol relays.

        Two relay-specific adjustments to the shared HTTP chain:

        * The ``DomainInspector`` is HTTP-host shaped (matches against URL
          host) and doesn't translate to protocol-relay traffic; the
          equivalent gate for SMTP is the ``recipient_allowlist`` policy.
          It's stripped so SMTP DATA inspection doesn't try to enforce
          HTTP-style domain rules on email recipients.

        * The ``secrets`` inspector defaults to **block** for relays even
          though HTTP egress now defaults to ``flag``. An email body is a
          deliberate, operator-invisible exfil channel, so a leaked secret
          there should be stopped rather than merely logged. An explicit
          ``secrets.action`` in config still wins and applies everywhere.

        The secrets adjustment is a thin wrapper that *delegates* to the
        shared instance rather than a separate copy, so live config edits
        (``allow_to_domains``, ``extra_patterns``, ``enabled``, ...) keep
        flowing into the relay path on hot-reload, and config supplied via
        the ``inspectors:`` list is honoured the same as the top-level
        ``secrets:`` block.
        """
        out: list = []
        for i in getattr(self, "inspectors", []) or []:
            if isinstance(i, DomainInspector):
                continue
            if isinstance(i, SecretsInspector):
                out.append(_RelaySecretsInspector(i))
            else:
                out.append(i)
        return out

    def _on_relay_start_done(self, task: "asyncio.Task", name: str) -> None:
        """Surface ``relay.start()`` exceptions instead of letting Python
        raise ``Task exception was never retrieved`` at GC time."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        ctx.log.error(f"agentcage: relay {name} start failed: {exc}")
        self._audit_write({
            "kind": "relay_start_failed",
            "relay": name,
            "error": str(exc),
        })

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

        # entropy — opt-in. Enable via top-level `entropy: {...}` (dict, may be
        # empty for defaults) or by adding `- name: entropy` to `inspectors:`.
        # `entropy: false` continues to be a no-op (legacy disable).
        entropy_cfg = self.cfg.get("entropy")
        if isinstance(entropy_cfg, dict):
            out["entropy"] = entropy_cfg

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

    # ── TLS passthrough ────────────────────────────────────

    def _apply_passthrough(self) -> None:
        """Set mitmproxy ignore_hosts from the passthrough config."""
        passthrough = (self.cfg.get("domains") or {}).get("passthrough") or []
        if passthrough:
            import re as _re
            parts = []
            for domain in passthrough:
                escaped = _re.escape(domain)
                parts.append(f"^(.+\\.)?{escaped}(:\\d+)?$")
            regex = "|".join(parts)
            ctx.options.update(ignore_hosts=[regex])
            ctx.log.info(f"agentcage: TLS passthrough for {passthrough}")
        else:
            ctx.options.update(ignore_hosts=[])

    # ── Hot-reload ────────────────────────────────────────

    def _maybe_reload(self) -> None:
        """Re-read config if the file has been modified since last load."""
        try:
            mtime = os.stat(CONFIG_PATH).st_mtime
        except OSError:
            return
        if mtime == self._config_mtime:
            return
        try:
            with open(CONFIG_PATH) as f:
                new_cfg = yaml.safe_load(f) or {}
        except Exception as e:
            ctx.log.warn(f"agentcage: config reload failed, keeping old config: {e}")
            return
        self.cfg = new_cfg

        # Reconfigure built-in inspectors in-place
        legacy_map = self._build_legacy_config()
        for inspector in self.inspectors:
            if inspector.name in legacy_map and legacy_map[inspector.name] is not None:
                inspector.configure(legacy_map[inspector.name])

        # Reconfigure the secret injector too — it is NOT part of the
        # inspector chain (inspectors must see placeholders, injection
        # happens after them), so the loop above never reaches it. Without
        # this, rules declared after start never load and `secret set`'s
        # re-staged values are never re-read: configure() re-reads the
        # staged value files, which is the entire live-update mechanism.
        # An empty/removed secret_injection section clears the rules.
        self.injector.configure(self.cfg.get("secret_injection") or [])

        # Update rate-limit settings
        rl_cfg = self.cfg.get("rate_limit") or {}
        self._rl_rate = float(rl_cfg.get("requests_per_second", 10))
        self._rl_burst = int(rl_cfg.get("burst", 50))

        # Update logging settings
        logging_cfg = self.cfg.get("logging") or {}
        if "allowed_requests" in logging_cfg:
            self.log_allowed = bool(logging_cfg["allowed_requests"])
        else:
            self.log_allowed = bool(self.cfg.get("log_allowed", True))

        # Update TLS passthrough (--ignore-hosts)
        self._apply_passthrough()

        # Rebuild the Policy API (domains.auto) controller: enabling /
        # disabling auto, or changing the decider/host/rate-limit, must take
        # effect on live config edit, not only on egress restart. Idempotent
        # and safe to call every reload (its docstring says so) — it no-ops
        # when disabled and re-reads the api_key from the re-staged secret.
        self._init_domain_requests()

        self._config_mtime = mtime
        names = [i.name for i in self.inspectors]
        ctx.log.info(f"agentcage: config reloaded, inspectors={names}")

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

    async def request(self, flow: http.HTTPFlow) -> None:
        self._maybe_reload()

        # Reverse proxy flows are inbound traffic (host → cage via proxy).
        # Detect early so we can guard the transparent-mode host rewrite AND
        # gate the control-host short-circuit below on the egress path only.
        is_reverse = isinstance(
            getattr(flow.client_conn, "proxy_mode", None), ReverseMode
        )
        direction = "inbound" if is_reverse else "outbound"

        # ── Policy API control host (egress path only) ───────────
        # Short-circuit BEFORE the SNI/Host strict check, rate limiter,
        # secret-injection policy, and the inspector chain. The control
        # host is a synthetic local endpoint (never forwarded upstream), so
        # none of those gates apply. Matching requires both SNI and Host to
        # equal the control host for TLS flows (a mismatch falls through to
        # the SNI check below, which rejects it). See docs/explain/policy-api.md.
        #
        # The control host must be unreachable on inbound reverse flows
        # because Host/SNI are client-controlled there: a cage with
        # published inbound ports (container.ports, wired as mitmproxy
        # reverse listeners) forwards client traffic with the client's Host
        # preserved, so ANY client that can reach a published port could
        # call the unauthenticated control plane (GET /v1/allowlist,
        # POST /v1/allowlist/requests). The design reserves the control
        # host for the caged agent on the EGRESS path only, so gate the
        # short-circuit on the flow NOT being a reverse-mode (inbound) flow.
        pa = getattr(self, "domain_requests", None)
        if pa is not None and pa.enabled and not is_reverse:
            sni = getattr(getattr(flow, "client_conn", None), "sni", None)
            if isinstance(sni, bytes):
                try:
                    sni = sni.decode("idna")
                except UnicodeError:
                    sni = sni.decode("utf-8", "replace")
            if pa.is_control_host(sni, flow.request.host_header):
                await pa.handle(flow)
                return

        # In transparent mode, flow.request.host is the raw destination IP
        # (from SO_ORIGINAL_DST).  Rewrite it to the actual hostname from the
        # Host header (HTTP) or TLS SNI (HTTPS) so domain filtering, logging,
        # and secret injection all see the real hostname.
        # Skip for reverse proxy flows — the host is the configured upstream
        # and must not be overwritten with the client's Host header.
        if not is_reverse:
            # CTF F3 (0.22.6, HIGH): strict SNI ↔ Host header match.
            # The rewrite below makes the proxy FOLLOW the Host header
            # for the upstream connection. If the cage opened TLS with
            # SNI=A and then sent an HTTP `Host: B` inside that TLS,
            # the upstream connection would go to B while every
            # forensic identifier downstream (audit logs, allowlist
            # decisions, secret_injection rule selection) was keyed
            # on either A or B — never both. The attacker controls
            # which one is queried at each decision point. Closing
            # this requires enforcing equality before any host rewrite.
            #
            # HTTP requests (no SNI) are exempt: the Host header is
            # the only authority available, and the destination IP is
            # already trusted to come from the cage's allowlisted
            # resolver (or, in transparent mode, from SO_ORIGINAL_DST
            # which mitmproxy preserves into flow.request.host).
            sni = getattr(getattr(flow, "client_conn", None), "sni", None)
            if isinstance(sni, bytes):
                try:
                    sni = sni.decode("idna")
                except UnicodeError:
                    sni = sni.decode("utf-8", "replace")
            host_hdr = flow.request.host_header
            if isinstance(sni, str) and sni and host_hdr:
                # Strip optional port from the Host header before
                # comparing; SNI is host-only by spec.
                hh_host = host_hdr.rsplit(":", 1)[0] if ":" in host_hdr else host_hdr
                sni_norm = sni.lower().rstrip(".")
                hh_norm = hh_host.lower().rstrip(".")
                if sni_norm != hh_norm:
                    reason = (
                        f"SNI/Host header mismatch: TLS was established "
                        f"with SNI={sni!r} but HTTP Host header is "
                        f"{host_hdr!r}; agentcage requires strict equality "
                        f"so audit identity, allowlist decisions, and "
                        f"secret-injection routing all reference the same "
                        f"upstream"
                    )
                    flow.response = http.Response.make(
                        403,
                        json.dumps(
                            {"blocked": True, "reason": reason,
                             "host": host_hdr, "by": "agentcage"}
                        ).encode(),
                        {"Content-Type": "application/json"},
                    )
                    flow.metadata["agentcage_blocked"] = True
                    self._log(
                        flow, "blocked",
                        "sni-host mismatch", [],
                    )
                    return

            pretty = flow.request.pretty_host
            if pretty != flow.request.host:
                flow.request.host = pretty

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
            proto = "https" if flow.client_conn.tls_established else "http"
            flow.request.headers["x-forwarded-proto"] = proto

            # Rewrite Origin to match the (now-preserved) Host header so
            # origin-checking middleware doesn't see a mismatch.
            host_hdr = flow.request.host_header or f"{flow.request.host}:{flow.request.port}"
            if flow.request.headers.get("origin"):
                flow.request.headers["origin"] = f"{proto}://{host_hdr}"

        results.extend(await run_inspector_chain(
            self.inspectors,
            ctx_obj,
            method="request",
            skip=(
                lambda insp: is_reverse
                and isinstance(insp, DomainInspector)
            ),
        ))

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

    async def response(self, flow: http.HTTPFlow) -> None:
        # Control-host responses are synthesized by the addon; never run
        # response inspectors or secret redaction on them.
        if flow.metadata.get("agentcage_control"):
            return
        # Only run response inspectors if the request wasn't blocked
        if flow.metadata.get("agentcage_blocked"):
            self._cap_pending.pop(flow.id, None)
            return

        # ── REQUEST-side secret redaction (CRITICAL) ──────────
        # The upstream has already received the secret-substituted
        # request bytes (mitmproxy forwarded after the ``request`` hook
        # returned). Now we restore placeholder form on
        # ``flow.request.url`` / ``.headers`` / ``.content`` so the
        # capture serialization below — both the staged
        # ``pending["outbound_req"]`` snapshot from the ``request()``
        # hook AND any fresh snapshot taken here — does NOT write raw
        # secret bytes to ``capture.jsonl``. The capture file is
        # bind-mounted into the cage rootfs (mode 0644, world-readable)
        # so anything serialized post-inject is readable by the cage
        # workload — defeating the whole placeholder-injection trust
        # model. The redaction is purely cosmetic for downstream
        # serializers; the real request is already on the wire.
        self.injector.redact_request(flow)
        # Refresh the staged outbound-request snapshot with the redacted
        # form, overwriting the post-inject snapshot the ``request()``
        # hook stashed (which still held the raw secret bytes — that
        # snapshot was the leak point).
        if self._capture and flow.id in self._cap_pending:
            try:
                self._cap_pending[flow.id]["outbound_req"] = (
                    self._capture.snapshot_request(flow)
                )
            except Exception as e:  # pragma: no cover
                ctx.log.warn(
                    f"agentcage: outbound-request re-snapshot failed: {e}"
                )

        is_reverse = isinstance(
            getattr(flow.client_conn, "proxy_mode", None), ReverseMode
        )
        direction = "inbound" if is_reverse else "outbound"

        ctx_obj = self._build_context(flow, response=True)
        results: list[InspectionResult] = []

        results.extend(await run_inspector_chain(
            self.inspectors,
            ctx_obj,
            method="response",
        ))

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

    # ── Non-HTTP TCP bypass guard ────────────────────────
    #
    # Background: mitmproxy in transparent mode handles TCP/80 + TCP/443
    # via the iptables REDIRECT installed in ``proxy.container.j2``. For
    # bytes that look like HTTP, mitmproxy dispatches to ``HttpLayer`` and
    # the ``request``/``response``/``websocket_message`` hooks above
    # enforce policy. For everything else — raw bytes after the TCP
    # handshake, or TLS that does not carry HTTP inside — mitmproxy's
    # ``next_layer`` (with the default ``rawtcp=True``) falls back to
    # ``TCPLayer``, which simply BRIDGES bytes between the cage and the
    # original destination. NO request/response/websocket hook fires for
    # those flows, so the allowlist, inspector chain, and secret-injection
    # policy never run. A cage workload that opens a socket to (e.g.)
    # ``1.1.1.1:443`` and writes raw bytes can exfiltrate freely.
    #
    # We restore the L7 invariant by killing every TCP flow that reaches
    # this hook. ``HttpLayer``-handled flows never produce a ``TCPFlow``,
    # so this hook only fires for the bypass path. Killing here uses two
    # belts:
    #
    #   1. ``flow.server_conn.error = ...`` — checked by mitmproxy's
    #      ``open_connection`` (see ``proxy/server.py``) after the
    #      ``server_connect`` hook. The upstream TCP connection is never
    #      opened, so no bytes leave the cage.
    #   2. ``flow.kill()`` — sets ``flow.live = False`` and ``flow.error``
    #      so downstream addons and the audit pipeline see the canonical
    #      killed state.
    #
    # Audit entries land in the same ``audit.jsonl`` as HTTP decisions
    # (kind=tcp_bypass_blocked, decision=blocked) so existing forensic
    # tooling shows the kill.
    #
    # Protocol relays (IMAP/SMTP) listen on cage-author-chosen loopback
    # ports inside this same mitmproxy process. The cage reaches them via
    # 127.0.0.1; those sockets are served by the relay's own asyncio
    # accept loop and never pass through mitmproxy's transparent
    # intercept (the iptables REDIRECT only rewrites tcp/80 and the
    # configured ``inspected_tcp_ports``, not loopback). So this hook
    # firing always means a non-HTTP cage egress on an intercepted port.

    def _tcp_flow_target(self, flow) -> str:
        """Best-effort dest descriptor for a non-HTTP TCP bypass.

        Picks the most-trustworthy identifier available:
          * TLS SNI (``flow.client_conn.sni``) — the cage chose it but
            we mint a forged cert against it, so it commits the cage to
            this name.
          * ``flow.server_conn.peername`` — the actual peer IP after
            connect (rarely populated under ``connection_strategy=lazy``).
          * ``flow.server_conn.address`` — the SO_ORIGINAL_DST address
            iptables preserved (the cage's TCP destination IP:port).

        Returns a printable ``host:port`` style string for audit logs.
        Never raises — defensive against MagicMock-typed attrs in tests.
        """
        sni = getattr(getattr(flow, "client_conn", None), "sni", None)
        if isinstance(sni, bytes):
            try:
                sni = sni.decode("idna")
            except UnicodeError:
                sni = sni.decode("utf-8", "replace")
        if isinstance(sni, str) and sni:
            return sni
        server = getattr(flow, "server_conn", None)
        for attr in ("peername", "address"):
            value = getattr(server, attr, None)
            if isinstance(value, tuple) and value:
                host = value[0]
                port = value[1] if len(value) > 1 else None
                if isinstance(host, str) and host:
                    return f"{host}:{port}" if port is not None else host
        return "<unknown>"

    def tcp_start(self, flow) -> None:
        """Block raw TCP / non-HTTP flows that bypass the L7 hooks.

        See the section comment above for why this is a security fix.
        """
        target = self._tcp_flow_target(flow)
        reason = (
            f"non-http TCP bypass: cage opened a raw TCP/TLS flow to "
            f"{target} that does not speak HTTP; the L7 allowlist, "
            f"inspectors, and secret-injection policy do not apply to "
            f"raw byte streams"
        )
        # Belt 1: refuse the upstream connect. ``open_connection`` in
        # mitmproxy/proxy/server.py reads ``command.connection.error``
        # after the ``server_connect`` hook and aborts before opening a
        # socket; ``tcp_start`` fires BEFORE ``OpenConnection`` is
        # yielded by ``TCPLayer.start`` (with ``connection_strategy=
        # lazy``), so setting it here wins the race.
        server = getattr(flow, "server_conn", None)
        if server is not None:
            try:
                server.error = reason
            except Exception:
                # Defensive: in tests the server_conn may be a MagicMock
                # whose attribute assignment can be intercepted. Setting
                # it is best-effort — flow.kill() below is the
                # always-available backstop.
                pass
        # Belt 2: canonical killed state for any downstream addons.
        try:
            if getattr(flow, "killable", True):
                flow.kill()
        except Exception:
            pass

        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": "tcp_bypass_blocked",
            "direction": "outbound",
            "decision": "blocked",
            "reason": reason,
            "host": target,
        }
        # Match the regular _log() audit sink: stderr + audit.jsonl.
        line = json.dumps(entry)
        print(line, file=sys.stderr, flush=True)
        if self._audit_file:
            try:
                self._audit_file.write(line + "\n")
                self._audit_file.flush()
            except OSError:
                pass

    async def websocket_message(self, flow: http.HTTPFlow) -> None:
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

            results.extend(await run_inspector_chain(
                self.inspectors,
                ws_ctx,
                method="request",
                skip=(
                    lambda insp: is_reverse
                    and isinstance(insp, DomainInspector)
                ),
            ))

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
            results.extend(await run_inspector_chain(
                self.inspectors,
                ws_ctx,
                method="response",
                skip=(
                    lambda insp: is_reverse
                    and isinstance(insp, DomainInspector)
                ),
            ))

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
