"""agentcage — mitmproxy traffic inspection with pluggable inspectors."""

import asyncio
import copy
import dataclasses
import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, NamedTuple, Optional

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

# Capacity of the per-host rate-limit table (see _check_rate_limit). The
# limiter runs before the allowlist, so every distinct Host a cage sends —
# plain HTTP lets it pick any — would otherwise add an entry for the life
# of the process.
_RL_MAX_HOSTS = 4096

# How often the background task checks the config file for an edit (see
# _config_reload_loop). One stat() per tick; a proxied request also checks
# before it is handled, so this only sets the latency for a cage with no
# HTTP traffic (relay-only, or idle).
_CONFIG_POLL_SECONDS = 1.0


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


class _RunningRelay(NamedTuple):
    """A started protocol relay and what it was built from.

    ``_sync_protocol_relays`` keeps the relay across a reload only while
    both still match: ``entry`` (a copy of its ``protocol_relays`` entry)
    and ``credentials`` (see ``_relay_credentials_digest``).
    """

    entry: dict
    credentials: str
    relay: Any


def _log_allowed(cfg: dict) -> bool:
    """Whether allowed requests reach the durable log (HTTP and relays).

    ``logging.allowed_requests`` wins whenever it is present, even as
    ``false``; the legacy top-level ``log_allowed`` is the fallback only
    when it is absent; and with neither the answer is **off** — the
    host's documented default (``docs/reference/configuration.md``) and
    the value it validates against. This used to fall back to on, so an
    operator who never wrote a ``logging`` block got every allowed
    request and relay command in the log. Pinned to the host by
    ``tests/fixtures/contracts/logging_defaults.json``.
    """
    logging_cfg = cfg.get("logging") or {}
    if "allowed_requests" in logging_cfg:
        return bool(logging_cfg["allowed_requests"])
    return bool(cfg.get("log_allowed", False))


def _relay_credentials_digest(entry: dict) -> str:
    """SHA-256 over the values a relay's ``auth.*_source`` resolve to now.

    Lets a reload notice a rotated credential without keeping another
    plaintext copy of it. Resolved through the same lookup the relays
    use (staged file, then ``$XDG_RUNTIME_DIR``, then env); a source
    that does not resolve contributes "" (the relay itself refuses it).
    """
    from secret_lookup import resolve_credential

    auth = entry.get("auth")
    if not isinstance(auth, dict):
        auth = {}
    values = []
    for key in ("user_source", "password_source"):
        try:
            values.append(resolve_credential(str(auth.get(key) or "")))
        except ValueError:
            values.append("")
    return hashlib.sha256("\0".join(values).encode()).hexdigest()


# ── Orchestrator ─────────────────────────────────────────


class Agentcage:
    """mitmproxy addon that delegates inspection to a chain of inspectors."""

    def load(self, loader) -> None:
        with open(CONFIG_PATH) as f:
            self.cfg = yaml.safe_load(f) or {}
        self._config_mtime = os.stat(CONFIG_PATH).st_mtime
        self.log_allowed = _log_allowed(self.cfg)
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
        # {host: [tokens, last_time]}, least recently used first; bounded
        # at _RL_MAX_HOSTS by _check_rate_limit.
        self._rl_buckets: OrderedDict[str, list] = OrderedDict()

        self._load_builtin_inspectors()
        self._load_custom_inspectors()

        # agents.decider — opt-in auto-managed allowlist (introspection + on-demand requests).
        # Constructed only when ``policy_api.enable`` is set in the proxy
        # config; absent → None → zero new surface (the control host is not
        # even resolved). See docs/explain/policy-api.md and
        # data/proxy/policy_api.py.
        self.domain_requests = None
        self._policy_sweeper: Optional[asyncio.Task] = None
        # Traffic watcher — opt-in in-egress LLM traffic auditor
        # (data/proxy/watcher.py). Same construction pattern as
        # absent ``agents.watcher.enable`` → self.traffic_watcher
        # stays None → module not even imported → zero new surface.
        # The ring is the watcher's fresh-audit source: every audit entry
        # funnels through _audit_write, so the watcher gets a copy
        # appended here when it is enabled.
        self.traffic_watcher = None
        self._watcher_task: Optional[asyncio.Task] = None
        self._watcher_ring = None  # created with the watcher itself
        # Peer-address guard state (see server_connect). The cache is
        # keyed by granted host; the poisoned set records hosts caught
        # rebinding so the L7 gate refuses them on the next request.
        self._peer_dns_cache: dict = {}
        self._poisoned_peers: set = set()
        self._running = False
        # Config hot-reload: the background poll task (running() → done())
        # and the single-flight guard shared with the per-request check.
        self._reload_task: Optional[asyncio.Task] = None
        self._reloading = False
        self._init_domain_requests()
        self._init_watcher()

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

        # Per-flow capture staging — stores partial snapshots between hooks
        self._cap_pending: dict[str, dict] = {}

        # Capture JSONL — full request/response bodies for HAR export
        self._capture = None
        self._capture_cfg: Optional[dict] = None
        self._init_capture()

        # Protocol relays — started in running(), re-synced on reload.
        # ``_relays_by_name`` maps each relay name to its _RunningRelay
        # (the relay and what it was built from); ``_relays`` is the same
        # relays as a list, which done() drains.
        self._relays: list = []
        self._relays_by_name: dict[str, _RunningRelay] = {}
        self._relay_apply_task: Optional[asyncio.Task] = None

        names = [i.name for i in self.inspectors]
        ctx.log.info(
            f"agentcage loaded: inspectors={names}, "
            f"injection_rules={len(self.injector.rules)}"
        )

    def _init_domain_requests(self) -> None:
        """Build, reconfigure or drop the Policy API controller.

        Runs at load and on every config hot-reload. While the decider
        stays enabled the live ``PolicyApi`` is reconfigured IN PLACE, not
        rebuilt: a rebuild refilled its token bucket, so every reload
        (each ``secret set`` / ``domain add`` touches the config) handed the
        cage a fresh burst of LLM-decider calls, and it cancelled and
        restarted the sweeper for nothing. A new instance is built only on
        disabled → enabled (grants survive that too: they live in the
        ``DomainInspector`` overlay + the persisted grants file, which the
        constructor replays); enabled → disabled drops it.

        Also owns the sweeper task lifecycle: enabling agents.decider on a
        live cage starts the TTL sweeper and disabling it stops it —
        without this, a hot-enabled feature would leave grants permanently
        unswept and host overlay changes unreconciled.
        """
        pa_cfg = (self.cfg.get("agents") or {}).get("decider") or {}
        if not isinstance(pa_cfg, dict) or not pa_cfg.get("enable"):
            self._drop_domain_requests()
            return
        dom = next((i for i in self.inspectors
                    if isinstance(i, DomainInspector)), None)
        if dom is None:
            ctx.log.warn(
                "agentcage: agents.decider enabled but no domain inspector "
                "loaded; control endpoints disabled"
            )
            self._drop_domain_requests()
            return
        if self.domain_requests is not None:
            try:
                self.domain_requests.reconfigure(self.cfg, dom)
            except Exception as e:
                # Same outcome as a failed init: a malformed block disables
                # the control endpoints until the next good reload.
                ctx.log.warn(f"agentcage: agents.decider reconfigure failed: {e}")
                self._drop_domain_requests()
                return
        else:
            try:
                from policy_api import PolicyApi
                self.domain_requests = PolicyApi(
                    self.cfg, dom, self._audit_write, ctx.log
                )
                ctx.log.info(
                    f"agentcage: agents.decider enabled (host={self.domain_requests.host}, "
                    f"introspection={self.domain_requests.introspection_enabled}, "
                    f"request={self.domain_requests.request_enabled})"
                )
            except Exception as e:
                ctx.log.warn(f"agentcage: agents.decider init failed: {e}")
                self.domain_requests = None
                return
        # Start the sweeper when the proxy is already running (hot-reload
        # path) and none is live — on enable, or if an earlier start found
        # no loop. A live sweeper polls the reconfigured instance, so it is
        # left alone. At load time running() starts it once the loop is up.
        if self._running and (self._policy_sweeper is None
                              or self._policy_sweeper.done()):
            self._start_policy_sweeper()

    def _drop_domain_requests(self) -> None:
        """Tear down the Policy API controller and its sweeper task."""
        if self._policy_sweeper is not None:
            self._policy_sweeper.cancel()
            self._policy_sweeper = None
        self.domain_requests = None

    def running(self) -> None:
        """Called after the proxy is fully started — apply TLS passthrough
        and start any non-HTTP protocol relay listeners."""
        self._running = True
        self._apply_passthrough()
        self._sync_protocol_relays()
        self._start_policy_sweeper()
        self._start_watcher_task()
        self._start_reload_task()

    def _start_reload_task(self) -> None:
        """Start the config-file poll (_config_reload_loop) as a task."""
        try:
            self._reload_task = asyncio.get_event_loop().create_task(
                self._config_reload_loop()
            )
        except RuntimeError:
            # No running loop (test contexts) — best-effort, same as the
            # policy sweeper; requests still check before they are handled.
            self._reload_task = None

    async def _config_reload_loop(self) -> None:
        """Check the config file for an edit every _CONFIG_POLL_SECONDS.

        ``request()`` checks too, but only a proxied HTTP request reaches
        it: a cage that only talks through protocol relays, or is idle,
        would otherwise never apply a relay change, a Policy API or
        watcher reconfiguration, a re-staged secret or a passthrough edit.
        Each tick is one stat() unless the file moved. A failing tick is
        logged by _reload_check and the loop carries on.
        """
        while True:
            await asyncio.sleep(_CONFIG_POLL_SECONDS)
            self._reload_check()

    def _reload_check(self) -> None:
        """Apply a config edit if there is one; never raises.

        The one entry point for both triggers, the poll task and
        ``request()``. Single-flight: ``_maybe_reload`` is synchronous and
        never awaits, so on the event loop one check always runs to the
        end before the other starts, and the second finds the mtime
        already recorded and does nothing. ``_reloading`` makes that
        explicit, and turns a check re-entered from inside a reload into
        a no-op rather than a nested reload.

        A failure is logged, not raised: raised from the poll task it
        would end the task (no more live edits), and raised from
        ``request()`` it would abort the hook before the inspector chain
        ran, letting that request through uninspected. ``_maybe_reload``
        records the file's mtime before applying it, so a version that
        fails part-way is not retried every second; the next edit is.
        """
        # getattr: test contexts build the addon without load().
        if getattr(self, "_reloading", False):
            return
        self._reloading = True
        try:
            self._maybe_reload()
        except Exception as e:
            ctx.log.error(
                f"agentcage: config reload failed part-way: {e!r}; "
                "the next config change retries"
            )
        finally:
            self._reloading = False

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

    def _init_watcher(self) -> None:
        """Build (or rebuild) the traffic watcher from the live config.

        Mirrors ``_init_domain_requests`` (it is the pattern the
        egress-local DNS-apply rework established for in-egress loops),
        with two watcher-specific refinements the reviewers of the
        feature demanded:

        * NO-OP WHEN UNCHANGED: every proxy-config reload lands here
          (an unrelated ``logging.level`` edit included), and a rebuild
          would discard the watcher's scan state (capture offset, scan
          counters) and re-analyze the same window — duplicating LLM
          cost and findings. When the ``watcher`` block is identical to
          the one the live watcher was built from, keep it — the ring
          survives a rebuild by design, but the cursors don't.
        * CONSTRUCT BEFORE CANCEL: the replacement is built (and its
          config parsed) BEFORE the old task is cancelled, so a
          malformed hot-reload keeps the last working watcher running
          instead of stopping monitoring on a bad edit.
        """
        w_cfg = ((self.cfg.get("agents") or {}).get("watcher")) or {}
        if not isinstance(w_cfg, dict):
            if w_cfg:
                ctx.log.warn(
                    "agentcage: watcher config is not a mapping "
                    f"(got {type(w_cfg).__name__}) — watcher disabled")
            w_cfg = {}
        if self.traffic_watcher is not None \
                and self.traffic_watcher.cfg == w_cfg:
            # Unchanged watcher block: keep the loop + scan state, but
            # still re-point the mutable refs. ``agents.decider`` is
            # reconfigured in place on most reloads, but toggling it
            # builds or drops the PolicyApi (_init_domain_requests above),
            # so an unrefreshed ``_pa`` would keep revoking through a
            # discarded, sweeper-cancelled instance (or miss a new one);
            # ``secret set`` re-stages the key file without changing the
            # config value that names it, so the key needs a re-read too.
            self.traffic_watcher.refresh_runtime_refs(
                self._watcher_domain_inspector(), self.domain_requests)
            return
        if not w_cfg.get("enable"):
            self._cancel_watcher_task()
            self.traffic_watcher = None
            self._watcher_ring = None
            return
        try:
            from watcher import RING_MAX, Watcher
            # The audit ring: bounded, created here so it survives watcher
            # rebuilds (a hot-reload of interval/model must not drop the
            # fresh-traffic history the old watcher was holding).
            if self._watcher_ring is None:
                from collections import deque
                self._watcher_ring = deque(maxlen=RING_MAX)
            new_watcher = Watcher(
                self.cfg, self._watcher_domain_inspector(),
                self.domain_requests, self._audit_write, ctx.log,
                self._watcher_ring, CAPTURE_PATH,
            )
        except Exception as e:
            # The old watcher (if any) stays live and keeps scanning with
            # its previous config: a malformed hot-reload must not stop
            # monitoring.
            ctx.log.warn(f"agentcage: watcher init failed: {e}")
            return
        self._cancel_watcher_task()
        self.traffic_watcher = new_watcher
        ctx.log.info(
            f"agentcage: traffic watcher enabled "
            f"(interval={new_watcher._interval}s, "
            f"provider={new_watcher._provider})"
        )
        if self._running:
            self._start_watcher_task()

    def _cancel_watcher_task(self) -> None:
        """Cancel the watcher scan task (used by disable/rebuild/done)."""
        if self._watcher_task is not None:
            self._watcher_task.cancel()
            self._watcher_task = None

    def _watcher_domain_inspector(self):
        """The DomainInspector instance, or None when not loaded.

        The watcher uses it read-only for baseline/grant context and —
        only for revocations — through the PolicyApi's overlay machinery;
        a missing inspector just means the digest carries no domain
        lists and revocations find no grants.
        """
        return next((i for i in self.inspectors
                     if isinstance(i, DomainInspector)), None)

    def _start_watcher_task(self) -> None:
        """Start the watcher scan loop as an asyncio task."""
        if self.traffic_watcher is None:
            return
        try:
            self._watcher_task = asyncio.get_event_loop().create_task(
                self.traffic_watcher.watcher_loop()
            )
        except RuntimeError:
            # No running loop (test contexts) — best-effort, same as the
            # policy sweeper.
            self._watcher_task = None

    async def done(self) -> None:
        """Drain protocol relays cleanly on shutdown.

        ``ImapRelay.stop()`` cancels in-flight client sessions so long-
        lived IDLE connections receive a ``* BYE`` close instead of a
        TCP reset. Without this hook the careful shutdown logic in the
        relay is never invoked; mitmproxy just tears down the loop.

        A reload's stop/start task still in flight is awaited first:
        stopping a relay whose start() has not bound yet is a no-op, and
        the listener would then come up after shutdown.

        The config poll is cancelled before anything else, so no reload
        can schedule a relay start while the relays are being drained.
        """
        self._running = False
        reload_task = getattr(self, "_reload_task", None)
        if reload_task is not None:
            reload_task.cancel()
            try:
                await reload_task
            except asyncio.CancelledError:
                pass
            self._reload_task = None
        apply_task = getattr(self, "_relay_apply_task", None)
        if apply_task is not None and not apply_task.done():
            await asyncio.wait([apply_task])
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
        # The traffic watcher's scan loop rides the same lifecycle as
        # the policy sweeper: cancelled here on orderly shutdown, and
        # restarted/removed by _init_watcher on hot-reload.
        if getattr(self, "_watcher_task", None) is not None:
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except asyncio.CancelledError:
                pass
            self._watcher_task = None

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
        self._ring_ingest(entry)
        line = json.dumps(entry)
        print(line, file=sys.stderr, flush=True)
        # getattr throughout: test contexts construct the addon via
        # __new__ without load()'s attributes, and _log now funnels here
        # (it used to duplicate these sinks); a partially-constructed
        # instance must degrade to stderr-only, not raise.
        audit_file = getattr(self, "_audit_file", None)
        if audit_file:
            try:
                if not getattr(self, "_audit_capped", False):
                    import os as _os
                    try:
                        if audit_file.tell() > _AUDIT_CAP_BYTES:
                            self._audit_capped = True
                            ctx.log.warn(
                                "agentcage: audit log at cap "
                                f"({_AUDIT_CAP_BYTES} bytes); file writes "
                                "suspended (stderr only) — rotate the file "
                                "to resume"
                            )
                    except OSError:
                        pass
                if not getattr(self, "_audit_capped", False):
                    audit_file.write(line + "\n")
                    audit_file.flush()
            except OSError:
                pass

    def _sync_protocol_relays(self) -> None:
        """Make the running ``protocol_relays`` listeners (IMAP, SMTP)
        match the live config.

        Called from running() at boot and from _maybe_reload on every
        config change, on the asyncio loop mitmproxy is using. Relays
        are housed in this process — same systemd-creds mount, same
        audit pipeline — to avoid expanding the trust boundary across
        more containers.

        Entries are diffed against the running relays by ``name``:

        * identical entry, same credentials → the running relay is kept
          untouched, so its client sessions (a long IMAP IDLE, say)
          survive the reload;
        * changed entry, or credentials that now resolve to different
          values (``agentcage secret set`` re-stages the file and bumps
          the config mtime; a relay reads its credentials only when it
          is built) → the old relay is stopped and a new one built
          from the new entry. If the new entry fails validation or
          construction the old relay is still stopped: the running set
          is always what a fresh boot with this config would produce,
          minus the restarts the diff avoids;
        * removed entry → stopped;
        * new entry → validated, built and started exactly as at boot,
          with the same ``relay_config_invalid`` / ``relay_init_failed``
          / ``relay_start_failed`` audit records.

        A later entry reusing a name is ``relay_config_invalid`` and the
        first one wins: diffing by name needs unique names, and a
        duplicate would otherwise be a listener nothing tracks.

        Validation and construction happen here, synchronously, so the
        bookkeeping is settled before this returns and the next reload
        diffs against it. Stopping and starting are async and run as one
        task (_apply_relay_changes) that stops everything first and only
        then starts the replacements — a changed relay that keeps its
        listen port has released the socket before the new listener
        binds it. Each task waits for the previous one, so back-to-back
        reloads apply in order.
        """
        from relays import get as _get_relay
        from relays._validate import validate_relay_entry

        relay_cfg = self.cfg.get("protocol_relays") or []
        current: dict = getattr(self, "_relays_by_name", None) or {}
        # Built fresh on every sync — after _maybe_reload reconfigured the
        # inspectors — so a (re)started relay gets the current chain.
        # Kept relays hold the chain they were built with; it shares the
        # inspector instances, which reload reconfigures in place.
        relay_inspectors = self._build_relay_inspectors() if relay_cfg else []

        wanted: dict[str, _RunningRelay] = {}
        starts: list[tuple[str, object]] = []
        seen: set[str] = set()
        for entry in relay_cfg:
            rname = entry.get("name", "?") if isinstance(entry, dict) else "?"
            try:
                validate_relay_entry(entry)
                if rname in seen:
                    raise ValueError(f"duplicate relay name {rname!r}")
            except (ValueError, TypeError) as e:
                # TypeError: an unhashable ``name`` (the host rejects
                # one, but a reload must not crash on it).
                ctx.log.warn(f"agentcage: relay {rname} invalid config: {e}")
                self._audit_write({
                    "kind": "relay_config_invalid",
                    "relay": rname,
                    "error": str(e),
                })
                continue
            seen.add(rname)
            # Digested BEFORE the relay reads them: a value re-staged in
            # between leaves a stale digest, which only costs one extra
            # restart on the next reload — never a relay kept on old
            # credentials.
            creds = _relay_credentials_digest(entry)
            running = current.get(rname)
            if (running is not None and running.entry == entry
                    and running.credentials == creds):
                wanted[rname] = running
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
            # A copy: it is compared against the next reload's entry and
            # must not alias anything a relay could mutate.
            wanted[rname] = _RunningRelay(copy.deepcopy(entry), creds, relay)
            starts.append((rname, relay))
            ctx.log.info(f"agentcage: scheduled relay {rname} ({rtype})")

        stops = []
        for rname, running in current.items():
            kept = wanted.get(rname)
            if kept is None or kept.relay is not running.relay:
                ctx.log.info(f"agentcage: stopping relay {rname}")
                stops.append(running.relay)
        self._relays_by_name = wanted
        self._relays = [r.relay for r in wanted.values()]
        if not stops and not starts:
            return

        prev = getattr(self, "_relay_apply_task", None)
        coro = self._apply_relay_changes(prev, stops, starts)
        try:
            task = asyncio.get_event_loop().create_task(coro)
        except Exception as e:
            coro.close()
            for rname, relay in starts:
                ctx.log.warn(
                    f"agentcage: relay {rname} start scheduling failed: {e}"
                )
                self._relay_start_failed(rname, relay, e)
            return
        task.add_done_callback(self._on_relay_apply_done)
        self._relay_apply_task = task

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

    async def _apply_relay_changes(
        self,
        prev: Optional["asyncio.Task"],
        stops: list,
        starts: list,
    ) -> None:
        """Stop ``stops``, then start ``starts`` (see _sync_protocol_relays).

        Every stop is awaited before any start: ``stop()`` closes the
        listener and waits for it (and its cancelled sessions), which is
        what frees a reused listen port for the replacement. A start
        failure is audited and drops that relay from the running set; it
        never affects the other relays.
        """
        if prev is not None and not prev.done():
            # asyncio.wait, not await: it never raises, so a failed or
            # cancelled predecessor cannot abort this batch.
            await asyncio.wait([prev])
        if stops:
            await asyncio.gather(
                *[r.stop() for r in stops], return_exceptions=True
            )
        if not starts:
            return
        results = await asyncio.gather(
            *[r.start() for _name, r in starts], return_exceptions=True
        )
        for (rname, relay), result in zip(starts, results):
            if isinstance(result, BaseException):
                self._relay_start_failed(rname, relay, result)

    def _relay_start_failed(self, name: str, relay, exc: BaseException) -> None:
        """Audit a relay that could not start, and forget it.

        Dropping it from the running set means the next reload treats
        the entry as new and tries again, instead of calling it unchanged
        and leaving the name dead until a restart. Only that exact relay
        object is dropped: a later reload may already have replaced it.
        """
        ctx.log.error(f"agentcage: relay {name} start failed: {exc}")
        self._audit_write({
            "kind": "relay_start_failed",
            "relay": name,
            "error": str(exc),
        })
        by_name = getattr(self, "_relays_by_name", None) or {}
        running = by_name.get(name)
        if running is not None and running.relay is relay:
            del by_name[name]
            self._relays = [r.relay for r in by_name.values()]

    def _on_relay_apply_done(self, task: "asyncio.Task") -> None:
        """Surface an unexpected failure of the stop/start task instead
        of letting Python raise ``Task exception was never retrieved`` at
        GC time. Per-relay failures are handled inside the task."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            ctx.log.error(f"agentcage: relay reload failed: {exc}")

    # ── Capture ──────────────────────────────────────────

    def _init_capture(self) -> None:
        """Build (or rebuild) the capture writer from the live config.

        Called from load() and on every reload. A no-op when the
        ``capture`` section equals the one the current writer was built
        from, so an unrelated edit never reopens the file.

        * Disabled (``enable_har`` off, or ``AGENTCAGE_CAPTURE`` empty):
          the old writer is closed and the staged ``_cap_pending``
          entries are dropped — those flows are simply not captured, the
          same as any flow that starts after the edit.
        * Enabled or changed: the new writer is constructed BEFORE the
          old one is closed, so a bad edit (an unparsable limit, an
          unwritable path) logs a warning and keeps the working writer;
          the bad section is not recorded, so the next edit retries.
          Both writers append to the same file, so nothing is rotated or
          truncated by the swap. Staged ``_cap_pending`` entries are
          plain snapshots and are kept: those flows complete under the
          new writer, with its filters and limits applied to whatever is
          snapshotted from then on (request bodies already snapshotted
          keep the old truncation). That includes a WebSocket entry held
          open past its 101: its buffered frames move to the new writer,
          which writes the entry when the socket ends.
        """
        cap_cfg = self.cfg.get("capture") or {}
        if not isinstance(cap_cfg, dict):
            ctx.log.warn(
                "agentcage: capture config is not a mapping "
                f"(got {type(cap_cfg).__name__}) — capture disabled")
            cap_cfg = {}
        if cap_cfg == self._capture_cfg:
            return
        if not (cap_cfg.get("enable_har") and CAPTURE_PATH):
            if self._capture is not None:
                self._capture.close()
                ctx.log.info("agentcage: capture disabled")
            self._capture = None
            self._cap_pending.clear()
            self._capture_cfg = cap_cfg
            return
        try:
            from capture import CaptureWriter
            new_writer = CaptureWriter(cap_cfg, CAPTURE_PATH)
        except Exception as e:
            ctx.log.warn(f"agentcage: cannot init capture: {e}")
            return
        old = self._capture
        if old is not None:
            new_writer.adopt_ws_buffers(old)
            old.close()
        self._capture = new_writer
        self._capture_cfg = cap_cfg
        ctx.log.info(f"agentcage: capture enabled → {CAPTURE_PATH}")

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
                # Reconfigure-in-place when an inspector of this name is
                # already loaded (the hot-reload path calls this method on
                # every config change — appending again would run the
                # inspector twice per request). Matched by the entry's
                # declared name falling back to the loaded class's name on
                # the append below; the file itself is NOT re-imported on
                # reload — a changed implementation needs an egress restart.
                existing = next(
                    (i for i in self.inspectors
                     if name and i.name == name), None)
                if existing is not None:
                    existing.configure(cfg)
                    continue
                inspector = load_inspector_from_file(path)
                existing = next(
                    (i for i in self.inspectors
                     if i.name == inspector.name), None)
                if existing is not None:
                    existing.configure(cfg)
                    continue
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
        """Re-read config if the file has been modified since last load.

        Called through _reload_check (the poll task and ``request()``).
        """
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
            # Retried on every check, so a read that caught a write in
            # progress succeeds on the next one; but logged once per file
            # version, since the poll checks every second.
            if mtime != getattr(self, "_config_bad_mtime", None):
                self._config_bad_mtime = mtime
                ctx.log.warn(
                    f"agentcage: config reload failed, keeping old config: {e}")
            return
        self.cfg = new_cfg
        # Recorded before applying: a step that raises part-way leaves
        # this version applied up to that step, and retrying it every
        # second would only repeat the failure. The next edit retries.
        self._config_mtime = mtime

        # Reconfigure built-in inspectors in-place
        legacy_map = self._build_legacy_config()
        for inspector in self.inspectors:
            if inspector.name in legacy_map and legacy_map[inspector.name] is not None:
                inspector.configure(legacy_map[inspector.name])

        # Re-apply the explicit ``inspectors:`` section AFTER the legacy
        # map, mirroring the initial-load precedence (legacy first, the
        # explicit section wins). Without this, every hot reload silently
        # RESET any builtin configured only via ``inspectors:`` back to
        # legacy/default config — for a cage whose content-type exemptions
        # live in that section, the first ``domain add``/``domain rm`` or
        # agents.decider grant after egress start wiped
        # ``host_exempt_content_types`` in place and multipart uploads
        # started 403ing on body entropy (hit in production 2026-09-01:
        # ElevenLabs STT voice-note uploads). ``_load_custom_inspectors``
        # is reload-safe: it reconfigures in place and never appends a
        # duplicate. An entry REMOVED from the section keeps its last
        # config until restart — acceptable; removal is not a live-reload
        # operation for any other section either.
        self._load_custom_inspectors()

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
        self.log_allowed = _log_allowed(self.cfg)

        # Update TLS passthrough (--ignore-hosts)
        self._apply_passthrough()

        # Re-sync protocol relays (diffed by name: unchanged ones keep
        # running) and rebuild the capture writer if its section moved.
        # Relays only once running() has started them: before that there
        # is nothing to diff against, and running() reads the newest
        # config anyway.
        if getattr(self, "_running", False):
            self._sync_protocol_relays()
        self._init_capture()

        # Reconfigure the Policy API (agents.decider) controller in place:
        # enabling / disabling auto, or changing the decider/host/rate-limit,
        # must take effect on live config edit, not only on egress restart.
        # Safe to call every reload — it keeps the live instance (and its
        # rate-limit bucket), no-ops when disabled, and re-reads the api_key
        # from the re-staged secret.
        self._init_domain_requests()
        # Same for the traffic watcher: enabling/disabling it, or changing
        # its interval/model/key, takes effect on the live edit.
        self._init_watcher()

        names = [i.name for i in self.inspectors]
        ctx.log.info(f"agentcage: config reloaded, inspectors={names}")

    # ── Request handling ─────────────────────────────────

    def _check_rate_limit(self, host: str) -> bool:
        """Token-bucket rate limiter per host. Returns True if allowed.

        The bucket table is an LRU capped at ``_RL_MAX_HOSTS``: a new host
        past the cap evicts the least recently used one. Trade-off: an
        evicted host's bucket restarts full when it comes back, so a cage
        that churns through ``_RL_MAX_HOSTS`` other names can reset one
        host's bucket. Each reset costs it thousands of requests and buys
        back one burst: the limiter stays a throttle on runaway loops, not
        a hard ceiling against a cage set on evading it (it never was one —
        it is per host). Unbounded, the same churn could grow the table
        until the egress hit its memory limit.
        """
        if not self._rl_rate:
            return True
        now = time.monotonic()
        bucket = self._rl_buckets.get(host)
        if bucket is None:
            bucket = self._rl_buckets[host] = [self._rl_burst, now]
            while len(self._rl_buckets) > _RL_MAX_HOSTS:
                self._rl_buckets.popitem(last=False)
        else:
            self._rl_buckets.move_to_end(host)
        elapsed = now - bucket[1]
        bucket[1] = now
        bucket[0] = min(self._rl_burst, bucket[0] + elapsed * self._rl_rate)
        if bucket[0] >= 1:
            bucket[0] -= 1
            return True
        return False

    async def request(self, flow: http.HTTPFlow) -> None:
        # The poll task applies an edit within _CONFIG_POLL_SECONDS; this
        # check makes a request sent right after the edit see it too.
        self._reload_check()

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

        # ── Rebind backstop ──────────────────────────────────────
        # A granted host caught resolving to a non-global address in
        # server_connected (too late to stop THAT request — mitmproxy does
        # not re-read connection.error after connecting) is poisoned here,
        # so every subsequent request to it is refused at L7. The normal
        # path is server_connect, which aborts before any socket opens;
        # this only fires when the answer changed underneath us.
        # getattr: tests and hot-reload paths construct the addon without
        # running __init__, and this gate must never be the thing that
        # breaks the request path.
        _poisoned = getattr(self, "_poisoned_peers", None)
        if _poisoned:
            _pk = (flow.request.host or "").lower().rstrip(".")
            if _pk in _poisoned:
                reason = (
                    f"granted domain {_pk} was observed resolving to a "
                    f"non-global address; refusing further requests"
                )
                flow.response = http.Response.make(
                    403,
                    json.dumps(
                        {"blocked": True, "reason": reason,
                         "host": flow.request.host, "by": "agentcage"}
                    ).encode(),
                    {"Content-Type": "application/json"},
                )
                flow.metadata["agentcage_blocked"] = True
                self._log(flow, "blocked", reason, [])
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
            # Strip client-attribution headers instead of synthesizing them.
            # Rootless port publishing (pasta) rewrites the source address,
            # so the only value we could put in X-Forwarded-For is the
            # egress's own network address — an attribution chain that never
            # resolves to a real client. openclaw 2.0 (v2026.8+) rejects
            # exactly that shape on Gateway-authenticated routes with
            # `proxy_attribution_required` (and older versions merely logged
            # the useless value). With no forwarded headers at all, the
            # upstream app attributes the connection as a direct remote
            # client, which is what this relay effectively is. Deleting the
            # headers (rather than leaving them untouched) also keeps a
            # client-forged X-Forwarded-For from ever reaching the app.
            try:
                client_ip = flow.client_conn.address[0]
            except (AttributeError, IndexError, TypeError):
                pass
            for hdr in ("x-forwarded-for", "x-forwarded-proto",
                        "x-forwarded-host", "x-real-ip", "forwarded"):
                flow.request.headers.pop(hdr, None)
            proto = "https" if flow.client_conn.tls_established else "http"

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

        # Source IP for inbound requests (as observed by the reverse
        # listener; audit-log only, never forwarded upstream)
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
                if self._is_websocket_upgrade(flow):
                    # The 101 arrives before any frame: keep the entry
                    # open, with both HTTP halves, for websocket_message
                    # to add frames to and websocket_end / error to write.
                    # Only the domain filters are final here; min_action
                    # is checked at the write, against the decision the
                    # frames may have escalated (see _finish_ws_capture).
                    if self._capture.captures_host(pending["host"]):
                        pending["inbound_resp"] = (
                            self._capture.snapshot_response(flow)
                        )
                        pending["outbound_resp"] = cap_outbound_resp
                        pending["websocket"] = True
                        self._cap_pending[flow.id] = pending
                elif self._capture.should_capture(pending["decision"], pending["host"]):
                    cap_inbound_resp = self._capture.snapshot_response(flow)
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
                    )

    @staticmethod
    def _is_websocket_upgrade(flow: http.HTTPFlow) -> bool:
        """True for the 101 response of a WebSocket upgrade.

        The proxy sets ``flow.websocket`` before the response hook exactly
        when a WebSocket follows (101, ``Upgrade: websocket``, WebSocket
        support on); the status check keeps a flow whose response an
        addon replaced from counting.
        """
        resp = flow.response
        return (resp is not None and resp.status_code == 101
                and getattr(flow, "websocket", None) is not None)

    def error(self, flow: http.HTTPFlow) -> None:
        """Release the capture state of a flow that ended in an error.

        ``request()`` stages a capture entry that ``response()`` completes
        and pops. A flow that errors before a response (upstream refused or
        reset the connection, the client went away, mitmproxy's
        ``body_size_limit``, a killed flow) never reaches ``response()``, so
        without this hook each one left its staged snapshots — request
        bodies up to ``max_body_size`` apiece — in memory for the life of
        the process.

        Such an entry is dropped, not written: there is no response half to
        pair it with, the audit log already holds the request's decision,
        and a half entry would be a new shape for ``cage har`` and the
        watcher to read. A WebSocket entry left open past its 101 is the
        exception: it has both halves, so it is written with the frames
        recorded so far (see ``_finish_ws_capture``).
        """
        self._finish_ws_capture(flow)

    def _finish_ws_capture(self, flow: http.HTTPFlow) -> None:
        """Write a flow's open WebSocket entry, then release its state.

        Called when the socket ends or the flow errors; whichever comes
        first writes the entry and the other finds nothing. The entry
        goes to whichever writer is live now, so one swapped in by a
        reload while the socket was open (it adopted the buffered frames)
        still records it. ``min_action`` is applied here, against the
        upgrade's decision escalated by its frames: a socket whose frames
        were flagged or blocked is captured under ``flag`` / ``block``
        even though its upgrade was allowed. Anything else the flow holds
        (a staged non-WebSocket entry) is dropped as before.
        """
        pending = self._cap_pending.get(flow.id)
        if self._capture and pending and pending.get("websocket"):
            messages, omitted = self._capture.pop_ws_buffer(flow.id)
            if self._capture.should_capture(pending["decision"], pending["host"]):
                self._capture.write_entry(
                    flow_id=flow.id,
                    direction=pending["direction"],
                    decision=pending["decision"],
                    host=pending["host"],
                    method=pending["method"],
                    path=pending["path"],
                    inspectors=pending["inspectors"],
                    inbound_req=pending["inbound_req"],
                    inbound_resp=pending["inbound_resp"],
                    outbound_req=pending["outbound_req"],
                    outbound_resp=pending["outbound_resp"],
                    ws_messages=messages or None,
                    ws_messages_omitted=omitted,
                )
        self._release_flow_capture(flow)

    def _release_flow_capture(self, flow: http.HTTPFlow) -> None:
        """Drop everything capture holds for this flow (no-op if nothing)."""
        self._cap_pending.pop(flow.id, None)
        if self._capture:
            self._capture.pop_ws_messages(flow.id)

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

    # ── Peer-address validation for granted hosts ───────────
    # Every name-based check — never_grant, the IP-encoding guard, the
    # decider itself — reasons about the NAME. DNS answers the name, and the
    # answer can change after the grant. A domain granted while it resolved
    # somewhere harmless can have its A record repointed at 169.254.169.254
    # a second later (classic DNS rebinding), and nothing keyed on the name
    # would notice. `localtest.me` needs no rebinding at all: it is a real
    # public domain whose A record is 127.0.0.1.
    #
    # So this is the one check that looks at the ADDRESS, at the moment it
    # matters — when mitmproxy is about to talk to it.
    #
    # Scoped deliberately to GRANT-ONLY hosts. Baseline domains are the
    # operator's own choice: an internal artifact mirror on 10.x in
    # `domains.allow` is a legitimate, deliberate configuration, and this
    # must not break it. Inbound port-forwards are the same story from the
    # other direction — mitmproxy runs `--mode reverse:http://<cage-ip>` and
    # connects to the cage's private address on purpose. Neither is a
    # granted domain, so neither is affected.

    def _domain_inspector(self) -> Optional[DomainInspector]:
        return next((i for i in self.inspectors
                     if isinstance(i, DomainInspector)), None)

    @staticmethod
    def _non_global_ip(value) -> Optional[str]:
        """Return *value* as a string when it is a non-global IP address.

        ``None`` when it is not an IP at all (a hostname, at the point in
        the connection where mitmproxy has not resolved it yet) or when it
        is globally routable.
        """
        if not value:
            return None
        host = value[0] if isinstance(value, (tuple, list)) else value
        if not isinstance(host, str):
            return None
        # IPv6 scope suffix (fe80::1%eth0) is not part of the address.
        host = host.split("%", 1)[0].strip("[]")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None  # a hostname; nothing to judge yet
        # Unwrap ::ffff:169.254.169.254 — an IPv4 target reached over a
        # v6 socket must not launder itself past this check.
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        return None if ip.is_global else str(ip)

    def _guard_peer(self, data, phase: str) -> None:
        """Refuse a granted host that resolves to a non-global address."""
        server = getattr(data, "server", None)
        if server is None:
            return
        dom = self._domain_inspector()
        if dom is None or not getattr(dom, "granted", None):
            return  # no grants in play; nothing this check applies to
        host = ""
        addr = getattr(server, "address", None)
        if addr:
            host = str(addr[0] if isinstance(addr, (tuple, list)) else addr)
        # `sni` is set for TLS flows before the upstream connect and is the
        # name the allowlist was evaluated against.
        sni = getattr(server, "sni", None)
        candidates = [h for h in (host, sni) if h]
        if not any(dom.is_grant_only(h) for h in candidates):
            return
        for value in (getattr(server, "peername", None), addr):
            bad = self._non_global_ip(value)
            if not bad:
                continue
            target = next(
                (h for h in candidates if dom.is_grant_only(h)), host or "?"
            )
            self._refuse_peer(server, target, bad, phase)
            return

    def _log_peer_block(self, host: str, ip: str, phase: str,
                        reason: str) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": "private_peer_blocked",
            "direction": "outbound",
            "decision": "blocked",
            "reason": reason,
            "host": host,
            "peer_ip": ip,
            "phase": phase,
        }
        # Same funnel as _log: stderr + audit.jsonl + watcher ring.
        self._audit_write(entry)

    def _resolve_all(self, host: str) -> list:
        """Every address *host* resolves to, cached briefly.

        Called only for grant-only hosts, and only from ``server_connect``.
        That placement is what makes the lookup safe: the host is ALREADY
        granted, so the cage can already resolve it through the egress's
        dnsmasq — this adds no DNS the cage could not trigger itself. (The
        same lookup at *request* time, against an arbitrary not-yet-granted
        string, would be a DNS exfiltration channel: non-allowlisted names
        are sinkholed locally today and never leave the host.)

        The cache keeps a burst of requests to one granted host from
        re-resolving on every connection; the window is deliberately short
        so a rebind is caught on the next connect rather than after a
        normal DNS TTL.
        """
        now = time.time()
        hit = self._peer_dns_cache.get(host)
        if hit and now - hit[0] < 5.0:
            return hit[1]
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            addrs = [i[4][0] for i in infos]
        except OSError:
            addrs = []
        self._peer_dns_cache[host] = (now, addrs)
        if len(self._peer_dns_cache) > 256:      # bound the cache
            self._peer_dns_cache.clear()
        return addrs

    def server_connect(self, data) -> None:
        """Refuse before the socket opens — the only hook that can.

        mitmproxy reads ``connection.error`` after this hook and aborts
        without connecting. It does NOT re-check after
        ``ServerConnectedHook``, so a verdict reached later cannot stop the
        request that is already in flight — which is why the resolution
        happens here rather than reusing mitmproxy's own.

        EVERY answer is checked, not just the first: a rebinding payload
        commonly returns a public address alongside the internal one and
        relies on the client picking either.
        """
        try:
            server = getattr(data, "server", None)
            if server is None:
                return
            dom = self._domain_inspector()
            if dom is None or not getattr(dom, "granted", None):
                return
            addr = getattr(server, "address", None)
            host = ""
            if addr:
                host = str(addr[0] if isinstance(addr, (tuple, list)) else addr)
            sni = getattr(server, "sni", None)
            target = next(
                (h for h in (host, sni) if h and dom.is_grant_only(h)), ""
            )
            if not target:
                return
            # The address itself may already be an IP (transparent mode).
            candidates = [host] if host else []
            candidates += self._resolve_all(target)
            for value in candidates:
                bad = self._non_global_ip(value)
                if bad:
                    self._refuse_peer(server, target, bad, "server_connect")
                    return
        except Exception as e:  # never break the proxy over this check
            print(f"agentcage: peer guard error: {e!r}", file=sys.stderr,
                  flush=True)

    def server_connected(self, data) -> None:
        """Backstop: catch a rebind between our lookup and mitmproxy's.

        This CANNOT stop the request already in flight — mitmproxy does not
        re-read ``connection.error`` after this hook. It audits the event and
        poisons the host so the next request to it is refused at the L7
        ``request()`` gate, which can still return a 403.
        """
        try:
            self._guard_peer(data, "server_connected")
        except Exception as e:
            print(f"agentcage: peer guard error: {e!r}", file=sys.stderr,
                  flush=True)

    def _refuse_peer(self, server, host: str, ip: str, phase: str) -> None:
        reason = (
            f"granted domain {host} resolves to non-global address {ip}; "
            f"refusing the upstream connection. A grant is a NAME, and DNS "
            f"can point that name at an internal address after the fact "
            f"(rebinding) or by design (localtest.me). Operator-configured "
            f"baseline domains are unaffected."
        )
        try:
            server.error = reason
        except Exception:
            pass
        self._poisoned_peers.add(host.lower().rstrip("."))
        self._log_peer_block(host, ip, phase, reason)

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
        # Through the shared sink (stderr + audit.jsonl + ring), not a
        # standalone write: an egress-bypass block is exactly the kind
        # of event the traffic watcher exists to see, and _ring_ingest
        # is the single funnel point every other producer already uses.
        self._audit_write(entry)

    async def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Inspect, inject, and redact WebSocket frame payloads."""
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        content = msg.content
        if not content:
            return

        # Taken before the inspectors can await, so the recorded time is
        # the frame's arrival (see _capture_ws_frame).
        frame_ts = datetime.now(timezone.utc).isoformat()

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
                decision = "blocked"
                self._log(flow, "blocked", f"websocket: {reason}", results, direction="outbound")
            else:
                content, injected = self.injector.inject_ws_content(
                    body_bytes, host
                )
                msg.content = content
                flagged = [r for r in results if r.action == "flag"]
                decision = "flagged" if flagged else "allowed"
                if flagged:
                    reasons = "; ".join(r.reason for r in flagged)
                    self._log(
                        flow, "flagged", f"websocket: {reasons}", results, direction="outbound", secrets_injected=injected
                    )
                elif self.log_allowed or injected:
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
                decision = "blocked"
                self._log(flow, "blocked", f"websocket: {reason}", results, direction="inbound")
            else:
                decision = (
                    "flagged" if any(r.action == "flag" for r in results)
                    else "allowed"
                )
                if self.log_allowed:
                    self._log(flow, "allowed", "websocket", results, direction="inbound")

            # Redact real secrets before content reaches the cage
            content, _redacted = self.injector.redact_ws_content(body_bytes)
            msg.content = content

        self._capture_ws_frame(flow, msg, body_bytes, frame_ts, decision)

    def _capture_ws_frame(self, flow: http.HTTPFlow, msg, body_bytes: bytes,
                          ts: str, decision: str) -> None:
        """Record one WebSocket message on the flow's open capture entry.

        Runs after the message was inspected and rewritten, and only for
        a flow whose entry ``response()`` kept open at the 101. What is
        recorded is the message as it arrived (``body_bytes``) with every
        real secret value swapped for its placeholder: the redaction the
        cage-bound direction gets before forwarding, and what the HTTP
        outbound request snapshot holds. For a cage → remote message that
        is the placeholder form the cage sent, never the injected value
        (nor a token a transform derived from it); a dropped message that
        carried a literal secret is redacted the same way. The entry's
        decision escalates to the worst of its frames' (blocked > flagged
        > allowed), which ``min_action`` is checked against at the write.
        """
        if not self._capture:
            return
        pending = self._cap_pending.get(flow.id)
        if not pending or not pending.get("websocket"):
            return
        recorded, _names = self.injector.redact_ws_content(body_bytes)
        self._capture.add_ws_frame(
            flow.id,
            from_client=bool(msg.from_client),
            is_text=msg.is_text is True,
            content=recorded,
            ts=ts,
            decision=decision,
        )
        order = {"allowed": 0, "flagged": 1, "blocked": 2}
        if order[decision] > order.get(pending["decision"], 0):
            pending["decision"] = decision

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        """Write a WebSocket flow's capture entry when the socket ends.

        Fires on every close, clean or abnormal (a dropped connection ends
        the socket with code 1006). ``response()`` kept the entry open at
        the 101 and ``websocket_message`` added the frames; this writes it
        and releases the flow's state (see ``_finish_ws_capture``).
        """
        self._finish_ws_capture(flow)

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

    def _ring_ingest(self, entry: dict) -> None:
        """Copy one audit entry into the traffic watcher's ring (if on).

        The single funnel point: every audit producer (HTTP/WS decisions
        via _log, peer guard, relays, DNS, the Policy API, the watcher
        itself) lands here. Bounded, O(1), and populated only while the
        watcher is enabled — see _init_watcher.
        """
        if getattr(self, "_watcher_ring", None) is None:
            return
        try:
            self._watcher_ring.append(dict(entry))
        except Exception:  # pragma: no cover — defensive
            pass

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
        if (
            decision == "allowed"
            and not self.log_allowed
            and not secrets_injected
            and not secrets_redacted
        ):
            # An allowed request that carried a secret is always logged:
            # which requests received a credential is the audit trail
            # that matters, whatever logging.allowed_requests says.
            #
            # For plain allowed traffic the durable/log output is
            # suppressed (journald noise and disk — the operator's choice
            # via logging.allowed_requests),
            # but the watcher's ring MUST still see ALLOWED traffic:
            # exfiltration and beacons live in traffic that was allowed,
            # so suppressing the watcher's evidence along with the log
            # would blind the auditor to exactly its subject. Ingest the
            # ring copy and stop before _audit_write's durable sinks.
            self._ring_ingest(entry)
            return
        # Everything else rides the ONE audit funnel: stderr print +
        # audit.jsonl (capped) + the watcher ring — no direct writes, so
        # no producer can bypass the watcher.
        self._audit_write(entry)


addons = [Agentcage()]
