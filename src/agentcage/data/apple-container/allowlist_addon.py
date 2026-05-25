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
        self._audit_fh = self._open_log(AUDIT_LOG_PATH)
        self._capture_fh = self._open_log(CAPTURE_PATH)

        # Protocol relays (IMAP, SMTP, ...) — loaded here, instantiated
        # in the ``running()`` hook once the mitmproxy asyncio loop is
        # live. We can't start TCP listeners from __init__ because the
        # loop may not exist yet (mitmproxy creates it during its own
        # startup). The relay objects themselves live in
        # ``self._relays`` so the ``done()`` hook can drain them.
        self._relay_entries: list[dict] = _load_protocol_relays()
        self._relays: list = []

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
        """
        host = flow.request.pretty_host.lower()
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
        host = flow.request.pretty_host.lower()
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
        host = flow.request.pretty_host
        now = datetime.now(timezone.utc).isoformat()

        entry: dict = {
            "ts": now,
            "direction": "outbound",
            "method": flow.request.method,
            "host": host,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "port": flow.request.port,
            "source": "apple-container",
            "inspectors": [],
            "secrets_injected": [],
            "secrets_redacted": [],
        }

        if _host_allowed(host, self.allowed):
            # Apply secret injection BEFORE the upstream request goes out.
            # Substitutions happen in place; we record the env names in
            # the audit entry so the operator can see what was swapped.
            # `secret_transforms` is a sibling field (mapping env →
            # transform name) — present only when at least one rule ran
            # through a transform like google-jwt-bearer, so the operator
            # can distinguish raw-env substitution from derived-value
            # substitution at audit time.
            injected, transforms = self._maybe_inject(flow)
            entry["decision"] = "allowed"
            entry["reason"] = "domain-allowlist"
            entry["secrets_injected"] = injected
            if transforms:
                entry["secret_transforms"] = transforms
            self._audit(entry)
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
            return

        # Redact BEFORE capture so capture.jsonl never sees raw values.
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
