"""Read-only data providers for the web interface (and the CLI).

Every function here returns JSON-able dicts describing one *panel* of the
operator dashboard. The web server (``agentcage web``) serializes them; the
CLI (`agentcage overview`) prints them — both are thin wrappers over this
module, which is what guarantees the web interface never gains a view the
terminal lacks.

Design rules, so the panel registry stays a real extensibility contract:

- **Read-only.** Providers observe state (config, metadata, backend status,
  audit streams); they never mutate it. Anything that writes belongs in the
  CLI and, later, in explicitly-marked write endpoints.
- **Secrets are never values.** Secret material (placeholders, resolved
  values, sources) is out of scope — only *names* and presence booleans
  cross this boundary, mirroring what `secret list` already shows.
- **Backend-agnostic.** Status and streams go through the ``Backend``
  protocol (`is_running`, `service_names`, `logs_argv`, `audit_argv`) so the
  same panel works for container, vm, and apple-container cages.
- **Fail per-panel, not per-page.** A provider raises; the caller (server
  route or CLI) decides how to surface it. One broken cage must not blank
  the whole overview.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import agentcage.state as state
from agentcage.audit import (
    AuditEntry,
    AuditFilter,
    compute_summary,
    extract_audit_json,
)
from agentcage.backends import get_backend
from agentcage.podman import Podman
from agentcage.services import expected_secrets

# How long a stream-reading subprocess (audit / logs) may run before the
# panel gives up. These are tail-style readers against local journals or
# bind-mounted files; anything slower is a wedged backend, not slow data.
_SUBPROCESS_TIMEOUT = 15

# Cage names are validated at create time with this pattern (see cli.init);
# re-checking here means an attacker-supplied URL segment can never reach a
# state-dir path join with ``..`` or a slash in it.
_CAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class CageNotFound(Exception):
    """The named cage does not exist (maps to HTTP 404)."""


class ProviderError(Exception):
    """A panel could not be rendered (maps to HTTP 503)."""


class LegacyCageError(ProviderError):
    """Pre-v0.22 cage with the legacy 3-service shape (maps to HTTP 409)."""


# ── registry ───────────────────────────────────────────────


@dataclass(frozen=True)
class Panel:
    """One dashboard panel: a route, its provider, and its CLI twin.

    ``cli`` is the command that renders the same data in the terminal —
    the parity contract the web interface is built under. ``stream``
    (optional) is the SSE live-tail variant of the panel, where the CLI
    twin takes ``-f``.
    """

    key: str                     # "traffic" — stable identifier
    title: str                   # "Traffic" — human label
    path: str                    # "/api/v1/cages/{name}/traffic"
    cli: str                      # "agentcage cage audit NAME"
    description: str
    cage_scoped: bool            # True → path carries a {name} segment
    stream: str = ""            # SSE variant, e.g. "/api/v1/cages/{name}/traffic/stream"


#: Registered panels, in dashboard order. To add a panel: write a provider
#: function below, append an entry here, and (if the capability is new)
#: give it a CLI command. The server serves every registered panel; the
#: frontend renders the manifest, so no per-panel wiring exists anywhere.
PANELS: list[Panel] = [
    Panel("overview", "Overview", "/api/v1/overview",
          "agentcage overview", "All cages: status, isolation, secrets, domains.",
          cage_scoped=False),
    Panel("doctor", "Doctor", "/api/v1/doctor",
          "agentcage doctor",
          "System health checks (Podman, systemd, secret backend, ...).",
          cage_scoped=False),
    Panel("cage", "Cage detail", "/api/v1/cages/{name}",
          "agentcage cage show NAME",
          "Configuration and per-service runtime status for one cage.",
          cage_scoped=True),
    Panel("secrets", "Secrets", "/api/v1/cages/{name}/secrets",
          "agentcage secret list NAME",
          "Expected secrets and whether each is set (names only — never values).",
          cage_scoped=True),
    Panel("allowlist", "Allowlist", "/api/v1/cages/{name}/allowlist",
          "agentcage domain list NAME; agentcage cage grants list NAME",
          "Domain baseline, passthrough entries, expiry, and runtime grants.",
          cage_scoped=True),
    Panel("traffic", "Traffic", "/api/v1/cages/{name}/traffic",
          "agentcage cage audit NAME [--summary]",
          "Proxy decisions: recent entries and aggregate statistics.",
          cage_scoped=True,
          stream="/api/v1/cages/{name}/traffic/stream"),
    Panel("dns", "DNS", "/api/v1/cages/{name}/dns",
          "agentcage cage audit NAME --method DNS --summary",
          "DNS decisions from the egress resolver: queries, sinkholed lookups, top domains.",
          cage_scoped=True),
    Panel("capture", "Capture", "/api/v1/cages/{name}/capture",
          "agentcage cage har NAME [--json-lines]",
          "Captured HTTP flows (inbound view only) with HAR export.",
          cage_scoped=True),
    Panel("logs", "Logs", "/api/v1/cages/{name}/logs",
          "agentcage cage logs NAME",
          "Recent service journal output for the cage and egress units.",
          cage_scoped=True,
          stream="/api/v1/cages/{name}/logs/stream"),
]


def manifest() -> list[dict]:
    """Panel manifest (what GET /api/v1/manifest serves)."""
    return [
        {
            "key": p.key,
            "title": p.title,
            "path": p.path,
            "cli": p.cli,
            "description": p.description,
            "cage_scoped": p.cage_scoped,
            **({"stream": p.stream} if p.stream else {}),
        }
        for p in PANELS
    ]


# ── helpers ─────────────────────────────────────────────────


def _require_cage(name: str) -> None:
    """Validate *name* (shape + existence) before any state-dir use."""
    if not _CAGE_NAME_RE.match(name or ""):
        raise CageNotFound(f"cage '{name}' does not exist")
    if not state.deployment_exists(name):
        raise CageNotFound(f"cage '{name}' does not exist")


def _require_v022(name: str) -> None:
    """Refuse legacy v0.21 cages (3-service shape), like the CLI does."""
    meta = state.load_metadata(name)
    ver = meta.get("agentcage_version") or "0.0.0"
    try:
        parts = tuple(int(x) for x in ver.split(".")[:3])
    except ValueError:
        parts = (0, 0, 0)
    if parts < (0, 22):
        raise LegacyCageError(
            f"cage '{name}' was created with agentcage v{ver} (legacy "
            f"3-service layout); destroy and recreate it to inspect it here"
        )


def _podman_for_cage(name: str, cfg) -> Podman:
    """The right Podman for the cage: through the VM when one is running.

    Mirrors the CLI's helper of the same name.
    """
    if getattr(cfg, "isolation", None) == "vm":
        from agentcage.lima.instance import LimaInstance
        from agentcage.lima.podman import VmPodman

        if LimaInstance(name).is_running():
            return VmPodman(name)  # type: ignore[return-value]
    return Podman()


def _secret_names_present(name: str, cfg) -> set[str]:
    """Which expected secret names have a stored value.

    apple-container cages have no host podman; read the backend's secret
    store (keychain / plaintext) instead — the same source `secret list`
    and `cage show` use.
    """
    if getattr(cfg, "isolation", None) == "apple-container":
        from agentcage.secret_store import SecretStoreError, resolve_store
        try:
            store = resolve_store(cfg)
        except SecretStoreError:
            return set()
        return set(store.names(name, state_dir=state.deployment_dir(name)))
    podman = _podman_for_cage(name, cfg)
    return {
        s.get("Name", "").removeprefix(f"{name}.")
        for s in podman.secret_list(prefix=f"{name}.")
    }


def _read_domain_config(raw: dict) -> tuple[str, list[str], list[str]]:
    """(mode, domains, passthrough) from raw config — new + legacy shapes.

    Same interpretation as the CLI's `domain list`.
    """
    domains = raw.get("domains") or {}
    passthrough = list(domains.get("passthrough") or [])
    if "allow" in domains:
        return "allowlist", list(domains.get("allow") or []), passthrough
    if "block" in domains:
        return "blocklist", list(domains.get("block") or []), passthrough
    mode = domains.get("mode", "allowlist")
    return mode, list(domains.get("list") or []), passthrough


def _domain_expires(raw: dict) -> dict[str, str]:
    """The ``domains.expires`` map, lowercased like `domain list` reads it.

    Values are coerced to ``str``: bare ISO timestamps in YAML parse as
    datetime objects, and `domain list` renders them as strings anyway.
    """
    dom = raw.get("domains") or {}
    out: dict[str, str] = {}
    for k, v in (dom.get("expires") or {}).items():
        if v is None:
            continue
        # datetime values render with isoformat ("T" separator), matching
        # how the operator wrote them in cage.yaml.
        out[str(k).lower().rstrip(".")] = (
            v.isoformat() if hasattr(v, "isoformat") else str(v)
        )
    return out


def _grants_overlay(name: str, cfg) -> list[dict] | None:
    """Runtime grants overlay, isolation-aware (None = VM unreachable)."""
    if getattr(cfg, "isolation", None) == "vm":
        from agentcage.backends.vm import pull_grants
        from agentcage.lima.instance import LimaInstance

        return pull_grants(name, LimaInstance(name))
    return state.load_grants(name)


def _run_capture(argv: list[str], *, timeout: int = _SUBPROCESS_TIMEOUT) -> str:
    """Run a reader subprocess and return its merged stdout+stderr.

    The audit/log readers write to either stream depending on the backend's
    log driver; merging here (like the CLI's audit reader) means a panel
    never silently shows an empty stream because podman put the JSON on
    the other side of the pipe.
    """
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ProviderError(f"reader not available: {argv[0]} ({exc})") from exc
    except subprocess.TimeoutExpired as exc:
        raise ProviderError(
            f"reader timed out after {timeout}s: {' '.join(argv[:2])}…"
        ) from exc
    return proc.stdout + (proc.stderr or "")


def _service_status(name: str, cfg) -> dict:
    """Per-service running state + the aggregate status word.

    ``backend`` and ``services`` come back as data even when the cage is
    stopped, so the dashboard can render a stopped cage without extra
    calls. Backend tooling missing from PATH (``podman``, ``journalctl``) is
    reported as ``status: unknown`` + a ``detail`` message rather than a
    500 — an operator without the runtime installed still gets a page.
    """
    try:
        backend = get_backend(cfg)
        services = []
        running = 0
        for svc in backend.service_names(name):
            up = bool(backend.is_running(name, svc))
            running += up
            services.append({"service": svc, "running": up})
    except Exception as exc:
        return {"status": "unknown", "detail": str(exc),
                "running": 0, "total": 0, "services": []}
    total = len(services)
    if total and running == total:
        status = f"running ({running}/{total})"
    elif total and running == 0:
        status = f"stopped (0/{total})"
    elif total:
        status = f"degraded ({running}/{total})"
    else:
        status = "unknown"
    return {"status": status, "running": running, "total": total,
            "services": services}


def _secrets_counts(name: str, cfg) -> dict:
    try:
        expected = expected_secrets(cfg)
        present = _secret_names_present(name, cfg)
    except Exception as exc:  # secret store unreadable — counts, not a 500
        return {"expected": 0, "present": 0, "missing": 0, "error": str(exc)}
    missing = [k for k in expected if k not in present]
    return {"expected": len(expected), "present": len(expected) - len(missing),
            "missing": len(missing)}


def _domains_counts(name: str, cfg) -> dict:
    try:
        raw = state.load_raw_config(name)
        mode, entries, _ = _read_domain_config(raw)
        return {"mode": mode, "domains": len(entries)}
    except Exception:
        return {"mode": "unknown", "domains": 0}


# ── panels ──────────────────────────────────────────────────


def overview() -> dict:
    """All cages at a glance — the landing panel.

    One row per deployment; a cage whose config fails to load is reported
    inline (``status: "config error"``) rather than taking down the page.
    CLI twin: ``agentcage overview``.
    """
    cages = []
    for name in state.list_deployments():
        try:
            cfg = state.load_deployment_config(name)
        except Exception as exc:
            cages.append({
                "name": name,
                "status": "config error",
                "detail": str(exc),
            })
            continue

        meta = state.load_metadata(name)
        row = {
            "name": name,
            "lifecycle": meta.get("lifecycle", cfg.lifecycle),
            "isolation": cfg.isolation,
            "scaffold": meta.get("scaffold", cfg.scaffold),
            "version": meta.get("agentcage_version", "-"),
            "image": cfg.container.image,
        }

        # v0.21 cages predate the 2-service shape; annotate instead of
        # mislabeling them stopped (same call as `cage list`).
        ver = meta.get("agentcage_version") or "0.0.0"
        try:
            parts = tuple(int(x) for x in ver.split(".")[:3])
        except ValueError:
            parts = (0, 0, 0)
        if parts < (0, 22):
            row.update({
                "status": "legacy v0.21",
                "detail": "destroy + recreate required",
                "services": [],
            })
            cages.append(row)
            continue

        try:
            svc = _service_status(name, cfg)
            row.update({
                "status": svc["status"],
                "services": svc["services"],
            })
        except Exception as exc:
            row.update({"status": "unknown", "detail": str(exc),
                        "services": []})

        row["secrets"] = _secrets_counts(name, cfg)
        row["domains"] = _domains_counts(name, cfg)
        cages.append(row)

    return {"cages": cages}


def cage_detail(name: str) -> dict:
    """One cage: identity, config, per-service status.

    CLI twin: ``agentcage cage show NAME``.
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    meta = state.load_metadata(name)
    detail = {
        "name": cfg.name,
        "isolation": cfg.isolation,
        "image": cfg.container.image,
        "lifecycle": meta.get("lifecycle", cfg.lifecycle),
        "scaffold": meta.get("scaffold", cfg.scaffold),
        "version": meta.get("agentcage_version", "-"),
        "ports": list(cfg.container.ports or []),
        "secrets": _secrets_counts(name, cfg),
        "domains": _domains_counts(name, cfg),
    }
    detail.update(_service_status(name, cfg))
    return detail


def cage_secrets(name: str) -> dict:
    """Expected secrets for a cage with presence flags — names only.

    Never includes values, placeholders, or sources: a dashboard is a
    read surface, and `secret list` already draws this exact line.
    CLI twin: ``agentcage secret list NAME``.
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    expected = expected_secrets(cfg)
    try:
        present = _secret_names_present(name, cfg)
    except Exception as exc:
        # secret store unreadable (no podman on PATH, locked keychain):
        # say that instead of a 500 — `secret list` has the same failure
        return {
            "name": name,
            "expected": len(expected),
            "missing": 0,
            "secrets": [{"name": e, "present": None}
                        for e in expected],
            "error": f"secret store unavailable: {exc}",
        }
    secrets = []
    for env in expected:
        entry = {"name": env, "present": env in present}
        # Injection targets (scope of the swap) are config, not secret
        # material — surfacing them mirrors what `cage show` implies.
        for rule in cfg.secret_injection:
            if rule.env == env:
                entry["inject_to"] = list(rule.inject_to or [])
                break
        secrets.append(entry)
    return {
        "name": name,
        "expected": len(secrets),
        "missing": sum(1 for s in secrets if not s["present"]),
        "secrets": secrets,
    }


def cage_allowlist(name: str) -> dict:
    """Domain policy for a cage: baseline, passthrough, expiry, grants.

    CLI twin: ``agentcage domain list NAME`` (baseline) and
    ``agentcage cage grants list NAME`` (overlay).
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    raw = state.load_raw_config(name)
    mode, entries, passthrough = _read_domain_config(raw)
    expires = _domain_expires(raw)
    pt_set = set(passthrough)

    domains = []
    for d in sorted(set(entries) | pt_set):
        domains.append({
            "domain": d,
            "passthrough": d in pt_set,
            "expires": expires.get(d.lower().rstrip(".")),
        })

    grants = None
    grants_note = None
    try:
        grants = _grants_overlay(name, cfg)
    except Exception as exc:
        grants_note = f"grants unavailable: {exc}"
    if grants is None and grants_note is None:
        # VM unreachable: the overlay lives guest-side; say so rather than
        # showing an empty list that reads as "no grants".
        grants_note = "cage VM unreachable — the grants overlay lives inside the VM"
    data = {
        "name": name,
        "mode": mode,
        "domains": domains,
        "baseline": sorted(cfg.domains.allow or []),
        "grants": [
            {
                "domain": str(e.get("domain", "")),
                "granted_at": str(e.get("granted_at", "")),
                "expires_at": str(e.get("expires_at", "")),
                "reason": str(e.get("reason", "")),
                "source": e.get("source", ""),
            }
            for e in (grants or [])
        ],
    }
    if grants_note:
        data["grants_note"] = grants_note
    return data


def _audit_stream_argv(name: str, cfg, *, follow: bool) -> list[str]:
    """The backend's audit reader argv (batch or follow).

    apple-container tails a host-side bind-mounted audit.jsonl; a missing
    file means "no traffic yet" for that backend, and the CLI reports it
    the same way.
    """
    if getattr(cfg, "isolation", None) == "apple-container":
        from agentcage.backends.apple_container import AppleContainerBackend
        path = AppleContainerBackend().logs_dir(name) / "audit.jsonl"
        if not path.is_file():
            raise ProviderError(
                f"no audit log yet for cage '{name}' (no proxy traffic "
                f"since start)"
            )
    return get_backend(cfg).audit_argv(name, follow=follow)


def _read_audit_entries(name: str, cfg, filt: AuditFilter) -> list[AuditEntry]:
    """All audit entries matching *filt* (the batch panels' shared reader)."""
    argv = _audit_stream_argv(name, cfg, follow=False)
    out = _run_capture(argv)
    entries: list[AuditEntry] = []
    for line in out.splitlines():
        d = extract_audit_json(line)
        if d is None:
            continue
        entry = AuditEntry.from_dict(d)
        if filt.matches(entry):
            entries.append(entry)
    return entries


def cage_traffic(
    name: str,
    *,
    limit: int = 100,
    decisions: list[str] | None = None,
    hosts: list[str] | None = None,
    methods: list[str] | None = None,
    since: str | None = None,
) -> dict:
    """Proxy decisions for a cage: recent entries + aggregate summary.

    CLI twin: ``agentcage cage audit NAME [--json] [--summary]``. Reads
    the same audit stream (backend.audit_argv) and the same filter +
    summary machinery the CLI uses, so the numbers cannot drift.
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)

    since_dt = None
    if since:
        from agentcage.har import parse_since
        since_dt = parse_since(since)
        if since_dt is None:
            raise ProviderError(
                f"invalid since {since!r}: use 1h, 30m, 7d, or an ISO date"
            )

    filt = AuditFilter(
        decisions=list(decisions or []),
        hosts=list(hosts or []),
        methods=list(methods or []),
        since=since_dt,
    )
    entries = _read_audit_entries(name, cfg, filt)

    # Summary over *all* filtered entries (parity with `cage audit
    # --summary`), then the display limit — otherwise ?limit= would shrink
    # the aggregates and the web numbers would drift from the CLI's.
    summary = compute_summary(entries)
    if limit > 0:
        entries = entries[-limit:]

    return {
        "name": name,
        "count": len(entries),
        "summary": summary,
        "entries": [e.raw for e in entries],
    }


def cage_dns(name: str, *, limit: int = 100, since: str | None = None) -> dict:
    """DNS decisions for a cage: queries, sinkholes, top domains.

    The egress's dnsmasq wrapper (dns-audit.sh) emits one audit entry per
    DNS decision (method ``DNS``); this panel is that slice of the audit
    stream. CLI twin: ``agentcage cage audit NAME --method DNS
    [--summary]``.
    """
    data = cage_traffic(
        name, limit=limit, methods=["DNS"], since=since,
    )
    data["panel"] = "dns"
    return data


def cage_logs(
    name: str,
    *,
    services: list[str] | None = None,
    lines: int = 50,
) -> dict:
    """Recent journal output for the cage's services (non-following).

    CLI twin: ``agentcage cage logs NAME -n LINES``.
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    backend = get_backend(cfg)
    allowed = backend.service_names(name)
    selected = [s for s in (services or allowed) if s in allowed]
    if not selected:
        selected = allowed

    argv = backend.logs_argv(
        name, selected, follow=False, lines=max(0, lines),
    )
    out = _run_capture(argv)
    tail = out.splitlines()[-max(0, lines):] if lines > 0 else []

    return {
        "name": name,
        "services": selected,
        "lines": tail,
    }


# ── live streams (SSE backing) ──────────────────────────────


class LiveStream:
    """A follow-mode reader subprocess wrapped as an iterable of dicts.

    The CLI tails audit/log streams with ``Popen`` + a blocking read loop
    (``cage audit -f`` / ``cage logs -f``); this is the same reader
    reshaped for a server, where the *consumer* may vanish at any moment.
    ``close()`` is safe to call from a different thread than the
    iteration: it terminates the subprocess, which is what unblocks the
    blocked ``readline`` — closing a mid-execution generator from another
    thread is not, so the handle owns the process instead of the frame.
    """

    def __init__(self, argv: list[str], transform: Callable[[str], dict | None]):
        try:
            self._proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError as exc:
            raise ProviderError(f"reader not available: {argv[0]} ({exc})") from exc
        self._transform = transform
        self._closed = False

    def __iter__(self):
        assert self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                if self._closed:
                    return
                item = self._transform(line)
                if item is not None:
                    yield item
        finally:
            self.close()

    def close(self) -> None:
        """Terminate the reader (idempotent, thread-safe)."""
        self._closed = True
        if self._proc.poll() is None:
            self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)


def follow_traffic(
    name: str,
    *,
    decisions: list[str] | None = None,
    hosts: list[str] | None = None,
    methods: list[str] | None = None,
) -> "LiveStream":
    """Live audit decisions for a cage, one dict per entry.

    CLI twin: ``agentcage cage audit NAME -f --json``. Filters apply
    stream-side, exactly like the CLI's follow path.
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    filt = AuditFilter(
        decisions=list(decisions or []),
        hosts=list(hosts or []),
        methods=list(methods or []),
    )
    argv = _audit_stream_argv(name, cfg, follow=True)

    def transform(line: str) -> dict | None:
        d = extract_audit_json(line)
        if d is None:
            return None
        if not filt.matches(AuditEntry.from_dict(d)):
            return None
        return d

    return LiveStream(argv, transform)


def follow_logs(
    name: str,
    *,
    services: list[str] | None = None,
    lines: int = 50,
) -> "LiveStream":
    """Live service journal output for a cage, one dict per line.

    CLI twin: ``agentcage cage logs NAME -f``.
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    backend = get_backend(cfg)
    allowed = backend.service_names(name)
    selected = [s for s in (services or allowed) if s in allowed] or allowed
    argv = backend.logs_argv(
        name, selected, follow=True, lines=max(0, lines),
    )
    return LiveStream(
        argv, lambda line: {"line": line.rstrip("\n")},
    )


# ── capture (HAR) ───────────────────────────────────────────


def _capture_path(name: str, cfg) -> Path:
    """Host-visible capture.jsonl for the cage (backend-aware)."""
    if getattr(cfg, "isolation", None) == "apple-container":
        from agentcage.backends.apple_container import AppleContainerBackend
        return AppleContainerBackend().logs_dir(name) / "capture.jsonl"
    return state.capture_file(name)


def _read_capture_entries(path: Path, *, limit: int = 0) -> list[dict]:
    """Parsed capture entries (most recent last); *limit* keeps last N."""
    entries: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    if limit > 0:
        entries = entries[-limit:]
    return entries


# Capture entries carry both perspectives — inbound (what the cage saw:
# placeholders, redacted secrets) and outbound (the wire: real secrets).
# The web interface serves inbound only; the outbound view is the CLI's
# `cage har --view outbound` and it stays there, warning and all.
_INBOUND_ONLY_NOTE = (
    "web capture views are inbound-only (redacted); use "
    "'agentcage cage har --view outbound' for the wire perspective"
)


def cage_capture(name: str, *, limit: int = 100) -> dict:
    """Captured HTTP flows for a cage — status + recent entries.

    CLI twin: ``agentcage cage har NAME --json-lines`` (which can also
    print the outbound perspective; this panel cannot, by design).
    """
    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    path = _capture_path(name, cfg)
    enabled = bool(getattr(cfg, "capture", None) and cfg.capture.enable_har)

    data: dict = {
        "name": name,
        "enabled": enabled,
        "note": _INBOUND_ONLY_NOTE,
    }
    if not path.is_file():
        data.update({
            "captured": False,
            "count": 0,
            "entries": [],
            "detail": (
                "no capture file — add 'capture: {enable_har: true}' to "
                "cage.yaml and run 'agentcage cage update'"
            ),
        })
        return data

    entries = _read_capture_entries(path)
    data.update({
        "captured": True,
        "count": len(entries),
        "size": path.stat().st_size,
        "har": f"/api/v1/cages/{name}/capture/har",
    })
    if limit > 0:
        entries = entries[-limit:]

    # Sanitized summaries: inbound perspective only, metadata only — no
    # bodies (they can be megabytes) and never the outbound perspective.
    data["entries"] = [
        {
            "ts": e.get("ts", ""),
            "flow_id": e.get("flow_id", ""),
            "direction": e.get("direction", ""),
            "decision": e.get("decision", ""),
            "host": e.get("host", ""),
            "method": e.get("method", ""),
            "status": (e.get("inbound") or {}).get("response", {})
                        .get("status"),
            "resp_size": (e.get("inbound") or {}).get("response", {})
                        .get("bodySize", 0),
        }
        for e in entries
    ]
    return data


def cage_har(name: str, *, limit: int = 0) -> dict:
    """Full HAR 1.2 export of a cage's captured traffic — inbound view.

    CLI twin: ``agentcage cage har NAME`` (inbound is its default view
    too). The outbound (wire, secrets) perspective is deliberately not
    reachable from the web interface.
    """
    from agentcage.har import capture_to_har

    _require_cage(name)
    _require_v022(name)

    cfg = state.load_deployment_config(name)
    path = _capture_path(name, cfg)
    if not path.is_file():
        raise ProviderError(
            f"no capture file found for cage '{name}' (enable "
            f"'capture: {{enable_har: true}}' and run 'agentcage cage update')"
        )
    entries = _read_capture_entries(path, limit=limit)
    return capture_to_har(entries, view="inbound")


# ── doctor ──────────────────────────────────────────────────


def doctor() -> dict:
    """System health checks — the doctor panel.

    CLI twin: ``agentcage doctor``. ``run_doctor`` prints as it checks;
    the server captures that output so a dashboard request doesn't
    interleave check banners into the server log. The printed text and
    the returned results are the same data the CLI shows.
    """
    from agentcage.doctor import run_doctor

    with contextlib.redirect_stdout(io.StringIO()):
        results = run_doctor()
    checks = [
        {"level": r.level, "message": r.message, "hint": r.hint}
        for r in results
    ]
    return {
        "ok": not any(r.level == "error" for r in results),
        "pass": sum(1 for r in results if r.level == "pass"),
        "warn": sum(1 for r in results if r.level == "warn"),
        "error": sum(1 for r in results if r.level == "error"),
        "checks": checks,
    }
