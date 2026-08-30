"""Deployment state management — track configs in ~/.config/agentcage/."""

from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path

import yaml

# Domain-syntax validator shared by host-side code paths (this module, the
# grants watcher's promote step in cli.py). Kept in sync with the in-container
# copy in data/proxy/policy_api.py (_DOMAIN_RE) — the addon cannot import this
# module, so the regex is deliberately duplicated. It is the gate that stops
# overlay strings (which cross the trust boundary via the grants dir) from
# being rendered into dnsmasq directives unvalidated: a value containing '\n'
# or '/' would emit extra ``server=`` lines in dns-allowlist.conf.
from agentcage.config import Config, DOMAIN_RE, load_config, valid_domain  # noqa: F401

__all__ = ["DOMAIN_RE", "valid_domain"]

_CONFIG_DIR = Path(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
) / "agentcage"
_DEPLOYMENTS_DIR = _CONFIG_DIR / "cages"


def _deploy_dir(name: str) -> Path:
    return _DEPLOYMENTS_DIR / name


def deployment_dir(name: str) -> Path:
    """Return the state directory for a deployment."""
    return _deploy_dir(name)


def deployment_exists(name: str) -> bool:
    return (_deploy_dir(name) / "cage.yaml").is_file()


def save_deployment(name: str, config_path: str) -> None:
    """Copy a config file into the state directory for a deployment."""
    d = _deploy_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy2(config_path, d / "cage.yaml")


def remove_deployment(name: str) -> None:
    """Remove the state directory for a deployment."""
    d = _deploy_dir(name)
    if d.is_dir():
        shutil.rmtree(d)


def load_deployment_config(name: str) -> Config:
    """Load the stored config for a deployment."""
    p = _deploy_dir(name) / "cage.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"No stored config for deployment '{name}'")
    return load_config(str(p))


def stored_config_path(name: str) -> str:
    """Return the absolute path to the stored config for a deployment."""
    return str(_deploy_dir(name) / "cage.yaml")


def list_deployments() -> list[str]:
    """Return names of all deployments with stored config."""
    if not _DEPLOYMENTS_DIR.is_dir():
        return []
    return sorted(
        d.name
        for d in _DEPLOYMENTS_DIR.iterdir()
        if d.is_dir() and (d / "cage.yaml").is_file()
    )


def load_raw_config(name: str) -> dict:
    """Load stored config as raw dict (preserves all fields)."""
    p = _deploy_dir(name) / "cage.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"No stored config for cage '{name}'")
    with open(p) as f:
        return yaml.safe_load(f) or {}


def _atomic_write_text(p: Path, text: str) -> None:
    """Atomically write *text* to *p* via a PID-suffixed temp + rename.

    The temp lives in the same directory (so ``os.replace`` is atomic on a
    single filesystem) and is opened with ``O_CREAT | O_EXCL`` so a planted
    symlink at the temp path cannot be written through. The base temp name
    is PID-suffixed (``<p>.<pid>.tmp``); the host watcher and any ``cage
    update`` / ``domain add`` run on the host, and the in-container addon
    runs in a different PID namespace (or on a different host), so the two
    sides normally never collide on the same numeric PID.

    On ``FileExistsError`` (a leftover temp from a crashed writer, OR —
    because PID namespaces share a numeric space — a *different* writer's
    in-flight temp at the same numeric PID) the writer does NOT unlink the
    colliding temp: unlinking a concurrent writer's in-flight file would
    make its later rename fail (a lost write). Instead it retries ONCE
    with a counter-suffixed name (``<p>.<pid>.1.tmp``); a concurrent writer
    using the same base cannot be using the counter-suffixed name unless it
    too collided, in which case its own counter differs (or both abort —
    neither loses its write). If the retry also hits ``FileExistsError`` the
    write is aborted (never write through / delete an existing file). This
    never deletes anything. The final ``tmp.replace(p)`` is the atomic
    publish.

    Used by ``save_raw_config``, ``save_metadata``, and ``save_grants`` so
    the 1Hz host-side grants watcher (and any concurrent ``cage update`` /
    ``domain add``) never observes a half-written file: it sees either the
    old contents or the new contents, never a truncated prefix that would
    raise YAMLError / JSONDecodeError and kill the watcher loop.
    """
    p.parent.mkdir(parents=True, exist_ok=True)
    base = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    # Base PID-suffixed name, then a single counter-suffixed retry. We never
    # unlink a colliding temp: a cross-PID-namespace numeric-PID collision
    # means the base name may be ANOTHER writer's in-flight file.
    candidates = (base, p.with_name(f"{p.name}.{os.getpid()}.1.tmp"))
    fd = None
    tmp = base
    for tmp in candidates:
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            break
        except FileExistsError:
            continue
    if fd is None:
        # Both names exist — abort rather than unlink a possible concurrent
        # writer's in-flight temp.
        raise FileExistsError(
            f"cannot create atomic temp for {p}: both {candidates[0].name} "
            f"and {candidates[1].name} exist"
        )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    tmp.replace(p)


def save_raw_config(name: str, raw: dict) -> None:
    """Write raw config dict back to state dir (atomically).

    See :func:`_atomic_write_text` for why this is temp+rename rather than a
    bare ``open(p, "w")``: the grants watcher and ``cage update`` can read
    ``cage.yaml`` mid-write and die on a truncated YAML.
    """
    p = _deploy_dir(name) / "cage.yaml"
    _atomic_write_text(
        p, yaml.safe_dump(raw, default_flow_style=False, sort_keys=False))


def fill_placeholders(name: str, prev_raw: dict | None = None) -> bool:
    """Fill omitted secret-injection placeholders in a stored cage.yaml.

    Persists a generated entropic token for every rule that omits
    ``placeholder:`` (see :func:`agentcage.config.fill_raw_placeholders`).
    Returns True if the stored config was rewritten — callers must then
    reload their Config so downstream rendering sees the filled values.
    Note: rewriting goes through yaml.safe_dump and drops YAML comments;
    this only happens when at least one rule actually omits a placeholder.
    """
    from agentcage.config import fill_raw_placeholders
    raw = load_raw_config(name)
    if fill_raw_placeholders(raw, prev_raw):
        save_raw_config(name, raw)
        return True
    return False


# Keys from cage.yaml that the proxy addon actually reads
_PROXY_KEYS = frozenset({
    "domains", "secrets", "max_request_body", "entropy", "content_type",
    "inspectors", "rate_limit", "logging", "secret_injection", "capture",
    "protocol_relays",
})


_DATA_DIR = Path(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
) / "agentcage"


def capture_dir(name: str) -> Path:
    """Return (and create) ~/.local/share/agentcage/<name>/capture/."""
    d = _DATA_DIR / name / "capture"
    d.mkdir(parents=True, exist_ok=True)
    return d


def capture_file(name: str) -> Path:
    """Return path to capture.jsonl for a cage."""
    return capture_dir(name) / "capture.jsonl"


# ── Policy API grants overlay ──────────────────────────────
# The egress addon writes runtime domain grants to a YAML list file on a
# per-cage writable volume (see docs/explain/policy-api.md §3.4). The
# volume is bind-mounted from this host path (container + vm backends) so
# the host-side ``cage grants`` CLI can read/promote/revoke without exec-
# ing into the egress. Format — a top-level YAML list of entries:
#
#   - domain: registry.npmjs.org
#     granted_at: "2026-06-01T12:00:00+00:00"
#     expires_at: "2026-06-01T13:00:00+00:00"   # optional, empty = no expiry
#     reason: npm install requested
#     source: policy-hook
#
# The addon owns writes at runtime; the host CLI's revoke does a
# read-modify-write with atomic rename. Concurrent writers are bounded by
# the per-cage request rate limit; last-writer-wins on the rare overlap.


def cage_data_dir(name: str) -> Path:
    """Return (and create) ~/.local/share/agentcage/<name>/.

    The per-cage data root: grants/, capture/, policy-audit.jsonl, and
    watcher logs live under it.
    """
    d = _DATA_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def grants_dir(name: str) -> Path:
    """Return (and create) ~/.local/share/agentcage/<name>/grants/."""
    d = _DATA_DIR / name / "grants"
    d.mkdir(parents=True, exist_ok=True)
    return d


def grants_file(name: str) -> Path:
    """Return the path to the policy-api grants overlay for a cage."""
    return grants_dir(name) / "grants.yaml"


def load_grants(name: str) -> list[dict]:
    """Read the grants overlay as a list of entry dicts (empty if absent).

    ``ValueError`` covers ``UnicodeDecodeError`` (a subclass) raised by
    ``read_text`` / ``yaml.safe_load`` when the overlay file is non-UTF8
    garbage — a too-narrow catch (``OSError`` + ``YAMLError`` alone) lets it
    escape and crash the host-side grants watcher loop (and any ``cage
    grants`` CLI) permanently. Treat any unreadable overlay as empty.
    Mirrors the in-container twin ``policy_api._load_overlay``.
    """
    p = grants_file(name)
    if not p.is_file():
        return []
    try:
        data = yaml.safe_load(p.read_text())
    except (OSError, yaml.YAMLError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict) and e.get("domain")]


def save_grants(name: str, entries: list[dict]) -> None:
    """Atomically write the grants overlay (temp file + rename).

    The temp file name embeds the writer's PID so the host-side watcher and
    the in-container addon (separate PID namespaces) can each write their
    own temp concurrently without clobbering each other's file — the
    resolved final path is shared, but the temps never collide. The temp is
    opened with ``O_EXCL`` (see :func:`_atomic_write_text`) so a planted
    symlink can't be written through.
    """
    p = grants_file(name)
    _atomic_write_text(
        p, yaml.safe_dump(entries, default_flow_style=False, sort_keys=False))


def policy_audit_file(name: str) -> Path:
    """Per-cage Policy-API audit log (JSONL) — a SIBLING of the grants dir.

    The egress addon writes its own ``audit.jsonl`` (decisions, inspector
    verdicts) inside the container. The host-side grants watcher mutates
    the static baseline (``domain add``/``rm`` equivalent) — those mutations
    are operator-visible as stdout, but a structured record belongs here so
    the forensic trail of *which grant was applied/removed when and by whom*
    is greppable alongside the overlay that drove it.

    This file MUST NOT live inside ``grants_dir(name)``: that directory is
    writable by the egress container (group-shared with the operator via
    the podman user-namespace mapping — 0770 on the container backend,
    0777 on the apple backend) and is bind-mounted read-write into the
    egress container (``egress.container.j2``). A file inside it would
    therefore be readable, forgeable, and TRUNCATABLE by the caged agent's
    container side — a host forensic trail cannot be editable by the thing
    it is auditing. So it sits one level up, at
    ``~/.local/share/agentcage/<name>/policy-audit.jsonl``
    (a sibling of the ``grants/`` subdirectory), outside the bind mount.
    """
    return _DATA_DIR / name / "policy-audit.jsonl"


def append_policy_audit(name: str, entry: dict) -> None:
    """Append a structured JSON audit entry for a Policy-API baseline change.

    Each entry carries a ``ts`` (UTC ISO) and a ``kind`` so it composes with
    the egress audit schema (``policy_grant_applied`` / ``policy_grant_removed``).
    Best-effort: a write failure is swallowed (audit is defense-in-depth,
    never a reason to fail a grant promotion).
    """
    from datetime import datetime, timezone
    entry = {"ts": datetime.now(timezone.utc).isoformat(), **entry}
    try:
        # Ensure the audit file's parent exists. It is a SIBLING of the
        # grants dir (outside the container-writable + RW bind mount — see
        # policy_audit_file), so grants_dir's own mkdir does not cover it.
        policy_audit_file(name).parent.mkdir(parents=True, exist_ok=True)
        with open(policy_audit_file(name), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def save_metadata(name: str, metadata: dict) -> None:
    """Write metadata.json to the deployment state directory (atomically).

    Atomic (temp + rename via :func:`_atomic_write_text`) so the grants
    watcher and any concurrent ``cage update`` never read a half-written
    JSON file and die on ``JSONDecodeError``.
    """
    d = _deploy_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(d / "metadata.json", json.dumps(metadata))


def load_metadata(name: str) -> dict:
    """Read metadata.json for a deployment, returning {} if missing."""
    p = _deploy_dir(name) / "metadata.json"
    if not p.is_file():
        return {}
    with open(p) as f:
        return json.load(f)


def save_fingerprint(name: str, fingerprint: dict) -> None:
    """Atomically persist the last successful update fingerprint."""
    d = _deploy_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "fingerprint.json"
    temporary = d / "fingerprint.json.tmp"
    temporary.write_text(json.dumps(fingerprint, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def load_fingerprint(name: str) -> dict | None:
    """Load a deployment fingerprint, treating missing/corrupt state as stale."""
    path = _deploy_dir(name) / "fingerprint.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def save_proxy_config(name: str) -> str:
    """Write a proxy-specific config subset and return its path.

    Strips container, dns_servers, name, and other keys that the proxy
    does not need, so the full config is not exposed inside the proxy container.

    Also refreshes ``cage-env/placeholders.env`` (see
    :func:`save_placeholders_env`) — both files are cage.yaml-derived state
    the containers mount, and every deploy/restart path that needs one
    needs the other, so they are regenerated together to stay in lockstep.
    """
    raw = load_raw_config(name)
    proxy_cfg = {k: v for k, v in raw.items() if k in _PROXY_KEYS}
    # deepcopy: the ca_file -> ca_pem rewrite must not leak back into the
    # in-memory raw config (and from there into a cage.yaml rewrite),
    # which would replace the operator's path with a wall of PEM.
    proxy_cfg = resolve_relay_ca_files(copy.deepcopy(proxy_cfg))
    # Stamp the version so the Policy API's introspection payloads can
    # report it without depending on AGENTCAGE_VERSION reaching the
    # egress environment (it is not set there on every backend).
    try:
        from importlib.metadata import version as _v
        proxy_cfg["agentcage_version"] = _v("agentcage")
    except Exception:
        pass
    p = _deploy_dir(name) / "proxy-config.yaml"
    with open(p, "w") as f:
        yaml.safe_dump(proxy_cfg, f, default_flow_style=False, sort_keys=False)
    save_placeholders_env(name)
    return str(p)


def resolve_relay_ca_files(proxy_cfg: dict) -> dict:
    """Read each relay's ``upstream.ca_file`` and inline it as ``ca_pem``.

    The relay runs inside the proxy container, where a host path means
    nothing. Rather than bind-mount the file — which pins an inode, so a
    daemon that *replaces* its certificate on reinstall would be missed
    anyway, and which needs separate plumbing in the container, vm, and
    apple-container backends — the CLI reads it here and hands the proxy
    the contents. proxy-config.yaml is rewritten on every deploy and
    restart path, so a rotated certificate is picked up by
    ``cage restart`` with no config edit.

    Mutates and returns *proxy_cfg*. Raises ``ValueError`` with an
    actionable message if a declared file is missing or unreadable —
    failing at deploy beats a relay that cannot verify its upstream at
    3am and says only "certificate verify failed".
    """
    for relay in proxy_cfg.get("protocol_relays") or []:
        if not isinstance(relay, dict):
            continue
        upstream = relay.get("upstream")
        if not isinstance(upstream, dict):
            continue
        ca_file = upstream.pop("ca_file", "") or ""
        if not ca_file:
            continue
        path = Path(os.path.expanduser(os.path.expandvars(str(ca_file))))
        try:
            pem = path.read_text()
        except OSError as e:
            raise ValueError(
                f"protocol_relays[{relay.get('name', '?')}]."
                f"upstream.ca_file: cannot read {str(path)!r}: "
                f"{e.strerror or e}"
            ) from e
        if "-----BEGIN CERTIFICATE-----" not in pem:
            raise ValueError(
                f"protocol_relays[{relay.get('name', '?')}]."
                f"upstream.ca_file: {str(path)!r} holds no PEM certificate "
                f"(expected a '-----BEGIN CERTIFICATE-----' block)"
            )
        upstream["ca_pem"] = pem
    return proxy_cfg


def cage_env_dir(name: str) -> Path:
    """Host directory bind-mounted read-only into the cage at /run/agentcage/env.

    Holds only non-sensitive cage-facing derived files (placeholders are
    decoy tokens). A directory — not a single-file mount — so in-place
    rewrites always propagate regardless of inode churn. Path-only (no
    mkdir): quadlet rendering composes this path without side effects;
    :func:`save_placeholders_env` creates it on write.
    """
    return _deploy_dir(name) / "cage-env"


def placeholders_env_path(name: str) -> Path:
    """Path of the env-file holding the cage's placeholder variables."""
    return cage_env_dir(name) / "placeholders.env"


def save_placeholders_env(name: str) -> str:
    """Write ``ENV=PLACEHOLDER`` lines derived from the stored cage.yaml.

    The cage quadlet references this file via ``EnvironmentFile=`` (read by
    podman at container creation, so every restart — not just ``cage
    update`` — picks up placeholder changes) and bind-mounts its parent
    directory at ``/run/agentcage/env`` for in-cage consumers.

    Derived from the *raw* stored config (not ``load_config``) so it works
    in contexts where full validation would fail, mirroring
    ``save_proxy_config``. Rules without a placeholder are skipped — the
    CLI fills omitted placeholders at declare time. Written in place (no
    rename) so bind mounts keep tracking the same inode.
    """
    raw = load_raw_config(name)
    si = raw.get("secret_injection") or []
    rules = si.get("rules", []) if isinstance(si, dict) else si
    lines = []
    for entry in rules if isinstance(rules, list) else []:
        if not isinstance(entry, dict):
            continue
        env, placeholder = entry.get("env"), entry.get("placeholder")
        if env and placeholder:
            lines.append(f"{env}={placeholder}")
    p = placeholders_env_path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        f.write("".join(line + "\n" for line in lines))
    return str(p)


def runtime_secrets_dir(name: str) -> Path:
    """Per-cage tmpfs staging dir for real secret values.

    Matches the ``%t/agentcage/<name>/secrets`` path the egress quadlet
    mounts (systemd expands ``%t`` to ``$XDG_RUNTIME_DIR``): the egress
    ``ExecStartPre`` stages declared secrets here at every start, and the
    proxy reads them via the bind mount at ``/home/acproxy/secrets``.
    tmpfs only — real values never touch persistent disk unencrypted.
    Mounted into the egress exclusively, never the cage.
    """
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    d = Path(base) / "agentcage" / name / "secrets"
    d.mkdir(parents=True, exist_ok=True)
    for sub in (d, d.parent, d.parent.parent):
        try:
            sub.chmod(0o700)
        except PermissionError:
            # Once the egress has started, the secrets dir is owned by the
            # acproxy subuid (the quadlet chowns it for in-container
            # readability) — the host user can no longer chmod it. Modes
            # were already set 0700 at creation (here or by the quadlet's
            # `umask 077; mkdir -p` ExecStartPre).
            break
    return d


def dns_allowlist_path(name: str) -> Path:
    """Return the host path of the dnsmasq sidecar's allowlist file.

    The dnsmasq quadlet mounts this file read-only at
    ``/etc/dnsmasq-allow.conf`` and reads it via ``--servers-file``. Decoupling
    the allowlist from the quadlet's command line means a domain change is
    just a file rewrite — no systemd unit churn, no daemon-reload.
    """
    return _deploy_dir(name) / "dns-allowlist.conf"


def save_dns_allowlist(name: str) -> str:
    """Write the dnsmasq allowlist file for *name* from its stored cage.yaml.

    The output is dnsmasq's ``--servers-file`` format: one ``server=/<domain>/<upstream>``
    line per (allowed-domain × upstream-server) pair. dnsmasq treats this as
    a partial config, additive to anything in the main quadlet command line,
    and re-reads it on container start (or SIGHUP). Returns the path written.

    Idempotent. Cheap. Always safe to call. Empty when the cage isn't in
    allowlist mode — dnsmasq is fine with an empty file.
    """
    from agentcage.quadlets import _effective_dns_allowlist
    cfg = load_deployment_config(name)
    p = dns_allowlist_path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"server=/{domain}/{srv}"
        for domain in _effective_dns_allowlist(cfg)
        for srv in cfg.dns_servers
    ]
    p.write_text("\n".join(lines) + ("\n" if lines else ""))
    return str(p)
