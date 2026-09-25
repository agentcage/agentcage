#!/usr/bin/env python3
"""Generate the committed on-disk state-compatibility fixtures.

Why this exists
---------------
The host CLI is being rewritten in Rust (see ``RUST-PORT-PLAN.md`` §2.7). At
cutover every existing user has cages that the *Python* CLI deployed, and the
Rust binary must read all of that state in place, on first run, with no
migration step. None of the on-disk state carries a schema version —
``metadata.json`` is a bare ``json.dumps(dict)``; there is no ``state_version``
field anywhere in ``state.py`` — so there is nothing to branch on. The Rust
readers simply have to accept exactly what the Python writers produce.

This script captures "exactly what the Python writers produce" by driving the
**real** ``agentcage`` code paths (``state.save_deployment``,
``state.save_proxy_config``, ``secret_store``, ``quadlets.generate_quadlets``,
the ``cage backup`` click command, …) inside a throwaway XDG sandbox, then
copying the resulting tree into ``tests/fixtures/state-compat/<version>/``.

Usage
-----
    uv run python scripts/gen-state-fixtures.py            # write the fixture
    uv run python scripts/gen-state-fixtures.py --out DIR  # write elsewhere
    uv run python scripts/gen-state-fixtures.py --check    # regenerate + diff

Determinism
-----------
Re-running this script on a clean tree must produce a byte-identical fixture.
Everything that would otherwise vary per run is frozen up front; see
``_freeze_nondeterminism`` and the ``SCRUB_*`` constants below. The one thing
that genuinely cannot be reproduced is a real ``systemd-creds`` blob (it is
host-bound), so a fixed opaque blob is substituted — see ``FROZEN_CRED_BLOB``.

Adding a new generation
-----------------------
Do **not** overwrite an existing ``tests/fixtures/state-compat/<version>/``
directory. Bump the package version and run this script again; the Rust side
is then tested against several generations of on-disk state.
"""

from __future__ import annotations

# ── XDG sandbox ────────────────────────────────────────────
# agentcage.state computes _CONFIG_DIR / _DATA_DIR at *import* time from
# XDG_CONFIG_HOME / XDG_DATA_HOME, and quadlets.generate_quadlets resolves
# volume sources against $HOME. So the sandbox has to be in place before the
# first ``import agentcage.*`` below — hence the module-level side effect.
import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

SANDBOX = Path(tempfile.mkdtemp(prefix="agentcage-state-fixture-"))
atexit.register(shutil.rmtree, SANDBOX, ignore_errors=True)

#: Every path under SANDBOX is rewritten to this token in the committed
#: fixture. Keeps the fixture free of this machine's tmpdir and of any
#: ``/home/<user>`` path, while staying realistic in shape.
SCRUB_HOME = "/home/agentcage-fixture"
#: XDG_RUNTIME_DIR is ``/run/user/<uid>`` in the wild; freeze the uid.
SCRUB_RUNTIME_DIR = "/run/user/1000"
#: Frozen uid/gid used anywhere a real one would be emitted.
SCRUB_UID = 1000

os.environ["HOME"] = str(SANDBOX)
os.environ["XDG_CONFIG_HOME"] = str(SANDBOX / ".config")
os.environ["XDG_DATA_HOME"] = str(SANDBOX / ".local" / "share")
os.environ["XDG_RUNTIME_DIR"] = str(SANDBOX / "run-user")
os.environ["XDG_STATE_HOME"] = str(SANDBOX / ".local" / "state")
# A couple of configs below reference ${WORKSPACE_ROOT}; pin it so expansion
# does not depend on the invoking shell.
os.environ["WORKSPACE_ROOT"] = str(SANDBOX / "workspace")
for _sub in (".config", ".local/share", ".local/state", "run-user", "workspace"):
    (SANDBOX / _sub).mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import argparse  # noqa: E402
import datetime as _datetime  # noqa: E402
import gzip  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import tarfile  # noqa: E402
import textwrap  # noqa: E402
from unittest import mock  # noqa: E402

import yaml  # noqa: E402

# ── Frozen values ──────────────────────────────────────────

#: Wall clock for every ``datetime.now()`` in the generated state.
FROZEN_NOW = _datetime.datetime(2026, 3, 14, 15, 9, 26, tzinfo=_datetime.timezone.utc)
#: Hex suffix minted for secret_injection rules that omit ``placeholder:``.
#: The real code path is ``config.generate_placeholder`` →
#: ``secrets.token_hex(16)``; only the entropy source is frozen.
FROZEN_TOKEN_HEX = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
#: Subnet octet. Normally hash-derived from the cage name (which *is* stable),
#: but pinned explicitly so a future change to the hash cannot silently
#: invalidate a committed fixture.
FROZEN_NETWORK_OCTET = 137

#: A real ``systemd-creds --user encrypt`` blob, captured once and frozen.
#:
#: IMPORTANT: systemd-creds encryption is host-bound (host key / TPM2 / per-user
#: key). This blob's *contents* cannot be decrypted on any other machine — not
#: in CI, not on a developer's laptop, not by the Rust port. Only its
#: *presence*, filename, and byte shape may be asserted. It is included because
#: ``creds/<key>.cred`` is part of the state surface a Rust reader has to
#: enumerate (see ``SystemdCredsStore.delete`` and the quadlet's
#: ``LoadCredentialEncrypted=``), and its absence would hide that from the
#: fixture. The plaintext that was encrypted was the obviously-fake
#: ``TEST-NOT-A-REAL-SECRET-0001``.
FROZEN_CRED_BLOB = (
    "VbntHThZTUOoMZ0uuzMqxiAAAAABAAAADAAAABAAAAAKvioxUKCYliE4sqkAAAAABwAAAAAAAADyqKA\n"
    "z8o0qjY1cN3RzAa5DP6/cl74agFsBKT5IKHHkXzDVAkubdokKzMjOW/wxDn4XPK5z\n"
)

#: Never a real credential. Every value that stands in for a secret is one of
#: these, so a grep for real key material over the fixture comes back empty.
FAKE_SECRETS = {
    "ANTHROPIC_API_KEY": "TEST-NOT-A-REAL-SECRET-0001",
    "OPENROUTER_API_KEY": "TEST-NOT-A-REAL-SECRET-0002",
    "GITHUB_TOKEN": "TEST-NOT-A-REAL-SECRET-0003",
    "IMAP_PASSWORD": "TEST-NOT-A-REAL-SECRET-0004",
}

#: A fake CA the relay's ``upstream.ca_file`` points at. ``save_proxy_config``
#: inlines it as ``ca_pem``, so the fixture captures that rewrite.
FAKE_CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "TEST-NOT-A-REAL-CERTIFICATE-0001\n"
    "-----END CERTIFICATE-----\n"
)

RICH_CAGE = "acme-agent"
MINIMAL_CAGE = "plain-cage"
#: A macOS-shaped cage. Its per-cage state does NOT live under
#: ``$XDG_CONFIG_HOME/agentcage/cages/`` — ``AppleContainerBackend._state_dir``
#: puts it at ``~/.config/agentcage/apple-container/<name>/``, with the addon's
#: ``audit.jsonl`` / ``capture.jsonl`` in a ``logs/`` subdirectory. That is a
#: third state root, and RUST-PORT-PLAN.md §2.7's table does not mention it.
APPLE_CAGE = "mac-agent"


def _freeze_nondeterminism() -> None:
    """Replace every per-run-varying source with a fixed value.

    Both writers below do a *late* ``from datetime import datetime`` inside the
    function body (``state.append_policy_audit``) as well as a module-level
    ``import datetime`` (``cli``), so the clock is frozen by rebinding the
    attribute on the stdlib module itself rather than by patching call sites.
    This process is a throwaway generator; the mutation never escapes it.
    """
    real_datetime = _datetime.datetime

    class _FrozenDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return FROZEN_NOW.astimezone(_datetime.timezone.utc).replace(tzinfo=None)
            return FROZEN_NOW.astimezone(tz)

        @classmethod
        def utcnow(cls):
            return FROZEN_NOW.replace(tzinfo=None)

        @classmethod
        def today(cls):
            return cls.now()

    _datetime.datetime = _FrozenDatetime

    # Placeholder entropy. ``config.generate_placeholder`` does a *function
    # local* ``import secrets as _secrets``, so there is no module attribute
    # to patch — freeze the stdlib entry point itself, same as the clock
    # above, and leave the real format string exercised.
    import secrets as _stdlib_secrets

    _stdlib_secrets.token_hex = lambda n=32: FROZEN_TOKEN_HEX[: n * 2]


# ── Configs ────────────────────────────────────────────────


def rich_cage_yaml() -> str:
    """A config rich enough to cover every interesting on-disk shape.

    Multiple domains (allow / block / passthrough / expires), secrets from
    more than one source (``env:``, ``systemd-creds:``, and one rule that
    omits ``placeholder:`` so a token is minted), a protocol relay with a
    ``ca_file`` that ``save_proxy_config`` inlines, capture enabled, and both
    agents configured.
    """
    return textwrap.dedent(
        f"""\
        # agentcage state-compatibility fixture — generated, do not hand-edit.
        name: {RICH_CAGE}
        isolation: container
        lifecycle: service
        scaffold: claude-code

        container:
          image: "docker.io/library/node:22-slim"
          command: ["node", "/app/agent.js"]
          user: "1000:1000"
          read_only: true
          no_new_privileges: true
          drop_capabilities: ["ALL"]
          add_capabilities: []
          memory: "4g"
          cpus: "2.0"
          volumes:
            - "${{WORKSPACE_ROOT}}/src:/workspace:rw"
            - "${{WORKSPACE_ROOT}}/ro-assets:/assets:ro"
          named_volumes:
            acme-agent-npm: "/home/node/.npm:rw"
          tmpfs:
            - "/tmp:rw,noexec,nosuid,size=64M"
          env:
            NODE_ENV: "production"
            AGENT_PROFILE: "fixture"
          ports:
            - "127.0.0.1:18080:3000"
          nested_containers: false
          restart: "on-failure"
          restart_sec: 10
          timeout_start_sec: 300
          timeout_stop_sec: 60

        dns_servers:
          - 1.1.1.1
          - 9.9.9.9

        domains:
          mode: allowlist
          allow:
            - api.anthropic.com
            - github.com
            - "*.githubusercontent.com"
            - registry.npmjs.org
            - openrouter.ai
          block:
            - telemetry.example.com
          passthrough:
            - pinned-api.example.com
          expires:
            temp-download.example.com: "2026-09-08T18:00:00Z"

        ports:
          tcp:
            allow: [80, 443, 993]
            passthrough: []
          udp:
            allow: []
          icmp:
            allow: false

        secrets:
          backend: systemd-creds
          scope: user
          allow_plaintext: false

        secret_injection:
          - env: ANTHROPIC_API_KEY
            placeholder: "agentcage:secret:ANTHROPIC_API_KEY:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            inject_to:
              - api.anthropic.com
            inject_headers:
              - x-api-key
            inject_body: false
            source: "systemd-creds:ANTHROPIC_API_KEY"
          - env: GITHUB_TOKEN
            placeholder: "agentcage:secret:GITHUB_TOKEN:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            inject_to:
              - github.com
              - "*.githubusercontent.com"
            inject_headers:
              - authorization
            inject_body: false
            source: "env:FIXTURE_GITHUB_TOKEN"
          # placeholder omitted on purpose: fill_placeholders mints one and
          # rewrites cage.yaml, which is itself part of the state contract.
          - env: IMAP_PASSWORD
            inject_to:
              - imap.example.com
            inject_body: true

        agents:
          decider:
            enable: true
            provider: openrouter
            model: "z-ai/glm-5.3"
            api_key: "systemd-creds:OPENROUTER_API_KEY"
            context: >
              Fixture cage. Approve official package registries only.
            rate_limit_rps: 2.0
            rate_limit_burst: 5
          watcher:
            enable: true
            provider: openrouter
            model: "z-ai/glm-5.3"
            api_key: "systemd-creds:OPENROUTER_API_KEY"
            interval_seconds: 300
            window_seconds: 600
            max_flows: 100
            auto_revoke: true
            dedup_samples: true
            max_digest_tokens: 8000
            context: >
              Fixture cage. Flag encoded source code in request bodies.

        protocol_relays:
          - name: mail
            type: imap
            listen: "0.0.0.0:1143"
            upstream:
              host: imap.example.com
              port: 993
              tls: true
              tls_servername: imap.example.com
              ca_file: "~/fixture-ca.pem"
            policy:
              write_mode: organise
              folder_allowlist: ["INBOX", "Archive"]
              folder_denylist: ["Trash"]
            auth:
              user: "agent@example.com"
              password_source: "systemd-creds:IMAP_PASSWORD"

        capture:
          enable_har: true
          max_body_size: 1048576
          max_file_size: 104857600
          min_action: allowed
          domains: []
          exclude_domains:
            - registry.npmjs.org

        logging:
          level: info
          dns_queries: true
          proxy_connections: true
          allowed_requests: false

        max_request_body: 10485760

        exec_aliases:
          claude: ["claude", "--print"]

        help: |
          Fixture cage used by the state-compatibility test suite.
        """
    )


def minimal_cage_yaml() -> str:
    """The other end of the range: everything defaulted."""
    return textwrap.dedent(
        f"""\
        name: {MINIMAL_CAGE}
        container:
          image: "localhost/plain:latest"
        dns_servers:
          - 1.1.1.1
        """
    )


# ── Generation ─────────────────────────────────────────────


def _write_source_configs() -> dict[str, Path]:
    src = SANDBOX / "src-configs"
    src.mkdir(parents=True, exist_ok=True)
    (SANDBOX / "fixture-ca.pem").write_text(FAKE_CA_PEM)
    for sub in ("src", "ro-assets"):
        (SANDBOX / "workspace" / sub).mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, body in (
        (RICH_CAGE, rich_cage_yaml()),
        (MINIMAL_CAGE, minimal_cage_yaml()),
        (APPLE_CAGE, apple_cage_yaml()),
    ):
        p = src / f"{name}.yaml"
        p.write_text(body)
        paths[name] = p
    return paths


def _generate_cage_state(name: str, config_path: Path, *, rich: bool) -> None:
    """Drive the real writers for one cage."""
    from agentcage import state
    from agentcage.backends.container import ContainerBackend  # noqa: F401  (import check)

    state.save_deployment(name, str(config_path))
    # Mints and persists a placeholder for any rule that omitted one — this
    # rewrites cage.yaml through yaml.safe_dump, which is itself the shape a
    # Rust reader sees for any cage that has ever been updated.
    state.fill_placeholders(name)

    from importlib.metadata import version as _pkg_version

    metadata = {"agentcage_version": _pkg_version("agentcage")}
    if rich:
        metadata["scaffold"] = "claude-code"
    # services.py stamps the assigned subnet octet after install_units.
    metadata["network_octet"] = FROZEN_NETWORK_OCTET
    state.save_metadata(name, metadata)

    config_host_path = state.save_proxy_config(name)  # also writes placeholders.env
    state.save_dns_allowlist(name)

    if not rich:
        return

    # ── Secret stores ──────────────────────────────────────
    from agentcage import secret_resolver
    from agentcage.secret_store import ApplePlaintextStore, KeychainStore, SystemdCredsStore

    deploy_dir = state.deployment_dir(name)

    def _frozen_encrypt(key: str, value: str, state_dir: Path, scope: str = "system") -> Path:
        # Real path construction, frozen ciphertext (see FROZEN_CRED_BLOB).
        creds = Path(state_dir) / "creds"
        creds.mkdir(parents=True, exist_ok=True)
        out = creds / f"{key}.cred"
        out.write_text(FROZEN_CRED_BLOB)
        return out

    with mock.patch.object(secret_resolver, "encrypt_secret", _frozen_encrypt):
        store = SystemdCredsStore(scope="user", podman=None)
        for key in ("ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "IMAP_PASSWORD"):
            store.set(name, key, FAKE_SECRETS[key], state_dir=deploy_dir)

    # macOS keychain name index. ``KeychainStore.set`` would shell out to
    # security(1), which does not exist here; the index writer is the part
    # that lands on disk, so drive that directly.
    kc = KeychainStore()
    for key in ("ANTHROPIC_API_KEY", "GITHUB_TOKEN"):
        kc._index_add(deploy_dir, key)

    # Legacy cleartext store (apple-container / VM hand-off). Format is a
    # JSON *array of [key, value] pairs*, not an object — see
    # ``ApplePlaintextStore._save`` and ``vm._create_pending_secrets``.
    ap = ApplePlaintextStore()
    ap.set(name, "GITHUB_TOKEN", FAKE_SECRETS["GITHUB_TOKEN"], state_dir=deploy_dir)

    # ── Grants overlay + policy audit ──────────────────────
    state.save_grants(
        name,
        [
            {
                "domain": "files.pythonhosted.org",
                "granted_at": "2026-03-14T15:00:00+00:00",
                "expires_at": "2026-03-14T16:00:00+00:00",
                "reason": "pip install requested by the decider",
                "source": "policy-hook",
            },
            {
                "domain": "objects.githubusercontent.com",
                "granted_at": "2026-03-14T15:04:00+00:00",
                "expires_at": "",
                "reason": "release asset download",
                "source": "operator",
            },
        ],
    )
    state.append_policy_audit(
        name,
        {
            "kind": "policy_grant_applied",
            "domain": "files.pythonhosted.org",
            "actor": "fixture",
            "reason": "pip install requested by the decider",
        },
    )
    state.append_policy_audit(
        name,
        {
            "kind": "policy_grant_removed",
            "domain": "stale.example.com",
            "actor": "fixture",
            "reason": "expired",
        },
    )

    # ── Egress-written capture log ─────────────────────────
    # capture.jsonl crosses the trust boundary the other way: the
    # in-container addon writes it, the host CLI (``cage har``) reads it.
    # Produced here by the *real* in-container writer.
    #
    # Note there is deliberately no ``audit.jsonl`` beside it. On the
    # container and vm backends the addon's audit trail goes to *stderr* and
    # the host reads it back out of journalctl — there is no host-side audit
    # file at all. Only apple-container has one, under its own state root;
    # see APPLE_CAGE.
    _write_capture_jsonl(state.capture_file(name))

    # ── Rendered quadlets ──────────────────────────────────
    from agentcage.quadlets import cage_network_addrs, generate_quadlets
    from agentcage.services import write_resolv_files, patches_work_dir

    cfg = state.load_deployment_config(name)
    patches = patches_work_dir()
    addrs = cage_network_addrs(name, network_octet=FROZEN_NETWORK_OCTET)
    write_resolv_files(patches, name, addrs["ip_egress"], cfg.dns_servers)
    units = generate_quadlets(
        cfg,
        config_host_path,
        patches,
        name,
        rootless=True,
        network_octet=FROZEN_NETWORK_OCTET,
        store_secrets={"ANTHROPIC_API_KEY", "GITHUB_TOKEN", "IMAP_PASSWORD"},
    )
    # Mirrors ContainerBackend.install_units: quadlet types go to the quadlet
    # dir, plain .service units to the systemd-user dir. Each directory is
    # created only when something lands in it — an empty one cannot be
    # committed (see _copy_tree), and today no .service unit is emitted.
    unit_dir = SANDBOX / ".config" / "containers" / "systemd"
    user_unit_dir = SANDBOX / ".config" / "systemd" / "user"
    for filename, content in units.items():
        dest = user_unit_dir if filename.endswith(".service") else unit_dir
        dest.mkdir(parents=True, exist_ok=True)
        (dest / filename).write_text(content)

    # ── Fingerprint ────────────────────────────────────────
    # Fed the *scrubbed* inputs. ``compute_fingerprint`` hashes content, and
    # cage.yaml and the rendered units both carry absolute host paths, so
    # hashing the sandbox's own text would produce a different digest on
    # every run. Scrubbing first is exactly what a real operator whose home
    # is ``SCRUB_HOME`` would get — the real hash of the committed bytes.
    from agentcage.fingerprint import compute_fingerprint

    scrubbed_units = {k: _scrub(v) for k, v in units.items()}
    fp = compute_fingerprint(
        yaml.safe_load(_scrub(
            (state.deployment_dir(name) / "cage.yaml").read_text())) or {},
        resolved_config=yaml.safe_load(
            _scrub(Path(config_host_path).read_text())) or {},
        units=scrubbed_units,
        image_digests={
            "cage": "sha256:" + "11" * 32,
            "egress": "sha256:" + "22" * 32,
        },
        scaffold_version="deadbeef" * 8,
    )
    state.save_fingerprint(name, fp)


def _generate_apple_cage_state(name: str, config_path: Path) -> None:
    """Capture the macOS-shaped state tree.

    ``apple-container`` keeps its per-cage runtime state somewhere else
    entirely — ``~/.config/agentcage/apple-container/<name>/`` — while the
    cage's config still lives in the normal deployments dir. The addon's
    ``audit.jsonl`` and ``capture.jsonl`` are bind-mounted out of the egress
    microVM into a ``logs/`` subdirectory there, and that is where ``cage
    audit`` / ``cage har`` read them from on a Mac.
    """
    from agentcage import state
    from agentcage.backends.apple_container import AppleContainerBackend
    from agentcage.secret_store import ApplePlaintextStore, KeychainStore

    state.save_deployment(name, str(config_path))
    state.fill_placeholders(name)

    from importlib.metadata import version as _pkg_version

    state.save_metadata(name, {"agentcage_version": _pkg_version("agentcage")})
    state.save_proxy_config(name)
    state.save_dns_allowlist(name)

    deploy_dir = state.deployment_dir(name)
    # On macOS the keychain is the encrypting store, so the only host-side
    # artifact is the non-secret name index.
    kc = KeychainStore()
    for key in ("ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"):
        kc._index_add(deploy_dir, key)
    ApplePlaintextStore().set(
        name, "GITHUB_TOKEN", FAKE_SECRETS["GITHUB_TOKEN"], state_dir=deploy_dir,
    )

    logs = AppleContainerBackend().logs_dir(name)
    logs.mkdir(parents=True, exist_ok=True)
    _write_audit_jsonl(logs / "audit.jsonl")
    _write_capture_jsonl(logs / "capture.jsonl")
    # The supervisor's readiness marker and dnsmasq's own log sit alongside.
    (logs / "ready").write_text("")
    (logs / "dnsmasq.log").write_text(
        "Mar 14 15:09:26 dnsmasq[1]: started, version 2.90\n"
        "Mar 14 15:09:26 dnsmasq[1]: using nameserver 1.1.1.1#53 "
        "for domain api.anthropic.com\n"
    )


def apple_cage_yaml() -> str:
    return textwrap.dedent(
        f"""\
        name: {APPLE_CAGE}
        isolation: apple-container
        container:
          image: "docker.io/library/node:22-slim"
          volumes:
            - "${{WORKSPACE_ROOT}}/src:/workspace:rw"
        dns_servers:
          - 1.1.1.1
        domains:
          mode: allowlist
          allow:
            - api.anthropic.com
        secrets:
          backend: keychain
        secret_injection:
          - env: ANTHROPIC_API_KEY
            inject_to:
              - api.anthropic.com
            inject_headers:
              - x-api-key
        capture:
          enable_har: true
        """
    )


def _proxy_pkg_path() -> None:
    """Put the in-container proxy package on sys.path.

    ``data/proxy`` ships inside the egress image where it is imported as a
    top-level package (``capture``, ``addon``, …), so that is how it has to
    be imported here too — same as pytest's ``pythonpath`` setting.
    """
    proxy = Path(__file__).resolve().parent.parent / "src" / "agentcage" / "data" / "proxy"
    if str(proxy) not in sys.path:
        sys.path.insert(0, str(proxy))


def _stub_mitmproxy() -> None:
    """Stub mitmproxy so ``addon`` imports on a host without the proxy deps.

    Mirrors ``tests/conftest.py``. Only the import graph is stubbed; the
    audit serializer that actually produces ``audit.jsonl`` is the real one.
    """
    import types
    from unittest.mock import MagicMock

    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.__path__ = []
    mitmproxy.ctx = MagicMock()
    mitmproxy.http = MagicMock()
    proxy = types.ModuleType("mitmproxy.proxy")
    proxy.__path__ = []
    mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
    mode_specs.ReverseMode = MagicMock()
    mitmproxy.proxy = proxy
    proxy.mode_specs = mode_specs
    for mod, obj in (
        ("mitmproxy", mitmproxy),
        ("mitmproxy.ctx", mitmproxy.ctx),
        ("mitmproxy.http", mitmproxy.http),
        ("mitmproxy.proxy", proxy),
        ("mitmproxy.proxy.mode_specs", mode_specs),
    ):
        sys.modules.setdefault(mod, obj)


def _write_capture_jsonl(path: Path) -> None:
    """Produce ``capture.jsonl`` through the real ``CaptureWriter``.

    The request/response snapshots are shaped exactly as
    ``CaptureWriter.snapshot_request`` / ``snapshot_response`` emit them
    (headers as ``[[name, value], …]`` pairs, ``bodyEncoding``, ``bodySize``);
    building them from a live mitmproxy flow would need the proxy runtime,
    but the JSONL serialization — which is the actual format contract — is
    the writer's own.
    """
    _proxy_pkg_path()
    from capture import CaptureWriter  # type: ignore[import-not-found]

    writer = CaptureWriter(
        {
            "max_body_size": 1048576,
            "max_file_size": 104857600,
            "min_action": "all",
            "domains": [],
            "exclude_domains": [],
        },
        str(path),
    )

    inbound_req = {
        "method": "POST",
        "url": "https://api.anthropic.com/v1/messages",
        "httpVersion": "HTTP/1.1",
        "headers": [
            ["host", "api.anthropic.com"],
            ["content-type", "application/json"],
            ["x-api-key",
             "agentcage:secret:ANTHROPIC_API_KEY:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        ],
        "body": '{"model":"claude","max_tokens":16}',
        "bodyEncoding": None,
        "bodySize": 34,
    }
    # The outbound view is the wire view: the placeholder has been replaced
    # by the real value. In this fixture the "real value" is a fake.
    outbound_req = dict(inbound_req)
    outbound_req["headers"] = [
        ["host", "api.anthropic.com"],
        ["content-type", "application/json"],
        ["x-api-key", FAKE_SECRETS["ANTHROPIC_API_KEY"]],
    ]
    resp = {
        "status": 200,
        "statusText": "OK",
        "httpVersion": "HTTP/1.1",
        "headers": [["content-type", "application/json"]],
        "body": '{"id":"msg_fixture","type":"message"}',
        "bodyEncoding": None,
        "bodySize": 37,
        "mimeType": "application/json",
    }
    writer.write_entry(
        flow_id="fixture-flow-0001",
        direction="outbound",
        decision="allowed",
        host="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        inspectors=[],
        inbound_req=inbound_req,
        inbound_resp=resp,
        outbound_req=outbound_req,
        outbound_resp=resp,
    )

    blocked_req = {
        "method": "POST",
        "url": "https://telemetry.example.com/v1/events",
        "httpVersion": "HTTP/1.1",
        "headers": [["host", "telemetry.example.com"],
                    ["content-type", "application/json"]],
        "body": '{"event":"fixture"}',
        "bodyEncoding": None,
        "bodySize": 19,
    }
    writer.write_entry(
        flow_id="fixture-flow-0002",
        direction="outbound",
        decision="blocked",
        host="telemetry.example.com",
        method="POST",
        path="/v1/events",
        inspectors=[{
            "name": "domain", "action": "block",
            "reason": "domain not in allowlist", "severity": "high",
        }],
        inbound_req=blocked_req,
        inbound_resp={},
        outbound_req=blocked_req,
        outbound_resp={},
    )
    writer.close() if hasattr(writer, "close") else writer.flush()


def _write_audit_jsonl(path: Path) -> None:
    """Produce ``audit.jsonl`` through the real addon ``_audit_write``.

    ``Agentcage`` is constructed via ``__new__`` — the documented way its
    own test suite builds a partially-initialized instance — so the file is
    written by the shipping serializer rather than by a hand-rolled
    ``json.dumps`` that could drift from it.
    """
    _proxy_pkg_path()
    _stub_mitmproxy()
    from addon import Agentcage  # type: ignore[import-not-found]

    path.parent.mkdir(parents=True, exist_ok=True)
    inst = Agentcage.__new__(Agentcage)
    # _audit_write always mirrors to stderr (journald is the other sink);
    # swallow that here so the generator's own output stays readable.
    import contextlib

    devnull = contextlib.redirect_stderr(io.StringIO())
    with devnull, open(path, "a") as fh:
        inst._audit_file = fh
        for entry in (
            {
                "direction": "outbound",
                "method": "POST",
                "host": "api.anthropic.com",
                "port": 443,
                "path": "/v1/messages",
                "url": "https://api.anthropic.com/v1/messages",
                "decision": "allowed",
                "reason": "",
                "secrets_injected": ["ANTHROPIC_API_KEY"],
            },
            {
                "direction": "outbound",
                "method": "POST",
                "host": "telemetry.example.com",
                "port": 443,
                "path": "/v1/events",
                "url": "https://telemetry.example.com/v1/events",
                "decision": "blocked",
                "reason": "domain not in allowlist",
                "inspectors": [{
                    "name": "domain", "action": "block",
                    "reason": "domain not in allowlist", "severity": "high",
                }],
            },
            {
                "direction": "outbound",
                "method": "GET",
                "host": "github.com",
                "port": 443,
                "path": "/agentcage/agentcage",
                "url": "https://github.com/agentcage/agentcage",
                "decision": "flagged",
                "reason": "secret pattern in response body",
                "source": "relay",
                "secrets_redacted": ["GITHUB_TOKEN"],
                "inspectors": [{
                    "name": "secrets", "action": "flag",
                    "reason": "generic-api-key", "severity": "medium",
                }],
            },
        ):
            inst._audit_write(dict(entry))


def _generate_backup(name: str) -> Path:
    """Drive the real ``cage backup`` command with podman faked out."""
    from click.testing import CliRunner

    from agentcage import cli as _cli

    out = SANDBOX / f"{name}-backup.tar.gz"

    podman = mock.MagicMock()
    podman.secret_list.return_value = [
        {"Name": f"{name}.ANTHROPIC_API_KEY"},
        {"Name": f"{name}.GITHUB_TOKEN"},
        {"Name": f"{name}.IMAP_PASSWORD"},
    ]
    podman.secret_read.side_effect = lambda full: FAKE_SECRETS[full.split(".", 1)[1]]
    podman.volume_exists.return_value = False

    runner = CliRunner()
    with mock.patch.object(_cli, "_podman_for_cage", return_value=podman):
        result = runner.invoke(
            _cli.main,
            ["cage", "backup", name, "--output", str(out), "--include-secrets"],
        )
    if result.exit_code != 0:
        raise SystemExit(
            f"cage backup failed ({result.exit_code}):\n{result.output}\n"
            f"{result.exception!r}"
        )
    _rewrite_tarball_deterministic(out)
    return out


def _rewrite_tarball_deterministic(path: Path) -> None:
    """Repack *path* so two runs produce identical bytes.

    A ``tar.gz`` embeds per-run data that has nothing to do with the format
    contract: the gzip header carries an mtime and the original filename, and
    every tar member carries mtime, uid/gid, uname/gname and a *mode* from the
    machine that packed it. Normalize all of it, and run each member's text
    through :func:`_scrub` (the tarball carries a copy of ``cage.yaml``, which
    holds absolute host paths). Member *names, order, types and contents* —
    the parts a Rust reader actually has to handle — are left as ``cage
    backup`` produced them.

    Mode is normalized rather than preserved because it is not a stable part
    of the format: ``tar.add`` copies each state file's mode, which is
    whatever the producing host's umask happened to make it. Running the
    generator under ``umask 077`` instead of ``umask 022`` changed every
    member from 0644/0755 to 0600/0700 and so changed the archive bytes.
    """
    with tarfile.open(path, "r:gz") as tar:
        members = []
        for member in tar.getmembers():
            data = tar.extractfile(member).read() if member.isfile() else None
            members.append((member, data))

    members.sort(key=lambda item: item[0].name)

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for member, data in members:
            if data is not None:
                try:
                    data = _scrub(data.decode()).encode()
                except UnicodeDecodeError:
                    pass
                member.size = len(data)
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mode = 0o755 if member.isdir() else 0o644
            tar.addfile(member, io.BytesIO(data) if data is not None else None)

    with open(path, "wb") as fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0) as gz:
            gz.write(raw.getvalue())


# ── Scrubbing + copy-out ───────────────────────────────────

#: Binary state that must be copied through byte-for-byte.
_BINARY_SUFFIXES = {".gz", ".tar", ".tgz"}


def _scrub(text: str) -> str:
    """Replace this machine's paths and ids with the frozen stand-ins."""
    sandbox = str(SANDBOX)
    real_sandbox = os.path.realpath(sandbox)
    for needle in (real_sandbox, sandbox):
        text = text.replace(needle + "/run-user", SCRUB_RUNTIME_DIR)
        text = text.replace(needle, SCRUB_HOME)
    text = text.replace(f"/run/user/{os.getuid()}", SCRUB_RUNTIME_DIR)
    # Quadlets emit the invoking uid (Secret= target ownership, UIDMap, …).
    text = text.replace(f"uid={os.getuid()}", f"uid={SCRUB_UID}")
    text = text.replace(f"gid={os.getgid()}", f"gid={SCRUB_UID}")
    return text


def _copy_tree(src: Path, dst: Path) -> None:
    """Copy *src* into *dst*, scrubbing text and skipping empty directories.

    Empty directories are skipped deliberately: **git cannot represent one**.
    If the generator emitted an empty directory it would survive in the
    author's working tree, be silently dropped by ``git add``, and then make
    ``--check`` fail on every fresh checkout (CI) while passing locally — the
    directory is present on the generating side and absent on the committed
    side. Anything that cannot round-trip through git must not be produced.
    """
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        target = dst / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix in _BINARY_SUFFIXES:
            target.write_bytes(path.read_bytes())
        else:
            target.write_text(_scrub(path.read_text()))
        # Modes are deliberately NOT copied. git records only the executable
        # bit, so a 0600 file (pending_secrets.json, the creds blobs) comes
        # back from a checkout as 0644 no matter what is written here —
        # preserving it would imply a guarantee the fixture cannot make. The
        # 0600-at-rest property is asserted in the writers' own tests, not
        # here, and the comparison in compare_trees ignores modes to match.


def _assert_no_empty_dirs(out: Path) -> None:
    """Refuse to emit a tree git cannot reproduce — see :func:`_copy_tree`."""
    empty = sorted(
        str(d.relative_to(out))
        for d in out.rglob("*")
        if d.is_dir() and not any(d.iterdir())
    )
    if empty:
        raise SystemExit(
            "fixture contains directories git cannot track:\n  "
            + "\n  ".join(empty)
        )


# ── Tree comparison (``--check``) ──────────────────────────

#: Cap on how much of any one file's diff is printed.
_DIFF_LINE_CAP = 40


def _tar_members(blob: bytes) -> dict[str, bytes | None]:
    """Decompressed ``{member name: bytes or None for non-files}``."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        return {
            m.name: (tar.extractfile(m).read() if m.isfile() else None)
            for m in tar.getmembers()
        }


def _text_diff(rel: str, want: bytes, got: bytes) -> list[str]:
    """A unified diff when both sides decode, byte facts when they do not."""
    import difflib

    try:
        want_lines = want.decode().splitlines(keepends=True)
        got_lines = got.decode().splitlines(keepends=True)
    except UnicodeDecodeError:
        offset = next(
            (i for i, (a, b) in enumerate(zip(want, got)) if a != b),
            min(len(want), len(got)),
        )
        return [
            f"  binary: committed {len(want)}B, regenerated {len(got)}B, "
            f"first difference at byte {offset}"
        ]
    lines = list(
        difflib.unified_diff(
            want_lines, got_lines,
            fromfile=f"committed/{rel}", tofile=f"regenerated/{rel}",
        )
    )
    out = ["  " + line.rstrip("\n") for line in lines[:_DIFF_LINE_CAP]]
    if len(lines) > _DIFF_LINE_CAP:
        out.append(f"  … {len(lines) - _DIFF_LINE_CAP} more diff lines")
    return out


def _tarball_diff(rel: str, want: bytes, got: bytes) -> list[str]:
    """Compare the archive's *contents*, never the gzip stream.

    The gzip container carries an mtime, an original filename and a
    compression level, none of which are part of the backup format. Reporting
    "the bytes moved" for a tarball is useless; the member list and the member
    bytes are what a reader cares about.
    """
    try:
        want_members, got_members = _tar_members(want), _tar_members(got)
    except tarfile.TarError as e:  # pragma: no cover — corrupt fixture
        return [f"  cannot read as tar.gz: {e}"]

    out: list[str] = []
    for name in sorted(set(want_members) - set(got_members)):
        out.append(f"  - member only in committed: {name}")
    for name in sorted(set(got_members) - set(want_members)):
        out.append(f"  + member only in regenerated: {name}")
    # Order matters (the reader walks members in stream order), but only
    # report it when the *shared* members are ordered differently — an
    # added or removed member already explains a raw list mismatch.
    shared = set(want_members) & set(got_members)
    want_order = [n for n in want_members if n in shared]
    got_order = [n for n in got_members if n in shared]
    if want_order != got_order:
        out.append("  member order differs:")
        out.append(f"    committed:   {want_order}")
        out.append(f"    regenerated: {got_order}")
    for name in sorted(set(want_members) & set(got_members)):
        a, b = want_members[name], got_members[name]
        if a != b:
            out.append(f"  member differs: {name}")
            if a is not None and b is not None:
                out.extend(
                    "  " + line for line in _text_diff(f"{rel}!{name}", a, b)
                )
    if not out:
        out.append(
            "  members are identical — only the gzip/tar container bytes "
            "differ (compression level or header metadata)"
        )
    return out


def compare_trees(committed: Path, regenerated: Path) -> tuple[int, list[str]]:
    """Return ``(files_differing, report_lines)``, file by file.

    Returns ``(0, [])`` when the trees match. Directories are not compared
    (see :func:`_copy_tree`), and neither are file modes: git records only the
    executable bit, so a mode comparison would report differences that cannot
    be committed either way.
    """
    def _files(root: Path) -> dict[str, Path]:
        return {
            str(p.relative_to(root)): p
            for p in root.rglob("*") if p.is_file()
        }

    want, got = _files(committed), _files(regenerated)
    report: list[str] = []
    differing = 0

    for rel in sorted(set(want) - set(got)):
        differing += 1
        report.append(f"- in committed, NOT regenerated: {rel}")
    for rel in sorted(set(got) - set(want)):
        differing += 1
        report.append(f"+ regenerated, NOT committed: {rel}")

    for rel in sorted(set(want) & set(got)):
        a, b = want[rel].read_bytes(), got[rel].read_bytes()
        if a == b:
            continue
        differing += 1
        report.append(f"~ bytes differ: {rel}")
        if rel.endswith(".gz"):
            report.extend(_tarball_diff(rel, a, b))
        else:
            report.extend(_text_diff(rel, a, b))

    return differing, report


def _assert_clean(out: Path) -> None:
    """Fail loudly if this machine leaked into the fixture."""
    import socket

    forbidden = [
        os.path.expanduser("~"),
        str(SANDBOX),
        os.path.realpath(str(SANDBOX)),
        socket.gethostname(),
        f"/run/user/{os.getuid()}",
    ]
    # HOME is the sandbox at this point; also reject the invoking user's name.
    if os.environ.get("USER"):
        forbidden.append(f"/home/{os.environ['USER']}")
    bad = []
    for path in sorted(out.rglob("*")):
        if not path.is_file():
            continue
        blob = path.read_bytes()
        # A compressed member would hide a leaked path from a raw grep.
        if path.suffix == ".gz":
            blob = gzip.decompress(blob)
        for needle in forbidden:
            if needle and len(needle) > 3 and needle.encode() in blob:
                bad.append(f"{path.relative_to(out)}: {needle!r}")
    if bad:
        raise SystemExit("fixture is not clean:\n  " + "\n  ".join(bad))


README = """\
# `state-compat` fixtures — {version}

A byte-frozen snapshot of the on-disk state that **agentcage {version}
(Python)** writes for a deployed cage.

## Why

The host CLI is being rewritten in Rust (`RUST-PORT-PLAN.md` §2.7). At cutover
every existing user has cages that the Python CLI deployed, and the Rust binary
must read that state **in place, on first run, with no migration step**.

None of this state carries a schema version — `metadata.json` is a bare
`json.dumps(dict)`, and there is no `state_version` field anywhere in
`src/agentcage/state.py`. There is nothing to branch on. So the Rust readers
have to accept *exactly* what the Python writers produce, and this directory is
the definition of "exactly".

The Python tests in `tests/test_state_compat.py` load every file here through
the real Python readers and assert concrete values. Those same assertions are
what the Rust implementation will be held to.

## This is generated. Do not hand-edit.

    uv run python scripts/gen-state-fixtures.py

The generator drives the real code paths — `state.save_deployment`,
`state.fill_placeholders`, `state.save_proxy_config`, `state.save_grants`,
`secret_store.*`, `quadlets.generate_quadlets`, and the actual `cage backup`
click command — inside a throwaway XDG sandbox, then scrubs and copies the
result here. Re-running it on a clean tree produces a byte-identical tree.

`--check` regenerates into a temporary directory and reports every difference
file by file — added, removed, and changed with a unified diff; for the backup
tarball it compares decompressed members rather than the gzip stream. That is
how CI (and you) can prove the committed fixture still matches the code, and a
CI log alone is enough to diagnose a drift.

One trap worth knowing about: git cannot store an empty directory. If the
generator ever emits one it survives in the author's working tree, is silently
dropped by `git add`, and then makes `--check` fail on every fresh checkout
while passing locally. The generator refuses to write such a tree, and
`tests/test_state_compat.py` additionally asserts that every fixture file is
tracked by git.

## Adding a new generation

**Never overwrite this directory.** Bump the package version and run the
generator again; it writes `tests/fixtures/state-compat/<new-version>/`. Keeping
several generations is the point — the Rust reader has to cope with state
written by any version a user might be upgrading from.

## Layout

| Path | Corresponds to |
| :-- | :-- |
| `xdg-config/agentcage/cages/<name>/` | `$XDG_CONFIG_HOME/agentcage/cages/<name>/` |
| `xdg-config/agentcage/apple-container/<name>/` | `~/.config/agentcage/apple-container/<name>/` |
| `xdg-config/containers/systemd/` | `~/.config/containers/systemd/` (quadlets) |
| `xdg-data/agentcage/<name>/` | `$XDG_DATA_HOME/agentcage/<name>/` |
| `xdg-data/agentcage/patches/` | shared resolv.conf + nested-podman patch dir |
| `backup/<name>-backup.tar.gz` | output of `agentcage cage backup --include-secrets` |

Three cages are captured:

- **`{rich}`** — multiple domains, secrets from more than one source, a
  protocol relay, capture, grants, `creds/`, a fingerprint, rendered quadlets
  and a backup tarball.
- **`{minimal}`** — everything defaulted, so the *absence* of a file is
  captured too.
- **`{apple}`** — the macOS shape. Note where its runtime state lives:
  `~/.config/agentcage/apple-container/<name>/logs/` holds the addon's
  `audit.jsonl`, `capture.jsonl`, `dnsmasq.log` and `ready` marker. That is a
  third state root, separate from both XDG trees.

Two things about `audit.jsonl` are easy to get wrong and are captured here
deliberately. There is **no** host-side `audit.jsonl` for a container or vm
cage — the addon writes its audit trail to stderr and the host reads it back
out of `journalctl`. And the grants overlay is **`grants.yaml`**, a YAML list,
not JSON.

## Frozen values

Determinism is a hard requirement, so everything that varies per run is pinned:

- **Clock** — every `datetime.now()` returns `{frozen_now}`.
- **Paths** — the generator's sandbox is rewritten to `{scrub_home}`, and
  `$XDG_RUNTIME_DIR` to `{scrub_runtime}`. No path from the generating machine
  appears anywhere in this tree; the generator asserts that before writing.
- **UID/GID** — rewritten to `{scrub_uid}`.
- **Placeholder entropy** — `config.generate_placeholder` mints
  `agentcage:secret:<ENV>:<hex>` from `secrets.token_hex(16)`; the entropy
  source is frozen so the minted token is fixed.
- **Subnet octet** — pinned to `{octet}` rather than hash-derived.
- **Tarball metadata** — the gzip header mtime/filename and each tar member's
  mtime, uid/gid, uname/gname and mode are normalized after `cage backup`
  runs, and member text goes through the same path scrub as everything else.
  Member names, order, types and contents are what `cage backup` emitted.
  Mode is normalized because it is not a stable part of the format: `tar.add`
  copies each state file's mode, which is whatever the producing host's umask
  made it, so `umask 077` and `umask 022` produce different archive bytes for
  identical state.
- **File modes are not part of this fixture.** git records only the
  executable bit, so a file that is 0600 on a real host (`pending_secrets.json`,
  `creds/*.cred`) comes back from a checkout as 0644. The at-rest mode is a
  real property of those writers and is asserted in their own tests; it cannot
  be carried here, so the regeneration check ignores modes.

## Secrets

There are none. Every secret-shaped value is an obviously-fake
`TEST-NOT-A-REAL-SECRET-####` string and every certificate is
`TEST-NOT-A-REAL-CERTIFICATE-####`.

`xdg-config/agentcage/cages/{rich}/creds/*.cred` is the one thing that is
*not* generated by running the real encryptor: `systemd-creds` encryption is
host-bound (host key / TPM2 / per-user key), so a blob produced here could not
be decrypted in CI or on any other machine, and re-encrypting would not
reproduce byte-identically anyway. A single real-shaped blob is frozen into the
generator instead. **Assert its presence, filename and shape — never its
contents.** The plaintext behind it was `TEST-NOT-A-REAL-SECRET-0001`.
"""


def _write_readme(out: Path, version: str) -> None:
    (out / "README.md").write_text(
        README.format(
            version=version,
            rich=RICH_CAGE,
            minimal=MINIMAL_CAGE,
            apple=APPLE_CAGE,
            frozen_now=FROZEN_NOW.isoformat(),
            scrub_home=SCRUB_HOME,
            scrub_runtime=SCRUB_RUNTIME_DIR,
            scrub_uid=SCRUB_UID,
            octet=FROZEN_NETWORK_OCTET,
        )
    )


def _write_manifest(out: Path, version: str) -> None:
    files = sorted(
        str(p.relative_to(out))
        for p in out.rglob("*")
        if p.is_file() and p.name not in ("MANIFEST.json",)
    )
    (out / "MANIFEST.json").write_text(
        json.dumps(
            {
                "agentcage_version": version,
                "generator": "scripts/gen-state-fixtures.py",
                "cages": {
                    "rich": RICH_CAGE,
                    "minimal": MINIMAL_CAGE,
                    "apple": APPLE_CAGE,
                },
                "frozen": {
                    "now": FROZEN_NOW.isoformat(),
                    "home": SCRUB_HOME,
                    "runtime_dir": SCRUB_RUNTIME_DIR,
                    "uid": SCRUB_UID,
                    "token_hex": FROZEN_TOKEN_HEX,
                    "network_octet": FROZEN_NETWORK_OCTET,
                },
                "files": files,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def build(out: Path) -> str:
    from importlib.metadata import version as _pkg_version

    _freeze_nondeterminism()
    version = _pkg_version("agentcage")

    configs = _write_source_configs()
    _generate_cage_state(RICH_CAGE, configs[RICH_CAGE], rich=True)
    _generate_cage_state(MINIMAL_CAGE, configs[MINIMAL_CAGE], rich=False)
    _generate_apple_cage_state(APPLE_CAGE, configs[APPLE_CAGE])
    tarball = _generate_backup(RICH_CAGE)

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    _copy_tree(SANDBOX / ".config", out / "xdg-config")
    _copy_tree(SANDBOX / ".local" / "share", out / "xdg-data")
    (out / "backup").mkdir(parents=True, exist_ok=True)
    (out / "backup" / tarball.name).write_bytes(tarball.read_bytes())

    _assert_no_empty_dirs(out)
    _assert_clean(out)
    _write_readme(out, version)
    _write_manifest(out, version)
    return version


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=None,
                    help="output directory (default: tests/fixtures/state-compat/<version>)")
    ap.add_argument("--check", action="store_true",
                    help="regenerate into a temp dir and diff against the committed fixture")
    args = ap.parse_args()

    from importlib.metadata import version as _pkg_version
    version = _pkg_version("agentcage")
    committed = repo / "tests" / "fixtures" / "state-compat" / version

    if args.check:
        if not committed.is_dir():
            print(
                f"no committed fixture at {committed} "
                f"(installed agentcage version is {version})",
                file=sys.stderr,
            )
            return 1
        scratch = SANDBOX / "check-out"
        build(scratch)
        differing, report = compare_trees(committed, scratch)
        if not differing:
            print("fixture matches", file=sys.stderr)
            return 0
        print(
            f"fixture DIFFERS ({differing} file(s))\n"
            f"  committed:   {committed}\n"
            f"  regenerated: {scratch}\n",
            file=sys.stderr,
        )
        print("\n".join(report))
        return 1

    out = args.out or committed
    version = build(out)
    print(f"wrote {out} (agentcage {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
