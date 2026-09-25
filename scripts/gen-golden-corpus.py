#!/usr/bin/env python3
"""Regenerate the golden corpus under ``tests/fixtures/golden/``.

The corpus is a characterization net over everything the host
deterministically derives from a ``cage.yaml``: rendered quadlets,
``proxy-config.yaml``, ``dns-allowlist.conf``, ``cage-env/placeholders.env``,
the deployment fingerprint, HAR output, audit parse/filter/summary output,
volume-mount parsing, and — most importantly — every validation error message
and warning string.

Run it with::

    uv run python scripts/gen-golden-corpus.py

or, to generate somewhere else (what the determinism check does)::

    uv run python scripts/gen-golden-corpus.py --out /tmp/corpus-a

See ``tests/fixtures/golden/README.md`` for what the output means and when
re-blessing is appropriate.

Determinism
-----------
Everything host-specific is pinned before ``agentcage`` is imported, and every
remaining absolute path is scrubbed to a ``{{TOKEN}}`` on the way out.  See
``_build_sandbox`` and ``_install_determinism_patches``.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import dataclasses
import io
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "tests" / "fixtures" / "golden"
INPUTS_DIR = DEFAULT_OUT / "_inputs"

# Frozen stand-ins for values that legitimately differ between hosts and
# between releases.  They are pinned rather than scrubbed where the value is
# produced by code we call (a scrub would also hit a coincidentally equal
# literal in user config).
FROZEN_VERSION = "0.0.0-golden"
FROZEN_CLI_PATH = "/usr/bin/agentcage"
FROZEN_DNS_SERVERS = ["192.0.2.53", "192.0.2.54"]
FROZEN_CREDS_SCOPE = "user"
# The resolved Apple `container` path. `container_binary()` is a
# `shutil.which` over PATH and two install locations, so on any machine
# that is not a Mac with the .pkg installed it is None -- and the plist
# would never be rendered at all. Pinning it makes the apple-container
# cases produce the same plist everywhere, which is the same trick
# FROZEN_CLI_PATH plays for `shutil.which("agentcage")`.
FROZEN_CONTAINER_BINARY = "/usr/local/bin/container"

# ``generate_placeholder`` mints 16 random bytes per rule.  Replaced with a
# deterministic counter so the same corpus case always gets the same token.
_PLACEHOLDER_COUNTER = {"n": 0}


# ---------------------------------------------------------------------------
# Sandbox + determinism
# ---------------------------------------------------------------------------

def _build_sandbox(work: Path) -> dict[str, str]:
    """Create a hermetic HOME/XDG tree and return the env it implies.

    ``state.py`` resolves ``XDG_CONFIG_HOME``/``XDG_DATA_HOME`` at *import*
    time, so this must run before ``agentcage.state`` is imported.
    """
    home = work / "home"
    for rel in (
        ".config/agentcage",
        ".local/share/agentcage",
        "agent",              # seed-config ${AGENT_DIR} volume source
        "project",            # mask-test project dir
        "workspace",
        "data",
        "e2e-work/test-agent",  # tests/configs/*.yaml relative volume source
        "certs",
    ):
        (home / rel).mkdir(parents=True, exist_ok=True)
    # A single-file volume source, to exercise the vm backend's file staging.
    (home / "dotfile.conf").write_text("# fake dotfile\n")
    (home / "certs" / "fake-ca.pem").write_text(
        "-----BEGIN CERTIFICATE-----\n"
        "RkFLRS1DRVJUSUZJQ0FURS1OT1QtUkVBTA==\n"
        "-----END CERTIFICATE-----\n"
    )
    runtime = work / "run"
    runtime.mkdir(parents=True, exist_ok=True)

    env = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_RUNTIME_DIR": str(runtime),
        # Referenced by corpus configs via ${...}; pinned so expandvars is
        # exercised without leaking the developer's environment.
        "GOLDEN_AGENT_DIR": str(home / "agent"),
        "TZ": "UTC",
        # A couple of env-var references that are deliberately *set* and one
        # that is deliberately absent (``GOLDEN_UNSET_VAR``), so the
        # "env var reference is unset" warning is reachable.
        "GOLDEN_SET_VAR": "set-value",
    }
    os.environ.pop("GOLDEN_UNSET_VAR", None)
    global _ORIGINAL_HOME
    _ORIGINAL_HOME = os.path.realpath(os.path.expanduser("~"))
    os.environ.update(env)
    return env


_ORIGINAL_HOME = ""


def _assert_no_leaks(out_root: Path, work: Path) -> None:
    """Fail loudly if a host-specific string survived into the corpus.

    Cheap insurance: a scrub rule that silently stops matching would produce a
    corpus that only reproduces on the machine that made it, and the
    determinism check (two runs, same machine) would not catch it.
    """
    needles = [str(work), os.path.realpath(work), str(REPO_ROOT)]
    if _ORIGINAL_HOME and _ORIGINAL_HOME not in ("/", ""):
        needles.append(_ORIGINAL_HOME)
    needles = sorted({n for n in needles if n}, key=len, reverse=True)

    offenders: list[str] = []
    for path in sorted(out_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for needle in needles:
            if needle in body:
                offenders.append(f"{path.relative_to(out_root)}: {needle!r}")
                break
    if offenders:
        raise SystemExit(
            "host-specific paths leaked into the corpus:\n  "
            + "\n  ".join(offenders[:20]))


def _install_determinism_patches() -> None:
    """Pin every host-dependent value reached by the corpus pipeline."""
    import importlib.metadata as _md
    import platform
    import secrets as _secrets

    import agentcage.config as config
    import agentcage.har as har
    import agentcage.quadlets as quadlets
    import agentcage.secret_resolver as secret_resolver

    # 1. Package version. It lands in the egress quadlet, proxy-config.yaml
    #    and the HAR creator block. Each binding is patched separately
    #    because two of them were bound at import time.
    _real_version = _md.version

    def _version(name: str) -> str:
        if name == "agentcage":
            return FROZEN_VERSION
        return _real_version(name)

    _md.version = _version                      # for function-local imports
    quadlets._pkg_version = _version
    har.pkg_version = _version
    try:
        import agentcage.backends.apple_container as apple_container
        apple_container._agentcage_version = lambda: FROZEN_VERSION
    except Exception:                            # pragma: no cover - defensive
        pass

    # 2. Host DNS detection: reads /etc/resolv.conf (and scutil on macOS).
    global _REAL_HOST_DNS
    _REAL_HOST_DNS = config._host_dns_servers
    config._host_dns_servers = lambda: list(FROZEN_DNS_SERVERS)

    # 3. ``shutil.which("agentcage")`` in the generated units.
    quadlets._agentcage_cli = lambda: FROZEN_CLI_PATH

    # 4. ``secrets.scope: auto`` probes systemd-creds with a subprocess.
    secret_resolver.detect_default_scope = lambda: FROZEN_CREDS_SCOPE

    # 5. Placeholder entropy.
    def _token_hex(n: int = 16) -> str:
        _PLACEHOLDER_COUNTER["n"] += 1
        # 32 hex chars for n=16, matching the real token shape.
        return ("%0*x" % (n * 2, _PLACEHOLDER_COUNTER["n"]))

    _secrets.token_hex = _token_hex

    # 6. Platform. Pinned to Linux/x86_64 so the corpus is identical on a
    #    developer's Mac; the apple-container cases flip it explicitly (the
    #    same trick tests/test_apple_container.py uses).
    platform.system = lambda: _PLATFORM["system"]
    platform.machine = lambda: _PLATFORM["machine"]
    platform.mac_ver = lambda: (_PLATFORM["mac_ver"], ("", "", ""), "")

    # 7. The Apple `container` CLI, for the apple-container cases' units
    #    and launchd plist. Two patches, and the second one is a safety
    #    interlock rather than a determinism one:
    #
    #    * ``container_binary()`` is a ``shutil.which``; pin it so the
    #      plist's ProgramArguments is the same on every machine.
    #    * ``_gui_domain_reachable()`` shells out to ``launchctl print
    #      gui/<uid>``. On Linux that is a FileNotFoundError and the real
    #      code already answers False -- but on a CONTRIBUTOR'S MAC it
    #      would answer True, and ``_install_launchd_plist`` would then
    #      run ``launchctl bootstrap`` against their live session. A
    #      corpus generator must not install a launch agent on the
    #      machine that runs it. Pinned to False, which is also the
    #      branch whose only side effect is the file write this corpus
    #      wants.
    import agentcage.apple_container.cli as _ac_cli
    import agentcage.backends.apple_container as _ac_backend
    _ac_cli.container_binary = lambda: FROZEN_CONTAINER_BINARY
    _ac_backend._gui_domain_reachable = lambda uid: False


_PLATFORM = {"system": "Linux", "machine": "x86_64", "mac_ver": "0"}
_REAL_HOST_DNS = None


@contextlib.contextmanager
def _as_platform(system: str, machine: str, mac_ver: str = "26.0"):
    prev = dict(_PLATFORM)
    _PLATFORM.update(system=system, machine=machine, mac_ver=mac_ver)
    try:
        yield
    finally:
        _PLATFORM.update(prev)


class Scrubber:
    """Replace host-specific absolute paths with stable ``{{TOKEN}}``s.

    Longest prefix first, so ``$HOME/.config`` is not half-rewritten by the
    ``$HOME`` rule.
    """

    def __init__(self, work: Path) -> None:
        real_work = os.path.realpath(work)
        real_home = os.path.realpath(Path(real_work) / "home")
        rules = [
            (os.path.join(real_home, ".local", "share"), "{{XDG_DATA_HOME}}"),
            (os.path.join(real_home, ".config"), "{{XDG_CONFIG_HOME}}"),
            (real_home, "{{HOME}}"),
            (os.path.join(real_work, "run"), "{{XDG_RUNTIME_DIR}}"),
            (real_work, "{{WORK}}"),
            (str(REPO_ROOT), "{{REPO}}"),
        ]
        # Also scrub the non-realpath spellings, which turn up wherever the
        # code interpolates ``$HOME`` without resolving symlinks.
        extra = []
        for raw, token in list(rules):
            plain = str(Path(raw))
            if plain != raw:
                extra.append((plain, token))
        rules.extend(extra)
        rules.append((str(work), "{{WORK}}"))
        rules.append((str(work / "home"), "{{HOME}}"))
        # Deduplicate, longest first.
        seen: dict[str, str] = {}
        for raw, token in rules:
            seen.setdefault(raw, token)
        self._rules = sorted(seen.items(), key=lambda kv: -len(kv[0]))

    # quadlets.py base64-encodes host paths before embedding them in a
    # systemd Exec= line (a path is quoted once by systemd and again by bash,
    # and no single escaping survives both). A plain string replace cannot see
    # inside that blob, so decode candidates, scrub, and re-encode. The
    # corpus therefore stores base64("{{HOME}}/project"), and any
    # reimplementation must apply the same scrub before comparing.
    _B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

    def _scrub_b64(self, match: re.Match) -> str:
        import base64
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except Exception:
            return blob
        scrubbed = self._replace(decoded)
        if scrubbed == decoded:
            return blob
        return base64.b64encode(scrubbed.encode("utf-8")).decode("ascii")

    def _replace(self, value: str) -> str:
        for raw, token in self._rules:
            if raw and raw in value:
                value = value.replace(raw, token)
        return value

    def text(self, value: str) -> str:
        value = self._B64_RE.sub(self._scrub_b64, value)
        return self._replace(value)


# ---------------------------------------------------------------------------
# Raise-site coverage (which validation errors the corpus actually reaches)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class RaiseSite:
    key: str          # "<qualname>#<n>" — stable across unrelated line shifts
    lineno: int       # used only to match execution traces; never reported
    label: str        # "<ExcType>: <message template>", see _raise_label


# NOTE — this report is a committed fixture, so every byte of it must be
# interpreter-independent. ``ast.unparse`` is NOT: its quote selection for
# f-strings moved with PEP 701, so 3.12/3.13 render
# ``f"...{d['k']}..."`` with an outer double quote while 3.14 reuses the
# single quote. Generating on one interpreter and checking on another then
# fails on pure quote style. So nothing here round-trips source text. The
# renderer below reads only node *types* and *constant values*, both of which
# are fixed by the grammar rather than by a pretty-printer.

_ELLIPSIS = "{…}"


def _message_template(node: ast.AST) -> str:
    """Render an exception's message argument as a stable template.

    Literal text survives verbatim; every interpolated expression collapses to
    ``{…}``. That is the part the Rust port actually has to reproduce, and it
    cannot drift with the host interpreter.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else str(node.value)
    if isinstance(node, ast.JoinedStr):          # an f-string
        return "".join(_message_template(v) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _ELLIPSIS
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        # "a" + b and "a %s" % b both read as one message.
        return _message_template(node.left) + _message_template(node.right)
    return _ELLIPSIS


def _exception_name(node: ast.AST) -> str:
    """The raised exception's name, without unparsing anything."""
    if isinstance(node, ast.Call):
        return _exception_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return "?"


def _raise_label(node: ast.Raise) -> str:
    """``"<ExcType>: <message template>"`` for one raise statement."""
    if node.exc is None:
        return "bare re-raise"
    name = _exception_name(node.exc)
    message = ""
    if isinstance(node.exc, ast.Call) and node.exc.args:
        message = _message_template(node.exc.args[0])
    message = " ".join(message.split())
    label = f"{name}: {message}" if message else name
    return label if len(label) <= 200 else label[:197] + "..."


def _md_code(text: str) -> str:
    """Wrap *text* in a Markdown code span that survives embedded backticks."""
    if "`" not in text:
        return f"`{text}`"
    run = max(len(m) for m in re.findall(r"`+", text))
    fence = "`" * (run + 1)
    return f"{fence} {text} {fence}"


def _collect_raise_sites(path: Path) -> list[RaiseSite]:
    """Every ``raise`` statement in *path*, keyed stably by qualname+index."""
    tree = ast.parse(path.read_text(), filename=str(path))
    sites: list[RaiseSite] = []
    counts: dict[str, int] = {}

    def walk(node: ast.AST, qual: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, f"{qual}.{child.name}" if qual else child.name)
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{qual}.{child.name}" if qual else child.name)
            else:
                if isinstance(child, ast.Raise):
                    n = counts.get(qual, 0)
                    counts[qual] = n + 1
                    sites.append(RaiseSite(
                        key=f"{qual or '<module>'}#{n}",
                        lineno=child.lineno,
                        label=_raise_label(child),
                    ))
                walk(child, qual)

    walk(tree, "")
    return sites


class RaiseTracer:
    """Record which lines of the watched files execute.

    ``sys.settrace`` rather than a coverage dependency: the corpus must be
    regenerable from a bare checkout.
    """

    def __init__(self, filenames: set[str]) -> None:
        self._watch = filenames
        self.hits: dict[str, set[int]] = {f: set() for f in filenames}
        self._prev = None

    def _trace(self, frame, event, arg):
        filename = frame.f_code.co_filename
        if filename not in self._watch:
            return None
        if event == "line":
            self.hits[filename].add(frame.f_lineno)
        return self._trace

    def __enter__(self) -> RaiseTracer:
        self._prev = sys.gettrace()
        sys.settrace(self._trace)
        return self

    def __exit__(self, *exc) -> None:
        sys.settrace(self._prev)


# ---------------------------------------------------------------------------
# Case catalogue
# ---------------------------------------------------------------------------

def _seed_cases() -> list[tuple[str, str]]:
    """Cases lifted verbatim from the repo's existing config fixtures.

    ``${E2E_PORT_*}`` placeholders are substituted textually (they are shell
    variables the e2e harness exports, and a port field is never passed
    through ``expandvars``).  ``${AGENT_DIR}`` and ``${E2E_MASK_PROJECT_DIR}``
    are rewritten to ``${HOME}``-relative paths so the *expandvars* code path
    in the quadlet renderer is still exercised.
    """
    subs = {
        "${E2E_PORT_HARDENED}": "3101",
        "${E2E_PORT_HAR}": "3102",
        "${E2E_PORT_SECOND}": "3103",
        "${E2E_PORT_SECRETS}": "3104",
        "${E2E_PORT_SECRETS_SRC}": "3105",
        "${E2E_PORT_VM}": "3106",
        "${AGENT_DIR}": "${HOME}/agent",
        "${E2E_MASK_PROJECT_DIR}": "${HOME}/project",
    }
    out: list[tuple[str, str]] = []
    for base, prefix in (
        (REPO_ROOT / "tests" / "configs", "seed-unit"),
        (REPO_ROOT / "tests" / "e2e" / "configs", "seed-e2e"),
    ):
        for path in sorted(base.glob("*.yaml")):
            text = path.read_text()
            for needle, value in subs.items():
                text = text.replace(needle, value)
            out.append((f"{prefix}-{path.stem}", text))
    return out


def _y(obj: object) -> str:
    """Dump a case body as YAML the way the corpus stores it."""
    import yaml
    return yaml.safe_dump(obj, default_flow_style=False, sort_keys=False)


_BASE = {
    "name": "PLACEHOLDER",
    "container": {
        "image": "docker.io/library/node:22-slim",
        "command": ["node", "/app/agent.js"],
    },
    "domains": {"allow": ["api.example.com", "cdn.example.com"]},
    "dns_servers": ["192.0.2.53"],
}


# Sentinel: drop this key from the merged result instead of setting it.
DELETE = "__DELETE__"


def _base(name: str, **overlay) -> dict:
    """Deep-ish copy of the base config with *overlay* merged one level down.

    A nested value of :data:`DELETE` removes that key, which is how a case
    gets a ``domains:`` block with no ``allow:`` at all (the base has one, and
    a present-but-null ``allow`` still selects allowlist mode).
    """
    import copy
    cfg = copy.deepcopy(_BASE)
    cfg["name"] = name
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            merged = copy.deepcopy(cfg[key])
            for k, v in value.items():
                if v == DELETE:
                    merged.pop(k, None)
                else:
                    merged[k] = copy.deepcopy(v)
            cfg[key] = merged
        elif value == DELETE:
            cfg.pop(key, None)
        else:
            cfg[key] = copy.deepcopy(value)
    return cfg


def _matrix_cases() -> list[tuple[str, str, dict]]:
    """The generated valid-config matrix.

    One dimension varied at a time off a shared base, plus a few deliberate
    combinations.  A full cartesian product would be tens of thousands of
    cases and would not find anything the one-at-a-time sweep misses, because
    the validator's rules are almost entirely per-field.

    Returns ``(case_id, yaml_text, opts)`` where *opts* carries per-case
    generation knobs (currently only ``platform``).
    """
    cases: list[tuple[str, dict, dict]] = []

    def add(case_id: str, cfg: dict, **opts) -> None:
        cases.append((case_id, cfg, opts))

    linux = {}
    darwin = {"platform": ("Darwin", "arm64")}

    # ── isolation backends ─────────────────────────────────
    add("backend-container", _base("backend-container", isolation="container"))
    add("backend-vm", _base(
        "backend-vm", isolation="vm", vm={"vcpus": 2, "mem_mb": 2048},
    ))
    add("backend-vm-defaults", _base("backend-vm-defaults", isolation="vm"))
    add("backend-vm-file-volume", _base(
        "backend-vm-file-volume", isolation="vm",
        container={"volumes": ["${HOME}/dotfile.conf:/etc/app.conf:ro"]},
    ))
    add("backend-apple-container", _base(
        "backend-apple-container", isolation="apple-container",
    ), **darwin)
    add("backend-apple-container-autostart", _base(
        "backend-apple-container-autostart", isolation="apple-container",
        apple_container_autostart=True,
    ), **darwin)
    # Every apple-container "silently has no effect" warning at once.
    add("backend-apple-container-drops", _base(
        "backend-apple-container-drops", isolation="apple-container",
        container={
            "named_volumes": {"ac-data": "/data:rw"},
            "podman_secrets": ["FAKE_STORE_KEY"],
            "nested_containers": False,
            "ports": ["127.0.0.1:3000:3000"],
            "userns": "private",
            "drop_capabilities": ["CAP_NET_RAW"],
            "read_only": True,
            "security_label_disable": False,
            "tmpfs": [
                "/tmp:rw,noexec,nosuid,size=64M",
                "/workspace/.git/hooks:rw,noexec,tmpcopyup",
                "/workspace/.claude:rw,nosuid",
            ],
            "volumes": ["${HOME}/workspace:/workspace:rw"],
        },
    ), **darwin)
    add("backend-apple-container-copyup-unseedable", _base(
        "backend-apple-container-copyup-unseedable", isolation="apple-container",
        container={
            "named_volumes": {"state": "/var/lib/state:rw"},
            "tmpfs": ["/var/lib/state/secrets:rw,tmpcopyup",
                      "/plain/image/dir:rw,tmpcopyup"],
        },
    ), **darwin)
    add("backend-apple-container-inspectors", _base(
        "backend-apple-container-inspectors", isolation="apple-container",
        inspectors=[
            {"name": "domain"},
            {"name": "not-a-real-inspector"},
            {"name": "custom", "path": "/etc/agentcage/inspectors/x.py"},
        ],
    ), **darwin)
    # The fields `generate_units` persists that no other apple case
    # reaches (PR E3). Split three ways because two of them are about a
    # precedence rule, and a single case cannot show both sides of one.
    #
    # 1. Everything that has to reach the EGRESS and must never reach the
    #    cage workload's `-e` env: relay credentials, both agents'
    #    api_keys, and the expiring-domain flag that makes the addon
    #    sweep. Plus the placeholder map, which is the `-e KEY={{PH}}`
    #    half of the same story.
    add("backend-apple-container-secrets-agents", _base(
        "backend-apple-container-secrets-agents", isolation="apple-container",
        secrets={"backend": "plaintext", "allow_plaintext": True},
        secret_injection=[
            {"env": "ANTHROPIC_API_KEY", "source": "env:GOLDEN_SET_VAR",
             "placeholder": "sk-ant-FAKE-0001",
             "inject_to": ["api.example.com"]},
            # Both placeholders are written out rather than left to
            # `fill_placeholders`: a generated `agentcage:secret:NAME:<hex>`
            # would put this case on golden_fingerprint.rs's
            # PLACEHOLDER_FILLED exemption list, which would stop the
            # `resolved_config` component being checked for the one
            # apple case that has agents and relays in it. The
            # skip-an-unfilled-placeholder branch is unreachable from a
            # corpus case anyway -- the harness fills them before
            # generate_units runs -- and is covered by a unit test.
            {"env": "OPENAI_API_KEY", "source": "env:GOLDEN_SET_VAR",
             "placeholder": "sk-openai-FAKE-0002",
             "inject_to": ["api.example.com"]},
        ],
        protocol_relays=[
            {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
             "upstream": {"host": "imap.example.com", "port": 993},
             "auth": {"user_source": "env:FAKE_IMAP_USER",
                      "password_source": "env:FAKE_IMAP_PASS"}},
        ],
        agents={
            "decider": {"enable": True, "provider": "anthropic",
                        "model": "claude-x", "api_key": "env:FAKE_DECIDER_KEY"},
            "watcher": {"enable": True, "provider": "openai",
                        "model": "gpt-x",
                        "api_key": "systemd-creds:FAKE_WATCHER_KEY"},
        },
        domains={"allow": ["api.example.com", "cdn.example.com"],
                 "expires": {"cdn.example.com": "2030-01-01T00:00:00Z"}},
    ), **darwin)
    # 2. `container.cpus` / `container.memory` win over `vm.*` -- the
    #    footgun the Python's comment describes, where a per-cage cap
    #    written in cage.yaml used to be silently dropped on Mac. Both
    #    halves are set so the precedence is visible, and the port
    #    policy and `container.env` ride along.
    add("backend-apple-container-resources", _base(
        "backend-apple-container-resources", isolation="apple-container",
        lifecycle="ephemeral",
        container={"cpus": "2.5", "memory": "3g",
                   "env": {"AGENT_HOME": "${GOLDEN_AGENT_DIR}",
                           "PLAIN": "literal"}},
        vm={"vcpus": 8, "mem_mb": 16384},
        ports={"tcp": {"allow": [443, 8080], "passthrough": [8080, 22]},
               "udp": {"allow": [53, 123]},
               "icmp": {"allow": True}},
    ), **darwin)
    # 3. Neither side set, which is the ONLY way to reach the "no
    #    --cpus / --memory flag at all, let Apple's defaults apply"
    #    branch: `VmConfig.vcpus` defaults to 4 and `mem_mb` to 4096, so
    #    every other case -- including the plain `backend-apple-container`
    #    one -- takes the vm fallback and renders "4" / "4096m". The
    #    `vcpus >= 1` guard is gated on `isolation: vm`, so zeros are
    #    valid here and nowhere else.
    add("backend-apple-container-no-resource-caps", _base(
        "backend-apple-container-no-resource-caps", isolation="apple-container",
        vm={"vcpus": 0, "mem_mb": 0},
    ), **darwin)
    add("backend-firecracker-migration", _base(
        "backend-firecracker-migration", isolation="firecracker",
        firecracker={"vcpus": 8, "mem_mb": 8192},
    ))

    # ── lifecycle ──────────────────────────────────────────
    for lifecycle in ("service", "interactive", "ephemeral"):
        add(f"lifecycle-{lifecycle}", _base(
            f"lifecycle-{lifecycle}", lifecycle=lifecycle,
        ))

    # ── secret sources, one per supported scheme ───────────
    for scheme, source in (
        ("env", "env:GOLDEN_SET_VAR"),
        ("cmd", "cmd:printf fake-secret-value"),
        ("systemd-creds", "systemd-creds:FAKE_CRED_NAME"),
        ("podman", "podman:FAKE_PODMAN_SECRET"),
        ("empty", ""),
    ):
        add(f"secrets-source-{scheme}", _base(
            f"secrets-source-{scheme}",
            secret_injection=[{
                "env": "FAKE_API_KEY",
                "placeholder": "agentcage:secret:FAKE_API_KEY:"
                               + "0" * 32,
                "inject_to": ["api.example.com"],
                "source": source,
            }],
        ))
    # Placeholder omitted entirely → generated at declare time.
    add("secrets-placeholder-generated", _base(
        "secrets-placeholder-generated",
        secret_injection=[
            {"env": "GEN_ONE", "inject_to": ["api.example.com"]},
            {"env": "GEN_TWO", "inject_to": ["cdn.example.com"],
             "source": "env:GOLDEN_SET_VAR"},
        ],
    ))
    # Non-conforming explicit placeholder → warning, preserved verbatim.
    add("secrets-placeholder-legacy", _base(
        "secrets-placeholder-legacy",
        secret_injection=[{
            "env": "LEGACY_KEY", "placeholder": "{{LEGACY_KEY}}",
            "inject_to": ["api.example.com"],
        }],
    ))
    add("secrets-injection-options", _base(
        "secrets-injection-options",
        secret_injection=[{
            "env": "BODY_KEY",
            "placeholder": "agentcage:secret:BODY_KEY:" + "1" * 32,
            "inject_to": ["api.example.com"],
            "source": "env:GOLDEN_SET_VAR",
            "inject_body": True,
            "inject_headers": [" x-honeycomb-team ", "X-Custom-Auth"],
        }],
    ))
    add("secrets-transform-google-jwt", _base(
        "secrets-transform-google-jwt",
        secret_injection=[{
            "env": "GOOGLE_SA",
            "placeholder": "agentcage:secret:GOOGLE_SA:" + "2" * 32,
            "inject_to": ["oauth2.googleapis.com"],
            "source": "env:GOLDEN_SET_VAR",
            "transform": "google-jwt-bearer",
            "transform_config": {"scope": "https://www.googleapis.com/auth/cloud-platform"},
        }],
        domains={"allow": ["oauth2.googleapis.com"]},
    ))
    # Mapping form (``secret_injection.rules``) rather than a bare list.
    add("secrets-injection-rules-mapping", _base(
        "secrets-injection-rules-mapping",
        secret_injection={"rules": [{
            "env": "MAPPED_KEY",
            "placeholder": "agentcage:secret:MAPPED_KEY:" + "3" * 32,
            "inject_to": ["api.example.com"],
        }]},
    ))
    # Injected names must be stripped from env/podman_secrets.
    add("secrets-stripped-from-env", _base(
        "secrets-stripped-from-env",
        container={
            "env": {"FAKE_API_KEY": "should-be-stripped", "KEEP_ME": "kept"},
            "podman_secrets": ["FAKE_API_KEY", "KEEP_SECRET"],
        },
        secret_injection=[{
            "env": "FAKE_API_KEY",
            "placeholder": "agentcage:secret:FAKE_API_KEY:" + "4" * 32,
            "inject_to": ["api.example.com"],
        }],
    ))
    for backend in ("auto", "systemd-creds", "plaintext"):
        add(f"secrets-backend-{backend}", _base(
            f"secrets-backend-{backend}",
            secrets={"backend": backend, "allow_plaintext": backend == "plaintext"},
        ))
    for scope in ("auto", "user", "system"):
        add(f"secrets-scope-{scope}", _base(
            f"secrets-scope-{scope}",
            secrets={"scope": scope},
            secret_injection=[{
                "env": "SCOPED_KEY",
                "placeholder": "agentcage:secret:SCOPED_KEY:" + "5" * 32,
                "inject_to": ["api.example.com"],
                "source": "systemd-creds:SCOPED_KEY",
            }],
        ))

    # ── protocol relays ────────────────────────────────────
    add("relay-imap", _base(
        "relay-imap",
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
            "upstream": {"host": "imap.example.com", "port": 993, "tls": True},
            "auth": {
                "type": "imap-login",
                "user_source": "env:GOLDEN_SET_VAR",
                "password_source": "systemd-creds:FAKE_IMAP_PASSWORD",
            },
            "policy": {
                "readonly": True,
                "folder_allowlist": ["INBOX", "Archive"],
                "folder_denylist": ["Trash"],
                "idle_timeout_seconds": 1800,
                "conn_rate_limit": "10/min",
            },
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1143]}},
    ))
    add("relay-imap-write-mode", _base(
        "relay-imap-write-mode",
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
            "upstream": {
                "host": "imap.example.com", "port": 993, "tls": True,
                "tls_servername": "imap-real.example.com",
            },
            "auth": {"password_source": "env:GOLDEN_SET_VAR"},
            "policy": {"write_mode": "organise"},
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1143]}},
    ))
    add("relay-imap-ca-file", _base(
        "relay-imap-ca-file",
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
            "upstream": {
                "host": "imap.example.com", "port": 993, "tls": True,
                "ca_file": "${HOME}/certs/fake-ca.pem",
            },
            "auth": {"password_source": "env:GOLDEN_SET_VAR"},
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1143]}},
    ))
    add("relay-imap-plaintext-upstream", _base(
        "relay-imap-plaintext-upstream",
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "127.0.0.1:1143",
            "upstream": {"host": "imap.internal.example", "port": 143, "tls": False},
            "auth": {},
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1143]}},
    ))
    add("relay-smtp", _base(
        "relay-smtp",
        protocol_relays=[{
            "name": "out", "type": "smtp", "listen": "0.0.0.0:1587",
            "upstream": {"host": "smtp.example.com", "port": 587, "tls": True},
            "auth": {
                "type": "plain",
                "user_source": "env:GOLDEN_SET_VAR",
                "password_source": "cmd:printf fake-smtp-password",
            },
            "policy": {
                "sender_allowlist": ["agent@example.com"],
                "recipient_allowlist": {
                    "addresses": ["ops@example.com"],
                    "domains": ["example.com"],
                },
                "max_message_bytes": 1048576,
                "max_recipients": 3,
                "send_rate_limit": "5/hour",
                "idle_timeout_seconds": 300,
            },
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1587]}},
    ))
    add("relay-smtp-recipient-shorthand", _base(
        "relay-smtp-recipient-shorthand",
        protocol_relays=[{
            "name": "out", "type": "smtp", "listen": "0.0.0.0:1587",
            "upstream": {"host": "smtp.example.com", "port": 587},
            "auth": {},
            "policy": {
                "recipient_allowlist": ["ops@example.com", "sec@example.com"],
                "bypass_inspectors_for_allowlisted": [],
            },
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1587]}},
    ))
    add("relay-ca-pem-inline", _base(
        "relay-ca-pem-inline",
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
            "upstream": {
                "host": "imap.example.com", "port": 993,
                "ca_pem": "-----BEGIN CERTIFICATE-----\nRkFLRQ==\n"
                          "-----END CERTIFICATE-----\n",
            },
            "auth": {},
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1143]}},
    ))

    # ── capture ────────────────────────────────────────────
    add("capture-off", _base("capture-off", capture={"enable_har": False}))
    add("capture-on", _base("capture-on", capture={"enable_har": True}))
    add("capture-tuned", _base(
        "capture-tuned",
        capture={
            "enable_har": True,
            "max_body_size": 4096,
            "max_file_size": 0,
            "min_action": "flag",
            "domains": ["api.example.com"],
            "exclude_domains": ["cdn.example.com"],
        },
    ))

    # ── inspectors ─────────────────────────────────────────
    add("inspectors-builtin-chain", _base(
        "inspectors-builtin-chain",
        inspectors=[
            {"name": "domain"},
            {"name": "secrets", "config": {"action": "block"}},
            {"name": "body-size", "config": {"max_bytes": 1048576}},
            {"name": "entropy", "config": {"threshold": 4.5}},
            {"name": "content-type", "config": {"action": "flag"}},
        ],
    ))
    add("inspectors-custom-path", _base(
        "inspectors-custom-path",
        inspectors=[{"name": "house-rules",
                     "path": "/etc/agentcage/inspectors/house_rules.py"}],
    ))
    add("inspectors-empty", _base("inspectors-empty", inspectors=[]))

    # ── rate limits + proxy-only keys ──────────────────────
    add("proxy-keys-rate-limit", _base(
        "proxy-keys-rate-limit",
        rate_limit={"requests_per_second": 5, "burst": 20},
        max_request_body=2097152,
        entropy={"threshold": 4.2, "action": "flag"},
        content_type={"action": "block", "allow": ["application/json"]},
        secrets={"enabled": True, "action": "block",
                 "extra_patterns": ["FAKE-[0-9]{4}"]},
    ))

    # ── agents ─────────────────────────────────────────────
    for provider, model, base_url in (
        ("anthropic", "claude-fake-1", ""),
        ("openai", "gpt-fake-1", ""),
        ("openrouter", "vendor/model-fake", "https://openrouter.example.com/api/v1"),
    ):
        add(f"agents-decider-{provider}", _base(
            f"agents-decider-{provider}",
            agents={"decider": {
                "enable": True,
                "provider": provider,
                "model": model,
                "api_key": "systemd-creds:FAKE_DECIDER_KEY",
                "base_url": base_url,
            }},
        ))
    add("agents-decider-full", _base(
        "agents-decider-full",
        agents={"decider": {
            "enable": True,
            "provider": "anthropic",
            "model": "claude-fake-1",
            "api_key": "env:GOLDEN_SET_VAR",
            "host": "control.agentcage.local",
            "context": "This cage builds documentation for an internal wiki.",
            "rate_limit": {"requests_per_second": 0, "burst": 0},
            "timeout_seconds": 20,
            "max_tokens": 4096,
        }},
    ))
    add("agents-watcher-full", _base(
        "agents-watcher-full",
        agents={"watcher": {
            "enable": True,
            "provider": "openai",
            "model": "gpt-fake-1",
            "api_key": "systemd-creds:FAKE_WATCHER_KEY",
            "interval_seconds": 600,
            "window_seconds": 7200,
            "max_flows": 500,
            "max_digest_tokens": 16000,
            "auto_revoke": False,
            "dedup_samples": False,
            "context": "Read-only documentation cage.",
            "timeout_seconds": 45,
        }},
    ))
    # Spend-guardrail warnings.
    add("agents-watcher-unbounded-digest", _base(
        "agents-watcher-unbounded-digest",
        agents={"watcher": {
            "enable": True, "provider": "anthropic", "model": "claude-fake-1",
            "api_key": "env:GOLDEN_SET_VAR", "max_digest_tokens": 0,
        }},
    ))
    add("agents-watcher-expensive", _base(
        "agents-watcher-expensive",
        agents={"watcher": {
            "enable": True, "provider": "anthropic", "model": "claude-fake-1",
            "api_key": "env:GOLDEN_SET_VAR",
            "interval_seconds": 60, "max_flows": 2000,
            "max_digest_tokens": 100000,
        }},
    ))
    add("agents-both", _base(
        "agents-both",
        agents={
            "decider": {
                "enable": True, "provider": "anthropic",
                "model": "claude-fake-1", "api_key": "env:GOLDEN_SET_VAR",
            },
            "watcher": {
                "enable": True, "provider": "anthropic",
                "model": "claude-fake-1", "api_key": "env:GOLDEN_SET_VAR",
            },
        },
    ))
    add("agents-disabled-blocks", _base(
        "agents-disabled-blocks",
        agents={"decider": {"enable": False}, "watcher": {"enable": False}},
    ))
    # Watcher with no domains section at all (mode "") is allowed.
    add("agents-watcher-no-domains", {
        "name": "agents-watcher-no-domains",
        "container": {"image": "docker.io/library/node:22-slim"},
        "dns_servers": ["192.0.2.53"],
        "agents": {"watcher": {
            "enable": True, "provider": "anthropic", "model": "claude-fake-1",
            "api_key": "env:GOLDEN_SET_VAR",
        }},
    })

    # ── volume mounts, one shape at a time ─────────────────
    add("volumes-ro", _base(
        "volumes-ro",
        container={"volumes": ["${HOME}/workspace:/workspace:ro"]},
    ))
    add("volumes-rw", _base(
        "volumes-rw",
        container={"volumes": ["${HOME}/workspace:/workspace:rw"]},
    ))
    add("volumes-no-options", _base(
        "volumes-no-options",
        container={"volumes": ["${HOME}/workspace:/workspace"]},
    ))
    add("volumes-np", _base(
        "volumes-np",
        container={"volumes": ["${HOME}/workspace:/workspace:np"]},
    ))
    add("volumes-np-rw", _base(
        "volumes-np-rw",
        container={"volumes": ["${HOME}/project:/project:rw,np"]},
    ))
    add("volumes-np-file", _base(
        "volumes-np-file",
        container={"volumes": ["${HOME}/dotfile.conf:/etc/app.conf:np"]},
    ))
    add("volumes-selinux-relabel", _base(
        "volumes-selinux-relabel",
        container={"volumes": ["${HOME}/workspace:/workspace:rw,z"]},
    ))
    add("volumes-missing-source", _base(
        "volumes-missing-source",
        container={"volumes": ["${HOME}/does-not-exist:/missing:ro"]},
    ))
    add("volumes-unresolved-var", _base(
        "volumes-unresolved-var",
        container={"volumes": ["${GOLDEN_UNSET_VAR}/x:/x:ro"]},
    ))
    add("volumes-named", _base(
        "volumes-named",
        container={"named_volumes": {"state": "/var/lib/state:rw",
                                     "cache": "/var/cache:ro"}},
    ))
    add("volumes-multiple", _base(
        "volumes-multiple",
        container={
            "volumes": [
                "${HOME}/workspace:/workspace:rw",
                "${HOME}/project:/project:ro",
                "${HOME}/data:/data:rw,np",
            ],
            "named_volumes": {"state": "/var/lib/state:rw"},
        },
    ))

    # ── tmpfs + masking ────────────────────────────────────
    add("tmpfs-plain", _base(
        "tmpfs-plain",
        container={"tmpfs": ["/tmp:rw,noexec,nosuid,size=64M"]},
    ))
    add("tmpfs-no-options", _base(
        "tmpfs-no-options", container={"tmpfs": ["/scratch"]},
    ))
    add("tmpfs-mask-over-bind", _base(
        "tmpfs-mask-over-bind",
        container={
            "volumes": ["${HOME}/project:/workspace:rw"],
            "tmpfs": ["/workspace/.git/hooks:rw,noexec,nosuid,nodev,size=64M"],
        },
    ))
    add("tmpfs-mask-copyup", _base(
        "tmpfs-mask-copyup",
        container={
            "volumes": ["${HOME}/project:/workspace:rw"],
            "tmpfs": ["/workspace/.claude:rw,tmpcopyup"],
        },
    ))
    add("tmpfs-mask-no-copyup", _base(
        "tmpfs-mask-no-copyup",
        container={
            "volumes": ["${HOME}/project:/workspace:rw"],
            "tmpfs": ["/workspace/.claude:rw,notmpcopyup"],
        },
    ))
    add("tmpfs-mask-over-named-volume", _base(
        "tmpfs-mask-over-named-volume",
        container={
            "named_volumes": {"state": "/var/lib/state:rw"},
            "tmpfs": ["/var/lib/state/secrets:rw,tmpcopyup"],
        },
    ))
    add("tmpfs-mask-over-np", _base(
        "tmpfs-mask-over-np",
        container={
            "volumes": ["${HOME}/project:/workspace:rw,np"],
            "tmpfs": ["/workspace/.git/hooks:rw,tmpcopyup"],
        },
    ))
    add("tmpfs-mask-trailing-slash", _base(
        "tmpfs-mask-trailing-slash",
        container={
            "volumes": ["${HOME}/project:/workspace:rw"],
            "tmpfs": ["/workspace/.git/hooks/:rw,noexec"],
        },
    ))

    # ── logging ────────────────────────────────────────────
    for level in ("debug", "info", "warning", "error", "critical"):
        add(f"logging-level-{level}", _base(
            f"logging-level-{level}", logging={"level": level},
        ))
    add("logging-per-service", _base(
        "logging-per-service",
        logging={
            "level": "warning", "dns": "debug", "proxy": "error",
            "cage": "critical", "dns_queries": True,
            "proxy_connections": True, "allowed_requests": True,
        },
    ))
    add("logging-legacy-log-allowed", _base(
        "logging-legacy-log-allowed", log_allowed=True,
    ))

    # ── ports ──────────────────────────────────────────────
    add("ports-defaults", _base("ports-defaults"))
    add("ports-tcp-extra", _base(
        "ports-tcp-extra", ports={"tcp": {"allow": [80, 443, 8448]}},
    ))
    add("ports-tcp-passthrough", _base(
        "ports-tcp-passthrough",
        ports={"tcp": {"allow": [80, 443, 9418], "passthrough": [9418]}},
    ))
    add("ports-tcp-passthrough-implicit", _base(
        "ports-tcp-passthrough-implicit",
        ports={"tcp": {"allow": [443], "passthrough": [8080]}},
    ))
    add("ports-udp", _base(
        "ports-udp", ports={"udp": {"allow": [443, 123]}},
    ))
    add("ports-icmp", _base("ports-icmp", ports={"icmp": {"allow": True}}))
    add("ports-none", _base(
        "ports-none",
        ports={"tcp": {"allow": [], "passthrough": []}, "udp": {"allow": []}},
    ))
    add("ports-all-inspected-removed", _base(
        "ports-all-inspected-removed",
        ports={"tcp": {"allow": [443], "passthrough": [443]}},
    ))
    add("ports-container-publish", _base(
        "ports-container-publish",
        container={"ports": ["127.0.0.1:3000:3000", "8081:8081", "3001:3001"]},
    ))

    # ── domains ────────────────────────────────────────────
    add("domains-allowlist", _base(
        "domains-allowlist", domains={"allow": ["a.example.com", "b.example.org"]},
    ))
    add("domains-blocklist", _base(
        "domains-blocklist", domains={"allow": DELETE, "block": ["bad.example.com"]},
    ))
    add("domains-legacy-mode-list", {
        "name": "domains-legacy-mode-list",
        "container": {"image": "docker.io/library/node:22-slim"},
        "dns_servers": ["192.0.2.53"],
        "domains": {"mode": "allowlist", "list": ["legacy.example.com"]},
    })
    add("domains-legacy-blocklist", {
        "name": "domains-legacy-blocklist",
        "container": {"image": "docker.io/library/node:22-slim"},
        "dns_servers": ["192.0.2.53"],
        "domains": {"mode": "blocklist", "list": ["bad.example.com"]},
    })
    add("domains-none", {
        "name": "domains-none",
        "container": {"image": "docker.io/library/node:22-slim"},
        "dns_servers": ["192.0.2.53"],
    })
    add("domains-allow-empty", _base(
        "domains-allow-empty", domains={"allow": []},
    ))
    add("domains-passthrough", _base(
        "domains-passthrough",
        domains={"allow": ["api.example.com"],
                 "passthrough": ["api.example.com", "chat.example.net"]},
    ))
    add("domains-two-letter-tld", _base(
        "domains-two-letter-tld",
        domains={"allow": ["api.example.io", "docs.example.co.uk"]},
    ))
    add("domains-single-label", _base(
        "domains-single-label",
        domains={"allow": ["api.example.com", "fcos-vm-home-01", "nas"]},
    ))
    add("domains-expires-map", _base(
        "domains-expires-map",
        domains={
            "allow": ["api.example.com", "tmp.example.org"],
            "expires": {"TMP.EXAMPLE.ORG.": "2030-01-01T00:00:00+00:00"},
        },
    ))
    add("domains-expires-list", _base(
        "domains-expires-list",
        domains={
            "allow": ["api.example.com", "tmp.example.org"],
            "expires": [{"domain": "tmp.example.org",
                         "expires_at": "2030-01-01T00:00:00+00:00"}],
        },
    ))
    add("domains-allow-and-block-empty", _base(
        "domains-allow-and-block-empty",
        domains={"allow": ["api.example.com"], "block": []},
    ))
    add("dns-servers-autodetected", {
        "name": "dns-servers-autodetected",
        "container": {"image": "docker.io/library/node:22-slim"},
        "domains": {"allow": ["api.example.com"]},
    })

    # ── container knobs ────────────────────────────────────
    add("container-image-digest-pin", _base(
        "container-image-digest-pin",
        container={"image": "docker.io/library/node@sha256:" + "a" * 64},
    ))
    add("container-user-image-default", _base(
        "container-user-image-default", container={"user": ""},
    ))
    add("container-user-explicit", _base(
        "container-user-explicit", container={"user": "0:0"},
    ))
    add("container-userns-keep-id", _base(
        "container-userns-keep-id", container={"userns": "keep-id"},
    ))
    add("container-resources", _base(
        "container-resources",
        container={"memory": "4g", "cpus": "2.5",
                   "restart": "always", "restart_sec": 30,
                   "timeout_start_sec": 900, "timeout_stop_sec": 90},
    ))
    add("container-caps", _base(
        "container-caps",
        container={"drop_capabilities": ["CAP_NET_RAW", "CAP_SYS_ADMIN"],
                   "add_capabilities": ["NET_BIND_SERVICE"],
                   "no_new_privileges": False,
                   "read_only": False,
                   "security_label_disable": False},
    ))
    add("container-drop-caps-empty", _base(
        "container-drop-caps-empty", container={"drop_capabilities": []},
    ))
    add("container-drop-caps-scalar", _base(
        "container-drop-caps-scalar", container={"drop_capabilities": "ALL"},
    ))
    add("container-nested", _base(
        "container-nested", container={"nested_containers": True},
    ))
    add("container-build", _base(
        "container-build",
        container={"build": {"containerfile": "Containerfile",
                             "args": {"BASE": "node:22-slim"}}},
    ))
    add("container-env-refs", _base(
        "container-env-refs",
        container={"env": {
            "SET": "${GOLDEN_SET_VAR}",
            "UNSET": "${GOLDEN_UNSET_VAR}",
            "MIXED": "a${GOLDEN_UNSET_VAR}b${GOLDEN_SET_VAR}c",
            "UNCLOSED": "${GOLDEN_UNSET",
            "PLAIN": "literal",
        }},
    ))
    add("container-timeouts-zero", _base(
        "container-timeouts-zero",
        container={"timeout_start_sec": 0, "timeout_stop_sec": 0,
                   "restart_sec": 0},
    ))
    add("container-podman-secrets", _base(
        "container-podman-secrets",
        container={"podman_secrets": ["FAKE_ONE", "FAKE_TWO"]},
    ))

    # ── misc top-level ─────────────────────────────────────
    add("misc-help-and-aliases", _base(
        "misc-help-and-aliases",
        help="Open http://localhost:3000 in your browser.\n",
        exec_aliases={"agent": ["node", "agent.js"], "sh": ["/bin/sh"]},
        scaffold="claude-code",
    ))
    add("misc-empty-config", {})
    add("misc-kitchen-sink", _base(
        "misc-kitchen-sink",
        isolation="container",
        lifecycle="interactive",
        container={
            "image": "docker.io/library/node:22-slim",
            "volumes": ["${HOME}/project:/workspace:rw",
                        "${HOME}/data:/data:rw,np"],
            "named_volumes": {"state": "/var/lib/state:rw"},
            "tmpfs": ["/tmp:rw,noexec,nosuid,size=64M",
                      "/workspace/.git/hooks:rw,noexec,nosuid,nodev,size=64M"],
            "ports": ["127.0.0.1:3000:3000"],
            "env": {"NODE_ENV": "production"},
            "memory": "2g", "cpus": "2",
            "user": "1000:1000", "userns": "keep-id",
            "read_only": False,
        },
        domains={"allow": ["api.example.com", "registry.example.net"],
                 "passthrough": ["registry.example.net"]},
        capture={"enable_har": True, "min_action": "flag"},
        logging={"level": "debug", "dns_queries": True},
        ports={"tcp": {"allow": [80, 443, 9418], "passthrough": [9418]},
               "udp": {"allow": [443]}, "icmp": {"allow": True}},
        secret_injection=[{
            "env": "FAKE_API_KEY",
            "inject_to": ["api.example.com"],
            "source": "systemd-creds:FAKE_API_KEY",
        }],
        inspectors=[{"name": "domain"}, {"name": "secrets"}],
        agents={"decider": {
            "enable": True, "provider": "anthropic", "model": "claude-fake-1",
            "api_key": "systemd-creds:FAKE_DECIDER_KEY",
        }},
    ))

    return [(case_id, _y(cfg), opts) for case_id, cfg, opts in cases]


def _invalid_cases() -> list[tuple[str, str, dict]]:
    """One case per distinct validation failure.

    Mined from every ``raise`` site reachable from a ``cage.yaml`` — in
    ``config.py`` itself and in the validators it calls
    (``volume_mounts``, ``secret_resolver``, ``relays._validate``).  The
    generated ``RAISE-COVERAGE.md`` reports which sites this reaches.
    """
    cases: list[tuple[str, object, dict]] = []
    darwin = {"platform": ("Darwin", "arm64")}

    def add(case_id: str, cfg, **opts) -> None:
        cases.append((case_id, cfg, opts))

    # ── load_config: file + YAML level ─────────────────────
    add("err-yaml-syntax", "RAW:name: [unclosed\n")
    add("err-yaml-tab", "RAW:name: x\n\tbad: 1\n")

    # ── validate_agents_raw ────────────────────────────────
    add("err-agents-domains-not-mapping", "RAW:domains: 'nope'\n")
    add("err-agents-domains-auto", _base(
        "x", domains={"allow": ["a.example.com"], "auto": {"enable": True}}))
    add("err-agents-top-level-watcher", _base("x", watcher={"enable": True}))
    add("err-agents-not-mapping", "RAW:agents: 'nope'\n")
    add("err-agents-unknown-role", _base("x", agents={"auditor": {}}))
    add("err-agents-role-not-mapping", _base("x", agents={"decider": "nope"}))
    add("err-agents-decider-kind", _base(
        "x", agents={"decider": {"kind": "llm"}}))
    add("err-agents-decider-wrapper-agent", _base(
        "x", agents={"decider": {"agent": {"provider": "anthropic"}}}))
    add("err-agents-watcher-wrapper-decider", _base(
        "x", agents={"watcher": {"decider": {"provider": "anthropic"}}}))
    add("err-agents-enable-not-bool", _base(
        "x", agents={"decider": {"enable": "false"}}))
    add("err-agents-auto-revoke-not-bool", _base(
        "x", agents={"watcher": {"enable": True, "auto_revoke": "no"}}))
    add("err-agents-dedup-samples-not-bool", _base(
        "x", agents={"watcher": {"enable": True, "dedup_samples": 1}}))

    # ── load_config: secrets section ───────────────────────
    add("err-secrets-scope-invalid", _base("x", secrets={"scope": "global"}))
    add("err-secrets-backend-invalid", _base("x", secrets={"backend": "vault"}))

    # ── secret_resolver validators ─────────────────────────
    add("err-secret-env-name-invalid", _base("x", secret_injection=[
        {"env": "not-a-valid-name", "inject_to": ["api.example.com"]}]))
    add("err-secret-source-scheme-unknown", _base("x", secret_injection=[
        {"env": "KEY", "source": "vault:KEY", "inject_to": ["api.example.com"]}]))
    add("err-secret-transform-unknown", _base("x", secret_injection=[
        {"env": "KEY", "source": "env:GOLDEN_SET_VAR", "transform": "nope",
         "inject_to": ["api.example.com"]}]))

    # ── relays/_validate.py ────────────────────────────────
    add("err-relay-entry-not-mapping", _base("x", protocol_relays=["nope"]))
    add("err-relay-missing-fields", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap"}]))
    add("err-relay-unknown-type", _base("x", protocol_relays=[
        {"name": "mail", "type": "pop3", "listen": "0.0.0.0:1110",
         "upstream": {"host": "h.example.com", "port": 110}}]))
    add("err-relay-upstream-not-mapping", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": "h.example.com:993"}]))
    add("err-relay-upstream-bad-port", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 70000}}]))
    add("err-relay-ca-file-not-string", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993, "ca_file": 7}}]))
    add("err-relay-ca-pem-not-string", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993, "ca_pem": 7}}]))
    add("err-relay-ca-pem-not-pem", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993,
                      "ca_pem": "not a certificate"}}]))
    add("err-relay-ca-file-and-pem", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993,
                      "ca_file": "/tmp/ca.pem",
                      "ca_pem": "-----BEGIN CERTIFICATE-----\nZg==\n"
                                "-----END CERTIFICATE-----\n"}}]))
    add("err-relay-servername-not-string", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993,
                      "tls_servername": ["a"]}}]))
    add("err-relay-tls-false-with-ca", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 143, "tls": False,
                      "ca_file": "/tmp/ca.pem"}}]))
    add("err-relay-write-mode-invalid", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993},
         "policy": {"write_mode": "readwrite"}}]))
    add("err-relay-write-mode-contradicts-readonly", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993},
         "policy": {"write_mode": "full", "readonly": True}}]))
    add("err-relay-folder-allowlist-not-list", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993},
         "policy": {"folder_allowlist": "INBOX"}}]))
    add("err-relay-auth-not-mapping", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993},
         "auth": "user:pass"}]))
    add("err-relay-auth-source-scheme", _base("x", protocol_relays=[
        {"name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
         "upstream": {"host": "h.example.com", "port": 993},
         "auth": {"password_source": "vault:PW"}}]))

    # ── load_config: agents blocks ─────────────────────────
    add("err-agents-llm-timeout-bool", _base("x", agents={"decider": {
        "enable": True, "provider": "anthropic", "model": "m",
        "api_key": "env:K", "timeout_seconds": True}}))
    add("err-agents-llm-max-tokens-not-number", _base("x", agents={"decider": {
        "enable": True, "provider": "anthropic", "model": "m",
        "api_key": "env:K", "max_tokens": "lots"}}))
    add("err-agents-decider-context-not-string", _base("x", agents={"decider": {
        "enable": True, "context": {"a": 1}}}))
    add("err-agents-watcher-context-not-string", _base("x", agents={"watcher": {
        "enable": True, "context": ["a"]}}))
    add("err-agents-decider-api-key-no-scheme", _base("x", agents={"decider": {
        "enable": True, "provider": "anthropic", "model": "m",
        "api_key": "BARE_KEY_NAME"}}))
    add("err-agents-watcher-api-key-no-scheme", _base("x", agents={"watcher": {
        "enable": True, "provider": "anthropic", "model": "m",
        "api_key": "BARE_KEY_NAME"}}))
    add("err-agents-watcher-number-not-number", _base("x", agents={"watcher": {
        "enable": True, "provider": "anthropic", "model": "m",
        "api_key": "env:K", "interval_seconds": "soon"}}))

    # ── load_config: ports structure ───────────────────────
    add("err-ports-not-mapping", _base("x", ports=[80, 443]))
    add("err-ports-tcp-not-mapping", _base("x", ports={"tcp": [80, 443]}))
    add("err-ports-tcp-allow-not-list", _base(
        "x", ports={"tcp": {"allow": "80,443"}}))
    add("err-ports-tcp-passthrough-not-list", _base(
        "x", ports={"tcp": {"passthrough": 9418}}))
    add("err-ports-udp-not-mapping", _base("x", ports={"udp": [443]}))
    add("err-ports-udp-allow-not-list", _base(
        "x", ports={"udp": {"allow": 443}}))
    add("err-ports-icmp-not-mapping", _base("x", ports={"icmp": True}))
    add("err-ports-icmp-allow-not-bool", _base(
        "x", ports={"icmp": {"allow": "yes-please"}}))

    # ── validate_config: identity + image ──────────────────
    add("err-name-missing", {
        "container": {"image": "docker.io/library/node:22-slim"},
        "dns_servers": ["192.0.2.53"]})
    add("err-name-invalid-chars", _base("Not_A_Valid_Name"))
    add("err-name-too-long", _base("a" * 64))
    add("err-image-missing", {
        "name": "err-image-missing", "container": {},
        "dns_servers": ["192.0.2.53"]})
    add("err-image-invalid-ref", _base(
        "x", container={"image": "!!not a ref!!"}))

    # ── volume_mounts.validate_non_persistent_volume ───────
    add("err-volume-np-with-z", _base(
        "x", container={"volumes": ["${HOME}/workspace:/workspace:np,z"]}))

    # ── validate_config: isolation + lifecycle ─────────────
    add("err-isolation-unknown", _base("x", isolation="jail"))
    add("err-lifecycle-unknown", _base("x", lifecycle="daemon"))
    add("err-isolation-container-on-macos", _base(
        "x", isolation="container"), **darwin)
    add("err-isolation-apple-on-linux", _base("x", isolation="apple-container"))
    add("err-isolation-apple-on-intel-mac", _base(
        "x", isolation="apple-container"),
        platform=("Darwin", "x86_64"))
    add("err-vm-vcpus-too-low", _base(
        "x", isolation="vm", vm={"vcpus": 0, "mem_mb": 2048}))
    add("err-vm-mem-too-low", _base(
        "x", isolation="vm", vm={"vcpus": 2, "mem_mb": 64}))

    # ── validate_config: logging ───────────────────────────
    add("err-logging-level-invalid", _base("x", logging={"level": "verbose"}))
    add("err-logging-service-level-invalid", _base(
        "x", logging={"dns": "verbose"}))

    # ── validate_config: container.ports specs ─────────────
    add("err-container-port-spec-shape", _base(
        "x", container={"ports": ["3000"]}))
    add("err-container-port-not-a-number", _base(
        "x", container={"ports": ["127.0.0.1:http:3000"]}))
    add("err-container-port-out-of-range", _base(
        "x", container={"ports": ["127.0.0.1:99999:3000"]}))

    # ── validate_config: ports.* entries ───────────────────
    add("err-port-entry-not-int", _base(
        "x", ports={"tcp": {"allow": ["443"]}}))
    add("err-port-entry-bool", _base("x", ports={"udp": {"allow": [True]}}))
    add("err-port-entry-out-of-range", _base(
        "x", ports={"tcp": {"allow": [70000]}}))
    add("err-port-entry-duplicate", _base(
        "x", ports={"tcp": {"allow": [443, 443]}}))
    add("err-port-reserved-8080", _base(
        "x", ports={"tcp": {"allow": [80, 443, 8080]}}))
    add("err-port-reserved-8443", _base(
        "x", ports={"tcp": {"allow": [80, 443, 8443]}}))
    add("err-port-collides-with-relay", _base(
        "x",
        ports={"tcp": {"allow": [80, 443, 1143]}},
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
            "upstream": {"host": "imap.example.com", "port": 993},
        }]))
    add("err-port-collides-with-publish", _base(
        "x",
        ports={"tcp": {"allow": [80, 443, 3000]}},
        container={"ports": ["127.0.0.1:3000:3000"]}))

    # ── validate_config: domains ───────────────────────────
    add("err-domains-allow-and-block", _base(
        "x", domains={"allow": ["a.example.com"], "block": ["b.example.com"]}))
    add("err-domain-syntax-newline", _base(
        "x", domains={"allow": ["evil.example.com\nserver=/x/1.2.3.4"]}))
    add("err-domain-syntax-uppercase", _base(
        "x", domains={"allow": ["API.example.com"]}))
    add("err-domain-syntax-ip-literal", _base(
        "x", domains={"allow": ["192.0.2.10"]}))
    add("err-domain-syntax-short-tld", _base(
        "x", domains={"allow": ["x.c"]}))
    add("err-domain-syntax-block", _base(
        "x", domains={"block": ["bad domain.example.com"]}))
    add("err-domain-syntax-passthrough", _base(
        "x", domains={"allow": ["a.example.com"],
                      "passthrough": [".example.com"]}))
    add("err-domain-syntax-expires-key", _base(
        "x", domains={"allow": ["a.example.com"],
                      "expires": {"not/a/domain": "2030-01-01T00:00:00Z"}}))

    # ── validate_config: nested containers ─────────────────
    add("err-nested-containers-on-vm", _base(
        "x", isolation="vm", container={"nested_containers": True}))

    # ── validate_config: agents.decider ────────────────────
    def _decider(**over):
        block = {
            "enable": True, "provider": "anthropic", "model": "claude-fake-1",
            "api_key": "systemd-creds:FAKE_KEY",
        }
        block.update(over)
        return block

    add("err-decider-timeout-not-positive", _base(
        "x", agents={"decider": _decider(timeout_seconds=0)}))
    add("err-decider-timeout-not-finite", _base(
        "x", agents={"decider": _decider(timeout_seconds=".inf")}))
    add("err-decider-host-single-label", _base(
        "x", agents={"decider": _decider(host="agentcage")}))
    add("err-decider-host-in-allow", _base(
        "x",
        domains={"allow": ["api.example.com", "agentcage.local"]},
        agents={"decider": _decider()}))
    add("err-decider-requires-allowlist", _base(
        "x", domains={"allow": DELETE, "block": ["bad.example.com"]},
        agents={"decider": _decider()}))
    add("err-decider-provider-invalid", _base(
        "x", agents={"decider": _decider(provider="ollama")}))
    add("err-decider-provider-wrong-case", _base(
        "x", agents={"decider": _decider(provider="Anthropic")}))
    add("err-decider-model-missing", _base(
        "x", agents={"decider": _decider(model="")}))
    add("err-decider-max-tokens-too-small", _base(
        "x", agents={"decider": _decider(max_tokens=256)}))
    add("err-decider-api-key-missing", _base(
        "x", agents={"decider": _decider(api_key="")}))
    add("err-decider-api-key-cmd", _base(
        "x", agents={"decider": _decider(api_key="cmd:printf fake")}))
    add("err-decider-api-key-podman", _base(
        "x", agents={"decider": _decider(api_key="podman:FAKE")}))
    add("err-decider-base-url-http", _base(
        "x", agents={"decider": _decider(base_url="http://llm.example.com/v1")}))
    add("err-decider-rate-limit-negative", _base(
        "x", agents={"decider": _decider(
            rate_limit={"requests_per_second": -1, "burst": 5})}))
    add("err-decider-context-too-long", _base(
        "x", agents={"decider": _decider(context="x" * 4097)}))

    # ── validate_config: agents.watcher ────────────────────
    def _watcher(**over):
        block = {
            "enable": True, "provider": "anthropic", "model": "claude-fake-1",
            "api_key": "systemd-creds:FAKE_KEY",
        }
        block.update(over)
        return block

    add("err-watcher-timeout-not-positive", _base(
        "x", agents={"watcher": _watcher(timeout_seconds=-1)}))
    add("err-watcher-blocklist-mode", _base(
        "x", domains={"allow": DELETE, "block": ["bad.example.com"]},
        agents={"watcher": _watcher()}))
    add("err-watcher-provider-invalid", _base(
        "x", agents={"watcher": _watcher(provider="ollama")}))
    add("err-watcher-model-missing", _base(
        "x", agents={"watcher": _watcher(model="")}))
    add("err-watcher-max-tokens-too-small", _base(
        "x", agents={"watcher": _watcher(max_tokens=512)}))
    add("err-watcher-api-key-missing", _base(
        "x", agents={"watcher": _watcher(api_key="")}))
    add("err-watcher-api-key-cmd", _base(
        "x", agents={"watcher": _watcher(api_key="cmd:printf fake")}))
    add("err-watcher-api-key-podman", _base(
        "x", agents={"watcher": _watcher(api_key="podman:FAKE")}))
    add("err-watcher-base-url-http", _base(
        "x", agents={"watcher": _watcher(base_url="http://llm.example.com/v1")}))
    add("err-watcher-interval-too-fast", _base(
        "x", agents={"watcher": _watcher(interval_seconds=30)}))
    add("err-watcher-window-too-long", _base(
        "x", agents={"watcher": _watcher(window_seconds=999999)}))
    add("err-watcher-window-zero", _base(
        "x", agents={"watcher": _watcher(window_seconds=0)}))
    add("err-watcher-max-flows-too-low", _base(
        "x", agents={"watcher": _watcher(max_flows=1)}))
    add("err-watcher-max-flows-too-high", _base(
        "x", agents={"watcher": _watcher(max_flows=5000)}))
    add("err-watcher-digest-tokens-too-low", _base(
        "x", agents={"watcher": _watcher(max_digest_tokens=100)}))
    add("err-watcher-digest-tokens-too-high", _base(
        "x", agents={"watcher": _watcher(max_digest_tokens=1000000)}))
    add("err-watcher-context-too-long", _base(
        "x", agents={"watcher": _watcher(context="y" * 5000)}))

    # ── quadlets.generate_quadlets ─────────────────────────
    # Not a validate_config raise, but the same operator-facing class of
    # error and the only one produced by the renderer.
    add("err-volume-outside-home", _base(
        "err-volume-outside-home", container={"volumes": ["/etc:/etc:ro"]}))

    # ── state.resolve_relay_ca_files ───────────────────────
    add("err-relay-ca-file-missing", _base(
        "err-relay-ca-file-missing",
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
            "upstream": {"host": "imap.example.com", "port": 993,
                         "ca_file": "${HOME}/certs/absent.pem"},
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1143]}}))
    add("err-relay-ca-file-not-pem", _base(
        "err-relay-ca-file-not-pem",
        protocol_relays=[{
            "name": "mail", "type": "imap", "listen": "0.0.0.0:1143",
            "upstream": {"host": "imap.example.com", "port": 993,
                         "ca_file": "${HOME}/dotfile.conf"},
        }],
        ports={"tcp": {"allow": [80, 443], "passthrough": [1143]}}))

    out: list[tuple[str, str, dict]] = []
    for case_id, cfg, opts in cases:
        if isinstance(cfg, str) and cfg.startswith("RAW:"):
            text = cfg[len("RAW:"):]
        else:
            body = dict(cfg)
            # Every error case gets the case id as its cage name unless it is
            # specifically testing the name field.
            if body.get("name") == "x":
                body["name"] = case_id
            text = _y(body)
        out.append((case_id, text, opts))
    return out


# ---------------------------------------------------------------------------
# Special cases: error paths that no cage.yaml on disk can reach
# ---------------------------------------------------------------------------

def _special_cases(out_root: Path, scrubber: Scrubber, work: Path) -> list[dict]:
    """Capture operator-facing errors raised outside the load-a-file path.

    Each one is a real, reachable `raise` in ``config.py`` that the ordinary
    corpus pipeline cannot trigger: the file is never opened, or a different
    entry point calls the validator. They get an ``invocation.txt`` in place
    of ``input/cage.yaml``.
    """
    import agentcage.config as config_mod

    records: list[dict] = []

    def record(case_id: str, invocation: str, fn) -> None:
        w = CorpusWriter(out_root / "invalid" / case_id, scrubber)
        w.write("invocation.txt", invocation + "\n")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            w.write("error.txt", f"{type(exc).__name__}: {exc}\n")
            records.append({
                "case": case_id, "kind": "invalid", "platform": ["Linux", "x86_64"],
                "error_type": type(exc).__name__, "stage": "special",
            })
            return
        raise SystemExit(f"special case {case_id} did not raise")

    # load_config on a path that cannot be opened.
    missing = work / "staging" / "definitely-absent.yaml"
    record(
        "err-file-unreadable",
        "config.load_config('<missing path>')",
        lambda: config_mod.load_config(str(missing)),
    )

    # validate_agents_raw with a non-mapping. load_config short-circuits a
    # scalar document into an empty Config before reaching this, but
    # state.save_deployment calls the validator directly.
    record(
        "err-config-not-a-mapping",
        "config.validate_agents_raw('just a string')",
        lambda: config_mod.validate_agents_raw("just a string"),
    )

    # Host DNS auto-detection with nothing usable. Both messages are
    # platform-specific; the patched ``_host_dns_servers`` in the rest of the
    # corpus hides them, so call the real implementation here.
    real_host_dns = _REAL_HOST_DNS

    def _no_upstreams(system: str):
        def run():
            saved_read = config_mod._read_nameservers
            saved_scutil = config_mod._scutil_dns_servers
            config_mod._read_nameservers = lambda path: ["127.0.0.53"]
            config_mod._scutil_dns_servers = lambda: []
            try:
                with _as_platform(system, "x86_64"):
                    real_host_dns()
            finally:
                config_mod._read_nameservers = saved_read
                config_mod._scutil_dns_servers = saved_scutil
        return run

    record(
        "err-dns-detect-linux",
        "config._host_dns_servers() with only loopback resolvers (Linux)",
        _no_upstreams("Linux"),
    )
    record(
        "err-dns-detect-macos",
        "config._host_dns_servers() with only loopback resolvers (Darwin)",
        _no_upstreams("Darwin"),
    )

    return records


# ---------------------------------------------------------------------------
# Per-case pipeline
# ---------------------------------------------------------------------------

def _dataclass_to_jsonable(value):
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _dataclass_to_jsonable(getattr(value, f.name))
                for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {k: _dataclass_to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dataclass_to_jsonable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_dataclass_to_jsonable(v) for v in value)
    return value


def _json_text(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


class CorpusWriter:
    """Writes scrubbed text files, recording every path it produced."""

    def __init__(self, root: Path, scrubber: Scrubber) -> None:
        self.root = root
        self._scrub = scrubber
        self.written: list[str] = []

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._scrub.text(text), encoding="utf-8")
        self.written.append(rel)


def _volume_report(cfg) -> dict:
    """Everything ``volume_mounts.py`` derives from this config's mounts."""
    from agentcage import volume_mounts as vm

    mount_targets = [
        (vm.split_volume_spec(spec)[1],
         "" if vm.is_non_persistent_volume(spec) else vm.split_volume_spec(spec)[0])
        for spec in cfg.container.volumes
    ] + [
        (mount.split(":", 1)[0], "")
        for mount in cfg.container.named_volumes.values()
    ]
    volumes = []
    for spec in cfg.container.volumes:
        source, target, options = vm.split_volume_spec(spec)
        volumes.append({
            "spec": spec,
            "source": source,
            "target": target,
            "raw_options": options,
            "options": vm.volume_options(spec),
            "non_persistent": vm.is_non_persistent_volume(spec),
        })
    tmpfs = []
    for spec in cfg.container.tmpfs:
        target = vm.tmpfs_spec_target(spec)
        tmpfs.append({
            "spec": spec,
            "target": target,
            "options": vm.tmpfs_spec_options(spec),
            "wants_copyup": vm.tmpfs_wants_copyup(spec),
            "enclosing_mount": list(vm.enclosing_mount(target, mount_targets)),
        })
    return {
        "mount_targets": [list(t) for t in mount_targets],
        "volumes": volumes,
        "tmpfs": tmpfs,
        # mask_mountpoint_dirs returns dict[host_source -> [host dirs]].
        # Iterating it yields only the KEYS, which silently recorded the bind
        # sources and dropped the host paths underneath them -- the half that
        # #320's ExecStopPost rmdir chain actually consumes, including its
        # deepest-first ordering. Record ordered [source, [dirs]] pairs so the
        # ordering stays visible; a JSON object would not promise to keep it.
        "mask_mountpoint_dirs": [
            [source, list(dirs)]
            for source, dirs in vm.mask_mountpoint_dirs(
                cfg.container.tmpfs, mount_targets).items()
        ],
        "mask_copyup_entries": [
            list(entry) for entry in vm.mask_copyup_entries(
                cfg.container.tmpfs, mount_targets)
        ],
    }


def _run_case(case_id: str, yaml_text: str, opts: dict, out_root: Path,
              scrubber: Scrubber, work: Path) -> dict:
    """Load, validate and render one case; return its manifest record."""
    from agentcage import quadlets, state
    from agentcage.config import load_config, validate_config
    from agentcage.fingerprint import compute_fingerprint

    system, machine = opts.get("platform", ("Linux", "x86_64"))
    # Restart the placeholder counter for every case so a token depends only
    # on its position within its own cage.yaml, not on how many cases ran
    # first — otherwise inserting a case renumbers the whole corpus.
    _PLACEHOLDER_COUNTER["n"] = 0

    staging = work / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    src = staging / f"{case_id}.yaml"
    src.write_text(yaml_text)

    with _as_platform(system, machine):
        try:
            cfg = load_config(str(src))
            warnings = validate_config(cfg)
        except Exception as exc:  # noqa: BLE001 — capturing the UX string is the point
            w = CorpusWriter(out_root / "invalid" / case_id, scrubber)
            w.write("input/cage.yaml", yaml_text)
            w.write("error.txt", f"{type(exc).__name__}: {exc}\n")
            return {
                "case": case_id, "kind": "invalid", "platform": [system, machine],
                "error_type": type(exc).__name__,
            }

        w = CorpusWriter(out_root / "valid" / case_id, scrubber)
        w.write("input/cage.yaml", yaml_text)
        w.write("warnings.txt", "".join(line + "\n" for line in warnings))
        pre_fill_config_text = _json_text(_dataclass_to_jsonable(cfg))
        w.write("resolved-config.json", pre_fill_config_text)

        deploy_name = cfg.name or case_id
        stderr = io.StringIO()
        try:
            state.save_deployment(deploy_name, str(src))
            state.fill_placeholders(deploy_name)
            cfg = state.load_deployment_config(deploy_name)
            stored = state.stored_config_path(deploy_name)

            # `resolved-config.json` above is the config as FIRST loaded.
            # `fill_placeholders` then generates an
            # `agentcage:secret:NAME:<hex>` for every declared injection
            # rule that has not got one, and the reload picks those up —
            # so for a cage with generated placeholders the object the
            # fingerprint is computed over is not the one in that file.
            #
            # Written only when the two differ, which is three cases out
            # of 128. Writing it unconditionally would put 125
            # byte-identical duplicates in the corpus; leaving it out
            # entirely is what made one of five fingerprint components
            # unverifiable for those three, which the Rust side had to
            # carry as a skip list.
            post_fill_config_text = _json_text(_dataclass_to_jsonable(cfg))
            filled_differs = post_fill_config_text != pre_fill_config_text
            if filled_differs:
                w.write("resolved-config-filled.json", post_fill_config_text)

            proxy_yaml = Path(state.save_proxy_config(deploy_name)).read_text()
            dns_conf = Path(state.save_dns_allowlist(deploy_name)).read_text()
            placeholders = state.placeholders_env_path(deploy_name).read_text()

            patches = work / "patches"
            patches.mkdir(parents=True, exist_ok=True)
            if cfg.isolation == "apple-container":
                # quadlets.py is not the apple-container renderer: that
                # backend has no quadlets at all. `generate_units` returns
                # one `<cage>.json` metadata blob that `start()` rebuilds
                # the `container run` argv from, and `_install_launchd_plist`
                # writes a launchd job when the cage opts into autostart.
                #
                # Both are recorded here (PR E3). Before it they were not,
                # and the gap was not only "no units": `cli.py`'s
                # `_update_fingerprint` feeds `backend.generate_units` to
                # `compute_fingerprint` on EVERY backend, so recording no
                # units meant recording a fingerprint no real deploy would
                # ever produce.
                from agentcage.backends.apple_container import (
                    AppleContainerBackend,
                )
                backend = AppleContainerBackend()
                with contextlib.redirect_stderr(stderr):
                    units = backend.generate_units(
                        cfg,
                        config_host_path=stored,
                        patches_host_dir=str(patches),
                        deploy_name=deploy_name,
                        used_octets=None,
                        network_octet=None,
                    )
                # A SECOND redirect, not the same one: the installer's
                # note goes to a scratch buffer so it cannot land in
                # render-warnings.txt, while `generate_units`'s own
                # warnings -- the skipped-volume ones `_user_volume_argv`
                # emits -- stay in `stderr` where the rest of the corpus
                # expects them.
                with contextlib.redirect_stderr(io.StringIO()):
                    # The REAL installer, not a re-typed copy of its
                    # f-string. On Linux -- and, thanks to the pinned
                    # `_gui_domain_reachable`, on a contributor's Mac too --
                    # it writes the file and returns before touching
                    # launchctl. The note it prints about the deferred
                    # load is a property of the sandbox, not of the cage,
                    # so it is
                    # swallowed rather than recorded.
                    backend._install_launchd_plist(deploy_name)
                plist_path = backend._launchd_plist_path(deploy_name)
                launchd = {plist_path.name: plist_path.read_text()}
            else:
                launchd = {}
                with contextlib.redirect_stderr(stderr):
                    units = quadlets.generate_quadlets(
                        cfg,
                        config_host_path=stored,
                        patches_host_dir=str(patches),
                        deploy_name=deploy_name,
                        rootless=True,
                        used_octets=None,
                        network_octet=None,
                        store_secrets=None,
                    )
        except Exception as exc:  # noqa: BLE001
            shutil.rmtree(out_root / "valid" / case_id, ignore_errors=True)
            w2 = CorpusWriter(out_root / "invalid" / case_id, scrubber)
            w2.write("input/cage.yaml", yaml_text)
            w2.write("error.txt", f"{type(exc).__name__}: {exc}\n")
            return {
                "case": case_id, "kind": "invalid", "platform": [system, machine],
                "error_type": type(exc).__name__,
                "stage": "render",
            }

        w.write("proxy-config.yaml", proxy_yaml)
        w.write("dns-allowlist.conf", dns_conf)
        w.write("placeholders.env", placeholders)
        w.write("volume-mounts.json", _json_text(_volume_report(cfg)))
        w.write("render-warnings.txt", stderr.getvalue())

        for filename, content in sorted((units or {}).items()):
            w.write(f"quadlets/{filename}", content)
        # The launchd job, for the apple-container cases only. It is NOT a
        # unit: nothing hashes it, `start()` does not read it, and it is
        # written only when `apple_container_autostart` is set. The corpus
        # records what `_install_launchd_plist` produces for every
        # apple-container case regardless, because the document is a pure
        # function of the cage name, the resolved `container` path and the
        # state dir -- autostart decides whether it is INSTALLED, not what
        # it says. `autostart` in the unit JSON is the flag itself.
        for filename, content in sorted(launchd.items()):
            w.write(f"launchd/{filename}", content)

        # The fingerprint hashes the unit TEXT, which embeds absolute host
        # paths. Hash the scrubbed text instead, so the recorded digest is a
        # property of the corpus rather than of whoever's machine generated
        # it. Everything else about the fingerprint chain — stable_json, the
        # component layout, the sha256-of-sha256s — is exercised unchanged.
        scrubbed_units = {
            name: scrubber.text(text) for name, text in (units or {}).items()
        }
        stored_yaml = Path(stored).read_text()
        image_digests = {cfg.container.image: "sha256:" + "0" * 64}
        fingerprint = compute_fingerprint(
            scrubber.text(stored_yaml),
            resolved_config=_dataclass_to_jsonable(cfg),
            units=scrubbed_units,
            image_digests=image_digests,
            scaffold_version=cfg.scaffold,
        )
        # A recipe, not a copy: every large input is already a file in this
        # directory, so name it rather than duplicating megabytes of quadlet
        # text into a second artifact.
        w.write("stored-cage.yaml", stored_yaml)
        w.write("fingerprint-inputs.json", _json_text({
            "cage_yaml": "stored-cage.yaml",
            "resolved_config": (
                "resolved-config-filled.json" if filled_differs
                else "resolved-config.json"
            ),
            "units": "quadlets/* (filename -> file contents; {} when absent)",
            "image_digests": image_digests,
            "scaffold_version": cfg.scaffold,
        }))
        w.write("fingerprint.json", _json_text(fingerprint))

        return {
            "case": case_id,
            "kind": "valid",
            "platform": [system, machine],
            "cage_name": deploy_name,
            "isolation": cfg.isolation,
            "warning_count": len(warnings),
            "unit_count": len(units or {}),
        }


# ---------------------------------------------------------------------------
# Shared (config-independent) artifacts
# ---------------------------------------------------------------------------

def _write_shared(out_root: Path, scrubber: Scrubber) -> None:
    from agentcage import audit as audit_mod
    from agentcage import config as config_mod
    from agentcage import har as har_mod
    from agentcage import volume_mounts as vm

    w = CorpusWriter(out_root / "shared", scrubber)

    # ── HAR, from the committed capture fixture ────────────
    raw_lines = (INPUTS_DIR / "capture.jsonl").read_text().splitlines()
    entries = [json.loads(line) for line in raw_lines if line.strip()]
    for view in ("inbound", "outbound"):
        w.write(f"har/{view}.json", _json_text(har_mod.capture_to_har(entries, view)))

    har_filters = {
        "all": har_mod.CaptureFilter(),
        "decision-blocked": har_mod.CaptureFilter(decisions=["blocked"]),
        "direction-outbound": har_mod.CaptureFilter(directions=["outbound"]),
        "host-example-com": har_mod.CaptureFilter(hosts=["example.com"]),
        "method-post-lowercase": har_mod.CaptureFilter(methods=["post"]),
        "min-action-flag": har_mod.CaptureFilter(min_action="flag"),
        "min-action-block": har_mod.CaptureFilter(min_action="block"),
        "since-2024-03": har_mod.CaptureFilter(
            since=datetime(2024, 3, 1, tzinfo=timezone.utc)),
    }
    filter_report = {}
    for label, filt in sorted(har_filters.items()):
        kept = [e for e in entries if filt.matches(e)]
        filter_report[label] = [e["flow_id"] for e in kept]
    w.write("har/filters.json", _json_text(filter_report))
    w.write("har/filtered-blocked.json", _json_text(har_mod.capture_to_har(
        [e for e in entries if har_filters["decision-blocked"].matches(e)],
        "outbound")))

    # ``parse_since`` returns a *relative* datetime for "1h"/"30m"/"7d", so
    # record the offset from "now" in whole seconds rather than the instant.
    since_report = {}
    for spec in ["1h", "30m", "7d", "2024-01-01", "2024-01-01T00:00:00+00:00",
                 "2024-01-01T00:00:00", "not-a-since", "", "5x", "0h"]:
        parsed_since = har_mod.parse_since(spec)
        if parsed_since is None:
            since_report[spec] = None
        elif re.match(r"^\d+[hHmMdD]$", spec):
            delta = datetime.now(timezone.utc) - parsed_since
            since_report[spec] = {"relative_seconds": round(delta.total_seconds())}
        else:
            since_report[spec] = {"absolute": parsed_since.isoformat()}
    w.write("har/parse-since.json", _json_text(since_report))

    # ── audit, from the committed audit fixture ────────────
    audit_lines = (INPUTS_DIR / "audit.jsonl").read_text().splitlines()
    parsed = [audit_mod.extract_audit_json(line) for line in audit_lines]
    w.write("audit/extract.json", _json_text([
        {"line": line, "parsed": value}
        for line, value in zip(audit_lines, parsed)
    ]))
    audit_entries = [audit_mod.AuditEntry.from_dict(d) for d in parsed if d]
    w.write("audit/entries.json", _json_text(
        [_dataclass_to_jsonable(e) for e in audit_entries]))

    audit_filters = {
        "all": audit_mod.AuditFilter(),
        "decision-blocked": audit_mod.AuditFilter(decisions=["blocked"]),
        "direction-inbound": audit_mod.AuditFilter(directions=["inbound"]),
        "host-evil": audit_mod.AuditFilter(hosts=["evil"]),
        "inspector-domain": audit_mod.AuditFilter(inspectors=["domain"]),
        "method-post-lowercase": audit_mod.AuditFilter(methods=["post"]),
        "severity-warning": audit_mod.AuditFilter(min_severity="warning"),
        "severity-critical": audit_mod.AuditFilter(min_severity="critical"),
        "severity-high-watcher": audit_mod.AuditFilter(min_severity="high"),
        "since-2024-03": audit_mod.AuditFilter(
            since=datetime(2024, 3, 1, tzinfo=timezone.utc)),
    }
    w.write("audit/filters.json", _json_text({
        label: [e.url or e.host for e in audit_entries if filt.matches(e)]
        for label, filt in sorted(audit_filters.items())
    }))
    summary = audit_mod.compute_summary(audit_entries)
    w.write("audit/summary.json", _json_text(summary))
    w.write("audit/summary.txt", audit_mod.format_summary(summary) + "\n")
    w.write("audit/table.txt", "\n".join(
        [audit_mod.format_table_header()]
        + [audit_mod.format_table_row(e, color=False) for e in audit_entries]
    ) + "\n")
    w.write("audit/table-color.txt", "\n".join(
        [audit_mod.format_table_header()]
        + [audit_mod.format_table_row(e, color=True) for e in audit_entries]
    ) + "\n")

    # ── volume-mount parsing, as a standalone table ────────
    volume_specs = [
        "/src:/dst",
        "/src:/dst:ro",
        "/src:/dst:rw,np",
        "/src:/dst:np",
        "/src:/dst:np,z",
        "/src:/dst:rw,z,U",
        "/src",
        "",
        "/src:/dst:",
        "/a/b/c:/x/y/z:ro,nosuid",
    ]
    tmpfs_specs = [
        "/tmp",
        "/tmp:rw,noexec,nosuid,size=64M",
        "/workspace/.git/hooks:rw,tmpcopyup",
        "/workspace/.git/hooks:rw,notmpcopyup",
        "/workspace/.git/hooks:rw,tmpcopyup,notmpcopyup",
        "/workspace/.claude/",
        "/a:",
    ]
    mount_targets = [("/workspace", "/host/project"), ("/var/lib/state", ""),
                     ("/data", "/host/data")]
    table = {
        "volume_specs": [],
        "tmpfs_specs": [],
        "mount_targets": [list(t) for t in mount_targets],
        # See the note in _volume_report: this is a dict, and iterating it
        # recorded only the bind sources.
        "mask_mountpoint_dirs": [
            [source, list(dirs)] for source, dirs
            in vm.mask_mountpoint_dirs(tmpfs_specs, mount_targets).items()],
        "mask_copyup_entries": [
            list(e) for e in vm.mask_copyup_entries(tmpfs_specs, mount_targets)],
    }
    for spec in volume_specs:
        source, target, raw = vm.split_volume_spec(spec)
        entry = {
            "spec": spec, "source": source, "target": target,
            "raw_options": raw, "options": vm.volume_options(spec),
            "non_persistent": vm.is_non_persistent_volume(spec),
        }
        try:
            vm.validate_non_persistent_volume(spec)
            entry["validation_error"] = None
        except ValueError as exc:
            entry["validation_error"] = str(exc)
        table["volume_specs"].append(entry)
    for spec in tmpfs_specs:
        target = vm.tmpfs_spec_target(spec)
        table["tmpfs_specs"].append({
            "spec": spec, "target": target,
            "options": vm.tmpfs_spec_options(spec),
            "wants_copyup": vm.tmpfs_wants_copyup(spec),
            "enclosing_mount": list(vm.enclosing_mount(target, mount_targets)),
        })
    w.write("volume-mounts.json", _json_text(table))

    # ── domain syntax + encoded-private-IP tables ──────────
    domains = [
        "example.com", "api.example.com", "a.b.c.example.com",
        "EXAMPLE.COM", "example.com.", "example", "nas", "fcos-vm-home-01",
        "-bad.example.com", "bad-.example.com", "x.c", "x.co",
        "192.0.2.1", "::1", "example.com\n", "example.com\nserver=/x/1.1.1.1",
        "exa mple.com", "example.com/path", ".example.com", "",
        "a" * 64 + ".example.com", ("a" * 60 + ".") * 5 + "example.com",
        "169-254-169-254.nip.io", "10-0-0-1.sslip.io", "127-0-0-1.localtest.me",
        "8-8-8-8.nip.io", "010-1-1-1.nip.io", "10.0.0.1.nip.io",
        "10-years.example.com", "1-2-3-4-5.example.com",
        "192-168-1-1.traefik.me", "999-1-1-1.nip.io",
    ]
    w.write("domain-validation.json", _json_text([
        {
            "domain": d,
            "valid_domain": config_mod.valid_domain(d),
            "valid_domain_single_label": config_mod.valid_domain(
                d, allow_single_label=True),
            "encoded_private_ip": config_mod.encoded_private_ip(d),
        }
        for d in domains
    ]))

    # ── egress image content hash ──────────────────────────
    # These two live in ``agentcage.egress_hash`` once PR A5 has extracted
    # them out of ``backends/apple_container.py``; that PR keeps the old
    # private names as aliases, so both spellings work. Prefer the real home
    # and fall back, so this script is correct both before and after A5 lands
    # in whatever branch it is run from. The VALUE must not move either way —
    # the image tag it feeds must not drift between the Python and Rust
    # builds (RUST-PORT-PLAN.md §2.1).
    # NB the two modules spell these differently: `egress_hash` exports them
    # public (A5's real home), while `backends.apple_container` keeps the
    # underscore-prefixed aliases. Importing the *names* rather than the
    # module is what makes both spellings work -- an earlier version bound
    # the module and then called the private names on it, which found A5's
    # module and then raised AttributeError.
    try:
        from agentcage.egress_hash import (
            egress_build_inputs as _build_inputs,
            egress_content_hash as _content_hash,
        )
    except ImportError:  # pre-A5 tree
        from agentcage.backends.apple_container import (
            _egress_build_inputs as _build_inputs,
            _egress_content_hash as _content_hash,
        )
    # Deliberately unguarded. A previous revision wrapped this in a bare
    # `except Exception` that wrote "UNAVAILABLE: <err>" into the corpus --
    # which turns a programming error into a committed fixture that would
    # pass CI forever once blessed. The hash feeds the egress image tag
    # (RUST-PORT-PLAN.md §2.1); if it cannot be computed, the corpus is
    # wrong and generation should stop.
    inputs = _build_inputs()
    w.write("egress-content-hash.txt", _content_hash() + "\n")
    w.write("egress-build-inputs.txt", "".join(
        f"{rel} {path.stat().st_size}\n" for rel, path in inputs))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def generate(out_root: Path, work: Path, *, trace: bool = True) -> dict:
    out_root.mkdir(parents=True, exist_ok=True)
    for sub in ("valid", "invalid", "shared"):
        shutil.rmtree(out_root / sub, ignore_errors=True)

    scrubber = Scrubber(work)
    cases: list[tuple[str, str, dict]] = []
    cases += [(cid, text, {}) for cid, text in _seed_cases()]
    cases += _matrix_cases()
    cases += _invalid_cases()

    seen: set[str] = set()
    for case_id, _text, _opts in cases:
        if case_id in seen:
            raise SystemExit(f"duplicate corpus case id: {case_id}")
        seen.add(case_id)

    import agentcage.config as config_mod
    config_path = os.path.realpath(config_mod.__file__)
    tracer_files = {config_path}
    tracer = RaiseTracer(tracer_files) if trace else None

    records = []
    ctx = tracer if tracer is not None else contextlib.nullcontext()
    # tests/configs/*.yaml carry relative volume paths; resolve them against a
    # sandbox directory rather than the developer's cwd.
    prev_cwd = os.getcwd()
    os.chdir(os.environ["HOME"] + "/e2e-work")
    try:
        with ctx:
            for case_id, text, opts in cases:
                records.append(_run_case(
                    case_id, text, opts, out_root, scrubber, work))
            records += _special_cases(out_root, scrubber, work)
    finally:
        os.chdir(prev_cwd)

    _write_shared(out_root, scrubber)
    _assert_no_leaks(out_root, work)

    valid = [r for r in records if r["kind"] == "valid"]
    invalid = [r for r in records if r["kind"] == "invalid"]

    # Distinct error strings.
    messages: set[str] = set()
    for rec in invalid:
        path = out_root / "invalid" / rec["case"] / "error.txt"
        messages.add(path.read_text())

    manifest = {
        "schema": 1,
        "cases": sorted(records, key=lambda r: r["case"]),
        "stats": {
            "total": len(records),
            "valid": len(valid),
            "invalid": len(invalid),
            "distinct_error_messages": len(messages),
        },
    }
    (out_root / "manifest.json").write_text(_json_text(manifest))

    if tracer is not None:
        _write_raise_coverage(out_root, Path(config_path),
                              tracer.hits[config_path])

    return manifest


def _write_raise_coverage(out_root: Path, config_path: Path,
                          executed: set[int]) -> None:
    sites = _collect_raise_sites(config_path)
    covered = [s for s in sites if s.lineno in executed]
    uncovered = [s for s in sites if s.lineno not in executed]
    lines = [
        "# `config.py` raise-site coverage",
        "",
        "Generated by `scripts/gen-golden-corpus.py`. Each site is keyed by",
        "`<qualname>#<n>` — the n-th `raise` inside that function — and",
        "labelled with its message TEMPLATE, every interpolation collapsed to",
        "`{\u2026}`.",
        "",
        "Neither the key nor the label is round-tripped source, and no line",
        "numbers appear here. That is deliberate twice over: this report is a",
        "committed fixture, so it must not churn on edits elsewhere in the",
        "file, and it must be byte-identical on every CPython in the CI",
        "matrix. `ast.unparse` is neither — PEP 701 moved its f-string quote",
        "selection — so nothing here goes through it. See the corpus README,",
        "\u201cInterpreter independence\u201d.",
        "",
        f"- total raise sites: {len(sites)}",
        f"- reached by the corpus: {len(covered)}",
        f"- not reached: {len(uncovered)}",
        "",
        "## Reached",
        "",
    ]
    for site in covered:
        lines.append(f"- `{site.key}` — {_md_code(site.label)}")
    lines += ["", "## Not reached", ""]
    if not uncovered:
        lines.append("_none_")
    for site in uncovered:
        lines.append(f"- `{site.key}` — {_md_code(site.label)}")
    lines.append("")
    (out_root / "RAISE-COVERAGE.md").write_text("\n".join(lines))
    (out_root / "raise-coverage.json").write_text(_json_text({
        "covered": sorted(s.key for s in covered),
        "uncovered": sorted(s.key for s in uncovered),
    }))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="corpus output directory")
    parser.add_argument("--work", type=Path, default=None,
                        help="sandbox directory (default: a fresh temp dir)")
    parser.add_argument("--no-trace", action="store_true",
                        help="skip raise-site coverage tracing")
    args = parser.parse_args(argv)

    tmp = None
    if args.work is None:
        tmp = tempfile.mkdtemp(prefix="agentcage-golden-")
        work = Path(tmp)
    else:
        work = args.work
        work.mkdir(parents=True, exist_ok=True)

    try:
        manifest = run_in_sandbox(args.out, work, trace=not args.no_trace)
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    stats = manifest["stats"]
    print(f"corpus written to {args.out}")
    print(f"  valid cases            : {stats['valid']}")
    print(f"  invalid cases          : {stats['invalid']}")
    print(f"  distinct error messages: {stats['distinct_error_messages']}")
    return 0


def run_in_sandbox(out_root: Path, work: Path, *, trace: bool = True) -> dict:
    """Set up the sandbox, import agentcage, and generate.

    Split out from ``main`` so the pytest module can call it directly.
    """
    sys.path.insert(0, str(REPO_ROOT / "src"))
    _build_sandbox(work)
    _install_determinism_patches()
    return generate(out_root, work, trace=trace)


if __name__ == "__main__":
    raise SystemExit(main())
