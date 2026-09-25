#!/usr/bin/env python3
"""Generate the vm-backend fixtures under ``tests/fixtures/vm/``.

``VmBackend.generate_units`` is the one renderer the golden corpus does
not reach. The corpus calls ``quadlets.generate_quadlets`` directly, so
for a ``isolation: vm`` case it records the units a *container* deploy
of the same config would produce — it never sees the Lima YAML, and it
never sees the two things the vm backend does on top of the renderer:

* the ``TimeoutStartSec`` floor (``VM_MIN_TIMEOUT_START_SEC``), applied
  to a copy of the config so repeated generation stays deterministic;
* the ``lima.yaml`` / ``quadlets/<name>`` key layout the deploy path
  installs from.

So this records ``generate_units`` whole, per case: every file it
returns, in dict order, plus whatever it wrote to stderr. The Rust port
(RUST-PORT-PLAN.md Track E, PR E1) reproduces them byte for byte in
``rust/agentcage-cli/tests/golden_vm_units.rs``.

Determinism is not re-invented here. The sandbox, the frozen version,
the frozen DNS servers and creds scope, the counter-based placeholder
tokens and the path scrubber are ``gen-golden-corpus.py``'s, imported
rather than copied, so a case in this fixture and a case in the corpus
are scrubbed by the same rules and the Rust side can answer both from
one hermetic tree. Two further things are pinned here, because only
this renderer reads them:

* ``pwd.getpwuid(os.getuid()).pw_name`` — the guest user name Lima
  mirrors from the host, which lands in the provisioning script;
* ``LimaInstance`` — ``generate_units`` asks the guest for its podman
  secret store, and a machine that happens to have ``limactl`` and a
  running cage would otherwise produce a different fixture than one
  that does not. The stub answers "no such instance", which is the
  state every first ``cage create`` is in.

Usage:
    uv run python scripts/gen-vm-fixture.py          # write
    uv run python scripts/gen-vm-fixture.py --check  # fail if stale

See tests/fixtures/vm/README.md.
"""

from __future__ import annotations

import argparse
import contextlib
import filecmp
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "tests" / "fixtures" / "vm"

# The guest user name the provisioning script is rendered for. Frozen so
# the fixture does not record whoever ran the generator.
FROZEN_LIMA_USER = "cageuser"


def _corpus_module():
    """``scripts/gen-golden-corpus.py``, imported by path.

    A hyphen is not an identifier, so this is the import that name
    costs. Worth it: the alternative is a second copy of the sandbox and
    the scrubber, and the two would drift on exactly the rule that
    mattered.
    """
    path = REPO_ROOT / "scripts" / "gen-golden-corpus.py"
    name = "agentcage_golden_corpus"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Registered before execution because the module defines a
    # `@dataclasses.dataclass`, and dataclasses resolves annotations
    # through `sys.modules[cls.__module__]`.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def _cases() -> list[dict]:
    """Every case, as ``{id, platform, yaml}``.

    Declared inline rather than read from ``tests/configs/`` because
    what is being characterized is the *vm* path, and the axes that
    matter to it — the memory rounding, the port-spec shapes, which
    volume sources become Lima mounts, the timeout floor and the two
    ``vmType`` drivers — are not the axes the shared config corpus was
    built around.
    """
    return [
        {
            "id": "defaults",
            "why": "The smallest vm cage: default vcpus/mem, no ports, no volumes.",
            "yaml": """\
name: vm-defaults
isolation: vm
container:
  image: docker.io/library/alpine:3.20
domains:
  allow:
  - api.example.com
""",
        },
        {
            "id": "resources-rounded",
            "why": "mem_mb 1500 is ceil()'d to 2GiB; vcpus reaches `cpus`.",
            "yaml": """\
name: vm-resources
isolation: vm
container:
  image: docker.io/library/alpine:3.20
vm:
  vcpus: 2
  mem_mb: 1500
""",
        },
        {
            "id": "ports",
            "why": "Both port-spec shapes: HOST:GUEST binds loopback, BIND:HOST:GUEST does not.",
            "yaml": """\
name: vm-ports
isolation: vm
container:
  image: docker.io/library/alpine:3.20
  ports:
  - "8080:80"
  - "0.0.0.0:8443:443"
""",
        },
        {
            "id": "volumes",
            "why": (
                "Every _extra_mounts_for_volumes branch that does not raise: an ro "
                "directory, an rw directory, a duplicate of the first, a path under "
                "the default data mount, a path that does not exist (warning), and a "
                "single-file source (no Lima mount; the quadlet stages a copy)."
            ),
            "yaml": """\
name: vm-volumes
isolation: vm
container:
  image: docker.io/library/alpine:3.20
  volumes:
  - "${HOME}/project:/workspace:ro"
  - "${HOME}/data:/data:rw"
  - "${HOME}/project:/second:ro"
  - "${HOME}/.local/share/agentcage:/state:ro"
  - "${HOME}/not-there:/missing:rw"
  - "${HOME}/dotfile.conf:/etc/dotfile.conf:ro"
""",
        },
        {
            "id": "volume-np",
            "why": "An `np` bind is shared read-only with Lima however the cage sees it.",
            "yaml": """\
name: vm-np
isolation: vm
container:
  image: docker.io/library/alpine:3.20
  volumes:
  - "${HOME}/workspace:/workspace:rw,np"
""",
        },
        {
            "id": "volume-blocked",
            "why": "A volume resolving under ~/.ssh is refused, not skipped.",
            "yaml": """\
name: vm-blocked
isolation: vm
container:
  image: docker.io/library/alpine:3.20
  volumes:
  - "${HOME}/.ssh:/keys:ro"
""",
        },
        {
            "id": "timeout-floored",
            "why": "60s is raised to the 300s vm floor.",
            "yaml": """\
name: vm-timeout-low
isolation: vm
container:
  image: docker.io/library/alpine:3.20
  timeout_start_sec: 60
""",
        },
        {
            "id": "timeout-preserved",
            "why": "A value at or above the floor is left alone.",
            "yaml": """\
name: vm-timeout-high
isolation: vm
container:
  image: docker.io/library/alpine:3.20
  timeout_start_sec: 600
""",
        },
        {
            "id": "darwin",
            "why": "platform.system() == Darwin selects vz, rosetta and virtiofs.",
            "platform": ("Darwin", "arm64"),
            "yaml": """\
name: vm-darwin
isolation: vm
container:
  image: docker.io/library/alpine:3.20
  ports:
  - "3000:3000"
""",
        },
        {
            "id": "kitchen-sink",
            "why": (
                "The units, not the Lima YAML: secrets with a placeholder and a "
                "source: scheme, a relay, both agents, capture and a domain list, so "
                "the vm-local Volume= paths and the Secret= emission are recorded "
                "alongside the floor."
            ),
            "yaml": """\
name: vm-full
isolation: vm
container:
  image: docker.io/library/node:22-slim
  command: ["node", "/app/agent.js"]
  timeout_start_sec: 90
  env:
    NODE_ENV: production
vm:
  vcpus: 8
  mem_mb: 8192
domains:
  allow:
  - api.anthropic.com
  - registry.npmjs.org
capture:
  enable: true
secret_injection:
- env: ANTHROPIC_API_KEY
  source: "env:ANTHROPIC_API_KEY"
  placeholder: generate
- env: GITHUB_TOKEN
  source: "podman:"
agents:
  decider:
    enable: true
    api_key: "env:OPENROUTER_API_KEY"
protocol_relays:
- name: mail
  type: smtp
  listen: 0.0.0.0:1587
  upstream:
    host: smtp.example.com
    port: 587
    tls: true
  auth:
    type: plain
    user_source: "env:GOLDEN_SET_VAR"
    password_source: "cmd:printf fake-smtp-password"
ports:
  tcp:
    passthrough:
    - 1587
""",
        },
    ]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class _StubLimaInstance:
    """``LimaInstance`` for a guest that does not exist.

    ``generate_units`` only calls ``exists()`` / ``is_running()``, and
    both answering False is what puts ``store_secrets`` at ``None`` —
    the legacy emit-everything behaviour a first ``cage create`` gets
    (issue #262). Recording the *other* branch would mean recording a
    live guest's secret store, which is not a property of the code.
    """

    def __init__(self, cage_name: str) -> None:
        self.name = f"agentcage-{cage_name}"

    def exists(self) -> bool:
        return False

    def is_running(self) -> bool:
        return False


class _StubPwd:
    """``pwd`` with one frozen passwd entry."""

    class _Entry:
        pw_name = FROZEN_LIMA_USER

    @staticmethod
    def getpwuid(_uid):  # noqa: ANN001 - mirrors the stdlib signature
        return _StubPwd._Entry()


def _install_vm_patches() -> None:
    from agentcage.backends import vm as vm_backend
    from agentcage.lima import provisioning

    vm_backend.LimaInstance = _StubLimaInstance
    provisioning.pwd = _StubPwd


def _render_case(case: dict, out_root: Path, scrubber, work: Path,
                 corpus) -> dict:
    """Render one case and write its directory; return the manifest record."""
    from agentcage import state
    from agentcage.backends.vm import VmBackend
    from agentcage.config import load_config

    case_id = case["id"]
    system, machine = case.get("platform", ("Linux", "x86_64"))
    corpus._PLACEHOLDER_COUNTER["n"] = 0

    staging = work / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    src = staging / f"{case_id}.yaml"
    src.write_text(case["yaml"])

    out = out_root / case_id
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)

    def write(relative: str, text: str) -> None:
        path = out / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(scrubber.text(text))

    write("input/cage.yaml", case["yaml"])
    write("why.txt", case["why"] + "\n")

    with corpus._as_platform(system, machine):
        cfg = load_config(str(src))
        deploy_name = cfg.name
        state.save_deployment(deploy_name, str(src))
        state.fill_placeholders(deploy_name)
        cfg = state.load_deployment_config(deploy_name)
        stored = state.stored_config_path(deploy_name)
        patches = work / "patches"
        patches.mkdir(parents=True, exist_ok=True)

        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                units = VmBackend().generate_units(
                    cfg,
                    config_host_path=str(stored),
                    patches_host_dir=str(patches),
                    deploy_name=deploy_name,
                )
        except Exception as exc:  # noqa: BLE001 — the UX string is the point
            write("error.txt", f"{type(exc).__name__}: {exc}\n")
            write("render-warnings.txt", stderr.getvalue())
            return {
                "case": case_id,
                "kind": "invalid",
                "platform": [system, machine],
                "cage_name": deploy_name,
                "error_type": type(exc).__name__,
            }

    for filename, content in units.items():
        write(f"units/{filename}", content)
    # The config the render actually saw: `save_deployment` +
    # `fill_placeholders` rewrite `placeholder: generate` into a minted
    # token, so re-parsing `input/cage.yaml` would render different
    # units. The Rust side loads this one, as the golden corpus's
    # `stored-cage.yaml` is loaded.
    write("stored-cage.yaml", Path(stored).read_text())
    write("render-warnings.txt", stderr.getvalue())
    # Dict order is part of the contract: `install_units` writes in this
    # order, and `lima.yaml` has to come first because `start` reads it
    # before the quadlets are pushed.
    write("unit-order.json", json.dumps(list(units), indent=2) + "\n")

    return {
        "case": case_id,
        "kind": "valid",
        "platform": [system, machine],
        "cage_name": deploy_name,
        "isolation": cfg.isolation,
        # The caller's config, AFTER the render: `generate_units` floors
        # a deepcopy, so this must still be what cage.yaml asked for.
        # The floored value is what reached the unit.
        "config_timeout_start_sec": cfg.container.timeout_start_sec,
        "unit_timeout_start_sec": max(
            cfg.container.timeout_start_sec, VmBackend.VM_MIN_TIMEOUT_START_SEC
        ),
        "unit_count": len(units),
        "warning_count": len(
            [line for line in stderr.getvalue().splitlines() if line]
        ),
    }


def generate(out_root: Path, work: Path) -> dict:
    corpus = _corpus_module()
    sys.path.insert(0, str(REPO_ROOT / "src"))
    corpus._build_sandbox(work)
    corpus._install_determinism_patches()
    _install_vm_patches()
    scrubber = corpus.Scrubber(work)

    out_root.mkdir(parents=True, exist_ok=True)
    for child in sorted(out_root.iterdir()):
        if child.is_dir():
            shutil.rmtree(child)

    records = []
    previous_cwd = os.getcwd()
    os.chdir(os.environ["HOME"])
    try:
        for case in _cases():
            records.append(_render_case(case, out_root, scrubber, work, corpus))
    finally:
        os.chdir(previous_cwd)

    corpus._assert_no_leaks(out_root, work)

    manifest = {
        "schema": 1,
        "lima_user": FROZEN_LIMA_USER,
        "version": corpus.FROZEN_VERSION,
        "dns_servers": list(corpus.FROZEN_DNS_SERVERS),
        "creds_scope": corpus.FROZEN_CREDS_SCOPE,
        "cases": sorted(records, key=lambda record: record["case"]),
        "stats": {
            "total": len(records),
            "valid": len([r for r in records if r["kind"] == "valid"]),
            "invalid": len([r for r in records if r["kind"] == "invalid"]),
        },
    }
    (out_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _tree_differs(left: Path, right: Path) -> list[str]:
    """Relative paths that differ between two directories."""
    def files(root: Path) -> set[str]:
        return {
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file()
        }

    differences = sorted(files(left) ^ files(right))
    for relative in sorted(files(left) & files(right)):
        if not filecmp.cmp(left / relative, right / relative, shallow=False):
            differences.append(relative)
    return sorted(set(differences))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--check", action="store_true",
        help="generate into a temp dir and fail if it differs from --out",
    )
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="agentcage-vm-fixture-"))
    try:
        if args.check:
            fresh = Path(tempfile.mkdtemp(prefix="agentcage-vm-check-"))
            try:
                manifest = generate(fresh, work)
                differences = _tree_differs(args.out, fresh)
                if differences:
                    print("vm fixtures are stale; re-run:", file=sys.stderr)
                    print("  uv run python scripts/gen-vm-fixture.py",
                          file=sys.stderr)
                    for relative in differences[:40]:
                        print(f"    {relative}", file=sys.stderr)
                    return 1
                print(f"vm fixtures are current ({manifest['stats']['total']} cases)")
                return 0
            finally:
                shutil.rmtree(fresh, ignore_errors=True)

        manifest = generate(args.out, work)
        print(f"vm fixtures written to {args.out}")
        print(f"  valid cases  : {manifest['stats']['valid']}")
        print(f"  invalid cases: {manifest['stats']['invalid']}")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
