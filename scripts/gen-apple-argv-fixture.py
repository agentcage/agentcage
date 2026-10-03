#!/usr/bin/env python3
"""Generate tests/fixtures/apple-container/argv.json.

The three argv builders on ``AppleContainerBackend`` -- ``exec_argv``,
``logs_argv`` and ``audit_argv`` -- are what ``cage exec`` / ``cage
shell``, ``cage logs`` and ``cage audit`` dispatch through on macOS.
Each one is a pure function of its arguments plus three host facts, and
this records what the REAL methods return across a matrix of inputs so
the Rust port (RUST-PORT-PLAN.md Track E, PR E3) can be held to the
bytes rather than to a second, hand-kept copy of the shapes.

The three host facts are patched, not sampled:

* ``platform.system()`` / ``platform.machine()`` -> Darwin / arm64.
  ``tests/test_apple_container.py`` has done this since the backend was
  written (line 44) and there has never been a macOS runner in CI; none
  of these three methods actually branches on the platform, but running
  them anywhere else would be recording a lie about where they run.
* ``apple_container.cli.container_binary()`` -> a pinned path, or
  ``None`` for the not-installed cases. It is a ``shutil.which``, so on
  a Linux runner it is ``None`` for every case and the interesting
  argv would never be produced.
* ``services.current_placeholders()`` -> declared per case. The real
  function reads the stored cage.yaml at call time (that is the point:
  a secret declared after the cage started is usable in a new session
  without a restart), and it is already ported and tested on its own
  (PR D9/D12). Declaring the pairs here keeps this fixture about the
  argv and not about state layout.

``audit_argv`` is the one that is not a fourth variation on a theme.
PR D8 established that there is no host-side ``audit.jsonl`` for a
``container`` or ``vm`` cage -- the egress addon writes its trail to
stderr and the host reads the journal -- and that only apple-container
bind-mounts a file. So this is agentcage's only file-reading audit path
and nothing else in the port covers it. ``HOME`` is pinned to a
throwaway directory and scrubbed to ``{{HOME}}`` on the way out,
because the apple state root is an ``expanduser`` with no XDG lookup
and an XDG sandbox does not redirect it.

Usage:
    uv run python scripts/gen-apple-argv-fixture.py          # write
    uv run python scripts/gen-apple-argv-fixture.py --check  # fail if stale

See tests/fixtures/apple-container/README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OUT = _ROOT / "tests" / "fixtures" / "apple-container"

sys.path.insert(0, str(_ROOT / "src"))

# The pinned `container` path. Both of `container_binary`'s fallback
# candidates are plausible; this is the one the .pkg installs.
FROZEN_CONTAINER_BINARY = "/usr/local/bin/container"

# The home the apple state root hangs off. Scrubbed to {{HOME}}.
_HOME = Path(tempfile.mkdtemp(prefix="agentcage-apple-argv-")) / "home"


def _patch() -> None:
    """Pin the three host facts, and HOME."""
    import platform

    import agentcage.apple_container.cli as ac_cli
    import agentcage.services as services

    _HOME.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(_HOME)
    # Deliberately NOT under $HOME/.config. The apple state root is
    # `Path(os.path.expanduser("~/.config/agentcage/apple-container"))`
    # -- an expanduser with no XDG lookup anywhere near it -- so the
    # recorded audit path must come out under {{HOME}}/.config even
    # though XDG_CONFIG_HOME points somewhere else entirely. That is a
    # testing hazard as much as a portability wart (an XDG sandbox does
    # not redirect this root), and recording it here is how the fixture
    # says so out loud.
    os.environ["XDG_CONFIG_HOME"] = str(_HOME.parent / "xdg-config")

    platform.system = lambda: "Darwin"
    platform.machine = lambda: "arm64"
    platform.mac_ver = lambda: ("26.0", ("", "", ""), "arm64")

    # Rebound per case by `_with_binary` / `_with_placeholders`.
    ac_cli.container_binary = lambda: FROZEN_CONTAINER_BINARY
    services.current_placeholders = lambda name: []


def _scrub(value: str) -> str:
    return value.replace(str(_HOME), "{{HOME}}")


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------

# Two decoy tokens, in the shape `fill_placeholders` generates. Never
# real values: the placeholder is what the cage's environment gets, and
# the mitmproxy addon substitutes the secret on the wire.
_PLACEHOLDERS = [
    ("ANTHROPIC_API_KEY", "agentcage:secret:ANTHROPIC_API_KEY:0001"),
    ("OPENAI_API_KEY", "agentcage:secret:OPENAI_API_KEY:0002"),
]


def _exec_cases() -> list[dict]:
    """Every dimension `exec_argv` branches on, plus the two refusals.

    Not a cartesian product: the service dispatch, the `-u` spec, the
    setpriv wrap, the `-it` flag and the env prefix are independent, and
    a sweep that varies one at a time off a shared row finds everything
    a product would. The combinations that ARE listed are the ones where
    two dimensions interact -- `as_root` changes both the spec and the
    wrap, and the wrap changes where the env prefix lands.
    """
    cases: list[dict] = []

    def add(case_id: str, why: str, **kwargs) -> None:
        case = {
            "id": case_id,
            "why": why,
            "name": "demo",
            "service": "cage",
            "command": ["ls", "-la"],
            "interactive": False,
            "as_root": False,
            "placeholders": [],
            "binary": FROZEN_CONTAINER_BINARY,
        }
        case.update(kwargs)
        cases.append(case)

    # ── service dispatch ───────────────────────────────────
    add("cage-default", "the shape a bare `cage exec` produces")
    add("cage-explicit", "`--service cage` is the same as no flag",
        service="cage")
    add("cage-empty-service", "the CLI's 'no --service given'", service="")
    add("egress", "the sibling microVM, addressed as <cage>-egress",
        service="egress")
    add("egress-as-root", "uid 0 on the egress: NET_ADMIN is left alone "
        "because iptables debugging there may need it",
        service="egress", as_root=True)
    add("unknown-service", "`--service proxy` is a name from the legacy "
        "single-VM model and no longer exists", service="proxy")

    # ── the setpriv wrap ───────────────────────────────────
    add("cage-as-root", "the operator debug path: uid 0:0 with NET_ADMIN "
        "dropped, so F2's route-bypass chain stays closed", as_root=True)
    add("cage-interactive", "-it, between the -u spec and the target",
        interactive=True)
    add("cage-as-root-interactive", "both at once", as_root=True,
        interactive=True)
    add("egress-interactive", "-it with an explicit -u spec",
        service="egress", interactive=True)

    # ── the env prefix ─────────────────────────────────────
    add("cage-placeholders", "a cage session carries the current decoy "
        "tokens, chained through env(1) because Apple's `container exec` "
        "has no --env", placeholders=_PLACEHOLDERS)
    add("cage-placeholders-as-root", "the env prefix lands after the "
        "setpriv wrap in both wrap shapes", as_root=True,
        placeholders=_PLACEHOLDERS)
    add("egress-placeholders", "the egress gets NONE of them: it reads the "
        "real values off its own bind mount", service="egress",
        placeholders=_PLACEHOLDERS)
    add("cage-one-placeholder", "a single pair, so the `env` prefix is not "
        "only exercised at length 2",
        placeholders=[_PLACEHOLDERS[0]])

    # ── the command ────────────────────────────────────────
    add("command-separator-form", "what `cage exec demo -- ls -la` parses "
        "to (PR D12): the separator is consumed by the parser and never "
        "reaches the backend", command=["ls", "-la"])
    add("command-no-separator-form", "what `cage exec demo ls -la` parses "
        "to -- the same list, so the same argv", command=["ls", "-la"])
    add("command-inner-separator", "a `--` the operator meant as an "
        "argument is forwarded verbatim",
        command=["git", "log", "--", "src"])
    add("command-shell-c", "an argument with spaces and a $ stays one "
        "argv element", command=["sh", "-c", "echo $HOME && ls"])
    add("command-single-word", "the `cage shell` shape",
        command=["bash"], interactive=True)

    # ── the refusals ───────────────────────────────────────
    add("no-container-cli", "the Apple `container` .pkg is not installed",
        binary=None)
    add("unknown-service-and-no-cli", "the service is checked FIRST, so "
        "this reports the service and not the missing binary",
        service="proxy", binary=None)

    return cases


def _logs_cases() -> list[dict]:
    cases: list[dict] = []

    def add(case_id: str, why: str, **kwargs) -> None:
        case = {
            "id": case_id,
            "why": why,
            "name": "demo",
            "services": [],
            "follow": False,
            "lines": 0,
            "min_level": None,
            "binary": FROZEN_CONTAINER_BINARY,
        }
        case.update(kwargs)
        cases.append(case)

    add("no-services", "an empty list tails the cage VM")
    add("cage", "explicitly", services=["cage"])
    add("egress", "the sibling", services=["egress"])
    add("cage-then-egress", "first recognized entry wins",
        services=["cage", "egress"])
    add("egress-then-cage", "and order is the list's, not a preference",
        services=["egress", "cage"])
    add("unknown-service", "an unrecognized name is skipped, not refused -- "
        "`proxy` quietly tails the cage", services=["proxy"])
    add("unknown-then-egress", "the loop keeps going past one it does not "
        "know", services=["proxy", "egress"])
    add("follow", "-f, between `logs` and the target", follow=True)
    add("follow-egress", "both", services=["egress"], follow=True)
    add("lines-ignored", "Apple's `container logs` has no -n; the parameter "
        "exists for protocol parity and is dropped", lines=500)
    add("min-level-ignored", "and it cannot filter by level either",
        min_level="warning")
    add("no-container-cli", "the .pkg is not installed", binary=None)

    return cases


def _audit_cases() -> list[dict]:
    cases: list[dict] = []

    def add(case_id: str, why: str, **kwargs) -> None:
        case = {
            "id": case_id,
            "why": why,
            "name": "demo",
            "since": None,
            "follow": False,
        }
        case.update(kwargs)
        cases.append(case)

    add("tail", "the default over-read: 10000 lines, because not every "
        "line in the file is an audit record")
    add("follow", "-F, not -f: the supervisor can rotate or replace the "
        "file under us and tail has to reopen it", follow=True)
    add("since-ignored", "a JSONL file has no journalctl-style time index, "
        "so `cage audit --since` is applied after parsing, as "
        "AuditFilter.since", since="10 minutes ago")
    add("since-ignored-following", "same, while following",
        since="2026-01-01", follow=True)
    add("other-cage", "the path is per-cage, under the apple state root",
        name="other-cage")

    return cases


# ---------------------------------------------------------------------------
# Running them
# ---------------------------------------------------------------------------

def _record(fn) -> dict:
    """Call *fn*, recording either its argv or its refusal."""
    from agentcage.backend import BackendUnsupported
    try:
        return {"argv": [_scrub(str(part)) for part in fn()]}
    except BackendUnsupported as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def _run() -> dict:
    import agentcage.apple_container.cli as ac_cli
    import agentcage.services as services
    from agentcage.backends.apple_container import AppleContainerBackend

    backend = AppleContainerBackend()

    exec_out = []
    for case in _exec_cases():
        ac_cli.container_binary = lambda b=case["binary"]: b
        pairs = [tuple(p) for p in case["placeholders"]]
        services.current_placeholders = lambda name, p=pairs: p
        result = _record(lambda c=case: backend.exec_argv(
            c["name"], c["service"], list(c["command"]),
            interactive=c["interactive"], as_root=c["as_root"],
        ))
        exec_out.append({**case, **result})

    logs_out = []
    for case in _logs_cases():
        ac_cli.container_binary = lambda b=case["binary"]: b
        result = _record(lambda c=case: backend.logs_argv(
            c["name"], list(c["services"]), follow=c["follow"],
            lines=c["lines"], min_level=c["min_level"],
        ))
        logs_out.append({**case, **result})

    audit_out = []
    for case in _audit_cases():
        result = _record(lambda c=case: backend.audit_argv(
            c["name"], since=c["since"], follow=c["follow"],
        ))
        audit_out.append({
            **case,
            "audit_path": _scrub(str(backend.logs_dir(case["name"]) / "audit.jsonl")),
            **result,
        })

    return {
        "fixture": "apple-container-argv",
        "module": "agentcage.backends.apple_container",
        "generator": "scripts/gen-apple-argv-fixture.py",
        "summary": (
            f"{len(exec_out)} exec_argv, {len(logs_out)} logs_argv and "
            f"{len(audit_out)} audit_argv calls, recorded by running the "
            "real AppleContainerBackend methods with platform.system() "
            "patched to Darwin, container_binary() pinned and "
            "current_placeholders declared per case. Host paths are "
            "scrubbed to {{HOME}}."
        ),
        "frozen_container_binary": FROZEN_CONTAINER_BINARY,
        "exec_argv": exec_out,
        "logs_argv": logs_out,
        "audit_argv": audit_out,
    }


def _render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the committed fixture is stale")
    args = ap.parse_args()

    _patch()
    text = _render(_run())
    path = _OUT / "argv.json"

    if args.check:
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 1
        if path.read_text() != text:
            print(
                f"STALE: {path.relative_to(_ROOT)} does not match the current "
                "Python. Regenerate with:\n"
                "    uv run python scripts/gen-apple-argv-fixture.py\n"
                "then READ the diff -- a one-flag change should be a "
                "one-line diff.",
                file=sys.stderr,
            )
            return 1
        print(f"current: {path.relative_to(_ROOT)}")
        return 0

    _OUT.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print(f"wrote {path.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
