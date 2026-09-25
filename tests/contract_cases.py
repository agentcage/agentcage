"""The contract fixtures, and the checks both sides of the boundary share.

Not a test module: it holds no assertions of its own and pytest does not
collect it. It exists so that ``test_contract_fixtures.py`` (the proxy
side, Python forever) and ``test_contract_fixtures_host.py`` (the host
side, which the Rust suite replaces at cutover) can assert the *same*
cases with the *same* checkers without either file importing the other
side of the trust boundary.

That constraint is `scripts/classify-tests.py --fail-on-both`, and it is
not bookkeeping. A test file that imports both sides has no home after
the port: delete it with the host tests and the proxy coverage goes with
it; keep it as pytest and it imports a module that no longer exists in
Python. PR A6 split every file that straddled; this one arrived from a
parallel branch a day later and straddled again.

Nothing here imports ``agentcage`` or the proxy. It reads JSON, compares
values, and — for the mutation arm — reads a source file off disk as
*text*. `_mutate` is the subtle case: it takes a repo-relative path and
`exec`s the mutated source into a throwaway namespace, so the file it
loads is chosen by its caller. The importing side stays the caller's
business, and this module stays neutral.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

_FIXTURES = Path(__file__).parent / "fixtures" / "contracts"
ROOT = Path(__file__).parent.parent


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / f"{name}.json").read_text())


VALID_DOMAIN = _load("valid_domain")
ENCODED_PRIVATE_IP = _load("encoded_private_ip")
IS_NEVER_GRANT = _load("is_never_grant")
VALIDATE_RELAY_ENTRY = _load("validate_relay_entry")
SHARED_CONSTANTS = _load("shared_constants")
SCAFFOLD_INSPECTORS = _load("scaffold_inspectors")

ALL = {
    "valid_domain": VALID_DOMAIN,
    "encoded_private_ip": ENCODED_PRIVATE_IP,
    "is_never_grant": IS_NEVER_GRANT,
    "validate_relay_entry": VALIDATE_RELAY_ENTRY,
    "shared_constants": SHARED_CONSTANTS,
    "scaffold_inspectors": SCAFFOLD_INSPECTORS,
}

FIXTURE_DIR = _FIXTURES


def ids(doc: dict) -> list[str]:
    return [c["id"] for c in doc["cases"]]


# ── per-case checkers, shared by the real tests and the mutants ──

def check_valid_domain(case: dict, impl) -> None:
    got = impl(case["input"])
    assert got == case["expected"], (
        f"valid_domain({case['input']!r}) == {got!r}, fixture says "
        f"{case['expected']!r} — {case['why']}"
    )


def check_valid_domain_single(case: dict, impl) -> None:
    got = impl(case["input"])
    assert got == case["expected_allow_single_label"], (
        f"valid_domain({case['input']!r}, allow_single_label=True) == "
        f"{got!r}, fixture says {case['expected_allow_single_label']!r} — "
        f"{case['why']}"
    )


def check_encoded_private_ip(case: dict, impl) -> None:
    got = impl(case["input"])
    assert got == case["expected"], (
        f"encoded_private_ip({case['input']!r}) == {got!r}, fixture says "
        f"{case['expected']!r} — {case['why']}"
    )


def check_is_never_grant(case: dict, impl) -> None:
    got = impl(case["input"], set(case["never_grant"]))
    assert got == case["expected"], (
        f"is_never_grant({case['input']!r}, {sorted(case['never_grant'])}) "
        f"== {got!r}, fixture says {case['expected']!r} — {case['why']}"
    )


def check_validate_relay_entry(case: dict, impl) -> None:
    calls: list = []
    try:
        impl(case["entry"], source_validator=calls.append)
        ok, error = True, None
    except ValueError as exc:
        ok, error = False, str(exc)

    assert ok == case["ok"], (
        f"{case['id']}: validator {'accepted' if ok else 'rejected'} the "
        f"entry, fixture says it must be "
        f"{'accepted' if case['ok'] else 'rejected'} — {case['why']}"
        + (f"\n  raised: {error}" if error else "")
    )
    # The message is user-visible: `agentcage cage create` prints it
    # verbatim. An operator fixing config errors one at a time must get the
    # same guidance from either implementation, so it is pinned exactly.
    assert error == case["error"], (
        f"{case['id']}: error message drifted.\n"
        f"  got:      {error!r}\n"
        f"  fixture:  {case['error']!r}\n"
        f"  why:      {case['why']}"
    )
    assert calls == case["source_validator_calls"], (
        f"{case['id']}: source_validator received {calls!r}, fixture says "
        f"{case['source_validator_calls']!r}"
    )


# ── the mutation machinery: proof that the fixtures bite ─────

def mutate(rel_path: str, *replacements: tuple[str, str]) -> types.ModuleType:
    """Load a REAL source file with textual mutations applied, in memory.

    Not a stub and not a monkeypatch: the module's own source is read from
    disk, edited, and executed into a fresh namespace, so what the mutation
    tests exercise is the same code path an editor would produce. Nothing
    is written to disk, and the temporary ``sys.modules`` entry (which
    ``@dataclass`` needs to resolve its own annotations) is removed again,
    so a mutant cannot leak into another test or shadow the real module.

    Each replacement must match exactly once — a mutation that silently
    matched nothing would make the test below pass for the wrong reason
    (an unmutated implementation trivially conforms).
    """
    path = ROOT / rel_path
    src = path.read_text()
    for old, new in replacements:
        assert src.count(old) == 1, (
            f"mutation target appears {src.count(old)} times in {rel_path}, "
            f"expected exactly 1 — the implementation moved, update the "
            f"mutation:\n  {old!r}"
        )
        src = src.replace(old, new)
    name = f"_agentcage_mutant_{path.stem}_{len(sys.modules)}"
    mod = types.ModuleType(name)
    mod.__file__ = str(path)
    sys.modules[name] = mod
    try:
        exec(compile(src, str(path), "exec"), mod.__dict__)
    finally:
        sys.modules.pop(name, None)
    return mod


def must_fail(checker, cases, impl) -> list[str]:
    """Run the whole corpus and return the ids that caught the mutant."""
    caught = []
    for case in cases:
        try:
            checker(case, impl)
        except AssertionError:
            caught.append(case["id"])
    return caught
