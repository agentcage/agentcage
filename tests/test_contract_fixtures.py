"""Cross-language conformance: both sides of the trust boundary vs. the fixture.

agentcage has four pieces of security logic that exist on BOTH sides of its
trust boundary — the host CLI and the in-egress proxy. Today they agree
because they are the same language: ``validate_relay_entry`` is literally
one module imported from two paths, and the other three are duplicated and
held in sync by tests that import both copies and compare them to each
other.

Neither mechanism survives the Rust port of the host CLI. Rust cannot
import a Python module, and a pytest cannot import the Rust side. So the
agreement is moved into something neither implementation owns: a plain-JSON
fixture under ``tests/fixtures/contracts/``, generated from the current
Python implementation by ``scripts/gen-contract-fixtures.py`` and asserted
here by BOTH sides.

That is the shape that survives the port::

    before:   host == proxy
    after:    host == fixture   AND   proxy == fixture

and after the port the Rust suite becomes a third assertion against the
same file, via ``serde_json``.

Two things this file deliberately does NOT do:

* It does not compare host to proxy directly. That assertion is what is
  being replaced; keeping it would hide a case where both sides drifted
  together away from the recorded contract.
* It does not hand-write a single expectation. Everything asserted here
  comes out of the JSON, and the JSON comes out of the generator.

``TestFixturesBite`` at the bottom is the load-bearing part: a fixture that
passes no matter what the implementation does is worse than no fixture,
because it reads like coverage. Those tests apply real source-level
mutations to each implementation and require the conformance check to fail.
"""

from __future__ import annotations

import ipaddress  # noqa: F401  (re-exported into mutated module namespaces)
import json
import re  # noqa: F401
import subprocess
import sys
import types
from pathlib import Path

import pytest

_FIXTURES = Path(__file__).parent / "fixtures" / "contracts"
_ROOT = Path(__file__).parent.parent


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / f"{name}.json").read_text())


VALID_DOMAIN = _load("valid_domain")
ENCODED_PRIVATE_IP = _load("encoded_private_ip")
IS_NEVER_GRANT = _load("is_never_grant")
VALIDATE_RELAY_ENTRY = _load("validate_relay_entry")
SHARED_CONSTANTS = _load("shared_constants")
SCAFFOLD_INSPECTORS = _load("scaffold_inspectors")

_ALL = {
    "valid_domain": VALID_DOMAIN,
    "encoded_private_ip": ENCODED_PRIVATE_IP,
    "is_never_grant": IS_NEVER_GRANT,
    "validate_relay_entry": VALIDATE_RELAY_ENTRY,
    "shared_constants": SHARED_CONSTANTS,
    "scaffold_inspectors": SCAFFOLD_INSPECTORS,
}


def _ids(doc: dict) -> list[str]:
    return [c["id"] for c in doc["cases"]]


# ── the two sides ────────────────────────────────────────────

def _proxy_module():
    """``policy_api`` as the proxy container imports it (a BARE name).

    ``pyproject.toml`` puts ``src/agentcage/data/proxy`` on the pytest
    pythonpath precisely so this import is the one the egress image does.
    ``tests/conftest.py`` stubs mitmproxy at collection time so it loads
    on a host without the proxy's dependencies.
    """
    import policy_api

    return policy_api


def _proxy_valid_domain(domain: str) -> bool:
    return _proxy_module().PolicyApi._valid_domain(domain)


def _proxy_encoded_private_ip(domain: str):
    return _proxy_module()._encoded_private_ip(domain)


def _proxy_is_never_grant(domain: str, never: set) -> bool:
    pa = _proxy_module()
    api = pa.PolicyApi.__new__(pa.PolicyApi)
    api._never_grant = set(never)
    return api._is_never_grant(domain)


def _host_valid_domain(domain: str) -> bool:
    from agentcage.config import valid_domain

    return valid_domain(domain)


def _host_valid_domain_single(domain: str) -> bool:
    from agentcage.config import valid_domain

    return valid_domain(domain, allow_single_label=True)


def _host_encoded_private_ip(domain: str):
    from agentcage.config import encoded_private_ip

    return encoded_private_ip(domain)


def _host_is_never_grant(domain: str, never: set) -> bool:
    from agentcage.cli import _is_never_grant

    return _is_never_grant(domain, set(never))


def _host_validate_relay_entry(entry, source_validator=None):
    """The relay validator as the HOST reaches it.

    ``config.py`` imports it from the package path. Today that resolves to
    the same file the proxy loads under a bare name; after the port it is a
    separate Rust implementation, which is why both paths are asserted.
    """
    from agentcage.data.proxy.relays._validate import validate_relay_entry

    return validate_relay_entry(entry, source_validator=source_validator)


def _proxy_validate_relay_entry(entry, source_validator=None):
    """The relay validator as the PROXY reaches it (a bare ``relays`` import)."""
    from relays._validate import validate_relay_entry

    return validate_relay_entry(entry, source_validator=source_validator)


# ── per-case checkers, shared by the real tests and the mutants ──

def _check_valid_domain(case: dict, impl) -> None:
    got = impl(case["input"])
    assert got == case["expected"], (
        f"valid_domain({case['input']!r}) == {got!r}, fixture says "
        f"{case['expected']!r} — {case['why']}"
    )


def _check_valid_domain_single(case: dict, impl) -> None:
    got = impl(case["input"])
    assert got == case["expected_allow_single_label"], (
        f"valid_domain({case['input']!r}, allow_single_label=True) == "
        f"{got!r}, fixture says {case['expected_allow_single_label']!r} — "
        f"{case['why']}"
    )


def _check_encoded_private_ip(case: dict, impl) -> None:
    got = impl(case["input"])
    assert got == case["expected"], (
        f"encoded_private_ip({case['input']!r}) == {got!r}, fixture says "
        f"{case['expected']!r} — {case['why']}"
    )


def _check_is_never_grant(case: dict, impl) -> None:
    got = impl(case["input"], set(case["never_grant"]))
    assert got == case["expected"], (
        f"is_never_grant({case['input']!r}, {sorted(case['never_grant'])}) "
        f"== {got!r}, fixture says {case['expected']!r} — {case['why']}"
    )


def _check_validate_relay_entry(case: dict, impl) -> None:
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


# ── Contract 1: valid_domain ─────────────────────────────────


class TestValidDomain:
    """``config.valid_domain`` vs ``PolicyApi._valid_domain``.

    The gate that stops a string crossing the trust boundary (a grants
    overlay entry) from being rendered into a dnsmasq directive, and the
    gate the addon applies to a runtime grant request. If the two sides
    disagree, a domain is accepted by one and refused by the other.
    """

    @pytest.mark.parametrize("case", VALID_DOMAIN["cases"], ids=_ids(VALID_DOMAIN))
    def test_host(self, case):
        _check_valid_domain(case, _host_valid_domain)

    @pytest.mark.parametrize("case", VALID_DOMAIN["cases"], ids=_ids(VALID_DOMAIN))
    def test_proxy(self, case):
        _check_valid_domain(case, _proxy_valid_domain)

    @pytest.mark.parametrize("case", VALID_DOMAIN["cases"], ids=_ids(VALID_DOMAIN))
    def test_host_allow_single_label(self, case):
        """Host-only mode: the proxy has no counterpart and must not.

        ``allow_single_label=True`` accepts a bare LAN/mDNS hostname on
        OPERATOR-owned paths only. The runtime grant paths — the addon's
        request endpoint, the grants reconcile, ``grants promote`` — stay
        strict-dotted, because a single-label name is exactly what an
        internal service looks like. The fixture records both columns so
        the Rust port cannot quietly collapse them into one.
        """
        _check_valid_domain_single(case, _host_valid_domain_single)


# ── Contract 2: encoded_private_ip ───────────────────────────


class TestEncodedPrivateIp:
    """``config.encoded_private_ip`` vs ``policy_api._encoded_private_ip``.

    The structural half of the SSRF guard. A wildcard-DNS name like
    ``169-254-169-254.nip.io`` is a syntactically valid PUBLIC hostname
    carrying none of the never-grant suffixes, and resolves to the cloud
    metadata endpoint. Drift here means one side of the boundary stops
    seeing the encoding.
    """

    @pytest.mark.parametrize(
        "case", ENCODED_PRIVATE_IP["cases"], ids=_ids(ENCODED_PRIVATE_IP))
    def test_host(self, case):
        _check_encoded_private_ip(case, _host_encoded_private_ip)

    @pytest.mark.parametrize(
        "case", ENCODED_PRIVATE_IP["cases"], ids=_ids(ENCODED_PRIVATE_IP))
    def test_proxy(self, case):
        _check_encoded_private_ip(case, _proxy_encoded_private_ip)


# ── Contract 3: is_never_grant ───────────────────────────────


class TestIsNeverGrant:
    """``cli._is_never_grant`` vs ``PolicyApi._is_never_grant``.

    Which domains can never be granted at runtime, whatever the decider
    says. The proxy copy refuses the grant; the host copy stops the
    reconcile promoting such a domain into the operator's baseline from an
    overlay that was hand-edited or written by an older addon. A drift here
    is the worst of the four: it is the floor under the decider.
    """

    @pytest.mark.parametrize(
        "case", IS_NEVER_GRANT["cases"], ids=_ids(IS_NEVER_GRANT))
    def test_host(self, case):
        _check_is_never_grant(case, _host_is_never_grant)

    @pytest.mark.parametrize(
        "case", IS_NEVER_GRANT["cases"], ids=_ids(IS_NEVER_GRANT))
    def test_proxy(self, case):
        _check_is_never_grant(case, _proxy_is_never_grant)

    def test_default_never_set_matches_both_implementations(self):
        """The fixture's default set must be the one both sides compute.

        The cases are only as good as the set they are evaluated against,
        so pin where that set comes from: ``config._AUTO_NEVER_GRANT``
        plus the default decider control host on the host side, and the
        addon's ``_effective_never_grant`` literal plus ``self.host`` on
        the proxy side.
        """
        from agentcage.cli import _host_never_grant
        from agentcage.config import _AUTO_NEVER_GRANT

        used = {frozenset(c["never_grant"]) for c in IS_NEVER_GRANT["cases"]}
        expected = frozenset(_host_never_grant({}))
        assert expected in used, (
            f"no fixture case uses the real built-in never-grant floor "
            f"{sorted(expected)}; the corpus only covers "
            f"{[sorted(s) for s in used]}"
        )

        pa = _proxy_module()
        api = pa.PolicyApi.__new__(pa.PolicyApi)
        api.host = "agentcage.local"
        assert api._effective_never_grant([]) == set(expected)
        assert set(_AUTO_NEVER_GRANT) <= expected


# ── Contract 4: validate_relay_entry ─────────────────────────


class TestValidateRelayEntry:
    """The one contract that is currently a single shared module.

    ``config.py`` imports it as ``agentcage.data.proxy.relays._validate``;
    the egress container imports it as ``relays._validate`` (it ships
    without the CLI package on the path). Same file today, two Python
    module objects, one Rust implementation and one Python module
    tomorrow. Both import paths are asserted so the seam is already
    described by tests before it becomes a real one.
    """

    @pytest.mark.parametrize(
        "case", VALIDATE_RELAY_ENTRY["cases"], ids=_ids(VALIDATE_RELAY_ENTRY))
    def test_host(self, case):
        _check_validate_relay_entry(case, _host_validate_relay_entry)

    @pytest.mark.parametrize(
        "case", VALIDATE_RELAY_ENTRY["cases"], ids=_ids(VALIDATE_RELAY_ENTRY))
    def test_proxy(self, case):
        _check_validate_relay_entry(case, _proxy_validate_relay_entry)

    def test_the_two_import_paths_are_distinct_module_objects(self):
        """Not a tautology: they are two entries in ``sys.modules``.

        If this ever starts failing because one import path disappeared,
        the contract has changed shape and the fixture's ``implementations``
        block needs updating with it.
        """
        import relays._validate as proxy_side
        from agentcage.data.proxy.relays import _validate as host_side

        assert proxy_side is not host_side
        assert Path(proxy_side.__file__) == Path(host_side.__file__)

    def test_no_source_validator_is_equivalent_for_every_case(self):
        """The hook is optional; omitting it must not change the verdict.

        The proxy passes ``None`` (the canonical source validator is not
        importable inside the container); the host passes
        ``secret_resolver.validate_source``. The fixture carries ONE
        answer for both call shapes, which is only sound if the hook adds
        an arm rather than altering the existing ones.
        """
        for case in VALIDATE_RELAY_ENTRY["cases"]:
            try:
                _host_validate_relay_entry(case["entry"])
                ok, error = True, None
            except ValueError as exc:
                ok, error = False, str(exc)
            assert (ok, error) == (case["ok"], case["error"]), case["id"]


# ── Contract 5: shared constants ─────────────────────────────


def _host_constant(case_id: str):
    import agentcage.config as config
    from agentcage.data.proxy.relays._validate import (
        KNOWN_RELAY_TYPES, _WRITE_MODES,
    )

    return {
        "max_capture_file_bytes": lambda: config.MAX_CAPTURE_FILE_BYTES,
        "auto_never_grant": lambda: sorted(
            {h.lower().rstrip(".") for h in config._AUTO_NEVER_GRANT}),
        "builtin_inspector_names": lambda: sorted(
            config._BUILTIN_INSPECTOR_NAMES),
        "known_relay_types": lambda: sorted(KNOWN_RELAY_TYPES),
        "relay_write_modes": lambda: sorted(_WRITE_MODES),
    }[case_id]()


def _proxy_constant(case_id: str, tmp_path):
    import addon
    from capture import CaptureWriter
    from relays._validate import KNOWN_RELAY_TYPES, _WRITE_MODES

    def _capture_default():
        writer = CaptureWriter(
            {"enable_har": True, "max_body_size": 10485760,
             "min_action": "all", "domains": [], "exclude_domains": []},
            str(tmp_path / "capture.jsonl"),
        )
        return writer._max_file

    def _never_grant_floor():
        pa = _proxy_module()
        api = pa.PolicyApi.__new__(pa.PolicyApi)
        api.host = "agentcage.local"
        # _effective_never_grant unions in the control host; the fixture
        # records the FLOOR, which is what config._AUTO_NEVER_GRANT holds.
        return sorted(api._effective_never_grant([]) - {"agentcage.local"})

    return {
        "max_capture_file_bytes": _capture_default,
        "auto_never_grant": _never_grant_floor,
        "builtin_inspector_names": lambda: sorted(addon._BUILTIN_INSPECTORS),
        "known_relay_types": lambda: sorted(KNOWN_RELAY_TYPES),
        "relay_write_modes": lambda: sorted(_WRITE_MODES),
    }[case_id]()


class TestSharedConstants:
    """Numbers and sets that exist twice because the addon cannot import.

    Not behaviour, so no mutation arm — a constant has no branches. The
    assertion is simply that both sides produce the recorded value, which
    is what ``tests/cross_language/test_capture_format_conformance.py``
    and A6's never-grant-set assertion were doing pairwise.
    """

    @pytest.mark.parametrize(
        "case", SHARED_CONSTANTS["cases"], ids=_ids(SHARED_CONSTANTS))
    def test_host(self, case):
        got = _host_constant(case["id"])
        assert got == case["value"], (
            f"{case['host']} == {got!r}, fixture says {case['value']!r} — "
            f"{case['why']}"
        )

    @pytest.mark.parametrize(
        "case", SHARED_CONSTANTS["cases"], ids=_ids(SHARED_CONSTANTS))
    def test_proxy(self, case, tmp_path):
        got = _proxy_constant(case["id"], tmp_path)
        assert got == case["value"], (
            f"{case['proxy']} == {got!r}, fixture says {case['value']!r} — "
            f"{case['why']}"
        )


# ── Contract 6: scaffold -> addon inspector handshake ────────


class TestScaffoldInspectors:
    """The rendered cage.yaml is a format contract, so split it at the file.

    ``init.render_config`` (host, becoming Rust) writes the config;
    ``addon._load_builtin_inspectors`` (egress, Python forever) reads it
    back and decides what to load. Asserting the two halves separately —
    host produces the recorded config, proxy loads the recorded
    inspectors from it — means neither test needs the other side, which
    is what makes the pair survive the port.
    """

    @pytest.mark.parametrize(
        "case", SCAFFOLD_INSPECTORS["cases"], ids=_ids(SCAFFOLD_INSPECTORS))
    def test_host_renders_the_recorded_config(self, case):
        import yaml

        from agentcage.init import render_config

        rendered = yaml.safe_load(
            render_config("contract-fixture", scaffold=case["scaffold"])) or {}
        keys = list(case["inspector_config"])
        got = {k: rendered[k] for k in keys if k in rendered}
        assert got == case["inspector_config"], (
            f"scaffold {case['scaffold']!r} renders a different "
            f"inspector-relevant config than the fixture records — "
            f"{case['why']}"
        )

    @pytest.mark.parametrize(
        "case", SCAFFOLD_INSPECTORS["cases"], ids=_ids(SCAFFOLD_INSPECTORS))
    def test_proxy_loads_the_recorded_inspectors(self, case):
        from addon import Agentcage

        api = Agentcage.__new__(Agentcage)
        api.cfg = case["inspector_config"]
        api.inspectors = []
        api.log_allowed = False
        api._load_builtin_inspectors()
        api._load_custom_inspectors()
        assert [i.name for i in api.inspectors] == case["loaded_inspectors"], (
            f"scaffold {case['scaffold']!r}: the addon loads a different "
            f"inspector chain than the fixture records — {case['why']}"
        )


# ── fixture hygiene ──────────────────────────────────────────


class TestFixtureIntegrity:
    @pytest.mark.parametrize("name", sorted(_ALL))
    def test_shape(self, name):
        doc = _ALL[name]
        assert doc["contract"] == name
        assert doc["summary"].strip()
        assert set(doc["implementations"]) == {"host", "proxy"}
        assert doc["cases"], "an empty contract fixture asserts nothing"

    @pytest.mark.parametrize("name", sorted(_ALL))
    def test_ids_are_unique_and_documented(self, name):
        doc = _ALL[name]
        ids = _ids(doc)
        assert len(ids) == len(set(ids)), "case ids are the diff's anchors"
        for case in doc["cases"]:
            assert case["why"].strip(), f"{case['id']} has no rationale"

    @pytest.mark.parametrize("name", sorted(_ALL))
    def test_is_pure_json_no_python_isms(self, name):
        """A Rust test reads these with serde_json and nothing else.

        ``json.loads`` already proves it parses; this pins the part that
        is easy to lose — that the file is ASCII-only, so the cases
        carrying zero-width and non-breaking characters survive a
        round-trip through an editor, a terminal or a diff viewer intact.
        """
        raw = (_FIXTURES / f"{name}.json").read_bytes()
        assert raw.isascii(), "fixtures must be ASCII-escaped JSON"
        assert raw.endswith(b"\n")
        assert json.loads(raw.decode()) == _ALL[name]

    def test_superset_of_the_cross_language_vectors(self):
        """These fixtures must cover everything ``tests/cross_language/`` does.

        PR A6 lifted the SSRF corpus into
        ``tests/cross_language/vectors.py`` and wrote, in every file of
        that directory, that A4 dissolves the directory by turning its
        assertions into JSON fixtures. That is only true if nothing is
        dropped on the way, so assert the containment rather than assume
        it. Skipped when A6 has not landed yet — the two branches merge
        separately — and enforced the moment it does.
        """
        vectors = _ROOT / "tests" / "cross_language" / "vectors.py"
        if not vectors.exists():
            pytest.skip("tests/cross_language/vectors.py not present (PR A6)")
        ns: dict = {}
        exec(compile(vectors.read_text(), str(vectors), "exec"), ns)
        wanted = set(ns["BYPASS"]) | set(ns["ALLOWED"])
        for name in ("encoded_private_ip", "is_never_grant"):
            covered = {c["input"] for c in _ALL[name]["cases"]}
            assert wanted <= covered, (
                f"{name}.json is missing cross_language vectors: "
                f"{sorted(wanted - covered)} — regenerate the fixtures"
            )

    def test_generator_output_is_current(self):
        """Hand-editing a fixture is the failure mode this guards.

        An expectation typed by a human is an expectation that can be
        wrong; every one of these comes out of running the real
        implementation. If this fails, run the generator and review the
        diff — a changed expectation is a changed security contract.
        """
        proc = subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "gen-contract-fixtures.py"),
             "--check"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, (
            f"contract fixtures are out of date:\n{proc.stdout}{proc.stderr}"
        )


# ── the mutation check: proof that the fixtures bite ─────────


def _mutate(rel_path: str, *replacements: tuple[str, str]) -> types.ModuleType:
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
    path = _ROOT / rel_path
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


def _must_fail(checker, cases, impl) -> list[str]:
    """Run the whole corpus and return the ids that caught the mutant."""
    caught = []
    for case in cases:
        try:
            checker(case, impl)
        except AssertionError:
            caught.append(case["id"])
    return caught


class TestFixturesBite:
    """Mutate each implementation; the fixture must notice.

    A conformance fixture that passes against a broken implementation is
    worse than no fixture, because it reads like coverage in a review. The
    mutations below are not arbitrary noise — each one is a mistake a Rust
    port could plausibly make:

    * reaching for a "is this a private range" helper instead of the IANA
      special-purpose registry,
    * anchoring a regex at end-of-line instead of end-of-string,
    * treating a one-character TLD as a TLD,
    * an off-by-one on a port bound,
    * rewording an error message while porting it.

    Each test asserts the SPECIFIC cases that catch the mutant, not merely
    that something failed: that way a later fixture edit which deletes the
    case carrying the guarantee fails here too, instead of silently
    shifting the proof onto some unrelated case.
    """

    # ── host side ──

    def test_host_valid_domain_mutation_is_caught(self):
        """Host: drop the ``last label >= 2`` check.

        The regex alone accepts ``x.c``; the explicit length check is what
        rejects a single-letter TLD. A port that ships the regex and
        forgets the two checks layered on top of it lands exactly here.
        """
        mutant = _mutate(
            "src/agentcage/config.py",
            ('return len(domain.split(".")[-1]) >= 2', "return True"),
        )
        caught = _must_fail(
            _check_valid_domain, VALID_DOMAIN["cases"], mutant.valid_domain)
        assert "one-char-tld" in caught, caught
        assert "ipv4-three-octet" in caught, caught

    def test_host_valid_domain_anchor_mutation_is_caught(self):
        """Host: the ``\\Z`` -> ``$`` anchor regression, plus the guard.

        Python's ``$`` matches immediately before ONE trailing newline, so
        ``"evil.com\\n"`` would validate and render as a split dnsmasq
        directive — persistent per-cage config corruption. The whitespace
        guard is defence in depth against exactly this, so the mutation
        removes both, which is what a port that copies the regex and skips
        the belt-and-braces check produces.

        Exactly ONE case in the corpus catches this, and that is the
        finding worth recording: ``$`` only reopens the hole for a newline
        in final position, so ``evil.com\\nserver=/x/`` stays rejected and
        every "obvious" injection payload keeps passing. Delete
        ``trailing-newline`` and the whole regression becomes invisible.
        """
        mutant = _mutate(
            "src/agentcage/config.py",
            (r'r"(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z"',
             r'r"(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"'),
            ("if not isinstance(domain, str) or any(c.isspace() for c in domain):",
             "if not isinstance(domain, str):"),
        )
        caught = _must_fail(
            _check_valid_domain, VALID_DOMAIN["cases"], mutant.valid_domain)
        assert caught == ["trailing-newline"], caught

    def test_host_valid_domain_length_mutation_is_caught(self):
        """Host: drop the 253-character lookahead from the regex.

        The two sides reach the same limit by different routes — the host
        through ``(?=.{1,253}$)`` inside the pattern, the proxy through an
        explicit ``len(domain) > 253`` before it. Two routes to one number
        is exactly the shape that drifts, so the corpus walks the
        boundary at 252/253/254/260.
        """
        mutant = _mutate(
            "src/agentcage/config.py",
            ('r"^(?=.{1,253}$)"\n', 'r"^"\n'),
        )
        caught = _must_fail(
            _check_valid_domain, VALID_DOMAIN["cases"], mutant.valid_domain)
        assert caught == ["total-254", "total-260"], caught

    def test_host_encoded_private_ip_mutation_is_caught(self):
        """Host: ``is_global`` -> ``is_private``.

        The tempting simplification, and wrong: the two are different
        predicates, not synonyms. CGNAT is the proof — 100.64.0.0/10 is
        non-global AND non-private at the same time — so a Rust port that
        reaches for a crate's ``is_private()`` ships this bug.
        """
        # Pin the claim the README rests on, rather than asserting it in
        # prose: these two properties genuinely disagree for CGNAT.
        assert ipaddress.ip_address("100.64.0.1").is_global is False
        assert ipaddress.ip_address("100.64.0.1").is_private is False

        mutant = _mutate(
            "src/agentcage/config.py",
            ("return None if ip.is_global else str(ip)",
             "return str(ip) if ip.is_private else None"),
        )
        caught = _must_fail(
            _check_encoded_private_ip, ENCODED_PRIVATE_IP["cases"],
            mutant.encoded_private_ip)
        assert "cgnat-low" in caught, caught
        assert "cgnat-high" in caught, caught

    def test_host_relay_port_bound_mutation_is_caught(self):
        """Host: an off-by-one on the lower port bound.

        ``port: 0`` is the single commonest relay misconfiguration (an
        unset key in YAML), and accepting it means the relay binds
        somewhere the operator did not choose.
        """
        mutant = _mutate(
            "src/agentcage/data/proxy/relays/_validate.py",
            ("if not host or not (1 <= port <= 65535):",
             "if not host or not (0 <= port <= 65535):"),
        )
        caught = _must_fail(
            _check_validate_relay_entry, VALIDATE_RELAY_ENTRY["cases"],
            mutant.validate_relay_entry)
        assert "err-port-0" in caught, caught
        assert "err-port-missing" in caught, caught

    def test_host_relay_message_mutation_is_caught(self):
        """Host: reword an error message, change nothing else.

        This is the mutation a behavioural test suite misses entirely —
        accept/reject is unchanged. But ``agentcage cage create`` prints
        these verbatim, so the wording IS the contract: after the port an
        operator must not get different guidance depending on whether the
        host or the proxy rejected their config.
        """
        mutant = _mutate(
            "src/agentcage/data/proxy/relays/_validate.py",
            ('raise ValueError(f"protocol_relays[{name}].auth must be a mapping")',
             'raise ValueError(f"protocol_relays[{name}].auth must be a dict")'),
        )
        caught = _must_fail(
            _check_validate_relay_entry, VALIDATE_RELAY_ENTRY["cases"],
            mutant.validate_relay_entry)
        assert "err-auth-list" in caught, caught
        assert "err-auth-string" in caught, caught

    # ── proxy side ──

    def test_proxy_encoded_private_ip_mutation_is_caught(self):
        """Proxy: accept only the hyphen spelling of the encoded address.

        ``nip.io`` serves both ``169-254-169-254.nip.io`` and
        ``169.254.169.254.nip.io``; dropping ``.`` from the separator class
        leaves the dotted spelling of the metadata endpoint wide open.
        """
        mutant = _mutate(
            "src/agentcage/data/proxy/policy_api.py",
            (r'r"^(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?:$|[-.])"',
             r'r"^(\d{1,3})[-](\d{1,3})[-](\d{1,3})[-](\d{1,3})(?:$|[-.])"'),
        )
        caught = _must_fail(
            _check_encoded_private_ip, ENCODED_PRIVATE_IP["cases"],
            mutant._encoded_private_ip)
        assert "metadata-dotted" in caught, caught
        assert "link-local-metadata" in caught, caught

    def test_proxy_valid_domain_mutation_is_caught(self):
        """Proxy: an off-by-one on the last-label length check."""
        mutant = _mutate(
            "src/agentcage/data/proxy/policy_api.py",
            ("if len(labels[-1]) < 2:", "if len(labels[-1]) < 1:"),
        )
        caught = _must_fail(
            _check_valid_domain, VALID_DOMAIN["cases"],
            mutant.PolicyApi._valid_domain)
        assert "one-char-tld" in caught, caught

    def test_proxy_is_never_grant_mutation_is_caught(self):
        """Proxy: string-suffix matching instead of a label walk.

        ``endswith`` is the obvious-looking port of "suffix match" and it
        is wrong in both directions: it blocks ``notinternal.com`` (an
        over-block, its own bug) while still passing the encoded-IP names.
        The corpus carries the near-misses that separate the two.
        """
        mutant = _mutate(
            "src/agentcage/data/proxy/policy_api.py",
            ('        parts = domain.lower().rstrip(".").split(".")\n'
             "        for i in range(len(parts)):\n"
             '            if ".".join(parts[i:]) in self._never_grant:\n'
             "                return True\n"
             "        return False",
             '        d = domain.lower().rstrip(".")\n'
             "        return any(d.endswith(n) for n in self._never_grant)"),
        )

        def _impl(domain, never):
            api = mutant.PolicyApi.__new__(mutant.PolicyApi)
            api._never_grant = set(never)
            return api._is_never_grant(domain)

        caught = _must_fail(
            _check_is_never_grant, IS_NEVER_GRANT["cases"], _impl)
        assert "near-internal-concat" in caught, caught
        assert "near-localhost-substring" in caught, caught
        assert "operator-sibling" in caught, caught

    def test_unmutated_modules_still_conform(self):
        """The control arm: ``_mutate`` with no edits must pass everything.

        Without this, a mutation test could pass because ``_mutate``
        itself is broken — an exec'd module that raises on every input
        "catches" every mutant.
        """
        mod = _mutate("src/agentcage/config.py")
        assert _must_fail(
            _check_valid_domain, VALID_DOMAIN["cases"], mod.valid_domain) == []
        assert _must_fail(
            _check_encoded_private_ip, ENCODED_PRIVATE_IP["cases"],
            mod.encoded_private_ip) == []
