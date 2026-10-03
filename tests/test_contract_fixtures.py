"""The PROXY side of the contract fixtures, plus the fixtures' own hygiene.

agentcage has six pieces of logic that exist on BOTH sides of its trust
boundary — the host CLI and the in-egress proxy. They used to agree
because they were the same language: tests imported both copies and
compared them to each other. Neither mechanism survives the Rust port of
the host CLI, so the agreement moved into something neither
implementation owns — a plain-JSON fixture under
``tests/fixtures/contracts/``, generated from the current Python by
``scripts/gen-contract-fixtures.py`` and asserted by both sides
separately::

    before:   host == proxy
    after:    host == fixture   AND   proxy == fixture

and after the port the Rust suite becomes a third assertion against the
same file, via ``serde_json``.

**This file is the half that lives forever.** The egress proxy stays
Python inside the mitmproxy image, so these assertions stay pytest. The
host half is ``test_contract_fixtures_host.py``, which the Rust suite
replaces at cutover; what they share is ``tests/contract_cases.py``. No file
imports both sides — see `scripts/classify-tests.py`.

Two things this file deliberately does NOT do:

* It does not compare host to proxy directly. That assertion is what is
  being replaced; keeping it would hide a case where both sides drifted
  together away from the recorded contract. (The one place that identity
  is still asserted — the two import paths of the shared relay validator
  — is a genuinely cross-language fact and lives in
  ``tests/cross_language/``.)
* It does not hand-write a single expectation. Everything asserted here
  comes out of the JSON, and the JSON comes out of the generator.

``TestFixturesBite`` at the bottom is the load-bearing part: a fixture
that passes no matter what the implementation does is worse than no
fixture, because it reads like coverage. Those tests apply real
source-level mutations to each implementation and require the
conformance check to fail.
"""

from __future__ import annotations

import ipaddress  # noqa: F401  (re-exported into mutated module namespaces)
import json
import re  # noqa: F401
import subprocess
import sys
from pathlib import Path  # noqa: F401

import pytest

from tests.contract_cases import (
    ALL,
    ENCODED_PRIVATE_IP,
    FIXTURE_DIR,
    IS_NEVER_GRANT,
    ROOT,
    SCAFFOLD_INSPECTORS,
    SHARED_CONSTANTS,
    VALID_DOMAIN,
    VALIDATE_RELAY_ENTRY,
    check_encoded_private_ip,
    check_is_never_grant,
    check_valid_domain,
    check_validate_relay_entry,
    ids,
    must_fail,
    mutate,
)


# ── the proxy side ────────────────────────────────────────

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

def _proxy_validate_relay_entry(entry, source_validator=None):
    """The relay validator as the PROXY reaches it (a bare ``relays`` import)."""
    from relays._validate import validate_relay_entry

    return validate_relay_entry(entry, source_validator=source_validator)

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

class TestValidDomain:
    """``config.valid_domain`` vs ``PolicyApi._valid_domain``.

    The gate that stops a string crossing the trust boundary (a grants
    overlay entry) from being rendered into a dnsmasq directive, and the
    gate the addon applies to a runtime grant request. If the two sides
    disagree, a domain is accepted by one and refused by the other.
    """

    @pytest.mark.parametrize("case", VALID_DOMAIN["cases"], ids=ids(VALID_DOMAIN))
    def test_proxy(self, case):
        check_valid_domain(case, _proxy_valid_domain)

class TestEncodedPrivateIp:
    """``config.encoded_private_ip`` vs ``policy_api._encoded_private_ip``.

    The structural half of the SSRF guard. A wildcard-DNS name like
    ``169-254-169-254.nip.io`` is a syntactically valid PUBLIC hostname
    carrying none of the never-grant suffixes, and resolves to the cloud
    metadata endpoint. Drift here means one side of the boundary stops
    seeing the encoding.
    """

    @pytest.mark.parametrize(
        "case", ENCODED_PRIVATE_IP["cases"], ids=ids(ENCODED_PRIVATE_IP))
    def test_proxy(self, case):
        check_encoded_private_ip(case, _proxy_encoded_private_ip)

class TestIsNeverGrant:
    """``cli._is_never_grant`` vs ``PolicyApi._is_never_grant``.

    Which domains can never be granted at runtime, whatever the decider
    says. The proxy copy refuses the grant; the host copy stops the
    reconcile promoting such a domain into the operator's baseline from an
    overlay that was hand-edited or written by an older addon. A drift here
    is the worst of the four: it is the floor under the decider.
    """

    @pytest.mark.parametrize(
        "case", IS_NEVER_GRANT["cases"], ids=ids(IS_NEVER_GRANT))
    def test_proxy(self, case):
        check_is_never_grant(case, _proxy_is_never_grant)

    def test_the_fixture_uses_the_set_the_addon_computes(self):
        """The proxy half of the old both-sides assertion.

        ``_effective_never_grant`` unions the built-in floor with the
        control host. The fixture records the result; the host half
        asserts that ``config._AUTO_NEVER_GRANT`` plus the default
        control host produces the same set, against the same JSON. Two
        assertions against one recording, rather than one assertion
        across the boundary.
        """
        used = {frozenset(c["never_grant"]) for c in IS_NEVER_GRANT["cases"]}
        pa = _proxy_module()
        api = pa.PolicyApi.__new__(pa.PolicyApi)
        api.host = "agentcage.local"
        computed = frozenset(api._effective_never_grant([]))
        assert computed in used, (
            f"no fixture case uses the floor the addon computes "
            f"{sorted(computed)}; the corpus only covers "
            f"{[sorted(s) for s in used]}"
        )

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
        "case", VALIDATE_RELAY_ENTRY["cases"], ids=ids(VALIDATE_RELAY_ENTRY))
    def test_proxy(self, case):
        check_validate_relay_entry(case, _proxy_validate_relay_entry)

    def test_no_source_validator_is_equivalent_for_every_case(self):
        """The hook is optional; omitting it must not change the verdict.

        This is the proxy's own call shape: the canonical source
        validator is not importable inside the container, so the egress
        passes ``None``. The host passes
        ``secret_resolver.validate_source``. The fixture carries ONE
        answer for both, which is only sound if the hook adds an arm
        rather than altering the existing ones — and it is the proxy,
        the side that actually omits it, that has to prove that.
        """
        for case in VALIDATE_RELAY_ENTRY["cases"]:
            try:
                _proxy_validate_relay_entry(case["entry"])
                ok, error = True, None
            except ValueError as exc:
                ok, error = False, str(exc)
            assert (ok, error) == (case["ok"], case["error"]), case["id"]

class TestSharedConstants:
    """Numbers and sets that exist twice because the addon cannot import.

    Not behaviour, so no mutation arm — a constant has no branches. The
    assertion is simply that both sides produce the recorded value, which
    is what ``tests/cross_language/test_capture_format_conformance.py``
    and A6's never-grant-set assertion were doing pairwise.
    """

    @pytest.mark.parametrize(
        "case", SHARED_CONSTANTS["cases"], ids=ids(SHARED_CONSTANTS))
    def test_proxy(self, case, tmp_path):
        got = _proxy_constant(case["id"], tmp_path)
        assert got == case["value"], (
            f"{case['proxy']} == {got!r}, fixture says {case['value']!r} — "
            f"{case['why']}"
        )

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
        "case", SCAFFOLD_INSPECTORS["cases"], ids=ids(SCAFFOLD_INSPECTORS))
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

class TestFixtureIntegrity:

    @pytest.mark.parametrize("name", sorted(ALL))
    def test_shape(self, name):
        doc = ALL[name]
        assert doc["contract"] == name
        assert doc["summary"].strip()
        assert set(doc["implementations"]) == {"host", "proxy"}
        assert doc["cases"], "an empty contract fixture asserts nothing"

    @pytest.mark.parametrize("name", sorted(ALL))
    def test_ids_are_unique_and_documented(self, name):
        doc = ALL[name]
        case_ids = ids(doc)
        assert len(case_ids) == len(set(case_ids)), (
            "case ids are the diff's anchors"
        )
        for case in doc["cases"]:
            assert case["why"].strip(), f"{case['id']} has no rationale"

    @pytest.mark.parametrize("name", sorted(ALL))
    def test_is_pure_json_no_python_isms(self, name):
        """A Rust test reads these with serde_json and nothing else.

        ``json.loads`` already proves it parses; this pins the part that
        is easy to lose — that the file is ASCII-only, so the cases
        carrying zero-width and non-breaking characters survive a
        round-trip through an editor, a terminal or a diff viewer intact.
        """
        raw = (FIXTURE_DIR / f"{name}.json").read_bytes()
        assert raw.isascii(), "fixtures must be ASCII-escaped JSON"
        assert raw.endswith(b"\n")
        assert json.loads(raw.decode()) == ALL[name]

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
        vectors = ROOT / "tests" / "cross_language" / "vectors.py"
        if not vectors.exists():
            pytest.skip("tests/cross_language/vectors.py not present (PR A6)")
        ns: dict = {}
        exec(compile(vectors.read_text(), str(vectors), "exec"), ns)
        wanted = set(ns["BYPASS"]) | set(ns["ALLOWED"])
        for name in ("encoded_private_ip", "is_never_grant"):
            covered = {c["input"] for c in ALL[name]["cases"]}
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
            [sys.executable, str(ROOT / "scripts" / "gen-contract-fixtures.py"),
             "--check"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, (
            f"contract fixtures are out of date:\n{proc.stdout}{proc.stderr}"
        )

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

    def test_proxy_encoded_private_ip_mutation_is_caught(self):
        """Proxy: accept only the hyphen spelling of the encoded address.

        ``nip.io`` serves both ``169-254-169-254.nip.io`` and
        ``169.254.169.254.nip.io``; dropping ``.`` from the separator class
        leaves the dotted spelling of the metadata endpoint wide open.
        """
        mutant = mutate(
            "src/agentcage/data/proxy/policy_api.py",
            (r'r"^(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?:$|[-.])"',
             r'r"^(\d{1,3})[-](\d{1,3})[-](\d{1,3})[-](\d{1,3})(?:$|[-.])"'),
        )
        caught = must_fail(
            check_encoded_private_ip, ENCODED_PRIVATE_IP["cases"],
            mutant._encoded_private_ip)
        assert "metadata-dotted" in caught, caught
        assert "link-local-metadata" in caught, caught

    def test_proxy_valid_domain_mutation_is_caught(self):
        """Proxy: an off-by-one on the last-label length check."""
        mutant = mutate(
            "src/agentcage/data/proxy/policy_api.py",
            ("if len(labels[-1]) < 2:", "if len(labels[-1]) < 1:"),
        )
        caught = must_fail(
            check_valid_domain, VALID_DOMAIN["cases"],
            mutant.PolicyApi._valid_domain)
        assert "one-char-tld" in caught, caught

    def test_proxy_is_never_grant_mutation_is_caught(self):
        """Proxy: string-suffix matching instead of a label walk.

        ``endswith`` is the obvious-looking port of "suffix match" and it
        is wrong in both directions: it blocks ``notinternal.com`` (an
        over-block, its own bug) while still passing the encoded-IP names.
        The corpus carries the near-misses that separate the two.
        """
        mutant = mutate(
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

        caught = must_fail(
            check_is_never_grant, IS_NEVER_GRANT["cases"], _impl)
        assert "near-internal-concat" in caught, caught
        assert "near-localhost-substring" in caught, caught
        assert "operator-sibling" in caught, caught

    def test_host_relay_port_bound_mutation_is_caught(self):
        """an off-by-one on the lower port bound.

        ``port: 0`` is the single commonest relay misconfiguration (an
        unset key in YAML), and accepting it means the relay binds
        somewhere the operator did not choose.
        """
        mutant = mutate(
            "src/agentcage/data/proxy/relays/_validate.py",
            ("if not host or not (1 <= port <= 65535):",
             "if not host or not (0 <= port <= 65535):"),
        )
        caught = must_fail(
            check_validate_relay_entry, VALIDATE_RELAY_ENTRY["cases"],
            mutant.validate_relay_entry)
        assert "err-port-0" in caught, caught
        assert "err-port-missing" in caught, caught

    def test_host_relay_message_mutation_is_caught(self):
        """reword an error message, change nothing else.

        This is the mutation a behavioural test suite misses entirely —
        accept/reject is unchanged. But ``agentcage cage create`` prints
        these verbatim, so the wording IS the contract: after the port an
        operator must not get different guidance depending on whether the
        host or the proxy rejected their config.
        """
        mutant = mutate(
            "src/agentcage/data/proxy/relays/_validate.py",
            ('raise ValueError(f"protocol_relays[{name}].auth must be a mapping")',
             'raise ValueError(f"protocol_relays[{name}].auth must be a dict")'),
        )
        caught = must_fail(
            check_validate_relay_entry, VALIDATE_RELAY_ENTRY["cases"],
            mutant.validate_relay_entry)
        assert "err-auth-list" in caught, caught
        assert "err-auth-string" in caught, caught
