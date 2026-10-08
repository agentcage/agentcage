"""The HOST side of the contract fixtures.

Half of a pair. ``test_contract_fixtures.py`` holds the proxy half and
``tests/contract_cases.py`` holds what they share; the split is what
``scripts/classify-tests.py --fail-on-both`` requires, and the reason is
in that module's docstring.

**This file is the half with an end date.** The host CLI becomes a Rust
binary, so at cutover these assertions move to the Rust suite reading the
same JSON with ``serde_json``, and this file is deleted outright rather
than edited. Keeping the host half in its own file is what makes that a
file removal instead of surgery on a file the proxy still needs.

Everything asserted here comes out of ``tests/fixtures/contracts/``,
which comes out of ``scripts/gen-contract-fixtures.py`` running the real
implementation. Nothing is hand-written, and nothing here imports the
proxy.
"""

from __future__ import annotations

import ipaddress  # noqa: F401  (re-exported into mutated module namespaces)
import re  # noqa: F401
from pathlib import Path  # noqa: F401

import pytest

from tests.contract_cases import (
    ENCODED_PRIVATE_IP,
    IS_NEVER_GRANT,
    SCAFFOLD_INSPECTORS,
    SHARED_CONSTANTS,
    VALID_DOMAIN,
    check_encoded_private_ip,
    check_is_never_grant,
    check_valid_domain,
    check_valid_domain_single,
    ids,
    must_fail,
    mutate,
)


# ── the host side ──────────────────────────────────────────

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

# The constants the host owns outright.
#
# `known_relay_types` and `relay_write_modes` are NOT here, and their
# absence is the split working rather than a gap. They live in
# `relays/_validate.py`, which is physically on the proxy side of the
# boundary; the host reaches them only because both sides are Python
# today, and `tests/cross_language/test_relay_module_identity.py` pins
# that "only because". Asserting them from here would import the proxy
# tree — the one thing this file must not do — and would assert nothing
# `test_contract_fixtures.py` does not already assert about the very
# same objects. After the port they are Rust constants, checked against
# this same JSON by `contract_relay_entry.rs`.
HOST_OWNED_CONSTANTS = (
    "max_capture_file_bytes",
    "auto_never_grant",
    "builtin_inspector_names",
)


def _host_constant(case_id: str):
    import agentcage.config as config

    return {
        "max_capture_file_bytes": lambda: config.MAX_CAPTURE_FILE_BYTES,
        "auto_never_grant": lambda: sorted(
            {h.lower().rstrip(".") for h in config._AUTO_NEVER_GRANT}),
        "builtin_inspector_names": lambda: sorted(
            config._BUILTIN_INSPECTOR_NAMES),
    }[case_id]()

class TestValidDomain:
    """``config.valid_domain`` vs ``PolicyApi._valid_domain``.

    The gate that stops a string crossing the trust boundary (a grants
    overlay entry) from being rendered into a dnsmasq directive, and the
    gate the addon applies to a runtime grant request. If the two sides
    disagree, a domain is accepted by one and refused by the other.
    """

    @pytest.mark.parametrize("case", VALID_DOMAIN["cases"], ids=ids(VALID_DOMAIN))
    def test_host(self, case):
        check_valid_domain(case, _host_valid_domain)

    @pytest.mark.parametrize("case", VALID_DOMAIN["cases"], ids=ids(VALID_DOMAIN))
    def test_host_allow_single_label(self, case):
        """Host-only mode: the proxy has no counterpart and must not.

        ``allow_single_label=True`` accepts a bare LAN/mDNS hostname on
        OPERATOR-owned paths only. The runtime grant paths — the addon's
        request endpoint, the grants reconcile, ``grants promote`` — stay
        strict-dotted, because a single-label name is exactly what an
        internal service looks like. The fixture records both columns so
        the Rust port cannot quietly collapse them into one.
        """
        check_valid_domain_single(case, _host_valid_domain_single)

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
    def test_host(self, case):
        check_encoded_private_ip(case, _host_encoded_private_ip)

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
    def test_host(self, case):
        check_is_never_grant(case, _host_is_never_grant)

    def test_the_fixture_uses_the_real_built_in_floor(self):
        """The cases are only as good as the set they run against.

        So pin where that set comes from: ``config._AUTO_NEVER_GRANT``
        plus the default decider control host. The proxy half asserts
        that its own ``_effective_never_grant`` computes the same set,
        against the same fixture — which is the split that replaces the
        old host-imports-proxy comparison.
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
        assert set(_AUTO_NEVER_GRANT) <= expected

class TestSharedConstants:
    """Numbers and sets that exist twice because the addon cannot import.

    Not behaviour, so no mutation arm — a constant has no branches. The
    assertion is simply that both sides produce the recorded value, which
    is what ``tests/cross_language/test_capture_format_conformance.py``
    and A6's never-grant-set assertion were doing pairwise.
    """

    @pytest.mark.parametrize(
        "case",
        [c for c in SHARED_CONSTANTS["cases"] if c["id"] in HOST_OWNED_CONSTANTS],
        ids=[c["id"] for c in SHARED_CONSTANTS["cases"]
             if c["id"] in HOST_OWNED_CONSTANTS])
    def test_host(self, case):
        got = _host_constant(case["id"])
        assert got == case["value"], (
            f"{case['host']} == {got!r}, fixture says {case['value']!r} — "
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

    def test_host_valid_domain_mutation_is_caught(self):
        """Host: drop the ``last label >= 2`` check.

        The regex alone accepts ``x.c``; the explicit length check is what
        rejects a single-letter TLD. A port that ships the regex and
        forgets the two checks layered on top of it lands exactly here.
        """
        mutant = mutate(
            "src/agentcage/config.py",
            ('return len(domain.split(".")[-1]) >= 2', "return True"),
        )
        caught = must_fail(
            check_valid_domain, VALID_DOMAIN["cases"], mutant.valid_domain)
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
        mutant = mutate(
            "src/agentcage/config.py",
            (r'r"(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z"',
             r'r"(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"'),
            ("if not isinstance(domain, str) or any(c.isspace() for c in domain):",
             "if not isinstance(domain, str):"),
        )
        caught = must_fail(
            check_valid_domain, VALID_DOMAIN["cases"], mutant.valid_domain)
        assert caught == ["trailing-newline"], caught

    def test_host_valid_domain_length_mutation_is_caught(self):
        """Host: drop the 253-character lookahead from the regex.

        The two sides reach the same limit by different routes — the host
        through ``(?=.{1,253}$)`` inside the pattern, the proxy through an
        explicit ``len(domain) > 253`` before it. Two routes to one number
        is exactly the shape that drifts, so the corpus walks the
        boundary at 252/253/254/260.
        """
        mutant = mutate(
            "src/agentcage/config.py",
            ('r"^(?=.{1,253}$)"\n', 'r"^"\n'),
        )
        caught = must_fail(
            check_valid_domain, VALID_DOMAIN["cases"], mutant.valid_domain)
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

        mutant = mutate(
            "src/agentcage/config.py",
            ("return None if ip.is_global else str(ip)",
             "return str(ip) if ip.is_private else None"),
        )
        caught = must_fail(
            check_encoded_private_ip, ENCODED_PRIVATE_IP["cases"],
            mutant.encoded_private_ip)
        assert "cgnat-low" in caught, caught
        assert "cgnat-high" in caught, caught

    def test_unmutated_modules_still_conform(self):
        """The control arm: ``_mutate`` with no edits must pass everything.

        Without this, a mutation test could pass because ``_mutate``
        itself is broken — an exec'd module that raises on every input
        "catches" every mutant.
        """
        mod = mutate("src/agentcage/config.py")
        assert must_fail(
            check_valid_domain, VALID_DOMAIN["cases"], mod.valid_domain) == []
        assert must_fail(
            check_encoded_private_ip, ENCODED_PRIVATE_IP["cases"],
            mod.encoded_private_ip) == []
