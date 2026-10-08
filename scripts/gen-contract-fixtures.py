#!/usr/bin/env python3
"""Generate the cross-language conformance fixtures under tests/fixtures/contracts/.

Four pieces of security logic exist on both sides of agentcage's trust
boundary — the host CLI and the in-egress proxy. Today they agree because
they are the same language (one is literally the same module; three are
duplicated and held in sync by a pytest that imports both). Neither
mechanism survives the Rust port of the host CLI: Rust cannot import a
Python module, and a pytest cannot import the Rust side.

So the agreement has to be pinned in something neither side owns. This
script runs the CURRENT Python implementation over a curated corpus of
inputs and writes the outcomes to plain JSON. After the port the fixture —
not either implementation — is the oracle, and both suites assert against
it (`tests/test_contract_fixtures.py` here, `serde_json` on the Rust side).

The inputs are hand-curated; the EXPECTATIONS are always computed, never
typed. That is the point: a case cannot be added with a wrong expectation,
and a behaviour change shows up as a fixture diff in review rather than as
silent drift between two implementations.

Usage:
    uv run python scripts/gen-contract-fixtures.py          # write
    uv run python scripts/gen-contract-fixtures.py --check  # fail if stale

See tests/fixtures/contracts/README.md for how to add a case.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OUT = _ROOT / "tests" / "fixtures" / "contracts"

sys.path.insert(0, str(_ROOT / "src"))

from agentcage.config import (  # noqa: E402
    _AUTO_NEVER_GRANT,
    _BUILTIN_INSPECTOR_NAMES,
    MAX_CAPTURE_FILE_BYTES,
    encoded_private_ip,
    valid_domain,
)
from agentcage.data.proxy.relays._validate import (  # noqa: E402
    KNOWN_RELAY_TYPES,
    _WRITE_MODES,
    validate_relay_entry,
)

# ``cli._is_never_grant`` is a four-line suffix walk over a set; importing
# agentcage.cli here would drag in click purely to reach it, and the
# generator must run with nothing but the stdlib on the path. Re-derive it
# from its two ingredients instead — the encoded-IP guard (imported above,
# the real thing) and the suffix walk, which is reproduced verbatim below.
# tests/test_contract_fixtures.py asserts the real cli._is_never_grant and
# the real PolicyApi._is_never_grant against what this writes, so a drift
# between this transcription and either implementation fails the suite.


def _is_never_grant(domain: str, never: set) -> bool:
    if encoded_private_ip(domain) is not None:
        return True
    parts = domain.lower().rstrip(".").split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in never:
            return True
    return False


# The built-in never-grant floor, as both sides compute it: the host's
# ``config._AUTO_NEVER_GRANT`` plus the decider control host, and the
# addon's ``_effective_never_grant`` literal plus ``self.host``.
DEFAULT_NEVER = ["agentcage.local", "internal", "local", "localhost", "metadata.goog"]
OPERATOR_NEVER = DEFAULT_NEVER + ["corp.example.com", "vault.example.net"]


# ── PR A6's shared vectors ──────────────────────────────────────────
# PR A6 lifted the SSRF corpus out of test_policy_api_ssrf_guard.py into
# ``tests/cross_language/vectors.py`` as plain no-import data, explicitly
# so this generator would have one place to serialise from. Import it when
# it is on disk (the two branches merge separately, so it may not be), and
# otherwise fall back to the transcription below — which is asserted equal
# to the real module whenever that module IS present, so the fallback
# cannot rot into a second source of truth.
_A6_BYPASS_FALLBACK = [
    "169-254-169-254.nip.io",
    "169.254.169.254.nip.io",
    "127-0-0-1.nip.io",
    "10-0-0-1.sslip.io",
    "192-168-1-1.traefik.me",
    "172.17.0.1.xip.io",
    "100-64-0-1.example.com",
]
_A6_ALLOWED_FALLBACK = [
    "registry.npmjs.org",
    "raw.githubusercontent.com",
    "codecov.io",
    "93-184-216-34.nip.io",
    "10-years.example.com",
    "1-2-3.example.com",
    "999-999-999-999.nip.io",
]


def _a6_vectors() -> tuple[list, list]:
    path = _ROOT / "tests" / "cross_language" / "vectors.py"
    if not path.exists():
        return _A6_BYPASS_FALLBACK, _A6_ALLOWED_FALLBACK
    ns: dict = {}
    exec(compile(path.read_text(), str(path), "exec"), ns)
    bypass, allowed = list(ns["BYPASS"]), list(ns["ALLOWED"])
    assert bypass == _A6_BYPASS_FALLBACK, (
        "tests/cross_language/vectors.py BYPASS changed; update the "
        f"fallback in this generator:\n{bypass}")
    assert allowed == _A6_ALLOWED_FALLBACK, (
        "tests/cross_language/vectors.py ALLOWED changed; update the "
        f"fallback in this generator:\n{allowed}")
    return bypass, allowed


A6_BYPASS, A6_ALLOWED = _a6_vectors()


def _with_a6_vectors(cases: list, why: str, **fields) -> list:
    """Append any A6 vector the curated corpus does not already carry.

    The fixtures must be a strict SUPERSET of what PR A6's
    ``tests/cross_language/`` asserts, because those files are meant to
    dissolve into these. Appending programmatically means a vector added
    there later shows up here on the next regeneration instead of being
    quietly dropped.
    """
    have = {c["input"] for c in cases}
    extra = []
    for d in A6_BYPASS + A6_ALLOWED:
        if d not in have:
            extra.append(_c(f"a6-vector-{d}", why, input=d, **fields))
            have.add(d)
    return cases + extra


def _c(id_: str, why: str, **kw) -> dict:
    """One case: a stable id, the reason it is here, plus its payload."""
    return {"id": id_, "why": why, **kw}


def _name_of_length(n: int) -> str:
    """A well-formed dotted name of EXACTLY *n* characters.

    Built rather than typed: a boundary case whose length is not the
    length its id claims tests the wrong boundary and looks fine in
    review, which is the whole failure mode this corpus exists to avoid.
    """
    last = n - 248  # 4 labels of 61 + 4 separators = 248
    assert 1 <= last <= 63, f"no 5-label name of length {n}"
    out = ".".join(["a" * 61] * 4) + "." + "a" * last
    assert len(out) == n
    return out


# ── Contract 1: valid_domain ────────────────────────────────────────

_VALID_DOMAIN_INPUTS = [
    # ── ordinary ──
    _c("plain-two-label", "the common case", input="example.com"),
    _c("subdomain", "the other common case", input="api.example.com"),
    _c("deep", "many labels are fine", input="a.b.c.deep.example.co.uk"),
    _c("hyphenated", "hyphens are legal mid-label", input="my-api.example.com"),
    _c("double-hyphen", "RFC allows -- mid-label", input="a--b.example.com"),
    _c("digit-leading-label", "3com.com is a real name", input="3com.com"),
    _c("all-digit-label", "digits-only labels are legal DNS", input="123.example.com"),
    _c("short-tld-two", ".io is the shortest real TLD shape", input="example.io"),
    _c("long-tld", "long TLDs exist", input="example.international"),
    _c("cdn-ish", "a real name the allowlist sees daily", input="registry.npmjs.org"),
    # ── case ──
    _c("uppercase-all", "the validator is lowercase-only by design; "
       "callers lowercase before validating", input="EXAMPLE.COM"),
    _c("uppercase-mixed", "one capital is enough to fail", input="Example.com"),
    _c("uppercase-tld", "capitals anywhere fail", input="example.COM"),
    # ── trailing / leading dots ──
    _c("trailing-dot", "the fully-qualified form; NOT accepted here even "
       "though the never-grant walk strips it", input="example.com."),
    _c("trailing-dot-double", "two trailing dots", input="example.com.."),
    _c("leading-dot", "the 'apex and everything under it' spelling "
       "operators reach for", input=".example.com"),
    _c("leading-dot-double", "two leading dots", input="..example.com"),
    _c("dot-only", "a lone separator", input="."),
    _c("dot-dot", "two lone separators", input=".."),
    # ── wildcards ──
    _c("wildcard-star-dot", "the spelling operators try first; agentcage "
       "suffix-matches instead, so '*' is not a legal entry", input="*.example.com"),
    _c("wildcard-star-tld", "a maximally broad wildcard", input="*.com"),
    _c("wildcard-bare", "the broadest string possible", input="*"),
    _c("wildcard-double-star", "glob-style recursion", input="**.example.com"),
    _c("wildcard-mid", "a star inside a label", input="ex*mple.com"),
    # ── empty labels ──
    _c("empty", "the empty string", input=""),
    _c("empty-label-mid", "a doubled separator", input="example..com"),
    _c("empty-label-lead", "starts with a separator", input=".com"),
    _c("empty-label-trail", "ends with a separator", input="com."),
    # ── single label ──
    _c("single-label-lan", "a LAN/mDNS host: rejected strictly, accepted "
       "under allow_single_label on operator-owned paths", input="nas"),
    _c("single-label-hostname", "the shape config.valid_domain's "
       "allow_single_label branch exists for", input="fcos-vm-home-01"),
    _c("single-label-localhost", "single-label AND a never-grant suffix",
       input="localhost"),
    _c("single-label-one-char", "one character is a legal DNS label, but "
       "the last-label >= 2 rule applies to the single-label branch too, "
       "so even allow_single_label rejects it", input="a"),
    _c("single-label-digit", "same, with a digit", input="7"),
    _c("single-label-two-char", "two characters clear the last-label rule",
       input="ns"),
    _c("single-label-63", "the longest legal label", input="a" * 63),
    _c("single-label-64", "one over the label limit", input="a" * 64),
    _c("single-label-trailing-hyphen", "labels may not end in a hyphen",
       input="nas-"),
    _c("single-label-leading-hyphen", "labels may not start with a hyphen",
       input="-nas"),
    # ── label length ──
    _c("label-63", "the longest legal label, dotted", input="a" * 63 + ".com"),
    _c("label-64", "one over the RFC 1035 label limit", input="a" * 64 + ".com"),
    _c("label-63-mid", "a long label in the middle", input="x." + "a" * 63 + ".com"),
    _c("label-64-mid", "an over-long label in the middle",
       input="x." + "a" * 64 + ".com"),
    # ── total length: the 253-byte limit ──
    _c("total-252", "one byte under the limit", input=_name_of_length(252)),
    _c("total-253", "exactly at the RFC 1035 name limit — the last length "
       "the regex's (?=.{1,253}$) lookahead admits",
       input=_name_of_length(253)),
    _c("total-254", "one byte over the limit. The host reaches this via "
       "the regex lookahead, the proxy via an explicit len() check before "
       "the regex — two routes to the same answer, which is exactly the "
       "kind of thing that drifts", input=_name_of_length(254)),
    _c("total-260", "well over the limit", input=_name_of_length(260)),
    # ── hyphen placement ──
    _c("leading-hyphen-label", "a label may not start with a hyphen",
       input="-lead.example.com"),
    _c("trailing-hyphen-label", "a label may not end with a hyphen",
       input="trail-.example.com"),
    _c("hyphen-only-label", "a label of one hyphen", input="-.example.com"),
    # ── last-label rules ──
    _c("one-char-tld", "the regex alone permits x.c; the explicit "
       "last-label >= 2 check is what rejects it", input="x.c"),
    _c("two-char-tld", "the shortest accepted last label", input="x.co"),
    _c("numeric-tld", "an all-digit last label is not an IP and passes",
       input="example.123"),
    _c("numeric-tld-one-char", "one-char numeric last label", input="example.1"),
    # ── IP literals ──
    _c("ipv4-literal", "matches the dotted-label shape; rejected explicitly "
       "because a dnsmasq server=/ key is a name, not an address",
       input="1.2.3.4"),
    _c("ipv4-public-dns", "a real address someone would try", input="8.8.8.8"),
    _c("ipv4-unspecified", "0.0.0.0 is still an IP literal", input="0.0.0.0"),
    _c("ipv4-loopback", "127.0.0.1 is still an IP literal", input="127.0.0.1"),
    _c("ipv4-broadcast", "255.255.255.255", input="255.255.255.255"),
    _c("ipv4-metadata", "the endpoint the whole guard exists for",
       input="169.254.169.254"),
    _c("ipv4-like-not-ip", "four dotted numeric labels where the last is "
       "> 255: NOT an IP, so it passes as a domain", input="1.2.3.456"),
    _c("ipv4-three-octet", "not an IP literal in Python", input="1.2.3"),
    _c("ipv6-loopback", "':' is outside the char class", input="::1"),
    _c("ipv6-full", "a routable v6 literal", input="2001:db8::1"),
    _c("ipv6-mapped-v4", "the IPv4-mapped spelling", input="::ffff:127.0.0.1"),
    _c("ipv6-bracketed", "the URL-authority spelling", input="[::1]"),
    # ── IDN / punycode ──
    _c("punycode", "the encoded form of bücher.de — this is what a "
       "resolver actually sees, and it passes", input="xn--bcher-kva.de"),
    _c("punycode-tld", "a punycode TLD", input="xn--fsq.jp"),
    _c("idn-unicode-german", "the DECODED form is rejected: callers must "
       "IDNA-encode before validating", input="bücher.de"),
    _c("idn-unicode-cjk", "decoded CJK", input="例え.jp"),
    _c("idn-arabic-digits", "Arabic-Indic digits are Unicode decimals but "
       "outside the ASCII char class", input="١٢٣.com"),
    _c("idn-homoglyph-cyrillic", "Cyrillic 'а' in an otherwise-ASCII name",
       input="exаmple.com"),
    _c("zero-width-space", "an invisible character inside a label",
       input="exa​mple.com"),
    _c("punycode-prefix-only", "a bare punycode marker", input="xn--.com"),
    # ── underscores ──
    _c("underscore-leading", "_dmarc is a real DNS name but not a legal "
       "hostname; the validator gates hostnames", input="_dmarc.example.com"),
    _c("underscore-mid", "an underscore mid-label", input="foo_bar.example.com"),
    _c("underscore-tld", "an underscore in the last label", input="example._com"),
    # ── injection: the reason this gate exists at all ──
    _c("trailing-newline", "the '$' vs '\\Z' anchor bug: '$' matches before "
       "ONE trailing newline, which would render as a split dnsmasq "
       "directive and corrupt the per-cage config", input="evil.com\n"),
    _c("trailing-newline-double", "two trailing newlines", input="evil.com\n\n"),
    _c("embedded-newline-directive", "the actual injection payload",
       input="evil.com\nserver=/anything/1.2.3.4"),
    _c("trailing-cr", "carriage return", input="evil.com\r"),
    _c("crlf", "the Windows-flavoured payload", input="evil.com\r\n"),
    _c("leading-space", "leading whitespace", input=" example.com"),
    _c("trailing-space", "trailing whitespace", input="example.com "),
    _c("embedded-space", "whitespace mid-string", input="evil com"),
    _c("tab", "a tab", input="evil.com\t"),
    _c("nbsp", "a non-breaking space — str.isspace() is True for it, which "
       "is why the guard uses isspace() and not a literal space check",
       input="evil.com "),
    _c("slash-path", "a URL path fragment", input="example.com/path"),
    _c("slash-traversal", "traversal-looking input", input="example.com/../x"),
    _c("scheme-prefixed", "a full URL", input="https://example.com"),
    _c("port-suffixed", "host:port", input="example.com:443"),
    _c("userinfo", "a URL authority with userinfo", input="user@example.com"),
    _c("semicolon", "a config-separator character", input="example.com;"),
    _c("hash", "a comment character", input="example.com#"),
    _c("nul", "an embedded NUL byte", input="example.com\x00"),
    _c("backslash", "a backslash", input="example\\.com"),
    _c("brace", "a brace", input="example{}.com"),
]


def _gen_valid_domain() -> dict:
    cases = []
    for spec in _VALID_DOMAIN_INPUTS:
        d = spec["input"]
        cases.append({
            **spec,
            "expected": valid_domain(d),
            "expected_allow_single_label": valid_domain(d, allow_single_label=True),
        })
    return {
        "contract": "valid_domain",
        "summary": (
            "Is this string a syntactically valid lowercase DNS domain? The "
            "gate that stops an overlay string from being rendered into a "
            "dnsmasq directive, and the gate the addon applies to a runtime "
            "grant request."
        ),
        "implementations": {
            "host": "agentcage.config.valid_domain (src/agentcage/config.py)",
            "proxy": ("policy_api.PolicyApi._valid_domain "
                      "(src/agentcage/data/proxy/policy_api.py)"),
        },
        "fields": {
            "input": "the candidate domain string",
            "expected": (
                "strict mode — the shape BOTH sides implement. The proxy's "
                "_valid_domain has no other mode; the host's valid_domain "
                "defaults to it."
            ),
            "expected_allow_single_label": (
                "host-only: valid_domain(d, allow_single_label=True), which "
                "additionally accepts a bare LAN/mDNS label on "
                "OPERATOR-owned paths (domains.allow, `domain add`). The "
                "runtime grant paths never take this branch, so the proxy "
                "has no counterpart and must not be checked against it."
            ),
        },
        "cases": cases,
    }


# ── Contract 2: encoded_private_ip ──────────────────────────────────

_ENCODED_IP_INPUTS = [
    # ── the attack this exists for ──
    _c("metadata-hyphen", "the original red-team finding: resolves to the "
       "cloud metadata endpoint through a valid PUBLIC name",
       input="169-254-169-254.nip.io"),
    _c("metadata-dotted", "the dotted spelling of the same service",
       input="169.254.169.254.nip.io"),
    _c("metadata-mixed-separators", "the regex accepts '-' and '.' per "
       "position independently, so mixed spellings are caught too",
       input="169.254-169.254.nip.io"),
    _c("metadata-uppercase", "case must not evade the guard",
       input="169-254-169-254.NIP.IO"),
    _c("metadata-trailing-dot", "the FQDN spelling",
       input="169-254-169-254.nip.io."),
    _c("metadata-bare", "no service suffix at all — the regex anchors on "
       "the leftmost labels and allows end-of-string", input="169-254-169-254"),
    _c("metadata-hyphen-suffix", "the address run is followed by more "
       "hyphenated text", input="169-254-169-254-prod.example.com"),
    # ── service clones ──
    _c("sslip-rfc1918", "a different wildcard-DNS service", input="10-0-0-1.sslip.io"),
    _c("traefik-me", "another clone", input="192-168-1-1.traefik.me"),
    _c("xip-docker-bridge", "the docker bridge address", input="172.17.0.1.xip.io"),
    _c("localtest-me", "another clone", input="127-0-0-1.localtest.me"),
    _c("arbitrary-domain", "matching the ENCODING rather than a service "
       "denylist covers a self-hosted wildcard zone too",
       input="100-64-0-1.example.com"),
    # ── loopback / unspecified ──
    _c("loopback-hyphen", "127.0.0.1", input="127-0-0-1.nip.io"),
    _c("loopback-dotted", "the plain address", input="127.0.0.1"),
    _c("loopback-high", "the rest of 127/8", input="127-255-255-254.nip.io"),
    _c("unspecified", "0.0.0.0 — 'this host' and a classic SSRF bypass",
       input="0-0-0-0.nip.io"),
    _c("unspecified-dotted", "the plain address", input="0.0.0.0"),
    _c("zero-slash-eight", "0.0.0.0/8 generally", input="0-1-2-3.nip.io"),
    # ── link-local ──
    _c("link-local-metadata", "the plain metadata address",
       input="169.254.169.254"),
    _c("link-local-low", "the bottom of 169.254/16", input="169-254-0-1.nip.io"),
    _c("link-local-high", "the top of 169.254/16",
       input="169-254-255-255.nip.io"),
    _c("link-local-below", "169.253.x is PUBLIC — an off-by-one on the "
       "range boundary", input="169-253-255-255.nip.io"),
    _c("link-local-above", "169.255.x is PUBLIC", input="169-255-0-1.nip.io"),
    # ── RFC 1918 ──
    _c("rfc1918-10-low", "bottom of 10/8", input="10-0-0-0.nip.io"),
    _c("rfc1918-10-high", "top of 10/8", input="10-255-255-255.nip.io"),
    _c("rfc1918-172-low", "bottom of 172.16/12", input="172-16-0-0.nip.io"),
    _c("rfc1918-172-high", "top of 172.16/12", input="172-31-255-255.nip.io"),
    _c("rfc1918-172-below", "172.15.x is PUBLIC — the classic off-by-one "
       "on the awkward /12 boundary", input="172-15-255-255.nip.io"),
    _c("rfc1918-172-above", "172.32.x is PUBLIC", input="172-32-0-0.nip.io"),
    _c("rfc1918-192-168-low", "bottom of 192.168/16", input="192-168-0-0.nip.io"),
    _c("rfc1918-192-168-high", "top of 192.168/16",
       input="192-168-255-255.nip.io"),
    _c("rfc1918-192-167", "192.167.x is PUBLIC", input="192-167-255-255.nip.io"),
    _c("rfc1918-192-169", "192.169.x is PUBLIC", input="192-169-0-0.nip.io"),
    # ── CGNAT ──
    _c("cgnat-low", "bottom of 100.64/10 — reachable on a carrier network "
       "and NOT globally routable", input="100-64-0-0.nip.io"),
    _c("cgnat-high", "top of 100.64/10", input="100-127-255-255.nip.io"),
    _c("cgnat-below", "100.63.x is PUBLIC", input="100-63-255-255.nip.io"),
    _c("cgnat-above", "100.128.x is PUBLIC", input="100-128-0-0.nip.io"),
    # ── special-purpose ranges ──
    _c("test-net-2", "198.51.100.0/24 — the TEST-NET-2 sinkhole agentcage "
       "itself points blocked domains at", input="198-51-100-1.nip.io"),
    _c("test-net-1", "192.0.2.0/24", input="192-0-2-1.nip.io"),
    _c("test-net-3", "203.0.113.0/24", input="203-0-113-1.nip.io"),
    _c("benchmark", "198.18.0.0/15 benchmarking range", input="198-18-0-1.nip.io"),
    _c("ietf-protocol", "192.0.0.0/24 IETF protocol assignments",
       input="192-0-0-1.nip.io"),
    _c("reserved-240", "240.0.0.0/4 reserved", input="240-0-0-1.nip.io"),
    _c("broadcast", "255.255.255.255 limited broadcast",
       input="255-255-255-255.nip.io"),
    _c("multicast-local", "224.0.0.1 — CPython reports multicast as "
       "globally reachable, so the guard does NOT flag it. Recorded as "
       "observed behaviour, not as an endorsement", input="224-0-0-1.nip.io"),
    _c("multicast-test-net", "233.252.0.0/24 MCAST-TEST-NET",
       input="233-252-0-1.nip.io"),
    _c("anycast-6to4", "192.88.99.1, the deprecated 6to4 relay anycast "
       "address — also reported as global", input="192-88-99-1.nip.io"),
    # ── public addresses must NOT be flagged ──
    _c("public-example", "encodes a PUBLIC address — no worse than naming "
       "the host directly, and flagging it would break real nip.io use",
       input="93-184-216-34.nip.io"),
    _c("public-dns", "a well-known public resolver", input="8-8-8-8.nip.io"),
    _c("public-plain", "a plain public address", input="1.1.1.1"),
    # ── shapes that must NOT be misread ──
    _c("digit-leading-name", "a legitimate name that merely starts with "
       "digits", input="10-years.example.com"),
    _c("too-few-octets", "three groups is not an address",
       input="1-2-3.example.com"),
    _c("five-octets", "five groups: the regex reads the first FOUR and "
       "stops at the separator before the fifth, so this decodes to the "
       "PUBLIC 1.2.3.4 and is not flagged", input="1-2-3-4-5.example.com"),
    _c("five-octets-private", "the same shape where the first four groups "
       "are RFC1918 — appending a fifth group does not evade the guard",
       input="10-0-0-1-5.example.com"),
    _c("not-an-address", "each group is in range for \\d{1,3} but the "
       "result is not a valid IPv4 address", input="999-999-999-999.nip.io"),
    _c("octet-256", "one past the octet limit", input="256-1-1-1.nip.io"),
    _c("octet-four-digits", "\\d{1,3} cannot consume a 4-digit group, and "
       "no shorter match leaves a separator", input="10-0-0-1234.nip.io"),
    _c("not-leftmost", "the address is not where wildcard-DNS services put "
       "it; reading it anywhere would misfire on legitimate names",
       input="cdn.10-0-0-1.example.com"),
    _c("empty", "the empty string", input=""),
    _c("no-digits", "an ordinary name", input="registry.npmjs.org"),
    # ── alternate IP encodings: the documented limits of this guard ──
    _c("zero-padded-octet", "010.0.0.1 would be octal in some parsers; "
       "wildcard-DNS services do not encode this way, so the guard "
       "deliberately declines to guess", input="010-0-0-1.nip.io"),
    _c("zero-padded-all", "every octet zero-padded", input="010-000-000-001.nip.io"),
    _c("octal-full", "the 4-digit octal spelling does not match \\d{1,3} "
       "followed by a separator", input="0177-0-0-1.nip.io"),
    _c("decimal-integer", "2130706433 == 127.0.0.1 as a single integer. "
       "NOT caught: no wildcard-DNS service encodes this way, and the "
       "label would have to resolve to loopback for it to matter",
       input="2130706433.nip.io"),
    _c("hex-integer", "0x7f000001 == 127.0.0.1. Not caught, same reason",
       input="0x7f000001.nip.io"),
    _c("dotted-hex", "the dotted-hex spelling", input="0x7f.0x0.0x0.0x1.nip.io"),
    _c("dotted-octal", "the dotted-octal spelling", input="0177.0.0.1.nip.io"),
    _c("short-form-two-part", "127.1 expands to 127.0.0.1 in inet_aton, "
       "but not in Python's ipaddress and not in this guard", input="127.1"),
    _c("unicode-digits", "Arabic-Indic digits ARE \\d in a Python str "
       "pattern, so the regex matches — but ipaddress rejects non-ASCII "
       "digits, so the guard returns None. A Rust port using ASCII-only "
       "\\d reaches the same answer by a different route",
       input="١٦٩-٢٥٤-١٦٩-٢٥٤.nip.io"),
    # ── IPv6 ──
    _c("ipv6-loopback", "no dotted-quad run at the head", input="::1"),
    _c("ipv6-link-local", "the v6 link-local spelling", input="fe80::1"),
    _c("ipv6-mapped-metadata", "IPv4-mapped IPv6 — the dotted quad is "
       "present but not at the leftmost position",
       input="::ffff:169.254.169.254"),
    _c("ipv6-mapped-hostname", "the mapped form spelled as a hostname label",
       input="0--ffff-169-254-169-254.nip.io"),
    _c("ipv6-hyphen-encoded", "how sslip.io encodes v6: dashes for colons. "
       "Not matched by the v4 regex", input="fe80--1.sslip.io"),
    _c("ipv6-nat64", "the NAT64 well-known prefix with an embedded v4",
       input="64:ff9b::169.254.169.254"),
]


def _gen_encoded_private_ip() -> dict:
    cases = [
        {**spec, "expected": encoded_private_ip(spec["input"])}
        for spec in _with_a6_vectors(
            _ENCODED_IP_INPUTS,
            "carried over from tests/cross_language/vectors.py so this "
            "fixture is a superset of what PR A6's conformance test "
            "asserted")
    ]
    return {
        "contract": "encoded_private_ip",
        "summary": (
            "Does this hostname ENCODE a non-globally-routable IP address? "
            "The structural half of agentcage's SSRF guard: wildcard-DNS "
            "services (nip.io, sslip.io, clones) turn a syntactically valid "
            "PUBLIC name into a route to 169.254.169.254, which name-suffix "
            "matching cannot see. Returns the decoded address, or null."
        ),
        "implementations": {
            "host": "agentcage.config.encoded_private_ip (src/agentcage/config.py)",
            "proxy": ("policy_api._encoded_private_ip "
                      "(src/agentcage/data/proxy/policy_api.py)"),
        },
        "fields": {
            "input": "the candidate hostname",
            "expected": (
                "the decoded dotted-quad string when the name encodes a "
                "non-global address, else null"
            ),
        },
        "notes": [
            "'Non-global' is CPython's ipaddress.IPv4Address.is_global. "
            "This is NOT interpreter-version-sensitive: every case in this "
            "file was run on CPython 3.12.0, 3.12.3, 3.12.4, 3.13.0 and "
            "3.14.7 and produced identical answers on all five. The "
            "is_global implementation is the same expression on all of "
            "them (`addr not in 100.64.0.0/10 and not addr.is_private`); "
            "gh-113171 altered is_private for some ranges and the is_global "
            "docstring, without moving the answer for any address here.",
            "A Rust port should still implement the IANA "
            "special-purpose registry explicitly rather than reach for a "
            "crate's is_private(): the two are different predicates, not "
            "synonyms. 100.64.0.0/10 is the proof — is_global is False and "
            "is_private is ALSO False for it, so 'not is_private' would "
            "let carrier-grade NAT through. The cgnat-* and test-net-* "
            "cases exist to make that substitution fail loudly, and "
            "test_host_encoded_private_ip_mutation_is_caught demonstrates "
            "it doing so.",
        ],
        "cases": cases,
    }


# ── Contract 3: is_never_grant ──────────────────────────────────────

_NEVER_GRANT_INPUTS = [
    # ── the built-in suffixes ──
    _c("internal-exact", "the bare suffix itself", input="internal",
       never_grant=DEFAULT_NEVER),
    _c("internal-suffix", "the canonical cloud metadata name",
       input="metadata.google.internal", never_grant=DEFAULT_NEVER),
    _c("internal-deep", "any depth under the suffix",
       input="a.b.c.d.internal", never_grant=DEFAULT_NEVER),
    _c("local-exact", "the bare suffix", input="local", never_grant=DEFAULT_NEVER),
    _c("local-suffix", "an mDNS name", input="printer.local",
       never_grant=DEFAULT_NEVER),
    _c("localhost-exact", "the bare suffix", input="localhost",
       never_grant=DEFAULT_NEVER),
    _c("localhost-suffix", "the RFC 6761 subdomain form",
       input="api.localhost", never_grant=DEFAULT_NEVER),
    _c("control-host", "the decider control host can never be granted to "
       "the cage", input="agentcage.local", never_grant=DEFAULT_NEVER),
    _c("metadata-goog", "GCP's PUBLIC metadata alias — the only cloud "
       "metadata name that does not end in .internal",
       input="metadata.goog", never_grant=DEFAULT_NEVER),
    _c("metadata-goog-sub", "a subdomain of it", input="v1.metadata.goog",
       never_grant=DEFAULT_NEVER),
    # ── suffix confusion: the near-misses that matter ──
    _c("near-evil-metadata", "an attacker-shaped label prefixing the real "
       "name. Still blocked — the walk matches on LABEL boundaries, and "
       "'internal' is a suffix here",
       input="evil-metadata.google.internal", never_grant=DEFAULT_NEVER),
    _c("near-internal-substring", "'internal' as a substring of a longer "
       "label must NOT match", input="notinternal.com",
       never_grant=DEFAULT_NEVER),
    _c("near-internal-prefix", "'internal' as a PREFIX label is not a "
       "suffix", input="internal.evil.com", never_grant=DEFAULT_NEVER),
    _c("near-internal-hyphen", "hyphen-joined, one label",
       input="my-internal", never_grant=DEFAULT_NEVER),
    _c("near-internal-concat", "concatenated into one label",
       input="xinternal", never_grant=DEFAULT_NEVER),
    _c("near-localhost-substring", "must not match", input="notlocalhost",
       never_grant=DEFAULT_NEVER),
    _c("near-localhost-prefix", "localhost as the leftmost label",
       input="localhost.evil.com", never_grant=DEFAULT_NEVER),
    _c("near-localhost-suffix-label", "localhost as the RIGHTMOST label "
       "under another name", input="evil.localhost", never_grant=DEFAULT_NEVER),
    _c("near-metadata-goog-concat", "one label, not a suffix match",
       input="xmetadata.goog", never_grant=DEFAULT_NEVER),
    _c("near-metadata-goog-tld", "'goog' alone is not in the set",
       input="something.goog", never_grant=DEFAULT_NEVER),
    _c("near-metadata-google", "the real TLD, not the metadata alias",
       input="metadata.google.com", never_grant=DEFAULT_NEVER),
    _c("near-local-substring", "'local' inside a label", input="nonlocal.com",
       never_grant=DEFAULT_NEVER),
    _c("near-local-hyphen", "hyphen-joined", input="my-local.com",
       never_grant=DEFAULT_NEVER),
    _c("near-control-host-prefix", "a name that merely starts the same way",
       input="agentcage.localdomain", never_grant=DEFAULT_NEVER),
    _c("near-control-host-concat", "one label", input="notagentcage.local",
       never_grant=DEFAULT_NEVER),
    # ── case and trailing dots ──
    _c("case-upper", "uppercase must not evade the walk",
       input="METADATA.GOOG", never_grant=DEFAULT_NEVER),
    _c("case-mixed", "mixed case", input="Metadata.Google.Internal",
       never_grant=DEFAULT_NEVER),
    _c("trailing-dot", "the FQDN spelling is stripped before matching",
       input="metadata.goog.", never_grant=DEFAULT_NEVER),
    _c("trailing-dot-upper", "both at once", input="INTERNAL.",
       never_grant=DEFAULT_NEVER),
    _c("trailing-dots-multiple", "rstrip removes every trailing dot",
       input="metadata.goog...", never_grant=DEFAULT_NEVER),
    # ── degenerate inputs ──
    _c("empty", "the empty string", input="", never_grant=DEFAULT_NEVER),
    _c("dot-only", "strips to empty", input=".", never_grant=DEFAULT_NEVER),
    _c("leading-dot", "an empty leftmost label", input=".internal",
       never_grant=DEFAULT_NEVER),
    _c("empty-never-set", "nothing is ever-never-granted; only the "
       "encoded-IP guard can fire", input="metadata.google.internal",
       never_grant=[]),
    _c("empty-never-set-encoded", "the encoded-IP guard fires even with an "
       "empty suffix set — it is structural, not name-based",
       input="169-254-169-254.nip.io", never_grant=[]),
    # ── encoded-IP arm: the case suffix matching structurally cannot see ──
    _c("encoded-metadata", "a valid PUBLIC name carrying no never-grant "
       "suffix that nonetheless reaches the metadata endpoint",
       input="169-254-169-254.nip.io", never_grant=DEFAULT_NEVER),
    _c("encoded-metadata-dotted", "the dotted spelling",
       input="169.254.169.254.nip.io", never_grant=DEFAULT_NEVER),
    _c("encoded-loopback", "loopback through a public name",
       input="127-0-0-1.nip.io", never_grant=DEFAULT_NEVER),
    _c("encoded-rfc1918", "RFC1918 through a public name",
       input="10-0-0-1.sslip.io", never_grant=DEFAULT_NEVER),
    _c("encoded-rfc1918-traefik", "a different clone service",
       input="192-168-1-1.traefik.me", never_grant=DEFAULT_NEVER),
    _c("encoded-docker-bridge", "the docker bridge",
       input="172.17.0.1.xip.io", never_grant=DEFAULT_NEVER),
    _c("encoded-cgnat", "CGNAT through an arbitrary zone — the guard is "
       "service-independent", input="100-64-0-1.example.com",
       never_grant=DEFAULT_NEVER),
    _c("encoded-public", "encodes a PUBLIC address; over-blocking a "
       "legitimate host is its own bug", input="93-184-216-34.nip.io",
       never_grant=DEFAULT_NEVER),
    _c("encoded-digit-name", "starts with digits, encodes nothing",
       input="10-years.example.com", never_grant=DEFAULT_NEVER),
    _c("encoded-too-few", "too few octets", input="1-2-3.example.com",
       never_grant=DEFAULT_NEVER),
    _c("encoded-not-an-address", "not a valid address at all",
       input="999-999-999-999.nip.io", never_grant=DEFAULT_NEVER),
    # ── ordinary allowed names ──
    _c("allowed-npm", "a name the allowlist sees daily",
       input="registry.npmjs.org", never_grant=DEFAULT_NEVER),
    _c("allowed-github", "another", input="raw.githubusercontent.com",
       never_grant=DEFAULT_NEVER),
    _c("allowed-codecov", "another", input="codecov.io",
       never_grant=DEFAULT_NEVER),
    # ── operator-supplied additions ──
    _c("operator-exact", "an operator's own never_grant entry",
       input="corp.example.com", never_grant=OPERATOR_NEVER),
    _c("operator-suffix", "and everything under it",
       input="git.corp.example.com", never_grant=OPERATOR_NEVER),
    _c("operator-sibling", "a sibling name outside the entry",
       input="notcorp.example.com", never_grant=OPERATOR_NEVER),
    _c("operator-parent", "the PARENT of an operator entry is not covered "
       "— suffix matching goes one way", input="example.com",
       never_grant=OPERATOR_NEVER),
    _c("operator-second", "the second operator entry",
       input="vault.example.net", never_grant=OPERATOR_NEVER),
    _c("operator-builtin-still-applies", "operator entries are unioned "
       "with, not substituted for, the built-in floor",
       input="metadata.google.internal", never_grant=OPERATOR_NEVER),
]


def _gen_is_never_grant() -> dict:
    cases = [
        {**spec, "expected": _is_never_grant(spec["input"], set(spec["never_grant"]))}
        for spec in _with_a6_vectors(
            _NEVER_GRANT_INPUTS,
            "carried over from tests/cross_language/vectors.py so this "
            "fixture is a superset of what PR A6's conformance test "
            "asserted", never_grant=DEFAULT_NEVER)
    ]
    return {
        "contract": "is_never_grant",
        "summary": (
            "Must this domain NEVER be granted, whatever the decider says? "
            "Two arms: a label-boundary suffix walk over the never-grant "
            "set, and the encoded-private-IP guard (the case suffix "
            "matching structurally cannot see)."
        ),
        "implementations": {
            "host": "agentcage.cli._is_never_grant(domain, never) (src/agentcage/cli.py)",
            "proxy": ("policy_api.PolicyApi._is_never_grant(domain), reading "
                      "self._never_grant (src/agentcage/data/proxy/policy_api.py)"),
        },
        "fields": {
            "input": "the candidate domain",
            "never_grant": (
                "the effective never-grant set for this case. The host "
                "builds it in cli._host_never_grant, the proxy in "
                "PolicyApi._effective_never_grant; both are "
                "config._AUTO_NEVER_GRANT plus the decider control host "
                "plus the operator's list."
            ),
            "expected": "true when the domain must never be granted",
        },
        "notes": [
            "The default set below is the built-in floor "
            "(config._AUTO_NEVER_GRANT = internal, local, localhost, "
            "metadata.goog) unioned with the default control host "
            "agentcage.local.",
            "Matching is on LABEL boundaries, not string suffixes: "
            "'notinternal.com' is not blocked by 'internal'.",
        ],
        "cases": cases,
    }


# ── Contract 4: validate_relay_entry ────────────────────────────────

_PEM = "-----BEGIN CERTIFICATE-----\nMIIBfoo\n-----END CERTIFICATE-----\n"


def _entry(**over) -> dict:
    """A well-formed IMAP relay entry, overridden key by key."""
    e = {
        "name": "mail",
        "type": "imap",
        "listen": "127.0.0.1:11143",
        "upstream": {"host": "imap.example.com", "port": 993},
    }
    e.update(over)
    return e


def _up(**over) -> dict:
    """A well-formed entry with upstream keys overridden."""
    e = _entry()
    e["upstream"] = {**e["upstream"], **over}
    return e


def _pol(**over) -> dict:
    """A well-formed entry with a policy block."""
    e = _entry()
    e["policy"] = dict(over)
    return e


_RELAY_INPUTS = [
    # ── accepted ──
    _c("ok-minimal", "the minimum viable entry", entry=_entry()),
    _c("ok-smtp", "the other known relay type",
       entry=_entry(type="smtp", listen="127.0.0.1:11587",
                    upstream={"host": "smtp.example.com", "port": 465})),
    _c("ok-port-1", "the bottom of the accepted port range",
       entry=_up(port=1)),
    _c("ok-port-65535", "the top of the accepted port range",
       entry=_up(port=65535)),
    _c("ok-port-string", "YAML quoting turns a port into a string; int() "
       "coercion accepts it", entry=_up(port="993")),
    _c("ok-plaintext-upstream", "tls: false with no TLS-only fields set",
       entry=_up(tls=False)),
    _c("ok-ca-file", "the operator-facing CA form", entry=_up(ca_file="/certs/ca.pem")),
    _c("ok-ca-pem", "the proxy-facing CA form", entry=_up(ca_pem=_PEM)),
    _c("ok-ca-pem-inline", "a PEM with the marker not at position 0",
       entry=_up(ca_pem="# issued by corp CA\n" + _PEM)),
    _c("ok-servername", "an SNI override on a TLS upstream",
       entry=_up(tls_servername="bridge.internal")),
    _c("ok-empty-ca-on-plaintext", "empty TLS-only fields do not trip the "
       "tls: false guard — only truthy ones do",
       entry=_up(tls=False, ca_file="", ca_pem="", tls_servername="")),
    _c("ok-null-ca-on-plaintext", "null is normalised to '' by `or ''`",
       entry=_up(tls=False, ca_file=None, ca_pem=None, tls_servername=None)),
    _c("ok-write-mode-none", "the most restrictive write mode",
       entry=_pol(write_mode="none")),
    _c("ok-write-mode-organise", "file and flag, never destroy",
       entry=_pol(write_mode="organise")),
    _c("ok-write-mode-full", "unrestricted", entry=_pol(write_mode="full")),
    _c("ok-write-mode-uppercase", "the mode is lowercased before checking",
       entry=_pol(write_mode="FULL")),
    _c("ok-write-mode-mixed-case", "mixed case", entry=_pol(write_mode="Organise")),
    _c("ok-readonly-agrees-none", "legacy readonly: true agrees with "
       "write_mode: none", entry=_pol(write_mode="none", readonly=True)),
    _c("ok-readonly-agrees-full", "legacy readonly: false agrees with "
       "write_mode: full", entry=_pol(write_mode="full", readonly=False)),
    _c("ok-readonly-alone", "the legacy spelling on its own is untouched "
       "by this validator", entry=_pol(readonly=True)),
    _c("ok-write-mode-null", "write_mode: null is treated as unset",
       entry=_pol(write_mode=None, readonly=True)),
    _c("ok-folder-lists", "both folder lists present and well-formed",
       entry=_pol(folder_allowlist=["INBOX", "Archive"], folder_denylist=[])),
    _c("ok-folder-lists-null", "null is 'unset', not 'wrong type'",
       entry=_pol(folder_allowlist=None, folder_denylist=None)),
    _c("ok-policy-null", "policy: null is normalised to {}",
       entry=_entry(policy=None)),
    _c("err-policy-not-mapping", "a truthy non-mapping policy is refused. "
       "It used to be skipped in silence — write_mode included — because "
       "the isinstance guard had no else branch, and the relay then died "
       "on policy.get() with an AttributeError naming nothing",
       entry=_entry(policy=["write_mode: none"])),
    _c("err-policy-string", "the same, spelled as a bare string",
       entry=_entry(policy="none")),
    _c("ok-policy-empty-list", "falsy is 'absent': `or {}` normalises it "
       "before the type is ever examined", entry=_entry(policy=[])),
    _c("ok-auth-mapping", "an auth block with no source_validator",
       entry=_entry(auth={"user_source": "env:MAIL_USER",
                          "password_source": "file:/run/secrets/mail"})),
    _c("ok-auth-null", "auth: null is normalised to {}", entry=_entry(auth=None)),
    _c("ok-unknown-keys", "unknown keys are ignored; the validator is "
       "structural, not a schema", entry=_entry(future_key="whatever")),
    _c("ok-upstream-extra-keys", "same for upstream",
       entry=_up(timeout_seconds=30)),
    # ── entry shape ──
    _c("err-entry-list", "a list where a mapping belongs", entry=["name", "mail"]),
    _c("err-entry-string", "a bare string", entry="mail"),
    _c("err-entry-null", "YAML's '- ' with nothing after it", entry=None),
    _c("err-entry-int", "a number", entry=7),
    _c("err-entry-bool", "a bare boolean", entry=True),
    # ── name / type / listen ──
    _c("err-missing-name", "no name key", entry={"type": "imap",
                                                 "listen": "127.0.0.1:11143"}),
    _c("err-missing-type", "no type key", entry={"name": "mail",
                                                 "listen": "127.0.0.1:11143"}),
    _c("err-missing-listen", "no listen key", entry={"name": "mail",
                                                     "type": "imap"}),
    _c("err-empty-entry", "an empty mapping", entry={}),
    _c("err-empty-name", "an empty name string", entry=_entry(name="")),
    _c("err-null-listen", "listen: null", entry=_entry(listen=None)),
    _c("err-name-numeric", "a YAML-numeric name; the message interpolates "
       "the value with Python repr, so it appears unquoted",
       entry=_entry(name=123, type="")),
    # ── relay type ──
    _c("err-unknown-type", "a plausible-but-unsupported protocol",
       entry=_entry(type="xmpp", listen="127.0.0.1:5222")),
    _c("err-type-case", "the type check is case-SENSITIVE",
       entry=_entry(type="IMAP")),
    _c("err-type-whitespace", "a stray space", entry=_entry(type="imap ")),
    _c("err-type-pop3", "another real protocol that is not supported",
       entry=_entry(type="pop3")),
    # ── upstream shape ──
    _c("err-upstream-list", "upstream as a list", entry=_entry(upstream=["host"])),
    _c("err-upstream-string", "upstream as a bare string",
       entry=_entry(upstream="imap.example.com:993")),
    _c("err-upstream-missing", "no upstream at all — normalised to {}, "
       "then fails the host/port check",
       entry={"name": "mail", "type": "imap", "listen": "127.0.0.1:11143"}),
    _c("err-upstream-null", "upstream: null", entry=_entry(upstream=None)),
    _c("err-upstream-no-host", "port but no host", entry=_entry(
        upstream={"port": 993})),
    _c("err-upstream-empty-host", "an empty host string", entry=_up(host="")),
    # ── port bounds ──
    _c("err-port-0", "0 is below the range", entry=_up(port=0)),
    _c("err-port-negative", "a negative port", entry=_up(port=-1)),
    _c("err-port-65536", "one above the range", entry=_up(port=65536)),
    _c("err-port-huge", "far above the range", entry=_up(port=999999)),
    _c("err-port-missing", "no port key", entry=_entry(
        upstream={"host": "imap.example.com"})),
    _c("err-port-null", "port: null coerces to 0", entry=_up(port=None)),
    _c("err-port-non-numeric", "a non-numeric string is caught by the "
       "try/except and becomes 0", entry=_up(port="imaps")),
    _c("err-port-list", "a list is caught by the try/except", entry=_up(port=[993])),
    _c("err-port-bool-false", "a falsy bool is refused too: there is no "
       "reading of port: false, and YAML 1.1 makes `port: no` the same "
       "thing", entry=_up(port=False)),
    _c("err-port-bool", "bool is an int subclass, so int(True) is 1 — a "
       "relay pointed at port 1 is never what the operator wrote, and "
       "YAML reads bare yes/on as booleans",
       entry=_up(port=True)),
    _c("err-host-list", "str() would make this the string '[1]', which is "
       "non-empty and so reads as 'present' — a config that validates and "
       "then fails DNS on a name nobody wrote", entry=_up(host=[1])),
    _c("err-host-mapping", "the same for a mapping", entry=_up(host={"a": 1})),
    _c("err-host-int", "a bare number", entry=_up(host=993)),
    _c("err-host-falsy-is-absent-not-a-type-error", "a falsy host is "
       "'absent', type unexamined — truthiness before type, matching "
       "ca_file/ca_pem — so it gets the requires-host-and-port message "
       "rather than a type complaint", entry=_up(host=[])),
    _c("ok-port-float-truncates", "a float truncates toward zero, so "
       "993.7 becomes 993 and PASSES", entry=_up(port=993.7)),
    _c("err-port-float-sub-one", "0.5 truncates to 0", entry=_up(port=0.5)),
    # ── ca_file / ca_pem / tls_servername types ──
    _c("err-ca-file-list", "a YAML list where a path belongs",
       entry=_up(ca_file=["/certs/ca.pem"])),
    _c("err-ca-file-mapping", "a mapping", entry=_up(ca_file={"path": "/c.pem"})),
    _c("err-ca-file-int", "a number", entry=_up(ca_file=1)),
    _c("err-ca-pem-list", "a list of lines instead of one blob",
       entry=_up(ca_pem=["cert"])),
    _c("err-ca-pem-mapping", "a mapping", entry=_up(ca_pem={"pem": _PEM})),
    _c("err-servername-list", "a list", entry=_up(tls_servername=["a", "b"])),
    _c("err-servername-int", "a number", entry=_up(tls_servername=443)),
    # ── ca_pem content ──
    _c("err-ca-pem-is-a-path", "the commonest mistake: pointing ca_pem at "
       "a file. The error names ca_file rather than failing at connect time",
       entry=_up(ca_pem="/certs/bridge.pem")),
    _c("err-ca-pem-private-key", "a PEM block of the wrong kind",
       entry=_up(ca_pem="-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")),
    _c("err-ca-pem-base64-only", "the body without the armour",
       entry=_up(ca_pem="MIIBfooMIIBfoo")),
    _c("err-ca-pem-marker-lowercase", "the marker match is case-sensitive",
       entry=_up(ca_pem="-----begin certificate-----\nMIIB\n")),
    # ── ca_file and ca_pem both set ──
    _c("err-ca-both", "ambiguous about which wins",
       entry=_up(ca_file="/certs/ca.pem", ca_pem=_PEM)),
    _c("err-ca-both-pem-invalid", "the PEM check runs BEFORE the "
       "both-set check, so a bad PEM wins the race",
       entry=_up(ca_file="/certs/ca.pem", ca_pem="/certs/other.pem")),
    # ── TLS-only fields with tls: false ──
    _c("err-plaintext-ca-file", "a CA next to tls: false reads as "
       "'verified' in review but verifies nothing",
       entry=_up(tls=False, ca_file="/certs/ca.pem")),
    _c("err-plaintext-ca-pem", "same for the inline form",
       entry=_up(tls=False, ca_pem=_PEM)),
    _c("err-plaintext-servername", "same for the SNI override",
       entry=_up(tls=False, tls_servername="bridge.internal")),
    _c("err-plaintext-all-three", "all three set; the iteration order of "
       "the check decides which is named first",
       entry=_up(tls=False, ca_file="/c.pem", ca_pem=_PEM,
                 tls_servername="bridge.internal")),
    _c("err-plaintext-tls-null", "tls: null is falsy, so bool() makes it "
       "a plaintext upstream — NOT the default-true path",
       entry=_up(tls=None, ca_pem=_PEM)),
    _c("err-plaintext-tls-zero", "tls: 0 is falsy too",
       entry=_up(tls=0, ca_pem=_PEM)),
    _c("ok-tls-truthy-string", "tls: 'false' is a non-empty STRING, which "
       "is truthy — a YAML-quoting footgun that silently keeps TLS ON",
       entry=_up(tls="false", ca_pem=_PEM)),
    # ── policy.write_mode ──
    _c("err-write-mode-unknown", "a plausible-but-wrong mode",
       entry=_pol(write_mode="readonly")),
    _c("err-write-mode-empty", "an empty string", entry=_pol(write_mode="")),
    _c("err-write-mode-bool", "a boolean", entry=_pol(write_mode=True)),
    _c("err-write-mode-int", "a number", entry=_pol(write_mode=0)),
    _c("err-write-mode-list", "a list", entry=_pol(write_mode=["none"])),
    # ── policy.readonly vs write_mode ──
    _c("err-readonly-contradicts-none", "readonly: false with write_mode: "
       "none — guessing which the operator meant is exactly the wrong call "
       "for a policy that gates writes",
       entry=_pol(write_mode="none", readonly=False)),
    _c("err-readonly-contradicts-full", "readonly: true with write_mode: full",
       entry=_pol(write_mode="full", readonly=True)),
    _c("err-readonly-contradicts-organise", "readonly: true implies 'none', "
       "which is not 'organise'",
       entry=_pol(write_mode="organise", readonly=True)),
    _c("err-readonly-contradicts-organise-false", "readonly: false implies "
       "'full', which is not 'organise'",
       entry=_pol(write_mode="organise", readonly=False)),
    _c("ok-readonly-null-implies-full", "readonly: null is falsy, so it "
       "implies 'full' and agrees with write_mode: full",
       entry=_pol(write_mode="full", readonly=None)),
    _c("err-readonly-null-vs-none", "readonly: null implies 'full', which "
       "contradicts write_mode: none", entry=_pol(write_mode="none", readonly=None)),
    _c("ok-readonly-truthy-string", "readonly: 'no' is a non-empty string, "
       "hence truthy, hence implies 'none' — another YAML-quoting footgun",
       entry=_pol(write_mode="none", readonly="no")),
    # ── policy folder lists ──
    _c("err-folder-allowlist-string", "a bare string instead of a list — "
       "the commonest YAML slip", entry=_pol(folder_allowlist="INBOX")),
    _c("err-folder-allowlist-mapping", "a mapping",
       entry=_pol(folder_allowlist={"INBOX": True})),
    _c("err-folder-denylist-string", "same for the denylist",
       entry=_pol(folder_denylist="Trash")),
    _c("err-folder-denylist-int", "a number", entry=_pol(folder_denylist=1)),
    _c("err-folder-allowlist-checked-first", "both wrong: allowlist is "
       "checked first", entry=_pol(folder_allowlist="INBOX",
                                   folder_denylist="Trash")),
    # ── auth shape ──
    _c("err-auth-list", "auth as a list", entry=_entry(auth=["user:bob"])),
    _c("err-auth-string", "auth as a bare string", entry=_entry(auth="bob:hunter2")),
    _c("err-auth-int", "auth as a number", entry=_entry(auth=1)),
    # ── ordering between checks ──
    _c("order-type-before-upstream", "an unknown type is reported before "
       "a bad upstream", entry=_entry(type="xmpp", upstream={"port": 0})),
    _c("order-required-before-type", "missing listen is reported before an "
       "unknown type", entry={"name": "mail", "type": "xmpp"}),
    _c("order-upstream-before-ca", "a bad port is reported before a bad PEM",
       entry=_up(port=0, ca_pem="/certs/x.pem")),
    _c("order-ca-pem-type-before-content", "a non-string ca_pem is "
       "reported before the PEM-content check", entry=_up(ca_pem=[_PEM])),
    _c("order-write-mode-before-folders", "an invalid write_mode is "
       "reported before a malformed folder list",
       entry=_pol(write_mode="bogus", folder_allowlist="INBOX")),
    _c("order-policy-before-auth", "a policy error is reported before an "
       "auth error", entry={**_pol(write_mode="bogus"), "auth": "bob"}),
]


def _gen_validate_relay_entry() -> dict:
    cases = []
    for spec in _RELAY_INPUTS:
        entry = spec["entry"]
        calls: list = []
        try:
            validate_relay_entry(entry, source_validator=calls.append)
            ok, error = True, None
        except ValueError as exc:
            ok, error = False, str(exc)
        # The no-hook form must agree on accept/reject and on the message;
        # the hook only ADDS the auth-source arm. Assert that here so the
        # fixture can carry one answer for both call shapes.
        try:
            validate_relay_entry(entry)
            ok2, error2 = True, None
        except ValueError as exc:
            ok2, error2 = False, str(exc)
        assert (ok, error) == (ok2, error2), spec["id"]
        cases.append({**spec, "ok": ok, "error": error,
                      "source_validator_calls": calls})
    return {
        "contract": "validate_relay_entry",
        "summary": (
            "Structural validation of one protocol_relays entry. The only "
            "contract of the four that is currently ONE module imported "
            "from both sides — the host as "
            "agentcage.data.proxy.relays._validate, the proxy as "
            "relays._validate. After the port it becomes two "
            "implementations, and the error strings are user-visible: "
            "`agentcage cage create` surfaces them verbatim."
        ),
        "implementations": {
            "host": ("agentcage.data.proxy.relays._validate.validate_relay_entry, "
                     "called from agentcage.config with "
                     "source_validator=secret_resolver.validate_source"),
            "proxy": ("relays._validate.validate_relay_entry, called from "
                      "addon.py with no source_validator"),
        },
        "fields": {
            "entry": "the protocol_relays entry, exactly as parsed from YAML",
            "ok": "true when the entry validates",
            "error": "when ok is false, the ValueError message VERBATIM",
            "source_validator_calls": (
                "the arguments the optional source_validator hook receives, "
                "in order. The host passes "
                "secret_resolver.validate_source here; the proxy passes "
                "None. A hook that never raises must not change ok/error, "
                "which the generator asserts."
            ),
        },
        "notes": [
            "Error messages interpolate Python type names "
            "(type(x).__name__) and Python reprs. The JSON-to-Python "
            "mapping a Rust port must reproduce: null -> NoneType, "
            "true/false -> bool, integer -> int, fractional number -> "
            "float, string -> str, array -> list, object -> dict.",
            "Python repr of a string uses single quotes ('imap'); repr of "
            "a number, boolean or null is bare (123, True, None).",
            "Check ORDER is part of the contract: an entry with two "
            "problems must report the SAME one on both sides, or an "
            "operator fixing errors one at a time gets different "
            "guidance depending on which implementation ran.",
        ],
        "cases": cases,
    }


# ── Contract 5: shared constants ────────────────────────────────────
#
# Not predicates — single values that exist twice because the addon cannot
# import ``agentcage``. Each is a number or a set that must be identical on
# both sides, and today nothing but a test keeps them equal. Three were
# already flagged in the source comments; ``max_capture_file_bytes`` came
# out of PR A6's audit of the boundary.


def _gen_shared_constants() -> dict:
    cases = [
        _c("max_capture_file_bytes",
           "the default cap on capture.jsonl. The host documents and "
           "validates against its constant; the proxy's CaptureWriter "
           "falls back to a literal of its own when max_file_size is "
           "unset. An operator who never sets the key must still get a "
           "bound, and the same one.",
           value=MAX_CAPTURE_FILE_BYTES,
           host="agentcage.config.MAX_CAPTURE_FILE_BYTES",
           proxy="capture.CaptureWriter default for cfg['max_file_size']"),
        _c("auto_never_grant",
           "the built-in never-grant floor. Duplicated because the addon "
           "cannot import agentcage; if the host's copy gains an entry the "
           "addon lacks, the reconcile refuses to promote a domain the "
           "addon will happily grant at runtime.",
           value=sorted({h.lower().rstrip(".") for h in _AUTO_NEVER_GRANT}),
           host="agentcage.config._AUTO_NEVER_GRANT",
           proxy=("the literal in PolicyApi._effective_never_grant, minus "
                  "the control host it adds")),
        _c("builtin_inspector_names",
           "the built-in inspector names. config.py mirrors the addon's "
           "_BUILTIN_INSPECTORS so the apple-container validator can flag "
           "a typo at parse time instead of letting it silently no-op at "
           "runtime — which means a name present on one side and not the "
           "other is a config that validates and then does nothing.",
           value=sorted(_BUILTIN_INSPECTOR_NAMES),
           host="agentcage.config._BUILTIN_INSPECTOR_NAMES",
           proxy="addon._BUILTIN_INSPECTORS keys"),
        _c("known_relay_types",
           "the protocol_relays types. Lives in the shared _validate "
           "module today, so it is one value; after the port it is two.",
           value=sorted(KNOWN_RELAY_TYPES),
           host="relays._validate.KNOWN_RELAY_TYPES (via agentcage.config)",
           proxy="relays._validate.KNOWN_RELAY_TYPES (bare import)"),
        _c("relay_write_modes",
           "the IMAP write-policy modes, same situation. These strings "
           "appear in the validator's error message, so the set and its "
           "SORTED order are both user-visible.",
           value=sorted(_WRITE_MODES),
           host="relays._validate._WRITE_MODES (via agentcage.config)",
           proxy="relays._validate._WRITE_MODES (bare import)"),
    ]
    return {
        "contract": "shared_constants",
        "summary": (
            "Values duplicated across the trust boundary because the addon "
            "cannot import the CLI package. Not behaviour — just numbers "
            "and sets that must be identical on both sides."
        ),
        "implementations": {
            "host": "src/agentcage/config.py (and the shared relays module)",
            "proxy": ("src/agentcage/data/proxy/{addon,capture}.py (and the "
                      "shared relays module)"),
        },
        "fields": {
            "value": "the value both sides must produce",
            "host": "where the host side gets it",
            "proxy": "where the proxy side gets it",
        },
        "cases": cases,
    }


# ── Contract 6: scaffold -> addon inspector handshake ───────────────
#
# The host renders cage.yaml; the egress addon reads it back and decides
# which inspectors to load. That makes the rendered config a FORMAT
# contract, and the only end-to-end assertion of it imports both sides at
# once. Split in two here so neither side needs the other: the host owns
# "what gets rendered", the proxy owns "what that config loads".

_INSPECTOR_CONFIG_KEYS = (
    "domains", "secrets", "max_request_body", "entropy", "content_type",
    "inspectors",
)

_SCAFFOLDS = [
    (None, "the blank default scaffold — no inspectors: block at all, so "
           "everything loaded comes from the legacy-key mapping"),
    ("arch", "a distro scaffold"),
    ("busybox", "the minimal scaffold: an EMPTY domains.allow, which must "
                "still load the domain inspector"),
    ("claude-code", "an agent scaffold"),
    ("codex", "an agent scaffold"),
    ("debian", "a distro scaffold"),
    ("openclaw", "the scaffold PR A6's conformance test used: loads "
                 "content-type, domain and secrets, and must NOT load "
                 "entropy (scaffolds no longer opt into it)"),
    ("pi", "an agent scaffold"),
    ("ubuntu", "a distro scaffold"),
]


def _gen_scaffold_inspectors() -> dict:
    import types as _types
    from unittest.mock import MagicMock

    import yaml

    # Stub mitmproxy exactly as tests/conftest.py does, so the addon
    # imports on a host without the proxy container's dependencies.
    _mp = _types.ModuleType("mitmproxy")
    _mp.__path__ = []
    _mp.ctx = MagicMock()
    _mp.http = MagicMock()
    _pr = _types.ModuleType("mitmproxy.proxy")
    _pr.__path__ = []
    _ms = _types.ModuleType("mitmproxy.proxy.mode_specs")
    _ms.ReverseMode = MagicMock()
    _mp.proxy = _pr
    _pr.mode_specs = _ms
    for key, mod in (("mitmproxy", _mp), ("mitmproxy.ctx", _mp.ctx),
                     ("mitmproxy.http", _mp.http), ("mitmproxy.proxy", _pr),
                     ("mitmproxy.proxy.mode_specs", _ms)):
        sys.modules.setdefault(key, mod)
    sys.path.insert(0, str(_ROOT / "src" / "agentcage" / "data" / "proxy"))

    from addon import Agentcage  # noqa: E402

    from agentcage.init import render_config  # noqa: E402

    cases = []
    for scaffold, why in _SCAFFOLDS:
        rendered = yaml.safe_load(
            render_config("contract-fixture", scaffold=scaffold)) or {}
        cfg = {k: rendered[k] for k in _INSPECTOR_CONFIG_KEYS if k in rendered}
        api = Agentcage.__new__(Agentcage)
        api.cfg = cfg
        api.inspectors = []
        api.log_allowed = False
        api._load_builtin_inspectors()
        api._load_custom_inspectors()
        cases.append(_c(
            scaffold or "default", why,
            scaffold=scaffold,
            inspector_config=cfg,
            loaded_inspectors=[i.name for i in api.inspectors],
        ))
    return {
        "contract": "scaffold_inspectors",
        "summary": (
            "The host renders cage.yaml; the egress addon reads it back and "
            "decides which inspectors to load. Split into the two halves "
            "that meet at the file: what the host renders, and what that "
            "config loads."
        ),
        "implementations": {
            "host": ("agentcage.init.render_config -> the inspector-relevant "
                     "keys of the rendered cage.yaml"),
            "proxy": ("addon.Agentcage._load_builtin_inspectors + "
                      "_load_custom_inspectors over that config"),
        },
        "fields": {
            "scaffold": "the scaffold name, or null for the blank default",
            "inspector_config": (
                "the slice of the rendered cage.yaml that drives inspector "
                "loading: " + ", ".join(_INSPECTOR_CONFIG_KEYS) + ". The "
                "HOST side is asserted against this."
            ),
            "loaded_inspectors": (
                "the inspector names, IN ORDER, that the addon loads from "
                "that config. The PROXY side is asserted against this."
            ),
        },
        "notes": [
            "Neither side needs the other: the host proves it renders the "
            "recorded config, the proxy proves that config loads the "
            "recorded inspectors. After the port the Rust suite takes the "
            "first half and pytest keeps the second.",
            "Order matters: inspectors run as a chain, so a reordering is "
            "a behaviour change even when the set is identical.",
        ],
        "cases": cases,
    }


_GENERATORS = {
    "valid_domain": _gen_valid_domain,
    "encoded_private_ip": _gen_encoded_private_ip,
    "is_never_grant": _gen_is_never_grant,
    "validate_relay_entry": _gen_validate_relay_entry,
    "shared_constants": _gen_shared_constants,
    "scaffold_inspectors": _gen_scaffold_inspectors,
}


def _render(doc: dict) -> str:
    # ensure_ascii so the file is byte-stable and reviewable in any
    # terminal: several cases carry zero-width and non-breaking
    # characters that are invisible (or worse, misleading) when raw.
    return json.dumps(doc, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if any fixture is out of date")
    args = ap.parse_args()

    _OUT.mkdir(parents=True, exist_ok=True)
    stale = []
    for name, gen in sorted(_GENERATORS.items()):
        doc = gen()
        text = _render(doc)
        path = _OUT / f"{name}.json"
        if args.check:
            current = path.read_text() if path.exists() else ""
            if current != text:
                stale.append(path)
            print(f"{'STALE' if current != text else 'ok   '} {path.name} "
                  f"({len(doc['cases'])} cases)")
        else:
            path.write_text(text)
            print(f"wrote {path.relative_to(_ROOT)} ({len(doc['cases'])} cases)")

    if stale:
        print("\nOut of date. Regenerate with:\n"
              "    uv run python scripts/gen-contract-fixtures.py\n"
              "and review the diff — a changed expectation is a changed "
              "security contract.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
