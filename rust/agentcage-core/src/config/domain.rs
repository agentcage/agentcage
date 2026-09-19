//! `valid_domain` and `encoded_private_ip` — the two domain predicates
//! that exist on *both* sides of agentcage's trust boundary.
//!
//! Host: `config.valid_domain` / `config.DOMAIN_RE` and
//! `config.encoded_private_ip`. Proxy: `policy_api.PolicyApi._valid_domain`
//! / `_DOMAIN_RE` and `policy_api._encoded_private_ip`. The addon cannot
//! import the CLI package — the egress image ships without it — so the
//! two copies are duplicated deliberately, and RUST-PORT-PLAN.md §2.2
//! lists both as cross-language contracts.
//!
//! # The oracle is the fixture, not either implementation
//!
//! Until now the copies were held equal by a pytest that imported both.
//! Rust cannot import a Python module and pytest cannot import this, so
//! PR A4 recorded the answers as language-neutral JSON:
//! `tests/fixtures/contracts/valid_domain.json` (96 cases) and
//! `encoded_private_ip.json` (77). `tests/contract_domain.rs` reads those
//! files off disk — it does not restate the cases — so this module and
//! `config.py` cannot drift apart without one of them failing.
//!
//! # Why `is_global` is spelled out here
//!
//! [`encoded_private_ip`] is the structural half of the SSRF guard.
//! Wildcard-DNS services (nip.io, sslip.io, traefik.me and clones) encode
//! an address in the hostname and resolve to it, so
//! `169-254-169-254.nip.io` is a syntactically valid *public* name
//! carrying none of the never-grant suffixes that reaches the cloud
//! metadata endpoint. Matching the *encoding* rather than keeping a
//! service denylist covers every present and future clone, because the
//! encoding is the trick itself.
//!
//! Python asks `ipaddress.IPv4Address.is_global`. That is **not** the same
//! predicate as any crate's `is_private()`, and the difference is not
//! academic: carrier-grade NAT, `100.64.0.0/10`, has `is_global == False`
//! and `is_private == False`, so a port that reached for `is_private()`
//! would wave CGNAT straight through the guard. So the IANA
//! special-purpose ranges are written out in `PRIVATE_NETWORKS` and
//! `is_global` is derived from them exactly as CPython derives it. The
//! `cgnat-*` and `test-net-*` cases in the fixture exist to make the
//! substitution fail loudly.

/// Whether a bare single label counts as a domain.
///
/// `config.valid_domain(d, allow_single_label=...)`. The distinction is
/// a security boundary rather than a convenience:
///
/// - [`LabelPolicy::StrictDotted`] is the shape *both* sides implement,
///   and the only one the proxy has. Every **runtime grant** path takes
///   it — the addon's request endpoint, the grants reconcile, `grants
///   promote` — because a grant crosses the cage trust boundary and
///   "syntactically valid PUBLIC hostname" is part of that threat model.
///   A single-label name is exactly what an internal service looks like.
/// - [`LabelPolicy::AllowSingleLabel`] additionally accepts a bare
///   LAN/mDNS/tailnet hostname (`nas`, `fcos-vm-home-01`). Only
///   **operator-owned** lists take it: the static `domains.allow` /
///   `block` / `passthrough` / `expires` entries and `domain add`. Those
///   strings come from the same person who could edit `cage.yaml`
///   anyway, and single-label hosts worked there in every release before
///   0.34.0's strict-dotted validator broke real configs.
///
/// The fixture carries both columns (`expected` and
/// `expected_allow_single_label`) so the port cannot quietly collapse
/// them into one mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelPolicy {
    /// At least two labels — what the proxy implements, and what every
    /// runtime-grant path uses.
    StrictDotted,
    /// Also accept one bare label, on operator-owned paths only.
    AllowSingleLabel,
}

/// True if `domain` is a syntactically valid lowercase DNS domain.
///
/// Rejects anything that is not a plain dotted hostname — in particular
/// strings containing newlines, slashes, or other characters that would
/// inject additional directives when interpolated into dnsmasq config.
/// That is the whole job: `domains.allow` / `block` flow verbatim into
/// `state.save_dns_allowlist`'s `server=/<domain>/` lines, and
/// `domains.passthrough` is `re.escape`d into a mitmproxy
/// `--ignore-hosts` regex *and* merged into the DNS allowlist. A value
/// containing `\n` would emit extra `server=` lines — per-cage dnsmasq
/// config corruption that fails `dnsmasq --test`.
///
/// Three checks beyond the shape, each mirroring `config.py`:
///
/// 1. **No whitespace anywhere.** Defence in depth — the label charset
///    already excludes it mid-string — but explicit, so a future tweak
///    to the shape rules cannot silently re-open the injection. Python
///    anchors its regex on `\Z` rather than `$` for the same reason:
///    `$` matches immediately before one trailing newline, so
///    `"evil.com\n"` would otherwise pass.
/// 2. **No IP literals.** The label charset is all-digits-friendly, so
///    `1.2.3.4` matches the dotted-label shape. An IP literal in
///    `domains.allow` is nonsensical — dnsmasq `server=/` keys are DNS
///    names — and would be a confusing no-op.
/// 3. **Last label >= 2 characters.** The shape permits a one-character
///    last label, so `x.c` would otherwise pass. A single-letter TLD is
///    not a real public suffix and makes an overly broad grant.
#[must_use]
pub fn valid_domain(domain: &str, policy: LabelPolicy) -> bool {
    // `if not isinstance(domain, str) or any(c.isspace() for c in domain)`.
    // The isinstance half is the type system's job here.
    if domain.chars().any(is_python_space) {
        return false;
    }

    if !matches_domain_shape(domain) {
        // A single label never matches the dotted shape (its suffix
        // group is `+`). Accept it only on operator-owned paths, and
        // only when it is a well-formed label by the same charset and
        // length rules — the injection properties are identical.
        if policy != LabelPolicy::AllowSingleLabel || !is_label(domain) {
            return false;
        }
    }

    // Reject IP literals. IPv6 literals cannot reach here (`:` is not in
    // either shape's charset), which is why only the v4 form is
    // implemented; `ipaddress.ip_address` covers both in Python and the
    // v6 half is unreachable.
    if is_ipv4_literal(domain) {
        return false;
    }

    // `len(domain.split(".")[-1]) >= 2`.
    domain
        .rsplit('.')
        .next()
        .is_some_and(|last| last.chars().count() >= 2)
}

/// The embedded address when `domain` encodes a non-global IP, else
/// `None`.
///
/// `None` when it embeds no IP, or embeds a globally routable one —
/// naming a public host the long way round is no more dangerous than
/// naming it directly. Only the leftmost labels are inspected: that is
/// where these services put the address, so a legitimate name that
/// merely starts with digits (`10-years.example.com`) is not misread.
#[must_use]
pub fn encoded_private_ip(domain: &str) -> Option<String> {
    // `_IP_LABEL_RE.match(domain.lower().rstrip("."))`.
    let lowered = domain.to_lowercase();
    let candidate = lowered.trim_end_matches('.');
    let octets = leading_ip_labels(candidate)?;

    // Not how these services encode; avoid octal ambiguity.
    if octets
        .iter()
        .any(|octet| octet.len() > 1 && octet.starts_with('0'))
    {
        return None;
    }

    // `ipaddress.ip_address(".".join(octets))`, whose only remaining
    // failure mode after the leading-zero guard is an octet above 255.
    let mut address: u32 = 0;
    for octet in octets {
        let value: u8 = octet.parse().ok()?;
        address = (address << 8) | u32::from(value);
    }

    if is_global(address) {
        None
    } else {
        Some(format!(
            "{}.{}.{}.{}",
            address >> 24,
            (address >> 16) & 0xff,
            (address >> 8) & 0xff,
            address & 0xff
        ))
    }
}

// ── the shape rules ─────────────────────────────────────

/// `DOMAIN_RE.match(domain)`, which is
/// `^(?=.{1,253}$)(<label>)(\.<label>)+\Z`.
///
/// The lookahead reduces to a length check. `.` does not match a newline
/// and `$` allows one trailing newline, but [`valid_domain`] has already
/// refused every string containing whitespace by the time this runs, so
/// what is left is "between 1 and 253 characters".
fn matches_domain_shape(domain: &str) -> bool {
    let length = domain.chars().count();
    if length == 0 || length > 253 {
        return false;
    }
    // The first group is mandatory; the `(\.<label>)+` suffix needs at
    // least one more.
    let mut labels = domain.split('.');
    let Some(first) = labels.next() else {
        return false;
    };
    if !is_label(first) {
        return false;
    }
    let mut suffix_labels = 0;
    for label in labels {
        if !is_label(label) {
            return false;
        }
        suffix_labels += 1;
    }
    suffix_labels >= 1
}

/// One label: `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`.
///
/// Also `SINGLE_LABEL_RE` in full — the two are the same expression,
/// which is why `valid_domain`'s single-label branch reuses it.
///
/// Byte-wise rather than char-wise: every accepted byte is ASCII, so a
/// multi-byte character fails the charset test before its length can
/// matter.
fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let permitted = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    match bytes {
        [only] => permitted(*only),
        [first, middle @ .., last] if middle.len() <= 61 => {
            permitted(*first)
                && permitted(*last)
                && middle.iter().all(|byte| permitted(*byte) || *byte == b'-')
        }
        // The empty label, and anything longer than 63 bytes.
        _ => false,
    }
}

/// `str.isspace()`, which is wider than Rust's `char::is_whitespace`.
///
/// CPython counts a character as space when its Unicode category is
/// `Zs`/`Zl`/`Zp` *or* its bidirectional class is `WS`, `B` or `S`. The
/// concrete set is short enough to write down, and writing it down is
/// the point: `char::is_whitespace` follows the `White_Space` property,
/// which omits the C0 separators `U+001C`–`U+001F`. Those are exactly
/// the kind of character a domain-injection attempt would carry.
pub(super) fn is_python_space(character: char) -> bool {
    matches!(
        character as u32,
        0x09..=0x0d
            | 0x1c..=0x20
            | 0x85
            | 0xa0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
    )
}

/// `ipaddress.ip_address(text)` succeeding for an IPv4 dotted quad.
///
/// CPython's `_parse_octet` in full: non-empty, at most three digits,
/// ASCII digits only, no leading zero on a multi-digit octet, value at
/// most 255.
fn is_ipv4_literal(text: &str) -> bool {
    let mut octets = 0;
    for part in text.split('.') {
        if parse_octet(part).is_none() {
            return false;
        }
        octets += 1;
    }
    octets == 4
}

/// One octet of a dotted quad, by CPython's rules.
fn parse_octet(part: &str) -> Option<u8> {
    if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    part.parse().ok()
}

/// `_IP_LABEL_RE.match`, which is
/// `^(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?:$|[-.])`.
///
/// No backtracking is needed despite `\d{1,3}` being greedy: the
/// character after each group must be `-` or `.`, and neither is a
/// digit, so the run of digits at each position is taken whole or the
/// match fails. A run of four or more digits therefore cannot match at
/// all — which is what keeps `2130706433.nip.io` out.
///
/// `\d` in Python matches every Unicode decimal digit, not just ASCII.
/// This matches ASCII only, and the answer is the same either way:
/// Python's `_parse_octet` refuses a non-ASCII octet
/// (`not octet_str.isascii()`), so `١٦٩-٢٥٤-١٦٩-٢٥٤.nip.io` returns
/// `None` there by raising and `None` here by not matching. The fixture
/// pins that case.
fn leading_ip_labels(text: &str) -> Option<[&str; 4]> {
    let bytes = text.as_bytes();
    let mut octets: [&str; 4] = [""; 4];
    let mut position = 0;

    for (index, slot) in octets.iter_mut().enumerate() {
        let start = position;
        while position < bytes.len() && bytes[position].is_ascii_digit() {
            position += 1;
        }
        let digits = position - start;
        if digits == 0 || digits > 3 {
            return None;
        }
        *slot = &text[start..position];

        if index < 3 {
            // The mandatory `[-.]` between groups. The regex accepts
            // either separator per position independently, so mixed
            // spellings (`169.254-169.254.nip.io`) are caught too.
            if !matches!(bytes.get(position), Some(b'-' | b'.')) {
                return None;
            }
            position += 1;
        }
    }

    // `(?:$|[-.])` — end of string, or a separator. Anything else means
    // the leading digits were part of a longer label
    // (`10-0-0-1234.nip.io`).
    if position < bytes.len() && !matches!(bytes[position], b'-' | b'.') {
        return None;
    }
    Some(octets)
}

// ── CPython's `IPv4Address.is_global` ───────────────────

/// `_constants._private_networks`, as `(network, prefix length)`.
///
/// The IANA IPv4 Special-Purpose Address Registry, spelled out rather
/// than delegated — see the module docs for why. Order is CPython's.
const PRIVATE_NETWORKS: [(u32, u32); 14] = [
    (u32::from_be_bytes([0, 0, 0, 0]), 8),       // "this network"
    (u32::from_be_bytes([10, 0, 0, 0]), 8),      // RFC 1918
    (u32::from_be_bytes([127, 0, 0, 0]), 8),     // loopback
    (u32::from_be_bytes([169, 254, 0, 0]), 16),  // link-local
    (u32::from_be_bytes([172, 16, 0, 0]), 12),   // RFC 1918
    (u32::from_be_bytes([192, 0, 0, 0]), 24),    // IETF protocol
    (u32::from_be_bytes([192, 0, 0, 170]), 31),  // NAT64/DNS64 discovery
    (u32::from_be_bytes([192, 0, 2, 0]), 24),    // TEST-NET-1
    (u32::from_be_bytes([192, 168, 0, 0]), 16),  // RFC 1918
    (u32::from_be_bytes([198, 18, 0, 0]), 15),   // benchmarking
    (u32::from_be_bytes([198, 51, 100, 0]), 24), // TEST-NET-2
    (u32::from_be_bytes([203, 0, 113, 0]), 24),  // TEST-NET-3
    (u32::from_be_bytes([240, 0, 0, 0]), 4),     // reserved
    (u32::from_be_bytes([255, 255, 255, 255]), 32), // broadcast
];

/// `_constants._private_networks_exceptions` — the two addresses inside
/// `192.0.0.0/24` that gh-113171 carved back out as globally reachable.
const PRIVATE_EXCEPTIONS: [(u32, u32); 2] = [
    (u32::from_be_bytes([192, 0, 0, 9]), 32),  // PCP anycast
    (u32::from_be_bytes([192, 0, 0, 10]), 32), // NAT64/DNS64 anycast
];

/// `_constants._public_network` — carrier-grade NAT.
///
/// The one range that makes `is_global` and `is_private` different
/// predicates: this is `is_global == False` **and** `is_private ==
/// False`. The whole reason this module does not call a crate's
/// `is_private()`.
const CARRIER_GRADE_NAT: (u32, u32) = (u32::from_be_bytes([100, 64, 0, 0]), 10);

/// `address in IPv4Network(network/prefix)`.
fn in_network(address: u32, (network, prefix): (u32, u32)) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    address & mask == network
}

/// `IPv4Address.is_private`.
fn is_private(address: u32) -> bool {
    PRIVATE_NETWORKS
        .iter()
        .any(|network| in_network(address, *network))
        && !PRIVATE_EXCEPTIONS
            .iter()
            .any(|network| in_network(address, *network))
}

/// `IPv4Address.is_global`.
///
/// CPython's definition verbatim: not carrier-grade NAT, and not
/// private. Every case in `encoded_private_ip.json` was recorded on
/// CPython 3.12.0, 3.12.3, 3.12.4, 3.13.0 and 3.14.7 and answered
/// identically on all five, so this is a fixed target rather than a
/// moving one.
fn is_global(address: u32) -> bool {
    !in_network(address, CARRIER_GRADE_NAT) && !is_private(address)
}

#[cfg(test)]
mod tests {
    use super::{LabelPolicy, encoded_private_ip, is_global, is_private, valid_domain};

    /// The contract fixtures are the real test (`tests/contract_domain.rs`).
    /// These are the two or three properties worth stating in prose.
    #[test]
    fn the_single_label_modes_are_not_the_same_mode() {
        assert!(!valid_domain("nas", LabelPolicy::StrictDotted));
        assert!(valid_domain("nas", LabelPolicy::AllowSingleLabel));
        // Neither mode accepts a one-character last label.
        assert!(!valid_domain("a", LabelPolicy::AllowSingleLabel));
        assert!(!valid_domain("x.c", LabelPolicy::AllowSingleLabel));
    }

    #[test]
    fn a_newline_never_reaches_dnsmasq() {
        assert!(!valid_domain("evil.com\n", LabelPolicy::AllowSingleLabel));
        assert!(!valid_domain(
            "evil.com\nserver=/x/1.2.3.4",
            LabelPolicy::StrictDotted
        ));
        // U+001F is whitespace to Python and not to Rust's
        // `char::is_whitespace`. It has to be refused anyway.
        assert!(!valid_domain("evil.com\u{1f}", LabelPolicy::StrictDotted));
    }

    /// The finding this module is written around: reaching for a crate's
    /// `is_private()` would let carrier-grade NAT through.
    #[test]
    fn carrier_grade_nat_is_not_private_but_is_not_global_either() {
        let cgnat = u32::from_be_bytes([100, 64, 0, 1]);
        assert!(!is_private(cgnat), "CGNAT is not in the private registry");
        assert!(
            !is_global(cgnat),
            "...and it is still not globally routable"
        );
        assert_eq!(
            encoded_private_ip("100-64-0-1.example.com").as_deref(),
            Some("100.64.0.1")
        );
    }

    #[test]
    fn only_the_leftmost_labels_are_inspected() {
        assert_eq!(encoded_private_ip("10-years.example.com"), None);
        assert_eq!(encoded_private_ip("cdn.10-0-0-1.example.com"), None);
    }
}
