//! Reducing one capture entry to a digest-safe sample.
//!
//! Secret hygiene lives here. Only the INBOUND view of a body is excerpted
//! (placeholders, as the cage wrote it); the outbound view contributes
//! sizes and statuses alone, because a capture file written by an older
//! egress can hold real secrets there (a server's echo of an injected
//! value, a minted token). Sensitive header values are dropped by name.
//! Secret names may reach the model; values never.

use rand::Rng as _;

use crate::json::{self, Json};

use super::ScanRng;
use super::pyval::{self, obj, py_str, str_or};

/// Longest body excerpt, in code points.
pub const BODY_EXCERPT_CHARS: usize = 512;

/// Header names whose values never ride the digest, whatever the
/// perspective. Name-matched, case-insensitive, no substring surprises.
pub const SENSITIVE_HEADERS: [&str; 11] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-auth",
    "x-amz-security-token",
    "x-session-token",
    "api-key",
    "private-token",
];

/// Keep header names always, values only for non-sensitive names.
///
/// `headers` is the capture's `[[name, value], …]`; items that are not a
/// list of at least two elements are skipped.
#[must_use]
pub fn redact_headers(headers: Option<&Json>) -> Vec<Json> {
    let Some(Json::Array(items)) = headers else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|h| match h {
            Json::Array(pair) if pair.len() >= 2 => {
                let name = py_str(&pair[0]);
                let value = if SENSITIVE_HEADERS.contains(&name.to_lowercase().as_str()) {
                    "[redacted]".to_owned()
                } else {
                    py_str(&pair[1])
                };
                Some(Json::Array(vec![Json::Str(name), Json::Str(value)]))
            }
            _ => None,
        })
        .collect()
}

/// A short textual excerpt of a body; a base64 body becomes a size note.
///
/// Base64 bodies are opaque (and possibly the wire view of a real secret),
/// so they are never excerpted. A long body is not excerpted head-only
/// when an `rng` is given: a fixed "first 512 chars" window is the
/// cheapest evasion there is (pad the front, put the payload after it).
/// With an `rng` the excerpt is head + a random middle slice + tail, so
/// the tail always covers the end and the middle lands somewhere the cage
/// cannot predict. Without one (the corpus mode) it is head-only.
pub fn excerpt_body(
    body: Option<&Json>,
    encoding: Option<&Json>,
    rng: Option<&mut ScanRng>,
) -> String {
    let Some(body) = pyval::truthy(body) else {
        return String::new();
    };
    if encoding.and_then(Json::as_str) == Some("base64") {
        let n = py_str(body).chars().count();
        return format!("[binary body, {n} b64 chars, not excerpted]");
    }
    let text = py_str(body);
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n <= BODY_EXCERPT_CHARS {
        return text;
    }
    let Some(rng) = rng else {
        let head: String = chars[..BODY_EXCERPT_CHARS].iter().collect();
        return format!("{head}…[truncated]");
    };
    let head_n = BODY_EXCERPT_CHARS / 2;
    let tail_n = BODY_EXCERPT_CHARS / 4;
    let mid_n = BODY_EXCERPT_CHARS - head_n - tail_n;
    let (lo, hi) = (head_n, head_n.max(n - tail_n - mid_n));
    let start = if hi > lo {
        rng.random_range(lo..=hi)
    } else {
        lo
    };
    let head: String = chars[..head_n].iter().collect();
    let mid: String = chars[start..(start + mid_n).min(n)].iter().collect();
    let tail: String = chars[n - tail_n..].iter().collect();
    let after = (n - tail_n).saturating_sub(start + mid_n);
    format!(
        "{head}…[{} chars skipped]…{mid}…[{after} chars skipped]…{tail}",
        start - head_n
    )
}

/// The request path and query as the cage wrote them.
///
/// The capture entry's top-level `path` was read after injection by older
/// egresses, so an `inject_body` rule's real value can sit in its query.
/// The inbound snapshot's `url` is placeholder-safe and is the source;
/// without one, the top-level path is used with its query stripped, since
/// the query is where an injected secret rides.
fn safe_path(entry: &Json, in_req: &Json) -> String {
    let url = str_or(in_req.get("url"), "");
    if !url.is_empty()
        && let Some((path, query)) = urlsplit_path_query(&url)
    {
        let q = if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        };
        return pyval::prefix(&format!("{path}{q}"), 256);
    }
    let path = str_or(entry.get("path"), "");
    pyval::prefix(path.split('?').next().unwrap_or(""), 256)
}

/// `urllib.parse.urlsplit(url)`'s path and query, or `None` where it
/// raises `ValueError` (a malformed bracketed host).
fn urlsplit_path_query(url: &str) -> Option<(String, String)> {
    let mut url: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    if let Some(i) = url.find(':')
        && i > 0
        && url.as_bytes()[0].is_ascii_alphabetic()
        && url[..i]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        url.drain(..=i);
    }
    if url.starts_with("//") {
        let rest = &url[2..];
        let delim = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let netloc = &rest[..delim];
        let open = netloc.contains('[');
        let close = netloc.contains(']');
        if open != close {
            return None;
        }
        if open && !bracketed_netloc_ok(netloc) {
            return None;
        }
        url.drain(..2 + delim);
    }
    if let Some(i) = url.find('#') {
        url.truncate(i);
    }
    match url.split_once('?') {
        Some((path, query)) => Some((path.to_owned(), query.to_owned())),
        None => Some((url, String::new())),
    }
}

/// `_check_bracketed_netloc`: the bracketed host must be an IPv6 address
/// (or an `IPvFuture` literal), with nothing before the bracket and only a
/// port after it.
fn bracketed_netloc_ok(netloc: &str) -> bool {
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, hp)| hp);
    let hostname = if let Some((before, bracketed)) = host_port.split_once('[') {
        if !before.is_empty() {
            return false;
        }
        let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
        if !port.is_empty() && !port.starts_with(':') {
            return false;
        }
        host
    } else {
        host_port.split_once(':').map_or(host_port, |(h, _)| h)
    };
    if let Some(rest) = hostname.strip_prefix('v') {
        // `\Av[a-fA-F0-9]+\..+\Z`
        let Some((hex, tail)) = rest.split_once('.') else {
            return false;
        };
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) && !tail.is_empty();
    }
    // `ipaddress.ip_address(host)` must be IPv6 (an IPv4 address in
    // brackets is refused too); a non-empty zone id is allowed.
    let addr = match hostname.split_once('%') {
        Some((addr, zone)) if !zone.is_empty() && !zone.contains('%') => addr,
        Some(_) => return false,
        None => hostname,
    };
    addr.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Reduce one capture entry to a digest-safe sample.
///
/// `host_hint` stands in for a missing `host`. Key order is the replaced
/// implementation's, so the digest serializes identically.
pub fn sample_capture(entry: &Json, host_hint: &str, mut rng: Option<&mut ScanRng>) -> Json {
    let inbound = obj(entry.get("inbound"));
    let in_req = obj(inbound.get("request"));
    let in_resp = obj(inbound.get("response"));
    let out_req = obj(obj(entry.get("outbound")).get("request"));
    let method =
        match pyval::truthy(entry.get("method")).or_else(|| pyval::truthy(in_req.get("method"))) {
            Some(v) => py_str(v),
            None => String::new(),
        };
    let host = match pyval::truthy(entry.get("host")) {
        Some(v) => py_str(v),
        None => host_hint.to_owned(),
    };
    let inspectors: Vec<Json> = match entry.get("inspectors") {
        Some(Json::Array(items)) => items
            .iter()
            .filter(|i| matches!(i, Json::Object(_)))
            .map(|i| {
                json::object([
                    (
                        "name",
                        i.get("name").cloned().unwrap_or_else(|| Json::string("")),
                    ),
                    (
                        "severity",
                        i.get("severity")
                            .cloned()
                            .unwrap_or_else(|| Json::string("")),
                    ),
                    (
                        "reason",
                        Json::Str(pyval::prefix(&pyval::str_get(i, "reason", ""), 200)),
                    ),
                ])
            })
            .collect(),
        _ => Vec::new(),
    };
    let get_or = |o: &Json, k: &str, d: Json| o.get(k).cloned().unwrap_or(d);
    let mut sample = json::object([
        ("ts", get_or(entry, "ts", Json::string(""))),
        ("direction", get_or(entry, "direction", Json::string(""))),
        ("method", Json::Str(method)),
        ("host", Json::Str(host)),
        ("path", Json::Str(safe_path(entry, in_req))),
        ("decision", get_or(entry, "decision", Json::string(""))),
        ("inspectors", Json::Array(inspectors)),
        (
            "request_body_size",
            get_or(in_req, "bodySize", Json::Int(0)),
        ),
        ("response_status", get_or(in_resp, "status", Json::Int(0))),
        (
            "response_body_size",
            get_or(in_resp, "bodySize", Json::Int(0)),
        ),
        (
            "outbound_request_body_size",
            get_or(out_req, "bodySize", Json::Int(0)),
        ),
    ]);
    let body = in_req.get("body");
    let encoding = in_req.get("bodyEncoding");
    let text = excerpt_body(body, encoding, rng.as_deref_mut());
    if !text.is_empty() {
        sample.set("request_body_excerpt", Json::Str(text));
    }
    // Evasion fingerprints, computed where the raw body is visible: a
    // base64 body is invisible to the model by design, and a body longer
    // than the excerpt has content it cannot see. Neither is a verdict.
    if encoding.and_then(Json::as_str) == Some("base64") && body.is_some_and(Json::is_truthy) {
        sample.set("request_body_binary", Json::Bool(true));
    }
    if str_or(body, "").chars().count() > BODY_EXCERPT_CHARS {
        sample.set("request_body_exceeds_excerpt", Json::Bool(true));
    }
    let resp_text = excerpt_body(in_resp.get("body"), in_resp.get("bodyEncoding"), rng);
    if !resp_text.is_empty() {
        sample.set("response_body_excerpt", Json::Str(resp_text));
    }
    let first15 = match in_resp.get("headers") {
        Some(v) if v.is_truthy() => match v {
            Json::Array(items) => Some(Json::Array(items.iter().take(15).cloned().collect())),
            _ => None,
        },
        _ => None,
    };
    let resp_headers = redact_headers(first15.as_ref());
    if !resp_headers.is_empty() {
        sample.set("response_headers_sample", Json::Array(resp_headers));
    }
    sample
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng as _;

    #[test]
    fn the_tail_always_survives_a_random_excerpt() {
        let body = Json::Str(format!("{}PAYLOAD-CANARY", "A".repeat(5000)));
        for seed in 0..50 {
            let mut rng = ScanRng::seed_from_u64(seed);
            let ex = excerpt_body(Some(&body), None, Some(&mut rng));
            assert!(ex.contains("PAYLOAD-CANARY"));
        }
    }

    #[test]
    fn a_middle_payload_is_sometimes_sampled_and_never_by_head_only() {
        let body = Json::Str(format!(
            "{}PAYLOAD-CANARY{}",
            "A".repeat(2000),
            "B".repeat(2000)
        ));
        assert!(!excerpt_body(Some(&body), None, None).contains("PAYLOAD-CANARY"));
        let hits = (0..400)
            .filter(|seed| {
                let mut rng = ScanRng::seed_from_u64(*seed);
                excerpt_body(Some(&body), None, Some(&mut rng)).contains("PAYLOAD-CANARY")
            })
            .count();
        assert!(hits > 0);
        let mut rng = ScanRng::seed_from_u64(1);
        assert!(
            excerpt_body(Some(&body), None, Some(&mut rng))
                .chars()
                .count()
                < 700
        );
        let mut rng = ScanRng::seed_from_u64(3);
        assert_eq!(
            excerpt_body(Some(&Json::string("hello")), None, Some(&mut rng)),
            "hello"
        );
    }
}
