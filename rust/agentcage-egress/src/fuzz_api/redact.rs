//! Streaming redaction against buffered redaction.
//!
//! A streamed response is redacted by [`StreamRedactor`], a buffered one
//! by [`Injector::redact_response`]; the streaming module's claim is that
//! the two are byte-for-byte the same for every body and every way it is
//! cut into chunks, with the same rule names reported. A difference is a
//! secret that leaks on one path and not the other, so this target builds
//! bodies that are dense in the spellings redaction looks for (literal,
//! percent- and JSON-escaped, base64 at every alignment, cut-off
//! prefixes), for one to three secrets picked from real-shaped values or
//! made up by the fuzzer, and cuts them at fuzzer-chosen offsets.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::rc::Rc;

use bytes::Bytes;

use crate::inject::{Injector, Rule, StreamRedactError, StreamRedactor};
use crate::message::{Headers, Response};

use super::Input;

/// Secrets shaped like the ones a cage is given.
const VALUES: [&str; 12] = [
    "sk-live-0123456789abcdef",
    "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "xoxb-1234-5678-AbCdEfGhIjKl",
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
    "p@ss w/rd \"q\" \u{e9}\u{1f511}",
    "abc+def/ghi==",
    "tok_9f8e7d6c5b4a",
    "ffffffffffff",
    "%%%%%%%%%",
    "short",
];

/// Bytes that sit around secrets in real responses, and the partial
/// escapes and base64 runs that make the scanners work.
const FILLERS: [&[u8]; 12] = [
    b"data: {\"delta\": \"",
    b"\"}\n\n",
    b" ",
    b"\r\n",
    b"AAAABBBBccccdddd0123",
    b"%2",
    b"%25",
    b"\\u00",
    b"\\",
    b"==",
    b"+/-_",
    b"\xff\x00\x10\xc3",
];

fn percent(value: &str, upper: bool) -> String {
    value.bytes().fold(String::new(), |mut out, b| {
        if upper {
            let _ = write!(out, "%{b:02X}");
        } else {
            let _ = write!(out, "%{b:02x}");
        }
        out
    })
}

fn b64(data: &[u8], url: bool, pad: bool) -> Vec<u8> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let engine = match (url, pad) {
        (false, true) => &STANDARD,
        (false, false) => &STANDARD_NO_PAD,
        (true, true) => &URL_SAFE,
        (true, false) => &URL_SAFE_NO_PAD,
    };
    engine.encode(data).into_bytes()
}

/// The `k`th way a server can spell `value` back.
fn spelling(value: &str, k: u8) -> Vec<u8> {
    match k % 12 {
        0 => value.as_bytes().to_vec(),
        1 => percent(value, true).into_bytes(),
        2 => percent(value, false).into_bytes(),
        3 => value
            .encode_utf16()
            .fold(String::new(), |mut out, u| {
                let _ = write!(out, "\\u{u:04x}");
                out
            })
            .into_bytes(),
        4 => value
            .chars()
            .map(|c| match c {
                ' ' => "+".to_owned(),
                '/' => "\\/".to_owned(),
                '"' => "\\\"".to_owned(),
                '\u{e9}' => "\\u00e9".to_owned(),
                c if !c.is_ascii_alphanumeric() && c.is_ascii() => {
                    format!("%{:02X}", u32::from(c))
                }
                c => c.to_string(),
            })
            .collect::<String>()
            .into_bytes(),
        // Base64 at the three alignments, in both alphabets, padded and
        // not: inside a Basic credential, a JWT segment, a blob.
        n => {
            let n = n - 5;
            let prefix: &[u8] = [&b""[..], b"u:", b"ab", b"xyz:"][usize::from(n % 4)];
            let raw = [prefix, value.as_bytes(), b"!tail"].concat();
            b64(&raw, n >= 4, n % 2 == 0)
        }
    }
}

/// A body built from fuzzer-chosen pieces.
fn body(input: &mut Input<'_>, values: &[String]) -> Vec<u8> {
    let mut body = Vec::new();
    while !input.is_empty() && body.len() < 64 * 1024 {
        match input.below(7) {
            0 | 1 => {
                let value = &values[input.below(values.len())];
                body.extend(spelling(value, input.byte()));
            }
            2 => {
                // A spelling cut short: a prefix that never completes.
                let value = &values[input.below(values.len())];
                let full = spelling(value, input.byte());
                let keep = input.below(full.len().max(1));
                body.extend_from_slice(&full[..keep]);
            }
            3 => body.extend_from_slice(FILLERS[input.below(FILLERS.len())]),
            4 => {
                let n = input.below(24);
                body.extend_from_slice(input.take(n));
            }
            5 => {
                let n = input.below(48);
                body.extend((0..n).map(|_| b"ab0+/-_="[input.below(8)]));
            }
            _ => body.push(input.byte()),
        }
    }
    body
}

/// A rule set as the cache keys it: each value with its placeholder variant.
type Secrets = Vec<(String, u8)>;

/// An injector for `secrets`, reused across inputs: building one compiles
/// every secret's patterns, which would otherwise be most of the fuzzer's
/// time.
fn injector(secrets: Secrets) -> Rc<Injector> {
    thread_local! {
        static CACHE: RefCell<HashMap<Secrets, Rc<Injector>>> = RefCell::default();
    }
    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() > 4096 {
            cache.clear();
        }
        let built = cache.entry(secrets).or_insert_with_key(|secrets| {
            let rules = secrets
                .iter()
                .enumerate()
                .map(|(i, (value, variant))| {
                    let name = format!("SECRET_{i}");
                    let placeholder = format!(
                        "agentcage:secret:{name}:{:04x}",
                        0x1f3 * u32::from(*variant)
                    );
                    Rule::new(&name, &placeholder, value, &[])
                })
                .collect();
            Rc::new(Injector::with_rules(rules, &[]))
        });
        Rc::clone(built)
    })
}

/// Buffered redaction of an identity-encoded response.
fn buffered(inj: &Injector, headers: &Headers, body: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut resp = Response {
        status: 200,
        headers: headers.clone(),
        body: body.to_vec(),
        ..Response::default()
    };
    let names = inj.redact_response(&mut resp).expect("an identity body");
    (resp.body, names)
}

/// Streamed redaction, headers first as the streaming head is; `None`
/// when the redactor aborts the exchange.
fn streamed(
    mut red: StreamRedactor,
    headers: &Headers,
    body: &[u8],
    cuts: &[usize],
) -> Option<(Vec<u8>, Vec<String>)> {
    let mut headers = headers.clone();
    let header_found = Injector::redact_headers_with(&mut headers, red.forms());
    let body = Bytes::copy_from_slice(body);
    let mut out = Vec::new();
    let mut at = 0;
    for &cut in cuts.iter().chain(std::iter::once(&body.len())) {
        match red.push(body.slice(at..cut), &mut out) {
            Ok(()) => {}
            Err(StreamRedactError::UnboundedRun) => return None,
        }
        at = cut;
    }
    red.finish(&mut out);
    Some((out.concat(), red.names(&header_found)))
}

/// Streaming redaction equals buffered redaction.
pub fn redact_stream(data: &[u8]) {
    let mut input = Input::new(data);
    let count = 1 + input.below(3);
    let mut values: Vec<String> = Vec::new();
    for _ in 0..count {
        let pick = input.below(VALUES.len() + 2);
        let value = if pick < VALUES.len() {
            VALUES[pick].to_owned()
        } else {
            // A value the fuzzer makes up: any bytes, any length.
            let n = 1 + input.below(40);
            String::from_utf8_lossy(input.take(n)).into_owned()
        };
        if !value.is_empty() {
            values.push(value);
        }
    }
    if values.is_empty() {
        return;
    }
    let secrets: Vec<(String, u8)> = values
        .iter()
        .map(|v| (v.clone(), input.byte() % 4))
        .collect();
    let inj = injector(secrets);
    let mut headers = Headers::new();
    if input.byte().is_multiple_of(4) {
        let value = &values[input.below(values.len())];
        headers.add("X-Echo", spelling(value, input.byte()));
    }
    let max_hold = match input.byte() {
        0..=31 => Some(32 + usize::from(input.byte())),
        _ => None,
    };
    let ncuts = input.below(8);
    let cut_bytes: Vec<u16> = (0..ncuts)
        .map(|_| u16::from_le_bytes([input.byte(), input.byte()]))
        .collect();
    let body = body(&mut input, &values);

    let mut cuts: Vec<usize> = cut_bytes
        .iter()
        .map(|&c| usize::from(c) % (body.len() + 1))
        .collect();
    cuts.sort_unstable();

    let want = buffered(&inj, &headers, &body);
    let mut red = inj.stream_redactor().expect("rules configured");
    if let Some(max_hold) = max_hold {
        red = red.with_max_hold(max_hold);
    }
    let Some(got) = streamed(red, &headers, &body, &cuts) else {
        return;
    };
    assert!(
        got.0 == want.0,
        "streamed body differs for cuts {cuts:?}\n  values {values:?}\n  body     {:?}\n  buffered {:?}\n  streamed {:?}",
        String::from_utf8_lossy(&body),
        String::from_utf8_lossy(&want.0),
        String::from_utf8_lossy(&got.0),
    );
    assert_eq!(got.1, want.1, "names differ for cuts {cuts:?}");
}
