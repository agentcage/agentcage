//! Fuzz harnesses for the HTTP/1 codec and protocol detection (reached
//! through [`crate::fuzz_api`]; they live here because the codec is
//! private to the proxy module).
//!
//! The HTTP/1 properties, for any bytes a peer sends:
//!
//! * nothing panics, and nothing allocates more than the body cap;
//! * the buffered body reader ([`h1::read_body`], used for every request
//!   and for responses the pipeline needs whole) and the incremental one
//!   ([`h1::BodyReader`], used for streamed responses) agree on the body
//!   and on where the next message starts — two framings of one byte
//!   stream would be a desync between the proxy's own two paths;
//! * a message the proxy accepted, re-encoded the way it is forwarded,
//!   passes the proxy's own smuggling checks and parses back to the same
//!   head and body: what the egress emits frames unambiguously.

use super::budget::{BodyBudget, Reservation};
use super::detect::{self, Plain};
use super::h1::{self, Framing, ReadError};
use super::io::Buffered;
use crate::fuzz_api::{Input, PieceStream, block_on};
use crate::message::{Headers, Request, Response};

/// The body cap the harness reads under (the proxy's is configurable;
/// a small one keeps every allocation small).
const MAX_BODY: usize = 1 << 20;

/// What reading one message produced.
#[derive(Debug, PartialEq, Eq)]
enum Read {
    /// The body and every byte after it.
    Body(Vec<u8>, Vec<u8>),
    /// A malformed or truncated body.
    Malformed,
    /// Over the cap (only the buffered reader has one).
    TooLarge,
}

fn connection(wire: &[u8], sizes: &[usize]) -> Buffered {
    Buffered::new(Box::new(PieceStream::new(wire.to_vec(), sizes.to_vec())))
}

/// Every byte left on `conn`.
async fn remainder(conn: &mut Buffered) -> Vec<u8> {
    while conn.fill().await.expect("in-memory read") > 0 {}
    conn.buf.to_vec()
}

/// Read a body framed by `framing` off `conn`, whole or piece by piece.
async fn read_body(conn: &mut Buffered, framing: Framing, streaming: bool) -> Read {
    let result = if streaming {
        let mut reader = h1::BodyReader::new(framing);
        let mut body = Vec::new();
        loop {
            match reader.next(conn).await {
                Ok(Some(piece)) => body.extend_from_slice(&piece),
                Ok(None) => break Ok(body),
                Err(e) => break Err(e),
            }
        }
    } else {
        let budget = BodyBudget::new(usize::MAX);
        let mut reservation = Reservation::new(&budget);
        h1::read_body(conn, framing, MAX_BODY, &mut reservation).await
    };
    match result {
        Ok(body) => Read::Body(body, remainder(conn).await),
        Err(ReadError::Malformed(_)) => Read::Malformed,
        Err(ReadError::BodyTooLarge | ReadError::BudgetExhausted) => Read::TooLarge,
        Err(e @ (ReadError::Eof | ReadError::Io(_) | ReadError::HeadTooLarge)) => {
            panic!("unexpected body error: {e}")
        }
    }
}

/// Check that the buffered and the incremental reader agree on the body
/// of the message whose head `parse` accepts at the start of `wire`, and
/// return the head, framing and what the buffered reader read (`None`
/// when the proxy refuses the head).
fn read_message<H>(
    wire: &[u8],
    sizes: &[usize],
    parse: impl Fn(&[u8]) -> Result<(H, Framing), String>,
) -> Option<(H, Framing, Read)> {
    let read = |streaming: bool| {
        block_on(async {
            let mut conn = connection(wire, sizes);
            let head = h1::read_head(&mut conn).await.ok()?;
            let (head, framing) = parse(&head).ok()?;
            let body = read_body(&mut conn, framing, streaming).await;
            Some((head, framing, body))
        })
    };
    let (head, framing, whole) = read(false)?;
    let (_, _, streamed) = read(true).expect("the head parsed once");
    match &whole {
        Read::Body(..) | Read::Malformed => assert_eq!(
            streamed, whole,
            "the streaming reader disagrees with the buffered one ({framing:?})"
        ),
        // The incremental reader has no cap: whatever it makes of it.
        Read::TooLarge => {}
    }
    Some((head, framing, whole))
}

fn without(headers: &Headers, name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    headers
        .0
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case(name.as_bytes()))
        .cloned()
        .collect()
}

/// A request as the client connection accepts one (head, smuggling
/// checks, framing).
fn parse_request(head: &[u8]) -> Result<(h1::RequestHead, Framing), String> {
    let parsed = h1::parse_request_head(head)?;
    h1::validate_framing(&parsed.headers, &parsed.version, None)?;
    let framing = h1::request_framing(&parsed.headers)?;
    Ok((parsed, framing))
}

pub(crate) fn h1_request(data: &[u8]) {
    let mut input = Input::new(data);
    let sizes = input.piece_sizes();
    let wire = input.rest();
    let Some((head, _, Read::Body(body, _))) = read_message(wire, &sizes, parse_request) else {
        return;
    };
    // Forwarded upstream as `write_request` encodes it.
    let req = Request {
        method: head.method.clone(),
        path: head.target.clone(),
        http_version: head.version.clone(),
        headers: head.headers.clone(),
        body: body.clone(),
        ..Request::default()
    };
    let encoded = h1::encode_request(&req);
    let Some((again, _, read)) = read_message(&encoded, &sizes, parse_request) else {
        panic!(
            "the re-encoded request is refused: {:?}",
            String::from_utf8_lossy(&encoded)
        );
    };
    assert_eq!(again.method, head.method);
    assert_eq!(again.target, head.target);
    assert_eq!(again.version, head.version);
    assert_eq!(again.headers, head.headers);
    assert_eq!(read, Read::Body(body, Vec::new()));
}

const METHODS: [&str; 5] = ["GET", "HEAD", "CONNECT", "POST", "get"];

pub(crate) fn h1_response(data: &[u8]) {
    let mut input = Input::new(data);
    let method = METHODS[input.below(METHODS.len())];
    let sizes = input.piece_sizes();
    let wire = input.rest();
    // As `send_h1_head` reads one: interim responses skipped.
    let parse = |head: &[u8]| -> Result<(h1::ResponseHead, Framing), String> {
        let parsed = h1::parse_response_head(head)?;
        if (100..=199).contains(&parsed.status) && parsed.status != 101 {
            return Err("interim".into());
        }
        h1::validate_framing(&parsed.headers, &parsed.version, Some(parsed.status))?;
        let framing = h1::response_framing(method, parsed.status, &parsed.headers)?;
        Ok((parsed, framing))
    };
    let Some((head, _, Read::Body(body, _))) = read_message(wire, &sizes, parse) else {
        return;
    };
    // Relayed to the client as `write_response` encodes it.
    let resp = Response {
        status: head.status,
        reason: head.reason.clone(),
        http_version: head.version.clone(),
        headers: head.headers.clone(),
        body: body.clone(),
    };
    let encoded = h1::encode_response(&resp, method);
    let Some((again, _, read)) = read_message(&encoded, &sizes, parse) else {
        panic!(
            "the re-encoded response is refused: {:?}",
            String::from_utf8_lossy(&encoded)
        );
    };
    assert_eq!(again.status, head.status);
    assert_eq!(again.reason, head.reason);
    assert_eq!(again.version, head.version);
    // A length may have been added or corrected; nothing else changes.
    assert_eq!(
        without(&again.headers, "content-length"),
        without(&head.headers, "content-length")
    );
    assert_eq!(read, Read::Body(body, Vec::new()));
}

pub(crate) fn tls_detect(data: &[u8]) {
    let full = detect::parse_client_hello(data);
    if let Ok(Some(hello)) = &full {
        assert!(detect::starts_like_tls(data));
        let _ = detect::choose_alpn(&hello.alpn);
    }
    // The proxy parses whatever it has buffered so far and reads on at
    // `Ok(None)`: a prefix must never decide differently from the whole.
    let step = (data.len() / 16).max(1);
    for end in (0..data.len()).step_by(step) {
        let prefix = &data[..end];
        match detect::parse_client_hello(prefix) {
            Ok(None) => {}
            decided => assert_eq!(decided, full, "the first {end} bytes decide differently"),
        }
        if let Ok(host) = detect::host_header(prefix) {
            assert_eq!(detect::host_header(data), Ok(host));
        }
        let plain = detect::classify_plain(prefix, false);
        if plain != Plain::NeedMore && prefix.contains(&b'\n') {
            assert_eq!(detect::classify_plain(data, false), plain);
        }
    }
    for eof in [false, true] {
        let plain = detect::classify_plain(data, eof);
        assert!(!(eof && plain == Plain::NeedMore));
    }
}
