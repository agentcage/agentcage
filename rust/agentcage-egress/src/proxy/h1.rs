//! The HTTP/1 codec.
//!
//! Heads are parsed with `httparse` into [`Headers`], which keep every
//! header's name spelling, position and duplicates; they are written back
//! byte for byte (plan D10). Bodies are read whole (Content-Length,
//! chunked, or until close) and re-framed on the way out: a chunked
//! message goes out as one chunk, a `Content-Length` is corrected to the
//! body actually sent (the pipeline may have injected a secret into it),
//! and a message that needs a length and has none gets `content-length`.
//!
//! Framing headers are validated the way the replaced implementation
//! validated them against request smuggling: both `Transfer-Encoding` and
//! `Content-Length`, several of either, an unknown transfer coding, a
//! request whose coding does not end in `chunked`, or a malformed length
//! are refused.

use std::io;

use bytes::BytesMut;

use super::detect::find;
use super::io::Buffered;
use crate::message::{Headers, Request, Response};

/// The largest request or response head accepted.
pub(crate) const MAX_HEAD: usize = 256 * 1024;
const MAX_HEADERS: usize = 512;

/// Why a head or body could not be read.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// The peer closed the stream before sending anything.
    Eof,
    /// A socket error.
    Io(io::Error),
    /// The bytes are not valid HTTP/1.
    Malformed(String),
    /// The head exceeds [`MAX_HEAD`].
    HeadTooLarge,
    /// The body exceeds the cap.
    BodyTooLarge,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => f.write_str("connection closed"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Malformed(why) => f.write_str(why),
            Self::HeadTooLarge => f.write_str("header section too large"),
            Self::BodyTooLarge => f.write_str("body too large"),
        }
    }
}

/// A parsed request line and headers.
#[derive(Debug)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) version: String,
    pub(crate) headers: Headers,
}

/// A parsed status line and headers.
#[derive(Debug)]
pub(crate) struct ResponseHead {
    pub(crate) version: String,
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Headers,
}

/// How a message body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    /// Exactly this many bytes (0 = no body).
    Length(u64),
    /// Chunked transfer coding.
    Chunked,
    /// Everything until the peer closes.
    UntilEof,
}

/// The index just past the blank line that ends a head (`\n\n` or
/// `\n\r\n`), if the buffer holds one.
fn head_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(pos) = buf[i..].iter().position(|&b| b == b'\n') {
        let at = i + pos + 1;
        match &buf[at..] {
            [b'\n', ..] => return Some(at + 1),
            [b'\r', b'\n', ..] => return Some(at + 2),
            _ => i = at,
        }
    }
    None
}

/// Read one head off `conn` (leading blank lines skipped).
pub(crate) async fn read_head(conn: &mut Buffered) -> Result<BytesMut, ReadError> {
    loop {
        while conn.buf.starts_with(b"\r\n") || conn.buf.starts_with(b"\n") {
            let skip = if conn.buf[0] == b'\r' { 2 } else { 1 };
            let _ = conn.buf.split_to(skip);
        }
        if let Some(end) = head_end(&conn.buf) {
            return Ok(conn.buf.split_to(end));
        }
        if conn.buf.len() > MAX_HEAD {
            return Err(ReadError::HeadTooLarge);
        }
        let n = conn.fill().await.map_err(ReadError::Io)?;
        if n == 0 {
            if conn.buf.is_empty() {
                return Err(ReadError::Eof);
            }
            return Err(ReadError::Malformed(
                "connection closed before the header section was complete".into(),
            ));
        }
    }
}

fn version(minor: Option<u8>) -> String {
    match minor {
        Some(0) => "HTTP/1.0".into(),
        _ => "HTTP/1.1".into(),
    }
}

fn collect_headers(parsed: &[httparse::Header<'_>]) -> Headers {
    Headers(
        parsed
            .iter()
            .map(|h| (h.name.as_bytes().to_vec(), h.value.to_vec()))
            .collect(),
    )
}

pub(crate) fn parse_request_head(head: &[u8]) -> Result<RequestHead, String> {
    let mut storage = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut storage);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err("incomplete request head".into()),
        Err(e) => return Err(format!("Bad HTTP request: {e}")),
    }
    Ok(RequestHead {
        method: req.method.unwrap_or_default().to_string(),
        target: req.path.unwrap_or_default().to_string(),
        version: version(req.version),
        headers: collect_headers(req.headers),
    })
}

pub(crate) fn parse_response_head(head: &[u8]) -> Result<ResponseHead, String> {
    let mut storage = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut storage);
    let mut config = httparse::ParserConfig::default();
    config.allow_obsolete_multiline_headers_in_responses(true);
    config.allow_spaces_after_header_name_in_responses(true);
    match config.parse_response(&mut resp, head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err("incomplete response head".into()),
        Err(e) => return Err(format!("Cannot parse HTTP response: {e}")),
    }
    Ok(ResponseHead {
        version: version(resp.version),
        status: resp.code.unwrap_or_default(),
        reason: resp.reason.unwrap_or_default().to_string(),
        headers: collect_headers(resp.headers),
    })
}

/// The transfer codings the replaced implementation accepted, normalised.
fn parse_transfer_encoding(value: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(value)
        .ok()
        .filter(|t| t.is_ascii())
        .ok_or_else(|| format!("invalid transfer-encoding header: {value:?}"))?;
    let normalised: String = text
        .to_ascii_lowercase()
        .split(',')
        .map(|part| part.trim_matches([' ', '\t']))
        .collect::<Vec<_>>()
        .join(",");
    match normalised.as_str() {
        "chunked" | "compress,chunked" | "deflate,chunked" | "gzip,chunked" | "compress"
        | "deflate" | "gzip" | "identity" => Ok(normalised),
        _ => Err(format!(
            "unknown transfer-encoding header: {:?}",
            String::from_utf8_lossy(value)
        )),
    }
}

fn parse_content_length(value: &[u8]) -> Result<u64, String> {
    let valid = !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && (value == b"0" || value[0] != b'0');
    if !valid {
        return Err(format!(
            "invalid content-length header: {:?}",
            String::from_utf8_lossy(value)
        ));
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "invalid content-length header".to_string())
}

/// The smuggling checks on a message's framing headers.
///
/// `status` is `None` for a request.
pub(crate) fn validate_framing(
    headers: &Headers,
    version: &str,
    status: Option<u16>,
) -> Result<(), String> {
    let te: Vec<&[u8]> = values(headers, "transfer-encoding");
    let cl: Vec<&[u8]> = values(headers, "content-length");
    if !te.is_empty() && !cl.is_empty() {
        return Err("message with both transfer-encoding and content-length headers".into());
    }
    if !te.is_empty() {
        if te.len() > 1 {
            return Err("multiple transfer-encoding headers".into());
        }
        let shown = String::from_utf8_lossy(te[0]);
        if version != "HTTP/1.1" {
            return Err(format!(
                "unexpected HTTP transfer-encoding {shown:?} for {version}"
            ));
        }
        if let Some(code) = status {
            if (100..=199).contains(&code) || code == 204 {
                return Err(format!(
                    "unexpected HTTP transfer-encoding {shown:?} for response with status code {code}"
                ));
            }
        }
        let parsed = parse_transfer_encoding(te[0])?;
        if status.is_none() && !parsed.ends_with("chunked") {
            return Err(format!(
                "unexpected HTTP transfer-encoding {parsed:?} for request"
            ));
        }
    } else if !cl.is_empty() {
        if cl.len() > 1 {
            return Err("multiple content-length headers".into());
        }
        parse_content_length(cl[0])?;
    }
    Ok(())
}

fn values<'a>(headers: &'a Headers, name: &str) -> Vec<&'a [u8]> {
    headers
        .0
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| v.as_slice())
        .collect()
}

fn is_chunked(headers: &Headers) -> bool {
    values(headers, "transfer-encoding")
        .first()
        .is_some_and(|v| {
            String::from_utf8_lossy(v)
                .to_ascii_lowercase()
                .contains("chunked")
        })
}

pub(crate) fn request_framing(headers: &Headers) -> Result<Framing, String> {
    if let Some(te) = values(headers, "transfer-encoding").first() {
        let parsed = parse_transfer_encoding(te)?;
        if parsed.ends_with("chunked") {
            return Ok(Framing::Chunked);
        }
    }
    match values(headers, "content-length").first() {
        Some(cl) => Ok(Framing::Length(parse_content_length(cl)?)),
        None => Ok(Framing::Length(0)),
    }
}

/// Whether a response to `method` with `status` can carry a body at all.
pub(crate) fn response_has_body(method: &str, status: u16) -> bool {
    !(method.eq_ignore_ascii_case("HEAD")
        || (100..=199).contains(&status)
        || status == 204
        || status == 304
        || ((200..=299).contains(&status) && method.eq_ignore_ascii_case("CONNECT")))
}

pub(crate) fn response_framing(
    method: &str,
    status: u16,
    headers: &Headers,
) -> Result<Framing, String> {
    if !response_has_body(method, status) {
        return Ok(Framing::Length(0));
    }
    if let Some(te) = values(headers, "transfer-encoding").first() {
        let parsed = parse_transfer_encoding(te)?;
        return Ok(if parsed.ends_with("chunked") {
            Framing::Chunked
        } else {
            Framing::UntilEof
        });
    }
    match values(headers, "content-length").first() {
        Some(cl) => Ok(Framing::Length(parse_content_length(cl)?)),
        None => Ok(Framing::UntilEof),
    }
}

/// Read a body framed by `framing`, refusing more than `max` bytes.
pub(crate) async fn read_body(
    conn: &mut Buffered,
    framing: Framing,
    max: usize,
) -> Result<Vec<u8>, ReadError> {
    match framing {
        Framing::Length(n) => {
            let n = usize::try_from(n).map_err(|_| ReadError::BodyTooLarge)?;
            if n > max {
                return Err(ReadError::BodyTooLarge);
            }
            while conn.buf.len() < n {
                if conn.fill().await.map_err(ReadError::Io)? == 0 {
                    return Err(ReadError::Malformed(
                        "connection closed before the body was complete".into(),
                    ));
                }
            }
            Ok(conn.buf.split_to(n).to_vec())
        }
        Framing::UntilEof => {
            loop {
                if conn.buf.len() > max {
                    return Err(ReadError::BodyTooLarge);
                }
                if conn.fill().await.map_err(ReadError::Io)? == 0 {
                    break;
                }
            }
            Ok(conn.buf.split().to_vec())
        }
        Framing::Chunked => read_chunked(conn, max).await,
    }
}

async fn read_line(conn: &mut Buffered) -> Result<BytesMut, ReadError> {
    loop {
        if let Some(pos) = find(&conn.buf, b"\n") {
            let mut line = conn.buf.split_to(pos + 1);
            line.truncate(pos);
            if line.ends_with(b"\r") {
                line.truncate(pos - 1);
            }
            return Ok(line);
        }
        if conn.buf.len() > MAX_HEAD {
            return Err(ReadError::Malformed("chunk line too long".into()));
        }
        if conn.fill().await.map_err(ReadError::Io)? == 0 {
            return Err(ReadError::Malformed(
                "connection closed inside a chunked body".into(),
            ));
        }
    }
}

async fn read_chunked(conn: &mut Buffered, max: usize) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    loop {
        let line = read_line(conn).await?;
        let size_text = line[..].split(|&b| b == b';').next().unwrap_or_default();
        let size_text = std::str::from_utf8(size_text)
            .map_err(|_| ReadError::Malformed("invalid chunk size".into()))?
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| ReadError::Malformed(format!("invalid chunk size: {size_text:?}")))?;
        if size == 0 {
            // Trailers are read and dropped.
            loop {
                if read_line(conn).await?.is_empty() {
                    return Ok(body);
                }
            }
        }
        if body.len().saturating_add(size) > max {
            return Err(ReadError::BodyTooLarge);
        }
        while conn.buf.len() < size + 2 {
            if conn.fill().await.map_err(ReadError::Io)? == 0 {
                return Err(ReadError::Malformed(
                    "connection closed inside a chunked body".into(),
                ));
            }
        }
        body.extend_from_slice(&conn.buf.split_to(size));
        let crlf = conn.buf.split_to(2);
        if &crlf[..] != b"\r\n" {
            return Err(ReadError::Malformed("missing CRLF after chunk".into()));
        }
    }
}

/// Whether the message asks for the connection to close after it.
pub(crate) fn connection_close(version: &str, headers: &Headers) -> bool {
    let tokens: Vec<String> = headers
        .get_all("connection")
        .iter()
        .flat_map(|v| {
            v.split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    if tokens.iter().any(|t| t == "close") {
        return true;
    }
    if tokens.iter().any(|t| t == "keep-alive") {
        return false;
    }
    !matches!(version, "HTTP/1.1" | "HTTP/2.0")
}

/// Fix the framing headers for a body of `len` bytes; returns whether the
/// body goes out chunked.
fn fix_framing(headers: &mut Headers, len: usize, needs_length: bool) -> bool {
    if is_chunked(headers) {
        return true;
    }
    if headers.contains("content-length") {
        headers.set("content-length", len.to_string());
    } else if needs_length {
        headers.add("content-length", len.to_string());
    }
    false
}

fn put_headers(out: &mut Vec<u8>, headers: &Headers) {
    for (name, value) in &headers.0 {
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

fn put_body(out: &mut Vec<u8>, body: &[u8], chunked: bool) {
    if chunked {
        if !body.is_empty() {
            out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        out.extend_from_slice(body);
    }
}

/// The wire bytes of `req`, origin-form, as an HTTP/1 request.
pub(crate) fn encode_request(req: &Request) -> Vec<u8> {
    let mut headers = req.headers.clone();
    let version = if req.http_version.starts_with("HTTP/1") {
        req.http_version.as_str()
    } else {
        // An HTTP/2 request going to an HTTP/1 server: one Cookie header
        // (HTTP/1 does not allow several), and the authority as Host (the
        // HTTP/2 codec already stored it as one).
        let cookies = headers.get_all("cookie");
        if cookies.len() > 1 {
            headers.set("cookie", cookies.join("; "));
        }
        "HTTP/1.1"
    };
    let chunked = fix_framing(&mut headers, req.body.len(), !req.body.is_empty());
    let path = if req.path.is_empty() { "/" } else { &req.path };
    let mut out = format!("{} {} {}\r\n", req.method, path, version).into_bytes();
    put_headers(&mut out, &headers);
    put_body(&mut out, &req.body, chunked);
    out
}

/// The wire bytes of `resp`, as an HTTP/1 response to a `method` request.
pub(crate) fn encode_response(resp: &Response, method: &str) -> Vec<u8> {
    let mut headers = resp.headers.clone();
    let (version, reason) = if resp.http_version.starts_with("HTTP/1") {
        (resp.http_version.as_str(), resp.reason.clone())
    } else {
        ("HTTP/1.1", super::reason_phrase(resp.status).to_string())
    };
    let has_body = response_has_body(method, resp.status);
    let chunked = has_body && fix_framing(&mut headers, resp.body.len(), true);
    let mut out = format!("{version} {} {reason}\r\n", resp.status).into_bytes();
    put_headers(&mut out, &headers);
    if has_body {
        put_body(&mut out, &resp.body, chunked);
    }
    out
}

/// The head of a `101 Switching Protocols` (or any body-less response),
/// written as-is.
pub(crate) fn encode_head_only(resp: &Response) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason).into_bytes();
    put_headers(&mut out, &resp.headers);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::io::Buffered;

    fn conn(data: &[u8]) -> Buffered {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let data = data.to_vec();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            server.write_all(&data).await.unwrap();
            server.shutdown().await.unwrap();
            // Keep the other half alive until the reader is done.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        Buffered::new(Box::new(client))
    }

    #[tokio::test]
    async fn heads_keep_case_order_and_duplicates() {
        let mut c = conn(b"\r\nPOST /p?q=1 HTTP/1.1\r\nHost: a\r\nX-B: 1\r\nx-b: 2\r\nContent-Length: 3\r\n\r\nabcGET");
        let head = read_head(&mut c).await.unwrap();
        let req = parse_request_head(&head).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/p?q=1");
        assert_eq!(
            req.headers.to_strings(),
            [
                ("Host", "a"),
                ("X-B", "1"),
                ("x-b", "2"),
                ("Content-Length", "3")
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        let framing = request_framing(&req.headers).unwrap();
        assert_eq!(read_body(&mut c, framing, 10).await.unwrap(), b"abc");
        assert_eq!(&c.buf[..], b"GET");
    }

    #[tokio::test]
    async fn chunked_bodies_are_joined_and_capped() {
        let mut c = conn(b"4;x=y\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: t\r\n\r\nrest");
        assert_eq!(
            read_body(&mut c, Framing::Chunked, 100).await.unwrap(),
            b"Wikipedia"
        );
        assert_eq!(&c.buf[..], b"rest");
        let mut c = conn(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
        assert!(matches!(
            read_body(&mut c, Framing::Chunked, 8).await,
            Err(ReadError::BodyTooLarge)
        ));
        let mut c = conn(b"");
        assert!(matches!(
            read_body(&mut c, Framing::Length(9), 8).await,
            Err(ReadError::BodyTooLarge)
        ));
    }

    #[test]
    fn smuggling_shapes_are_refused() {
        let h = |pairs: &[(&str, &str)]| {
            let mut headers = Headers::new();
            for (k, v) in pairs {
                headers.add(*k, *v);
            }
            headers
        };
        let ok = h(&[("Transfer-Encoding", "gzip , chunked")]);
        assert!(validate_framing(&ok, "HTTP/1.1", None).is_ok());
        for bad in [
            h(&[("Transfer-Encoding", "chunked"), ("Content-Length", "3")]),
            h(&[("Content-Length", "3"), ("content-length", "3")]),
            h(&[("Content-Length", "03")]),
            h(&[("Content-Length", "+3")]),
            h(&[("Transfer-Encoding", "gzip")]),
            h(&[("Transfer-Encoding", "chunked, gzip")]),
            h(&[
                ("Transfer-Encoding", "chunked"),
                ("Transfer-Encoding", "chunked"),
            ]),
        ] {
            assert!(validate_framing(&bad, "HTTP/1.1", None).is_err(), "{bad:?}");
        }
        assert!(
            validate_framing(&h(&[("Transfer-Encoding", "chunked")]), "HTTP/1.0", None).is_err()
        );
        assert!(
            validate_framing(&h(&[("Transfer-Encoding", "gzip")]), "HTTP/1.1", Some(200)).is_ok()
        );
        assert!(
            validate_framing(
                &h(&[("Transfer-Encoding", "chunked")]),
                "HTTP/1.1",
                Some(204)
            )
            .is_err()
        );
    }

    #[test]
    fn encoding_fixes_lengths_and_keeps_header_bytes() {
        let mut req = Request {
            method: "POST".into(),
            path: "/x".into(),
            http_version: "HTTP/1.1".into(),
            body: b"injected-secret".to_vec(),
            ..Request::default()
        };
        req.headers.add("HoSt", "a.test");
        req.headers.add("Content-Length", "11");
        req.headers.add("X-A", "1");
        let wire = encode_request(&req);
        assert_eq!(
            wire,
            b"POST /x HTTP/1.1\r\nHoSt: a.test\r\nContent-Length: 15\r\nX-A: 1\r\n\r\ninjected-secret"
        );
        req.headers.set("Content-Length", "0");
        req.headers.remove("content-length");
        req.headers.add("Transfer-Encoding", "chunked");
        assert!(encode_request(&req).ends_with(b"\r\n\r\nf\r\ninjected-secret\r\n0\r\n\r\n"));

        let resp = Response {
            status: 200,
            reason: String::new(),
            http_version: "HTTP/2.0".into(),
            headers: Headers::new(),
            body: b"hi".to_vec(),
        };
        assert_eq!(
            encode_response(&resp, "GET"),
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi"
        );
        assert_eq!(encode_response(&resp, "HEAD"), b"HTTP/1.1 200 OK\r\n\r\n");
    }

    #[test]
    fn keep_alive_follows_version_and_connection_tokens() {
        let mut h = Headers::new();
        assert!(!connection_close("HTTP/1.1", &h));
        assert!(connection_close("HTTP/1.0", &h));
        h.add("Connection", "Upgrade, close");
        assert!(connection_close("HTTP/1.1", &h));
        let mut k = Headers::new();
        k.add("connection", "keep-alive");
        assert!(!connection_close("HTTP/1.0", &k));
    }
}
