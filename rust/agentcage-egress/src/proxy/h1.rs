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

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::budget::Reservation;
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
    /// Buffering the body would exceed the process-wide body budget.
    BudgetExhausted,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => f.write_str("connection closed"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Malformed(why) => f.write_str(why),
            Self::HeadTooLarge => f.write_str("header section too large"),
            Self::BodyTooLarge => f.write_str("body too large"),
            Self::BudgetExhausted => f.write_str("body budget exhausted"),
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
        if let Some(code) = status
            && ((100..=199).contains(&code) || code == 204)
        {
            return Err(format!(
                "unexpected HTTP transfer-encoding {shown:?} for response with status code {code}"
            ));
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
///
/// Every byte buffered is reserved on `budget` first (refused with
/// [`ReadError::BudgetExhausted`] when the process-wide budget stays
/// full), and every allocation is fallible: an allocation failure is a
/// refused body, never an abort of the whole egress. A body of known
/// length is read into one allocation of exactly that size; one of
/// unknown length grows by a quarter at a time, never by doubling.
pub(crate) async fn read_body(
    conn: &mut Buffered,
    framing: Framing,
    max: usize,
    budget: &mut Reservation,
) -> Result<Vec<u8>, ReadError> {
    match framing {
        Framing::Length(n) => {
            let n = usize::try_from(n).map_err(|_| ReadError::BodyTooLarge)?;
            if n > max {
                return Err(ReadError::BodyTooLarge);
            }
            if !budget.grow_to(n).await {
                return Err(ReadError::BudgetExhausted);
            }
            if conn.buf.len() >= n {
                return Ok(conn.buf.split_to(n).to_vec());
            }
            let mut body: Vec<u8> = Vec::new();
            body.try_reserve_exact(n)
                .map_err(|_| ReadError::BudgetExhausted)?;
            read_exact_into(
                conn,
                &mut body,
                n,
                "connection closed before the body was complete",
            )
            .await?;
            Ok(body)
        }
        Framing::UntilEof => {
            let head = conn.buf.split();
            if head.len() > max {
                return Err(ReadError::BodyTooLarge);
            }
            let mut body: Vec<u8> = Vec::new();
            reserve(budget, &mut body, head.len()).await?;
            body.extend_from_slice(&head);
            drop(head);
            loop {
                reserve(budget, &mut body, READ_STEP).await?;
                let read = (&mut conn.io)
                    .take(READ_STEP as u64)
                    .read_buf(&mut body)
                    .await
                    .map_err(ReadError::Io)?;
                if read == 0 {
                    return Ok(body);
                }
                if body.len() > max {
                    return Err(ReadError::BodyTooLarge);
                }
            }
        }
        Framing::Chunked => read_chunked(conn, max, budget).await,
    }
}

/// How much one read of a body of unknown length asks for.
const READ_STEP: usize = 64 * 1024;

async fn reserve(
    budget: &mut Reservation,
    body: &mut Vec<u8>,
    extra: usize,
) -> Result<(), ReadError> {
    if budget.make_room(body, extra).await {
        Ok(())
    } else {
        Err(ReadError::BudgetExhausted)
    }
}

/// Append exactly `n` more bytes to `body` (which has room for them):
/// whatever is already buffered first, then straight from the socket,
/// so the bytes are never staged in the read buffer and copied again.
async fn read_exact_into(
    conn: &mut Buffered,
    body: &mut Vec<u8>,
    n: usize,
    truncated: &str,
) -> Result<(), ReadError> {
    let from_buf = n.min(conn.buf.len());
    body.extend_from_slice(&conn.buf.split_to(from_buf));
    let end = body.len() + (n - from_buf);
    while body.len() < end {
        let want = (end - body.len()) as u64;
        let read = (&mut conn.io)
            .take(want)
            .read_buf(body)
            .await
            .map_err(ReadError::Io)?;
        if read == 0 {
            return Err(ReadError::Malformed(truncated.into()));
        }
    }
    Ok(())
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

async fn read_chunked(
    conn: &mut Buffered,
    max: usize,
    budget: &mut Reservation,
) -> Result<Vec<u8>, ReadError> {
    const CLOSED: &str = "connection closed inside a chunked body";
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
        reserve(budget, &mut body, size).await?;
        read_exact_into(conn, &mut body, size, CLOSED).await?;
        while conn.buf.len() < 2 {
            if conn.fill().await.map_err(ReadError::Io)? == 0 {
                return Err(ReadError::Malformed(CLOSED.into()));
            }
        }
        let crlf = conn.buf.split_to(2);
        if &crlf[..] != b"\r\n" {
            return Err(ReadError::Malformed("missing CRLF after chunk".into()));
        }
    }
}

/// How much one streaming read asks the socket for.
const STREAM_READ: usize = 64 * 1024;

/// Where an incremental chunked read is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chunk {
    /// Expecting a chunk-size line.
    Size,
    /// Inside a chunk's data, this many bytes left.
    Data(u64),
    /// Expecting the CRLF after a chunk's data.
    DataEnd,
}

/// A body read a piece at a time, as it arrives, for streaming: each
/// piece is a slice of the connection's read buffer handed on without a
/// copy.
#[derive(Debug)]
pub(crate) struct BodyReader {
    framing: Framing,
    /// Bytes left of a `Content-Length` body.
    remaining: u64,
    chunk: Chunk,
    done: bool,
}

impl BodyReader {
    pub(crate) fn new(framing: Framing) -> Self {
        let remaining = match framing {
            Framing::Length(n) => n,
            _ => 0,
        };
        Self {
            framing,
            remaining,
            chunk: Chunk::Size,
            done: matches!(framing, Framing::Length(0)),
        }
    }

    /// Whether the whole body has been read.
    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Read more into `conn`'s buffer; end of stream is an error saying
    /// `truncated` (`None`: a clean end, `Ok(false)`).
    async fn fill(conn: &mut Buffered, truncated: Option<&str>) -> Result<bool, ReadError> {
        if conn.buf.capacity() - conn.buf.len() < 4096 {
            conn.buf.reserve(STREAM_READ);
        }
        let n = conn
            .io
            .read_buf(&mut conn.buf)
            .await
            .map_err(ReadError::Io)?;
        match (n, truncated) {
            (0, Some(why)) => Err(ReadError::Malformed(why.into())),
            (0, None) => Ok(false),
            _ => Ok(true),
        }
    }

    /// The next piece of the body; `None` once it is complete.
    pub(crate) async fn next(&mut self, conn: &mut Buffered) -> Result<Option<Bytes>, ReadError> {
        if self.done {
            return Ok(None);
        }
        match self.framing {
            Framing::Length(_) => {
                if conn.buf.is_empty() {
                    Self::fill(conn, Some("connection closed before the body was complete"))
                        .await?;
                }
                let take = usize::try_from(self.remaining)
                    .unwrap_or(usize::MAX)
                    .min(conn.buf.len());
                self.remaining -= take as u64;
                self.done = self.remaining == 0;
                Ok(Some(conn.buf.split_to(take).freeze()))
            }
            Framing::UntilEof => {
                if conn.buf.is_empty() && !Self::fill(conn, None).await? {
                    self.done = true;
                    return Ok(None);
                }
                Ok(Some(conn.buf.split().freeze()))
            }
            Framing::Chunked => self.next_chunked(conn).await,
        }
    }

    async fn next_chunked(&mut self, conn: &mut Buffered) -> Result<Option<Bytes>, ReadError> {
        const CLOSED: &str = "connection closed inside a chunked body";
        loop {
            match self.chunk {
                Chunk::Size => {
                    let line = read_line(conn).await?;
                    let size_text = line[..].split(|&b| b == b';').next().unwrap_or_default();
                    let size_text = std::str::from_utf8(size_text)
                        .map_err(|_| ReadError::Malformed("invalid chunk size".into()))?
                        .trim();
                    let size = u64::from_str_radix(size_text, 16).map_err(|_| {
                        ReadError::Malformed(format!("invalid chunk size: {size_text:?}"))
                    })?;
                    if size == 0 {
                        // Trailers are read and dropped.
                        while !read_line(conn).await?.is_empty() {}
                        self.done = true;
                        return Ok(None);
                    }
                    self.chunk = Chunk::Data(size);
                }
                Chunk::Data(left) => {
                    if conn.buf.is_empty() {
                        Self::fill(conn, Some(CLOSED)).await?;
                    }
                    let take = usize::try_from(left)
                        .unwrap_or(usize::MAX)
                        .min(conn.buf.len());
                    let left = left - take as u64;
                    self.chunk = if left == 0 {
                        Chunk::DataEnd
                    } else {
                        Chunk::Data(left)
                    };
                    return Ok(Some(conn.buf.split_to(take).freeze()));
                }
                Chunk::DataEnd => {
                    while conn.buf.len() < 2 {
                        Self::fill(conn, Some(CLOSED)).await?;
                    }
                    if &conn.buf.split_to(2)[..] != b"\r\n" {
                        return Err(ReadError::Malformed("missing CRLF after chunk".into()));
                    }
                    self.chunk = Chunk::Size;
                }
            }
        }
    }
}

/// How a streamed body is framed towards an HTTP/1 client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamFraming {
    /// As many bytes as the head's `Content-Length` says, as they come.
    Length,
    /// Chunked transfer coding, one chunk per piece.
    Chunked,
    /// Until the connection closes (an HTTP/1.0 client, which cannot
    /// read chunked).
    Close,
}

/// The head of a streamed response, its framing headers made to match
/// `framing`: a `Content-Length` kept only for [`StreamFraming::Length`],
/// `Transfer-Encoding: chunked` only for [`StreamFraming::Chunked`].
pub(crate) fn encode_stream_head(resp: &Response, framing: StreamFraming) -> Vec<u8> {
    let mut headers = resp.headers.clone();
    let (version, reason) = if resp.http_version.starts_with("HTTP/1") {
        (resp.http_version.as_str(), resp.reason.clone())
    } else {
        ("HTTP/1.1", super::reason_phrase(resp.status).to_string())
    };
    match framing {
        StreamFraming::Length => headers.remove("transfer-encoding"),
        StreamFraming::Chunked => {
            headers.remove("content-length");
            if !is_chunked(&headers) {
                headers.remove("transfer-encoding");
                headers.add("transfer-encoding", "chunked");
            }
        }
        StreamFraming::Close => {
            headers.remove("content-length");
            headers.remove("transfer-encoding");
        }
    }
    let mut out = status_line(version, resp.status, &reason);
    put_headers(&mut out, &headers);
    out
}

/// Write one piece of a streamed body, flushed: a token stream reaches
/// the client as it is produced.
pub(crate) async fn write_piece(
    conn: &mut Buffered,
    piece: &[u8],
    framing: StreamFraming,
) -> io::Result<()> {
    if piece.is_empty() {
        return Ok(());
    }
    if framing != StreamFraming::Chunked {
        conn.io.write_all(piece).await?;
        return conn.io.flush().await;
    }
    let size = format!("{:x}\r\n", piece.len());
    if piece.len() <= 16 * 1024 {
        let mut frame = Vec::with_capacity(size.len() + piece.len() + 2);
        frame.extend_from_slice(size.as_bytes());
        frame.extend_from_slice(piece);
        frame.extend_from_slice(b"\r\n");
        conn.io.write_all(&frame).await?;
    } else {
        conn.io.write_all(size.as_bytes()).await?;
        conn.io.write_all(piece).await?;
        conn.io.write_all(b"\r\n").await?;
    }
    conn.io.flush().await
}

/// End a streamed body.
pub(crate) async fn write_end(conn: &mut Buffered, framing: StreamFraming) -> io::Result<()> {
    match framing {
        StreamFraming::Chunked => conn.write_all(b"0\r\n\r\n").await,
        StreamFraming::Length => conn.io.flush().await,
        StreamFraming::Close => conn.io.shutdown().await,
    }
}

/// Whether a response's transfer coding allows streaming: none, or plain
/// `chunked` (a body that is also transfer-compressed is kept whole and
/// passed on as it is).
pub(crate) fn plain_transfer_coding(headers: &Headers) -> bool {
    match values(headers, "transfer-encoding").first() {
        None => true,
        Some(te) => parse_transfer_encoding(te).is_ok_and(|t| t == "chunked"),
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
    if headers.contains("transfer-encoding") {
        // A transfer coding without `chunked` (a response read until the
        // upstream closed): the body is close-delimited on the way out
        // too, and the connection closes after it. A `Content-Length`
        // beside the coding would frame it a second, different way — the
        // shape the smuggling checks refuse on the way in.
        return false;
    }
    if headers.contains("content-length") {
        headers.set("content-length", len.to_string());
    } else if needs_length {
        headers.add("content-length", len.to_string());
    }
    false
}

/// A status line. The code is always three digits, the only shape the
/// parser accepts: an upstream's `000`..`099` goes out as it came, not as
/// a one- or two-digit code no client can parse.
fn status_line(version: &str, status: u16, reason: &str) -> Vec<u8> {
    format!("{version} {status:03} {reason}\r\n").into_bytes()
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

/// The bytes that frame a body: what goes before and after it.
fn body_frame(len: usize, chunked: bool) -> (Vec<u8>, &'static [u8]) {
    match (chunked, len) {
        (false, _) => (Vec::new(), b""),
        (true, 0) => (Vec::new(), b"0\r\n\r\n"),
        (true, n) => (format!("{n:x}\r\n").into_bytes(), b"\r\n0\r\n\r\n"),
    }
}

/// Write a head and a body without first concatenating them: a large
/// body is not copied a second time just to be sent.
async fn write_message(
    conn: &mut Buffered,
    mut head: Vec<u8>,
    body: &[u8],
    chunked: bool,
) -> io::Result<()> {
    let (before, after) = body_frame(body.len(), chunked);
    head.extend_from_slice(&before);
    if body.len() <= 64 * 1024 {
        head.extend_from_slice(body);
        head.extend_from_slice(after);
        return conn.write_all(&head).await;
    }
    conn.io.write_all(&head).await?;
    conn.io.write_all(body).await?;
    conn.io.write_all(after).await?;
    conn.io.flush().await
}

/// Send `req` as `encode_request` encodes it.
pub(crate) async fn write_request(conn: &mut Buffered, req: &Request) -> io::Result<()> {
    let (head, chunked) = request_head(req);
    write_message(conn, head, &req.body, chunked).await
}

/// Send `resp` as [`encode_response`] encodes it.
pub(crate) async fn write_response(
    conn: &mut Buffered,
    resp: &Response,
    method: &str,
) -> io::Result<()> {
    let (head, chunked, has_body) = response_head(resp, method);
    let body: &[u8] = if has_body { &resp.body } else { b"" };
    write_message(conn, head, body, chunked && has_body).await
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
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn encode_request(req: &Request) -> Vec<u8> {
    let (mut out, chunked) = request_head(req);
    put_body(&mut out, &req.body, chunked);
    out
}

/// The head of `encode_request`, and whether the body goes out chunked.
fn request_head(req: &Request) -> (Vec<u8>, bool) {
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
    (out, chunked)
}

/// The wire bytes of `resp`, as an HTTP/1 response to a `method` request.
pub(crate) fn encode_response(resp: &Response, method: &str) -> Vec<u8> {
    let (mut out, chunked, has_body) = response_head(resp, method);
    if has_body {
        put_body(&mut out, &resp.body, chunked);
    }
    out
}

/// The head of [`encode_response`], whether the body goes out chunked,
/// and whether the response carries a body at all.
fn response_head(resp: &Response, method: &str) -> (Vec<u8>, bool, bool) {
    let mut headers = resp.headers.clone();
    let (version, reason) = if resp.http_version.starts_with("HTTP/1") {
        (resp.http_version.as_str(), resp.reason.clone())
    } else {
        ("HTTP/1.1", super::reason_phrase(resp.status).to_string())
    };
    let has_body = response_has_body(method, resp.status);
    let chunked = has_body && fix_framing(&mut headers, resp.body.len(), true);
    let mut out = status_line(version, resp.status, &reason);
    put_headers(&mut out, &headers);
    (out, chunked, has_body)
}

/// The head of a `101 Switching Protocols` (or any body-less response),
/// written as-is.
pub(crate) fn encode_head_only(resp: &Response) -> Vec<u8> {
    let mut out = status_line("HTTP/1.1", resp.status, &resp.reason);
    put_headers(&mut out, &resp.headers);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::io::Buffered;

    fn budget() -> crate::proxy::budget::Reservation {
        crate::proxy::budget::Reservation::new(&crate::proxy::budget::BodyBudget::new(usize::MAX))
    }

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
    async fn known_lengths_are_read_into_one_exact_allocation() {
        use crate::proxy::budget::{BodyBudget, Reservation};
        let n: usize = 3 << 20;
        let mut data = vec![b'a'; n];
        data.extend_from_slice(b"NEXT");
        let mut c = conn(&data);
        // Some of the body is already buffered, the rest still unread.
        c.fill().await.unwrap();
        assert!(!c.buf.is_empty() && c.buf.len() < n);
        let budget = BodyBudget::new(usize::MAX);
        let mut r = Reservation::new(&budget);
        let body = read_body(&mut c, Framing::Length(n as u64), n, &mut r)
            .await
            .unwrap();
        assert_eq!(body.len(), n);
        assert_eq!(body.capacity(), n, "exactly the declared length");
        assert_eq!(budget.used(), n);
        // The bytes after the body are left for the next message.
        while c.buf.len() < 4 {
            assert!(c.fill().await.unwrap() > 0);
        }
        assert_eq!(&c.buf[..], b"NEXT");
        drop(r);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn unknown_lengths_grow_by_a_quarter_within_the_budget() {
        use crate::proxy::budget::{BodyBudget, Reservation};
        let big: usize = 2 << 20;
        let mut chunked = format!("{big:x}\r\n").into_bytes();
        chunked.extend(std::iter::repeat_n(b'b', big));
        chunked.extend_from_slice(b"\r\n5\r\nhello\r\n0\r\n\r\n");
        let budget = BodyBudget::new(usize::MAX);
        let mut r = Reservation::new(&budget);
        let mut c = conn(&chunked);
        let body = read_body(&mut c, Framing::Chunked, usize::MAX, &mut r)
            .await
            .unwrap();
        assert_eq!(body.len(), big + 5);
        assert!(
            body.capacity() <= big + big / 4 + 64 * 1024,
            "{}",
            body.capacity()
        );
        assert_eq!(budget.used(), body.capacity());
        drop(r);

        let mut r = Reservation::new(&budget);
        let mut c = conn(&vec![b'e'; 3 << 20]);
        let body = read_body(&mut c, Framing::UntilEof, usize::MAX, &mut r)
            .await
            .unwrap();
        assert_eq!(body.len(), 3 << 20);
        assert!(body.capacity() <= (3 << 20) * 5 / 4 + 64 * 1024 * 2);
        drop(r);
        assert_eq!(budget.used(), 0);

        // Over the budget: refused, and nothing stays reserved.
        let small = BodyBudget::with_wait(1 << 20, std::time::Duration::from_millis(10));
        for framing in [Framing::Chunked, Framing::Length(big as u64)] {
            let mut r = Reservation::new(&small);
            let mut c = conn(&chunked);
            assert!(matches!(
                read_body(&mut c, framing, usize::MAX, &mut r).await,
                Err(ReadError::BudgetExhausted)
            ));
            drop(r);
            assert_eq!(small.used(), 0);
        }
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
        assert_eq!(
            read_body(&mut c, framing, 10, &mut budget()).await.unwrap(),
            b"abc"
        );
        assert_eq!(&c.buf[..], b"GET");
    }

    #[tokio::test]
    async fn chunked_bodies_are_joined_and_capped() {
        let mut c = conn(b"4;x=y\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: t\r\n\r\nrest");
        assert_eq!(
            read_body(&mut c, Framing::Chunked, 100, &mut budget())
                .await
                .unwrap(),
            b"Wikipedia"
        );
        assert_eq!(&c.buf[..], b"rest");
        let mut c = conn(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
        assert!(matches!(
            read_body(&mut c, Framing::Chunked, 8, &mut budget()).await,
            Err(ReadError::BodyTooLarge)
        ));
        let mut c = conn(b"");
        assert!(matches!(
            read_body(&mut c, Framing::Length(9), 8, &mut budget()).await,
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

    /// Found by the `h1_response` fuzz target: a status the parser took
    /// from three digits (`000`) went out as one (`0`), which no client
    /// (nor the egress itself) can parse.
    #[test]
    fn status_codes_go_out_as_three_digits() {
        let head = parse_response_head(b"HTTP/1.1 042 odd\r\n\r\n").unwrap();
        let resp = Response {
            status: head.status,
            reason: head.reason,
            http_version: head.version,
            headers: head.headers,
            body: Vec::new(),
        };
        assert_eq!(
            encode_response(&resp, "GET"),
            b"HTTP/1.1 042 odd\r\ncontent-length: 0\r\n\r\n"
        );
        assert!(encode_head_only(&resp).starts_with(b"HTTP/1.1 042 odd\r\n"));
        assert!(
            encode_stream_head(&resp, StreamFraming::Chunked).starts_with(b"HTTP/1.1 042 odd\r\n")
        );
    }

    /// Found by the `h1_response` fuzz target: a response framed by a
    /// transfer coding without `chunked` (read until the upstream closed)
    /// was relayed with a `Content-Length` added beside the
    /// `Transfer-Encoding` — two framings, which the egress's own
    /// smuggling checks refuse.
    #[test]
    fn a_close_delimited_response_gets_no_length_beside_its_coding() {
        let mut resp = Response {
            status: 200,
            reason: "OK".into(),
            http_version: "HTTP/1.1".into(),
            headers: Headers::new(),
            body: b"\x1f\x8b\x08\x00".to_vec(),
        };
        resp.headers.add("Transfer-Encoding", "gzip");
        let wire = encode_response(&resp, "GET");
        assert_eq!(
            wire,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n\x1f\x8b\x08\x00"
        );
        let head = parse_response_head(&wire).unwrap();
        assert!(validate_framing(&head.headers, &head.version, Some(200)).is_ok());
        assert_eq!(
            response_framing("GET", 200, &head.headers),
            Ok(Framing::UntilEof)
        );
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
