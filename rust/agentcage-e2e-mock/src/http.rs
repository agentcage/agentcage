//! The minimum of HTTP/1.x the mocks need: read one request head, read a
//! `Content-Length` body, write one response and close.
//!
//! Every response carries `Content-Length` and `Connection: close`, so
//! the egress never has to guess where a body ends and never reuses a
//! connection to a mock.

use std::io::{self, BufRead, Read, Write};

/// Longest request line or header line accepted, as in the
/// `http.server` the first version of these mocks used.
const MAX_LINE: usize = 65_536;
/// Most header lines accepted.
const MAX_HEADERS: usize = 100;
/// Largest request body read.
const MAX_BODY: u64 = 16 * 1024 * 1024;

/// One parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, as sent.
    pub method: String,
    /// The request target, as sent (origin form: path plus query).
    pub target: String,
    /// Header fields in arrival order, names as sent.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// The first header named `name` (ASCII case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The target without its query string.
    #[must_use]
    pub fn path(&self) -> &str {
        self.target.split_once('?').map_or(&self.target, |(p, _)| p)
    }

    /// The declared body length (0 when absent or unparsable).
    #[must_use]
    pub fn content_length(&self) -> u64 {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }
}

/// What reading a request head can yield.
#[derive(Debug)]
pub enum Head {
    /// A well-formed head.
    Request(Request),
    /// The peer closed before sending anything.
    Eof,
    /// Something that is not an HTTP request; answer 400.
    Malformed,
}

fn read_line<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = reader
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
    }
    let line = String::from_utf8_lossy(&buf);
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_owned()))
}

/// Read one request head.
///
/// # Errors
/// On I/O errors or an over-long line.
pub fn read_head<R: BufRead>(reader: &mut R) -> io::Result<Head> {
    let Some(line) = read_line(reader)? else {
        return Ok(Head::Eof);
    };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Ok(Head::Malformed);
    };
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Ok(Head::Malformed);
    }
    let mut headers = Vec::new();
    loop {
        let Some(line) = read_line(reader)? else {
            return Ok(Head::Malformed);
        };
        if line.is_empty() {
            break;
        }
        if headers.len() == MAX_HEADERS {
            return Ok(Head::Malformed);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Ok(Head::Malformed);
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Ok(Head::Request(Request {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
    }))
}

/// Read the request's `Content-Length` body.
///
/// Reading it (rather than answering straight away) matters even where
/// the body is ignored: closing a socket with unread input makes the
/// kernel send a reset, which can reach the egress before the response.
///
/// # Errors
/// On I/O errors or a body shorter than declared.
pub fn read_body<R: Read>(reader: &mut R, request: &Request) -> io::Result<Vec<u8>> {
    let len = request.content_length().min(MAX_BODY);
    let mut body = Vec::new();
    reader.take(len).read_to_end(&mut body)?;
    if (body.len() as u64) < len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short body"));
    }
    Ok(body)
}

/// Write a complete response and flush it.
///
/// # Errors
/// On I/O errors.
pub fn write_response<W: Write>(
    writer: &mut W,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )?;
    writer.write_all(body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::{Head, read_body, read_head};
    use std::io::Cursor;

    #[test]
    fn parses_head_and_body() {
        let raw = b"POST /post?x=1 HTTP/1.1\r\nHost: a\r\ncontent-length: 3\r\n\r\nabcEXTRA";
        let mut cur = Cursor::new(&raw[..]);
        let Head::Request(req) = read_head(&mut cur).unwrap() else {
            panic!("not a request")
        };
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/post?x=1");
        assert_eq!(req.path(), "/post");
        assert_eq!(req.header("HOST"), Some("a"));
        assert_eq!(read_body(&mut cur, &req).unwrap(), b"abc");
    }

    #[test]
    fn eof_and_garbage() {
        assert!(matches!(
            read_head(&mut Cursor::new(&b""[..])).unwrap(),
            Head::Eof
        ));
        assert!(matches!(
            read_head(&mut Cursor::new(&b"hello\r\n\r\n"[..])).unwrap(),
            Head::Malformed
        ));
    }
}
