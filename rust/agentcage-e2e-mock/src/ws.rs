//! The WebSocket echo behind `GET /ws`.
//!
//! Each text or binary message is answered with one text message,
//! `{"echo": <payload as UTF-8, lossy>, "sha256": <hex digest>}`, the
//! digest taken over the payload bytes as they ARRIVED. The egress
//! redacts a real secret value back to its placeholder on the way into
//! the cage, so the echo field alone cannot show that a placeholder was
//! injected on the way out; the digest, which redaction cannot touch,
//! can (phase 9, test 9.20).
//!
//! Deliberately small: one frame is one message (no continuation
//! frames, which neither the probe nor the egress produce for these
//! short messages), pings are answered, a close is answered and ends the
//! connection.

use std::fmt::Write as _;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;

use base64::Engine as _;
use serde::Serialize;
use sha1::{Digest as _, Sha1};
use sha2::{Digest as _, Sha256};

use crate::http::Request;
use crate::spaced_json;

/// RFC 6455 section 1.3.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest frame payload accepted.
const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;

const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
#[must_use]
pub fn accept_key(key: &str) -> String {
    let digest = Sha1::digest(format!("{key}{GUID}").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// The echo's reply to one message.
#[must_use]
pub fn reply(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    let hex = digest.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    spaced_json::to_string(&Reply {
        echo: &String::from_utf8_lossy(payload),
        sha256: &hex,
    })
}

#[derive(Serialize)]
struct Reply<'a> {
    echo: &'a str,
    sha256: &'a str,
}

/// Complete the handshake for `request` and echo until the peer closes.
///
/// # Errors
/// On I/O errors.
pub fn echo(
    request: &Request,
    mut reader: BufReader<TcpStream>,
    mut writer: TcpStream,
) -> io::Result<()> {
    let accept = accept_key(request.header("sec-websocket-key").unwrap_or(""));
    write!(
        writer,
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )?;
    writer.flush()?;
    while let Some((opcode, payload)) = read_frame(&mut reader)? {
        match opcode {
            OP_CLOSE => {
                // Echo the status code (if any) and stop.
                writer.write_all(&frame(OP_CLOSE, &payload[..payload.len().min(2)]))?;
                return writer.flush();
            }
            OP_PING => writer.write_all(&frame(OP_PONG, &payload))?,
            OP_TEXT | OP_BINARY => writer.write_all(&frame(OP_TEXT, reply(&payload).as_bytes()))?,
            _ => {}
        }
        writer.flush()?;
    }
    Ok(())
}

/// One client frame as `(opcode, unmasked payload)`, or `None` at EOF.
///
/// # Errors
/// On I/O errors, a truncated frame or an oversized payload.
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 2];
    match reader.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let opcode = head[0] & 0x0F;
    let masked = head[1] & 0x80 != 0;
    let len = match head[1] & 0x7F {
        126 => {
            let mut b = [0u8; 2];
            reader.read_exact(&mut b)?;
            u64::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            reader.read_exact(&mut b)?;
            u64::from_be_bytes(b)
        }
        n => u64::from(n),
    };
    if len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut mask = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask)?;
    }
    let mut payload = Vec::new();
    reader.take(len).read_to_end(&mut payload)?;
    if (payload.len() as u64) < len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short frame"));
    }
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
    Ok(Some((opcode, payload)))
}

/// One unmasked server frame with FIN set.
#[must_use]
pub fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let n = payload.len();
    match (u8::try_from(n), u16::try_from(n)) {
        (Ok(n8), _) if n8 < 126 => out.push(n8),
        (_, Ok(n16)) => {
            out.push(126);
            out.extend_from_slice(&n16.to_be_bytes());
        }
        _ => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::{accept_key, frame, read_frame, reply};
    use std::io::Cursor;

    #[test]
    fn rfc6455_accept_example() {
        // RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn reply_shape() {
        assert_eq!(
            reply(b"abc"),
            r#"{"echo": "abc", "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}"#
        );
    }

    #[test]
    fn masked_round_trip_and_lengths() {
        let payload = vec![b'x'; 300];
        let mask = [1u8, 2, 3, 4];
        let mut raw = vec![0x81, 0x80 | 0x7e, 0x01, 0x2C];
        raw.extend_from_slice(&mask);
        raw.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let (op, got) = read_frame(&mut Cursor::new(raw)).unwrap().unwrap();
        assert_eq!((op, got), (1, payload));
        assert_eq!(frame(1, b"hi"), vec![0x81, 2, b'h', b'i']);
        assert_eq!(&frame(1, &[0; 300])[..4], &[0x81, 126, 0x01, 0x2C]);
        assert_eq!(&frame(1, &vec![0; 70_000])[..2], &[0x81, 127]);
        assert!(read_frame(&mut Cursor::new(Vec::new())).unwrap().is_none());
    }
}
