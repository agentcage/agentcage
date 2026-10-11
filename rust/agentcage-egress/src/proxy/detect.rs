//! Protocol detection from the first bytes a client sends: a TLS
//! `ClientHello` (with its SNI and ALPN offers), HTTP, or something else.
//!
//! The rules are the replaced implementation's layer decision: a TLS
//! record header (`0x16 0x03 0x00..=0x03`) means TLS; otherwise the bytes
//! are HTTP unless they are "probably not HTTP" — fewer than three bytes,
//! no space, the first space after the first newline, a non-alphabetic
//! method start, or an `SSH` banner.

/// The parts of a `ClientHello` the proxy acts on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// The `server_name` extension's host name, if any.
    pub sni: Option<String>,
    /// The ALPN protocols offered, in the client's order.
    pub alpn: Vec<Vec<u8>>,
}

/// Whether `data` starts like a TLS record.
pub(crate) fn starts_like_tls(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03
}

/// The ALPN protocols the proxy can speak, in the order it prefers them
/// when none is otherwise chosen.
pub(crate) const HTTP_ALPNS: [&[u8]; 4] = [b"h2", b"http/1.1", b"http/1.0", b"http/0.9"];

/// The first protocol the client offers that the proxy speaks (the
/// client's preference wins).
pub(crate) fn choose_alpn(offers: &[Vec<u8>]) -> Option<Vec<u8>> {
    offers
        .iter()
        .find(|offer| HTTP_ALPNS.contains(&offer.as_slice()))
        .cloned()
}

/// Parse the `ClientHello` at the start of `data` (record headers
/// included, possibly spread over several records).
///
/// Returns `Ok(None)` when more bytes are needed.
///
/// # Errors
///
/// The records or the `ClientHello` are malformed.
pub fn parse_client_hello(data: &[u8]) -> Result<Option<ClientHello>, String> {
    let mut handshake = Vec::new();
    let mut offset = 0;
    loop {
        if data.len() < offset + 5 {
            return Ok(None);
        }
        let header = &data[offset..offset + 5];
        if !starts_like_tls(header) {
            return Err(format!("expected a TLS record, got {header:02x?}"));
        }
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if size == 0 {
            return Err("record must not be empty".into());
        }
        offset += 5;
        if data.len() < offset + size {
            return Ok(None);
        }
        handshake.extend_from_slice(&data[offset..offset + size]);
        offset += size;
        if handshake.len() >= 4 {
            let len = usize::from(handshake[1]) << 16
                | usize::from(handshake[2]) << 8
                | usize::from(handshake[3]);
            if handshake.len() >= len + 4 {
                if handshake[0] != 0x01 {
                    return Err("not a ClientHello".into());
                }
                return parse_body(&handshake[4..len + 4]).map(Some);
            }
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.data.len() < n {
            return Err("truncated ClientHello".into());
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<usize, String> {
        Ok(usize::from(self.take(1)?[0]))
    }

    fn u16(&mut self) -> Result<usize, String> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn vec8(&mut self) -> Result<&'a [u8], String> {
        let n = self.u8()?;
        self.take(n)
    }

    fn vec16(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()?;
        self.take(n)
    }
}

fn parse_body(body: &[u8]) -> Result<ClientHello, String> {
    let mut r = Reader { data: body };
    r.take(2)?; // legacy_version
    r.take(32)?; // random
    r.vec8()?; // session id
    r.vec16()?; // cipher suites
    r.vec8()?; // compression methods
    let mut hello = ClientHello::default();
    if r.data.is_empty() {
        return Ok(hello);
    }
    let mut exts = Reader { data: r.vec16()? };
    while !exts.data.is_empty() {
        let kind = exts.u16()?;
        let mut ext = Reader {
            data: exts.vec16()?,
        };
        match kind {
            0 => {
                let mut names = Reader { data: ext.vec16()? };
                while !names.data.is_empty() {
                    let name_type = names.u8()?;
                    let name = names.vec16()?;
                    if name_type == 0 && hello.sni.is_none() {
                        hello.sni = Some(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            16 => {
                let mut protos = Reader { data: ext.vec16()? };
                while !protos.data.is_empty() {
                    hello.alpn.push(protos.vec8()?.to_vec());
                }
            }
            _ => {}
        }
    }
    Ok(hello)
}

/// What a plaintext prefix looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plain {
    /// It looks like an HTTP request.
    Http,
    /// It does not.
    Other,
    /// Too few bytes to tell yet.
    NeedMore,
}

/// Classify plaintext client bytes. `eof` means no more will come.
pub(crate) fn classify_plain(data: &[u8], eof: bool) -> Plain {
    let decided = |no_http: bool| if no_http { Plain::Other } else { Plain::Http };
    if data.len() >= 3 && !data[..3].iter().all(u8::is_ascii_alphabetic) {
        return Plain::Other;
    }
    if data.starts_with(b"SSH") {
        return Plain::Other;
    }
    let Some(newline) = data.iter().position(|&b| b == b'\n') else {
        // The replaced implementation decided on the first segment; a
        // request line split across segments is read on instead, up to a
        // bound, rather than mistaken for raw TCP.
        if eof || data.len() >= 8 * 1024 {
            return Plain::Other;
        }
        return Plain::NeedMore;
    };
    let space = data.iter().position(|&b| b == b' ');
    decided(data.len() < 3 || space.is_none_or(|s| s > newline))
}

/// The `Host` header of a buffered plaintext request head, as the
/// passthrough check reads it: the first header block line `Host:` with
/// at least one whitespace before the value. `Ok(None)` when the head ends
/// first; `Err(())` when more bytes are needed.
pub(crate) fn host_header(data: &[u8]) -> Result<Option<String>, ()> {
    let mut i = 0;
    while let Some(pos) = find(&data[i..], b"\r\n") {
        let start = i + pos + 2;
        let rest = &data[start..];
        if rest.starts_with(b"\r\n") {
            return Ok(None);
        }
        if rest.len() >= 5 && rest[..5].eq_ignore_ascii_case(b"host:") {
            let after = &rest[5..];
            if let Some(end) = find(after, b"\r\n") {
                let line = &after[..end];
                if line.first().is_some_and(u8::is_ascii_whitespace) {
                    let value = String::from_utf8_lossy(line).trim().to_string();
                    if !value.is_empty() {
                        return Ok(Some(value));
                    }
                }
            } else {
                return Err(());
            }
        }
        i = start;
    }
    Err(())
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(sni: Option<&str>, alpn: &[&[u8]]) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut list = vec![0u8];
            list.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
            list.extend_from_slice(name.as_bytes());
            let mut ext = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
            ext.extend(list);
            exts.extend_from_slice(&0u16.to_be_bytes());
            exts.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
            exts.extend(ext);
        }
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for p in alpn {
                list.push(u8::try_from(p.len()).unwrap());
                list.extend_from_slice(p);
            }
            let mut ext = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
            ext.extend(list);
            exts.extend_from_slice(&16u16.to_be_bytes());
            exts.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
            exts.extend(ext);
        }
        let mut body = vec![3, 3];
        body.extend([0u8; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 0x01]);
        body.extend([1, 0]);
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend(exts);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        hs.extend(body);
        hs
    }

    fn records(hs: &[u8], split: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in hs.chunks(split) {
            out.extend([0x16, 0x03, 0x01]);
            out.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    #[test]
    fn sni_and_alpn_come_out_of_a_hello_split_over_records() {
        let hs = hello(Some("example.com"), &[b"h2", b"http/1.1"]);
        for split in [hs.len(), 7, 1] {
            let data = records(&hs, split);
            for cut in [0, 3, data.len() - 1] {
                assert_eq!(parse_client_hello(&data[..cut]).unwrap(), None);
            }
            let parsed = parse_client_hello(&data).unwrap().unwrap();
            assert_eq!(parsed.sni.as_deref(), Some("example.com"));
            assert_eq!(parsed.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        }
        let bare = parse_client_hello(&records(&hello(None, &[]), 1000))
            .unwrap()
            .unwrap();
        assert_eq!(bare, ClientHello::default());
    }

    #[test]
    fn garbage_after_a_tls_header_is_an_error() {
        assert!(parse_client_hello(b"\x16\x03\x01\x00\x00").is_err());
        assert!(parse_client_hello(b"\x16\x03\x01\x00\x04\x02\x00\x00\x00").is_err());
    }

    #[test]
    fn plaintext_classification_follows_the_layer_rules() {
        assert_eq!(classify_plain(b"GET / HTTP/1.1\r\n", false), Plain::Http);
        assert_eq!(classify_plain(b"GET / HTTP/1.1", false), Plain::NeedMore);
        assert_eq!(classify_plain(b"GET / HTTP/1.1", true), Plain::Other);
        assert_eq!(classify_plain(b"SSH-2.0-OpenSSH\r\n", false), Plain::Other);
        assert_eq!(classify_plain(b"\x00\x01\x02", false), Plain::Other);
        assert_eq!(classify_plain(b"EHLO\r\nx y", false), Plain::Other);
        assert_eq!(classify_plain(b"GE", true), Plain::Other);
    }

    #[test]
    fn the_host_header_is_found_or_the_head_ends() {
        assert_eq!(
            host_header(b"GET / HTTP/1.1\r\nAccept: */*\r\nHOST:  a.test:81 \r\n\r\n"),
            Ok(Some("a.test:81".into()))
        );
        assert_eq!(host_header(b"GET / HTTP/1.1\r\nX: y\r\n\r\n"), Ok(None));
        assert_eq!(host_header(b"GET / HTTP/1.1\r\nHost: a"), Err(()));
        assert_eq!(
            choose_alpn(&[b"x".to_vec(), b"http/1.1".to_vec(), b"h2".to_vec()]),
            Some(b"http/1.1".to_vec())
        );
    }
}
