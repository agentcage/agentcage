//! The IMAP and SMTP relays' parsing of what the cage and the upstream
//! send.

use crate::relays::imap::{self, Literal, ResponseFilter};
use crate::relays::smtp;
use crate::relays::{Line, Reader, STREAM_LINE_LIMIT};

use super::{Input, PieceStream, block_on, pieces};

const WRITE_MODES: [&str; 3] = ["full", "organise", "none"];

/// The IMAP relay's line handling, for lines from the cage and the
/// upstream's response stream.
pub fn imap(data: &[u8]) {
    let mut input = Input::new(data);
    let write_mode = WRITE_MODES[input.below(WRITE_MODES.len())];
    let folder_lists = input.byte() & 1 == 1;
    let sizes = input.piece_sizes();
    let data = input.rest();
    for line in data.split_inclusive(|&b| b == b'\n') {
        client_line(line);
    }
    response_stream(data, &sizes, write_mode, folder_lists);
}

/// What the relay reads out of one line from the cage.
fn client_line(line: &[u8]) {
    if let Ok(Some(lit)) = imap::client_literal(line) {
        assert_eq!(line[lit.start], b'{');
        // A non-synchronising literal is relayed as a synchronising one,
        // which must announce the same literal.
        if lit.size <= imap::MAX_LITERAL_BYTES {
            let sync = imap::synchronising(line, lit);
            assert_eq!(
                imap::client_literal(&sync),
                Ok(Some(Literal { sync: true, ..lit })),
                "{:?}",
                String::from_utf8_lossy(&sync)
            );
        }
    }
    // A bare-LF line goes upstream CRLF-terminated: the same verdict.
    assert_eq!(imap::line_fault(&imap::crlf(line)), imap::line_fault(line));
    let _ = imap::command_name(line);
    let tag = line.split(|&b| b == b' ').next().unwrap_or_default();
    let _ = imap::valid_tag(tag);

    // The mailbox argument: as the relay reads it, quoting it back
    // (as the relay writes a canonical name) reads the same.
    let args = line.splitn(3, |&b| b == b' ').nth(2).unwrap_or_default();
    if let Some(name) = imap::extract_mailbox(args) {
        assert_eq!(
            imap::extract_mailbox(&imap::quote(&name)).as_deref(),
            Some(name.as_str())
        );
        let _ = imap::fold(&name);
    }
    let text = String::from_utf8_lossy(line);
    if let Some(decoded) = imap::mutf7_decode(&text) {
        // Decoding is what a deny entry is matched against: encoding the
        // result again must decode to it.
        let encoded = mutf7_encode(&decoded);
        assert_eq!(
            imap::mutf7_decode(&encoded).as_deref(),
            Some(decoded.as_str()),
            "{encoded:?}"
        );
        let _ = imap::fold(&decoded);
    }
}

/// RFC 3501 §5.1.3 modified UTF-7.
fn mutf7_encode(text: &str) -> String {
    use base64::Engine as _;

    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let mut out = String::new();
    let mut run: Vec<u16> = Vec::new();
    let flush = |run: &mut Vec<u16>, out: &mut String| {
        if run.is_empty() {
            return;
        }
        let bytes: Vec<u8> = run.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&engine.encode(bytes).replace('/', ","));
        out.push('-');
        run.clear();
    };
    for c in text.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut run, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut units = [0u16; 2];
            run.extend_from_slice(c.encode_utf16(&mut units));
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Run the upstream → cage filter over `data` with `held_limit`, fed in
/// `sizes` pieces.
fn filtered(
    data: &[u8],
    sizes: &[usize],
    held_limit: usize,
    write_mode: &'static str,
    folder_lists: bool,
) -> Result<Vec<u8>, imap::Unfilterable> {
    let mut filter = ResponseFilter::new(
        Box::new(move |t| imap::capability_hidden(t, write_mode, folder_lists)),
        None,
        held_limit,
    );
    let mut out = Vec::new();
    for piece in pieces(data, sizes) {
        out.extend(filter.feed(piece)?);
    }
    out.extend(filter.finish());
    Ok(out)
}

fn response_stream(data: &[u8], sizes: &[usize], write_mode: &'static str, folder_lists: bool) {
    // How the upstream's bytes happen to be segmented must not change
    // what reaches the cage.
    let whole = filtered(data, &[usize::MAX], usize::MAX, write_mode, folder_lists)
        .expect("no line outgrows an unbounded limit");
    let cut = filtered(data, sizes, usize::MAX, write_mode, folder_lists)
        .expect("no line outgrows an unbounded limit");
    assert_eq!(cut, whole, "segmentation changed the filtered stream");
    // With no literal anywhere, no capability list reaching the cage may
    // still advertise a hidden capability.
    if !data.contains(&b'{') {
        for line in whole.split_inclusive(|&b| b == b'\n') {
            let upper = line.to_ascii_uppercase();
            if let Some(list) = upper.strip_prefix(b"* CAPABILITY ") {
                for token in list.split(u8::is_ascii_whitespace) {
                    let token = String::from_utf8_lossy(token);
                    assert!(
                        token.is_empty()
                            || !imap::capability_hidden(&token, write_mode, folder_lists),
                        "{token:?} advertised in {:?}",
                        String::from_utf8_lossy(line)
                    );
                }
            }
        }
    }
    // A small held-line limit streams long lines raw instead; that may
    // refuse the stream, but never panics.
    let _ = filtered(data, sizes, 1 + sizes[0] % 64, write_mode, folder_lists);
}

/// The SMTP relay's parsing: addresses, message headers, and the DATA
/// phase in both directions.
pub fn smtp(data: &[u8]) {
    let mut input = Input::new(data);
    let sizes = input.piece_sizes();
    let data = input.rest();

    for line in data.split_inclusive(|&b| b == b'\n') {
        let _ = smtp::extract_address(&String::from_utf8_lossy(line));
    }
    let (content_type, headers) = smtp::message_headers(data);
    assert_eq!(content_type.matches('/').count(), 1, "{content_type:?}");
    assert!(!content_type.contains(';'));
    assert_eq!(content_type, content_type.to_lowercase());
    assert!(headers.iter().all(|(name, _)| !name.contains(':')));

    from_cage(data, &sizes);
    to_upstream(data);
}

/// A message the cage dot-stuffs (as an RFC 5321 client does) arrives as
/// it was written, and the command after it is read in step.
fn from_cage(message: &[u8], sizes: &[usize]) {
    let mut message = message.to_vec();
    if !message.ends_with(b"\n") {
        message.extend_from_slice(b"\r\n");
    }
    let mut wire = Vec::new();
    for line in message.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b".") {
            wire.push(b'.');
        }
        wire.extend_from_slice(line);
    }
    wire.extend_from_slice(b".\r\nQUIT\r\n");
    let (body, next) = read_data(&wire, sizes);
    let Some(body) = body else {
        return; // a line over the relay's limit ends the session
    };
    assert_eq!(body, message, "the message changed in transit");
    assert_eq!(next.as_deref(), Some(&b"QUIT\r\n"[..]));
}

/// What the upstream is sent after `DATA` ends exactly once, at its end,
/// for a strict server and for one that also ends lines at a bare CR or
/// LF (the SMTP smuggling shapes), and unstuffs back to the message.
fn to_upstream(body: &[u8]) {
    let wire = smtp::dot_stuff(body);
    assert!(wire.ends_with(b"\r\n.\r\n"));
    let eol = |b: u8| b == b'\r' || b == b'\n';
    for i in 0..wire.len() {
        let line_start = i == 0 || eol(wire[i - 1]);
        let dot_line = wire[i] == b'.' && wire.get(i + 1).copied().is_some_and(eol);
        if line_start && dot_line {
            assert_eq!(
                i,
                wire.len() - 3,
                "an end of data inside the message: {:?}",
                String::from_utf8_lossy(&wire)
            );
        }
    }
    let mut want = body.to_vec();
    if !want.ends_with(b"\r\n") {
        want.extend_from_slice(b"\r\n");
    }
    // Unstuffed line by line, lines ending at CRLF, CR or LF (the
    // stuffing's own reading), it is the message again.
    let mut back = Vec::new();
    let mut rest = &wire[..];
    while !rest.is_empty() {
        let end = match rest.iter().position(|&b| eol(b)) {
            Some(i) if rest[i] == b'\r' && rest.get(i + 1) == Some(&b'\n') => i + 2,
            Some(i) => i + 1,
            None => rest.len(),
        };
        let (line, tail) = rest.split_at(end);
        rest = tail;
        if line == b".\r\n" {
            assert!(rest.is_empty());
            break;
        }
        back.extend_from_slice(line.strip_prefix(b".").unwrap_or(line));
    }
    assert_eq!(back, want);
}

/// Read a DATA phase off `wire` with the relay's line reader: the
/// message (`None` if a line is over the limit) and the next line.
fn read_data(wire: &[u8], sizes: &[usize]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    block_on(async {
        let mut reader = Reader::new(PieceStream::new(wire.to_vec(), sizes.to_vec()));
        let mut body = Vec::new();
        loop {
            match reader
                .read_line(STREAM_LINE_LIMIT)
                .await
                .expect("in-memory read")
            {
                Line::Data(line) if line.is_empty() => return (None, None),
                Line::Data(line) => match smtp::data_line(&line) {
                    Some(line) => body.extend_from_slice(line),
                    None => break,
                },
                Line::TooLong { .. } => return (None, None),
            }
        }
        let next = match reader
            .read_line(STREAM_LINE_LIMIT)
            .await
            .expect("in-memory read")
        {
            Line::Data(line) => Some(line),
            Line::TooLong { .. } => None,
        };
        (Some(body), next)
    })
}
