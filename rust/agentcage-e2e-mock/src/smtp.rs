//! The SMTP upstream behind the protocol relay (plaintext, line based).
//!
//! Every command line is appended to `smtp.log`; every message completed
//! with the final `.` is appended to `smtp.jsonl` as
//! `{"from": ..., "to": [...], "body": ...}`. A client that goes away in
//! the middle of DATA delivers nothing, so nothing is recorded (9.10).

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;

use serde::Serialize;

use crate::log::LogDir;
use crate::spaced_json;

/// Default listen address (loopback in the egress's namespace).
pub const ADDR: &str = "127.0.0.1:3025";

fn read_line<R: BufRead>(reader: &mut R, raw: &mut Vec<u8>) -> io::Result<Option<String>> {
    raw.clear();
    if reader.read_until(b'\n', raw)? == 0 {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(raw);
    Ok(Some(text.trim_end_matches(['\r', '\n']).to_owned()))
}

/// One `smtp.jsonl` record.
#[derive(Serialize)]
struct Delivered<'a> {
    from: &'a str,
    to: &'a [String],
    body: &'a str,
}

fn send(w: &mut TcpStream, s: &str) -> io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// `line` from its `skip`-th character on, trimmed (`line[skip:].strip()`).
fn tail(line: &str, skip: usize) -> String {
    line.chars()
        .skip(skip)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Serve one connection.
///
/// # Errors
/// On I/O errors; the caller drops the connection.
pub fn handle(stream: TcpStream, log: &Arc<LogDir>) -> io::Result<()> {
    let mut w = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut raw = Vec::new();
    send(&mut w, "220 mock ESMTP ready\r\n")?;
    let mut sender = String::new();
    let mut rcpts: Vec<String> = Vec::new();
    while let Some(line) = read_line(&mut reader, &mut raw)? {
        log.append("smtp.log", &line);
        let verb = line.split(' ').next().unwrap_or("").to_uppercase();
        match verb.as_str() {
            "EHLO" | "HELO" => send(
                &mut w,
                "250-mock\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n",
            )?,
            "AUTH" => send(&mut w, "235 2.7.0 accepted\r\n")?,
            "MAIL" => {
                sender = tail(&line, 10); // after "MAIL FROM:"
                rcpts.clear();
                send(&mut w, "250 2.1.0 ok\r\n")?;
            }
            "RCPT" => {
                rcpts.push(tail(&line, 8)); // after "RCPT TO:"
                send(&mut w, "250 2.1.5 ok\r\n")?;
            }
            "DATA" => {
                send(&mut w, "354 go ahead\r\n")?;
                let mut lines = Vec::new();
                let mut complete = false;
                while let Some(text) = read_line(&mut reader, &mut raw)? {
                    if text == "." {
                        complete = true;
                        break;
                    }
                    // Undo dot-stuffing (RFC 5321 section 4.5.2).
                    lines.push(if text.starts_with("..") {
                        text[1..].to_owned()
                    } else {
                        text
                    });
                }
                if !complete {
                    // The client went away mid-DATA: nothing was
                    // delivered, so nothing is recorded.
                    return Ok(());
                }
                log.append(
                    "smtp.jsonl",
                    &spaced_json::to_string(&Delivered {
                        from: &sender,
                        to: &rcpts,
                        body: &lines.join("\n"),
                    }),
                );
                send(&mut w, "250 2.0.0 queued\r\n")?;
            }
            "RSET" | "NOOP" => send(&mut w, "250 2.0.0 ok\r\n")?,
            "QUIT" => return send(&mut w, "221 2.0.0 bye\r\n"),
            _ => send(&mut w, "502 5.5.2 unknown\r\n")?,
        }
    }
    Ok(())
}
