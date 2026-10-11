//! The IMAP upstream behind the protocol relay (plaintext, line based).
//!
//! Every command line the relay forwards is appended to `imap.log`, so
//! the phase can show what reached the server (the injected login) and
//! what never did (the cage's own credentials, the refused commands).
//! Answers are canned: one message in INBOX, and a tagged OK for
//! anything unrecognised.

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::log::LogDir;

/// Default listen address (loopback in the egress's namespace).
pub const ADDR: &str = "127.0.0.1:3143";

/// The one message in INBOX; 9.3 looks for its body text.
pub const MESSAGE: &str = "From: sender@example.com\r\n\
                           To: agent@example.com\r\n\
                           Subject: e2e mock message\r\n\
                           \r\n\
                           hello from the mock imap server\r\n";

/// The full answer to one command line, and whether to hang up after it.
#[must_use]
pub fn respond(line: &str) -> (String, bool) {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return ("* BAD missing command\r\n".to_owned(), false);
    }
    let tag = parts[0];
    let mut cmd = parts[1].to_uppercase();
    let args = parts.get(2).copied().unwrap_or("");
    if cmd == "UID" && !args.is_empty() {
        let sub = args.split(' ').next().unwrap_or("");
        cmd = format!("UID {}", sub.to_uppercase());
    }
    let reply = match cmd.as_str() {
        "CAPABILITY" => {
            format!("* CAPABILITY IMAP4rev1 IDLE UIDPLUS\r\n{tag} OK CAPABILITY completed\r\n")
        }
        "SELECT" | "EXAMINE" => format!(
            "* FLAGS (\\Seen \\Deleted)\r\n\
             * 1 EXISTS\r\n\
             * OK [UIDVALIDITY 1] ok\r\n\
             {tag} OK [READ-WRITE] {cmd} completed\r\n"
        ),
        "FETCH" | "UID FETCH" => format!(
            "* 1 FETCH (UID 1 BODY[] {{{}}}\r\n{MESSAGE})\r\n{tag} OK FETCH completed\r\n",
            MESSAGE.len()
        ),
        "LIST" => {
            format!("* LIST () \"/\" INBOX\r\n* LIST () \"/\" Trash\r\n{tag} OK LIST completed\r\n")
        }
        "STORE" | "UID STORE" => {
            format!("* 1 FETCH (FLAGS (\\Seen))\r\n{tag} OK STORE completed\r\n")
        }
        "LOGOUT" => return (format!("* BYE bye\r\n{tag} OK LOGOUT completed\r\n"), true),
        _ => format!("{tag} OK {cmd} completed\r\n"),
    };
    (reply, false)
}

/// Serve one connection.
///
/// # Errors
/// On I/O errors; the caller drops the connection.
pub fn handle(stream: TcpStream, log: &Arc<LogDir>) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    writer.write_all(b"* OK mock IMAP ready\r\n")?;
    let mut raw = Vec::new();
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&raw);
        let line = text.trim_end_matches(['\r', '\n']);
        log.append("imap.log", line);
        let (reply, bye) = respond(line);
        writer.write_all(reply.as_bytes())?;
        writer.flush()?;
        if bye {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::respond;

    #[test]
    fn canned_answers() {
        assert_eq!(respond("a1").0, "* BAD missing command\r\n");
        assert_eq!(respond("a2 noop").0, "a2 OK NOOP completed\r\n");
        assert_eq!(
            respond("a3 uid fetch 1 BODY[]").0.lines().last(),
            Some("a3 OK FETCH completed")
        );
        assert!(
            respond("a3 uid fetch 1 BODY[]")
                .0
                .starts_with("* 1 FETCH (UID 1 BODY[] {111}\r\nFrom:")
        );
        assert!(
            respond("a4 select INBOX")
                .0
                .ends_with("a4 OK [READ-WRITE] SELECT completed\r\n")
        );
        assert_eq!(respond("a5 UID").0, "a5 OK UID completed\r\n");
        assert_eq!(
            respond("a6 LOGOUT"),
            ("* BYE bye\r\na6 OK LOGOUT completed\r\n".to_owned(), true)
        );
    }
}
