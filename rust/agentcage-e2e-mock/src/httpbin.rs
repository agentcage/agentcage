//! The httpbin.org / example.com stand-in.
//!
//! Any GET, POST or PUT is answered `200` with
//! `{"ok": true, "path": <request target>, "method": <method>}`. Other
//! methods get `501`, as they did from the first (`http.server`-based)
//! version of this mock. `GET /ws` with `Upgrade: websocket` is the
//! WebSocket echo in [`crate::ws`] instead.

use std::io::{self, BufReader};
use std::net::TcpStream;
use std::time::Duration;

use serde::Serialize;

use crate::http::{self, Head};
use crate::spaced_json;

/// The port the harness binds (inside the egress's network namespace,
/// where the egress quadlet has lowered `ip_unprivileged_port_start`).
pub const PORT: u16 = 80;

/// The answer to every GET/POST/PUT.
#[derive(Serialize)]
struct Answer<'a> {
    ok: bool,
    path: &'a str,
    method: &'a str,
}

/// Serve one connection.
///
/// # Errors
/// On I/O errors; the caller drops the connection.
pub fn handle(stream: TcpStream) -> io::Result<()> {
    // A stalled peer must not pin a thread forever; a WebSocket clears
    // the timeout once upgraded.
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let request = match http::read_head(&mut reader)? {
        Head::Request(r) => r,
        Head::Eof => return Ok(()),
        Head::Malformed => {
            return http::write_response(
                &mut writer,
                400,
                "Bad Request",
                "text/plain",
                b"bad request\n",
            );
        }
    };
    if request.method == "GET"
        && request.path() == "/ws"
        && request
            .header("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    {
        reader.get_ref().set_read_timeout(None)?;
        return crate::ws::echo(&request, reader, writer);
    }
    http::read_body(&mut reader, &request)?;
    match request.method.as_str() {
        "GET" | "POST" | "PUT" => {
            let body = spaced_json::to_string(&Answer {
                ok: true,
                path: &request.target,
                method: &request.method,
            });
            http::write_response(&mut writer, 200, "OK", "application/json", body.as_bytes())
        }
        other => {
            let body = format!("Unsupported method ('{other}')\n");
            http::write_response(
                &mut writer,
                501,
                "Not Implemented",
                "text/plain",
                body.as_bytes(),
            )
        }
    }
}
