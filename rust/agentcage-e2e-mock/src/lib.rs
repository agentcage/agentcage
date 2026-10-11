//! Mock upstreams for the agentcage end-to-end suite.
//!
//! `tests/e2e/lib.sh` runs the `agentcage-e2e-mock` binary in a container
//! that joins a cage egress's network namespace, so the egress's own
//! outbound connections reach these listeners on loopback while the cage
//! cannot address them at all. Two roles:
//!
//! * [`httpbin`]: a stand-in for httpbin.org / example.com on port 80 that
//!   answers any GET/POST/PUT with a small JSON document, plus a WebSocket
//!   echo on `/ws` ([`ws`]).
//! * the phase 9 services: an IMAP ([`imap`]) and an SMTP ([`smtp`])
//!   upstream for the protocol relays, a stub LLM ([`llm`]) answering the
//!   forced-tool-call shape for the domain decider and the traffic
//!   watcher, and a TLS server ([`tls`]) for a passthrough domain.
//!
//! Every response is fixed: the phase scripts assert on them byte for
//! byte or field by field, so a change here is a change to the suite.
//! JSON goes through [`pyjson`], whose spacing the scripts grep for.

pub mod http;
pub mod httpbin;
pub mod imap;
pub mod llm;
pub mod log;
pub mod pyjson;
pub mod smtp;
pub mod tls;
pub mod ws;

use std::io;
use std::net::{TcpListener, TcpStream};
use std::thread;

/// Accept connections on `listener` forever, one thread per connection.
///
/// A failed accept is skipped rather than fatal (a peer that resets
/// before `accept` returns must not take the mock down), and a handler's
/// own I/O errors end only its connection.
pub fn serve_forever<F>(listener: &TcpListener, handler: F)
where
    F: Fn(TcpStream) -> io::Result<()> + Send + Sync + Clone + 'static,
{
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = handler.clone();
        thread::spawn(move || {
            let _ = handler(stream);
        });
    }
}
