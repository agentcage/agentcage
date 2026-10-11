//! The upstream connector: resolve, vet, connect, TLS, ALPN.
//!
//! Resolution is getaddrinfo on a blocking thread (`tokio::net::lookup_host`)
//! on every connection, with no cache of our own: `/etc/hosts` edits and
//! DNS changes are seen at once (the e2e harness maps mocked names to
//! loopback that way). The addresses go to [`FlowHandler::server_connect`]
//! and only what it returns is dialled — there is deliberately no
//! blanket refusal of loopback or private addresses here: the peer guard
//! applies to grant-only hosts, and that scoping is the handler's.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpStream;

use super::h1;
use super::io::{BoxIo, Buffered};
use super::tls::{UpstreamTls, server_name};
use super::{ConnInfo, ConnectDecision, ConnectTarget, FlowHandler, UpstreamError};
use crate::message::{Request, Response};

/// How long one TCP connect attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// An open upstream HTTP connection.
pub(crate) enum UpstreamConn {
    /// HTTP/1 (also: no ALPN, or plain TCP).
    H1(Buffered),
    /// HTTP/2, multiplexed.
    H2(h2::client::SendRequest<Bytes>),
}

/// Every address `host` resolves to (an address literal is itself), in
/// resolver order, duplicates removed.
pub(crate) async fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let answers = tokio::net::lookup_host((bare, port))
        .await
        .map_err(|e| e.to_string())?;
    let mut out: Vec<IpAddr> = Vec::new();
    for addr in answers {
        if !out.contains(&addr.ip()) {
            out.push(addr.ip());
        }
    }
    if out.is_empty() {
        return Err("no addresses".into());
    }
    Ok(out)
}

/// Resolve `target`, let the handler vet the answers, and connect to the
/// first allowed address that accepts.
pub(crate) async fn connect_vetted<H: FlowHandler>(
    handler: &H,
    conn: &ConnInfo,
    target: &ConnectTarget,
    resolved: Option<Vec<IpAddr>>,
) -> Result<TcpStream, UpstreamError> {
    let resolved =
        match resolved {
            Some(addrs) => addrs,
            None => resolve(&target.host, target.port).await.map_err(|error| {
                UpstreamError::Resolve {
                    host: target.host.clone(),
                    error,
                }
            })?,
        };
    let allowed = match handler.server_connect(conn, target, &resolved) {
        ConnectDecision::Allow(addrs) => addrs,
        ConnectDecision::Refuse(reason) => return Err(UpstreamError::Refused(reason)),
    };
    let display = super::host_port("", &target.host, target.port);
    let mut last = String::from("no address allowed");
    for ip in allowed {
        let addr = SocketAddr::new(ip, target.port);
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "connection timed out".into(),
        }
    }
    Err(UpstreamError::Connect {
        target: display,
        error: last,
    })
}

/// Open an HTTP connection to `target`, over TLS (verified against
/// `sni`, offering `alpn`) when `tls` is set.
pub(crate) async fn open<H: FlowHandler>(
    handler: &H,
    conn: &ConnInfo,
    upstream_tls: &Arc<UpstreamTls>,
    target: &ConnectTarget,
    tls: bool,
    alpn: &[Vec<u8>],
) -> Result<UpstreamConn, UpstreamError> {
    let tcp = connect_vetted(handler, conn, target, None).await?;
    if !tls {
        return Ok(UpstreamConn::H1(Buffered::new(Box::new(tcp))));
    }
    let config = upstream_tls
        .client_config(alpn)
        .map_err(|e| UpstreamError::Tls(e.to_string()))?;
    let name =
        server_name(target.sni.as_deref().unwrap_or(&target.host)).map_err(UpstreamError::Tls)?;
    let stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|e| UpstreamError::Tls(e.to_string()))?;
    let negotiated = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let io: BoxIo = Box::new(stream);
    if negotiated.as_deref() == Some(b"h2") {
        Ok(UpstreamConn::H2(super::h2::client(io).await?))
    } else {
        Ok(UpstreamConn::H1(Buffered::new(io)))
    }
}

/// The outcome of one HTTP/1 exchange with an upstream.
pub(crate) struct H1Exchange {
    pub(crate) response: Response,
    /// The connection may carry another request.
    pub(crate) reusable: bool,
}

/// Send `req` on an HTTP/1 upstream connection and read the response
/// (interim `1xx` responses other than `101` are skipped). On error, the
/// flag says whether nothing was received — a dead keep-alive connection,
/// so a retry on a fresh one is safe.
pub(crate) async fn send_h1(
    up: &mut Buffered,
    req: &Request,
    max: usize,
) -> Result<H1Exchange, (UpstreamError, bool)> {
    let protocol = |e: String| UpstreamError::Protocol(e);
    if let Err(e) = up.write_all(&h1::encode_request(req)).await {
        return Err((protocol(e.to_string()), true));
    }
    loop {
        let head = match h1::read_head(up).await {
            Ok(head) => head,
            Err(h1::ReadError::Eof) => {
                return Err((protocol("server closed connection".into()), true));
            }
            Err(h1::ReadError::Io(e)) => return Err((protocol(e.to_string()), true)),
            Err(e) => return Err((protocol(e.to_string()), false)),
        };
        let parsed = h1::parse_response_head(&head).map_err(|e| (protocol(e), false))?;
        if (100..=199).contains(&parsed.status) && parsed.status != 101 {
            continue;
        }
        h1::validate_framing(&parsed.headers, &parsed.version, Some(parsed.status)).map_err(
            |e| {
                (
                    protocol(format!(
                        "Received {e} from server, refusing to prevent request smuggling attacks."
                    )),
                    false,
                )
            },
        )?;
        let framing = h1::response_framing(&req.method, parsed.status, &parsed.headers)
            .map_err(|e| (protocol(e), false))?;
        let body = h1::read_body(up, framing, max).await.map_err(|e| match e {
            h1::ReadError::BodyTooLarge => {
                (UpstreamError::ResponseBodyTooLarge { limit: max }, false)
            }
            other => (protocol(other.to_string()), false),
        })?;
        let reusable = parsed.status != 101
            && framing != h1::Framing::UntilEof
            && !h1::connection_close(&req.http_version, &req.headers)
            && !h1::connection_close(&parsed.version, &parsed.headers)
            && req.http_version.starts_with("HTTP/1");
        return Ok(H1Exchange {
            response: Response {
                status: parsed.status,
                reason: parsed.reason,
                http_version: parsed.version,
                headers: parsed.headers,
                body,
            },
            reusable,
        });
    }
}
