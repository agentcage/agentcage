//! HTTP/2 on both sides, translated to and from [`Request`] / [`Response`].
//!
//! The HTTP/2 `:authority` is carried as a `Host` header (inserted first
//! when the client sent none), so the pipeline reads one field whatever the
//! protocol; going out over HTTP/2 the first `Host` value becomes
//! `:authority` again. Messages crossing from HTTP/1 lose the headers
//! HTTP/2 forbids (`Connection` and the ones it names as hop-by-hop,
//! `Transfer-Encoding`, `Upgrade`, a `TE` other than `trailers`) and their
//! names are lowercased, as HTTP/2 requires.

use std::sync::Arc;

use bytes::Bytes;
use h2::RecvStream;
use http::{HeaderName, HeaderValue};

use super::conn::{self, Shared};
use super::io::BoxIo;
use super::{ConnInfo, FlowHandler, Refusal, StreamOutcome, UpstreamError, host_port};
use crate::message::{Headers, Request, Response};

/// Headers that are meaningless (and illegal) in HTTP/2.
fn connection_specific(name: &[u8], value: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_slice(),
        b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade"
    ) || (lower == b"te" && !value.eq_ignore_ascii_case(b"trailers"))
}

/// Why an HTTP/2 body could not be read.
pub(crate) enum BodyError {
    TooLarge,
    Budget,
    Stream(h2::Error),
}

/// The declared `content-length` of a head, if it has a valid one.
fn declared_length(headers: &http::HeaderMap) -> Option<usize> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Read a whole HTTP/2 body, returning flow-control credit as it goes.
///
/// Every byte is reserved on `budget` before it is buffered, and every
/// allocation is fallible (see [`super::h1::read_body`]). With a declared
/// `content-length` the body is refused before a byte is read when it is
/// over `max`, and otherwise read into one allocation of exactly that
/// size (the codec itself enforces that the stream carries exactly that
/// many bytes); without one it grows by a quarter at a time.
pub(crate) async fn read_body(
    body: &mut RecvStream,
    max: usize,
    declared: Option<usize>,
    budget: &mut super::budget::Reservation,
) -> Result<Vec<u8>, BodyError> {
    let mut out = Vec::new();
    if let Some(n) = declared {
        if n > max {
            return Err(BodyError::TooLarge);
        }
        if !budget.grow_to(n).await {
            return Err(BodyError::Budget);
        }
        out.try_reserve_exact(n).map_err(|_| BodyError::Budget)?;
    }
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(BodyError::Stream)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        if out.len() + chunk.len() > max {
            return Err(BodyError::TooLarge);
        }
        if !budget.make_room(&mut out, chunk.len()).await {
            return Err(BodyError::Budget);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn to_headers(map: &http::HeaderMap) -> Headers {
    Headers(
        map.iter()
            .map(|(k, v)| (k.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect(),
    )
}

fn to_header_map(headers: &Headers, skip_host: bool) -> Result<http::HeaderMap, String> {
    let mut map = http::HeaderMap::new();
    for (name, value) in &headers.0 {
        if connection_specific(name, value) || (skip_host && name.eq_ignore_ascii_case(b"host")) {
            continue;
        }
        let name = HeaderName::from_bytes(&name.to_ascii_lowercase()).map_err(|e| {
            format!(
                "invalid header name {:?}: {e}",
                String::from_utf8_lossy(name)
            )
        })?;
        let value =
            HeaderValue::from_bytes(value).map_err(|e| format!("invalid header value: {e}"))?;
        map.append(name, value);
    }
    Ok(map)
}

/// The request as the pipeline sees it, from an HTTP/2 request head and
/// its body. Destination fields come from the connection.
pub(crate) fn request_from_h2(
    head: &http::request::Parts,
    body: Vec<u8>,
    conn: &ConnInfo,
) -> Request {
    let mut headers = to_headers(&head.headers);
    if let Some(authority) = head.uri.authority()
        && !headers.contains("host")
    {
        headers.0.insert(
            0,
            (b"host".to_vec(), authority.as_str().as_bytes().to_vec()),
        );
    }
    let (host, port) = match &conn.server_addr {
        Some(addr) => (addr.host.clone(), addr.port),
        None => (String::new(), 0),
    };
    let scheme = match conn.listener {
        // A reverse listener speaks plain HTTP to the cage whatever the
        // client used.
        super::ListenerKind::Reverse => "http",
        _ if conn.tls => "https",
        _ => "http",
    };
    Request {
        method: head.method.as_str().to_string(),
        scheme: scheme.to_string(),
        host,
        port,
        path: head
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), |p| p.as_str().to_string()),
        http_version: "HTTP/2.0".to_string(),
        headers,
        body,
    }
}

/// An HTTP/2 request head for `req`.
pub(crate) fn request_to_h2(req: &Request) -> Result<http::Request<()>, String> {
    let authority = req
        .headers
        .get_all("host")
        .into_iter()
        .next()
        .unwrap_or_else(|| host_port(&req.scheme, &req.host, req.port));
    let path = if req.path.is_empty() { "/" } else { &req.path };
    let uri: http::Uri = format!("{}://{}{}", req.scheme, authority, path)
        .parse()
        .map_err(|e| format!("invalid request target: {e}"))?;
    let mut out = http::Request::builder()
        .method(req.method.as_str())
        .uri(uri)
        .version(http::Version::HTTP_2)
        .body(())
        .map_err(|e| format!("invalid request: {e}"))?;
    *out.headers_mut() = to_header_map(&req.headers, true)?;
    Ok(out)
}

/// The response as the pipeline sees it, from an HTTP/2 response head.
pub(crate) fn response_from_h2(head: &http::response::Parts, body: Vec<u8>) -> Response {
    Response {
        status: head.status.as_u16(),
        reason: String::new(),
        http_version: "HTTP/2.0".to_string(),
        headers: to_headers(&head.headers),
        body,
    }
}

/// An HTTP/2 response head for `resp` to a `method` request; a
/// `content-length` is corrected (or added) for the body actually sent.
pub(crate) fn response_to_h2(resp: &Response, method: &str) -> Result<http::Response<()>, String> {
    let mut headers = resp.headers.clone();
    if super::h1::response_has_body(method, resp.status) {
        if headers.contains("content-length") {
            headers.set("content-length", resp.body.len().to_string());
        } else {
            headers.add("content-length", resp.body.len().to_string());
        }
    }
    let mut out = http::Response::builder()
        .status(resp.status)
        .version(http::Version::HTTP_2)
        .body(())
        .map_err(|e| format!("invalid response: {e}"))?;
    *out.headers_mut() = to_header_map(&headers, false)?;
    Ok(out)
}

/// Aborts a task when dropped: the request-body sender of an HTTP/2
/// upstream stream, which outlives nothing of its exchange.
#[derive(Debug)]
pub(crate) struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Send `req` on an HTTP/2 upstream connection and wait for the response
/// head: the head (empty body), the body stream, and the task still
/// sending the request body, if any.
///
/// The request body is handed to the codec as `Bytes` without a copy
/// (`req.body` is moved out and put back afterwards, without a copy once
/// the codec has let go of it), a window at a time as the server's flow
/// control admits it. It is sent by its own task, concurrently with the
/// wait for the response: a server that answers before reading the whole
/// upload (an early 413) would otherwise never be heard, the sender
/// waiting for window the server will not open.
pub(crate) async fn send_head(
    sender: &h2::client::SendRequest<Bytes>,
    req: &mut Request,
) -> Result<(Response, RecvStream, Option<AbortOnDrop>), UpstreamError> {
    let protocol = |e: h2::Error| UpstreamError::Protocol(e.to_string());
    let head = request_to_h2(req).map_err(UpstreamError::Protocol)?;
    let mut sender = sender.clone().ready().await.map_err(protocol)?;
    let empty = req.body.is_empty();
    let (response, mut stream) = sender.send_request(head, empty).map_err(protocol)?;
    let sending = (!empty).then(|| {
        let body = Bytes::from(std::mem::take(&mut req.body));
        let data = body.clone();
        let task = tokio::spawn(async move {
            let _ = send_body(&mut stream, data, true).await;
        });
        (AbortOnDrop(task), body)
    });
    let response = response.await;
    let sending = sending.map(|(task, body)| {
        req.body = Vec::from(body);
        task
    });
    let (parts, recv) = response.map_err(protocol)?.into_parts();
    Ok((response_from_h2(&parts, Vec::new()), recv, sending))
}

/// Read a whole upstream response body (the buffered path).
pub(crate) async fn read_response_body(
    recv: &mut RecvStream,
    headers: &crate::message::Headers,
    max: usize,
    budget: &mut super::budget::Reservation,
) -> Result<Vec<u8>, UpstreamError> {
    let declared = headers
        .get("content-length")
        .and_then(|v| v.trim().parse().ok());
    let limit = budget.limit();
    read_body(recv, max, declared, budget)
        .await
        .map_err(|e| match e {
            BodyError::TooLarge => UpstreamError::ResponseBodyTooLarge { limit: max },
            BodyError::Budget => UpstreamError::BodyBudgetExhausted { limit },
            BodyError::Stream(e) => UpstreamError::Protocol(e.to_string()),
        })
}

/// Send `data` on `stream` (ending it when `end`), a window's worth at a
/// time as the peer's flow control admits it, so the whole body is never
/// queued in the codec at once and the caller holds its budget until it
/// is out.
async fn send_body(
    stream: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end: bool,
) -> Result<(), h2::Error> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let granted = match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(granted) => granted?,
            None => return Ok(()),
        };
        if granted == 0 {
            continue;
        }
        let chunk = data.split_to(granted.min(data.len()));
        stream.send_data(chunk, end && data.is_empty())?;
    }
    Ok(())
}

/// The per-stream receive window advertised on both sides.
///
/// HTTP/2's default is 64 KiB, and a receiver can never have more than
/// one window in flight, so with the default a single download runs at
/// one window per round trip: about 2.5 MB/s at 25 ms, a twentieth of
/// what the same link does over HTTP/1. A buffered body uses the memory
/// anyway; a streamed one returns credit only as its pieces reach the
/// client, so at most one window per stream sits in the codec.
const STREAM_WINDOW: u32 = 8 * 1024 * 1024;

/// The connection-level receive window: room for a few streams at full
/// speed at once.
const CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;

/// Open an HTTP/2 client session on an upstream stream.
pub(crate) async fn client(io: BoxIo) -> Result<h2::client::SendRequest<Bytes>, UpstreamError> {
    let (sender, connection) = h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake(io)
        .await
        .map_err(|e| UpstreamError::Protocol(e.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

/// Serve an HTTP/2 client: every stream is one exchange, concurrently.
pub(crate) async fn serve<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    conn: Arc<ConnInfo>,
    io: BoxIo,
    alpn_offers: Arc<Vec<Vec<u8>>>,
) {
    let mut session = match h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake(io)
        .await
    {
        Ok(session) => session,
        Err(e) => {
            // A client that rejects the leaf certificate does so after our
            // side of the TLS handshake has completed (TLS 1.3), so what
            // reaches here is a connection that closed before the HTTP/2
            // preface. Say what that usually means: the bare h2 error
            // reads like an egress fault.
            let hint = if conn.tls {
                format!(
                    " (the client closed the TLS session before sending a request; \
                     if it reported a certificate error, it does not trust the cage CA \
                     for {}: point it at /certs/agentcage-ca.pem)",
                    conn.sni.as_deref().unwrap_or("this host")
                )
            } else {
                String::new()
            };
            eprintln!(
                "agentcage-egress: conn {}: HTTP/2 handshake failed: {e}{hint}",
                conn.id
            );
            return;
        }
    };
    while let Some(next) = session.accept().await {
        let Ok((request, respond)) = next else { break };
        let shared = Arc::clone(&shared);
        let conn = Arc::clone(&conn);
        let offers = Arc::clone(&alpn_offers);
        tokio::spawn(async move {
            stream(shared, conn, request, respond, offers).await;
        });
    }
}

/// What an HTTP/2 client stream gets: a whole response, or a head and a
/// body relayed as it arrives.
// Built once per stream and matched on at once, like `conn::Exchanged`;
// boxing the streamed case would only add an allocation.
#[allow(clippy::large_enum_variant)]
enum Answer<F> {
    Whole(Response),
    Streamed {
        resp: Response,
        flow: F,
        stream: Box<dyn super::ResponseStream>,
        body: conn::UpstreamBody,
    },
}

async fn stream<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    conn: Arc<ConnInfo>,
    request: http::Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    offers: Arc<Vec<Vec<u8>>>,
) {
    let max = shared.settings.load().max_body;
    let (parts, mut body) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let declared = declared_length(&parts.headers);
    // Held until the response body has been handed to the codec.
    let mut req_budget = super::budget::Reservation::new(&shared.budget);
    let mut resp_budget = super::budget::Reservation::new(&shared.budget);
    let mut refused_body = false;
    let answer = match read_body(&mut body, max, declared, &mut req_budget).await {
        Ok(body) => {
            let req = request_from_h2(&parts, body, &conn);
            match conn::exchange(&shared, &conn, req, &offers, &mut resp_budget).await {
                conn::Exchanged::Done(resp) | conn::Exchanged::RawUpgrade(resp) => {
                    Answer::Whole(resp)
                }
                conn::Exchanged::Upgrade { resp, flow, .. } => {
                    // HTTP/2 has no 101; the upstream should never send one.
                    shared
                        .handler
                        .flow_end(&conn, flow, super::FlowEnd::Completed);
                    Answer::Whole(resp)
                }
                conn::Exchanged::Stream {
                    resp,
                    flow,
                    stream,
                    body,
                } => Answer::Streamed {
                    resp,
                    flow,
                    stream,
                    body,
                },
            }
        }
        Err(BodyError::TooLarge) => {
            refused_body = true;
            let req = request_from_h2(&parts, Vec::new(), &conn);
            Answer::Whole(shared.handler.transport_refusal(
                &conn,
                Some(&req),
                &Refusal::RequestBodyTooLarge { limit: max },
            ))
        }
        Err(BodyError::Budget) => {
            refused_body = true;
            let req = request_from_h2(&parts, Vec::new(), &conn);
            Answer::Whole(shared.handler.transport_refusal(
                &conn,
                Some(&req),
                &Refusal::BodyBudgetExhausted {
                    limit: shared.budget.limit(),
                },
            ))
        }
        Err(BodyError::Stream(_)) => return,
    };
    let response = match answer {
        Answer::Whole(response) => response,
        Answer::Streamed {
            resp,
            flow,
            stream,
            body,
        } => {
            // The request body is not needed any more.
            drop(req_budget);
            relay(&shared, &conn, &mut respond, &resp, flow, stream, body).await;
            return;
        }
    };
    let Ok(head) = response_to_h2(&response, &method) else {
        respond.send_reset(h2::Reason::INTERNAL_ERROR);
        return;
    };
    let has_body =
        super::h1::response_has_body(&method, response.status) && !response.body.is_empty();
    match respond.send_response(head, !has_body) {
        Ok(mut stream) if has_body => {
            let _ = send_body(&mut stream, Bytes::from(response.body), true).await;
        }
        _ => {}
    }
    // The body is in the codec's hands only now: the budget is released
    // here, not when it was queued whole.
    drop((req_budget, resp_budget));
    if refused_body {
        drain_refused(&mut body, &mut respond).await;
    }
}

/// The client is still uploading a body we refused. Dropping the request
/// stream now would reset it with CANCEL, which discards the queued
/// refusal: the client would see a framing error, not the 413/503.
/// Discard what it sends for a moment so the refusal goes out, then tell
/// it to stop with `NO_ERROR` (RFC 9113 8.1).
async fn drain_refused(body: &mut RecvStream, respond: &mut h2::server::SendResponse<Bytes>) {
    let drain = async {
        while let Some(Ok(chunk)) = body.data().await {
            let _ = body.flow_control().release_capacity(chunk.len());
        }
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), drain).await;
    respond.send_reset(h2::Reason::NO_ERROR);
}

/// The HTTP/2 head of a streamed response: a `content-length` kept only
/// when the body goes out unchanged.
fn stream_head_to_h2(resp: &Response, keep_length: bool) -> Result<http::Response<()>, String> {
    let mut headers = resp.headers.clone();
    if !keep_length {
        headers.remove("content-length");
    }
    let mut out = http::Response::builder()
        .status(resp.status)
        .version(http::Version::HTTP_2)
        .body(())
        .map_err(|e| format!("invalid response: {e}"))?;
    *out.headers_mut() = to_header_map(&headers, false)?;
    Ok(out)
}

/// Relay a streamed response to an HTTP/2 client: DATA frames as pieces
/// come, sent as the client's flow control admits them; a failure
/// mid-body resets the stream.
async fn relay<H: FlowHandler>(
    shared: &Shared<H>,
    conn: &ConnInfo,
    respond: &mut h2::server::SendResponse<Bytes>,
    resp: &Response,
    flow: H::Flow,
    mut stream: Box<dyn super::ResponseStream>,
    mut body: conn::UpstreamBody,
) {
    let mut reservation = super::budget::Reservation::new(&shared.budget);
    let mut ended = false;
    let head = stream_head_to_h2(resp, stream.passthrough());
    let outcome = match head.map(|head| respond.send_response(head, false)) {
        Err(reason) => {
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            StreamOutcome::Refused(reason)
        }
        Ok(Err(_)) => StreamOutcome::ClientGone,
        Ok(Ok(mut out)) => loop {
            match conn::next_piece(&mut *stream, &mut body, &mut ended, &mut reservation).await {
                Ok(Some(piece)) => {
                    if send_body(&mut out, piece, false).await.is_err() {
                        break StreamOutcome::ClientGone;
                    }
                }
                Ok(None) => {
                    if out.send_data(Bytes::new(), true).is_err() {
                        break StreamOutcome::ClientGone;
                    }
                    break StreamOutcome::Completed;
                }
                Err(outcome) => {
                    out.send_reset(h2::Reason::INTERNAL_ERROR);
                    break outcome;
                }
            }
        },
    };
    let completed = outcome == StreamOutcome::Completed;
    let end = conn::stream_flow_end(&outcome);
    stream.close(outcome);
    shared.handler.flow_end(conn, flow, end);
    if completed {
        // An HTTP/1 upstream read to its end can serve the next request.
        let _ = body.finish(resp.status, &shared.pool);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h1_requests_lose_hop_by_hop_headers_and_get_an_authority() {
        let mut req = Request {
            method: "GET".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            port: 443,
            path: "/a?b".into(),
            http_version: "HTTP/1.1".into(),
            ..Request::default()
        };
        for (k, v) in [
            ("Host", "example.com"),
            ("Connection", "keep-alive"),
            ("TE", "gzip"),
            ("X-Custom", "1"),
            ("Transfer-Encoding", "chunked"),
        ] {
            req.headers.add(k, v);
        }
        let h2 = request_to_h2(&req).unwrap();
        assert_eq!(h2.uri().authority().unwrap().as_str(), "example.com");
        assert_eq!(h2.uri().path_and_query().unwrap().as_str(), "/a?b");
        let names: Vec<_> = h2.headers().keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["x-custom"]);
    }
}
