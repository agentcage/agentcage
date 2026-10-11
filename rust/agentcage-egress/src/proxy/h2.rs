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
use super::{ConnInfo, FlowHandler, Refusal, UpstreamError, host_port};
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
    Stream(h2::Error),
}

/// Read a whole HTTP/2 body, returning flow-control credit as it goes.
pub(crate) async fn read_body(body: &mut RecvStream, max: usize) -> Result<Vec<u8>, BodyError> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(BodyError::Stream)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        if out.len() + chunk.len() > max {
            return Err(BodyError::TooLarge);
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
    if let Some(authority) = head.uri.authority() {
        if !headers.contains("host") {
            headers.0.insert(
                0,
                (b"host".to_vec(), authority.as_str().as_bytes().to_vec()),
            );
        }
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

/// Send `req` on an HTTP/2 upstream connection and read the response.
pub(crate) async fn send(
    sender: &h2::client::SendRequest<Bytes>,
    req: &Request,
    max: usize,
) -> Result<Response, UpstreamError> {
    let protocol = |e: h2::Error| UpstreamError::Protocol(e.to_string());
    let head = request_to_h2(req).map_err(UpstreamError::Protocol)?;
    let mut sender = sender.clone().ready().await.map_err(protocol)?;
    let (response, mut stream) = sender
        .send_request(head, req.body.is_empty())
        .map_err(protocol)?;
    if !req.body.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(&req.body), true)
            .map_err(protocol)?;
    }
    let response = response.await.map_err(protocol)?;
    let (parts, mut body) = response.into_parts();
    let body = read_body(&mut body, max).await.map_err(|e| match e {
        BodyError::TooLarge => UpstreamError::ResponseBodyTooLarge { limit: max },
        BodyError::Stream(e) => protocol(e),
    })?;
    Ok(response_from_h2(&parts, body))
}

/// Open an HTTP/2 client session on an upstream stream.
pub(crate) async fn client(io: BoxIo) -> Result<h2::client::SendRequest<Bytes>, UpstreamError> {
    let (sender, connection) = h2::client::handshake(io)
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
    let mut session = match h2::server::handshake(io).await {
        Ok(session) => session,
        Err(e) => {
            eprintln!(
                "agentcage-egress: conn {}: HTTP/2 handshake failed: {e}",
                conn.id
            );
            return;
        }
    };
    let pool = conn::UpstreamPool::default();
    while let Some(next) = session.accept().await {
        let Ok((request, respond)) = next else { break };
        let shared = Arc::clone(&shared);
        let conn = Arc::clone(&conn);
        let pool = pool.clone();
        let offers = Arc::clone(&alpn_offers);
        tokio::spawn(async move {
            stream(shared, conn, request, respond, pool, offers).await;
        });
    }
}

async fn stream<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    conn: Arc<ConnInfo>,
    request: http::Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    pool: conn::UpstreamPool,
    offers: Arc<Vec<Vec<u8>>>,
) {
    let max = shared.settings.load().max_body;
    let (parts, mut body) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let response = match read_body(&mut body, max).await {
        Ok(body) => {
            let req = request_from_h2(&parts, body, &conn);
            let mut slot = None;
            match conn::exchange(&shared, &conn, req, &pool, &mut slot, &offers).await {
                conn::Exchanged::Done(resp) | conn::Exchanged::RawUpgrade(resp) => resp,
                conn::Exchanged::Upgrade { resp, flow, .. } => {
                    // HTTP/2 has no 101; the upstream should never send one.
                    shared
                        .handler
                        .flow_end(&conn, flow, super::FlowEnd::Completed);
                    resp
                }
            }
        }
        Err(BodyError::TooLarge) => {
            let req = request_from_h2(&parts, Vec::new(), &conn);
            shared.handler.transport_refusal(
                &conn,
                Some(&req),
                &Refusal::RequestBodyTooLarge { limit: max },
            )
        }
        Err(BodyError::Stream(_)) => return,
    };
    let Ok(head) = response_to_h2(&response, &method) else {
        respond.send_reset(h2::Reason::INTERNAL_ERROR);
        return;
    };
    let has_body =
        super::h1::response_has_body(&method, response.status) && !response.body.is_empty();
    match respond.send_response(head, !has_body) {
        Ok(mut stream) if has_body => {
            let _ = stream.send_data(Bytes::from(response.body), true);
        }
        _ => {}
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
