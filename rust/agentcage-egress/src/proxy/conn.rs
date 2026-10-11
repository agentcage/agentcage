//! One client connection, from the first byte to the last.
//!
//! The decision sequence follows the replaced implementation's layer
//! stack. A transparent connection (or the inside of a `CONNECT` tunnel)
//! is peeked at; a passthrough destination is spliced raw; TLS is
//! terminated with a leaf minted from the `ClientHello`; what is inside is
//! served as HTTP/2 or HTTP/1 by ALPN, else sniffed, and anything that is
//! not HTTP goes to the bypass hook and is closed. The forward listener
//! speaks plaintext HTTP/1 (`CONNECT` and absolute-form); a reverse
//! listener serves HTTP (plain or TLS) to the cage address.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use bytes::Bytes;
use tokio::net::TcpStream;

use super::detect::{self, ClientHello, Plain};
use super::io::{BoxIo, Buffered};
use super::tls::{UpstreamTls, server_config};
use super::upstream::{self, UpstreamConn};
use super::{
    ConnInfo, ConnectPurpose, ConnectTarget, FlowEnd, FlowHandler, ListenerKind, Refusal,
    RequestAction, ServerAddr, TransportSettings, UpstreamError, h1, parse_authority,
};
use crate::ca::{CertAuthority, LeafName};
use crate::message::{Request, Response};

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// What every connection task shares.
pub(crate) struct Shared<H> {
    pub(crate) handler: Arc<H>,
    pub(crate) ca: Arc<CertAuthority>,
    pub(crate) upstream_tls: Arc<UpstreamTls>,
    pub(crate) settings: Arc<ArcSwap<TransportSettings>>,
}

/// Which upstream an HTTP connection may be reused for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamKey {
    host: String,
    port: u16,
    tls: bool,
    sni: Option<String>,
}

/// HTTP/2 upstream sessions of one client connection, shared by its
/// streams.
#[derive(Clone, Default)]
pub(crate) struct UpstreamPool(Arc<Mutex<HashMap<UpstreamKey, h2::client::SendRequest<Bytes>>>>);

impl UpstreamPool {
    fn get(&self, key: &UpstreamKey) -> Option<h2::client::SendRequest<Bytes>> {
        self.0.lock().ok()?.get(key).cloned()
    }

    fn put(&self, key: UpstreamKey, sender: h2::client::SendRequest<Bytes>) {
        if let Ok(mut map) = self.0.lock() {
            map.insert(key, sender);
        }
    }

    fn forget(&self, key: &UpstreamKey) {
        if let Ok(mut map) = self.0.lock() {
            map.remove(key);
        }
    }
}

/// An idle HTTP/1 upstream connection kept for the next request.
pub(crate) type H1Slot = Option<(UpstreamKey, Buffered)>;

/// The result of running one request through the handler and upstream.
// Built once per request and matched on at once; boxing the upgrade case
// would only add an allocation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Exchanged<F> {
    /// Send this response; the flow (if any) has ended.
    Done(Response),
    /// Send this `101` and relay WebSocket messages; the flow continues.
    Upgrade {
        resp: Response,
        flow: F,
        req: Request,
        upstream: Buffered,
    },
    /// Send this `101`, then treat the connection as a TCP bypass.
    RawUpgrade(Response),
}

pub(crate) fn is_websocket(req: &Request, resp: &Response) -> bool {
    resp.status == 101
        && resp
            .headers
            .get("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        && req.headers.get("sec-websocket-version").as_deref() == Some("13")
}

fn is_websocket_request(req: &Request) -> bool {
    req.headers
        .get("upgrade")
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
}

/// Drop an `h2c` upgrade offer: the proxy speaks HTTP/2 only over TLS,
/// and an endpoint switching protocols mid-connection would break it.
fn strip_h2c(req: &mut Request) {
    if req.headers.get("upgrade").as_deref() == Some("h2c") {
        req.headers.remove("upgrade");
        req.headers.remove("connection");
        req.headers.remove("http2-settings");
    }
}

/// The SNI an upstream TLS connection carries: the client's own SNI when
/// the request still goes to the address the client connected to,
/// otherwise the (re-targeted) host name.
fn upstream_sni(conn: &ConnInfo, req: &Request) -> Option<String> {
    if req.scheme != "https" {
        return None;
    }
    match &conn.server_addr {
        Some(addr) if addr.host == req.host => conn.sni.clone().or_else(|| Some(req.host.clone())),
        _ => Some(req.host.clone()),
    }
}

/// Run `req` through the handler and, when it is forwarded, the upstream.
pub(crate) async fn exchange<H: FlowHandler>(
    shared: &Shared<H>,
    conn: &ConnInfo,
    mut req: Request,
    pool: &UpstreamPool,
    slot: &mut H1Slot,
    alpn_offers: &[Vec<u8>],
) -> Exchanged<H::Flow> {
    let handler = &*shared.handler;
    strip_h2c(&mut req);
    if let Some(resp) = handler.intercept(conn, &mut req).await {
        return Exchanged::Done(resp);
    }
    let mut flow = match handler.request(conn, &mut req).await {
        RequestAction::Respond(resp) => return Exchanged::Done(resp),
        RequestAction::Forward(flow) => flow,
    };
    let websocket = is_websocket_request(&req);
    if websocket {
        // Messages are relayed whole and uncompressed; an extension the
        // relay does not implement must not be negotiated.
        req.headers.remove("sec-websocket-extensions");
    }
    let max = shared.settings.load().max_body;
    let tls = req.scheme == "https";
    let key = UpstreamKey {
        host: req.host.clone(),
        port: req.port,
        tls,
        sni: upstream_sni(conn, &req),
    };
    let offers: Vec<Vec<u8>> = if !tls || !conn.tls {
        Vec::new()
    } else if websocket && !alpn_offers.is_empty() {
        // A WebSocket upgrade needs HTTP/1 upstream.
        vec![b"http/1.1".to_vec()]
    } else {
        alpn_offers.to_vec()
    };
    let result = send(shared, conn, &req, &key, &offers, pool, slot, max).await;
    let (mut resp, upgraded) = match result {
        Ok(ok) => ok,
        Err(err) => return Exchanged::Done(handler.upstream_error(conn, flow, &req, &err)),
    };
    handler.response(conn, &mut flow, &mut req, &mut resp).await;
    if resp.status == 101 {
        if let (true, Some(upstream)) = (is_websocket(&req, &resp), upgraded) {
            return Exchanged::Upgrade {
                resp,
                flow,
                req,
                upstream,
            };
        }
        handler.flow_end(conn, flow, FlowEnd::Completed);
        return Exchanged::RawUpgrade(resp);
    }
    handler.flow_end(conn, flow, FlowEnd::Completed);
    Exchanged::Done(resp)
}

/// Send on a reused connection when there is one (retrying once on a
/// fresh connection when a reused one turns out dead), else on a new one.
/// A `101` comes back with its connection for the upgrade.
#[allow(clippy::too_many_arguments)]
async fn send<H: FlowHandler>(
    shared: &Shared<H>,
    conn: &ConnInfo,
    req: &Request,
    key: &UpstreamKey,
    offers: &[Vec<u8>],
    pool: &UpstreamPool,
    slot: &mut H1Slot,
    max: usize,
) -> Result<(Response, Option<Buffered>), UpstreamError> {
    if let Some(sender) = pool.get(key) {
        match super::h2::send(&sender, req, max).await {
            Ok(resp) => return Ok((resp, None)),
            Err(UpstreamError::Protocol(_)) => pool.forget(key),
            Err(other) => return Err(other),
        }
    }
    let reused = match slot.take() {
        Some((slot_key, up)) if slot_key == *key => Some(up),
        _ => None,
    };
    if let Some(mut up) = reused {
        match upstream::send_h1(&mut up, req, max).await {
            Ok(done) => return Ok(finish_h1(done, up, key, slot)),
            Err((_, true)) => {}
            Err((err, false)) => return Err(err),
        }
    }
    let target = ConnectTarget {
        host: req.host.clone(),
        port: req.port,
        sni: key.sni.clone(),
        purpose: ConnectPurpose::Http,
    };
    match upstream::open(
        &*shared.handler,
        conn,
        &shared.upstream_tls,
        &target,
        key.tls,
        offers,
    )
    .await?
    {
        UpstreamConn::H2(sender) => {
            let resp = super::h2::send(&sender, req, max).await?;
            pool.put(key.clone(), sender);
            Ok((resp, None))
        }
        UpstreamConn::H1(mut up) => {
            let done = upstream::send_h1(&mut up, req, max)
                .await
                .map_err(|(err, _)| err)?;
            Ok(finish_h1(done, up, key, slot))
        }
    }
}

fn finish_h1(
    done: upstream::H1Exchange,
    up: Buffered,
    key: &UpstreamKey,
    slot: &mut H1Slot,
) -> (Response, Option<Buffered>) {
    if done.response.status == 101 {
        return (done.response, Some(up));
    }
    if done.reusable {
        *slot = Some((key.clone(), up));
    }
    (done.response, None)
}

/// Serve one accepted TCP connection.
pub(crate) async fn handle<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    stream: TcpStream,
    listener: ListenerKind,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    server_addr: Option<ServerAddr>,
) {
    let _ = stream.set_nodelay(true);
    let info = ConnInfo {
        id: NEXT_CONN.fetch_add(1, Ordering::Relaxed),
        listener,
        client_addr,
        local_addr,
        server_addr,
        via_connect: false,
        sni: None,
        tls: false,
        alpn: None,
    };
    let client = Buffered::new(Box::new(stream));
    match listener {
        ListenerKind::Regular => {
            serve_h1(shared, Arc::new(info), client, Arc::new(Vec::new())).await;
        }
        ListenerKind::Transparent => intercept(shared, info, client).await,
        ListenerKind::Reverse => reverse(shared, info, client).await,
    }
}

fn log(conn: &ConnInfo, message: &str) {
    eprintln!(
        "agentcage-egress: conn {} from {}: {message}",
        conn.id, conn.client_addr
    );
}

/// What the first client bytes turned out to be.
enum Peeked {
    Tls(ClientHello),
    Http { host_header: Option<String> },
    Other,
}

/// Read until the protocol is known (and, for plaintext HTTP, the `Host`
/// header has been seen). `None` when the client closed first.
async fn peek(client: &mut Buffered) -> Option<Peeked> {
    let mut eof = false;
    loop {
        let data = &client.buf[..];
        if detect::starts_like_tls(data) {
            match detect::parse_client_hello(data) {
                Ok(Some(hello)) => return Some(Peeked::Tls(hello)),
                // A broken hello still goes to the TLS handshake, which
                // fails it.
                Err(_) => return Some(Peeked::Tls(ClientHello::default())),
                Ok(None) if eof => return Some(Peeked::Tls(ClientHello::default())),
                Ok(None) => {}
            }
        } else if data.len() >= 3 || eof {
            match detect::classify_plain(data, eof) {
                Plain::Other => return Some(Peeked::Other),
                Plain::Http => match detect::host_header(data) {
                    Ok(host_header) => return Some(Peeked::Http { host_header }),
                    Err(()) if eof || data.len() > h1::MAX_HEAD => {
                        return Some(Peeked::Http { host_header: None });
                    }
                    Err(()) => {}
                },
                Plain::NeedMore => {}
            }
        }
        if eof {
            return if client.buf.is_empty() {
                None
            } else {
                Some(Peeked::Other)
            };
        }
        match client.fill().await {
            Ok(0) => eof = true,
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

/// The transparent listener and the inside of a `CONNECT` tunnel.
async fn intercept<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    mut info: ConnInfo,
    mut client: Buffered,
) {
    let Some(peeked) = peek(&mut client).await else {
        return;
    };
    let Some(server) = info.server_addr.clone() else {
        log(&info, "no destination address; closing");
        return;
    };
    if let Peeked::Tls(hello) = &peeked {
        info.sni = hello.sni.clone().filter(|s| !s.is_empty());
    }
    let host_header = match &peeked {
        Peeked::Http { host_header } => host_header.clone(),
        _ => None,
    };
    if let Some(resolved) =
        passthrough_decision(&shared, &info, &server, host_header.as_deref()).await
    {
        splice(&shared, &info, &server, resolved, client).await;
        return;
    }
    match peeked {
        Peeked::Other => {
            shared.handler.tcp_bypass(&info);
        }
        Peeked::Http { .. } => {
            serve_h1(shared, Arc::new(info), client, Arc::new(Vec::new())).await;
        }
        Peeked::Tls(hello) => {
            terminate_tls(shared, info, client, &hello, true).await;
        }
    }
}

/// Whether to splice, and to which addresses: `Some(None)` dials the
/// destination by name, `Some(Some(addrs))` dials those vetted addresses.
async fn passthrough_decision<H: FlowHandler>(
    shared: &Shared<H>,
    info: &ConnInfo,
    server: &ServerAddr,
    host_header: Option<&str>,
) -> Option<Option<Vec<IpAddr>>> {
    let handler = &*shared.handler;
    if handler.is_passthrough(info, &server.display()) {
        // The destination itself is a passthrough name (or address):
        // nothing for the cage to spoof.
        return Some(None);
    }
    let mut names: Vec<String> = Vec::new();
    if let Some(header) = host_header {
        let candidate = if header
            .rsplit_once(':')
            .is_some_and(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            header.to_string()
        } else {
            format!("{header}:{}", server.port)
        };
        if handler.is_passthrough(info, &candidate) {
            names.push(parse_authority(header).0);
        }
    }
    if let Some(sni) = &info.sni {
        if handler.is_passthrough(info, &format!("{sni}:{}", server.port)) {
            names.push(sni.clone());
        }
    }
    if names.is_empty() {
        return None;
    }
    // Plan D4: a name the cage chose only earns a splice when the
    // destination is one of that name's addresses; otherwise the flow is
    // intercepted like any other.
    let dest = upstream::resolve(&server.host, server.port).await.ok()?;
    for name in names {
        let Ok(addrs) = upstream::resolve(&name, server.port).await else {
            continue;
        };
        let common: Vec<IpAddr> = dest
            .iter()
            .copied()
            .filter(|ip| addrs.contains(ip))
            .collect();
        if !common.is_empty() {
            return Some(Some(common));
        }
        log(
            info,
            &format!(
                "passthrough refused for {name}: destination {} is not one of its addresses; intercepting",
                server.display()
            ),
        );
    }
    None
}

async fn splice<H: FlowHandler>(
    shared: &Shared<H>,
    info: &ConnInfo,
    server: &ServerAddr,
    resolved: Option<Vec<IpAddr>>,
    client: Buffered,
) {
    let target = ConnectTarget {
        host: server.host.clone(),
        port: server.port,
        sni: info.sni.clone(),
        purpose: ConnectPurpose::Passthrough,
    };
    let mut up = match upstream::connect_vetted(&*shared.handler, info, &target, resolved).await {
        Ok(up) => up,
        Err(e) => {
            log(info, &format!("passthrough to {}: {e}", server.display()));
            return;
        }
    };
    let mut client = client.into_io();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
}

/// Terminate the client's TLS and serve what is inside. `sniff` makes a
/// session without an HTTP ALPN go through plaintext detection (a non-HTTP
/// payload is a bypass); reverse listeners serve HTTP regardless.
async fn terminate_tls<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    mut info: ConnInfo,
    client: Buffered,
    hello: &ClientHello,
    sniff: bool,
) {
    let mut names = vec![match &info.sni {
        Some(sni) => LeafName::parse(sni),
        None => LeafName::Ip(info.local_addr.ip()),
    }];
    if let Some(server) = &info.server_addr {
        names.push(LeafName::parse(&server.host));
    }
    let leaf = match shared.ca.leaf(&names) {
        Ok(leaf) => leaf,
        Err(e) => {
            log(&info, &format!("cannot mint a certificate: {e}"));
            return;
        }
    };
    let chosen = detect::choose_alpn(&hello.alpn);
    let config = match server_config(leaf, chosen, !hello.alpn.is_empty()) {
        Ok(config) => config,
        Err(e) => {
            log(&info, &format!("TLS config: {e}"));
            return;
        }
    };
    let stream = match tokio_rustls::TlsAcceptor::from(config)
        .accept(client.into_io())
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            log(&info, &format!("client TLS handshake failed: {e}"));
            return;
        }
    };
    info.tls = true;
    info.alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let offers = Arc::new(hello.alpn.clone());
    let io: BoxIo = Box::new(stream);
    match info.alpn.as_deref() {
        Some(b"h2") => super::h2::serve(shared, Arc::new(info), io, offers).await,
        Some(_) => serve_h1(shared, Arc::new(info), Buffered::new(io), offers).await,
        None if !sniff => serve_h1(shared, Arc::new(info), Buffered::new(io), offers).await,
        None => {
            let mut inner = Buffered::new(io);
            match peek(&mut inner).await {
                None => {}
                Some(Peeked::Http { .. }) => serve_h1(shared, Arc::new(info), inner, offers).await,
                Some(_) => shared.handler.tcp_bypass(&info),
            }
        }
    }
}

async fn reverse<H: FlowHandler>(shared: Arc<Shared<H>>, mut info: ConnInfo, mut client: Buffered) {
    while client.buf.len() < 3 {
        match client.fill().await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    if detect::starts_like_tls(&client.buf) {
        let hello = loop {
            match detect::parse_client_hello(&client.buf) {
                Ok(Some(hello)) => break hello,
                Ok(None) => match client.fill().await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                },
                Err(_) => break ClientHello::default(),
            }
        };
        info.sni = hello.sni.clone().filter(|s| !s.is_empty());
        terminate_tls(shared, info, client, &hello, false).await;
    } else {
        serve_h1(shared, Arc::new(info), client, Arc::new(Vec::new())).await;
    }
}

fn error_response(status: u16, message: &str) -> Response {
    let mut resp = super::make_response(
        status,
        &[("Connection", "close"), ("Content-Type", "text/plain")],
        message.as_bytes().to_vec(),
    );
    resp.headers.0.retain(|(k, _)| k != b"content-length");
    resp.headers
        .add("content-length", resp.body.len().to_string());
    resp
}

/// A response whose body ends only when the connection does.
fn close_delimited(resp: &Response) -> bool {
    resp.headers
        .get("transfer-encoding")
        .is_some_and(|te| !te.to_ascii_lowercase().contains("chunked"))
}

/// The request's destination when it reached the forward proxy:
/// absolute-form names it; origin-form goes by `Host`.
fn forward_target(head: &h1::RequestHead) -> Result<(String, String, u16, String), String> {
    if let Some((scheme, rest)) = head.target.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = parse_authority(authority);
        let port = match (port, scheme.as_str()) {
            (Some(p), _) => p,
            (None, "http") => 80,
            (None, "https") => 443,
            _ => return Err(format!("Bad HTTP request line: {:?}", head.target)),
        };
        if host.is_empty() || !matches!(scheme.as_str(), "http" | "https") {
            return Err(format!("Invalid request scheme: {scheme}"));
        }
        return Ok((scheme, host, port, path));
    }
    let Some(header) = head.headers.get("host") else {
        return Err("HTTP request has no host header, destination unknown.".into());
    };
    let (host, port) = parse_authority(&header);
    if host.is_empty() || host.contains(':') && !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6())
    {
        return Err("HTTP request has no host header, destination unknown.".into());
    }
    Ok(("http".into(), host, port.unwrap_or(80), head.target.clone()))
}

/// What the next HTTP/1 request on a connection turned out to be.
enum Next {
    /// A complete request, body read.
    Request(Request),
    /// `CONNECT` on the forward proxy.
    Connect(h1::RequestHead),
    /// The connection is over (closed, or answered with an error).
    Close,
}

async fn reply(client: &mut Buffered, resp: &Response, method: &str) {
    let _ = client.write_all(&h1::encode_response(resp, method)).await;
}

/// Scheme, host, port and path of a request: from the request line on the
/// forward proxy, from the connection everywhere else (the transparent
/// listener, a tunnel, a reverse listener).
fn request_target(
    info: &ConnInfo,
    parsed: &h1::RequestHead,
    regular: bool,
) -> Result<(String, String, u16, String), String> {
    if regular {
        return forward_target(parsed);
    }
    let server = info.server_addr.clone().unwrap_or(ServerAddr {
        host: String::new(),
        port: 0,
    });
    let scheme = if info.listener != ListenerKind::Reverse && info.tls {
        "https"
    } else {
        "http"
    };
    let path = match parsed.target.split_once("://") {
        Some((_, rest)) => rest
            .find('/')
            .map_or_else(|| "/".to_string(), |i| rest[i..].to_string()),
        None => parsed.target.clone(),
    };
    Ok((scheme.to_string(), server.host, server.port, path))
}

/// Read the next request off `client`, answering malformed, refused and
/// oversized requests directly.
async fn next_request<H: FlowHandler>(
    shared: &Shared<H>,
    info: &ConnInfo,
    client: &mut Buffered,
    settings: &TransportSettings,
) -> Next {
    let head = match h1::read_head(client).await {
        Ok(head) => head,
        Err(h1::ReadError::Eof | h1::ReadError::Io(_)) => return Next::Close,
        Err(e) => {
            reply(client, &error_response(400, &e.to_string()), "GET").await;
            return Next::Close;
        }
    };
    let parsed = match h1::parse_request_head(&head) {
        Ok(parsed) => parsed,
        Err(e) => {
            reply(client, &error_response(400, &e), "GET").await;
            return Next::Close;
        }
    };
    let regular = info.listener == ListenerKind::Regular && !info.via_connect;
    if parsed.method.eq_ignore_ascii_case("CONNECT") {
        if regular {
            return Next::Connect(parsed);
        }
        let msg = "the egress received an HTTP CONNECT request on a listener that is not the forward proxy";
        reply(client, &error_response(400, msg), "GET").await;
        return Next::Close;
    }
    let (scheme, host, port, path) = match request_target(info, &parsed, regular) {
        Ok(target) => target,
        Err(e) => {
            reply(client, &error_response(400, &e), "GET").await;
            return Next::Close;
        }
    };
    let mut req = Request {
        method: parsed.method,
        scheme,
        host,
        port,
        path,
        http_version: parsed.version,
        headers: parsed.headers,
        body: Vec::new(),
    };
    if regular && !settings.inspected_ports.contains(&port) {
        let refusal = Refusal::ForwardPort {
            host: req.host.clone(),
            port,
        };
        let resp = shared.handler.transport_refusal(info, Some(&req), &refusal);
        reply(client, &resp, &req.method).await;
        return Next::Close;
    }
    let framing = match h1::validate_framing(&req.headers, &req.http_version, None)
        .map_err(|e| {
            format!("Received {e} from client, refusing to prevent request smuggling attacks.")
        })
        .and_then(|()| h1::request_framing(&req.headers))
    {
        Ok(framing) => framing,
        Err(e) => {
            reply(client, &error_response(400, &e), "GET").await;
            return Next::Close;
        }
    };
    if req
        .headers
        .get("expect")
        .is_some_and(|e| e.eq_ignore_ascii_case("100-continue"))
    {
        if client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .is_err()
        {
            return Next::Close;
        }
        req.headers.remove("expect");
    }
    match h1::read_body(client, framing, settings.max_body).await {
        Ok(body) => {
            req.body = body;
            Next::Request(req)
        }
        Err(h1::ReadError::BodyTooLarge) => {
            let refusal = Refusal::RequestBodyTooLarge {
                limit: settings.max_body,
            };
            let resp = shared.handler.transport_refusal(info, Some(&req), &refusal);
            reply(client, &resp, &req.method).await;
            Next::Close
        }
        Err(h1::ReadError::Malformed(e)) => {
            reply(client, &error_response(400, &e), "GET").await;
            Next::Close
        }
        Err(_) => Next::Close,
    }
}

/// Serve HTTP/1 requests on `client` until it closes.
pub(crate) async fn serve_h1<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    info: Arc<ConnInfo>,
    mut client: Buffered,
    alpn_offers: Arc<Vec<Vec<u8>>>,
) {
    let pool = UpstreamPool::default();
    let mut slot: H1Slot = None;
    loop {
        // Loaded per request, so a reload applies to the next request on a
        // kept-alive connection without disturbing it.
        let settings = shared.settings.load_full();
        let req = match next_request(&shared, &info, &mut client, &settings).await {
            Next::Request(req) => req,
            Next::Connect(head) => {
                Box::pin(connect_tunnel(shared, &info, client, &head)).await;
                return;
            }
            Next::Close => return,
        };
        let close = h1::connection_close(&req.http_version, &req.headers);
        let method = req.method.clone();
        match exchange(&shared, &info, req, &pool, &mut slot, &alpn_offers).await {
            Exchanged::Done(resp) => {
                if client
                    .write_all(&h1::encode_response(&resp, &method))
                    .await
                    .is_err()
                {
                    return;
                }
                let resp_close = resp.http_version.starts_with("HTTP/1")
                    && h1::connection_close(&resp.http_version, &resp.headers);
                if close || resp_close || close_delimited(&resp) {
                    return;
                }
            }
            Exchanged::Upgrade {
                resp,
                flow,
                req,
                upstream,
            } => {
                if client
                    .write_all(&h1::encode_head_only(&resp))
                    .await
                    .is_err()
                {
                    shared.handler.flow_end(
                        &info,
                        flow,
                        FlowEnd::Aborted("client went away".into()),
                    );
                    return;
                }
                super::ws::relay(&shared, &info, flow, &req, client, upstream).await;
                return;
            }
            Exchanged::RawUpgrade(resp) => {
                let _ = client.write_all(&h1::encode_head_only(&resp)).await;
                shared.handler.tcp_bypass(&info);
                return;
            }
        }
    }
}

/// `CONNECT host:port` on the forward proxy: refuse a non-inspected port,
/// else answer `200 Connection established` and intercept the tunnel.
async fn connect_tunnel<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    info: &ConnInfo,
    mut client: Buffered,
    head: &h1::RequestHead,
) {
    let (host, port) = parse_authority(&head.target);
    let Some(port) = port.filter(|_| !host.is_empty()) else {
        let msg = format!(
            "Bad HTTP request line: {:?}",
            format!("{} {} {}", head.method, head.target, head.version)
        );
        let _ = client
            .write_all(&h1::encode_response(&error_response(400, &msg), "GET"))
            .await;
        return;
    };
    if !shared.settings.load().inspected_ports.contains(&port) {
        let req = Request {
            method: head.method.clone(),
            scheme: String::new(),
            host: host.clone(),
            port,
            path: String::new(),
            http_version: head.version.clone(),
            headers: head.headers.clone(),
            body: Vec::new(),
        };
        let resp = shared.handler.transport_refusal(
            info,
            Some(&req),
            &Refusal::ForwardPort { host, port },
        );
        let _ = client
            .write_all(&h1::encode_response(&resp, "CONNECT"))
            .await;
        return;
    }
    let established = format!("{} 200 Connection established\r\n\r\n", head.version);
    if client.write_all(established.as_bytes()).await.is_err() {
        return;
    }
    while client.buf.starts_with(b"\r") || client.buf.starts_with(b"\n") {
        let _ = client.buf.split_to(1);
    }
    let mut tunnel = info.clone();
    tunnel.server_addr = Some(ServerAddr { host, port });
    tunnel.via_connect = true;
    intercept(shared, tunnel, client).await;
}
