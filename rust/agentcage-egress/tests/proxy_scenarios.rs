//! Scenario tests for the proxy core: an in-process egress with a test CA,
//! mock upstreams (HTTP/1, HTTP/2, TLS under a test root, WebSocket, a
//! silent TCP server) and real clients (rustls, h2, tungstenite; curl when
//! installed).
//!
//! The transparent listener is driven through its original-destination
//! seam; the real `SO_ORIGINAL_DST` + iptables `REDIRECT` path needs a
//! network namespace and is covered end to end.

// The test handler implements the async hooks with plain `async fn`s,
// some of which have nothing to await.
#![allow(clippy::too_many_lines, clippy::unused_async_trait_impl, missing_docs)]

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

use agentcage_egress::ca::CertAuthority;
use agentcage_egress::message::{Request, Response};
use agentcage_egress::proxy::{
    ConnInfo, ConnectDecision, ConnectTarget, FlowEnd, FlowHandler, ListenerKind, ListenerSpec,
    PassthroughMatcher, Proxy, Refusal, RequestAction, TransportSettings, UpstreamError, WsMessage,
    WsVerdict, make_response, retarget_to_host,
};

mod support;

// ── Test handler ─────────────────────────────────────────────

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<String>>,
    passthrough: PassthroughMatcher,
    refuse_connect: bool,
    /// The peer guard refuses every pooled connection at reuse.
    refuse_reuse: bool,
    control_host: Option<String>,
}

impl Recorder {
    fn push(&self, event: String) {
        self.events.lock().unwrap().push(event);
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn has(&self, prefix: &str) -> bool {
        self.events().iter().any(|e| e.starts_with(prefix))
    }
}

impl FlowHandler for Recorder {
    type Flow = String;

    async fn intercept(&self, conn: &ConnInfo, req: &mut Request) -> Option<Response> {
        let host = req.host_header().unwrap_or_default();
        if self.control_host.as_deref() == Some(host.as_str()) {
            self.push(format!("intercept {host} sni={:?}", conn.sni));
            return Some(make_response(
                200,
                &[("Content-Type", "application/json")],
                b"{\"ok\": true}".to_vec(),
            ));
        }
        None
    }

    async fn request(&self, conn: &ConnInfo, req: &mut Request) -> RequestAction<String> {
        self.push(format!(
            "request {:?} {} {} {}:{} {} sni={:?} tls={} alpn={:?}",
            conn.listener,
            req.method,
            req.scheme,
            req.host,
            req.port,
            req.path,
            conn.sni,
            conn.tls,
            conn.alpn.as_deref().map(String::from_utf8_lossy),
        ));
        if req.path.starts_with("/blocked") {
            return RequestAction::Respond(make_response(
                403,
                &[("Content-Type", "application/json")],
                b"{\"blocked\": true}".to_vec(),
            ));
        }
        if conn.listener != ListenerKind::Reverse {
            retarget_to_host(req);
        }
        if req.path.starts_with("/inject") {
            // The pipeline injects secrets into bodies; Content-Length
            // must follow.
            req.body = String::from_utf8_lossy(&req.body)
                .replace("PLACEHOLDER", "real-secret-value")
                .into_bytes();
        }
        RequestAction::Forward(req.path.clone())
    }

    async fn response(
        &self,
        _: &ConnInfo,
        flow: &mut String,
        _: &mut Request,
        resp: &mut Response,
    ) {
        self.push(format!("response {flow} {}", resp.status));
        if flow.starts_with("/respblock") {
            *resp = make_response(403, &[], b"response blocked".to_vec());
        }
    }

    async fn websocket_message(
        &self,
        _: &ConnInfo,
        _: &mut String,
        _: &Request,
        msg: &mut WsMessage,
    ) -> WsVerdict {
        self.push(format!(
            "ws from_client={} text={} {}",
            msg.from_client,
            msg.is_text,
            String::from_utf8_lossy(&msg.content)
        ));
        if msg.content == b"drop-me" {
            return WsVerdict::Drop;
        }
        if msg.from_client {
            msg.content = String::from_utf8_lossy(&msg.content)
                .replace("secret", "SECRET")
                .into_bytes();
        }
        WsVerdict::Forward
    }

    fn flow_end(&self, _: &ConnInfo, flow: String, end: FlowEnd) {
        self.push(format!("end {flow} {end:?}"));
    }

    fn upstream_error(
        &self,
        _: &ConnInfo,
        flow: String,
        _: &Request,
        err: &UpstreamError,
    ) -> Response {
        self.push(format!("upstream_error {flow} {err:?}"));
        make_response(
            err.status(),
            &[("Content-Type", "application/json")],
            b"{\"blocked\": false}".to_vec(),
        )
    }

    fn transport_refusal(&self, _: &ConnInfo, _: Option<&Request>, refusal: &Refusal) -> Response {
        self.push(format!("refusal {refusal:?}"));
        match refusal {
            Refusal::ForwardPort { .. } => make_response(403, &[], b"port".to_vec()),
            Refusal::RequestBodyTooLarge { .. } => make_response(413, &[], b"big".to_vec()),
            Refusal::BodyBudgetExhausted { .. } => make_response(503, &[], b"budget".to_vec()),
        }
    }

    fn tcp_bypass(&self, conn: &ConnInfo) {
        self.push(format!("bypass {}", conn.bypass_target()));
    }

    fn server_connect(
        &self,
        _: &ConnInfo,
        target: &ConnectTarget,
        resolved: &[IpAddr],
    ) -> ConnectDecision {
        self.push(format!(
            "connect {}:{} {:?}",
            target.host, target.port, target.purpose
        ));
        if self.refuse_connect {
            return ConnectDecision::Refuse("peer guard says no".into());
        }
        // Prefer IPv4 loopback: the mocks listen on 127.0.0.1 only.
        let mut addrs: Vec<IpAddr> = resolved.iter().copied().filter(IpAddr::is_ipv4).collect();
        if addrs.is_empty() {
            addrs = resolved.to_vec();
        }
        ConnectDecision::Allow(addrs)
    }

    fn may_reuse(&self, _: &ConnInfo, _: &ConnectTarget, _: IpAddr) -> bool {
        !self.refuse_reuse
    }

    fn is_passthrough(&self, _: &ConnInfo, candidate: &str) -> bool {
        self.passthrough.matches(candidate)
    }
}

// ── Test PKI ─────────────────────────────────────────────────

struct TestRoot {
    cert: CertificateDer<'static>,
    leaf: Arc<rustls::sign::CertifiedKey>,
}

fn test_root() -> TestRoot {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
    TestRoot {
        cert: ca_cert.der().clone(),
        leaf: Arc::new(rustls::sign::CertifiedKey::new(
            vec![leaf_cert.der().clone()],
            signer,
        )),
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn mock_tls_config(root: &TestRoot, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(Arc::clone(&root.leaf))));
    config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(config)
}

fn client_tls(root: &CertificateDer<'static>, alpn: &[&[u8]]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

// ── Mock upstreams ───────────────────────────────────────────

/// Bytes the `/counted/` mock managed to write.
static STREAMED: AtomicUsize = AtomicUsize::new(0);

/// A gzip body that echoes the real secret back.
fn gzip_secret() -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for i in 0..200 {
        std::io::Write::write_all(
            &mut e,
            format!("line {i}: token=REALSECRETVALUE12345\n").as_bytes(),
        )
        .unwrap();
    }
    e.finish().unwrap()
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Read one HTTP/1 message head + body (Content-Length or chunked).
async fn read_message(
    io: &mut (impl AsyncRead + Unpin),
    buf: &mut Vec<u8>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    loop {
        if let Some(end) = find(buf, b"\r\n\r\n") {
            let head = buf[..end + 4].to_vec();
            buf.drain(..end + 4);
            let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
            let mut body = Vec::new();
            if text.contains("transfer-encoding: chunked") {
                loop {
                    while find(buf, b"\r\n").is_none() {
                        read_more(io, buf).await?;
                    }
                    let line_end = find(buf, b"\r\n").unwrap();
                    let size =
                        usize::from_str_radix(String::from_utf8_lossy(&buf[..line_end]).trim(), 16)
                            .ok()?;
                    buf.drain(..line_end + 2);
                    while buf.len() < size + 2 {
                        read_more(io, buf).await?;
                    }
                    body.extend_from_slice(&buf[..size]);
                    buf.drain(..size + 2);
                    if size == 0 {
                        break;
                    }
                }
            } else if let Some(pos) = text.find("content-length:") {
                let n: usize = text[pos + 15..].lines().next()?.trim().parse().ok()?;
                while buf.len() < n {
                    read_more(io, buf).await?;
                }
                body = buf.drain(..n).collect();
            }
            return Some((head, body));
        }
        read_more(io, buf).await?;
    }
}

async fn read_more(io: &mut (impl AsyncRead + Unpin), buf: &mut Vec<u8>) -> Option<()> {
    let mut chunk = vec![0u8; 16384];
    let n = io.read(&mut chunk).await.ok()?;
    if n == 0 {
        return None;
    }
    buf.extend_from_slice(&chunk[..n]);
    Some(())
}

/// The echo body: the request head bytes as received, then the body.
fn echo_body(head: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = head.to_vec();
    out.extend_from_slice(body);
    out
}

async fn serve_h1_echo(mut io: Box<dyn Io>) {
    let mut buf = Vec::new();
    while let Some((head, body)) = read_message(&mut io, &mut buf).await {
        let path = String::from_utf8_lossy(&head)
            .split(' ')
            .nth(1)
            .unwrap_or("")
            .to_string();
        let reply = if let Some(n) = path.strip_prefix("/big/") {
            let n: usize = n.parse().unwrap();
            let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").into_bytes();
            r.extend(std::iter::repeat_n(b'x', n));
            r
        } else if path == "/close" {
            let mut r = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil-close".to_vec();
            let _ = io.write_all(&r).await;
            let _ = io.shutdown().await;
            r.clear();
            return;
        } else if let Some(n) = path
            .strip_prefix("/stream/")
            .or_else(|| path.strip_prefix("/counted/"))
        {
            let counted = path.starts_with("/counted/");
            // A long chunked body of text lines, written as the reader
            // takes it.
            let n: usize = n.parse().unwrap();
            let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
            if io.write_all(head).await.is_err() {
                return;
            }
            let line = b"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\n";
            let block: Vec<u8> = line.iter().copied().cycle().take(64 * 1024).collect();
            let mut sent = 0;
            while sent < n {
                let take = block.len().min(n - sent);
                let mut frame = format!("{take:x}\r\n").into_bytes();
                frame.extend_from_slice(&block[..take]);
                frame.extend_from_slice(b"\r\n");
                if io.write_all(&frame).await.is_err() {
                    if counted {
                        STREAMED.fetch_add(sent, Ordering::SeqCst);
                    }
                    return;
                }
                sent += take;
            }
            if counted {
                STREAMED.fetch_add(sent, Ordering::SeqCst);
            }
            b"0\r\n\r\n".to_vec()
        } else if path == "/drip" {
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            if io.write_all(head).await.is_err() {
                return;
            }
            for i in 0..3 {
                let event = format!("data: tick {i} REALSECRETVALUE12345\n\n");
                let frame = format!("{:x}\r\n{event}\r\n", event.len());
                if io.write_all(frame.as_bytes()).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            b"0\r\n\r\n".to_vec()
        } else if path == "/gzip-secret" {
            let body = gzip_secret();
            let mut r = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            r.extend(body);
            r
        } else if path == "/reset" {
            let mut r = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n".to_vec();
            r.extend(std::iter::repeat_n(b'r', 1000));
            let _ = io.write_all(&r).await;
            let _ = io.shutdown().await;
            return;
        } else if path == "/chunked" {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Up: 1\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec()
        } else {
            let echo = echo_body(&head, &body);
            let mut r = format!(
                "HTTP/1.1 200 OK\r\nX-Mock: h1\r\nx-mock: dup\r\nContent-Length: {}\r\n\r\n",
                echo.len()
            )
            .into_bytes();
            r.extend(echo);
            r
        };
        if io.write_all(&reply).await.is_err() {
            return;
        }
    }
}

async fn serve_h2_echo(io: Box<dyn Io>) {
    let Ok(mut conn) = h2::server::handshake(io).await else {
        return;
    };
    while let Some(Ok((req, mut respond))) = conn.accept().await {
        tokio::spawn(async move {
            let (parts, mut body) = req.into_parts();
            let mut data = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
                data.extend_from_slice(&chunk);
            }
            let mut text = format!(
                "{} {} h2 authority={}\n",
                parts.method,
                parts.uri.path(),
                parts
                    .uri
                    .authority()
                    .map_or("", http::uri::Authority::as_str)
            );
            for (k, v) in &parts.headers {
                let _ = writeln!(text, "{}: {}", k, v.to_str().unwrap_or("?"));
            }
            text.push_str(&String::from_utf8_lossy(&data));
            let path = parts.uri.path().to_string();
            let mut resp = http::Response::builder().status(200).header("x-mock", "h2");
            if path == "/gzip-secret" {
                resp = resp.header("content-encoding", "gzip");
            }
            let mut stream = respond
                .send_response(resp.body(()).unwrap(), false)
                .unwrap();
            match path.as_str() {
                "/gzip-secret" => {
                    let _ = stream.send_data(Bytes::from(gzip_secret()), true);
                }
                "/reset" => {
                    let _ = stream.send_data(Bytes::from(vec![b'r'; 1000]), false);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    stream.send_reset(h2::Reason::INTERNAL_ERROR);
                }
                p if p.starts_with("/stream/") => {
                    let n: usize = p["/stream/".len()..].parse().unwrap();
                    let line = b"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\n";
                    let block = Bytes::from(
                        line.iter()
                            .copied()
                            .cycle()
                            .take(16 * 1024)
                            .collect::<Vec<u8>>(),
                    );
                    let mut sent = 0;
                    while sent < n {
                        let take = block.len().min(n - sent);
                        stream.reserve_capacity(take);
                        let Some(Ok(_)) = std::future::poll_fn(|cx| stream.poll_capacity(cx)).await
                        else {
                            return;
                        };
                        if stream.send_data(block.slice(..take), false).is_err() {
                            return;
                        }
                        sent += take;
                    }
                    let _ = stream.send_data(Bytes::new(), true);
                }
                _ => {
                    let _ = stream.send_data(Bytes::from(text), true);
                }
            }
        });
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Plain,
    Tls(&'static [&'static [u8]]),
    Ws,
    WsTls,
    Silent,
}

struct Mock {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

async fn mock(kind: Kind, root: &TestRoot) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let tls = match kind {
        Kind::Tls(alpn) => Some(mock_tls_config(root, alpn)),
        Kind::WsTls => Some(mock_tls_config(root, &[b"http/1.1"])),
        _ => None,
    };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let tls = tls.clone();
            tokio::spawn(async move {
                let (io, alpn): (Box<dyn Io>, Option<Vec<u8>>) = match tls {
                    Some(config) => {
                        let Ok(s) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await
                        else {
                            return;
                        };
                        let alpn = s.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                        (Box::new(s), alpn)
                    }
                    None => (Box::new(stream), None),
                };
                match kind {
                    Kind::Silent => {
                        let mut io = io;
                        let mut sink = Vec::new();
                        let _ = io.read_to_end(&mut sink).await;
                    }
                    Kind::Ws | Kind::WsTls => {
                        let Ok(mut ws) = tokio_tungstenite::accept_async(io).await else {
                            return;
                        };
                        while let Some(Ok(msg)) = ws.next().await {
                            let reply = match msg {
                                Message::Text(t) => Message::text(format!("echo:{}", t.as_str())),
                                Message::Binary(b) => {
                                    let mut v = b"echo:".to_vec();
                                    v.extend_from_slice(&b);
                                    Message::binary(v)
                                }
                                Message::Close(_) => break,
                                _ => continue,
                            };
                            if ws.send(reply).await.is_err() {
                                break;
                            }
                        }
                    }
                    _ if alpn.as_deref() == Some(b"h2") => serve_h2_echo(io).await,
                    _ => serve_h1_echo(io).await,
                }
            });
        }
    });
    Mock { addr, accepted }
}

// ── The egress under test ────────────────────────────────────

struct Egress {
    regular: SocketAddr,
    transparent: SocketAddr,
    reverse: Option<SocketAddr>,
    ca: CertificateDer<'static>,
    ca_pem: String,
    original_dst: Arc<Mutex<SocketAddr>>,
    settings: Arc<arc_swap::ArcSwap<TransportSettings>>,
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "agentcage-egress-scn-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn egress<H: FlowHandler>(
    handler: Arc<H>,
    root: &TestRoot,
    ports: Vec<u16>,
    max_body: usize,
    reverse_target: Option<SocketAddr>,
) -> Egress {
    egress_with_budget(handler, root, ports, max_body, reverse_target, None).await
}

async fn egress_with_budget<H: FlowHandler>(
    handler: Arc<H>,
    root: &TestRoot,
    ports: Vec<u16>,
    max_body: usize,
    reverse_target: Option<SocketAddr>,
    body_budget: Option<usize>,
) -> Egress {
    let (ca, _) = CertAuthority::load_or_create(&temp_dir("ca"), "scenario").unwrap();
    let ca = Arc::new(ca);
    let original_dst = Arc::new(Mutex::new("127.0.0.1:9".parse().unwrap()));
    let od = Arc::clone(&original_dst);
    let proxy = Proxy::new(
        handler,
        Arc::clone(&ca),
        TransportSettings {
            max_body,
            inspected_ports: ports,
        },
    )
    .with_extra_upstream_roots(vec![root.cert.clone()])
    .with_original_dst(Arc::new(move |_| Ok(*od.lock().unwrap())));
    let proxy = match body_budget {
        Some(limit) => proxy.with_body_budget(limit),
        None => proxy,
    };
    let mut specs = vec![
        ListenerSpec::Regular("127.0.0.1:0".parse().unwrap()),
        ListenerSpec::Transparent("127.0.0.1:0".parse().unwrap()),
    ];
    if let Some(target) = reverse_target {
        specs.push(ListenerSpec::Reverse {
            bind: "127.0.0.1:0".parse().unwrap(),
            target,
        });
    }
    let bound = proxy.bind(&specs).await.unwrap();
    let addrs = bound.local_addrs();
    let find = |k: ListenerKind| addrs.iter().find(|(kind, _)| *kind == k).map(|(_, a)| *a);
    let settings = bound.settings();
    tokio::spawn(bound.run());
    Egress {
        regular: find(ListenerKind::Regular).unwrap(),
        transparent: find(ListenerKind::Transparent).unwrap(),
        reverse: find(ListenerKind::Reverse),
        ca: ca.cert_der().clone(),
        ca_pem: ca.cert_pem().to_string(),
        original_dst,
        settings,
    }
}

/// Open a `CONNECT` tunnel through the forward proxy; returns the status
/// line and the stream.
async fn connect(proxy: SocketAddr, target: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while find(&buf, b"\r\n\r\n").is_none() {
        if s.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    (line, s)
}

/// Send raw request bytes and read one response (head, body).
async fn roundtrip(
    io: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request: &[u8],
) -> (String, Vec<u8>) {
    io.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_message(io, &mut buf))
        .await
        .expect("response in time")
        .expect("a response");
    (String::from_utf8_lossy(&head).into_owned(), body)
}

async fn h2_get(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    authority: &str,
    path: &str,
    body: &[u8],
) -> (u16, String) {
    let (sender, conn) = h2::client::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut sender = sender.ready().await.unwrap();
    let req = http::Request::builder()
        .method(if body.is_empty() { "GET" } else { "POST" })
        .uri(format!("https://{authority}{path}"))
        .header("x-client", "h2")
        .body(())
        .unwrap();
    let (resp, mut stream) = sender.send_request(req, body.is_empty()).unwrap();
    if !body.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(body), true)
            .unwrap();
    }
    let resp = resp.await.unwrap();
    let status = resp.status().as_u16();
    let mut recv = resp.into_body();
    let mut data = Vec::new();
    while let Some(Ok(chunk)) = recv.data().await {
        let _ = recv.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
    }
    (status, String::from_utf8_lossy(&data).into_owned())
}

fn sn(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_string()).unwrap()
}

// ── Scenarios ────────────────────────────────────────────────

#[tokio::test]
async fn connect_tls_http1_preserves_header_bytes_and_fixes_lengths() {
    let root = test_root();
    let up = mock(Kind::Tls(&[b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let target = format!("localhost:{}", up.addr.port());
    let (line, tunnel) = connect(eg.regular, &target).await;
    assert_eq!(line, "HTTP/1.1 200 Connection established");
    let mut tls = client_tls(&eg.ca, &[b"http/1.1"])
        .connect(sn("localhost"), tunnel)
        .await
        .unwrap();
    let (head, body) = roundtrip(
        &mut tls,
        format!(
            "POST /inject HTTP/1.1\r\nHost: localhost:{p}\r\nX-Dup: a\r\nUser-Agent: t\r\nx-dup: b\r\nContent-Length: 15\r\n\r\nkey=PLACEHOLDER",
            p = up.addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(
        head.contains("X-Mock: h1\r\nx-mock: dup\r\n"),
        "response duplicates kept: {head}"
    );
    let echo = String::from_utf8_lossy(&body);
    let expected_head = format!(
        "POST /inject HTTP/1.1\r\nHost: localhost:{p}\r\nX-Dup: a\r\nUser-Agent: t\r\nx-dup: b\r\nContent-Length: 21\r\n\r\nkey=real-secret-value",
        p = up.addr.port()
    );
    assert_eq!(echo, expected_head);
    // Keep-alive: a second request on the same tunnel and upstream.
    let (head, _) = roundtrip(
        &mut tls,
        format!(
            "GET /chunked HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            up.addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
    assert_eq!(
        up.accepted.load(Ordering::SeqCst),
        1,
        "upstream connection reused"
    );
    let events = handler.events();
    assert!(events[0].starts_with(&format!(
        "request Regular POST https localhost:{} /inject sni=Some(\"localhost\") tls=true alpn=Some(\"http/1.1\")",
        up.addr.port()
    )), "{events:?}");
    assert!(handler.has("end /inject Completed"));
}

#[tokio::test]
async fn absolute_form_plain_http_and_origin_form_with_host() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let url = format!("http://127.0.0.1:{}/a?b=1", up.addr.port());
    let (head, body) = roundtrip(
        &mut s,
        format!(
            "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            up.addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        String::from_utf8_lossy(&body).starts_with("GET /a?b=1 HTTP/1.1\r\n"),
        "origin-form upstream"
    );
    let (head, _) = roundtrip(
        &mut s,
        format!(
            "GET /o HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            up.addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, body) = roundtrip(
        &mut s,
        b"GET /blocked HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
    )
    .await;
    // Port 1 is not inspected: refused before the request hook.
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(body, b"port");
    assert!(handler.has("refusal ForwardPort"));
}

#[tokio::test]
async fn forward_proxy_refuses_connect_to_uninspected_ports() {
    let root = test_root();
    let up = mock(Kind::Silent, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(Arc::clone(&handler), &root, vec![443], 1 << 20, None).await;
    let (line, _) = connect(eg.regular, &format!("localhost:{}", up.addr.port())).await;
    assert!(line.starts_with("HTTP/1.1 403"), "{line}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(up.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn alpn_h2_to_h2_h2_to_h1_and_h1_to_h2() {
    let root = test_root();
    let up_h2 = mock(Kind::Tls(&[b"h2", b"http/1.1"]), &root).await;
    let up_h1 = mock(Kind::Tls(&[b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up_h2.addr.port(), up_h1.addr.port()],
        1 << 20,
        None,
    )
    .await;

    // h2 client → h2 upstream.
    let auth = format!("localhost:{}", up_h2.addr.port());
    let (_, t) = connect(eg.regular, &auth).await;
    let tls = client_tls(&eg.ca, &[b"h2", b"http/1.1"])
        .connect(sn("localhost"), t)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (status, text) = h2_get(tls, &auth, "/x", b"body!").await;
    assert_eq!(status, 200);
    assert!(
        text.starts_with(&format!("POST /x h2 authority={auth}\n")),
        "{text}"
    );
    assert!(
        text.contains("x-client: h2\n") && text.ends_with("body!"),
        "{text}"
    );

    // h2 client → HTTP/1-only upstream.
    let auth = format!("localhost:{}", up_h1.addr.port());
    let (_, t) = connect(eg.regular, &auth).await;
    let tls = client_tls(&eg.ca, &[b"h2", b"http/1.1"])
        .connect(sn("localhost"), t)
        .await
        .unwrap();
    let (status, text) = h2_get(tls, &auth, "/y", b"").await;
    assert_eq!(status, 200);
    assert!(
        text.starts_with("GET /y HTTP/1.1\r\nhost: "),
        "authority became Host: {text}"
    );

    // HTTP/1 client (preferring it) → h2-capable upstream.
    let auth = format!("localhost:{}", up_h2.addr.port());
    let (_, t) = connect(eg.regular, &auth).await;
    let mut tls = client_tls(&eg.ca, &[b"http/1.1", b"h2"])
        .connect(sn("localhost"), t)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let (head, body) = roundtrip(
        &mut tls,
        format!("GET /z HTTP/1.1\r\nHost: {auth}\r\nConnection: keep-alive\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.starts_with(&format!("GET /z h2 authority={auth}\n")),
        "{text}"
    );
    assert!(!text.contains("connection:"), "hop-by-hop dropped: {text}");
}

#[tokio::test]
async fn transparent_plain_and_tls_retarget_to_the_host_name() {
    let root = test_root();
    let up_plain = mock(Kind::Plain, &root).await;
    let up_tls = mock(Kind::Tls(&[b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(Arc::clone(&handler), &root, vec![], 1 << 20, None).await;

    // Plain HTTP: original destination an address, Host a name.
    *eg.original_dst.lock().unwrap() = up_plain.addr;
    let mut s = TcpStream::connect(eg.transparent).await.unwrap();
    let (head, body) = roundtrip(&mut s, b"GET /t HTTP/1.1\r\nHost: localhost:9999\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let echo = String::from_utf8_lossy(&body);
    assert!(
        echo.contains(&format!("\r\nHost: localhost:{}\r\n", up_plain.addr.port())),
        "Host rewritten to the name and the original port: {echo}"
    );
    assert!(handler.has(&format!(
        "request Transparent GET http 127.0.0.1:{} /t",
        up_plain.addr.port()
    )));
    assert!(handler.has(&format!("connect localhost:{} Http", up_plain.addr.port())));

    // TLS with SNI.
    *eg.original_dst.lock().unwrap() = up_tls.addr;
    let s = TcpStream::connect(eg.transparent).await.unwrap();
    let mut tls = client_tls(&eg.ca, &[])
        .connect(sn("localhost"), s)
        .await
        .unwrap();
    let (head, _) = roundtrip(
        &mut tls,
        format!(
            "GET /s HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            up_tls.addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // Without SNI the leaf is minted for the address.
    let s = TcpStream::connect(eg.transparent).await.unwrap();
    let mut tls = client_tls(&eg.ca, &[])
        .connect(sn("127.0.0.1"), s)
        .await
        .unwrap();
    let (head, _) = roundtrip(
        &mut tls,
        format!(
            "GET /ip HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            up_tls.addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
}

#[tokio::test]
async fn reverse_keeps_the_host_header_and_relays_websockets() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(Arc::clone(&handler), &root, vec![], 1 << 20, Some(up.addr)).await;
    let mut s = TcpStream::connect(eg.reverse.unwrap()).await.unwrap();
    let (head, body) = roundtrip(
        &mut s,
        b"GET /in HTTP/1.1\r\nHost: public.example:8080\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(String::from_utf8_lossy(&body).contains("\r\nHost: public.example:8080\r\n"));
    assert!(handler.has(&format!(
        "request Reverse GET http 127.0.0.1:{} /in",
        up.addr.port()
    )));

    let ws_up = mock(Kind::Ws, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![],
        1 << 20,
        Some(ws_up.addr),
    )
    .await;
    let s = TcpStream::connect(eg.reverse.unwrap()).await.unwrap();
    let (mut ws, resp) = tokio_tungstenite::client_async("ws://public.example/socket", s)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws.send(Message::text("hello secret")).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::text("echo:hello SECRET"));
    assert!(handler.has("ws from_client=false text=true echo:hello SECRET"));
}

#[tokio::test]
async fn websockets_through_connect_tls_inject_drop_and_keep_types() {
    let root = test_root();
    let up = mock(Kind::WsTls, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let auth = format!("localhost:{}", up.addr.port());
    let (_, t) = connect(eg.regular, &auth).await;
    let tls = client_tls(&eg.ca, &[b"http/1.1"])
        .connect(sn("localhost"), t)
        .await
        .unwrap();
    let (mut ws, resp) = tokio_tungstenite::client_async(format!("wss://{auth}/ws"), tls)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws.send(Message::text("drop-me")).await.unwrap();
    ws.send(Message::text("a secret")).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::text("echo:a SECRET")
    );
    ws.send(Message::binary(vec![0u8, 1, 2])).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::binary(b"echo:\x00\x01\x02".to_vec())
    );
    ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = handler.events();
    assert!(
        events
            .iter()
            .any(|e| e == "ws from_client=true text=true drop-me"),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e == "ws from_client=true text=false \u{0}\u{1}\u{2}"),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.starts_with("end /ws WebSocketClosed")),
        "{events:?}"
    );
}

#[tokio::test]
async fn passthrough_splices_only_when_the_destination_is_the_names_address() {
    let root = test_root();
    let up = mock(Kind::Tls(&[b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder {
        passthrough: PassthroughMatcher::new(&["localhost".to_string()]),
        ..Recorder::default()
    });
    let eg = egress(Arc::clone(&handler), &root, vec![], 1 << 20, None).await;

    // SNI localhost to 127.0.0.1: spliced — the client sees the upstream's
    // own certificate and no HTTP hook runs.
    *eg.original_dst.lock().unwrap() = up.addr;
    let s = TcpStream::connect(eg.transparent).await.unwrap();
    let mut tls = client_tls(&root.cert, &[])
        .connect(sn("localhost"), s)
        .await
        .unwrap();
    let (head, _) = roundtrip(
        &mut tls,
        b"GET /spliced HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(!handler.has("request"), "{:?}", handler.events());
    assert!(handler.has(&format!("connect 127.0.0.1:{} Passthrough", up.addr.port())));

    // SNI localhost to some other address (plan D4): intercepted instead.
    let other: SocketAddr = format!("127.0.0.2:{}", up.addr.port()).parse().unwrap();
    *eg.original_dst.lock().unwrap() = other;
    let s = TcpStream::connect(eg.transparent).await.unwrap();
    let mut tls = client_tls(&eg.ca, &[])
        .connect(sn("localhost"), s)
        .await
        .unwrap();
    let (head, _) = roundtrip(
        &mut tls,
        format!(
            "GET /spoofed HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            up.addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        handler.has("request Transparent GET https 127.0.0.2"),
        "{:?}",
        handler.events()
    );
}

#[tokio::test]
async fn non_http_is_a_bypass_and_never_reaches_upstream() {
    let root = test_root();
    let up = mock(Kind::Silent, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;

    *eg.original_dst.lock().unwrap() = up.addr;
    let mut s = TcpStream::connect(eg.transparent).await.unwrap();
    s.write_all(b"\x00\x01\x02 raw bytes\n").await.unwrap();
    let mut buf = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0, "closed without a reply");
    assert!(handler.has(&format!("bypass 127.0.0.1:{}", up.addr.port())));

    // Inside a CONNECT tunnel: an SSH banner.
    let (line, mut t) = connect(eg.regular, &format!("localhost:{}", up.addr.port())).await;
    assert!(line.contains("200"));
    t.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), t.read_to_end(&mut buf))
        .await
        .unwrap();
    assert!(
        handler.has(&format!("bypass localhost:{}", up.addr.port())),
        "{:?}",
        handler.events()
    );

    // TLS without HTTP inside: bypass named by the SNI.
    let s = TcpStream::connect(eg.transparent).await.unwrap();
    let mut tls = client_tls(&eg.ca, &[])
        .connect(sn("localhost"), s)
        .await
        .unwrap();
    tls.write_all(b"\x00\x00binary-protocol\n").await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf)).await;
    assert!(handler.has("bypass localhost"), "{:?}", handler.events());
    assert_eq!(
        up.accepted.load(Ordering::SeqCst),
        0,
        "no upstream socket ever opened"
    );
}

#[tokio::test]
async fn body_caps_and_upstream_failures_go_to_the_handler() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port(), dead.port()],
        1024,
        None,
    )
    .await;
    let p = up.addr.port();

    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let big = "x".repeat(2048);
    let (head, body) = roundtrip(&mut s, format!("POST http://127.0.0.1:{p}/up HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 2048\r\n\r\n{big}").as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 413"), "{head}");
    assert_eq!(body, b"big");

    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let (head, _) = roundtrip(
        &mut s,
        format!("GET http://127.0.0.1:{p}/big/4096 HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert!(handler.has("upstream_error /big/4096 ResponseBodyTooLarge"));

    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let (head, body) = roundtrip(
        &mut s,
        format!(
            "GET http://127.0.0.1:{d}/gone HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n",
            d = dead.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(body, b"{\"blocked\": false}");
    assert!(
        handler.has("upstream_error /gone Connect"),
        "{:?}",
        handler.events()
    );

    // A hot settings change applies to the next request on an open
    // connection, which stays open.
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let (head, _) = roundtrip(
        &mut s,
        format!("GET http://127.0.0.1:{p}/big/2000 HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    let mut next = (**eg.settings.load()).clone();
    next.max_body = 1 << 20;
    eg.settings.store(Arc::new(next));
    let (head, body) = roundtrip(
        &mut s,
        format!("GET http://127.0.0.1:{p}/big/2000 HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), 2000);
}

#[tokio::test]
async fn bodies_past_the_process_budget_are_refused_with_a_503() {
    const MIB: usize = 1024 * 1024;
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress_with_budget(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        64 * MIB,
        None,
        Some(2 * MIB),
    )
    .await;
    let p = up.addr.port();
    let get = |n: usize| {
        format!("GET http://127.0.0.1:{p}/big/{n} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n")
    };

    // A response under the per-body cap but over the whole budget.
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let (head, body) = roundtrip(&mut s, get(3 * MIB).as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert_eq!(body, b"{\"blocked\": false}");
    assert!(
        handler.has(&format!(
            "upstream_error /big/{} BodyBudgetExhausted",
            3 * MIB
        )),
        "{:?}",
        handler.events()
    );
    // Its reservation was released: what fits still goes through, on the
    // same connection.
    let (head, body) = roundtrip(&mut s, get(MIB + MIB / 2).as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), MIB + MIB / 2);

    // A request body over the budget is refused before it is read.
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let (head, body) = roundtrip(
        &mut s,
        format!(
            "POST http://127.0.0.1:{p}/up HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: {}\r\n\r\n",
            3 * MIB
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert_eq!(body, b"budget");
    assert!(handler.has("refusal BodyBudgetExhausted"));
}

#[tokio::test]
async fn refused_connects_and_blocks_never_open_a_socket() {
    let root = test_root();
    let up = mock(Kind::Silent, &root).await;
    let handler = Arc::new(Recorder {
        refuse_connect: true,
        ..Recorder::default()
    });
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let p = up.addr.port();
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let (head, _) = roundtrip(
        &mut s,
        format!("GET http://127.0.0.1:{p}/x HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert!(handler.has("upstream_error /x Refused(\"peer guard says no\")"));
    let (head, _) = roundtrip(
        &mut s,
        format!("GET http://127.0.0.1:{p}/blocked HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(up.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_control_host_is_answered_in_process() {
    let root = test_root();
    let handler = Arc::new(Recorder {
        control_host: Some("agentcage.local".into()),
        ..Recorder::default()
    });
    let eg = egress(Arc::clone(&handler), &root, vec![443], 1 << 20, None).await;
    let (_, t) = connect(eg.regular, "agentcage.local:443").await;
    let mut tls = client_tls(&eg.ca, &[b"http/1.1"])
        .connect(sn("agentcage.local"), t)
        .await
        .unwrap();
    let (head, body) = roundtrip(
        &mut tls,
        b"GET /v1/health HTTP/1.1\r\nHost: agentcage.local\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"{\"ok\": true}");
    assert!(handler.has("intercept agentcage.local sni=Some(\"agentcage.local\")"));
    assert!(!handler.has("connect"), "never resolved or connected");
    assert!(!handler.has("request"));
}

#[tokio::test]
async fn response_hook_can_replace_the_response() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let p = up.addr.port();
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    let (head, body) = roundtrip(
        &mut s,
        format!("GET http://127.0.0.1:{p}/respblock HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(body, b"response blocked");
}

#[tokio::test]
async fn curl_through_the_forward_proxy_when_installed() {
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("curl not installed; skipping");
        return;
    }
    let root = test_root();
    let up = mock(Kind::Tls(&[b"h2", b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let dir = temp_dir("curl");
    std::fs::create_dir_all(&dir).unwrap();
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, &eg.ca_pem).unwrap();
    for http in ["--http1.1", "--http2"] {
        let out = tokio::process::Command::new("curl")
            .args([
                "-sS",
                "-m",
                "10",
                http,
                "-o",
                "-",
                "-w",
                "\n%{http_code} %{http_version}",
            ])
            .arg("--proxy")
            .arg(format!("http://{}", eg.regular))
            .arg("--cacert")
            .arg(&ca_path)
            .arg(format!("https://localhost:{}/curl", up.addr.port()))
            .output()
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{http}: {text} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let expected = if http == "--http2" {
            "200 2"
        } else {
            "200 1.1"
        };
        assert!(text.ends_with(expected), "{http}: {text}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

// ── Streamed responses (the real pipeline) ───────────────────

const SECRET: &str = "REALSECRETVALUE12345";
const PLACEHOLDER: &str = "agentcage:secret:TEST_TOKEN:0011";

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// The request pipeline over an engine allowing `localhost`, with a
/// secret-injection rule (`secrets`) and capture (`capture`): the
/// pipeline, its audit output and the capture file.
fn pipeline(
    secrets: bool,
    capture: bool,
) -> (
    Arc<agentcage_egress::flow::Pipeline>,
    Sink,
    std::path::PathBuf,
) {
    pipeline_with(
        secrets,
        capture,
        "",
        Arc::new(agentcage_egress::inspect::chain::NoPlugins),
    )
}

/// [`pipeline`], with `extra` appended to the config and custom
/// inspectors loaded through `plugins`.
fn pipeline_with(
    secrets: bool,
    capture: bool,
    extra: &str,
    plugins: Arc<dyn agentcage_egress::inspect::chain::PluginLoader + Send + Sync>,
) -> (
    Arc<agentcage_egress::flow::Pipeline>,
    Sink,
    std::path::PathBuf,
) {
    use agentcage_egress::engine::{Engine, EngineOptions};
    let dir = temp_dir("pipeline");
    std::fs::create_dir_all(&dir).unwrap();
    let mut yaml =
        String::from("domains:\n  allow: [localhost]\nrate_limit:\n  requests_per_second: 0\n");
    if secrets {
        let _ = write!(
            yaml,
            "secret_injection:\n  rules:\n    - env: TEST_TOKEN\n      placeholder: \"{PLACEHOLDER}\"\n      inject_to: [localhost]\n"
        );
    }
    if capture {
        yaml.push_str("capture:\n  enable_har: true\n  max_body_size: 2048\n");
    }
    yaml.push_str(extra);
    let config = dir.join("config.yaml");
    std::fs::write(&config, &yaml).unwrap();
    let sink = Sink::default();
    let audit = Arc::new(
        agentcage_egress::audit::AuditWriter::new(None).with_stderr(Box::new(sink.clone())),
    );
    let capture_path = dir.join("capture.jsonl");
    let engine = Engine::boot(EngineOptions {
        config_path: Some(config),
        audit,
        capture: Arc::new(agentcage_egress::capture::Capture::new(Some(
            capture_path.clone(),
        ))),
        plugins,
        policy_paths: agentcage_egress::policy::PolicyPaths::new(
            dir.join("grants"),
            dir.join("dns/granted"),
        ),
        watcher_paths: agentcage_egress::watcher::WatcherPaths {
            dir: dir.join("watcher"),
            capture: None,
        },
    });
    let cfg = agentcage_egress::config::Config::parse("t", &yaml).unwrap();
    engine.injector.configure_with(
        cfg.get("secret_injection"),
        &|_| SECRET.to_owned(),
        &agentcage_egress::transforms::build,
    );
    (
        Arc::new(agentcage_egress::flow::Pipeline::new(engine)),
        sink,
        capture_path,
    )
}

/// Read a response head, then its body (chunked or `Content-Length`)
/// without keeping it: its length, the first `keep` bytes, the time to
/// the first body byte and to the end.
struct Streamed {
    head: String,
    len: usize,
    kept: Vec<u8>,
    first: Duration,
    total: Duration,
    complete: bool,
}

async fn read_streamed(io: &mut (impl AsyncRead + Unpin), keep: usize) -> Streamed {
    let started = std::time::Instant::now();
    let mut buf = Vec::new();
    let end = loop {
        if let Some(end) = find(&buf, b"\r\n\r\n") {
            break end;
        }
        read_more(io, &mut buf).await.expect("a head");
    };
    let head = String::from_utf8_lossy(&buf[..end + 4]).into_owned();
    buf.drain(..end + 4);
    let lower = head.to_ascii_lowercase();
    let mut out = Streamed {
        head,
        len: 0,
        kept: Vec::new(),
        first: Duration::ZERO,
        total: Duration::ZERO,
        complete: false,
    };
    let take = |out: &mut Streamed, data: &[u8]| {
        if out.len == 0 && !data.is_empty() {
            out.first = started.elapsed();
        }
        out.len += data.len();
        let room = keep.saturating_sub(out.kept.len());
        out.kept.extend_from_slice(&data[..room.min(data.len())]);
    };
    if lower.contains("transfer-encoding: chunked") {
        loop {
            while find(&buf, b"\r\n").is_none() {
                if read_more(io, &mut buf).await.is_none() {
                    out.total = started.elapsed();
                    return out;
                }
            }
            let line_end = find(&buf, b"\r\n").unwrap();
            let size = usize::from_str_radix(String::from_utf8_lossy(&buf[..line_end]).trim(), 16)
                .unwrap();
            buf.drain(..line_end + 2);
            let mut left = size;
            while left > 0 {
                if buf.is_empty() && read_more(io, &mut buf).await.is_none() {
                    out.total = started.elapsed();
                    return out;
                }
                let n = left.min(buf.len());
                take(&mut out, &buf[..n]);
                buf.drain(..n);
                left -= n;
            }
            while buf.len() < 2 {
                if read_more(io, &mut buf).await.is_none() {
                    out.total = started.elapsed();
                    return out;
                }
            }
            buf.drain(..2);
            if size == 0 {
                out.complete = true;
                break;
            }
        }
    } else if let Some(pos) = lower.find("content-length:") {
        let n: usize = lower[pos + 15..]
            .lines()
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        loop {
            let chunk = std::mem::take(&mut buf);
            take(&mut out, &chunk);
            if out.len >= n {
                out.complete = out.len == n;
                break;
            }
            if read_more(io, &mut buf).await.is_none() {
                break;
            }
        }
    }
    out.total = started.elapsed();
    out
}

async fn forward_get(eg: &Egress, port: u16, path: &str, keep: usize) -> Streamed {
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    s.write_all(
        format!("GET http://localhost:{port}{path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(120), read_streamed(&mut s, keep))
        .await
        .expect("response in time")
}

#[tokio::test]
async fn large_responses_stream_past_the_buffer_cap_in_bounded_memory() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let p = up.addr.port();
    // A 1 MiB body cap and an 8 MiB budget: a buffered 300 MB response
    // would be a 502.
    for secrets in [false, true] {
        let (handler, audit, _) = pipeline(secrets, false);
        let eg = egress_with_budget(handler, &root, vec![p], 1 << 20, None, Some(8 << 20)).await;
        let n = if secrets { 64 << 20 } else { 300 << 20 };
        let got = forward_get(&eg, p, &format!("/stream/{n}"), 64).await;
        assert!(got.head.starts_with("HTTP/1.1 200"), "{}", got.head);
        assert!(got.complete, "secrets={secrets} {}", got.head);
        assert_eq!(got.len, n);
        assert_eq!(&got.kept[..10], b"0123456789");
        let lower = got.head.to_ascii_lowercase();
        assert!(lower.contains("transfer-encoding: chunked"), "{}", got.head);
        // A body of known length keeps it when it goes on unchanged, and
        // loses it when redaction may change it.
        let got = forward_get(&eg, p, "/big/3000000", 0).await;
        assert!(got.complete && got.len == 3_000_000, "{}", got.head);
        let lower = got.head.to_ascii_lowercase();
        assert_eq!(
            lower.contains("content-length: 3000000"),
            !secrets,
            "{}",
            got.head
        );
        assert!(!audit.text().contains("upstream_error"), "{}", audit.text());
    }
}

/// A custom inspector keeps responses buffered only if it declares the
/// response phase: under a 1 MiB body cap, a 3 MiB response streams past
/// a request-only plugin, and is refused (502, too large to buffer) when
/// a loaded plugin inspects responses, or was built against 1.0.0 and so
/// is asked about every phase.
#[tokio::test]
async fn responses_stream_unless_a_loaded_plugin_declares_responses() {
    use agentcage_egress::plugin::{Limits, Loader, WasmPluginLoader};
    let Some(dir) = support::plugin_dir() else {
        return;
    };
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let p = up.addr.port();
    let entry = |name: &str, file: &str, config: &str| {
        format!("inspectors:\n  - name: {name}\n    path: {file}.wasm\n    config: {config}\n")
    };
    let cases = [
        (
            entry("header-policy", "header_policy_inspector", "{}"),
            true,
        ),
        (
            entry(
                "dlp",
                "dlp_regex_inspector",
                "{patterns: [{name: n, regex: zzz-never}]}",
            ),
            true,
        ),
        (
            entry(
                "dlp",
                "dlp_regex_inspector",
                "{patterns: [{name: n, regex: zzz-never}], responses: true}",
            ),
            false,
        ),
        (entry("legacy", "legacy_inspector", "{}"), false),
    ];
    let n = 3 << 20;
    for (yaml, streams) in cases {
        let plugins = Arc::new(WasmPluginLoader::new(Loader::new(
            vec![dir.to_path_buf()],
            Limits::default(),
        )));
        let (handler, audit, _) = pipeline_with(false, false, &yaml, plugins);
        let eg = egress(handler, &root, vec![p], 1 << 20, None).await;
        let got = forward_get(&eg, p, &format!("/stream/{n}"), 16).await;
        if streams {
            assert!(got.head.starts_with("HTTP/1.1 200"), "{yaml}{}", got.head);
            assert!(got.complete && got.len == n, "{yaml}{}", got.head);
        } else {
            assert!(got.head.starts_with("HTTP/1.1 502"), "{yaml}{}", got.head);
            assert!(
                audit
                    .text()
                    .contains("response body exceeds the 1048576-byte limit"),
                "{yaml}{}",
                audit.text()
            );
        }
    }
}

#[tokio::test]
async fn a_slow_event_stream_reaches_the_client_as_it_is_produced() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let p = up.addr.port();
    let (handler, _, _) = pipeline(true, true);
    let eg = egress(handler, &root, vec![p], 1 << 20, None).await;
    let got = forward_get(&eg, p, "/drip", 4096).await;
    assert!(got.complete, "{}", got.head);
    assert!(
        got.first < Duration::from_millis(300) && got.total >= Duration::from_millis(1000),
        "first byte {:?}, total {:?}",
        got.first,
        got.total
    );
    let text = String::from_utf8(got.kept).unwrap();
    assert_eq!(text.matches(PLACEHOLDER).count(), 3, "{text}");
    assert!(!text.contains(SECRET), "{text}");
}

#[tokio::test]
async fn a_compressed_secret_echo_is_redacted_and_sent_identity() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let p = up.addr.port();
    let (handler, _, capture) = pipeline(true, true);
    let eg = egress(handler, &root, vec![p], 1 << 20, None).await;
    let got = forward_get(&eg, p, "/gzip-secret", 1 << 20).await;
    assert!(got.complete, "{}", got.head);
    let lower = got.head.to_ascii_lowercase();
    assert!(!lower.contains("content-encoding"), "{}", got.head);
    assert!(!lower.contains("content-length"), "{}", got.head);
    let text = String::from_utf8(got.kept).unwrap();
    assert_eq!(text.matches(PLACEHOLDER).count(), 200);
    assert!(!text.contains(SECRET));
    // The capture entry holds the redacted, decoded body, cut at its
    // max_body_size, with the whole size.
    let line = std::fs::read_to_string(&capture).unwrap();
    assert!(!line.contains(SECRET), "{line}");
    assert!(line.contains("\"bodyTruncated\":true"), "{line}");
    assert!(
        line.contains(&format!("\"bodyOriginalSize\":{}", text.len())),
        "{line}"
    );

    // Over HTTP/2 both ways.
    let up2 = mock(Kind::Tls(&[b"h2"]), &root).await;
    let (handler, _, _) = pipeline(true, false);
    let eg = egress(handler, &root, vec![up2.addr.port()], 1 << 20, None).await;
    *eg.original_dst.lock().unwrap() = up2.addr;
    let tcp = TcpStream::connect(eg.transparent).await.unwrap();
    let tls = client_tls(&eg.ca, &[b"h2"])
        .connect(sn("localhost"), tcp)
        .await
        .unwrap();
    let authority = format!("localhost:{}", up2.addr.port());
    let (status, body) = h2_get(tls, &authority, "/gzip-secret", b"").await;
    assert_eq!(status, 200);
    assert_eq!(body.matches(PLACEHOLDER).count(), 200, "{body}");
    assert!(!body.contains(SECRET));
}

#[tokio::test]
async fn an_upstream_reset_mid_body_cuts_the_client_off_and_is_audited_once() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let p = up.addr.port();
    let (handler, audit, _) = pipeline(true, false);
    let eg = egress(handler, &root, vec![p], 1 << 20, None).await;
    let got = forward_get(&eg, p, "/reset", 0).await;
    assert!(got.head.starts_with("HTTP/1.1 200"), "{}", got.head);
    assert!(!got.complete, "the client sees a cut-off body");
    // What redaction still held when the upstream failed is never sent.
    assert!(got.len <= 1000);
    let log = audit.text();
    assert_eq!(log.matches("\"upstream_error\"").count(), 1, "{log}");

    // HTTP/2: the stream is reset.
    let up2 = mock(Kind::Tls(&[b"h2"]), &root).await;
    let (handler, audit, _) = pipeline(false, false);
    let eg = egress(handler, &root, vec![up2.addr.port()], 1 << 20, None).await;
    *eg.original_dst.lock().unwrap() = up2.addr;
    let tcp = TcpStream::connect(eg.transparent).await.unwrap();
    let tls = client_tls(&eg.ca, &[b"h2"])
        .connect(sn("localhost"), tcp)
        .await
        .unwrap();
    let (sender, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut sender = sender.ready().await.unwrap();
    let req = http::Request::builder()
        .uri(format!("https://localhost:{}/reset", up2.addr.port()))
        .body(())
        .unwrap();
    let (resp, _) = sender.send_request(req, true).unwrap();
    let resp = resp.await.unwrap();
    let mut recv = resp.into_body();
    let mut got = 0;
    let mut failed = false;
    while let Some(chunk) = recv.data().await {
        if let Ok(c) = chunk {
            got += c.len();
        } else {
            failed = true;
            break;
        }
    }
    assert!(failed, "reset, not a clean end ({got} bytes)");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(audit.text().matches("\"upstream_error\"").count(), 1);
}

#[tokio::test]
async fn a_client_that_goes_away_stops_the_upstream_read() {
    let root = test_root();
    let up = mock(Kind::Plain, &root).await;
    let p = up.addr.port();
    let (handler, _, _) = pipeline(false, false);
    let eg = egress(handler, &root, vec![p], 1 << 20, None).await;
    let before = STREAMED.load(Ordering::SeqCst);
    let n: usize = 2 << 30;
    let mut s = TcpStream::connect(eg.regular).await.unwrap();
    s.write_all(
        format!("GET http://localhost:{p}/counted/{n} HTTP/1.1\r\nHost: localhost:{p}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut read = 0;
    while read < 4 << 20 {
        read += s.read(&mut buf).await.unwrap();
    }
    drop(s);
    // The mock's writes fail soon after: far less than the body was sent.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let sent = STREAMED.load(Ordering::SeqCst) - before;
    assert!(sent > 0 && sent < 256 << 20, "{sent}");
}

// ── Upstream pooling and TLS resumption ──────────────────────

/// One HTTP/1 request in a fresh `CONNECT` tunnel (a fresh client
/// connection) with its own TLS session; the response head.
async fn one_tunnel_request(eg: &Egress, target: &str, sni: &str, path: &str) -> String {
    let (_, tunnel) = connect(eg.regular, target).await;
    let mut tls = client_tls(&eg.ca, &[b"http/1.1"])
        .connect(sn(sni), tunnel)
        .await
        .unwrap();
    let (head, _) = roundtrip(
        &mut tls,
        format!("GET {path} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
    )
    .await;
    head
}

#[tokio::test]
async fn upstream_connections_are_reused_across_client_connections() {
    let root = test_root();
    let up = mock(Kind::Tls(&[b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let target = format!("localhost:{}", up.addr.port());
    for path in ["/one", "/two", "/three"] {
        let head = one_tunnel_request(&eg, &target, "localhost", path).await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    }
    assert_eq!(
        up.accepted.load(Ordering::SeqCst),
        1,
        "three client connections, one upstream connection"
    );
    // The same upstream dialled by address is another connection (the
    // key is what was dialled, as well as the name verified).
    let by_ip = format!("127.0.0.1:{}", up.addr.port());
    let head = one_tunnel_request(&eg, &by_ip, "localhost", "/by-ip").await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert_eq!(up.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn h2_upstream_sessions_are_shared_by_client_connections() {
    let root = test_root();
    let up = mock(Kind::Tls(&[b"h2", b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let auth = format!("localhost:{}", up.addr.port());
    for path in ["/a", "/b"] {
        let (_, t) = connect(eg.regular, &auth).await;
        let tls = client_tls(&eg.ca, &[b"h2", b"http/1.1"])
            .connect(sn("localhost"), t)
            .await
            .unwrap();
        let (status, text) = h2_get(tls, &auth, path, b"").await;
        assert_eq!(status, 200);
        assert!(text.starts_with(&format!("GET {path} h2 ")), "{text}");
    }
    assert_eq!(up.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_pooled_connection_the_peer_guard_now_refuses_is_not_reused() {
    let root = test_root();
    let up = mock(Kind::Tls(&[b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder {
        refuse_reuse: true,
        ..Recorder::default()
    });
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let target = format!("localhost:{}", up.addr.port());
    for path in ["/one", "/two"] {
        let head = one_tunnel_request(&eg, &target, "localhost", path).await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    }
    assert_eq!(up.accepted.load(Ordering::SeqCst), 2);
    // Each was vetted by `server_connect` when it was opened.
    let connects = handler
        .events()
        .iter()
        .filter(|e| e.starts_with("connect "))
        .count();
    assert_eq!(connects, 2);
}

#[tokio::test]
async fn agents_reconnecting_resume_their_tls_session() {
    let root = test_root();
    let up = mock(Kind::Tls(&[b"http/1.1"]), &root).await;
    let handler = Arc::new(Recorder::default());
    let eg = egress(
        Arc::clone(&handler),
        &root,
        vec![up.addr.port()],
        1 << 20,
        None,
    )
    .await;
    let target = format!("localhost:{}", up.addr.port());
    // One client config, as one agent process keeps one.
    let client = client_tls(&eg.ca, &[b"http/1.1"]);
    let mut kinds = Vec::new();
    for path in ["/one", "/two"] {
        let (_, tunnel) = connect(eg.regular, &target).await;
        let mut tls = client.connect(sn("localhost"), tunnel).await.unwrap();
        let (head, _) = roundtrip(
            &mut tls,
            format!("GET {path} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        kinds.push(tls.get_ref().1.handshake_kind());
    }
    assert_eq!(
        kinds,
        [
            Some(rustls::HandshakeKind::Full),
            Some(rustls::HandshakeKind::Resumed)
        ]
    );
}
