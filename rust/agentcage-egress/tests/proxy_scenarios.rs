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

// ── Test handler ─────────────────────────────────────────────

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<String>>,
    passthrough: PassthroughMatcher,
    refuse_connect: bool,
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
            502,
            &[("Content-Type", "application/json")],
            b"{\"blocked\": false}".to_vec(),
        )
    }

    fn transport_refusal(&self, _: &ConnInfo, _: Option<&Request>, refusal: &Refusal) -> Response {
        self.push(format!("refusal {refusal:?}"));
        match refusal {
            Refusal::ForwardPort { .. } => make_response(403, &[], b"port".to_vec()),
            Refusal::RequestBodyTooLarge { .. } => make_response(413, &[], b"big".to_vec()),
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
            let resp = http::Response::builder()
                .status(200)
                .header("x-mock", "h2")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(resp, false).unwrap();
            let _ = stream.send_data(Bytes::from(text), true);
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

async fn egress(
    handler: Arc<Recorder>,
    root: &TestRoot,
    ports: Vec<u16>,
    max_body: usize,
    reverse_target: Option<SocketAddr>,
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
