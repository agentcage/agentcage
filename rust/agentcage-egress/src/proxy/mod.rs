//! The proxy core: listeners, protocol detection, TLS, HTTP/1, HTTP/2,
//! WebSockets and the upstream connector.
//!
//! This module moves bytes; it decides nothing about policy. Every
//! decision is a call into a [`FlowHandler`], the seam the request
//! pipeline (`crate::flow`) implements. The transport guarantees the
//! ordering the pipeline relies on:
//!
//! * **Lazy upstream.** A client's TLS handshake completes (with a leaf
//!   minted from its SNI) and its whole request is read before anything is
//!   resolved or connected upstream. Nothing leaves the egress until
//!   [`FlowHandler::request`] returns [`RequestAction::Forward`], so a
//!   blocked request, a 429 or a Policy API call never opens a socket.
//! * **Fully buffered bodies**, capped at [`TransportSettings::max_body`]
//!   (plan D6): a body over the cap is an error response from the handler,
//!   never an out-of-memory kill.
//! * **The handler vets every upstream address.** The transport resolves a
//!   name (getaddrinfo semantics, no cache), hands the answers to
//!   [`FlowHandler::server_connect`], and connects only to what comes
//!   back, so a granted name cannot be re-resolved to somewhere else
//!   between the check and the connect.
//! * **Non-HTTP on an intercepted port** reaches
//!   [`FlowHandler::tcp_bypass`] and is closed before any upstream socket
//!   exists. **Passthrough** (`domains.passthrough`) is a raw splice with
//!   no HTTP hooks, granted only when the destination address is one the
//!   SNI name resolves to (plan D4).
//! * **Forward-proxy targets** are limited to the inspected ports (plan
//!   D3); anything else is refused through
//!   [`FlowHandler::transport_refusal`].
//!
//! Header case, order and duplicates survive HTTP/1 in both directions
//! (plan D10): the HTTP/1 codec is our own, on top of `httparse`.

mod conn;
mod detect;
mod h1;
mod h2;
mod io;
mod listen;
mod tls;
mod upstream;
mod ws;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::ca::CertAuthority;
use crate::message::{Headers, Request, Response};

pub use detect::{ClientHello, parse_client_hello};
pub use listen::{
    BoundProxy, ListenerSpec, OriginalDstFn, ReverseSpecError, original_dst, parse_bind,
    parse_reverse_spec,
};

/// Which listener accepted a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerKind {
    /// The forward proxy (`CONNECT` and absolute-form HTTP).
    Regular,
    /// The transparent listener behind iptables `REDIRECT`.
    Transparent,
    /// A reverse listener forwarding a published port into the cage.
    Reverse,
}

/// Which way a flow goes, as audit records spell it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Cage → internet.
    Outbound,
    /// Internet → cage (reverse listeners).
    Inbound,
}

impl Direction {
    /// `"outbound"` or `"inbound"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
        }
    }
}

/// A `host:port` the client's connection was headed for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAddr {
    /// A name or an address literal (no brackets).
    pub host: String,
    /// The port.
    pub port: u16,
}

impl ServerAddr {
    /// `host:port`, without brackets for IPv6 (the form audit records use).
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// What the transport knows about one client connection.
///
/// One `ConnInfo` covers every request on the connection (and every
/// stream of an HTTP/2 connection). Inside a `CONNECT` tunnel it is the
/// tunnel's: `server_addr` is the `CONNECT` target and `via_connect` is set.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    /// A process-unique connection number, for logs.
    pub id: u64,
    /// The listener that accepted it.
    pub listener: ListenerKind,
    /// The client's address.
    pub client_addr: SocketAddr,
    /// The address the client connected to (the listener's).
    pub local_addr: SocketAddr,
    /// Where the connection was going: the original destination
    /// (`SO_ORIGINAL_DST`) on the transparent listener, the `CONNECT`
    /// target in a tunnel, the cage address on a reverse listener; `None`
    /// for plain forward-proxy requests, whose target is per request.
    pub server_addr: Option<ServerAddr>,
    /// Whether this is the inside of a forward-proxy `CONNECT` tunnel.
    pub via_connect: bool,
    /// The TLS SNI the client sent, if it spoke TLS and sent one.
    pub sni: Option<String>,
    /// Whether the client side is TLS (intercepted).
    pub tls: bool,
    /// The ALPN protocol negotiated with the client.
    pub alpn: Option<Vec<u8>>,
}

impl ConnInfo {
    /// `inbound` on a reverse listener, `outbound` everywhere else.
    #[must_use]
    pub fn direction(&self) -> Direction {
        match self.listener {
            ListenerKind::Reverse => Direction::Inbound,
            _ => Direction::Outbound,
        }
    }

    /// The best identifier for a flow that never became HTTP: the SNI the
    /// client committed to, else the destination `host:port`, else
    /// `<unknown>`.
    #[must_use]
    pub fn bypass_target(&self) -> String {
        if let Some(sni) = self.sni.as_deref().filter(|s| !s.is_empty()) {
            return sni.to_string();
        }
        match &self.server_addr {
            Some(addr) if !addr.host.is_empty() => addr.display(),
            _ => "<unknown>".to_string(),
        }
    }
}

/// What [`FlowHandler::request`] decided.
#[derive(Debug)]
pub enum RequestAction<F> {
    /// Send the (possibly rewritten) request upstream, to `req.host` and
    /// `req.port` over `req.scheme`; the handler's per-flow state comes
    /// back in every later hook of this flow.
    Forward(F),
    /// Answer the client with this response; nothing goes upstream and no
    /// other hook runs for this flow.
    Respond(Response),
}

/// One complete WebSocket message (fragments already joined).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsMessage {
    /// Sent by the client of this connection (on a reverse listener the
    /// client is the outside caller, not the cage).
    pub from_client: bool,
    /// A text message (else binary); kept when forwarding.
    pub is_text: bool,
    /// The payload; the handler may rewrite it.
    pub content: Vec<u8>,
}

/// What to do with a WebSocket message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsVerdict {
    /// Forward `content` (as possibly rewritten).
    Forward,
    /// Drop the message; the connection stays open.
    Drop,
}

/// How a forwarded flow ended, for [`FlowHandler::flow_end`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowEnd {
    /// The response was delivered (and no WebSocket followed).
    Completed,
    /// A WebSocket that followed the response has closed, cleanly or not.
    WebSocketClosed,
    /// The flow failed after the response hook (the client went away
    /// mid-write, or similar).
    Aborted(String),
}

/// A refusal the transport makes before the request hook runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A forward-proxy target (`CONNECT` or absolute-form) on a port that
    /// is not inspected (plan D3).
    ForwardPort {
        /// The target host.
        host: String,
        /// The refused port.
        port: u16,
    },
    /// The request body exceeds the cap (plan D6).
    RequestBodyTooLarge {
        /// The cap, in bytes.
        limit: usize,
    },
}

/// Why a forwarded request got no upstream response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamError {
    /// [`FlowHandler::server_connect`] refused every address.
    Refused(String),
    /// The name did not resolve.
    Resolve {
        /// The name.
        host: String,
        /// The resolver's error.
        error: String,
    },
    /// No address accepted the TCP connection.
    Connect {
        /// `host:port` as dialled.
        target: String,
        /// The last socket error.
        error: String,
    },
    /// The upstream TLS handshake failed (including verification).
    Tls(String),
    /// The upstream broke the HTTP protocol or closed mid-response.
    Protocol(String),
    /// The response body exceeds the cap (plan D6).
    ResponseBodyTooLarge {
        /// The cap, in bytes.
        limit: usize,
    },
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "connection refused by policy: {reason}"),
            Self::Resolve { host, error } => write!(f, "cannot resolve {host}: {error}"),
            Self::Connect { target, error } => write!(f, "cannot connect to {target}: {error}"),
            Self::Tls(error) => write!(f, "upstream TLS handshake failed: {error}"),
            Self::Protocol(error) => write!(f, "upstream protocol error: {error}"),
            Self::ResponseBodyTooLarge { limit } => {
                write!(f, "response body exceeds the {limit}-byte limit")
            }
        }
    }
}

/// Why the transport is about to open an upstream connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectPurpose {
    /// To forward an HTTP request (`Forward` from the request hook).
    Http,
    /// To splice a passthrough connection.
    Passthrough,
}

/// An upstream connection about to be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectTarget {
    /// The name (or address literal) being dialled.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The SNI the connection carries (upstream TLS SNI for HTTP, the
    /// client's SNI for a splice).
    pub sni: Option<String>,
    /// HTTP or passthrough.
    pub purpose: ConnectPurpose,
}

/// What [`FlowHandler::server_connect`] decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectDecision {
    /// Connect to these addresses, in order (normally all of the resolved
    /// ones).
    Allow(Vec<IpAddr>),
    /// Do not connect; the reason goes to [`FlowHandler::upstream_error`]
    /// as [`UpstreamError::Refused`] for HTTP flows.
    Refuse(String),
}

/// The policy seam: everything the transport asks the pipeline.
///
/// Hooks that may run inspectors are async (the pipeline runs CPU-bound
/// work off the runtime); the rest are synchronous and must be cheap.
pub trait FlowHandler: Send + Sync + 'static {
    /// Per-flow state, created by [`Self::request`] and handed back to
    /// every later hook of the same flow (the capture entry staged for
    /// the response, the decision a WebSocket escalates…). Dropped or
    /// passed to [`Self::flow_end`] / [`Self::upstream_error`] when the
    /// flow ends, so nothing is left behind for an errored flow.
    type Flow: Send + 'static;

    /// Answer a request in-process before anything else sees it — the
    /// Policy API control host. Runs before [`Self::request`]; a response
    /// here skips every other hook. The default answers nothing.
    fn intercept(
        &self,
        conn: &ConnInfo,
        req: &mut Request,
    ) -> impl Future<Output = Option<Response>> + Send {
        let _ = (conn, req);
        async { None }
    }

    /// The request hook: a complete request, body buffered (still
    /// content-encoded). `req.host` / `req.port` are the destination as
    /// the listener knows it (the original destination, the `CONNECT`
    /// target, the absolute-form URL, the cage address); re-targeting to
    /// the `Host` name is the handler's job (see [`retarget_to_host`]).
    fn request(
        &self,
        conn: &ConnInfo,
        req: &mut Request,
    ) -> impl Future<Output = RequestAction<Self::Flow>> + Send;

    /// The response hook: the complete upstream response. The handler may
    /// rewrite or replace `resp` in place (a response block); `req` is the
    /// request as it was sent upstream, which the handler may rewrite for
    /// its own records (the transport only reads it again for WebSocket
    /// hooks).
    fn response(
        &self,
        conn: &ConnInfo,
        flow: &mut Self::Flow,
        req: &mut Request,
        resp: &mut Response,
    ) -> impl Future<Output = ()> + Send;

    /// One complete WebSocket message, either direction.
    fn websocket_message(
        &self,
        conn: &ConnInfo,
        flow: &mut Self::Flow,
        req: &Request,
        msg: &mut WsMessage,
    ) -> impl Future<Output = WsVerdict> + Send;

    /// A forwarded flow is over (see [`FlowEnd`]).
    fn flow_end(&self, conn: &ConnInfo, flow: Self::Flow, end: FlowEnd);

    /// A forwarded request got no response (plan D5): return what the
    /// client gets (a JSON 502) and record it.
    fn upstream_error(
        &self,
        conn: &ConnInfo,
        flow: Self::Flow,
        req: &Request,
        err: &UpstreamError,
    ) -> Response;

    /// The transport refused a request before the request hook: return
    /// the response (403 for a port, 413 for a body) and record it.
    /// `req` is the request head when there is one.
    fn transport_refusal(
        &self,
        conn: &ConnInfo,
        req: Option<&Request>,
        refusal: &Refusal,
    ) -> Response;

    /// A connection on an intercepted port turned out not to be HTTP (raw
    /// TCP, TLS without HTTP inside, a non-WebSocket `101` upgrade). The
    /// transport closes it right after this returns; no upstream socket
    /// was or will be opened.
    fn tcp_bypass(&self, conn: &ConnInfo);

    /// Vet the resolved addresses of an upstream connection before any is
    /// dialled (the peer guard).
    fn server_connect(
        &self,
        conn: &ConnInfo,
        target: &ConnectTarget,
        resolved: &[IpAddr],
    ) -> ConnectDecision;

    /// Whether `candidate` (`host:port`, a `Host` header, `sni:port`)
    /// names a passthrough destination. [`PassthroughMatcher`] implements
    /// the configured rule.
    fn is_passthrough(&self, conn: &ConnInfo, candidate: &str) -> bool;
}

/// Transport settings that a reload may change; read once per request
/// through [`BoundProxy::settings`], so swapping them never touches an
/// open connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportSettings {
    /// The largest request or response body buffered (plan D6).
    pub max_body: usize,
    /// The ports forward-proxy targets may use (`INSPECTED_TCP_PORTS`,
    /// plan D3).
    pub inspected_ports: Vec<u16>,
}

/// The default body cap: 256 MiB.
pub const DEFAULT_MAX_BODY: usize = 256 * 1024 * 1024;

impl Default for TransportSettings {
    fn default() -> Self {
        Self {
            max_body: DEFAULT_MAX_BODY,
            inspected_ports: vec![80, 443],
        }
    }
}

/// Parse `INSPECTED_TCP_PORTS` (space- or comma-separated ports).
///
/// # Errors
///
/// A token is not a port number.
pub fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    text.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .map(|t| t.parse::<u16>().map_err(|_| format!("not a port: {t:?}")))
        .collect()
}

/// The static parts of a proxy: its CA, upstream trust and settings.
pub struct Proxy<H: FlowHandler> {
    handler: Arc<H>,
    ca: Arc<CertAuthority>,
    upstream_tls: Arc<tls::UpstreamTls>,
    settings: Arc<ArcSwap<TransportSettings>>,
    original_dst: Option<OriginalDstFn>,
}

impl<H: FlowHandler> std::fmt::Debug for Proxy<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy").finish_non_exhaustive()
    }
}

impl<H: FlowHandler> Proxy<H> {
    /// A proxy that mints leaves from `ca`, verifies upstreams against the
    /// Mozilla roots, and asks `handler` for every decision.
    #[must_use]
    pub fn new(handler: Arc<H>, ca: Arc<CertAuthority>, settings: TransportSettings) -> Self {
        Self {
            handler,
            ca,
            upstream_tls: Arc::new(tls::UpstreamTls::new(Vec::new())),
            settings: Arc::new(ArcSwap::from_pointee(settings)),
            original_dst: None,
        }
    }

    /// Also trust these roots upstream. Test-only (`--upstream-ca`): a
    /// production egress verifies against the Mozilla bundle alone.
    #[doc(hidden)]
    #[must_use]
    pub fn with_extra_upstream_roots(
        mut self,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        self.upstream_tls = Arc::new(tls::UpstreamTls::new(roots));
        self
    }

    /// Replace how the transparent listener learns a connection's
    /// original destination (`SO_ORIGINAL_DST` by default). Test seam:
    /// scenario tests have no iptables `REDIRECT`.
    #[doc(hidden)]
    #[must_use]
    pub fn with_original_dst(mut self, f: OriginalDstFn) -> Self {
        self.original_dst = Some(f);
        self
    }

    /// Bind every listener, then serve with [`BoundProxy::run`].
    ///
    /// # Errors
    ///
    /// A listener address cannot be bound.
    pub async fn bind(self, specs: &[ListenerSpec]) -> std::io::Result<BoundProxy<H>> {
        listen::bind(self, specs).await
    }
}

/// The status reason phrases the replaced implementation used.
#[must_use]
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Time-out",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range not satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        444 => "No Response",
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Time-out",
        505 => "HTTP Version not supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage Space",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

/// A synthesized response, shaped like the replaced implementation's:
/// `HTTP/1.1`, the standard reason phrase, the given headers in order,
/// then `content-length`.
#[must_use]
pub fn make_response(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> Response {
    let mut list = Headers::new();
    for (name, value) in headers {
        list.add(*name, *value);
    }
    list.add("content-length", body.len().to_string());
    Response {
        status,
        reason: reason_phrase(status).to_string(),
        http_version: "HTTP/1.1".to_string(),
        headers: list,
        body,
    }
}

/// Split a `Host` header / authority into host and optional port, the way
/// the replaced implementation's lenient parse did: brackets removed from
/// an IPv6 literal; a value that does not parse is returned whole with no
/// port.
#[must_use]
pub fn parse_authority(authority: &str) -> (String, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            if tail.is_empty() {
                return (host.to_string(), None);
            }
            if let Some(port) = tail.strip_prefix(':').and_then(|p| p.parse().ok()) {
                return (host.to_string(), Some(port));
            }
        }
        return (authority.to_string(), None);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !host.is_empty() => match port.parse() {
            Ok(port) => (host.to_string(), Some(port)),
            Err(_) => (authority.to_string(), None),
        },
        _ => (authority.to_string(), None),
    }
}

/// `host[:port]`, the port left out when it is the scheme's default; an
/// IPv6 literal is bracketed.
#[must_use]
pub fn host_port(scheme: &str, host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let default = matches!((scheme, port), ("http", 80) | ("https", 443));
    if default {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// Re-target an outbound request to the name in its `Host` header, keeping
/// the destination port (a port in the header is ignored), and rewrite an
/// existing `Host` header to `host[:port]` to match — what setting the
/// request's host did in the replaced implementation. A request whose
/// `Host` names the destination already is left alone. Returns whether
/// the host changed.
pub fn retarget_to_host(req: &mut Request) -> bool {
    let Some(header) = req.host_header() else {
        return false;
    };
    let (name, _) = parse_authority(&header);
    if name == req.host {
        return false;
    }
    req.host = name;
    if req.headers.contains("host") {
        let value = host_port(&req.scheme, &req.host, req.port);
        req.headers.set("Host", value);
    }
    true
}

/// The `domains.passthrough` rule: a candidate matches a domain `d` when it
/// is `d` or a subdomain of it, optionally followed by `:<port>`,
/// case-insensitively (`^(.+\.)?<d>(:\d+)?$` per domain).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassthroughMatcher {
    domains: Vec<String>,
}

impl PassthroughMatcher {
    /// A matcher for `domains`.
    #[must_use]
    pub fn new(domains: &[String]) -> Self {
        Self {
            domains: domains.iter().map(|d| d.to_ascii_lowercase()).collect(),
        }
    }

    /// Whether no domain is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Whether `candidate` matches any configured domain.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        let candidate = candidate.to_ascii_lowercase();
        // Strip an optional `:<digits>` suffix, as the pattern allows it.
        let host = match candidate.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                host
            }
            _ => candidate.as_str(),
        };
        self.domains.iter().any(|d| {
            host == d
                || (host.len() > d.len() + 1
                    && host.ends_with(d.as_str())
                    && host.as_bytes()[host.len() - d.len() - 1] == b'.')
        })
    }
}

/// A handler that forwards everything unchanged (after re-targeting to
/// the `Host` name on outbound flows), allows every address and records
/// nothing. For tests, and the binary until the request pipeline is wired.
#[derive(Debug, Default)]
pub struct PassThroughHandler {
    /// Passthrough domains.
    pub passthrough: PassthroughMatcher,
}

impl FlowHandler for PassThroughHandler {
    type Flow = ();

    fn request(
        &self,
        conn: &ConnInfo,
        req: &mut Request,
    ) -> impl Future<Output = RequestAction<()>> + Send {
        if conn.direction() == Direction::Outbound {
            retarget_to_host(req);
        }
        std::future::ready(RequestAction::Forward(()))
    }

    fn response(
        &self,
        _: &ConnInfo,
        (): &mut (),
        _: &mut Request,
        _: &mut Response,
    ) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }

    fn websocket_message(
        &self,
        _: &ConnInfo,
        (): &mut (),
        _: &Request,
        _: &mut WsMessage,
    ) -> impl Future<Output = WsVerdict> + Send {
        std::future::ready(WsVerdict::Forward)
    }

    fn flow_end(&self, _: &ConnInfo, (): (), _: FlowEnd) {}

    fn upstream_error(&self, _: &ConnInfo, (): (), _: &Request, err: &UpstreamError) -> Response {
        make_response(
            502,
            &[("Content-Type", "text/plain")],
            err.to_string().into_bytes(),
        )
    }

    fn transport_refusal(&self, _: &ConnInfo, _: Option<&Request>, refusal: &Refusal) -> Response {
        match refusal {
            Refusal::ForwardPort { host, port } => make_response(
                403,
                &[("Content-Type", "text/plain")],
                format!("port {port} is not an inspected port ({host})").into_bytes(),
            ),
            Refusal::RequestBodyTooLarge { limit } => make_response(
                413,
                &[("Content-Type", "text/plain")],
                format!("request body exceeds {limit} bytes").into_bytes(),
            ),
        }
    }

    fn tcp_bypass(&self, _: &ConnInfo) {}

    fn server_connect(
        &self,
        _: &ConnInfo,
        _: &ConnectTarget,
        resolved: &[IpAddr],
    ) -> ConnectDecision {
        ConnectDecision::Allow(resolved.to_vec())
    }

    fn is_passthrough(&self, _: &ConnInfo, candidate: &str) -> bool {
        self.passthrough.matches(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_parsing_is_lenient() {
        assert_eq!(parse_authority("example.com"), ("example.com".into(), None));
        assert_eq!(
            parse_authority("example.com:8443"),
            ("example.com".into(), Some(8443))
        );
        assert_eq!(parse_authority("[::1]:443"), ("::1".into(), Some(443)));
        assert_eq!(parse_authority("[::1]"), ("::1".into(), None));
        assert_eq!(parse_authority("::1"), ("::1".into(), None));
        assert_eq!(parse_authority("a:b"), ("a:b".into(), None));
    }

    #[test]
    fn retargeting_follows_the_host_name_and_keeps_the_port() {
        let mut req = Request {
            scheme: "https".into(),
            host: "192.0.2.1".into(),
            port: 443,
            ..Request::default()
        };
        req.headers.add("host", "example.com:9999");
        assert!(retarget_to_host(&mut req));
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert_eq!(req.headers.get("host").as_deref(), Some("example.com"));
        assert_eq!(req.headers.0[0].0, b"host", "spelling kept");
        req.port = 8443;
        req.host = "192.0.2.1".into();
        retarget_to_host(&mut req);
        assert_eq!(req.headers.get("host").as_deref(), Some("example.com:8443"));
        assert!(!retarget_to_host(&mut req), "already there");
    }

    #[test]
    fn passthrough_matches_domain_subdomains_and_ports() {
        let m = PassthroughMatcher::new(&["Pinned.example".to_string()]);
        for yes in [
            "pinned.example",
            "a.pinned.example",
            "x.y.PINNED.example:443",
            "pinned.example:8443",
        ] {
            assert!(m.matches(yes), "{yes}");
        }
        for no in [
            "notpinned.example",
            "pinned.example.evil",
            "pinned.examplex:443",
            ".pinned.example",
            "pinned.example:",
        ] {
            assert!(!m.matches(no), "{no}");
        }
    }

    #[test]
    fn bypass_target_prefers_sni_then_address() {
        let mut conn = ConnInfo {
            id: 1,
            listener: ListenerKind::Transparent,
            client_addr: "10.0.0.2:5000".parse().unwrap(),
            local_addr: "10.0.0.1:8443".parse().unwrap(),
            server_addr: Some(ServerAddr {
                host: "1.1.1.1".into(),
                port: 443,
            }),
            via_connect: false,
            sni: None,
            tls: false,
            alpn: None,
        };
        assert_eq!(conn.bypass_target(), "1.1.1.1:443");
        conn.sni = Some("x.test".into());
        assert_eq!(conn.bypass_target(), "x.test");
        conn.sni = None;
        conn.server_addr = None;
        assert_eq!(conn.bypass_target(), "<unknown>");
    }

    #[test]
    fn synthesized_responses_end_with_content_length() {
        let r = make_response(403, &[("Content-Type", "application/json")], b"{}".to_vec());
        assert_eq!(r.reason, "Forbidden");
        assert_eq!(
            r.headers.to_strings(),
            vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("content-length".to_string(), "2".to_string())
            ]
        );
    }
}
