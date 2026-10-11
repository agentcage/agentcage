//! Listeners: the forward proxy, the transparent listener and the
//! reverse listeners, and the accept loops behind them.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::net::{TcpListener, TcpStream};

use super::conn::{self, Shared};
use super::{FlowHandler, ListenerKind, Proxy, ServerAddr, TransportSettings};

/// How the transparent listener learns where a redirected connection was
/// going.
pub type OriginalDstFn = Arc<dyn Fn(&TcpStream) -> io::Result<SocketAddr> + Send + Sync>;

/// One listener to bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerSpec {
    /// The forward proxy (`--regular`).
    Regular(SocketAddr),
    /// The transparent listener (`--transparent`).
    Transparent(SocketAddr),
    /// A reverse listener (`--reverse <target>@<bind>`): plain HTTP to
    /// `target`, the `Host` header kept.
    Reverse {
        /// Where to listen.
        bind: SocketAddr,
        /// The cage address and port to forward to.
        target: SocketAddr,
    },
}

impl ListenerSpec {
    fn bind_addr(&self) -> SocketAddr {
        match self {
            Self::Regular(a) | Self::Transparent(a) => *a,
            Self::Reverse { bind, .. } => *bind,
        }
    }

    fn kind(&self) -> ListenerKind {
        match self {
            Self::Regular(_) => ListenerKind::Regular,
            Self::Transparent(_) => ListenerKind::Transparent,
            Self::Reverse { .. } => ListenerKind::Reverse,
        }
    }
}

/// A malformed `--reverse` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseSpecError(pub String);

impl std::fmt::Display for ReverseSpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid reverse listener {:?}: expected <cage_ip>:<port>@<bind_ip>:<port>",
            self.0
        )
    }
}

impl std::error::Error for ReverseSpecError {}

/// Parse a listen address: `ip:port`, `[v6]:port`, or `:port` (all IPv4
/// interfaces).
///
/// # Errors
///
/// The text is not an address.
pub fn parse_bind(text: &str) -> Result<SocketAddr, String> {
    let full = if text.starts_with(':') {
        format!("0.0.0.0{text}")
    } else {
        text.to_string()
    };
    full.parse()
        .map_err(|_| format!("invalid listen address: {text:?}"))
}

/// Parse `--reverse <cage_ip>:<port>@<bind>:<port>` (an `http://` before
/// the target is accepted).
///
/// # Errors
///
/// Either half is not an address.
pub fn parse_reverse_spec(text: &str) -> Result<ListenerSpec, ReverseSpecError> {
    let err = || ReverseSpecError(text.to_string());
    let (target, bind) = text.split_once('@').ok_or_else(err)?;
    let target = target.strip_prefix("http://").unwrap_or(target);
    Ok(ListenerSpec::Reverse {
        bind: parse_bind(bind).map_err(|_| err())?,
        target: target.parse().map_err(|_| err())?,
    })
}

/// Bound listeners, ready to serve.
pub struct BoundProxy<H: FlowHandler> {
    shared: Arc<Shared<H>>,
    listeners: Vec<(ListenerSpec, TcpListener)>,
    original_dst: OriginalDstFn,
}

impl<H: FlowHandler> std::fmt::Debug for BoundProxy<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundProxy")
            .field("listeners", &self.local_addrs())
            .finish_non_exhaustive()
    }
}

pub(crate) async fn bind<H: FlowHandler>(
    proxy: Proxy<H>,
    specs: &[ListenerSpec],
) -> io::Result<BoundProxy<H>> {
    let mut listeners = Vec::with_capacity(specs.len());
    for spec in specs {
        let listener = TcpListener::bind(spec.bind_addr()).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot listen on {}: {e}", spec.bind_addr()),
            )
        })?;
        listeners.push((spec.clone(), listener));
    }
    Ok(BoundProxy {
        shared: Arc::new(Shared {
            handler: proxy.handler,
            ca: proxy.ca,
            upstream_tls: proxy.upstream_tls,
            settings: proxy.settings,
        }),
        listeners,
        original_dst: proxy.original_dst.unwrap_or_else(|| Arc::new(original_dst)),
    })
}

impl<H: FlowHandler> BoundProxy<H> {
    /// Each listener's kind and actual address (port 0 resolved).
    #[must_use]
    pub fn local_addrs(&self) -> Vec<(ListenerKind, SocketAddr)> {
        self.listeners
            .iter()
            .filter_map(|(spec, l)| Some((spec.kind(), l.local_addr().ok()?)))
            .collect()
    }

    /// The live transport settings: store a new value to reconfigure
    /// without touching open connections.
    #[must_use]
    pub fn settings(&self) -> Arc<ArcSwap<TransportSettings>> {
        Arc::clone(&self.shared.settings)
    }

    /// Accept and serve on every listener until the process exits.
    ///
    /// # Errors
    ///
    /// Never returns `Ok`; an accept loop that fails for good returns its
    /// error.
    pub async fn run(self) -> io::Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        for (spec, listener) in self.listeners {
            let shared = Arc::clone(&self.shared);
            let original_dst = Arc::clone(&self.original_dst);
            tasks.spawn(accept_loop(shared, spec, listener, original_dst));
        }
        match tasks.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(e)) => Err(io::Error::other(e)),
            None => Ok(()),
        }
    }
}

async fn accept_loop<H: FlowHandler>(
    shared: Arc<Shared<H>>,
    spec: ListenerSpec,
    listener: TcpListener,
    original_dst: OriginalDstFn,
) -> io::Result<()> {
    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Per-connection failures (EMFILE, ECONNABORTED) must not
                // stop the listener.
                eprintln!("agentcage-egress: accept on {}: {e}", spec.bind_addr());
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(local_addr) = stream.local_addr() else {
            continue;
        };
        let server_addr = match &spec {
            ListenerSpec::Regular(_) => None,
            ListenerSpec::Reverse { target, .. } => Some(ServerAddr {
                host: target.ip().to_string(),
                port: target.port(),
            }),
            ListenerSpec::Transparent(_) => match original_dst(&stream) {
                // A connection that reached the transparent port without
                // being redirected would make the proxy dial itself.
                Ok(dst) if dst == local_addr => {
                    eprintln!(
                        "agentcage-egress: connection from {client_addr} to {local_addr} was not redirected; closing"
                    );
                    continue;
                }
                Ok(dst) => Some(ServerAddr {
                    host: dst.ip().to_string(),
                    port: dst.port(),
                }),
                Err(e) => {
                    eprintln!(
                        "agentcage-egress: no original destination for {client_addr}: {e}; closing"
                    );
                    continue;
                }
            },
        };
        let shared = Arc::clone(&shared);
        let kind = spec.kind();
        tokio::spawn(conn::handle(
            shared,
            stream,
            kind,
            client_addr,
            local_addr,
            server_addr,
        ));
    }
}

/// `SO_ORIGINAL_DST` (`IP6T_SO_ORIGINAL_DST` for IPv6): where the client
/// was connecting before iptables `REDIRECT` sent it here.
///
/// # Errors
///
/// No conntrack entry, or not Linux.
#[cfg(target_os = "linux")]
pub fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    use nix::sys::socket::{getsockopt, sockopt};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};
    if stream.local_addr()?.is_ipv6() {
        let raw = getsockopt(stream, sockopt::Ip6tOriginalDst).map_err(io::Error::from)?;
        let ip = Ipv6Addr::from(raw.sin6_addr.s6_addr);
        return Ok(SocketAddr::V6(SocketAddrV6::new(
            ip,
            u16::from_be(raw.sin6_port),
            0,
            0,
        )));
    }
    let raw = getsockopt(stream, sockopt::OriginalDst).map_err(io::Error::from)?;
    let ip = Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr));
    Ok(SocketAddr::new(ip.into(), u16::from_be(raw.sin_port)))
}

/// `SO_ORIGINAL_DST` exists only on Linux.
///
/// # Errors
///
/// Always.
#[cfg(not(target_os = "linux"))]
pub fn original_dst(_: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_and_reverse_specs_parse() {
        assert_eq!(
            parse_bind(":8443").unwrap(),
            "0.0.0.0:8443".parse().unwrap()
        );
        assert_eq!(
            parse_bind("10.1.2.3:8080").unwrap(),
            "10.1.2.3:8080".parse().unwrap()
        );
        assert!(parse_bind("nope").is_err());
        assert_eq!(
            parse_reverse_spec("10.0.0.5:3000@0.0.0.0:3000").unwrap(),
            ListenerSpec::Reverse {
                bind: "0.0.0.0:3000".parse().unwrap(),
                target: "10.0.0.5:3000".parse().unwrap(),
            }
        );
        assert!(parse_reverse_spec("http://10.0.0.5:3000@:3000").is_ok());
        assert!(parse_reverse_spec("10.0.0.5:3000").is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn original_dst_without_a_redirect_is_the_local_address_or_an_error() {
        // No iptables here: the kernel reports either the connection's own
        // destination (conntrack loaded, no NAT) or ENOENT. Both are
        // handled by the accept loop; the REDIRECT path is e2e-only.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        match original_dst(&server) {
            Ok(dst) => assert_eq!(dst, addr),
            Err(e) => assert!(e.raw_os_error().is_some(), "{e}"),
        }
    }
}
