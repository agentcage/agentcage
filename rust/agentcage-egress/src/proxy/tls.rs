//! rustls configuration for both sides of an intercepted connection.
//!
//! Both sides resume TLS sessions. Upstream, one client config per ALPN
//! list is built once and kept, so its session cache outlives the
//! connection that filled it: a new client connection to a host the egress
//! talked to recently skips the full handshake (and its certificate chain
//! verification). Cage-facing, every per-connection server config shares
//! one ticket key, so an agent reconnecting to the same name resumes
//! instead of paying for a fresh key exchange.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{
    ClientHello, NoServerSessionStorage, ProducesTickets, ResolvesServerCert, ServerConfig,
};
use rustls::sign::CertifiedKey;

/// The most upstream client configs kept, one per distinct ALPN list. The
/// list mirrors the client's offer, so it is cage-controlled; past this a
/// config is built per connection again (and resumes nothing) rather than
/// letting the map grow.
const MAX_CLIENT_CONFIGS: usize = 32;

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

/// Serves one pre-minted leaf whatever the client asks for: the leaf was
/// minted from this connection's `ClientHello` before the handshake began.
#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// The ticket key every cage-facing TLS session shares (rotated by rustls
/// every six hours, never written anywhere); `None` when the platform
/// cannot make one, which only costs resumption.
pub(crate) fn ticketer() -> Option<Arc<dyn ProducesTickets>> {
    rustls::crypto::ring::Ticketer::new().ok()
}

/// The client-facing TLS config for one connection: `leaf`, and an ALPN
/// list that makes rustls pick exactly `alpn` — the client's first offer
/// the proxy speaks. When the client offered protocols but none the proxy
/// speaks, the list holds one it cannot have offered, so the handshake
/// fails with `no_application_protocol`, as the replaced implementation's
/// did; a client that offered none gets no ALPN.
///
/// With `tickets`, the session can be resumed from a ticket. rustls only
/// resumes a session under the SNI it was made for, and the caller only
/// passes tickets when the client sent one, so a resumed session never
/// stands in for a leaf minted for another name.
pub(crate) fn server_config(
    leaf: Arc<CertifiedKey>,
    alpn: Option<Vec<u8>>,
    client_offered_alpn: bool,
    tickets: Option<&Arc<dyn ProducesTickets>>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(leaf)));
    config.alpn_protocols = match alpn {
        Some(proto) => vec![proto],
        None if client_offered_alpn => vec![b"\x00agentcage-none".to_vec()],
        None => Vec::new(),
    };
    // A per-connection session cache could never be hit again; resumption
    // is by ticket only.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    if let Some(tickets) = tickets {
        config.ticketer = Arc::clone(tickets);
    }
    Ok(Arc::new(config))
}

/// The upstream trust store (the Mozilla roots plus any test roots) and
/// the client configs built from it.
#[derive(Debug)]
pub(crate) struct UpstreamTls {
    roots: Arc<rustls::RootCertStore>,
    configs: Mutex<HashMap<Vec<Vec<u8>>, Arc<ClientConfig>>>,
}

impl UpstreamTls {
    pub(crate) fn new(extra: Vec<CertificateDer<'static>>) -> Self {
        let mut roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for cert in extra {
            // A malformed test root is the test's problem; skip it.
            let _ = roots.add(cert);
        }
        Self {
            roots: Arc::new(roots),
            configs: Mutex::new(HashMap::new()),
        }
    }

    /// A client config offering `alpn` (the client's own offers,
    /// mirrored), the same one every time for the same list: its session
    /// cache (rustls' default, keyed by server name) is what lets the next
    /// connection to a host resume.
    pub(crate) fn client_config(
        &self,
        alpn: &[Vec<u8>],
    ) -> Result<Arc<ClientConfig>, rustls::Error> {
        let mut configs = self.configs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(config) = configs.get(alpn) {
            return Ok(Arc::clone(config));
        }
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(Arc::clone(&self.roots))
            .with_no_client_auth();
        config.alpn_protocols = alpn.to_vec();
        let config = Arc::new(config);
        if configs.len() < MAX_CLIENT_CONFIGS {
            configs.insert(alpn.to_vec(), Arc::clone(&config));
        }
        Ok(config)
    }
}

/// The name an upstream certificate is verified against: an address
/// literal is verified as an IP SAN (and sends no SNI), anything else as a
/// DNS name.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(bare.to_string()).map_err(|e| format!("invalid server name {host:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::HandshakeKind;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    fn leaf_for(name: &str) -> (CertificateDer<'static>, Arc<CertifiedKey>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().clone();
        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing = provider().key_provider.load_private_key(pk).unwrap();
        (der.clone(), Arc::new(CertifiedKey::new(vec![der], signing)))
    }

    /// A TLS server that answers each connection with one byte and reports
    /// how each handshake went.
    async fn server(
        config: Arc<ServerConfig>,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::Receiver<HandshakeKind>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(config);
            while let Ok((tcp, _)) = listener.accept().await {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let kind = tls.get_ref().1.handshake_kind().unwrap();
                let _ = tls.write_all(b"x").await;
                let _ = tls.shutdown().await;
                let _ = tx.send(kind).await;
            }
        });
        (addr, rx)
    }

    async fn connect(
        config: Arc<ClientConfig>,
        addr: std::net::SocketAddr,
        name: &str,
    ) -> HandshakeKind {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(config)
            .connect(server_name(name).unwrap(), tcp)
            .await
            .unwrap();
        // Reading drives the post-handshake ticket messages in.
        let mut byte = [0u8; 1];
        tls.read_exact(&mut byte).await.unwrap();
        tls.get_ref().1.handshake_kind().unwrap()
    }

    #[tokio::test]
    async fn the_upstream_side_resumes_across_connections() {
        let (der, leaf) = leaf_for("upstream.test");
        let tickets = ticketer().unwrap();
        let (addr, mut seen) =
            server(server_config(leaf, None, false, Some(&tickets)).unwrap()).await;
        let upstream = UpstreamTls::new(vec![der]);
        let first = upstream.client_config(&[]).unwrap();
        assert_eq!(
            connect(first, addr, "upstream.test").await,
            HandshakeKind::Full
        );
        assert_eq!(seen.recv().await, Some(HandshakeKind::Full));
        // A new connection, as a new client connection would make: the
        // cached config remembers the session.
        let again = upstream.client_config(&[]).unwrap();
        assert_eq!(
            connect(again, addr, "upstream.test").await,
            HandshakeKind::Resumed
        );
        assert_eq!(seen.recv().await, Some(HandshakeKind::Resumed));
    }

    #[tokio::test]
    async fn the_cage_side_resumes_only_with_a_shared_ticket_key() {
        let (der, leaf) = leaf_for("cage.test");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let client = Arc::new(
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        // A new server config per connection, as the proxy builds them,
        // sharing the ticket key: the second connection resumes.
        let tickets = ticketer().unwrap();
        for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
            let config = server_config(Arc::clone(&leaf), None, false, Some(&tickets)).unwrap();
            let (addr, _seen) = server(config).await;
            assert_eq!(
                connect(Arc::clone(&client), addr, "cage.test").await,
                expected
            );
        }
        // Without the ticket key nothing resumes.
        let (addr, _seen) = server(server_config(leaf, None, false, None).unwrap()).await;
        assert_eq!(
            connect(client, addr, "cage.test").await,
            HandshakeKind::Full
        );
    }

    #[test]
    fn client_configs_are_cached_per_alpn_list_and_bounded() {
        let upstream = UpstreamTls::new(Vec::new());
        let h2 = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let a = upstream.client_config(&h2).unwrap();
        let b = upstream.client_config(&h2).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let c = upstream.client_config(&[]).unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        for i in 0..MAX_CLIENT_CONFIGS * 2 {
            let _ = upstream.client_config(&[format!("p{i}").into_bytes()]);
        }
        assert_eq!(upstream.configs.lock().unwrap().len(), MAX_CLIENT_CONFIGS);
    }
}
