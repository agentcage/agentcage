//! rustls configuration for both sides of an intercepted connection.

use std::sync::Arc;

use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
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

/// The client-facing TLS config for one connection: `leaf`, and an ALPN
/// list that makes rustls pick exactly `alpn` — the client's first offer
/// the proxy speaks. When the client offered protocols but none the proxy
/// speaks, the list holds one it cannot have offered, so the handshake
/// fails with `no_application_protocol`, as the replaced implementation's
/// did; a client that offered none gets no ALPN.
pub(crate) fn server_config(
    leaf: Arc<CertifiedKey>,
    alpn: Option<Vec<u8>>,
    client_offered_alpn: bool,
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
    Ok(Arc::new(config))
}

/// The upstream trust store: the Mozilla roots plus any test roots.
#[derive(Debug)]
pub(crate) struct UpstreamTls {
    roots: Arc<rustls::RootCertStore>,
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
        }
    }

    /// A client config offering `alpn` (the client's own offers, mirrored).
    pub(crate) fn client_config(
        &self,
        alpn: &[Vec<u8>],
    ) -> Result<Arc<ClientConfig>, rustls::Error> {
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(Arc::clone(&self.roots))
            .with_no_client_auth();
        config.alpn_protocols = alpn.to_vec();
        Ok(Arc::new(config))
    }
}

/// The name an upstream certificate is verified against: an address
/// literal is verified as an IP SAN (and sends no SNI), anything else as a
/// DNS name.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(bare.to_string()).map_err(|e| format!("invalid server name {host:?}: {e}"))
}
