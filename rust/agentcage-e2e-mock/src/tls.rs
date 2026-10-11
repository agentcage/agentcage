//! The upstream of a passthrough domain: a TLS server with its own
//! self-signed certificate, generated at startup so no private key is
//! ever committed.
//!
//! Test 9.21 identifies the certificate by its issuer O, which must read
//! [`ISSUER_O`]: a cage that is shown it was spliced through, while one
//! shown a cage-CA certificate was intercepted.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// Default listen address. Every interface, not loopback: a passthrough
/// splice dials the cage's ORIGINAL destination, which phase 9 points at
/// the egress's own cage-network address.
pub const ADDR: &str = "0.0.0.0:443";
/// The certificate's subject (and so issuer) organization.
pub const ISSUER_O: &str = "e2e passthrough mock";
/// The certificate's CN and only subjectAltName.
pub const NAME: &str = "pt.e2e.test";

/// The body every request is answered with.
const BODY: &str = r#"{"passthrough": true}"#;

/// A server config holding a fresh self-signed certificate for [`NAME`],
/// and that certificate.
///
/// # Errors
/// When key generation or certificate signing fails.
pub fn server_config()
-> Result<(Arc<ServerConfig>, CertificateDer<'static>), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(vec![NAME.to_owned()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, ISSUER_O);
    dn.push(DnType::CommonName, NAME);
    params.distinguished_name = dn;
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let cert = CertificateDer::from(cert.der().to_vec());
    let chain = vec![cert.clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(config), cert))
}

/// Serve one connection: handshake, read once, answer with a small JSON
/// document and close.
///
/// # Errors
/// On handshake or I/O errors; the caller drops the connection.
pub fn handle(stream: TcpStream, config: &Arc<ServerConfig>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let conn = ServerConnection::new(Arc::clone(config)).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, stream);
    let mut buf = vec![0u8; 65_536];
    let _ = tls.read(&mut buf)?;
    write!(
        tls,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )?;
    tls.conn.send_close_notify();
    tls.flush()
}
