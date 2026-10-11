//! Upstream TLS policy shared by the IMAP and SMTP relays.
//!
//! One module rather than a copy in each relay: a drifting copy would
//! silently downgrade certificate verification on one protocol and not
//! the other, the class of bug that never shows up in a passing test run.
//!
//! The trust store always starts from the Mozilla roots
//! (`webpki-roots`), which is what a public mail host needs. `ca_pem` is
//! *added* to it, for upstreams no public CA covers: a self-hosted server
//! behind a private CA, or a local decrypting daemon (such as a mail
//! bridge) that mints its own self-signed certificate at setup time.
//! Additive, not exclusive: one relay's private certificate is never the
//! reason another relay can't reach a normal upstream. The cost is that
//! `ca_pem` does not pin; a public CA that mis-issues for the same name
//! still satisfies the check.
//!
//! Verification and the name check stay on in every case. There is
//! deliberately no "skip verification" mode: an unverified upstream is an
//! unauthenticated one, and the relay hands it real credentials. When the
//! upstream is addressed by IP, so its certificate name can never match,
//! the operator adds the certificate and names it with `tls_servername`,
//! which is presented in SNI and checked against the certificate.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_name};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

use super::Stream;

/// How long the TLS handshake may take, as asyncio's default
/// `ssl_handshake_timeout`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// The ring provider, the one the whole crate uses.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build the client config for a relay's upstream: the Mozilla roots
/// plus every certificate in `ca_pem`.
///
/// # Errors
///
/// `ca_pem` holds no certificate, or one that does not parse. The
/// message goes into the relay's upstream-failure audit record.
pub fn client_config(ca_pem: &str) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut pinned = Vec::new();
    if !ca_pem.is_empty() {
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            let cert = cert.map_err(|e| format!("ca_pem: cannot read PEM: {e}"))?;
            roots
                .add(cert.clone())
                .map_err(|e| format!("ca_pem: unusable certificate: {e}"))?;
            pinned.push(cert);
        }
        if pinned.is_empty() {
            return Err("ca_pem: no certificate or crl found".to_owned());
        }
    }
    let provider = provider();
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .map_err(|e| format!("cannot build certificate verifier: {e}"))?;
    let verifier = Arc::new(Verifier { inner, pinned });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Handshake with `name` as SNI and the name the certificate must carry.
pub(crate) async fn handshake(
    config: Arc<ClientConfig>,
    name: &str,
    tcp: tokio::net::TcpStream,
) -> Result<Box<dyn Stream>, String> {
    let server_name = ServerName::try_from(name.to_owned()).map_err(|_| {
        format!(
            "invalid server name: {}",
            agentcage_core::python::repr_str(name)
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp)).await {
        Ok(Ok(stream)) => Ok(Box::new(stream)),
        Ok(Err(e)) => Err(handshake_error(&e, name)),
        Err(_) => Err(
            "SSL handshake is taking longer than 60.0 seconds: aborting the connection".to_owned(),
        ),
    }
}

/// The handshake failure as a sentence. Certificate problems read
/// `certificate verify failed: …`, the wording operators (and the
/// replaced implementation's tests) look for.
fn handshake_error(e: &std::io::Error, name: &str) -> String {
    let Some(tls) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return e.to_string();
    };
    match tls {
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => format!("certificate verify failed: certificate is not valid for '{name}'"),
        rustls::Error::InvalidCertificate(cert) => {
            format!("certificate verify failed: {}", describe(cert))
        }
        other => other.to_string(),
    }
}

fn describe(e: &CertificateError) -> String {
    match e {
        CertificateError::UnknownIssuer => "unable to get local issuer certificate".to_owned(),
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
            "certificate has expired".to_owned()
        }
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            "certificate is not yet valid".to_owned()
        }
        other => format!("{other:?}"),
    }
}

/// The Mozilla-roots-plus-`ca_pem` verifier, plus one fallback.
///
/// A self-signed certificate the operator put in `ca_pem` is accepted
/// when the server presents exactly that certificate, even if it is
/// flagged as a CA. The path validator refuses a CA certificate used as
/// a server certificate, but that is precisely what local decrypting
/// daemons generate (a self-signed, CA-flagged certificate that is its
/// own trust anchor), and the replaced implementation's TLS stack took
/// it. The fallback still checks the name and the validity period; the
/// trust comes from the presented bytes being identical to an anchor the
/// operator configured.
#[derive(Debug)]
struct Verifier {
    inner: Arc<WebPkiServerVerifier>,
    pinned: Vec<CertificateDer<'static>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let err = match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(ok) => return Ok(ok),
            Err(e) => e,
        };
        if !self
            .pinned
            .iter()
            .any(|p| p.as_ref() == end_entity.as_ref())
        {
            return Err(err);
        }
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_name(&parsed, server_name)?;
        let Some((not_before, not_after)) = validity(end_entity.as_ref()) else {
            return Err(CertificateError::BadEncoding.into());
        };
        let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        if now < not_before {
            return Err(CertificateError::NotValidYet.into());
        }
        if now > not_after {
            return Err(CertificateError::Expired.into());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ── Certificate validity, read straight from the DER ────

/// One DER TLV: `(tag, content, rest)`.
fn tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// `(notBefore, notAfter)` of a certificate, as Unix seconds.
///
/// Only the fallback in [`Verifier`] needs this, for a certificate the
/// path validator already parsed, so a small walker over the fixed
/// prefix of `TBSCertificate` is enough: optional `[0]` version, serial,
/// signature algorithm, issuer, then `Validity`.
fn validity(der: &[u8]) -> Option<(i64, i64)> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    let (tag, _, after) = tlv(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    for _ in 0..3 {
        rest = tlv(rest)?.2; // serial, signature, issuer
    }
    let (_, validity, _) = tlv(rest)?;
    let (t1, nb, more) = tlv(validity)?;
    let (t2, na, _) = tlv(more)?;
    Some((der_time(t1, nb)?, der_time(t2, na)?))
}

/// A `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime`
/// (`YYYYMMDDHHMMSSZ`) as Unix seconds.
fn der_time(tag: u8, text: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(text).ok()?.strip_suffix('Z')?;
    let num = |s: &str| s.parse::<i64>().ok();
    let (year, rest) = match tag {
        0x17 if text.len() == 12 => {
            let yy = num(&text[..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &text[2..])
        }
        0x18 if text.len() == 14 => (num(&text[..4])?, &text[4..]),
        _ => return None,
    };
    let (month, day) = (num(&rest[..2])?, num(&rest[2..4])?);
    let (h, m, sec) = (num(&rest[4..6])?, num(&rest[6..8])?, num(&rest[8..10])?);
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + m * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_times() {
        assert_eq!(der_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(der_time(0x18, b"20261010120000Z"), Some(1_791_633_600));
        assert_eq!(der_time(0x17, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(der_time(0x17, b"bad"), None);
    }

    #[test]
    fn ca_pem_must_hold_a_certificate() {
        assert!(client_config("").is_ok());
        assert_eq!(
            client_config("not a pem").unwrap_err(),
            "ca_pem: no certificate or crl found"
        );
    }
}
