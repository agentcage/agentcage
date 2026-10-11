//! The per-cage CA: generated on first start into the private CA dir,
//! reloaded on later starts, public cert published for the cage; leaf
//! certificates minted per server name and cached.
//!
//! Every cage gets its own CA (plan D11). The egress generates it the first
//! time it starts, inside the cage's private certs volume, and from then on
//! loads only that CA: exactly two files, [`CA_KEY_FILE`] (mode 0600) and
//! [`CA_CERT_FILE`]. Nothing else in the directory is ever read, so a CA
//! written by the implementation this crate replaces is never picked up —
//! switching engines is a fresh-CA event by design.
//!
//! The CA key is ECDSA P-256. `rcgen` cannot generate RSA keys, and P-256
//! is the one curve every TLS stack a cage might run (OpenSSL, Go, Node,
//! Java, rustls, `SChannel`) accepts for both CA and leaf signatures, at a
//! fraction of RSA's signing cost on the leaf-minting hot path.
//!
//! Leaves follow the replaced implementation's shape: valid from two days
//! ago (clients with a slow clock) for 199 days, `serverAuth` EKU, an
//! authority key identifier equal to the CA's subject key identifier, no
//! subject key identifier of their own, CN = the first SAN when it is
//! shorter than 64 characters (the SAN extension is then non-critical,
//! critical otherwise). One difference: every leaf carries one ECDSA P-256
//! key generated at start-up rather than the CA key itself, so the CA key
//! signs certificates and nothing else.

use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use ring::rand::SecureRandom as _;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// The CA private key inside the private CA dir (PKCS#8 PEM, mode 0600).
pub const CA_KEY_FILE: &str = "ca-key.pem";
/// The CA certificate inside the private CA dir (PEM).
pub const CA_CERT_FILE: &str = "ca-cert.pem";

/// How long the CA is valid for, counted from [`VALIDITY_OFFSET`] ago.
const CA_VALIDITY: Duration = Duration::from_secs(10 * 365 * 86_400);
/// How long a leaf is valid for, counted from [`VALIDITY_OFFSET`] ago.
const LEAF_VALIDITY: Duration = Duration::from_secs(199 * 86_400);
/// Backdating, for clients whose clock runs behind.
const VALIDITY_OFFSET: Duration = Duration::from_secs(2 * 86_400);
/// Leaves kept in the cache; the oldest-used one is evicted past this.
const LEAF_CACHE_CAP: usize = 100;
/// A cached leaf is re-minted after this long, well inside its validity,
/// so a long-running egress never serves an expired certificate.
const LEAF_REFRESH: Duration = Duration::from_secs(7 * 86_400);
/// The X.509 upper bound on a common name (`ub-common-name`).
const CN_MAX: usize = 64;

/// Why the CA could not be loaded, created, published or used.
#[derive(Debug)]
pub enum CaError {
    /// Reading or writing a CA file failed.
    Io(PathBuf, std::io::Error),
    /// A CA file exists but cannot be parsed, or key and cert disagree.
    Invalid(PathBuf, String),
    /// Certificate generation failed.
    Generate(String),
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "{}: {e}", path.display()),
            Self::Invalid(path, why) => write!(f, "{}: {why}", path.display()),
            Self::Generate(why) => write!(f, "certificate generation failed: {why}"),
        }
    }
}

impl std::error::Error for CaError {}

/// Whether [`CertAuthority::load_or_create`] found a CA or made one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaOrigin {
    /// This start generated the CA (first start of this cage's egress).
    Generated,
    /// The CA from an earlier start was loaded.
    Loaded,
}

/// A name a leaf certificate is minted for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LeafName {
    /// A DNS name (the client's SNI, or a CONNECT host).
    Dns(String),
    /// An address (the local address when there is no SNI, or the
    /// destination address).
    Ip(IpAddr),
}

impl LeafName {
    /// An IP SAN when `text` parses as an address (brackets allowed), a
    /// DNS SAN otherwise.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let bare = text.trim_start_matches('[').trim_end_matches(']');
        match bare.parse::<IpAddr>() {
            Ok(ip) => Self::Ip(ip),
            Err(_) => Self::Dns(text.to_ascii_lowercase()),
        }
    }

    fn as_text(&self) -> String {
        match self {
            Self::Dns(name) => name.clone(),
            Self::Ip(ip) => ip.to_string(),
        }
    }
}

struct CachedLeaf {
    key: Arc<CertifiedKey>,
    minted: Instant,
}

/// This cage's CA and the leaf certificates it signs.
pub struct CertAuthority {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    leaf_key: KeyPair,
    leaf_signer: Arc<dyn rustls::sign::SigningKey>,
    cache: Mutex<IndexMap<Vec<LeafName>, CachedLeaf>>,
}

impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority")
            .field("fingerprint", &self.fingerprint_sha256())
            .finish_non_exhaustive()
    }
}

/// The CA's subject common name for a cage: `agentcage egress CA (<cage>)`,
/// with the cage name shortened so the CN stays within 64 characters.
#[must_use]
pub fn ca_common_name(cage_name: &str) -> String {
    const PREFIX: &str = "agentcage egress CA (";
    let room = CN_MAX - PREFIX.len() - 1;
    let name: String = cage_name.chars().take(room).collect();
    format!("{PREFIX}{name})")
}

impl CertAuthority {
    /// Load this cage's CA from `dir`, or generate one there when the
    /// directory holds none.
    ///
    /// The certificate file is the commit point: it is renamed into place
    /// after the key, so a start interrupted between the two leaves a key
    /// without a certificate, which the next start replaces. A certificate
    /// without its key is refused rather than silently replaced, since the
    /// certificate may already be trusted by the cage.
    ///
    /// # Errors
    ///
    /// The directory cannot be created or written, a CA file is
    /// unreadable or malformed, the key does not match the certificate,
    /// or generation fails.
    pub fn load_or_create(dir: &Path, cage_name: &str) -> Result<(Self, CaOrigin), CaError> {
        let key_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);
        if cert_path.exists() {
            if !key_path.exists() {
                return Err(CaError::Invalid(
                    key_path,
                    "the CA certificate exists but its private key is missing".into(),
                ));
            }
            return Ok((Self::load(&key_path, &cert_path)?, CaOrigin::Loaded));
        }
        create_private_dir(dir)?;
        let (key, cert_pem) = generate_ca(cage_name)?;
        write_atomic(&key_path, key.serialize_pem().as_bytes(), 0o600)?;
        write_atomic(&cert_path, cert_pem.as_bytes(), 0o644)?;
        Ok((
            Self::from_parts(key, cert_pem, &cert_path)?,
            CaOrigin::Generated,
        ))
    }

    fn load(key_path: &Path, cert_path: &Path) -> Result<Self, CaError> {
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| CaError::Io(key_path.to_path_buf(), e))?;
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| CaError::Io(cert_path.to_path_buf(), e))?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|e| CaError::Invalid(key_path.to_path_buf(), e.to_string()))?;
        Self::from_parts(key, cert_pem, cert_path)
    }

    fn from_parts(key: KeyPair, cert_pem: String, cert_path: &Path) -> Result<Self, CaError> {
        let invalid = |why: String| CaError::Invalid(cert_path.to_path_buf(), why);
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| invalid(format!("not a PEM certificate: {e}")))?;
        if !spki_matches(&cert_der, &key) {
            return Err(invalid(
                "the CA certificate does not belong to the CA private key".into(),
            ));
        }
        let issuer =
            Issuer::from_ca_cert_der(&cert_der, key).map_err(|e| invalid(e.to_string()))?;
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| CaError::Generate(e.to_string()))?;
        let leaf_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signer = rustls::crypto::ring::sign::any_ecdsa_type(&leaf_der)
            .map_err(|e| CaError::Generate(e.to_string()))?;
        Ok(Self {
            cert_pem,
            cert_der,
            issuer,
            leaf_key,
            leaf_signer,
            cache: Mutex::new(IndexMap::new()),
        })
    }

    /// The CA certificate, PEM.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate, DER.
    #[must_use]
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The CA certificate's SHA-256 fingerprint, lowercase hex.
    #[must_use]
    pub fn fingerprint_sha256(&self) -> String {
        let hash = ring::digest::digest(&ring::digest::SHA256, self.cert_der.as_ref());
        hash.as_ref().iter().fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    /// Publish the public certificate (never the key) at `path`, replacing
    /// whatever is there atomically, mode 0644: the cage mounts the
    /// directory read-only and polls for this file.
    ///
    /// # Errors
    ///
    /// The file cannot be written or renamed into place.
    pub fn publish(&self, path: &Path) -> Result<(), CaError> {
        write_atomic(path, self.cert_pem.as_bytes(), 0o644)
    }

    /// A leaf for `names` (first name = CN), from the cache when one was
    /// minted recently for the same names.
    ///
    /// # Errors
    ///
    /// `names` is empty or holds a name `rcgen` refuses, or signing fails.
    ///
    /// # Panics
    ///
    /// The cache lock was poisoned by a panicking minter.
    pub fn leaf(&self, names: &[LeafName]) -> Result<Arc<CertifiedKey>, CaError> {
        let mut unique: Vec<LeafName> = Vec::with_capacity(names.len());
        for name in names {
            if !unique.contains(name) {
                unique.push(name.clone());
            }
        }
        if unique.is_empty() {
            return Err(CaError::Generate("no name to mint a leaf for".into()));
        }
        {
            let mut cache = self.cache.lock().expect("leaf cache poisoned");
            if let Some(index) = cache.get_index_of(&unique) {
                let fresh = cache[index].minted.elapsed() < LEAF_REFRESH;
                if fresh {
                    let last = cache.len() - 1;
                    cache.move_index(index, last);
                    return Ok(Arc::clone(&cache[last].key));
                }
            }
        }
        let key = Arc::new(self.mint(&unique)?);
        let mut cache = self.cache.lock().expect("leaf cache poisoned");
        cache.shift_remove(&unique);
        cache.insert(
            unique,
            CachedLeaf {
                key: Arc::clone(&key),
                minted: Instant::now(),
            },
        );
        while cache.len() > LEAF_CACHE_CAP {
            cache.shift_remove_index(0);
        }
        Ok(key)
    }

    fn mint(&self, names: &[LeafName]) -> Result<CertifiedKey, CaError> {
        let generate = |e: rcgen::Error| CaError::Generate(e.to_string());
        let mut params = CertificateParams::default();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - VALIDITY_OFFSET;
        params.not_after = params.not_before + LEAF_VALIDITY;
        params.serial_number = Some(random_serial()?);
        let mut dn = DistinguishedName::new();
        let cn = names[0].as_text();
        if cn.len() < CN_MAX {
            dn.push(DnType::CommonName, cn);
        }
        params.distinguished_name = dn;
        params.subject_alt_names = names
            .iter()
            .map(|name| match name {
                LeafName::Dns(dns) => {
                    Ok(SanType::DnsName(dns.clone().try_into().map_err(generate)?))
                }
                LeafName::Ip(ip) => Ok(SanType::IpAddress(*ip)),
            })
            .collect::<Result<_, CaError>>()?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .map_err(generate)?;
        Ok(CertifiedKey::new(
            vec![cert.der().clone(), self.cert_der.clone()],
            Arc::clone(&self.leaf_signer),
        ))
    }
}

fn generate_ca(cage_name: &str) -> Result<(KeyPair, String), CaError> {
    let generate = |e: rcgen::Error| CaError::Generate(e.to_string());
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(generate)?;
    let mut params = CertificateParams::default();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - VALIDITY_OFFSET;
    params.not_after = params.not_before + CA_VALIDITY;
    params.serial_number = Some(random_serial()?);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ca_common_name(cage_name));
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).map_err(generate)?;
    Ok((key, cert.pem()))
}

/// A positive 128-bit serial (top bit clear, so DER needs no sign byte
/// games and no stack reads it as negative).
fn random_serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CaError::Generate("no system randomness".into()))?;
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01 << 6;
    Ok(SerialNumber::from_slice(&bytes))
}

/// Whether the certificate's subject public key is `key`'s.
fn spki_matches(cert: &CertificateDer<'_>, key: &KeyPair) -> bool {
    // The SPKI's raw public key bytes appear verbatim in the DER; a
    // full parse is not needed to tell a mismatched pair apart.
    let raw = key.public_key_raw();
    cert.as_ref().windows(raw.len()).any(|window| window == raw)
}

fn create_private_dir(dir: &Path) -> Result<(), CaError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| CaError::Io(dir.to_path_buf(), e))
}

/// Write `data` to a sibling temp file with `mode`, then rename it over
/// `path`, so a reader never sees a partial file.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), CaError> {
    let io = |e| CaError::Io(path.to_path_buf(), e);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        // The umask may have narrowed the mode; the public cert must stay
        // world-readable for the cage's uid.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("agentcage-ca-{tag}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_common_name_fits_the_x509_bound() {
        assert_eq!(ca_common_name("web"), "agentcage egress CA (web)");
        let long = "x".repeat(100);
        assert_eq!(ca_common_name(&long).len(), 64);
    }

    #[test]
    fn first_start_generates_and_later_starts_reload_the_same_ca() {
        let dir = tempdir("reload");
        let (first, origin) = CertAuthority::load_or_create(&dir, "one").unwrap();
        assert_eq!(origin, CaOrigin::Generated);
        let (again, origin) = CertAuthority::load_or_create(&dir, "one").unwrap();
        assert_eq!(origin, CaOrigin::Loaded);
        assert_eq!(first.fingerprint_sha256(), again.fingerprint_sha256());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.join(CA_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn two_instances_get_two_cas() {
        let (a, b) = (tempdir("a"), tempdir("b"));
        let (ca_a, _) = CertAuthority::load_or_create(&a, "same").unwrap();
        let (ca_b, _) = CertAuthority::load_or_create(&b, "same").unwrap();
        assert_ne!(ca_a.fingerprint_sha256(), ca_b.fingerprint_sha256());
        let _ = (std::fs::remove_dir_all(a), std::fs::remove_dir_all(b));
    }

    #[test]
    fn other_files_in_the_dir_are_never_read() {
        let dir = tempdir("foreign");
        // A CA in some other engine's file names: ignored, a fresh one made.
        std::fs::write(dir.join("other-ca.pem"), "junk").unwrap();
        std::fs::write(dir.join("other-ca-cert.pem"), "junk").unwrap();
        let (_, origin) = CertAuthority::load_or_create(&dir, "c").unwrap();
        assert_eq!(origin, CaOrigin::Generated);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_cert_without_its_key_is_refused_and_a_key_without_cert_replaced() {
        let dir = tempdir("partial");
        let (ca, _) = CertAuthority::load_or_create(&dir, "c").unwrap();
        std::fs::remove_file(dir.join(CA_CERT_FILE)).unwrap();
        let (fresh, origin) = CertAuthority::load_or_create(&dir, "c").unwrap();
        assert_eq!(origin, CaOrigin::Generated);
        assert_ne!(ca.fingerprint_sha256(), fresh.fingerprint_sha256());
        std::fs::remove_file(dir.join(CA_KEY_FILE)).unwrap();
        assert!(matches!(
            CertAuthority::load_or_create(&dir, "c"),
            Err(CaError::Invalid(..))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_mismatched_key_is_refused() {
        let (a, b) = (tempdir("ma"), tempdir("mb"));
        CertAuthority::load_or_create(&a, "a").unwrap();
        CertAuthority::load_or_create(&b, "b").unwrap();
        std::fs::copy(b.join(CA_KEY_FILE), a.join(CA_KEY_FILE)).unwrap();
        assert!(matches!(
            CertAuthority::load_or_create(&a, "a"),
            Err(CaError::Invalid(..))
        ));
        let _ = (std::fs::remove_dir_all(a), std::fs::remove_dir_all(b));
    }

    #[test]
    fn publish_writes_the_public_cert_only() {
        let dir = tempdir("publish");
        let (ca, _) = CertAuthority::load_or_create(&dir.join("ca"), "p").unwrap();
        let out = dir.join("agentcage-ca.pem");
        ca.publish(&out).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(text, ca.cert_pem());
        assert!(!text.contains("PRIVATE KEY"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn leaves_are_cached_per_name_set() {
        let dir = tempdir("leaf");
        let (ca, _) = CertAuthority::load_or_create(&dir, "l").unwrap();
        let a = ca.leaf(&[LeafName::parse("example.com")]).unwrap();
        let b = ca.leaf(&[LeafName::parse("Example.com")]).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let c = ca
            .leaf(&[LeafName::parse("example.com"), LeafName::parse("10.0.0.1")])
            .unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        assert_eq!(a.cert.len(), 2, "leaf + CA chain");
        for i in 0..(LEAF_CACHE_CAP + 5) {
            ca.leaf(&[LeafName::Dns(format!("h{i}.test"))]).unwrap();
        }
        assert!(ca.cache.lock().unwrap().len() <= LEAF_CACHE_CAP);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn leaves_verify_against_the_ca_in_rustls() {
        use rustls::client::danger::ServerCertVerifier as _;
        let dir = tempdir("verify");
        let (ca, _) = CertAuthority::load_or_create(&dir, "v").unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap();
        let now = rustls::pki_types::UnixTime::now();
        let leaf = ca
            .leaf(&[
                LeafName::parse("api.example.com"),
                LeafName::parse("192.0.2.7"),
            ])
            .unwrap();
        for name in ["api.example.com", "192.0.2.7"] {
            let server = rustls::pki_types::ServerName::try_from(name).unwrap();
            verifier
                .verify_server_cert(&leaf.cert[0], &leaf.cert[1..], &server, &[], now)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let wrong = rustls::pki_types::ServerName::try_from("other.example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(&leaf.cert[0], &[], &wrong, &[], now)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn leaves_verify_in_openssl_when_installed() {
        let run =
            |args: &[&std::ffi::OsStr]| std::process::Command::new("openssl").args(args).output();
        if run(&["version".as_ref()]).is_err() {
            eprintln!("openssl not installed; skipping");
            return;
        }
        let dir = tempdir("openssl");
        let (ca, _) = CertAuthority::load_or_create(&dir.join("ca"), "o").unwrap();
        let leaf = ca.leaf(&[LeafName::parse("svc.example.com")]).unwrap();
        let der = dir.join("leaf.der");
        let pem = dir.join("leaf.pem");
        std::fs::write(&der, leaf.cert[0].as_ref()).unwrap();
        let ca_pem = dir.join("ca").join(CA_CERT_FILE);
        let out = run(&[
            "x509".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-in".as_ref(),
            der.as_os_str(),
            "-out".as_ref(),
            pem.as_os_str(),
        ])
        .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = run(&[
            "verify".as_ref(),
            "-x509_strict".as_ref(),
            "-purpose".as_ref(),
            "sslserver".as_ref(),
            "-verify_hostname".as_ref(),
            "svc.example.com".as_ref(),
            "-CAfile".as_ref(),
            ca_pem.as_os_str(),
            pem.as_os_str(),
        ])
        .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
