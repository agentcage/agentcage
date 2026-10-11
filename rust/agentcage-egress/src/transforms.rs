//! Secret transforms: `google-jwt-bearer` mints an OAuth access token
//! from a service-account key and injects that instead of the key.
//!
//! A transform turns a rule's staged secret (a long-lived, high-privilege
//! credential) into the short-lived value that actually goes on the wire,
//! so the credential itself never leaves the egress. The injector calls
//! [`Transform::get_value`] every time it substitutes the rule's
//! placeholder on a request to an `inject_to` host, and treats every value
//! [`Transform::active_values`] lists as a secret exactly like the
//! credential: redacted back to the placeholder wherever real values are
//! (capture, responses, WebSocket frames, audit records) and blocked when
//! it heads for a host outside `inject_to`.
//!
//! `get_value` may block on a network call (a mint), so the injector must
//! run off the async runtime.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::{Mapping, Value};
use crate::json::{self, Json};

/// Why a transform could not be built or produce a value. The message is
/// operator-facing (logged); the cage's request keeps its placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransformError(pub String);

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransformError {}

/// A secret transform.
pub trait Transform: Send + Sync + std::fmt::Debug {
    /// The value to put on the wire now: cached, or freshly derived.
    ///
    /// # Errors
    ///
    /// The value cannot be produced (rate limit, mint failure); the
    /// placeholder is left in place.
    fn get_value(&self) -> Result<String, TransformError>;

    /// Every value [`Transform::get_value`] returned that may still be in
    /// use, or `None` when the transform does not track them (the
    /// injector then remembers the last two values itself).
    fn active_values(&self) -> Option<Vec<String>> {
        None
    }
}

/// The registered transform names, sorted.
#[must_use]
pub fn known() -> Vec<&'static str> {
    vec!["google-jwt-bearer"]
}

/// Build the transform `name` for `secret` with its `transform_config`.
///
/// # Errors
///
/// `name` is not registered, or the transform refuses its config or
/// secret.
pub fn build(
    name: &str,
    secret: &str,
    config: &Value,
) -> Result<Arc<dyn Transform>, TransformError> {
    match name {
        "google-jwt-bearer" => {
            let Value::Mapping(config) = config else {
                return Err(TransformError(
                    "google-jwt-bearer: transform_config must be a mapping".into(),
                ));
            };
            Ok(Arc::new(GoogleJwtBearer::new(secret, config)?))
        }
        _ => Err(TransformError(format!(
            "unknown transform '{name}'. Registered: {}",
            known().join(", ")
        ))),
    }
}

// ── Clock and token endpoint seams ───────────────────────

/// Time as the transform reads it: wall-clock seconds for expiry and
/// monotonic seconds for the mint rate bucket.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Seconds since the Unix epoch (`time.time()`).
    fn wall(&self) -> f64;
    /// Seconds on a monotonic clock (`time.monotonic()`).
    fn monotonic(&self) -> f64;
}

/// The real clock.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn wall(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    }

    fn monotonic(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }
}

/// An HTTP reply from the token endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// The status code.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// Where the transform POSTs its assertion. Tests substitute a mock.
pub trait TokenEndpoint: Send + Sync + std::fmt::Debug {
    /// POST `body` as `application/x-www-form-urlencoded` to `url`.
    ///
    /// # Errors
    ///
    /// The request could not be made or no reply arrived (the message is
    /// the network reason). A reply with any status is `Ok`.
    fn post_form(&self, url: &str, body: &str, timeout: Duration) -> Result<HttpReply, String>;
}

/// The real token endpoint client: blocking, rustls with the webpki
/// roots, and no redirects followed (a redirect would carry the request
/// past the audience allowlist).
#[derive(Debug, Default)]
pub struct UreqEndpoint;

impl TokenEndpoint for UreqEndpoint {
    fn post_form(&self, url: &str, body: &str, timeout: Duration) -> Result<HttpReply, String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        let mut response = agent
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(body)
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(HttpReply { status, body })
    }
}

// ── google-jwt-bearer ────────────────────────────────────

const DEFAULT_AUDIENCE: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_REFRESH_MARGIN: i64 = 300;
const DEFAULT_MINT_RATE_PER_HOUR: i64 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The hosts the JWT audience (which is also the token POST target) may
/// name. The SA JSON's own `token_uri` is never used: a hostile key file
/// must not be able to send the signed assertion elsewhere.
pub const ALLOWED_AUDIENCE_HOSTS: [&str; 2] = ["oauth2.googleapis.com", "accounts.google.com"];

/// The mint rate limit: capacity one hour of budget, refilled
/// continuously.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: f64,
}

impl TokenBucket {
    /// A full bucket of `max(1, rate_per_hour)` tokens, its clock starting
    /// at `now` (monotonic seconds).
    #[must_use]
    pub fn new(rate_per_hour: i64, now: f64) -> Self {
        #[allow(clippy::cast_precision_loss)]
        let capacity = rate_per_hour.max(1) as f64;
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec: capacity / 3600.0,
            last: now,
        }
    }

    /// Take one token at `now`; false when the bucket is empty.
    pub fn take(&mut self, now: f64) -> bool {
        let elapsed = now - self.last;
        self.last = now;
        self.tokens = self
            .capacity
            .min(self.tokens + elapsed * self.refill_per_sec);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Default)]
struct MintState {
    cached_token: Option<String>,
    cached_expiry: f64,
    /// Every minted token that may still be in use, with its expiry, in
    /// mint order: the cached one and, after a refresh, the previous one
    /// until its own expiry. Bounded by the mint rate over one lifetime.
    issued: Vec<(String, f64)>,
}

impl MintState {
    fn prune(&mut self, now: f64) {
        self.issued.retain(|(_, expiry)| *expiry > now);
    }
}

/// Mints Google `OAuth2` access tokens with the JWT-bearer flow from a
/// service-account key that never leaves this object.
pub struct GoogleJwtBearer {
    scopes: Vec<String>,
    audience: String,
    refresh_margin: i64,
    client_email: String,
    key: ring::signature::RsaKeyPair,
    bucket: Mutex<TokenBucket>,
    // Held across the mint, so concurrent callers on a cold cache wait
    // for one mint instead of each minting (single flight).
    state: Mutex<MintState>,
    endpoint: Arc<dyn TokenEndpoint>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for GoogleJwtBearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key, never a token.
        f.debug_struct("GoogleJwtBearer")
            .field("client_email", &self.client_email)
            .field("audience", &self.audience)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

fn err(message: impl Into<String>) -> TransformError {
    TransformError(message.into())
}

/// `str(value)` for the scalars a config can hold.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        Value::Number(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

impl GoogleJwtBearer {
    /// Build from the SA key JSON and `transform_config`, minting through
    /// the real endpoint on the system clock.
    ///
    /// # Errors
    ///
    /// As [`GoogleJwtBearer::with_parts`].
    pub fn new(secret: &str, config: &Mapping) -> Result<Self, TransformError> {
        Self::with_parts(
            secret,
            config,
            Arc::new(UreqEndpoint),
            Arc::new(SystemClock::default()),
        )
    }

    /// Build with an explicit token endpoint and clock.
    ///
    /// # Errors
    ///
    /// No `scopes`; an audience that is not https or not on
    /// [`ALLOWED_AUDIENCE_HOSTS`]; a non-integer `refresh_margin` or
    /// `mint_rate_per_hour`; a key that is not JSON, lacks
    /// `client_email` / `private_key`, or holds no usable RSA key.
    pub fn with_parts(
        secret: &str,
        config: &Mapping,
        endpoint: Arc<dyn TokenEndpoint>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, TransformError> {
        // `list(config.get("scopes") or [])`: a string is a list of its
        // characters there, kept for parity.
        let scopes: Vec<String> = match config.get("scopes") {
            Some(Value::Sequence(items)) => items.iter().map(py_str).collect(),
            Some(Value::String(s)) => s.chars().map(String::from).collect(),
            _ => Vec::new(),
        };
        if scopes.is_empty() {
            return Err(err(
                "google-jwt-bearer: transform_config.scopes is required",
            ));
        }
        let audience = match config.get("audience") {
            Some(v) if crate::config::truthy(v) => py_str(v),
            _ => DEFAULT_AUDIENCE.to_owned(),
        };
        validate_audience(&audience)?;
        let int_option = |key: &str, default: i64| -> Result<i64, TransformError> {
            match config.get(key) {
                None => Ok(default),
                v => crate::config::as_i64(v)
                    .ok_or_else(|| err(format!("google-jwt-bearer: {key} must be an integer"))),
            }
        };
        let refresh_margin = int_option("refresh_margin", DEFAULT_REFRESH_MARGIN)?;
        let rate = int_option("mint_rate_per_hour", DEFAULT_MINT_RATE_PER_HOUR)?;
        let bucket = TokenBucket::new(rate, clock.monotonic());

        let sa = json::parse(secret)
            .map_err(|e| err(format!("google-jwt-bearer: SA key is not valid JSON: {e}")))?;
        let field = |name: &str| -> Result<String, TransformError> {
            match sa.get(name) {
                Some(Json::Str(s)) => Ok(s.clone()),
                Some(_) => Err(err(format!(
                    "google-jwt-bearer: SA key field '{name}' is not a string"
                ))),
                None => Err(err(format!(
                    "google-jwt-bearer: SA key missing required field: '{name}'"
                ))),
            }
        };
        let client_email = field("client_email")?;
        let private_key = field("private_key")?;
        let key = load_private_key(&private_key)?;
        Ok(Self {
            scopes,
            audience,
            refresh_margin,
            client_email,
            key,
            bucket: Mutex::new(bucket),
            state: Mutex::new(MintState::default()),
            endpoint,
            clock,
        })
    }

    /// The token POST target (always the audience).
    #[must_use]
    pub fn token_uri(&self) -> &str {
        &self.audience
    }

    /// The signed assertion for `now` (wall-clock seconds).
    ///
    /// # Errors
    ///
    /// Signing failed.
    pub fn assertion(&self, now: f64) -> Result<String, TransformError> {
        let header = json::object([("alg", Json::string("RS256")), ("typ", Json::string("JWT"))]);
        // `int(now)`: wall time is positive, so truncation is the floor.
        #[allow(clippy::cast_possible_truncation)]
        let iat = now as i64;
        let claims = json::object([
            ("iss", Json::string(self.client_email.clone())),
            ("scope", Json::string(self.scopes.join(" "))),
            ("aud", Json::string(self.audience.clone())),
            ("iat", Json::Int(iat)),
            ("exp", Json::Int(iat + 3600)),
        ]);
        let signing_input = format!(
            "{}.{}",
            b64url(json::to_compact_string(&header).as_bytes()),
            b64url(json::to_compact_string(&claims).as_bytes())
        );
        let mut signature = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| err("google-jwt-bearer: signing failed"))?;
        Ok(format!("{signing_input}.{}", b64url(&signature)))
    }

    /// The form body sent (POST) for `assertion`.
    #[must_use]
    pub fn request_body(assertion: &str) -> String {
        format!(
            "grant_type={}&assertion={}",
            quote_plus("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            quote_plus(assertion)
        )
    }

    fn mint(&self, now: f64) -> Result<(String, f64), TransformError> {
        let assertion = self.assertion(now)?;
        let body = Self::request_body(&assertion);
        let reply = self
            .endpoint
            .post_form(&self.audience, &body, HTTP_TIMEOUT)
            .map_err(|reason| {
                eprintln!("google-jwt-bearer: mint failed (network): {reason}");
                err(format!(
                    "google-jwt-bearer: mint failed (network: {reason})"
                ))
            })?;
        if !(200..300).contains(&reply.status) {
            let detail: String = String::from_utf8_lossy(&reply.body)
                .chars()
                .take(500)
                .collect();
            eprintln!(
                "google-jwt-bearer: mint failed (HTTP {}): {detail}",
                reply.status
            );
            return Err(err(format!(
                "google-jwt-bearer: mint failed (HTTP {})",
                reply.status
            )));
        }
        let malformed = || err("google-jwt-bearer: malformed token response from Google");
        let text = std::str::from_utf8(&reply.body).map_err(|_| malformed())?;
        let payload = json::parse(text).map_err(|_| malformed())?;
        let token = match payload.get("access_token") {
            Some(Json::Str(s)) if !s.is_empty() => s.clone(),
            _ => return Err(malformed()),
        };
        // `int(payload.get("expires_in") or 0)`.
        let expires_in = match payload.get("expires_in") {
            Some(Json::Int(n)) => *n,
            #[allow(clippy::cast_possible_truncation)]
            Some(Json::Float(f)) if f.is_finite() => f.trunc() as i64,
            Some(Json::Str(s)) => s.trim().parse().map_err(|_| malformed())?,
            Some(Json::Bool(b)) => i64::from(*b),
            _ => 0,
        };
        if expires_in <= 0 {
            return Err(malformed());
        }
        #[allow(clippy::cast_precision_loss)]
        Ok((token, now + expires_in as f64))
    }
}

impl Transform for GoogleJwtBearer {
    fn get_value(&self) -> Result<String, TransformError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = self.clock.wall();
        #[allow(clippy::cast_precision_loss)]
        let margin = self.refresh_margin as f64;
        if let Some(token) = &state.cached_token {
            if now + margin < state.cached_expiry {
                return Ok(token.clone());
            }
        }
        let allowed = self
            .bucket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(self.clock.monotonic());
        if !allowed {
            return Err(err("google-jwt-bearer: mint rate limit exceeded"));
        }
        let (token, expiry) = self.mint(now)?;
        state.cached_token = Some(token.clone());
        state.cached_expiry = expiry;
        state.prune(now);
        match state.issued.iter_mut().find(|(t, _)| *t == token) {
            Some(slot) => slot.1 = expiry,
            None => state.issued.push((token.clone(), expiry)),
        }
        #[allow(clippy::cast_possible_truncation)]
        let expires_in = (expiry - now) as i64;
        eprintln!(
            "google-jwt-bearer: minted token, scopes={}, expires_in={expires_in}s",
            self.scopes.join(" ")
        );
        Ok(token)
    }

    fn active_values(&self) -> Option<Vec<String>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune(self.clock.wall());
        Some(state.issued.iter().map(|(t, _)| t.clone()).collect())
    }
}

fn validate_audience(url: &str) -> Result<(), TransformError> {
    let parts = crate::inject::urlsplit(url);
    if parts.scheme != "https" {
        return Err(err(format!(
            "google-jwt-bearer: audience must be https://, got '{url}'"
        )));
    }
    let host = parts.hostname().unwrap_or_default().to_lowercase();
    let allowed = ALLOWED_AUDIENCE_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")));
    if !allowed {
        return Err(err(format!(
            "google-jwt-bearer: audience host '{host}' not in allowlist ({})",
            ALLOWED_AUDIENCE_HOSTS.join(", ")
        )));
    }
    Ok(())
}

/// The RSA key in a PEM `private_key`: PKCS#8 (`BEGIN PRIVATE KEY`, what
/// Google issues) or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
fn load_private_key(pem: &str) -> Result<ring::signature::RsaKeyPair, TransformError> {
    let bad = |why: &str| err(format!("google-jwt-bearer: cannot load private key: {why}"));
    for (label, pkcs8) in [("PRIVATE KEY", true), ("RSA PRIVATE KEY", false)] {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let Some(start) = pem.find(&begin) else {
            continue;
        };
        let body_start = start + begin.len();
        let Some(stop) = pem[body_start..].find(&end) else {
            return Err(bad("unterminated PEM block"));
        };
        let b64: String = pem[body_start..body_start + stop]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = crate::inject::b64_decode_std(&b64).ok_or_else(|| bad("invalid base64"))?;
        let key = if pkcs8 {
            ring::signature::RsaKeyPair::from_pkcs8(&der)
        } else {
            ring::signature::RsaKeyPair::from_der(&der)
        };
        return key.map_err(|e| bad(&e.to_string()));
    }
    Err(bad("no RSA private key PEM block"))
}

/// RFC 7515 base64url without padding.
fn b64url(data: &[u8]) -> String {
    let std = crate::inject::b64_encode_std(data);
    std.trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect()
}

/// `urllib.parse.quote_plus`: unreserved characters kept, space as `+`,
/// everything else `%XX`.
fn quote_plus(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(char::from(b));
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A clock driven by hand.
    #[derive(Debug)]
    pub(crate) struct FakeClock {
        pub(crate) wall: Mutex<f64>,
        pub(crate) mono: Mutex<f64>,
    }

    impl FakeClock {
        pub(crate) fn at(wall: f64) -> Arc<Self> {
            Arc::new(Self {
                wall: Mutex::new(wall),
                mono: Mutex::new(0.0),
            })
        }
        pub(crate) fn advance(&self, secs: f64) {
            *self.wall.lock().unwrap() += secs;
            *self.mono.lock().unwrap() += secs;
        }
    }

    impl Clock for FakeClock {
        fn wall(&self) -> f64 {
            *self.wall.lock().unwrap()
        }
        fn monotonic(&self) -> f64 {
            *self.mono.lock().unwrap()
        }
    }

    /// A token endpoint returning scripted replies and recording calls.
    #[derive(Debug, Default)]
    pub(crate) struct MockEndpoint {
        pub(crate) replies: Mutex<Vec<Result<HttpReply, String>>>,
        pub(crate) calls: Mutex<Vec<(String, String)>>,
        pub(crate) delay: Duration,
        pub(crate) count: AtomicUsize,
    }

    impl MockEndpoint {
        pub(crate) fn tokens(tokens: &[(&str, i64)]) -> Arc<Self> {
            let replies = tokens
                .iter()
                .rev()
                .map(|(t, e)| {
                    Ok(HttpReply {
                        status: 200,
                        body: format!(r#"{{"access_token": "{t}", "expires_in": {e}}}"#)
                            .into_bytes(),
                    })
                })
                .collect();
            Arc::new(Self {
                replies: Mutex::new(replies),
                ..Self::default()
            })
        }
    }

    impl TokenEndpoint for MockEndpoint {
        fn post_form(&self, url: &str, body: &str, timeout: Duration) -> Result<HttpReply, String> {
            assert_eq!(timeout, Duration::from_secs(10));
            self.count.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.calls.lock().unwrap().push((url.into(), body.into()));
            let mut replies = self.replies.lock().unwrap();
            if replies.len() > 1 {
                replies.pop().unwrap()
            } else {
                replies.last().cloned().expect("a scripted reply")
            }
        }
    }

    pub(crate) fn fixture() -> Json {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/egress/injection.json"
        );
        json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    pub(crate) fn sa_key() -> String {
        let f = fixture();
        let t = f.get("transform").unwrap();
        json::to_string(&json::object([
            ("type", Json::string("service_account")),
            ("client_email", t.get("client_email").unwrap().clone()),
            ("private_key", t.get("private_key").unwrap().clone()),
        ]))
    }

    pub(crate) fn mapping(yaml: &str) -> Mapping {
        match agentcage_core::yaml::load(yaml).unwrap() {
            Value::Mapping(m) => m,
            Value::Null => Mapping::new(),
            other => panic!("{other:?}"),
        }
    }

    fn bearer(cfg: &str, endpoint: Arc<MockEndpoint>, clock: Arc<FakeClock>) -> GoogleJwtBearer {
        GoogleJwtBearer::with_parts(&sa_key(), &mapping(cfg), endpoint, clock).unwrap()
    }

    #[test]
    fn registry() {
        assert_eq!(known(), ["google-jwt-bearer"]);
        let e = build("nonexistent", "", &Value::Null).unwrap_err();
        assert_eq!(
            e.0,
            "unknown transform 'nonexistent'. Registered: google-jwt-bearer"
        );
    }

    #[test]
    fn token_bucket() {
        let mut b = TokenBucket::new(10, 0.0);
        for _ in 0..10 {
            assert!(b.take(0.0));
        }
        assert!(!b.take(0.0));
        let mut b = TokenBucket::new(3600, 0.0);
        for _ in 0..3600 {
            b.take(0.0);
        }
        assert!(!b.take(0.0));
        assert!(b.take(2.0));
        assert!(b.take(2.0));
        assert!(!b.take(2.0));
        assert!(TokenBucket::new(0, 0.0).take(0.0));
    }

    /// The construction errors and the signed assertion, as recorded from
    /// the Python transform (`injection.json` → `transform`).
    #[test]
    fn matches_the_python_transform() {
        let f = fixture();
        let t = f.get("transform").unwrap();
        let Some(Json::Array(errors)) = t.get("config_errors") else {
            panic!()
        };
        for case in errors {
            let secret = case.get("secret").and_then(Json::as_str).unwrap();
            let secret = if secret == "<valid>" {
                sa_key()
            } else {
                secret.to_owned()
            };
            let cfg = mapping(case.get("config_yaml").and_then(Json::as_str).unwrap());
            let got = GoogleJwtBearer::with_parts(
                &secret,
                &cfg,
                MockEndpoint::tokens(&[("x", 1)]),
                FakeClock::at(0.0),
            );
            let want = case.get("error").and_then(Json::as_str);
            match (got, want) {
                (Ok(_), None) => {}
                (Err(e), Some(w)) => assert!(e.0.starts_with(w), "{e} vs {w}"),
                (got, want) => panic!("{got:?} vs {want:?}"),
            }
        }
        let Some(Json::Array(mints)) = t.get("mints") else {
            panic!()
        };
        for case in mints {
            let cfg = case.get("config_yaml").and_then(Json::as_str).unwrap();
            let Some(Json::Float(now)) = case.get("now").cloned() else {
                panic!("mint case without a float `now`")
            };
            let endpoint = MockEndpoint::tokens(&[("ya29.minted", 3600)]);
            let t = bearer(cfg, endpoint.clone(), FakeClock::at(now));
            assert_eq!(t.get_value().unwrap(), "ya29.minted");
            let calls = endpoint.calls.lock().unwrap();
            assert_eq!(calls[0].0, case.get("url").and_then(Json::as_str).unwrap());
            assert_eq!(calls[0].1, case.get("body").and_then(Json::as_str).unwrap());
        }
    }

    #[test]
    fn caches_refreshes_and_tracks_active_tokens() {
        let clock = FakeClock::at(1_000_000.0);
        let endpoint = MockEndpoint::tokens(&[("ya29.first", 3600), ("ya29.second", 3600)]);
        let t = bearer(
            "scopes: [a]\nrefresh_margin: 300\n",
            endpoint.clone(),
            clock.clone(),
        );
        assert_eq!(t.active_values(), Some(vec![]));
        assert_eq!(t.get_value().unwrap(), "ya29.first");
        assert_eq!(t.get_value().unwrap(), "ya29.first");
        assert_eq!(endpoint.count.load(Ordering::SeqCst), 1);
        clock.advance(3400.0);
        assert_eq!(t.get_value().unwrap(), "ya29.second");
        assert_eq!(
            t.active_values(),
            Some(vec!["ya29.first".into(), "ya29.second".into()])
        );
        clock.advance(201.0);
        assert_eq!(t.active_values(), Some(vec!["ya29.second".into()]));
        clock.advance(3600.0);
        assert_eq!(t.active_values(), Some(vec![]));
    }

    #[test]
    fn rate_limit_and_failures() {
        let clock = FakeClock::at(1_000_000.0);
        let endpoint = MockEndpoint::tokens(&[("ya29.x", 3600)]);
        let t = bearer(
            "scopes: [a]\nmint_rate_per_hour: 1\n",
            endpoint,
            clock.clone(),
        );
        t.get_value().unwrap();
        clock.advance(3400.0);
        // Inside the margin, and the bucket refilled only 3400/3600.
        assert_eq!(
            t.get_value().unwrap_err().0,
            "google-jwt-bearer: mint rate limit exceeded"
        );

        let failing = |reply: Result<HttpReply, String>| {
            let endpoint = Arc::new(MockEndpoint {
                replies: Mutex::new(vec![reply]),
                ..MockEndpoint::default()
            });
            bearer("scopes: [a]\n", endpoint, FakeClock::at(5.0))
                .get_value()
                .unwrap_err()
                .0
        };
        assert_eq!(
            failing(Ok(HttpReply {
                status: 403,
                body: br#"{"error": "invalid_grant"}"#.to_vec()
            })),
            "google-jwt-bearer: mint failed (HTTP 403)"
        );
        assert_eq!(
            failing(Err("connection refused".into())),
            "google-jwt-bearer: mint failed (network: connection refused)"
        );
        assert_eq!(
            failing(Ok(HttpReply {
                status: 200,
                body: br#"{"expires_in": 3600}"#.to_vec()
            })),
            "google-jwt-bearer: malformed token response from Google"
        );
        assert_eq!(
            failing(Ok(HttpReply {
                status: 200,
                body: br#"{"access_token": "t", "expires_in": 0}"#.to_vec()
            })),
            "google-jwt-bearer: malformed token response from Google"
        );
    }

    #[test]
    fn concurrent_callers_share_one_mint() {
        let endpoint = Arc::new(MockEndpoint {
            replies: Mutex::new(vec![Ok(HttpReply {
                status: 200,
                body: br#"{"access_token": "ya29.shared", "expires_in": 3600}"#.to_vec(),
            })]),
            delay: Duration::from_millis(50),
            ..MockEndpoint::default()
        });
        let t = Arc::new(bearer(
            "scopes: [a]\n",
            endpoint.clone(),
            FakeClock::at(1e6),
        ));
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let t = t.clone();
                std::thread::spawn(move || t.get_value().unwrap())
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), "ya29.shared");
        }
        assert_eq!(endpoint.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_debug_form_never_shows_the_key() {
        let t = bearer(
            "scopes: [a]\n",
            MockEndpoint::tokens(&[("x", 1)]),
            FakeClock::at(0.0),
        );
        let shown = format!("{t:?}");
        assert!(!shown.contains("PRIVATE"), "{shown}");
    }
}
