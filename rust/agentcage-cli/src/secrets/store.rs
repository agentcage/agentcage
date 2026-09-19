//! `secret_store.py` -- four backends and the fail-closed choice.
//!
//! | store | at rest | who decrypts | index |
//! | :-- | :-- | :-- | :-- |
//! | [`SystemdCredsStore`] | `<state>/creds/<KEY>.cred`, encrypted | the systemd unit, via `LoadCredentialEncrypted` | the directory listing |
//! | [`KeychainStore`] | a macOS keychain item | agentcage, at deploy time | `<state>/secret_keys.json` |
//! | [`PlaintextStore`] | the podman secret store, **cleartext** | already cleartext | podman |
//! | [`ApplePlaintextStore`] | `<state>/pending_secrets.json`, **cleartext**, 0600 | already cleartext | the file itself |
//!
//! Every backend encrypts at rest except the two plaintext ones, and
//! neither of those is reachable without an explicit opt-in --
//! `backend: plaintext`, `secrets.allow_plaintext: true`, or a `podman:`
//! source on the rule. [`resolve_store`] is where that is enforced, and
//! it refuses rather than defaulting: a cage whose host has no
//! encrypting backend fails `secret set` instead of quietly writing
//! cleartext.
//!
//! # The two file formats, and the trap in each
//!
//! `secret_keys.json` is a JSON array of **strings**, sorted. It is a
//! name index and holds no values -- the `security` CLI cannot
//! enumerate items by service and account, so the keychain backend has
//! to remember what it put there.
//!
//! `pending_secrets.json` is a JSON array of **`[key, value]` pairs**,
//! not an object. Both writers agree on that -- `ApplePlaintextStore`
//! here and the VM hand-off in `cli.py` and `run.py` -- and a reader
//! that assumed a map would fail on every cage that has ever used
//! either path. PR A7's fixture pins it, and so does
//! `tests/secrets_state_fixtures.rs`.
//!
//! Both are written through [`agentcage_core::har::json::dumps`] rather
//! than a serializer of this crate's choosing, because `json.dumps`'s
//! default item separator is `", "` -- with the space -- and the
//! fixture is byte-compared.
//!
//! # `names()` is not implemented by every store
//!
//! Python's base `SecretStore.names` raises `NotImplementedError`, and
//! neither `SystemdCredsStore` nor `PlaintextStore` overrides it. That
//! is not an oversight to fix in the port: both of those keep their
//! names somewhere the caller can already see (a directory listing,
//! `podman secret ls`), and `cage secret list` reads them from there.
//! Here it is [`SecretError::Store`] with a message naming the backend,
//! because Rust has no `NotImplementedError` and a `panic!` would turn
//! a Python exception a caller can catch into an abort.

use std::cell::OnceCell;
use std::fmt;
use std::path::{Path, PathBuf};

use agentcage_core::config::types::Config;
use agentcage_core::har::json::{DumpOptions, Json, dumps, parse};
use agentcage_core::python::repr_str;
use agentcage_exec::tools::podman::Podman;
use agentcage_exec::tools::security::{KeychainTarget, Security};
use agentcage_exec::{CommandRunner, ExecError};

use super::resolver::{SecretHost, replace_podman_secret};
use super::{SecretError, is_file};

/// The host platform, as `resolve_store` reads it.
///
/// `sys.platform == "darwin"` appears twice in `secret_store.py` and
/// decides whether a `vm` cage's secrets go to the keychain or to
/// `systemd-creds`. Taken as a parameter rather than read from
/// `cfg!(target_os)` at the decision point so the macOS branches are
/// reachable from a Linux test -- the same reason
/// `test_secret_store.py` monkeypatches `ss.sys.platform`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Anything that is not macOS.
    Other,
    /// macOS.
    MacOs,
}

impl Platform {
    /// The platform this binary was built for.
    #[must_use]
    pub fn host() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }

    /// `sys.platform == "darwin"`.
    #[must_use]
    pub fn is_darwin(self) -> bool {
        self == Self::MacOs
    }
}

/// The four podman secret operations a store needs.
///
/// `secret_store.py` takes a `podman` object and calls four methods on
/// it; the object is either `podman.Podman` or the Lima-routed
/// `VmPodman` that PR E1 adds. This is that duck type written down, in
/// the same spirit as [`agentcage_exec::tools::podman::SecretLister`],
/// and it is what lets a test drive a store without a podman.
pub trait PodmanSecrets: fmt::Debug {
    /// Whether a secret of this name is in the store.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    fn secret_exists(&self, name: &str) -> Result<bool, ExecError>;

    /// Create it, with the value **on stdin**.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] on a non-zero exit.
    fn secret_create(&self, name: &str, value: &str) -> Result<(), ExecError>;

    /// Remove it, reporting success.
    ///
    /// # Errors
    ///
    /// Only if podman itself could not be run.
    fn secret_remove(&self, name: &str) -> Result<bool, ExecError>;

    /// Read its value back.
    ///
    /// # Errors
    ///
    /// [`ExecError::Failed`] when there is no such secret.
    fn secret_read(&self, name: &str) -> Result<String, ExecError>;
}

impl PodmanSecrets for Podman<'_> {
    fn secret_exists(&self, name: &str) -> Result<bool, ExecError> {
        Self::secret_exists(self, name)
    }

    fn secret_create(&self, name: &str, value: &str) -> Result<(), ExecError> {
        Self::secret_create(self, name, value)
    }

    fn secret_remove(&self, name: &str) -> Result<bool, ExecError> {
        Self::secret_remove(self, name)
    }

    fn secret_read(&self, name: &str) -> Result<String, ExecError> {
        Self::secret_read(self, name)
    }
}

/// A place to keep a cage's secrets.
///
/// The management surface `secret set` / `secret rm` / `secret list`
/// and the deploy paths use.
pub trait SecretStore: fmt::Debug {
    /// The identifier used in `cage.yaml`'s `secrets.backend`, and the
    /// string `cli._store_secret` branches on to choose its success
    /// message.
    ///
    /// Note that two stores answer `"plaintext"`:
    /// [`PlaintextStore`] and [`ApplePlaintextStore`]. That is
    /// deliberate -- the warning an operator must see is the same one,
    /// and the platform difference is not theirs to care about.
    fn name(&self) -> &'static str;

    /// Whether the cage runtime decrypts the value itself.
    ///
    /// True for [`SystemdCredsStore`] (the unit's
    /// `LoadCredentialEncrypted`) and for [`PlaintextStore`] (the value
    /// is already in the podman store); false when agentcage has to
    /// retrieve and deliver it at deploy time.
    fn runtime_decrypts(&self) -> bool;

    /// Whether this backend can be used on this host right now.
    fn available(&self) -> bool;

    /// Store `value` for `cage`'s `key`.
    ///
    /// # Errors
    ///
    /// [`SecretError`] when the backend refused or could not be
    /// reached.
    fn set(&self, cage: &str, key: &str, value: &str, state_dir: &Path) -> Result<(), SecretError>;

    /// Remove `cage`'s `key`.
    ///
    /// # Errors
    ///
    /// [`SecretError`] when the backend could not be reached. A key
    /// that was not there is not an error, in any backend.
    fn delete(&self, cage: &str, key: &str, state_dir: &Path) -> Result<(), SecretError>;

    /// The names of the secrets stored for `cage`.
    ///
    /// # Errors
    ///
    /// [`SecretError::Store`] for a backend that does not keep an
    /// index; see the module docs.
    fn names(&self, cage: &str, state_dir: &Path) -> Result<Vec<String>, SecretError> {
        let _ = (cage, state_dir);
        Err(SecretError::store(format!(
            "backend {} does not support name listing",
            repr_str(self.name())
        )))
    }

    /// The cleartext value, or `None`.
    ///
    /// # Errors
    ///
    /// [`SecretError::Store`] for a backend whose runtime decrypts and
    /// which therefore never implements retrieval.
    fn get(&self, cage: &str, key: &str, state_dir: &Path) -> Result<Option<String>, SecretError> {
        let _ = (cage, key, state_dir);
        Err(SecretError::store(format!(
            "backend {} does not support value retrieval",
            repr_str(self.name())
        )))
    }
}

/// `<cage>.<KEY>` -- the name a secret has in the podman store and the
/// account name it has in the keychain.
#[must_use]
pub fn qualified(cage: &str, key: &str) -> String {
    format!("{cage}.{key}")
}

// ── systemd-creds ────────────────────────────────────────────

/// Linux: encrypt to `<state>/creds/<KEY>.cred`; the Quadlet decrypts.
#[derive(Debug)]
pub struct SystemdCredsStore<'a> {
    host: &'a SecretHost<'a>,
    scope: String,
    podman: Option<&'a dyn PodmanSecrets>,
}

impl<'a> SystemdCredsStore<'a> {
    /// A store encrypting with the configured `secrets.scope`.
    ///
    /// `podman` is optional because `secret set` on a host with no
    /// podman still has to be able to write the `.cred` blob -- the
    /// podman half only drops a *stale* secret of the same name, which
    /// the unit's `ExecStartPre` would otherwise prefer over the newly
    /// encrypted one.
    #[must_use]
    pub fn new(
        host: &'a SecretHost<'a>,
        scope: impl Into<String>,
        podman: Option<&'a dyn PodmanSecrets>,
    ) -> Self {
        Self {
            host,
            scope: scope.into(),
            podman,
        }
    }

    /// Drop a podman secret of the same name, if there is one.
    ///
    /// Both `set` and `delete` do this. After `set` it matters for
    /// correctness rather than tidiness: the egress unit's
    /// `ExecStartPre` only creates the podman secret when it is absent,
    /// so a stale one would shadow the value just encrypted and the
    /// cage would keep running on the old credential.
    fn drop_stale_podman_secret(&self, cage: &str, key: &str) -> Result<(), SecretError> {
        let Some(podman) = self.podman else {
            return Ok(());
        };
        let full = qualified(cage, key);
        if podman
            .secret_exists(&full)
            .map_err(|e| SecretError::store(e.to_string()))?
        {
            podman
                .secret_remove(&full)
                .map_err(|e| SecretError::store(e.to_string()))?;
        }
        Ok(())
    }
}

impl SecretStore for SystemdCredsStore<'_> {
    fn name(&self) -> &'static str {
        "systemd-creds"
    }

    fn runtime_decrypts(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        self.host.default_backend() == super::Backend::SystemdCreds
    }

    fn set(&self, cage: &str, key: &str, value: &str, state_dir: &Path) -> Result<(), SecretError> {
        let scope = self.host.resolve_scope(&self.scope)?;
        self.host.encrypt_secret(key, value, state_dir, scope)?;
        self.drop_stale_podman_secret(cage, key)
    }

    fn delete(&self, cage: &str, key: &str, state_dir: &Path) -> Result<(), SecretError> {
        let cred = state_dir.join("creds").join(format!("{key}.cred"));
        // `Path.unlink(missing_ok=True)`.
        match std::fs::remove_file(&cred) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(SecretError::io(&cred, e)),
        }
        self.drop_stale_podman_secret(cage, key)
    }
}

// ── plaintext (podman) ───────────────────────────────────────

/// The unencrypted podman secret store. Explicit opt-in only.
#[derive(Debug)]
pub struct PlaintextStore<'a> {
    podman: Option<&'a dyn PodmanSecrets>,
}

impl<'a> PlaintextStore<'a> {
    /// A store over this podman, or over none at all.
    ///
    /// `None` is the Python's `PlaintextStore(None)`, which
    /// `resolve_store` can and does construct: `available()` answers
    /// False for it, and the `auto` path checks that -- but the
    /// `backend: plaintext` and `podman:` paths do not, so a cage
    /// configured that way on a host with no podman fails at `set`
    /// rather than at resolution. Reproduced, not fixed.
    #[must_use]
    pub fn new(podman: Option<&'a dyn PodmanSecrets>) -> Self {
        Self { podman }
    }

    /// The podman, or the error the Python gets from `None.secret_*`.
    fn podman(&self) -> Result<&dyn PodmanSecrets, SecretError> {
        self.podman
            .ok_or_else(|| SecretError::store("no podman available for the plaintext store"))
    }
}

impl SecretStore for PlaintextStore<'_> {
    fn name(&self) -> &'static str {
        "plaintext"
    }

    fn runtime_decrypts(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        self.podman.is_some()
    }

    fn set(
        &self,
        cage: &str,
        key: &str,
        value: &str,
        _state_dir: &Path,
    ) -> Result<(), SecretError> {
        replace_podman_secret(self.podman()?, &qualified(cage, key), value)
    }

    fn delete(&self, cage: &str, key: &str, _state_dir: &Path) -> Result<(), SecretError> {
        let podman = self.podman()?;
        let full = qualified(cage, key);
        if podman
            .secret_exists(&full)
            .map_err(|e| SecretError::store(e.to_string()))?
        {
            podman
                .secret_remove(&full)
                .map_err(|e| SecretError::store(e.to_string()))?;
        }
        Ok(())
    }

    fn get(&self, cage: &str, key: &str, _state_dir: &Path) -> Result<Option<String>, SecretError> {
        let podman = self.podman()?;
        let full = qualified(cage, key);
        if !podman
            .secret_exists(&full)
            .map_err(|e| SecretError::store(e.to_string()))?
        {
            return Ok(None);
        }
        podman
            .secret_read(&full)
            .map(Some)
            .map_err(|e| SecretError::store(e.to_string()))
    }
}

// ── keychain (macOS; PR E2b owns the behaviour) ──────────────

/// macOS: a keychain item per secret, plus a non-secret name index.
///
/// # Whose PR this is
///
/// The keychain *behaviour* is PR E2b's, gated on Apple hardware, and
/// the argv was pinned by PR D1 in
/// [`agentcage_exec::tools::security`]. What is here is the wiring: the
/// target-selection order, the index file (which PR A7's fixture
/// captures and this PR must read), and the store trait impl. Nothing
/// here re-derives an argv.
///
/// # The known argv exposure
///
/// [`SecretStore::set`] below reaches
/// [`agentcage_exec::tools::security::Security::add`], which builds
/// `security add-generic-password -s agentcage -a <cage>.<KEY> -w
/// <CLEARTEXT> -U`. The cleartext is in argv and therefore in `ps` for
/// the life of the child. It is the only such path in the code being
/// ported, it is marked with
/// [`agentcage_exec::Command::secret_arg`] so it is redacted from
/// everything this workspace prints, and it is *not* changed here --
/// see the module docs in [`agentcage_exec::tools::security`] for why
/// the obvious fix needs a Mac to verify.
///
/// # Target selection
///
/// The login keychain if it is genuinely writable (an unlocked GUI
/// session), else the System keychain if passwordless `sudo` already
/// works, else fail closed. It never prompts. The probe is a *write* --
/// an add followed by a delete -- because the login keychain answers
/// reads over a headless SSH session and then refuses writes.
#[derive(Debug)]
pub struct KeychainStore<'a> {
    runner: &'a dyn CommandRunner,
    platform: Platform,
    target: OnceCell<KeychainTarget>,
}

impl<'a> KeychainStore<'a> {
    /// A keychain store for this platform.
    #[must_use]
    pub fn new(runner: &'a dyn CommandRunner, platform: Platform) -> Self {
        Self {
            runner,
            platform,
            target: OnceCell::new(),
        }
    }

    /// `_target()` -- which keychain, and whether it needs `sudo -n`.
    ///
    /// Only a *success* is cached, which is Python's behaviour: the
    /// failure path raises without assigning `_target_cache`, so a
    /// keychain unlocked between two calls is picked up.
    ///
    /// # Errors
    ///
    /// [`SecretError::Store`] off macOS, and when neither target is
    /// writable.
    pub fn target(&self) -> Result<&KeychainTarget, SecretError> {
        if let Some(target) = self.target.get() {
            return Ok(target);
        }
        if !self.platform.is_darwin() {
            return Err(SecretError::store("keychain backend is macOS-only"));
        }
        let security = Security::new(self.runner);
        let found = if security
            .writable(&KeychainTarget::login())
            .map_err(|e| SecretError::store(e.to_string()))?
        {
            KeychainTarget::login()
        } else if security
            .writable(&KeychainTarget::system())
            .map_err(|e| SecretError::store(e.to_string()))?
        {
            KeychainTarget::system()
        } else {
            return Err(SecretError::store(
                "macOS keychain unavailable: the login keychain is locked \
                 (no unlocked GUI session) and passwordless sudo for the \
                 System keychain is not configured. Log into the Mac's GUI, \
                 set up NOPASSWD sudo for /usr/bin/security, or set \
                 secrets.allow_plaintext.",
            ));
        };
        Ok(self.target.get_or_init(|| found))
    }

    /// `<state>/secret_keys.json`.
    #[must_use]
    pub fn index_path(state_dir: &Path) -> PathBuf {
        state_dir.join("secret_keys.json")
    }

    /// Read the name index, or an empty list.
    ///
    /// Every failure is an empty list -- a missing file, a truncated
    /// write, a JSON document that is not an array of strings. Python's
    /// `except Exception: return []` is deliberate: the index is a
    /// convenience for `secret list`, and a corrupt one must not make
    /// the cage unusable.
    fn read_index(state_dir: &Path) -> Vec<String> {
        let path = Self::index_path(state_dir);
        if !is_file(&path) {
            return Vec::new();
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let Ok(Json::Array(items)) = parse(&text) else {
            return Vec::new();
        };
        items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<String>>>()
            .unwrap_or_default()
    }

    /// Write the index: a JSON array of strings, sorted, deduplicated.
    fn write_index(state_dir: &Path, keys: &[String]) -> Result<(), SecretError> {
        let mut sorted: Vec<String> = keys.to_vec();
        sorted.sort();
        let doc = Json::Array(sorted.into_iter().map(Json::Str).collect());
        let path = Self::index_path(state_dir);
        std::fs::write(&path, dumps(&doc, DumpOptions::default()))
            .map_err(|e| SecretError::io(&path, e))
    }

    /// `_index_add` -- the key, moved to the end and then sorted.
    fn index_add(state_dir: &Path, key: &str) -> Result<(), SecretError> {
        let mut keys: Vec<String> = Self::read_index(state_dir)
            .into_iter()
            .filter(|k| k != key)
            .collect();
        keys.push(key.to_string());
        Self::write_index(state_dir, &keys)
    }

    /// `_index_remove`.
    fn index_remove(state_dir: &Path, key: &str) -> Result<(), SecretError> {
        let keys: Vec<String> = Self::read_index(state_dir)
            .into_iter()
            .filter(|k| k != key)
            .collect();
        Self::write_index(state_dir, &keys)
    }
}

impl SecretStore for KeychainStore<'_> {
    fn name(&self) -> &'static str {
        "keychain"
    }

    fn runtime_decrypts(&self) -> bool {
        false
    }

    fn available(&self) -> bool {
        self.target().is_ok()
    }

    fn set(&self, cage: &str, key: &str, value: &str, state_dir: &Path) -> Result<(), SecretError> {
        let target = self.target()?;
        let account = Security::account(cage, key);
        Security::new(self.runner)
            .add(target, &account, value)
            .map_err(|e| match e {
                ExecError::Failed { stderr, .. } => {
                    SecretError::store(format!("keychain add failed: {stderr}"))
                }
                other => SecretError::store(format!("keychain add failed: {other}")),
            })?;
        Self::index_add(state_dir, key)
    }

    fn delete(&self, cage: &str, key: &str, state_dir: &Path) -> Result<(), SecretError> {
        let target = self.target()?;
        // The Python ignores the result entirely: deleting a key that
        // is not in the keychain still has to clear the index.
        let _ = Security::new(self.runner).delete(target, &Security::account(cage, key));
        Self::index_remove(state_dir, key)
    }

    fn names(&self, _cage: &str, state_dir: &Path) -> Result<Vec<String>, SecretError> {
        // `cage` is unused, exactly as in the Python: the index is
        // per-deployment-directory, and the directory already is the
        // cage. `_index_add` even calls `self.names("")`.
        Ok(Self::read_index(state_dir))
    }

    fn get(&self, cage: &str, key: &str, _state_dir: &Path) -> Result<Option<String>, SecretError> {
        let target = self.target()?;
        Security::new(self.runner)
            .find(target, &Security::account(cage, key))
            .map_err(|e| SecretError::store(e.to_string()))
    }
}

// ── plaintext (apple-container) ──────────────────────────────

/// macOS opt-in cleartext: the legacy `pending_secrets.json`, 0600.
///
/// The file is a JSON array of `[key, value]` pairs. See the module
/// docs; a reader that assumes a map is wrong.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApplePlaintextStore;

impl ApplePlaintextStore {
    /// `<state>/pending_secrets.json`.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join("pending_secrets.json")
    }

    /// Read the pairs, in file order.
    ///
    /// A `Vec` of pairs rather than a map because Python's
    /// `{k: v for k, v in json.loads(...)}` keeps *insertion* order and
    /// the writer dumps that order straight back out. A `BTreeMap`
    /// would silently re-sort the file on the next write, and an
    /// `IndexMap` would be a new dependency for a two-line invariant.
    ///
    /// Every failure -- missing file, unreadable file, a document that
    /// is not an array of two-element string arrays -- is an empty
    /// list, which is Python's `except Exception: return {}`.
    #[must_use]
    pub fn load(state_dir: &Path) -> Vec<(String, String)> {
        let path = Self::path(state_dir);
        if !is_file(&path) {
            return Vec::new();
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let Ok(Json::Array(rows)) = parse(&text) else {
            return Vec::new();
        };
        let mut pairs: Vec<(String, String)> = Vec::with_capacity(rows.len());
        for row in &rows {
            let Json::Array(cells) = row else {
                return Vec::new();
            };
            // `for k, v in ...` raises on anything but a 2-tuple, and
            // the raise is caught into `{}`.
            let [key, value] = cells.as_slice() else {
                return Vec::new();
            };
            let (Some(key), Some(value)) = (key.as_str(), value.as_str()) else {
                return Vec::new();
            };
            set_pair(&mut pairs, key, value);
        }
        pairs
    }

    /// Write the pairs with `O_WRONLY|O_CREAT|O_TRUNC, 0600`.
    ///
    /// The mode is the point: this file holds cleartext credentials, so
    /// it must not be world-readable even for the moment between
    /// creation and a `chmod`. Note the Python's flags -- no `O_EXCL`,
    /// and the mode applies only when the file is created, so an
    /// existing file keeps whatever mode it had. Reproduced exactly.
    ///
    /// # Errors
    ///
    /// [`SecretError::Io`] when the file could not be written.
    pub fn save(state_dir: &Path, pairs: &[(String, String)]) -> Result<(), SecretError> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = Self::path(state_dir);
        let doc = Json::Array(
            pairs
                .iter()
                .map(|(k, v)| Json::Array(vec![Json::string(k), Json::string(v)]))
                .collect(),
        );
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| SecretError::io(&path, e))?;
        file.write_all(dumps(&doc, DumpOptions::default()).as_bytes())
            .map_err(|e| SecretError::io(&path, e))
    }
}

/// Python's `d[k] = v`: replace in place if the key is there, append
/// otherwise. The position of a key's first appearance is kept.
fn set_pair(pairs: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(slot) = pairs.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value.to_string();
        return;
    }
    pairs.push((key.to_string(), value.to_string()));
}

impl SecretStore for ApplePlaintextStore {
    fn name(&self) -> &'static str {
        "plaintext"
    }

    fn runtime_decrypts(&self) -> bool {
        false
    }

    fn available(&self) -> bool {
        true
    }

    fn set(
        &self,
        _cage: &str,
        key: &str,
        value: &str,
        state_dir: &Path,
    ) -> Result<(), SecretError> {
        let mut pairs = Self::load(state_dir);
        set_pair(&mut pairs, key, value);
        Self::save(state_dir, &pairs)
    }

    fn delete(&self, _cage: &str, key: &str, state_dir: &Path) -> Result<(), SecretError> {
        let mut pairs = Self::load(state_dir);
        pairs.retain(|(k, _)| k != key);
        Self::save(state_dir, &pairs)
    }

    fn names(&self, _cage: &str, state_dir: &Path) -> Result<Vec<String>, SecretError> {
        let mut names: Vec<String> = Self::load(state_dir).into_iter().map(|(k, _)| k).collect();
        names.sort();
        Ok(names)
    }

    fn get(&self, _cage: &str, key: &str, state_dir: &Path) -> Result<Option<String>, SecretError> {
        Ok(Self::load(state_dir)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v))
    }
}

// ── choosing one ─────────────────────────────────────────────

/// Backend names valid in `cage.yaml`'s `secrets.backend`.
///
/// The same set [`agentcage_core::config::secret::KNOWN_BACKENDS`]
/// validates against, repeated here only so this module can be read on
/// its own. `"keychain"` is the spelling; the module docstring in
/// `secret_store.py` says `system-keychain`, which is not a value the
/// parser accepts.
pub const KNOWN_BACKENDS: [&str; 4] = ["auto", "keychain", "plaintext", "systemd-creds"];

/// The platform's explicit-opt-in cleartext store.
///
/// `plaintext_store_for`: a file on apple-container, the podman store
/// everywhere else.
#[must_use]
pub fn plaintext_store_for<'a>(
    cfg: &Config,
    podman: Option<&'a dyn PodmanSecrets>,
) -> Box<dyn SecretStore + 'a> {
    if cfg.isolation == "apple-container" {
        Box::new(ApplePlaintextStore)
    } else {
        Box::new(PlaintextStore::new(podman))
    }
}

/// `resolve_store` -- pick the store for `cfg`, fail-closed.
///
/// The order is: an explicit per-rule `source:` scheme, then
/// `secrets.backend`, then -- for `auto` -- the platform's encrypting
/// backend, then `allow_plaintext`, then a refusal.
///
/// # What decides "the platform's encrypting backend"
///
/// Not the host OS alone. `apple-container` gets the keychain, and so
/// does **`isolation: vm` on a macOS host**, which is the subtle one:
/// `secret set` runs on the host, `systemd-creds` lives in the guest
/// and is not reachable from there, so `auto` would find no encrypting
/// backend and refuse every `secret set` -- which made `domains.auto`,
/// whose decider `api_key` is mandatory, unusable on a Mac without
/// opting into plaintext. The keychain is the host's encrypting store
/// and the vm backend bridges the value into the guest at deploy time.
///
/// Note the asymmetry this creates, which is the Python's and is
/// reproduced: that host-keychain rule applies to `auto` only. An
/// explicit `backend: systemd-creds` on a macOS vm cage still builds a
/// [`SystemdCredsStore`], finds it unavailable, and refuses.
///
/// # Errors
///
/// [`SecretError::Store`] when a named backend is unavailable, and when
/// `auto` finds no encrypting backend and `allow_plaintext` is unset.
pub fn resolve_store<'a>(
    cfg: &Config,
    host: &'a SecretHost<'a>,
    podman: Option<&'a dyn PodmanSecrets>,
    source_scheme: &str,
    platform: Platform,
) -> Result<Box<dyn SecretStore + 'a>, SecretError> {
    let allow_plaintext = cfg.secrets.allow_plaintext;
    let is_apple = cfg.isolation == "apple-container";
    let host_keychain = is_apple || (cfg.isolation == "vm" && platform.is_darwin());

    let plaintext = || -> Box<dyn SecretStore + 'a> {
        if is_apple {
            Box::new(ApplePlaintextStore)
        } else {
            Box::new(PlaintextStore::new(podman))
        }
    };

    // An explicit per-rule scheme wins over `secrets.backend`.
    if source_scheme == "podman" {
        return Ok(plaintext());
    }
    if source_scheme == "systemd-creds" {
        return Ok(Box::new(SystemdCredsStore::new(
            host,
            &cfg.secrets.scope,
            podman,
        )));
    }

    let backend = if cfg.secrets.backend.is_empty() {
        "auto"
    } else {
        cfg.secrets.backend.as_str()
    };

    match backend {
        "plaintext" => Ok(plaintext()),
        "systemd-creds" => {
            let store = SystemdCredsStore::new(host, &cfg.secrets.scope, podman);
            if !store.available() {
                return Err(SecretError::store(
                    "secrets.backend is 'systemd-creds' but systemd-creds \
                     encryption is not usable on this host",
                ));
            }
            Ok(Box::new(store))
        }
        "keychain" => {
            let store = KeychainStore::new(host.runner(), platform);
            if !store.available() {
                return Err(SecretError::store(
                    "secrets.backend 'keychain' requires macOS with an unlocked \
                     login keychain or passwordless sudo for the System keychain",
                ));
            }
            Ok(Box::new(store))
        }
        // `auto`, and anything else -- the parser has already rejected
        // every other spelling, and the Python's `if` chain falls
        // through to this branch for them too.
        _ => {
            if host_keychain {
                let store = KeychainStore::new(host.runner(), platform);
                if store.available() {
                    return Ok(Box::new(store));
                }
            } else {
                let store = SystemdCredsStore::new(host, &cfg.secrets.scope, podman);
                if store.available() {
                    return Ok(Box::new(store));
                }
            }
            if allow_plaintext {
                return Ok(plaintext());
            }
            Err(SecretError::store(
                "no encrypting secret backend is available and \
                 secrets.allow_plaintext is not set",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplePlaintextStore, KNOWN_BACKENDS, SecretStore, set_pair};

    #[test]
    fn the_backend_names_match_the_parsers() {
        assert_eq!(
            KNOWN_BACKENDS,
            agentcage_core::config::secret::KNOWN_BACKENDS
        );
    }

    #[test]
    fn assigning_an_existing_key_keeps_its_position() {
        let mut pairs = vec![
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ];
        set_pair(&mut pairs, "A", "9");
        assert_eq!(pairs[0], ("A".to_string(), "9".to_string()));
        set_pair(&mut pairs, "C", "3");
        assert_eq!(pairs[2], ("C".to_string(), "3".to_string()));
    }

    /// The apple store's own index, on a directory that has no file:
    /// an empty list, never an error and never a panic.
    #[test]
    fn a_missing_pending_secrets_file_reads_as_empty() {
        let store = ApplePlaintextStore;
        let missing = std::path::Path::new("/nonexistent-agentcage-d3");
        assert_eq!(store.names("c", missing).unwrap(), Vec::<String>::new());
        assert_eq!(store.get("c", "K", missing).unwrap(), None);
    }
}
