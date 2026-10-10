//! The egress's one secret lookup.
//!
//! Every consumer of a secret value resolves it here: the injector, the
//! Policy API's decider key, the traffic watcher's key and the protocol
//! relays' credentials. One chain, so a value change, a tombstone or a
//! delivery channel behaves the same for all of them.
//!
//! Two channels, in order:
//!
//! 1. `$AGENTCAGE_SECRETS_DIR/<NAME>` (default `/home/acproxy/secrets`),
//!    the staged tmpfs file. The host stages it before the egress starts
//!    and `agentcage secret set` rewrites it live; on apple-container it
//!    is the only channel. The process env is frozen at container
//!    creation, so only this file can carry a value change.
//! 2. The process env (the Podman Secret `type=env` channel).
//!
//! An existing file is authoritative, with its trailing newlines stripped
//! and nothing else. An existing but empty file is a tombstone: the value
//! is `""` and the lookup does not fall back to a stale env value. Only a
//! missing file moves on to the env. An existing but unreadable file is
//! `""` too (fail closed). The directory is read per call, never cached.

use std::path::PathBuf;

/// The default staged-secrets directory.
pub const DEFAULT_SECRETS_DIR: &str = "/home/acproxy/secrets";

fn secrets_dir() -> PathBuf {
    match std::env::var_os("AGENTCAGE_SECRETS_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(DEFAULT_SECRETS_DIR),
    }
}

/// Resolve secret `name`: staged file, then env. `""` when unset or
/// tombstoned; callers fail closed on `""`.
#[must_use]
pub fn read_secret(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    // A name with a path separator would read outside the staged dir.
    // The host never produces one; refuse rather than resolve it.
    if name.contains('/') || name == "." || name == ".." {
        return String::new();
    }
    let path = secrets_dir().join(name);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => match std::fs::read(&path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                text.trim_end_matches('\n').to_owned()
            }
            Err(e) => {
                eprintln!("secret_lookup: failed reading {}: {e}", path.display());
                String::new()
            }
        },
        Ok(_) => std::env::var(name).unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::env::var(name).unwrap_or_default()
        }
        Err(e) => {
            eprintln!("secret_lookup: failed reading {}: {e}", path.display());
            String::new()
        }
    }
}

/// Why a relay credential source was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedSource(pub String);

impl std::fmt::Display for UnsupportedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported relay credential source: {:?}", self.0)
    }
}

impl std::error::Error for UnsupportedSource {}

/// Read a relay `auth.*_source` (`scheme:NAME`).
///
/// Only `env:`, `systemd-creds:` and a bare `:NAME` resolve; `cmd:` and
/// `podman:` are refused (the host refuses them for relay credentials at
/// validation, and nothing in the egress runs a command).
///
/// # Errors
///
/// Any other scheme.
pub fn resolve_credential(source: &str) -> Result<String, UnsupportedSource> {
    let (scheme, arg) = source.split_once(':').unwrap_or((source, ""));
    match scheme {
        "env" | "systemd-creds" | "" => Ok(read_secret(arg)),
        _ => Err(UnsupportedSource(source.to_owned())),
    }
}
