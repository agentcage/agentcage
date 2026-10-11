//! The grants overlay file and the DNS publish of granted names.
//!
//! `grants.yaml` is shared state: the host's `cage grants` reads it,
//! revokes from it and promotes out of it, writing with the same
//! temp-file scheme used here (`agentcage-state`'s `atomic` module), so
//! the format and the write discipline are a contract, not a detail:
//!
//! * a YAML list of `{domain, granted_at, expires_at, reason, source}`
//!   mappings (extra keys kept), sorted by domain; `expires_at: ''` is
//!   permanent;
//! * written to `grants.yaml.<pid>.tmp`, or `grants.yaml.<pid>.1.tmp` if
//!   that exists, opened `O_CREAT|O_EXCL` so a planted symlink is never
//!   written through, then renamed over the file. A colliding temp is
//!   never unlinked: across PID namespaces it may be the host's in-flight
//!   write;
//! * read lossily: anything unreadable or malformed is an empty overlay.
//!
//! The DNS publish is the egress-local half of making a grant resolvable:
//! the sorted, still-valid granted names, one per line, written to
//! `/home/acproxy/dns/granted` by temp + rename, **then** the `reload`
//! flag beside it is touched. The supervisor (root) renders dnsmasq's
//! servers-file from it and HUPs dnsmasq; this process (uid 200, empty
//! bounding set) can do neither. Bare names only, never `server=` lines:
//! the egress may name a zone but not choose where it is forwarded.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use agentcage_core::config::domain::matches_domain_shape;

use crate::config::Mapping;
use crate::inspect::domain::{parse_overlay, render_overlay};

/// Default `AGENTCAGE_GRANTS_DIR`.
pub const DEFAULT_GRANTS_DIR: &str = "/var/lib/agentcage";
/// Default `AGENTCAGE_DNS_PUBLISH`.
pub const DEFAULT_DNS_PUBLISH: &str = "/home/acproxy/dns/granted";

/// Where the Policy API keeps its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPaths {
    /// The overlay, `<grants dir>/grants.yaml`.
    pub grants_file: PathBuf,
    /// The published list of granted names.
    pub dns_publish: PathBuf,
    /// The supervisor's reload flag, `reload` beside [`Self::dns_publish`].
    pub dns_reload: PathBuf,
    /// The PID the temp file names carry. The process id in production;
    /// a parameter so the collision branches can be driven from tests.
    pub pid: u32,
}

impl PolicyPaths {
    /// Paths under `grants_dir` and at `dns_publish`.
    #[must_use]
    pub fn new(grants_dir: impl Into<PathBuf>, dns_publish: impl Into<PathBuf>) -> Self {
        let dns_publish = dns_publish.into();
        let dns_reload = match dns_publish.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join("reload"),
            _ => PathBuf::from(".").join("reload"),
        };
        Self {
            grants_file: grants_dir.into().join("grants.yaml"),
            dns_publish,
            dns_reload,
            pid: std::process::id(),
        }
    }

    /// From `AGENTCAGE_GRANTS_DIR` and `AGENTCAGE_DNS_PUBLISH`, with the
    /// image defaults (`os.environ.get(name, default)`: a set-but-empty
    /// variable is taken as given).
    #[must_use]
    pub fn from_env() -> Self {
        let var = |name: &str, default: &str| {
            std::env::var_os(name).map_or_else(|| PathBuf::from(default), PathBuf::from)
        };
        Self::new(
            var("AGENTCAGE_GRANTS_DIR", DEFAULT_GRANTS_DIR),
            var("AGENTCAGE_DNS_PUBLISH", DEFAULT_DNS_PUBLISH),
        )
    }
}

/// The overlay's mtime, `None` when it cannot be stat'ed (the Python's
/// `0.0`). Compared for equality only: any change means "reconcile".
pub(crate) fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Load the overlay. Unreadable, not UTF-8, malformed, not a list: all
/// an empty overlay, as the reader must never fail on a file the caged
/// side of the boundary can write.
pub(crate) fn load(path: &Path) -> Vec<Mapping> {
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    // Strict UTF-8, as Python's text-mode `open` decodes it: a file with
    // one bad byte is garbage, not a document with a replacement char.
    let Ok(text) = String::from_utf8(bytes) else {
        return Vec::new();
    };
    parse_overlay(&text)
}

/// Write `entries` as the overlay, atomically. On success returns the
/// new mtime.
pub(crate) fn write(
    paths: &PolicyPaths,
    entries: &[Mapping],
) -> Result<Option<SystemTime>, String> {
    let target = &paths.grants_file;
    let text = render_overlay(entries).map_err(|e| e.to_string())?;
    if let Some(dir) = target.parent()
        && !dir.as_os_str().is_empty()
    {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let name = target
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let sibling = |n: String| target.with_file_name(n);
    let candidates = [
        sibling(format!("{name}.{}.tmp", paths.pid)),
        sibling(format!("{name}.{}.1.tmp", paths.pid)),
    ];
    let mut opened = None;
    for candidate in &candidates {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(candidate)
        {
            Ok(file) => {
                opened = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    let Some((tmp, mut file)) = opened else {
        let base = |p: &PathBuf| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        };
        return Err(format!(
            "temp files {} and {} both exist after retry; aborting persist (not unlinking a \
             possible concurrent writer's in-flight temp)",
            base(&candidates[0]),
            base(&candidates[1])
        ));
    };
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            fs::rename(tmp, target)
        });
    if let Err(e) = written {
        // Our own temp only, and only because our own write failed;
        // leaving it would push the next persist onto the `.1` name and
        // the one after into an abort.
        let _ = fs::remove_file(tmp);
        return Err(e.to_string());
    }
    Ok(mtime(target))
}

/// The names to publish: valid-shaped (the regex alone, so the publish
/// never carries something the dnsmasq renderer would split), not
/// expired at `now_iso` (lexical, the overlay contract), sorted.
pub(crate) fn publishable(granted: &[(String, Mapping)], now_iso: &str) -> Vec<String> {
    let mut names: Vec<String> = granted
        .iter()
        .filter(|(d, entry)| {
            if d.is_empty() || !matches_domain_shape(d) {
                return false;
            }
            let exp = match entry.get("expires_at") {
                Some(v) if crate::config::truthy(v) => agentcage_core::python::str_of(v),
                _ => String::new(),
            };
            exp.is_empty() || exp.as_str() > now_iso
        })
        .map(|(d, _)| d.clone())
        .collect();
    names.sort();
    names
}

/// Publish `names` for the supervisor, then raise the reload flag.
pub(crate) fn publish_dns(paths: &PolicyPaths, names: &[String]) -> Result<(), String> {
    let target = &paths.dns_publish;
    if let Some(dir) = target.parent()
        && !dir.as_os_str().is_empty()
    {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut tmp_name = target.as_os_str().to_owned();
    tmp_name.push(format!(".{}.tmp", paths.pid));
    let tmp = PathBuf::from(tmp_name);
    // A stale temp of our own (a crash mid-publish) is ours to clear;
    // nobody else writes this directory.
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    let body = names.iter().fold(String::new(), |mut out, d| {
        out.push_str(d);
        out.push('\n');
        out
    });
    let written = file.write_all(body.as_bytes()).and_then(|()| {
        drop(file);
        fs::rename(&tmp, target)
    });
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    // Only after the list is in place, so a fresh flag never renders a
    // stale list.
    fs::File::create(&paths.dns_reload).map_err(|e| e.to_string())?;
    Ok(())
}
