//! The two questions every cage-addressing command in `cli.py` asks
//! before it does anything: does this cage exist, and is it one this
//! version can still talk to.
//!
//! They are here rather than inside a command because `cli.py` calls
//! `_ensure_v022_cage` from **25 places** and the exists-check from
//! nearly as many. PR D13 (`cage har`) is the first ported body that
//! needs either; D6–D12 take them from here rather than copying them,
//! which is the only way the wording stays one wording.
//!
//! Both report to a stream and hand back an exit status rather than
//! exiting, so a test can read what an operator would have seen. The
//! statuses are not the same — the v0.22 gate exits **2**, not 1 — and
//! that difference is load-bearing: a script that treats "no such cage"
//! and "this cage predates the current layout" alike would retry a
//! migration forever.

use std::io::Write;

use agentcage_state::paths::Paths;

/// Exit status for "there is no such cage".
pub const EXIT_NO_SUCH_CAGE: u8 = 1;

/// Exit status for "this cage was made by a version whose layout is
/// gone" — `cli.py:275`'s `sys.exit(2)`.
pub const EXIT_LEGACY_CAGE: u8 = 2;

/// `if not state.deployment_exists(name): ... sys.exit(1)`.
///
/// Returns the exit status when the cage is unknown, having written the
/// Python's one-line message to `stderr`.
///
/// "Exists" means a stored `cage.yaml`, not a directory: `cage destroy
/// --keep-secrets` leaves the directory behind with `creds/` in it, and
/// a cage that is only a directory is not addressable.
pub fn require_cage(paths: &Paths, name: &str, stderr: &mut dyn Write) -> Option<u8> {
    if paths.deployment_exists(name) {
        return None;
    }
    let _ = writeln!(stderr, "error: cage '{name}' does not exist");
    Some(EXIT_NO_SUCH_CAGE)
}

/// `_ensure_v022_cage` — refuse a v0.21 cage's legacy 3-service shape.
///
/// v0.22 collapsed `cage` / `proxy` / `dns` into `cage` / `egress`.
/// Every command below this line addresses the two-service shape, so a
/// v0.21 cage would either fail with a confusing podman error or, worse,
/// target the wrong workload.
///
/// # Two things this reproduces that look like bugs
///
/// **A missing `metadata.json` reads as v0.0.0**, which is below
/// `(0, 22)`, so a cage whose metadata never got written — or got
/// removed — is told to migrate away from a layout it may never have
/// had. `state.load_metadata` answers `{}` for an absent file and
/// `cli.py:276` turns that into `"0.0.0"`; both halves are faithful.
///
/// **The comparison is `(major, minor)` only.** `_parse_version` reads
/// two components and gives `(0, 0)` for anything it cannot, so a
/// metadata stamp of `"garbage"` also trips the gate.
///
/// A malformed `metadata.json` is the one case that is *not* faithful:
/// the Python's `json.load` raises out of the command with a traceback.
/// Here it is a message and [`EXIT_NO_SUCH_CAGE`], because a traceback
/// is not an error report.
pub fn ensure_v022_cage(paths: &Paths, name: &str, stderr: &mut dyn Write) -> Option<u8> {
    let metadata = match paths.load_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = writeln!(
                stderr,
                "error: cannot read state for cage '{name}': {error}"
            );
            return Some(EXIT_NO_SUCH_CAGE);
        }
    };
    // `meta.get("agentcage_version") or "0.0.0"` — `or`, so a null, an
    // empty string and a missing key all become "0.0.0".
    let version = metadata
        .get("agentcage_version")
        .filter(|value| value.is_truthy())
        .and_then(|value| value.as_str())
        .unwrap_or("0.0.0")
        .to_owned();

    if parse_version(&version) >= (0, 22) {
        return None;
    }

    // One `click.echo` of one f-string that already ends in a newline,
    // so click's own newline makes the trailing blank line. Reproduced
    // rather than tidied: it is what an operator's terminal shows.
    let _ = write!(
        stderr,
        "error: cage '{name}' was created with agentcage v{version}, which used the\n  \
         legacy 3-service layout (cage / proxy / dns). v0.22 unified these into a\n  \
         single 'egress' service. The cage cannot be addressed by v0.22 commands.\n\
         \n  \
         To migrate, run:\n    \
         systemctl --user stop {name}-cage {name}-proxy {name}-dns\n    \
         agentcage cage destroy {name}\n    \
         agentcage cage create -c <your cage.yaml>\n\n"
    );
    Some(EXIT_LEGACY_CAGE)
}

/// `_parse_version` — `'X.Y[.Z…]'` to `(X, Y)`, and `(0, 0)` on garbage.
///
/// Python catches `ValueError`, `TypeError` and `IndexError` around
/// `int(parts[0]), int(parts[1])`, so anything that is not two leading
/// integer components lands on `(0, 0)`. Note `int()` tolerates
/// surrounding whitespace and a leading `+`/`-`; `str::parse::<u32>`
/// tolerates neither, which only matters for a metadata stamp no writer
/// produces.
#[must_use]
pub fn parse_version(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok());
    let minor = parts.next().and_then(|p| p.parse().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => (major, minor),
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn version_parsing_matches_the_python() {
        assert_eq!(parse_version("0.40.1"), (0, 40));
        assert_eq!(parse_version("0.22"), (0, 22));
        assert_eq!(parse_version("1.0.0-rc1"), (1, 0));
        // Every failure mode Python's three `except` clauses cover.
        assert_eq!(parse_version("0.0.0"), (0, 0));
        assert_eq!(parse_version("garbage"), (0, 0));
        assert_eq!(parse_version("1"), (0, 0));
        assert_eq!(parse_version(""), (0, 0));
    }

    /// The gate is `< (0, 22)`, so 0.22.0 itself passes.
    #[test]
    fn the_boundary_is_inclusive() {
        assert!(parse_version("0.22.0") >= (0, 22));
        assert!(parse_version("0.21.9") < (0, 22));
    }
}
