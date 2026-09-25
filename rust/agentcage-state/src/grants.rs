//! The Policy-API grants overlay, and the audit trail beside it.
//!
//! # The overlay is `grants/grants.yaml`, a top-level YAML **list**
//!
//! An earlier draft of RUST-PORT-PLAN.md §2.7 said `grants.json`. It
//! is neither JSON nor an object. `state.py:243` is
//! `grants_dir(name) / "grants.yaml"` and the format is a sequence of
//! mappings:
//!
//! ```yaml
//! - domain: registry.npmjs.org
//!   granted_at: '2026-06-01T12:00:00+00:00'
//!   expires_at: '2026-06-01T13:00:00+00:00'   # empty = no expiry
//!   reason: npm install requested
//!   source: policy-hook
//! ```
//!
//! An **empty `expires_at` means no expiry, not expired.** The state
//! fixture carries one of each for exactly this reason.
//!
//! # Why the reader swallows everything
//!
//! `load_grants` catches `(OSError, yaml.YAMLError, ValueError)` and
//! returns `[]`. The `ValueError` is not decorative: it covers
//! `UnicodeDecodeError`, which is a subclass of it, and which
//! `read_text` raises when the overlay is non-UTF-8 garbage. Without
//! that catch the exception escapes and **permanently** breaks the
//! grants reconcile and every `cage grants` command, because the
//! overlay is written by the in-container addon across the trust
//! boundary and the host cannot assume anything about its contents.
//!
//! So an unreadable overlay is an empty overlay. The port keeps that:
//! [`Paths::load_grants`] is infallible, and the lossy UTF-8 decode is
//! not a shortcut — it is `read_text`'s failure mode folded into the
//! same answer.
//!
//! This mirrors the in-container twin, `policy_api._load_overlay`.
//!
//! # Why `policy-audit.jsonl` is not in `grants/`
//!
//! `grants/` is bind-mounted read-write into the egress container and
//! group-shared with the operator through podman's user-namespace
//! mapping (0770 on the container backend, 0777 on the apple one). A
//! forensic record of which grant was applied or removed, and by whom,
//! placed inside it would be readable, forgeable and truncatable by
//! the caged agent's own container. A host audit trail cannot be
//! editable by the thing it audits, so it sits one level up, a sibling
//! of `grants/` and outside the mount.

use std::fs;
use std::io::Write as _;

use agentcage_core::har::json::{DumpOptions, Json, dumps};
use agentcage_core::yaml::{self, Mapping, Value};

use crate::atomic::atomic_write_text;
use crate::error::{Result, StateError};
use crate::paths::Paths;

impl Paths {
    /// `state.grants_dir`, created.
    ///
    /// The Python helper `mkdir`s on the way in and callers rely on
    /// it, so the side effect is in the name here rather than hidden
    /// in a getter. [`Paths::grants_dir`] is the path-only version.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if the directory cannot be created.
    pub fn ensure_grants_dir(&self, name: &str) -> Result<std::path::PathBuf> {
        let dir = self.grants_dir(name);
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create directory", e))?;
        Ok(dir)
    }

    /// `state.cage_data_dir`, created.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if the directory cannot be created.
    pub fn ensure_cage_data_dir(&self, name: &str) -> Result<std::path::PathBuf> {
        let dir = self.cage_data_dir(name);
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create directory", e))?;
        Ok(dir)
    }

    /// `state.capture_dir`, created.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if the directory cannot be created.
    pub fn ensure_capture_dir(&self, name: &str) -> Result<std::path::PathBuf> {
        let dir = self.capture_dir(name);
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create directory", e))?;
        Ok(dir)
    }

    /// `state.load_grants` — the overlay, or an empty list.
    ///
    /// Infallible: see the module docs. Entries that are not mappings,
    /// or that carry no truthy `domain`, are dropped — the same
    /// `[e for e in data if isinstance(e, dict) and e.get("domain")]`
    /// filter the Python applies, which is the gate that stops a
    /// malformed overlay entry from reaching the dnsmasq renderer.
    #[must_use]
    pub fn load_grants(&self, name: &str) -> Vec<Mapping> {
        let path = self.grants_file(name);
        if !path.is_file() {
            return Vec::new();
        }
        // `p.read_text()` raising UnicodeDecodeError is one of the
        // cases the Python catches, so a lossy decode reaches the same
        // answer by the same route: garbage in, empty overlay out.
        let Ok(bytes) = fs::read(&path) else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&bytes);
        let Ok(Value::Sequence(entries)) = yaml::load(&text) else {
            // `if not isinstance(data, list): return []` also covers a
            // YAMLError, which lands here as the `Err` arm.
            return Vec::new();
        };
        entries
            .into_iter()
            .filter_map(|entry| match entry {
                Value::Mapping(mapping) => Some(mapping),
                _ => None,
            })
            .filter(|mapping| {
                mapping
                    .get("domain")
                    .is_some_and(agentcage_core::yaml::python_bool)
            })
            .collect()
    }

    /// `state.save_grants` — atomically, via [`crate::atomic`].
    ///
    /// The host CLI's `grants revoke` is a read-modify-write and the
    /// in-container addon writes the same path from another PID
    /// namespace; the temp-name scheme in [`crate::atomic`] is what
    /// keeps the two from clobbering each other's in-flight file.
    /// Concurrent writers are bounded by the per-cage request rate
    /// limit, and the resolved final path is last-writer-wins on the
    /// rare overlap — which is the Python's stated design, not an
    /// oversight.
    ///
    /// # Errors
    ///
    /// [`StateError::Yaml`] if the entries cannot be emitted safely,
    /// then whatever [`atomic_write_text`] returns.
    pub fn save_grants(&self, name: &str, entries: &[Mapping]) -> Result<()> {
        let path = self.grants_file(name);
        let document = Value::Sequence(entries.iter().cloned().map(Value::Mapping).collect());
        let text = yaml::dump(&document).map_err(|source| StateError::Yaml {
            path: path.clone(),
            source,
        })?;
        atomic_write_text(&path, &text)
    }

    /// `state.append_policy_audit` — one JSON object per line.
    ///
    /// `ts` is **prepended**, not appended: the Python builds
    /// `{"ts": ..., **entry}`, so a caller that passes its own `ts`
    /// has it overridden and the key still sorts first in the file.
    /// The fixture asserts that position.
    ///
    /// Best-effort, and the signature says so by returning nothing:
    /// `except OSError: pass`. Audit is defence in depth and is never
    /// a reason to fail a grant promotion — a write that fails here
    /// must not turn a successful `grants promote` into an error.
    pub fn append_policy_audit(&self, name: &str, timestamp: &str, entry: &Json) {
        // `{"ts": datetime.now(timezone.utc).isoformat(), **entry}` --
        // `ts` first, then the caller's fields, and a caller's own
        // `ts` overwrites the value in that first slot rather than
        // adding a second one. `Json::set` is `dict.__setitem__` and
        // has exactly that behaviour.
        let mut record = Json::Object(vec![("ts".to_owned(), Json::string(timestamp))]);
        if let Json::Object(fields) = entry {
            for (key, value) in fields {
                record.set(key.clone(), value.clone());
            }
        }
        let line = format!("{}\n", dumps(&record, DumpOptions::default()));

        let path = self.policy_audit_file(name);
        // The parent is a SIBLING of grants/, so `ensure_grants_dir`'s
        // mkdir does not cover it.
        let Some(parent) = path.parent() else { return };
        if fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) else {
            return;
        };
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use crate::paths::Paths;
    use crate::testdir::TestDir;
    use agentcage_core::har::json::parse;
    use agentcage_core::yaml::{self, Value};
    use std::fs;

    fn overlay(paths: &Paths, name: &str, text: &str) {
        let path = paths.grants_file(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn an_absent_overlay_is_empty_not_an_error() {
        let dir = TestDir::new("grants-absent");
        let paths = Paths::under(dir.path());
        assert!(paths.load_grants("x").is_empty());
    }

    #[test]
    fn unreadable_garbage_is_an_empty_overlay() {
        // The `ValueError` catch: `UnicodeDecodeError` is a subclass,
        // and letting it escape breaks the reconcile permanently.
        let dir = TestDir::new("grants-garbage");
        let paths = Paths::under(dir.path());
        fs::create_dir_all(paths.grants_dir("x")).unwrap();
        fs::write(paths.grants_file("x"), [0xff, 0xfe, 0x00, 0x80]).unwrap();
        assert!(paths.load_grants("x").is_empty());

        overlay(&paths, "y", "{not: a, list: true}\n");
        assert!(paths.load_grants("y").is_empty());

        overlay(&paths, "z", "- [unclosed\n");
        assert!(paths.load_grants("z").is_empty());
    }

    #[test]
    fn entries_without_a_truthy_domain_are_dropped() {
        let dir = TestDir::new("grants-filter");
        let paths = Paths::under(dir.path());
        overlay(
            &paths,
            "x",
            "- domain: keep.example.com\n\
             - domain: ''\n\
             - notadomain: true\n\
             - a string, not a mapping\n",
        );
        let grants = paths.load_grants("x");
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants[0].get("domain"),
            Some(&Value::String("keep.example.com".to_owned()))
        );
    }

    #[test]
    fn save_grants_round_trips_and_keeps_an_empty_expiry_empty() {
        let dir = TestDir::new("grants-save");
        let paths = Paths::under(dir.path());
        overlay(
            &paths,
            "x",
            "- domain: a.example.com\n  expires_at: ''\n  source: operator\n",
        );
        let grants = paths.load_grants("x");
        paths.save_grants("x", &grants).unwrap();

        let reread = paths.load_grants("x");
        assert_eq!(reread, grants);
        // An empty string, not a null and not a missing key.
        assert_eq!(
            reread[0].get("expires_at"),
            Some(&Value::String(String::new()))
        );
        // And it survives as a *quoted* empty string, which is what
        // PyYAML reads back as `""` rather than as None.
        let text = fs::read_to_string(paths.grants_file("x")).unwrap();
        assert_eq!(yaml::load(&text).unwrap(), {
            Value::Sequence(grants.into_iter().map(Value::Mapping).collect())
        });
    }

    #[test]
    fn the_audit_trail_is_a_sibling_of_the_container_writable_dir() {
        let dir = TestDir::new("grants-audit");
        let paths = Paths::under(dir.path());
        paths.append_policy_audit(
            "x",
            "2026-03-14T15:09:26+00:00",
            &parse(r#"{"kind": "policy_grant_applied", "domain": "a.example.com"}"#).unwrap(),
        );
        paths.append_policy_audit(
            "x",
            "2026-03-14T15:10:00+00:00",
            &parse(r#"{"kind": "policy_grant_removed", "ts": "IGNORED"}"#).unwrap(),
        );

        let text = fs::read_to_string(paths.policy_audit_file("x")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with(r#"{"ts": "2026-03-14T15:09:26+00:00", "#));
        // A caller's own `ts` does not get a second slot.
        assert_eq!(lines[1].matches("\"ts\"").count(), 1);

        assert_eq!(
            paths.policy_audit_file("x").parent(),
            paths.grants_dir("x").parent()
        );
    }

    #[test]
    fn an_unwritable_audit_trail_is_swallowed() {
        // `except OSError: pass` — never fail a grant promotion over
        // the audit write.
        let dir = TestDir::new("grants-audit-fail");
        let paths = Paths::under(dir.path());
        // A regular file where the per-cage data dir has to be.
        fs::create_dir_all(paths.data_root()).unwrap();
        fs::write(paths.cage_data_dir("x"), "not a directory").unwrap();
        paths.append_policy_audit(
            "x",
            "2026-03-14T15:09:26+00:00",
            &parse(r#"{"kind": "k"}"#).unwrap(),
        );
    }
}
