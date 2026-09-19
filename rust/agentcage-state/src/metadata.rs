//! `metadata.json` and `fingerprint.json` — the two JSON files in a
//! deployment directory, written by two functions that do *not* agree
//! with each other.
//!
//! | | `metadata.json` | `fingerprint.json` |
//! | :-- | :-- | :-- |
//! | writer | `json.dumps(metadata)` | `json.dumps(fp, indent=2, sort_keys=True) + "\n"` |
//! | key order | insertion | sorted |
//! | layout | one line, no trailing newline | two-space indent, trailing newline |
//! | atomicity | [`crate::atomic`] | its own `.tmp` + rename, **no `O_EXCL`** |
//! | missing file | `{}` | `None` |
//! | unreadable | raises | `None` |
//!
//! Those differences are not style. The state-compat fixture asserts
//! both shapes on disk, and the fingerprint's sorted-and-indented form
//! is what `cage update` compares against to decide whether a cage
//! needs redeploying.
//!
//! # Why `agentcage_core::har::json::Json` and not `serde_json`
//!
//! Because `metadata.json`'s key order is *insertion* order and
//! `serde_json::Value`'s object is a `BTreeMap`, which sorts. A round
//! trip through it would quietly re-order the file — and `cli.py` does
//! exactly that round trip (`meta = load_metadata(name); meta[k] = v;
//! save_metadata(name, meta)`) in five places.
//!
//! The obvious fix, `serde_json`'s `preserve_order` feature, is a trap:
//! Cargo unifies features across the workspace, so it would also
//! re-order `agentcage-core`'s `stable_json`, and every `cage update`
//! no-op check depends on *that* being sorted. Core already solved
//! this for `har.py` with its own Python-shaped JSON value — insertion
//! ordered, with `json.dumps`'s separators, `ensure_ascii` and
//! `sort_keys` as options — and it is the right type here for exactly
//! the same reason.
//!
//! # `save_fingerprint` really does skip the atomic writer
//!
//! `state.py:375` writes `fingerprint.json.tmp` with a plain
//! `write_text` and then `replace`s it. No PID suffix, no `O_EXCL`, no
//! retry. That is a deliberate asymmetry with the three files that use
//! [`crate::atomic::atomic_write_text`] and it is preserved here rather
//! than "improved", because the fingerprint has no concurrent reader a
//! torn read would break: it is written at the end of a deploy and
//! read at the start of the next one, both under the same
//! single-threaded CLI invocation. The cross-PID-namespace collision
//! the atomic writer exists for cannot reach it — the in-container
//! addon does not write fingerprints.
//!
//! Porting the weaker writer is the right call anyway: strengthening
//! it would change the temp filename, and a half-upgraded machine with
//! a Python and a Rust agentcage would then leave two different stray
//! temp files instead of one predictable one.

use std::fs;

use agentcage_core::har::json::{DumpOptions, Json, dumps, parse};

use crate::atomic::atomic_write_text;
use crate::error::{Result, StateError};
use crate::paths::Paths;

/// `json.dumps(metadata)` — one line, `", "` / `": "`, insertion order.
#[must_use]
pub fn dumps_metadata(value: &Json) -> String {
    dumps(value, DumpOptions::default())
}

/// `json.dumps(fp, indent=2, sort_keys=True) + "\n"`.
#[must_use]
pub fn dumps_fingerprint(value: &Json) -> String {
    format!(
        "{}\n",
        dumps(
            value,
            DumpOptions {
                indent: Some(2),
                sort_keys: true,
                ..DumpOptions::default()
            },
        )
    )
}

impl Paths {
    /// `state.load_metadata` — an empty object when the file is absent.
    ///
    /// # Errors
    ///
    /// [`StateError::Value`] on a malformed file. The Python raises
    /// too: `json.load` here is not wrapped, unlike
    /// [`Paths::load_fingerprint`]'s.
    pub fn load_metadata(&self, name: &str) -> Result<Json> {
        let path = self.metadata_path(name);
        if !path.is_file() {
            return Ok(Json::Object(Vec::new()));
        }
        let text = crate::deployment::read_to_string(&path)?;
        parse(&text).map_err(|error| {
            StateError::value(format!("{} is not valid JSON: {error}", path.display()))
        })
    }

    /// `state.save_metadata` — atomically, via [`crate::atomic`].
    ///
    /// Atomic because the grants reconcile and a concurrent `cage
    /// update` read this file; a truncated prefix would be a
    /// `JSONDecodeError` that aborts the reconcile.
    ///
    /// # Errors
    ///
    /// As [`crate::atomic::atomic_write_text`].
    pub fn save_metadata(&self, name: &str, metadata: &Json) -> Result<()> {
        let dir = self.deployment_dir(name);
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create directory", e))?;
        atomic_write_text(&self.metadata_path(name), &dumps_metadata(metadata))
    }

    /// `state.load_fingerprint` — `None` for missing **or corrupt**.
    ///
    /// Infallible on purpose, and this one really is the Python:
    /// `except (OSError, json.JSONDecodeError): return None`, plus a
    /// final `isinstance(value, dict)` guard. Every way of failing to
    /// read a fingerprint means the same thing to the caller — the
    /// cage is stale and must be redeployed — and turning an
    /// unreadable file into an error would make `cage update` refuse
    /// to run rather than redeploy.
    #[must_use]
    pub fn load_fingerprint(&self, name: &str) -> Option<Json> {
        let path = self.fingerprint_path(name);
        if !path.is_file() {
            return None;
        }
        let text = fs::read_to_string(&path).ok()?;
        let value = parse(&text).ok()?;
        matches!(value, Json::Object(_)).then_some(value)
    }

    /// `state.save_fingerprint` — `indent=2, sort_keys=True`, a
    /// trailing newline, and a plain `.tmp` + rename.
    ///
    /// See the module docs for why this does not go through the atomic
    /// writer.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] on the write or the rename.
    pub fn save_fingerprint(&self, name: &str, fingerprint: &Json) -> Result<()> {
        let dir = self.deployment_dir(name);
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create directory", e))?;
        let path = self.fingerprint_path(name);
        let temporary = dir.join("fingerprint.json.tmp");
        fs::write(&temporary, dumps_fingerprint(fingerprint))
            .map_err(|e| StateError::io(&temporary, "write", e))?;
        fs::rename(&temporary, &path)
            .map_err(|e| StateError::io(&temporary, "rename into place", e))
    }
}

#[cfg(test)]
mod tests {
    use super::dumps_metadata;
    use crate::paths::Paths;
    use crate::testdir::TestDir;
    use agentcage_core::har::json::{Json, parse};
    use std::fs;

    fn object(pairs: &[(&str, Json)]) -> Json {
        Json::Object(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    #[test]
    fn metadata_is_one_line_in_insertion_order() {
        let meta = object(&[
            ("agentcage_version", Json::string("0.40.1")),
            ("scaffold", Json::string("claude-code")),
            ("network_octet", Json::Int(137)),
        ]);
        let text = dumps_metadata(&meta);
        assert_eq!(
            text,
            r#"{"agentcage_version": "0.40.1", "scaffold": "claude-code", "network_octet": 137}"#
        );
        assert!(!text.contains('\n'));
    }

    #[test]
    fn re_setting_a_key_keeps_its_slot() {
        // `Json::set` is `dict.__setitem__`: an existing key keeps the
        // position it was first inserted at.
        let mut meta = object(&[
            ("agentcage_version", Json::string("0.40.0")),
            ("scaffold", Json::string("pi")),
        ]);
        meta.set("agentcage_version", Json::string("0.40.1"));
        assert_eq!(
            dumps_metadata(&meta),
            r#"{"agentcage_version": "0.40.1", "scaffold": "pi"}"#
        );
    }

    #[test]
    fn metadata_round_trips_through_the_disk() {
        let dir = TestDir::new("metadata");
        let paths = Paths::under(dir.path());
        let meta = object(&[
            ("agentcage_version", Json::string("0.40.1")),
            ("scaffold", Json::string("claude-code")),
            ("network_octet", Json::Int(137)),
        ]);
        paths.save_metadata("x", &meta).unwrap();
        assert_eq!(paths.load_metadata("x").unwrap(), meta);
        assert_eq!(
            paths.load_metadata("no-such-cage").unwrap(),
            Json::Object(Vec::new())
        );
    }

    #[test]
    fn the_fingerprint_is_sorted_indented_and_newline_terminated() {
        let dir = TestDir::new("fingerprint");
        let paths = Paths::under(dir.path());
        let fp = parse(
            r#"{"version": 1, "fingerprint": "ff",
                "components": {"units": "aa", "cage_yaml": "bb"}}"#,
        )
        .unwrap();
        paths.save_fingerprint("x", &fp).unwrap();

        let text = fs::read_to_string(paths.fingerprint_path("x")).unwrap();
        assert!(text.ends_with("}\n"));
        assert!(text.lines().nth(1).unwrap().starts_with("  \"components\""));
        // sort_keys=True, at every level.
        assert!(text.contains("\"cage_yaml\": \"bb\",\n    \"units\": \"aa\""));

        // Reading it back gives the *file's* key order, which
        // `sort_keys=True` made sorted -- so the round trip is not an
        // equality on the value, it is idempotence on the bytes. That
        // is the property `cage update` needs: a stored fingerprint
        // rewritten unchanged must produce the same file.
        let reread = paths.load_fingerprint("x").unwrap();
        paths.save_fingerprint("x", &reread).unwrap();
        assert_eq!(
            fs::read_to_string(paths.fingerprint_path("x")).unwrap(),
            text
        );
        assert!(
            !paths
                .deployment_dir("x")
                .join("fingerprint.json.tmp")
                .exists()
        );
    }

    #[test]
    fn a_corrupt_fingerprint_is_stale_not_fatal() {
        let dir = TestDir::new("fingerprint-corrupt");
        let paths = Paths::under(dir.path());
        fs::create_dir_all(paths.deployment_dir("x")).unwrap();

        assert_eq!(paths.load_fingerprint("x"), None);
        fs::write(paths.fingerprint_path("x"), "{ truncated").unwrap();
        assert_eq!(paths.load_fingerprint("x"), None);
        // Valid JSON, wrong shape: the `isinstance(value, dict)` guard.
        fs::write(paths.fingerprint_path("x"), "[1, 2]").unwrap();
        assert_eq!(paths.load_fingerprint("x"), None);
    }
}
