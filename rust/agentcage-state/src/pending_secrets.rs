//! `pending_secrets.json` and `secret_keys.json` — the file layer only.
//!
//! The stores that own these files are D3's (`secret_store.py`'s
//! `ApplePlaintextStore` and `KeychainStore`). What is here is the
//! *format*, because both files live in the deployment directory this
//! crate defines and because one of them is a documented trap:
//!
//! > **`pending_secrets.json` is a JSON array of `[key, value]` pairs,
//! > not an object.** Both writers agree on this — `ApplePlaintextStore._save`
//! > and the VM hand-off at `cli.py:1008`. A Rust reader assuming a map
//! > fails on every cage that used either path.
//!
//! — RUST-PORT-PLAN.md §2.7, and the state fixture carries
//! `[["GITHUB_TOKEN", "TEST-NOT-A-REAL-SECRET-0003"]]` to prove it.
//!
//! Pairs rather than an object is not an accident worth normalising
//! away: the file is written by `os.write(fd, json.dumps(pairs))` onto
//! a descriptor opened `O_CREAT|O_EXCL|O_WRONLY, 0o600`, and the
//! ordering it preserves is the order the operator passed `--secret`
//! on the command line.
//!
//! `secret_keys.json` is the other shape: a sorted JSON array of
//! *strings*. It is a non-secret name index — which keys a cage has,
//! not what they are — so that `secret list` can work without
//! unlocking a Keychain.
//!
//! Neither reader here decrypts or authenticates anything. `creds/` is
//! handled the same way: the blobs are host-bound `systemd-creds`
//! output, opaque everywhere except the machine that made them, so the
//! only correct operation on one is to hand it to `systemd-creds
//! decrypt` — never to parse it.

use std::fs;

use agentcage_core::har::json::{Json, parse};

use crate::error::{Result, StateError};
use crate::paths::Paths;

impl Paths {
    /// `pending_secrets.json`, as the `[key, value]` pairs it is.
    ///
    /// An absent file is an empty list. Entries that are not
    /// two-element string arrays are dropped rather than failing the
    /// read, which is what `ApplePlaintextStore._load`'s
    /// `except Exception: return []` amounts to for a partially
    /// corrupt file.
    ///
    /// # Errors
    ///
    /// [`StateError::Json`] when the document as a whole does not
    /// parse or is not an array.
    pub fn load_pending_secrets(&self, name: &str) -> Result<Vec<(String, String)>> {
        let path = self.pending_secrets_path(name);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = crate::deployment::read_to_string(&path)?;
        let document = parse(&text).map_err(|error| {
            StateError::value(format!("{} is not valid JSON: {error}", path.display()))
        })?;
        let Json::Array(pairs) = &document else {
            return Err(StateError::value(format!(
                "{} is a JSON {}, not an array of [key, value] pairs",
                path.display(),
                json_type(&document)
            )));
        };
        Ok(pairs
            .iter()
            .filter_map(|pair| {
                let Json::Array(pair) = pair else { return None };
                let [key, value] = pair.as_slice() else {
                    return None;
                };
                Some((key.as_str()?.to_owned(), value.as_str()?.to_owned()))
            })
            .collect())
    }

    /// `secret_keys.json` — a sorted array of key names, or empty.
    ///
    /// # Errors
    ///
    /// [`StateError::Json`] on a malformed file.
    pub fn load_secret_key_index(&self, name: &str) -> Result<Vec<String>> {
        let path = self.secret_keys_path(name);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = crate::deployment::read_to_string(&path)?;
        let document = parse(&text).map_err(|error| {
            StateError::value(format!("{} is not valid JSON: {error}", path.display()))
        })?;
        let Json::Array(keys) = &document else {
            return Err(StateError::value(format!(
                "{} is a JSON {}, not an array of key names",
                path.display(),
                json_type(&document)
            )));
        };
        Ok(keys
            .iter()
            .filter_map(|key| key.as_str().map(str::to_owned))
            .collect())
    }

    /// The `creds/<key>.cred` blobs a cage has, sorted by key name.
    ///
    /// Filenames only. The contents are host-bound ciphertext.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if `creds/` exists but cannot be listed.
    pub fn list_cred_keys(&self, name: &str) -> Result<Vec<String>> {
        let dir = self.creds_dir(name);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut keys = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| StateError::io(&dir, "read directory", e))? {
            let entry = entry.map_err(|e| StateError::io(&dir, "read directory", e))?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if let Some(key) = file_name.strip_suffix(".cred") {
                keys.push(key.to_owned());
            }
        }
        keys.sort();
        Ok(keys)
    }
}

fn json_type(value: &Json) -> &'static str {
    match value {
        Json::Null => "null",
        Json::Bool(_) => "bool",
        Json::Int(_) | Json::BigInt(_) | Json::Float(_) => "number",
        Json::Str(_) => "string",
        Json::Array(_) => "array",
        Json::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use crate::paths::Paths;
    use crate::testdir::TestDir;
    use std::fs;

    fn sandbox(name: &str) -> (TestDir, Paths) {
        let dir = TestDir::new(name);
        let paths = Paths::under(dir.path());
        fs::create_dir_all(paths.deployment_dir("x")).unwrap();
        (dir, paths)
    }

    #[test]
    fn pending_secrets_are_pairs_and_an_object_is_refused() {
        let (_dir, paths) = sandbox("pending");
        assert!(paths.load_pending_secrets("x").unwrap().is_empty());

        fs::write(
            paths.pending_secrets_path("x"),
            r#"[["A", "one"], ["B", "two"]]"#,
        )
        .unwrap();
        assert_eq!(
            paths.load_pending_secrets("x").unwrap(),
            [
                ("A".to_owned(), "one".to_owned()),
                ("B".to_owned(), "two".to_owned())
            ]
        );

        // The trap the plan calls out: a map is not this format.
        fs::write(paths.pending_secrets_path("x"), r#"{"A": "one"}"#).unwrap();
        let error = paths.load_pending_secrets("x").unwrap_err();
        assert!(
            error.to_string().contains("not an array of [key, value]"),
            "{error}"
        );
    }

    #[test]
    fn the_key_index_is_a_sorted_array_of_strings() {
        let (_dir, paths) = sandbox("keyindex");
        assert!(paths.load_secret_key_index("x").unwrap().is_empty());
        fs::write(
            paths.secret_keys_path("x"),
            r#"["ANTHROPIC_API_KEY", "GITHUB_TOKEN"]"#,
        )
        .unwrap();
        assert_eq!(
            paths.load_secret_key_index("x").unwrap(),
            ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"]
        );
    }

    #[test]
    fn cred_blobs_are_listed_by_key_never_parsed() {
        let (_dir, paths) = sandbox("creds");
        assert!(paths.list_cred_keys("x").unwrap().is_empty());
        fs::create_dir_all(paths.creds_dir("x")).unwrap();
        fs::write(paths.cred_path("x", "B_KEY"), "opaque").unwrap();
        fs::write(paths.cred_path("x", "A_KEY"), "opaque").unwrap();
        fs::write(paths.creds_dir("x").join("README"), "not a blob").unwrap();
        assert_eq!(paths.list_cred_keys("x").unwrap(), ["A_KEY", "B_KEY"]);
    }
}
