//! The stored `cage.yaml`, and the deployment directory around it.
//!
//! `state.py`'s first half. Every function here is a method on
//! [`Paths`] with the same name as the Python free function it ports,
//! so `state.load_raw_config(name)` reads as
//! `paths.load_raw_config(name)`.
//!
//! # Two readers, not one
//!
//! `cage.yaml` is read two different ways and the difference is not
//! cosmetic:
//!
//! * [`Paths::load_raw_config`] returns the YAML document *unchanged*.
//!   Key order survives, unknown keys survive, and nothing is filled in
//!   from a default. This is what `save_proxy_config`,
//!   `save_placeholders_env` and `cage edit` use, because they have to
//!   write the document back out without rewriting the operator's file.
//! * [`Paths::load_deployment_config`] runs the full parser and returns
//!   a [`Config`], with defaults applied and the host probed for
//!   `isolation` and `dns_servers`.
//!
//! Both of them run `validate_agents_raw` — the removed-key check that
//! refuses `domains.auto`, a top-level `watcher:` and the pre-flat
//! `agents.*.agent` nesting. `load_raw_config` can opt out of it, and
//! exactly one caller does: `cage update -c` reads the *previous* file
//! only to carry generated placeholders forward, and must not be
//! stopped by settings it is about to discard.

use std::fs;
use std::path::Path;

use agentcage_core::config::{
    Config, HostProbe, fill_raw_placeholders, placeholder_for, validate_agents_document,
};
use agentcage_core::yaml::{self, Value};

use crate::atomic::atomic_write_text;
use crate::error::{Result, StateError};
use crate::paths::Paths;

/// Whether [`Paths::load_raw_config`] enforces the agent schema.
///
/// `load_raw_config(name, *, check_agent_schema: bool = True)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentSchema {
    /// The default: refuse a document carrying removed agent keys.
    Check,
    /// Read it anyway.
    ///
    /// Only for the `cage update -c` path, which reads the previous
    /// `cage.yaml` solely to retain generated secret placeholders. Its
    /// old operational settings are never applied or migrated, so
    /// refusing to *read* them would block a replacement that fixes
    /// them.
    Skip,
}

impl Paths {
    /// `state.deployment_exists` — is there a stored `cage.yaml`?
    ///
    /// The directory alone does not count: `cage destroy` can leave an
    /// empty one behind, and `creds/` outlives a config when
    /// `--keep-secrets` was passed.
    #[must_use]
    pub fn deployment_exists(&self, name: &str) -> bool {
        self.stored_config_path(name).is_file()
    }

    /// `state.list_deployments` — every cage with a stored config.
    ///
    /// Sorted, and empty rather than an error when the deployments
    /// directory does not exist at all — a fresh install has no cages,
    /// which is not a failure.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if the directory exists but cannot be read.
    pub fn list_deployments(&self) -> Result<Vec<String>> {
        let dir = self.deployments_dir();
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| StateError::io(&dir, "read directory", e))? {
            let entry = entry.map_err(|e| StateError::io(&dir, "read directory", e))?;
            if !entry.path().is_dir() || !entry.path().join("cage.yaml").is_file() {
                continue;
            }
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    /// `state.load_raw_config` — the stored YAML, unchanged.
    ///
    /// `yaml.safe_load(f) or {}`: an empty file yields an empty
    /// mapping rather than a null document.
    ///
    /// # Errors
    ///
    /// [`StateError::Missing`] with the Python's own wording when
    /// there is no stored config, [`StateError::Yaml`] on a malformed
    /// file, [`StateError::Config`] when the agent schema check bites.
    pub fn load_raw_config(&self, name: &str, schema: AgentSchema) -> Result<Value> {
        let path = self.stored_config_path(name);
        if !path.is_file() {
            return Err(StateError::missing(
                format!("No stored config for cage '{name}'"),
                &path,
            ));
        }
        let text = read_to_string(&path)?;
        let raw = yaml::load(&text).map_err(|source| StateError::Yaml {
            path: path.clone(),
            source,
        })?;
        // `yaml.safe_load(f) or {}` — a falsy document becomes `{}`.
        let raw = if yaml::python_bool(&raw) {
            raw
        } else {
            Value::Mapping(yaml::Mapping::new())
        };
        if schema == AgentSchema::Check {
            validate_agents_document(&raw)?;
        }
        Ok(raw)
    }

    /// `state.load_deployment_config` — the stored config, parsed.
    ///
    /// # Errors
    ///
    /// [`StateError::Missing`] — note the wording differs from
    /// [`Paths::load_raw_config`]'s by one word, "deployment" rather
    /// than "cage", because the two Python functions were written at
    /// different times and both messages are user-visible.
    /// [`StateError::Config`] for anything the parser rejects.
    pub fn load_deployment_config(&self, name: &str, host: &dyn HostProbe) -> Result<Config> {
        let path = self.stored_config_path(name);
        if !path.is_file() {
            return Err(StateError::missing(
                format!("No stored config for deployment '{name}'"),
                &path,
            ));
        }
        let text = read_to_string(&path)?;
        Ok(agentcage_core::config::load(
            &path.to_string_lossy(),
            &text,
            host,
        )?)
    }

    /// `state.save_deployment` — copy an operator's file into the
    /// state directory as `cage.yaml`.
    ///
    /// The source is validated before the copy, not after: a config
    /// with a removed agent key must not land in the state directory
    /// at all, because every later command reads it from there.
    ///
    /// One divergence from `shutil.copy2`: the file's mode is carried
    /// over but its mtime is not. Nothing reads the mtime — `cage
    /// update` compares a content fingerprint — and preserving it
    /// would need a crate for `utimensat`.
    ///
    /// # Errors
    ///
    /// [`StateError::Yaml`] / [`StateError::Config`] if the source is
    /// not a storable config, [`StateError::Io`] on the copy.
    pub fn save_deployment(&self, name: &str, config_path: &Path) -> Result<()> {
        let text = read_to_string(config_path)?;
        let raw = yaml::load(&text).map_err(|source| StateError::Yaml {
            path: config_path.to_path_buf(),
            source,
        })?;
        validate_agents_document(&raw)?;

        let dir = self.deployment_dir(name);
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create directory", e))?;
        let dest = self.stored_config_path(name);
        fs::copy(config_path, &dest).map_err(|e| StateError::io(&dest, "copy config into", e))?;
        Ok(())
    }

    /// `state.save_raw_config` — write a raw document back, atomically.
    ///
    /// `yaml.safe_dump(raw, default_flow_style=False, sort_keys=False)`
    /// — block style, and **insertion order preserved**, because
    /// `cage edit` shows the result to the operator and re-sorting
    /// their file would be a gratuitous diff.
    ///
    /// Atomic because the grants reconcile and a concurrent `cage
    /// update` read this file while it is being written; a truncated
    /// prefix would raise a YAML error and abort the reconcile. See
    /// [`crate::atomic`].
    ///
    /// # Errors
    ///
    /// [`StateError::Config`] if the document fails the agent schema
    /// check, [`StateError::Yaml`] if it cannot be emitted safely for
    /// PyYAML to read back, and whatever [`atomic_write_text`] returns.
    pub fn save_raw_config(&self, name: &str, raw: &Value) -> Result<()> {
        validate_agents_document(raw)?;
        let path = self.stored_config_path(name);
        let text = yaml::dump(raw).map_err(|source| StateError::Yaml {
            path: path.clone(),
            source,
        })?;
        atomic_write_text(&path, &text)
    }

    /// `state.remove_deployment` — delete the state directory.
    ///
    /// A missing directory is success, as `if d.is_dir()` makes it.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if the tree exists and cannot be removed.
    pub fn remove_deployment(&self, name: &str) -> Result<()> {
        let dir = self.deployment_dir(name);
        if !dir.is_dir() {
            return Ok(());
        }
        fs::remove_dir_all(&dir).map_err(|e| StateError::io(&dir, "remove directory", e))
    }

    /// `state.fill_placeholders` — mint a token for every injection
    /// rule that omits one, and rewrite `cage.yaml` if any were.
    ///
    /// Returns whether the stored config was rewritten; a caller that
    /// gets `true` must reload its [`Config`] so downstream rendering
    /// sees the filled values.
    ///
    /// `previous` is the prior document on a `cage update -c` /
    /// `cage edit`, so an already-persisted token is carried over
    /// rather than regenerated — a fresh token would desynchronize
    /// every process still holding the old one in its environment.
    ///
    /// Note what a rewrite costs: it goes through the YAML emitter and
    /// **drops comments**. That is why it only happens when a rule
    /// actually omits a placeholder.
    ///
    /// `mint` supplies the entropy; [`mint_placeholder`] is the real
    /// one. It is a parameter for the same reason
    /// `fill_raw_placeholders` takes one — so a test can pin it.
    ///
    /// # Errors
    ///
    /// As [`Paths::load_raw_config`] and [`Paths::save_raw_config`].
    pub fn fill_placeholders(
        &self,
        name: &str,
        previous: Option<&Value>,
        mint: &mut dyn FnMut(&str) -> String,
    ) -> Result<bool> {
        let mut raw = self.load_raw_config(name, AgentSchema::Check)?;
        if !fill_raw_placeholders(&mut raw, previous, mint) {
            return Ok(false);
        }
        self.save_raw_config(name, &raw)?;
        Ok(true)
    }
}

/// `config.generate_placeholder(env)` with real entropy.
///
/// `secrets.token_hex(16)` — 16 bytes from the OS pool, hex-encoded.
/// The bytes come from `/dev/urandom`, which is what `os.urandom`
/// reads on every platform agentcage runs on, and reading it with
/// `std::fs` keeps the crate free of a randomness dependency for its
/// one use.
///
/// # Panics
///
/// If `/dev/urandom` cannot be read. Minting a *predictable*
/// placeholder would be worse than failing: the token's entropy is
/// what stops an outbound document that happens to contain the literal
/// string from having a real credential substituted into it.
#[must_use]
pub fn mint_placeholder(env: &str) -> String {
    use std::fmt::Write as _;
    use std::io::Read as _;

    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .expect("read 16 bytes from /dev/urandom");
    let mut token = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    placeholder_for(env, &token)
}

/// `open(p).read()`, with the path in the error.
pub(crate) fn read_to_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| StateError::io(path, "read", e))
}

#[cfg(test)]
mod tests {
    use super::{AgentSchema, mint_placeholder};
    use crate::error::StateError;
    use crate::paths::Paths;
    use crate::testdir::TestDir;
    use agentcage_core::yaml::Value;
    use std::fs;

    fn sandbox() -> (TestDir, Paths) {
        let dir = TestDir::new("deployment");
        let paths = Paths::under(dir.path());
        (dir, paths)
    }

    fn write_cage(paths: &Paths, name: &str, text: &str) {
        let path = paths.stored_config_path(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn a_missing_config_says_cage_here_and_deployment_there() {
        let (_dir, paths) = sandbox();
        let raw = paths
            .load_raw_config("nope", AgentSchema::Check)
            .unwrap_err();
        assert_eq!(raw.to_string(), "No stored config for cage 'nope'");

        let host = agentcage_core::config::FixedHost::linux(&["1.1.1.1"]);
        let parsed = paths.load_deployment_config("nope", &host).unwrap_err();
        assert_eq!(parsed.to_string(), "No stored config for deployment 'nope'");
    }

    #[test]
    fn an_empty_cage_yaml_reads_as_an_empty_mapping() {
        let (_dir, paths) = sandbox();
        write_cage(&paths, "blank", "");
        let raw = paths.load_raw_config("blank", AgentSchema::Check).unwrap();
        assert_eq!(raw, Value::Mapping(agentcage_core::yaml::Mapping::new()));
    }

    #[test]
    fn the_agent_schema_check_can_be_skipped_but_is_on_by_default() {
        let (_dir, paths) = sandbox();
        write_cage(&paths, "old", "name: old\nwatcher:\n  enable: true\n");

        let refused = paths
            .load_raw_config("old", AgentSchema::Check)
            .unwrap_err();
        assert!(matches!(refused, StateError::Config(_)), "{refused:?}");
        assert_eq!(
            refused.to_string(),
            "top-level watcher is no longer supported; \
             use agents.watcher with flat LLM fields"
        );

        // `cage update -c` reads it anyway, to carry placeholders over.
        paths.load_raw_config("old", AgentSchema::Skip).unwrap();
    }

    #[test]
    fn list_deployments_needs_a_cage_yaml_not_just_a_directory() {
        let (_dir, paths) = sandbox();
        assert_eq!(paths.list_deployments().unwrap(), Vec::<String>::new());

        write_cage(&paths, "beta", "name: beta\n");
        write_cage(&paths, "alpha", "name: alpha\n");
        // A directory left behind by `cage destroy --keep-secrets`.
        fs::create_dir_all(paths.creds_dir("ghost")).unwrap();

        assert_eq!(paths.list_deployments().unwrap(), ["alpha", "beta"]);
        assert!(paths.deployment_exists("alpha"));
        assert!(!paths.deployment_exists("ghost"));
    }

    #[test]
    fn save_deployment_refuses_a_removed_agent_key_before_copying() {
        let (dir, paths) = sandbox();
        let source = dir.join("cage.yaml");
        fs::write(&source, "name: x\ndomains:\n  auto:\n    enable: true\n").unwrap();

        let error = paths.save_deployment("x", &source).unwrap_err();
        assert!(error.to_string().starts_with("domains.auto is no longer"));
        assert!(
            !paths.stored_config_path("x").exists(),
            "a refused config must not reach the state dir"
        );
    }

    #[test]
    fn save_and_remove_round_trip() {
        let (dir, paths) = sandbox();
        let source = dir.join("cage.yaml");
        fs::write(&source, "name: x\ncontainer:\n  image: localhost/x\n").unwrap();

        paths.save_deployment("x", &source).unwrap();
        assert!(paths.deployment_exists("x"));

        paths.remove_deployment("x").unwrap();
        assert!(!paths.deployment_exists("x"));
        // A second removal is not an error.
        paths.remove_deployment("x").unwrap();
    }

    #[test]
    fn save_raw_config_keeps_key_order() {
        let (_dir, paths) = sandbox();
        write_cage(
            &paths,
            "x",
            "name: x\nisolation: container\nlifecycle: service\n",
        );
        let raw = paths.load_raw_config("x", AgentSchema::Check).unwrap();
        paths.save_raw_config("x", &raw).unwrap();

        let text = fs::read_to_string(paths.stored_config_path("x")).unwrap();
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|line| line.split(':').next())
            .collect();
        assert_eq!(keys, ["name", "isolation", "lifecycle"]);
    }

    #[test]
    fn fill_placeholders_mints_only_for_rules_that_omit_one() {
        let (_dir, paths) = sandbox();
        write_cage(
            &paths,
            "x",
            "name: x\nsecret_injection:\n\
             - env: KEPT\n  placeholder: agentcage:secret:KEPT:0000\n\
             - env: MINTED\n",
        );
        let mut mint = |env: &str| format!("agentcage:secret:{env}:deadbeef");
        assert!(paths.fill_placeholders("x", None, &mut mint).unwrap());

        let text = fs::read_to_string(paths.stored_config_path("x")).unwrap();
        assert!(text.contains("agentcage:secret:KEPT:0000"));
        assert!(text.contains("agentcage:secret:MINTED:deadbeef"));

        // Idempotent: nothing left to fill, so no rewrite.
        assert!(!paths.fill_placeholders("x", None, &mut mint).unwrap());
    }

    #[test]
    fn a_minted_placeholder_carries_32_hex_characters() {
        let token = mint_placeholder("ANTHROPIC_API_KEY");
        let suffix = token.rsplit(':').next().unwrap();
        assert!(token.starts_with("agentcage:secret:ANTHROPIC_API_KEY:"));
        assert_eq!(suffix.len(), 32);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(token, mint_placeholder("ANTHROPIC_API_KEY"));
    }
}
