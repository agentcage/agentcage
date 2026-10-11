//! `validate_config`'s inspector-chain warnings.
//!
//! PR C3 of docs/history/rust-port-plan.md's Track C, and the last of the four
//! areas it owns. Small, but it is a cross-language contract — PR A6's
//! audit of the trust boundary found it, and §2.2's original list of
//! four did not have it.
//!
//! # The handshake
//!
//! `config.inspectors` is kept as **raw mappings**, not a typed struct:
//! the proxy addon's dispatch is the single source of truth for which
//! keys an inspector entry may carry, so the host copies the operator's
//! mapping through `proxy-config.yaml` untouched rather than modelling
//! it twice. What the host *does* know is the set of names the addon
//! can dispatch, and that set is duplicated —
//! [`BUILTIN_INSPECTOR_NAMES`] here mirrors `addon._BUILTIN_INSPECTORS`
//! there, because the addon cannot import `agentcage`.
//!
//! A name present on one side and not the other is the quiet failure
//! this warning exists to make loud: a config that validates and then
//! does nothing. `shared_constants.json` pins the set, and
//! `scaffold_inspectors.json` pins the other end of the same
//! handshake — `init.render_config` must emit a config the addon can
//! load, for all nine scaffolds.
//!
//! # Why these are warnings and not errors
//!
//! They fire only on the apple-container backend, where the in-cage
//! addon dispatches built-ins through the same
//! `data/proxy/inspectors` registry the container backend uses.
//! Built-in names run end to end; an unknown name is a typo that will
//! silently no-op. That does not block the deploy — several stock
//! scaffolds set fields unconditionally for the container backend — so
//! the operator is told which of their entries are decorative on this
//! backend and the cage still starts. See issue #120.
//!
//! # Custom inspectors (`path:`)
//!
//! An entry with a `path:` is a custom inspector: a WebAssembly
//! component (`EGRESS-PORT-PLAN.md` D2). `cage create` / `cage update`
//! copy each referenced file into the cage's `inspectors/` data
//! directory by its file name, the egress mounts that directory at
//! `/etc/agentcage/inspectors`, and `proxy-config.yaml` names each
//! plugin by that file name. [`validate_plugins`] refuses, on every
//! backend, what could not work: a non-`.wasm` path (a `.py` one gets
//! the migration pointer), a missing or built-in name, and two entries
//! sharing a name or a file name.

use crate::python::repr_str;
use crate::yaml::{Value, python_bool};

use super::ConfigError;
use super::types::{BUILTIN_INSPECTOR_NAMES, Config};

/// The page a refused Python inspector is pointed at.
pub const CUSTOM_INSPECTORS_GUIDE: &str = "docs/how-to/custom-inspectors.md";

/// One `inspectors:` entry that names a plugin file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginRef {
    /// The entry's position in `inspectors:`.
    pub index: usize,
    /// The entry's `name`.
    pub name: String,
    /// The entry's `path`, as written: relative to the directory of the
    /// `cage.yaml` it came from, or absolute.
    pub path: String,
}

impl PluginRef {
    /// The file name the plugin is staged and loaded under.
    #[must_use]
    pub fn file_name(&self) -> &str {
        plugin_file_name(&self.path)
    }
}

/// The last `/`-separated component of a plugin `path`.
#[must_use]
pub fn plugin_file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Every entry with a (truthy, string) `path`, in order.
///
/// Entries [`validate_plugins`] would refuse for a non-string path are
/// skipped; a validated config has none.
#[must_use]
pub fn plugin_refs(config: &Config) -> Vec<PluginRef> {
    config
        .inspectors
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let path = entry.get("path").filter(|p| python_bool(p))?.as_str()?;
            Some(PluginRef {
                index,
                name: entry
                    .get("name")
                    .map(crate::python::str_of)
                    .unwrap_or_default(),
                path: path.to_owned(),
            })
        })
        .collect()
}

/// Refuse custom-inspector entries that cannot be staged or loaded.
///
/// # Errors
///
/// [`ConfigError::Value`] naming the first offending entry.
pub fn validate_plugins(config: &Config) -> Result<(), ConfigError> {
    let mut seen: Vec<(usize, String, String)> = Vec::new();
    for (index, entry) in config.inspectors.iter().enumerate() {
        let Some(path) = entry.get("path").filter(|p| python_bool(p)) else {
            continue;
        };
        let name = entry
            .get("name")
            .map(crate::python::str_of)
            .unwrap_or_default();
        let label = format!("inspectors[{index}] {}", repr_str(&name));
        let Value::String(path) = path else {
            return Err(ConfigError::value(format!(
                "{label}: path must be a string"
            )));
        };
        if path.to_ascii_lowercase().ends_with(".py") {
            return Err(ConfigError::value(format!(
                "{label}: custom Python inspectors (path: {}) are no longer supported. \
                 Build the inspector as a WebAssembly component (.wasm) with the \
                 agentcage-inspector-sdk crate; see {CUSTOM_INSPECTORS_GUIDE}.",
                repr_str(path)
            )));
        }
        let file = plugin_file_name(path);
        // Exactly `.wasm`, as the egress loader requires; `.wasm` alone is a
        // hidden file with no extension.
        if std::path::Path::new(file)
            .extension()
            .is_none_or(|e| e != "wasm")
        {
            return Err(ConfigError::value(format!(
                "{label}: path must name a WebAssembly component file ending in .wasm \
                 (got: {})",
                repr_str(path)
            )));
        }
        if name.is_empty() {
            return Err(ConfigError::value(format!(
                "inspectors[{index}]: a custom inspector (path: {}) needs a name",
                repr_str(path)
            )));
        }
        if BUILTIN_INSPECTOR_NAMES.contains(&name.as_str()) {
            return Err(ConfigError::value(format!(
                "{label}: a custom inspector cannot take the name of a built-in \
                 inspector; choose another name"
            )));
        }
        for (other, other_name, other_file) in &seen {
            if *other_name == name {
                return Err(ConfigError::value(format!(
                    "{label}: the name is already used by inspectors[{other}]"
                )));
            }
            if other_file == file {
                return Err(ConfigError::value(format!(
                    "{label}: the file name {} is already used by inspectors[{other}] \
                     (plugins are staged into the egress by file name)",
                    repr_str(file)
                )));
            }
        }
        seen.push((index, name, file.to_owned()));
    }
    Ok(())
}

/// The apple-container inspector warnings, in `config.py`'s order.
///
/// Empty on every other backend: the container and vm backends stage
/// custom inspectors and dispatch built-ins alike, so there is nothing
/// to warn about.
#[must_use]
pub fn inspector_warnings(config: &Config) -> Vec<String> {
    if config.isolation != "apple-container" {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    // `enumerate(config.inspectors or [])` — the index is the
    // operator's line number in all but name, so it leads the message.
    // `config.py` skips an entry that is not a mapping; `load_config`
    // already dropped those, so the guard is structural here.
    for (index, entry) in config.inspectors.iter().enumerate() {
        // `entry.get("name", "")` and `entry.get("path")`, with
        // Python's truthiness on the second: a `path: ""` or
        // `path: null` is not a custom inspector.
        let name = entry
            .get("name")
            .map(crate::python::str_of)
            .unwrap_or_default();
        // A `path:` entry is a custom inspector: staged and mounted on
        // this backend like on the others, and refused by
        // `validate_plugins` if it cannot be.
        let has_path = entry.get("path").is_some_and(python_bool);

        if !has_path && !name.is_empty() && !BUILTIN_INSPECTOR_NAMES.contains(&name.as_str()) {
            let mut valid: Vec<&str> = BUILTIN_INSPECTOR_NAMES.to_vec();
            valid.sort_unstable();
            warnings.push(format!(
                "inspectors[{index}] {}: not a known built-in inspector — the in-cage \
                 addon will skip this entry. Valid names: {}.",
                repr_str(&name),
                valid.join(", ")
            ));
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::inspector_warnings;
    use crate::config::{FixedHost, load};

    fn warnings(document: &str) -> Vec<String> {
        let host = FixedHost::linux(&["192.0.2.53"]);
        let config = load("<test>", document, &host).expect("parse");
        inspector_warnings(&config)
    }

    #[test]
    fn the_container_backend_is_silent() {
        assert!(
            warnings(
                "name: c\nisolation: container\ninspectors:\n- name: nope\n- name: c\n  \
                 path: /x.py\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn apple_container_names_the_index_and_the_valid_set() {
        let produced = warnings(
            "name: c\nisolation: apple-container\ninspectors:\n- name: domain\n\
             - name: not-a-real-inspector\n- name: custom\n  path: plugins/x.wasm\n",
        );
        assert_eq!(
            produced,
            [
                "inspectors[1] 'not-a-real-inspector': not a known built-in inspector — \
              the in-cage addon will skip this entry. Valid names: body-size, \
              content-type, domain, entropy, secrets."
            ]
        );
    }

    fn plugin_error(entries: &str) -> String {
        let host = FixedHost::linux(&["192.0.2.53"]);
        let config =
            load("<test>", &format!("name: c\ninspectors:\n{entries}"), &host).expect("parse");
        super::validate_plugins(&config).unwrap_err().to_string()
    }

    #[test]
    fn plugins_must_be_named_wasm_components() {
        let ok = load(
            "<test>",
            "name: c\ninspectors:\n- name: a\n  path: plugins/a.wasm\n\
             - name: b\n  path: /abs/b.wasm\n- name: entropy\n",
            &FixedHost::linux(&["192.0.2.53"]),
        )
        .unwrap();
        super::validate_plugins(&ok).unwrap();
        let refs = super::plugin_refs(&ok);
        assert_eq!(refs.len(), 2);
        assert_eq!((refs[1].index, refs[1].file_name()), (1, "b.wasm"));

        let py = plugin_error("- name: house\n  path: rules.py\n");
        assert!(
            py.contains("custom Python inspectors (path: 'rules.py') are no longer supported"),
            "{py}"
        );
        assert!(py.contains(super::CUSTOM_INSPECTORS_GUIDE), "{py}");
        assert!(
            plugin_error("- name: x\n  path: x.so\n").contains("ending in .wasm (got: 'x.so')")
        );
        assert!(plugin_error("- name: x\n  path: 3\n").contains("path must be a string"));
        assert_eq!(
            plugin_error("- path: x.wasm\n"),
            "inspectors[0]: a custom inspector (path: 'x.wasm') needs a name"
        );
        assert!(plugin_error("- name: domain\n  path: d.wasm\n").contains("name of a built-in"));
        assert_eq!(
            plugin_error("- name: x\n  path: a/x.wasm\n- name: x\n  path: y.wasm\n"),
            "inspectors[1] 'x': the name is already used by inspectors[0]"
        );
        assert!(
            plugin_error("- name: x\n  path: a/p.wasm\n- name: y\n  path: b/p.wasm\n")
                .contains("the file name 'p.wasm' is already used by inspectors[0]")
        );
    }

    /// `path:` wins over the name check, and an empty path does not
    /// count as one.
    #[test]
    fn a_falsy_path_is_not_a_custom_inspector() {
        assert!(
            warnings(
                "name: c\nisolation: apple-container\ninspectors:\n- name: domain\n  path: ''\n"
            )
            .is_empty()
        );
    }
}
