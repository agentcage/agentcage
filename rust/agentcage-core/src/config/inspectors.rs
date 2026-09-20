//! `validate_config`'s inspector-chain warnings.
//!
//! PR C3 of RUST-PORT-PLAN.md's Track C, and the last of the four
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
//! Built-in names run end to end; a `path:` entry names a custom
//! Python file that is not staged into the wrapper image, and an
//! unknown name is a typo that will silently no-op. Neither blocks the
//! deploy — several stock scaffolds set fields unconditionally for the
//! container backend — so the operator is told which of their entries
//! are decorative on this backend and the cage still starts. See issue
//! #120.

use crate::python::repr_str;
use crate::yaml::python_bool;

use super::types::{BUILTIN_INSPECTOR_NAMES, Config};

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
        let has_path = entry.get("path").is_some_and(python_bool);

        if has_path {
            warnings.push(format!(
                "inspectors[{index}] {}: custom Python file inspectors (path: ...) are \
                 not yet staged into the apple-container wrapper image — the in-cage \
                 addon will skip this entry. Use a built-in inspector or stay on the \
                 container backend.",
                repr_str(&name)
            ));
        } else if !name.is_empty() && !BUILTIN_INSPECTOR_NAMES.contains(&name.as_str()) {
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
             - name: not-a-real-inspector\n- name: custom\n  path: /etc/agentcage/x.py\n",
        );
        assert_eq!(
            produced,
            [
                "inspectors[1] 'not-a-real-inspector': not a known built-in inspector — \
                 the in-cage addon will skip this entry. Valid names: body-size, \
                 content-type, domain, entropy, secrets.",
                "inspectors[2] 'custom': custom Python file inspectors (path: ...) are \
                 not yet staged into the apple-container wrapper image — the in-cage \
                 addon will skip this entry. Use a built-in inspector or stay on the \
                 container backend.",
            ]
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
