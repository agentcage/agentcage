//! Custom inspector plugins: staging them into the cage's data dir.
//!
//! A cage.yaml `inspectors:` entry with a `path:` names a WebAssembly
//! component on the host, relative to the directory the cage.yaml was
//! read from (or absolute). The egress cannot see the host's tree, so
//! `cage create` and `cage update -c` copy each referenced file into
//! `<data_root>/<name>/inspectors/` under its file name, and the
//! backends mount that directory read-only at
//! `/etc/agentcage/inspectors`. `proxy-config.yaml` then names each
//! plugin by that file name ([`crate::derived`]).
//!
//! The staged copy is the cage's from then on, the way the frozen build
//! context is: `cage update` without `-c` has no operator tree to read
//! from and redeploys what was staged, after checking that every plugin
//! the stored config names is there.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::config::{Config, PluginRef, plugin_refs};
use agentcage_core::python::repr_str;

use crate::error::{Result, StateError};
use crate::paths::Paths;

impl Paths {
    /// Copy the plugins `config` references from `source_dir` (the
    /// directory of the cage.yaml they were written against) into
    /// [`Paths::inspectors_dir`], replacing whatever was staged before.
    ///
    /// Every source is checked before anything is written, so a missing
    /// file leaves the previous staging intact. A config without plugins
    /// removes the directory.
    ///
    /// # Errors
    ///
    /// [`StateError::Value`] naming the entry whose file is missing or
    /// not a regular file; [`StateError::Io`] if the copy fails.
    pub fn stage_inspector_plugins(
        &self,
        name: &str,
        config: &Config,
        source_dir: &Path,
    ) -> Result<()> {
        let plugins = plugin_refs(config);
        let sources = plugins
            .iter()
            .map(|plugin| resolve_source(plugin, source_dir))
            .collect::<Result<Vec<PathBuf>>>()?;

        let dir = self.inspectors_dir(name);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| StateError::io(&dir, "remove", e))?;
        }
        if plugins.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create", e))?;
        for (plugin, source) in plugins.iter().zip(&sources) {
            let dest = dir.join(plugin.file_name());
            fs::copy(source, &dest).map_err(|e| StateError::io(&dest, "copy a plugin to", e))?;
        }
        Ok(())
    }

    /// Check that every plugin the cage's config names is staged.
    ///
    /// The `cage update` (no `-c`) path: there is no operator tree to
    /// copy from, so a plugin added to the stored config by hand has to
    /// arrive through `cage update -c`.
    ///
    /// # Errors
    ///
    /// [`StateError::Value`] naming the first plugin that is not staged.
    pub fn check_inspector_plugins_staged(&self, name: &str, config: &Config) -> Result<()> {
        let dir = self.inspectors_dir(name);
        for plugin in plugin_refs(config) {
            if !dir.join(plugin.file_name()).is_file() {
                return Err(StateError::value(format!(
                    "inspectors[{}] {}: plugin {} is not staged for cage '{name}'; \
                     run `agentcage cage update -c <cage.yaml>` so it can be copied \
                     from the directory the cage.yaml is in",
                    plugin.index,
                    repr_str(&plugin.name),
                    repr_str(plugin.file_name())
                )));
            }
        }
        Ok(())
    }

    /// File name to SHA-256 (hex) of every staged plugin the config
    /// names, for the deployment fingerprint. Empty when it names none;
    /// a plugin that is not staged hashes as the empty string, so a
    /// later staging changes the fingerprint.
    #[must_use]
    pub fn inspector_plugin_digests(
        &self,
        name: &str,
        config: &Config,
    ) -> BTreeMap<String, String> {
        let dir = self.inspectors_dir(name);
        plugin_refs(config)
            .iter()
            .map(|plugin| {
                let digest = fs::read(dir.join(plugin.file_name()))
                    .map(|bytes| agentcage_core::fingerprint::sha256_hex(&bytes))
                    .unwrap_or_default();
                (plugin.file_name().to_owned(), digest)
            })
            .collect()
    }
}

/// The host file a plugin entry names: `path` against `source_dir`
/// unless absolute, required to be a regular file (symlinks followed).
fn resolve_source(plugin: &PluginRef, source_dir: &Path) -> Result<PathBuf> {
    let source = source_dir.join(&plugin.path);
    if source.is_file() {
        return Ok(source);
    }
    let problem = if source.exists() {
        "is not a regular file"
    } else {
        "does not exist"
    };
    Err(StateError::value(format!(
        "inspectors[{}] {}: plugin file {} {problem}",
        plugin.index,
        repr_str(&plugin.name),
        repr_str(&source.display().to_string())
    )))
}

#[cfg(test)]
mod tests {
    use agentcage_core::config::{FixedHost, load};

    use crate::{Paths, TestDir};

    fn config(entries: &str) -> agentcage_core::config::Config {
        load(
            "<test>",
            &format!("name: c\ninspectors:\n{entries}"),
            &FixedHost::linux(&["192.0.2.53"]),
        )
        .unwrap()
    }

    #[test]
    fn plugins_are_copied_by_file_name_and_replaced_whole() {
        let t = TestDir::new("plugins");
        let paths = Paths::under(t.path());
        let src = t.path().join("src");
        std::fs::create_dir_all(src.join("plugins")).unwrap();
        std::fs::write(src.join("plugins/a.wasm"), b"A").unwrap();
        std::fs::write(src.join("b.wasm"), b"B").unwrap();
        let abs = src.join("b.wasm");
        let cfg = config(&format!(
            "- name: a\n  path: plugins/a.wasm\n- name: b\n  path: {}\n- name: entropy\n",
            abs.display()
        ));
        paths.stage_inspector_plugins("c", &cfg, &src).unwrap();
        let dir = paths.inspectors_dir("c");
        assert_eq!(std::fs::read(dir.join("a.wasm")).unwrap(), b"A");
        assert_eq!(std::fs::read(dir.join("b.wasm")).unwrap(), b"B");
        paths.check_inspector_plugins_staged("c", &cfg).unwrap();
        let digests = paths.inspector_plugin_digests("c", &cfg);
        assert_eq!(digests.len(), 2);
        assert_eq!(
            digests["a.wasm"],
            "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"
        );

        // A missing source refuses and leaves the staging untouched.
        let bad = config("- name: a\n  path: plugins/a.wasm\n- name: z\n  path: z.wasm\n");
        let err = paths
            .stage_inspector_plugins("c", &bad, &src)
            .unwrap_err()
            .to_string();
        assert!(err.contains("inspectors[1] 'z': plugin file"), "{err}");
        assert!(err.contains("does not exist"), "{err}");
        assert!(dir.join("b.wasm").is_file());
        let err = paths
            .check_inspector_plugins_staged("c", &bad)
            .unwrap_err()
            .to_string();
        assert!(err.contains("plugin 'z.wasm' is not staged"), "{err}");

        // Restaging replaces the directory; no plugins removes it.
        let one = config("- name: a\n  path: plugins/a.wasm\n");
        paths.stage_inspector_plugins("c", &one, &src).unwrap();
        assert!(!dir.join("b.wasm").exists());
        paths
            .stage_inspector_plugins("c", &config("- name: entropy\n"), &src)
            .unwrap();
        assert!(!dir.exists());
        assert!(
            paths
                .inspector_plugin_digests("c", &config("- name: entropy\n"))
                .is_empty()
        );
    }
}
