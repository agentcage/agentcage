//! `registry.resolve_build_args` and the scaffold-name probe that
//! `cage create` records in `metadata.json`.
//!
//! Only the slice `cage create` / `cage update` reach. The full scaffold
//! machinery — rendering, the search path, `run_scaffold_setup` — is PR
//! D14; what is here is the point-in-time tag resolution the build path
//! applies to *user-provided* configs, where there is no scaffold to
//! consult.

use agentcage_core::config::types::OrderedMap;
use agentcage_exec::CommandRunner;
use agentcage_exec::tools::skopeo::Skopeo;

/// One build arg whose value the resolver moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The build-arg name.
    pub key: String,
    /// What it was.
    pub old: String,
    /// What it became.
    pub new: String,
}

/// `registry.resolve_build_args(build_args)` — the no-scaffold case.
///
/// `cage create` and `cage update` call it without `scaffold_args`,
/// because an existing cage owns a frozen copy of its scaffold config
/// and must not consult the live registry of scaffolds. That reduces
/// `_resolve_one` to its "user-added arg" branch:
///
/// * already tagged → left alone, respecting the author's pin;
/// * untagged and registry-path-like (it has a `/`) → resolved to the
///   highest version tag the registry offers;
/// * anything else → passed through.
///
/// Returns the resolved map in the config's insertion order — the order
/// that reaches `--build-arg` on argv — and the changes, for the caller
/// to echo.
#[must_use]
pub fn resolve_build_args(
    runner: &dyn CommandRunner,
    build_args: &OrderedMap<String>,
) -> (Vec<(String, String)>, Vec<Change>) {
    let mut resolved = Vec::with_capacity(build_args.len());
    let mut changes = Vec::new();
    for (key, current) in build_args {
        let new = resolve_one(runner, current);
        if &new != current {
            changes.push(Change {
                key: key.clone(),
                old: current.clone(),
                new: new.clone(),
            });
        }
        resolved.push((key.clone(), new));
    }
    (resolved, changes)
}

/// `registry._resolve_one(current, None, resolver)`.
fn resolve_one(runner: &dyn CommandRunner, current: &str) -> String {
    // `_, _, tag = current.rpartition(":")` then `if ":" in current and
    // tag` — a trailing colon is *not* a pin.
    if let Some((_, tag)) = current.rsplit_once(':') {
        if !tag.is_empty() {
            return current.to_owned();
        }
    }
    if !current.contains('/') {
        return current.to_owned();
    }
    match resolve_latest_tag(runner, current) {
        Some(tag) => format!("{current}:{tag}"),
        None => current.to_owned(),
    }
}

/// `registry.resolve_latest_tag` — the highest version-shaped tag.
///
/// Version-shaped means `^v?\d[\d.]*$`, and an architecture suffix
/// (`-amd64`, `-arm64`, `-x86_64`, `-aarch64`) disqualifies a tag — but
/// the arch check runs on the *unfiltered* tag, so it can only ever
/// exclude something the version pattern already rejected. Kept anyway,
/// because reproducing the Python is the point.
#[must_use]
pub fn resolve_latest_tag(runner: &dyn CommandRunner, image: &str) -> Option<String> {
    let tags = Skopeo::new(runner).list_tags(image).ok()?;
    let mut matching: Vec<&String> = tags
        .iter()
        .filter(|tag| is_version_tag(tag) && !has_arch_suffix(tag))
        .collect();
    matching.sort_by_key(|tag| version_key(tag));
    matching.last().map(|tag| (*tag).clone())
}

/// `^v?\d[\d.]*$`.
fn is_version_tag(tag: &str) -> bool {
    let body = tag.strip_prefix('v').unwrap_or(tag);
    body.starts_with(|c: char| c.is_ascii_digit())
        && body.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// `-(amd64|arm64|x86_64|aarch64)$`.
fn has_arch_suffix(tag: &str) -> bool {
    ["-amd64", "-arm64", "-x86_64", "-aarch64"]
        .iter()
        .any(|suffix| tag.ends_with(suffix))
}

/// One component of a dotted version, as `registry._version_key` sorts
/// them: integers compare as integers, everything else as text.
///
/// Python would raise comparing an `int` to a `str`; it never does,
/// because the caller has already filtered to `^v?\d[\d.]*$`, where
/// every component that is not empty is an integer.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Part {
    Number(u64),
    Text(String),
}

fn version_key(tag: &str) -> Vec<Part> {
    tag.trim_start_matches('v')
        .split('.')
        .map(|part| {
            part.parse::<u64>()
                .map_or_else(|_| Part::Text(part.to_owned()), Part::Number)
        })
        .collect()
}

/// `init.infer_scaffold_from_image`.
///
/// `localhost/agentcage-scaffold-<name>[:tag]` names a scaffold-built
/// image, and the name counts only if it is one agentcage ships.
#[must_use]
pub fn infer_scaffold_from_image(image: &str) -> Option<String> {
    let rest = image.strip_prefix("localhost/agentcage-scaffold-")?;
    // `([a-z0-9-]+?)(?::|$)` — non-greedy up to the first colon.
    let name = rest.split(':').next().unwrap_or_default();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return None;
    }
    embedded_scaffolds().into_iter().find(|known| known == name)
}

/// `init.list_scaffolds`, restricted to what the binary embeds.
///
/// The Python globs two sources: `templates/presets/*.yaml.j2` and every
/// directory on the scaffold search path holding a `cage.yaml.j2`. Both
/// are reproduced against the embedded trees; what is *not* reproduced
/// is the project-local `.agentcage/scaffolds` directory, which needs a
/// `git rev-parse` and belongs to PR D14. This call site only ever asks
/// "is this name one agentcage ships?", which a project-local scaffold
/// is not.
///
/// `tree()` yields paths relative to the tree root, so a scaffold is
/// `<name>/cage.yaml.j2` and a preset is `presets/<name>.yaml.j2`.
#[must_use]
pub fn embedded_scaffolds() -> Vec<String> {
    let mut names: Vec<String> = agentcage_assets::tree("scaffolds")
        .filter_map(|(path, _)| {
            let (dir, file) = path.split_once('/')?;
            (file == "cage.yaml.j2").then(|| dir.to_owned())
        })
        .collect();
    names.extend(agentcage_assets::tree("templates").filter_map(|(path, _)| {
        path.strip_prefix("presets/")
            .and_then(|file| file.strip_suffix(".yaml.j2"))
            .map(str::to_owned)
    }));
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::{
        Change, embedded_scaffolds, infer_scaffold_from_image, is_version_tag, resolve_build_args,
        resolve_latest_tag, version_key,
    };
    use agentcage_core::config::types::OrderedMap;
    use agentcage_exec::{FakeRunner, Reply};

    #[test]
    fn version_tags_are_the_ones_the_python_matches() {
        assert!(is_version_tag("2026.2.24"));
        assert!(is_version_tag("v0.1.2"));
        assert!(is_version_tag("1"));
        assert!(!is_version_tag("latest"));
        assert!(!is_version_tag("1.2-rc1"));
        assert!(!is_version_tag(""));
    }

    #[test]
    fn versions_sort_numerically_not_lexically() {
        assert!(version_key("1.10.0") > version_key("1.9.0"));
        assert!(version_key("v2.0") > version_key("1.99"));
    }

    #[test]
    fn a_pinned_arg_never_reaches_the_registry() {
        let fake = FakeRunner::new();
        let mut args = OrderedMap::new();
        args.insert("BASE".to_owned(), "ghcr.io/x/y:1.2.3".to_owned());
        args.insert("PLAIN".to_owned(), "somevalue".to_owned());
        let (resolved, changes) = resolve_build_args(&fake, &args);
        assert_eq!(
            resolved,
            [
                ("BASE".to_owned(), "ghcr.io/x/y:1.2.3".to_owned()),
                ("PLAIN".to_owned(), "somevalue".to_owned()),
            ]
        );
        assert!(changes.is_empty());
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }

    #[test]
    fn an_untagged_registry_ref_is_resolved_and_reported() {
        let fake = FakeRunner::new();
        fake.push(Reply::ok(
            r#"{"Tags": ["latest", "1.9.0", "1.10.0", "1.10.0-arm64"]}"#,
        ));
        let mut args = OrderedMap::new();
        args.insert("BASE".to_owned(), "ghcr.io/x/y".to_owned());
        let (resolved, changes) = resolve_build_args(&fake, &args);
        assert_eq!(
            resolved,
            [("BASE".to_owned(), "ghcr.io/x/y:1.10.0".to_owned())]
        );
        assert_eq!(
            changes,
            [Change {
                key: "BASE".to_owned(),
                old: "ghcr.io/x/y".to_owned(),
                new: "ghcr.io/x/y:1.10.0".to_owned(),
            }]
        );
    }

    #[test]
    fn a_registry_that_offers_nothing_usable_leaves_the_value_alone() {
        let fake = FakeRunner::new();
        fake.push(Reply::ok(r#"{"Tags": ["latest", "edge"]}"#));
        assert_eq!(resolve_latest_tag(&fake, "ghcr.io/x/y"), None);
    }

    #[test]
    fn the_scaffold_probe_only_accepts_names_the_binary_ships() {
        let scaffolds = embedded_scaffolds();
        assert!(
            scaffolds.contains(&"claude-code".to_owned()),
            "{scaffolds:?}"
        );
        assert_eq!(
            infer_scaffold_from_image("localhost/agentcage-scaffold-claude-code:0.1"),
            Some("claude-code".to_owned())
        );
        assert_eq!(
            infer_scaffold_from_image("localhost/agentcage-scaffold-claude-code"),
            Some("claude-code".to_owned())
        );
        assert_eq!(
            infer_scaffold_from_image("localhost/agentcage-scaffold-nope:1"),
            None
        );
        assert_eq!(infer_scaffold_from_image("node:22-slim"), None);
        assert_eq!(infer_scaffold_from_image(""), None);
    }
}
