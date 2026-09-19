//! The half of `cli.py` that decides whether a `cage update` has
//! anything to do.
//!
//! `cage update` must be a **no-op when nothing changed** — that is what
//! `fingerprint.json` exists for, and it is the cutover's acceptance
//! check (RUST-PORT-PLAN.md Track F, F2). PR C4 ported the hash itself
//! and matched every corpus case; what lives here is the part that
//! gathers the five inputs, which is where a port goes wrong silently:
//! a digest computed over the wrong image set still *looks* like a
//! fingerprint, it just never matches twice.
//!
//! Also here: staging a Containerfile's build context into the cage's
//! state directory, and resolving point-in-time image tags for build
//! args, because both feed that digest.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::config::Config;
use agentcage_core::fingerprint::{
    CageYaml, Fingerprint, Inputs, compute_fingerprint, is_state_artifact, scaffold_context_digest,
};
use agentcage_core::har::json::Json;
use agentcage_core::quadlets::Quadlets;
use agentcage_exec::tools::podman::Podman;
use agentcage_state::{AgentSchema, Paths};

use crate::backend::{BackendError, ContainerBackend};

// ── image identities ─────────────────────────────────────────

/// `cli._image_identity` — a stable content identity from an inspect.
///
/// Digests before ids, and a sorted JSON array of `RepoDigests` before
/// either: a locally built image has no digest at all, and an image
/// pulled twice under different tags has the same one.
#[must_use]
pub fn image_identity(inspect: Option<&serde_json::Value>) -> String {
    let Some(serde_json::Value::Object(map)) = inspect else {
        return "unavailable".to_owned();
    };
    for key in ["RepoDigests", "repoDigests"] {
        if let Some(serde_json::Value::Array(values)) = map.get(key) {
            if !values.is_empty() {
                let mut strings: Vec<String> = values.iter().map(value_to_str).collect();
                strings.sort();
                // `json.dumps(sorted(...))` — Python's default
                // separators put a space after each comma.
                return serde_json::to_string(&strings)
                    .unwrap_or_default()
                    .replace("\",\"", "\", \"");
            }
        }
    }
    for key in ["Digest", "digest", "Id", "ID", "id"] {
        if let Some(value) = map.get(key) {
            // `if value:` — a falsy value falls through to the next key.
            let text = value_to_str(value);
            if !text.is_empty() && text != "null" && text != "false" && text != "0" {
                return text;
            }
        }
    }
    "unavailable".to_owned()
}

/// `str(value)` for the handful of JSON shapes an inspect can hold.
fn value_to_str(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `cli._containerfile_image_refs` — the concrete images a staged
/// Containerfile's `FROM` lines name.
///
/// `ARG` defaults fill in where a build arg does not, `${VAR}` and
/// `$VAR` are substituted, and a reference that is still unresolved,
/// names an earlier build stage, or is `scratch` is dropped. An
/// unreadable Containerfile yields nothing rather than failing: the
/// build will produce the real error a moment later.
#[must_use]
pub fn containerfile_image_refs(
    config: &Config,
    state_dir: &Path,
    resolved_args: &[(String, String)],
) -> BTreeSet<String> {
    let containerfile = &config.container.build.containerfile;
    if containerfile.is_empty() {
        return BTreeSet::new();
    }
    let path = resolve_containerfile(containerfile, state_dir);
    let Ok(content) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };

    let mut args: Vec<(String, String)> = resolved_args.to_vec();
    for line in content.lines() {
        if let Some((name, default)) = parse_arg(line) {
            if !args.iter().any(|(key, _)| key == &name) {
                if let Some(default) = default {
                    args.push((name, default));
                }
            }
        }
    }

    let mut refs = BTreeSet::new();
    let mut stages: BTreeSet<String> = BTreeSet::new();
    for line in content.lines() {
        let Some((reference, stage)) = parse_from(line) else {
            continue;
        };
        let expanded = substitute(&reference, &args);
        if !expanded.eq_ignore_ascii_case("scratch")
            && !stages.contains(&expanded)
            && !expanded.contains('$')
        {
            refs.insert(expanded);
        }
        if let Some(stage) = stage {
            stages.insert(stage);
        }
    }
    refs
}

/// A Containerfile path, resolved against the cage's state dir when it
/// is relative. The one rule every consumer of `build.containerfile`
/// has to agree on.
#[must_use]
pub fn resolve_containerfile(containerfile: &str, base: &Path) -> PathBuf {
    let path = PathBuf::from(containerfile);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

/// `re.match(r"\s*ARG\s+([A-Za-z_]\w*)(?:=(\S+))?", line)`.
fn parse_arg(line: &str) -> Option<(String, Option<String>)> {
    let rest = line.trim_start().strip_prefix("ARG")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace())
        .collect::<String>();
    let (name, default) = match token.split_once('=') {
        Some((name, value)) if !value.is_empty() => (name.to_owned(), Some(value.to_owned())),
        Some((name, _)) => (name.to_owned(), None),
        None => (token.clone(), None),
    };
    if !is_identifier(&name) {
        return None;
    }
    Some((name, default))
}

/// `re.match(r"\s*FROM\s+(?:--\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)`.
fn parse_from(line: &str) -> Option<(String, Option<String>)> {
    let trimmed = line.trim_start();
    if trimmed.len() < 4 || !trimmed[..4].eq_ignore_ascii_case("FROM") {
        return None;
    }
    let rest = &trimmed[4..];
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let mut tokens = rest.split_whitespace();
    let mut reference = tokens.next()?;
    // A single optional `--flag`, as the Python's regex allows.
    if reference.starts_with("--") {
        reference = tokens.next()?;
    }
    let stage = match (tokens.next(), tokens.next()) {
        (Some(keyword), Some(name)) if keyword.eq_ignore_ascii_case("AS") => Some(name.to_owned()),
        _ => None,
    };
    Some((reference.to_owned(), stage))
}

/// `$NAME` / `${NAME}`, replaced from `args`, left verbatim when absent.
fn substitute(reference: &str, args: &[(String, String)]) -> String {
    let mut out = String::with_capacity(reference.len());
    let chars: Vec<char> = reference.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '$' {
            out.push(chars[index]);
            index += 1;
            continue;
        }
        let braced = chars.get(index + 1) == Some(&'{');
        let start = index + if braced { 2 } else { 1 };
        let mut end = start;
        while end < chars.len() && is_identifier_char(chars[end], end == start) {
            end += 1;
        }
        let name: String = chars[start..end].iter().collect();
        let closed = !braced || chars.get(end) == Some(&'}');
        if name.is_empty() || !closed {
            out.push('$');
            index += 1;
            continue;
        }
        let consumed = if braced { end + 1 } else { end };
        match args.iter().find(|(key, _)| key == &name) {
            Some((_, value)) => out.push_str(value),
            None => out.extend(&chars[index..consumed]),
        }
        index = consumed;
    }
    out
}

fn is_identifier_char(c: char, first: bool) -> bool {
    c == '_' || c.is_ascii_alphabetic() || (!first && c.is_ascii_digit())
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    if chars.next().is_some_and(|c| is_identifier_char(c, true)) {
        chars.all(|c| is_identifier_char(c, false))
    } else {
        false
    }
}

/// `cli._update_image_digests` — every image that can affect this
/// deployment, resolved to a content identity.
///
/// The set is: the cage's own image, the concrete `FROM` references of
/// its staged Containerfile, and the version-pinned egress image. With
/// `refresh`, upstream references that are not `localhost/` builds are
/// pulled first, so a moved `:latest` shows up as a changed digest and
/// the cage actually rebuilds.
///
/// A configured image with no readable Containerfile is treated as an
/// upstream reference itself — the legacy best-effort pull, kept
/// because a missing staged file fails later in the build anyway.
#[must_use]
pub fn update_image_digests(
    config: &Config,
    paths: &Paths,
    podman: &Podman<'_>,
    egress_image: &str,
    resolved_args: &[(String, String)],
    refresh: bool,
) -> BTreeMap<String, String> {
    let state_dir = paths.deployment_dir(&config.name);
    let mut refs: BTreeSet<String> = BTreeSet::new();
    refs.insert(config.container.image.clone());

    let mut upstream = containerfile_image_refs(config, &state_dir, resolved_args);
    let containerfile = &config.container.build.containerfile;
    let staged_is_readable =
        !containerfile.is_empty() && resolve_containerfile(containerfile, &state_dir).is_file();
    if !staged_is_readable {
        upstream.insert(config.container.image.clone());
    }
    refs.extend(upstream.iter().cloned());
    refs.insert(egress_image.to_owned());

    let mut identities = BTreeMap::new();
    for reference in refs {
        if reference.is_empty() {
            continue;
        }
        if refresh && upstream.contains(&reference) && !reference.starts_with("localhost/") {
            let _ = podman.pull(&reference);
        }
        let identity = podman
            .image_inspect(&reference)
            .map_or_else(|_| "unavailable".to_owned(), |v| image_identity(Some(&v)));
        identities.insert(reference, identity);
    }
    identities
}

// ── the scaffold build context ───────────────────────────────

/// `fingerprint.scaffold_context_version` — the I/O half.
///
/// The digest itself is [`scaffold_context_digest`]; this is the
/// directory walk the pure crate cannot do. The three special answers
/// are the Python's: `""` for a cage with no Containerfile, `"missing"`
/// for a root that is not a directory, and the digest otherwise.
#[must_use]
pub fn scaffold_context_version(state_dir: &Path, containerfile: &str) -> String {
    if containerfile.is_empty() {
        return String::new();
    }
    let mut root = fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    let path = PathBuf::from(containerfile);
    if path.is_absolute() {
        let resolved = fs::canonicalize(&path).unwrap_or(path);
        match resolved.parent() {
            Some(parent) => root = parent.to_path_buf(),
            None => return "missing".to_owned(),
        }
    }
    if !root.is_dir() {
        return "missing".to_owned();
    }

    let mut relative: Vec<String> = Vec::new();
    collect_files(&root, &root, &mut relative);
    scaffold_context_digest(&relative, |path| fs::read(root.join(path)))
        .unwrap_or_else(|_| "missing".to_owned())
}

/// Every *file* under `root`, as a relative POSIX path.
///
/// Prunes at the top-level state artifacts rather than at every depth,
/// which is what `relative.parts[0] in _STATE_ARTIFACTS` means — and
/// what keeps `creds/` out without also excluding a build input that
/// happens to be called `creds` three levels down.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_string_lossy().into_owned();
        if is_state_artifact(&relative) {
            continue;
        }
        // `path.is_file()` follows symlinks, as the Python's does.
        if path.is_dir() {
            collect_files(root, &path, out);
        } else if path.is_file() {
            out.push(relative);
        }
    }
}

// ── the fingerprint ──────────────────────────────────────────

/// The five inputs, gathered and hashed.
#[derive(Debug)]
pub struct Computed {
    /// The fingerprint itself.
    pub fingerprint: Fingerprint,
    /// The units it was computed over, so a caller that let this
    /// function render them can install the same ones.
    pub units: Quadlets,
}

/// Everything [`update_fingerprint`] needs besides the backend and the
/// state roots.
///
/// A struct because four of the six are `Option`s or `bool`s and
/// transposing `refresh_images` with a `network_octet` of `None` would
/// compile and produce a fingerprint that never matches twice.
#[derive(Debug)]
pub struct FingerprintRequest<'a> {
    /// The cage's configuration, as the deploy will render it.
    pub config: &'a Config,
    /// The deployment name, which is the cage name for every path this
    /// PR reaches.
    pub name: &'a str,
    /// Absolute host path to the stored `cage.yaml`.
    pub config_host_path: &'a str,
    /// The cage's already-allocated subnet octet, or `None` to derive.
    pub network_octet: Option<u32>,
    /// Pull upstream references before inspecting them, so a moved
    /// `:latest` shows up as a changed digest.
    pub refresh_images: bool,
    /// Units already rendered, or `None` to render them here.
    pub units: Option<Quadlets>,
}

/// `cli._update_fingerprint`.
///
/// When `units` is `None` the units are rendered here — which means
/// refreshing the patches directory and writing the resolv files first,
/// because the renderer bakes their paths into the quadlets. That is
/// the preflight shape: it has to produce exactly the units a deploy
/// would, without deploying.
///
/// # Errors
///
/// [`BackendError`] if the render or a state read fails.
pub fn update_fingerprint(
    backend: &ContainerBackend<'_>,
    paths: &Paths,
    request: FingerprintRequest<'_>,
) -> Result<Computed, BackendError> {
    let FingerprintRequest {
        config,
        name,
        config_host_path,
        network_octet,
        refresh_images,
        units,
    } = request;
    let resolved_args: Vec<(String, String)> = config
        .container
        .build
        .args
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let units = if let Some(units) = units {
        units
    } else {
        let patches = crate::services::ensure_patches(paths).map_err(BackendError::Assets)?;
        let used = crate::services::collect_used_octets(paths, name);
        let addrs =
            agentcage_core::quadlets::cage_network_addrs(&config.name, Some(&used), network_octet)?;
        crate::services::write_resolv_files(
            &patches,
            &config.name,
            &addrs.ip_egress,
            &config.dns_servers,
        )
        .map_err(BackendError::Assets)?;
        let rendered = backend.generate_units(
            config,
            config_host_path,
            &patches.display().to_string(),
            name,
            Some(&used),
            network_octet,
        )?;
        // The Python's `generate_quadlets` writes these to stderr
        // itself, so they appear once here on a no-op update and twice
        // on a real one (preflight, then the deploy's own render).
        // Reproduced rather than deduplicated: a warning the operator
        // saw under Python and not under Rust is a regression in the
        // only output this path has.
        for warning in &rendered.warnings {
            eprint!("{warning}");
        }
        rendered
    };

    let image_digests = update_image_digests(
        config,
        paths,
        backend.podman(),
        &backend.egress_image(),
        &resolved_args,
        refresh_images,
    );

    let raw_text =
        fs::read_to_string(paths.stored_config_path(name)).map_err(BackendError::Assets)?;
    let state_dir = paths.deployment_dir(name);
    let context_version =
        scaffold_context_version(&state_dir, &config.container.build.containerfile);
    let metadata = paths
        .load_metadata(name)
        .unwrap_or_else(|_| Json::Object(Vec::new()));
    let scaffold = metadata
        .get("scaffold")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();

    let unit_map: BTreeMap<String, String> = units
        .files
        .iter()
        .map(|(name, body)| (name.clone(), body.clone()))
        .collect();
    let resolved = agentcage_core::config::json::to_value(config);
    let fingerprint = compute_fingerprint(Inputs {
        cage_yaml: CageYaml::Text(&raw_text),
        resolved_config: &resolved,
        units: &unit_map,
        image_digests: &image_digests,
        scaffold_version: &format!("{scaffold}:{context_version}"),
    })
    .map_err(|error| BackendError::Config(agentcage_core::config::ConfigError::runtime(error)))?;

    Ok(Computed { fingerprint, units })
}

/// Whether the stored config parses under the agent schema.
///
/// `cage update -c` reads the *previous* document with the schema check
/// disabled, because an explicit replacement must work even when what
/// is on disk is no longer supported.
#[must_use]
pub fn previous_raw(paths: &Paths, name: &str) -> Option<agentcage_core::yaml::Value> {
    paths.load_raw_config(name, AgentSchema::Skip).ok()
}

#[cfg(test)]
mod tests {
    use super::{containerfile_image_refs, image_identity, substitute};
    use agentcage_core::config::Config;

    #[test]
    fn repo_digests_win_and_are_sorted() {
        let inspect = serde_json::json!({
            "RepoDigests": ["b@sha256:2", "a@sha256:1"],
            "Id": "sha256:deadbeef",
        });
        assert_eq!(
            image_identity(Some(&inspect)),
            r#"["a@sha256:1", "b@sha256:2"]"#
        );
    }

    #[test]
    fn an_id_is_the_fallback_and_a_non_object_is_unavailable() {
        let inspect = serde_json::json!({"Id": "sha256:deadbeef"});
        assert_eq!(image_identity(Some(&inspect)), "sha256:deadbeef");
        assert_eq!(image_identity(None), "unavailable");
        assert_eq!(
            image_identity(Some(&serde_json::json!(["not", "a", "map"]))),
            "unavailable"
        );
        assert_eq!(
            image_identity(Some(&serde_json::json!({"RepoDigests": []}))),
            "unavailable"
        );
    }

    #[test]
    fn variables_expand_from_build_args_and_survive_when_absent() {
        let args = [("BASE".to_owned(), "debian:13".to_owned())];
        assert_eq!(substitute("${BASE}", &args), "debian:13");
        assert_eq!(substitute("$BASE", &args), "debian:13");
        assert_eq!(substitute("${OTHER}", &args), "${OTHER}");
        assert_eq!(substitute("$OTHER", &args), "$OTHER");
        assert_eq!(substitute("plain:1", &args), "plain:1");
    }

    #[test]
    fn from_lines_resolve_args_and_drop_stages_and_scratch() {
        let dir = agentcage_state::TestDir::new("cfrefs");
        std::fs::write(
            dir.path().join("Containerfile"),
            "ARG BASE=node:22-slim\n\
             ARG OTHER\n\
             FROM ${BASE} AS build\n\
             FROM --platform=linux/amd64 alpine:3 AS runtime\n\
             FROM build\n\
             FROM scratch\n\
             FROM $OTHER\n",
        )
        .unwrap();

        let mut config = Config::default();
        config.container.build.containerfile = "Containerfile".to_owned();
        let refs = containerfile_image_refs(&config, dir.path(), &[]);
        let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
        assert_eq!(refs, ["alpine:3", "node:22-slim"]);
    }

    #[test]
    fn a_build_arg_overrides_the_containerfiles_own_default() {
        let dir = agentcage_state::TestDir::new("cfargs");
        std::fs::write(
            dir.path().join("Containerfile"),
            "ARG BASE=node:22-slim\nFROM ${BASE}\n",
        )
        .unwrap();
        let mut config = Config::default();
        config.container.build.containerfile = "Containerfile".to_owned();
        let refs = containerfile_image_refs(
            &config,
            dir.path(),
            &[("BASE".to_owned(), "node:24-slim".to_owned())],
        );
        assert_eq!(
            refs.iter().map(String::as_str).collect::<Vec<_>>(),
            ["node:24-slim"]
        );
    }
}
