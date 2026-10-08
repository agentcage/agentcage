//! `apple_container/scaffold.py` — building a cage's own image.
//!
//! The container backend builds the cage image with host podman. On a
//! Mac there is no host podman, so the same build goes through Apple's
//! `container build`. What is built is the cage's **staged**
//! Containerfile — the copy frozen into the deployment directory at
//! create time — never the live scaffold on disk, so an agentcage
//! upgrade that changes a scaffold cannot leak into an existing cage on
//! `cage update`.
//!
//! # The `--pull` suppression
//!
//! `container build --pull` applies to every stage. A two-stage
//! scaffold whose cage image is `FROM localhost/…` therefore makes
//! BuildKit try to fetch a ref that has no registry behind it, and the
//! build dies with `ECONNREFUSED` (POSIXErrorCode 61). So a
//! Containerfile with any `localhost/` base drops `--pull` and says it
//! did; `--no-cache` still forces the rebuild the operator asked for.
//! [`base_image_refs`] is the scan that decides, and it has to
//! understand multi-stage aliases: in `FROM x AS build` … `FROM build`,
//! the second `FROM` is not a pull.

use std::path::Path;

use agentcage_core::config::OrderedMap;
use agentcage_exec::CommandRunner;
use agentcage_exec::tools::apple::AppleContainer;

use crate::output;

/// `_base_image_refs` — the external bases a Containerfile pulls.
///
/// Intra-file stage aliases and `scratch` are excluded; leading build
/// flags (`FROM --platform=… ref`) are skipped so the real ref is
/// found. An unreadable file is an empty list, not an error — the
/// build is about to fail on its own and with a better message.
#[must_use]
pub fn base_image_refs(containerfile: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(containerfile) else {
        return Vec::new();
    };
    let mut aliases: Vec<String> = Vec::new();
    let mut refs: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line
            .split_whitespace()
            .filter(|token| !token.starts_with("--"))
            .collect();
        if tokens.len() < 2 || !tokens[0].eq_ignore_ascii_case("FROM") {
            continue;
        }
        let reference = tokens[1];
        let alias = if tokens.len() >= 4 && tokens[2].eq_ignore_ascii_case("AS") {
            Some(tokens[3])
        } else {
            None
        };
        if !aliases.iter().any(|known| known == reference)
            && !reference.eq_ignore_ascii_case("scratch")
        {
            refs.push(reference.to_owned());
        }
        if let Some(alias) = alias {
            aliases.push(alias.to_owned());
        }
    }
    refs
}

/// `build_image_from_staged` — `container build` for the cage image.
///
/// Build args are resolved point-in-time the way the container backend
/// resolves them (an untagged registry ref gains a concrete tag), so
/// `--pull` fetches a fresh base without mutating the frozen
/// `cage.yaml`.
///
/// # Errors
///
/// [`ExecError`](agentcage_exec::ExecError) when `container` is missing
/// or the build exits non-zero. The build's own output has already
/// reached the terminal.
pub fn build_image_from_staged(
    runner: &dyn CommandRunner,
    image: &str,
    containerfile: &Path,
    context_dir: &Path,
    build_args: &OrderedMap<String>,
    quiet: bool,
    flags: super::image::BuildFlags,
) -> Result<(), agentcage_exec::ExecError> {
    let super::image::BuildFlags { no_cache, pull } = flags;
    let (resolved, changes) = crate::registry::resolve_build_args(runner, build_args);

    let echo = |message: &str| {
        if !quiet {
            output::echo(message);
        }
    };
    for change in &changes {
        echo(&format!("Build arg {}: {}", change.key, change.new));
    }
    echo(&format!(
        "Building {image} from {}{} (apple-container)...",
        containerfile.display(),
        if no_cache { " (no-cache)" } else { "" }
    ));

    let mut effective_pull = pull;
    if pull
        && base_image_refs(containerfile)
            .iter()
            .any(|reference| reference.starts_with("localhost/"))
    {
        effective_pull = false;
        echo(
            "Skipping --pull: Containerfile has a local-only ('localhost/') \
             base image with no registry source; --no-cache still forces a \
             full rebuild.",
        );
    }

    let mut argv = vec![
        "build".to_owned(),
        "-t".to_owned(),
        image.to_owned(),
        "-f".to_owned(),
        containerfile.display().to_string(),
    ];
    if no_cache {
        argv.push("--no-cache".to_owned());
    }
    if effective_pull {
        argv.push("--pull".to_owned());
    }
    for (key, value) in &resolved {
        argv.push("--build-arg".to_owned());
        argv.push(format!("{key}={value}"));
    }
    argv.push(context_dir.display().to_string());

    // Apple's CLI writes its own progress to stderr and would fight an
    // agentcage spinner for the line, which is why the Python wraps
    // every streaming `container` call in `pause_active_spinner`.
    output::pause_active_spinner(|| {
        AppleContainer::new(runner)
            .run_streaming(argv, true)
            .map(|_| ())
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::base_image_refs;

    fn refs_of(body: &str) -> Vec<String> {
        let dir = std::env::temp_dir().join(format!(
            "agentcage-apple-build-{}-{}",
            std::process::id(),
            body.len()
        ));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("Containerfile");
        std::fs::write(&path, body).expect("write");
        let refs = base_image_refs(&path);
        let _ = std::fs::remove_dir_all(&dir);
        refs
    }

    #[test]
    fn a_stage_alias_is_not_a_base_image() {
        let refs = refs_of(
            "FROM docker.io/library/golang:1.23 AS build\n\
             RUN go build\n\
             FROM build\n\
             COPY --from=build /app /app\n",
        );
        assert_eq!(refs, vec!["docker.io/library/golang:1.23".to_owned()]);
    }

    #[test]
    fn build_flags_and_scratch_and_comments_are_skipped() {
        let refs = refs_of(
            "# a comment\n\
             \n\
             FROM --platform=linux/arm64 localhost/base:latest\n\
             FROM scratch\n",
        );
        assert_eq!(refs, vec!["localhost/base:latest".to_owned()]);
    }

    #[test]
    fn an_unreadable_file_is_an_empty_list() {
        assert!(base_image_refs(Path::new("/nonexistent/Containerfile")).is_empty());
    }
}
