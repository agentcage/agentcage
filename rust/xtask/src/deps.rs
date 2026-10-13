//! `cargo xtask update-deps` — the pinned container base images.
//!
//! A Containerfile either pins its base image by digest and names the
//! tag it tracks in a `# update-from: <ref>` comment, or floats on a
//! plain tag with no such comment. For a pinned one this asks the
//! registry (via `skopeo inspect`) for that tag's current digest and
//! reports — or, with `--update`, rewrites — any pin that has moved. A
//! floating one has nothing to update: it is reported and left alone.
//! A shipped Containerfile floats so that a rebuild picks up the base's
//! security fixes.
//!
//! Rust dependencies are not handled here: `cargo update` and the
//! `cargo deny` CI job cover them.

use std::path::Path;
use std::process::{Command, ExitCode};

/// Where the shipped Containerfiles live.
const CONTAINERS: &str = "src/agentcage/data/containers";

/// What one Containerfile pins.
#[derive(Debug, PartialEq, Eq)]
struct Pin {
    /// The `# update-from:` reference, e.g. `docker.io/library/debian:trixie-slim`.
    source: String,
    /// The image half of the pinned `FROM <image>@<digest>`.
    image: String,
    /// The pinned digest, `sha256:…`.
    digest: String,
}

/// The base image of a Containerfile that floats on purpose: a plain-tag
/// `FROM` (no `@sha256:` digest) and no `# update-from:` comment. A file
/// with only one of the two is half-pinned and gets `None`.
fn floating_from(text: &str) -> Option<String> {
    if text.lines().any(|line| line.starts_with("# update-from:")) {
        return None;
    }
    let reference = text.lines().find_map(|line| {
        let rest = line.strip_prefix("FROM")?;
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        rest.split_whitespace().next()
    })?;
    (!reference.contains('@')).then(|| reference.to_owned())
}

/// The pin in a Containerfile, or why it has none.
fn parse_pin(text: &str) -> Result<Pin, &'static str> {
    let source = text
        .lines()
        .find_map(|line| line.strip_prefix("# update-from:"))
        .map(|rest| rest.trim().to_owned())
        .filter(|rest| !rest.is_empty())
        .ok_or("no # update-from: comment found")?;
    let (image, digest) = text
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("FROM")?.trim_start();
            let reference = rest.split_whitespace().next()?;
            let (image, digest) = reference.split_once('@')?;
            digest
                .strip_prefix("sha256:")
                .filter(|hex| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
                .map(|_| (image.to_owned(), digest.to_owned()))
        })
        .ok_or("no digest-pinned FROM found")?;
    Ok(Pin {
        source,
        image,
        digest,
    })
}

/// The digest a reference currently resolves to, from `skopeo inspect`.
fn latest_digest(reference: &str) -> Result<String, String> {
    let output = Command::new("skopeo")
        .args(["inspect", &format!("docker://{reference}")])
        .output()
        .map_err(|e| format!("cannot run skopeo: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "skopeo inspect failed for {reference}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("skopeo inspect output for {reference}: {e}"))?;
    json["Digest"]
        .as_str()
        .filter(|d| !d.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("skopeo inspect gave no Digest for {reference}"))
}

/// The first 20 characters of a digest, for display.
fn short(digest: &str) -> String {
    format!("{}...", digest.chars().take(20).collect::<String>())
}

/// Check (and optionally update) every shipped Containerfile's pin.
///
/// Exits non-zero when an update is available and was not applied, so a
/// scheduled job can notice.
pub(crate) fn run(root: &Path, update: bool) -> Result<ExitCode, String> {
    let dir = root.join(CONTAINERS);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("Containerfile"))
        .collect();
    names.sort();

    let (mut pending, mut current, mut errors) = (0, 0, 0);
    for name in names {
        let path = dir.join(&name);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("\n[containers] {name}");
        let pin = match parse_pin(&text) {
            Ok(pin) => pin,
            Err(why) => {
                match floating_from(&text) {
                    Some(reference) => {
                        println!("  floating: {reference} (not pinned; nothing to update)");
                    }
                    None => println!("  skipped: {why}"),
                }
                continue;
            }
        };
        let latest = match latest_digest(&pin.source) {
            Ok(latest) => latest,
            Err(error) => {
                println!("  error: {error}");
                errors += 1;
                continue;
            }
        };
        println!("  current: {}", short(&pin.digest));
        if latest == pin.digest {
            println!("  latest:  {} (up to date)", short(&latest));
            current += 1;
            continue;
        }
        println!("  latest:  {}", short(&latest));
        if update {
            let rewritten = text.replace(
                &format!("{}@{}", pin.image, pin.digest),
                &format!("{}@{latest}", pin.image),
            );
            std::fs::write(&path, rewritten).map_err(|e| format!("{}: {e}", path.display()))?;
            println!("  -> updated digest in {name}");
        } else {
            println!("  -> update available (run with --update to apply)");
            pending += 1;
        }
    }
    println!("\nSummary: {pending} update(s) available, {current} up to date, {errors} error(s)");
    Ok(if pending > 0 || errors > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::{Pin, floating_from, parse_pin};

    #[test]
    fn a_pinned_containerfile_parses() {
        let text = "# header\n#\n# update-from: docker.io/library/debian:trixie-slim\n\
                    FROM docker.io/library/debian@sha256:a29215f6\nRUN true\n";
        assert_eq!(
            parse_pin(text),
            Ok(Pin {
                source: "docker.io/library/debian:trixie-slim".to_owned(),
                image: "docker.io/library/debian".to_owned(),
                digest: "sha256:a29215f6".to_owned(),
            })
        );
    }

    #[test]
    fn missing_pieces_are_reported() {
        assert_eq!(
            parse_pin("FROM debian@sha256:ab\n"),
            Err("no # update-from: comment found")
        );
        assert_eq!(
            parse_pin("# update-from: debian:12\nFROM debian:12\n"),
            Err("no digest-pinned FROM found")
        );
    }

    #[test]
    fn a_floating_containerfile_is_recognised() {
        assert_eq!(
            floating_from("# header\nFROM docker.io/library/alpine:3\nRUN true\n"),
            Some("docker.io/library/alpine:3".to_owned())
        );
        // Half-pinned: a tracked tag without a digest, or a digest
        // without the tag it tracks.
        assert_eq!(floating_from("# update-from: alpine:3\nFROM alpine:3\n"), None);
        assert_eq!(floating_from("FROM alpine@sha256:ab\n"), None);
        assert_eq!(floating_from("RUN true\n"), None);
    }

    /// The real Containerfiles are either properly pinned or deliberately
    /// floating, never half of each, so the task never silently skips an
    /// image it should be tracking.
    #[test]
    fn the_shipped_containerfiles_are_pinned_or_floating() {
        let dir = crate::repo_root().join(super::CONTAINERS);
        for name in ["Containerfile.egress", "Containerfile.nested"] {
            let text = std::fs::read_to_string(dir.join(name)).expect("readable");
            assert!(
                parse_pin(&text).is_ok() || floating_from(&text).is_some(),
                "{name} is half-pinned: a digest FROM needs `# update-from:`, \
                 a tag FROM must not have one"
            );
        }
    }
}
