//! `cargo xtask update-deps` — the pinned container base images.
//!
//! Every shipped Containerfile pins its base image by digest and names
//! the tag it tracks in a `# update-from: <ref>` comment. This asks the
//! registry (via `skopeo inspect`) for that tag's current digest and
//! reports — or, with `--update`, rewrites — any pin that has moved.
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
                println!("  skipped: {why}");
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
    use super::{Pin, parse_pin};

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

    /// The real Containerfiles stay parseable, so the task never
    /// silently skips the image it exists for.
    #[test]
    fn the_shipped_containerfiles_are_pinned() {
        let dir = crate::repo_root().join(super::CONTAINERS);
        for name in ["Containerfile.egress", "Containerfile.nested"] {
            let text = std::fs::read_to_string(dir.join(name)).expect("readable");
            assert!(parse_pin(&text).is_ok(), "{name} has no usable pin");
        }
    }
}
