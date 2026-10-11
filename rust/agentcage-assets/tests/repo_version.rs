//! The version is written down once, in the root `VERSION` file.
//!
//! `scripts/check-version.sh` enforces agreement between `VERSION`, the
//! Cargo workspace and the CHANGELOG with nothing but a POSIX shell. These
//! tests run it against the tree and pin its failure paths against
//! miniature copies of the three files it reads. The number matters
//! beyond cosmetics: it is `agentcage --version`, the egress image tag
//! and the quadlet `Image=` pin.
//!
//! Lives in `agentcage-assets` because this crate's [`VERSION`] constant
//! is the workspace version the binary stamps into everything it ships.
//!
//! [`VERSION`]: agentcage_assets::VERSION

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is nested at rust/<crate>")
        .to_path_buf()
}

fn version() -> String {
    fs::read_to_string(repo_root().join("VERSION"))
        .expect("VERSION")
        .trim()
        .to_owned()
}

fn run(script: &Path, args: &[&str]) -> Output {
    // Through `sh` rather than exec'ing the copy: a file just written by
    // one test thread can still be open in a child another thread forked,
    // and exec'ing it then fails with ETXTBSY.
    Command::new("sh")
        .arg(script)
        .args(args)
        // A tag build in CI sets these; the script reads them as an
        // implicit tag argument, which is not what these cases test.
        .env_remove("GITHUB_REF_TYPE")
        .env_remove("GITHUB_REF_NAME")
        .output()
        .unwrap_or_else(|e| panic!("{}: {e}", script.display()))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn the_compiled_in_version_is_the_version_file() {
    assert_eq!(agentcage_assets::VERSION, version());
}

#[test]
fn check_version_passes_on_the_tree_as_committed() {
    let out = run(&repo_root().join("scripts/check-version.sh"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
}

/// The guard that keeps `git tag v0.41.0` off a 0.40.1 tree.
#[test]
fn check_version_rejects_a_mismatched_tag() {
    let out = run(
        &repo_root().join("scripts/check-version.sh"),
        &["v99.99.99"],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("does not match VERSION"),
        "{}",
        stderr(&out)
    );
}

/// The member list and the directory tree agree. Cargo errors on a
/// listed member that does not exist, but says nothing about a crate
/// directory nobody listed: it is never built, tested or linted.
#[test]
fn every_crate_directory_is_a_workspace_member() {
    let root = repo_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    let start = manifest.find("members = [").expect("a members list");
    let end = start + manifest[start..].find(']').expect("the list closes");
    let members: Vec<&str> = manifest[start..end]
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix('"'))
        .filter_map(|l| l.split('"').next())
        .collect();
    assert!(!members.is_empty());
    for member in &members {
        assert!(
            root.join(member).join("Cargo.toml").is_file(),
            "{member} is listed but has no Cargo.toml"
        );
    }
    let mut on_disk: Vec<String> = fs::read_dir(root.join("rust"))
        .expect("rust/")
        .filter_map(Result::ok)
        .filter(|e| e.path().join("Cargo.toml").is_file())
        .map(|e| format!("rust/{}", e.file_name().to_string_lossy()))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = members
        .iter()
        .filter(|m| m.starts_with("rust/") && m.matches('/').count() == 1)
        .map(|m| (*m).to_owned())
        .collect();
    listed.sort();
    assert_eq!(listed, on_disk);
}

/// A throwaway tree `check-version.sh` can run against, so the failure
/// paths are exercised without touching the checkout.
fn miniature_repo(cargo_version: &str, crate_manifest: &str) -> (PathBuf, PathBuf) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "agentcage-check-version-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    let v = version();
    fs::create_dir_all(dir.join("rust/agentcage-core")).expect("mkdir");
    fs::create_dir_all(dir.join("scripts")).expect("mkdir");
    fs::write(dir.join("VERSION"), format!("{v}\n")).expect("VERSION");
    fs::write(dir.join("CHANGELOG.md"), format!("## [{v}]\n")).expect("CHANGELOG");
    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[workspace]\nmembers = [\"rust/agentcage-core\"]\n\n\
             [workspace.package]\nversion = \"{cargo_version}\"\n"
        ),
    )
    .expect("Cargo.toml");
    fs::write(dir.join("rust/agentcage-core/Cargo.toml"), crate_manifest).expect("crate");
    let script = dir.join("scripts/check-version.sh");
    fs::copy(repo_root().join("scripts/check-version.sh"), &script).expect("copy script");
    (dir, script)
}

const INHERITING: &str = "[package]\nname = \"agentcage-core\"\nversion.workspace = true\n";

#[test]
fn check_version_accepts_an_agreeing_cargo_workspace() {
    let (dir, script) = miniature_repo(&version(), INHERITING);
    let out = run(&script, &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let _ = fs::remove_dir_all(dir);
}

/// The guard that stops `VERSION` being bumped without Cargo.toml.
#[test]
fn check_version_rejects_a_cargo_version_mismatch() {
    let (dir, script) = miniature_repo("99.99.99", INHERITING);
    let out = run(&script, &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("[workspace.package] version is '99.99.99'"),
        "{}",
        stderr(&out)
    );
    let _ = fs::remove_dir_all(dir);
}

/// A member crate with its own version would win for that crate alone.
#[test]
fn check_version_rejects_a_crate_pinning_its_own_version() {
    let (dir, script) = miniature_repo(
        &version(),
        "[package]\nname = \"agentcage-core\"\nversion = \"0.1.0\"\n",
    );
    let out = run(&script, &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("sets a static version"),
        "{}",
        stderr(&out)
    );
    let _ = fs::remove_dir_all(dir);
}
