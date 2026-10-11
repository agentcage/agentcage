//! The repository invariants CI enforces (`cargo xtask check-invariants`).
//!
//! agentcage is Rust end to end: a static host binary and a static egress
//! binary, with no interpreter anywhere in what ships. Four things would
//! quietly undo that, and none of them would fail any other check:
//!
//! 1. **The host binary shelling out to Python.** Then it is not
//!    self-contained, and an install with no interpreter breaks at
//!    whichever subcommand reaches that line.
//! 2. **A shipped image installing an interpreter.** Every Containerfile
//!    under `src/agentcage/data/` builds an image agentcage runs (the
//!    egress, the nested-podman helper, the apple-container wrapper).
//!    Scaffold Containerfiles are exempt: they build the *workload*,
//!    which is whatever the operator wants.
//!
//! Each check reports independently, so a run says everything that is
//! wrong rather than only the first thing.

use std::path::Path;
use std::process::{Command, ExitCode};

/// Rust files allowed to name a Python interpreter, and why.
///
/// `cage verify` runs a probe INSIDE the cage, where the workload image's
/// interpreter is the subject of the test rather than a dependency of
/// the host binary — the host never executes it.
const RUST_PYTHON_ALLOWED: [(&str, &str); 1] = [(
    "rust/agentcage-cli/src/cli/cage/verify.rs",
    "the in-cage probe: this python3 runs in the workload container, not on the host",
)];

/// One check: the problems it found, empty when the invariant holds.
type Check = fn(&dyn Repo) -> Vec<String>;

/// The tracked files and their contents.
pub(crate) trait Repo {
    /// Every tracked path, POSIX-relative to the root.
    fn files(&self) -> &[String];
    /// A tracked file's bytes, or `None` when it is not a readable file
    /// (a submodule, a deleted-but-staged path).
    fn read(&self, rel: &str) -> Option<Vec<u8>>;
}

/// The checkout on disk, as `git ls-files` lists it.
struct Checkout<'a> {
    root: &'a Path,
    files: Vec<String>,
}

impl Repo for Checkout<'_> {
    fn files(&self) -> &[String] {
        &self.files
    }

    fn read(&self, rel: &str) -> Option<Vec<u8>> {
        let path = self.root.join(rel);
        path.is_file().then(|| std::fs::read(path).ok()).flatten()
    }
}

/// Every tracked file, from `git ls-files`.
fn tracked_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .map_err(|e| format!("cannot run git ls-files: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output
        .stdout
        .split(|b| *b == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect())
}

/// Run every check against the checkout and print the verdicts.
pub(crate) fn run(root: &Path, verbose: bool) -> Result<ExitCode, String> {
    // A tracked path deleted in the working tree is not part of what a
    // commit of it would contain.
    let files = tracked_files(root)?
        .into_iter()
        .filter(|rel| root.join(rel).symlink_metadata().is_ok())
        .collect();
    let repo = Checkout { root, files };
    let checks: [(&str, Check); 2] = [
        ("Rust does not shell out to Python", rust_has_no_python),
        (
            "no shipped image installs an interpreter",
            shipped_images_have_no_interpreter,
        ),
    ];
    let mut failed = 0;
    for (title, check) in checks {
        let problems = check(&repo);
        println!(
            "{} {title}",
            if problems.is_empty() { "ok  " } else { "FAIL" }
        );
        for problem in &problems {
            println!("        {problem}");
        }
        failed += problems.len();
    }
    if verbose {
        println!("\nscanned {} tracked files", repo.files().len());
    }
    if failed > 0 {
        eprintln!("\n{failed} invariant violation(s); see rust/xtask/src/invariants.rs.");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Lines of `bytes`, lossily decoded.
fn lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Check 1: no `"python"` / `"python3"` string literal in the source of
/// a shipped crate (`rust/<crate>/src/**`, not its tests, and not this
/// crate, which never ships).
fn rust_has_no_python(repo: &dyn Repo) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen_allowed = Vec::new();
    for rel in repo.files() {
        let mut parts = rel.split('/');
        let shipped = parts.next() == Some("rust")
            && parts.next().is_some_and(|krate| krate != "xtask")
            && parts.next() == Some("src")
            && Path::new(rel).extension().is_some_and(|ext| ext == "rs");
        if !shipped {
            continue;
        }
        let Some(bytes) = repo.read(rel) else {
            continue;
        };
        for (index, line) in lines(&bytes).iter().enumerate() {
            let stripped = line.trim_start();
            // A comment may discuss python freely; what matters is argv.
            if stripped.starts_with("//") {
                continue;
            }
            if !(line.contains("\"python\"") || line.contains("\"python3\"")) {
                continue;
            }
            if let Some((allowed, _)) = RUST_PYTHON_ALLOWED.iter().find(|(p, _)| p == rel) {
                seen_allowed.push(*allowed);
                continue;
            }
            problems.push(format!(
                "{rel}:{}: Rust must not shell out to a Python interpreter — the binary has to stand alone\n    {stripped}",
                index + 1
            ));
        }
    }
    // An allowlist entry that no longer matches anything is a stale
    // exemption, and a stale exemption is how the next one gets waved
    // through.
    for (rel, why) in RUST_PYTHON_ALLOWED {
        if !seen_allowed.contains(&rel) {
            problems.push(format!(
                "{rel}: allowlisted for '{why}' but names no interpreter any more — drop the entry"
            ));
        }
    }
    problems
}

/// Whether one Containerfile line installs an interpreter package
/// (`python`, `python3`, `python3-minimal`, `python3-pip`, `py3-*`).
fn installs_interpreter(line: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .any(|token| {
            let token = token.to_ascii_lowercase();
            token.starts_with("python") || token.starts_with("py3-")
        })
}

/// Check 2: no Containerfile under `src/agentcage/data/` installs an
/// interpreter or starts from an image that has one by name.
fn shipped_images_have_no_interpreter(repo: &dyn Repo) -> Vec<String> {
    let mut problems = Vec::new();
    for rel in repo.files() {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        if !(rel.starts_with("src/agentcage/data/") && name.starts_with("Containerfile")) {
            continue;
        }
        let Some(bytes) = repo.read(rel) else {
            continue;
        };
        let mut continued = false;
        for (index, line) in lines(&bytes).iter().enumerate() {
            let stripped = line.trim();
            let instruction = stripped
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            // A RUN or FROM line, or a continuation of one; comments
            // and template comments are prose.
            let relevant = continued || instruction == "RUN" || instruction == "FROM";
            continued = relevant && stripped.ends_with('\\');
            if !relevant || stripped.starts_with('#') || stripped.starts_with("{#") {
                continue;
            }
            if installs_interpreter(stripped) {
                problems.push(format!(
                    "{rel}:{}: a shipped image must not carry an interpreter\n    {stripped}",
                    index + 1
                ));
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        Repo, installs_interpreter, rust_has_no_python, shipped_images_have_no_interpreter,
    };

    /// An in-memory repository.
    struct Fake {
        files: Vec<String>,
        contents: BTreeMap<String, Vec<u8>>,
    }

    impl Fake {
        fn new(entries: &[(&str, &str)]) -> Self {
            Self {
                files: entries.iter().map(|(p, _)| (*p).to_owned()).collect(),
                contents: entries
                    .iter()
                    .map(|(p, c)| ((*p).to_owned(), c.as_bytes().to_vec()))
                    .collect(),
            }
        }
    }

    impl Repo for Fake {
        fn files(&self) -> &[String] {
            &self.files
        }

        fn read(&self, rel: &str) -> Option<Vec<u8>> {
            self.contents.get(rel).cloned()
        }
    }

    const VERIFY: (&str, &str) = (
        "rust/agentcage-cli/src/cli/cage/verify.rs",
        "let probe = [\"python3\", \"-c\"];\n",
    );

    #[test]
    fn python_in_rust_is_refused_outside_the_allowlist() {
        let clean = Fake::new(&[
            VERIFY,
            (
                "rust/agentcage-core/src/a.rs",
                "// \"python\" here is prose\n",
            ),
        ]);
        assert!(rust_has_no_python(&clean).is_empty());

        let dirty = Fake::new(&[
            VERIFY,
            (
                "rust/agentcage-core/src/a.rs",
                "Command::new(\"python3\");\n",
            ),
            // Tests and the xtask itself are not shipped.
            (
                "rust/agentcage-core/tests/t.rs",
                "Command::new(\"python3\");\n",
            ),
            ("rust/xtask/src/x.rs", "Command::new(\"python\");\n"),
        ]);
        let problems = rust_has_no_python(&dirty);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("rust/agentcage-core/src/a.rs:1:"));

        // A stale allowlist entry is itself a failure.
        let stale = Fake::new(&[(
            "rust/agentcage-cli/src/cli/cage/verify.rs",
            "fn main() {}\n",
        )]);
        assert_eq!(rust_has_no_python(&stale).len(), 1);
    }

    #[test]
    fn interpreter_packages_are_recognised() {
        assert!(installs_interpreter("RUN apt-get install -y python3"));
        assert!(installs_interpreter("    python3-minimal \\"));
        assert!(installs_interpreter("RUN apk add py3-yaml"));
        assert!(installs_interpreter(
            "FROM docker.io/library/python:3.12-alpine"
        ));
        assert!(!installs_interpreter("RUN apt-get install -y dnsmasq jq"));
        assert!(!installs_interpreter(
            "COPY bin/agentcage-egress /opt/agentcage/"
        ));
    }

    #[test]
    fn shipped_containerfiles_may_not_install_an_interpreter() {
        let repo = Fake::new(&[
            (
                "src/agentcage/data/containers/Containerfile.egress",
                "# python is not here\nFROM debian\nRUN apt-get install -y \\\n    jq \\\n    python3\n",
            ),
            // Scaffolds build the workload; exempt.
            (
                "src/agentcage/scaffolds/codex/Containerfile",
                "RUN apt-get install -y python3\n",
            ),
        ]);
        let problems = shipped_images_have_no_interpreter(&repo);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("Containerfile.egress:5:"));
    }
}
