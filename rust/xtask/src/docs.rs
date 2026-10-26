//! `cargo xtask check-docs` — live documentation against the CLI and release.
//!
//! Prose is not reviewable by a machine, so this checks only the claims a
//! regression silently falsifies:
//!
//! 1. **Install examples pin the current release.** A `cargo install ...
//!    --tag vX.Y.Z` in the README or install guide that names an older
//!    version sends readers to a stale release every time VERSION moves.
//! 2. **`AGENTCAGE_VERSION` pins name the current release.** The install
//!    guide tells readers to set `AGENTCAGE_VERSION=x.y.z` to pick a
//!    release, so a concrete pin there (or in the README) rots the same
//!    way the `--tag` examples do. A placeholder such as
//!    `AGENTCAGE_VERSION=<version>` is deliberately not pinned and passes.
//! 3. **No `dns` log service.** `cage logs` (and `cage exec` / `cage shell`)
//!    accept exactly `cage` and `egress`; DNS runs inside the egress
//!    service, so `-s dns` names a service that does not exist. The check
//!    reads prose as well as fenced commands, so ``Use `-s dns`.`` is
//!    caught, not only a `bash` example.
//! 4. **Fenced service examples use an allowed value.** This is the same
//!    rule as (3), stated as a value check so a future flag spelling is
//!    caught, not only the literal `-s dns`.
//! 5. **The install docs describe how the installer actually works.** Its
//!    default path installs the release's prebuilt binary, and `--build`
//!    compiles from source; the old "builds from source with cargo" default
//!    was wrong for the current installer.
//!
//! History and planning records are exempt: `docs/history/`, `docs/roadmap/`
//! and CHANGELOG entries describe what the product used to do, or discuss it,
//! and are allowed to keep doing so.

use std::path::Path;
use std::process::{Command, ExitCode};

/// The `-s/--service` values the CLI accepts (`cli/args.rs::SERVICES`).
const SERVICES: [&str; 2] = ["cage", "egress"];

/// Files whose pinned release references (`cargo install --tag`,
/// `AGENTCAGE_VERSION=`) must name `VERSION`.
const PINNED_INSTALL_DOCS: [&str; 2] = ["README.md", "docs/get-started/install.md"];

/// The environment variable that pins the release `install.sh` fetches.
const VERSION_ENV: &str = "AGENTCAGE_VERSION";

/// One check: the problems it found, empty when the documentation holds.
type Check = fn(&dyn Docs, &str) -> Vec<String>;

/// The tracked live Markdown files and their contents.
pub(crate) trait Docs {
    /// Every live documentation path, POSIX-relative to the root.
    fn paths(&self) -> &[String];
    /// A file's contents, or `None` when it is not readable text.
    fn read(&self, rel: &str) -> Option<String>;
}

/// The checkout on disk, as `git ls-files` lists it.
struct Checkout<'a> {
    root: &'a Path,
    paths: Vec<String>,
}

impl Docs for Checkout<'_> {
    fn paths(&self) -> &[String] {
        &self.paths
    }

    fn read(&self, rel: &str) -> Option<String> {
        let path = self.root.join(rel);
        path.is_file()
            .then(|| std::fs::read_to_string(path).ok())
            .flatten()
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

/// Whether a path is live documentation rather than history or a changelog.
fn is_live_doc(rel: &str) -> bool {
    Path::new(rel)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
        && rel != "CHANGELOG.md"
        && !rel.starts_with("docs/history/")
        && !rel.starts_with("docs/roadmap/")
}

/// Run every documentation check against the checkout and print the verdicts.
pub(crate) fn run(root: &Path, verbose: bool) -> Result<ExitCode, String> {
    let paths = tracked_files(root)?
        .into_iter()
        .filter(|rel| is_live_doc(rel) && root.join(rel).symlink_metadata().is_ok())
        .collect();
    let repo = Checkout { root, paths };
    let version = repo
        .read("VERSION")
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .ok_or("VERSION is missing or empty")?;

    let checks: [(&str, Check); 5] = [
        ("install examples pin the VERSION tag", pinned_install_tags),
        (
            "AGENTCAGE_VERSION pins name the current release",
            pinned_version_env,
        ),
        ("no live doc names a dns log service", no_dns_service),
        (
            "fenced service examples use cage or egress",
            documented_service_values,
        ),
        (
            "install docs document the prebuilt installer and --build",
            installer_docs,
        ),
    ];

    let mut failed = 0;
    for (title, check) in checks {
        let problems = check(&repo, &version);
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
        println!("\nscanned {} live Markdown files", repo.paths().len());
        println!(
            "scanned {} release-pinned docs: {}",
            PINNED_INSTALL_DOCS.len(),
            PINNED_INSTALL_DOCS.join(", ")
        );
    }
    if failed > 0 {
        eprintln!("\n{failed} documentation violation(s); see rust/xtask/src/docs.rs.");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Every `--tag` value on a command line.
fn tags_on_line(line: &str) -> Vec<&str> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut tags = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if *token == "--tag" {
            if let Some(tag) = tokens.get(index + 1) {
                tags.push(*tag);
            }
        } else if let Some(tag) = token.strip_prefix("--tag=") {
            tags.push(tag);
        }
    }
    tags
}

/// Whether a value is a concrete release (`1.2.3`), not a placeholder
/// (`<version>`, `master`) that is deliberately not pinned.
fn is_concrete_version(value: &str) -> bool {
    !value.is_empty()
        && value.contains('.')
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
}

/// Whether a tag is a concrete release (`v1.2.3`), not a placeholder
/// (`v<version>`) that is deliberately not pinned.
fn is_release_tag(tag: &str) -> bool {
    tag.strip_prefix('v').is_some_and(is_concrete_version)
}

/// Check 1: a pinned `cargo install --tag` names the current VERSION.
fn pinned_install_tags(repo: &dyn Docs, version: &str) -> Vec<String> {
    let expected = format!("v{version}");
    let mut problems = Vec::new();
    for rel in PINNED_INSTALL_DOCS {
        let Some(text) = repo.read(rel) else {
            problems.push(format!("{rel}: install guide is missing"));
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if !line.contains("cargo install") {
                continue;
            }
            for tag in tags_on_line(line) {
                if is_release_tag(tag) && tag != expected {
                    problems.push(format!(
                        "{rel}:{}: `cargo install ... --tag {tag}` is stale; VERSION is {version} \
                         (use {expected})\n    {line}",
                        index + 1
                    ));
                }
            }
        }
    }
    problems
}

/// Every `AGENTCAGE_VERSION=x.y.z` value on a line.
///
/// The env var is written inside inline code in the install guide
/// (``set `AGENTCAGE_VERSION=0.53.1` ``), so the token is trimmed of its
/// backticks and sentence punctuation before the prefix is read.
fn version_env_values(line: &str) -> Vec<&str> {
    let mut values = Vec::new();
    for token in line.split_whitespace() {
        let token = trim_token(token);
        let Some(value) = token.strip_prefix(VERSION_ENV) else {
            continue;
        };
        if let Some(value) = value.strip_prefix('=') {
            values.push(trim_token(value));
        }
    }
    values
}

/// Check 2: a pinned `AGENTCAGE_VERSION` names the current VERSION.
fn pinned_version_env(repo: &dyn Docs, version: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for rel in PINNED_INSTALL_DOCS {
        let Some(text) = repo.read(rel) else {
            problems.push(format!("{rel}: install guide is missing"));
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            for value in version_env_values(line) {
                if is_concrete_version(value) && value != version {
                    problems.push(format!(
                        "{rel}:{}: `{VERSION_ENV}={value}` pins an old release; VERSION is \
                         {version} (drop the pin, or set {VERSION_ENV}={version})\n    {line}",
                        index + 1
                    ));
                }
            }
        }
    }
    problems
}

/// A token with Markdown and sentence punctuation trimmed, so a flag or
/// value written inline (`` -s ``, `` `dns`. ``, `` `[cage]` ``) compares
/// as the CLI sees it.
///
/// The sentence punctuation matters as much as the backticks: prose such
/// as ``Use `-s dns`.`` ends the value with a full stop, and the flag with
/// an opening backtick (and, when a line break falls there, nothing).
fn trim_token(token: &str) -> &str {
    token.trim_matches(|character: char| {
        matches!(
            character,
            '`' | '\'' | '"' | '[' | ']' | '(' | ')' | ',' | ';' | ':' | '.' | '!' | '?'
        )
    })
}

/// Every `-s`/`--service` value on a line, prose included.
fn all_service_values(line: &str) -> Vec<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut values = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let token = trim_token(token);
        if token == "-s" || token == "--service" {
            if let Some(value) = tokens.get(index + 1) {
                values.push(trim_token(value).to_owned());
            }
        } else if let Some(value) = token
            .strip_prefix("-s=")
            .or_else(|| token.strip_prefix("--service="))
        {
            values.push(trim_token(value).to_owned());
        }
    }
    values
}

/// The `-s`/`--service` values on one `agentcage logs|exec|shell` example.
///
/// The short `-s` is overloaded (`run -s KEY` sets a secret, `watcher
/// findings -s high` sets a severity), so only the commands that own a
/// service option are parsed here.
fn command_service_values(line: &str) -> Vec<String> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix('$').map_or(trimmed, str::trim_start);
    let tokens: Vec<&str> = trimmed
        .split_whitespace()
        .take_while(|token| !token.starts_with('#'))
        .collect();
    let mut index = match tokens.first().copied() {
        Some("agentcage") => 1,
        Some("cage") => 0,
        _ => return Vec::new(),
    };
    if tokens.get(index).copied() == Some("cage") {
        index += 1;
    }
    let Some(command) = tokens.get(index).copied() else {
        return Vec::new();
    };
    if !matches!(command, "logs" | "exec" | "shell") {
        return Vec::new();
    }
    index += 1;

    let mut values = Vec::new();
    while index < tokens.len() {
        let token = tokens[index];
        if token == "--" {
            break;
        }
        let flag = trim_token(token);
        if flag == "-s" || flag == "--service" {
            if let Some(value) = tokens.get(index + 1) {
                values.push(trim_token(value).to_owned());
            }
            index += 2;
            continue;
        }
        if let Some(value) = flag
            .strip_prefix("-s=")
            .or_else(|| flag.strip_prefix("--service="))
        {
            values.push(trim_token(value).to_owned());
        }
        index += 1;
    }
    values
}

/// Check 3: no live doc, in prose or a command, names `dns` as a service.
fn no_dns_service(repo: &dyn Docs, _version: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for rel in repo.paths() {
        if !is_live_doc(rel) {
            continue;
        }
        let Some(text) = repo.read(rel) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if all_service_values(line).iter().any(|value| value == "dns") {
                problems.push(format!(
                    "{rel}:{}: `dns` is not a service; DNS runs inside the egress service — use \
                     `-s egress`\n    {}",
                    index + 1,
                    line.trim()
                ));
            }
        }
    }
    problems
}

/// Check 4: every service value in a fenced command example is allowed.
fn documented_service_values(repo: &dyn Docs, _version: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for rel in repo.paths() {
        if !is_live_doc(rel) {
            continue;
        }
        let Some(text) = repo.read(rel) else {
            continue;
        };
        let mut fence: Option<char> = None;
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            let marker = if trimmed.starts_with("```") {
                Some('`')
            } else if trimmed.starts_with("~~~") {
                Some('~')
            } else {
                None
            };
            if let Some(marker) = marker {
                match fence {
                    None => fence = Some(marker),
                    Some(open) if open == marker => fence = None,
                    Some(_) => {}
                }
                continue;
            }
            if fence.is_none() {
                continue;
            }
            for value in command_service_values(line) {
                if !SERVICES.contains(&value.as_str()) {
                    problems.push(format!(
                        "{rel}:{}: `{value}` is not a valid `-s/--service` value (allowed: cage, \
                         egress)\n    {}",
                        index + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    problems
}

/// Check 5: the install docs name the prebuilt default and `--build` opt-out.
fn installer_docs(repo: &dyn Docs, _version: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for rel in PINNED_INSTALL_DOCS {
        let Some(text) = repo.read(rel) else {
            problems.push(format!("{rel}: install guide is missing"));
            continue;
        };
        if !text.to_ascii_lowercase().contains("prebuilt") {
            problems.push(format!(
                "{rel}: the install instructions must say the release's prebuilt binary is the default"
            ));
        }
        if !text.contains("--build") {
            problems.push(format!(
                "{rel}: the install instructions must document `--build` for building from source"
            ));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        Docs, documented_service_values, installer_docs, no_dns_service, pinned_install_tags,
        pinned_version_env,
    };

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    /// Fixture files on disk, removed when the test ends.
    #[derive(Debug)]
    struct TempTree {
        root: PathBuf,
        paths: Vec<String>,
    }

    impl TempTree {
        fn new(entries: &[(&str, &str)]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("agentcage-check-docs-{}-{id}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("create the fixture root");
            for (rel, text) in entries {
                let path = root.join(rel);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).expect("create a fixture directory");
                }
                std::fs::write(path, text).expect("write a fixture file");
            }
            Self {
                root,
                paths: entries.iter().map(|(rel, _)| (*rel).to_owned()).collect(),
            }
        }
    }

    impl Docs for TempTree {
        fn paths(&self) -> &[String] {
            &self.paths
        }

        fn read(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(self.root.join(rel)).ok()
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn stale_cargo_install_tags_are_refused() {
        let clean = TempTree::new(&[
            (
                "README.md",
                "cargo install --locked --git https://example.invalid/repo --tag v0.53.1 agentcage-cli\n",
            ),
            (
                "docs/get-started/install.md",
                "cargo install --locked --git https://example.invalid/repo --tag v<version> agentcage-cli\n",
            ),
        ]);
        assert!(pinned_install_tags(&clean, "0.53.1").is_empty());

        let stale = TempTree::new(&[
            (
                "README.md",
                "cargo install --locked --git https://example.invalid/repo --tag v0.50.0 agentcage-cli\n",
            ),
            (
                "docs/get-started/install.md",
                "cargo install --locked --git https://example.invalid/repo --tag v0.53.1 agentcage-cli\n",
            ),
        ]);
        let problems = pinned_install_tags(&stale, "0.53.1");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("README.md:1:"));
        assert!(problems[0].contains("v0.53.1"));
    }

    #[test]
    fn stale_version_env_pins_are_refused() {
        let clean = TempTree::new(&[
            ("README.md", "No pin here.\n"),
            (
                "docs/get-started/install.md",
                "To pick a release, set `AGENTCAGE_VERSION=0.53.1` (the default is the latest \
                 release) or leave it unset.\n\
                 A placeholder such as `AGENTCAGE_VERSION=<version>` is not a pin.\n",
            ),
        ]);
        assert!(pinned_version_env(&clean, "0.53.1").is_empty());

        let stale = TempTree::new(&[
            (
                "README.md",
                "Pinned: `AGENTCAGE_VERSION=0.52.0`, the previous release.\n",
            ),
            (
                "docs/get-started/install.md",
                "To pick a release, set `AGENTCAGE_VERSION=0.50.3` (the default is the latest \
                 release).\n",
            ),
        ]);
        let problems = pinned_version_env(&stale, "0.53.1");
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].starts_with("README.md:1:"));
        assert!(problems[0].contains("AGENTCAGE_VERSION=0.52.0"));
        assert!(problems[1].starts_with("docs/get-started/install.md:1:"));
        assert!(problems[1].contains("AGENTCAGE_VERSION=0.50.3"));
        assert!(problems[1].contains("VERSION is 0.53.1"));
    }

    #[test]
    fn inline_code_dns_service_is_refused() {
        let repo = TempTree::new(&[
            (
                "README.md",
                "Use `-s dns`. DNS runs inside the egress.\n\
                 Use `-s egress` instead.\n",
            ),
            (
                "docs/get-started/quickstart.md",
                "Pull the log for one service with `-s dns` or `--service=dns`.\n\
                 The proxy is `-s egress`.\n",
            ),
        ]);
        let problems = no_dns_service(&repo, "0.53.1");
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].starts_with("README.md:1:"), "{problems:?}");
        assert!(
            problems[1].starts_with("docs/get-started/quickstart.md:1:"),
            "{problems:?}"
        );

        let clean = TempTree::new(&[(
            "README.md",
            "Use `-s egress`. The proxy carries DNS.\n\
             The flag is `-s`, and `-s=cage` is the workload log.\n",
        )]);
        assert!(no_dns_service(&clean, "0.53.1").is_empty());
    }

    #[test]
    fn dns_is_not_a_log_service() {
        let repo = TempTree::new(&[
            ("README.md", "agentcage cage logs box -s dns\n"),
            (
                "docs/history/old-plan.md",
                "agentcage cage logs box -s dns\n",
            ),
            (
                "docs/roadmap/bugs/560-dns-log-service.md",
                "agentcage cage logs box -s dns\n",
            ),
        ]);
        let problems = no_dns_service(&repo, "0.53.1");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("README.md:1:"));
        assert!(problems[0].contains("-s egress"));
    }

    #[test]
    fn service_examples_must_use_a_known_value() {
        let repo = TempTree::new(&[(
            "README.md",
            "```bash\n\
             agentcage cage logs box -s egress\n\
             agentcage cage exec box --service cage -- true\n\
             agentcage run claude-code -s ANTHROPIC_API_KEY\n\
             agentcage watcher findings box -s high\n\
             $ agentcage cage shell box -s=proxy\n\
             ```\n",
        )]);
        let problems = documented_service_values(&repo, "0.53.1");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("proxy"));
        assert!(problems[0].contains("README.md:6:"));
    }

    #[test]
    fn install_docs_describe_the_prebuilt_installer() {
        let current = TempTree::new(&[
            (
                "README.md",
                "The installer downloads the prebuilt release binary; pass --build to compile it.\n",
            ),
            (
                "docs/get-started/install.md",
                "The release's prebuilt binary is the default; --build compiles from source.\n",
            ),
        ]);
        assert!(installer_docs(&current, "0.53.1").is_empty());

        let old = TempTree::new(&[
            ("README.md", "It builds agentcage from source with cargo.\n"),
            (
                "docs/get-started/install.md",
                "It builds agentcage from source with cargo.\n",
            ),
        ]);
        let problems = installer_docs(&old, "0.53.1");
        assert_eq!(problems.len(), 4, "{problems:?}");
    }
}
