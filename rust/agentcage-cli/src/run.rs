//! `run.py` — the ephemeral cage.
//!
//! ```text
//! agentcage run <scaffold> [--project DIR] [--name NAME]
//!      │
//!      ├─ resolve scaffold → render config
//!      ├─ auto-generate name if needed
//!      ├─ build image + deploy cage
//!      ├─ run the session to completion   ← returns on exit
//!      └─ finally: stop cage (state dir preserved)
//! ```
//!
//! # How an ephemeral cage differs from one `cage create` made
//!
//! Only in four places, and they are all in this file:
//!
//! * **The config is never the operator's.** It is rendered from the
//!   scaffold into a temporary directory, `save_deployment` copies it
//!   into the cage's state dir, and the temporary copy is deleted on the
//!   way out. There is no `cage.yaml` for the operator to edit, which is
//!   why every secret the scaffold declares has to arrive on the command
//!   line.
//! * **The name is generated** unless `--name` is given, from the
//!   scaffold's own `name_prefix` and a Docker-style adjective/noun
//!   pair, checked against the cages that already exist.
//! * **The session owns the foreground.** `run` deploys, hands the
//!   terminal to the workload, and only returns when that exits.
//! * **It stops the cage on the way out — and only stops it.** The
//!   deployment directory, the quadlets, the named volumes and the
//!   podman secrets all survive, so `cage audit <name>` still works
//!   afterwards and `cage start <name>` brings the same cage back. An
//!   ephemeral cage is ephemeral in its *session*, not in its state;
//!   `cage destroy` is still the only thing that removes one. The name
//!   collision check at the top is what makes that safe to repeat.
//!
//! Everything else — the secret pre-flight, the port check, the
//! placeholder fill, the build, the deploy — is `cage create`'s path,
//! called in `cage create`'s order.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentcage_core::config::Config;
use agentcage_core::quadlets::QuadletHost;
use agentcage_exec::{Command, CommandRunner};
use agentcage_state::Paths;

use crate::scaffold::{RenderRequest, Scaffolds, SetupOptions, TempDir};

/// `run._ADJECTIVES`.
const ADJECTIVES: [&str; 50] = [
    "bold", "brave", "bright", "calm", "cool", "dark", "deep", "dry", "fair", "fast", "firm",
    "free", "glad", "gold", "good", "gray", "keen", "kind", "late", "lean", "long", "mild", "neat",
    "new", "odd", "old", "pale", "pure", "rare", "raw", "red", "rich", "safe", "shy", "slim",
    "soft", "tall", "thin", "warm", "wide", "wild", "wise", "blue", "grim", "hale", "lush", "prim",
    "tame", "true", "vast",
];

/// `run._NOUNS`.
const NOUNS: [&str; 50] = [
    "ant", "bay", "bee", "cod", "cow", "dew", "doe", "elm", "elk", "emu", "ewe", "fig", "fox",
    "gem", "gnu", "hog", "ivy", "jay", "kit", "lad", "log", "mew", "nit", "oak", "orb", "owl",
    "pea", "ram", "ray", "roe", "rue", "rye", "sap", "sky", "sow", "sun", "tar", "tern", "tic",
    "vow", "wax", "web", "yak", "yam", "yew", "zap", "ash", "birch", "fern", "hawk",
];

/// `run.generate_name` — `<prefix>-<adjective>-<noun>`, unused.
///
/// The prefix comes from the scaffold's `name_prefix`, falling back to
/// the scaffold's own name. A hundred attempts, and then it gives up —
/// 2,500 combinations per prefix means a collision streak that long is a
/// machine with an implausible number of cages, not bad luck.
///
/// # Errors
///
/// The Python's `RuntimeError` message, as a string.
pub fn generate_name(
    paths: &Paths,
    scaffolds: &Scaffolds,
    scaffold: &str,
) -> Result<String, String> {
    let prefix = scaffolds.name_prefix(scaffold);
    let existing: BTreeSet<String> = paths
        .list_deployments()
        .unwrap_or_default()
        .into_iter()
        .collect();
    for _ in 0..100 {
        let adjective = ADJECTIVES[pick(ADJECTIVES.len())];
        let noun = NOUNS[pick(NOUNS.len())];
        let name = format!("{prefix}-{adjective}-{noun}");
        if !existing.contains(&name) {
            return Ok(name);
        }
    }
    Err("Could not generate a unique cage name after 100 attempts".to_owned())
}

/// `random.choice` over a list of `len` items.
///
/// From `/dev/urandom`, because the binary carries no PRNG and this is
/// the only place that needs one. Modulo bias over 50 items out of 2^64
/// is far below anything that matters for picking a word.
fn pick(len: usize) -> usize {
    use std::io::Read as _;

    let mut bytes = [0u8; 8];
    if fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_err()
    {
        return 0;
    }
    usize::try_from(u64::from_be_bytes(bytes) % len as u64).unwrap_or(0)
}

/// `run._resolve_exec_cmd` — what the session runs.
///
/// With `--` extras, they are a **complete** command, binary included:
/// `agentcage run codex -- codex --help` runs `codex --help`, not
/// `codex codex --help`. Before that was fixed the alias was prepended
/// even when extras were given, so
/// `run claude-code -- claude --dangerously-skip-permissions -p "<prompt>"`
/// became `claude claude …`, and claude read the second `claude` as its
/// positional prompt and ignored `-p` — the agent answered "claude"
/// instead of the operator's actual question.
///
/// Without extras: the scaffold's first `exec_alias`, else `/bin/bash`.
#[must_use]
pub fn resolve_exec_cmd(config: &Config, extra_args: &[String]) -> Vec<String> {
    if !extra_args.is_empty() {
        return extra_args.to_vec();
    }
    if let Some((_, alias)) = config.exec_aliases.iter().next() {
        return alias.clone();
    }
    vec!["/bin/bash".to_owned()]
}

/// `run._vm_podman_prefix` — how to reach podman for a cage.
///
/// There is no host podman on the vm backend; containers run inside the
/// Lima VM.
#[must_use]
pub fn vm_podman_prefix(isolation: &str, name: &str) -> Vec<String> {
    if isolation == "vm" {
        vec![
            "limactl".to_owned(),
            "shell".to_owned(),
            format!("agentcage-{name}"),
            "--".to_owned(),
        ]
    } else {
        Vec::new()
    }
}

/// `run._ensure_volume_dirs` — create missing bind-mount sources.
///
/// Scaffolds may declare host bind-mounts for state persistence, and on
/// a fresh machine the source may not exist. podman cannot bind-mount a
/// missing source and the quadlet layer skips it, so a login inside the
/// cage would never round-trip to the host.
///
/// Three things are deliberately left alone: a source that still carries
/// an unexpanded `${VAR}` (not ours to invent), one whose basename has
/// an extension (it looks like a file, and a single file cannot be
/// shared into a Lima VM), and anything outside the home directory.
pub fn ensure_volume_dirs(volumes: &[String], host: &dyn QuadletHost) {
    let home = host.realpath(&agentcage_core::quadlets::expanduser("~", host));
    for volume in volumes {
        let host_part = volume.split(':').next().unwrap_or_default();
        let expanded = agentcage_core::quadlets::expandvars(
            &agentcage_core::quadlets::expanduser(host_part, host),
            host,
        );
        if expanded.contains('$') {
            continue; // unresolved variable — not ours to create
        }
        let real = host.realpath(&expanded);
        if Path::new(&real).exists() {
            continue;
        }
        let basename = Path::new(&real)
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        // `os.path.splitext(basename)[1]` — a leading dot is not an
        // extension, so `.bashrc` is still a directory candidate.
        if basename.trim_start_matches('.').contains('.') {
            continue; // looks like a file — leave it to the skip logic
        }
        if real == home || real.starts_with(&format!("{home}/")) {
            let _ = fs::create_dir_all(&real);
        }
    }
}

/// `run._stage_scaffold_build_context` — freeze the scaffold's build
/// context into the cage's state dir.
///
/// So a later `cage update` can rebuild from the state dir without the
/// scaffold being reachable. Sibling *files* are copied (config
/// templates excluded), and then the canonical `AGENTS.md` and
/// `skills/agentcage` are staged for the Containerfile's `COPY` lines —
/// a rebuild without them fails at the `COPY`, because the scaffold
/// directory deliberately ships neither.
pub fn stage_scaffold_build_context(
    paths: &Paths,
    scaffolds: &Scaffolds,
    scaffold: &str,
    containerfile: &str,
    name: &str,
) {
    let Some(dir) = scaffolds.resolve(scaffold) else {
        return;
    };
    let source = dir.join(containerfile);
    if !source.is_file() {
        return;
    }
    let Some(dest) = paths
        .stored_config_path(name)
        .parent()
        .map(Path::to_path_buf)
    else {
        return;
    };
    if let Err(error) = fs::create_dir_all(&dest) {
        eprintln!("warning: could not stage the build context: {error}");
        return;
    }
    // Files only, and no `.yaml` / `.yml` / `.j2`: the Python's
    // `_stage_scaffold_build_context` copies siblings rather than
    // recursing, unlike `cli._stage_build_context`.
    if let Ok(entries) = fs::read_dir(dir) {
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| matches!(e, "yaml" | "yml" | "j2"))
            {
                continue;
            }
            let target = dest.join(entry.file_name());
            let _ = fs::remove_file(&target);
            let _ = fs::copy(&path, &target);
        }
    }
    let _ = crate::staging::stage_scaffold_assets(&source, &dest, scaffold);
}

// ── the proxy monitor ────────────────────────────────────────

/// A running `podman logs -f <proxy>` reader.
///
/// Held by [`execute`] for the life of the session and stopped in its
/// cleanup. Dropping it sets the stop flag; the thread notices on its
/// next line and exits, and the child is reaped when the stream is
/// dropped with it.
#[derive(Debug)]
pub struct ProxyMonitor {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ProxyMonitor {
    /// Tail the proxy's log and print blocked-request notifications.
    ///
    /// Writes to `/dev/tty` rather than to stdout, because the
    /// interactive session owns the process's stdout for as long as it
    /// runs. No tty (CI, a pipe) means no monitor, which is the
    /// Python's `except OSError: return`.
    ///
    /// stdin is `/dev/null`. On the vm backend the command is wrapped in
    /// `limactl shell` → ssh, and ssh reads its stdin to forward it to
    /// the remote side; inheriting the terminal makes it race the
    /// interactive session for the operator's keystrokes, and roughly
    /// half of them get eaten.
    #[must_use]
    pub fn start(
        runner: Arc<dyn CommandRunner>,
        prefix: &[String],
        container: &str,
    ) -> Option<Self> {
        let mut tty = fs::OpenOptions::new().write(true).open("/dev/tty").ok()?;
        let mut argv: Vec<String> = prefix.to_vec();
        argv.extend([
            "podman".to_owned(),
            "logs".to_owned(),
            "-f".to_owned(),
            container.to_owned(),
        ]);
        let (head, tail) = argv.split_first()?;
        let command = Command::new(head.clone())
            .args(tail.to_vec())
            .stdin_null()
            .merge_stderr();

        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("agentcage-proxy-monitor".to_owned())
            .spawn(move || {
                let Ok(mut lines) = runner.stream(&command) else {
                    return;
                };
                while let Some(line) = lines.next_line() {
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Some(notice) = blocked_notice(&line) {
                        let _ = tty.write_all(notice.as_bytes());
                        let _ = tty.flush();
                    }
                }
            })
            .ok()?;
        Some(Self {
            stop,
            handle: Some(handle),
        })
    }

    /// Ask the thread to stop and wait for it.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // Detached rather than joined: the thread is parked in a
            // blocking read on the child's stdout, and it only notices
            // the flag when the next line arrives. The Python joins with
            // a three-second timeout and moves on for the same reason;
            // Rust has no timed join, and leaving it is what the timeout
            // amounts to.
            drop(handle);
        }
    }
}

impl Drop for ProxyMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One audit line, turned into the terminal notice — or `None`.
///
/// Only `"decision": "blocked"` entries produce anything, and a line
/// that is not JSON at all is skipped rather than reported: the proxy's
/// log carries mitmproxy's own chatter as well.
fn blocked_notice(line: &str) -> Option<String> {
    const DIM: &str = "\x1b[2m";
    const RED: &str = "\x1b[31m";
    const RESET: &str = "\x1b[0m";

    let line = line.trim();
    if line.is_empty() || !line.contains("\"decision\"") {
        return None;
    }
    let entry = agentcage_core::har::json::parse(line).ok()?;
    if entry
        .get("decision")
        .and_then(agentcage_core::har::json::Json::as_str)
        != Some("blocked")
    {
        return None;
    }
    let host = entry
        .get("host")
        .and_then(agentcage_core::har::json::Json::as_str)
        .unwrap_or("?");
    let reason = entry
        .get("reason")
        .and_then(agentcage_core::har::json::Json::as_str)
        .unwrap_or("blocked");
    Some(format!(
        "\r{DIM}[agentcage]{RESET} {RED}blocked{RESET} {DIM}\u{2192}{RESET} {host} {DIM}({reason}){RESET}\n"
    ))
}

// ── the temporary config ─────────────────────────────────────

/// The rendered config, written where `load_config` can read it.
///
/// A directory rather than a file, because `load_config` resolves
/// `containerfile:` relative to the config's own directory and the
/// Python hands it a `tempfile.mkdtemp()` for exactly that reason.
#[derive(Debug)]
pub struct StagedConfig {
    dir: TempDir,
}

impl StagedConfig {
    /// Write `text` to `<tmp>/cage.yaml`.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the directory or the file cannot be
    /// written.
    pub fn write(text: &str) -> std::io::Result<Self> {
        let dir = TempDir::new("agentcage-run-")?;
        fs::write(dir.path().join("cage.yaml"), text)?;
        Ok(Self { dir })
    }

    /// The config's path.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.path().join("cage.yaml")
    }
}

/// `SetupOptions` for the host build loop, given a cage's isolation.
#[must_use]
pub fn setup_options(isolation: &str, quiet: bool, no_cache: bool, pull: bool) -> SetupOptions<'_> {
    SetupOptions {
        isolation: Some(isolation),
        quiet,
        no_cache,
        pull,
    }
}

/// The render `run` performs: the scaffold's template, this cage's name,
/// this host's isolation, and no port override.
#[must_use]
pub fn render_request<'a>(
    name: &'a str,
    scaffold: &'a str,
    isolation: &'a str,
) -> RenderRequest<'a> {
    RenderRequest {
        name,
        image: "",
        isolation,
        scaffold: Some(scaffold),
        port: None,
    }
}

/// `--set-secret` specs, split into `(key, value)` with a prompt for a
/// bare `KEY`.
///
/// # Errors
///
/// The message to report when the terminal cannot be read.
pub fn parse_set_secrets(specs: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut parsed = Vec::with_capacity(specs.len());
    for spec in specs {
        if let Some((key, value)) = spec.split_once('=') {
            parsed.push((key.to_owned(), value.to_owned()));
        } else {
            let value = crate::terminal::prompt_hidden(&format!("Value for {spec}"))
                .map_err(|error| format!("could not read a value for {spec}: {error}"))?;
            parsed.push((spec.clone(), value));
        }
    }
    Ok(parsed)
}

/// `run._stage_set_secrets` for the `vm` backend — write
/// `pending_secrets.json` at mode 0600.
///
/// There is no host podman on the vm backend, so the values are staged
/// for the backend to create *inside* the VM (and then unlink). The
/// apple-container backend deliberately does not use this path: it
/// re-stages from the cage's configured at-rest store at every start,
/// and a `pending_secrets.json` it never reads would be a file full of
/// credentials that did nothing.
///
/// # Errors
///
/// [`std::io::Error`] from the write.
pub fn stage_pending_secrets(
    paths: &Paths,
    name: &str,
    parsed: &[(String, String)],
) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if parsed.is_empty() {
        return Ok(());
    }
    let pairs: Vec<agentcage_core::har::json::Json> = parsed
        .iter()
        .map(|(key, value)| {
            agentcage_core::har::json::Json::Array(vec![
                agentcage_core::har::json::Json::string(key),
                agentcage_core::har::json::Json::string(value),
            ])
        })
        .collect();
    let body = agentcage_core::har::json::dumps(
        &agentcage_core::har::json::Json::Array(pairs),
        agentcage_core::har::json::DumpOptions::default(),
    );
    let path = paths.pending_secrets_path(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(body.as_bytes())
}

/// Delete a deployment, ignoring the failure.
///
/// The cleanup path on a failed build: the Python's
/// `if state.deployment_exists(...): state.remove_deployment(...)`.
pub fn discard_deployment(paths: &Paths, name: &str) {
    if paths.deployment_exists(name) {
        let _ = paths.remove_deployment(name);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ADJECTIVES, NOUNS, blocked_notice, ensure_volume_dirs, resolve_exec_cmd, vm_podman_prefix,
    };
    use agentcage_core::config::Config;

    #[test]
    fn the_word_lists_are_the_pythons() {
        assert_eq!(ADJECTIVES.len(), 50);
        assert_eq!(NOUNS.len(), 50);
        assert_eq!(ADJECTIVES[0], "bold");
        assert_eq!(NOUNS[NOUNS.len() - 1], "hawk");
    }

    /// Extras replace the alias entirely — the regression the Python's
    /// docstring is mostly about.
    #[test]
    fn extras_are_a_complete_command_and_never_prefixed() {
        let mut config = Config::default();
        config
            .exec_aliases
            .insert("claude".to_owned(), vec!["claude".to_owned()]);
        assert_eq!(
            resolve_exec_cmd(
                &config,
                &["claude".to_owned(), "-p".to_owned(), "hi".to_owned()]
            ),
            ["claude", "-p", "hi"]
        );
        assert_eq!(resolve_exec_cmd(&config, &[]), ["claude"]);

        let bare = Config::default();
        assert_eq!(resolve_exec_cmd(&bare, &[]), ["/bin/bash"]);
    }

    #[test]
    fn only_the_vm_backend_needs_a_podman_prefix() {
        assert_eq!(
            vm_podman_prefix("vm", "x"),
            ["limactl", "shell", "agentcage-x", "--"]
        );
        assert!(vm_podman_prefix("container", "x").is_empty());
        assert!(vm_podman_prefix("apple-container", "x").is_empty());
    }

    #[test]
    fn only_blocked_decisions_reach_the_terminal() {
        assert!(blocked_notice("").is_none());
        assert!(blocked_notice("mitmproxy: listening").is_none());
        assert!(blocked_notice(r#"{"decision": "allowed", "host": "x"}"#).is_none());
        assert!(blocked_notice(r#"{"decision": "blocked""#).is_none());
        let notice = blocked_notice(
            r#"{"decision": "blocked", "host": "evil.example", "reason": "denied"}"#,
        )
        .expect("a notice");
        assert!(notice.contains("evil.example"), "{notice:?}");
        assert!(notice.contains("denied"), "{notice:?}");
        assert!(notice.starts_with('\r'), "{notice:?}");
        assert!(notice.ends_with('\n'), "{notice:?}");
    }

    /// A directory under `$HOME` is created; a file-looking path, an
    /// unexpanded variable and anything outside `$HOME` are not.
    #[test]
    fn volume_sources_are_created_only_inside_the_home_directory() {
        let dir = agentcage_state::TestDir::new("volume-dirs");
        let home = dir.path().display().to_string();
        let host = FakeHost { home: home.clone() };

        ensure_volume_dirs(
            &[
                format!("{home}/state:/state:rw"),
                "~/from-tilde:/t:rw".to_owned(),
                format!("{home}/config.json:/c:ro"),
                format!("{home}/.bashrc-dir:/b:ro"),
                "${UNSET_VAR}/x:/x:ro".to_owned(),
                "/etc/agentcage-should-not-exist:/e:ro".to_owned(),
                "named-volume:/v:rw".to_owned(),
            ],
            &host,
        );

        assert!(dir.path().join("state").is_dir());
        assert!(dir.path().join("from-tilde").is_dir());
        assert!(!dir.path().join("config.json").exists());
        assert!(dir.path().join(".bashrc-dir").is_dir());
        assert!(!std::path::Path::new("/etc/agentcage-should-not-exist").exists());
        // A named volume has no `/`, so it is not a host path at all and
        // nothing is created for it — the Python relies on the same
        // containment check to ignore it.
        assert!(!dir.path().join("named-volume").exists());
    }

    /// The four `QuadletHost` answers `ensure_volume_dirs` reaches for,
    /// against a directory the test owns.
    #[derive(Debug)]
    struct FakeHost {
        home: String,
    }

    impl agentcage_core::quadlets::QuadletHost for FakeHost {
        fn env_var(&self, name: &str) -> Option<String> {
            (name == "HOME").then(|| self.home.clone())
        }

        fn realpath(&self, path: &str) -> String {
            crate::hostenv::realpath(path)
        }

        fn exists(&self, path: &str) -> bool {
            std::path::Path::new(path).exists()
        }

        fn is_dir(&self, path: &str) -> bool {
            std::path::Path::new(path).is_dir()
        }

        fn stage_vm_file_volume(&self, source: &str, _deploy_name: &str) -> Result<String, String> {
            Ok(source.to_owned())
        }

        fn detect_default_creds_scope(&self) -> Option<String> {
            None
        }
    }
}
