//! `agentcage cage har` — export captured HTTP traffic as HAR 1.2 JSON.
//!
//! PR D13 of the Rust port (RUST-PORT-PLAN.md §3, Track D row D13).
//!
//! # What is already done, and what this module is
//!
//! [`agentcage_core::har`] (PR C6) is the whole builder: both views,
//! eight filters, `--since` parsing, and the two JSON serializations
//! Python produces from the same value. It is held byte-for-byte to the
//! five artifacts under `tests/fixtures/golden/shared/har/`.
//!
//! So this module is the *command*: find the capture file, read it,
//! filter it, write the result, and say something useful when any of
//! that is impossible. Nothing here builds a HAR entry.
//!
//! # Where the capture file lives — two roots, not one
//!
//! | isolation | file |
//! | :-- | :-- |
//! | `container`, `vm` | `$XDG_DATA_HOME/agentcage/<name>/capture/capture.jsonl` |
//! | `apple-container` | `~/.config/agentcage/apple-container/<name>/logs/capture.jsonl` |
//!
//! The second expands `~` **directly** and ignores `XDG_CONFIG_HOME`
//! (`backends/apple_container.py:206`), so it is not merely a different
//! subdirectory of the same root — it is a different root, and pointing
//! `XDG_CONFIG_HOME` at a sandbox does not move it. Both come from
//! [`Paths`], which is the only place that wart is written down.
//!
//! Whichever is chosen, the **rotated** generation is read first. The
//! capture writer rolls over at `capture.max_file_size` and keeps one
//! previous file, `capture.jsonl.1`, which holds the *older* half; a
//! reader that took only the live file would silently shorten every
//! export taken after a rollover.
//!
//! # Where this is deliberately not the Python
//!
//! `cli.py`'s `cage har` has no error handling around its file I/O. An
//! unreadable capture file, a capture file that is not UTF-8, and an
//! `-o` path in a directory that does not exist each end in a Python
//! traceback — one of them (`PermissionError` on the capture file)
//! after the command has already printed nothing at all. Every one of
//! those is a message and exit 1 here. The traceback is not a contract:
//! it prints this repository's absolute paths, it is not stable across
//! Python versions, and nothing can parse it.
//!
//! One further inherited quirk is *not* reproduced, and it is a
//! side effect rather than output. `state.capture_dir` calls
//! `mkdir(parents=True, exist_ok=True)` before returning, so merely
//! *asking* the Python where a capture file would be creates
//! `$XDG_DATA_HOME/agentcage/<name>/capture/` — including on the error
//! path, where `cage har` reports that there is no capture file and
//! leaves an empty directory behind for it. [`Paths::capture_file`] is
//! pure, so this reports the same error and creates nothing.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use agentcage_core::har::json::{self as json, DumpOptions, Json};
use agentcage_core::har::{CaptureFilter, capture_to_har, dumps, parse_since};
use agentcage_core::yaml;
use agentcage_exec::CommandRunner;
use agentcage_state::AgentSchema;
use agentcage_state::paths::Paths;

use crate::preflight;

/// Exit status for every failure this command reports itself.
///
/// `cli.py` uses `sys.exit(1)` for all three of its own error paths;
/// the v0.22 gate's 2 comes from [`crate::preflight`].
const EXIT_FAILURE: u8 = 1;

/// The parsed `cage har` invocation.
///
/// One field per declared option, named for the option's clap id so the
/// mapping in `cli::cage::query` reads as a list rather than a
/// translation. `view` and `max_entries` carry the parser's defaults
/// (`"inbound"` and `0`) rather than `Option`s, because click's
/// `show_default` makes them part of the documented surface.
#[derive(Clone, Debug)]
pub struct HarArgs {
    /// The cage to export.
    pub name: String,
    /// `inbound` (what the bot saw) or `outbound` (what went on the
    /// wire, with real secrets in it).
    pub view: String,
    /// `-d/--decision`, repeatable.
    pub decisions: Vec<String>,
    /// `--host`, repeatable, substring match.
    pub hosts: Vec<String>,
    /// `--method`, repeatable, case-insensitive.
    pub methods: Vec<String>,
    /// `--direction`, repeatable.
    pub directions: Vec<String>,
    /// `--since`, a relative window or an ISO date.
    pub since: Option<String>,
    /// `-n/--max-entries`; `0` means unlimited, and the limit keeps the
    /// **last** n.
    pub max_entries: i64,
    /// `-o/--output`; stdout when absent.
    pub output_file: Option<PathBuf>,
    /// `--json-lines`, with the hidden `--json` already folded in.
    pub json_lines: bool,
}

/// Run `cage har` against the real environment.
///
/// The `runner` is not for the export: it is how the isolation backend
/// is resolved when the stored `cage.yaml` leaves `isolation:` out, and
/// on any host that is not a Mac it is never consulted at all.
#[must_use]
pub fn main(args: &HarArgs) -> u8 {
    let paths = Paths::from_env();
    let runner = agentcage_exec::SystemRunner::new();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    run(&paths, &runner, args, &mut stdout, &mut stderr)
}

/// `cage har`'s body, with its world passed in.
///
/// The order of the checks is `cli.py`'s order and it is observable: a
/// v0.21 cage is refused (exit 2) *before* anything asks whether it has
/// a capture file, and the outbound-secrets warning is printed only
/// once the file has been found, so a failed export never warns about
/// data it did not read.
#[must_use]
pub fn run(
    paths: &Paths,
    runner: &dyn CommandRunner,
    args: &HarArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    if let Some(code) = preflight::require_cage(paths, &args.name, stderr) {
        return code;
    }
    if let Some(code) = preflight::ensure_v022_cage(paths, &args.name, stderr) {
        return code;
    }

    let capture_path = match capture_path(paths, runner, &args.name) {
        Ok(path) => path,
        Err(message) => {
            let _ = writeln!(stderr, "error: {message}");
            return EXIT_FAILURE;
        }
    };
    if !capture_path.is_file() {
        report_missing_capture(&args.name, &capture_path, stderr);
        return EXIT_FAILURE;
    }

    // Every outbound view carries real injected secrets, whichever
    // output form it takes, so every one of them warns.
    //
    // `cli.py` used to write `if view == "outbound" and not
    // json_lines`, which dropped the warning from the one form people
    // pipe into other tools while the piped bytes still held the API
    // keys. The warning goes to stderr and cannot corrupt stdout, so
    // there was nothing for the suppression to protect. Fixed in the
    // same commit as this port; see `tests/fixtures/cage-har/`.
    if args.view == "outbound" {
        let _ = writeln!(
            stderr,
            "WARNING: --view outbound includes real secrets (API keys, tokens). \
             Treat the output as sensitive."
        );
    }

    let filter = CaptureFilter {
        decisions: args.decisions.clone(),
        directions: args.directions.clone(),
        hosts: args.hosts.clone(),
        methods: args.methods.clone(),
        // `cage har` declares no `--min-action`; `cage audit` does.
        min_action: None,
        since: args.since.as_deref().and_then(parse_since),
    };

    let mut entries = match read_entries(&capture_path, &filter) {
        Ok(entries) => entries,
        Err(message) => {
            let _ = writeln!(stderr, "error: {message}");
            return EXIT_FAILURE;
        }
    };

    // `entries[-max_entries:]` — the LAST n. A negative `-n` is not a
    // usage error in click and does not limit anything, because the
    // test is `> 0`.
    if args.max_entries > 0 {
        let keep = usize::try_from(args.max_entries).unwrap_or(usize::MAX);
        if entries.len() > keep {
            entries.drain(..entries.len() - keep);
        }
    }

    let text = if args.json_lines {
        // `json.dumps(entry)` with every default: one line, `", "` and
        // `": "` separators, `ensure_ascii=True`, insertion order.
        entries
            .iter()
            .map(|entry| json::dumps(entry, DumpOptions::default()) + "\n")
            .collect::<String>()
    } else {
        // `json.dumps(har, indent=2)` — NOT the corpus's
        // `sort_keys=True, ensure_ascii=False` form. See
        // `agentcage_core::har::dumps`.
        dumps(&capture_to_har(&entries, &args.view)) + "\n"
    };

    let Some(output_file) = args.output_file.as_deref() else {
        let _ = stdout.write_all(text.as_bytes());
        return 0;
    };
    if let Err(error) = fs::write(output_file, &text) {
        let _ = writeln!(
            stderr,
            "error: cannot write {}: {error}",
            output_file.display()
        );
        return EXIT_FAILURE;
    }
    // Only the HAR branch reports. The JSONL branch writes the file and
    // says nothing, which is `cli.py`'s asymmetry, not a port's.
    if !args.json_lines {
        let _ = writeln!(
            stderr,
            "Wrote {} entries to {}",
            entries.len(),
            output_file.display()
        );
    }
    0
}

/// The `error:` block for a capture file that is not there.
///
/// Five lines and a blank one, and the advice is the same whether
/// capture was never enabled or simply has not seen traffic yet —
/// nothing on disk distinguishes those.
fn report_missing_capture(name: &str, capture_path: &Path, stderr: &mut dyn Write) {
    let _ = writeln!(stderr, "error: no capture file found for cage '{name}'");
    let _ = writeln!(stderr, "  Expected: {}", capture_path.display());
    let _ = writeln!(stderr);
    let _ = writeln!(
        stderr,
        "  Add this to your cage.yaml and run `agentcage cage update`:"
    );
    let _ = writeln!(stderr, "    capture:");
    let _ = writeln!(stderr, "      enable_har: true");
}

/// Which of the two roots this cage's capture lives under.
///
/// # Errors
///
/// A message ready to print when the stored `cage.yaml` cannot be read
/// or parsed. The Python lets the `ValueError` out of
/// `state.load_deployment_config` and click turns it into a traceback.
fn capture_path(paths: &Paths, runner: &dyn CommandRunner, name: &str) -> Result<PathBuf, String> {
    if is_apple_container(paths, runner, name)? {
        Ok(paths.apple_capture_file(name))
    } else {
        Ok(paths.capture_file(name))
    }
}

/// `_is_apple_container(state.load_deployment_config(name))`.
///
/// Resolved from the stored YAML rather than from a full
/// [`agentcage_core::config`] parse, and the difference is worth being
/// explicit about. A full parse needs a `HostProbe`, whose other half
/// is `_host_dns_servers()` — and that probe *fails* on a host whose
/// only resolvers are loopback addresses, which would make `cage har`
/// refuse to read a file it does not need DNS for. (The Python has
/// exactly that bug: `cage har` on such a host raises
/// `RuntimeError: no usable DNS servers`, from a command that never
/// resolves a name.) Only `isolation:` is read here, with the same
/// resolution `config.py:981` applies:
///
/// * a truthy `isolation:` wins, and a non-string one is not
///   `"apple-container"`, exactly as Python's `==` finds;
/// * an absent, null or empty one takes the host probe;
/// * `firecracker` migrates to `vm`, which is not apple-container
///   either way.
fn is_apple_container(
    paths: &Paths,
    runner: &dyn CommandRunner,
    name: &str,
) -> Result<bool, String> {
    let raw = paths
        .load_raw_config(name, AgentSchema::Skip)
        .map_err(|error| error.to_string())?;
    let declared = raw
        .get("isolation")
        .filter(|value| yaml::python_bool(value));
    Ok(match declared {
        Some(value) => value.as_str() == Some("apple-container"),
        None => default_isolation(runner) == "apple-container",
    })
}

/// `config.default_isolation()` — the best backend for *this* host.
///
/// Linux and every other non-Mac answer `container` without asking
/// anything, which is the only branch a Linux host or a CI runner
/// reaches. The Darwin branch reproduces the arch, version and
/// binary tests, and reads the macOS major version from `sw_vers` where
/// the Python reads `platform.mac_ver()` — the same stand-in, and for
/// the same reason, as [`crate::doctor`]'s.
fn default_isolation(runner: &dyn CommandRunner) -> &'static str {
    const MIN_MACOS_MAJOR: u32 = 26;

    if !cfg!(target_os = "macos") {
        return "container";
    }
    if std::env::consts::ARCH != "aarch64" {
        return "vm";
    }
    if crate::doctor::macos_major(runner).is_none_or(|major| major < MIN_MACOS_MAJOR) {
        return "vm";
    }
    if agentcage_exec::tools::apple::AppleContainer::new(runner)
        .binary()
        .is_none()
    {
        return "vm";
    }
    "apple-container"
}

/// Read the rotated generation and then the live file, keeping the
/// entries that survive `filter`.
///
/// # Errors
///
/// A message ready to print when a file that exists cannot be read.
/// Unparseable *lines* are not an error — they are skipped, as
/// `cli.py`'s `except (json.JSONDecodeError, ValueError): continue`
/// skips them, which is what makes a capture file truncated mid-write
/// by a killed addon still exportable.
fn read_entries(capture_path: &Path, filter: &CaptureFilter) -> Result<Vec<Json>, String> {
    let rotated = rotated_path(capture_path);
    let mut sources: Vec<&Path> = Vec::with_capacity(2);
    if rotated.is_file() {
        sources.push(&rotated);
    }
    sources.push(capture_path);

    let mut entries = Vec::new();
    for source in sources {
        let text = fs::read_to_string(source)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(entry) = json::parse(line) else {
                continue;
            };
            if filter.matches(&entry) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

/// `Path(f"{capture_path}.1")` — a suffix on the whole path, not a
/// replaced extension. `with_extension` would turn `capture.jsonl` into
/// `capture.1`, which is a different file and the wrong one.
fn rotated_path(capture_path: &Path) -> PathBuf {
    let mut raw: OsString = capture_path.to_path_buf().into_os_string();
    raw.push(".1");
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use agentcage_core::har::json::{self as json, DumpOptions};
    use agentcage_exec::FakeRunner;

    use super::{HarArgs, default_isolation, rotated_path};

    fn args(name: &str) -> HarArgs {
        HarArgs {
            name: name.to_owned(),
            view: "inbound".to_owned(),
            decisions: Vec::new(),
            hosts: Vec::new(),
            methods: Vec::new(),
            directions: Vec::new(),
            since: None,
            max_entries: 0,
            output_file: None,
            json_lines: false,
        }
    }

    #[test]
    fn the_rotated_file_is_a_suffix_not_an_extension() {
        assert_eq!(
            rotated_path(Path::new("/a/capture/capture.jsonl")),
            PathBuf::from("/a/capture/capture.jsonl.1")
        );
        // What `with_extension` would have produced instead.
        assert_ne!(
            rotated_path(Path::new("/a/capture/capture.jsonl")),
            PathBuf::from("/a/capture/capture.1")
        );
    }

    /// The only branch reachable off a Mac, and it must not shell out:
    /// the `FakeRunner` records every call and there should be none.
    #[test]
    #[cfg_attr(target_os = "macos", ignore = "the Darwin branch probes the host")]
    fn a_non_mac_host_answers_container_without_probing() {
        let fake = FakeRunner::new();
        assert_eq!(default_isolation(&fake), "container");
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }

    /// The defaults the parser supplies are the ones `cli.py` documents.
    #[test]
    fn the_defaults_are_clicks_defaults() {
        let args = args("x");
        assert_eq!(args.view, "inbound");
        assert_eq!(args.max_entries, 0);
        assert!(!args.json_lines);
        assert!(args.output_file.is_none());
    }

    /// `json.dumps(entry)` defaults, which the `--json-lines` branch
    /// writes one of per record. Spelled out here because it is the one
    /// serialization in this command that the golden corpus does not
    /// cover at all.
    #[test]
    fn json_lines_uses_pythons_dumps_defaults() {
        let entry = json::parse(r#"{"b":1,"a":"é","n":null}"#).expect("parse");
        assert_eq!(
            json::dumps(&entry, DumpOptions::default()),
            "{\"b\": 1, \"a\": \"\\u00e9\", \"n\": null}"
        );
    }
}
