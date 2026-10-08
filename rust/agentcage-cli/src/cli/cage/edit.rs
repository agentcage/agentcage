//! `cli.cage_edit` — edit a cage's stored config safely.
//!
//! The point of the command, as against `$EDITOR
//! ~/.config/agentcage/cages/<name>/cage.yaml`, is that a bad edit
//! cannot leave the cage unloadable: the edited text is validated
//! *before* anything is written, a rejected edit is kept so the
//! operator does not lose it, the good file is backed up, the write is
//! atomic, and the operator is then told which of their changes applied
//! live and which need a restart or a rebuild.
//!
//! # The editor seam is `click.edit`, not the `$EDITOR` dance
//! `scaffold edit` does
//!
//! Two different behaviours in the Python, reproduced separately rather
//! than unified:
//!
//! * `scaffold edit` reads `EDITOR` then `VISUAL` and opens the
//!   scaffold's file **in place**;
//! * `cage edit` is `click.edit(text=…, require_save=True)`, which
//!   prefers **`VISUAL` over `EDITOR`**, falls back to
//!   `sensible-editor` / `vim` / `nano` / `vi`, edits a *copy* in a
//!   temporary file, and treats "mtime unchanged" as "the operator
//!   quit without saving".
//!
//! The order really is opposite between the two commands. Unifying them
//! would be a behaviour change dressed as tidying.
//!
//! The mtime dance is click's and is not superstition: it backdates the
//! temp file by two seconds before launching the editor, because a
//! filesystem with 1- or 2-second timestamp resolution plus an editor
//! that exits quickly would otherwise look like "no change" and discard
//! the operator's work.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime};

use agentcage_core::config::{self, Config};
use agentcage_core::yaml::{self, Value};
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};

/// `_PROXY_HOT_RELOAD_KEYS` — top-level keys the proxy picks up by
/// polling `proxy-config.yaml`'s mtime, so a change needs no restart.
const PROXY_HOT_RELOAD_KEYS: [&str; 9] = [
    "max_request_body",
    "entropy",
    "content_type",
    "inspectors",
    "rate_limit",
    "logging",
    "secret_injection",
    "capture",
    "protocol_relays",
];

/// `_REBUILD_KEYS` — keys that need a destroy and recreate, because
/// they decide the image or the network shape rather than its contents.
const REBUILD_KEYS: [&str; 2] = ["isolation", "vm"];

/// How the three buckets came out.
struct Classified {
    live: BTreeSet<String>,
    restart: BTreeSet<String>,
    rebuild: BTreeSet<String>,
}

/// `_classify_changes` — bucket the changed top-level keys.
fn classify_changes(before: &Value, after: &Value) -> Classified {
    let mut out = Classified {
        live: BTreeSet::new(),
        restart: BTreeSet::new(),
        rebuild: BTreeSet::new(),
    };
    let keys = |value: &Value| -> BTreeSet<String> {
        value
            .as_mapping()
            .map(|map| {
                map.keys()
                    .filter_map(|k| k.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut all = keys(before);
    all.extend(keys(after));
    for key in all {
        let k = Value::from(key.as_str());
        if before.get(&k) == after.get(&k) {
            continue;
        }
        if key == "domains" || key == "agents" {
            // Same live-apply shape as `domains`: `save_proxy_config`
            // below bumps `proxy-config.yaml`'s mtime and the addon's
            // poll reloads the agents block in place — and an agents
            // edit can move the LLM provider host that has to resolve,
            // which is exactly what `update_dns_quadlet` handles.
            out.live.insert(key);
        } else if PROXY_HOT_RELOAD_KEYS.contains(&key.as_str()) {
            out.live.insert(key);
        } else if REBUILD_KEYS.contains(&key.as_str()) {
            out.rebuild.insert(key);
        } else {
            out.restart.insert(key);
        }
    }
    out
}

/// `cage edit`.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> std::process::ExitCode {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    match run(ctx, &name) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => code,
    }
}

#[allow(clippy::too_many_lines)]
fn run(ctx: &Ctx, name: &str) -> Result<(), std::process::ExitCode> {
    if !ctx.paths.deployment_exists(name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(std::process::ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, name)?;

    let state_dir = ctx.paths.deployment_dir(name);
    let config_path = ctx.paths.stored_config_path(name);
    let rejected_path = state_dir.join("cage.yaml.rejected");
    let backup_path = state_dir.join("cage.yaml.bak");

    let original_raw = ctx
        .paths
        .load_raw_config(name, agentcage_state::AgentSchema::Check)
        .map_err(|error| {
            eprintln!("error: {error}");
            std::process::ExitCode::from(EXIT_FAILURE)
        })?;
    let original_text = std::fs::read_to_string(&config_path).map_err(|error| {
        eprintln!("error: {}: {error}", config_path.display());
        std::process::ExitCode::from(EXIT_FAILURE)
    })?;

    let edited_text = match edit_text(&original_text) {
        Ok(Some(text)) => text,
        // `None` is click's `require_save`: the operator quit without
        // saving, or saved the file back unchanged.
        Ok(None) => {
            println!("No changes to cage '{name}'.");
            return Ok(());
        }
        Err(message) => {
            eprintln!("error: {message}");
            return Err(std::process::ExitCode::from(EXIT_FAILURE));
        }
    };
    if edited_text == original_text {
        println!("No changes to cage '{name}'.");
        return Ok(());
    }

    // Every refusal from here on writes the edit to `cage.yaml.rejected`
    // and says the original is untouched. Losing an operator's edit to a
    // typo would make the command worse than the editor it replaces.
    let reject = |message: &str| -> std::process::ExitCode {
        let _ = std::fs::write(&rejected_path, &edited_text);
        eprintln!("error: {message}");
        eprintln!("  Rejected edits saved to {}", rejected_path.display());
        eprintln!(
            "  Original config at {} is unchanged.",
            config_path.display()
        );
        std::process::ExitCode::from(EXIT_FAILURE)
    };

    let mut edited_raw = match yaml::load_named("edited config", &edited_text) {
        Ok(document) => document,
        Err(error) => {
            let where_ = match error.location() {
                Some(l) => format!(" at line {}, column {}", l.line(), l.column()),
                None => String::new(),
            };
            return Err(reject(&format!(
                "edited config is not valid YAML{where_}: {error}"
            )));
        }
    };

    if edited_raw.as_mapping().is_none() {
        return Err(reject(
            "edited config must be a YAML mapping at the top level",
        ));
    }

    // Renaming needs state-directory moves, secret renames and unit
    // rewrites, none of which this command does. Refusing is the whole
    // contract here, not a limitation to work around.
    let key = Value::from("name");
    let before_name = original_raw.get(&key).and_then(Value::as_str);
    let after_name = edited_raw.get(&key).and_then(Value::as_str);
    if before_name != after_name {
        return Err(reject(&format!(
            "renaming a cage via 'cage edit' is not supported (cage.yaml \
             'name' changed from '{}' to '{}')",
            before_name.unwrap_or_default(),
            after_name.unwrap_or_default()
        )));
    }

    // Fill omitted `secret_injection` placeholders before rendering, so
    // the diff shows the minted token and validation sees the final
    // document. Carrying from the pre-edit config keeps an already
    // generated placeholder stable when the operator leaves
    // `placeholder:` off a rule that already had one.
    config::fill_raw_placeholders(
        &mut edited_raw,
        Some(&original_raw),
        &mut agentcage_state::mint_placeholder,
    );

    let rendered = match yaml::dump(&edited_raw) {
        Ok(text) => text,
        Err(error) => {
            return Err(reject(&format!(
                "edited config could not be re-rendered: {error}"
            )));
        }
    };

    // Validate through the real loader. The Python writes `rendered` to
    // a temporary file inside the state directory because `load_config`
    // takes a path; `config::load` takes the text, so there is no temp
    // file to create, fail to clean up, or leak into the state tree.
    //
    // One visible consequence, and it is an improvement: a parse-stage
    // message that embeds its source now names the cage's own
    // `cage.yaml` instead of a temporary filename that has already been
    // deleted by the time the operator reads it.
    let host = agentcage_cli::hostenv::RealHost;
    let config: Config = match config::load(&config_path.display().to_string(), &rendered, &host) {
        Ok(config) => config,
        Err(error) => {
            return Err(reject(&format!("edited config failed validation: {error}")));
        }
    };
    let warnings = match config::validate(&config, &host) {
        Ok(warnings) => warnings,
        Err(error) => {
            return Err(reject(&format!("edited config failed validation: {error}")));
        }
    };
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }

    // Show what changed before writing it.
    print!(
        "{}",
        unified_diff(
            &original_text,
            &rendered,
            &format!("{name}/cage.yaml (before)"),
            &format!("{name}/cage.yaml (after)"),
        )
    );

    // A good edit supersedes any rejected one from a previous attempt.
    let _ = std::fs::remove_file(&rejected_path);

    // Back up the previous good file *before* replacing it, so a crash
    // between the rename and "all done" still leaves a recoverable
    // config.
    if let Err(error) = std::fs::copy(&config_path, &backup_path) {
        eprintln!(
            "error: could not back up {}: {error}",
            config_path.display()
        );
        return Err(std::process::ExitCode::from(EXIT_FAILURE));
    }
    if let Err(error) = ctx.paths.save_raw_config(name, &edited_raw) {
        eprintln!("error: {error}");
        return Err(std::process::ExitCode::from(EXIT_FAILURE));
    }

    // Always, even when no proxy key moved: it is cheap and it keeps
    // `proxy-config.yaml` in lockstep with `cage.yaml`.
    if let Err(error) = ctx.paths.save_proxy_config(name, agentcage_core::VERSION) {
        eprintln!("warning: could not refresh proxy-config.yaml: {error}");
    }

    let changes = classify_changes(&original_raw, &edited_raw);

    if changes.live.contains("domains") || changes.live.contains("agents") {
        crate::cli::domain::update_dns_quadlet(ctx, &config)?;
    }

    if changes.live.contains("agents") {
        // The scan loops and the provider DNS entries apply live, but
        // two things the agents need are decided at unit-generation
        // time: the grants volume their findings are written to, and
        // the `Secret=` directive for each api_key. Without a refresh a
        // freshly enabled watcher has no host-visible volume, its
        // findings land in the container's ephemeral layer, and
        // `watcher findings` reports the silent all-clear the feature
        // exists to prevent.
        if let Err(error) = crate::cli::secret::live::refresh_units(ctx, name, &config) {
            eprintln!("warning: quadlet refresh failed: {error}");
        }
        println!(
            "  agents: updated. Scanning and domain evaluation apply live. \
             Restart the cage if a findings volume or api_key secret was just \
             added (`agentcage cage restart` adopts the refreshed units)."
        );
    }

    if changes.live.contains("secret_injection") {
        // Rules hot-reload at the proxy and new exec sessions read the
        // placeholders out of the stored config, but the unit files and
        // the boot-time environment only converge through a refresh.
        // Running containers are left alone.
        if let Err(error) = crate::cli::secret::live::refresh_units(ctx, name, &config) {
            eprintln!("warning: quadlet refresh failed: {error}");
        }
        println!(
            "  secret_injection: proxy rules apply on the next request; new \
             exec sessions see the updated placeholders. Restart the cage to \
             refresh the boot process's environment."
        );
    }

    println!(
        "Updated cage '{name}'. Backup at {}.",
        backup_path.display()
    );
    if !changes.live.is_empty() {
        println!("  Live-applied: {}", joined(&changes.live));
    }
    if !changes.restart.is_empty() {
        println!(
            "  Needs restart ({}): agentcage cage restart {name}",
            joined(&changes.restart)
        );
    }
    if !changes.rebuild.is_empty() {
        println!(
            "  Needs rebuild ({}): agentcage cage update {name} (or destroy + create)",
            joined(&changes.rebuild)
        );
    }
    Ok(())
}

/// `", ".join(sorted(keys))` — a `BTreeSet` is already sorted.
fn joined(keys: &BTreeSet<String>) -> String {
    keys.iter().cloned().collect::<Vec<_>>().join(", ")
}

// ── click.edit ───────────────────────────────────────────────

/// `click.edit(text, extension=".yaml", require_save=True)`.
///
/// `Ok(None)` is click's `require_save` verdict: the temp file's mtime
/// did not move, so the operator quit without saving and their cage
/// must be left alone.
///
/// # Errors
///
/// A message ready to print when the editor could not be started or
/// exited non-zero — click raises `ClickException` for both, and both
/// mean the edit did not happen.
fn edit_text(text: &str) -> Result<Option<String>, String> {
    let editor = resolve_editor(&|key| std::env::var(key).ok());
    // `if text and not text.endswith("\n"): text += "\n"`. A rendered
    // cage.yaml always ends in one, so this is theory rather than
    // practice — but an operator's hand-written file reaching here
    // without a trailing newline should not silently gain one only on
    // some paths.
    let mut data = text.to_owned();
    if !data.is_empty() && !data.ends_with('\n') {
        data.push('\n');
    }

    let path = temp_path();
    std::fs::write(&path, &data).map_err(|e| format!("{}: {e}", path.display()))?;
    let result = (|| -> Result<Option<String>, String> {
        // Backdate by two seconds, then read back what the filesystem
        // actually recorded. click's comment is worth keeping: on a
        // filesystem with 1- or 2-second timestamp resolution, an
        // editor that exits quickly would leave the mtime equal to the
        // write above and `require_save` would throw the edit away.
        let backdated = SystemTime::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        set_mtime(&path, backdated);
        let before = mtime(&path);

        let mut argv = agentcage_assets::shlex::split(&editor)
            .map_err(|_| format!("{editor}: not a well-formed command"))?;
        argv.push(path.display().to_string());
        let (program, editor_args) = argv
            .split_first()
            .ok_or_else(|| format!("{editor}: not a well-formed command"))?;

        // The editor owns the terminal: inherit all three streams, as
        // `subprocess.Popen` with no redirection does.
        let status = std::process::Command::new(program)
            .args(editor_args)
            .status()
            .map_err(|e| format!("{editor}: Editing failed: {e}"))?;
        if !status.success() {
            return Err(format!("{editor}: Editing failed"));
        }

        if mtime(&path) == before {
            return Ok(None);
        }
        let edited =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        // `rv.decode("utf-8-sig").replace("\r\n", "\n")` — strip a BOM
        // an editor may have added, and normalize the line endings one
        // may have rewritten.
        Ok(Some(
            edited
                .strip_prefix('\u{feff}')
                .unwrap_or(&edited)
                .replace("\r\n", "\n"),
        ))
    })();
    let _ = std::fs::remove_file(&path);
    result
}

/// `click._termui_impl.Editor.get_editor`.
///
/// **`VISUAL` before `EDITOR`**, which is the opposite of
/// `scaffold edit`'s order — see the module docs. An empty value does
/// not count as set, so `VISUAL=` falls through to `EDITOR`.
///
/// The environment arrives as a lookup rather than being read here,
/// for the reason the rest of this crate injects host facts: the
/// workspace forbids `unsafe`, so a test cannot call
/// `std::env::set_var`, and a resolution order worth a comment is
/// worth an assertion.
fn resolve_editor(env: &dyn Fn(&str) -> Option<String>) -> String {
    for key in ["VISUAL", "EDITOR"] {
        if let Some(value) = env(key) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    for candidate in ["sensible-editor", "vim", "nano"] {
        if which(candidate) {
            return candidate.to_owned();
        }
    }
    "vi".to_owned()
}

/// `shutil.which`, for the editor fallbacks only.
fn which(program: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        std::fs::metadata(&candidate).is_ok_and(|m| m.is_file()) && is_executable(&candidate)
    })
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

/// `tempfile.mkstemp(prefix="editor-", suffix=".yaml")`.
///
/// In the system temp directory, not the state directory: this is a
/// scratch copy the operator edits, and a crash must not leave it
/// looking like part of the cage's state.
fn temp_path() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("editor-{}-{nanos}.yaml", std::process::id()))
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// `os.utime`, best-effort: a filesystem that refuses it only means
/// `require_save` falls back to comparing the write's own timestamp,
/// which is what click's workaround exists to avoid rather than
/// something it depends on.
fn set_mtime(path: &Path, when: SystemTime) {
    let _ = filetime_set(path, when);
}

#[cfg(unix)]
fn filetime_set(path: &Path, when: SystemTime) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    let times = std::fs::FileTimes::new()
        .set_accessed(when)
        .set_modified(when);
    file.set_times(times)
}

#[cfg(not(unix))]
fn filetime_set(_path: &Path, _when: SystemTime) -> std::io::Result<()> {
    Ok(())
}

// ── difflib.unified_diff ─────────────────────────────────────

/// `difflib.unified_diff(..., lineterm="\n")` over whole lines.
///
/// The header is difflib's: `--- fromfile` / `+++ tofile`, with no
/// trailing tab-date because the Python passes no `fromfiledate`.
/// Hunks are `@@ -l,s +l,s @@` with three lines of context.
///
/// **One documented divergence.** difflib groups its opcodes with
/// `SequenceMatcher`, which is not a shortest-edit algorithm — it has a
/// junk heuristic and an `autojunk` rule that make it prefer
/// human-readable groupings over minimal ones. This is a plain
/// longest-common-subsequence diff. For the edits this command sees —
/// a few lines of a config changing — the two agree; on pathological
/// input the hunk boundaries could differ. Nothing asserts this text
/// and nothing parses it: it is printed for a person to read before
/// their config is written. Reimplementing `SequenceMatcher` to make a
/// human-facing diff byte-identical would be a poor trade, and saying
/// so is better than implying a parity that is not there.
fn unified_diff(before: &str, after: &str, from_file: &str, to_file: &str) -> String {
    use std::fmt::Write as _;

    let old: Vec<&str> = before.lines().collect();
    let new: Vec<&str> = after.lines().collect();
    let tagged: Vec<Tagged> = lcs_opcodes(&old, &new)
        .into_iter()
        .map(|op| match op {
            Op::Equal(x, y) => Tagged {
                tag: Tag::Same,
                old: Some(x),
                new: Some(y),
            },
            Op::Delete(x) => Tagged {
                tag: Tag::Del,
                old: Some(x),
                new: None,
            },
            Op::Insert(y) => Tagged {
                tag: Tag::Ins,
                old: None,
                new: Some(y),
            },
        })
        .collect();
    if tagged.iter().all(|line| line.tag == Tag::Same) {
        return String::new();
    }

    // Cut hunks around each run of change, with `CONTEXT` lines either
    // side, merging runs whose context windows touch.
    let mut groups: Vec<(usize, usize)> = Vec::new();
    for index in tagged
        .iter()
        .enumerate()
        .filter(|(_, line)| line.tag != Tag::Same)
        .map(|(index, _)| index)
    {
        let lo = index.saturating_sub(CONTEXT);
        let hi = (index + CONTEXT + 1).min(tagged.len());
        match groups.last_mut() {
            Some(last) if lo <= last.1 => last.1 = hi,
            _ => groups.push((lo, hi)),
        }
    }

    let mut out = format!("--- {from_file}\n+++ {to_file}\n");
    for (lo, hi) in groups {
        let slice = &tagged[lo..hi];
        let old_start = slice.iter().find_map(|line| line.old);
        let new_start = slice.iter().find_map(|line| line.new);
        let old_len = slice.iter().filter(|line| line.tag != Tag::Ins).count();
        let new_len = slice.iter().filter(|line| line.tag != Tag::Del).count();
        // difflib prints a 1-based start, and 0 for an empty range.
        let old_from = if old_len == 0 {
            0
        } else {
            old_start.unwrap_or(0) + 1
        };
        let new_from = if new_len == 0 {
            0
        } else {
            new_start.unwrap_or(0) + 1
        };
        let _ = writeln!(out, "@@ -{old_from},{old_len} +{new_from},{new_len} @@");
        for line in slice {
            let _ = match line.tag {
                Tag::Same => writeln!(out, " {}", old[line.old.unwrap_or(0)]),
                Tag::Del => writeln!(out, "-{}", old[line.old.unwrap_or(0)]),
                Tag::Ins => writeln!(out, "+{}", new[line.new.unwrap_or(0)]),
            };
        }
    }
    out
}

/// `difflib.unified_diff`'s three lines of context either side of a
/// change.
const CONTEXT: usize = 3;

/// What one line of the edit script is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    Same,
    Del,
    Ins,
}

/// One line of the expanded edit script, with its index on each side.
///
/// `None` is "this line does not exist on that side", which is what
/// makes the hunk header's start and length computable without a
/// sentinel index.
struct Tagged {
    tag: Tag,
    old: Option<usize>,
    new: Option<usize>,
}

enum Op {
    Equal(usize, usize),
    Delete(usize),
    Insert(usize),
}

/// A longest-common-subsequence edit script over whole lines.
fn lcs_opcodes(old: &[&str], new: &[&str]) -> Vec<Op> {
    let (old_len, new_len) = (old.len(), new.len());
    // `table[x][y]` is the LCS length of `old[x..]` and `new[y..]`.
    let mut table = vec![vec![0usize; new_len + 1]; old_len + 1];
    for x in (0..old_len).rev() {
        for y in (0..new_len).rev() {
            table[x][y] = if old[x] == new[y] {
                table[x + 1][y + 1] + 1
            } else {
                table[x + 1][y].max(table[x][y + 1])
            };
        }
    }
    let mut ops = Vec::new();
    let (mut x, mut y) = (0usize, 0usize);
    while x < old_len && y < new_len {
        if old[x] == new[y] {
            ops.push(Op::Equal(x, y));
            x += 1;
            y += 1;
        } else if table[x + 1][y] >= table[x][y + 1] {
            ops.push(Op::Delete(x));
            x += 1;
        } else {
            ops.push(Op::Insert(y));
            y += 1;
        }
    }
    while x < old_len {
        ops.push(Op::Delete(x));
        x += 1;
    }
    while y < new_len {
        ops.push(Op::Insert(y));
        y += 1;
    }
    ops
}

#[cfg(test)]
mod tests {
    use agentcage_core::yaml;

    use super::{classify_changes, resolve_editor, unified_diff};

    fn doc(text: &str) -> yaml::Value {
        yaml::load_named("t", text).expect("valid YAML")
    }

    /// The three buckets, and the two keys that are deliberately `live`
    /// despite not being proxy keys.
    #[test]
    fn changes_land_in_the_right_bucket() {
        let before = doc(
            "name: x\nisolation: container\ndomains:\n  allow: [a.test]\n\
             capture:\n  enable_har: false\ncontainer:\n  image: alpine\n",
        );
        let after = doc(
            "name: x\nisolation: vm\ndomains:\n  allow: [a.test, b.test]\n\
             capture:\n  enable_har: true\ncontainer:\n  image: ubuntu\n",
        );
        let c = classify_changes(&before, &after);
        assert!(c.live.contains("domains"), "{:?}", c.live);
        assert!(c.live.contains("capture"), "{:?}", c.live);
        assert!(c.rebuild.contains("isolation"), "{:?}", c.rebuild);
        // `container` is neither hot-reloadable nor a rebuild key, so it
        // is the restart bucket — the default, and the one an operator
        // most often lands in.
        assert!(c.restart.contains("container"), "{:?}", c.restart);
    }

    /// An `agents` edit is `live` *and* triggers the DNS path, because
    /// it can move the LLM provider host that has to resolve.
    #[test]
    fn an_agents_change_is_live() {
        let before = doc("name: x\n");
        let after = doc("name: x\nagents:\n  decider:\n    enable: true\n");
        let c = classify_changes(&before, &after);
        assert_eq!(c.live.iter().cloned().collect::<Vec<_>>(), vec!["agents"]);
        assert!(c.restart.is_empty() && c.rebuild.is_empty());
    }

    /// A key added or removed counts as changed, not just one whose
    /// value moved — `set(before) | set(after)` in the Python.
    #[test]
    fn an_added_or_removed_key_counts() {
        let c = classify_changes(&doc("name: x\n"), &doc("name: x\ncapture: {}\n"));
        assert!(c.live.contains("capture"));
        let c = classify_changes(&doc("name: x\ncapture: {}\n"), &doc("name: x\n"));
        assert!(c.live.contains("capture"));
    }

    #[test]
    fn an_identical_document_changes_nothing() {
        let c = classify_changes(&doc("name: x\na: 1\n"), &doc("name: x\na: 1\n"));
        assert!(c.live.is_empty() && c.restart.is_empty() && c.rebuild.is_empty());
    }

    /// difflib's header and hunk shape, which is what an operator reads
    /// before their config is written.
    #[test]
    fn the_diff_reads_like_difflib() {
        let before = "name: x\nimage: alpine\nports:\n  - 80\n";
        let after = "name: x\nimage: ubuntu\nports:\n  - 80\n";
        let diff = unified_diff(before, after, "x/cage.yaml (before)", "x/cage.yaml (after)");
        assert_eq!(
            diff,
            "--- x/cage.yaml (before)\n\
             +++ x/cage.yaml (after)\n\
             @@ -1,4 +1,4 @@\n\
             \u{20}name: x\n\
             -image: alpine\n\
             +image: ubuntu\n\
             \u{20}ports:\n\
             \u{20}  - 80\n",
            "{diff}"
        );
    }

    /// No change is the empty string, not a bare header — the Python
    /// guards on `if diff:` and prints nothing.
    #[test]
    fn an_unchanged_document_has_no_diff() {
        assert_eq!(unified_diff("a\nb\n", "a\nb\n", "f", "t"), "");
    }

    /// A pure insertion, where difflib's start line for the empty side
    /// is the line *before* the insertion rather than zero.
    #[test]
    fn an_insertion_numbers_both_sides() {
        let diff = unified_diff("a\nb\n", "a\nnew\nb\n", "f", "t");
        assert!(diff.contains("@@ -1,2 +1,3 @@\n"), "{diff}");
        assert!(diff.contains("+new\n"), "{diff}");
    }

    /// `VISUAL` wins over `EDITOR` here — the opposite of
    /// `scaffold edit`, and the difference is click's.
    #[test]
    fn visual_beats_editor() {
        let both = |key: &str| match key {
            "VISUAL" => Some("visual-editor".to_owned()),
            "EDITOR" => Some("editor-editor".to_owned()),
            _ => None,
        };
        assert_eq!(resolve_editor(&both), "visual-editor");

        // An empty value is not "set", so it falls through to EDITOR.
        let empty_visual = |key: &str| match key {
            "VISUAL" => Some(String::new()),
            "EDITOR" => Some("editor-editor".to_owned()),
            _ => None,
        };
        assert_eq!(resolve_editor(&empty_visual), "editor-editor");

        // Neither set: click falls back to a known editor, never to
        // nothing. `vi` is the floor.
        let unset = |_: &str| None;
        let fallback = resolve_editor(&unset);
        assert!(
            ["sensible-editor", "vim", "nano", "vi"].contains(&fallback.as_str()),
            "unexpected fallback: {fallback}"
        );
    }
}
