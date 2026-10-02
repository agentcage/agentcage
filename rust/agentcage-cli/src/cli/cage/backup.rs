//! `cage backup` and `cage restore` — `cli.py:3349` and `cli.py:3467`.
//!
//! # The shape of a backup
//!
//! A gzipped tar with one top-level directory, `agentcage-backup/`,
//! holding a `manifest.json` and up to four subdirectories. PR A7
//! committed one that the *Python* produced, and PR D2 pinned its
//! contract by reading it through the system `tar`
//! (`agentcage-state/tests/state_compat.rs:1418`): twelve members, the
//! whole manifest, the bare secret values, and an archived `cage.yaml`
//! equal by parsed value to the one in the state tree. Restoring that
//! exact tarball is this PR's acceptance check, and
//! [`tests::the_python_made_backup_restores_onto_the_state_fixtures`]
//! is where it happens.
//!
//! The container format itself — deterministic writing, traversal-safe
//! reading, and what the Python does about `../../.bashrc` — is
//! [`agentcage_cli::archive`], which is where the tar and gzip crates
//! this PR added are used.
//!
//! # What is restored, and in what order
//!
//! The order is the Python's, and it is observable:
//!
//! 0. **Extraction and the build-context preflight**, before anything
//!    destructive. `--force` destroys the existing cage and clears its
//!    state dir, so every refusal that could happen after that point
//!    has to happen before it — otherwise a tarball that cannot rebuild
//!    the cage leaves the host with neither the old cage nor a restored
//!    one, and with orphaned `<target>.KEY` secrets. This is the
//!    ordering `cli.py:3535` calls out in a comment of its own.
//! 1. **Secrets**, into the podman store, because the build that
//!    follows resolves `Secret=` directives against it.
//! 2. **Config**, through `save_deployment` — which validates the
//!    document rather than trusting the archive, so a hand-edited
//!    tarball cannot install a `cage.yaml` no other command would
//!    accept.
//! 3. **Derived files** (`proxy-config.yaml`, `dns-allowlist.conf`) are
//!    *regenerated*, never restored. `proxy-config.yaml` is in the
//!    archive because a human reading a backup wants to see what the
//!    proxy was told; it is not read back, because the generator is the
//!    source of truth and an old one would silently pin stale policy.
//! 4. **Build and start**, unless `--no-start`.
//! 5. **Volumes**, which need the cage stopped again — podman will not
//!    import into a volume a running container holds.
//! 6. **Capture**, last, because `build_and_deploy` does not touch it.
//!
//! # apple-container
//!
//! A second archive *shape*, not a second archive format: same
//! `agentcage-backup/` root, same `manifest.json`, one more member.
//! The three differences are all the backend's rather than this
//! command's, and they are enumerated on [`backup_apple`] —
//! `--include-secrets` is refused outright, `named_volumes` is always
//! empty, and `capture.jsonl`/`audit.jsonl` both come out of the
//! per-cage logs dir the egress microVM bind-mounts.
//!
//! [`backup_apple`] and [`restore_apple`] are
//! `_cage_backup_apple_container` (`cli.py:3400`) and
//! `_cage_restore_apple_container` (`cli.py:3505`). Everything the two
//! shapes genuinely share — staging the config, the build-context
//! preflight, reinstalling the build context, rewriting `name:` for a
//! clone — is the same code here, where the Python duplicates it. That
//! matters most for the step-0 ordering above: it is one place rather
//! than two.
//!
//! # What is not here
//!
//! The `vm` branch. `_podman_for_cage` routes a running vm cage's
//! secret and volume calls through `VmPodman` *inside the Lima guest*,
//! which is a different store from the host podman every line below
//! talks to. It is refused here with the same message every other
//! not-yet-ported command uses rather than being half-served by the
//! container path.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentcage_core::config::Config;
use agentcage_core::har::datetime::DateTime;
use agentcage_core::har::json::{DumpOptions, Json, dumps, parse as parse_json};
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};
use agentcage_cli::archive::{self, Member};
use agentcage_cli::backend::BackendError;
use agentcage_cli::scaffold::TempDir;
use agentcage_cli::services;

/// The top-level directory every member lives under.
const ROOT: &str = "agentcage-backup";

/// `isolation:` for the apple-container backend, spelled once.
///
/// Both halves of this command compare against it, and the restore
/// half compares a string that came out of a *file* — a manifest's
/// `isolation` — so the comparison has to be the same one the backup
/// half writes.
const APPLE_CONTAINER: &str = "apple-container";

/// The one format version this agentcage writes and the highest it
/// reads. `cli.py:3491` refuses anything greater and accepts anything
/// less, including the `0` a manifest with no such key reads as.
const FORMAT_VERSION: i64 = 1;

/// Entries in a cage's state dir that must never travel in a backup,
/// in *either* direction — skipped on the way in and on the way out, so
/// a tarball written by another build cannot smuggle one back into a
/// restored cage. `cli.py:502`.
///
/// * `creds` / `pending_secrets.json` — credential material and the
///   transient plaintext hand-off consumed at start. A backup taken
///   without `--include-secrets` must not carry either.
/// * `secret_keys.json` — the keychain store's *name index*. The values
///   live in the host keychain and never travel, so restoring the index
///   onto a clean host advertises every key as stored while none is,
///   which turns `cage update`'s fail-closed missing-secrets check into
///   a lie and starts the cage with no secrets at all. This is the one
///   entry here whose absence is a security property rather than tidiness.
/// * `fingerprint.json` — describes the *source* host's build. Restored
///   verbatim it makes `cage update` short-circuit with "already up to
///   date" and skip the rebuild the restored cage still needs.
/// * the rest is generated noise that restore recreates.
const BACKUP_EXCLUDE: &[&str] = &[
    "creds",
    "pending_secrets.json",
    "cage-env",
    "secret_keys.json",
    "fingerprint.json",
    "cage.yaml.bak",
    "cage.yaml.rejected",
];

/// The config files restore has always known how to reinstall by name.
/// Anything else in the dir is build context — the Containerfile and
/// what it `COPY`s. `cli.py:510`.
const BACKUP_MANAGED_CONFIG: &[&str] = &["cage.yaml", "metadata.json", "proxy-config.yaml"];

/// Build noise that must never be copied into a backup: caches, VCS
/// metadata, dependency trees, soft-deleted leftovers.
/// `shutil.ignore_patterns` at `cli.py:479`, spelled out.
///
/// Applied at the top level of the state dir as well as inside it. The
/// Python's `copytree` only reaches the directories it walks, so a
/// *top-level* `__pycache__/` or `Containerfile.deleted.<ts>` would be
/// copied wholesale; `_copy_cage_state_dir` applies the same filter to
/// the first level by hand and so does [`stage_backup_config`].
fn is_build_noise(name: &str) -> bool {
    name == "__pycache__"
        || name == ".git"
        || name == "node_modules"
        // Case-sensitively, as `fnmatch` is on the hosts this runs on:
        // a file genuinely named `.PYC` is not bytecode.
        || Path::new(name).extension() == Some(std::ffi::OsStr::new("pyc"))
        // `*.deleted.*` — what `cage edit` renames a removed
        // Containerfile to, timestamp and all.
        || name.contains(".deleted.")
}

// ─────────────────────────────────────────────────────────
// cage backup
// ─────────────────────────────────────────────────────────

/// `cage backup` — the body.
pub(crate) fn backup(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match backup_inner(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one body, matching `cli.py:3355`. The archive is assembled \
              in the order the Python's staging directory is filled, and \
              each section's decisions feed the manifest at the end — \
              splitting it would mean passing the member list and five \
              flags through helpers that mean nothing apart from this \
              sequence. Same reasoning as `create.rs`."
)]
fn backup_inner(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let include_secrets = matches.get_flag("include_secrets");

    if !ctx.paths.deployment_exists(&name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, &name)?;

    let config = ctx
        .paths
        .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    // `_is_apple_container(cfg)` — `cli.py:3652`, which is a one-line
    // read of `cfg.isolation` (`cli.py:68`) and not a backend probe.
    // Dispatched on the string here for the same reason: the apple
    // branch needs no backend handle at all. The only thing the Python
    // constructs an `AppleContainerBackend` for in `_cage_backup_
    // apple_container` is `logs_dir(name)`, which in the port is a
    // pure [`Paths`] accessor. `domain.rs` and `cage/logs.rs` branch
    // the same way and reach for `as_apple()` only where there is
    // actually a backend call to make — which, for backup, there is not.
    if config.isolation == APPLE_CONTAINER {
        return backup_apple(ctx, &name, &config, matches);
    }
    require_container_backend(&config, "cage backup")?;

    let output = matches.get_one::<String>("output").map_or_else(
        || PathBuf::from(format!("{name}-backup-{}.tar.gz", file_timestamp())),
        PathBuf::from,
    );

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let mut members: Vec<Member> = Vec::new();

    // ── Config ──────────────────────────────────────────
    //
    // The *whole* state dir minus [`BACKUP_EXCLUDE`], not a fixed
    // filename allowlist: a cage that builds from a staged
    // `Containerfile` has to carry that Containerfile and everything it
    // `COPY`s, or the tarball cannot rebuild it on a clean host.
    let state_dir = ctx.paths.deployment_dir(&name);
    let config_members = stage_backup_config(&state_dir);
    let has_build_context = build_context_included(&state_dir, &config_members);
    members.extend(config_members);

    // ── Secrets ─────────────────────────────────────────
    //
    // Two different lists, and the difference is the whole reason the
    // manifest has both `secret_keys` and `secrets_included`:
    // `expected` is what the *config* asks for (injection rules, podman
    // secrets, relay credentials and the agents' shared api_key), while
    // `stored` is what the store happens to hold right now. The
    // manifest records the first, so a restore can tell the operator
    // what to set; the archive carries the second, because that is all
    // there is to carry.
    let expected = services::expected_secrets(&config);
    let prefix = format!("{name}.");
    let stored: Vec<String> = podman
        .secret_list(&prefix)
        .unwrap_or_default()
        .into_iter()
        .map(|full| full[prefix.len().min(full.len())..].to_owned())
        .collect();

    if include_secrets {
        eprintln!("WARNING: Including secrets in backup. Store the tarball securely.");
        if !stored.is_empty() {
            members.push(Member::Dir(format!("{ROOT}/secrets")));
            for key in &stored {
                let value = podman.secret_read(&format!("{prefix}{key}")).map_err(|e| {
                    eprintln!("error: could not read secret '{key}': {e}");
                    ExitCode::from(EXIT_FAILURE)
                })?;
                members.push(Member::File(
                    format!("{ROOT}/secrets/{key}"),
                    value.into_bytes(),
                ));
            }
        }
    } else {
        println!(
            "Secrets not included. Use --include-secrets to include them. \
             You will need to re-set secrets after restore."
        );
    }

    // ── Volumes ─────────────────────────────────────────
    //
    // Exported to the staging directory rather than into memory: a
    // named volume is a workspace, and `podman volume export` writes a
    // tar of whatever is in it.
    let staging = TempDir::new("agentcage-backup-").map_err(|error| {
        eprintln!("error: could not create a staging directory: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    let mut volume_names: Vec<String> = Vec::new();
    if config.isolation == "container" && !config.container.named_volumes.is_empty() {
        members.push(Member::Dir(format!("{ROOT}/volumes")));
        for volume in config.container.named_volumes.keys() {
            if podman.volume_exists(volume).unwrap_or(false) {
                let exported = staging.path().join(format!("{volume}.tar"));
                if let Err(error) = podman.volume_export(volume, &exported.display().to_string()) {
                    eprintln!("error: could not export volume '{volume}': {error}");
                    return Err(ExitCode::from(EXIT_FAILURE));
                }
                members.push(Member::FileFrom(
                    format!("{ROOT}/volumes/{volume}.tar"),
                    exported,
                ));
                volume_names.push(volume.clone());
            } else {
                eprintln!("warning: volume '{volume}' does not exist, skipping");
            }
        }
    }

    // ── Capture ─────────────────────────────────────────
    let capture = ctx.paths.capture_file(&name);
    let has_capture = capture
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.len() > 0);
    if has_capture {
        members.push(Member::Dir(format!("{ROOT}/capture")));
        members.push(Member::FileFrom(
            format!("{ROOT}/capture/capture.jsonl"),
            capture,
        ));
    }

    // ── Manifest ────────────────────────────────────────
    //
    // Key order is the Python's `dict` literal order, which is what
    // `json.dumps` writes and what a human diffing two backups sees.
    let manifest = Json::Object(vec![
        ("format_version".to_owned(), Json::Int(FORMAT_VERSION)),
        (
            "agentcage_version".to_owned(),
            Json::string(ctx.version.clone()),
        ),
        ("cage_name".to_owned(), Json::string(name.clone())),
        (
            "isolation".to_owned(),
            Json::string(config.isolation.clone()),
        ),
        (
            "timestamp".to_owned(),
            Json::string(DateTime::now_utc().isoformat()),
        ),
        ("has_secrets".to_owned(), Json::Bool(!expected.is_empty())),
        ("has_capture".to_owned(), Json::Bool(has_capture)),
        (
            "named_volumes".to_owned(),
            Json::Array(
                volume_names
                    .iter()
                    .map(|name| Json::string(name.as_str()))
                    .collect(),
            ),
        ),
        (
            "secret_keys".to_owned(),
            Json::Array(
                expected
                    .iter()
                    .map(|key| Json::string(key.as_str()))
                    .collect(),
            ),
        ),
        (
            "secrets_included".to_owned(),
            Json::Bool(include_secrets && !stored.is_empty()),
        ),
        (
            "build_context_included".to_owned(),
            Json::Bool(has_build_context),
        ),
    ]);
    members.push(Member::File(
        format!("{ROOT}/manifest.json"),
        format!("{}\n", dumps(&manifest, DumpOptions::indented())).into_bytes(),
    ));

    archive::write_targz(&output, &members).map_err(|error| {
        eprintln!("error: could not write {}: {error}", output.display());
        ExitCode::from(EXIT_FAILURE)
    })?;

    println!("Backup saved to {}", output.display());
    println!(
        "  Secrets: {} keys ({})",
        stored.len(),
        if include_secrets {
            "included"
        } else {
            "not included"
        }
    );
    println!("  Volumes: {}", volume_names.len());
    println!("  Capture: {}", if has_capture { "yes" } else { "no" });
    Ok(())
}

/// `cage backup` on the apple-container backend —
/// `_cage_backup_apple_container`, `cli.py:3400`.
///
/// Three things differ from the container path, and all three are
/// facts about the backend rather than choices this command makes.
/// The docstring at `cli.py:3403` enumerates them and this is that
/// list:
///
/// * **No host secret store.** This backend's secrets are env-passed
///   at start out of the invoking shell's environment, so after start
///   there is nothing on the host to read a value back out of — the
///   values were never agentcage's to keep. `--include-secrets` is
///   therefore a *refusal* and not a silent no-op: writing a tarball
///   with no secrets in it in response to a flag that asks for them is
///   how a restore ends up quietly credential-less. What travels is
///   the env *names*, so the restore host knows what to export.
/// * **No named volumes.** apple-container has no podman volume
///   equivalent; `container.named_volumes` is one of the knobs this
///   backend silently drops, so the manifest's `named_volumes` is
///   always `[]` and no `volumes/` member is emitted at all. (The
///   container path emits an *empty* `volumes/` directory whenever the
///   cage declares any, which is why the pinned fixture has one.)
/// * **Two log members.** `capture.jsonl` *and* `audit.jsonl` both sit
///   in the per-cage logs dir that the egress microVM bind-mounts
///   ([`Paths::apple_logs_dir`]). On a container cage the capture is
///   under `$XDG_DATA_HOME` and the audit stream is the journal, with
///   no file to carry — hence the extra `audit/` member here, and the
///   extra `has_audit` manifest key that goes with it.
///
/// [`Paths::apple_logs_dir`]: agentcage_state::Paths::apple_logs_dir
fn backup_apple(
    ctx: &Ctx,
    name: &str,
    config: &Config,
    matches: &ArgMatches,
) -> Result<(), ExitCode> {
    if matches.get_flag("include_secrets") {
        eprintln!(
            "error: --include-secrets is not supported on apple-container \
             (secrets are env-passed at start from the host environment, \
             not stored in a secret store; the backup manifest records the \
             expected env names so you can re-set them on the restore host)"
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let output = matches.get_one::<String>("output").map_or_else(
        || PathBuf::from(format!("{name}-backup-{}.tar.gz", file_timestamp())),
        PathBuf::from,
    );

    // ── Config ──────────────────────────────────────────
    //
    // Shared with the container path, exclusions and build context and
    // all: a cage's state dir is the state dir whatever runs it.
    let state_dir = ctx.paths.deployment_dir(name);
    let mut members = stage_backup_config(&state_dir);
    let has_build_context = build_context_included(&state_dir, &members);

    // ── Secret env names, no values ─────────────────────
    //
    // `cfg.secret_injection` alone, *not* `expected_secrets`. The
    // container path records the wider list — injection rules plus
    // podman secrets, relay credentials and the agents' shared
    // `api_key` — because those are things its store can hold. Here
    // the manifest is a note to the operator about what to `export`,
    // and only an injection rule names an env var to export. The
    // difference is observable in `secret_keys`, so it is reproduced
    // rather than unified with the call above.
    let secret_envs: Vec<&str> = config
        .secret_injection
        .iter()
        .map(|rule| rule.env.as_str())
        .collect();
    if !secret_envs.is_empty() {
        println!(
            "Secrets not included (apple-container env-pass model). \
             After restore, re-set these on the host environment: {}",
            secret_envs.join(", ")
        );
    }

    // ── Capture and audit ───────────────────────────────
    let logs_dir = ctx.paths.apple_logs_dir(name);
    let has_capture = carry_apple_log(&logs_dir, "capture", &mut members);
    let has_audit = carry_apple_log(&logs_dir, "audit", &mut members);

    // ── Manifest ────────────────────────────────────────
    //
    // Key order is the Python `dict` literal's at `cli.py:3476`, which
    // is *not* the container manifest's: `has_audit` is wedged in after
    // `has_capture`. A human diffing two backups sees this order, so it
    // is kept rather than normalized against the other branch.
    let manifest = Json::Object(vec![
        ("format_version".to_owned(), Json::Int(FORMAT_VERSION)),
        (
            "agentcage_version".to_owned(),
            Json::string(ctx.version.clone()),
        ),
        ("cage_name".to_owned(), Json::string(name)),
        ("isolation".to_owned(), Json::string(APPLE_CONTAINER)),
        (
            "timestamp".to_owned(),
            Json::string(DateTime::now_utc().isoformat()),
        ),
        (
            "has_secrets".to_owned(),
            Json::Bool(!secret_envs.is_empty()),
        ),
        ("has_capture".to_owned(), Json::Bool(has_capture)),
        ("has_audit".to_owned(), Json::Bool(has_audit)),
        // Not supported on apple-container, and so not a `Vec` that
        // something upstream might have filled: the empty literal is
        // the statement.
        ("named_volumes".to_owned(), Json::Array(Vec::new())),
        (
            "secret_keys".to_owned(),
            Json::Array(secret_envs.iter().map(|env| Json::string(*env)).collect()),
        ),
        // Never true on this backend — there is no store to read from,
        // which is what the refusal above is about. `cage restore`
        // reads this key to decide whether to look for a `secrets/`
        // member, so a `false` here is what keeps it from reporting a
        // missing one.
        ("secrets_included".to_owned(), Json::Bool(false)),
        (
            "build_context_included".to_owned(),
            Json::Bool(has_build_context),
        ),
    ]);
    members.push(Member::File(
        format!("{ROOT}/manifest.json"),
        format!("{}\n", dumps(&manifest, DumpOptions::indented())).into_bytes(),
    ));

    archive::write_targz(&output, &members).map_err(|error| {
        eprintln!("error: could not write {}: {error}", output.display());
        ExitCode::from(EXIT_FAILURE)
    })?;

    println!("Backup saved to {}", output.display());
    println!(
        "  Secrets: {} env names (values not stored — re-set on restore host)",
        secret_envs.len()
    );
    println!("  Volumes: 0 (not supported on apple-container)");
    println!("  Capture: {}", if has_capture { "yes" } else { "no" });
    // Two spaces of padding, as `cli.py:3502` writes it, so the four
    // summary values line up in a terminal.
    println!("  Audit:   {}", if has_audit { "yes" } else { "no" });
    Ok(())
}

/// Add `<logs_dir>/<sub>.jsonl` to the archive as `<sub>/<sub>.jsonl`,
/// and say whether it was there to add.
///
/// Zero length counts as absent, which is the `st_size > 0` at
/// `cli.py:3460`. It is not pedantry: `start` creates the logs dir and
/// the egress microVM's supervisor opens both files before it has
/// written a line, so an empty one is "no stream yet" rather than "a
/// stream of nothing" — and a member plus a `true` flag would promise
/// a restore content the archive does not hold.
fn carry_apple_log(logs_dir: &Path, sub: &str, members: &mut Vec<Member>) -> bool {
    let source = logs_dir.join(format!("{sub}.jsonl"));
    if !source
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.len() > 0)
    {
        return false;
    }
    members.push(Member::Dir(format!("{ROOT}/{sub}")));
    members.push(Member::FileFrom(
        format!("{ROOT}/{sub}/{sub}.jsonl"),
        source,
    ));
    true
}

/// The archive members for a cage's state dir. `cli.py:539`.
///
/// Walks the whole directory rather than naming three files, so a cage
/// that builds from a staged `Containerfile` carries its build context.
/// [`BACKUP_EXCLUDE`] is applied at the top level only — that is where
/// the generated state lives, and a `creds/` *inside* someone's build
/// context is their file, not ours — while [`is_build_noise`] applies
/// at every level.
///
/// Unreadable entries are skipped rather than fatal: a backup of most
/// of a cage is worth more than no backup, and the summary the command
/// prints is not a promise of completeness.
fn stage_backup_config(state_dir: &Path) -> Vec<Member> {
    let mut members = vec![Member::Dir(format!("{ROOT}/config"))];
    for (name, path) in read_sorted(state_dir) {
        if BACKUP_EXCLUDE.contains(&name.as_str()) || is_build_noise(&name) {
            continue;
        }
        collect_backup_entry(&path, &name, &mut members);
    }
    members
}

/// One state-dir entry and, for a directory, everything under it.
///
/// `relative` is the path inside `config/`, which is both the member
/// name and what [`archive::link_stays_inside`] judges a link against.
fn collect_backup_entry(path: &Path, relative: &str, members: &mut Vec<Member>) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    let name = format!("{ROOT}/config/{relative}");

    // Checked first, and never followed: `is_dir()`/`is_file()` both
    // resolve the link, so a link to a directory would be recursed into
    // and a link to a file would be copied by value — which is how a
    // link to `~/.ssh` ends up inside a backup.
    if meta.is_symlink() {
        let Ok(target) = std::fs::read_link(path) else {
            return;
        };
        let target = target.to_string_lossy().into_owned();
        if archive::link_stays_inside(Path::new(relative), &target) {
            members.push(Member::Symlink(name, target));
        } else {
            // Neither carried nor dereferenced. Carrying it makes the
            // whole tarball unrestorable — `extract_into` refuses it,
            // as does `tarfile`'s `data` filter — and dereferencing it
            // copies host content into the backup.
            eprintln!(
                "warning: skipped symlink {relative} -> {target} — it points \
                 outside the cage's config dir, which a backup cannot carry; \
                 re-create it on the restore host"
            );
        }
        return;
    }

    if meta.is_dir() {
        members.push(Member::Dir(name));
        for (child, child_path) in read_sorted(path) {
            if is_build_noise(&child) {
                continue;
            }
            collect_backup_entry(&child_path, &format!("{relative}/{child}"), members);
        }
        return;
    }

    if meta.is_file() {
        members.push(Member::FileFrom(name, path.to_owned()));
    }
}

/// A directory's entries as `(file name, path)`, sorted by name.
///
/// Sorted because `write_targz` sorts anyway and a stable walk makes
/// the warnings a backup prints reproducible; empty when the directory
/// cannot be read, which is the "skip rather than fail" above.
fn read_sorted(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut entries: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            )
        })
        .collect();
    entries.sort();
    entries
}

/// Is the Containerfile the restored `cage.yaml` will build from
/// actually in this archive? `cli.py:593`.
///
/// Deliberately *not* "the state dir held entries beyond the managed
/// config": every state dir has generated siblings — `dns-allowlist.conf`,
/// a scaffold's `AGENTS.md` — so that test could never be false, and a
/// manifest field that is always true tells a restore nothing. A cage
/// with no build step records false, because there is no build context
/// to carry.
///
/// Both halves have to hold: the file has to be *resolvable* inside the
/// state dir, and it has to have been *emitted* as a member. The second
/// is what makes a Containerfile that [`is_build_noise`] filtered out,
/// or one reached through a pruned symlink, report false rather than
/// promising a rebuild the tarball cannot do.
fn build_context_included(state_dir: &Path, members: &[Member]) -> bool {
    let containerfile = backup_containerfile(state_dir);
    let Some(relative) = carried_containerfile(state_dir, &containerfile) else {
        return false;
    };
    let name = format!("{ROOT}/config/{}", relative.display());
    members.iter().any(|member| member.name() == name)
}

/// `container.build.containerfile` from the `cage.yaml` in `dir`, or
/// `""`. `cli.py:616`.
///
/// Reads the document rather than taking the field off a parsed
/// [`Config`]: restore asks this of a directory unpacked from an
/// archive, where there is no loaded config and the document may be one
/// the loader would reject. Every failure is `""`, which means "no
/// build step" and so "nothing to check" — the config loader is what
/// reports a malformed document, a page later and with a better message.
fn backup_containerfile(dir: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(dir.join("cage.yaml")) else {
        return String::new();
    };
    let Ok(raw) = agentcage_core::yaml::load(&text) else {
        return String::new();
    };
    raw.get("container")
        .and_then(|container| container.get("build"))
        .and_then(|build| build.get("containerfile"))
        .and_then(agentcage_core::yaml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Resolve `containerfile` inside `dir`, or `None` if it is not carried
/// there. `cli.py:636`. Returns the path *relative to `dir`*.
///
/// Both escaping shapes are refused rather than joined. Rust's
/// `Path::join` discards `dir` entirely when the argument is absolute —
/// the same trap as Python's `Path.__truediv__` — and `..` segments
/// climb out, so a naive join reports a file that exists only on the
/// host as one the backup carries. That is the difference between
/// `build_context_included: true` and a restore that can actually build.
fn carried_containerfile(dir: &Path, containerfile: &str) -> Option<PathBuf> {
    if containerfile.is_empty() || Path::new(containerfile).is_absolute() {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in Path::new(containerfile).components() {
        match component {
            std::path::Component::Normal(part) => relative.push(part),
            std::path::Component::CurDir => {}
            // `a/../Containerfile` is accepted by the Python, which
            // resolves before it checks; only a climb that actually
            // leaves `dir` is refused.
            std::path::Component::ParentDir => {
                if !relative.pop() {
                    return None;
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
        }
    }
    if relative.as_os_str().is_empty() {
        return None;
    }
    dir.join(&relative).is_file().then_some(relative)
}

// ─────────────────────────────────────────────────────────
// cage restore
// ─────────────────────────────────────────────────────────

/// What `cage restore` reads out of `manifest.json`.
///
/// Every field is optional in the same way the Python's `.get(...)`
/// calls make it optional, except `cage_name`, which `cli.py:3505`
/// subscripts directly — a manifest without one is a `KeyError` there
/// and a named refusal here.
#[derive(Debug)]
struct Manifest {
    format_version: i64,
    cage_name: String,
    isolation: String,
    secret_keys: Vec<String>,
    secrets_included: bool,
    named_volumes: Vec<String>,
    /// Only ever reported back to the operator, never trusted: the
    /// preflight looks at what the archive *holds*, because a manifest
    /// is the part of a backup a person can edit.
    build_context_included: bool,
}

impl Manifest {
    fn parse(text: &str) -> Option<Self> {
        let value = parse_json(text).ok()?;
        let strings = |key: &str| -> Vec<String> {
            match value.get(key) {
                Some(Json::Array(items)) => items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                    .collect(),
                _ => Vec::new(),
            }
        };
        Some(Self {
            format_version: match value.get("format_version") {
                Some(&Json::Int(version)) => version,
                _ => 0,
            },
            cage_name: value.get("cage_name")?.as_str()?.to_owned(),
            isolation: value
                .get("isolation")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
            secret_keys: strings("secret_keys"),
            secrets_included: value.get("secrets_included").is_some_and(Json::is_truthy),
            named_volumes: strings("named_volumes"),
            build_context_included: value
                .get("build_context_included")
                .is_some_and(Json::is_truthy),
        })
    }
}

/// `cage restore` — the body.
pub(crate) fn restore(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match restore_inner(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one body, matching `cli.py:3473`. As in `create.rs`: every \
              step reads what the previous one wrote, the order is \
              observable from outside, and splitting it would thread \
              half a dozen intermediates through helpers that mean \
              nothing apart from this sequence."
)]
fn restore_inner(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let tarball = PathBuf::from(
        matches
            .get_one::<String>("tarball")
            .expect("required by the parser"),
    );
    let new_name = matches.get_one::<String>("new_name").map(String::as_str);
    let force = matches.get_flag("force");
    let no_start = matches.get_flag("no_start");

    // ── Read manifest ───────────────────────────────────
    //
    // One divergence, and it is an improvement: a tarball that is not a
    // gzip stream at all raises an uncaught `tarfile.ReadError` in the
    // Python and prints a traceback. Here every unreadable archive —
    // not gzip, truncated, no manifest, malformed manifest — lands on
    // the same one-line refusal `cli.py:3485` writes for the last two.
    let manifest = match archive::read_member(&tarball, &format!("{ROOT}/manifest.json")) {
        Ok(Some(bytes)) => Manifest::parse(&String::from_utf8_lossy(&bytes)),
        Ok(None) => None,
        Err(error) => {
            eprintln!("error: invalid backup — {error}");
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    };
    let Some(manifest) = manifest else {
        eprintln!("error: invalid backup — missing or corrupt manifest.json");
        return Err(ExitCode::from(EXIT_FAILURE));
    };

    // ── Validate ────────────────────────────────────────
    if manifest.format_version > FORMAT_VERSION {
        eprintln!(
            "error: unsupported backup format version {} \
             (this agentcage supports version {FORMAT_VERSION})",
            manifest.format_version
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    let target = new_name.unwrap_or(&manifest.cage_name).to_owned();
    if !is_valid_cage_name(&target) {
        eprintln!(
            "error: name must be 1-63 lowercase alphanumeric characters or \
             hyphens, starting with a letter or digit (got: '{target}')"
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    // ── Extract ─────────────────────────────────────────
    //
    // Into a 0700 directory: a `--include-secrets` backup holds bare
    // credentials, and `$TMPDIR` is usually world-traversable.
    //
    // Before the `--force` destroy below, and before any secret is
    // created, because every refusal from here to the end of the
    // preflight is a `return Err` — and `--force` destroys the cage and
    // clears its state dir. An abort after that point leaves the host
    // with neither the old cage nor a restored one, and with orphaned
    // `<target>.KEY` podman secrets. That was the bug: the destroy was
    // first and the archive was never even opened until after it.
    let staging = TempDir::new("agentcage-restore-").map_err(|error| {
        eprintln!("error: could not create a staging directory: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    if let Err(error) = archive::extract_into(&tarball, staging.path()) {
        eprintln!("error: invalid backup — {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    let backup_dir = staging.path().join(ROOT);

    // ── Preflight ───────────────────────────────────────
    let config_src = backup_dir.join("config");
    if !config_src.join("cage.yaml").is_file() {
        eprintln!("error: invalid backup — missing config/cage.yaml");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    check_restore_build_context(&manifest, &config_src)?;

    // `cli.py:3786` branches on the *manifest's* `isolation`, not on
    // the archived `cage.yaml`'s and not on anything installed on this
    // host: a restore onto a clean machine has no stored config to
    // read, and the manifest is what says which shape the tarball is.
    //
    // The branch is here, after extraction and the preflight, rather
    // than at the top where the Python's is. `_cage_restore_apple_
    // container` repeats all four of those steps verbatim
    // (`cli.py:3531`-`3543`) — including the comment about why they
    // come before the `--force` destroy — and the one thing that must
    // not exist in two copies is that ordering.
    if manifest.isolation == APPLE_CONTAINER {
        return restore_apple(
            ctx,
            &tarball,
            &manifest,
            &target,
            &backup_dir,
            new_name,
            force,
            no_start,
        );
    }

    // ── Handle an existing cage ─────────────────────────
    if ctx.paths.deployment_exists(&target) {
        if !force {
            eprintln!("error: cage '{target}' already exists (use --force to overwrite)");
            return Err(ExitCode::from(EXIT_FAILURE));
        }
        println!("Destroying existing cage '{target}'...");
        let backend = ctx.backend();
        backend.stop(&target);
        if let Err(error) = backend.destroy_resources(&target, false) {
            eprintln!("warning: {error}");
        }
        if ctx.paths.deployment_exists(&target) {
            if let Err(error) = ctx.paths.remove_deployment(&target) {
                eprintln!("warning: {error}");
            }
        }
    }

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());

    restore_secrets(&podman, &manifest, &target, &backup_dir);
    restore_config(ctx, &target, &backup_dir, new_name)?;

    // ── Build and deploy ────────────────────────────────
    if no_start {
        println!("Cage state restored. Run: agentcage cage update {target} to build and start.");
        if !manifest.named_volumes.is_empty() {
            println!(
                "Note: Named volumes will be imported when the cage is \
                 started for the first time."
            );
        }
    } else {
        let config = ctx
            .paths
            .load_deployment_config(&target, &agentcage_cli::hostenv::RealHost)
            .map_err(|error| {
                eprintln!("error: {error}");
                ExitCode::from(EXIT_FAILURE)
            })?;
        require_container_backend(&config, "cage restore")?;

        if !manifest.secrets_included && !manifest.secret_keys.is_empty() {
            let env = agentcage_cli::secrets::SystemEnv;
            let missing = services::check_secrets(&podman, &ctx.paths, &target, &config, &env);
            if !missing.is_empty() {
                eprintln!(
                    "warning: {} secrets are missing — cage may fail to start",
                    missing.len()
                );
            }
        }

        let config_host_path = ctx.paths.proxy_config_path(&target);
        let backend = ctx.ensure_backend_ready(&config)?;
        // No exclusion, and no pinned octet: the restored cage's own
        // `network_octet` came out of the archived `metadata.json` and
        // may belong to a cage that already exists on *this* host.
        // `cli.py:3640` collects every used octet — including the
        // target's own, which is why the allocator has to be free to
        // move it.
        let used = services::collect_used_octets(&ctx.paths, "");
        services::build_and_deploy(
            &backend,
            &ctx.paths,
            &services::DeployPlan {
                config: &config,
                config_host_path: &config_host_path.display().to_string(),
                deploy_name: &target,
                used_octets: Some(&used),
                network_octet: None,
                quiet: false,
                no_cache: false,
                pull: false,
            },
        )
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;

        // ── Import named volumes ────────────────────────
        //
        // After the deploy and with the cage stopped again: podman
        // refuses to import into a volume a running container holds.
        let volumes_dir = backup_dir.join("volumes");
        let mut exported: Vec<PathBuf> = std::fs::read_dir(&volumes_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "tar"))
            .collect();
        exported.sort();
        if !exported.is_empty() {
            println!("Importing volumes...");
            backend.stop(&target);
            for archive_path in exported {
                let volume = archive_path
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if let Err(error) =
                    podman.volume_import(&volume, &archive_path.display().to_string())
                {
                    eprintln!("warning: could not import volume '{volume}': {error}");
                    continue;
                }
                println!("  Imported volume '{volume}'");
            }
            if let Err(error) = backend.start(&config.name, false) {
                eprintln!("error: {error}");
                return Err(ExitCode::from(EXIT_FAILURE));
            }
        }
    }

    restore_capture(ctx, &target, &backup_dir);

    println!("Cage '{target}' restored from {}", tarball.display());
    Ok(())
}

/// `cage restore` on the apple-container backend —
/// `_cage_restore_apple_container`, `cli.py:3505`.
///
/// The mirror of [`backup_apple`], and the mirror is what makes it
/// short: every host-podman step the container path takes is one this
/// backend does not have. There is no secret store to write into — the
/// archive carries no values, so the operator is handed the `export`
/// lines instead — and no volume to import. What is *extra* is the
/// pair of log files, which go back before `start` rather than after,
/// because this backend's `start` creates the logs dir and chmods it
/// to 1777 while leaving whatever is already in it alone. On the
/// container path the capture is restored last, since `build_and_deploy`
/// never touches it.
///
/// Called with extraction and the build-context preflight already
/// done; see the dispatch in [`restore_inner`] for why they are not
/// repeated here.
#[expect(
    clippy::too_many_arguments,
    reason = "the three flags and the three names `cage restore` was \
              invoked with, which is what `_cage_restore_apple_container` \
              takes too (`tarball`, `manifest`, `new_name`, `force`, \
              `no_start`) plus the two things the shared prefix in \
              `restore_inner` has already computed from them — the \
              validated target name and the extracted archive's root. \
              Re-deriving either here would be a second copy of a \
              decision the caller has made."
)]
fn restore_apple(
    ctx: &Ctx,
    tarball: &Path,
    manifest: &Manifest,
    target: &str,
    backup_dir: &Path,
    new_name: Option<&str>,
    force: bool,
    no_start: bool,
) -> Result<(), ExitCode> {
    // ── Handle an existing cage ─────────────────────────
    if ctx.paths.deployment_exists(target) {
        if !force {
            eprintln!("error: cage '{target}' already exists (use --force to overwrite)");
            return Err(ExitCode::from(EXIT_FAILURE));
        }
        println!("Destroying existing cage '{target}'...");
        // The backend of the cage that is *here*, not of the tarball:
        // restoring an apple-container backup over a cage that is
        // currently a container one has to stop and destroy it with
        // podman, or its units and network outlive it. `cli.py:3550`
        // loads the stored config for exactly that, and falls back to
        // the **apple** backend when it cannot be loaded — not to the
        // container one `Ctx::backend_of` defaults to, because in this
        // branch the tarball is the only evidence of what the cage is.
        //
        // One divergence: the Python's `except Exception` also wraps
        // the `stop`/`destroy_resources` calls, so a backend that
        // *throws* gets retried against the apple one. Here a failed
        // destroy is a warning and the restore continues, which is what
        // the container path above does and what `cage destroy` itself
        // does — a second attempt through a backend that was already
        // ruled out cannot succeed where the first failed, and the
        // state dir is removed either way on the next line.
        let isolation = ctx
            .paths
            .load_deployment_config(target, &agentcage_cli::hostenv::RealHost)
            .map_or_else(|_| APPLE_CONTAINER.to_owned(), |config| config.isolation);
        let backend = ctx.backend_for(&isolation);
        backend.stop(target);
        if let Err(error) = backend.destroy_resources(target, false) {
            eprintln!("warning: {error}");
        }
        if ctx.paths.deployment_exists(target) {
            if let Err(error) = ctx.paths.remove_deployment(target) {
                eprintln!("warning: {error}");
            }
        }
    }

    // ── Secrets, which are the operator's to re-set ─────
    //
    // The whole of this backend's secret restore. There is no store to
    // check a key against, so unlike [`restore_secrets`] this cannot
    // narrow the list to the ones that are actually missing — every
    // recorded name is printed, because from the host's side they are
    // all equally unknowable.
    if !manifest.secret_keys.is_empty() {
        eprintln!(
            "Secrets are env-passed at start on apple-container — set \
             these on the host environment before `cage start`:"
        );
        for key in &manifest.secret_keys {
            eprintln!("  export {key}=<value>");
        }
    }

    restore_config(ctx, target, backup_dir, new_name)?;

    // ── capture.jsonl / audit.jsonl ─────────────────────
    //
    // Into the logs dir the egress microVM bind-mounts, and before the
    // `start` below for the reason in this function's docs. A failure
    // is a warning: the config is already installed, and losing a
    // *log* must not turn a successful restore into a failed one.
    let logs_dir = ctx.paths.apple_logs_dir(target);
    if let Err(error) = std::fs::create_dir_all(&logs_dir) {
        eprintln!("warning: could not create {}: {error}", logs_dir.display());
    }
    for sub in ["capture", "audit"] {
        let source = backup_dir.join(format!("{sub}/{sub}.jsonl"));
        if source.is_file() {
            if let Err(error) = std::fs::copy(&source, logs_dir.join(format!("{sub}.jsonl"))) {
                eprintln!("warning: could not restore {sub}.jsonl: {error}");
            }
        }
    }

    if no_start {
        println!("Cage state restored. Run: agentcage cage update {target} to build and start.");
        // No named-volume note, unlike the container path: this
        // backend has none to import, and the manifest's list is empty
        // by construction.
        return Ok(());
    }

    let config = ctx
        .paths
        .load_deployment_config(target, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;

    // Not `build_and_deploy`: that is the container/vm path, with host
    // podman, quadlets and an octet allocator. `cli.py:3628` drives
    // this backend's own build and start directly and says so in a
    // comment, so this does too.
    //
    // The backend is the archive's, unconditionally, as the Python's
    // `AppleContainerBackend()` is — not `backend_for(&config.isolation)`.
    // A hand-edited tarball whose manifest says `apple-container` and
    // whose `cage.yaml` says something else would otherwise dispatch
    // on the document and land on a backend that cannot have produced
    // this archive's shape.
    let backend = ctx.backend_for(APPLE_CONTAINER);
    let Some(apple) = backend.as_apple() else {
        eprintln!("error: internal: apple isolation resolved to another backend");
        return Err(ExitCode::from(EXIT_FAILURE));
    };
    apple
        .build_artifacts(&config, target, false, false, false)
        .map_err(|error| report_backend_error(&error))?;
    // Called once. The Python calls `generate_units` twice and throws
    // the first result away (`cli.py:3629`-`3632`), which is harmless
    // but double-prints the `container.volumes` warnings the renderer
    // emits. One call, one set of warnings.
    let units = apple
        .generate_units(&config, target)
        .map_err(|error| report_backend_error(&error))?;
    apple
        .install_units(&units, false)
        .map_err(|error| report_backend_error(&error))?;
    apple
        .start(target, false)
        .map_err(|error| report_backend_error(&error))?;

    println!("Cage '{target}' restored from {}", tarball.display());
    Ok(())
}

/// A backend failure, reported the way every other command body
/// reports one: the message the backend already phrased for the
/// operator, and click's exit status.
fn report_backend_error(error: &BackendError) -> ExitCode {
    eprintln!("error: {error}");
    ExitCode::from(EXIT_FAILURE)
}

/// Put the archived secret values back into the podman store, or tell
/// the operator which ones they have to set by hand.
///
/// Best-effort, as the Python is: a store that cannot be written is a
/// warning, because the config has already been extracted and the
/// operator can set the secrets afterwards. A `return Err` here would
/// leave the cage half-restored with nothing said about it.
fn restore_secrets(
    podman: &agentcage_exec::tools::podman::Podman<'_>,
    manifest: &Manifest,
    target: &str,
    backup_dir: &Path,
) {
    let secrets_dir = backup_dir.join("secrets");
    if secrets_dir.is_dir() && manifest.secrets_included {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&secrets_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().is_file())
            .map(|entry| entry.path())
            .collect();
        files.sort();
        let mut restored = 0usize;
        for file in files {
            let key = file.file_name().map(|n| n.to_string_lossy().into_owned());
            let (Some(key), Ok(value)) = (key, std::fs::read_to_string(&file)) else {
                continue;
            };
            let full = format!("{target}.{key}");
            if podman.secret_exists(&full).unwrap_or(false) {
                let _ = podman.secret_remove(&full);
            }
            match podman.secret_create(&full, &value) {
                Ok(()) => restored += 1,
                Err(error) => eprintln!("warning: could not restore secret '{key}': {error}"),
            }
        }
        println!("Restored {restored} secrets.");
        return;
    }

    if manifest.secrets_included || manifest.secret_keys.is_empty() {
        return;
    }
    let missing: Vec<&String> = manifest
        .secret_keys
        .iter()
        .filter(|key| {
            !podman
                .secret_exists(&format!("{target}.{key}"))
                .unwrap_or(false)
        })
        .collect();
    if missing.is_empty() {
        return;
    }
    eprintln!("Secrets were not included in this backup. Set them with:");
    for key in missing {
        eprintln!("  agentcage secret set {target} {key}");
    }
}

/// Install the archived `cage.yaml` and `metadata.json`, then
/// regenerate everything derived from them.
///
/// `new_name` is `Some` only for a clone: the `name:` field inside the
/// document has to agree with the directory it is stored under, or
/// every later command addresses the wrong cage. The rewrite goes
/// through the YAML loader and emitter, exactly as `cli.py:3578` does,
/// which means it **drops comments** — a cost the Python already pays
/// and the one place a restore is not byte-faithful.
fn restore_config(
    ctx: &Ctx,
    target: &str,
    backup_dir: &Path,
    new_name: Option<&str>,
) -> Result<(), ExitCode> {
    let config_src = backup_dir.join("config");
    let cage_yaml = config_src.join("cage.yaml");
    if !cage_yaml.is_file() {
        eprintln!("error: invalid backup — missing config/cage.yaml");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    if let Some(new_name) = new_name {
        let text = std::fs::read_to_string(&cage_yaml).map_err(|error| {
            eprintln!("error: {}: {error}", cage_yaml.display());
            ExitCode::from(EXIT_FAILURE)
        })?;
        let mut raw = agentcage_core::yaml::load(&text).map_err(|error| {
            eprintln!("error: invalid backup — config/cage.yaml: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
        let Some(mapping) = raw.as_mapping_mut() else {
            eprintln!("error: invalid backup — config/cage.yaml is not a mapping");
            return Err(ExitCode::from(EXIT_FAILURE));
        };
        mapping.insert(
            agentcage_core::yaml::Value::String("name".to_owned()),
            agentcage_core::yaml::Value::String(new_name.to_owned()),
        );
        let dumped = agentcage_core::yaml::dump(&raw).map_err(|error| {
            eprintln!("error: could not rewrite config/cage.yaml: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
        std::fs::write(&cage_yaml, dumped).map_err(|error| {
            eprintln!("error: {}: {error}", cage_yaml.display());
            ExitCode::from(EXIT_FAILURE)
        })?;
    }

    // `save_deployment` validates the document before it copies it, so
    // an archive carrying a `cage.yaml` no other command would accept
    // is refused here rather than three steps later in the renderer.
    ctx.paths
        .save_deployment(target, &cage_yaml)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;

    let metadata_src = config_src.join("metadata.json");
    if metadata_src.is_file() {
        let dest = ctx.paths.metadata_path(target);
        if let Err(error) = std::fs::copy(&metadata_src, &dest) {
            eprintln!("warning: could not restore metadata.json: {error}");
        }
    }

    // Reinstall the build context. `--force` cleared the state dir via
    // `remove_deployment`, so anything an operator staged there by hand
    // is already gone; the tarball is the only source.
    restore_build_context(&config_src, &ctx.paths.deployment_dir(target));

    // Regenerated, not restored. See the module docs.
    ctx.paths
        .save_proxy_config(target, &ctx.version)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    ctx.paths
        .save_dns_allowlist(target, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    Ok(())
}

/// Refuse, before anything destructive or expensive happens, a backup
/// that cannot rebuild the cage. `cli.py:662`.
///
/// A `cage.yaml` whose `container.build.containerfile` names a file the
/// archive does not carry cannot be rebuilt on a clean host. Without
/// this the failure surfaces much later as an opaque "local-only image
/// is not present in the local image store" from the backend — and,
/// with `--force`, only *after* the existing cage has been destroyed.
fn check_restore_build_context(manifest: &Manifest, config_src: &Path) -> Result<(), ExitCode> {
    let containerfile = backup_containerfile(config_src);
    if containerfile.is_empty() {
        // No build step: nothing to rebuild and nothing to carry.
        return Ok(());
    }
    if carried_containerfile(config_src, &containerfile).is_some() {
        return Ok(());
    }
    if Path::new(&containerfile).is_absolute() {
        // An absolute containerfile lives outside the cage's state dir,
        // so a backup never carries it; the build reads it straight off
        // the host. Check the path the build will actually use rather
        // than joining it onto `config_src`, which `Path::join` would
        // silently discard.
        if Path::new(&containerfile).is_file() {
            return Ok(());
        }
        eprintln!(
            "error: this backup cannot rebuild the cage — its cage.yaml builds \
             from the absolute path '{containerfile}', which is outside the \
             backup and does not exist on this host.\n  \
             Restore with --no-start, stage the build context into the cage's \
             config dir, point container.build.containerfile at it, and run \
             'agentcage cage update <name>'."
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    // `True`/`False`, not Rust's `false`: the operator reading this is
    // being told what to look for in `manifest.json`, which is JSON
    // written by a Python `json.dumps` in every backup taken so far.
    let flag = if manifest.build_context_included {
        "True"
    } else {
        "False"
    };
    eprintln!(
        "error: this backup cannot rebuild the cage — its cage.yaml builds from \
         '{containerfile}', which the tarball does not contain \
         (build_context_included={flag}).\n  \
         Backups taken before the build context was included omit it. Either \
         re-take the backup with a newer agentcage, or restore with --no-start, \
         stage the build context into the cage's config dir, and run \
         'agentcage cage update <name>'."
    );
    Err(ExitCode::from(EXIT_FAILURE))
}

/// Reinstall a backup's build context into a cage's state dir.
/// `cli.py:653`.
///
/// [`BACKUP_MANAGED_CONFIG`] is skipped because restore installs those
/// three by name — through `save_deployment`, which validates. And
/// [`BACKUP_EXCLUDE`] is skipped *again* here, on the way out: the
/// archive this reads may not be one agentcage wrote, and a hand-made
/// tarball carrying `secret_keys.json` must not be able to plant the
/// keychain index in a restored cage. That is the whole reason the
/// exclusion is applied in both directions rather than only at backup.
fn restore_build_context(config_src: &Path, deploy_dir: &Path) {
    for (name, path) in read_sorted(config_src) {
        if BACKUP_MANAGED_CONFIG.contains(&name.as_str()) || BACKUP_EXCLUDE.contains(&name.as_str())
        {
            continue;
        }
        copy_restored_entry(&path, &deploy_dir.join(&name));
    }
}

/// Copy one extracted entry into the state dir, links as links.
///
/// Best-effort per entry, as the rest of restore is: a build context
/// that is missing a file fails the rebuild with a message about that
/// file, which is better than a restore that refuses at the last step.
fn copy_restored_entry(source: &Path, dest: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(source) else {
        return;
    };

    if meta.is_symlink() {
        let Ok(target) = std::fs::read_link(source) else {
            return;
        };
        // Whatever is in the way, including a directory.
        if std::fs::symlink_metadata(dest).is_ok() {
            let removed = if dest.is_dir() && !dest.is_symlink() {
                std::fs::remove_dir_all(dest)
            } else {
                std::fs::remove_file(dest)
            };
            if removed.is_err() {
                return;
            }
        }
        if let Err(error) = std::os::unix::fs::symlink(&target, dest) {
            eprintln!(
                "warning: could not restore symlink {}: {error}",
                dest.display()
            );
        }
        return;
    }

    if meta.is_dir() {
        if let Err(error) = std::fs::create_dir_all(dest) {
            eprintln!("warning: could not restore {}: {error}", dest.display());
            return;
        }
        for (name, child) in read_sorted(source) {
            copy_restored_entry(&child, &dest.join(&name));
        }
        return;
    }

    if meta.is_file() {
        if let Err(error) = std::fs::copy(source, dest) {
            eprintln!("warning: could not restore {}: {error}", dest.display());
        }
    }
}

/// Copy the archived `capture.jsonl` back into the cage's data dir.
///
/// Last, and best-effort: the cage is already running by the time this
/// happens, and a failure to restore a *log* must not turn a successful
/// restore into a failed one.
fn restore_capture(ctx: &Ctx, target: &str, backup_dir: &Path) {
    let source = backup_dir.join("capture/capture.jsonl");
    if !source.is_file() {
        return;
    }
    let dest = ctx.paths.capture_file(target);
    // `state.capture_dir` creates the directory on the way past; the
    // Rust `Paths` accessor is pure, so the mkdir is explicit.
    if let Some(parent) = dest.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("warning: could not restore capture.jsonl: {error}");
            return;
        }
    }
    if let Err(error) = std::fs::copy(&source, &dest) {
        eprintln!("warning: could not restore capture.jsonl: {error}");
    }
}

// ─────────────────────────────────────────────────────────
// shared
// ─────────────────────────────────────────────────────────

/// `^[a-z0-9][a-z0-9-]{0,62}$`, spelled out.
///
/// A restore is the one path that takes a cage name from a *file*
/// rather than from argv, and that name becomes a directory under
/// `~/.config/agentcage/cages/` and a podman secret prefix. `cli.py:3509`
/// checks it for exactly that reason and this is the same check.
fn is_valid_cage_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    name.len() <= 63 && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The `vm` / `apple-container` refusal, in the wording every other
/// ported command uses.
fn require_container_backend(config: &Config, command: &str) -> Result<(), ExitCode> {
    if config.isolation == "container" {
        return Ok(());
    }
    eprintln!(
        "error: `{command}` on the '{}' backend is not ported yet \
         (RUST-PORT-PLAN.md Track E)",
        config.isolation
    );
    Err(ExitCode::from(EXIT_FAILURE))
}

/// `datetime.datetime.now().strftime("%Y%m%d-%H%M%S")`, in UTC.
///
/// The one deliberate divergence in this PR, and it is confined to a
/// *default filename*: the Python uses local time and there is no
/// timezone database in this binary — `agentcage-core`'s `DateTime` is
/// forty lines of civil-calendar arithmetic written for `--since`, not
/// a date library, and adding one for a filename would be a poor trade.
/// Nothing parses this string; `cage restore` takes the path it is
/// given, and the e2e suite passes `-o`.
fn file_timestamp() -> String {
    let iso = DateTime::now_utc().isoformat();
    // `YYYY-MM-DDTHH:MM:SS…` → `YYYYMMDD-HHMMSS`.
    let (date, rest) = iso.split_at(10);
    let time: String = rest
        .chars()
        .skip(1)
        .take(8)
        .filter(char::is_ascii_digit)
        .collect();
    format!("{}-{time}", date.replace('-', ""))
}

#[cfg(test)]
mod tests {
    use super::{
        Manifest, ROOT, backup_inner, build_context_included, carried_containerfile,
        check_restore_build_context, file_timestamp, is_valid_cage_name, restore_build_context,
        restore_capture, restore_config, restore_inner, restore_secrets, stage_backup_config,
    };
    use crate::cli::context::Ctx;
    use agentcage_cli::archive::{self, Member};
    use agentcage_core::yaml;
    use agentcage_exec::{FakeRunner, Reply};
    use agentcage_state::{Paths, TestDir};
    use std::fs;
    use std::path::{Path, PathBuf};

    const GENERATION: &str = "0.40.1";
    const RICH: &str = "acme-agent";

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/state-compat")
            .join(GENERATION)
    }

    fn ctx(dir: &TestDir, fake: FakeRunner) -> Ctx {
        Ctx {
            paths: Paths::under(dir.join("home")),
            runner: Box::new(fake),
            version: GENERATION.to_owned(),
        }
    }

    /// The relay CA the fixture's `cage.yaml` names as
    /// `upstream.ca_file: ~/fixture-ca.pem`. `save_proxy_config`
    /// resolves it for real, so it has to exist under the sandbox home
    /// — the same thing `state_compat.rs` does rather than stubbing the
    /// resolver out.
    fn plant_ca(dir: &TestDir) {
        let home = dir.join("home");
        fs::create_dir_all(&home).unwrap();
        fs::write(
            home.join("fixture-ca.pem"),
            "-----BEGIN CERTIFICATE-----\n\
             TEST-NOT-A-REAL-CERTIFICATE-0001\n\
             -----END CERTIFICATE-----\n",
        )
        .unwrap();
    }

    fn fixture_state(relative: &str) -> String {
        fs::read_to_string(fixture_root().join(relative)).unwrap()
    }

    /// **The acceptance check.** PR A7 drove the *Python's own*
    /// `cage backup --include-secrets` to produce
    /// `backup/acme-agent-backup.tar.gz`; PR D2 pinned its member list
    /// and manifest and said outright that reading it was this PR's
    /// job. So: restore that exact archive and assert the tree it
    /// leaves behind against the state fixtures the same generator
    /// produced.
    ///
    /// The deploy half is not exercised — it needs podman, a kernel and
    /// a network, which is what **e2e phase 5** is for. What is
    /// exercised is everything that decides what lands on disk.
    #[test]
    fn the_python_made_backup_restores_onto_the_state_fixtures() {
        let dir = TestDir::new("restore-fixture");
        plant_ca(&dir);
        let fake = FakeRunner::new();
        fake.assume_installed();
        // Three `secret inspect` probes (none exist yet) and three
        // `secret create`s.
        for _ in 0..3 {
            fake.push(Reply::status(1));
            fake.push(Reply::success());
        }
        let ctx = ctx(&dir, fake.clone());

        let tarball = fixture_root().join(format!("backup/{RICH}-backup.tar.gz"));
        let staging = dir.join("staging");
        archive::extract_into(&tarball, &staging).unwrap();
        let backup_dir = staging.join("agentcage-backup");

        let manifest =
            Manifest::parse(&fs::read_to_string(backup_dir.join("manifest.json")).unwrap())
                .expect("the fixture manifest parses");
        assert_eq!(manifest.format_version, 1);
        assert_eq!(manifest.cage_name, RICH);
        assert_eq!(manifest.isolation, "container");
        assert!(manifest.secrets_included);
        assert_eq!(
            manifest.secret_keys,
            [
                "ANTHROPIC_API_KEY",
                "GITHUB_TOKEN",
                "IMAP_PASSWORD",
                "OPENROUTER_API_KEY"
            ]
        );

        let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
        restore_secrets(&podman, &manifest, RICH, &backup_dir);
        restore_config(&ctx, RICH, &backup_dir, None).unwrap();
        restore_capture(&ctx, RICH, &backup_dir);

        // ── The stored config is the fixture's, by parsed value and
        //    key order. `eq_with_key_order` is the same comparison D2
        //    used on the archived copy.
        let stored =
            yaml::load(&fs::read_to_string(ctx.paths.stored_config_path(RICH)).unwrap()).unwrap();
        let expected = yaml::load(&fixture_state(&format!(
            "xdg-config/agentcage/cages/{RICH}/cage.yaml"
        )))
        .unwrap();
        assert!(yaml::eq_with_key_order(&stored, &expected));

        // ── metadata.json comes through byte-for-byte: it is copied,
        //    not regenerated, and `network_octet` has to survive.
        assert_eq!(
            fs::read_to_string(ctx.paths.metadata_path(RICH)).unwrap(),
            fixture_state(&format!("xdg-config/agentcage/cages/{RICH}/metadata.json"))
        );

        // ── The derived files are *regenerated*, and they come out
        //    equal to what the Python generator wrote.
        assert!(yaml::eq_with_key_order(
            &yaml::load(&fs::read_to_string(ctx.paths.proxy_config_path(RICH)).unwrap()).unwrap(),
            &yaml::load(&fixture_state(&format!(
                "xdg-config/agentcage/cages/{RICH}/proxy-config.yaml"
            )))
            .unwrap()
        ));
        assert_eq!(
            fs::read_to_string(ctx.paths.dns_allowlist_path(RICH)).unwrap(),
            fixture_state(&format!(
                "xdg-config/agentcage/cages/{RICH}/dns-allowlist.conf"
            ))
        );

        // ── capture.jsonl is restored verbatim into the data root.
        assert_eq!(
            fs::read_to_string(ctx.paths.capture_file(RICH)).unwrap(),
            fixture_state(&format!("xdg-data/agentcage/{RICH}/capture/capture.jsonl"))
        );

        // ── And the three secrets the archive carried went into the
        //    store with their bare values, on stdin rather than in argv.
        let calls = fake.calls();
        let creates: Vec<_> = calls
            .iter()
            .filter(|call| call.argv().get(1).is_some_and(|arg| arg == "secret"))
            .filter(|call| call.argv().get(2).is_some_and(|arg| arg == "create"))
            .collect();
        assert_eq!(creates.len(), 3);
        assert_eq!(
            creates[0].argv(),
            [
                "podman",
                "secret",
                "create",
                "acme-agent.ANTHROPIC_API_KEY",
                "-"
            ]
        );
        assert_eq!(
            creates[0].stdin_text().as_deref(),
            Some("TEST-NOT-A-REAL-SECRET-0001")
        );
        assert_eq!(creates[1].argv()[3], "acme-agent.GITHUB_TOKEN".to_owned());
        assert_eq!(creates[2].argv()[3], "acme-agent.IMAP_PASSWORD".to_owned());
    }

    /// A clone lands under the new name *and* the document's own `name:`
    /// field is rewritten, because everything downstream reads the
    /// field rather than the directory.
    #[test]
    fn a_renamed_restore_rewrites_the_name_inside_the_document() {
        let dir = TestDir::new("restore-rename");
        plant_ca(&dir);
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = ctx(&dir, fake);

        let tarball = fixture_root().join(format!("backup/{RICH}-backup.tar.gz"));
        let staging = dir.join("staging");
        archive::extract_into(&tarball, &staging).unwrap();
        let backup_dir = staging.join("agentcage-backup");

        restore_config(&ctx, "acme-clone", &backup_dir, Some("acme-clone")).unwrap();

        let stored =
            yaml::load(&fs::read_to_string(ctx.paths.stored_config_path("acme-clone")).unwrap())
                .unwrap();
        assert_eq!(
            stored.get("name").and_then(yaml::Value::as_str),
            Some("acme-clone")
        );
        assert!(!ctx.paths.deployment_exists(RICH));
    }

    /// A backup with no `config/cage.yaml` is refused before anything
    /// is written, which is the difference between an invalid archive
    /// and a half-created cage.
    #[test]
    fn a_backup_without_a_config_is_refused() {
        let dir = TestDir::new("restore-noconfig");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = ctx(&dir, fake);
        let empty = dir.join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert!(restore_config(&ctx, "x", &empty, None).is_err());
        assert!(!ctx.paths.deployment_exists("x"));
    }

    /// Round-trip: back a cage up with the Rust writer, and the archive
    /// it produces is one the Rust reader restores onto an equal tree.
    /// The member list is asserted against the twelve names PR D2
    /// pinned, minus the three the fake store does not hold.
    #[test]
    fn a_rust_made_backup_round_trips() {
        let dir = TestDir::new("backup-roundtrip");
        plant_ca(&dir);
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = ctx(&dir, fake);

        // A cage on disk: the fixture's own config and metadata.
        let source = dir.join("cage.yaml");
        fs::write(
            &source,
            fixture_state(&format!("xdg-config/agentcage/cages/{RICH}/cage.yaml")),
        )
        .unwrap();
        ctx.paths.save_deployment(RICH, &source).unwrap();
        fs::write(
            ctx.paths.metadata_path(RICH),
            fixture_state(&format!("xdg-config/agentcage/cages/{RICH}/metadata.json")),
        )
        .unwrap();
        ctx.paths.save_proxy_config(RICH, GENERATION).unwrap();
        fs::create_dir_all(ctx.paths.capture_dir(RICH)).unwrap();
        fs::write(
            ctx.paths.capture_file(RICH),
            fixture_state(&format!("xdg-data/agentcage/{RICH}/capture/capture.jsonl")),
        )
        .unwrap();

        let out = dir.join("out.tar.gz");
        let fake = FakeRunner::new();
        fake.assume_installed();
        // `podman secret ls` — an empty store — then `volume exists`
        // for the cage's one named volume, which says no.
        fake.push(Reply::ok(""));
        fake.push(Reply::status(1));
        let ctx = Ctx {
            paths: ctx.paths,
            runner: Box::new(fake),
            version: GENERATION.to_owned(),
        };

        let matches = crate::cli::command(false)
            .try_get_matches_from([
                "agentcage",
                "cage",
                "backup",
                RICH,
                "-o",
                &out.display().to_string(),
            ])
            .unwrap();
        let leaf = matches
            .subcommand()
            .and_then(|(_, sub)| sub.subcommand())
            .map(|(_, leaf)| leaf)
            .unwrap();
        assert!(backup_inner(&ctx, leaf).is_ok());

        assert_eq!(
            archive::member_names(&out).unwrap(),
            [
                "agentcage-backup/capture",
                "agentcage-backup/capture/capture.jsonl",
                "agentcage-backup/config",
                "agentcage-backup/config/cage.yaml",
                "agentcage-backup/config/metadata.json",
                "agentcage-backup/config/proxy-config.yaml",
                "agentcage-backup/manifest.json",
                "agentcage-backup/volumes",
            ]
        );

        // And two backups of an unchanged cage are the same bytes.
        let again = dir.join("again.tar.gz");
        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.push(Reply::ok(""));
        fake.push(Reply::status(1));
        let ctx = Ctx {
            paths: ctx.paths,
            runner: Box::new(fake),
            version: GENERATION.to_owned(),
        };
        let matches = crate::cli::command(false)
            .try_get_matches_from([
                "agentcage",
                "cage",
                "backup",
                RICH,
                "-o",
                &again.display().to_string(),
            ])
            .unwrap();
        let leaf = matches
            .subcommand()
            .and_then(|(_, sub)| sub.subcommand())
            .map(|(_, leaf)| leaf)
            .unwrap();
        assert!(backup_inner(&ctx, leaf).is_ok());
        // The manifest's timestamp is the one field that moves, so the
        // comparison is member-wise with it excluded — the same thing
        // `gen-state-fixtures.py:1019` does when it diffs a tarball.
        for name in ["config/cage.yaml", "config/proxy-config.yaml"] {
            let full = format!("agentcage-backup/{name}");
            assert_eq!(
                archive::read_member(&out, &full).unwrap(),
                archive::read_member(&again, &full).unwrap(),
                "{name}"
            );
        }
    }

    // ─────────────────────────────────────────────────────
    // the build context
    // ─────────────────────────────────────────────────────

    /// A cage that builds from a Containerfile staged in its state dir.
    const CAGE_YAML_BUILD: &str = "\
name: acme-agent
container:
  image: docker.io/library/node:22-slim
  build:
    containerfile: Containerfile
";

    /// The same cage with no build step, which is the common case and
    /// the one whose `build_context_included` must be false.
    const CAGE_YAML_NO_BUILD: &str = "\
name: acme-agent
container:
  image: docker.io/library/node:22-slim
";

    /// A cage's state dir as it looks on disk, generated siblings and
    /// all. The two that matter are `fingerprint.json` and
    /// `secret_keys.json`: every real state dir has them, so every test
    /// here starts with the two entries that must not travel.
    fn fake_state_dir(root: &Path, cage_yaml: &str, containerfile: bool) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("cage.yaml"), cage_yaml).unwrap();
        fs::write(root.join("metadata.json"), "{\"network_octet\": 42}\n").unwrap();
        fs::write(root.join("proxy-config.yaml"), "listen: 8080\n").unwrap();
        fs::write(
            root.join("dns-allowlist.conf"),
            "server=/example.com/1.1.1.1\n",
        )
        .unwrap();
        fs::write(root.join("fingerprint.json"), "{\"fingerprint\": \"x\"}").unwrap();
        fs::write(root.join("secret_keys.json"), "[\"API_KEY\"]").unwrap();
        if containerfile {
            fs::write(
                root.join("Containerfile"),
                "FROM scratch\nCOPY skills /skills\n",
            )
            .unwrap();
            fs::create_dir_all(root.join("skills")).unwrap();
            fs::write(root.join("skills/tool.py"), "print('hi')\n").unwrap();
        }
        root.to_owned()
    }

    /// The member names [`stage_backup_config`] produces, with the
    /// `agentcage-backup/config/` prefix stripped for legibility.
    fn staged_names(state_dir: &Path) -> Vec<String> {
        stage_backup_config(state_dir)
            .iter()
            .filter_map(|member| {
                member
                    .name()
                    .strip_prefix(&format!("{ROOT}/config/"))
                    .map(ToOwned::to_owned)
            })
            .collect()
    }

    /// **The security-critical one.** `secret_keys.json` is the keychain
    /// store's *name index*, and the values it names live in the host
    /// keychain and never travel. Restoring the index onto a clean host
    /// would advertise every key as stored while none is, which makes
    /// `cage update`'s fail-closed missing-secrets check pass vacuously
    /// and starts the cage with no secrets at all.
    ///
    /// `fingerprint.json` is the same shape of bug one step down: it
    /// describes the *source* host's build, so a restored cage looks
    /// already up to date and skips the rebuild it needs.
    #[test]
    fn the_secret_index_and_the_fingerprint_never_travel() {
        let dir = TestDir::new("backup-exclude");
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_BUILD, true);
        let names = staged_names(&state);

        assert!(!names.iter().any(|n| n == "secret_keys.json"), "{names:?}");
        assert!(!names.iter().any(|n| n == "fingerprint.json"), "{names:?}");
        // ... while the build context itself is carried, which is the
        // whole reason the allowlist became an exclusion list.
        assert!(names.iter().any(|n| n == "Containerfile"), "{names:?}");
        assert!(names.iter().any(|n| n == "skills/tool.py"), "{names:?}");
        // ... and so are the generated siblings a restore wants.
        assert!(names.iter().any(|n| n == "dns-allowlist.conf"), "{names:?}");
    }

    /// Credential material, in a backup taken without
    /// `--include-secrets` and in one taken with it: `creds/` and the
    /// plaintext hand-off are excluded unconditionally, because the
    /// `secrets/` member is the only sanctioned way a value travels.
    #[test]
    fn credential_material_never_travels() {
        let dir = TestDir::new("backup-creds");
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_BUILD, true);
        fs::create_dir_all(state.join("creds")).unwrap();
        fs::write(state.join("creds/token"), "sekrit").unwrap();
        fs::write(
            state.join("pending_secrets.json"),
            "{\"API_KEY\": \"sk-1\"}",
        )
        .unwrap();
        fs::create_dir_all(state.join("cage-env")).unwrap();
        fs::write(state.join("cage-env/placeholders.env"), "A=1\n").unwrap();

        let names = staged_names(&state);
        assert!(!names.iter().any(|n| n.contains("creds")), "{names:?}");
        assert!(
            !names.iter().any(|n| n.contains("pending_secrets")),
            "{names:?}"
        );
        assert!(!names.iter().any(|n| n.contains("cage-env")), "{names:?}");
    }

    /// Outcome one of three: the cage builds, and the Containerfile it
    /// builds from is in the archive.
    #[test]
    fn build_context_included_is_true_when_the_containerfile_is_carried() {
        let dir = TestDir::new("backup-ctx-true");
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_BUILD, true);
        assert!(build_context_included(&state, &stage_backup_config(&state)));
    }

    /// Outcome two: no build step, so there is no context to carry.
    ///
    /// This is the case that makes the flag worth having. It is
    /// deliberately *not* "the state dir held entries beyond the three
    /// managed config files" — every state dir has generated siblings,
    /// so that test could never be false and the flag would be a
    /// constant.
    #[test]
    fn build_context_included_is_false_without_a_build_step() {
        let dir = TestDir::new("backup-ctx-nobuild");
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_NO_BUILD, false);
        fs::write(state.join("AGENTS.md"), "# agents\n").unwrap();

        let members = stage_backup_config(&state);
        assert!(!build_context_included(&state, &members));
        // The extra files still travel; only the flag is about the build.
        assert!(staged_names(&state).iter().any(|n| n == "AGENTS.md"));
    }

    /// Outcome three: the cage builds, but the Containerfile is not
    /// there. This is the old contextless tarball, and reporting it as
    /// true is what sends a restore into an opaque backend failure.
    #[test]
    fn build_context_included_is_false_when_the_containerfile_is_missing() {
        let dir = TestDir::new("backup-ctx-missing");
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_BUILD, false);
        assert!(!build_context_included(
            &state,
            &stage_backup_config(&state)
        ));
    }

    /// The ignore list applies to the *top level* of the state dir too,
    /// not only inside the directories a recursive copy walks — which
    /// is where a `__pycache__/` or a soft-deleted
    /// `Containerfile.deleted.<ts>` actually lives.
    #[test]
    fn top_level_build_noise_is_ignored() {
        let dir = TestDir::new("backup-noise");
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_BUILD, true);
        fs::create_dir_all(state.join("__pycache__")).unwrap();
        fs::write(state.join("__pycache__/junk.pyc"), "x").unwrap();
        fs::write(state.join("Containerfile.deleted.20260101-000000"), "old").unwrap();
        // ... and inside a directory, which is the case that already
        // worked and must keep working.
        fs::create_dir_all(state.join("skills/__pycache__")).unwrap();
        fs::write(state.join("skills/__pycache__/t.pyc"), "x").unwrap();

        let names = staged_names(&state);
        assert!(
            !names.iter().any(|n| n.contains("__pycache__")),
            "{names:?}"
        );
        assert!(!names.iter().any(|n| n.contains(".deleted.")), "{names:?}");
        assert!(names.iter().any(|n| n == "Containerfile"), "{names:?}");
    }

    /// A link that stays inside the config dir is carried as a link; one
    /// that points out of it is dropped with a warning.
    ///
    /// Neither alternative is acceptable. Carrying the escaping link
    /// makes the *whole* tarball unrestorable — `extract_into` refuses
    /// it and so does `tarfile`'s `data` filter — and dereferencing it
    /// copies whatever it points at, which here is a private key, into
    /// the backup.
    #[test]
    fn escaping_symlinks_are_pruned_and_in_tree_ones_are_kept() {
        let dir = TestDir::new("backup-symlinks");
        fs::write(dir.join("id_rsa"), "PRIVATE KEY").unwrap();
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_BUILD, true);
        std::os::unix::fs::symlink("tool.py", state.join("skills/alias.py")).unwrap();
        std::os::unix::fs::symlink("nowhere.txt", state.join("dangling")).unwrap();
        std::os::unix::fs::symlink(dir.join("id_rsa"), state.join("host-link")).unwrap();
        std::os::unix::fs::symlink("../../id_rsa", state.join("skills/escape")).unwrap();

        let members = stage_backup_config(&state);
        let names = staged_names(&state);

        assert!(names.iter().any(|n| n == "skills/alias.py"), "{names:?}");
        // Dangling is fine: nothing is ever followed.
        assert!(names.iter().any(|n| n == "dangling"), "{names:?}");
        assert!(!names.iter().any(|n| n == "host-link"), "{names:?}");
        assert!(!names.iter().any(|n| n == "skills/escape"), "{names:?}");

        // The kept ones are links, not copies — a dereferenced
        // `alias.py` would be a `FileFrom` holding `tool.py`'s bytes.
        assert!(members.iter().any(|m| matches!(
            m,
            Member::Symlink(name, target)
                if name.ends_with("config/skills/alias.py") && target == "tool.py"
        )));

        // And the archive they produce is one the reader accepts, with
        // no trace of the file the escaping links pointed at.
        let out = dir.join("out.tar.gz");
        archive::write_targz(&out, &members).unwrap();
        let extracted = dir.join("extracted");
        archive::extract_into(&out, &extracted).unwrap();
        let config = extracted.join("agentcage-backup/config");
        assert!(
            fs::symlink_metadata(config.join("skills/alias.py"))
                .unwrap()
                .is_symlink()
        );
        assert!(!config.join("host-link").exists());
        for name in archive::member_names(&out).unwrap() {
            if let Ok(Some(bytes)) = archive::read_member(&out, &name) {
                assert!(
                    !bytes.windows(11).any(|w| w == b"PRIVATE KEY"),
                    "{name} carries host content"
                );
            }
        }
    }

    /// `Path::join` silently discards its left side when the right side
    /// is absolute, and `..` segments climb out of it — so a naive join
    /// reports a file that exists only on the host as one the backup
    /// carries. Both shapes are refused.
    #[test]
    fn carried_containerfile_rejects_absolute_and_escaping_paths() {
        let dir = TestDir::new("backup-cf-paths");
        let config = dir.join("config");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("Containerfile"), "FROM scratch\n").unwrap();
        let outside = dir.join("Containerfile");
        fs::write(&outside, "FROM scratch\n").unwrap();

        assert_eq!(
            carried_containerfile(&config, "Containerfile"),
            Some(PathBuf::from("Containerfile"))
        );
        assert_eq!(
            carried_containerfile(&config, "./Containerfile"),
            Some(PathBuf::from("Containerfile"))
        );
        // Climbs out and lands on a file that really exists — which is
        // exactly the case a join would have reported as carried.
        assert_eq!(carried_containerfile(&config, "../Containerfile"), None);
        assert_eq!(
            carried_containerfile(&config, &outside.display().to_string()),
            None
        );
        assert_eq!(carried_containerfile(&config, "/etc/passwd"), None);
        assert_eq!(carried_containerfile(&config, ""), None);
        assert_eq!(carried_containerfile(&config, "nope"), None);
    }

    /// The preflight's three answers, on the extracted `config/` a
    /// restore actually sees.
    #[test]
    fn the_preflight_refuses_only_a_tarball_that_cannot_rebuild() {
        let dir = TestDir::new("restore-preflight");

        let carried = fake_state_dir(&dir.join("carried"), CAGE_YAML_BUILD, true);
        assert!(check_restore_build_context(&manifest_with(false), &carried).is_ok());

        let no_build = fake_state_dir(&dir.join("nobuild"), CAGE_YAML_NO_BUILD, false);
        assert!(check_restore_build_context(&manifest_with(false), &no_build).is_ok());

        let contextless = fake_state_dir(&dir.join("contextless"), CAGE_YAML_BUILD, false);
        assert!(check_restore_build_context(&manifest_with(false), &contextless).is_err());

        // An absolute containerfile is resolved against the *host*, not
        // joined onto the backup dir: present it passes, missing it is
        // refused with a different message.
        let host_cf = dir.join("elsewhere/Containerfile");
        fs::create_dir_all(host_cf.parent().unwrap()).unwrap();
        fs::write(&host_cf, "FROM scratch\n").unwrap();
        let absolute = fake_state_dir(
            &dir.join("absolute"),
            &format!(
                "name: acme-agent\ncontainer:\n  build:\n    containerfile: {}\n",
                host_cf.display()
            ),
            false,
        );
        assert!(check_restore_build_context(&manifest_with(false), &absolute).is_ok());

        let gone = fake_state_dir(
            &dir.join("gone"),
            &format!(
                "name: acme-agent\ncontainer:\n  build:\n    containerfile: {}\n",
                dir.join("missing/Containerfile").display()
            ),
            false,
        );
        assert!(check_restore_build_context(&manifest_with(false), &gone).is_err());
    }

    /// A manifest carrying nothing but the fields the preflight reports.
    fn manifest_with(build_context_included: bool) -> Manifest {
        Manifest {
            format_version: 1,
            cage_name: RICH.to_owned(),
            isolation: "container".to_owned(),
            secret_keys: Vec::new(),
            secrets_included: false,
            named_volumes: Vec::new(),
            build_context_included,
        }
    }

    /// The exclusion is applied on the way *out* as well as on the way
    /// in, so a hand-crafted tarball cannot plant the keychain name
    /// index or a foreign fingerprint in a restored cage. A tarball is
    /// the one artifact in this program that arrives from outside it.
    #[test]
    fn a_hand_crafted_tarball_cannot_reinstall_the_excluded_entries() {
        let dir = TestDir::new("restore-smuggle");
        let config_src = fake_state_dir(&dir.join("config"), CAGE_YAML_NO_BUILD, false);
        fs::create_dir_all(config_src.join("creds")).unwrap();
        fs::write(config_src.join("creds/token"), "sekrit").unwrap();

        let deploy = dir.join("deploy");
        fs::create_dir_all(&deploy).unwrap();
        restore_build_context(&config_src, &deploy);

        assert!(!deploy.join("secret_keys.json").exists());
        assert!(!deploy.join("fingerprint.json").exists());
        assert!(!deploy.join("creds").exists());
        // The three managed config files are installed by name, through
        // `save_deployment`, not by this.
        assert!(!deploy.join("cage.yaml").exists());
        assert!(!deploy.join("metadata.json").exists());
        assert!(!deploy.join("proxy-config.yaml").exists());
        // Everything else does come through.
        assert!(deploy.join("dns-allowlist.conf").is_file());
    }

    /// A build context survives the round trip: backed up from a state
    /// dir, restored into one, with its directory tree and its in-tree
    /// links intact and none of the excluded state along for the ride.
    #[test]
    fn a_build_context_round_trips() {
        let dir = TestDir::new("backup-ctx-roundtrip");
        let state = fake_state_dir(&dir.join("state"), CAGE_YAML_BUILD, true);
        std::os::unix::fs::symlink("tool.py", state.join("skills/alias.py")).unwrap();

        let out = dir.join("out.tar.gz");
        archive::write_targz(&out, &stage_backup_config(&state)).unwrap();

        let staging = dir.join("staging");
        archive::extract_into(&out, &staging).unwrap();
        let config_src = staging.join("agentcage-backup/config");
        let deploy = dir.join("deploy");
        fs::create_dir_all(&deploy).unwrap();
        restore_build_context(&config_src, &deploy);

        assert_eq!(
            fs::read_to_string(deploy.join("Containerfile")).unwrap(),
            "FROM scratch\nCOPY skills /skills\n"
        );
        assert_eq!(
            fs::read_to_string(deploy.join("skills/tool.py")).unwrap(),
            "print('hi')\n"
        );
        assert!(
            fs::symlink_metadata(deploy.join("skills/alias.py"))
                .unwrap()
                .is_symlink()
        );
        assert!(!deploy.join("secret_keys.json").exists());
        assert!(!deploy.join("fingerprint.json").exists());
    }

    /// **The ordering fix.** `--force` destroys the existing cage and
    /// clears its state dir; the preflight refuses a tarball that
    /// cannot rebuild. Run in the wrong order that leaves the host with
    /// neither the old cage nor a restored one — and with orphaned
    /// `<target>.KEY` podman secrets. So extraction and the preflight
    /// come first, and a refusal costs nothing.
    #[test]
    fn a_forced_restore_of_a_contextless_tarball_keeps_the_existing_cage() {
        let dir = TestDir::new("restore-force-contextless");
        plant_ca(&dir);
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = ctx(&dir, fake.clone());

        // An existing cage, which must still be here afterwards.
        let source = dir.join("cage.yaml");
        fs::write(
            &source,
            fixture_state(&format!("xdg-config/agentcage/cages/{RICH}/cage.yaml")),
        )
        .unwrap();
        ctx.paths.save_deployment(RICH, &source).unwrap();
        let before = fs::read_to_string(ctx.paths.stored_config_path(RICH)).unwrap();

        // A backup from before build contexts were carried: its
        // cage.yaml builds from a Containerfile the tarball omits.
        let tarball = dir.join("old.tar.gz");
        archive::write_targz(
            &tarball,
            &[
                Member::Dir(format!("{ROOT}/config")),
                Member::File(
                    format!("{ROOT}/config/cage.yaml"),
                    CAGE_YAML_BUILD.as_bytes().to_vec(),
                ),
                Member::File(
                    format!("{ROOT}/manifest.json"),
                    format!(
                        "{{\"format_version\": 1, \"cage_name\": \"{RICH}\", \
                          \"isolation\": \"container\", \
                          \"secret_keys\": [\"API_KEY\"], \
                          \"secrets_included\": true}}\n"
                    )
                    .into_bytes(),
                ),
            ],
        )
        .unwrap();

        let matches = crate::cli::command(false)
            .try_get_matches_from([
                "agentcage",
                "cage",
                "restore",
                &tarball.display().to_string(),
                "--force",
            ])
            .unwrap();
        let leaf = matches
            .subcommand()
            .and_then(|(_, sub)| sub.subcommand())
            .map(|(_, leaf)| leaf)
            .unwrap();
        assert!(restore_inner(&ctx, leaf).is_err());

        // The cage is untouched: still deployed, same document.
        assert!(ctx.paths.deployment_exists(RICH));
        assert_eq!(
            fs::read_to_string(ctx.paths.stored_config_path(RICH)).unwrap(),
            before
        );
        // Nothing was stopped, destroyed, or written to the secret
        // store — the refusal happened before any of it could run.
        let calls = fake.calls();
        let verbs: Vec<String> = calls
            .iter()
            .map(|call| call.argv().join(" "))
            .filter(|argv| {
                argv.contains("secret create") || argv.contains("stop") || argv.contains("rm")
            })
            .collect();
        assert!(verbs.is_empty(), "{verbs:?}");
    }

    /// The same ordering, exercised through the whole command: a real
    /// backup of a real cage, restored over itself with `--force`.
    /// Here the preflight passes, so the destroy *does* run — which is
    /// what makes the test above about ordering rather than about the
    /// preflight refusing everything.
    #[test]
    fn a_backup_taken_by_the_command_excludes_the_index_and_the_fingerprint() {
        let dir = TestDir::new("backup-cmd-exclude");
        plant_ca(&dir);
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = ctx(&dir, fake);

        let source = dir.join("cage.yaml");
        fs::write(
            &source,
            fixture_state(&format!("xdg-config/agentcage/cages/{RICH}/cage.yaml")),
        )
        .unwrap();
        ctx.paths.save_deployment(RICH, &source).unwrap();
        // `ensure_v022_cage` reads this; a cage without one is legacy.
        fs::write(
            ctx.paths.metadata_path(RICH),
            fixture_state(&format!("xdg-config/agentcage/cages/{RICH}/metadata.json")),
        )
        .unwrap();
        ctx.paths.save_proxy_config(RICH, GENERATION).unwrap();
        let state = ctx.paths.deployment_dir(RICH);
        fs::write(state.join("secret_keys.json"), "[\"ANTHROPIC_API_KEY\"]").unwrap();
        fs::write(state.join("fingerprint.json"), "{\"fingerprint\": \"x\"}").unwrap();
        fs::create_dir_all(state.join("creds")).unwrap();
        fs::write(state.join("creds/token"), "sekrit").unwrap();
        fs::write(state.join("AGENTS.md"), "# agents\n").unwrap();

        let out = dir.join("out.tar.gz");
        let fake = FakeRunner::new();
        fake.assume_installed();
        // `podman secret ls`, then `volume exists` for the cage's one
        // named volume.
        fake.push(Reply::ok(""));
        fake.push(Reply::status(1));
        let ctx = Ctx {
            paths: ctx.paths,
            runner: Box::new(fake),
            version: GENERATION.to_owned(),
        };
        let matches = crate::cli::command(false)
            .try_get_matches_from([
                "agentcage",
                "cage",
                "backup",
                RICH,
                "-o",
                &out.display().to_string(),
            ])
            .unwrap();
        let leaf = matches
            .subcommand()
            .and_then(|(_, sub)| sub.subcommand())
            .map(|(_, leaf)| leaf)
            .unwrap();
        assert!(backup_inner(&ctx, leaf).is_ok());

        let names = archive::member_names(&out).unwrap();
        for forbidden in [
            "agentcage-backup/config/secret_keys.json",
            "agentcage-backup/config/fingerprint.json",
            "agentcage-backup/config/creds",
            "agentcage-backup/config/creds/token",
        ] {
            assert!(!names.iter().any(|n| n == forbidden), "{forbidden}");
        }
        // The rest of the state dir is there, which is the change.
        assert!(
            names
                .iter()
                .any(|n| n == "agentcage-backup/config/AGENTS.md")
        );
        assert!(
            names
                .iter()
                .any(|n| n == "agentcage-backup/config/cage.yaml")
        );

        // The fixture cage has no build step, so the flag is false —
        // and it is present, which older manifests have no key for.
        let manifest = String::from_utf8(
            archive::read_member(&out, "agentcage-backup/manifest.json")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(
            manifest.contains("\"build_context_included\": false"),
            "{manifest}"
        );
    }

    // ─────────────────────────────────────────────────────
    // apple-container
    // ─────────────────────────────────────────────────────

    const APPLE: &str = "apple-cage";

    /// An apple-container cage, as `cage create` leaves one, with two
    /// injection rules so the manifest's `secret_keys` has something in
    /// it. The shape is the golden corpus's `backend-apple-container`
    /// case plus `secret_injection`, which is the one config section
    /// this backend's backup actually reads.
    const CAGE_YAML_APPLE: &str = "\
name: apple-cage
isolation: apple-container
container:
  image: docker.io/library/node:22-slim
domains:
  allow:
  - api.example.com
secret_injection:
- env: ANTHROPIC_API_KEY
  source: env:HOST_ANTHROPIC_KEY
  placeholder: sk-ant-FAKE-0001
  inject_to:
  - api.example.com
- env: GITHUB_TOKEN
  source: env:HOST_GITHUB_TOKEN
  placeholder: ghp-FAKE-0002
  inject_to:
  - api.example.com
";

    /// An apple-container cage on disk, with whichever of its two log
    /// streams the caller asks for already in the per-cage logs dir.
    ///
    /// `metadata.json` is written because `ensure_v022_cage` reads it:
    /// a cage without one is legacy, and `cage backup` refuses it
    /// before any of this is reached.
    fn apple_cage(dir: &TestDir, fake: FakeRunner, logs: &[(&str, &str)]) -> Ctx {
        let ctx = ctx(dir, fake);
        let source = dir.join("apple.yaml");
        fs::write(&source, CAGE_YAML_APPLE).unwrap();
        ctx.paths.save_deployment(APPLE, &source).unwrap();
        fs::write(
            ctx.paths.metadata_path(APPLE),
            "{\"agentcage_version\": \"0.40.1\", \"network_octet\": 42}\n",
        )
        .unwrap();
        ctx.paths.save_proxy_config(APPLE, GENERATION).unwrap();

        let logs_dir = ctx.paths.apple_logs_dir(APPLE);
        fs::create_dir_all(&logs_dir).unwrap();
        for (sub, body) in logs {
            fs::write(logs_dir.join(format!("{sub}.jsonl")), body).unwrap();
        }
        ctx
    }

    /// The leaf `ArgMatches` for a `cage backup` / `cage restore`
    /// invocation, parsed through the real command tree so the flags
    /// under test are the ones `main` hands over.
    fn leaf_matches(argv: &[&str]) -> clap::ArgMatches {
        crate::cli::command(false)
            .try_get_matches_from(argv)
            .unwrap()
            .subcommand()
            .and_then(|(_, sub)| sub.subcommand())
            .map(|(_, leaf)| leaf.clone())
            .expect("a two-level subcommand")
    }

    fn manifest_text(tarball: &Path) -> String {
        String::from_utf8(
            archive::read_member(tarball, "agentcage-backup/manifest.json")
                .unwrap()
                .expect("every backup has a manifest"),
        )
        .unwrap()
    }

    /// **The refusal.** There is no host secret store on this backend —
    /// values are env-passed at start out of the invoking shell and
    /// agentcage never keeps them — so `--include-secrets` cannot be
    /// honoured. It has to *fail* rather than quietly produce a tarball
    /// with no secrets in it, which is how a restore ends up silently
    /// credential-less.
    #[test]
    fn an_apple_backup_refuses_include_secrets() {
        let dir = TestDir::new("apple-backup-include-secrets");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = apple_cage(&dir, fake.clone(), &[]);

        let out = dir.join("out.tar.gz");
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "backup",
            APPLE,
            "--include-secrets",
            "-o",
            &out.display().to_string(),
        ]);
        assert!(backup_inner(&ctx, &matches).is_err());
        // Nothing was written, and nothing was asked of a store that
        // does not exist.
        assert!(!out.exists());
        assert!(fake.calls().is_empty(), "{:?}", fake.argv_sequence());
    }

    /// The shape, against the three differences the Python's docstring
    /// enumerates: no `secrets/` and no `volumes/` member, an `audit/`
    /// one the container path never emits, and a manifest whose
    /// `named_volumes` is empty and whose `secret_keys` are the
    /// injection rules' env names.
    #[test]
    fn an_apple_backup_carries_both_logs_and_no_secret_store() {
        let dir = TestDir::new("apple-backup-shape");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = apple_cage(
            &dir,
            fake.clone(),
            &[
                ("capture", "{\"id\": 1}\n"),
                ("audit", "{\"event\": \"allow\"}\n"),
            ],
        );

        let out = dir.join("out.tar.gz");
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "backup",
            APPLE,
            "-o",
            &out.display().to_string(),
        ]);
        assert!(backup_inner(&ctx, &matches).is_ok());

        assert_eq!(
            archive::member_names(&out).unwrap(),
            [
                "agentcage-backup/audit",
                "agentcage-backup/audit/audit.jsonl",
                "agentcage-backup/capture",
                "agentcage-backup/capture/capture.jsonl",
                "agentcage-backup/config",
                "agentcage-backup/config/cage.yaml",
                "agentcage-backup/config/metadata.json",
                "agentcage-backup/config/proxy-config.yaml",
                "agentcage-backup/manifest.json",
            ]
        );

        let text = manifest_text(&out);
        let manifest = Manifest::parse(&text).expect("the manifest parses");
        assert_eq!(manifest.isolation, "apple-container");
        assert_eq!(manifest.cage_name, APPLE);
        assert_eq!(manifest.secret_keys, ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"]);
        assert!(!manifest.secrets_included);
        assert!(manifest.named_volumes.is_empty());
        // The keys the container manifest does not have the same way:
        // `has_audit` exists at all, and `named_volumes` is the empty
        // literal rather than a list this backend could ever fill.
        assert!(text.contains("\"has_audit\": true"), "{text}");
        assert!(text.contains("\"has_capture\": true"), "{text}");
        assert!(text.contains("\"has_secrets\": true"), "{text}");
        assert!(text.contains("\"named_volumes\": []"), "{text}");
        assert!(text.contains("\"secrets_included\": false"), "{text}");
        // Key order is the Python dict literal's, which puts `has_audit`
        // between `has_capture` and `named_volumes`.
        assert!(
            text.find("\"has_capture\"") < text.find("\"has_audit\""),
            "{text}"
        );
        assert!(
            text.find("\"has_audit\"") < text.find("\"named_volumes\""),
            "{text}"
        );

        // No store was consulted, and there is none to consult:
        // `FakeRunner` panics on an unstubbed call, so a stray
        // `podman secret ls` would fail this test before the assertion
        // below did.
        assert!(fake.calls().is_empty(), "{:?}", fake.argv_sequence());
        assert!(
            !archive::member_names(&out)
                .unwrap()
                .iter()
                .any(|name| name.contains("secrets") || name.contains("volumes"))
        );
    }

    /// Zero length is "no stream yet", not "a stream of nothing":
    /// `start` creates the logs dir and the supervisor opens both files
    /// before writing a line, so an empty one must not become a member
    /// and must not set its manifest flag.
    #[test]
    fn empty_apple_log_streams_are_not_carried() {
        let dir = TestDir::new("apple-backup-empty-logs");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = apple_cage(&dir, fake, &[("capture", ""), ("audit", "")]);

        let out = dir.join("out.tar.gz");
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "backup",
            APPLE,
            "-o",
            &out.display().to_string(),
        ]);
        assert!(backup_inner(&ctx, &matches).is_ok());

        let names = archive::member_names(&out).unwrap();
        assert!(!names.iter().any(|n| n.contains("/capture")), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("/audit")), "{names:?}");
        let text = manifest_text(&out);
        assert!(text.contains("\"has_capture\": false"), "{text}");
        assert!(text.contains("\"has_audit\": false"), "{text}");
    }

    /// A cage with no injection rules records an empty `secret_keys`
    /// and `has_secrets: false`. The field is `cfg.secret_injection`
    /// alone on this backend, not the wider `expected_secrets` the
    /// container manifest records — only an injection rule names an env
    /// var an operator could `export`.
    #[test]
    fn an_apple_backup_of_a_cage_with_no_rules_records_no_secret_keys() {
        let dir = TestDir::new("apple-backup-no-rules");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = ctx(&dir, fake);
        let source = dir.join("apple.yaml");
        fs::write(
            &source,
            "name: apple-cage\nisolation: apple-container\ncontainer:\n  \
             image: docker.io/library/node:22-slim\n",
        )
        .unwrap();
        ctx.paths.save_deployment(APPLE, &source).unwrap();
        fs::write(
            ctx.paths.metadata_path(APPLE),
            "{\"agentcage_version\": \"0.40.1\", \"network_octet\": 42}\n",
        )
        .unwrap();

        let out = dir.join("out.tar.gz");
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "backup",
            APPLE,
            "-o",
            &out.display().to_string(),
        ]);
        assert!(backup_inner(&ctx, &matches).is_ok());
        let text = manifest_text(&out);
        assert!(text.contains("\"secret_keys\": []"), "{text}");
        assert!(text.contains("\"has_secrets\": false"), "{text}");
    }

    /// **The round trip.** An apple backup taken by the command, read
    /// back by the command: the config lands under the new name with
    /// its `name:` field rewritten, the derived files are regenerated,
    /// and both log streams go back into the per-cage logs dir — the
    /// apple one, which expands `~` directly and ignores
    /// `XDG_DATA_HOME`.
    ///
    /// `--no-start` because everything past it is two image builds and
    /// a microVM, which is what the e2e apple phase is for. What is
    /// exercised here is everything that decides what lands on disk.
    #[test]
    fn an_apple_backup_round_trips_through_restore() {
        let dir = TestDir::new("apple-roundtrip");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = apple_cage(
            &dir,
            fake.clone(),
            &[
                ("capture", "{\"id\": 1}\n"),
                ("audit", "{\"event\": \"allow\"}\n"),
            ],
        );

        let out = dir.join("out.tar.gz");
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "backup",
            APPLE,
            "-o",
            &out.display().to_string(),
        ]);
        assert!(backup_inner(&ctx, &matches).is_ok());

        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "restore",
            &out.display().to_string(),
            "--name",
            "apple-clone",
            "--no-start",
        ]);
        assert!(restore_inner(&ctx, &matches).is_ok());

        // The document is installed under the new name, and its own
        // `name:` agrees with the directory it is stored under.
        let stored =
            yaml::load(&fs::read_to_string(ctx.paths.stored_config_path("apple-clone")).unwrap())
                .unwrap();
        assert_eq!(
            stored.get("name").and_then(yaml::Value::as_str),
            Some("apple-clone")
        );
        assert_eq!(
            stored.get("isolation").and_then(yaml::Value::as_str),
            Some("apple-container")
        );

        // Regenerated, not restored.
        assert!(ctx.paths.proxy_config_path("apple-clone").is_file());
        assert!(ctx.paths.dns_allowlist_path("apple-clone").is_file());

        // Both streams went back into the apple logs dir, which is the
        // part of the state layout no other backend uses.
        let logs = ctx.paths.apple_logs_dir("apple-clone");
        assert_eq!(
            fs::read_to_string(logs.join("capture.jsonl")).unwrap(),
            "{\"id\": 1}\n"
        );
        assert_eq!(
            fs::read_to_string(logs.join("audit.jsonl")).unwrap(),
            "{\"event\": \"allow\"}\n"
        );
        // ... and not into the container layout's capture file, which
        // is where `restore_capture` would have put the first of them.
        assert!(!ctx.paths.capture_file("apple-clone").exists());

        // A clone leaves the source cage alone, and neither direction
        // touched podman.
        assert!(ctx.paths.deployment_exists(APPLE));
        assert!(fake.calls().is_empty(), "{:?}", fake.argv_sequence());
    }

    /// Restoring onto a name that already exists is refused without
    /// `--force`, before anything is written — the same contract as the
    /// container path, reached through the apple branch.
    #[test]
    fn an_apple_restore_onto_an_existing_cage_needs_force() {
        let dir = TestDir::new("apple-restore-exists");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = apple_cage(&dir, fake.clone(), &[("capture", "{\"id\": 1}\n")]);

        let out = dir.join("out.tar.gz");
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "backup",
            APPLE,
            "-o",
            &out.display().to_string(),
        ]);
        assert!(backup_inner(&ctx, &matches).is_ok());

        let before = fs::read_to_string(ctx.paths.stored_config_path(APPLE)).unwrap();
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "restore",
            &out.display().to_string(),
            "--no-start",
        ]);
        assert!(restore_inner(&ctx, &matches).is_err());
        assert_eq!(
            fs::read_to_string(ctx.paths.stored_config_path(APPLE)).unwrap(),
            before
        );
        assert!(fake.calls().is_empty(), "{:?}", fake.argv_sequence());
    }

    /// **The ordering, on the apple branch.**
    /// `test_force_restore_contextless_apple_keeps_existing_cage` in
    /// `tests/test_backup_restore.py`, ported: a `--force` restore of
    /// an apple tarball that cannot rebuild the cage has to be refused
    /// *before* the destroy, or the host is left with neither the old
    /// cage nor a restored one.
    ///
    /// This is also what pins the dispatch's position. The apple branch
    /// sits after the shared extraction and preflight, so a tarball
    /// that fails the preflight never reaches [`restore_apple`] and
    /// never stops or destroys anything.
    #[test]
    fn a_forced_apple_restore_of_a_contextless_tarball_keeps_the_existing_cage() {
        let dir = TestDir::new("apple-restore-force-contextless");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = apple_cage(&dir, fake.clone(), &[]);
        let before = fs::read_to_string(ctx.paths.stored_config_path(APPLE)).unwrap();

        // An apple backup whose cage.yaml builds from a Containerfile
        // the tarball omits.
        let tarball = dir.join("old.tar.gz");
        archive::write_targz(
            &tarball,
            &[
                Member::Dir(format!("{ROOT}/config")),
                Member::File(
                    format!("{ROOT}/config/cage.yaml"),
                    "name: apple-cage\nisolation: apple-container\ncontainer:\n  \
                     image: docker.io/library/node:22-slim\n  build:\n    \
                     containerfile: Containerfile\n"
                        .as_bytes()
                        .to_vec(),
                ),
                Member::File(
                    format!("{ROOT}/manifest.json"),
                    format!(
                        "{{\"format_version\": 1, \"cage_name\": \"{APPLE}\", \
                          \"isolation\": \"apple-container\", \
                          \"secret_keys\": [\"ANTHROPIC_API_KEY\"], \
                          \"secrets_included\": false}}\n"
                    )
                    .into_bytes(),
                ),
            ],
        )
        .unwrap();

        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "restore",
            &tarball.display().to_string(),
            "--force",
        ]);
        assert!(restore_inner(&ctx, &matches).is_err());

        assert!(ctx.paths.deployment_exists(APPLE));
        assert_eq!(
            fs::read_to_string(ctx.paths.stored_config_path(APPLE)).unwrap(),
            before
        );
        // Nothing was stopped or destroyed: no backend was reached at
        // all, which `FakeRunner`'s panic-on-unstubbed-call enforces as
        // firmly as this assertion does.
        assert!(fake.calls().is_empty(), "{:?}", fake.argv_sequence());
    }

    /// The `vm` backend is **not** opened by any of the above. It
    /// refuses for its own reasons — `_podman_for_cage` routes a
    /// running vm cage's secret and volume calls through `VmPodman`
    /// *inside the Lima guest*, a store nothing in this file talks to —
    /// and the apple dispatch must not have become a general
    /// "not container" branch on the way in.
    #[test]
    fn the_vm_backend_is_still_refused() {
        let dir = TestDir::new("vm-backup-refused");
        let fake = FakeRunner::new();
        fake.assume_installed();
        let ctx = ctx(&dir, fake);

        let source = dir.join("vm.yaml");
        fs::write(
            &source,
            "name: vm-cage\nisolation: vm\ncontainer:\n  \
             image: docker.io/library/node:22-slim\n",
        )
        .unwrap();
        ctx.paths.save_deployment("vm-cage", &source).unwrap();
        fs::write(
            ctx.paths.metadata_path("vm-cage"),
            "{\"agentcage_version\": \"0.40.1\", \"network_octet\": 42}\n",
        )
        .unwrap();

        let out = dir.join("out.tar.gz");
        let matches = leaf_matches(&[
            "agentcage",
            "cage",
            "backup",
            "vm-cage",
            "-o",
            &out.display().to_string(),
        ]);
        assert!(backup_inner(&ctx, &matches).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn cage_names_from_a_manifest_are_checked() {
        assert!(is_valid_cage_name("basic"));
        assert!(is_valid_cage_name("a"));
        assert!(is_valid_cage_name("e2e-second"));
        assert!(is_valid_cage_name("0abc"));
        assert!(!is_valid_cage_name(""));
        assert!(!is_valid_cage_name("-leading"));
        assert!(!is_valid_cage_name("Upper"));
        assert!(!is_valid_cage_name("has/slash"));
        assert!(!is_valid_cage_name("../escape"));
        assert!(!is_valid_cage_name("has_underscore"));
        assert!(!is_valid_cage_name(&"a".repeat(64)));
        assert!(is_valid_cage_name(&"a".repeat(63)));
    }

    #[test]
    fn the_default_filename_timestamp_is_fifteen_characters() {
        let stamp = file_timestamp();
        assert_eq!(stamp.len(), 15, "{stamp}");
        assert_eq!(stamp.as_bytes()[8], b'-');
        assert_eq!(stamp.chars().filter(char::is_ascii_digit).count(), 14);
    }
}
