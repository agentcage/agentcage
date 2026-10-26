//! The cage lifecycle: `list`, `show`, `status`, `start`, `stop`,
//! `restart`, `destroy`, `prune`.
//!
//! # Why they are all in one file
//!
//! They were not, at first. D6 landed `list` / `show` / `status` /
//! `destroy` because e2e phase 1 could not clean up after itself
//! without them, D12 added `stop` for phase 6's tmpfs teardown and D9
//! added `restart` because the live-secret path falls back to it. Each
//! took only the slice its own phase needed.
//!
//! PR D7 owns the group, so the slices are one module now. That is not
//! tidiness: `start` and `restart` regenerate the same two derived
//! files, `prune` runs `destroy`'s teardown in a loop, and five of the
//! eight open with the identical existence-then-version gate. Spread
//! across three files those would have drifted — the `cage stop` that
//! refuses a `vm` cage and the `cage start` that quietly mis-starts one
//! is exactly the kind of pair this collapses.
//!
//! # The shape every command here shares
//!
//! 1. Does the cage exist? No → `error: cage '<name>' does not exist`,
//!    exit 1.
//! 2. Is it a v0.22 cage? No → the migration procedure, exit 2. See
//!    [`ensure_v022_cage`]; `destroy` and `list` are exempt, and
//!    deliberately so.
//! 3. Is its backend ported? No → refuse rather than address the wrong
//!    containers (docs/history/rust-port-plan.md Track E).

use std::process::ExitCode;

use agentcage_core::har::datetime::DateTime;
use agentcage_core::har::json::Json;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage, parse_version};
use agentcage_cli::backend::SERVICE_NAMES;
use agentcage_cli::backends::AnyBackend;
use agentcage_state::Paths;

/// `cage list` — one row per cage, with live status.
pub(crate) fn list(ctx: &Ctx) -> ExitCode {
    let names = ctx.paths.list_deployments().unwrap_or_default();
    if names.is_empty() {
        println!("No cages found.");
        return ExitCode::SUCCESS;
    }

    println!(
        "{:<25} {:<14} {:<12} {:<15} STATUS",
        "NAME", "LIFECYCLE", "ISOLATION", "SCAFFOLD"
    );
    for name in names {
        let Ok(config) = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
        else {
            println!(
                "{name:<25} {:<14} {:<12} {:<15} unknown (config error)",
                "?", "?", "-"
            );
            continue;
        };
        let metadata = ctx
            .paths
            .load_metadata(&name)
            .unwrap_or_else(|_| Json::Object(Vec::new()));
        let lifecycle = string_or(&metadata, "lifecycle", &config.lifecycle);
        let scaffold = {
            let value = string_or(&metadata, "scaffold", &config.scaffold);
            if value.is_empty() {
                "-".to_owned()
            } else {
                value
            }
        };

        // A v0.21 cage's containers are named `<name>-proxy` /
        // `<name>-dns`, which `service_names()` no longer knows about,
        // so probing would mislabel a running legacy cage as stopped.
        let version = string_or(&metadata, "agentcage_version", "0.0.0");
        let version = if version.is_empty() {
            "0.0.0".to_owned()
        } else {
            version
        };
        if parse_version(&version) < (0, 22) {
            println!(
                "{name:<25} {lifecycle:<14} {:<12} {scaffold:<15} \
                 (legacy v0.21 — destroy + recreate)",
                config.isolation
            );
            continue;
        }

        let (running, total) = ctx.backend_for(&config.isolation).running_count(&name);
        let status = if running == total {
            format!("running ({running}/{total})")
        } else if running == 0 {
            if lifecycle == "interactive" || lifecycle == "ephemeral" {
                "exited".to_owned()
            } else {
                format!("stopped (0/{total})")
            }
        } else {
            format!("degraded ({running}/{total})")
        };
        println!(
            "{name:<25} {lifecycle:<14} {:<12} {scaffold:<15} {status}",
            config.isolation
        );
    }
    ExitCode::SUCCESS
}

/// `cage show` — one cage's configuration and status.
pub(crate) fn show(ctx: &Ctx, name: &str) -> ExitCode {
    match show_inner(ctx, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// `cage status` — `show` with a NAME, `list` without one.
pub(crate) fn status(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match matches.get_one::<String>("name") {
        Some(name) => show(ctx, name),
        None => list(ctx),
    }
}

fn show_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    if !ctx.paths.deployment_exists(name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, name)?;

    let config = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    let metadata = ctx
        .paths
        .load_metadata(name)
        .unwrap_or_else(|_| Json::Object(Vec::new()));
    let backend = ctx.backend_for(&config.isolation);

    let (running, total) = backend.running_count(name);
    let status = if running == total {
        format!("running ({running}/{total})")
    } else if running == 0 {
        format!("stopped (0/{total})")
    } else {
        format!("degraded ({running}/{total})")
    };

    println!("Name:       {}", config.name);
    println!("Isolation:  {}", config.isolation);
    println!("Image:      {}", config.container.image);
    // The *staged* Containerfile, which is the copy `cage update`
    // actually builds. Editing the one they authored has no effect.
    if !config.container.build.containerfile.is_empty() {
        let staged = ctx
            .paths
            .deployment_dir(name)
            .join(&config.container.build.containerfile);
        if staged.is_file() {
            println!("Build:      {}", staged.display());
        }
    }
    let version = string_or(&metadata, "agentcage_version", "-");
    println!(
        "Version:    {}",
        if version.is_empty() { "-" } else { &version }
    );
    println!("Status:     {status}");

    if !config.container.ports.is_empty() {
        println!("Ports:      {}", config.container.ports.join(", "));
    }

    // Domain info comes from the *raw* document, not the parsed config:
    // `_read_domain_config` reports what is written, and it differs from
    // the dataclass in one visible way — a `domains:` block with neither
    // `allow` nor `block` reads as `allowlist` here and as `""` there.
    if let Ok(raw) = ctx
        .paths
        .load_raw_config(name, agentcage_state::AgentSchema::Check)
    {
        let (mode, entries, passthrough) = read_domain_config(&raw);
        println!("Domains:    {mode} ({entries} domains)");
        if passthrough > 0 {
            println!("Passthrough: {passthrough} domains");
        }
    }

    let expected = agentcage_cli::services::expected_secrets(&config);
    if !expected.is_empty() {
        // Host podman is the secret store — except on apple-container,
        // which has no host podman and keeps its secrets in the macOS
        // keychain (or, under `backend: plaintext`, in the cage's own
        // state directory). Asking podman about one of those cages is
        // the failure mode this backend keeps producing: podman does
        // not error, it answers *nothing found*, so every secret was
        // reported missing on a cage that had all of them. Observed
        // against a real cage — `Secrets: 0/3 (3 missing)` where earlier
        // releases said `3/3`.
        //
        // The source here is the one `secret list` uses, which is what
        // makes the two agree.
        let present: Vec<String> = if crate::cli::secret::apple::is_apple_container(&config) {
            crate::cli::secret::apple::secret_names(ctx, &config, name)
        } else {
            let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
            let prefix = format!("{name}.");
            podman
                .secret_list(&prefix)
                .unwrap_or_default()
                .into_iter()
                .map(|full| full[prefix.len().min(full.len())..].to_owned())
                .collect()
        };
        let provided = expected.iter().filter(|key| present.contains(key)).count();
        let missing = expected.len() - provided;
        if missing > 0 {
            println!(
                "Secrets:    {provided}/{} ({missing} missing)",
                expected.len()
            );
        } else {
            println!("Secrets:    {}/{}", expected.len(), expected.len());
        }
    }
    Ok(())
}

/// `cage stop` — stop both units without destroying anything.
///
/// Here rather than in PR D7 for the same reason the four above are
/// here: **e2e phase 6** tears the `e2e-mask` cage down with it, and
/// that teardown is what makes the `/workspace/.git/hooks` tmpfs
/// vanish — the exact thing 6.11 is measuring. A `cage stop` that
/// exits `EX_SOFTWARE` leaves the mask standing and the assertion
/// meaningless.
pub(crate) fn stop(ctx: &Ctx, name: &str) -> ExitCode {
    match stop_inner(ctx, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn stop_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    // A legacy cage is refused here and *not* in `destroy` — stopping
    // one would address units that no longer exist under these names,
    // while destroy is the documented way out.
    let config = addressable(ctx, name, "cage stop")?;
    ctx.backend_for(&config.isolation).stop(name);
    agentcage_cli::services::record_stopped_at(&ctx.paths, name);
    println!("Stopped cage '{name}'");
    Ok(())
}

/// `cage start` — bring a stopped cage back up.
///
/// `cli.py:2107`. It is not `backend.start` with a gate in front of it:
/// four things are refreshed first, and each one exists because the
/// cage was editable while it was down.
///
/// 1. **The nested-podman patch tree** is re-copied from the embedded
///    assets, overwriting whatever is in the work directory. `cage
///    create` and `cage restart` both do it; a `start` that did not
///    would be the one way to boot a cage against a tampered shim.
/// 2. **`env:` and `cmd:` secrets are re-resolved** into the podman
///    store. The value behind `env:GITHUB_TOKEN` is whatever the
///    operator's environment says *now*, and the quadlet's `Secret=`
///    directives resolve at container creation — so a stale store
///    boots the cage with last week's token. Strict, as at create: a
///    resolution failure aborts the start rather than launching a
///    container whose `Secret=` names nothing.
/// 3. **`proxy-config.yaml`** (and, through it,
///    `cage-env/placeholders.env`) and **`dns-allowlist.conf`** are
///    regenerated from `cage.yaml`, so an edit made while the cage was
///    stopped applies on this boot. Neither is baked into a unit file,
///    which is why no quadlet regeneration and no `daemon-reload` is
///    needed here.
/// 4. **The backend's prerequisites** are checked, which is
///    `_ensure_backend_ready` — the diagnostics that turn a downed
///    podman into a named prerequisite rather than an "image not
///    found" three steps later.
pub(crate) fn start(ctx: &Ctx, name: &str) -> ExitCode {
    match start_inner(ctx, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn start_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    let config = addressable(ctx, name, "cage start")?;

    if let Err(error) = agentcage_cli::services::ensure_patches(&ctx.paths) {
        eprintln!("error: {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    // Container mode only, as in `cage create` and `run`: the vm and
    // apple-container backends materialize their own secrets at start,
    // and on a macOS host there is no podman store to populate.
    if config.isolation == "container" {
        let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
        let env = agentcage_cli::secrets::SystemEnv;
        let host = agentcage_cli::secrets::SecretHost::detect(ctx.runner.as_ref(), &env);
        if let Err(error) = host.resolve_and_populate(
            &podman,
            &config,
            name,
            &ctx.paths.deployment_dir(name),
            &std::collections::BTreeSet::new(),
            true,
        ) {
            eprintln!("error: {}", error.message());
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }

    ctx.paths
        .save_proxy_config(name, &ctx.version)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    ctx.paths
        .save_dns_allowlist(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;

    let backend = ctx.ensure_backend_ready(&config)?;
    backend.start(name, false).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    agentcage_cli::services::clear_stopped_at(&ctx.paths, name);
    println!("Started cage '{name}'");
    Ok(())
}

/// Steps 1–3 of the preamble every command in this module shares: the
/// cage exists, it is not a v0.21 cage, and its backend is one this
/// port can address. Returns the stored config, which every caller
/// wants next anyway.
///
/// `verb` names the command in the Track E refusal, so `cage start` on
/// an `apple-container` cage says `cage start` and not the name of
/// whichever helper happened to notice.
fn addressable(
    ctx: &Ctx,
    name: &str,
    verb: &str,
) -> Result<agentcage_core::config::Config, ExitCode> {
    if !ctx.paths.deployment_exists(name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, name)?;
    let config = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    if let Some(refusal) = AnyBackend::refusal(&config.isolation, verb) {
        eprintln!("{refusal}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    Ok(config)
}
/// `cage restart` — restart the services without rebuilding anything.
///
/// `cli.py:1803`. PR D7's command; it is here because **e2e phase 3**
/// needs it (3.3b proves a placeholder edit applies on a plain restart,
/// with no `cage update`; 3.5c proves the cage still boots after a
/// `secret rm`) and because the same `_restart_cage` is already the
/// fallback half of this PR's live-apply path.
///
/// The patch files are re-copied from the embedded assets first, which
/// overwrites any tampering — the same thing `cage create` does.
pub(crate) fn restart(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    match restart_inner(ctx, &name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn restart_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    let _config = addressable(ctx, name, "cage restart")?;
    if let Err(error) = agentcage_cli::services::ensure_patches(&ctx.paths) {
        eprintln!("error: {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    if crate::cli::secret::live::restart(ctx, name) {
        agentcage_cli::services::clear_stopped_at(&ctx.paths, name);
    }
    println!("Restarted cage '{name}'");
    Ok(())
}

/// `cage destroy` — stop, remove quadlets, podman resources and state.
pub(crate) fn destroy(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let yes = matches.get_flag("yes");
    let keep_secrets = matches.get_flag("keep_secrets");

    if !yes {
        let mut detail = "This will stop containers, remove quadlets, and state.".to_owned();
        detail.push_str(if keep_secrets {
            " Scoped secrets will be kept."
        } else {
            " Scoped secrets will also be removed."
        });
        if !confirm(&format!("Destroy cage \"{name}\"? {detail}")) {
            // `click.confirm(..., abort=True)` raises `Abort`, which
            // click renders as this line and exit 1.
            eprintln!("Aborted!");
            return ExitCode::from(EXIT_FAILURE);
        }
    }

    // Remove a pre-rework grants watcher BEFORE stopping the cage, so a
    // vm cage's in-guest cleanup can still run.
    if ctx.paths.deployment_exists(&name)
        && let Ok(config) = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
    {
        agentcage_cli::legacy_watcher::remove_legacy_grants_watcher(
            ctx.runner.as_ref(),
            &config.name,
            &config.isolation,
        );
    }

    let removed = destroy_cage(ctx, &name, keep_secrets, true);

    println!();
    if removed.is_empty() {
        println!("Nothing to remove (cage \"{name}\" not found).");
    } else {
        println!("Removed:");
        for item in &removed {
            println!("  {item}");
        }
    }
    print_kept(&ctx.paths, &name);
    ExitCode::SUCCESS
}

/// Print the `Kept:` block: the per-cage data directory `destroy` does
/// not remove, and what is still in it (#423).
///
/// The deployment and the data directory are different things. The
/// former is what `destroy` removes; the latter holds the grants
/// overlay, the capture log, the policy audit trail and the timing
/// ledger, and outliving the cage is the point — deleting the audit
/// trail on `destroy` would make it erasable by the command that
/// removes the evidence of why it mattered. That decision stands;
/// what was wrong is that the command did not say so, and that the
/// list it said it with was hard-coded.
///
/// **The inventory is read off the directory and not asserted.** It is
/// taken *after* the teardown, so what it names is what actually
/// survived it, and there is no block at all when the directory is not
/// there. Two things that were wrong when this was a fixed sentence:
///
/// * `capture/` is the container and vm backend's log. An
///   `apple-container` cage writes `capture.jsonl` under
///   `~/.config/agentcage/apple-container/<name>/logs/`, which is the
///   apple state tree `destroy` removes (see
///   `agentcage_state::Paths::apple_capture_file` and
///   `har::capture_path`), so naming `capture/` there claimed to keep
///   a log that had just been deleted. The deploy still creates the
///   host `capture/` directory for every backend, but on apple it is
///   empty; empty directories are skipped, see below.
/// * `inspectors/` is staged deployment content, removed by
///   `remove_deployment`, so it must not be named as data that stayed.
///   Reading the directory after the teardown covers it without a
///   special case, and also covers the one path that does leave it
///   behind: destroy on a name with neither a stored config nor
///   backend resources.
///
/// A directory that holds nothing is skipped: `grants/` created at
/// deploy time but never written, or apple's empty `capture/`, keeps
/// no data and naming it would only suggest it did. The path line is
/// still printed either way — it is what the operator has to remove by
/// hand — and a `Kept:` heading over an otherwise empty directory is
/// the truth, not noise.
fn print_kept(paths: &Paths, name: &str) {
    let data = paths.cage_data_dir(name);
    if !data.is_dir() {
        return;
    }
    println!("Kept:");
    println!("  data:{}", data.display());
    let entries = kept_entries(&data);
    if !entries.is_empty() {
        println!("  left in place: {}", entries.join(", "));
    }
}

/// The top-level entries of the data directory that hold something,
/// as names to print: a directory gets a trailing `/`, a file does
/// not.
///
/// Sorted, because the order of a `read_dir` is the filesystem's and
/// this output is pinned by a test. An entry whose metadata or
/// directory cannot be read is skipped rather than reported: the
/// block's whole point is not to name anything the operator cannot
/// find.
pub(crate) fn kept_entries(data: &std::path::Path) -> Vec<String> {
    let mut entries: Vec<String> = std::fs::read_dir(data)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| holds_data(path))
        .filter_map(|path| {
            let name = path.file_name()?.to_string_lossy().into_owned();
            Some(if path.is_dir() {
                format!("{name}/")
            } else {
                name
            })
        })
        .collect();
    entries.sort();
    entries
}

/// Whether `path` keeps anything: a file always does, a directory only
/// when it has an entry of its own.
///
/// A directory that cannot be read answers *no* — see
/// [`kept_entries`].
fn holds_data(path: &std::path::Path) -> bool {
    !path.is_dir() || std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
}

/// What [`destroy_cage_status`] removed and whether the teardown was
/// complete.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DestroyResult {
    /// The removal descriptions `cage destroy` prints, in order.
    pub(crate) removed: Vec<String>,
    /// Whether every part of the teardown succeeded. False means at
    /// least one resource or the deployment itself may still be there,
    /// even when the deployment directory is gone.
    pub(crate) complete: bool,
}

/// Stop, destroy, forget.
///
/// When the stored config cannot be loaded the fallback is simply the
/// container backend: its `has_resources` is a filesystem check and
/// its podman calls already tolerate a podman that cannot be run.
///
/// The returned list is only what was removed, for `cage destroy` and
/// `cage prune` to print. Callers that need to know whether teardown
/// *finished* must use [`destroy_cage_status`]: a failed
/// `destroy_resources` is otherwise indistinguishable from a complete
/// one once the deployment directory has been removed.
pub(crate) fn destroy_cage(ctx: &Ctx, name: &str, keep_secrets: bool, echo: bool) -> Vec<String> {
    destroy_cage_status(ctx, name, keep_secrets, echo).removed
}

/// [`destroy_cage`], also reporting whether the teardown was complete.
///
/// `complete` is false when `destroy_resources` errors or when the
/// deployment cannot be removed — the two failures `destroy_cage`
/// itself only warns about. `run --rm` uses this so a partial teardown
/// is reported as a failure rather than as `Removed` merely because
/// `deployment_exists` became false.
pub(crate) fn destroy_cage_status(
    ctx: &Ctx,
    name: &str,
    keep_secrets: bool,
    echo: bool,
) -> DestroyResult {
    let backend = ctx.backend_of(name);
    let known = ctx.paths.deployment_exists(name);
    if !known && !backend.has_resources(name) {
        if echo {
            println!("Nothing to remove for '{name}' (no stored config and no backend resources).");
        }
        return DestroyResult {
            removed: Vec::new(),
            complete: true,
        };
    }

    if echo {
        println!("Stopping services...");
    }
    backend.stop(name);

    if echo {
        println!("Removing resources...");
    }
    let mut complete = true;
    let mut removed = match backend.destroy_resources(name, keep_secrets) {
        Ok(removed) => removed,
        Err(error) => {
            eprintln!("warning: {error}");
            complete = false;
            Vec::new()
        }
    };

    if ctx.paths.deployment_exists(name) {
        let removal = if keep_secrets {
            ctx.paths.remove_deployment_keeping_secrets(name)
        } else {
            ctx.paths.remove_deployment(name)
        };
        match removal {
            Err(error) => {
                eprintln!("warning: {error}");
                complete = false;
            }
            Ok(()) if ctx.paths.deployment_exists(name) => {
                // Defensive: a `remove_deployment` that returned Ok
                // but left the directory is not a complete teardown.
                complete = false;
            }
            Ok(()) => removed.push(format!("state:{name}")),
        }
    }
    DestroyResult { removed, complete }
}

/// `cage prune` — remove every *exited* interactive or ephemeral cage.
///
/// `cli.py:1445`. Three filters decide the candidate list, and all
/// three matter:
///
/// * **Lifecycle.** Only `interactive` and `ephemeral` cages are
///   prunable. A `service` cage that happens to be down is down on
///   purpose — `cage stop` is a thing operators do — and removing it
///   would be indistinguishable from data loss. The lifecycle is read
///   from metadata first, falling back to `cage.yaml`, because `cage
///   run` records the lifecycle it actually deployed with.
/// * **Version.** A v0.21 cage is skipped, not refused: its containers
///   are named `<name>-proxy` / `<name>-dns`, so probing the v0.22
///   shape would answer "not running" for a *live* legacy cage and
///   prune it out from under its workload. The operator destroys those
///   by name. This is the third exemption from the v0.21 gate and the
///   only one that is silent — `list` annotates, `destroy` proceeds,
///   `prune` walks past.
/// * **Running.** Zero of the cage's services up.
///
/// `--older-than` is a fourth filter, applied to the **time the cage
/// stopped**, not to the deployment directory's or `metadata.json`'s
/// mtime. `run` and `cage stop` write `stopped_at` into
/// `metadata.json`; every successful start path (`cage start`,
/// `cage restart`, `cage update`, `cage restore`, and the live-secret
/// restart fallback) clears it. A metadata mtime proves only that
/// metadata was written: a cage that ran for a month and rebooted five
/// minutes ago would look ancient. So a cage with no recorded
/// `stopped_at` is skipped — "I cannot prove it is old" must never
/// mean "remove it", and a missing stop time must never stand in for
/// one.
///
/// The teardown itself is `destroy`'s, run with its narration
/// suppressed, so a ten-cage prune
/// prints ten `Removing <name>...` lines rather than thirty. A failure
/// on one cage warns and continues — a prune that stops at the first
/// stuck cage leaves the rest of the list uncollected.
pub(crate) fn prune(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let yes = matches.get_flag("yes");
    let dry_run = matches.get_flag("dry_run");
    let older_than = match matches.get_one::<String>("older_than") {
        Some(spec) => match crate::cli::domain::parse_duration(spec) {
            Ok(seconds) => Some(seconds),
            Err(message) => {
                eprintln!("error: invalid --older-than: {message}");
                return ExitCode::from(EXIT_FAILURE);
            }
        },
        None => None,
    };

    let candidates = prune_candidates(ctx, older_than);
    if candidates.is_empty() {
        println!("Nothing to prune.");
        return ExitCode::SUCCESS;
    }

    if dry_run {
        println!("Dry run: no cages will be removed.");
    } else {
        println!("The following exited cages will be removed:");
    }
    for name in &candidates {
        println!("  {name}");
    }

    if dry_run {
        println!("Would prune {} cage(s).", candidates.len());
        return ExitCode::SUCCESS;
    }

    if !yes && !confirm(&format!("\nRemove {} cage(s)?", candidates.len())) {
        eprintln!("Aborted!");
        return ExitCode::from(EXIT_FAILURE);
    }

    for name in &candidates {
        println!("Removing {name}...");
        destroy_cage(ctx, name, false, false);
        // The teardown is destroy's, so the retention notice is too.
        // Silent here would leave a prune of ten cages claiming to have
        // removed ten data directories it did not touch (#423).
        print_kept(&ctx.paths, name);
    }
    println!("Pruned {} cage(s).", candidates.len());
    ExitCode::SUCCESS
}

/// The cages `prune` is allowed to remove, after every filter.
fn prune_candidates(ctx: &Ctx, older_than: Option<i64>) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();

    for name in ctx.paths.list_deployments().unwrap_or_default() {
        let Ok(config) = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
        else {
            continue;
        };
        // Track E. Only a backend this port can probe: an
        // apple-container cage answered by the container backend would
        // read as exited while it is up, and prune acts on that answer.
        if AnyBackend::refusal(&config.isolation, "cage prune").is_some() {
            continue;
        }
        let metadata = ctx
            .paths
            .load_metadata(&name)
            .unwrap_or_else(|_| Json::Object(Vec::new()));
        let lifecycle = string_or(&metadata, "lifecycle", &config.lifecycle);
        if lifecycle != "interactive" && lifecycle != "ephemeral" {
            continue;
        }
        let version = string_or(&metadata, "agentcage_version", "0.0.0");
        let version = if version.is_empty() {
            "0.0.0".to_owned()
        } else {
            version
        };
        if parse_version(&version) < (0, 22) {
            continue;
        }
        if ctx.backend_for(&config.isolation).running_count(&name).0 != 0 {
            continue;
        }
        if let Some(seconds) = older_than
            && stopped_age_seconds(&metadata).is_none_or(|age| age < seconds)
        {
            continue;
        }
        candidates.push(name);
    }
    candidates
}

/// Seconds since the cage last stopped, or `None` when it has no
/// recorded stop time.
///
/// Deliberately no `metadata.json` mtime fallback: the file's
/// modification time is not the time the cage stopped, and treating it
/// as one can remove a cage that restarted moments ago. A missing,
/// empty or unparseable `stopped_at` answers `None`, and
/// `--older-than` then skips the cage rather than guessing.
fn stopped_age_seconds(metadata: &Json) -> Option<i64> {
    let stopped = metadata
        .get("stopped_at")
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .and_then(DateTime::from_isoformat)?;
    DateTime::now_utc()
        .seconds_since(&stopped.assume_utc())
        .map(|seconds| seconds.max(0))
}

/// `click.confirm` — `[y/N]`, default no, EOF is no.
fn confirm(prompt: &str) -> bool {
    use std::io::{BufRead as _, Write as _};

    let mut out = std::io::stdout();
    let _ = write!(out, "{prompt} [y/N]: ");
    let _ = out.flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// `cli._read_domain_config`, reduced to what `cage show` prints:
/// `(mode, domain count, passthrough count)`.
///
/// Both the current `allow`/`block` shape and the legacy `mode` +
/// `list` one, because a cage deployed by an older agentcage still has
/// the legacy keys on disk and §2.7 forbids a migration step.
fn read_domain_config(raw: &agentcage_core::yaml::Value) -> (String, usize, usize) {
    let domains = raw.get("domains");
    let sequence_len = |key: &str| -> usize {
        domains
            .and_then(|d| d.get(key))
            .and_then(|v| v.as_sequence())
            .map_or(0, Vec::len)
    };
    let has = |key: &str| domains.is_some_and(|d| d.get(key).is_some());
    let passthrough = sequence_len("passthrough");
    if has("allow") {
        return ("allowlist".to_owned(), sequence_len("allow"), passthrough);
    }
    if has("block") {
        return ("blocklist".to_owned(), sequence_len("block"), passthrough);
    }
    let mode = domains
        .and_then(|d| d.get("mode"))
        .and_then(agentcage_core::yaml::Value::as_str)
        .unwrap_or("allowlist")
        .to_owned();
    (mode, sequence_len("list"), passthrough)
}

/// `meta.get(key, fallback)` for a string-valued metadata entry.
fn string_or(metadata: &Json, key: &str, fallback: &str) -> String {
    metadata
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

/// The count `cage list` and `cage show` both print, exposed so
/// `cage verify` can agree with them.
#[must_use]
pub(crate) fn service_status(backend: &AnyBackend<'_>, name: &str) -> Vec<(String, bool)> {
    SERVICE_NAMES
        .iter()
        .map(|service| ((*service).to_owned(), backend.is_running(name, service)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{prune, prune_candidates};
    use crate::cli::context::Ctx;
    use agentcage_core::har::datetime::DateTime;
    use agentcage_core::har::json::Json;
    use agentcage_exec::{FakeRunner, Reply};
    use agentcage_state::{Paths, TestDir};

    fn ctx_under(dir: &std::path::Path, fake: FakeRunner) -> Ctx {
        Ctx {
            paths: Paths::under(dir),
            runner: Box::new(fake),
            version: "9.9.9".to_owned(),
        }
    }

    /// Stage one deployment with the metadata `prune` reads.
    fn stage(
        home: &std::path::Path,
        name: &str,
        lifecycle: &str,
        version: &str,
        stopped_at: Option<&str>,
    ) -> Paths {
        let paths = Paths::under(home);
        let source = home.join(format!("{name}.yaml"));
        std::fs::write(
            &source,
            format!(
                "name: {name}\nisolation: container\nlifecycle: {lifecycle}\ncontainer:\n  image: \"alpine\"\n"
            ),
        )
        .expect("write config");
        paths
            .save_deployment(name, &source)
            .expect("save deployment");
        let mut metadata = Json::Object(vec![
            ("agentcage_version".to_owned(), Json::string(version)),
            ("lifecycle".to_owned(), Json::string(lifecycle)),
        ]);
        if let Some(stopped_at) = stopped_at {
            metadata.set("stopped_at", Json::string(stopped_at));
        }
        paths.save_metadata(name, &metadata).expect("save metadata");
        paths
    }

    /// `--older-than` compares the recorded stop time, and the three
    /// existing filters still win over it: a recent cage, a service
    /// cage, a legacy cage and a running cage all stay.
    #[test]
    fn older_than_filters_by_stopped_at_and_never_selects_forbidden_cages() {
        let dir = TestDir::new("prune-older-than");
        let old = "2000-01-01T00:00:00+00:00";
        let now = DateTime::now_utc().isoformat();
        stage(dir.path(), "old-cage", "interactive", "0.53.1", Some(old));
        stage(
            dir.path(),
            "recent-cage",
            "interactive",
            "0.53.1",
            Some(&now),
        );
        stage(dir.path(), "service-cage", "service", "0.53.1", Some(old));
        stage(
            dir.path(),
            "legacy-cage",
            "interactive",
            "0.21.5",
            Some(old),
        );
        stage(
            dir.path(),
            "running-cage",
            "interactive",
            "0.53.1",
            Some(old),
        );

        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.default_reply(Reply::success());
        fake.on(
            [
                "podman",
                "inspect",
                "--format",
                "{{.State.Status}}",
                "running-cage-cage",
            ],
            Reply::ok("running"),
        );
        let ctx = ctx_under(dir.path(), fake);

        assert_eq!(prune_candidates(&ctx, Some(3600)), ["old-cage"]);
        assert_eq!(
            prune_candidates(&ctx, None),
            ["old-cage", "recent-cage"],
            "without --older-than both stopped interactive cages are candidates"
        );
    }

    /// A cage with no `stopped_at` is skipped by `--older-than` even
    /// when its `metadata.json` mtime is ancient. The file's mtime is
    /// not the time the cage stopped: a cage that ran for a month and
    /// rebooted five minutes ago has old metadata and no stop recorded.
    #[test]
    fn older_than_skips_a_cage_with_no_recorded_stop_even_with_old_metadata() {
        let dir = TestDir::new("prune-old-metadata-no-stop");
        let paths = stage(dir.path(), "no-stop-cage", "interactive", "0.53.1", None);

        // Make the metadata file look years old, which the former
        // mtime fallback would have treated as a stop time.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(paths.metadata_path("no-stop-cage"))
            .expect("metadata is writable");
        file.set_times(
            std::fs::FileTimes::new().set_modified(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
            ),
        )
        .expect("mtime is settable");

        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.default_reply(Reply::success());
        let ctx = ctx_under(dir.path(), fake);

        assert!(
            prune_candidates(&ctx, Some(3600)).is_empty(),
            "a cage with no stopped_at was selected by --older-than"
        );
        // Without the age filter it is still an ordinary stopped
        // interactive cage, so the absence of a stop time is not a
        // permanent exemption.
        assert_eq!(prune_candidates(&ctx, None), ["no-stop-cage"]);
    }

    /// `--dry-run` prints the candidate list and returns without
    /// touching the deployment or asking for confirmation.
    #[test]
    fn prune_dry_run_changes_nothing() {
        let dir = TestDir::new("prune-dry-run");
        let paths = stage(
            dir.path(),
            "dry-cage",
            "interactive",
            "0.53.1",
            Some("2000-01-01T00:00:00+00:00"),
        );

        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.default_reply(Reply::success());
        let ctx = ctx_under(dir.path(), fake.clone());

        let root = crate::cli::cage::command()
            .try_get_matches_from(["cage", "prune", "--dry-run", "--older-than", "1h"])
            .expect("the argv parses");
        let leaf = root.subcommand_matches("prune").expect("the prune leaf");
        let _ = prune(&ctx, leaf);

        assert!(
            paths.deployment_exists("dry-cage"),
            "--dry-run removed the cage"
        );
        assert!(
            !fake.argv_sequence().iter().any(|argv| {
                argv.first().map(String::as_str) == Some("systemctl")
                    && argv.iter().any(|arg| arg == "stop")
            }),
            "--dry-run reached the teardown: {:?}",
            fake.argv_sequence()
        );
    }
}
