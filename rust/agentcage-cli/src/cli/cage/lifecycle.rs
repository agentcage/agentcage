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
//!    containers (RUST-PORT-PLAN.md Track E).

use std::process::ExitCode;

use agentcage_core::har::json::Json;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage, parse_version};
use agentcage_cli::backend::SERVICE_NAMES;
use agentcage_cli::backends::AnyBackend;

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
        let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
        let prefix = format!("{name}.");
        let present: Vec<String> = podman
            .secret_list(&prefix)
            .unwrap_or_default()
            .into_iter()
            .map(|full| full[prefix.len().min(full.len())..].to_owned())
            .collect();
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
    crate::cli::secret::live::restart(ctx, name);
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
    if ctx.paths.deployment_exists(&name) {
        if let Ok(config) = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
        {
            agentcage_cli::legacy_watcher::remove_legacy_grants_watcher(
                ctx.runner.as_ref(),
                &config.name,
                &config.isolation,
            );
        }
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
    ExitCode::SUCCESS
}

/// `services.destroy_cage` — stop, destroy, forget.
///
/// The Python falls back to probing each backend when the stored config
/// cannot be loaded, because on macOS the default `ContainerBackend`
/// calls `podman`, which is not installed. Only one backend is ported,
/// so the fallback here is simply "use it anyway": its `has_resources`
/// is a filesystem check and its podman calls already tolerate a podman
/// that cannot be run.
fn destroy_cage(ctx: &Ctx, name: &str, keep_secrets: bool, echo: bool) -> Vec<String> {
    let backend = ctx.backend_of(name);
    let known = ctx.paths.deployment_exists(name);
    if !known && !backend.has_resources(name) {
        if echo {
            println!("Nothing to remove for '{name}' (no stored config and no backend resources).");
        }
        return Vec::new();
    }

    if echo {
        println!("Stopping services...");
    }
    backend.stop(name);

    if echo {
        println!("Removing resources...");
    }
    let mut removed = backend
        .destroy_resources(name, keep_secrets)
        .unwrap_or_else(|error| {
            eprintln!("warning: {error}");
            Vec::new()
        });

    if ctx.paths.deployment_exists(name) {
        if let Err(error) = ctx.paths.remove_deployment(name) {
            eprintln!("warning: {error}");
        } else {
            removed.push(format!("state:{name}"));
        }
    }
    removed
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
/// The teardown itself is `destroy`'s, run with its narration
/// suppressed: the Python passes no `echo` here, so a ten-cage prune
/// prints ten `Removing <name>...` lines rather than thirty. A failure
/// on one cage warns and continues — a prune that stops at the first
/// stuck cage leaves the rest of the list uncollected.
pub(crate) fn prune(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let yes = matches.get_flag("yes");
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
        if ctx.backend_for(&config.isolation).running_count(&name).0 == 0 {
            candidates.push(name);
        }
    }

    if candidates.is_empty() {
        println!("Nothing to prune.");
        return ExitCode::SUCCESS;
    }

    println!("The following exited cages will be removed:");
    for name in &candidates {
        println!("  {name}");
    }

    if !yes && !confirm(&format!("\nRemove {} cage(s)?", candidates.len())) {
        eprintln!("Aborted!");
        return ExitCode::from(EXIT_FAILURE);
    }

    for name in &candidates {
        println!("Removing {name}...");
        destroy_cage(ctx, name, false, false);
    }
    println!("Pruned {} cage(s).", candidates.len());
    ExitCode::SUCCESS
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
