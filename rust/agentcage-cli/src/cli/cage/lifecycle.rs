//! `cage list`, `cage show`, `cage status`, `cage destroy`.
//!
//! The read-only half of the cage lifecycle plus the one command that
//! removes things. They land here rather than waiting for PR D7 because
//! e2e phase 1 — this PR's acceptance check — asserts on all four, and
//! a phase that cannot clean up after itself is not repeatable.

use std::process::ExitCode;

use agentcage_core::har::json::Json;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage, parse_version};
use agentcage_cli::backend::{ContainerBackend, SERVICE_NAMES};

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
    let backend = ctx.backend();
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

        let (running, total) = backend.running_count(&name);
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
    let backend = ctx.backend();

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
    if !ctx.paths.deployment_exists(name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    // A legacy cage is refused here and *not* in `destroy` — stopping
    // one would address units that no longer exist under these names,
    // while destroy is the documented way out.
    ensure_v022_cage(&ctx.paths, name)?;

    let config = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    if config.isolation != "container" {
        eprintln!(
            "error: `cage stop` on the '{}' backend is not ported yet \
             (RUST-PORT-PLAN.md Track E)",
            config.isolation
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    ctx.backend().stop(name);
    println!("Stopped cage '{name}'");
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

    let removed = destroy_cage(ctx, &name, keep_secrets);

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
fn destroy_cage(ctx: &Ctx, name: &str, keep_secrets: bool) -> Vec<String> {
    let backend = ctx.backend();
    let known = ctx.paths.deployment_exists(name);
    if !known && !backend.has_resources(name) {
        println!("Nothing to remove for '{name}' (no stored config and no backend resources).");
        return Vec::new();
    }

    println!("Stopping services...");
    backend.stop(name);

    println!("Removing resources...");
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
pub(crate) fn service_status(backend: &ContainerBackend<'_>, name: &str) -> Vec<(String, bool)> {
    SERVICE_NAMES
        .iter()
        .map(|service| ((*service).to_owned(), backend.is_running(name, service)))
        .collect()
}
