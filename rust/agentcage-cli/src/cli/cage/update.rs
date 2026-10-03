//! `cage update` — rebuild and restart an existing cage.
//!
//! `cli.py:1097`. The interesting half is the *decision*: an update
//! whose inputs have not moved must be a no-op, and the whole of
//! `fingerprint.py` exists to make that checkable. The five inputs are
//! gathered in [`agentcage_cli::deploy::update_fingerprint`]; what is here is
//! the order they are gathered in, which is load-bearing.
//!
//! Specifically: the units are rendered and the image identities
//! resolved **before anything is stopped**. A no-op update has to be
//! non-disruptive, and a cage that got stopped and restarted to discover
//! nothing changed would be worse than one that never checked.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use agentcage_core::config::Config;
use agentcage_core::fingerprint::fingerprint_matches;
use agentcage_core::har::json::Json;
use clap::ArgMatches;

use crate::cli::cage::create::{build_container_image, report_port_conflicts, stage_context};
use crate::cli::context::{
    Ctx, EXIT_FAILURE, ensure_v022_cage, load_and_validate, load_stored_and_validate,
};
use agentcage_cli::deploy;
use agentcage_cli::services;

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match run(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one body, matching `cli.py:1097`. See `create.rs` for the \
              same reasoning: the sequence is the contract."
)]
fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let positional = matches.get_one::<String>("name").cloned();
    let config_path = matches.get_one::<String>("config_path").map(PathBuf::from);
    let no_cache = matches.get_flag("no_cache");
    let pull = matches.get_flag("pull");
    let force = matches.get_flag("force");

    if positional.is_none() && config_path.is_none() {
        eprintln!(
            "error: either NAME or -c/--config is required (the cage to update \
             must be identifiable)"
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let (name, config) = if let Some(path) = &config_path {
        adopt_config(ctx, path, positional.as_deref())?
    } else {
        {
            let name = positional.expect("checked above");
            if !ctx.paths.deployment_exists(&name) {
                eprintln!("error: cage '{name}' does not exist");
                return Err(ExitCode::from(EXIT_FAILURE));
            }
            ensure_v022_cage(&ctx.paths, &name)?;
            // The cage's cage.yaml and Containerfile are frozen at
            // create time and owned by the cage from then on — a
            // scaffold is a one-shot generator, not a live dependency.
            // `cage update` without `-c` never re-reads the scaffold and
            // never mutates the stored config.
            ctx.paths
                .fill_placeholders(&name, None, &mut agentcage_state::mint_placeholder)
                .map_err(|error| state_error(&error))?;
            let config = load_stored_and_validate(&ctx.paths, &name)?;
            (name, config)
        }
    };

    // Pre-rework cages carry a host-side grants watcher whose command no
    // longer exists; on an upgraded host the unit crash-loops on every
    // boot. Remove it now, while a vm cage's guest is still running —
    // update stops services only later. Best-effort and idempotent.
    agentcage_cli::legacy_watcher::remove_legacy_grants_watcher(
        ctx.runner.as_ref(),
        &config.name,
        &config.isolation,
    );

    // Merge into existing metadata so scaffold / network_octet survive.
    let mut metadata = ctx
        .paths
        .load_metadata(&name)
        .unwrap_or_else(|_| Json::Object(Vec::new()));
    metadata.set("agentcage_version", Json::string(&ctx.version));
    ctx.paths
        .save_metadata(&name, &metadata)
        .map_err(|error| state_error(&error))?;

    let config_host_path = ctx
        .paths
        .save_proxy_config(&name, &ctx.version)
        .map_err(|error| state_error(&error))?;
    ctx.paths
        .save_dns_allowlist(&name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| state_error(&error))?;

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let env = agentcage_cli::secrets::SystemEnv;

    // Checked against the store that actually backs this cage. Only the
    // container backend keeps secrets on host podman; the vm backend's
    // live inside the guest and apple-container's in the keychain, and
    // querying host podman for either reports everything as missing.
    let missing = if config.isolation == "container" {
        services::check_secrets(&podman, &ctx.paths, &name, &config, &env)
    } else {
        Vec::new()
    };
    if !missing.is_empty() {
        eprintln!("error: missing secrets for cage '{name}':");
        for key in &missing {
            eprintln!("  {key}");
        }
        eprintln!("Create them with:");
        for key in &missing {
            eprintln!("  agentcage secret set {name} {key}");
        }
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    // Preserve the octet the podman network was created with. Deriving
    // it fresh here can land elsewhere if create-time collision
    // resolution shifted it, and the egress then refuses to start:
    // "requested static ip 10.89.X.10 not in any subnet on network".
    let existing_octet =
        ctx.paths
            .load_metadata(&name)
            .ok()
            .and_then(|meta| match meta.get("network_octet") {
                Some(&Json::Int(octet)) => u32::try_from(octet).ok(),
                _ => None,
            });

    let backend = ctx.ensure_backend_ready(&config)?;
    let computed = deploy::update_fingerprint(
        &backend,
        &ctx.paths,
        deploy::FingerprintRequest {
            config: &config,
            name: &name,
            config_host_path: &config_host_path.display().to_string(),
            network_octet: existing_octet,
            refresh_images: true,
            units: None,
        },
    )
    .map_err(|error| backend_error(&error))?;

    let stored = ctx.paths.load_fingerprint(&name);
    let running = agentcage_cli::backend::SERVICE_NAMES
        .iter()
        .all(|service| backend.is_running(&name, service));
    let unchanged = stored
        .as_ref()
        .is_some_and(|stored| fingerprint_matches(stored, &computed.fingerprint));
    if !(force || no_cache || pull) && running && unchanged {
        println!("cage '{name}' already up to date (use --force to rebuild anyway)");
        return Ok(());
    }

    // Stop before the port check — the running cage's own ports would
    // otherwise read as conflicts.
    println!("Stopping services...");
    backend.stop(&name);

    // Container port release can lag behind service stop, so retry.
    if !services::check_port_availability(&config).is_empty() {
        for _ in 0..5 {
            std::thread::sleep(Duration::from_secs(1));
            if services::check_port_availability(&config).is_empty() {
                break;
            }
        }
    }
    report_port_conflicts(&config)?;

    if config.isolation == "container" && !config.container.build.containerfile.is_empty() {
        let config_dir = config_path
            .as_deref()
            .and_then(Path::parent)
            .map_or_else(|| ctx.paths.deployment_dir(&name), Path::to_path_buf);
        build_container_image(ctx, &config, &config_dir, no_cache, pull)?;
    }

    let used = services::collect_used_octets(&ctx.paths, &name);
    let deployed = services::build_and_deploy(
        &backend,
        &ctx.paths,
        &services::DeployPlan {
            config: &config,
            config_host_path: &config_host_path.display().to_string(),
            deploy_name: &name,
            used_octets: Some(&used),
            network_octet: existing_octet,
            quiet: false,
            no_cache,
            pull,
        },
    )
    .map_err(|error| backend_error(&error))?;

    // Only record a fingerprint once the whole build/install/start path
    // succeeded, and re-inspect the image identities: a Containerfile
    // build may have moved the target image since the preflight
    // snapshot.
    let final_fingerprint = deploy::update_fingerprint(
        &backend,
        &ctx.paths,
        deploy::FingerprintRequest {
            config: &config,
            name: &name,
            config_host_path: &config_host_path.display().to_string(),
            network_octet: existing_octet,
            refresh_images: false,
            units: Some(deployed.units),
        },
    )
    .map_err(|error| backend_error(&error))?;
    ctx.paths
        .save_fingerprint(&name, &final_fingerprint.fingerprint.to_json())
        .map_err(|error| state_error(&error))?;
    println!("Updated cage '{name}'");

    if !config.help.is_empty() {
        println!();
        println!("{}", config.help.trim_end());
    }
    Ok(())
}

/// `cage update -c <file>` — adopt a replacement config.
///
/// The previous stored document is captured before it is overwritten so
/// already-generated placeholders carry over: a fresh token would
/// desynchronize every process still holding the old one. It is read
/// with the agent-schema check *disabled*, because an explicit
/// replacement has to work even when what is on disk is no longer
/// supported — and the replacement itself was fully validated first.
fn adopt_config(
    ctx: &Ctx,
    path: &Path,
    positional: Option<&str>,
) -> Result<(String, Config), ExitCode> {
    let mut config = load_and_validate(path)?;
    let name = match positional {
        None => config.name.clone(),
        Some(given) if config.name == given => given.to_owned(),
        Some(given) => {
            eprintln!(
                "error: config name '{}' does not match cage '{given}'",
                config.name
            );
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    };
    if !ctx.paths.deployment_exists(&name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, &name)?;

    let previous = deploy::previous_raw(&ctx.paths, &name);
    ctx.paths
        .save_deployment(&name, path)
        .map_err(|error| state_error(&error))?;
    let filled = ctx
        .paths
        .fill_placeholders(
            &name,
            previous.as_ref(),
            &mut agentcage_state::mint_placeholder,
        )
        .map_err(|error| state_error(&error))?;
    if filled {
        config = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
            .map_err(|error| state_error(&error))?;
    }
    stage_context(&config, path, &ctx.paths.deployment_dir(&name));
    Ok((name, config))
}

fn state_error(error: &agentcage_state::StateError) -> ExitCode {
    eprintln!("error: {error}");
    ExitCode::from(EXIT_FAILURE)
}

fn backend_error(error: &agentcage_cli::backend::BackendError) -> ExitCode {
    eprintln!("error: {error}");
    ExitCode::from(EXIT_FAILURE)
}
