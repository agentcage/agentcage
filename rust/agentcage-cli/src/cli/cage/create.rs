//! `cage create` — build images, generate quadlets, install, and start.
//!
//! `cli.py:835`, in the order it does things, because the order is the
//! contract: state is saved before the build so a failed build leaves a
//! cage that `cage update` can retry, secrets are stored before the
//! build so they are available to it, and `save_proxy_config` runs
//! before the build so the egress has something to read the moment the
//! quadlet starts it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentcage_core::config::Config;
use agentcage_core::har::json::Json;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, load_and_validate};
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
    reason = "one body, matching `cli.py:835`. Every step reads state \
              the previous one wrote and the order is observable from \
              outside — splitting it would mean threading a dozen \
              intermediates through helpers with no meaning apart from \
              this sequence."
)]
fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    agentcage_cli::output::banner(&ctx.version);

    let config_path = resolve_config_argument(matches)?;
    let no_cache = matches.get_flag("no_cache");
    let pull = matches.get_flag("pull");
    let show_timing = matches.get_flag("show_timing");
    if show_timing {
        // `os.environ["AGENTCAGE_TIMING"] = "1"` in the Python. See
        // `timing::enable_echo` for why this is a flag and not an
        // environment write.
        agentcage_cli::timing::enable_echo();
    }
    let secrets: Vec<String> = matches
        .get_many::<String>("secrets")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    let mut config = load_and_validate(&config_path)?;
    warn_about_rw_host_binds(&config);

    let name = config.name.clone();
    if ctx.paths.deployment_exists(&name) {
        eprintln!("error: cage '{name}' already exists");
        eprintln!("  Use 'agentcage cage update {name}' to update it.");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let env = agentcage_cli::secrets::SystemEnv;

    // Secrets given with `--set-secret` are about to exist, so they are
    // not missing.
    let being_set: Vec<&str> = secrets
        .iter()
        .map(|spec| spec.split_once('=').map_or(spec.as_str(), |(key, _)| key))
        .collect();
    let missing: Vec<String> = if config.isolation == "container"
        || agentcage_exec::command::which_on_path("podman").is_some()
    {
        services::check_secrets(&podman, &ctx.paths, &name, &config, &env)
            .into_iter()
            .filter(|key| !being_set.contains(&key.as_str()))
            .collect()
    } else {
        Vec::new()
    };
    if !missing.is_empty() {
        eprintln!("error: missing secrets for cage '{name}':");
        for key in &missing {
            eprintln!("  {key}");
        }
        eprintln!("Create them with --set-secret or after creation:");
        let flags = missing.iter().fold(String::new(), |mut acc, key| {
            use std::fmt::Write as _;
            let _ = write!(acc, " -s {key}=VALUE");
            acc
        });
        eprintln!(
            "  agentcage cage create -c {}{flags}",
            config_path.display()
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    report_port_conflicts(&config)?;

    // ── state ───────────────────────────────────────────
    ctx.paths
        .save_deployment(&name, &config_path)
        .map_err(|error| state_error(&error))?;
    // Rules may omit `placeholder:` — persist generated tokens into the
    // stored config and reload so the quadlets and the proxy see them.
    let filled = ctx
        .paths
        .fill_placeholders(&name, None, &mut agentcage_state::mint_placeholder)
        .map_err(|error| state_error(&error))?;
    if filled {
        config = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
            .map_err(|error| state_error(&error))?;
    }

    let mut metadata = vec![("agentcage_version".to_owned(), Json::string(&ctx.version))];
    if let Some(scaffold) =
        agentcage_cli::registry::infer_scaffold_from_image(&config.container.image)
    {
        metadata.push(("scaffold".to_owned(), Json::string(&scaffold)));
    }
    ctx.paths
        .save_metadata(&name, &Json::Object(metadata))
        .map_err(|error| state_error(&error))?;

    // Freeze the Containerfile and its sibling build inputs so a later
    // `cage update` can rebuild without the operator's tree.
    stage_context(&config, &config_path, &ctx.paths.deployment_dir(&name));

    // ── secrets ─────────────────────────────────────────
    if !secrets.is_empty() {
        store_secrets(ctx, &config, &name, &secrets)?;
    }

    // `env:` and `cmd:` sources are materialized into the podman store
    // now, so the quadlet's `Secret=` directives resolve at boot.
    if config.isolation == "container" {
        let host = agentcage_cli::secrets::SecretHost::detect(ctx.runner.as_ref(), &env);
        let skip = std::collections::BTreeSet::new();
        if let Err(error) = host.resolve_and_populate(
            &podman,
            &config,
            &name,
            &ctx.paths.deployment_dir(&name),
            &skip,
            true,
        ) {
            eprintln!("error: {}", error.message());
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }

    let config_host_path = ctx
        .paths
        .save_proxy_config(&name, &ctx.version)
        .map_err(|error| state_error(&error))?;
    ctx.paths
        .save_dns_allowlist(&name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| state_error(&error))?;

    // ── images ──────────────────────────────────────────
    if config.isolation == "container" && !config.container.build.containerfile.is_empty() {
        let phase = agentcage_cli::timing::Phase::start("build.cage", Some(&name));
        let outcome = build_container_image(
            ctx,
            &config,
            config_path.parent().unwrap_or(Path::new(".")),
            no_cache,
            pull,
        );
        drop(phase);
        outcome?;
    }

    if config.isolation == "container" {
        println!("Pulling {}...", config.container.image);
        let phase = agentcage_cli::timing::Phase::start("pull.cage", Some(&name));
        let pulled = podman.pull(&config.container.image).unwrap_or(false);
        drop(phase);
        if !pulled {
            eprintln!(
                "warning: pull failed for {} (local image or no network — \
                 continuing with cached image)",
                config.container.image
            );
        }
    }

    let used_octets = services::collect_used_octets(&ctx.paths, "");
    let backend = ctx.ensure_backend_ready(&config)?;

    let deployed = services::build_and_deploy(
        &backend,
        &ctx.paths,
        &services::DeployPlan {
            config: &config,
            config_host_path: &config_host_path.display().to_string(),
            deploy_name: &name,
            used_octets: Some(&used_octets),
            network_octet: None,
            quiet: false,
            no_cache,
            pull,
        },
    );
    if let Err(error) = deployed {
        // Stop partially-started services but preserve state for
        // debugging: `cage update` is the documented retry.
        //
        // Not on the vm backend, where `stop` powers the Lima guest
        // off. The guest *is* the preserved state: all four recovery
        // commands printed below shell into it, and the units the
        // teardown would stop live inside it and go down with it
        // anyway. Powering it off is the opposite of what this branch
        // says it does.
        if config.isolation != "vm" {
            backend.stop(&name);
        }
        eprintln!("{error}");
        println!();
        eprintln!("Create failed. State preserved for debugging:");
        eprintln!("  Inspect logs:    agentcage cage logs {name}");
        eprintln!(
            "  Inspect quadlets: ls {}/{name}-*",
            backend.unit_dir().display()
        );
        eprintln!("  Retry:           agentcage cage update {name}");
        eprintln!("  Clean up:        agentcage cage destroy {name}");
        if show_timing {
            agentcage_cli::timing::print_summary(&name);
        }
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    println!();
    println!("Logs:");
    println!("  agentcage cage logs {name}");

    if !config.help.is_empty() {
        println!();
        println!("{}", config.help.trim_end());
    }

    if show_timing {
        agentcage_cli::timing::print_summary(&name);
    }
    Ok(())
}

/// `cli.py:845` — reconcile the positional config and `-c/--config`.
///
/// Two parameters for one value, resolved here rather than declared
/// mutually exclusive, because the Python reports its own error for the
/// both-given case and `create ./x.yaml -c ./x.yaml` is allowed when
/// they are the same string.
fn resolve_config_argument(matches: &ArgMatches) -> Result<PathBuf, ExitCode> {
    let positional = matches.get_one::<String>("config_pos");
    let flag = matches.get_one::<String>("config_path");
    if let (Some(positional), Some(flag)) = (positional, flag) {
        if positional != flag {
            eprintln!("error: config given both positionally and with -c; specify it once");
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }
    let Some(path) = flag.or(positional) else {
        eprintln!(
            "error: missing config — pass a path (e.g. `create ./cage.yaml`) \
             or use -c/--config"
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    };
    Ok(PathBuf::from(path))
}

/// CTF F4 — apple-container has an identity `uid_map`, so an rw host bind
/// gives the cage write access to the host at uid 1000.
///
/// Container and vm shift uids through rootless podman's user namespace,
/// so the warning is apple-container's alone.
fn warn_about_rw_host_binds(config: &Config) {
    if config.isolation != "apple-container" || config.container.volumes.is_empty() {
        return;
    }
    let mounts: Vec<&String> = config
        .container
        .volumes
        .iter()
        .filter(|volume| is_rw_host_bind(volume))
        .collect();
    if mounts.is_empty() {
        return;
    }
    eprintln!(
        "warning: apple-container has identity uid_map; rw host bind mounts \
         grant the cage write access to the host filesystem at uid 1000. \
         Affected mounts:"
    );
    for mount in mounts {
        eprintln!("  {mount}");
    }
    eprintln!(
        "  Add ``:ro`` to make these mounts read-only, or run on the \
         ``container`` / ``vm`` backend where rootless podman \
         user-namespace shift isolates the host uid range."
    );
}

/// `cli._is_rw_host_bind`.
///
/// A named volume has no host path — only a `/`- or `~`-rooted source
/// is a bind. The mode suffix exists only for a three-part spec, and
/// anything whose comma-separated options do not include `ro` is
/// writable.
#[must_use]
pub(crate) fn is_rw_host_bind(spec: &str) -> bool {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 {
        return false;
    }
    let source = parts[0];
    if !source.starts_with('/') && !source.starts_with('~') {
        return false;
    }
    let mode = if parts.len() >= 3 {
        parts[parts.len() - 1]
    } else {
        ""
    };
    !mode.split(',').any(|option| option == "ro")
}

/// The port-conflict refusal, shared with `cage update`.
///
/// # Errors
///
/// [`EXIT_FAILURE`] when any published host port is taken.
pub(crate) fn report_port_conflicts(config: &Config) -> Result<(), ExitCode> {
    let conflicts = services::check_port_availability(config);
    if conflicts.is_empty() {
        return Ok(());
    }
    for conflict in &conflicts {
        let container_port = conflict.spec.rsplit(':').next().unwrap_or_default();
        let suggestion = conflict.host_port.parse::<u16>().map_or_else(
            |_| conflict.host_port.clone(),
            |port| services::suggest_alt_port(port).to_string(),
        );
        eprintln!(
            "error: port {} on {} is already in use\n  \
             Another cage or service may be using this port.\n  \
             Change the host port in your cage config, e.g.:\n    \
             ports:\n      \
             - \"{}:{suggestion}:{container_port}\"",
            conflict.host_port, conflict.host_bind, conflict.host_bind
        );
    }
    Err(ExitCode::from(EXIT_FAILURE))
}

/// Freeze the Containerfile's build context into the cage's state dir.
///
/// Shared with `cage update -c`, which does exactly the same thing for
/// exactly the same reason.
pub(crate) fn stage_context(config: &Config, config_path: &Path, state_dir: &Path) {
    let containerfile = &config.container.build.containerfile;
    if containerfile.is_empty() {
        return;
    }
    let source = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(containerfile);
    if !source.is_file() {
        return;
    }
    let context = source.parent().unwrap_or(Path::new("."));
    if let Err(error) = agentcage_cli::staging::stage_build_context(context, state_dir, true) {
        eprintln!("warning: could not stage the build context: {error}");
    }
    // The return value says whether anything was written, which only
    // `cage restore`'s reporting cares about.
    let _ = agentcage_cli::staging::stage_scaffold_assets(&source, state_dir, &config.scaffold);
}

/// `services.build_container_image` plus `cli._build_container_image`'s
/// echo callback.
///
/// `config_dir` is where the `containerfile:` path is resolved from:
/// the config's own directory at create time, the cage's state
/// directory on an update without `-c`.
///
/// # Errors
///
/// [`EXIT_FAILURE`] if the build fails.
pub(crate) fn build_container_image(
    ctx: &Ctx,
    config: &Config,
    config_dir: &Path,
    no_cache: bool,
    pull: bool,
) -> Result<(), ExitCode> {
    let containerfile = agentcage_cli::hostenv::realpath(
        &deploy::resolve_containerfile(&config.container.build.containerfile, config_dir)
            .display()
            .to_string(),
    );
    let context_dir = Path::new(&containerfile)
        .parent()
        .map_or_else(|| ".".to_owned(), |p| p.display().to_string());

    // Point-in-time tag resolution. Scaffold-aware bumping happens
    // earlier in the update path; here only untagged registry refs in a
    // user-provided config are filled in.
    let (resolved_args, changes) = agentcage_cli::registry::resolve_build_args(
        ctx.runner.as_ref(),
        &config.container.build.args,
    );
    for change in &changes {
        println!("Build arg {}: {}", change.key, change.new);
    }

    // The resolved path, not the one they authored: for an existing
    // cage this is the staged copy in the state dir, and editing the
    // original has no effect.
    println!(
        "Building {} from {containerfile}{}...",
        config.container.image,
        if no_cache { " (no-cache)" } else { "" }
    );

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    podman
        .build_image(
            &config.container.image,
            &context_dir,
            &agentcage_exec::tools::podman::BuildOptions {
                containerfile: Some(containerfile),
                cap_add: services::BUILD_CAPS
                    .iter()
                    .map(|c| (*c).to_owned())
                    .collect(),
                no_cache,
                pull,
                build_args: resolved_args,
                quiet: false,
            },
        )
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })
}

/// `--set-secret`, for the container backend.
///
/// `KEY=VALUE` or a bare `KEY`, which prompts. The prompt is
/// `click.prompt(..., hide_input=True)`: a terminal read with echo off.
///
/// The storing itself is [`SecretWriter`], shared with `secret set` —
/// it is `cli._store_secret`, and the two call sites have to agree
/// about which backend takes a value and what happens when it refuses.
///
/// The `KEY=VALUE` form puts a credential in agentcage's own argv and
/// in the operator's shell history. That is pre-existing and
/// deliberately reproduced (see [`agentcage_cli::secrets`]); the bare
/// `KEY` form is the one to reach for, and `secret set` has no other.
fn store_secrets(ctx: &Ctx, config: &Config, name: &str, specs: &[String]) -> Result<(), ExitCode> {
    let env = agentcage_cli::secrets::SystemEnv;
    let writer = crate::cli::secret::set::SecretWriter::new(
        ctx.runner.as_ref(),
        &env,
        config,
        name,
        ctx.paths.deployment_dir(name),
    );

    for spec in specs {
        let (key, value) = if let Some((key, value)) = spec.split_once('=') {
            (key.to_owned(), value.to_owned())
        } else {
            let value = agentcage_cli::terminal::prompt_hidden(&format!("Value for {spec}"))
                .map_err(|error| {
                    eprintln!("error: could not read a value for {spec}: {error}");
                    ExitCode::from(EXIT_FAILURE)
                })?;
            (spec.clone(), value)
        };
        writer.set(&key, &value)?;
    }
    Ok(())
}

fn state_error(error: &agentcage_state::StateError) -> ExitCode {
    eprintln!("error: {error}");
    ExitCode::from(EXIT_FAILURE)
}

#[cfg(test)]
mod tests {
    use super::is_rw_host_bind;

    /// The doctests `cli._is_rw_host_bind` carries, verbatim.
    #[test]
    fn rw_host_binds_are_the_ones_the_python_flags() {
        assert!(is_rw_host_bind("/Users/m1/proj:/workspace"));
        assert!(!is_rw_host_bind("/Users/m1/proj:/workspace:ro"));
        assert!(is_rw_host_bind("/Users/m1/proj:/workspace:rw"));
        assert!(!is_rw_host_bind("agentcage-cache:/cache"));
        assert!(is_rw_host_bind("~/proj:/workspace"));
        assert!(!is_rw_host_bind("/only-one-part"));
        assert!(!is_rw_host_bind("/a:/b:z,ro"));
        assert!(is_rw_host_bind("/a:/b:z,rw"));
    }
}
