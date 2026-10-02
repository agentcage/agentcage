//! Making a just-stored secret take effect — the zero-restart path.
//!
//! `cli._refresh_units` (`cli.py:3890`) and
//! `cli._apply_secret_live_or_restart` (`cli.py:3936`). Both `secret
//! set` and `secret rm` end here, and the two differ only in the value
//! they pass: `rm` passes the empty string, which stages a tombstone.
//!
//! # Why there are two paths and not one
//!
//! The restart path always works and always costs the workload its
//! process state — a long-running agent loses whatever it was doing.
//! The live path costs nothing and works only when the *running* egress
//! container already has the staged-secrets directory mounted. Whether
//! it does is not a property of the unit files (which may have been
//! converged a moment ago without a restart) but of the container, so
//! it is asked of the container.
//!
//! The order inside the live path is load-bearing and is commented at
//! the call: stage first, bump `proxy-config.yaml`'s mtime second. A
//! bump before the write races the addon's mtime poll, which would
//! reload the old file and then never re-trigger.

use agentcage_core::config::Config;

use crate::cli::context::Ctx;
use agentcage_cli::cage_podman::CagePodman;
use agentcage_cli::services;

/// `cli._apply_secret_live_or_restart`.
///
/// An empty `value` is a tombstone (`secret rm`): the injector skips
/// the rule instead of falling back to the stale value frozen in the
/// egress process environment.
///
/// Nothing here can fail the command. A cage that has since been
/// destroyed, a config that no longer loads, a quadlet refresh that
/// throws — each is a reason to do less, not to report that the secret
/// was not stored, because by this point it was.
pub(crate) fn apply_or_restart(ctx: &Ctx, name: &str, key: &str, value: &str) {
    if !ctx.paths.deployment_exists(name) {
        return;
    }
    let Ok(config) = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
    else {
        return;
    };
    // `cfg.name`, not the directory name: a cage's stored config owns
    // the name its units and containers carry.
    let cage = config.name.clone();

    if let Err(error) = refresh_units(ctx, &cage, &config) {
        eprintln!("warning: quadlet refresh failed: {error}");
    }

    let backend = ctx.backend_for(&config.isolation);
    if !backend.is_running(&cage, "cage") {
        // A stopped cage needs nothing beyond the convergence above:
        // the next start re-stages every value from the store.
        return;
    }

    let podman = CagePodman::for_cage(ctx.runner.as_ref(), &config.isolation, &cage);
    if services::cage_has_live_secret_channel(&podman, &cage, &config) {
        match stage(ctx, &podman, &cage, key, value) {
            Ok(()) => {
                println!(
                    "Secret applied to running cage '{cage}' without a restart \
                     (already-running processes keep their current environment; \
                     new connections pick it up immediately)."
                );
                return;
            }
            Err(error) => {
                eprintln!("warning: live secret apply failed ({error}); falling back to restart");
            }
        }
    }
    println!("Restarting cage '{cage}'...");
    restart(ctx, &cage);
}

/// The staged write, then the mtime bump — in that order.
fn stage(
    ctx: &Ctx,
    podman: &CagePodman<'_>,
    cage: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    services::stage_secret_value(podman, ctx.runner.as_ref(), &ctx.paths, cage, key, value)
        .map_err(|error| error.to_string())?;
    // AFTER staging: the addon reloads on the next request when
    // `proxy-config.yaml`'s mtime moves, and it must find the new value
    // already on disk when it does.
    ctx.paths
        .save_proxy_config(cage, &ctx.version)
        .map(|_| ())
        .map_err(|error| error.to_string())?;
    // And on `vm`, one more hop. The proxy inside the guest polls the
    // guest's *copy* of `proxy-config.yaml`, not the host file the line
    // above just touched, so without this push the mtime bump never
    // reaches the addon and the staged value is never read. `cli.py:4400`.
    if podman.is_guest() {
        agentcage_cli::vm::VmBackend::new(&ctx.paths, ctx.runner.as_ref(), &ctx.version)
            .push_config_files(cage)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// `cli._restart_cage` — regenerate the cage.yaml-derived files, then
/// restart and wait.
///
/// The two derived files are rewritten first so an out-of-band edit to
/// `cage.yaml` is picked up: `proxy-config.yaml` is what the proxy
/// reads for allowlist decisions, `dns-allowlist.conf` is what dnsmasq
/// reads through `--servers-file`, and `save_proxy_config` also
/// rewrites `cage-env/placeholders.env`, which the cage quadlet names
/// as `EnvironmentFile=` and podman re-reads at container creation —
/// so a placeholder change applies on a plain restart, with no quadlet
/// regeneration.
///
/// On apple-container neither of those two files drives anything; that
/// backend's derived artifact is the unit metadata, and
/// [`reinstall_apple_units`] is the step that regenerates it.
pub(crate) fn restart(ctx: &Ctx, cage: &str) {
    if let Err(error) = ctx.paths.save_proxy_config(cage, &ctx.version) {
        eprintln!("warning: {error}");
    }
    if let Err(error) = ctx
        .paths
        .save_dns_allowlist(cage, &agentcage_cli::hostenv::RealHost)
    {
        eprintln!("warning: {error}");
    }
    // `backend_of` loads the config and throws it away; the apple step
    // below needs it, so it is loaded once here and the backend built
    // from it. A config that will not load still falls back to the
    // container backend, which is `get_backend`'s own default and what
    // keeps `cage destroy` working on an unparseable `cage.yaml`.
    let config = ctx
        .paths
        .load_deployment_config(cage, &agentcage_cli::hostenv::RealHost)
        .ok();
    let backend = ctx.backend_for(
        config
            .as_ref()
            .map_or("container", |config| config.isolation.as_str()),
    );
    if let (Some(config), Some(_)) = (config.as_ref(), backend.as_apple()) {
        reinstall_apple_units(&backend, config, cage);
    }
    services::restart_cage(&backend, cage);
}

/// `cli._reinstall_apple_units` — regenerate the apple-container unit
/// metadata from the stored `cage.yaml`, before the cage comes back up.
///
/// That metadata (`~/.config/agentcage/apple-container/<name>.json`) is
/// the argv recipe `AppleBackend::start` reads, and it is a *derived*
/// artifact only create/update/import ever wrote — the restart path
/// never regenerated it. Doing it here gives apple-container the same
/// "edits made while stopped take effect on next start" reconcile the
/// container path gets from `save_proxy_config` / `save_dns_allowlist`,
/// and self-heals a missing metadata file (registry and image intact)
/// instead of hard-failing in `start()`, which used to point the
/// operator at `cage create` — a command that refuses on an existing
/// cage.
///
/// It is what makes `secret set --declare` work on this backend at
/// all. A declared rule's name and placeholder reach `stage_secrets`
/// and the cage's `-e NAME={{NAME}}` *only* through this snapshot
/// (`apple::units` builds `secret_envs` and
/// `secret_env_placeholders` from `config.secret_injection`), so
/// without the regeneration the rule would sit in `cage.yaml` and
/// nowhere else. Same for a rotated placeholder.
///
/// `config_host_path` and `patches_host_dir` are the quadlet path's
/// arguments and this backend ignores them — it bakes absolute paths
/// at create time — so they are passed empty, as the Python passes
/// `""`. The octet arguments are the container backend's shared
/// `10.89.x` pool, which Apple's per-cage auto-allocated subnets have
/// no equivalent of.
///
/// A failure is a warning, not a refusal: `restart` has no error
/// channel and its two file writes above already report this way. The
/// Python lets the exception propagate into a traceback.
fn reinstall_apple_units(
    backend: &agentcage_cli::backends::AnyBackend<'_>,
    config: &Config,
    cage: &str,
) {
    match backend.generate_units(config, "", "", cage, None, None) {
        Ok(units) => {
            for warning in &units.warnings {
                eprint!("{warning}");
            }
            if let Err(error) = backend.install_units(&units, true) {
                eprintln!("warning: apple-container unit metadata not reinstalled: {error}");
            }
        }
        Err(error) => {
            eprintln!("warning: apple-container unit metadata not regenerated: {error}");
        }
    }
}

/// `cli._refresh_units` — converge the quadlets with stored state, with
/// no restart and no work when nothing changed.
///
/// The point is convergence: a secret declared or removed a moment ago
/// needs its `Secret=` / staging lines in the unit files so that *any*
/// future boot — systemd crash recovery, the fallback restart above —
/// comes up consistent with `cage.yaml`. Image builds are skipped
/// (quadlets reference images by name) and the network octet is pinned
/// from metadata exactly as `cage update` pins it, so regenerated
/// static IPs stay inside the existing podman network.
///
/// `install_units` — and the global `systemctl --user daemon-reload`
/// inside it — runs **only** when the regenerated content differs from
/// what is installed. `secret set` for an already-declared secret
/// changes no unit file, so the common path does zero daemon-reloads,
/// which also avoids racing a concurrent `cage create`'s
/// daemon-reload on the same user systemd instance. e2e phases 3, 5
/// and 6 run in parallel and would otherwise collide.
pub(crate) fn refresh_units(ctx: &Ctx, cage: &str, config: &Config) -> Result<(), String> {
    // apple-container is excluded in the Python because its
    // `generate_units` output is a metadata snapshot tied to the build
    // pipeline; `vm` is included there and excluded here only because
    // its backend is Track E.
    if config.isolation != "container" {
        return Ok(());
    }
    let backend = ctx.backend();
    let octet =
        ctx.paths
            .load_metadata(cage)
            .ok()
            .and_then(|meta| match meta.get("network_octet") {
                Some(&agentcage_core::har::json::Json::Int(octet)) => u32::try_from(octet).ok(),
                _ => None,
            });
    let config_host_path = ctx
        .paths
        .save_proxy_config(cage, &ctx.version)
        .map_err(|error| error.to_string())?;
    let patches =
        agentcage_cli::backend::patches_work_dir(&ctx.paths).map_err(|error| error.to_string())?;
    let used = services::collect_used_octets(&ctx.paths, cage);
    let units = backend
        .generate_units(
            config,
            &config_host_path.display().to_string(),
            &patches.display().to_string(),
            cage,
            Some(&used),
            octet,
        )
        .map_err(|error| error.to_string())?;
    for warning in &units.warnings {
        eprint!("{warning}");
    }
    if units
        .files
        .iter()
        .all(|(filename, content)| installed_matches(ctx, filename, content))
    {
        return Ok(());
    }
    backend
        .install_units(&units, true)
        .map_err(|error| error.to_string())
}

/// `cli._installed_unit_matches` — is `filename` already on disk with
/// exactly this content?
///
/// Two candidate locations, both under the quadlet directory: the file
/// itself, and a `quadlets/` subdirectory some installations use.
///
/// A divergence worth naming, because it is the Python's and is
/// reproduced rather than fixed: `install_units` writes a plain
/// `.service` unit to the *systemd user* directory, and this looks for
/// it in the quadlet directory, so such a unit never matches and forces
/// a reinstall. The container backend emits no `.service` units today —
/// the one it used to emit, the grants watcher, is what
/// `legacy_watcher` removes — so the branch is unreachable in practice.
/// Correcting it here would make this the one place in the port that
/// decides where a unit lives, which is `agentcage_state::Units`'s job.
fn installed_matches(ctx: &Ctx, filename: &str, content: &str) -> bool {
    let dir = ctx.paths.quadlet_dir();
    [dir.join(filename), dir.join("quadlets").join(filename)]
        .iter()
        .any(|candidate| {
            candidate.is_file()
                && std::fs::read_to_string(candidate).is_ok_and(|on_disk| on_disk == content)
        })
}
