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
use agentcage_core::fingerprint::{fingerprint_matches, only_images_differ};
use agentcage_core::har::json::Json;
use clap::ArgMatches;

use crate::cli::cage::create::{build_container_image, report_port_conflicts, stage_context};
use crate::cli::context::{
    Ctx, EXIT_FAILURE, ensure_v022_cage, load_and_validate, load_stored_and_validate,
};
use agentcage_cli::backends::AnyBackend;
use agentcage_cli::base_images::{self, BaseStatus, ImageStore};
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
    // `--no-pull` and `--pull` are refused together by the parser.
    let no_pull = matches.get_flag("no_pull");

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

    // Custom inspector plugins: restaged from the new cage.yaml's
    // directory with `-c`; otherwise the staged copy is the cage's, and
    // every plugin the stored config names has to be in it.
    let staged = match config_path.as_deref() {
        Some(path) => ctx.paths.stage_inspector_plugins(
            &name,
            &config,
            path.parent().unwrap_or(Path::new(".")),
        ),
        None => ctx.paths.check_inspector_plugins_staged(&name, &config),
    };
    staged.map_err(|error| state_error(&error))?;

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
            // The pull-then-inspect refresh is apple-container's only
            // way to see a moved upstream image; the other two backends
            // ask the registry for a digest instead (`base_images`),
            // which pulls nothing.
            refresh_images: !no_pull && matches!(backend, AnyBackend::Apple(_)),
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
    // Only an image identity moved (another cage's update rebuilt the
    // shared egress, a base was pulled): the cage's own inputs are what
    // they were.
    let images_only = !unchanged
        && stored
            .as_ref()
            .is_some_and(|stored| only_images_differ(stored, &computed.fingerprint));
    // Running, and inputs unchanged but for image identities: the only
    // reasons left to rebuild are those images, a moved base, or
    // `--pull` / `--no-cache`, and they restart only when the rebuilt
    // image differs from the one the cage runs.
    let refreshable = !matches!(backend, AnyBackend::Apple(_));
    if !force && running && unchanged && !refreshable && !(no_cache || pull) {
        println!("cage '{name}' already up to date (use --force to rebuild anyway)");
        return Ok(());
    }
    let mut prebuilt = false;
    if !force && running && (unchanged || images_only) && refreshable {
        let request = RefreshRequest {
            config: &config,
            name: &name,
            config_dir: config_path.as_deref().and_then(Path::parent),
            no_cache,
            pull,
            trigger: if images_only {
                Trigger::ImagesMoved
            } else if no_pull {
                Trigger::NoPull
            } else {
                Trigger::CheckRegistry
            },
        };
        match refresh(ctx, &backend, &request)? {
            Refreshed::Nothing => {
                println!("cage '{name}' already up to date (use --force to rebuild anyway)");
                return Ok(());
            }
            Refreshed::Unchanged => {
                println!("Image unchanged; not restarting");
                // The rebuild moved the local base and image
                // identities the fingerprint covers; record them, or
                // the next update would see "changed inputs" and
                // restart for nothing.
                deploy::record_fingerprint(
                    &backend,
                    &ctx.paths,
                    deploy::FingerprintRequest {
                        config: &config,
                        name: &name,
                        config_host_path: &config_host_path.display().to_string(),
                        network_octet: existing_octet,
                        refresh_images: false,
                        units: Some(computed.units),
                    },
                )
                .map_err(|error| backend_error(&error))?;
                println!("cage '{name}' up to date");
                return Ok(());
            }
            Refreshed::Changed => prebuilt = true,
        }
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

    if !prebuilt
        && config.isolation == "container"
        && !config.container.build.containerfile.is_empty()
    {
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
    deploy::record_fingerprint(
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
    println!("Updated cage '{name}'");

    if !config.help.is_empty() {
        println!();
        println!("{}", config.help.trim_end());
    }
    Ok(())
}

/// What [`refresh`] needs besides the context and the backend.
struct RefreshRequest<'a> {
    config: &'a Config,
    name: &'a str,
    /// The `-c` config's directory, when one was given.
    config_dir: Option<&'a Path>,
    no_cache: bool,
    pull: bool,
    /// What, besides the flags above, decides whether to rebuild.
    trigger: Trigger,
}

/// Why [`refresh`] would rebuild when neither `--pull` nor `--no-cache`
/// asks it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// Ask the registry whether a base moved.
    CheckRegistry,
    /// `--no-pull`: do not ask; nothing moved as far as this run knows.
    NoPull,
    /// The fingerprint's image identities moved and nothing else did:
    /// rebuild both images, without asking the registry.
    ImagesMoved,
}

/// How a refresh of a running, unchanged cage ended.
#[derive(Debug, PartialEq, Eq)]
enum Refreshed {
    /// No base moved and no flag asked for a rebuild: nothing was built.
    Nothing,
    /// Something was rebuilt, and every running container already runs
    /// the image its tag now names.
    Unchanged,
    /// A container runs an image its tag no longer names: restart.
    Changed,
}

/// Rebuild what a moved base (or `--pull` / `--no-cache`, or a moved
/// image identity) asks for, while the cage keeps running, and say
/// whether it has to restart.
///
/// Container and vm backends only. The registry check runs unless
/// `--no-pull`, or `--pull` / `--no-cache` already force both builds.
/// The builds keep `--pull=newer`, so a moved base is pulled by the
/// build that needs it. The restart decision compares, per service,
/// the image the running container was started from with the image its
/// tag names after the build: the units name images by tag, and a tag
/// that now names a different image is exactly what a restart picks up.
fn refresh(
    ctx: &Ctx,
    backend: &AnyBackend<'_>,
    request: &RefreshRequest<'_>,
) -> Result<Refreshed, ExitCode> {
    let &RefreshRequest {
        config,
        name,
        config_dir,
        no_cache,
        pull,
        trigger,
    } = request;
    let vm_podman;
    let store: &dyn ImageStore = match backend {
        AnyBackend::Container(backend) => backend.podman(),
        AnyBackend::Vm(backend) => {
            vm_podman = backend.podman(name);
            &vm_podman
        }
        AnyBackend::Apple(_) => return Ok(Refreshed::Nothing),
    };
    let state_dir = ctx.paths.deployment_dir(name);
    let built_from_containerfile = !config.container.build.containerfile.is_empty();
    let cage_action = if built_from_containerfile {
        "rebuilding the cage image"
    } else {
        "re-pulling the cage image"
    };

    let forced = no_cache || pull || trigger == Trigger::ImagesMoved;
    let (mut egress, mut cage) = (forced, forced);
    if forced {
        let why = if pull {
            "--pull"
        } else if no_cache {
            "--no-cache"
        } else {
            "an image this cage uses changed since the last update"
        };
        println!("Rebuilding images ({why})...");
    } else if trigger == Trigger::CheckRegistry {
        (egress, cage) = moved_bases(store, config, &state_dir, cage_action);
    }
    if !(egress || cage) {
        return Ok(Refreshed::Nothing);
    }

    match backend {
        AnyBackend::Container(container) => {
            if egress {
                container
                    .build_artifacts(no_cache, pull, false)
                    .map_err(|error| backend_error(&error))?;
            }
            if cage && built_from_containerfile {
                let config_dir = config_dir.map_or_else(|| state_dir.clone(), Path::to_path_buf);
                build_container_image(ctx, config, &config_dir, no_cache, pull)?;
            } else if cage && (pull || (!forced && trigger == Trigger::CheckRegistry)) {
                // A registry image, not a build: re-pull it when the
                // registry has a newer one or `--pull` says so. (When
                // only its local identity moved, the tag already names
                // the new image.) A failed pull leaves the running image
                // in place, and the comparison below then finds nothing
                // to restart for.
                println!("Pulling {}...", config.container.image);
                let _ = container.podman().pull(&config.container.image);
            }
        }
        // The vm backend builds the egress and the cage image together,
        // inside the guest, and pulls a registry image the same way.
        AnyBackend::Vm(_) => backend
            .build_artifacts(Some(config), name, no_cache, pull, false)
            .map_err(|error| backend_error(&error))?,
        AnyBackend::Apple(_) => unreachable!("returned above"),
    }

    let mut changed = Vec::new();
    for (service, image) in [
        ("egress", backend.egress_image()),
        ("cage", config.container.image.clone()),
    ] {
        let running = base_images::running_image(store, &format!("{name}-{service}"));
        let current = base_images::current_image(store, &image);
        if base_images::image_changed(running.as_deref(), current.as_deref()) {
            changed.push(service);
        }
    }
    if changed.is_empty() {
        return Ok(Refreshed::Unchanged);
    }
    println!(
        "{} image changed; restarting cage '{name}'",
        changed.join(" and ")
    );
    Ok(Refreshed::Changed)
}

/// Ask the registry about the egress's and the cage image's bases.
///
/// Returns whether each needs rebuilding, having said why; a check that
/// could not run is one warning and counts as unchanged.
fn moved_bases(
    store: &dyn ImageStore,
    config: &Config,
    state_dir: &Path,
    cage_action: &str,
) -> (bool, bool) {
    println!("Checking base images for updates...");
    let mut failure = None;
    let mut moved = [false, false];
    for ((action, refs), flag) in [
        ("rebuilding egress", base_images::egress_base_refs()),
        (cage_action, base_images::cage_base_refs(config, state_dir)),
    ]
    .into_iter()
    .zip(&mut moved)
    {
        let checked = base_images::check(store, &refs);
        for (reference, status) in &checked.changed {
            match status {
                BaseStatus::NotLocal => {
                    println!("base {reference} is not in the local image store; {action}");
                }
                _ => println!("base {reference} has a newer image; {action}"),
            }
        }
        *flag = !checked.changed.is_empty();
        if failure.is_none() {
            failure = checked.failure;
        }
    }
    if let Some(failure) = failure {
        eprintln!(
            "warning: could not check base images for updates ({failure}); \
             treating them as unchanged (--no-pull skips this check)"
        );
    }
    (moved[0], moved[1])
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

#[cfg(test)]
mod tests {
    use agentcage_cli::backend::ContainerBackend;
    use agentcage_cli::backends::AnyBackend;
    use agentcage_core::config::Config;
    use agentcage_exec::{Elevation, FakeRunner, Reply};
    use agentcage_state::{Paths, TestDir};
    use serde_json::json;

    use super::{RefreshRequest, Refreshed, Trigger, refresh};
    use crate::cli::context::Ctx;

    const EGRESS_BASE: &str = "docker.io/library/alpine:3";
    const IMAGE: &str = "docker.io/library/node:22-slim";

    fn config() -> Config {
        let mut config = Config {
            name: "t".to_owned(),
            ..Config::default()
        };
        config.container.image = IMAGE.to_owned();
        config
    }

    fn local(digest: &str, id: &str) -> Reply {
        Reply::ok(
            json!([{
                "Id": id,
                "Digest": digest,
                "RepoDigests": [format!("x@{digest}")],
                "Os": "linux",
                "Architecture": "amd64",
            }])
            .to_string(),
        )
    }

    fn remote(digest: &str) -> Reply {
        Reply::ok(
            json!({"manifests": [
                {"digest": digest, "platform": {"os": "linux", "architecture": "amd64"}}
            ]})
            .to_string(),
        )
    }

    fn container(image: &str) -> Reply {
        Reply::ok(json!([{"Image": image}]).to_string())
    }

    /// Run `refresh` for a container cage against `fake`.
    fn run(fake: &FakeRunner, flags: (bool, bool, bool)) -> Refreshed {
        let (no_cache, pull, no_pull) = flags;
        let trigger = if no_pull {
            Trigger::NoPull
        } else {
            Trigger::CheckRegistry
        };
        run_with(fake, no_cache, pull, trigger)
    }

    fn run_with(fake: &FakeRunner, no_cache: bool, pull: bool, trigger: Trigger) -> Refreshed {
        let dir = TestDir::new("update-refresh");
        let ctx = Ctx {
            paths: Paths::under(dir.join("home")),
            runner: Box::new(fake.clone()),
            version: "9.9.9".to_owned(),
        };
        let backend = AnyBackend::Container(ContainerBackend::with_elevation(
            &ctx.paths,
            ctx.runner.as_ref(),
            &ctx.version,
            Elevation::none(),
        ));
        let config = config();
        refresh(
            &ctx,
            &backend,
            &RefreshRequest {
                config: &config,
                name: "t",
                config_dir: None,
                no_cache,
                pull,
                trigger,
            },
        )
        .unwrap_or_else(|_| panic!("refresh failed"))
    }

    #[test]
    fn no_pull_asks_nothing_and_builds_nothing() {
        let fake = FakeRunner::new();
        assert_eq!(run(&fake, (false, false, true)), Refreshed::Nothing);
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn unmoved_bases_are_a_no_op() {
        let fake = FakeRunner::new();
        fake.on(
            ["podman", "image", "inspect", EGRESS_BASE],
            local("sha256:e", "e1"),
        )
        .on(
            ["podman", "manifest", "inspect", EGRESS_BASE],
            remote("sha256:e"),
        )
        .on(
            ["podman", "image", "inspect", IMAGE],
            local("sha256:n", "n1"),
        )
        .on(["podman", "manifest", "inspect", IMAGE], remote("sha256:n"));
        assert_eq!(run(&fake, (false, false, false)), Refreshed::Nothing);
        assert_eq!(fake.call_count(), 4, "{:?}", fake.argv_sequence());
    }

    /// An unreachable registry is "unchanged", not a failure.
    #[test]
    fn an_unreachable_registry_is_treated_as_unchanged() {
        let fake = FakeRunner::new();
        fake.on(
            ["podman", "manifest", "inspect"],
            Reply::failed(125, "Error: proxyconnect tcp: connection refused"),
        )
        .on(["podman", "image", "inspect"], local("sha256:n", "n1"));
        assert_eq!(run(&fake, (false, false, false)), Refreshed::Nothing);
    }

    /// A moved registry image is re-pulled; whether the cage restarts
    /// depends only on whether the running container's image is the
    /// one the tag names afterwards.
    #[test]
    fn a_moved_image_is_pulled_and_restarts_only_if_the_id_changed() {
        for (pulled_id, expected) in [("n1", Refreshed::Unchanged), ("n2", Refreshed::Changed)] {
            let fake = FakeRunner::new();
            fake.on(
                ["podman", "image", "inspect", EGRESS_BASE],
                local("sha256:e", "e1"),
            )
            .on(
                ["podman", "manifest", "inspect", EGRESS_BASE],
                remote("sha256:e"),
            )
            .on(
                ["podman", "manifest", "inspect", IMAGE],
                remote("sha256:new"),
            )
            .on(["podman", "pull", IMAGE], Reply::status(0))
            .on(["podman", "inspect", "t-egress"], container("e-img"))
            .on(["podman", "inspect", "t-cage"], container("n1"))
            .on(
                ["podman", "image", "inspect", IMAGE],
                local("sha256:n", pulled_id),
            )
            // The egress tag: its hash depends on which binary the
            // test process staged, so matched last and by prefix.
            .on(["podman", "image", "inspect"], local("sha256:x", "e-img"));
            assert_eq!(run(&fake, (false, false, false)), expected, "{pulled_id}");
            assert!(
                fake.argv_sequence()
                    .contains(&vec!["podman".into(), "pull".into(), IMAGE.into()]),
                "{:?}",
                fake.argv_sequence()
            );
        }
    }

    /// `--pull` skips the check and refreshes; an egress or cage
    /// container that cannot be inspected restarts.
    #[test]
    fn pull_skips_the_check_and_an_uninspectable_container_restarts() {
        let fake = FakeRunner::new();
        // `--pull` rebuilds the egress too; stub the build.
        agentcage_cli::egress_image::provide_binary_for_tests(b"egress");
        fake.on(["podman", "build"], Reply::status(0))
            .on(["podman", "pull", IMAGE], Reply::status(0))
            .on(
                ["podman", "inspect", "t-egress"],
                Reply::failed(125, "no such container"),
            )
            .on(["podman", "image", "inspect"], local("sha256:x", "id"))
            .on(["podman", "inspect", "t-cage"], container("id"));
        assert_eq!(run(&fake, (false, true, false)), Refreshed::Changed);
        assert!(
            !fake
                .argv_sequence()
                .iter()
                .any(|argv| argv.get(1).is_some_and(|verb| verb == "manifest")),
            "--pull must not run the registry check"
        );
    }

    /// Only image identities moved in the fingerprint (say, another
    /// cage's update rebuilt the shared egress): both images are
    /// refreshed without a registry check, and the cage restarts only
    /// if a container runs an image its tag no longer names.
    #[test]
    fn moved_image_identities_rebuild_without_a_check() {
        agentcage_cli::egress_image::provide_binary_for_tests(b"egress");
        for (egress_running, expected) in [
            ("e-new", Refreshed::Unchanged),
            ("e-old", Refreshed::Changed),
        ] {
            let fake = FakeRunner::new();
            fake.on(["podman", "build"], Reply::status(0))
                .on(["podman", "pull", IMAGE], Reply::status(0))
                .on(["podman", "inspect", "t-egress"], container(egress_running))
                .on(["podman", "inspect", "t-cage"], container("n1"))
                .on(
                    ["podman", "image", "inspect", IMAGE],
                    local("sha256:n", "n1"),
                )
                .on(["podman", "image", "inspect"], local("sha256:x", "e-new"));
            assert_eq!(
                run_with(&fake, false, false, Trigger::ImagesMoved),
                expected
            );
            let argv = fake.argv_sequence();
            assert!(
                !argv
                    .iter()
                    .any(|a| a.get(1).is_some_and(|verb| verb == "manifest")),
                "{argv:?}"
            );
            assert!(
                argv.iter()
                    .any(|a| a.get(1).is_some_and(|verb| verb == "build"))
            );
            // The local tag already moved; nothing to fetch.
            assert!(
                !argv
                    .iter()
                    .any(|a| a.get(1).is_some_and(|verb| verb == "pull")),
                "{argv:?}"
            );
        }
    }
}
