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
//! 1. **Secrets first**, into the podman store, because the build that
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
//! # What is not here
//!
//! The `vm` and `apple-container` branches. `_podman_for_cage` routes a
//! running vm cage's secret and volume calls through `VmPodman` inside
//! the Lima guest, and `_cage_backup_apple_container` is a different
//! archive shape entirely (no secret values, an `audit/` member,
//! `named_volumes` always empty). Both are Track E, and both are
//! refused here with the same message every other ported command uses
//! rather than being half-served by the container path.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentcage_core::config::Config;
use agentcage_core::har::datetime::DateTime;
use agentcage_core::har::json::{DumpOptions, Json, dumps, parse as parse_json};
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};
use agentcage_cli::archive::{self, Member};
use agentcage_cli::scaffold::TempDir;
use agentcage_cli::services;

/// The top-level directory every member lives under.
const ROOT: &str = "agentcage-backup";

/// The one format version this agentcage writes and the highest it
/// reads. `cli.py:3491` refuses anything greater and accepts anything
/// less, including the `0` a manifest with no such key reads as.
const FORMAT_VERSION: i64 = 1;

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
    require_container_backend(&config, "cage backup")?;

    let output = matches.get_one::<String>("output").map_or_else(
        || PathBuf::from(format!("{name}-backup-{}.tar.gz", file_timestamp())),
        PathBuf::from,
    );

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let mut members: Vec<Member> = Vec::new();

    // ── Config ──────────────────────────────────────────
    //
    // Three files, and only the ones that exist: a cage created before
    // `save_proxy_config` ran has no `proxy-config.yaml`, and
    // `metadata.json` is missing on a cage whose create failed partway.
    for (file, source) in [
        ("cage.yaml", ctx.paths.stored_config_path(&name)),
        ("metadata.json", ctx.paths.metadata_path(&name)),
        ("proxy-config.yaml", ctx.paths.proxy_config_path(&name)),
    ] {
        if source.is_file() {
            members.push(Member::FileFrom(format!("{ROOT}/config/{file}"), source));
        }
    }
    members.push(Member::Dir(format!("{ROOT}/config")));

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
    if manifest.isolation == "apple-container" {
        eprintln!(
            "error: restoring an 'apple-container' backup is not ported yet \
             (RUST-PORT-PLAN.md Track E)"
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

    // ── Extract ─────────────────────────────────────────
    //
    // Into a 0700 directory: a `--include-secrets` backup holds bare
    // credentials, and `$TMPDIR` is usually world-traversable.
    let staging = TempDir::new("agentcage-restore-").map_err(|error| {
        eprintln!("error: could not create a staging directory: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    if let Err(error) = archive::extract_into(&tarball, staging.path()) {
        eprintln!("error: invalid backup — {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    let backup_dir = staging.path().join(ROOT);

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
        Manifest, backup_inner, file_timestamp, is_valid_cage_name, restore_capture,
        restore_config, restore_secrets,
    };
    use crate::cli::context::Ctx;
    use agentcage_cli::archive;
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
