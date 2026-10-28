//! `agentcage run SCAFFOLD [EXTRA_ARGS]...` — the ephemeral-cage flow.
//!
//! # Two names, one command
//!
//! `cli.py` declares `run` as a free-standing `@click.command`, adds it
//! to the `cage` group as `cage run` (`cli.py:820`), and surfaces it at
//! the top level through `_BannerGroup._global_aliases` — which is why
//! `agentcage run` works although the root's command listing never
//! mentions it. [`command`] is called twice for the same reason, and
//! [`crate::cli::TOP_LEVEL_ALIASES`] records that `run` at the root
//! means `cage run`.
//!
//! # The passthrough
//!
//! `context_settings={"ignore_unknown_options": True}` plus a
//! `nargs=-1, type=click.UNPROCESSED` trailing argument. What it buys:
//! `agentcage run codex -- codex --version` hands `codex --version` to
//! the workload instead of rejecting `--version`, and
//! `agentcage run claude-code --verbose -- --not-a-flag` still reads
//! `--verbose` as this command's own flag.
//!
//! clap reproduces that with **`allow_hyphen_values` on the trailing
//! positional, and deliberately not `trailing_var_arg`.** The difference
//! matters. `trailing_var_arg` stops parsing at the first positional, so
//! `run claude-code --verbose -- x` would hand `--verbose` to the
//! workload — which is what click does *not* do: click keeps matching
//! its own declared options wherever they appear and only passes the
//! ones it does not recognise. `allow_hyphen_values` has exactly that
//! behaviour, verified in `tests/passthrough.rs` against the recorded
//! click parses in `tests/fixtures/cli-surface/parse-cases.json`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use agentcage_core::config::Config;
use agentcage_core::har::json::Json;
use clap::{Arg, ArgMatches, Command};

use crate::cli::context::{Ctx, load_and_validate};

use crate::cli::args::{ISOLATIONS, PATH, TEXT, flag, leaf, multi_opt, value_opt};

/// The `run` docstring, verbatim from `cli.py:766`.
///
/// click's `\x08` no-rewrap markers before the two blocks are dropped:
/// they are formatter instructions, not text, and clap has no equivalent.
const RUN_LONG: &str = "\
Run a coding agent in a sandboxed cage.

Examples:
  agentcage run claude-code -s ANTHROPIC_API_KEY
  agentcage run codex --project /path/to/repo -s OPENAI_API_KEY=sk-...
  agentcage run claude-code --isolation vm -s ANTHROPIC_API_KEY
  agentcage run claude-code --no-cache --pull -s ANTHROPIC_API_KEY
  agentcage run codex --name my-session -s OPENAI_API_KEY -- codex --help

Secrets: every secret a scaffold declares is required. `run` aborts
before starting the cage if one is missing — supply it with `-s KEY`
(prompts) / `-s KEY=VALUE`, or via a configured `source:`. A scaffold
that lists alternative credentials under `auth:` needs only one of them:
the one given with `-s`, else one the scaffold allows from the
environment (claude-code: an exported CLAUDE_CODE_OAUTH_TOKEN from
`claude setup-token`), which is stored like `-s` and never enters the
cage. `--no-cache`/`--pull` force a clean rebuild (ignore the layer cache
/ re-pull the base image) across every isolation backend — container,
vm, and apple-container alike.";

/// Build the `run` command. Registered twice: as `cage run`, and hidden
/// at the root.
pub(crate) fn command() -> Command {
    leaf("run")
        .about("Run a coding agent in a sandboxed cage.")
        .long_about(RUN_LONG)
        .arg(Arg::new("scaffold").required(true).value_name("SCAFFOLD"))
        .arg(value_opt(
            "project_dir",
            "project",
            PATH,
            "Project directory to mount (default: current directory).",
        ))
        .arg(value_opt(
            "name",
            "name",
            TEXT,
            "Cage name (default: auto-generated).",
        ))
        .arg(
            multi_opt(
                "secrets",
                "set-secret",
                TEXT,
                "Set a secret (KEY=VALUE or KEY to prompt). Repeatable.",
            )
            .short('s'),
        )
        .arg(flag("verbose", "verbose", "Show full build output.").short('v'))
        .arg(
            value_opt(
                "isolation",
                "isolation",
                "[container|vm|apple-container]",
                "Isolation backend (default: auto-detect from platform).",
            )
            .value_parser(ISOLATIONS),
        )
        .arg(flag(
            "as_root",
            "as-root",
            "Run the session as root (uid 0) instead of the workload's uid 1000 user (debug only).",
        ))
        .arg(flag(
            "show_timing",
            "time",
            "Echo per-phase wall times and print a summary on completion.",
        ))
        .arg(flag(
            "no_cache",
            "no-cache",
            "Force a full image rebuild (ignore podman's layer cache).",
        ))
        .arg(flag(
            "pull",
            "pull",
            "Force re-pull of the base image from the registry.",
        ))
        .arg(flag(
            "rm",
            "rm",
            "Destroy the cage and its scoped resources after the session. The cage's audit data directory is kept.",
        ))
        .arg(
            flag(
                "keep",
                "keep",
                "Keep the stopped cage, its volumes and secrets after the session (default).",
            )
            .conflicts_with("rm"),
        )
        .arg(flag(
            "dry_run",
            "dry-run",
            "Render and validate the config, print the plan, and exit without changing anything.",
        ))
        .arg(
            Arg::new("extra_args")
                .num_args(0..)
                .value_name("EXTRA_ARGS")
                .allow_hyphen_values(true),
        )
}

// ── the body ─────────────────────────────────────────────────

/// `run.execute`, and `cli.run`'s thin wrapper around it.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    if matches.get_flag("show_timing") {
        agentcage_cli::timing::enable_echo();
    }
    let extra_args: Vec<String> = matches
        .get_many::<String>("extra_args")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();
    let secrets: Vec<String> = matches
        .get_many::<String>("secrets")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();
    let options = Options {
        scaffold: matches
            .get_one::<String>("scaffold")
            .cloned()
            .unwrap_or_default(),
        project_dir: matches.get_one::<String>("project_dir").cloned(),
        name: matches.get_one::<String>("name").cloned(),
        secrets,
        extra_args,
        verbose: matches.get_flag("verbose"),
        isolation: matches.get_one::<String>("isolation").cloned(),
        as_root: matches.get_flag("as_root"),
        show_timing: matches.get_flag("show_timing"),
        no_cache: matches.get_flag("no_cache"),
        pull: matches.get_flag("pull"),
        remove: matches.get_flag("rm"),
        dry_run: matches.get_flag("dry_run"),
    };
    // The session's own status is this process's status, which is
    // what makes
    // `agentcage run codex -- codex --version` usable in a script.
    ExitCode::from(u8::try_from(execute(ctx, &options)).unwrap_or(1))
}

/// Everything `run` was given.
///
/// Five `bool`s, which clippy would rather were an enum. They are five
/// independent switches on one command line, not a state machine —
/// `--verbose --no-cache --pull --as-root --time` is a legal and
/// meaningful combination of all of them — so the flat struct is the
/// honest shape, and it is the one `cli.py`'s signature has.
#[expect(clippy::struct_excessive_bools, reason = "five independent CLI flags")]
#[derive(Clone)]
struct Options {
    scaffold: String,
    project_dir: Option<String>,
    name: Option<String>,
    secrets: Vec<String>,
    extra_args: Vec<String>,
    verbose: bool,
    isolation: Option<String>,
    as_root: bool,
    show_timing: bool,
    no_cache: bool,
    pull: bool,
    remove: bool,
    dry_run: bool,
}

#[expect(
    clippy::too_many_lines,
    reason = "one body, matching `run.execute`. The order is the \
              contract — secrets before the filesystem, state before \
              the build, the session between the deploy and the stop — \
              and every step reads what the previous one wrote."
)]
fn execute(ctx: &Ctx, options: &Options) -> i32 {
    use agentcage_cli::output;
    use agentcage_cli::run as flow;

    let Ok(scaffolds) = agentcage_cli::scaffold::Scaffolds::system(ctx.runner.as_ref()) else {
        output::step_fail("Could not unpack the bundled scaffolds");
        return 1;
    };

    // A scaffold may publish alternative names in its own scaffold.yaml;
    // agentcage core has no table of them.
    let aliases = scaffolds.aliases();
    let scaffold = aliases
        .get(&options.scaffold)
        .cloned()
        .unwrap_or_else(|| options.scaffold.clone());

    let available = scaffolds.list();
    if !available.contains(&scaffold) {
        output::step_fail(&format!(
            "Unknown scaffold '{scaffold}'. Available: {}",
            available.join(", ")
        ));
        return 1;
    }

    let project_dir = match options.project_dir.clone() {
        Some(dir) => {
            // click's `type=click.Path(exists=True)`.
            if !Path::new(&dir).exists() {
                eprintln!("Error: Invalid value for '--project': Path '{dir}' does not exist.");
                return 2;
            }
            dir
        }
        None => {
            std::env::current_dir().map_or_else(|_| ".".to_owned(), |dir| dir.display().to_string())
        }
    };
    let project_dir = abspath(&project_dir);

    let quadlet_host = agentcage_cli::hostenv::RealQuadletHost::new(ctx.paths.data_root());
    let home = agentcage_core::quadlets::expanduser("~", &quadlet_host);
    if agentcage_cli::hostenv::realpath(&project_dir) == agentcage_cli::hostenv::realpath(&home) {
        eprintln!(
            "warning: mounting home directory ({project_dir}) as project workspace. \
             Sensitive files (e.g. .ssh, .aws) will be accessible to the agent."
        );
    }

    let cage_name = match options.name.clone() {
        Some(name) => name,
        None => match flow::generate_name(&ctx.paths, &scaffolds, &scaffold) {
            Ok(name) => name,
            Err(message) => {
                output::step_fail(&message);
                return 1;
            }
        },
    };

    if ctx.paths.deployment_exists(&cage_name) {
        output::step_fail(&format!(
            "Cage '{cage_name}' already exists. \
             Use --name to specify a different name, or destroy it first."
        ));
        return 1;
    }

    output::banner(&ctx.version);

    let isolation = options.isolation.clone().unwrap_or_else(|| {
        agentcage_core::config::HostProbe::default_isolation(&agentcage_cli::hostenv::RealHost)
    });

    // `os.environ["PROJECT_DIR"] = project_dir`, without the process
    // environment write Rust 2024 makes unsafe. See `hostenv::OVERLAY`.
    agentcage_cli::hostenv::publish_env("PROJECT_DIR", &project_dir);

    // A scaffold's `auth:` alternatives each authenticate on their own,
    // so the template renders the rule for one of them only (#559). One
    // taken from the environment is staged as if it were `-s KEY=VALUE`,
    // so it goes through the secret store on every backend and the cage
    // sees only the placeholder.
    let auth_choices = scaffolds.auth(&scaffold);
    let env = agentcage_cli::secrets::SystemEnv;
    let auth = match flow::select_auth(&auth_choices, &options.secrets, &env) {
        Ok(auth) => auth,
        Err(message) => {
            output::step_fail(&message);
            return 2;
        }
    };
    let with_env_auth;
    let options = match &auth {
        Some(flow::AuthChoice {
            key,
            from_env: Some(value),
        }) => {
            output::info("Auth", &format!("{key} (from the environment)"));
            let mut extended = options.clone();
            extended.secrets.push(format!("{key}={value}"));
            with_env_auth = extended;
            &with_env_auth
        }
        _ => options,
    };

    let text = match agentcage_cli::scaffold::render_config(
        &scaffolds,
        &flow::render_request(
            &cage_name,
            &scaffold,
            &isolation,
            auth.as_ref().map(|choice| choice.key.as_str()),
        ),
    ) {
        Ok(text) => text,
        Err(error) => {
            output::step_fail(&error.to_string());
            return 1;
        }
    };

    let staged = match flow::StagedConfig::write(&text) {
        Ok(staged) => staged,
        Err(error) => {
            output::step_fail(&format!("Could not write the rendered config: {error}"));
            return 1;
        }
    };
    let config_path = staged.path();

    let Ok(mut config) = load_and_validate(&config_path) else {
        return 1;
    };

    // `--dry-run` stops here, before the secret pre-flight, the port
    // probe, the state directory, the build or the session. It still
    // validates the rendered config and the volume declarations, and it
    // prints the plan a real invocation would follow.
    if options.dry_run {
        return dry_run(
            &ctx.paths,
            &project_dir,
            &scaffold,
            &cage_name,
            &config,
            options,
        );
    }

    // Fail fast on missing secrets, before any host filesystem is
    // touched — `cage create`'s secrets-then-ports order. Every
    // scaffold-declared rule is mandatory: there is no "optional
    // secret", so an agent that could otherwise authenticate
    // interactively (claude-code's OAuth `/login`) still needs a key
    // here, or must be launched from a persistent cage whose config the
    // operator can edit.
    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let being_set = flow::secret_keys(&options.secrets);
    // Only the container backend keeps secrets on host podman; asking
    // it about a vm or apple-container cage reports every key missing
    // (see `cage update`).
    if config.isolation == "container" {
        let missing: Vec<String> =
            agentcage_cli::services::check_secrets(&podman, &ctx.paths, &cage_name, &config, &env)
                .into_iter()
                .filter(|key| !being_set.contains(&key.as_str()))
                .collect();
        if !missing.is_empty() {
            output::step_fail(&format!("Missing secrets for cage '{cage_name}':"));
            for key in &missing {
                eprintln!("  {key}");
            }
            eprintln!("Provide them with --set-secret, e.g.:");
            let flags = missing.iter().fold(String::new(), |mut acc, key| {
                use std::fmt::Write as _;
                let _ = write!(acc, " -s {key}=VALUE");
                acc
            });
            eprintln!("  agentcage run {scaffold}{flags}");
            if let Some(hint) = flow::auth_hint(&scaffold, &auth_choices, &missing) {
                eprintln!("{hint}");
            }
            return 1;
        }
    }

    // A scaffold may declare host bind-mounts for state persistence; on
    // a fresh machine the source may not exist yet. An inline `np` bind
    // is intentionally non-persistent, so it gets no host directory.
    for volume in &config.container.volumes {
        if let Err(error) = agentcage_core::volume_mounts::validate_non_persistent_volume(volume) {
            output::step_fail(&error.to_string());
            return 1;
        }
    }
    let persistent: Vec<String> = config
        .container
        .volumes
        .iter()
        .filter(|volume| !agentcage_core::volume_mounts::is_non_persistent_volume(volume))
        .cloned()
        .collect();
    flow::ensure_volume_dirs(&persistent, &quadlet_host);

    let conflicts = agentcage_cli::services::check_port_availability(&config);
    if !conflicts.is_empty() {
        for conflict in &conflicts {
            output::step_fail(&format!(
                "Port {} is already in use ({})",
                conflict.host_port, conflict.spec
            ));
        }
        return 1;
    }

    // `cage create`'s step: a failed `run` discards its state but not
    // its backend resources, so this is the path most likely to find a
    // CA left under a reused name.
    if let Err(message) = ctx.purge_stale_ca(&config.isolation, &cage_name) {
        output::step_fail(&message);
        return 1;
    }

    // ── state ───────────────────────────────────────────
    if let Err(error) = ctx.paths.save_deployment(&cage_name, &config_path) {
        output::step_fail(&format!("Failed to save deployment state: {error}"));
        return 1;
    }
    // Scaffold templates mint their placeholders at render time, but a
    // user scaffold may still omit `placeholder:` — persist whatever is
    // missing and reload, so the quadlets and the proxy agree.
    match ctx
        .paths
        .fill_placeholders(&cage_name, None, &mut agentcage_state::mint_placeholder)
    {
        Ok(true) => {
            match ctx
                .paths
                .load_deployment_config(&cage_name, &agentcage_cli::hostenv::RealHost)
            {
                Ok(reloaded) => config = reloaded,
                Err(error) => {
                    output::step_fail(&format!("Failed to reload the stored config: {error}"));
                    flow::discard_deployment(&ctx.paths, &cage_name);
                    return 1;
                }
            }
        }
        Ok(false) => {}
        Err(error) => {
            output::step_fail(&format!("Failed to fill placeholders: {error}"));
            flow::discard_deployment(&ctx.paths, &cage_name);
            return 1;
        }
    }

    let mut metadata = ctx
        .paths
        .load_metadata(&cage_name)
        .unwrap_or_else(|_| Json::Object(Vec::new()));
    metadata.set("scaffold", Json::string(&scaffold));
    metadata.set("lifecycle", Json::string(&config.lifecycle));
    // Without `agentcage_version` the v0.22 legacy-cage detector reads
    // every freshly-created cage as pre-v0.22 and `cage list` annotates
    // it "legacy v0.21 — destroy + recreate".
    metadata.set("agentcage_version", Json::string(&ctx.version));
    if let Err(error) = ctx.paths.save_metadata(&cage_name, &metadata) {
        output::step_fail(&format!("Failed to save metadata: {error}"));
        flow::discard_deployment(&ctx.paths, &cage_name);
        return 1;
    }

    // Freeze the scaffold's Containerfile and siblings in the state dir
    // so `cage update` can rebuild — an ephemeral cage's build context
    // is a temporary directory that will not be there later.
    if !config.container.build.containerfile.is_empty() {
        flow::stage_scaffold_build_context(
            &ctx.paths,
            &scaffolds,
            &scaffold,
            &config.container.build.containerfile,
            &cage_name,
        );
    }

    if let Err(message) = deploy(ctx, &scaffolds, &scaffold, &config, &cage_name, options) {
        output::step_fail(&message);
        if options.show_timing {
            agentcage_cli::timing::print_summary(&cage_name);
        }
        flow::discard_deployment(&ctx.paths, &cage_name);
        return 1;
    }
    output::step_done(&output::dim(&cage_name));

    if options.show_timing {
        agentcage_cli::timing::print_summary(&cage_name);
    }

    println!();
    output::echo(&format!("  {}", output::dim(&project_dir)));
    output::echo(&format!(
        "  {} {} {}",
        output::dim("Ctrl+D to exit"),
        output::dim("\u{b7}"),
        output::dim(&format!("agentcage cage audit {cage_name}"))
    ));
    println!();
    output::separator();

    let exit_code = session(ctx, &config, &cage_name, options);

    finish_run(ctx, &config, &cage_name, options);

    // `shutil.rmtree(config_dir)` — the staged copy has been in the
    // cage's state dir since `save_deployment`.
    drop(staged);
    exit_code
}

/// `--rm` and the default keep path, sharing destroy's teardown.
///
/// Both branches reuse the existing lifecycle teardown. The default
/// (`--keep`, and what `run` has always done) stops the units and leaves
/// the deployment, volumes, secrets and data directory in place. `--rm`
/// calls `cage destroy`'s own teardown, so there is exactly one
/// implementation of what destroying a cage means, and uses its checked
/// result so a partial teardown is not reported as success.
///
/// The audit data directory is deliberately not deleted even by `--rm`:
/// it holds the policy audit trail, capture log and grants overlay, and
/// deleting evidence as an implicit side effect of ending a session is
/// the one thing this command must not do. The `Kept:` block says so and
/// names the command that removes it by hand.
fn finish_run(ctx: &Ctx, config: &Config, cage_name: &str, options: &Options) {
    use agentcage_cli::output;

    println!();
    output::separator();

    if options.remove {
        let spinner = output::Spinner::start("Removing cage...");
        let destroyed =
            crate::cli::cage::lifecycle::destroy_cage_status(ctx, cage_name, false, false);
        drop(spinner);
        // `complete`, not `deployment_exists`: `destroy_resources`
        // failures are warnings inside the teardown, so the deployment
        // directory can be gone while a network, volume or secret is
        // still there. Reporting that as `Removed` would claim success
        // for a partial teardown.
        if !destroyed.complete || ctx.paths.deployment_exists(cage_name) {
            println!(
                "  {}",
                output::dim(&format!(
                    "{cage_name} could not be fully destroyed; some resources may remain"
                ))
            );
            print_run_kept(&ctx.paths, cage_name, RunKept::RemoveFailed);
        } else if destroyed.removed.is_empty() {
            println!("  {}", output::dim(&format!("{cage_name} removed")));
            print_run_kept(&ctx.paths, cage_name, RunKept::Removed);
        } else {
            println!("  {}", output::dim(&format!("{cage_name} destroyed")));
            print_run_kept(&ctx.paths, cage_name, RunKept::Removed);
        }
        return;
    }

    {
        let _spinner = output::Spinner::start("Stopping cage...");
        ctx.backend_for(&config.isolation).stop(&config.name);
    }
    agentcage_cli::services::record_stopped_at(&ctx.paths, cage_name);
    println!("  {}", output::dim(&format!("{cage_name} stopped")));
    print_run_kept(&ctx.paths, cage_name, RunKept::Stopped);
}

/// What happened to the cage when the session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunKept {
    /// Default path: the cage is stopped and all its resources are kept.
    Stopped,
    /// `--rm` succeeded: the cage is gone, apart from its audit data.
    Removed,
    /// `--rm` was requested but teardown did not finish.
    RemoveFailed,
}

/// The `Kept:` block `run` prints after a session.
///
/// The state changes only the wording and the removal advice; the
/// inventory is read from disk, so it names exactly what survived.
fn print_run_kept(paths: &agentcage_state::Paths, name: &str, state: RunKept) {
    let data = paths.cage_data_dir(name);
    println!("Kept:");
    match state {
        RunKept::Stopped => {
            println!("  cage: {name} (stopped; deployment, volumes and secrets preserved)");
        }
        RunKept::Removed => println!("  cage: {name} (destroyed; audit data retained)"),
        RunKept::RemoveFailed => {
            println!("  cage: {name} (destroy incomplete; some resources may remain)");
        }
    }
    println!("  data:{}", data.display());
    if data.is_dir() {
        let entries = crate::cli::cage::lifecycle::kept_entries(&data);
        if !entries.is_empty() {
            println!("  left in place: {}", entries.join(", "));
        }
    }
    match state {
        RunKept::Removed => println!(
            "  remove with: rm -rf {}",
            agentcage_core::value_fmt::quote_text(&data.display().to_string())
        ),
        RunKept::Stopped | RunKept::RemoveFailed => {
            println!("  remove with: agentcage cage destroy {name} -y");
        }
    }
}

/// Render the plan a real `run` would follow, without touching the
/// cage's state.
///
/// Deliberately **no** bind probe here: `check_port_availability` binds
/// each host port to ask whether it is free, and `--dry-run` promises no
/// side effects. Conflicts with other cages' configured publishes are
/// reported from their stored configs instead, and the actual bind probe
/// remains part of the real deploy.
fn dry_run(
    paths: &agentcage_state::Paths,
    project_dir: &str,
    scaffold: &str,
    cage_name: &str,
    config: &Config,
    options: &Options,
) -> i32 {
    use agentcage_cli::output;

    for volume in &config.container.volumes {
        if let Err(error) = agentcage_core::volume_mounts::validate_non_persistent_volume(volume) {
            output::step_fail(&error.to_string());
            return 1;
        }
    }

    println!(
        "{}",
        plan_text(paths, project_dir, scaffold, cage_name, config, options)
    );
    0
}

/// The printable `--dry-run` plan. Kept separate from the printing so the
/// fields are testable without capturing stdout.
fn plan_text(
    paths: &agentcage_state::Paths,
    project_dir: &str,
    scaffold: &str,
    cage_name: &str,
    config: &Config,
    options: &Options,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    out.push_str("Dry run: no changes will be made.\n\n");
    let _ = writeln!(out, "  name: {cage_name}");
    let _ = writeln!(out, "  scaffold: {scaffold}");
    let _ = writeln!(out, "  isolation: {}", config.isolation);

    let image = if config.container.image.is_empty() {
        "(none)".to_owned()
    } else {
        config.container.image.clone()
    };
    let _ = writeln!(out, "  image: {image}");
    let containerfile = &config.container.build.containerfile;
    let build = if containerfile.is_empty() {
        format!("pull {image}")
    } else {
        let flags = format!(
            "{}{}",
            if options.no_cache { " --no-cache" } else { "" },
            if options.pull { " --pull=always" } else { "" }
        );
        format!("podman build -t {image} -f {containerfile}{flags} <scaffold context>")
    };
    let _ = writeln!(out, "  build: {build}");

    let _ = writeln!(out, "  project: {project_dir}");
    let mounts: Vec<String> = config
        .container
        .volumes
        .iter()
        .map(|volume| volume.replace("${PROJECT_DIR}", project_dir))
        .collect();
    let _ = writeln!(
        out,
        "  mounts: {}",
        if mounts.is_empty() {
            "none".to_owned()
        } else {
            mounts.join(", ")
        }
    );

    let _ = writeln!(out, "  allowlist: {}", domain_summary(config));

    let expected = agentcage_cli::services::expected_secrets(config);
    let provided: std::collections::BTreeSet<&str> =
        agentcage_cli::run::secret_keys(&options.secrets)
            .into_iter()
            .collect();
    let secrets = if expected.is_empty() {
        "none".to_owned()
    } else {
        expected
            .iter()
            .map(|key| {
                if provided.contains(key.as_str()) {
                    format!("{key} (provided)")
                } else {
                    format!("{key} (not provided)")
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(out, "  secrets: {secrets}");

    let ports = if config.container.ports.is_empty() {
        "none".to_owned()
    } else {
        config.container.ports.join(", ")
    };
    let _ = writeln!(out, "  ports: {ports}");
    let conflicts = conflicting_cages(paths, cage_name, config);
    let _ = writeln!(
        out,
        "  port conflicts: {}",
        if conflicts.is_empty() {
            "none with existing cages (the bind probe runs at deploy)".to_owned()
        } else {
            conflicts.join(", ")
        }
    );

    let exec = agentcage_cli::run::resolve_exec_cmd(config, &options.extra_args)
        .iter()
        .map(|arg| agentcage_core::value_fmt::quote_text(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let cleanup = if options.remove {
        format!("agentcage cage destroy {cage_name} -y")
    } else {
        format!(
            "agentcage cage stop {cage_name} (keeps deployment, volumes, secrets and audit data)"
        )
    };
    out.push_str("  commands:\n");
    let _ = writeln!(out, "    build: {build}");
    let _ = writeln!(out, "    session: {exec}");
    let _ = writeln!(out, "    cleanup: {cleanup}");
    out
}

/// `allowlist`, `blocklist` or `none`, with the entries and count.
fn domain_summary(config: &Config) -> String {
    let mode = if config.domains.mode.is_empty() {
        if !config.domains.allow.is_empty() {
            "allowlist"
        } else if !config.domains.block.is_empty() {
            "blocklist"
        } else {
            "none"
        }
    } else {
        config.domains.mode.as_str()
    };
    let entries = config.domains.list();
    if entries.is_empty() {
        mode.to_owned()
    } else {
        format!("{mode} ({}): {}", entries.len(), entries.join(", "))
    }
}

/// Other cages' stored configs that publish the same host bind/port.
///
/// This is the dry-run's non-binding conflict answer. It cannot see a
/// process outside agentcage holding the port; the real deploy's bind
/// probe does that, and `--dry-run` deliberately does not bind.
fn conflicting_cages(paths: &agentcage_state::Paths, name: &str, config: &Config) -> Vec<String> {
    let ours: Vec<(String, String)> = config
        .container
        .ports
        .iter()
        .filter_map(|spec| published_port(spec))
        .collect();
    if ours.is_empty() {
        return Vec::new();
    }
    let mut conflicts = Vec::new();
    for other in paths.list_deployments().unwrap_or_default() {
        if other == name {
            continue;
        }
        let Ok(other_config) =
            paths.load_deployment_config(&other, &agentcage_cli::hostenv::RealHost)
        else {
            continue;
        };
        for spec in &other_config.container.ports {
            if published_port(spec).is_some_and(|key| ours.contains(&key)) {
                conflicts.push(format!("{other}:{spec}"));
            }
        }
    }
    conflicts
}

/// `[BIND:]HOST:CONTAINER` to `(bind, host_port)`, skipping the shapes
/// `check_port_availability` also cannot probe.
fn published_port(spec: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        3 => Some((parts[0].to_owned(), parts[1].to_owned())),
        2 => Some(("0.0.0.0".to_owned(), parts[0].to_owned())),
        _ => None,
    }
}

/// The build-and-deploy half, so the caller's error path is one branch.
///
/// Verbose streams the build; quiet runs it under a spinner. Both call
/// the same two steps in the same order — the scaffold's own image
/// first, then the shared egress image and the units.
fn deploy(
    ctx: &Ctx,
    scaffolds: &agentcage_cli::scaffold::Scaffolds,
    scaffold: &str,
    config: &Config,
    cage_name: &str,
    options: &Options,
) -> Result<(), String> {
    use agentcage_cli::output;
    use agentcage_cli::services;

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());

    // `--set-secret`. Container mode writes the host podman store; the
    // vm backend has none, so values are staged for it to create inside
    // the VM; apple-container persists through the cage's configured
    // at-rest store, which is what its `start()` reads back.
    let parsed = agentcage_cli::run::parse_set_secrets(&options.secrets)?;
    let provided: std::collections::BTreeSet<String> =
        parsed.iter().map(|(key, _)| key.clone()).collect();
    match config.isolation.as_str() {
        "vm" => agentcage_cli::run::stage_pending_secrets(&ctx.paths, cage_name, &parsed)
            .map_err(|error| format!("Failed to stage secrets: {error}"))?,
        "apple-container" => {
            store_secrets(ctx, config, cage_name, &parsed)?;
        }
        _ => {
            for (key, value) in &parsed {
                let full = format!("{cage_name}.{key}");
                if podman.secret_exists(&full).unwrap_or(false) {
                    let _ = podman.secret_remove(&full);
                }
                podman
                    .secret_create(&full, value)
                    .map_err(|error| format!("Failed to set secret '{key}': {error}"))?;
            }
        }
    }

    // `env:` / `cmd:` / `systemd-creds:` sources are materialized into
    // the podman store now, so the quadlet's `Secret=` resolves at boot.
    // Container mode only: the vm backend bridges its own after it
    // starts. The pre-flight above already proved every expected secret
    // is obtainable, so nothing is stripped and a resolve-time failure
    // is loud.
    if config.isolation == "container" {
        let env = agentcage_cli::secrets::SystemEnv;
        let host = agentcage_cli::secrets::SecretHost::detect(ctx.runner.as_ref(), &env);
        host.resolve_and_populate(
            &podman,
            config,
            cage_name,
            &ctx.paths.deployment_dir(cage_name),
            &provided,
            true,
        )
        .map_err(|error| error.message().clone())?;
    }

    let used_octets = services::collect_used_octets(&ctx.paths, cage_name);
    let config_host_path = ctx
        .paths
        .save_proxy_config(cage_name, &ctx.version)
        .map_err(|error| format!("Failed to write the proxy config: {error}"))?;
    ctx.paths
        .save_dns_allowlist(cage_name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| format!("Failed to write the DNS allowlist: {error}"))?;

    let backend = ctx.backend_for(&config.isolation);
    backend.ensure_ready();
    let issues = backend.check_prerequisites();
    if !issues.is_empty() {
        return Err(format!(
            "prerequisites for the '{}' backend are not met: {}",
            config.isolation,
            issues.join(", ")
        ));
    }

    let quiet = !options.verbose;
    let run_steps = || -> Result<(), String> {
        // vm builds inside the VM and apple-container builds through
        // Apple's `container` CLI, so the host podman scaffold build is
        // skipped for both.
        if config.isolation == "container" {
            agentcage_cli::scaffold::run_scaffold_setup(
                scaffolds,
                ctx.runner.as_ref(),
                scaffold,
                &agentcage_cli::scaffold::SetupOptions {
                    // `run.py` calls `run_scaffold_setup` without
                    // `isolation=`, which is the legacy "always build"
                    // path — reached only when this branch already
                    // decided the isolation is `container`.
                    isolation: None,
                    quiet,
                    no_cache: options.no_cache,
                    pull: options.pull,
                },
            )?;
        }
        services::build_and_deploy(
            &backend,
            &ctx.paths,
            &services::DeployPlan {
                config,
                config_host_path: &config_host_path.display().to_string(),
                deploy_name: cage_name,
                used_octets: Some(&used_octets),
                network_octet: None,
                quiet,
                no_cache: options.no_cache,
                pull: options.pull,
            },
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    };

    if options.verbose {
        run_steps()
    } else {
        let _spinner = output::Spinner::start("Starting cage...");
        run_steps()
    }
}

/// `--set-secret` on apple-container: through the cage's configured
/// at-rest store, because that is the one the backend re-stages from at
/// every `start()`. A `pending_secrets.json` would be ignored.
fn store_secrets(
    ctx: &Ctx,
    config: &Config,
    cage_name: &str,
    parsed: &[(String, String)],
) -> Result<(), String> {
    let env = agentcage_cli::secrets::SystemEnv;
    let host = agentcage_cli::secrets::SecretHost::detect(ctx.runner.as_ref(), &env);
    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let state_dir = ctx.paths.deployment_dir(cage_name);
    for (key, value) in parsed {
        let scheme = config
            .secret_injection
            .iter()
            .find(|rule| &rule.env == key)
            .map(|rule| rule.source.split(':').next().unwrap_or_default())
            .unwrap_or_default();
        let store = agentcage_cli::secrets::resolve_store(
            config,
            &host,
            Some(&podman),
            scheme,
            agentcage_cli::secrets::Platform::host(),
        )
        .map_err(|error| format!("refusing to store secret '{key}': {}", error.message()))?;
        store
            .set(cage_name, key, value, &state_dir)
            .map_err(|error| format!("failed to store secret '{key}': {}", error.message()))?;
    }
    Ok(())
}

/// The interactive session: the workload owns the terminal until it
/// exits.
///
/// The proxy-log monitor runs alongside it and writes blocked-request
/// notices straight to `/dev/tty`, because stdout belongs to the
/// session. apple-container has neither a separate proxy container nor a
/// host podman, so it gets no monitor; its audit log is still written
/// inside the cage.
///
/// # Ctrl-C
///
/// The cage has to be stopped however the session ends. Rust's default for SIGINT is to die, which would
/// skip the stop, so the session is held inside
/// [`agentcage_cli::terminal::restored_terminal`]: its guard diverts
/// SIGINT away from this process for as long as the child is running,
/// and the child (which is in the same foreground process group) gets
/// the signal. The child then exits 130 and that becomes this function's
/// answer, the same status earlier releases gave. Their
/// `Session interrupted.` line is not printed, because there is no
/// longer an interruption here to report — and printing it on any 130 would mislabel a workload that
/// chose to exit 130 itself.
///
/// This is deliberately **not**
/// [`agentcage_cli::terminal::run_interactive`], which `cage exec` uses:
/// that one `execvp`s when stdin is not a terminal, replacing this
/// process. Here that would mean a non-interactive `agentcage run` never
/// reaching the stop.
fn session(ctx: &Ctx, config: &Config, cage_name: &str, options: &Options) -> i32 {
    use agentcage_cli::run as flow;

    let exec_cmd = flow::resolve_exec_cmd(config, &options.extra_args);
    let interactive = agentcage_cli::terminal::is_interactive();

    let mut monitor = if config.isolation == "apple-container" {
        None
    } else {
        flow::ProxyMonitor::start(
            Arc::new(agentcage_exec::SystemRunner::new()),
            &flow::vm_podman_prefix(&config.isolation, cage_name),
            &format!("{}-proxy", config.name),
        )
    };

    // Every backend routes through `exec_argv` so `--as-root` means the
    // same thing everywhere: the default drops to the workload's uid
    // 1000 user, `--as-root` opts back into root. `container` and `vm`
    // pass `-u` to `podman exec` because the cage quadlet's `User=` may
    // be empty (the `ubuntu` scaffold), in which case `podman exec`
    // would otherwise inherit the image's USER — root.
    let argv = match ctx.backend_for(&config.isolation).exec_argv(
        &config.name,
        "cage",
        &exec_cmd,
        interactive,
        options.as_root,
    ) {
        Ok(argv) => argv,
        // Only the apple backend refuses here, and only for a missing
        // `container` CLI: the service is the literal `"cage"`. The
        // stop below is skipped deliberately — nothing was started.
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };

    let exit_code = {
        let _guard = agentcage_cli::terminal::restored_terminal();
        match std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .status()
        {
            Ok(status) => agentcage_cli::terminal::exit_status_of(&status),
            Err(error) => {
                eprintln!("error: could not start the session: {error}");
                1
            }
        }
    };
    if let Some(monitor) = monitor.as_mut() {
        monitor.stop();
    }
    exit_code
}

/// `os.path.abspath` — absolute, `.`/`..` collapsed lexically, symlinks
/// left alone.
fn abspath(path: &str) -> String {
    let path = Path::new(path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    agentcage_core::volume_mounts::normpath(&absolute.display().to_string())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use agentcage_exec::{
        Command, CommandRunner, ExecError, FakeRunner, LineStream, Output, Reply,
    };
    use agentcage_state::{Paths, TestDir};

    use super::{Options, command, execute, finish_run, main, plan_text};
    use crate::cli::context::Ctx;
    use agentcage_core::config::Config;

    /// A runner that copies the cage's state directory out at the
    /// moment `podman build` is issued, then answers from the fake.
    ///
    /// The `run` flow stages the scaffold's build context into the
    /// cage's state dir and only then builds. Reading the state dir from
    /// inside the seam is what makes that observable: `deploy` is
    /// allowed to fail afterwards (and discard the deployment), but the
    /// bytes the build was about to run against are already captured.
    #[derive(Debug)]
    struct CapturingBuild {
        /// A clone of the fake the test keeps: `FakeRunner` shares its
        /// recorded state, and `Ctx` wants an owned `'static` runner.
        inner: FakeRunner,
        /// The cage's deployment dir — what the staging writes into.
        from: PathBuf,
        copy_to: PathBuf,
    }

    impl CapturingBuild {
        /// Whether this call is the scaffold build; if so, snapshot the
        /// staged state dir first.
        fn capture(&self, command: &Command) -> bool {
            let argv = command.argv();
            if argv.first().map(String::as_str) != Some("podman")
                || argv.get(1).map(String::as_str) != Some("build")
            {
                return false;
            }
            let _ = std::fs::remove_dir_all(&self.copy_to);
            copy_tree(&self.from, &self.copy_to).expect("copy the staged state dir out");
            true
        }
    }

    impl CommandRunner for CapturingBuild {
        fn run(&self, command: &Command) -> Result<Output, ExecError> {
            let build = self.capture(command);
            let output = self.inner.run(command)?;
            if build {
                // Fail the build so the flow stops here, right after the
                // observation: everything the assertion needs has been
                // captured, and nothing past this point is under test.
                return Ok(Output::failed(125, "the test stubs the build"));
            }
            Ok(output)
        }

        fn stream(&self, command: &Command) -> Result<Box<dyn LineStream>, ExecError> {
            self.capture(command);
            self.inner.stream(command)
        }

        fn which(&self, program: &str) -> Option<PathBuf> {
            self.inner.which(program)
        }
    }

    /// `shutil.copytree`, for the test's own snapshot.
    fn copy_tree(source: &Path, dest: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dest)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let from = entry.path();
            let to = dest.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&from, &to)?;
            } else {
                std::fs::copy(&from, &to)?;
            }
        }
        Ok(())
    }

    /// `agentcage run <scaffold>`, through the real command: the
    /// scaffold's build context and the canonical brief/skill are frozen
    /// into the cage's state dir before the build runs, so the
    /// Containerfile's `COPY` lines keep resolving after the ephemeral
    /// project directory is gone.
    ///
    /// This drives `main` (clap parse + `execute`), not
    /// `stage_scaffold_build_context`: making that call site in
    /// `execute` dead has to fail here, which it cannot if the helper is
    /// called directly. `claude-code` is one of the scaffolds whose
    /// Containerfile `COPY`s both canonical assets. The build itself is
    /// stubbed to fail — the assertion is on what preceded it.
    #[test]
    fn an_ephemeral_run_stages_its_build_context_and_canonical_assets() {
        let dir = TestDir::new("run-call-site");
        let paths = Paths::under(dir.path());
        let project = dir.join("project");
        std::fs::create_dir_all(&project).expect("project dir");
        let project_arg = project.display().to_string();

        let fake = FakeRunner::new();
        fake.assume_installed();
        // The scaffold image is not there, so `run_scaffold_setup` builds
        // it; the build is where the staged context is observed.
        fake.on(["podman", "image", "exists"], Reply::status(1));
        fake.on(["podman", "info", "--format", "json"], Reply::ok("{}"));
        fake.default_reply(Reply::success());
        let snapshot = TestDir::new("run-call-site-snapshot");
        let watcher = CapturingBuild {
            inner: fake.clone(),
            from: paths.deployment_dir("demo"),
            copy_to: snapshot.path().join("deployment"),
        };
        let ctx = Ctx {
            paths,
            runner: Box::new(watcher),
            version: "9.9.9".to_owned(),
        };

        let matches = command()
            .try_get_matches_from([
                "run",
                "claude-code",
                "--name",
                "demo",
                "--project",
                &project_arg,
                "--isolation",
                "container",
                "-s",
                "ANTHROPIC_API_KEY=sk-test",
            ])
            .expect("the argv parses");
        let _ = main(&ctx, &matches);

        assert!(
            fake.argv_sequence()
                .iter()
                .any(|argv| argv.get(1).map(String::as_str) == Some("build")),
            "no podman build was issued"
        );
        let staged = snapshot.path().join("deployment");
        assert!(
            staged.join("Containerfile").is_file(),
            "the build context was never staged: {:?}",
            list(&staged)
        );
        assert!(staged.join("README.md").is_file(), "{:?}", list(&staged));
        // Config templates are not build input.
        assert!(!staged.join("cage.yaml.j2").exists(), "{:?}", list(&staged));
        assert!(
            !staged.join("scaffold.yaml").exists(),
            "{:?}",
            list(&staged)
        );

        let brief = agentcage_assets::embedded_files()
            .iter()
            .find(|file| file.path == "scaffolds/AGENTS.md")
            .expect("the embedded brief");
        assert_eq!(
            std::fs::read(staged.join("AGENTS.md")).expect("the staged brief"),
            brief.bytes
        );
        assert!(
            staged.join("skills/agentcage/SKILL.md").is_file(),
            "{:?}",
            list(&staged)
        );
    }

    fn list(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every flag is independent; the helper keeps the tests focused.
    fn options(remove: bool, dry_run: bool) -> Options {
        Options {
            scaffold: String::new(),
            project_dir: None,
            name: None,
            secrets: Vec::new(),
            extra_args: Vec::new(),
            verbose: false,
            isolation: None,
            as_root: false,
            show_timing: false,
            no_cache: false,
            pull: false,
            remove,
            dry_run,
        }
    }

    #[test]
    fn keep_and_rm_are_a_usage_error_together() {
        let error = command()
            .try_get_matches_from(["run", "codex", "--keep", "--rm"])
            .expect_err("--keep and --rm must conflict");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn a_dry_run_plan_names_everything_a_real_run_would_use() {
        let dir = TestDir::new("run-plan");
        let paths = Paths::under(dir.path());
        let mut config = Config {
            name: "demo".to_owned(),
            isolation: "container".to_owned(),
            ..Config::default()
        };
        config.container.image = "localhost/agentcage-scaffold-claude-code:latest".to_owned();
        config.container.build.containerfile = "Containerfile".to_owned();
        config.container.ports = vec!["127.0.0.1:3000:3000".to_owned()];
        config.domains.mode = "allowlist".to_owned();
        config.domains.allow = vec!["anthropic.com".to_owned(), "claude.com".to_owned()];
        config
            .secret_injection
            .push(agentcage_core::config::SecretInjectionRule {
                env: "ANTHROPIC_API_KEY".to_owned(),
                ..agentcage_core::config::SecretInjectionRule::default()
            });
        let mut opts = options(false, true);
        opts.secrets = vec!["ANTHROPIC_API_KEY=sk-test".to_owned()];

        let text = plan_text(
            &paths,
            "/work/project",
            "claude-code",
            "demo",
            &config,
            &opts,
        );
        assert!(text.contains("Dry run: no changes will be made."), "{text}");
        assert!(text.contains("name: demo"), "{text}");
        assert!(text.contains("scaffold: claude-code"), "{text}");
        assert!(text.contains("isolation: container"), "{text}");
        assert!(
            text.contains("podman build -t localhost/agentcage-scaffold-claude-code:latest"),
            "{text}"
        );
        assert!(text.contains("project: /work/project"), "{text}");
        assert!(
            text.contains("allowlist (2): anthropic.com, claude.com"),
            "{text}"
        );
        assert!(
            text.contains("ANTHROPIC_API_KEY (provided)"),
            "the secret names are in the plan: {text}"
        );
        assert!(!text.contains("sk-test"), "a secret value leaked: {text}");
        assert!(text.contains("ports: 127.0.0.1:3000:3000"), "{text}");
        assert!(text.contains("port conflicts: none"), "{text}");
        assert!(text.contains("cleanup: agentcage cage stop demo"), "{text}");

        opts.remove = true;
        let text = plan_text(
            &paths,
            "/work/project",
            "claude-code",
            "demo",
            &config,
            &opts,
        );
        assert!(
            text.contains("cleanup: agentcage cage destroy demo -y"),
            "{text}"
        );
    }

    /// `--dry-run` stops before state, secrets, ports, the build and the
    /// session. The fake has no podman rule at all, so reaching any of
    /// those would panic rather than pass silently.
    #[test]
    fn a_dry_run_creates_no_state_and_calls_nothing() {
        let dir = TestDir::new("run-dry-run");
        let paths = Paths::under(dir.path());
        let project = dir.join("project");
        std::fs::create_dir_all(&project).expect("project dir");

        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.default_reply(Reply::success());
        let ctx = Ctx {
            paths: paths.clone(),
            runner: Box::new(fake.clone()),
            version: "9.9.9".to_owned(),
        };
        let mut opts = options(false, true);
        opts.scaffold = "claude-code".to_owned();
        opts.project_dir = Some(project.display().to_string());
        opts.name = Some("dry-demo".to_owned());
        opts.isolation = Some("container".to_owned());
        opts.secrets = vec!["ANTHROPIC_API_KEY=sk-test".to_owned()];

        assert_eq!(execute(&ctx, &opts), 0);
        assert!(!paths.deployment_exists("dry-demo"));
        assert!(
            !paths.deployment_dir("dry-demo").exists(),
            "the dry run created a deployment directory"
        );
        assert!(
            !paths.cage_data_dir("dry-demo").exists(),
            "the dry run created a data directory"
        );
        assert!(
            !fake
                .argv_sequence()
                .iter()
                .any(|argv| argv.first().map(String::as_str) == Some("podman")),
            "the dry run reached podman: {:?}",
            fake.argv_sequence()
        );
    }

    /// The default branch stops and keeps everything the deployment
    /// wrote, and records when it stopped for `prune --older-than`.
    #[test]
    fn the_default_branch_keeps_the_cage_and_records_stopped_at() {
        let dir = TestDir::new("run-keep");
        let paths = Paths::under(dir.path());
        let name = "kept-demo";
        stage_deployment(dir.path(), &paths, name);

        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.default_reply(Reply::success());
        let ctx = Ctx {
            paths: paths.clone(),
            runner: Box::new(fake),
            version: "9.9.9".to_owned(),
        };
        let config = Config {
            name: name.to_owned(),
            isolation: "container".to_owned(),
            ..Config::default()
        };

        finish_run(&ctx, &config, name, &options(false, false));

        assert!(
            paths.deployment_exists(name),
            "the default run discarded the deployment"
        );
        let metadata = paths.load_metadata(name).expect("metadata is readable");
        assert!(
            metadata
                .get("stopped_at")
                .and_then(agentcage_core::har::json::Json::as_str)
                .is_some_and(|value| !value.is_empty()),
            "no stopped_at was recorded: {metadata:?}"
        );
    }

    /// `--rm` must take destroy's teardown, not grow a second one, and
    /// it must leave the audit data directory behind.
    #[test]
    fn rm_destroys_the_deployment_through_the_lifecycle_teardown() {
        let dir = TestDir::new("run-rm");
        let paths = Paths::under(dir.path());
        let name = "rm-demo";
        stage_deployment(dir.path(), &paths, name);
        std::fs::create_dir_all(paths.grants_dir(name)).expect("data dir");
        std::fs::write(paths.policy_audit_file(name), "{\"decision\":\"allow\"}\n")
            .expect("audit file");

        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.default_reply(Reply::success());
        let ctx = Ctx {
            paths: paths.clone(),
            runner: Box::new(fake.clone()),
            version: "9.9.9".to_owned(),
        };
        let config = Config {
            name: name.to_owned(),
            isolation: "container".to_owned(),
            ..Config::default()
        };

        finish_run(&ctx, &config, name, &options(true, false));

        assert!(
            !paths.deployment_exists(name),
            "--rm left the deployment behind"
        );
        assert!(
            paths.policy_audit_file(name).is_file(),
            "--rm deleted the audit log"
        );
        let calls = fake.argv_sequence();
        assert!(
            calls.iter().any(|argv| {
                argv.first().map(String::as_str) == Some("podman")
                    && argv.get(1).map(String::as_str) == Some("network")
                    && argv.get(2).map(String::as_str) == Some("rm")
            }),
            "destroy's podman teardown did not run: {calls:?}"
        );
    }

    fn stage_deployment(home: &Path, paths: &Paths, name: &str) {
        let source = home.join(format!("{name}.yaml"));
        std::fs::write(
            &source,
            format!("name: {name}\nisolation: container\nlifecycle: interactive\ncontainer:\n  image: \"alpine\"\n"),
        )
        .expect("write source config");
        paths
            .save_deployment(name, &source)
            .expect("save deployment");
    }
}
