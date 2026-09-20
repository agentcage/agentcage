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
(prompts) / `-s KEY=VALUE`, or via a configured `source:`. There is no
\"optional secret\": an agent that would otherwise authenticate without a
key (e.g. claude-code's interactive OAuth `/login`) still needs one here,
or must be run from a persistent cage built with `agentcage init` whose
config you can edit. `--no-cache`/`--pull` force a clean rebuild (ignore
the layer cache / re-pull the base image) across every isolation backend
— container, vm, and apple-container alike.";

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
    };
    // The Python's `sys.exit(exit_code)`: the session's own status is
    // this process's status, which is what makes
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

    let text = match agentcage_cli::scaffold::render_config(
        &scaffolds,
        &flow::render_request(&cage_name, &scaffold, &isolation),
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

    // Fail fast on missing secrets, before any host filesystem is
    // touched — `cage create`'s secrets-then-ports order. Every
    // scaffold-declared rule is mandatory: there is no "optional
    // secret", so an agent that could otherwise authenticate
    // interactively (claude-code's OAuth `/login`) still needs a key
    // here, or must be launched from a persistent cage whose config the
    // operator can edit.
    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let env = agentcage_cli::secrets::SystemEnv;
    let being_set: Vec<&str> = options
        .secrets
        .iter()
        .map(|spec| spec.split_once('=').map_or(spec.as_str(), |(key, _)| key))
        .collect();
    if config.isolation == "container" || agentcage_exec::command::which_on_path("podman").is_some()
    {
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
    println!("  {}", output::dim(&project_dir));
    println!(
        "  {} {} {}",
        output::dim("Ctrl+D to exit"),
        output::dim("\u{b7}"),
        output::dim(&format!("agentcage cage audit {cage_name}"))
    );
    println!();
    output::separator();

    let exit_code = session(ctx, &config, &cage_name, options);

    // The cage is stopped, not destroyed: the deployment directory, the
    // quadlets, the named volumes and the secrets all survive, so
    // `agentcage cage audit <name>` works afterwards and
    // `agentcage cage start <name>` brings the same cage back.
    println!();
    output::separator();
    {
        let _spinner = output::Spinner::start("Stopping cage...");
        ctx.backend_for(&config.isolation).stop(&config.name);
    }
    println!("  {}", output::dim(&format!("{cage_name} stopped")));
    println!(
        "  {}",
        output::dim(&format!("agentcage cage audit {cage_name}"))
    );

    // `shutil.rmtree(config_dir)` — the staged copy has been in the
    // cage's state dir since `save_deployment`.
    drop(staged);
    exit_code
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
/// The Python catches `KeyboardInterrupt`, prints `Session interrupted.`
/// and falls through to its `finally` — the point being that the cage is
/// stopped either way. Rust's default for SIGINT is to die, which would
/// skip the stop, so the session is held inside
/// [`agentcage_cli::terminal::restored_terminal`]: its guard diverts
/// SIGINT away from this process for as long as the child is running,
/// and the child (which is in the same foreground process group) gets
/// the signal. The child then exits 130 and that becomes this function's
/// answer, so the status is the Python's. The `Session interrupted.`
/// line is not printed, because there is no longer an interruption here
/// to report — and printing it on any 130 would mislabel a workload that
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
    let argv = ctx.backend_for(&config.isolation).exec_argv(
        &config.name,
        "cage",
        &exec_cmd,
        interactive,
        options.as_root,
    );

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
