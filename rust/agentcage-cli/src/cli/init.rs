//! `agentcage init [NAME]` and `agentcage doctor` — the two top-level
//! leaf commands.
//!
//! Small enough to share a module, and they have nothing in common
//! except that neither belongs to a group.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgMatches, Command};

use crate::cli::context::{Ctx, EXIT_FAILURE};

use crate::cli::args::{INTEGER, ISOLATIONS, TEXT, flag, leaf, optional_positional, value_opt};

/// `agentcage init` — write a starter `cage.yaml`.
pub(crate) fn init() -> Command {
    leaf("init")
        .about("Scaffold a new agentcage config file.")
        .arg(optional_positional("name", "NAME"))
        .arg(
            value_opt("output", "output", TEXT, "Output file path.")
                .short('o')
                .default_value("cage.yaml"),
        )
        .arg(value_opt("image", "image", TEXT, "Container image.").default_value("node:22-slim"))
        .arg(
            value_opt(
                "isolation",
                "isolation",
                "[container|vm|apple-container]",
                "Isolation backend (default: auto-detect from platform — container on Linux, apple-container on macOS 26+ ASi when Apple `container` is installed, vm otherwise).",
            )
            .value_parser(ISOLATIONS),
        )
        .arg(flag("force", "force", "Overwrite existing file."))
        .arg(value_opt(
            "scaffold",
            "scaffold",
            TEXT,
            "Use a scaffold template (e.g. openclaw).",
        ))
        .arg(flag(
            "list_scaffolds",
            "list-scaffolds",
            "List available scaffolds and exit.",
        ))
        .arg(
            value_opt(
                "port",
                "port",
                INTEGER,
                "Host port to publish (scaffold-specific).",
            )
            .value_parser(clap::value_parser!(i64)),
        )
}

/// `agentcage doctor` — no arguments at all, which is the whole point.
pub(crate) fn doctor() -> Command {
    leaf("doctor").about("Check system health and diagnose common issues.")
}

// ── the body ─────────────────────────────────────────────────

/// `cli.py:663` — write a starter `cage.yaml`, then let the scaffold
/// prepare whatever it needs.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match run(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one body, matching `cli.py:663`. The order is observable: \
              the staging conflicts are refused before anything is \
              written, the config is written before the scaffold builds, \
              and the build context is frozen after."
)]
fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let scaffolds = scaffolds(ctx)?;

    // `--list-scaffolds` is checked before the NAME requirement,
    // deliberately: `agentcage init --list-scaffolds` with no name is
    // how the flag is meant to be used.
    if matches.get_flag("list_scaffolds") {
        let names = scaffolds.list();
        if names.is_empty() {
            println!("No scaffolds available.");
        } else {
            println!("Available scaffolds:");
            for name in names {
                println!("  {name}");
            }
        }
        return Ok(());
    }

    let Some(name) = matches.get_one::<String>("name") else {
        // click declares NAME optional so that `--list-scaffolds` can
        // stand alone, and then enforces it here. Same error, same
        // status.
        eprintln!("error: missing argument 'NAME'");
        return Err(ExitCode::from(EXIT_FAILURE));
    };
    if !agentcage_cli::scaffold::valid_scaffold_name(name) {
        eprintln!(
            "error: name must be 1-63 lowercase alphanumeric characters or \
             hyphens, starting with a letter or digit (got: {})",
            agentcage_core::python::repr_str(name)
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let scaffold = matches.get_one::<String>("scaffold");
    if let Some(scaffold) = scaffold {
        let available = scaffolds.list();
        if !available.contains(scaffold) {
            eprintln!(
                "error: unknown scaffold {} (available: {})",
                agentcage_core::python::repr_str(scaffold),
                if available.is_empty() {
                    "none".to_owned()
                } else {
                    available.join(", ")
                }
            );
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }

    let output = matches
        .get_one::<String>("output")
        .map_or_else(|| PathBuf::from("cage.yaml"), PathBuf::from);
    let force = matches.get_flag("force");
    if output.exists() && !force {
        eprintln!(
            "error: {} already exists (use --force to overwrite)",
            output.display()
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let isolation = matches
        .get_one::<String>("isolation")
        .cloned()
        .unwrap_or_else(|| {
            agentcage_core::config::HostProbe::default_isolation(&agentcage_cli::hostenv::RealHost)
        });
    let image = matches
        .get_one::<String>("image")
        .map_or("node:22-slim", String::as_str);
    let port = matches.get_one::<i64>("port").copied();

    let content = agentcage_cli::scaffold::render_config(
        &scaffolds,
        &agentcage_cli::scaffold::RenderRequest {
            name,
            image,
            isolation: &isolation,
            scaffold: scaffold.map(String::as_str),
            port,
        },
    )
    .map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;

    let meta = scaffold.and_then(|name| scaffolds.meta(name));
    let dest_dir = output.parent().filter(|p| !p.as_os_str().is_empty());
    let dest_dir = dest_dir.map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    // Every Containerfile this run would stage beside the config.
    let scaffold_dir = scaffold.and_then(|name| scaffolds.resolve(name));
    let mut staged_cfs: Vec<PathBuf> = Vec::new();
    if let (Some(meta), Some(dir)) = (meta.as_ref(), scaffold_dir.as_deref()) {
        for entry in &meta.build {
            if let Some(containerfile) = &entry.containerfile {
                let source = dir.join(containerfile);
                if source.is_file() {
                    staged_cfs.push(source);
                }
            }
        }
    }

    // The staging conflict check runs HERE, before the config is written
    // and before `run_scaffold_setup` builds anything. Refusing after
    // either would leave exactly the half-applied state this exists to
    // prevent: a cage.yaml naming the scaffold's image next to a
    // Containerfile that is not the scaffold's. See
    // `staging::stage_conflicts`.
    if let Some(scaffold) = scaffold.filter(|_| !force) {
        let conflicts: std::collections::BTreeSet<String> = staged_cfs
            .iter()
            .flat_map(|source| agentcage_cli::staging::stage_conflicts(source, &dest_dir, scaffold))
            .collect();
        if !conflicts.is_empty() {
            eprintln!(
                "error: {} already has files that differ from scaffold {}: {}\n  \
                 cage.yaml names the scaffold's image, but `cage create` would \
                 build these instead — the cage would not be the image its name \
                 claims. Move them aside, or pass --force to overwrite them.",
                dest_dir.display(),
                agentcage_core::python::repr_str(scaffold),
                conflicts.iter().cloned().collect::<Vec<_>>().join(", ")
            );
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }

    if let Err(error) = std::fs::write(&output, &content) {
        eprintln!("error: {}: {error}", output.display());
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    println!("Created {}", output.display());

    if let Some(scaffold) = scaffold.filter(|_| meta.is_some()) {
        agentcage_cli::scaffold::run_scaffold_setup(
            &scaffolds,
            ctx.runner.as_ref(),
            scaffold,
            &agentcage_cli::scaffold::SetupOptions {
                isolation: Some(&isolation),
                quiet: false,
                no_cache: false,
                pull: false,
            },
        )
        .map_err(|error| {
            agentcage_cli::output::step_fail(&error);
            ExitCode::from(EXIT_FAILURE)
        })?;

        // Freeze the scaffold's build context next to the config that
        // was just written, so `cage create -c <that config>` builds
        // from a tree the operator can see and edit — and so a
        // Containerfile that `COPY`s `AGENTS.md` resolves.
        //
        // `clobber` stays false so an operator's unrelated files (a
        // project README) survive, but `--force` must actually replace
        // the build inputs it was given permission to replace: a
        // refusal that then kept the stale file would be the original
        // bug with a prompt.
        for source in &staged_cfs {
            let build_context = source.parent().unwrap_or(Path::new("."));
            let clobber_names = if force {
                agentcage_cli::staging::build_inputs(source)
            } else {
                Vec::new()
            };
            if let Err(error) = agentcage_cli::staging::stage_build_context(
                build_context,
                &dest_dir,
                false,
                &clobber_names,
            ) {
                eprintln!("warning: could not stage the build context: {error}");
            }
            let _ = agentcage_cli::staging::stage_scaffold_assets(source, &dest_dir, scaffold);
        }
    }

    match meta.as_ref().filter(|meta| !meta.next_steps.is_empty()) {
        Some(meta) => {
            println!();
            println!("Next steps:");
            for (index, step) in meta.next_steps.iter().enumerate() {
                println!(
                    "  {}. {}",
                    index + 1,
                    format_step(step, name, &output, scaffold_dir.as_deref())
                );
            }
        }
        None if scaffold.is_none() => {
            println!();
            println!("Next steps:");
            println!(
                "  1. Edit {} — set your image, domains, and secrets",
                output.display()
            );
            println!("  2. agentcage cage create -c {}", output.display());
        }
        None => {}
    }
    Ok(())
}

/// `step.format(name=…, dest=…, scaffold_dir=…)`.
///
/// Three named fields and nothing else — no indexing, no format specs,
/// no positional arguments, because that is all `str.format` is ever
/// given here. A field this does not know is left in place rather than
/// raising, which is the one deliberate divergence: a scaffold author's
/// typo should not make `init` fail *after* the config has been written
/// and the image built.
fn format_step(step: &str, name: &str, dest: &Path, scaffold_dir: Option<&Path>) -> String {
    step.replace("{name}", name)
        .replace("{dest}", &dest.display().to_string())
        .replace(
            "{scaffold_dir}",
            &scaffold_dir.map_or_else(|| "None".to_owned(), |dir| dir.display().to_string()),
        )
}

/// The scaffold search path, or the one error that makes `init`
/// impossible.
fn scaffolds(ctx: &Ctx) -> Result<agentcage_cli::scaffold::Scaffolds, ExitCode> {
    agentcage_cli::scaffold::Scaffolds::system(ctx.runner.as_ref()).map_err(|error| {
        eprintln!("error: could not unpack the bundled scaffolds: {error}");
        ExitCode::from(EXIT_FAILURE)
    })
}
