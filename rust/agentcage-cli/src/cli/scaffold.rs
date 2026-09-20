//! `agentcage scaffold <command>` — user-authored cage templates.
//!
//! The only group in the tree that is a plain `click.Group` rather than
//! an `AliasGroup`: it publishes no aliases, and so prints no "Aliases:"
//! section. It also lives in its own Python module (`scaffold_cli.py`)
//! and is attached with `main.add_command(scaffold)`, which is why a
//! grep for `@main.group` in `cli.py` misses it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgMatches, Command};

use crate::cli::context::{Ctx, EXIT_FAILURE};

use crate::cli::args::{TEXT, flag, group, leaf, positional, value_opt};

/// `scaffold create`'s docstring, verbatim (minus click's `\\x08`).
const CREATE_LONG: &str = "\
Create a new user scaffold.

Examples:
  agentcage scaffold create my-agent
  agentcage scaffold create my-claude --from claude-code";

/// The `scaffold` group.
pub(crate) fn command() -> Command {
    group("scaffold")
        .about("Create and manage custom scaffolds.")
        .subcommand(create())
        .subcommand(
            leaf("delete")
                .about("Delete a user scaffold.")
                .arg(positional("name", "NAME"))
                .arg(flag("yes", "yes", "Skip confirmation.").short('y')),
        )
        .subcommand(
            leaf("edit")
                .about("Open a user scaffold in $EDITOR.")
                .arg(positional("name", "NAME")),
        )
        .subcommand(
            leaf("export")
                .about("Export a scaffold to a directory.")
                .arg(positional("name", "NAME"))
                .arg(positional("dest", "DEST")),
        )
        .subcommand(leaf("list").about("List all available scaffolds."))
        .subcommand(
            leaf("show")
                .about("Show details of a scaffold.")
                .arg(positional("name", "NAME")),
        )
}

/// `scaffold create NAME`.
fn create() -> Command {
    leaf("create")
        .about("Create a new user scaffold.")
        .long_about(CREATE_LONG)
        .arg(positional("name", "NAME"))
        .arg(value_opt(
            "from_scaffold",
            "from",
            TEXT,
            "Fork an existing scaffold as starting point.",
        ))
        .arg(flag("force", "force", "Overwrite existing scaffold."))
}

// ── the bodies ───────────────────────────────────────────────

/// `scaffold_cli.scaffold_create`.
pub(crate) fn create_main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let Ok(scaffolds) = resolve_search_path(ctx) else {
        return ExitCode::from(EXIT_FAILURE);
    };
    let name = named(matches, "name");
    if !agentcage_cli::scaffold::valid_scaffold_name(&name) {
        eprintln!(
            "error: name must be 1-63 lowercase alphanumeric characters or \
             hyphens, starting with a letter or digit (got: {})",
            agentcage_core::python::repr_str(&name)
        );
        return ExitCode::from(EXIT_FAILURE);
    }

    let dest = scaffolds.user_dir().join(&name);
    if dest.exists() && !matches.get_flag("force") {
        eprintln!(
            "error: scaffold {} already exists at {}\n  Use --force to overwrite.",
            agentcage_core::python::repr_str(&name),
            dest.display()
        );
        return ExitCode::from(EXIT_FAILURE);
    }

    if let Some(from) = matches.get_one::<String>("from_scaffold") {
        let Some(source) = scaffolds.resolve(from) else {
            let available = scaffolds.list();
            eprintln!(
                "error: scaffold {} not found (available: {})",
                agentcage_core::python::repr_str(from),
                if available.is_empty() {
                    "none".to_owned()
                } else {
                    available.join(", ")
                }
            );
            return ExitCode::from(EXIT_FAILURE);
        };
        if let Err(code) = replace_tree(&dest, |dest| copy_tree(&source, dest)) {
            return code;
        }
        println!(
            "Created scaffold {} from {}",
            agentcage_core::python::repr_str(&name),
            agentcage_core::python::repr_str(from)
        );
    } else {
        let starter = scaffolds.templates_dir().join("scaffold-starter");
        if let Err(code) = replace_tree(&dest, |dest| expand_starter(&starter, dest, &name)) {
            return code;
        }
        println!(
            "Created scaffold {}",
            agentcage_core::python::repr_str(&name)
        );
    }

    println!("  {}/", dest.display());
    println!();
    println!("Edit your scaffold, then use it:");
    println!("  agentcage run {name}");
    println!("  agentcage init my-cage --scaffold {name}");
    ExitCode::SUCCESS
}

/// `scaffold_cli.scaffold_list` — the four-column table.
pub(crate) fn list_main(ctx: &Ctx) -> ExitCode {
    let Ok(scaffolds) = resolve_search_path(ctx) else {
        return ExitCode::from(EXIT_FAILURE);
    };
    let names = scaffolds.list();
    if names.is_empty() {
        println!("No scaffolds available.");
        return ExitCode::SUCCESS;
    }
    let rows: Vec<[String; 4]> = names
        .iter()
        .map(|name| {
            let meta = scaffolds.meta(name).unwrap_or_default();
            [
                name.clone(),
                scaffolds.source(name).label().to_owned(),
                meta.lifecycle,
                meta.description,
            ]
        })
        .collect();
    let headers = ["NAME", "SOURCE", "LIFECYCLE", "DESCRIPTION"];
    // `max(len(h), max(len(r[i]) for r in rows))` — character counts,
    // not bytes, because a description may hold a non-ASCII character
    // and the Python measures a `str`.
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            rows.iter()
                .map(|row| row[index].chars().count())
                .chain(std::iter::once(header.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    println!("{}", join_padded(&headers.map(str::to_owned), &widths));
    for row in &rows {
        println!("{}", join_padded(row, &widths));
    }
    ExitCode::SUCCESS
}

/// `scaffold_cli.scaffold_show`.
pub(crate) fn show_main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let Ok(scaffolds) = resolve_search_path(ctx) else {
        return ExitCode::from(EXIT_FAILURE);
    };
    let name = named(matches, "name");
    let Some(dir) = scaffolds.resolve(&name) else {
        return not_found(&name);
    };
    let meta = scaffolds.meta(&name).unwrap_or_default();

    println!("Scaffold: {name}");
    println!("Source:   {}", scaffolds.source(&name).label());
    println!("Path:     {}", dir.display());
    if !meta.description.is_empty() {
        println!("Description: {}", meta.description);
    }
    if !meta.lifecycle.is_empty() {
        println!("Lifecycle: {}", meta.lifecycle);
    }
    if !meta.build.is_empty() {
        println!();
        println!("Build steps:");
        for entry in &meta.build {
            if let Some(containerfile) = &entry.containerfile {
                println!("  - build {} from {containerfile}", entry.image);
            } else if let Some(url) = &entry.git {
                println!("  - clone {url} \u{2192} build {}", entry.image);
            }
        }
    }
    ExitCode::SUCCESS
}

/// `scaffold_cli.scaffold_edit`.
pub(crate) fn edit_main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let Ok(scaffolds) = resolve_search_path(ctx) else {
        return ExitCode::from(EXIT_FAILURE);
    };
    let name = named(matches, "name");
    let Some(dir) = scaffolds.resolve(&name) else {
        return not_found(&name);
    };
    if scaffolds.source(&name) == agentcage_cli::scaffold::Source::Builtin {
        eprintln!(
            "error: {} is a built-in scaffold and cannot be edited directly.\n  \
             Fork it first: agentcage scaffold create my-{name} --from {name}",
            agentcage_core::python::repr_str(&name)
        );
        return ExitCode::from(EXIT_FAILURE);
    }

    // `os.environ.get("EDITOR", os.environ.get("VISUAL", ""))` — EDITOR
    // wins, and an empty EDITOR is *set*, so VISUAL never gets a look in
    // that case. Reproduced, quirk included.
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_default();
    if editor.is_empty() {
        println!("Scaffold directory: {}", dir.display());
        println!("  Set $EDITOR to open it automatically.");
        return ExitCode::SUCCESS;
    }

    // A file, not the directory: vim and nano want a path they can open.
    let mut target = dir.join("cage.yaml.j2");
    if !target.exists() {
        target = dir.join("scaffold.yaml");
    }
    if !target.exists() {
        target.clone_from(&dir);
    }

    let Ok(mut argv) = agentcage_assets::shlex::split(&editor) else {
        eprintln!("error: $EDITOR is not a well-formed command: {editor}");
        return ExitCode::from(EXIT_FAILURE);
    };
    argv.push(target.display().to_string());
    let Some((editor_program, editor_args)) = argv.split_first() else {
        println!("Scaffold directory: {}", dir.display());
        println!("  Set $EDITOR to open it automatically.");
        return ExitCode::SUCCESS;
    };
    // The editor owns the terminal, so this is not `run` with captured
    // output — it inherits all three streams, as `subprocess.run` does.
    let command = agentcage_exec::Command::new(editor_program.clone()).args(editor_args.to_vec());
    let _ = ctx.runner.run(&command);
    ExitCode::SUCCESS
}

/// `scaffold_cli.scaffold_delete`.
pub(crate) fn delete_main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let Ok(scaffolds) = resolve_search_path(ctx) else {
        return ExitCode::from(EXIT_FAILURE);
    };
    let name = named(matches, "name");
    let target = scaffolds.user_dir().join(&name);

    // A built-in is undeletable *unless* the user has their own copy
    // shadowing it — then this removes the copy and the built-in comes
    // back.
    if scaffolds.is_builtin(&name) && !target.join("cage.yaml.j2").exists() {
        eprintln!(
            "error: {} is a built-in scaffold and cannot be deleted.",
            agentcage_core::python::repr_str(&name)
        );
        return ExitCode::from(EXIT_FAILURE);
    }
    if !target.exists() {
        eprintln!(
            "error: no user scaffold {} at {}",
            agentcage_core::python::repr_str(&name),
            target.display()
        );
        return ExitCode::from(EXIT_FAILURE);
    }
    if !matches.get_flag("yes")
        && !confirm(&format!(
            "Delete scaffold {} at {}?",
            agentcage_core::python::repr_str(&name),
            target.display()
        ))
    {
        eprintln!("Aborted!");
        return ExitCode::from(EXIT_FAILURE);
    }
    if let Err(error) = std::fs::remove_dir_all(&target) {
        eprintln!("error: {}: {error}", target.display());
        return ExitCode::from(EXIT_FAILURE);
    }
    println!(
        "Deleted scaffold {}",
        agentcage_core::python::repr_str(&name)
    );
    ExitCode::SUCCESS
}

/// `scaffold_cli.scaffold_export`.
pub(crate) fn export_main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let Ok(scaffolds) = resolve_search_path(ctx) else {
        return ExitCode::from(EXIT_FAILURE);
    };
    let name = named(matches, "name");
    let Some(source) = scaffolds.resolve(&name) else {
        return not_found(&name);
    };
    let dest_root = PathBuf::from(named(matches, "dest"));
    let dest = dest_root.join(&name);
    if dest.exists() {
        eprintln!("error: {} already exists", dest.display());
        return ExitCode::from(EXIT_FAILURE);
    }
    if let Err(error) = std::fs::create_dir_all(&dest_root).and_then(|()| copy_tree(&source, &dest))
    {
        eprintln!("error: {}: {error}", dest.display());
        return ExitCode::from(EXIT_FAILURE);
    }
    println!(
        "Exported {} to {}",
        agentcage_core::python::repr_str(&name),
        dest.display()
    );
    ExitCode::SUCCESS
}

// ── helpers ──────────────────────────────────────────────────

fn resolve_search_path(ctx: &Ctx) -> Result<agentcage_cli::scaffold::Scaffolds, ()> {
    agentcage_cli::scaffold::Scaffolds::system(ctx.runner.as_ref()).map_err(|error| {
        eprintln!("error: could not unpack the bundled scaffolds: {error}");
    })
}

fn named(matches: &ArgMatches, id: &str) -> String {
    matches.get_one::<String>(id).cloned().unwrap_or_default()
}

fn not_found(name: &str) -> ExitCode {
    eprintln!(
        "error: scaffold {} not found",
        agentcage_core::python::repr_str(name)
    );
    ExitCode::from(EXIT_FAILURE)
}

/// `if dest.exists(): shutil.rmtree(dest)` then build it afresh.
fn replace_tree(
    dest: &Path,
    build: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), ExitCode> {
    if dest.exists() {
        if let Err(error) = std::fs::remove_dir_all(dest) {
            eprintln!("error: {}: {error}", dest.display());
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }
    if let Some(parent) = dest.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("error: {}: {error}", parent.display());
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }
    build(dest).map_err(|error| {
        eprintln!("error: {}: {error}", dest.display());
        ExitCode::from(EXIT_FAILURE)
    })
}

/// The starter template, with `{{SCAFFOLD_NAME}}` substituted.
///
/// Top-level *files* only, as the Python's `for src_file in
/// _STARTER_DIR.iterdir(): if src_file.is_file()` does.
fn expand_starter(starter: &Path, dest: &Path, name: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    let mut entries: Vec<_> = std::fs::read_dir(starter)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if !entry.file_type()?.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(entry.path())?;
        std::fs::write(
            dest.join(entry.file_name()),
            text.replace("{{SCAFFOLD_NAME}}", name),
        )?;
    }
    Ok(())
}

/// `shutil.copytree` — files, directories and modes.
fn copy_tree(source: &Path, dest: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
            let mode = std::fs::metadata(&from)?.permissions().mode();
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

/// `"  ".join(v.ljust(w) for v, w in zip(row, widths))`.
///
/// Python's `str.ljust` never truncates and pads by *characters*, and
/// the trailing column keeps its padding — which is what makes a
/// `scaffold list` diff against the Python's output byte-exact rather
/// than nearly so.
fn join_padded(row: &[String; 4], widths: &[usize]) -> String {
    let mut out = String::new();
    for (index, value) in row.iter().enumerate() {
        if index > 0 {
            out.push_str("  ");
        }
        out.push_str(value);
        let width = widths.get(index).copied().unwrap_or(0);
        for _ in value.chars().count()..width {
            out.push(' ');
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::join_padded;

    /// `str.ljust` pads the last column too — a table whose rows end
    /// with trailing spaces is what the Python prints.
    #[test]
    fn the_table_pads_the_way_python_does() {
        let row = [
            "openclaw".to_owned(),
            "built-in".to_owned(),
            "service".to_owned(),
            "x".to_owned(),
        ];
        assert_eq!(
            join_padded(&row, &[10, 8, 9, 11]),
            "openclaw    built-in  service    x          "
        );
    }
}
