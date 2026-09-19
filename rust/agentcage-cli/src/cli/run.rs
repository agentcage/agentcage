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

use clap::{Arg, Command};

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
