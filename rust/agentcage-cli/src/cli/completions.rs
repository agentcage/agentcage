//! Shell completions — the one place the port *adds* to the surface.
//!
//! # Why this exists, and why it is hidden
//!
//! click ships completion without a command. Every click program
//! responds to a private environment protocol: `_AGENTCAGE_COMPLETE=
//! bash_source agentcage` prints the bash script, and the printed script
//! re-invokes the binary with `_AGENTCAGE_COMPLETE=bash_complete` on
//! every Tab. agentcage once had an `agentcage completions <shell>`
//! wrapper and **deliberately deleted it** — the CHANGELOG entry
//! (v0.19.0) says it "added zero capability over upstream and created a
//! maintenance surface that could drift from Click".
//!
//! clap has no equivalent that is stable: `clap_complete::CompleteEnv`
//! does implement an env protocol, but it is behind the crate's
//! `unstable-dynamic` feature, and a shipped CLI should not have its
//! completion story behind a feature flag that can change shape in a
//! patch release. So the deleted wrapper comes back, as the least-bad of
//! the options, and it comes back **hidden**: it is not in `cli.py`'s
//! surface, and `tests/cli_surface.rs` allows it by name rather than by
//! loosening the "every command matches" assertion.
//!
//! # What a reviewer should check at cutover
//!
//! Nothing in the repo references the click protocol today — not
//! `install.sh`, not `docs/**` (the `docs/cli.md#shell-completion`
//! section the CHANGELOG points at is gone), not the e2e harness. So no
//! install path breaks. What *does* change is the instruction a user who
//! already set this up followed: anyone with
//! `eval "$(_AGENTCAGE_COMPLETE=zsh_source agentcage)"` in their
//! `.zshrc` gets an empty completion function after F2, silently. That
//! belongs in the F2/F5 release notes, and it is not fixed here.

use std::io;

use clap::{Arg, Command};
use clap_complete::Shell;

use crate::cli::args::leaf;

/// The shells `clap_complete` generates for, as the user spells them.
pub(crate) const SHELLS: [&str; 3] = ["bash", "zsh", "fish"];

/// `agentcage completions <SHELL>` — hidden, per the module docs.
pub(crate) fn command() -> Command {
    leaf("completions")
        .hide(true)
        .about("Print a shell completion script (bash, zsh or fish).")
        .arg(
            Arg::new("shell")
                .required(true)
                .value_name("SHELL")
                .value_parser(SHELLS),
        )
}

/// Write the completion script for `shell` to `out`.
///
/// Takes the root command by value because `clap_complete` needs a
/// `&mut Command` and mutates its internals while generating.
pub(crate) fn generate(shell: &str, mut root: Command, out: &mut dyn io::Write) {
    let shell: Shell = shell
        .parse()
        .unwrap_or_else(|_| unreachable!("value_parser restricts this to {SHELLS:?}"));
    let name = root.get_name().to_string();
    clap_complete::generate(shell, &mut root, name, out);
}
