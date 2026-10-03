//! The `agentcage` binary.
//!
//! # Why this crate exists
//!
//! Everything that talks to the world lives here: argument parsing, the
//! `CommandRunner` seam over `podman` / `systemctl` / `limactl` /
//! `container(1)`, the secret stores, terminal handling and every exit
//! code. [`agentcage_core`] is forbidden all of it, which is what makes
//! that crate testable by fixture diff. The split only pays off if this
//! side actually absorbs the mess, so when something here looks like it
//! could be pure, move it — do not weaken `agentcage-core`'s rules.
//!
//! It is also the only crate of the three that is a `[[bin]]`, so the
//! two libraries stay usable from tests, from benchmarks and from
//! whatever tooling wants them without dragging in a `main`.
//!
//! # What lives here now
//!
//! The clap command tree — see [`cli`], which replaces `cli.py`'s 5,632
//! lines with one module per command group. PR D5 built the whole parse
//! surface and wired every command to a stub; D6–D16 fill the bodies in,
//! each gated on the e2e phase that already covers it.
//!
//! `main` itself stays this short on purpose. Decide first, print last:
//! the tree and the dispatch are testable without spawning a process,
//! and this function is the only part that is not.

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    cli::dispatch(&args)
}
