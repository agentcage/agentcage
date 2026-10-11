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
//! The clap command tree — see [`cli`], one module per command group.
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
