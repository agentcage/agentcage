//! `cargo xtask` — repository maintenance tasks.
//!
//! - `check-invariants`: the static checks CI runs on every change
//!   ([`invariants`]).
//! - `check-docs`: live documentation against the CLI and VERSION
//!   ([`docs`]).
//! - `update-deps`: report (or apply) newer digests for the pinned
//!   container base images ([`deps`]).
//! - `gen-packaging`: render the Homebrew formula and the AUR `PKGBUILD`
//!   for a release ([`packaging`]).
//!
//! Each task works from the repository root, found from this crate's
//! manifest directory, so `cargo xtask` behaves the same from any
//! working directory inside the checkout.

mod deps;
mod docs;
mod invariants;
mod packaging;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// The command line.
#[derive(Debug, Parser)]
#[command(name = "cargo xtask", about = "agentcage repository tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

/// One task.
#[derive(Debug, Subcommand)]
enum Task {
    /// Check the repository invariants (what CI's `invariants` job runs).
    CheckInvariants {
        /// List what each check looked at.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Check live documentation against the CLI and the VERSION file.
    CheckDocs {
        /// List how many live documentation files were scanned.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Check the pinned container base images for newer digests.
    UpdateDeps {
        /// Rewrite the pins in place instead of only reporting.
        #[arg(long)]
        update: bool,
    },
    /// Render the Homebrew formula and the AUR PKGBUILD for a release.
    GenPackaging {
        /// The release version, with or without the leading `v`.
        #[arg(long)]
        version: String,
        /// A directory of built release assets (each with its `.sha256`).
        #[arg(
            long,
            conflicts_with = "from_release",
            required_unless_present = "from_release"
        )]
        dist: Option<PathBuf>,
        /// Read the checksums off the published GitHub release instead.
        #[arg(long)]
        from_release: bool,
        /// Where to write `agentcage.rb` and `PKGBUILD`.
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
}

/// The repository root: this crate lives at `rust/xtask`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is nested at rust/xtask inside the repository")
        .to_path_buf()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = repo_root();
    let result = match cli.task {
        Task::CheckInvariants { verbose } => invariants::run(&root, verbose),
        Task::CheckDocs { verbose } => docs::run(&root, verbose),
        Task::UpdateDeps { update } => deps::run(&root, update),
        Task::GenPackaging {
            version,
            dist,
            from_release,
            out,
        } => packaging::run(&version, dist.as_deref(), from_release, &out),
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}
