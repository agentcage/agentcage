//! `agentcage secret rm NAME KEY` — forget a value, everywhere it is
//! kept.
//!
//! `cli.py:3997`.

use std::process::ExitCode;

use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE};
use crate::cli::secret::{open_cage, require_container};

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match run(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// Removal is from **two** places, and both matter.
///
/// A `systemd-creds`-backed secret lives as a `.cred` blob in the
/// cage's state directory; the podman store entry only materializes
/// when the egress's decrypt `ExecStartPre` runs at start. So:
///
/// * a lingering `.cred` would resurrect the secret — and its staged
///   value — on the next egress start, and
/// * a secret set live on a running cage may have no store entry at
///   all yet.
///
/// Removing only one of the two is how a "removed" credential comes
/// back.
fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let key = matches
        .get_one::<String>("key")
        .expect("required by the parser")
        .clone();

    let config = open_cage(ctx, &name, false)?;
    require_container(&config, &name)?;

    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    let full = format!("{name}.{key}");
    let cred = ctx.paths.cred_path(&name, &key);

    let had_cred = cred.is_file();
    let had_store = podman.secret_exists(&full).unwrap_or(false);
    if !had_cred && !had_store {
        eprintln!("error: secret '{full}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    if had_store {
        let _ = podman.secret_remove(&full);
    }
    if had_cred {
        if let Err(error) = std::fs::remove_file(&cred) {
            eprintln!("error: {}: {error}", cred.display());
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }
    println!("Secret '{full}' removed.");

    // The empty value is a tombstone: the injector skips the rule
    // rather than falling back to the stale value frozen in the egress
    // process environment. It also re-converges the units, which is
    // what drops the now-dangling `Secret=<cage>.<KEY>` line — a cage
    // whose quadlet names a store entry that no longer exists fails to
    // start with `no secret with name or ID ...` (issue #262).
    crate::cli::secret::live::apply_or_restart(ctx, &name, &key, "");
    Ok(())
}
