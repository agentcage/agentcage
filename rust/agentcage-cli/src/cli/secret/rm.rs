//! `agentcage secret rm NAME KEY` — forget a value, everywhere it is
//! kept.
//!
//! `cli.py:3997`.

use std::process::ExitCode;

use agentcage_core::config::Config;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE};
use crate::cli::secret::{apple, open_cage, require_store_backend};

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match run(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// Removal is from **three** places, and all three matter.
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
/// The third is the value **at rest** when the runtime is not what
/// holds it — see [`agentcage_cli::secrets::at_rest_store`]. Those two
/// above are the container backend's two places; a vm cage on a Mac
/// resolves to the login keychain, which neither of them touches. That
/// is why `secret rm` used to report success on such a cage and leave
/// the value behind, and why the next `cage restart` put it straight
/// back — measured, on real hardware.
///
/// Removing only some of the three is how a "removed" credential comes
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
    require_store_backend(&config, &name)?;
    if apple::is_apple_container(&config) {
        return remove_apple(ctx, &config, &name, &key);
    }

    let podman = agentcage_cli::cage_podman::CagePodman::for_cage(
        ctx.runner.as_ref(),
        &config.isolation,
        &name,
    );
    let full = format!("{name}.{key}");
    let cred = ctx.paths.cred_path(&name, &key);
    let state_dir = ctx.paths.deployment_dir(&name);

    let had_cred = cred.is_file();
    let had_store = podman.secret_exists(&full).unwrap_or(false);

    let env = agentcage_cli::secrets::SystemEnv;
    let host = agentcage_cli::secrets::SecretHost::detect(ctx.runner.as_ref(), &env);
    let at_rest = agentcage_cli::secrets::at_rest_store(
        &config,
        &host,
        Some(&podman),
        agentcage_cli::secrets::Platform::host(),
    );
    let had_at_rest = at_rest.as_ref().is_some_and(|store| {
        agentcage_cli::secrets::at_rest_names(store.as_ref(), &name, &state_dir)
            .iter()
            .any(|n| n == &key)
    });

    if !had_cred && !had_store && !had_at_rest {
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
    if had_at_rest {
        let store = at_rest.as_ref().expect("checked above");
        if let Err(error) = store.delete(&name, &key, &state_dir) {
            // Reported, not fatal: the runtime copies are already gone,
            // so the secret has stopped being injected either way. The
            // operator needs to know the at-rest copy survived, because
            // the next start would otherwise restore it silently.
            eprintln!(
                "warning: could not remove '{full}' from the {} store: {error}",
                store.name()
            );
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

/// `secret_rm`'s apple branch (`cli.py:4297`) — removal from one place,
/// because there is only one.
///
/// Nothing of the container path applies. There is no `.cred` blob to
/// resurrect the value from (`systemd-creds` is not reachable from a
/// Mac host), no podman store entry to drop, and no dangling
/// `Secret=<cage>.<KEY>` line to converge away — this backend's units
/// are a metadata snapshot, and the next `start()` re-stages from
/// whatever the store holds *then*. So the whole removal is the
/// store's `delete`, and the only thing left is to cycle the cage so a
/// still-running one stops seeing the value.
///
/// The existence check reads the store's name index rather than
/// probing the keychain: `security find-generic-password` cannot
/// enumerate by service, which is why that index exists at all. The
/// message it guards names the cage — `does not exist for '<cage>'` —
/// where the container path's names the qualified secret. Both
/// spellings are the Python's.
fn remove_apple(ctx: &Ctx, config: &Config, name: &str, key: &str) -> Result<(), ExitCode> {
    if !apple::secret_names(ctx, config, name)
        .iter()
        .any(|stored| stored == key)
    {
        eprintln!("error: secret '{key}' does not exist for '{name}'");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    if let Err(error) = apple::delete(ctx, config, name, key) {
        // `resolve_store(cfg).delete(...)` is unguarded in the Python
        // and would raise here; a refusal carrying the store's own
        // complaint is this port's standing answer to a traceback.
        eprintln!(
            "error: failed to remove secret '{key}': {}",
            error.message()
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    println!("Secret '{key}' removed from '{name}'.");
    apple::restart_if_running(ctx, config);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::remove_apple;
    use crate::cli::context::Ctx;
    use agentcage_core::config::Config;
    use agentcage_exec::{FakeRunner, Reply};
    use agentcage_state::{Paths, TestDir};

    /// An apple cage pinned to the plaintext store, so that resolving
    /// it never probes the operator's real login keychain. See
    /// [`crate::cli::secret::apple`]'s tests for why that matters.
    fn apple_config() -> Config {
        let mut config = Config {
            name: "acme".to_owned(),
            isolation: "apple-container".to_owned(),
            ..Config::default()
        };
        config.secrets.backend = "plaintext".to_owned();
        config
    }

    /// A key that is not in the store is refused before anything is
    /// removed, and a key that is in it goes — from the store, and from
    /// nowhere else.
    #[test]
    fn apple_rm_refuses_an_unknown_key_and_removes_a_known_one() {
        let dir = TestDir::new("secret-rm-apple");
        let fake = FakeRunner::new();
        fake.assume_installed();
        // Every `container inspect`: the cage is not running, so the
        // removal is not followed by a restart.
        fake.default_reply(Reply::status(1));
        let ctx = Ctx {
            paths: Paths::under(dir.path()),
            runner: Box::new(fake.clone()),
            version: agentcage_core::VERSION.to_owned(),
        };
        let config = apple_config();
        let state_dir = ctx.paths.deployment_dir("acme");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(
            state_dir.join("pending_secrets.json"),
            r#"[["API_KEY", "v1"], ["OTHER", "v2"]]"#,
        )
        .expect("the store's file");

        assert!(remove_apple(&ctx, &config, "acme", "NOPE").is_err());
        // A refusal is a refusal: nothing was asked of the host, and
        // the store still holds both keys.
        assert_eq!(fake.call_count(), 0, "{:?}", fake.argv_sequence());

        remove_apple(&ctx, &config, "acme", "API_KEY").expect("a stored key is removed");
        let left = std::fs::read_to_string(state_dir.join("pending_secrets.json")).expect("read");
        assert!(!left.contains("API_KEY"), "{left}");
        assert!(left.contains("OTHER"), "{left}");

        // The only subprocess the whole removal runs is the
        // is-it-running probe — no `podman secret rm`, no `security`.
        let argv = fake.argv(0);
        assert!(argv[0].ends_with("container"), "{argv:?}");
        assert_eq!(&argv[1..], ["inspect", "acme"], "{argv:?}");
        assert_eq!(fake.call_count(), 1, "{:?}", fake.argv_sequence());
    }

    /// A `vm` cage whose at-rest store is a file: the key goes from
    /// there too, not just from the two places the container backend
    /// keeps a value.
    ///
    /// `ApplePlaintextStore` stands in for the keychain here — it is
    /// the other store whose `runtime_decrypts()` is false, and it is
    /// the one a test can drive without touching the operator's real
    /// login keychain. The code under test reads the flag, not the
    /// store's name.
    fn vm_file_store_config() -> Config {
        let mut config = Config {
            name: "rsvm".to_owned(),
            isolation: "apple-container".to_owned(),
            ..Config::default()
        };
        config.secrets.backend = "plaintext".to_owned();
        config
    }

    /// The bug, as a unit: a key present **only** at rest used to be
    /// reported as "does not exist", so there was no way to remove it —
    /// and a key present in both was removed from the runtime copy
    /// alone, so the next start brought it back.
    #[test]
    fn a_key_that_exists_only_at_rest_is_found_and_removed() {
        let dir = TestDir::new("secret-rm-at-rest");
        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.default_reply(Reply::status(1));
        let ctx = Ctx {
            paths: Paths::under(dir.path()),
            runner: Box::new(fake.clone()),
            version: agentcage_core::VERSION.to_owned(),
        };
        let config = vm_file_store_config();
        let state_dir = ctx.paths.deployment_dir("rsvm");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(
            state_dir.join("pending_secrets.json"),
            r#"[["API_KEY", "v1"]]"#,
        )
        .expect("the store's file");

        // No podman copy anywhere: this cage was never deployed.
        let env = agentcage_cli::secrets::SystemEnv;
        let host = agentcage_cli::secrets::SecretHost::detect(ctx.runner.as_ref(), &env);
        let store = agentcage_cli::secrets::at_rest_store(
            &config,
            &host,
            None,
            agentcage_cli::secrets::Platform::host(),
        )
        .expect("a file-backed store is an at-rest store");
        assert_eq!(
            agentcage_cli::secrets::at_rest_names(store.as_ref(), "rsvm", &state_dir),
            ["API_KEY"],
            "the key is at rest and nowhere else"
        );

        store
            .delete("rsvm", "API_KEY", &state_dir)
            .expect("deletes");
        let left = std::fs::read_to_string(state_dir.join("pending_secrets.json")).expect("read");
        assert!(!left.contains("API_KEY"), "{left}");
    }
}
