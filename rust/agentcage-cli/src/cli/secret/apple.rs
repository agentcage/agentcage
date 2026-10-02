//! The `apple-container` half of the `secret` group.
//!
//! `cli._is_apple_container` (`cli.py:68`),
//! `cli._apple_secret_names` (`cli.py:121`) and
//! `cli._apple_restart_if_running` (`cli.py:187`) — the three helpers
//! the four command bodies branch into, collected here because they
//! only make sense together and because each body's apple half is two
//! or three lines once they exist.
//!
//! # Why this backend needs a half of its own at all
//!
//! The other half of every body drives **host podman's** secret store:
//! `podman secret ls` for the names, `podman secret rm` for a removal,
//! and the staged-secrets bind mount of the running egress container
//! for a zero-restart apply. An apple cage has none of those. Its
//! values live in the macOS keychain (or, under
//! `secrets.allow_plaintext`, in `pending_secrets.json`) and are read
//! back through [`agentcage_cli::secrets::resolve_store`]; its
//! containers are Apple microVMs that host podman has never heard of.
//!
//! So asking podman anything about an apple cage does not fail — it
//! answers, wrongly. `podman secret ls` lists nothing, so every
//! declared key reads `MISSING`; `podman secret exists` says no, so a
//! secret that is really there is reported absent; and
//! `services::cage_has_live_secret_channel` inspects a container name
//! podman does not have and concludes there is no live channel. That
//! is the distinction `require_store_backend` draws in
//! [`super`]: wrong, rather than merely unimplemented.
//!
//! # And why there is no live-apply path here
//!
//! There is nowhere to stage to. The staged-secrets directory is
//! populated by [`crate::apple::backend::AppleBackend`]'s
//! `stage_secrets` at `start()` and **wiped** as soon as the egress has
//! read it (the durable copy is the keychain's), so writing a value
//! into it on a running cage would reach nothing. The Python does not
//! try: `secret_set`'s apple branch calls
//! [`restart_if_running`] instead of `_apply_secret_live_or_restart`,
//! and so does every other body here. Cycling the cage *is* the apply
//! on this backend.

use agentcage_core::config::Config;

use crate::cli::context::Ctx;
use agentcage_cli::secrets::{
    Platform, SecretError, SecretHost, SecretStore, SystemEnv, resolve_store,
};

/// `cli._is_apple_container` — does this cage use the apple-container
/// isolation backend?
pub(crate) fn is_apple_container(config: &Config) -> bool {
    config.isolation == "apple-container"
}

/// Resolve the cage's store and hand it to `f`.
///
/// A closure rather than a returned store because the store borrows
/// the [`SecretHost`] it was resolved against, and the host borrows the
/// [`SystemEnv`] — two locals that a function returning the store would
/// have to leak to keep alive.
///
/// # The two arguments that are *not* passed, both deliberately
///
/// `podman` is [`None`]: `_store_secret(None, cfg, …)` is how both of
/// the Python's apple call sites spell it, and there is no host podman
/// store on this backend for it to mean anything.
///
/// `source_scheme` is empty, which is the load-bearing one. A rule
/// carrying `source: systemd-creds:` would otherwise select
/// [`agentcage_cli::secrets::SystemdCredsStore`] *by name*, skipping
/// the availability probe — and its `get` then fails on a Mac, where
/// the binary does not exist, for exactly the cages that asked for the
/// more careful spelling. `AppleBackend::stage_secrets` resolves the
/// store the same way and for the same reason; the scheme is
/// decorative on this backend, because what stands in for both the
/// systemd credential and the podman `Secret=` env is the staged file
/// the egress addon reads from `/home/acproxy/secrets/NAME`.
///
/// # Errors
///
/// [`SecretError`] from `resolve_store` — a cage whose
/// `secrets.backend` is unavailable and which has not opted into
/// plaintext has no store to reach at all.
fn with_store<T>(
    ctx: &Ctx,
    config: &Config,
    f: impl FnOnce(&dyn SecretStore) -> T,
) -> Result<T, SecretError> {
    let env = SystemEnv;
    let host = SecretHost::detect(ctx.runner.as_ref(), &env);
    let store = resolve_store(config, &host, None, "", Platform::host())?;
    Ok(f(store.as_ref()))
}

/// `cli._apple_secret_names` — the keys stored for this cage, through
/// its own backend.
///
/// The keychain keeps a name index at `<state>/secret_keys.json`
/// (`security find-generic-password` cannot enumerate by service) and
/// the plaintext store keeps the names in the file itself. Either way
/// these are **names only**: nothing here reads a value, and the
/// keychain is not asked for one.
///
/// An unresolvable store is an empty set, not an error — Python's
/// `except SecretStoreError: return set()`. `secret list` then reports
/// every declared key as `MISSING`, which is the honest answer for a
/// cage whose store cannot be opened.
pub(crate) fn secret_names(ctx: &Ctx, config: &Config, name: &str) -> Vec<String> {
    let state_dir = ctx.paths.deployment_dir(name);
    match with_store(ctx, config, |store| store.names(name, &state_dir)) {
        Ok(Ok(names)) => names,
        // The inner `Err` is the one the Python does *not* swallow — it
        // only wraps `resolve_store`. It stays folded in here because
        // neither store this backend can resolve to has a fallible
        // `names`: both answer from a file and treat a missing or
        // corrupt one as empty, by design (a broken index must not make
        // the cage unusable). There is no reachable case to report.
        Ok(Err(_)) | Err(_) => Vec::new(),
    }
}

/// Forget `key`, through the cage's own backend.
///
/// # Errors
///
/// [`SecretError`] when the store could not be resolved or the removal
/// failed. The Python lets both raise — `resolve_store(cfg).delete(…)`
/// is unguarded at `cli.py:4307` — so this is the port's refusal
/// standing in for a traceback, in the same spirit as
/// `set::rules_for_append`'s.
pub(crate) fn delete(ctx: &Ctx, config: &Config, name: &str, key: &str) -> Result<(), SecretError> {
    let state_dir = ctx.paths.deployment_dir(name);
    with_store(ctx, config, |store| store.delete(name, key, &state_dir))?
}

/// `cli._apple_restart_if_running` — cycle the cage so a changed secret
/// takes effect, and do nothing at all if it is not up.
///
/// `stage_secrets` runs only at `start()`, so an edit to a running
/// cage's secrets is a no-op until the cage cycles — and an edit to a
/// *stopped* cage needs nothing, because the next start re-stages every
/// value from the store.
///
/// Silence on the stopped path is the Python's and is worth naming,
/// because the container path is not silent: `rotate-placeholders`
/// prints "Cage is not running — the new placeholders apply on next
/// start." there and nothing at all here. Reproduced rather than
/// evened out — what this port is judged against is the Python's
/// output, line for line, and a reassurance no Python release printed
/// would be this port inventing one.
///
/// `config.name` is the cage addressed, not the state directory's name:
/// a cage's stored config owns the name its containers carry.
pub(crate) fn restart_if_running(ctx: &Ctx, config: &Config) {
    let cage = &config.name;
    if !ctx.backend_for(&config.isolation).is_running(cage, "cage") {
        return;
    }
    println!("Restarting cage '{cage}'...");
    super::live::restart(ctx, cage);
}

#[cfg(test)]
mod tests {
    use super::{delete, is_apple_container, restart_if_running, secret_names};
    use crate::cli::context::Ctx;
    use agentcage_core::config::Config;
    use agentcage_exec::{FakeRunner, Reply};
    use agentcage_state::{Paths, TestDir};

    /// An apple cage pinned to the plaintext store.
    ///
    /// `backend: plaintext` is not decoration: it is what keeps every
    /// test in this module away from `security(1)`. An apple cage on
    /// `auto` resolves [`agentcage_cli::secrets::KeychainStore`], whose
    /// writability probe adds a generic password to the operator's
    /// **real login keychain** and deletes it again — which raises an
    /// access dialog on a machine with a GUI session. Naming the
    /// backend skips the probe entirely; `assert_eq!(fake.call_count(),
    /// 0)` below is the mechanical proof that it did.
    fn apple_config(name: &str) -> Config {
        let mut config = Config {
            name: name.to_owned(),
            isolation: "apple-container".to_owned(),
            ..Config::default()
        };
        config.secrets.backend = "plaintext".to_owned();
        config
    }

    fn ctx_under(dir: &std::path::Path, fake: FakeRunner) -> Ctx {
        Ctx {
            paths: Paths::under(dir),
            runner: Box::new(fake),
            version: agentcage_core::VERSION.to_owned(),
        }
    }

    #[test]
    fn only_the_apple_isolation_is_apple() {
        assert!(is_apple_container(&apple_config("a")));
        let mut container = Config {
            isolation: "container".to_owned(),
            ..Config::default()
        };
        assert!(!is_apple_container(&container));
        container.isolation = "vm".to_owned();
        assert!(!is_apple_container(&container));
    }

    /// The names come out of the store's own file, and no subprocess is
    /// run to get them — not `podman secret ls`, not `security`.
    #[test]
    fn names_are_read_from_the_store_and_not_from_podman() {
        let dir = TestDir::new("apple-secret-names");
        let fake = FakeRunner::new();
        let ctx = ctx_under(dir.path(), fake.clone());
        let config = apple_config("acme");

        let state_dir = ctx.paths.deployment_dir("acme");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        assert!(secret_names(&ctx, &config, "acme").is_empty());

        std::fs::write(
            state_dir.join("pending_secrets.json"),
            r#"[["API_KEY", "v1"], ["OTHER", "v2"]]"#,
        )
        .expect("the store's file");
        assert_eq!(
            secret_names(&ctx, &config, "acme"),
            vec!["API_KEY".to_owned(), "OTHER".to_owned()]
        );

        // The point of the whole module: nothing was asked of podman,
        // and nothing was asked of `security`.
        assert_eq!(fake.call_count(), 0, "{:?}", fake.argv_sequence());
    }

    /// A store that cannot be resolved is an empty set, not a panic and
    /// not a wrong answer.
    #[test]
    fn an_unresolvable_store_reports_no_names() {
        let dir = TestDir::new("apple-secret-names-refused");
        let fake = FakeRunner::new();
        fake.assume_missing();
        let ctx = ctx_under(dir.path(), fake.clone());
        let mut config = apple_config("acme");
        // `systemd-creds` on a Mac: named explicitly, so `resolve_store`
        // probes it rather than falling back, and the probe cannot
        // succeed with no binary. The same refusal `auto` would reach
        // on a host with no encrypting backend and no
        // `allow_plaintext`.
        config.secrets.backend = "systemd-creds".to_owned();

        let state_dir = ctx.paths.deployment_dir("acme");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(
            state_dir.join("pending_secrets.json"),
            r#"[["API_KEY", "v1"]]"#,
        )
        .expect("the store's file");

        assert!(secret_names(&ctx, &config, "acme").is_empty());
        assert!(
            delete(&ctx, &config, "acme", "API_KEY").is_err(),
            "a refused store cannot delete either"
        );
    }

    /// `delete` goes to the store's file, and leaves its neighbours.
    #[test]
    fn delete_removes_one_key_from_the_store() {
        let dir = TestDir::new("apple-secret-delete");
        let fake = FakeRunner::new();
        let ctx = ctx_under(dir.path(), fake.clone());
        let config = apple_config("acme");

        let state_dir = ctx.paths.deployment_dir("acme");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(
            state_dir.join("pending_secrets.json"),
            r#"[["API_KEY", "v1"], ["OTHER", "v2"]]"#,
        )
        .expect("the store's file");

        delete(&ctx, &config, "acme", "API_KEY").expect("the plaintext store deletes");
        assert_eq!(
            secret_names(&ctx, &config, "acme"),
            vec!["OTHER".to_owned()]
        );
        assert_eq!(fake.call_count(), 0, "{:?}", fake.argv_sequence());
    }

    /// A stopped apple cage is asked exactly once whether it is up, and
    /// is then left alone.
    ///
    /// The argv is the assertion: one `container inspect <cage>` and no
    /// `container stop`, which is what "silent and does nothing" has to
    /// mean for a command whose only other option is a restart.
    #[test]
    fn a_stopped_cage_is_not_restarted() {
        let dir = TestDir::new("apple-secret-stopped");
        let fake = FakeRunner::new();
        fake.assume_installed();
        // `container inspect` on a container that is not there exits
        // non-zero, which `AppleContainer::inspect` reads as `None`.
        fake.push(Reply::status(1));
        let ctx = ctx_under(dir.path(), fake.clone());

        restart_if_running(&ctx, &apple_config("acme"));

        let argv = fake.argv(0);
        assert!(argv[0].ends_with("container"), "{argv:?}");
        assert_eq!(&argv[1..], ["inspect", "acme"], "{argv:?}");
        assert_eq!(fake.call_count(), 1, "{:?}", fake.argv_sequence());
    }
}
