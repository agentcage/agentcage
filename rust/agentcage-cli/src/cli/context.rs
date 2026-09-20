//! What every command body needs before it can do anything: the state
//! roots, a way to run subprocesses, and the version string.
//!
//! `cli.py` reaches for these as module-level globals — `state` is
//! imported, `Podman()` is constructed at each call site, and
//! `version("agentcage")` is looked up wherever it is wanted. Threading
//! them instead is what makes a command body testable against a
//! `FakeRunner` and a `TestDir`.

use std::process::ExitCode;

use agentcage_core::config::Config;
use agentcage_exec::{CommandRunner, SystemRunner};
use agentcage_state::Paths;

use agentcage_cli::backend::ContainerBackend;

/// `EX_SOFTWARE`-free: this is click's `sys.exit(1)`, the status every
/// operator-facing refusal in `cli.py` uses.
pub(crate) const EXIT_FAILURE: u8 = 1;

/// The process-wide handles a command body runs against.
pub(crate) struct Ctx {
    /// The state roots.
    pub(crate) paths: Paths,
    /// The subprocess seam.
    pub(crate) runner: Box<dyn CommandRunner>,
    /// `importlib.metadata.version("agentcage")`.
    pub(crate) version: String,
}

impl Ctx {
    /// The real one: environment-derived paths, real subprocesses.
    #[must_use]
    pub(crate) fn system() -> Self {
        Self {
            paths: Paths::from_env(),
            runner: Box::new(SystemRunner::new()),
            version: agentcage_core::VERSION.to_owned(),
        }
    }

    /// A backend bound to this context.
    #[must_use]
    pub(crate) fn backend(&self) -> ContainerBackend<'_> {
        ContainerBackend::new(&self.paths, self.runner.as_ref(), &self.version)
    }

    /// `_ensure_backend_ready` — recover what can be recovered, then
    /// gate on prerequisites.
    ///
    /// Whatever is still unmet is reported under one header and the
    /// command aborts. The diagnostics already lived in the backend's
    /// `check_prerequisites`; nothing on the build path ran them, so a
    /// downed podman surfaced as a misleading "image not found".
    ///
    /// # Errors
    ///
    /// [`EXIT_FAILURE`] when a prerequisite is unmet.
    pub(crate) fn ensure_backend_ready(
        &self,
        config: &Config,
    ) -> Result<ContainerBackend<'_>, ExitCode> {
        let backend = self.backend();
        backend.ensure_ready();
        let issues = backend.check_prerequisites();
        if !issues.is_empty() {
            eprintln!(
                "error: prerequisites for the '{}' backend are not met:",
                config.isolation
            );
            for issue in issues {
                eprintln!("  - {issue}");
            }
            return Err(ExitCode::from(EXIT_FAILURE));
        }
        Ok(backend)
    }
}

/// `cli._parse_version` — `'X.Y[.Z…]'` to `(X, Y)`, `(0, 0)` on garbage.
///
/// One line, delegating, because there must be exactly one of these:
/// `cage list` and `cage prune` compare the same stamp the gate below
/// compares, and a second parser that rounded `"1"` differently would
/// annotate a cage as legacy that the gate then let through.
#[must_use]
pub(crate) fn parse_version(version: &str) -> (u32, u32) {
    agentcage_cli::preflight::parse_version(version)
}

/// `cli._ensure_v022_cage` — refuse to operate on a pre-v0.22 cage.
///
/// v0.22 collapsed the three-service shape (cage / proxy / dns) into
/// two (cage / egress). Every v0.22 command is wired to the new shape,
/// so running one against a legacy cage would either fail with a
/// confusing podman error or silently target the wrong workload.
///
/// `cage destroy` deliberately does **not** call this — it is the
/// documented escape hatch, and its filename enumeration covers both
/// shapes. `cage list` skips it too and annotates legacy entries inline.
///
/// The wording, the version parse and the "a malformed `metadata.json`
/// is exit 1, not exit 2" distinction all live in
/// [`agentcage_cli::preflight`], which `cage har` already reaches
/// through directly. This is the `ExitCode`-shaped face of it: the
/// `cli` bodies thread `Result<(), ExitCode>`, `har` threads a stream
/// and a `u8`, and neither should own a second copy of the message an
/// operator is told to follow.
///
/// # Errors
///
/// [`agentcage_cli::preflight::EXIT_LEGACY_CAGE`] (2), with the
/// migration procedure printed — except for a `metadata.json` that
/// exists and will not parse, which is
/// [`agentcage_cli::preflight::EXIT_NO_SUCH_CAGE`] (1) and a read
/// error, because telling someone to migrate away from a layout their
/// metadata never claimed is worse than saying the file is broken.
pub(crate) fn ensure_v022_cage(paths: &Paths, name: &str) -> Result<(), ExitCode> {
    match agentcage_cli::preflight::ensure_v022_cage(paths, name, &mut std::io::stderr()) {
        None => Ok(()),
        Some(code) => Err(ExitCode::from(code)),
    }
}

/// Load, validate and report a config file the way both `cage create`
/// and `cage update -c` do: a parse or validation failure is
/// `error: <message>` on stderr and exit 1; warnings are printed and
/// execution continues.
///
/// # Errors
///
/// [`EXIT_FAILURE`] on a parse or validation failure.
pub(crate) fn load_and_validate(path: &std::path::Path) -> Result<Config, ExitCode> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("error: {}: {error}", path.display());
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    };
    let host = agentcage_cli::hostenv::RealHost;
    let config = agentcage_core::config::load(&path.display().to_string(), &text, &host).map_err(
        |error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        },
    )?;
    let warnings = agentcage_core::config::validate(&config, &host).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    Ok(config)
}

/// The stored config for an existing cage, validated.
///
/// `cage update` without `-c` reloads what is on disk and re-validates
/// it, because an out-of-band edit to `cage.yaml` has to be caught here
/// rather than by the renderer three steps later.
///
/// # Errors
///
/// [`EXIT_FAILURE`] on a load or validation failure.
pub(crate) fn load_stored_and_validate(paths: &Paths, name: &str) -> Result<Config, ExitCode> {
    let host = agentcage_cli::hostenv::RealHost;
    let config = paths.load_deployment_config(name, &host).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    let warnings = agentcage_core::config::validate(&config, &host).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::{ensure_v022_cage, parse_version};
    use agentcage_core::har::json::Json;
    use agentcage_state::{Paths, TestDir};

    #[test]
    fn version_parsing_tolerates_anything() {
        assert_eq!(parse_version("0.22.1"), (0, 22));
        assert_eq!(parse_version("1.0"), (1, 0));
        assert_eq!(parse_version("garbage"), (0, 0));
        assert_eq!(parse_version(""), (0, 0));
        assert_eq!(parse_version("0"), (0, 0));
    }

    #[test]
    fn a_v021_cage_is_refused_and_a_v022_one_is_not() {
        let dir = TestDir::new("v022-gate");
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(paths.deployment_dir("old")).unwrap();
        paths
            .save_metadata(
                "old",
                &Json::Object(vec![(
                    "agentcage_version".to_owned(),
                    Json::string("0.21.4"),
                )]),
            )
            .unwrap();
        assert!(ensure_v022_cage(&paths, "old").is_err());

        std::fs::create_dir_all(paths.deployment_dir("new")).unwrap();
        paths
            .save_metadata(
                "new",
                &Json::Object(vec![(
                    "agentcage_version".to_owned(),
                    Json::string("0.40.1"),
                )]),
            )
            .unwrap();
        assert!(ensure_v022_cage(&paths, "new").is_ok());
    }

    /// A cage with no metadata at all reads as `0.0.0`, which is what
    /// the Python's `meta.get(...) or "0.0.0"` produces — and it is
    /// refused, deliberately: an unidentifiable cage is not one this
    /// version knows how to address.
    #[test]
    fn a_cage_without_metadata_is_treated_as_legacy() {
        let dir = TestDir::new("v022-nometa");
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(paths.deployment_dir("bare")).unwrap();
        assert!(ensure_v022_cage(&paths, "bare").is_err());
    }
}
