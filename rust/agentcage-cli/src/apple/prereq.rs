//! `apple_container/prerequisites.py` — what this host is missing.
//!
//! Four checks, in the Python's own order, each producing the string
//! `cage create` and `doctor` print verbatim. The order matters more
//! than it looks: a non-Darwin host returns after the first check
//! rather than going on to complain about its architecture, and a
//! missing binary returns before the apiserver probe, because asking a
//! binary that is not there whether its daemon is up produces a worse
//! message than saying it is not installed.

use agentcage_exec::CommandRunner;
use agentcage_exec::tools::apple::AppleContainer;

use crate::hostenv::{machine, system};

/// `_MIN_MACOS_MAJOR` — Apple's `container` needs macOS 26.
const MIN_MACOS_MAJOR: u32 = 26;

/// `check_prerequisites()` — one string per unmet requirement, empty
/// when the host can run an `apple-container` cage.
///
/// Note that the version check reports the detected major **as the
/// Python formats it**: `None` renders as `None`, because
/// `platform.mac_ver()` returning an empty string on a Mac is a real
/// state and the message has to be able to say so.
#[must_use]
pub fn check_prerequisites(runner: &dyn CommandRunner) -> Vec<String> {
    let mut issues = Vec::new();

    if system() != "Darwin" {
        issues.push(format!(
            "apple-container isolation requires macOS; current platform is {}",
            system()
        ));
        return issues;
    }

    if machine() != "arm64" {
        issues.push(format!(
            "apple-container isolation requires Apple Silicon (arm64); \
             current arch is {}",
            machine()
        ));
    }

    let major = crate::doctor::macos_major(runner);
    if major.is_none_or(|major| major < MIN_MACOS_MAJOR) {
        issues.push(format!(
            "apple-container isolation requires macOS {MIN_MACOS_MAJOR}+; \
             detected major version {}",
            match major {
                Some(major) => major.to_string(),
                None => "None".to_owned(),
            }
        ));
    }

    let cli = AppleContainer::new(runner);
    if cli.binary().is_none() {
        issues.push(
            "'container' CLI not found — install from \
             https://github.com/apple/container/releases (the .pkg installer)"
                .to_owned(),
        );
        return issues;
    }

    if !cli.system_running().unwrap_or(false) {
        issues.push(
            "Apple container apiserver is not running — run \
             'container system start --enable-kernel-install'"
                .to_owned(),
        );
    }

    issues
}

#[cfg(test)]
mod tests {
    use agentcage_exec::FakeRunner;

    use super::check_prerequisites;

    /// Off a Mac the first check short-circuits, so nothing is run.
    #[test]
    #[cfg_attr(target_os = "macos", ignore = "the Darwin branch probes the host")]
    fn a_non_mac_host_reports_one_issue_and_probes_nothing() {
        let fake = FakeRunner::new();
        let issues = check_prerequisites(&fake);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert!(issues[0].contains("requires macOS"), "{issues:?}");
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }
}
