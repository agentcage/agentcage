//! Pure agentcage logic, with no way to touch the outside world.
//!
//! # Why this crate exists
//!
//! The Python host CLI mixes decision-making with doing: [`config.py`]
//! validates *and* raises click errors, [`services.py`] renders quadlets
//! *and* shells out to podman. Testing that required 30k lines of
//! `monkeypatch`-heavy pytest (see RUST-PORT-PLAN.md section 4). The port
//! splits the two so the decision-making half can be tested by feeding it
//! values and comparing the answers against fixtures the Python
//! implementation generated — a diff, not a judgement call.
//!
//! `agentcage-core` is that half. The rules it holds itself to:
//!
//! - **no subprocess** — nothing in here runs `podman`, `systemctl`,
//!   `limactl` or `container(1)`. That is the `CommandRunner` seam in
//!   `agentcage-cli` (Track D, PR D1).
//! - **no I/O**, beyond what [`agentcage_assets`] hands it. Callers read
//!   files; this crate is given their contents.
//! - **no CLI** — no argument parsing, no `stdout`, no exit codes, no
//!   `clap`. Errors are returned, not printed.
//!
//! Anything that cannot honour those three belongs in `agentcage-cli`.
//!
//! # What will live here
//!
//! Per RUST-PORT-PLAN.md Track C, in the order those PRs land:
//!
//! | | Python source | PR |
//! | :-- | :-- | :-- |
//! | config types + parsing | `config.py` | C1 |
//! | validation: domains, ports, secrets, placeholders | `config.py` | C2 |
//! | validation: relays, agents, capture, inspectors | `config.py`, `data/proxy/relays/_validate.py` | C3 |
//! | `fingerprint` + `stable_json` | `fingerprint.py` | C4 |
//! | audit parse / filter / summary | `audit.py` | C5 |
//! | HAR builder | `har.py` | C6 |
//! | volume-mount parsing | `volume_mounts.py` | C7 |
//! | quadlet rendering (minijinja over the existing `.j2`) | `quadlets.py` | C8 |
//!
//! Three of those are cross-language contracts rather than ordinary
//! ports — the relay validator, `encoded_private_ip` and `_is_never_grant`
//! exist on both sides of the trust boundary and must agree exactly
//! (RUST-PORT-PLAN.md section 2.2). Their tests assert against the shared
//! fixtures from PR A4, not against hand-written expectations.
//!
//! # Dependencies
//!
//! None, today. That is not an aspiration to keep it that way — C8 needs
//! `minijinja`, C1 needs `serde` and a YAML crate (PR B2 picks which
//! one). It is a statement that each one arrives in the PR that needs it,
//! with the reasoning in that PR's body, rather than being pre-imported
//! here on a guess.
//!
//! [`config.py`]: https://github.com/agentcage/agentcage/blob/master/src/agentcage/config.py
//! [`services.py`]: https://github.com/agentcage/agentcage/blob/master/src/agentcage/services.py

pub mod audit;
pub mod fingerprint;
pub mod har;
pub mod volume_mounts;
pub mod yaml;

/// The agentcage version, baked in at compile time.
///
/// This is the number the Python CLI reads at runtime with
/// `importlib.metadata.version("agentcage")` at ~10 call sites. It sets
/// the egress image tag, the `Image=` pin in `egress.container.j2`,
/// `agentcage_version` in `cage.container.j2`, the `metadata.json` stamp
/// and `proxy_cfg["agentcage_version"]`, and the in-egress Python reads
/// it back out of `AGENTCAGE_VERSION` or the `proxy-config.yaml` stamp
/// rather than from its own package metadata. So once the CLI is Rust
/// this constant owns the version outright and there are no two package
/// versions to keep in lockstep (RUST-PORT-PLAN.md section 2.3).
///
/// It comes from `[workspace.package] version` in the root `Cargo.toml`,
/// which `scripts/check-version.sh` holds equal to the root `VERSION`
/// file. Read it from here rather than calling `env!` again, so there is
/// one place to change if the wiring ever moves.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    /// The version reaches the binary and looks like a version.
    ///
    /// Weak on its own — `scripts/check-version.sh` is what proves this
    /// equals the `VERSION` file, and `tests/test_version.py` covers the
    /// script. This catches the narrower failure where the workspace
    /// inheritance breaks and a crate ends up on Cargo's `0.0.0`
    /// default, which would otherwise surface as every image tag being
    /// silently wrong rather than as an error.
    #[test]
    fn version_is_a_release_number() {
        assert_ne!(
            VERSION, "0.0.0",
            "crate did not inherit the workspace version"
        );

        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "expected major.minor.patch, got {VERSION:?}"
        );
        assert!(
            parts[0].chars().all(|c| c.is_ascii_digit()),
            "major of {VERSION:?} is not numeric"
        );
        assert!(
            parts[1].chars().all(|c| c.is_ascii_digit()),
            "minor of {VERSION:?} is not numeric"
        );
        assert!(
            parts[2].starts_with(|c: char| c.is_ascii_digit()),
            "patch of {VERSION:?} does not start with a digit"
        );
    }
}
