//! The body cap and the body budget, from the config to the transport.
//!
//! `egress.max_body_bytes` and `egress.body_budget_bytes` (parsed by
//! [`EgressConfig::from_yaml`], the host's own parser) are applied on
//! every config (re)load: the cap by storing new
//! [`TransportSettings`](crate::proxy::TransportSettings), the budget by
//! [`BodyBudget::set_limit`]. Both take effect for the next body; nothing
//! in flight is cut.
//!
//! Two things can override the config:
//!
//! * **The environment** (`AGENTCAGE_MAX_BODY_BYTES`,
//!   `AGENTCAGE_BODY_BUDGET_BYTES`, or the matching `run` flags), for
//!   development. A value set there is pinned: config reloads leave it
//!   alone.
//! * **The address-space limit.** The supervisor sizes `RLIMIT_AS`
//!   from the budget at start ([`EgressConfig::address_space_bytes`],
//!   `agentcage-egress address-space`), and a running process cannot
//!   raise its own limit. A reload that raises the budget past what the
//!   limit leaves room for is clamped to that room (and logged) until the
//!   egress restarts, rather than letting buffered bodies run into a
//!   failed allocation that would abort the egress.

use std::path::Path;
use std::sync::Arc;

use agentcage_core::config::egress::{ADDRESS_SPACE_HEADROOM, EgressConfig};
use arc_swap::ArcSwap;

use crate::proxy::{BodyBudget, TransportSettings};

/// Values pinned by the environment (or `run` flags); `None` follows the
/// config.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `AGENTCAGE_MAX_BODY_BYTES`.
    pub max_body: Option<usize>,
    /// `AGENTCAGE_BODY_BUDGET_BYTES`.
    pub body_budget: Option<usize>,
}

/// The running transport's knobs the config drives.
#[derive(Debug)]
pub struct TransportLink {
    settings: Arc<ArcSwap<TransportSettings>>,
    budget: Arc<BodyBudget>,
    overrides: Overrides,
    address_space: Option<u64>,
}

impl TransportLink {
    /// A link to a bound proxy's settings and budget, with this process's
    /// address-space limit.
    #[must_use]
    pub fn new(
        settings: Arc<ArcSwap<TransportSettings>>,
        budget: Arc<BodyBudget>,
        overrides: Overrides,
    ) -> Self {
        Self {
            settings,
            budget,
            overrides,
            address_space: address_space_limit(),
        }
    }

    /// The same link judged against `limit` instead of the process's
    /// own address-space limit (`None`: unlimited). Tests.
    #[doc(hidden)]
    #[must_use]
    pub fn with_address_space(mut self, limit: Option<u64>) -> Self {
        self.address_space = limit;
        self
    }

    /// Apply a config's limits; returns what an operator should be told
    /// (a clamped budget), one line each.
    #[must_use = "the notes are for the operator; log them"]
    pub fn apply(&self, limits: &EgressConfig) -> Vec<String> {
        let mut notes = Vec::new();
        if self.overrides.max_body.is_none() {
            let max_body = to_usize(limits.max_body_bytes);
            if self.settings.load().max_body != max_body {
                let mut next = (**self.settings.load()).clone();
                next.max_body = max_body;
                self.settings.store(Arc::new(next));
            }
        }
        if self.overrides.body_budget.is_none() {
            let wanted = limits.body_budget_bytes;
            let room = self
                .address_space
                .map(|limit| limit.saturating_sub(ADDRESS_SPACE_HEADROOM));
            let budget = match room {
                Some(room) if wanted > room => {
                    notes.push(format!(
                        "egress.body_budget_bytes {wanted} does not fit the egress's \
                         address-space limit of {} bytes (set when it started); using \
                         {room} until the egress restarts",
                        self.address_space.unwrap_or_default()
                    ));
                    room
                }
                _ => wanted,
            };
            self.budget.set_limit(to_usize(budget));
        }
        notes
    }
}

/// The address-space limit the supervisor should start the egress
/// under, from the config at `path` (`None`, a missing file or one that
/// does not load: the defaults) and an environment override of the
/// budget. Printed by `agentcage-egress address-space`.
///
/// # Errors
///
/// The config exists but cannot be read, parsed, or its `egress:`
/// section is refused; the message says which. The supervisor falls back
/// to the default limit then, and the egress itself refuses that config.
pub fn address_space_for(path: Option<&Path>, body_budget: Option<usize>) -> Result<u64, String> {
    let mut limits = match path {
        Some(path) if path.exists() => {
            let cfg = crate::config::Config::load(path).map_err(|e| e.to_string())?;
            EgressConfig::from_yaml(cfg.get("egress"))?
        }
        _ => EgressConfig::default(),
    };
    if let Some(budget) = body_budget {
        limits.body_budget_bytes = budget as u64;
    }
    Ok(limits.address_space_bytes())
}

/// This process's soft `RLIMIT_AS`, `None` when unlimited (or unknown).
fn address_space_limit() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit};
        match getrlimit(Resource::RLIMIT_AS) {
            Ok((soft, _)) if soft != RLIM_INFINITY => Some(soft),
            _ => None,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// A byte count as a `usize`; validation bounds it far below either
/// width's maximum on a 64-bit target.
fn to_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn link(overrides: Overrides, address_space: Option<u64>) -> TransportLink {
        TransportLink {
            settings: Arc::new(ArcSwap::from_pointee(TransportSettings::default())),
            budget: crate::proxy::BodyBudget::with_wait(
                crate::proxy::DEFAULT_BODY_BUDGET,
                std::time::Duration::ZERO,
            ),
            overrides,
            address_space,
        }
    }

    fn limits(max_body: u64, budget: u64) -> EgressConfig {
        EgressConfig {
            max_body_bytes: max_body,
            body_budget_bytes: budget,
        }
    }

    #[test]
    fn the_core_defaults_are_the_transport_defaults() {
        let core = EgressConfig::default();
        assert_eq!(
            to_usize(core.max_body_bytes),
            crate::proxy::DEFAULT_MAX_BODY
        );
        assert_eq!(
            to_usize(core.body_budget_bytes),
            crate::proxy::DEFAULT_BODY_BUDGET
        );
    }

    #[test]
    fn a_config_sets_the_cap_and_the_budget() {
        let l = link(Overrides::default(), None);
        assert!(l.apply(&limits(8 * MIB, 64 * MIB)).is_empty());
        assert_eq!(l.settings.load().max_body, to_usize(8 * MIB));
        assert_eq!(l.budget.limit(), to_usize(64 * MIB));
        // And back.
        assert!(l.apply(&EgressConfig::default()).is_empty());
        assert_eq!(l.settings.load().max_body, crate::proxy::DEFAULT_MAX_BODY);
        assert_eq!(l.budget.limit(), crate::proxy::DEFAULT_BODY_BUDGET);
        // The rest of the settings are left as they were.
        assert_eq!(l.settings.load().inspected_ports, [80, 443]);
    }

    #[test]
    fn an_environment_override_is_pinned() {
        let l = link(
            Overrides {
                max_body: Some(5),
                body_budget: Some(7),
            },
            None,
        );
        l.settings.store(Arc::new(TransportSettings {
            max_body: 5,
            ..TransportSettings::default()
        }));
        l.budget.set_limit(7);
        assert!(l.apply(&limits(8 * MIB, 64 * MIB)).is_empty());
        assert_eq!(l.settings.load().max_body, 5);
        assert_eq!(l.budget.limit(), 7);
    }

    #[test]
    fn a_budget_past_the_address_space_is_clamped_until_a_restart() {
        let l = link(Overrides::default(), Some(2 << 30));
        let notes = l.apply(&limits(8 * MIB, 4 << 30));
        assert_eq!(l.budget.limit(), to_usize(1 << 30));
        assert_eq!(
            notes,
            [format!(
                "egress.body_budget_bytes {} does not fit the egress's address-space \
                 limit of {} bytes (set when it started); using {} until the egress restarts",
                4u64 << 30,
                2u64 << 30,
                1u64 << 30
            )]
        );
        assert!(l.apply(&limits(8 * MIB, 512 * MIB)).is_empty());
        assert_eq!(l.budget.limit(), to_usize(512 * MIB));
    }

    #[test]
    fn the_address_space_comes_from_the_config_or_the_override() {
        let dir = std::env::temp_dir().join(format!("agentcage-limits-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        assert_eq!(address_space_for(None, None), Ok(2 << 30));
        assert_eq!(address_space_for(Some(&path), None), Ok(2 << 30));
        std::fs::write(&path, "egress:\n  body_budget_bytes: 4294967296\n").unwrap();
        assert_eq!(address_space_for(Some(&path), None), Ok(5 << 30));
        assert_eq!(address_space_for(Some(&path), Some(1 << 30)), Ok(2 << 30));
        std::fs::write(&path, "egress:\n  body_budget_bytes: lots\n").unwrap();
        assert_eq!(
            address_space_for(Some(&path), None),
            Err("egress.body_budget_bytes must be a whole number of bytes (got \"lots\")".into())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
