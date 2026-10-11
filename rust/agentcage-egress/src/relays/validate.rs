//! Structural validation for `protocol_relays` entries.
//!
//! The host and the egress used to import one Python module for this, so
//! both sides of the trust boundary refused the same configs with the
//! same words. The host's Rust port of it lives in
//! [`agentcage_core::relays`], pinned by the language-neutral
//! `validate_relay_entry` contract fixture; the egress reuses it rather
//! than keep a third copy that could drift.

use crate::config::Value;

pub use agentcage_core::relays::{KNOWN_RELAY_TYPES, WRITE_MODES, is_rate_limit};

/// Validate one entry the way the egress does at start and on reload:
/// no source-scheme hook (the egress never sees which scheme the host
/// used; it refuses `cmd:` and `podman:` when it resolves them).
///
/// # Errors
///
/// The message the host's `cage create` would print for the same entry.
pub fn validate_relay_entry(entry: &Value) -> Result<(), String> {
    agentcage_core::relays::validate_relay_entry(entry, None).map_err(|e| e.to_string())
}
