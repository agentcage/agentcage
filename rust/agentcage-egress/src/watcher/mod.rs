//! The traffic watcher: an in-egress, after-the-fact LLM auditor.
//!
//! Opt-in (`agents.watcher.enable`). Every interval it re-reads the cage's
//! recent traffic — the audit ring every audit record is funnelled into,
//! allowed traffic included, plus the capture file tailed by byte offset —
//! and asks an LLM agent, prompted as a senior security analyst, whether
//! anything suspicious is going on in the aggregate shape of that traffic.
//!
//! Trust model: the watcher can only narrow. It may revoke runtime grants
//! (the egress's own overlay) when its analysis damns them, gated on
//! `auto_revoke`; it never grants, never edits the operator's baseline
//! (baseline removals are reported as recommendations) and never touches
//! the never-grant floor. The digest is untrusted data, never
//! instructions; the operator's `context` is the one trusted free text.
//!
//! Secret hygiene: the digest never carries real secret values — only the
//! inbound (placeholder) view of a body is excerpted, the outbound view
//! contributes metadata only, sensitive headers are dropped by name.
//!
//! Randomness: the cage controls every byte of its own traffic and can
//! read this code, so every deterministic boundary is somewhere it can
//! shape traffic to sit just past. Each scan draws one seed from OS
//! entropy and drives every random choice (excerpt windows, rarity
//! tie-breaks, budget sampling, the full-fidelity roll) from a [`ScanRng`]
//! seeded with it; the seed is recorded in `state.json`. Replaying a seed
//! reproduces a scan **only within this implementation**: the generator
//! is not the one the replaced implementation used, so its recorded seeds
//! do not carry over. The oracle corpus therefore pins the deterministic
//! (no-RNG) mode only.

pub mod config;
pub mod digest;
pub mod prompt;
pub(crate) mod pyval;
pub mod sample;
pub mod tail;

#[cfg(test)]
mod corpus;

pub use config::WatcherConfig;
pub use digest::{DigestInput, build_digest, dedup_samples, est_tokens, fit_to_budget};
pub use prompt::{is_never_revoke, normalise_finding, review_tool, system_prompt};
pub use sample::{excerpt_body, redact_headers, sample_capture};
pub use tail::{CaptureTail, TailLimits, TailRead};

/// The per-scan random generator. Seeded once per scan from OS entropy.
pub type ScanRng = rand::rngs::StdRng;
