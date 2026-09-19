//! The parts of the `agentcage` binary that are worth testing from
//! outside it.
//!
//! `main.rs` stays the binary. This library exists because an
//! integration test is a separate crate and cannot reach into a
//! `[[bin]]`, and the three modules here are exactly the kind that has
//! to be tested against something external: the styling fixtures under
//! `tests/fixtures/output/`, and a pty.
//!
//! Per RUST-PORT-PLAN.md Track D, PR D4 — `output.py`, `terminal.py` and
//! `_timing.py`. The command tree (D5) and the `CommandRunner` seam (D1)
//! land beside these.

/// Removal of the pre-rework grants watcher a legacy cage left behind
/// (PR D16).
pub mod legacy_watcher;
/// Styled terminal output: the banner, the status marks, the spinner.
pub mod output;
/// Secret resolution and the at-rest stores (PR D3).
pub mod secrets;
/// Host terminal hygiene around interactive cage sessions.
pub mod terminal;
/// Per-phase wall times, behind the hidden `--timings` flags.
pub mod timing;
