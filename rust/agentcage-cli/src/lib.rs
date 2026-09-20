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

/// The container backend: podman, quadlets, systemd (PR D6).
pub mod backend;
/// Fingerprint gathering — what makes `cage update` a no-op (PR D6).
pub mod deploy;
/// `agentcage doctor` — the host diagnostics (PR D15).
pub mod doctor;
/// `agentcage cage har` — the HAR export (PR D13).
pub mod har;
/// The host probes `agentcage-core` declares and does not implement.
pub mod hostenv;
/// Removal of the pre-rework grants watcher a legacy cage left behind
/// (PR D16).
pub mod legacy_watcher;
/// Styled terminal output: the banner, the status marks, the spinner.
pub mod output;
/// The checks a cage-addressing command runs before it does anything.
pub mod preflight;
/// Point-in-time image-tag resolution for build args (PR D6).
pub mod registry;
/// The ephemeral `agentcage run` flow (PR D14).
pub mod run;
/// `init.py` — the scaffold search path and renderer (PR D14).
pub mod scaffold;
/// Secret resolution and the at-rest stores (PR D3).
pub mod secrets;
/// `services.py` — build, render, install, start (PR D6).
pub mod services;
/// Staging a Containerfile's build context into a cage (PR D6).
pub mod staging;
/// Host terminal hygiene around interactive cage sessions.
pub mod terminal;
/// Per-phase wall times, behind the hidden `--timings` flags.
pub mod timing;
