//! The apple-container backend — the half that only ever produces text.
//!
//! Each of the two non-Linux backends is split into a **generation**
//! half, verifiable on a Linux CI runner, and an **execution** half that
//! needs the hardware (in `agentcage-cli`). This module is the
//! generation half: the per-cage unit metadata, the launchd plist, and
//! the three argv builders `cage exec`, `cage logs` and `cage audit`
//! dispatch through.
//!
//! Nothing here runs `container(1)`, writes a file or reads the
//! environment. Every host fact — the resolved `container` binary, the
//! per-cage state directory, the current placeholders, the expanded
//! volume list — arrives as an argument, so the whole module is a
//! function from values to text and can be diffed against recorded
//! output on a machine with no Apple silicon anywhere near it.
//!
//! # Why this is testable without a Mac
//!
//! There has never been a macOS runner in CI. The fixtures under
//! `tests/fixtures/apple-container/` and `tests/fixtures/golden/` were
//! recorded with the host platform faked as macOS, and record the argv,
//! the units and the plists for every `isolation: apple-container` case
//! in the corpus.
//!
//! # The three things worth knowing before reading
//!
//! * **The unit is a JSON blob, not a systemd unit.** Apple's
//!   `container` CLI has no unit concept: `generate_units` returns
//!   `{"<cage>.json": …}`, `start()` reads it back, and
//!   `compute_fingerprint` hashes it exactly as it hashes a quadlet on
//!   the container backend (fingerprinting is backend agnostic). So the
//!   bytes matter for the same reason a `.container`
//!   file's do.
//! * **The plist is hand-written text, not a plist library's output.**
//!   See [`launchd`].
//! * **`audit_argv` is the only audit path in agentcage that reads a
//!   file.** On `container` and `vm` the egress writes its trail
//!   to stderr and the host reads the journal; only apple-container
//!   bind-mounts an `audit.jsonl` the host can `tail`. See [`argv`].

pub mod argv;
pub mod launchd;
/// `--cpus` / `--memory` normalization for Apple's stricter parser.
pub mod resources;
pub mod units;

pub use argv::{AppleArgvError, Service, audit_argv, exec_argv, logs_argv};
pub use launchd::{plist_label, plist_text};
pub use resources::{normalize_cpus, normalize_memory};
pub use units::{generate_units, unit_json};

/// The 2-microVM model's two addressable services.
///
/// `proxy` / `dns` from the legacy single-VM model collapsed into
/// `egress`; the CLI uses these for status display and
/// `cage exec --service`.
pub const SERVICE_NAMES: [&str; 2] = ["cage", "egress"];
