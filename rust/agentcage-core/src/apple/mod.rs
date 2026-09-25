//! `backends/apple_container.py` — the half that only ever produces text.
//!
//! RUST-PORT-PLAN.md Track E splits each of the two non-Linux backends
//! into a **generation** half, verifiable on a Linux CI runner, and an
//! **execution** half that needs the hardware (§4.1). This module is the
//! generation half's second PR, E3: the per-cage unit metadata, the
//! launchd plist, and the three argv builders `cage exec`, `cage logs`
//! and `cage audit` dispatch through.
//!
//! Nothing here runs `container(1)`, writes a file or reads the
//! environment. Every host fact the Python reaches for — the resolved
//! `container` binary, the per-cage state directory, the current
//! placeholders, the expanded volume list — arrives as an argument, so
//! the whole module is a function from values to text and can be diffed
//! against the Python's own output on a machine with no Apple silicon
//! anywhere near it.
//!
//! # Why this is testable without a Mac
//!
//! `tests/test_apple_container.py` has patched `platform.system()` to
//! `"Darwin"` since the backend was written (line 44) and asserted on
//! the generated argv, units and plists. There has never been a macOS
//! runner in CI. `scripts/gen-apple-fixture.py` does the same thing and
//! records the answers; `tests/fixtures/golden/` records the units and
//! plists for every `isolation: apple-container` case in the corpus.
//!
//! # The three things worth knowing before reading
//!
//! * **The unit is a JSON blob, not a systemd unit.** Apple's
//!   `container` CLI has no unit concept: `generate_units` returns
//!   `{"<cage>.json": …}`, `start()` reads it back, and
//!   `compute_fingerprint` hashes it exactly as it hashes a quadlet on
//!   the container backend (`cli.py::_update_fingerprint` is backend
//!   agnostic). So the bytes matter for the same reason a `.container`
//!   file's do.
//! * **The plist is a hand-written f-string, not `plistlib` output.**
//!   See [`launchd`].
//! * **`audit_argv` is the only audit path in agentcage that reads a
//!   file.** On `container` and `vm` the egress addon writes its trail
//!   to stderr and the host reads the journal; only apple-container
//!   bind-mounts an `audit.jsonl` the host can `tail`. See [`argv`].

pub mod argv;
pub mod launchd;
pub mod units;

pub use argv::{AppleArgvError, Service, audit_argv, exec_argv, logs_argv};
pub use launchd::{plist_label, plist_text};
pub use units::{generate_units, unit_json};

/// `AppleContainerBackend.service_names` — the 2-microVM model's two
/// addressable services.
///
/// `proxy` / `dns` from the legacy single-VM model collapsed into
/// `egress`; `cli.py` uses these for status display and
/// `cage exec --service`.
pub const SERVICE_NAMES: [&str; 2] = ["cage", "egress"];
