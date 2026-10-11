//! The apple-container backend — Apple's `container` CLI, two microVMs.
//!
//! Roughly two thirds of it is verifiable on Linux, and the rest needs
//! Apple Silicon:
//!
//! | Half | What | Checked by |
//! | :-- | :-- | :-- |
//! | Generation A | image naming, the egress content-hash wiring, [`egress_config`], [`volumes`] | `tests/fixtures/apple-container/`, recorded from an earlier release |
//! | Generation B | `generate_units`, the launchd plist, `exec_argv` / `logs_argv` / `audit_argv` | a golden unit + plist diff |
//! | Execution | `start`/`stop`, secret staging, mask-mountpoint record/cleanup, waiting for the supervisor | `phase_apple.sh`, manually, on a Mac |
//!
//! # Why a Mac is not needed for the generation halves
//!
//! There is no macOS runner in CI and there never has been. The
//! fixtures under `tests/fixtures/apple-container/` were recorded with
//! the platform check patched to `"Darwin"`, and
//! `tests/golden_apple_container.rs` replays them against the argv,
//! units and plists this backend produces.
//!
//! # Two things about this backend that are not like the others
//!
//! **Its state root ignores `XDG_CONFIG_HOME`.** It is always
//! `~/.config/agentcage/apple-container`, so an XDG-only
//! sandbox does not redirect it — a portability wart, and a testing
//! hazard on top. [`agentcage_state::Paths`] records it, and
//! `tests/fixtures/apple-container/state-paths.json` pins it with the
//! XDG roots deliberately pointed somewhere else so the wart is visible
//! rather than coincidentally invisible.
//!
//! **It stages secrets to persistent disk.** `secrets/` lives under that
//! same state root, where the container backend uses a tmpfs under
//! `$XDG_RUNTIME_DIR`; macOS has neither. That is deliberate (plan
//! section 2.7) and must not be "fixed" toward the Linux shape —
//! [`agentcage_state::Paths::apple_secrets_dir`] is where it is written
//! down, and the writing itself is E5's.

/// The execution half: `start`, `stop`, `destroy`, the launchd job.
pub mod backend;
/// `container build` for a cage's own staged Containerfile.
pub mod build;
/// The three files the egress microVM mounts.
pub mod egress_config;
/// Image naming and the egress content-hash wiring.
pub mod image;
/// The #320 tmpfs-mask mount-point bookkeeping.
pub mod masks;
/// The unit JSON `generate_units` writes and `start` reads back.
pub mod meta;
/// `check_prerequisites` — what this host is missing.
pub mod prereq;
/// The two `container run` argvs, as pure functions.
pub mod run_argv;
/// `container.volumes` and `container.tmpfs`, as this backend means them.
pub mod volumes;
/// The per-cage wrapper image: naming, rendering, building.
pub mod wrapper;
