//! `backends/apple_container.py` — Apple's `container` CLI, two microVMs.
//!
//! RUST-PORT-PLAN.md Track E. The backend is the largest in the tree
//! (2,469 lines) and it is split across three PRs along a line that is
//! not arbitrary: **roughly two thirds of it is verifiable on Linux**,
//! and the rest needs Apple Silicon.
//!
//! | Half | What | Checked by |
//! | :-- | :-- | :-- |
//! | Generation A (**here**) | image naming, the egress content-hash wiring, [`egress_config`], [`volumes`] | `tests/fixtures/apple-container/`, generated from the Python |
//! | Generation B (E3) | `generate_units`, the launchd plist, `exec_argv` / `logs_argv` / `audit_argv` | a golden unit + plist diff |
//! | Execution (E5) | `start`/`stop`, `_stage_secrets`, mask-mountpoint record/cleanup, `_wait_supervisor_ready` | `phase_apple.sh`, manually, on a Mac |
//!
//! # Why a Mac is not needed for this half
//!
//! `tests/test_apple_container.py` has always patched `platform.system()`
//! to `"Darwin"` (line 44) and asserted on the argv, units and plists the
//! backend produced. There is no macOS runner in CI and there never has
//! been, so that *is* how this backend is tested. The fixtures under
//! `tests/fixtures/apple-container/` are the same trick, recorded:
//! `scripts/gen-apple-container-fixtures.py` drives the real Python with
//! the same patch and commits what came out, and
//! `tests/golden_apple_container.rs` replays it.
//!
//! PR C8 noted that the apple cases in the golden corpus carry a
//! `quadlets/NOT-APPLICABLE.txt` instead of units, because this backend
//! renders `container run` argv rather than going through the quadlet
//! templates, and left that gap to Track E. This closes the generation-A
//! part of it.
//!
//! # Two things about this backend that are not like the others
//!
//! **Its state root ignores `XDG_CONFIG_HOME`.** `_state_dir` is a bare
//! `expanduser("~/.config/agentcage/apple-container")`, so an XDG-only
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

/// `_render_egress_config` — the three files the egress microVM mounts.
pub mod egress_config;
/// Image naming and the egress content-hash wiring.
pub mod image;
/// `container.volumes` and `container.tmpfs`, as this backend means them.
pub mod volumes;
