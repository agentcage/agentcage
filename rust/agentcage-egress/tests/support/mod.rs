//! Building the plugin components the integration tests load.
//!
//! The components are built on first use by a nested
//! `cargo build --release --target wasm32-wasip2` into
//! `target/inspector-wasm/` (a separate target directory, so it never
//! waits on the lock the outer `cargo test` holds). When the
//! `wasm32-wasip2` target is not installed the tests print why and pass
//! without running, so `cargo test --workspace` works on any machine;
//! set `AGENTCAGE_REQUIRE_WASM=1` (CI does) to make a missing target a
//! failure instead.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The plugin crates: package name, and the `.wasm` file's stem.
const CRATES: [(&str, &str); 4] = [
    ("header-policy-inspector", "header_policy_inspector"),
    ("dlp-regex-inspector", "dlp_regex_inspector"),
    ("misbehaving-inspector", "misbehaving_inspector"),
    ("legacy-inspector", "legacy_inspector"),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn wasm_target_installed() -> bool {
    let Ok(out) = Command::new("rustc").args(["--print", "sysroot"]).output() else {
        return false;
    };
    let sysroot = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Path::new(&sysroot)
        .join("lib/rustlib/wasm32-wasip2")
        .is_dir()
}

/// The directory holding the built `.wasm` files, or `None` (after
/// saying why) when they cannot be built here.
pub(crate) fn plugin_dir() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        if !wasm_target_installed() {
            let msg = "wasm32-wasip2 target not installed \
                       (rustup target add wasm32-wasip2); plugin tests skipped";
            assert!(
                std::env::var_os("AGENTCAGE_REQUIRE_WASM").is_none(),
                "{msg}"
            );
            eprintln!("{msg}");
            return None;
        }
        let target_dir = workspace_root().join("target/inspector-wasm");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.current_dir(workspace_root())
            .args([
                "build",
                "--release",
                "--target",
                "wasm32-wasip2",
                "--target-dir",
            ])
            .arg(&target_dir);
        for (package, _) in CRATES {
            cmd.args(["-p", package]);
        }
        let status = cmd.status().expect("run cargo");
        assert!(status.success(), "building the plugin components failed");
        Some(target_dir.join("wasm32-wasip2/release"))
    })
    .as_deref()
}
