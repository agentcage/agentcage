//! Finds the linux-musl `agentcage-egress` binary for the host's
//! architecture and emits an `include_bytes!` of it.
//!
//! # Where the binary comes from
//!
//! 1. `AGENTCAGE_EGRESS_BIN`, a path to a built binary. Release builds
//!    set it to the artifact of the egress job (`publish.yml`). When set
//!    it must exist: a typo should fail the build, not ship a host
//!    binary with no egress.
//! 2. Otherwise `<target dir>/<musl target>/release/agentcage-egress`,
//!    which is where `cargo build --release --target <musl target> -p
//!    agentcage-egress` leaves it -- the developer flow in
//!    CONTRIBUTING.md.
//! 3. Otherwise nothing. The host still builds, and only
//!    `AGENTCAGE_EGRESS_ENGINE=rust` fails, at image-build time, with a
//!    message saying how to provide the binary. Release builds set
//!    `AGENTCAGE_REQUIRE_EGRESS_BIN=1`, which turns this case into a
//!    build failure.
//!
//! # Which architecture
//!
//! The one the host's own Linux VM or container runtime runs: a Linux
//! host runs the egress natively, a macOS host runs it in a VM of its
//! own architecture (Lima, Apple's containerization). So the egress
//! target is the host's arch with `-unknown-linux-musl`, whatever the
//! host's OS. The ELF header is checked against that before embedding,
//! along with static linkage, so a binary for the wrong machine, or one
//! needing a libc the image does not have, fails here rather than as an
//! `exec format error` inside a cage.

use std::fs;
use std::path::{Path, PathBuf};

/// Path to a prebuilt egress binary; takes precedence over `target/`.
const ENV_BIN: &str = "AGENTCAGE_EGRESS_BIN";

/// `1` makes a missing binary a build failure (release builds).
const ENV_REQUIRE: &str = "AGENTCAGE_REQUIRE_EGRESS_BIN";

/// The binary's file name in a cargo target directory.
const BIN_NAME: &str = "agentcage-egress";

/// ELF `e_machine` values for the two supported architectures.
const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;

/// `PT_INTERP`: present exactly when the binary needs a dynamic loader.
const PT_INTERP: u32 = 3;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed={ENV_BIN}");
    println!("cargo::rerun-if-env-changed={ENV_REQUIRE}");

    let os = env("CARGO_CFG_TARGET_OS");
    let arch = env("CARGO_CFG_TARGET_ARCH");
    let linux = linux_counterpart(&os, &arch);
    let require = std::env::var(ENV_REQUIRE).is_ok_and(|v| v == "1");

    let explicit = std::env::var_os(ENV_BIN).filter(|v| !v.is_empty());
    let found = if let Some(path) = explicit {
        let path = PathBuf::from(path);
        println!("cargo::rerun-if-changed={}", path.display());
        assert!(
            path.is_file(),
            "{ENV_BIN}={} does not name a file",
            path.display()
        );
        assert!(
            linux.is_some(),
            "{ENV_BIN} is set, but a {os}/{arch} host has no linux-musl egress counterpart"
        );
        Some(path)
    } else if let Some((target, _)) = linux {
        let candidate = target_dir().join(target).join("release").join(BIN_NAME);
        watch_for(&candidate);
        candidate.is_file().then_some(candidate)
    } else {
        None
    };

    if let (Some(path), Some((target, machine))) = (&found, linux) {
        check_elf(path, target, machine);
    }
    assert!(
        found.is_some() || !require,
        "{ENV_REQUIRE}=1 but no agentcage-egress binary was found: set {ENV_BIN}, or build \
         it first with `cargo build --release --target {} -p agentcage-egress`",
        linux.map_or("<linux-musl target>", |(t, _)| t)
    );

    let out = PathBuf::from(env("OUT_DIR")).join("egress_embed.rs");
    fs::write(&out, render(linux.map(|(t, _)| t), found.as_deref()))
        .unwrap_or_else(|err| panic!("could not write {}: {err}", out.display()));
}

/// A cargo-provided environment variable.
fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("cargo sets {name}"))
}

/// The linux-musl target and ELF machine a host of this OS and arch
/// runs its egress on, or `None` for a host agentcage does not support.
fn linux_counterpart(os: &str, arch: &str) -> Option<(&'static str, u16)> {
    if os != "linux" && os != "macos" {
        return None;
    }
    match arch {
        "x86_64" => Some(("x86_64-unknown-linux-musl", EM_X86_64)),
        "aarch64" => Some(("aarch64-unknown-linux-musl", EM_AARCH64)),
        _ => None,
    }
}

/// The cargo target directory this build writes into.
///
/// Found by walking up from `OUT_DIR` to the directory cargo marks with
/// `CACHEDIR.TAG`, so `CARGO_TARGET_DIR` and `--target-dir` are honoured
/// without reading either; the workspace's `target/` is the fallback.
fn target_dir() -> PathBuf {
    let out = PathBuf::from(env("OUT_DIR"));
    if let Some(dir) = out
        .ancestors()
        .find(|dir| dir.join("CACHEDIR.TAG").is_file())
    {
        return dir.to_path_buf();
    }
    PathBuf::from(env("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is nested at rust/<crate> inside the repository")
        .join("target")
}

/// Rerun when `path` appears or changes.
///
/// Watching a file that does not exist makes cargo rerun the script on
/// every build, which would relink the host binary every time. Watching
/// the nearest existing ancestor instead catches the binary arriving:
/// creating it (or the directory chain leading to it) changes that
/// ancestor's mtime.
fn watch_for(path: &Path) {
    let existing = path
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or_else(|| Path::new("/"));
    println!("cargo::rerun-if-changed={}", existing.display());
}

/// Refuse a binary that is not a static ELF for `machine`.
fn check_elf(path: &Path, target: &str, machine: u16) {
    let bytes =
        fs::read(path).unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()));
    let fail = |why: &str| -> ! {
        panic!(
            "{} is not usable as the {target} egress: {why}",
            path.display()
        )
    };
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        fail("not an ELF file");
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        fail("not a 64-bit little-endian ELF");
    }
    let found = u16::from_le_bytes([bytes[18], bytes[19]]);
    if found != machine {
        fail(&format!(
            "ELF machine 0x{found:x}, expected 0x{machine:x} -- built for the wrong architecture"
        ));
    }
    let phoff = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("eight bytes"),
    ))
    .unwrap_or(usize::MAX);
    let phentsize = usize::from(u16::from_le_bytes([bytes[54], bytes[55]]));
    let phnum = usize::from(u16::from_le_bytes([bytes[56], bytes[57]]));
    for index in 0..phnum {
        let start = phoff.saturating_add(index.saturating_mul(phentsize));
        let Some(header) = bytes.get(start..start.saturating_add(4)) else {
            fail("truncated program header table");
        };
        if u32::from_le_bytes(header.try_into().expect("four bytes")) == PT_INTERP {
            fail(
                "dynamically linked (it has a PT_INTERP); build it for the linux-musl \
                 target so it runs in an image whatever its libc",
            );
        }
    }
}

/// The generated module: the target, and the bytes if there are any.
fn render(target: Option<&str>, binary: Option<&Path>) -> String {
    let source = binary.map(|p| {
        fs::canonicalize(p)
            .unwrap_or_else(|_| p.to_path_buf())
            .to_str()
            .unwrap_or_else(|| panic!("non-UTF-8 egress path {}", p.display()))
            .to_owned()
    });
    // The path goes into `include_bytes!` only, never into a string
    // constant: the build machine's directory layout has no business in
    // a shipped binary.
    let binary = source.map_or_else(
        || "None".to_owned(),
        |path| format!("Some(include_bytes!({path:?}))"),
    );
    format!(
        "// @generated by rust/agentcage-egress-embed/build.rs -- do not edit.\n\n\
         pub(crate) const LINUX_TARGET: Option<&str> = {target:?};\n\
         pub(crate) static BINARY: Option<&[u8]> = {binary};\n"
    )
}
