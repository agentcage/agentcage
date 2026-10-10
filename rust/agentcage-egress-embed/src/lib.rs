//! The `agentcage-egress` binary, carried inside the host binary.
//!
//! The egress runs in a Linux container (or a Linux VM on macOS), so the
//! host has to ship a Linux build of it whatever the host's own OS is
//! (`EGRESS-PORT-PLAN.md` D9). This crate holds exactly that: the
//! linux-musl build for the host's architecture, found by `build.rs`
//! (which documents where it looks and what it checks), or nothing when
//! the host was built without one.
//!
//! Nothing here reads the bytes at runtime beyond handing them out; the
//! CLI stages them into the egress image's build context and hashes
//! them into the image tag.

mod generated {
    //! The build script's output, and nothing else.
    include!(concat!(env!("OUT_DIR"), "/egress_embed.rs"));
}

/// The linux-musl target whose binary this host carries, or would carry:
/// `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`, matching
/// the host's architecture. `None` on a host agentcage does not support.
pub const LINUX_TARGET: Option<&str> = generated::LINUX_TARGET;

/// The embedded egress binary, or `None` when this host was built
/// without one (a development build that never built the egress).
#[must_use]
pub fn binary() -> Option<&'static [u8]> {
    generated::BINARY
}

/// How to get a host binary that carries the egress, for the error a
/// build without one reports when the Rust engine is selected.
#[must_use]
pub fn missing_hint() -> String {
    let target = LINUX_TARGET.unwrap_or("<arch>-unknown-linux-musl");
    format!(
        "this agentcage was built without the agentcage-egress binary; build it with \
         `rustup target add {target} && cargo build --release --target {target} -p agentcage-egress`, \
         then rebuild agentcage (or point AGENTCAGE_EGRESS_BIN at a built binary when building it)"
    )
}

#[cfg(test)]
mod tests {
    use super::{LINUX_TARGET, binary, missing_hint};

    /// The target follows the host's architecture, never its OS.
    #[test]
    fn the_target_matches_the_host_arch() {
        let expected = if cfg!(target_arch = "x86_64") {
            Some("x86_64-unknown-linux-musl")
        } else if cfg!(target_arch = "aarch64") {
            Some("aarch64-unknown-linux-musl")
        } else {
            None
        };
        assert_eq!(LINUX_TARGET, expected);
    }

    /// When a binary is embedded, `build.rs` already checked it; this
    /// re-reads the header from the embedded bytes, so the check and the
    /// embed cannot have looked at two different files.
    #[test]
    fn an_embedded_binary_is_an_elf_for_the_host_arch() {
        let Some(bytes) = binary() else {
            eprintln!("no egress binary embedded in this build; nothing to check");
            return;
        };
        assert_eq!(&bytes[..4], b"\x7fELF");
        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        let expected = if cfg!(target_arch = "x86_64") {
            0x3e
        } else {
            0xb7
        };
        assert_eq!(machine, expected);
    }

    /// The hint names the command for this host's target.
    #[test]
    fn the_hint_names_the_target() {
        if let Some(target) = LINUX_TARGET {
            assert!(missing_hint().contains(&format!("--target {target}")));
        }
        assert!(missing_hint().contains("AGENTCAGE_EGRESS_BIN"));
    }
}
