//! The launchd plist an apple-container cage is started by, and its name.
//!
//! # Byte-for-byte, and why that is not a judgement call here
//!
//! `tests/fixtures/golden/README.md` splits its comparisons: YAML is
//! compared by parsed value, because PyYAML's emitter wraps at 80
//! columns and has quoting heuristics nothing downstream depends on,
//! and **everything else is compared byte-for-byte**. A launchd plist
//! is XML, and XML has formatting, so the obvious worry is that this is
//! pinned to some library's indentation rather than to agentcage's
//! behaviour.
//!
//! It is not, and the reason is worth stating once: **no plist library
//! is involved.** The document has always been a format string, so the
//! indentation, the key order, the `<true/>` / `<false/>` spelling and
//! the trailing newline are all agentcage's own source text, not a
//! serializer's opinion. There is no emitter to reimplement and no
//! cross-version drift to absorb — reproducing these bytes is
//! reproducing a format string. So the plist sits on the byte-exact
//! side of the corpus rule, with the rest of the units.
//!
//! It stays a format string rather than a plist crate's output for
//! exactly that reason: a crate would produce *valid* output that
//! differs byte for byte, which would turn a settled comparison into a
//! semantic one for no gain.
//!
//! # What this does not do
//!
//! Writing the file and the `launchctl bootout` / `bootstrap` /
//! `load -w` sequence around it are execution, gated on real hardware
//! (`agentcage-cli`). This module renders the text and names the file;
//! nothing here touches the disk.
//!
//! # Escaping
//!
//! There is none, and there never was. `name` is safe — the CLI
//! validates a cage name against `^[a-z0-9][a-z0-9-]{0,62}$` before it
//! can reach this path — but `binary` and `state_dir` are host paths,
//! and a home directory containing `&`, `<` or `>` yields a malformed
//! plist that `launchctl` refuses with a parse error. That is kept
//! rather than quietly fixed, because a fix that changed the bytes
//! would make every committed plist stale for a hazard no fixture has
//! hit.

/// `io.agentcage.<name>` — the plist's `Label`, its filename stem, and
/// the service name `launchctl bootout gui/<uid>/<label>` addresses.
///
/// Reverse-DNS form so the job does not collide with a non-agentcage
/// daemon in a `launchctl list`.
#[must_use]
pub fn plist_label(name: &str) -> String {
    format!("io.agentcage.{name}")
}

/// The plist text, including its trailing newline.
///
/// * `binary` — the resolved `container` path. The caller returns early
///   with a warning when there is none, so this function is only
///   reached with a real path.
/// * `state_dir` — `~/.config/agentcage/apple-container/<name>`
///   ([`Paths::apple_state_dir`](../../../agentcage_state/struct.Paths.html)).
///   It is interpolated twice, for the two log paths, with no trailing
///   separator.
#[must_use]
pub fn plist_text(name: &str, binary: &str, state_dir: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.agentcage.{name}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>start</string>
        <string>{name}</string>
    </array>
    <key>StandardOutPath</key>
    <string>{state_dir}/launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{state_dir}/launchd.err.log</string>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{plist_label, plist_text};

    #[test]
    fn the_label_is_reverse_dns() {
        assert_eq!(plist_label("demo"), "io.agentcage.demo");
    }

    /// The shape, so a reader can see it without a fixture. The bytes
    /// are pinned against recorded output in `tests/golden_apple.rs`.
    #[test]
    fn the_document_is_the_pinned_format_string() {
        let text = plist_text("demo", "/usr/local/bin/container", "/home/u/state/demo");
        assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(text.contains("<string>io.agentcage.demo</string>"));
        assert!(text.contains("        <string>/usr/local/bin/container</string>\n"));
        assert!(text.contains("<string>/home/u/state/demo/launchd.err.log</string>"));
        assert!(text.ends_with("</plist>\n"));
    }

    /// `container start <cage>` — not `agentcage cage start`, and not
    /// the egress sibling. Pinned because it is the line a Mac owner
    /// will want to look at first (see the PR description).
    #[test]
    fn the_job_execs_container_start_on_the_cage_only() {
        let text = plist_text("demo", "/opt/homebrew/bin/container", "/s/demo");
        let arguments: Vec<&str> = text
            .lines()
            .skip_while(|line| !line.contains("ProgramArguments"))
            .filter_map(|line| line.trim().strip_prefix("<string>"))
            .filter_map(|line| line.strip_suffix("</string>"))
            .collect();
        assert_eq!(
            arguments,
            [
                "/opt/homebrew/bin/container",
                "start",
                "demo",
                "/s/demo/launchd.out.log",
                "/s/demo/launchd.err.log"
            ]
        );
    }
}
