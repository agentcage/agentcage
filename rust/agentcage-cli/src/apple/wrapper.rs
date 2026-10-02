//! `apple_container/wrapper.py` — the per-cage wrapper image.
//!
//! The wrapper is `FROM <user image>` plus two scripts: `cage-init.sh`,
//! which becomes PID 1 of the cage microVM, and `cage-cmd.sh`, which
//! carries the user's own argv shell-escaped at **build** time. Nothing
//! of the proxy is in it — mitmproxy, dnsmasq and the supervisor live
//! in the egress sibling, built once per host from the shared
//! `agentcage-egress` image.
//!
//! # Why the argv is baked rather than passed
//!
//! The legacy wrapper shipped `cage-cmd.json` and parsed it in-guest
//! with `jq` at boot. That made the cage's entrypoint a string the
//! guest had to interpret, which is an argv-injection surface for any
//! `container.command` carrying a shell metacharacter. The Python
//! instead `shlex.quote`s each element host-side and writes
//! `exec <quoted argv>` into a `/bin/sh` script with a `RUN` heredoc,
//! so the guest parses nothing. [`shlex_join`] is that quoting, and it
//! is [`agentcage_core::quadlets::shlex_quote`] — the same function the
//! quadlet backend's mask hooks use, because it is the same `shlex`.

use std::path::Path;

use agentcage_core::quadlets::shlex_quote;
use agentcage_exec::tools::apple::AppleContainer;
use serde_json::Value;

/// The embedded template, relative to the `data` tree.
const WRAPPER_TEMPLATE: &str = "apple-container/Containerfile.wrapper.j2";

/// `cage-init.sh`, relative to the `data` tree.
const CAGE_INIT: &str = "apple-container/cage-init.sh";

/// `wrapped_image_name` — `localhost/agentcage-apple-<cage>:latest`.
///
/// Unchanged since the legacy single-VM model on purpose: `cage update`
/// on a cage last deployed by 0.21 finds the existing tag and replaces
/// it in place. Apple's `container build` retags freely, so the fact
/// that the *content* is unrecognizable to the legacy supervisor does
/// not matter.
#[must_use]
pub fn wrapped_image_name(cage: &str) -> String {
    format!("localhost/agentcage-apple-{cage}:latest")
}

/// `_shlex_join_argv` — shell-escape each element and join with spaces.
#[must_use]
pub fn shlex_join(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| shlex_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `_user_cmd` — the user image's effective CMD (`ENTRYPOINT` + `CMD`).
///
/// Apple's `container image inspect` answers with the OCI image index
/// plus a per-platform variant block, and the OCI config sits at
/// `variants[<platform>].config.config` with capitalized keys. The
/// arm64 variant wins; the first variant is the fallback, and three
/// older/flatter schemas are tried after that, exactly as the Python
/// does.
///
/// # Errors
///
/// A message ready to print when the image cannot be inspected, or
/// when it declares neither an entrypoint nor a command — there is
/// nothing to run in that case, and guessing would start a cage that
/// exits immediately.
pub fn user_cmd(
    runner: &dyn agentcage_exec::CommandRunner,
    image: &str,
) -> Result<Vec<String>, String> {
    let cli = AppleContainer::new(runner);
    let data = cli
        .image_inspect(image)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("cannot inspect user cage image '{image}'; is it pulled/built?"))?;

    let config = image_config(&data);
    let entrypoint = string_list(
        config
            .as_ref()
            .and_then(|c| c.get("Entrypoint").or_else(|| c.get("entrypoint"))),
    );
    let command = string_list(
        config
            .as_ref()
            .and_then(|c| c.get("Cmd").or_else(|| c.get("cmd"))),
    );
    let combined: Vec<String> = entrypoint.into_iter().chain(command).collect();
    if combined.is_empty() {
        return Err(format!(
            "user cage image '{image}' has neither ENTRYPOINT nor CMD; \
             agentcage cannot determine what to run"
        ));
    }
    Ok(combined)
}

/// The OCI config block, across the four schemas the Python tries.
fn image_config(data: &Value) -> Option<Value> {
    if let Some(variants) = data
        .get("variants")
        .or_else(|| data.get("Variants"))
        .and_then(Value::as_array)
    {
        let arm64 = variants.iter().find(|variant| {
            variant
                .get("platform")
                .and_then(|p| p.get("architecture"))
                .and_then(Value::as_str)
                == Some("arm64")
        });
        // `cfg = ((v["config"] or {})["config"]) or {}` — an empty map
        // when the keys are absent, which is *not* the same as falling
        // through to the flatter schemas below. The Python only tries
        // those when no variants list was found at all.
        if let Some(variant) = arm64.or_else(|| variants.first()) {
            return Some(
                variant
                    .get("config")
                    .and_then(|c| c.get("config"))
                    .cloned()
                    .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
            );
        }
    }
    data.get("config")
        .and_then(|c| c.get("config"))
        .or_else(|| data.get("config"))
        .or_else(|| data.get("Config"))
        .cloned()
}

/// Python's `[x] if isinstance(x, str) else (x or [])`, for a JSON
/// value that should be an argv.
fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(one)) => vec![one.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// `render_wrapper_containerfile` — the Containerfile, as text.
///
/// # Errors
///
/// A message ready to print when the template is missing from the
/// embedded tree or fails to render.
pub fn render_wrapper_containerfile(
    user_image: &str,
    user_cmd: &[String],
) -> Result<String, String> {
    let source = embedded(WRAPPER_TEMPLATE)?;
    let source = std::str::from_utf8(source)
        .map_err(|_| format!("{WRAPPER_TEMPLATE} is not valid UTF-8"))?;
    agentcage_core::quadlets::templates::render_source_untrimmed(
        WRAPPER_TEMPLATE,
        source,
        &serde_json::json!({
            "user_image": user_image,
            "user_cmd_quoted": shlex_join(user_cmd),
        }),
    )
    .map_err(|error| format!("could not render {WRAPPER_TEMPLATE}: {error}"))
}

/// `stage_build_context` — `cage-init.sh`, and nothing else.
///
/// The 2-microVM refactor moved every other file the legacy context
/// carried into the egress image or onto the host bind mounts, so the
/// Python's remaining body is a single `shutil.copy2`. Its back-compat
/// keyword arguments are not reproduced: there is no caller here that
/// could pass them.
///
/// # Errors
///
/// An I/O message when the directory cannot be created or the script
/// cannot be written.
pub fn stage_build_context(dest: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dest).map_err(|error| format!("{}: {error}", dest.display()))?;
    let bytes = embedded(CAGE_INIT)?;
    let target = dest.join("cage-init.sh");
    std::fs::write(&target, bytes).map_err(|error| format!("{}: {error}", target.display()))?;
    // `shutil.copy2` carries the mode across. The asset tree records
    // 0755 for this file and the build `COPY`s it, then `chmod`s it in
    // the image anyway, so the host-side mode is belt and braces --
    // but a non-executable staged script is the kind of difference
    // that only shows up as a cage that will not boot.
    set_executable(&target)?;
    Ok(())
}

/// 0755, the mode the asset tree records for `cage-init.sh`.
fn set_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// One file out of the embedded `data` tree.
fn embedded(relative: &str) -> Result<&'static [u8], String> {
    agentcage_assets::tree("data")
        .find(|(path, _)| *path == relative)
        .map(|(_, file)| file.bytes)
        .ok_or_else(|| format!("{relative} is not in the embedded asset tree"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        image_config, render_wrapper_containerfile, shlex_join, string_list, wrapped_image_name,
    };

    #[test]
    fn the_per_cage_tag_is_the_legacy_one() {
        assert_eq!(
            wrapped_image_name("demo"),
            "localhost/agentcage-apple-demo:latest"
        );
    }

    /// The quoting is what keeps a metacharacter out of the `exec`
    /// line, so it is asserted on the shapes that would break it.
    #[test]
    fn the_argv_is_shell_escaped_elementwise() {
        assert_eq!(
            shlex_join(&["sleep".to_owned(), "infinity".to_owned()]),
            "sleep infinity"
        );
        assert_eq!(
            shlex_join(&[
                "sh".to_owned(),
                "-c".to_owned(),
                "echo $HOME && id".to_owned()
            ]),
            "sh -c 'echo $HOME && id'"
        );
        assert_eq!(shlex_join(&[String::new()]), "''");
        assert_eq!(shlex_join(&["it's".to_owned()]), r#"'it'"'"'s'"#);
    }

    /// The arm64 variant wins over an earlier amd64 one.
    #[test]
    fn the_config_comes_from_the_arm64_variant() {
        let data = json!({
            "variants": [
                {"platform": {"architecture": "amd64"},
                 "config": {"config": {"Cmd": ["/amd64"]}}},
                {"platform": {"architecture": "arm64"},
                 "config": {"config": {"Cmd": ["/arm64"]}}},
            ]
        });
        let config = image_config(&data).expect("a config");
        assert_eq!(string_list(config.get("Cmd")), vec!["/arm64".to_owned()]);
    }

    /// A variants list with no arm64 entry falls back to the first,
    /// and a missing nested config is an empty map rather than a
    /// fall-through to the flat schemas.
    #[test]
    fn a_variants_list_never_falls_through_to_the_flat_schema() {
        let data = json!({
            "variants": [{"platform": {"architecture": "amd64"}}],
            "config": {"Cmd": ["/flat"]},
        });
        let config = image_config(&data).expect("a config");
        assert!(string_list(config.get("Cmd")).is_empty(), "{config:?}");
    }

    #[test]
    fn a_string_entrypoint_becomes_a_one_element_argv() {
        assert_eq!(
            string_list(Some(&json!("/bin/sh"))),
            vec!["/bin/sh".to_owned()]
        );
        assert!(string_list(Some(&json!([]))).is_empty());
        assert!(string_list(None).is_empty());
    }

    /// The whitespace settings are the Python's, so the rendered file
    /// opens with the blank line the comment block leaves behind.
    #[test]
    fn the_render_keeps_the_comment_blocks_newline() {
        let text = render_wrapper_containerfile(
            "docker.io/library/ubuntu:24.04",
            &["sleep".to_owned(), "infinity".to_owned()],
        )
        .expect("renders");
        assert!(text.starts_with('\n'), "{:?}", &text[..40]);
        assert!(
            text.contains("FROM docker.io/library/ubuntu:24.04"),
            "{text}"
        );
        assert!(text.contains("exec sleep infinity"), "{text}");
        assert!(text.ends_with("CMD []\n"), "{:?}", &text[text.len() - 40..]);
    }
}
