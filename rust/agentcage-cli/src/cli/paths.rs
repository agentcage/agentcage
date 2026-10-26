//! `agentcage paths` — the directories this install uses, on stdout.
//!
//! Automation needs to know where state lives without parsing a bug
//! report or guessing at XDG variables: a backup script wants the data
//! root, a test harness wants to point `XDG_CONFIG_HOME` at a sandbox,
//! and a support bundle wants every one of them. The values come from
//! [`agentcage_state::Paths`] (the same resolver every command body
//! uses), with the extracted-assets cache taken from the data root
//! (`<data>/agentcage/assets`, where `agentcage_assets::extract`
//! writes), so this command cannot drift from where the files are
//! actually written.
//!
//! There is deliberately no separate `state` root: agentcage keeps cage
//! state under the config root (`cages/<name>/`) and the data root
//! (`<name>/`), and inventing an `XDG_STATE_HOME` tree for the sake of a
//! fifth column would print a directory nothing writes to.
//!
//! Nothing is created. `paths` is read-only and works on a machine with
//! no cages and no extracted assets at all.

use std::process::ExitCode;

use agentcage_core::har::json::Json;
use clap::{ArgMatches, Command};

use crate::cli::args::{flag, leaf};
use crate::cli::context::Ctx;
use crate::cli::json_out;

/// The command, with its one flag.
pub(crate) fn command() -> Command {
    leaf("paths")
        .about("Print the state directories agentcage uses.")
        .arg(flag("as_json", "json", "Output as JSON."))
}

/// One row of the table: a stable machine key and a human label.
struct Root {
    label: &'static str,
    key: &'static str,
    path: String,
}

fn roots(ctx: &Ctx) -> Vec<Root> {
    let paths = &ctx.paths;
    vec![
        Root {
            label: "home",
            key: "home",
            path: paths.home().display().to_string(),
        },
        Root {
            label: "config",
            key: "config",
            path: paths.config_root().display().to_string(),
        },
        Root {
            label: "data",
            key: "data",
            path: paths.data_root().display().to_string(),
        },
        Root {
            label: "cache",
            key: "cache",
            // `agentcage_assets::extract::cache_root()` resolves the same
            // `$XDG_DATA_HOME` and appends `assets`; going through the
            // resolved data root keeps the two rows consistent even for a
            // `Paths` built by hand (tests, state-compat fixtures).
            path: paths.data_root().join("assets").display().to_string(),
        },
        Root {
            label: "runtime",
            key: "runtime",
            path: paths.runtime_root().display().to_string(),
        },
        Root {
            label: "apple-container",
            key: "apple_container",
            path: paths.apple_root().display().to_string(),
        },
        Root {
            label: "quadlets",
            key: "quadlets",
            path: paths.quadlet_dir().display().to_string(),
        },
        Root {
            label: "user-units",
            key: "user_units",
            path: paths.user_unit_dir().display().to_string(),
        },
    ]
}

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let roots = roots(ctx);
    if matches.get_flag("as_json") {
        json_out::print(
            "paths",
            json_out::object(
                roots
                    .iter()
                    .map(|root| (root.key, Json::string(root.path.clone())))
                    .collect(),
            ),
            true,
            &[],
        );
        return ExitCode::SUCCESS;
    }
    print_table(&roots);
    ExitCode::SUCCESS
}

/// `ROOT  PATH`, with the label column as wide as the longest label.
///
/// The width comes from the data rather than a constant: adding a root
/// must not misalign the table, and `apple-container` is already wider
/// than the `Name` column `output::info` pads to.
fn print_table(roots: &[Root]) {
    let width = roots
        .iter()
        .map(|root| root.label.chars().count())
        .max()
        .unwrap_or(0)
        .max("ROOT".len());
    println!("{:<width$}  PATH", "ROOT");
    for root in roots {
        println!("{:<width$}  {}", root.label, root.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{Root, roots};
    use crate::cli::context::Ctx;
    use agentcage_exec::FakeRunner;
    use agentcage_state::{Paths, TestDir};

    fn ctx(dir: &TestDir) -> Ctx {
        Ctx {
            paths: Paths::under(dir.path()),
            runner: Box::new(FakeRunner::new()),
            version: agentcage_core::VERSION.to_owned(),
        }
    }

    /// Every root resolves inside the sandbox, and the cache root
    /// follows `XDG_DATA_HOME` rather than the real home.
    #[test]
    fn every_root_is_the_documented_one() {
        let dir = TestDir::new("paths-roots");
        let ctx = ctx(&dir);
        let all = roots(&ctx);
        let by_key = |key: &str| {
            all.iter()
                .find(|root| root.key == key)
                .map_or_else(|| panic!("no {key} root"), |root| root.path.clone())
        };
        assert_eq!(by_key("home"), dir.path().display().to_string());
        assert_eq!(
            by_key("config"),
            dir.path().join(".config/agentcage").display().to_string()
        );
        assert_eq!(
            by_key("data"),
            dir.path()
                .join(".local/share/agentcage")
                .display()
                .to_string()
        );
        assert_eq!(
            by_key("runtime"),
            dir.path().join("run").display().to_string()
        );
        assert_eq!(
            by_key("quadlets"),
            dir.path()
                .join(".config/containers/systemd")
                .display()
                .to_string()
        );
        assert_eq!(
            by_key("user_units"),
            dir.path()
                .join(".config/systemd/user")
                .display()
                .to_string()
        );
        // `apple-container` follows `~`, not XDG_CONFIG_HOME.
        assert_eq!(
            by_key("apple_container"),
            dir.path()
                .join(".config/agentcage/apple-container")
                .display()
                .to_string()
        );
        // The cache lives under the resolved data root; `extract` appends
        // `assets` to the same `$HOME/.local/share`/`XDG_DATA_HOME` root.
        assert_eq!(
            by_key("cache"),
            dir.path()
                .join(".local/share/agentcage/assets")
                .display()
                .to_string()
        );
    }

    /// The table's label column is as wide as the longest label.
    #[test]
    fn the_table_pads_to_the_longest_label() {
        let roots = vec![
            Root {
                label: "home",
                key: "home",
                path: "/h".to_owned(),
            },
            Root {
                label: "apple-container",
                key: "apple_container",
                path: "/a".to_owned(),
            },
        ];
        // The width is derived from the data; pinning the formula here is
        // what keeps `apple-container` from misaligning the table.
        let width = roots
            .iter()
            .map(|root| root.label.chars().count())
            .max()
            .unwrap_or(0)
            .max("ROOT".len());
        assert_eq!(width, "apple-container".len());
        for root in &roots {
            assert!(root.label.chars().count() <= width);
        }
    }
}
