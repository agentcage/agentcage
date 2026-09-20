//! Reproduce `tests/fixtures/apple-container/`, recorded from the Python.
//!
//! The fixtures under that directory were produced by
//! `scripts/gen-apple-container-fixtures.py`, which drives the real
//! `backends/apple_container.py` with `platform.system()` patched to
//! `"Darwin"` — the same trick `tests/test_apple_container.py` has used
//! since that backend existed, because there is no macOS runner in CI
//! and there never has been. So this file runs on Linux and is not a
//! weaker check for it: it is the *same* check the Python suite makes,
//! against the same recording.
//!
//! What it covers is Track E's generation half A — image naming, the
//! egress content-hash wiring, `_render_egress_config`,
//! `_user_volume_argv`, `_tmpfs_targets` and `_tmpfs_copyup_seeds`.
//! `start`/`stop`/`_stage_secrets` are E5 and need a Mac.
//!
//! The fixture is the specification. Every expectation in it was
//! computed by running the Python, never typed, so a divergence here is
//! a diff rather than a judgement call. Re-blessing is
//! `uv run python scripts/gen-apple-container-fixtures.py`, and the
//! `--check` mode of the same script runs in CI so a change to the
//! Python that this port does not follow fails there too.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_cli::apple::egress_config::{render_dnsmasq_conf, render_egress_config};
use agentcage_cli::apple::image::{BuildFlags, egress_build_argv, egress_image_name};
use agentcage_cli::apple::volumes::{
    mask_mount_targets, tmpfs_copyup_seeds, tmpfs_targets, user_volume_argv,
};
use agentcage_core::config::FixedHost;
use agentcage_core::quadlets::QuadletHost;
use agentcage_state::{Paths, TestDir};
use serde_json::Value;

// ── fixture plumbing ─────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the fixtures are committed next to the Rust workspace")
}

fn fixture_root() -> PathBuf {
    repo_root().join("tests/fixtures/apple-container")
}

fn document(name: &str) -> Value {
    let path = fixture_root().join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{} is unreadable: {err}", path.display()));
    serde_json::from_str(&text).expect("the fixture is valid JSON")
}

fn text_of(value: &Value) -> &str {
    value.as_str().expect("a fixture string")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("a fixture array")
        .iter()
        .map(|item| text_of(item).to_owned())
        .collect()
}

/// Substitute the generator's tokens.
///
/// `{{ROOT}}` is the sandbox the recording was made in, `{{VERSION}}`
/// the package version at the time. Both are *deliberately* not in the
/// committed bytes: the first would pin someone's `/tmp`, the second
/// would go stale on every release.
fn untokenize(text: &str, root: &Path) -> String {
    text.replace("{{ROOT}}", &root.display().to_string())
        .replace("{{VERSION}}", agentcage_assets::VERSION)
}

/// A [`QuadletHost`] over a materialized fixture tree.
///
/// Real filesystem operations — `realpath` has to follow the symlinks
/// the tree carries, which is the whole point of two of the cases — but
/// the environment comes from the fixture rather than from the process,
/// so the test does not have to mutate `std::env` (which is
/// process-global and would race the other tests in this binary).
struct FixtureHost {
    home: String,
    env: Vec<(String, String)>,
}

impl QuadletHost for FixtureHost {
    fn env_var(&self, name: &str) -> Option<String> {
        self.env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }

    fn realpath(&self, path: &str) -> String {
        agentcage_cli::hostenv::realpath(path)
    }

    fn exists(&self, path: &str) -> bool {
        fs::metadata(path).is_ok()
    }

    fn is_dir(&self, path: &str) -> bool {
        fs::metadata(path).is_ok_and(|meta| meta.is_dir())
    }

    fn stage_vm_file_volume(&self, _source: &str, _deploy: &str) -> Result<String, String> {
        unreachable!("the apple backend never stages a vm file volume")
    }

    fn detect_default_creds_scope(&self) -> Option<String> {
        None
    }

    fn home(&self) -> String {
        self.home.clone()
    }
}

/// Materialize the tree `volumes.json` describes into a temp directory.
fn build_tree(tree: &Value) -> (TestDir, FixtureHost) {
    let dir = TestDir::new("apple-fixture");
    // `realpath` up front: on a host where the temp directory is itself
    // a symlink, every recorded path would otherwise differ from what
    // the checks below resolve to.
    let root = PathBuf::from(agentcage_cli::hostenv::realpath(
        &dir.path().display().to_string(),
    ));
    for rel in strings(&tree["dirs"]) {
        fs::create_dir_all(root.join(&rel)).expect("fixture directory");
    }
    for (link, target) in tree["symlinks"].as_object().expect("symlinks is an object") {
        let path = root.join(link);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("symlink parent");
        }
        std::os::unix::fs::symlink(text_of(target), &path).expect("fixture symlink");
    }
    let env = tree["env"]
        .as_object()
        .expect("env is an object")
        .iter()
        .map(|(key, value)| (key.clone(), untokenize(text_of(value), &root)))
        .collect();
    let host = FixtureHost {
        home: untokenize(text_of(&tree["home"]), &root),
        env,
    };
    (dir, host)
}

// ── image naming and the egress hash ─────────────────────────

/// The egress content hash, against the tree this binary carries.
///
/// The digest is already pinned by `tests/fixtures/egress_hash.json`
/// and checked in `agentcage-assets`. What this adds is that the value
/// the *Python* computed over the same tree, recorded independently, is
/// the same one — the cross-language half of the contract. A mismatch
/// means every Mac rebuilds its egress image once on upgrade and then
/// drifts permanently from the Python-computed tag.
#[test]
fn egress_content_hash_matches_the_python() {
    let fixture = document("image.json");
    assert_eq!(
        text_of(&fixture["content_hash"]),
        agentcage_assets::egress::content_hash(),
        "the egress content hash moved; if that was deliberate, re-bless \
         tests/fixtures/egress_hash.json too and expect every Mac to \
         rebuild once"
    );
}

#[test]
fn image_name_is_repo_version_hash() {
    let fixture = document("image.json");
    let expected =
        text_of(&fixture["image_name"]).replace("{{VERSION}}", agentcage_assets::VERSION);
    assert_eq!(
        agentcage_cli::apple::image::egress_image_name_embedded(),
        expected
    );
    assert_eq!(
        text_of(&fixture["repo"]),
        agentcage_cli::apple::image::EGRESS_IMAGE_REPO
    );
    assert_eq!(
        text_of(&fixture["containerfile_rel"]),
        agentcage_assets::egress::CONTAINERFILE_REL
    );
}

/// One byte of one `COPY` source changes the tag.
///
/// The recording is of the Python over a two-file build context; this
/// rebuilds that context and computes the same two tags. It is the
/// property the whole hash exists for (#312) — a version-only tag would
/// give the same string twice, which is how the #186 proxy-log fix
/// failed to reach hosts that already held `agentcage-egress:0.32.0`.
#[test]
fn a_changed_copy_source_changes_the_tag() {
    let fixture = document("image.json");
    let synthetic = &fixture["synthetic_context"];
    let dir = TestDir::new("apple-ctx");
    let context = dir.path();
    fs::create_dir_all(context.join("containers")).expect("containers/");
    fs::write(
        context.join(agentcage_assets::egress::CONTAINERFILE_REL),
        text_of(&synthetic["containerfile"]),
    )
    .expect("Containerfile");
    let source = context.join(text_of(&synthetic["copy_source_path"]));

    for phase in ["before", "after"] {
        fs::write(&source, text_of(&synthetic[phase]["body"])).expect("COPY source");
        assert_eq!(
            agentcage_cli::apple::image::egress_image_name_from_context(
                agentcage_assets::VERSION,
                context,
            ),
            untokenize(text_of(&synthetic[phase]["image_name"]), context),
            "{phase}: the tag over the synthetic context diverged"
        );
    }
    assert_ne!(
        text_of(&synthetic["before"]["image_name"]),
        text_of(&synthetic["after"]["image_name"]),
        "the fixture itself claims one byte does not move the tag"
    );
}

#[test]
fn build_argv_matches_the_python() {
    let fixture = document("image.json");
    let image = text_of(&fixture["image_name"]);
    let context = text_of(&fixture["build_context"]);
    for (key, flags) in [
        ("plain", BuildFlags::default()),
        (
            "no_cache",
            BuildFlags {
                no_cache: true,
                pull: false,
            },
        ),
        (
            "pull",
            BuildFlags {
                no_cache: false,
                pull: true,
            },
        ),
        (
            "no_cache_and_pull",
            BuildFlags {
                no_cache: true,
                pull: true,
            },
        ),
    ] {
        assert_eq!(
            egress_build_argv(image, Path::new(context), flags),
            strings(&fixture["build_argv"][key]),
            "{key}: the egress build argv diverged"
        );
    }
    // The fixture's `image_name` carries the `{{VERSION}}` token, so
    // the comparison above is of shape only; this pins the substitution
    // the real call makes.
    assert!(
        egress_image_name(agentcage_assets::VERSION, text_of(&fixture["content_hash"]))
            .starts_with(text_of(&fixture["repo"]))
    );
}

// ── the state root, and the XDG wart ─────────────────────────

/// The apple state root ignores `XDG_CONFIG_HOME`, and must keep doing so.
///
/// `_state_dir` is a bare `expanduser("~/.config/agentcage/apple-container")`.
/// A port that "fixed" it to follow XDG would relocate the state of
/// every cage a Python release deployed — and an XDG-only test sandbox
/// would not notice, which is why the fixture was recorded with the two
/// roots deliberately pointed at different places.
#[test]
fn state_paths_match_the_python() {
    let fixture = document("state-paths.json");
    let dir = TestDir::new("apple-state");
    let root = PathBuf::from(agentcage_cli::hostenv::realpath(
        &dir.path().display().to_string(),
    ));
    let env = &fixture["env"];
    let paths = Paths::from_roots(
        PathBuf::from(untokenize(text_of(&env["HOME"]), &root)),
        PathBuf::from(untokenize(text_of(&env["XDG_CONFIG_HOME"]), &root)),
        PathBuf::from(untokenize(text_of(&env["XDG_DATA_HOME"]), &root)),
        root.join("xdg/run"),
    );
    let name = text_of(&fixture["cage"]);
    let apple = &fixture["apple"];
    let expect = |key: &str| untokenize(text_of(&apple[key]), &root);

    assert_eq!(
        paths.apple_state_dir(name).display().to_string(),
        expect("state_dir")
    );
    assert_eq!(
        paths.apple_logs_dir(name).display().to_string(),
        expect("logs_dir")
    );
    assert_eq!(
        paths.apple_egress_config_dir(name).display().to_string(),
        expect("egress_config_dir")
    );
    assert_eq!(
        paths.apple_certs_dir(name).display().to_string(),
        expect("certs_dir")
    );
    assert_eq!(
        paths.apple_public_certs_dir(name).display().to_string(),
        expect("public_certs_dir")
    );
    assert_eq!(
        paths.apple_secrets_dir(name).display().to_string(),
        expect("secrets_dir")
    );
    assert_eq!(
        paths.apple_mask_mountpoints(name).display().to_string(),
        expect("mask_state_path")
    );

    // The contrast the fixture records: the container backend's secret
    // staging is a tmpfs under the runtime dir, the apple one is
    // persistent disk under the config root. Deliberate (plan section
    // 2.7) — macOS has neither an `XDG_RUNTIME_DIR` nor a tmpfs to use.
    let contrast = &fixture["contrast"];
    assert_eq!(
        paths.runtime_secrets_dir(name).display().to_string(),
        untokenize(text_of(&contrast["container_runtime_secrets_dir"]), &root)
    );
    assert!(
        paths
            .apple_secrets_dir(name)
            .starts_with(untokenize(text_of(&env["HOME"]), &root)),
        "the apple secrets dir must stay under HOME, not under XDG_CONFIG_HOME"
    );
}

// ── volumes and tmpfs ────────────────────────────────────────

#[expect(
    clippy::too_many_lines,
    reason = "one body per case, because the four helpers are checked \
              against the same case and in the order `start()` calls \
              them: the mask table is built from the argv the first one \
              returned. Splitting it would mean threading that argv \
              through helpers with no meaning apart from this sequence."
)]
#[test]
fn volumes_match_the_python() {
    let fixture = document("volumes.json");
    let (_dir, host) = build_tree(&fixture["tree"]);
    let root = PathBuf::from(host.home.trim_end_matches("/home"));
    let cases = fixture["cases"].as_array().expect("cases is an array");
    assert!(cases.len() >= 20, "the case table shrank unexpectedly");

    for case in cases {
        let id = text_of(&case["id"]);
        let volumes = strings(&case["volumes"]);
        let tmpfs = strings(&case["tmpfs"]);
        let skip: BTreeSet<String> = strings(&case["skip_targets"]).into_iter().collect();
        let expected = &case["expected"];

        let argv_expected = &expected["user_volume_argv"];
        let argv = match user_volume_argv(&volumes, &host) {
            Ok(argv) => {
                assert!(
                    argv_expected.get("error").is_none(),
                    "{id}: the Python raised and this did not"
                );
                argv
            }
            Err(error) => {
                // The one input that raises rather than warning: an `np`
                // option that cannot compose. Recorded with the Python's
                // exception class prefixed, as its corpus does.
                assert_eq!(
                    format!("ValueError: {error}"),
                    text_of(&argv_expected["error"]),
                    "{id}: the refusal message diverged"
                );
                continue;
            }
        };
        assert_eq!(
            argv.argv,
            strings(&argv_expected["argv"])
                .iter()
                .map(|s| untokenize(s, &root))
                .collect::<Vec<_>>(),
            "{id}: --volume argv diverged"
        );
        assert_eq!(
            argv.warnings,
            strings(&argv_expected["warnings"])
                .iter()
                .map(|s| untokenize(s, &root))
                .collect::<Vec<_>>(),
            "{id}: volume warnings diverged"
        );

        let targets = tmpfs_targets(&tmpfs);
        assert_eq!(
            targets.targets,
            strings(&expected["tmpfs_targets"]["targets"]),
            "{id}: --tmpfs targets diverged"
        );
        assert_eq!(
            targets.warnings,
            strings(&expected["tmpfs_targets"]["warnings"]),
            "{id}: tmpfs warnings diverged"
        );

        // The mask table is built from the EXPANDED entries, which is
        // what `start()` does. See the module docs.
        let mounts = mask_mount_targets(&argv.argv);
        let recorded: Vec<(String, String)> = expected["mask_mount_targets"]
            .as_array()
            .expect("mask_mount_targets is an array")
            .iter()
            .map(|pair| {
                (
                    untokenize(text_of(&pair[0]), &root),
                    untokenize(text_of(&pair[1]), &root),
                )
            })
            .collect();
        assert_eq!(
            mounts
                .iter()
                .map(|m| (m.target.clone(), m.source.clone()))
                .collect::<Vec<_>>(),
            recorded,
            "{id}: the mask mount table diverged"
        );

        let seeds = tmpfs_copyup_seeds(&tmpfs, &argv.argv, &skip, &host);
        let recorded: Vec<Vec<String>> = expected["tmpfs_copyup_seeds"]["seeds"]
            .as_array()
            .expect("seeds is an array")
            .iter()
            .map(|triple| {
                triple
                    .as_array()
                    .expect("a seed is a triple")
                    .iter()
                    .map(|part| untokenize(text_of(part), &root))
                    .collect()
            })
            .collect();
        assert_eq!(
            seeds
                .seeds
                .iter()
                .map(|seed| vec![
                    seed.host_source.clone(),
                    seed.lower.clone(),
                    seed.target.clone()
                ])
                .collect::<Vec<_>>(),
            recorded,
            "{id}: copy-up seeds diverged"
        );
        assert_eq!(
            seeds.warnings,
            strings(&expected["tmpfs_copyup_seeds"]["warnings"])
                .iter()
                .map(|s| untokenize(s, &root))
                .collect::<Vec<_>>(),
            "{id}: copy-up warnings diverged"
        );
    }
}

// ── the egress config ────────────────────────────────────────

/// Every apple case in the golden corpus, rendered.
///
/// This is what PR C8 left open: those cases carry a
/// `quadlets/NOT-APPLICABLE.txt` because the backend renders `container
/// run` argv and a launchd plist instead of units, and the artifacts it
/// *does* produce were recorded nowhere. Three of them are these files.
#[test]
fn egress_config_matches_the_python() {
    let fixture = document("egress-config.json");
    // The resolvers the generator pinned. `save_dns_allowlist` consults
    // the host only when the cage.yaml names none, and every fixture
    // input does — but a probe that read the developer's
    // /etc/resolv.conf would make this test machine-dependent, which is
    // exactly the bug the generator hit before it pinned them.
    let host = FixedHost::linux(&["192.0.2.53", "192.0.2.54"]);
    let cases = fixture["cases"].as_array().expect("cases is an array");
    assert!(cases.len() >= 10, "the case table shrank unexpectedly");

    for case in cases {
        let id = text_of(&case["case"]);
        let cage = text_of(&case["cage"]);
        let stored = case["stored"].as_bool().expect("stored is a bool");
        let dir = TestDir::new("apple-egress");
        let home = PathBuf::from(agentcage_cli::hostenv::realpath(
            &dir.path().display().to_string(),
        ));
        let paths = Paths::under(&home);
        let input = fixture_root().join(text_of(&case["input"]));

        // Both branches load the same cage.yaml; only one of them puts
        // it where `save_proxy_config` can find it. That IS the case
        // distinction: a stored config gets the full whitelisted
        // subset, an unstored one gets the minimal fallback.
        let config = if stored {
            paths
                .save_deployment(cage, &input)
                .expect("the fixture's cage.yaml is valid");
            paths
                .load_deployment_config(cage, &host)
                .expect("the stored config loads")
        } else {
            let text = fs::read_to_string(&input).expect("the fixture input is readable");
            let mut config =
                agentcage_core::config::load(&input.display().to_string(), &text, &host)
                    .expect("the fixture's cage.yaml is valid");
            if id == "pre-create-fallback-empty-dns-servers" {
                // No cage.yaml can express this: `load_config` replaces
                // an explicit `[]` with the host's resolvers. The
                // generator empties it on the loaded Config, so this
                // does the same.
                config.dns_servers.clear();
            }
            config
        };

        let rendered = render_egress_config(&paths, &config, cage, agentcage_core::VERSION, &host)
            .unwrap_or_else(|error| panic!("{id}: rendering failed: {error}"));
        assert_eq!(rendered.proxy_config_stored, stored, "{id}");
        assert_eq!(rendered.dns_allowlist_stored, stored, "{id}");

        for name in strings(&case["files"]) {
            let recorded =
                fs::read_to_string(fixture_root().join("egress-config").join(id).join(&name))
                    .unwrap_or_else(|err| panic!("{id}/{name} is unreadable: {err}"));
            let produced = fs::read_to_string(rendered.directory.join(&name))
                .unwrap_or_else(|err| panic!("{id}/{name} was not written: {err}"));
            assert_eq!(
                produced,
                recorded.replace("{{VERSION}}", agentcage_core::VERSION),
                "{id}: {name} diverged"
            );
        }
    }
}

/// The three files land where the egress bind-mounts them from.
#[test]
fn egress_config_lands_in_the_apple_state_root() {
    let dir = TestDir::new("apple-dest");
    let paths = Paths::under(dir.path());
    assert!(
        paths
            .apple_egress_config_dir("demo")
            .ends_with(".config/agentcage/apple-container/demo/egress-config")
    );
}

/// A sanity check on the renderer that does not go through a fixture:
/// the allowlist that reaches dnsmasq is the *effective* one.
#[test]
fn dnsmasq_scopes_recursion_per_zone() {
    let text = render_dnsmasq_conf(
        &["a.example.com".to_owned(), "b.example.com".to_owned()],
        &["192.0.2.53".to_owned(), "192.0.2.54".to_owned()],
    )
    .expect("renders");
    let forwarders: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("server="))
        .collect();
    // One line per (zone × upstream), and nothing else.
    assert_eq!(forwarders.len(), 4);
    for line in forwarders {
        assert!(line.starts_with("server=/"), "unscoped forwarder: {line}");
    }
}
