//! The golden corpus, against the Rust quadlet renderer.
//!
//! `tests/fixtures/golden/` records every unit file
//! `quadlets.generate_quadlets` produced for each valid case, and the
//! corpus README puts quadlets on the **byte-exact** side of its
//! comparison line: systemd is a byte-sensitive consumer, so "close
//! enough" is not a category here. Reproducing all of them is PR C8's
//! acceptance check (RUST-PORT-PLAN.md §4, Layer 1).
//!
//! # Why this test builds a filesystem
//!
//! `generate_quadlets` probes the host: it expands `~` and `$VAR` in
//! volume sources, calls `realpath`, refuses a source outside the home
//! directory, skips one that does not exist, and copies a single-file
//! source for the VM backend. The corpus was generated against a
//! hermetic tree the harness built under a throwaway work directory, so
//! this test rebuilds the same tree and answers those probes from it,
//! through [`QuadletHost`].
//!
//! Replaying the corpus's *scrubbed* paths instead — rendering with
//! `{{HOME}}` as the literal home — would be simpler and wrong:
//! `quadlets.py` runs `shlex.quote` over several host paths, and
//! `shlex.quote("{{HOME}}/x")` adds single quotes that
//! `shlex.quote("/tmp/…/home/x")` does not. So the render happens
//! against real paths and the *output* is scrubbed, which is the order
//! the harness used.
//!
//! # The base64 blobs
//!
//! `quadlets.py` base64-encodes host paths before embedding them in a
//! systemd `Exec=` line (a path is quoted once by systemd and again by
//! bash, and no single escaping survives both layers). A plain string
//! replace cannot see inside that blob, so the harness's scrubber
//! decodes candidates, scrubs, and re-encodes — the corpus stores
//! `base64("{{HOME}}/project")`. [`Scrubber`] reimplements that,
//! including the decode, because a reimplementation that skipped it
//! would fail on exactly the cases the mask bookkeeping exists for.

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_core::config::{Config, FixedHost, load};
use agentcage_core::quadlets::{
    GenerateOptions, QuadletHost, StatePaths, effective_dns_allowlist, generate_quadlets,
};

use common::repo_root;

/// What the harness pins `importlib.metadata.version("agentcage")` to,
/// so a release does not churn the corpus.
const FROZEN_VERSION: &str = "0.0.0-golden";

/// What it pins `config._host_dns_servers()` to.
const FROZEN_DNS_SERVERS: [&str; 2] = ["192.0.2.53", "192.0.2.54"];

/// What it pins `secret_resolver.detect_default_scope()` to.
const FROZEN_CREDS_SCOPE: &str = "user";

/// `tests/fixtures/golden/`.
fn corpus() -> PathBuf {
    repo_root().join("tests/fixtures/golden")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// One case, as `manifest.json` describes it.
struct Case {
    name: String,
    kind: String,
    platform: Vec<String>,
    stage: Option<String>,
}

fn manifest() -> Vec<Case> {
    let text = read(&corpus().join("manifest.json"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("manifest JSON");
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            name: case["case"].as_str().expect("case").to_owned(),
            kind: case["kind"].as_str().expect("kind").to_owned(),
            platform: case["platform"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            stage: case["stage"].as_str().map(str::to_owned),
        })
        .collect()
}

/// The isolation backend `config.default_isolation()` would pick on the
/// platform the harness pinned for this case.
fn host_probe(platform: &[String]) -> FixedHost {
    let isolation = match (
        platform.first().map(String::as_str),
        platform.get(1).map(String::as_str),
    ) {
        (Some("Darwin"), Some("arm64")) => "apple-container",
        (Some("Darwin"), _) => "vm",
        _ => "container",
    };
    FixedHost {
        isolation: isolation.to_owned(),
        dns_servers: Ok(FROZEN_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()),
    }
}

// ─── the hermetic tree ───────────────────────────────────────

/// The harness's `_build_sandbox`, rebuilt.
///
/// Same directories, same single-file volume source, same environment —
/// because a volume that does not exist is *skipped with a warning*, so
/// a missing directory here would not fail loudly, it would quietly
/// change the units.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    environment: BTreeMap<String, String>,
}

impl Sandbox {
    fn build(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "agentcage-golden-quadlets-{}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("work dir");
        // Resolve once: on macOS `/tmp` is a symlink, and every path
        // that reaches a unit has been through `realpath`.
        let root = fs::canonicalize(&root).expect("canonical work dir");
        let home = root.join("home");
        for relative in [
            ".config/agentcage",
            ".local/share/agentcage",
            "agent",
            "project",
            "workspace",
            "data",
            "e2e-work/test-agent",
            "certs",
        ] {
            fs::create_dir_all(home.join(relative)).expect("sandbox dir");
        }
        fs::write(home.join("dotfile.conf"), "# fake dotfile\n").expect("dotfile");
        fs::write(
            home.join("certs/fake-ca.pem"),
            "-----BEGIN CERTIFICATE-----\nRkFLRS1DRVJUSUZJQ0FURS1OT1QtUkVBTA==\n-----END CERTIFICATE-----\n",
        )
        .expect("fake ca");
        fs::create_dir_all(root.join("run")).expect("runtime dir");
        fs::create_dir_all(root.join("patches")).expect("patches dir");

        let mut environment = BTreeMap::new();
        for (key, value) in [
            ("HOME", home.display().to_string()),
            (
                "XDG_CONFIG_HOME",
                home.join(".config").display().to_string(),
            ),
            (
                "XDG_DATA_HOME",
                home.join(".local/share").display().to_string(),
            ),
            ("XDG_RUNTIME_DIR", root.join("run").display().to_string()),
            ("GOLDEN_AGENT_DIR", home.join("agent").display().to_string()),
            ("TZ", "UTC".to_owned()),
            ("GOLDEN_SET_VAR", "set-value".to_owned()),
            // GOLDEN_UNSET_VAR is deliberately absent: it is what makes
            // the "unresolved variable" warning reachable.
        ] {
            environment.insert(key.to_owned(), value);
        }
        Self {
            root,
            home,
            environment,
        }
    }

    fn state(&self) -> StatePaths {
        StatePaths {
            config_root: self.home.join(".config/agentcage").display().to_string(),
            data_root: self
                .home
                .join(".local/share/agentcage")
                .display()
                .to_string(),
        }
    }

    /// The harness runs each case with the working directory set to
    /// `$HOME/e2e-work`, which is what a relative volume source
    /// resolves against.
    fn cwd(&self) -> PathBuf {
        self.home.join("e2e-work")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// [`QuadletHost`] over a real directory tree, with the process
/// environment replaced by the sandbox's.
///
/// Nothing here reads `std::env`: the harness's environment is data, and
/// a test that mutated the process environment would race every other
/// test in the binary.
struct SandboxHost<'a> {
    sandbox: &'a Sandbox,
}

impl SandboxHost<'_> {
    /// `os.path.abspath` — relative to the harness's working directory.
    fn absolute(&self, path: &str) -> PathBuf {
        if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            self.sandbox.cwd().join(path)
        }
    }
}

impl QuadletHost for SandboxHost<'_> {
    fn env_var(&self, name: &str) -> Option<String> {
        self.sandbox.environment.get(name).cloned()
    }

    fn realpath(&self, path: &str) -> String {
        // `os.path.realpath` is non-strict: it resolves as far as the
        // filesystem goes and keeps the rest verbatim.
        let absolute = self.absolute(path);
        let mut trailing: Vec<std::ffi::OsString> = Vec::new();
        let mut probe = absolute.clone();
        loop {
            if let Ok(resolved) = fs::canonicalize(&probe) {
                let mut out = resolved;
                for part in trailing.iter().rev() {
                    out.push(part);
                }
                return out.display().to_string();
            }
            match probe.file_name() {
                Some(name) => {
                    trailing.push(name.to_owned());
                    if !probe.pop() {
                        return absolute.display().to_string();
                    }
                }
                None => return absolute.display().to_string(),
            }
        }
    }

    fn exists(&self, path: &str) -> bool {
        fs::metadata(self.absolute(path)).is_ok()
    }

    fn is_dir(&self, path: &str) -> bool {
        fs::metadata(self.absolute(path)).is_ok_and(|meta| meta.is_dir())
    }

    fn stage_vm_file_volume(&self, source: &str, deploy_name: &str) -> Result<String, String> {
        // `_stage_vm_file_volume`, including its use of a literal
        // `~/.local/share` rather than `XDG_DATA_HOME`. In the sandbox
        // the two coincide, which is why the corpus cannot tell them
        // apart — but the implementation should still be the one the
        // Python has.
        let data_dir = self.realpath(&format!(
            "{}/.local/share/agentcage",
            self.sandbox.home.display()
        ));
        let seed = PathBuf::from(data_dir).join(deploy_name).join("seed");
        fs::create_dir_all(&seed).map_err(|error| error.to_string())?;
        let name = Path::new(source)
            .file_name()
            .ok_or_else(|| format!("no basename in {source}"))?;
        let staged = seed.join(name);
        fs::copy(source, &staged).map_err(|error| error.to_string())?;
        Ok(staged.display().to_string())
    }

    fn detect_default_creds_scope(&self) -> Option<String> {
        Some(FROZEN_CREDS_SCOPE.to_owned())
    }
}

// ─── the scrubber ────────────────────────────────────────────

/// The harness's `Scrubber`, reimplemented.
///
/// Longest prefix first, so `$HOME/.config` is not half-rewritten by
/// the `$HOME` rule, and base64 blobs are rewritten from the inside
/// before the plain replace runs — the same order, because a blob whose
/// decoded text contains a scrubbed path must round-trip through
/// `base64` rather than being matched as text.
struct Scrubber {
    rules: Vec<(String, &'static str)>,
}

impl Scrubber {
    fn new(sandbox: &Sandbox) -> Self {
        let work = sandbox.root.display().to_string();
        let home = sandbox.home.display().to_string();
        let mut rules: Vec<(String, &'static str)> = vec![
            (format!("{home}/.local/share"), "{{XDG_DATA_HOME}}"),
            (format!("{home}/.config"), "{{XDG_CONFIG_HOME}}"),
            (home, "{{HOME}}"),
            (format!("{work}/run"), "{{XDG_RUNTIME_DIR}}"),
            (work, "{{WORK}}"),
            (repo_root().display().to_string(), "{{REPO}}"),
        ];
        rules.sort_by_key(|(raw, _)| std::cmp::Reverse(raw.len()));
        Self { rules }
    }

    fn text(&self, value: &str) -> String {
        self.replace(&self.scrub_base64(value))
    }

    fn replace(&self, value: &str) -> String {
        let mut out = value.to_owned();
        for (raw, token) in &self.rules {
            if !raw.is_empty() && out.contains(raw.as_str()) {
                out = out.replace(raw.as_str(), token);
            }
        }
        out
    }

    /// `_B64_RE.sub(self._scrub_b64, value)` — `[A-Za-z0-9+/]{16,}={0,2}`.
    ///
    /// A run shorter than 16 characters cannot match at any offset
    /// inside itself either, so walking maximal runs is the same search
    /// the regex engine does, greedily.
    fn scrub_base64(&self, value: &str) -> String {
        let bytes = value.as_bytes();
        let is_alphabet = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
        // Bytes, not chars: the alphabet is ASCII, so a run boundary is
        // always a character boundary, but a non-matching byte may be
        // part of a multi-byte character (the templates are full of
        // em-dashes) and must be copied through untouched.
        let mut out: Vec<u8> = Vec::with_capacity(value.len());
        let mut index = 0;
        while index < bytes.len() {
            if !is_alphabet(bytes[index]) {
                out.push(bytes[index]);
                index += 1;
                continue;
            }
            let start = index;
            while index < bytes.len() && is_alphabet(bytes[index]) {
                index += 1;
            }
            let body_end = index;
            let mut padding = 0;
            while padding < 2 && index < bytes.len() && bytes[index] == b'=' {
                padding += 1;
                index += 1;
            }
            let blob = &value[start..index];
            if body_end - start >= 16 {
                out.extend_from_slice(self.scrub_blob(blob).as_bytes());
            } else {
                out.extend_from_slice(blob.as_bytes());
            }
        }
        String::from_utf8(out).expect("only ASCII runs were rewritten")
    }

    fn scrub_blob(&self, blob: &str) -> String {
        let Some(decoded) = base64_decode(blob) else {
            return blob.to_owned();
        };
        let Ok(text) = String::from_utf8(decoded) else {
            return blob.to_owned();
        };
        let scrubbed = self.replace(&text);
        if scrubbed == text {
            return blob.to_owned();
        }
        agentcage_core::quadlets::b64(&scrubbed)
    }
}

/// `base64.b64decode(blob, validate=True)` — `None` where it raises.
#[expect(
    clippy::cast_possible_truncation,
    reason = "each shift-and-mask yields one byte by construction"
)]
fn base64_decode(blob: &str) -> Option<Vec<u8>> {
    if blob.len() % 4 != 0 || blob.is_empty() {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let bytes = blob.as_bytes();
    let mut out = Vec::with_capacity(blob.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let padding = if chunk.ends_with(b"==") {
            2
        } else {
            usize::from(chunk.ends_with(b"="))
        };
        if chunk[..4 - padding].contains(&b'=') {
            return None;
        }
        let mut triple = 0u32;
        for (offset, c) in chunk.iter().enumerate().take(4 - padding) {
            triple |= value(*c)? << (18 - 6 * offset);
        }
        out.push((triple >> 16) as u8);
        if padding < 2 {
            out.push((triple >> 8) as u8);
        }
        if padding < 1 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

// ─── the tests ───────────────────────────────────────────────

/// Render one case the way the harness did.
fn render_case(
    sandbox: &Sandbox,
    config: &Config,
) -> Result<agentcage_core::quadlets::Quadlets, agentcage_core::config::ConfigError> {
    let host = SandboxHost { sandbox };
    let state = sandbox.state();
    let deploy = config.name.clone();
    let config_host_path = format!("{}/cage.yaml", state.deployment_dir(&deploy));
    let patches = sandbox.root.join("patches").display().to_string();
    generate_quadlets(
        config,
        &GenerateOptions {
            config_host_path: &config_host_path,
            patches_host_dir: &patches,
            deploy_name: &deploy,
            rootless: true,
            used_octets: None,
            network_octet: None,
            store_secrets: None,
            state: &state,
            version: FROZEN_VERSION,
        },
        &host,
    )
}

/// The acceptance check: every unit file in the corpus, byte for byte.
#[test]
fn every_valid_case_reproduces_its_quadlets() {
    let sandbox = Sandbox::build("units");
    let scrubber = Scrubber::new(&sandbox);
    let root = corpus();

    let mut wrong: Vec<String> = Vec::new();
    let mut checked_cases = 0;
    let mut checked_units = 0;
    let mut not_applicable = 0;

    for case in manifest() {
        if case.kind != "valid" {
            continue;
        }
        let directory = root.join("valid").join(&case.name);
        let quadlets_dir = directory.join("quadlets");
        if quadlets_dir.join("NOT-APPLICABLE.txt").is_file() {
            // apple-container: `backends/apple_container.py` builds
            // `container run` argv and a launchd plist instead, and
            // never calls this module. Track E's, not C8's.
            not_applicable += 1;
            continue;
        }

        let stored = read(&directory.join("stored-cage.yaml"));
        let config = match load("cage.yaml", &stored, &host_probe(&case.platform)) {
            Ok(config) => config,
            Err(error) => {
                wrong.push(format!(
                    "{}: stored config does not load: {error}",
                    case.name
                ));
                continue;
            }
        };
        let produced = match render_case(&sandbox, &config) {
            Ok(produced) => produced,
            Err(error) => {
                wrong.push(format!("{}: render failed: {error}", case.name));
                continue;
            }
        };
        checked_cases += 1;

        let expected_names: Vec<String> = sorted_unit_names(&quadlets_dir);
        let mut produced_names: Vec<String> = produced.files.keys().cloned().collect();
        produced_names.sort();
        if produced_names != expected_names {
            wrong.push(format!(
                "{}: unit files differ\n  expected: {expected_names:?}\n  produced: {produced_names:?}",
                case.name
            ));
            continue;
        }

        for (filename, content) in &produced.files {
            let expected = read(&quadlets_dir.join(filename));
            let produced_text = scrubber.text(content);
            checked_units += 1;
            if produced_text != expected {
                wrong.push(format!(
                    "{}/{filename}:\n{}",
                    case.name,
                    first_difference(&expected, &produced_text)
                ));
            }
        }

        // `render-warnings.txt` is the Python's stderr, and it is on the
        // byte-exact side of the corpus's line too — these strings are
        // what an operator sees when a volume is skipped.
        let expected_warnings = read(&directory.join("render-warnings.txt"));
        let mut produced_warnings = String::new();
        for warning in &produced.warnings {
            produced_warnings.push_str(&scrubber.text(warning));
            produced_warnings.push('\n');
        }
        if produced_warnings != expected_warnings {
            wrong.push(format!(
                "{}/render-warnings.txt:\n{}",
                case.name,
                first_difference(&expected_warnings, &produced_warnings)
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} cases diverge:\n\n{}",
        wrong.len(),
        checked_cases,
        wrong.join("\n\n")
    );
    assert_eq!(
        not_applicable, 5,
        "the corpus's apple-container case count moved; check whether the new ones are really \
         outside quadlets.py"
    );
    assert_eq!(
        checked_cases, 120,
        "expected every valid case that has units; the corpus grew or shrank"
    );
    assert!(checked_units >= 600, "only {checked_units} units compared");
}

/// The one refusal `generate_quadlets` itself raises, as the corpus
/// records it.
///
/// The manifest marks three cases as failing at `"stage": "render"`;
/// the other two are `state.resolve_relay_ca_files`, which runs before
/// the renderer and belongs to Track D. Asserting the whole set here
/// means a fourth one added later has to be triaged rather than
/// silently landing outside any Rust test.
#[test]
fn a_volume_outside_the_home_directory_is_refused() {
    let render_stage: Vec<String> = manifest()
        .into_iter()
        .filter(|case| case.stage.as_deref() == Some("render"))
        .map(|case| case.name)
        .collect();
    assert_eq!(
        render_stage,
        [
            "err-relay-ca-file-missing",
            "err-relay-ca-file-not-pem",
            "err-volume-outside-home",
        ]
    );

    let sandbox = Sandbox::build("outside-home");
    let scrubber = Scrubber::new(&sandbox);
    let directory = corpus().join("invalid/err-volume-outside-home");
    let input = read(&directory.join("input/cage.yaml"));
    let expected = read(&directory.join("error.txt"));

    let config = load(
        "cage.yaml",
        &input,
        &host_probe(&["Linux".to_owned(), "x86_64".to_owned()]),
    )
    .expect("the config itself is valid");
    let error = render_case(&sandbox, &config).expect_err("outside the home directory");
    assert_eq!(
        format!("{}\n", scrubber.text(&error.as_python_traceback_line())),
        expected
    );
}

/// `state.save_dns_allowlist`'s output, which is
/// `quadlets._effective_dns_allowlist` crossed with `dns_servers`.
///
/// The file itself is `state.py`'s (Track D), but the ordering and the
/// merge — passthrough, then relay upstreams, then each enabled agent's
/// LLM host — are this module's, and nothing else in the corpus
/// exercises them. Applies to the apple-container cases too: that
/// backend skips the quadlets, not the allowlist.
#[test]
fn every_valid_case_reproduces_its_dns_allowlist() {
    let root = corpus();
    let mut wrong: Vec<String> = Vec::new();
    let mut checked = 0;

    for case in manifest() {
        if case.kind != "valid" {
            continue;
        }
        let directory = root.join("valid").join(&case.name);
        let stored = read(&directory.join("stored-cage.yaml"));
        let Ok(config) = load("cage.yaml", &stored, &host_probe(&case.platform)) else {
            continue;
        };
        let mut lines = String::new();
        for domain in effective_dns_allowlist(&config) {
            for server in &config.dns_servers {
                writeln!(lines, "server=/{domain}/{server}").expect("String write");
            }
        }
        let expected = read(&directory.join("dns-allowlist.conf"));
        checked += 1;
        if lines != expected {
            wrong.push(format!(
                "{}:\n{}",
                case.name,
                first_difference(&expected, &lines)
            ));
        }
    }

    assert!(wrong.is_empty(), "{}", wrong.join("\n\n"));
    assert_eq!(checked, 125);
}

/// Every `.j2` under `src/agentcage/templates/` is byte-identical to
/// what git has.
///
/// The port renders the templates rather than rewriting them, because
/// Python renders the same files until cutover. This is the tripwire
/// for "I made the Rust pass by editing the template".
#[test]
fn the_templates_are_unmodified() {
    // The renderer reads them through the embedded assets, so comparing
    // the embed against the working tree is what proves both halves see
    // the same bytes.
    let package = repo_root().join("src/agentcage");
    let mut seen = 0;
    for (name, file) in agentcage_assets::tree("templates") {
        let path = package.join("templates").join(name);
        let on_disk = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            on_disk, file.bytes,
            "{name} differs between the working tree and the embed"
        );
        seen += 1;
    }
    assert!(seen >= 4, "only {seen} templates embedded");
}

/// Sorted unit filenames in a case's `quadlets/` directory.
fn sorted_unit_names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("reading {}: {error}", directory.display()))
        .map(|entry| entry.expect("dir entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The first differing line, with a little context — a whole unit file
/// in the failure output buries the one byte that moved.
fn first_difference(expected: &str, produced: &str) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let produced_lines: Vec<&str> = produced.lines().collect();
    for (index, (want, got)) in expected_lines.iter().zip(produced_lines.iter()).enumerate() {
        if want != got {
            return format!("  line {}:\n  - {want}\n  + {got}", index + 1);
        }
    }
    format!(
        "  line count: expected {} lines, produced {}\n  - {:?}\n  + {:?}",
        expected_lines.len(),
        produced_lines.len(),
        expected_lines.get(produced_lines.len().min(expected_lines.len())),
        produced_lines.get(expected_lines.len().min(produced_lines.len())),
    )
}
