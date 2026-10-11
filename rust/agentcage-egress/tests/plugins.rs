//! Custom inspectors end to end: the example plugins and a misbehaving
//! fixture, compiled to WebAssembly components and loaded through
//! `agentcage_egress::plugin`.
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
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use agentcage_egress::inspect::{
    Action, Context, Direction, Inspector, Phase, Severity, Verdict, run_chain,
};
use agentcage_egress::json::Json;
use agentcage_egress::plugin::{Limits, Loader};

const CRATES: [(&str, &str); 3] = [
    ("header-policy-inspector", "header_policy_inspector"),
    ("dlp-regex-inspector", "dlp_regex_inspector"),
    ("misbehaving-inspector", "misbehaving_inspector"),
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
fn plugin_dir() -> Option<&'static Path> {
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

macro_rules! plugins_or_skip {
    () => {
        match plugin_dir() {
            Some(dir) => dir,
            None => return,
        }
    };
}

fn loader(dir: &Path) -> Loader {
    Loader::new(vec![dir.to_path_buf()], Limits::default())
}

fn load(dir: &Path, name: &str, file: &str, config: &str) -> Arc<dyn Inspector> {
    loader(dir)
        .load(name, &format!("{file}.wasm"), config)
        .unwrap_or_else(|e| panic!("load {file}: {e}"))
}

fn ctx(headers: &[(&str, &str)], body: Option<&str>) -> Context {
    let body_bytes = body.map(|b| b.as_bytes().to_vec());
    Context {
        url: "https://api.example.com/v1/items?q=1".into(),
        host: "api.example.com".into(),
        method: "POST".into(),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        content_type: "application/json".into(),
        body_size: body_bytes.as_ref().map_or(0, Vec::len),
        body_entropy: body_bytes
            .as_deref()
            .filter(|b| !b.is_empty())
            .map(agentcage_egress::inspect::shannon_entropy),
        body_text: body.map(str::to_owned),
        body_bytes,
        ..Context::default()
    }
}

fn verdict_of(plugin: &dyn Inspector, ctx: &Context) -> Verdict {
    plugin.inspect_request(ctx).expect("a verdict")
}

// ── The examples ────────────────────────────────────────────

#[test]
fn header_policy_flags_or_blocks_a_missing_header() {
    let dir = plugins_or_skip!();
    let flagger = load(dir, "header-policy", "header_policy_inspector", "{}");
    assert!(
        flagger
            .inspect_request(&ctx(&[("X-Trace-ID", "abc")], None))
            .is_none()
    );
    let v = verdict_of(flagger.as_ref(), &ctx(&[("Accept", "*/*")], None));
    assert_eq!(v.inspector, "header-policy");
    assert_eq!(v.action, Action::Flag);
    assert_eq!(v.severity, Severity::Warning);
    assert_eq!(v.reason, "Missing mandatory header: x-trace-id");
    assert_eq!(
        v.metadata,
        [("target_host".to_owned(), Json::string("api.example.com"))]
    );

    let blocker = load(
        dir,
        "header-policy",
        "header_policy_inspector",
        r#"{"required_header": "X-Request-Owner", "block_on_missing": true}"#,
    );
    let v = verdict_of(blocker.as_ref(), &ctx(&[("X-Trace-ID", "abc")], None));
    assert_eq!(v.action, Action::Block);
    assert_eq!(v.severity, Severity::Error);
    assert_eq!(v.reason, "Missing mandatory header: x-request-owner");
}

#[test]
fn a_config_the_plugin_refuses_fails_the_load() {
    let dir = plugins_or_skip!();
    let err = loader(dir)
        .load(
            "header-policy",
            "header_policy_inspector.wasm",
            r#"{"block_on_missing": "yes"}"#,
        )
        .unwrap_err();
    assert_eq!(
        err,
        "inspector header-policy: configure refused: block_on_missing must be a boolean"
    );
    let err = loader(dir)
        .load(
            "dlp",
            "dlp_regex_inspector.wasm",
            r#"{"patterns": [{"name": "x", "regex": "("}]}"#,
        )
        .unwrap_err();
    assert!(
        err.starts_with("inspector dlp: configure refused: patterns[0].regex: regex parse error"),
        "{err}"
    );
}

#[test]
fn dlp_regex_reports_where_it_matched_but_not_what() {
    let dir = plugins_or_skip!();
    let dlp = load(
        dir,
        "dlp",
        "dlp_regex_inspector",
        r#"{"patterns": [{"name": "codename", "regex": "(?i)\\bblue[- ]?falcon\\b"},
                         {"name": "ssn", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b"}]}"#,
    );
    assert!(
        dlp.inspect_request(&ctx(&[], Some(r#"{"a": "fine"}"#)))
            .is_none()
    );
    let v = verdict_of(dlp.as_ref(), &ctx(&[], Some(r#"{"note": "Blue-Falcon"}"#)));
    assert_eq!(v.action, Action::Block);
    assert_eq!(v.severity, Severity::Error);
    assert_eq!(v.reason, r#"DLP pattern "codename" matched in the body"#);
    let v = verdict_of(dlp.as_ref(), &ctx(&[("X-Id", "123-45-6789")], None));
    assert_eq!(v.reason, r#"DLP pattern "ssn" matched in the headers"#);
    // Responses are opt-in.
    assert!(
        dlp.inspect_response(&ctx(&[], Some("blue falcon")))
            .is_none()
    );
}

#[test]
fn plugins_sit_in_the_chain_with_built_ins() {
    let dir = plugins_or_skip!();
    let chain: Vec<Arc<dyn Inspector>> = vec![
        load(dir, "header-policy", "header_policy_inspector", "{}"),
        load(
            dir,
            "dlp",
            "dlp_regex_inspector",
            r#"{"patterns": [{"name": "n", "regex": "secret-plan"}]}"#,
        ),
        load(
            dir,
            "never",
            "misbehaving_inspector",
            r#"{"mode": "block"}"#,
        ),
    ];
    let mut c = ctx(&[], Some("the secret-plan"));
    let out = run_chain(&chain, &mut c, Phase::Request, &|_| false);
    let names: Vec<&str> = out.iter().map(|v| v.inspector.as_str()).collect();
    assert_eq!(names, ["header-policy", "dlp"]);
    assert_eq!(c.prior_results.len(), 2);
}

#[test]
fn the_chain_builder_loads_plugins_through_the_wasm_loader() {
    use agentcage_egress::config::Config;
    use agentcage_egress::inspect::chain::build_chain;
    use agentcage_egress::inspect::domain::DomainInspector;
    use agentcage_egress::plugin::WasmPluginLoader;

    let dir = plugins_or_skip!();
    let plugins = WasmPluginLoader::new(loader(dir));
    let domain = Arc::new(DomainInspector::new());
    let build = |yaml: &str| {
        let yaml = format!("domains: {{allow: [api.example.com]}}\n{yaml}");
        let cfg = Config::parse("config.yaml", &yaml).unwrap();
        build_chain(&cfg, &domain, &plugins)
            .map(agentcage_egress::inspect::chain::PendingChain::commit)
    };

    // The same component twice, under two names with two configs: each
    // slot runs as its own entry, with its own config.
    let chain = build(
        "inspectors:\n\
         \x20 - name: dlp-plan\n\
         \x20   path: dlp_regex_inspector.wasm\n\
         \x20   config: {patterns: [{name: plan, regex: secret-plan}], action: flag}\n\
         \x20 - name: dlp-key\n\
         \x20   path: dlp_regex_inspector.wasm\n\
         \x20   config: {patterns: [{name: key, regex: 'KEY-[0-9]+'}]}\n",
    )
    .unwrap();
    let names: Vec<&str> = chain.inspectors().iter().map(|i| i.name()).collect();
    assert_eq!(names[names.len() - 2..], ["dlp-plan", "dlp-key"]);
    let mut c = ctx(&[], Some("the secret-plan, KEY-42"));
    let out = run_chain(chain.inspectors(), &mut c, Phase::Request, &|_| false);
    let found: Vec<(&str, Action)> = out
        .iter()
        .map(|v| (v.inspector.as_str(), v.action))
        .collect();
    assert_eq!(
        found,
        [("dlp-plan", Action::Flag), ("dlp-key", Action::Block)]
    );

    // A rebuild (a reload) with a changed config takes effect.
    let chain = build(
        "inspectors:\n\
         \x20 - name: dlp-key\n\
         \x20   path: dlp_regex_inspector.wasm\n\
         \x20   config: {patterns: [{name: key, regex: 'KEY-[0-9]+'}], action: flag}\n",
    )
    .unwrap();
    let mut c = ctx(&[], Some("KEY-42"));
    let out = run_chain(chain.inspectors(), &mut c, Phase::Request, &|_| false);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].inspector.as_str(), out[0].action),
        ("dlp-key", Action::Flag)
    );

    // Anything that cannot be loaded fails the whole build (D1): a
    // missing file, an entry without a name, a config the plugin refuses.
    let Err(err) = build("inspectors:\n  - {name: x, path: missing.wasm}\n") else {
        panic!("refused");
    };
    assert!(err.contains("not found"), "{err}");
    let Err(err) = build("inspectors:\n  - {path: dlp_regex_inspector.wasm}\n") else {
        panic!("refused");
    };
    assert!(err.contains("needs a name"), "{err}");
    let Err(err) = build("inspectors:\n  - {name: dlp, path: dlp_regex_inspector.wasm}\n") else {
        panic!("refused");
    };
    assert!(
        err.contains("dlp: configure refused: patterns must be"),
        "{err}"
    );
}

// ── The context crosses intact ──────────────────────────────

#[test]
fn the_context_reaches_the_plugin_intact() {
    let dir = plugins_or_skip!();
    let p = load(
        dir,
        "probe",
        "misbehaving_inspector",
        r#"{"mode": "describe"}"#,
    );
    let mut c = ctx(&[("B", "2"), ("a", "1"), ("B", "3")], Some("hé"));
    c.prior_results.push(Verdict {
        metadata: vec![(
            "m".to_owned(),
            Json::Object(vec![("k".to_owned(), Json::Array(vec![Json::Int(1)]))]),
        )],
        ..Verdict::new("secrets", Action::Flag, "r", Severity::Error)
    });
    let v = verdict_of(p.as_ref(), &c);
    // The plugin's verdict is attributed to the configured name.
    assert_eq!(v.inspector, "probe");
    assert_eq!(
        v.reason,
        "Phase::Request Direction::Outbound POST https://api.example.com/v1/items?q=1 [B=2;a=1;B=3] \
         ct=application/json body=Some(3) text=Some(\"hé\") size=3 \
         entropy=Some(1.584962500721156) prior=[secrets:m={\"k\":[1]}]"
    );
    assert_eq!(
        v.metadata,
        [("host".to_owned(), Json::string("api.example.com"))]
    );

    let mut c = ctx(&[], None);
    c.direction = Direction::Inbound;
    let v = p.inspect_response(&c).unwrap();
    assert!(
        v.reason
            .starts_with("Phase::Response Direction::Inbound POST https://api.example.com/v1/items?q=1 [] ct=application/json body=None text=None size=0 entropy=None"),
        "{}",
        v.reason
    );
    c.websocket = true;
    assert!(
        p.inspect_response(&c)
            .unwrap()
            .reason
            .starts_with("Phase::Websocket Direction::Inbound")
    );
}

// ── Failing closed ──────────────────────────────────────────

fn failure(dir: &Path, mode: &str) -> Verdict {
    let p = load(
        dir,
        "bad",
        "misbehaving_inspector",
        &format!(r#"{{"mode": "{mode}"}}"#),
    );
    let v = verdict_of(p.as_ref(), &ctx(&[], Some("x")));
    assert_eq!(v.action, Action::Block, "{mode}: {}", v.reason);
    assert_eq!(v.severity, Severity::Error);
    assert_eq!(v.inspector, "bad");
    assert!(
        v.reason.starts_with("inspector bad failed: "),
        "{}",
        v.reason
    );
    v
}

#[test]
fn a_panic_blocks() {
    let dir = plugins_or_skip!();
    let v = failure(dir, "panic");
    assert!(v.reason.contains("unreachable"), "{}", v.reason);
}

#[test]
fn an_endless_loop_runs_out_of_fuel_and_blocks() {
    let dir = plugins_or_skip!();
    let start = Instant::now();
    let v = failure(dir, "loop");
    assert_eq!(
        v.reason,
        format!(
            "inspector bad failed: exceeded its CPU budget of {} fuel",
            Limits::DEFAULT_FUEL
        )
    );
    // The budget is meant to be tens of milliseconds; allow for a slow,
    // unoptimised CI machine.
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
}

#[test]
fn hoarding_memory_hits_the_limit_and_blocks() {
    let dir = plugins_or_skip!();
    let v = failure(dir, "alloc");
    assert_eq!(
        v.reason,
        "inspector bad failed: exceeded its memory limit of 64 MiB"
    );
}

#[test]
fn metadata_that_is_not_json_is_a_malformed_verdict() {
    let dir = plugins_or_skip!();
    let v = failure(dir, "bad-metadata");
    assert_eq!(
        v.reason,
        "inspector bad failed: malformed verdict: metadata \"k\" is not JSON"
    );
}

#[test]
fn reaching_for_a_capability_traps() {
    let dir = plugins_or_skip!();
    for mode in ["fs", "clock"] {
        let v = failure(dir, mode);
        assert!(v.reason.contains("unknown import"), "{mode}: {}", v.reason);
    }
    // The environment is answered, empty: there is nothing to read.
    let p = load(dir, "env", "misbehaving_inspector", r#"{"mode": "env"}"#);
    assert_eq!(
        verdict_of(p.as_ref(), &ctx(&[], None)).reason,
        "Err(NotPresent)"
    );
    // And `HashMap` works: its seed is the one other thing answered.
    let p = load(
        dir,
        "map",
        "misbehaving_inspector",
        r#"{"mode": "hashmap"}"#,
    );
    assert_eq!(verdict_of(p.as_ref(), &ctx(&[], None)).reason, "1");
}

#[test]
fn a_broken_instance_is_replaced_not_reused() {
    let dir = plugins_or_skip!();
    let p = load(dir, "bad", "misbehaving_inspector", r#"{"mode": "panic"}"#);
    for _ in 0..3 {
        let v = verdict_of(p.as_ref(), &ctx(&[], None));
        assert_eq!(v.action, Action::Block);
        // A poisoned instance would fail differently (or not at all) on
        // reuse; a fresh one fails the same way every time.
        assert!(v.reason.contains("unreachable"), "{}", v.reason);
    }
}

#[test]
fn a_configure_that_traps_or_refuses_fails_the_load() {
    let dir = plugins_or_skip!();
    let err = loader(dir)
        .load("bad", "misbehaving_inspector.wasm", r#"{"mode": "refuse"}"#)
        .unwrap_err();
    assert_eq!(err, "inspector bad: configure refused: mode refuse says no");
    let err = loader(dir)
        .load(
            "bad",
            "misbehaving_inspector.wasm",
            r#"{"mode": "configure-panic"}"#,
        )
        .unwrap_err();
    assert!(err.starts_with("inspector bad: "), "{err}");
    assert!(err.contains("unreachable"), "{err}");
}

#[test]
fn bytes_that_are_not_a_component_fail_the_load() {
    let dir = plugins_or_skip!();
    let scratch = Scratch::new("notwasm");
    std::fs::write(scratch.0.join("junk.wasm"), b"\0asm junk").unwrap();
    let err = Loader::new(vec![scratch.0.clone()], Limits::default())
        .load("junk", "junk.wasm", "{}")
        .unwrap_err();
    assert!(err.starts_with("inspector junk: "), "{err}");
    // And a core module that is valid wasm but not a component.
    std::fs::write(scratch.0.join("core.wasm"), b"\0asm\x01\0\0\0").unwrap();
    let err = Loader::new(vec![scratch.0.clone()], Limits::default())
        .load("core", "core.wasm", "{}")
        .unwrap_err();
    assert!(err.starts_with("inspector core: "), "{err}");
    let _ = dir;
}

#[test]
fn concurrent_calls_each_get_an_instance() {
    let dir = plugins_or_skip!();
    let p = load(
        dir,
        "dlp",
        "dlp_regex_inspector",
        r#"{"patterns": [{"name": "n", "regex": "needle"}]}"#,
    );
    std::thread::scope(|s| {
        for i in 0..8 {
            let p = Arc::clone(&p);
            s.spawn(move || {
                for j in 0..50 {
                    let body = if (i + j) % 2 == 0 { "a needle" } else { "hay" };
                    let got = p.inspect_request(&ctx(&[], Some(body)));
                    assert_eq!(got.is_some(), body.contains("needle"));
                }
            });
        }
    });
}

// ── Path confinement ────────────────────────────────────────

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agentcage-plugin-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn paths_are_confined_to_the_plugin_directories() {
    let root = Scratch::new("confine");
    let plugins = root.0.join("plugins");
    let outside = root.0.join("outside");
    std::fs::create_dir_all(plugins.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(plugins.join("a.wasm"), b"").unwrap();
    std::fs::write(plugins.join("sub/b.wasm"), b"").unwrap();
    std::fs::write(outside.join("evil.wasm"), b"").unwrap();
    std::fs::write(plugins.join("a.py"), b"").unwrap();
    std::os::unix::fs::symlink(outside.join("evil.wasm"), plugins.join("link.wasm")).unwrap();
    std::os::unix::fs::symlink(&outside, plugins.join("dirlink")).unwrap();
    std::fs::create_dir_all(plugins.join("dir.wasm")).unwrap();
    let l = Loader::new(
        vec![root.0.join("missing"), plugins.clone()],
        Limits::default(),
    );
    let real = std::fs::canonicalize(&plugins).unwrap();

    assert_eq!(l.resolve("a.wasm").unwrap(), real.join("a.wasm"));
    assert_eq!(l.resolve("sub/b.wasm").unwrap(), real.join("sub/b.wasm"));
    let abs = plugins.join("a.wasm");
    assert_eq!(
        l.resolve(abs.to_str().unwrap()).unwrap(),
        real.join("a.wasm")
    );

    let err = l.resolve("a.py").unwrap_err();
    assert!(err.contains("is not a .wasm component"), "{err}");
    assert!(err.contains("docs/how-to/custom-inspectors.md"), "{err}");
    for escape in [
        "link.wasm",
        "dirlink/evil.wasm",
        "../outside/evil.wasm",
        outside.join("evil.wasm").to_str().unwrap(),
    ] {
        let err = l.resolve(escape).unwrap_err();
        assert!(
            err.contains("is outside allowed directories"),
            "{escape}: {err}"
        );
    }
    assert!(l.resolve("nope.wasm").unwrap_err().contains("not found"));
    assert!(
        l.resolve("dir.wasm")
            .unwrap_err()
            .contains("not a regular file")
    );
}

// ── Measurements (P0.4) ─────────────────────────────────────

/// Per-call latency, pooled instances versus one instantiation (plus
/// `configure`) per call. Run with
/// `cargo test --release -p agentcage-egress --test plugins -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn measure_call_latency() {
    let dir = plugins_or_skip!();
    let dlp_cfg = r#"{"patterns": [{"name": "codename", "regex": "(?i)\\bblue[- ]?falcon\\b"},
                                   {"name": "ssn", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b"}]}"#;
    let cases = [
        ("header-policy", "header_policy_inspector", "{}"),
        ("dlp", "dlp_regex_inspector", dlp_cfg),
    ];
    let small = ctx(
        &[("Accept", "*/*"), ("X-Trace-ID", "1")],
        Some(r#"{"q": "hello"}"#),
    );
    let big_body = "lorem ipsum dolor sit amet ".repeat(40_000); // ~1 MiB
    let big = ctx(&[("X-Trace-ID", "1")], Some(&big_body));
    for (name, file, cfg) in cases {
        let start = Instant::now();
        let p = load(dir, name, file, cfg);
        println!(
            "{name}: first load (compile + instantiate + configure) {:?}",
            start.elapsed()
        );
        let start = Instant::now();
        let _again = load(dir, name, file, cfg);
        println!(
            "{name}: cached load (instantiate + configure) {:?}",
            start.elapsed()
        );
        for (label, c) in [("small body", &small), ("1 MiB body", &big)] {
            let n = if label == "small body" { 2000 } else { 50 };
            let _ = p.inspect_request(c);
            let start = Instant::now();
            for _ in 0..n {
                let _ = p.inspect_request(c);
            }
            println!(
                "{name}: pooled call, {label}: {:?}/call",
                start.elapsed() / n
            );
            let start = Instant::now();
            for _ in 0..(n / 10).max(5) {
                let fresh = load(dir, name, file, cfg);
                let _ = fresh.inspect_request(c);
            }
            println!(
                "{name}: per-call instantiation, {label}: {:?}/call",
                start.elapsed() / (n / 10).max(5)
            );
        }
    }
    // Fuel calibration: how long does the default budget last?
    let p = load(dir, "bad", "misbehaving_inspector", r#"{"mode": "loop"}"#);
    let start = Instant::now();
    let v = p.inspect_request(&small).unwrap();
    println!(
        "endless loop: {:?} until \"{}\" ({} fuel)",
        start.elapsed(),
        v.reason,
        Limits::DEFAULT_FUEL
    );
}
