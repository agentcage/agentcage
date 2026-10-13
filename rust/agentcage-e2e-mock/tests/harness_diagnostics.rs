//! The e2e harness's failure diagnostics and macOS host guard.
//!
//! Issue #317 reported two halves of the same problem: running
//! `bash tests/e2e/run.sh container` on macOS produced
//!
//! ```text
//! Phase 1: FAIL (0/0, 46s)
//! Total: 0 passed
//! ```
//!
//! with no explanation whatsoever.
//!
//! 1. `tests/e2e/lib.sh` swallowed the reason. `create_cage` folded
//!    stderr into stdout and every caller redirected stdout to
//!    `/dev/null`; `start_mock`'s image lookup died on a bare
//!    `set -e`/`pipefail` assignment before it could say anything.
//! 2. `tests/e2e/run.sh container` ran the wrong backend in the first
//!    place: the e2e configs pin no `isolation:` key, `container`
//!    isolation is rejected on macOS, so the phases silently resolved to
//!    apple-container whose image store podman cannot see.
//!
//! These tests drive the real shell scripts under a temp `PATH` of fake
//! shims so the host-specific paths can be exercised from any CI, plus a
//! few static checks for branches that cannot run without a real phase.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{Run, TempDir, e2e_dir, repo_root, run_bash, run_snippet, write_shim};

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref()).unwrap_or_else(|e| panic!("{}: {e}", path.as_ref().display()))
}

fn lib_sh() -> PathBuf {
    e2e_dir().join("lib.sh")
}

fn run_sh() -> PathBuf {
    e2e_dir().join("run.sh")
}

/// Lines that are not shell comments.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with('#'))
}

// ── run.sh refuses the podman-backed phases on a macOS host ──────────

struct DarwinHost {
    tmp: TempDir,
    bindir: PathBuf,
    touched: PathBuf,
}

impl DarwinHost {
    fn new() -> Self {
        let tmp = TempDir::new("darwin");
        let bindir = tmp.path().join("fakebin");
        fs::create_dir(&bindir).unwrap();
        // `uname -s` reports Darwin so the guard fires from any CI host.
        write_shim(&bindir, "uname", "echo Darwin");
        // Tripwires: the guard must fire BEFORE any backend command (or
        // the mock build) runs. If run.sh reaches its stale-cage sweep or
        // a phase, these record it.
        let touched = tmp.path().join("touched");
        for cmd in ["agentcage", "podman", "limactl", "container", "cargo"] {
            write_shim(
                &bindir,
                cmd,
                &format!("echo \"$0 $*\" >> \"{}\"\nexit 0", touched.display()),
            );
        }
        Self {
            tmp,
            bindir,
            touched,
        }
    }

    fn run(&self, args: &[&str]) -> Run {
        let run_sh = run_sh();
        let mut command = vec![run_sh.to_str().unwrap()];
        command.extend_from_slice(args);
        let _ = &self.tmp;
        run_bash(&command, &self.bindir, &[], Duration::from_secs(30))
    }

    fn assert_untouched(&self) {
        assert!(
            !self.touched.exists(),
            "guard ran backend commands before refusing: {}",
            fs::read_to_string(&self.touched).unwrap_or_default()
        );
    }
}

#[test]
fn run_sh_refuses_container_phases_on_darwin() {
    let cases: &[(&[&str], &str)] = &[
        (&["container"], "1 2 3 4 5 6 9"),
        (&["openclaw"], "8"),
        (&["all"], "1 2 3 4 5 6 8 9"),
        (&[], "1 2 3 4 5 6 8 9"), // no args: all phases
        (&["1"], "1"),
        (&["3", "7"], "3"), // 7 alone is fine, 3 is not
    ];
    for (args, expected) in cases {
        let host = DarwinHost::new();
        let r = host.run(args);
        assert_eq!(r.code, 1, "{args:?}\n{}", r.both());
        assert!(
            r.stderr.contains(&format!("phase(s) {expected} need")),
            "{args:?}\n{}",
            r.both()
        );
        host.assert_untouched();
    }
}

#[test]
fn run_sh_darwin_message_names_the_real_constraint_and_is_actionable() {
    let host = DarwinHost::new();
    let err = host.run(&["container"]).stderr;
    // Why, not just no.
    for want in [
        "'container' isolation (rootless podman)",
        "does not support on macOS",
        "podman cannot see",
        "#317",
    ] {
        assert!(err.contains(want), "missing {want:?} in:\n{err}");
    }
    // Where to go instead.
    for want in ["run.sh vm", "phase_apple.sh", "Linux host"] {
        assert!(err.contains(want), "missing {want:?} in:\n{err}");
    }
}

#[test]
fn run_sh_darwin_refusal_goes_to_stderr() {
    // stdout stays clean so it can't be mistaken for a phase result.
    let r = DarwinHost::new().run(&["container"]);
    assert!(!r.stdout.contains("ERROR"), "{}", r.both());
    assert!(r.stderr.starts_with("ERROR:"), "{}", r.both());
}

#[test]
fn run_sh_help_and_unknown_args_still_work_on_darwin() {
    // `-h` is handled during argument parsing and must not be blocked.
    let host = DarwinHost::new();
    let r = host.run(&["-h"]);
    assert_eq!(r.code, 0, "{}", r.both());
    assert!(r.stdout.contains("Usage:"), "{}", r.both());
    assert!(!r.stderr.contains("ERROR"), "{}", r.both());
    host.assert_untouched();

    let r = DarwinHost::new().run(&["bogus"]);
    assert_eq!(r.code, 1, "{}", r.both());
    assert!(r.stdout.contains("Unknown argument: bogus"), "{}", r.both());
}

#[test]
fn run_sh_guard_is_darwin_scoped_and_excludes_the_vm_phase() {
    // Static: phase 7 (Lima VM) is supported on macOS, so it must not be
    // in the blocked set, and the guard must sit behind a Darwin test so
    // Linux behaviour is unchanged. Asserted statically rather than by
    // running `run.sh vm`, which would launch the real phase 7.
    let text = read(run_sh());
    assert!(text.contains(r#"[ "$(uname -s)" = "Darwin" ]"#));
    assert!(text.contains("1|2|3|4|5|6|8|9) BLOCKED+="));
    assert!(!text.contains("|7|"));
    // The guard precedes the first thing that talks to a backend (the
    // stale-cage sweep, through the overridable "$AGENTCAGE") and the
    // mock build.
    let guard = text.find("BLOCKED+=").unwrap();
    assert!(guard < text.find(r#""$AGENTCAGE" cage list"#).unwrap());
    assert!(guard < text.find("e2e_mock_bin").unwrap());
}

// ── create_cage explains a failed create ─────────────────────────────

struct CreateHost {
    tmp: TempDir,
    bindir: PathBuf,
    config: PathBuf,
}

impl CreateHost {
    fn new() -> Self {
        let tmp = TempDir::new("create");
        let bindir = tmp.path().join("fakebin");
        fs::create_dir(&bindir).unwrap();
        // envsubst isn't installed everywhere; `cat` is a faithful
        // stand-in for a config with no ${VAR} references.
        write_shim(&bindir, "envsubst", "exec cat");
        // The failure dump queries systemd, podman and the journal; keep
        // it off the real host.
        for cmd in ["podman", "systemctl", "journalctl", "nsenter"] {
            write_shim(&bindir, cmd, "exit 1");
        }
        let config = tmp.path().join("cage.yaml");
        fs::write(&config, "name: e2e-fake\n").unwrap();
        Self {
            tmp,
            bindir,
            config,
        }
    }

    fn agentcage(&self, body: &str) {
        write_shim(&self.bindir, "agentcage", body);
    }

    fn create(&self, redirect: &str) -> Run {
        let _ = &self.tmp;
        let script = format!(
            "source \"{}\"\nrc=0\ncreate_cage \"{}\" {redirect} || rc=$?\necho \"RC=$rc\"\n",
            lib_sh().display(),
            self.config.display()
        );
        run_snippet(&script, &self.bindir, &[])
    }
}

#[test]
fn create_cage_failure_output_survives_dev_null_caller() {
    // The phase idiom `create_cage ... >/dev/null` must still show why a
    // create failed: the #317 regression.
    let host = CreateHost::new();
    host.agentcage(
        "echo \"Building egress image...\"\n\
         echo \"Error: container isolation is not available on macOS\" >&2\n\
         exit 42",
    );
    let r = host.create(">/dev/null");
    assert!(r.stdout.contains("RC=42"), "{}", r.both());
    assert!(
        r.stderr.contains("cage create FAILED (exit 42)"),
        "{}",
        r.both()
    );
    // Both streams of the failed command are preserved.
    assert!(
        r.stderr
            .contains("container isolation is not available on macOS")
    );
    assert!(r.stderr.contains("Building egress image..."));
}

#[test]
fn create_cage_failure_names_the_config() {
    let host = CreateHost::new();
    host.agentcage("exit 1");
    let r = host.create(">/dev/null");
    assert!(r.stderr.contains("cage.yaml"), "{}", r.both());
}

#[test]
fn create_cage_mute_failure_still_reports() {
    // A create that dies mutely still yields an exit code and a frame,
    // never a bare `FAIL (0/0)`.
    let host = CreateHost::new();
    host.agentcage("exit 7");
    let r = host.create(">/dev/null");
    assert!(r.stdout.contains("RC=7"), "{}", r.both());
    assert!(
        r.stderr.contains("cage create FAILED (exit 7)"),
        "{}",
        r.both()
    );
    assert!(r.stderr.contains("(no output)"), "{}", r.both());
}

#[test]
fn create_cage_success_stays_quiet() {
    // Nothing on either stream, so phases keep their clean output.
    let host = CreateHost::new();
    host.agentcage("echo \"Cage created.\"\nexit 0");
    // Deliberately NOT redirecting: output is captured, not streamed.
    let r = host.create("");
    assert!(r.stdout.contains("RC=0"), "{}", r.both());
    assert!(!r.stdout.contains("Cage created."), "{}", r.both());
    assert_eq!(r.stderr, "", "{}", r.both());
}

// ── start_mock never dies mutely ─────────────────────────────────────

struct MockHost {
    tmp: TempDir,
    bindir: PathBuf,
    mock_bin: PathBuf,
}

impl MockHost {
    fn new() -> Self {
        let tmp = TempDir::new("mock");
        let bindir = tmp.path().join("fakebin");
        fs::create_dir(&bindir).unwrap();
        // start_mock polls for the egress for up to 30s; don't wait.
        write_shim(&bindir, "sleep", "exit 0");
        // A stand-in for the mock binary, so nothing is built.
        let mock_bin = write_shim(tmp.path(), "agentcage-e2e-mock", "exit 0");
        Self {
            tmp,
            bindir,
            mock_bin,
        }
    }

    fn podman(&self, body: &str) {
        write_shim(&self.bindir, "podman", body);
    }

    fn call(&self, call: &str) -> Run {
        self.call_with(
            call,
            &[("E2E_MOCK_BIN", self.mock_bin.display().to_string())],
        )
    }

    fn call_with(&self, call: &str, env: &[(&str, String)]) -> Run {
        let _ = &self.tmp;
        let script = format!(
            "source \"{}\"\nrc=0\n{call} || rc=$?\necho \"RC=$rc\"\n",
            lib_sh().display()
        );
        run_snippet(&script, &self.bindir, env)
    }

    /// A podman for the mock lifecycle: the egress reports namespace
    /// `/run/netns/egress-new`, the mock reports `mock_netns`, and `run`
    /// invocations are appended to the returned log.
    fn netns_podman(&self, mock_netns: &str) -> PathBuf {
        let log = self.tmp.path().join("runlog");
        self.podman(&format!(
            "case \"$1\" in\n\
             \x20 inspect)\n\
             \x20   for a; do last=\"$a\"; done\n\
             \x20   case \"$last\" in\n\
             \x20     *-egress) echo /run/netns/egress-new ;;\n\
             \x20     *-mock) echo '{mock_netns}' ;;\n\
             \x20   esac ;;\n\
             \x20 run) echo \"$*\" >> \"{log}\"; echo cid ;;\n\
             \x20 exec) case \" $* \" in *\" -i \"*) cat >/dev/null ;; esac; exit 0 ;;\n\
             \x20 *) exit 0 ;;\n\
             esac",
            log = log.display()
        ));
        // `exec -i` drains stdin: _patch_egress_hosts pipes into it, and a
        // writer seeing EPIPE would fail under pipefail.
        log
    }
}

fn mock_image_ref() -> String {
    read(e2e_dir().join("mock-image.ref")).trim().to_owned()
}

#[test]
fn start_mock_invisible_egress_is_explained() {
    // An egress podman cannot see (the cage was built by a vm or
    // apple-container backend) yields an explanation and a non-zero
    // return, never a bare `FAIL (0/0)` from `set -e` (#317).
    let host = MockHost::new();
    host.podman(
        "case \"$1\" in\n\
         \x20 inspect) echo \"Error: no such container\" >&2; exit 125 ;;\n\
         \x20 run) echo \"run must not be reached\" >&2; exit 99 ;;\n\
         \x20 *) exit 0 ;;\n\
         esac",
    );
    let r = host.call("start_mock e2e-fake httpbin.org");
    assert!(r.stdout.contains("RC=1"), "{}", r.both());
    assert!(
        r.stderr
            .contains("e2e-fake-egress is not running in the podman store")
    );
    assert!(r.stderr.contains("different container store"));
    assert!(r.stderr.contains("#317"));
    assert!(
        !r.stderr.contains("run must not be reached"),
        "{}",
        r.both()
    );
}

#[test]
fn start_mock_podman_run_error_is_surfaced() {
    // A failed `podman run` reports podman's own message, not just a bare
    // "failed to start mock container".
    let host = MockHost::new();
    host.podman(
        "case \"$1\" in\n\
         \x20 inspect) echo /run/user/1000/netns/netns-egress ;;\n\
         \x20 run) echo \"Error: initializing source docker://debian: pull rate limit\" >&2; exit 125 ;;\n\
         \x20 *) exit 0 ;;\n\
         esac",
    );
    let r = host.call("start_mock e2e-fake httpbin.org");
    assert!(r.stdout.contains("RC=1"), "{}", r.both());
    assert!(
        r.stderr.contains("failed to start mock container"),
        "{}",
        r.both()
    );
    assert!(
        r.stderr.contains(&mock_image_ref()),
        "names the image\n{}",
        r.both()
    );
    assert!(
        r.stderr.contains("podman run FAILED (exit 125)"),
        "{}",
        r.both()
    );
    assert!(r.stderr.contains("pull rate limit"), "{}", r.both());
}

#[test]
fn start_mock_without_a_usable_binary_is_explained() {
    let host = MockHost::new();
    let log = host.netns_podman("");
    let missing = host.tmp.path().join("no-such-binary");
    let r = host.call_with(
        "start_mock e2e-fake httpbin.org",
        &[("E2E_MOCK_BIN", missing.display().to_string())],
    );
    assert!(r.stdout.contains("RC=1"), "{}", r.both());
    assert!(
        r.stderr.contains("is not an executable file"),
        "{}",
        r.both()
    );
    assert!(!log.exists(), "podman run reached: {}", read(&log));
}

// ── the mock shares the egress's namespace ───────────────────────────

#[test]
fn start_mock_joins_egress_netns_by_path() {
    let host = MockHost::new();
    let log = host.netns_podman("");
    let r = host.call("start_mock e2e-fake httpbin.org");
    assert!(r.stdout.contains("RC=0"), "{}", r.both());
    let run = read(&log);
    assert!(run.contains("--network ns:/run/netns/egress-new"), "{run}");
    assert!(
        run.contains("agentcage.e2e.netns=/run/netns/egress-new"),
        "{run}"
    );
    // The binary is mounted read-only and bound to loopback inside the
    // shared namespace.
    assert!(
        run.contains(&format!(
            "-v {}:/agentcage-e2e-mock:ro",
            host.mock_bin.display()
        )),
        "{run}"
    );
    assert!(run.contains(&mock_image_ref()), "{run}");
    assert!(
        run.contains("/agentcage-e2e-mock httpbin 127.0.0.1"),
        "{run}"
    );
    // Never the egress image, never a container: join (see below).
    assert!(!run.contains("agentcage-egress"), "{run}");
    assert!(!run.contains("container:"), "{run}");
}

#[test]
fn repatch_rehomes_mock_after_egress_restart() {
    // A restarted egress has a new namespace; the mock must follow.
    let host = MockHost::new();
    let log = host.netns_podman("/run/netns/egress-old");
    let r = host.call("repatch_mock e2e-fake httpbin.org");
    assert!(r.stdout.contains("RC=0"), "{}", r.both());
    assert!(read(&log).contains("--network ns:/run/netns/egress-new"));
}

#[test]
fn repatch_leaves_mock_alone_when_netns_unchanged() {
    let host = MockHost::new();
    let log = host.netns_podman("/run/netns/egress-new");
    let r = host.call("repatch_mock e2e-fake httpbin.org");
    assert!(r.stdout.contains("RC=0"), "{}", r.both());
    assert!(!log.exists(), "{}", read(&log));
}

#[test]
fn lib_sh_never_joins_by_container() {
    // `--network container:<cage>-egress` makes the mock a dependent of
    // the egress, and podman then refuses to remove or --replace the
    // egress: every egress restart would fail.
    let text = read(lib_sh());
    let bad: Vec<&str> = code_lines(&text)
        .filter(|l| l.contains("container:"))
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn mock_image_is_the_egress_base() {
    let reference = mock_image_ref();
    assert!(!reference.is_empty(), "tests/e2e/mock-image.ref is empty");
    // Same base as the egress image, so a cage create has already pulled
    // it: at least one egress Containerfile must build FROM exactly this
    // reference (a floating tag, as the egress base is not pinned).
    let mut containerfiles = Vec::new();
    find_files(
        &repo_root().join("src"),
        "Containerfile.egress",
        &mut containerfiles,
    );
    find_files(
        &repo_root().join("rust"),
        "Containerfile.egress",
        &mut containerfiles,
    );
    assert!(!containerfiles.is_empty(), "no egress Containerfile found");
    assert!(
        containerfiles.iter().any(|f| read(f)
            .lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["FROM", reference.as_str()])),
        "no egress Containerfile builds FROM {reference}: {containerfiles:?}"
    );
}

fn find_files(dir: &Path, prefix: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "target") {
                find_files(&path, prefix, out);
            }
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(prefix))
        {
            out.push(path);
        }
    }
}

// ── static guards over the scripts ───────────────────────────────────

fn e2e_scripts() -> Vec<PathBuf> {
    let mut scripts: Vec<PathBuf> = fs::read_dir(e2e_dir())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sh"))
        .collect();
    scripts.sort();
    assert!(!scripts.is_empty());
    scripts
}

#[test]
fn no_interpreter_exec_in_the_egress() {
    // Nothing in the harness may run an interpreter in the egress
    // container: its image ships none.
    let mut offenders = Vec::new();
    for script in e2e_scripts() {
        let text = read(&script);
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            // Commands aimed at the egress sibling, plus a continuation
            // line or two after them.
            let at_egress = line.contains("-egress") || line.contains("-s egress");
            let execs = ["podman exec", "cage exec", "container exec"]
                .iter()
                .any(|k| line.contains(k));
            if !(at_egress && execs) {
                continue;
            }
            let window = lines[i..lines.len().min(i + 3)].join(" ");
            if ["python", "node ", "perl"]
                .iter()
                .any(|k| window.contains(k))
            {
                offenders.push(format!(
                    "{}:{}: {}",
                    script.file_name().unwrap().to_string_lossy(),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// Every file under `dir`, recursively.
fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            all_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn the_harness_needs_no_python() {
    // The mocks are the Rust agentcage-e2e-mock binary and host-side JSON
    // goes through jq: no Python file, shebang or invocation anywhere in
    // tests/e2e (comments may still say a base image has no python).
    let mut files = Vec::new();
    all_files(&e2e_dir(), &mut files);
    let mut offenders = Vec::new();
    for file in &files {
        let name = file
            .strip_prefix(repo_root())
            .unwrap()
            .display()
            .to_string();
        if file.extension().is_some_and(|x| x == "py") {
            offenders.push(format!("{name}: a Python file"));
            continue;
        }
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        if text
            .lines()
            .next()
            .is_some_and(|l| l.starts_with("#!") && l.contains("python"))
        {
            offenders.push(format!("{name}: python shebang"));
        }
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with('#')
                || t.starts_with("//")
                || file.extension().is_some_and(|x| x == "md")
            {
                continue;
            }
            if line.contains("python") {
                offenders.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
fn the_harness_has_one_egress() {
    // There is one egress implementation: no phase branches on an engine.
    let mut files = Vec::new();
    all_files(&e2e_dir(), &mut files);
    let hits: Vec<String> = files
        .iter()
        .filter(|f| fs::read_to_string(f).is_ok_and(|t| t.contains("AGENTCAGE_EGRESS_ENGINE")))
        .map(|f| f.display().to_string())
        .collect();
    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn phase_callers_keep_create_cage_stderr() {
    // Callers must not re-swallow what create_cage now emits. Every phase
    // script except phase 7 (below) and phase 8 (which builds its cage
    // from a rendered scaffold, not via create_cage).
    for script in [
        "phase1_lifecycle.sh",
        "phase2_audit_logs.sh",
        "phase3_secrets.sh",
        "phase4_domains.sh",
        "phase5_backup.sh",
        "phase6_hardening.sh",
    ] {
        let text = read(e2e_dir().join(script));
        let calls: Vec<&str> = code_lines(&text)
            .filter(|l| l.contains("create_cage "))
            .map(str::trim)
            .collect();
        assert!(!calls.is_empty(), "{script}: no create_cage call found");
        for line in calls {
            assert!(
                !line.contains("2>&1"),
                "{script}: create_cage stderr is swallowed, hiding the #317 failure dump: {line}"
            );
        }
    }
}

#[test]
fn phase7_create_output_is_kept() {
    // Phase 7 is the one deliberate exception (its create is expected to
    // fail every run), so its output goes to a log rather than the
    // terminal. Kept, not discarded: when the VM never comes up, that log
    // is the only record of why, and it is printed at the failure.
    let text = read(e2e_dir().join("phase7_vm.sh"));
    assert!(text.contains(r#"create_cage "$CONFIGS/vm.yaml" >"$CREATE_LOG" 2>&1 || true"#));
    assert!(!text.contains(r#"create_cage "$CONFIGS/vm.yaml" >/dev/null"#));
    assert!(
        text.contains(r#""$CREATE_LOG" | head"#),
        "the log must be printed on failure"
    );
}
