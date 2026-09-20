//! Every `limactl` the `vm` backend's generation half builds, in full.
//!
//! `backends/vm.py` is a subprocess orchestrator: its contract with
//! Lima *is* the argv, so that is what this asserts — the whole list,
//! in order, with nothing extra, through
//! [`FakeRunner::assert_argv`] / [`FakeRunner::assert_call`].
//!
//! # Why full argv and not membership
//!
//! `test_vm_backend.py` pins four argv exactly ([`exec_argv`]'s four
//! shapes) and then falls back to substring checks on a `str(call)`
//! repr for everything else: `"podman" in str(c) and "build" in str(c)`
//! for the builds, `"stop" in cmd` for the service stops, `[:3] ==
//! ["systemctl", "--user", "start"]` for the deploy ordering, and
//! `any(path in script)` for the guest-side shell pipelines. Those pass
//! whatever the flags and the order are. D1 found the same shape in
//! `test_podman.py` and it had been hiding an ordering bug, so the
//! ported tests pin the list.
//!
//! Two of them also *never ran*: `logs_argv` and `audit_argv` have no
//! test at all in the Python suite, on any backend for the vm case.
//! They are pinned here for the first time.
//!
//! [`exec_argv`]: agentcage_cli::vm::VmBackend::exec_argv

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agentcage_cli::vm::VmBackend;
use agentcage_exec::tools::limactl::VmPodman;
use agentcage_exec::{FakeRunner, Reply};
use agentcage_state::Paths;

/// The version tag the backend stamps; never read by these tests except
/// through the build argv.
const VERSION: &str = "0.40.1";

/// The guest home every `echo ~` answers with.
const GUEST_QUADLET_DIR: &str = "/home/cageuser.linux/.config/containers/systemd";
const GUEST_HOME: &str = "/home/cageuser.linux";

/// The `limactl shell` prefix every guest command carries.
///
/// `--workdir /` pins the guest cwd, `--tty=false` keeps ssh from
/// allocating a PTY. Both are documented at `LimaInstance::shell_command`
/// and both are load-bearing — the second one is what keeps a piped
/// secret from being cooked by the line discipline.
const SHELL: [&str; 6] = ["limactl", "shell", "--workdir", "/", "--tty=false", "--"];

/// The same, with the instance name spliced in where it belongs.
fn shell(cage: &str, command: &[&str]) -> Vec<String> {
    let instance = format!("agentcage-{cage}");
    let mut argv: Vec<String> = SHELL[..5].iter().map(|s| (*s).to_string()).collect();
    argv.insert(5, instance);
    argv.push("--".to_owned());
    argv.extend(command.iter().map(|s| (*s).to_string()));
    argv
}

/// A throwaway state root, removed on drop.
struct Home {
    root: PathBuf,
}

impl Home {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("agentcage-vm-argv-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("home");
        Self {
            root: fs::canonicalize(&root).expect("canonical home"),
        }
    }

    fn paths(&self) -> Paths {
        Paths::under(&self.root)
    }

    fn write(&self, relative: &str, body: &str) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        fs::write(&path, body).expect("write");
        path
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A runner that answers `echo ~` with [`GUEST_HOME`] and everything
/// else with success.
/// A runner that answers only the guest-home probe.
///
/// The rule is the *whole* `bash -c "echo ~"` invocation rather than a
/// short `limactl shell` prefix. `FakeRunner::on` documents that the
/// first matching rule wins, so a broad prefix here would shadow every
/// specific rule a test registers afterwards — which is how an absent
/// findings file came back holding the guest's home directory.
fn runner_with_guest_home(cage: &str) -> FakeRunner {
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            &format!("agentcage-{cage}"),
            "--",
            "bash",
            "-c",
            "echo ~",
        ],
        Reply::ok(format!("{GUEST_HOME}\n")),
    );
    // Everything else in the guest succeeds silently. These tests assert
    // on the argv that was sent, not on what came back, and a default is
    // checked after every rule so it shadows nothing.
    runner.default_reply(Reply::success());
    runner
}

fn vm<'a>(paths: &'a Paths, runner: &'a FakeRunner) -> VmBackend<'a> {
    VmBackend::with_facts(paths, runner, VERSION, "Linux", "cageuser")
}

// ─── exec_argv ───────────────────────────────────────────────

#[test]
fn exec_argv_has_four_shapes_and_all_four_are_pinned() {
    let home = Home::new("exec");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    let backend = vm(&paths, &runner);
    let bash = vec!["bash".to_owned()];

    // Default: no `-it`, unprivileged, gid pinned.
    assert_eq!(
        backend.exec_argv("myapp", "cage", &bash, false, false),
        shell(
            "myapp",
            &["podman", "exec", "-u", "1000:1000", "myapp-cage", "bash"]
        )
        .into_iter()
        // `exec_argv` does not carry `--tty=false`: this is the one
        // path that may want a PTY.
        .filter(|part| part != "--tty=false")
        .collect::<Vec<_>>()
    );
    // `--as-root`.
    assert_eq!(
        backend.exec_argv("myapp", "cage", &bash, false, true)[8..],
        ["-u", "0:0", "myapp-cage", "bash"]
    );
    // `-it` goes *after* `-u <spec>` and before the container name.
    assert_eq!(
        backend.exec_argv("myapp", "cage", &bash, true, false)[6..],
        [
            "podman".to_owned(),
            "exec".to_owned(),
            "-u".to_owned(),
            "1000:1000".to_owned(),
            "-it".to_owned(),
            "myapp-cage".to_owned(),
            "bash".to_owned()
        ]
    );
    // Both, on the egress service.
    let sh = vec!["sh".to_owned()];
    assert_eq!(
        backend.exec_argv("myapp", "egress", &sh, true, true)[6..],
        [
            "podman".to_owned(),
            "exec".to_owned(),
            "-u".to_owned(),
            "0:0".to_owned(),
            "-it".to_owned(),
            "myapp-egress".to_owned(),
            "sh".to_owned()
        ]
    );
}

#[test]
fn a_cage_session_carries_the_current_placeholders() {
    let home = Home::new("exec-env");
    home.write(
        ".config/agentcage/cages/myapp/cage.yaml",
        "name: myapp\ncontainer:\n  image: alpine\nsecret_injection:\n\
         - env: API_KEY\n  placeholder: agentcage:secret:API_KEY:00ff\n",
    );
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    let backend = vm(&paths, &runner);

    let argv = backend.exec_argv("myapp", "cage", &["sh".to_owned()], false, false);
    assert_eq!(
        argv,
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "agentcage-myapp",
            "--",
            "podman",
            "exec",
            "-u",
            "1000:1000",
            "--env",
            "API_KEY=agentcage:secret:API_KEY:00ff",
            "myapp-cage",
            "sh",
        ]
    );
    // The egress service never gets them: the placeholders are the
    // cage's decoys, and the egress holds the real values.
    let egress = backend.exec_argv("myapp", "egress", &["sh".to_owned()], false, false);
    assert!(!egress.iter().any(|part| part == "--env"));
}

// ─── logs_argv / audit_argv ──────────────────────────────────

#[test]
fn logs_argv_wraps_journalctl_in_sg_systemd_journal() {
    let home = Home::new("logs");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    let backend = vm(&paths, &runner);

    let services = ["cage".to_owned(), "egress".to_owned()];
    assert_eq!(
        backend.logs_argv("myapp", &services, false, 0),
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "agentcage-myapp",
            "--",
            "sg",
            "systemd-journal",
            "-c",
            "journalctl -o cat --user-unit myapp-cage --user-unit myapp-egress",
        ]
    );
    // `-f` and `-n` land inside the quoted command, in that order.
    assert_eq!(
        backend.logs_argv("myapp", &services[..1], true, 50)[9],
        "journalctl -o cat --user-unit myapp-cage -f -n 50"
    );
    // `lines: 0` means "no -n", which is how `cage logs` spells its
    // default.
    assert_eq!(
        backend.logs_argv("myapp", &services[..1], false, 0)[9],
        "journalctl -o cat --user-unit myapp-cage"
    );
}

#[test]
fn audit_argv_reads_the_egress_unit_only() {
    let home = Home::new("audit");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    let backend = vm(&paths, &runner);

    assert_eq!(
        backend.audit_argv("myapp", None, false),
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "agentcage-myapp",
            "--",
            "sg",
            "systemd-journal",
            "-c",
            "journalctl --user-unit myapp-egress -o cat -n 10000",
        ]
    );
    // A `--since` with a space is quoted by `shlex.join`, not split.
    assert_eq!(
        backend.audit_argv("myapp", Some("10 minutes ago"), false)[9],
        "journalctl --user-unit myapp-egress -o cat --since '10 minutes ago' -n 10000"
    );
    // Following replaces the over-read rather than adding to it.
    assert_eq!(
        backend.audit_argv("myapp", None, true)[9],
        "journalctl --user-unit myapp-egress -o cat -f"
    );
}

// ─── push_config_files ───────────────────────────────────────

#[test]
fn push_config_files_sends_one_base64_pipeline_per_file() {
    let home = Home::new("push");
    home.write(
        ".config/agentcage/cages/demo/proxy-config.yaml",
        "allowed_domains:\n- api.example.com\n",
    );
    home.write(
        ".config/agentcage/cages/demo/dns-allowlist.conf",
        "server=/api.example.com/10.89.1.10\n",
    );
    home.write(
        ".config/agentcage/cages/demo/cage-env/placeholders.env",
        "API_KEY=agentcage:secret:API_KEY:00ff\n",
    );
    let paths = home.paths();
    let runner = runner_with_guest_home("demo");
    let backend = vm(&paths, &runner);

    backend.push_config_files("demo").expect("pushes");

    let calls = runner.argv_sequence();
    assert_eq!(calls.len(), 6, "one home probe, two mkdirs, three writes");
    assert_eq!(calls[0], shell("demo", &["bash", "-c", "echo ~"]));
    assert_eq!(
        calls[1],
        shell(
            "demo",
            &[
                "mkdir",
                "-p",
                &format!("{GUEST_HOME}/.config/agentcage-vm/cages/demo")
            ]
        )
    );
    assert_eq!(
        calls[2],
        shell(
            "demo",
            &[
                "bash",
                "-c",
                &format!(
                    "echo 'YWxsb3dlZF9kb21haW5zOgotIGFwaS5leGFtcGxlLmNvbQo=' | base64 -d > \
                     {GUEST_HOME}/.config/agentcage-vm/cages/demo/proxy-config.yaml"
                )
            ]
        )
    );
    // The redirect target, which is the last element of the `bash -c`
    // script rather than a fixed index -- the `limactl shell` prefix is
    // seven arguments before `bash`.
    assert!(
        calls[3]
            .last()
            .expect("argv")
            .ends_with("/dns-allowlist.conf"),
        "{:?}",
        calls[3]
    );
    assert_eq!(
        calls[4],
        shell(
            "demo",
            &[
                "mkdir",
                "-p",
                &format!("{GUEST_HOME}/.config/agentcage-vm/cages/demo/cage-env")
            ]
        )
    );
    assert!(
        calls[5]
            .last()
            .expect("argv")
            .ends_with("/cage-env/placeholders.env"),
        "{:?}",
        calls[5]
    );

    // Not one guest argument may carry `%h` or `~`: bash expands
    // neither, and `shlex.quote` would suppress the second.
    for call in calls.iter().skip(1) {
        for part in call {
            assert!(!part.contains("%h"), "unexpanded %h in {part:?}");
            assert!(
                !part.contains('~'),
                "unexpanded ~ in {part:?} (the `echo ~` probe is call 0)"
            );
        }
    }
}

#[test]
fn push_config_files_skips_the_files_that_are_not_there() {
    let home = Home::new("push-empty");
    let paths = home.paths();
    let runner = runner_with_guest_home("demo");
    let backend = vm(&paths, &runner);

    backend.push_config_files("demo").expect("pushes");
    assert_eq!(
        runner.call_count(),
        2,
        "the home probe and the mkdir, and nothing else"
    );
}

// ─── the guest-local grants overlay ──────────────────────────

#[test]
fn ensure_grants_dir_resolves_the_home_once_and_mkdirs() {
    let home = Home::new("grants-dir");
    let paths = home.paths();
    let runner = runner_with_guest_home("test");
    let backend = vm(&paths, &runner);

    backend.ensure_grants_dir("test").expect("creates");
    backend.ensure_grants_dir("test").expect("creates");

    runner.assert_argv(&[
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "bash",
            "-c",
            "echo ~",
        ],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "mkdir",
            "-p",
            "/home/cageuser.linux/.config/agentcage-vm/cages/test/grants",
        ],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "mkdir",
            "-p",
            "/home/cageuser.linux/.config/agentcage-vm/cages/test/grants",
        ],
    ]);
}

#[test]
fn pull_grants_tells_absent_from_unreadable() {
    let home = Home::new("pull-grants");
    let paths = home.paths();
    let script = format!(
        "if [ -f {GUEST_HOME}/.config/agentcage-vm/cages/test/grants/grants.yaml ]; \
         then cat {GUEST_HOME}/.config/agentcage-vm/cages/test/grants/grants.yaml; \
         else exit 42; fi"
    );

    // Exit 0 with a document: the entries.
    let runner = runner_with_guest_home("test");
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "sh",
        ],
        Reply::ok("- domain: api.example.com\n  source: policy\n"),
    );
    let entries = vm(&paths, &runner).pull_grants("test").expect("reachable");
    assert_eq!(entries.len(), 1);
    runner.assert_call(
        1,
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "sh",
            "-c",
            &script,
        ],
    );

    // Exit 42: the file is absent, which is a fresh cage's empty state.
    let runner = runner_with_guest_home("test");
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "sh",
        ],
        Reply::status(42),
    );
    assert_eq!(vm(&paths, &runner).pull_grants("test"), Some(Vec::new()));

    // Any other non-zero exit: a real read failure. `None`, never `[]`
    // — an empty overlay here would let the reconcile persist a wipe.
    let runner = runner_with_guest_home("test");
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "sh",
        ],
        Reply::failed(1, "cat: permission denied"),
    );
    assert_eq!(vm(&paths, &runner).pull_grants("test"), None);

    // Exit 0 with a document that is not a list: empty, not unreachable.
    let runner = runner_with_guest_home("test");
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "sh",
        ],
        Reply::ok("{not: a list}\n"),
    );
    assert_eq!(vm(&paths, &runner).pull_grants("test"), Some(Vec::new()));
}

#[test]
fn the_guest_home_is_resolved_once_per_cage() {
    let home = Home::new("home-cache");
    let paths = home.paths();
    let runner = runner_with_guest_home("test");
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "sh",
        ],
        Reply::status(42),
    );
    let backend = vm(&paths, &runner);

    // Called twice on purpose: the probe is what is under test, and the
    // returned overlay is not.
    let _ = backend.pull_grants("test");
    let _ = backend.pull_grants("test");
    backend.ensure_grants_dir("test").expect("creates");

    let probes = runner
        .argv_sequence()
        .into_iter()
        .filter(|argv| argv.last().map(String::as_str) == Some("echo ~"))
        .count();
    assert_eq!(probes, 1, "the `echo ~` round-trip is cached per cage");
}

#[test]
fn push_grants_writes_through_mktemp_and_mv() {
    let home = Home::new("push-grants");
    let paths = home.paths();
    let runner = runner_with_guest_home("test");
    let backend = vm(&paths, &runner);

    let document = agentcage_core::yaml::load("- domain: api.example.com\n  source: policy\n")
        .expect("parses");
    let entries: Vec<agentcage_core::yaml::Mapping> = match document {
        agentcage_core::yaml::Value::Sequence(items) => items
            .into_iter()
            .filter_map(|item| match item {
                agentcage_core::yaml::Value::Mapping(mapping) => Some(mapping),
                _ => None,
            })
            .collect(),
        _ => panic!("sequence"),
    };
    backend.push_grants("test", &entries).expect("pushes");

    let call = runner.argv(1);
    assert_eq!(&call[..8], &shell("test", &["sh"])[..8]);
    // The script is the last element: the `limactl shell` prefix is seven
    // arguments, then `bash`, `-c`, and the script itself.
    let script = call.last().expect("argv");
    let directory = format!("{GUEST_HOME}/.config/agentcage-vm/cages/test/grants");
    // `mktemp <dir>/XXXXXX` in the target's own directory — not a
    // predictable `<path>.tmp`, which a planted symlink would be
    // written through.
    assert!(
        script.starts_with(&format!("tmp=$(mktemp {directory}/XXXXXX) && ")),
        "{script}"
    );
    assert!(script.ends_with(&format!("&& mv \"$tmp\" {directory}/grants.yaml")));
    assert!(!script.contains(".tmp"));
    // The payload is base64 of exactly what `yaml.safe_dump(entries,
    // default_flow_style=False, sort_keys=False)` produces.
    let payload = script
        .split("echo '")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .expect("payload");
    assert_eq!(
        payload,
        agentcage_core::quadlets::b64("- domain: api.example.com\n  source: policy\n")
    );
}

#[test]
fn pull_watcher_output_uses_the_same_sentinel() {
    let home = Home::new("watcher");
    let paths = home.paths();
    let runner = runner_with_guest_home("test");
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-test",
            "--",
            "sh",
        ],
        Reply::status(42),
    );
    let backend = vm(&paths, &runner);

    assert_eq!(
        backend.pull_watcher_output("test", "findings.jsonl"),
        Some(String::new()),
        "an absent findings file is empty, not unreachable"
    );
    let script = runner.argv(1).pop().expect("script");
    assert!(script.contains(&format!(
        "{GUEST_HOME}/.config/agentcage-vm/cages/test/grants/watcher/findings.jsonl"
    )));
    assert!(script.contains("exit 42"));
}

// ─── quadlet push ────────────────────────────────────────────

#[test]
fn push_quadlets_sends_one_pipeline_per_unit_file() {
    let home = Home::new("quadlets");
    home.write(
        ".config/agentcage/lima/quadlets/demo-net.network",
        "[Network]\n",
    );
    home.write(
        ".config/agentcage/lima/quadlets/demo-cage.container",
        "[Container]\n",
    );
    let paths = home.paths();
    let runner = runner_with_guest_home("demo");
    // `push_quadlets` resolves the guest quadlet directory with its own
    // `echo ~/.config/containers/systemd`, not the `echo ~` probe. Until
    // the helper's rule was narrowed this was answered by a broad
    // `limactl shell` rule, which is why the expectation below used to
    // read as if the units landed straight in the guest's home.
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "bash",
            "-c",
            "echo ~/.config/containers/systemd",
        ],
        Reply::ok(format!("{GUEST_QUADLET_DIR}\n")),
    );
    let backend = vm(&paths, &runner);

    backend.push_quadlets("demo").expect("pushes");

    let calls = runner.argv_sequence();
    assert_eq!(
        calls.len(),
        4,
        "mkdir, the dir probe, and one write per unit"
    );
    assert_eq!(
        calls[0],
        shell(
            "demo",
            &["bash", "-c", "mkdir -p ~/.config/containers/systemd"]
        )
    );
    assert_eq!(
        calls[1],
        shell("demo", &["bash", "-c", "echo ~/.config/containers/systemd"])
    );
    // Sorted, so the sequence is a property of the code rather than of
    // the filesystem's readdir order.
    assert_eq!(
        calls[2],
        shell(
            "demo",
            &[
                "bash",
                "-c",
                &format!(
                    "echo 'W0NvbnRhaW5lcl0K' | base64 -d > \
                     {GUEST_QUADLET_DIR}/demo-cage.container"
                )
            ]
        )
    );
    assert!(calls[3][9].ends_with("/demo-net.network"));
}

// ─── secret bridging ─────────────────────────────────────────

#[test]
fn bridge_secrets_decrypts_on_the_host_and_pipes_into_the_guest() {
    let home = Home::new("bridge");
    home.write(".config/agentcage/cages/demo/creds/API_KEY.cred", "blob\n");
    let paths = home.paths();

    let runner = FakeRunner::new();
    runner.assume_installed();
    // Calls this test does not assert on still have to answer;
    // a default is checked after every rule, so it shadows none.
    runner.default_reply(Reply::success());
    runner.on(["systemd-creds", "decrypt"], Reply::ok("sk-decrypted"));
    runner.on(
        ["podman", "secret", "ls"],
        Reply::ok("demo.OTHER\nunrelated\n"),
    );
    runner.on(
        ["podman", "secret", "inspect"],
        Reply::ok("sk-from-host-store\n"),
    );
    let backend = vm(&paths, &runner);

    let bridged = backend.bridge_secrets("demo").expect("bridges");
    assert_eq!(
        bridged.messages,
        [
            "  Bridged secret (decrypted): demo.API_KEY",
            "  Bridged secret: demo.OTHER",
        ]
    );
    assert!(bridged.warnings.is_empty());

    let calls = runner.argv_sequence();
    assert_eq!(
        calls[0],
        [
            "systemd-creds",
            "decrypt",
            &home
                .root
                .join(".config/agentcage/cages/demo/creds/API_KEY.cred")
                .display()
                .to_string(),
            "-",
        ]
    );
    assert_eq!(
        calls[1],
        shell("demo", &["podman", "secret", "rm", "demo.API_KEY"])
    );
    assert_eq!(
        calls[2],
        shell("demo", &["podman", "secret", "create", "demo.API_KEY", "-"])
    );
    // The value is on stdin on **both** sides of the shell. Neither
    // `systemd-creds` nor `podman` sees it in an argv, where every
    // process on the host could read it out of /proc.
    assert_eq!(
        runner.call(2).stdin_text().as_deref(),
        Some("sk-decrypted"),
        "the decrypted value travels on stdin"
    );
    assert_eq!(
        calls[3],
        [
            "podman",
            "secret",
            "ls",
            "--noheading",
            "--format",
            "{{.Name}}"
        ]
    );
    assert_eq!(
        calls[4],
        [
            "podman",
            "secret",
            "inspect",
            "--showsecret",
            "--format",
            "{{.SecretData}}",
            "demo.OTHER",
        ]
    );
    assert_eq!(
        calls[5],
        shell("demo", &["podman", "secret", "rm", "demo.OTHER"])
    );
    assert_eq!(
        calls[6],
        shell("demo", &["podman", "secret", "create", "demo.OTHER", "-"])
    );
    assert_eq!(
        runner.call(6).stdin_text().as_deref(),
        Some("sk-from-host-store")
    );
    assert_eq!(calls.len(), 7);
}

#[test]
fn a_host_without_podman_bridges_only_the_creds() {
    let home = Home::new("bridge-nopodman");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    // Calls this test does not assert on still have to answer;
    // a default is checked after every rule, so it shadows none.
    runner.default_reply(Reply::success());
    runner.stub_missing("podman");
    let backend = vm(&paths, &runner);

    let bridged = backend.bridge_secrets("demo").expect("bridges");
    assert!(bridged.messages.is_empty());
    assert!(bridged.warnings.is_empty());
}

#[test]
fn pending_secrets_reach_the_guest_and_the_file_is_deleted() {
    let home = Home::new("pending");
    let pending = home.write(
        ".config/agentcage/cages/demo/pending_secrets.json",
        r#"[["API_KEY", "sk-pending"], ["OTHER", "two"]]"#,
    );
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    // Calls this test does not assert on still have to answer;
    // a default is checked after every rule, so it shadows none.
    runner.default_reply(Reply::success());
    let backend = vm(&paths, &runner);

    let messages = backend.create_pending_secrets("demo").expect("creates");
    assert_eq!(
        messages,
        [
            "  Secret 'demo.API_KEY' set in VM.",
            "  Secret 'demo.OTHER' set in VM.",
        ]
    );
    runner.assert_argv(&[
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "rm",
            "demo.API_KEY",
        ],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "create",
            "demo.API_KEY",
            "-",
        ],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "rm",
            "demo.OTHER",
        ],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "create",
            "demo.OTHER",
            "-",
        ],
    ]);
    assert_eq!(runner.call(1).stdin_text().as_deref(), Some("sk-pending"));
    assert!(
        !pending.exists(),
        "the plaintext file must not survive the deploy that consumed it"
    );
}

#[test]
fn source_secrets_are_resolved_into_the_guest_store() {
    let home = Home::new("sources");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    // Calls this test does not assert on still have to answer;
    // a default is checked after every rule, so it shadows none.
    runner.default_reply(Reply::success());

    let source = "name: demo\ncontainer:\n  image: alpine\n\
                  secret_injection:\n- env: API_KEY\n  source: env:FIXTURE_KEY\n\
                  - env: STORED\n  source: \"podman:\"\n";
    let config = agentcage_core::config::load(
        "cage.yaml",
        source,
        &agentcage_core::config::FixedHost {
            isolation: "vm".to_owned(),
            dns_servers: Ok(vec!["192.0.2.53".to_owned()]),
        },
    )
    .expect("loads");

    let env = agentcage_cli::secrets::MapEnv::new().with("FIXTURE_KEY", "sk-from-env");
    let host = agentcage_cli::secrets::SecretHost::new(&runner, &env, true);
    let backend = vm(&paths, &runner);

    let bridged = backend
        .resolve_source_secrets("demo", Some(&config), &host)
        .expect("resolves");
    assert!(bridged.warnings.is_empty());
    // `podman:` resolves to "already in the store" and creates nothing,
    // so only the `env:` rule reaches the guest.
    runner.assert_argv(&[
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "rm",
            "demo.API_KEY",
        ],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "create",
            "demo.API_KEY",
            "-",
        ],
    ]);
    assert_eq!(runner.call(1).stdin_text().as_deref(), Some("sk-from-env"));

    // No config: nothing to resolve, and the guest secrets already
    // created stay valid.
    let idle = FakeRunner::new();
    idle.assume_installed();
    let idle_paths = home.paths();
    let idle_backend = vm(&idle_paths, &idle);
    let idle_host = agentcage_cli::secrets::SecretHost::new(&idle, &env, true);
    assert_eq!(
        idle_backend
            .resolve_source_secrets("demo", None, &idle_host)
            .expect("no-ops"),
        agentcage_cli::vm::Bridged::default()
    );
    assert_eq!(idle.call_count(), 0);
}

#[test]
fn an_unresolvable_source_warns_and_the_deploy_goes_on() {
    let home = Home::new("sources-bad");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();

    let source = "name: demo\ncontainer:\n  image: alpine\n\
                  secret_injection:\n- env: API_KEY\n  source: env:NOT_SET\n";
    let config = agentcage_core::config::load(
        "cage.yaml",
        source,
        &agentcage_core::config::FixedHost {
            isolation: "vm".to_owned(),
            dns_servers: Ok(vec!["192.0.2.53".to_owned()]),
        },
    )
    .expect("loads");
    let env = agentcage_cli::secrets::MapEnv::new();
    let host = agentcage_cli::secrets::SecretHost::new(&runner, &env, true);

    let bridged = vm(&paths, &runner)
        .resolve_source_secrets("demo", Some(&config), &host)
        .expect("does not abort");
    assert_eq!(
        bridged.warnings,
        ["warning: could not resolve secret 'API_KEY' (env: source): env var 'NOT_SET' not set"]
    );
    assert_eq!(runner.call_count(), 0);
}

// ─── the E4 argv, built here ─────────────────────────────────

#[test]
fn the_build_and_copy_argv_are_pinned_for_e4() {
    let home = Home::new("builds");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    let backend = vm(&paths, &runner);

    assert_eq!(
        backend.copy_build_context_argv(
            "demo",
            Path::new("/opt/assets/data"),
            "/tmp/agentcage-build"
        ),
        [
            "limactl",
            "copy",
            "-r",
            "/opt/assets/data/.",
            "agentcage-demo:/tmp/agentcage-build/",
        ]
    );
    assert_eq!(
        backend.egress_build_argv(&[]),
        [
            "podman",
            "build",
            "--cap-add=CAP_CHOWN",
            "--cap-add=CAP_FOWNER",
            "--cap-add=CAP_SETUID",
            "--cap-add=CAP_SETGID",
            "--cap-add=CAP_DAC_OVERRIDE",
            "--cap-add=CAP_SETFCAP",
            "-t",
            "agentcage-egress:0.40.1",
            "-f",
            "/tmp/agentcage-build/containers/Containerfile.egress",
            "/tmp/agentcage-build",
        ]
    );
    // `--no-cache` / `--pull=always` come before the capabilities, as
    // `*build_flags` does in the Python.
    let flags = ["--no-cache".to_owned(), "--pull=always".to_owned()];
    assert_eq!(&backend.egress_build_argv(&flags)[2..4], &flags[..]);
    assert_eq!(
        backend.cage_build_argv("localhost/demo:latest", "Containerfile", &flags),
        [
            "podman",
            "build",
            "--no-cache",
            "--pull=always",
            "--cap-add=CAP_CHOWN",
            "--cap-add=CAP_FOWNER",
            "--cap-add=CAP_SETUID",
            "--cap-add=CAP_SETGID",
            "--cap-add=CAP_DAC_OVERRIDE",
            "--cap-add=CAP_SETFCAP",
            "-t",
            "localhost/demo:latest",
            "-f",
            "/tmp/agentcage-build/scaffold/Containerfile",
            "/tmp/agentcage-build/scaffold",
        ]
    );
    assert_eq!(
        VmBackend::infra_services("demo"),
        [
            "demo-net-network",
            "demo-certs-volume",
            "demo-public-certs-volume",
            "demo-egress",
        ]
    );
    assert_eq!(
        VmBackend::systemctl_argv("is-active", "demo-cage"),
        ["systemctl", "--user", "is-active", "demo-cage.service"]
    );
}

// ─── state queries ───────────────────────────────────────────

#[test]
fn is_running_asks_the_guest_only_when_the_guest_is_up() {
    let home = Home::new("running");
    let paths = home.paths();

    // A stopped instance: one `limactl list`, and no shell at all.
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.on(["limactl", "list"], Reply::ok(r#"{"status":"Stopped"}"#));
    assert!(!vm(&paths, &runner).is_running("demo", "cage"));
    runner.assert_argv(&[&["limactl", "list", "--json", "agentcage-demo"]]);

    // A running one: the unit is then asked.
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.on(["limactl", "list"], Reply::ok(r#"{"status":"Running"}"#));
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "systemctl",
        ],
        Reply::ok("active\n"),
    );
    assert!(vm(&paths, &runner).is_running("demo", "cage"));
    runner.assert_call(
        1,
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "systemctl",
            "--user",
            "is-active",
            "demo-cage.service",
        ],
    );
}

#[test]
fn destroy_resources_removes_the_guest_and_this_cages_config() {
    let home = Home::new("destroy");
    home.write(".config/agentcage/lima/lima.yaml", "vmType: qemu\n");
    home.write(
        ".config/agentcage/lima/quadlets/demo-cage.container",
        "[Container]\n",
    );
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    // Calls this test does not assert on still have to answer;
    // a default is checked after every rule, so it shadows none.
    runner.default_reply(Reply::success());
    runner.on(["limactl", "list"], Reply::ok(r#"{"status":"Stopped"}"#));
    let backend = vm(&paths, &runner);

    let removed = backend.destroy_resources("demo", false).expect("destroys");
    assert_eq!(
        removed,
        [
            "lima-instance:agentcage-demo".to_owned(),
            format!(
                "config:{}",
                home.root.join(".config/agentcage/lima/lima.yaml").display()
            ),
            format!(
                "quadlets:{}",
                home.root.join(".config/agentcage/lima/quadlets").display()
            ),
        ]
    );
    runner.assert_argv(&[
        &["limactl", "list", "--json", "agentcage-demo"],
        &["limactl", "delete", "--force", "agentcage-demo"],
    ]);
    // The shared directory survives; only this cage's files go.
    assert!(home.root.join(".config/agentcage/lima").is_dir());
}

#[test]
fn has_resources_is_false_without_limactl() {
    let home = Home::new("has");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_missing();
    assert!(!vm(&paths, &runner).has_resources("demo"));
    assert_eq!(
        runner.call_count(),
        0,
        "a missing limactl is answered by `which`, not by running it"
    );
}

// ─── prerequisites ───────────────────────────────────────────

#[test]
fn prerequisites_differ_by_platform() {
    let home = Home::new("prereq");
    let paths = home.paths();

    // macOS: Lima uses Virtualization.framework, so neither QEMU nor
    // /dev/kvm is asked about.
    let runner = FakeRunner::new();
    runner.assume_installed();
    let backend = VmBackend::with_facts(&paths, &runner, VERSION, "Darwin", "cageuser");
    assert!(backend.check_prerequisites().is_empty());
    assert_eq!(runner.which_lookups(), ["limactl"]);

    // Linux without Lima: the install hint.
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.stub_missing("limactl");
    let backend = VmBackend::with_facts(&paths, &runner, VERSION, "Linux", "cageuser");
    let issues = backend.check_prerequisites();
    assert!(issues[0].starts_with("'limactl' not found in PATH"));

    // Linux without QEMU: both architectures are probed before the
    // verdict.
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.stub_missing("qemu-system-x86_64");
    runner.stub_missing("qemu-system-aarch64");
    let backend = VmBackend::with_facts(&paths, &runner, VERSION, "Linux", "cageuser");
    assert!(
        backend
            .check_prerequisites()
            .iter()
            .any(|issue| issue.starts_with("QEMU not found")),
    );
    assert_eq!(
        runner.which_lookups(),
        ["limactl", "qemu-system-x86_64", "qemu-system-aarch64"]
    );

    // An OS that is neither.
    let runner = FakeRunner::new();
    runner.assume_installed();
    let backend = VmBackend::with_facts(&paths, &runner, VERSION, "FreeBSD", "cageuser");
    assert_eq!(
        backend.check_prerequisites(),
        ["unsupported platform: FreeBSD — Lima requires Linux or macOS"]
    );
}

// ─── VmPodman ────────────────────────────────────────────────

#[test]
fn vm_podman_wraps_every_secret_operation_in_the_same_shell() {
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "ls",
        ],
        Reply::ok("demo.API_KEY\ndemo.OTHER\nunrelated\n"),
    );
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "inspect",
            "--showsecret",
        ],
        Reply::ok("sk-guest\n"),
    );
    // `create`, `rm` and the bare `inspect` behind `secret_exists` are
    // one guest call each (lima/podman.py), so they need rules too.
    for verb in ["create", "rm", "inspect"] {
        runner.on(
            [
                "limactl",
                "shell",
                "--workdir",
                "/",
                "--tty=false",
                "agentcage-demo",
                "--",
                "podman",
                "secret",
                verb,
            ],
            Reply::ok(""),
        );
    }
    let podman = VmPodman::new(&runner, "demo");

    assert_eq!(
        podman.secret_list("demo.").expect("lists"),
        ["demo.API_KEY", "demo.OTHER"]
    );
    runner.assert_call(
        0,
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "ls",
            "--noheading",
            "--format",
            "{{.Name}}",
        ],
    );
    assert_eq!(
        podman.secret_read("demo.API_KEY").expect("reads"),
        "sk-guest"
    );
    podman.secret_create("demo.NEW", "sk-new").expect("creates");
    runner.assert_call(
        2,
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "create",
            "demo.NEW",
            "-",
        ],
    );
    assert_eq!(runner.call(2).stdin_text().as_deref(), Some("sk-new"));
    podman.secret_remove("demo.NEW").expect("removes");
    podman.secret_exists("demo.NEW").expect("asks");
    // Five operations, one guest call each.
    assert_eq!(runner.call_count(), 5);
}

#[test]
fn the_strict_lister_fails_where_the_lenient_one_shrugs() {
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.on(
        ["limactl", "shell"],
        Reply::failed(1, "Error: unable to connect"),
    );
    let podman = VmPodman::new(&runner, "demo");

    // Lenient: an empty view, which `cage show` and `secret list` want.
    assert!(podman.secret_list("demo.").expect("shrugs").is_empty());
    // Strict: an error, so the `Secret=` gate falls back to
    // emit-everything instead of dropping every directive (#262).
    assert!(podman.secret_list_strict("demo.").is_err());
}

// ─── generate_units, the store view ──────────────────────────

#[test]
fn a_running_guests_secret_store_reaches_the_renderer() {
    let home = Home::new("store-view");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    // Calls this test does not assert on still have to answer;
    // a default is checked after every rule, so it shadows none.
    runner.default_reply(Reply::success());
    runner.on(["limactl", "list"], Reply::ok(r#"{"status":"Running"}"#));
    runner.on(
        [
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "ls",
        ],
        Reply::ok("demo.API_KEY\n"),
    );
    let backend = vm(&paths, &runner);

    let config = agentcage_core::config::load(
        "cage.yaml",
        "name: demo\ncontainer:\n  image: alpine\nisolation: vm\n\
         secret_injection:\n- env: API_KEY\n  source: \"podman:\"\n\
         - env: ABSENT\n  source: \"podman:\"\n",
        &agentcage_core::config::FixedHost {
            isolation: "vm".to_owned(),
            dns_servers: Ok(vec!["192.0.2.53".to_owned()]),
        },
    )
    .expect("loads");

    let units = backend
        .generate_units(
            &config,
            "/tmp/cage.yaml",
            "/tmp/patches",
            "demo",
            None,
            None,
        )
        .expect("renders");
    let cage = units.files["quadlets/demo-cage.container"].as_str();
    // Store-aware emission: the secret the guest holds is referenced,
    // the one it does not is skipped rather than rendered as a
    // directive that fails the next boot with start-limit-hit.
    assert!(cage.contains("Secret=demo.API_KEY,type=env,target=API_KEY"));
    assert!(!cage.contains("ABSENT"));

    // Two round-trips, in this order: does it exist and is it running,
    // then the listing.
    runner.assert_argv(&[
        &["limactl", "list", "--json", "agentcage-demo"],
        &["limactl", "list", "--json", "agentcage-demo"],
        &[
            "limactl",
            "shell",
            "--workdir",
            "/",
            "--tty=false",
            "agentcage-demo",
            "--",
            "podman",
            "secret",
            "ls",
            "--noheading",
            "--format",
            "{{.Name}}",
        ],
    ]);
}

#[test]
fn an_unreachable_guest_keeps_the_legacy_emission() {
    let home = Home::new("store-view-down");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    // Calls this test does not assert on still have to answer;
    // a default is checked after every rule, so it shadows none.
    runner.default_reply(Reply::success());
    runner.on(["limactl", "list"], Reply::failed(1, "no such instance"));
    let backend = vm(&paths, &runner);

    let config = agentcage_core::config::load(
        "cage.yaml",
        "name: demo\ncontainer:\n  image: alpine\nisolation: vm\n\
         secret_injection:\n- env: API_KEY\n  source: \"podman:\"\n",
        &agentcage_core::config::FixedHost {
            isolation: "vm".to_owned(),
            dns_servers: Ok(vec!["192.0.2.53".to_owned()]),
        },
    )
    .expect("loads");

    let units = backend
        .generate_units(
            &config,
            "/tmp/cage.yaml",
            "/tmp/patches",
            "demo",
            None,
            None,
        )
        .expect("renders");
    assert!(units.files["quadlets/demo-cage.container"].contains("Secret=demo.API_KEY"));
}

/// The used-octet set is forwarded, not swallowed.
#[test]
fn a_pinned_octet_reaches_the_network_unit() {
    let home = Home::new("octet");
    let paths = home.paths();
    let runner = FakeRunner::new();
    runner.assume_installed();
    runner.on(["limactl", "list"], Reply::failed(1, "no such instance"));
    let backend = vm(&paths, &runner);

    let config = agentcage_core::config::load(
        "cage.yaml",
        "name: demo\ncontainer:\n  image: alpine\nisolation: vm\n",
        &agentcage_core::config::FixedHost {
            isolation: "vm".to_owned(),
            dns_servers: Ok(vec!["192.0.2.53".to_owned()]),
        },
    )
    .expect("loads");

    let used: BTreeSet<u32> = BTreeSet::new();
    let units = backend
        .generate_units(
            &config,
            "/tmp/cage.yaml",
            "/tmp/patches",
            "demo",
            Some(&used),
            Some(77),
        )
        .expect("renders");
    assert!(units.files["quadlets/demo-net.network"].contains("10.89.77.0/24"));
}
