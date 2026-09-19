//! argv assertions for the podman wrapper, against
//! `tests/test_podman.py`'s expectations.
//!
//! # What this file is
//!
//! `tests/test_podman.py` is the closest thing agentcage has to a
//! specification for the podman wrapper, and it is written in the style
//! this port is replacing: patch `subprocess.run`, then assert on
//! fragments of the recorded call -- `assert "-t" in cmd`,
//! `assert cmd[-3:] == [...]`, `assert "--no-cache" in cmd`.
//!
//! Membership assertions are weaker than they look. `assert "-f" in cmd`
//! passes whether `-f` precedes the Containerfile or trails it, and
//! `assert "FOO=bar" in cmd` passes if `--build-arg` ends up somewhere
//! else entirely. So each test below pins the **whole argv**, and says
//! in a comment which Python test it answers. Where the Python asserts
//! something weaker, the stronger assertion here is still compatible
//! with it -- it just also fails on the reorderings the Python would
//! accept.
//!
//! # Coverage
//!
//! `podman.py` has **21 invocation sites**. All 21 are pinned here, plus
//! the three `_podman_cmd` cases and the two secret-parsing helpers.
//! `test_podman.py` covers 16 of the 21 methods across 31 test
//! functions; the five it never invokes -- `run_and_remove`,
//! `volume_export`, `volume_create`, `volume_import`, `image_inspect`,
//! `container_exec`, `pull` -- are pinned here for the first time.

use agentcage_exec::tools::podman::{BuildOptions, Podman, VolumeMount, secret_env_names};
use agentcage_exec::{Command, Elevation, FakeRunner, Reply, Sink, Stdin};

/// A podman wrapper over a fresh fake, with no `runuser` prefix.
fn podman(fake: &FakeRunner) -> Podman<'_> {
    Podman::with_elevation(fake, Elevation::none())
}

/// A podman wrapper that drops to `alice`.
fn podman_as_alice(fake: &FakeRunner) -> Podman<'_> {
    Podman::with_elevation(fake, Elevation::runuser("alice"))
}

// ---------------------------------------------------------------------
// _podman_cmd  --  TestPodmanCmd
// ---------------------------------------------------------------------

/// `TestPodmanCmd::test_normal_user`, `test_root_without_sudo_user`.
///
/// Both Python cases assert `["podman"]`; they differ only in how the
/// environment gets there, which is [`Elevation::detect`]'s job and is
/// tested in `tools::tests`.
#[test]
fn unelevated_commands_start_with_podman() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake).image_exists("img").unwrap();
    fake.assert_call(0, &["podman", "image", "exists", "img"]);
}

/// `TestPodmanCmd::test_root_with_sudo_user`.
///
/// The prefix has to be a *prefix*: `runuser -u alice -- podman image
/// exists img`, with the `--` between runuser's flags and podman's.
#[test]
fn elevated_commands_are_wrapped_in_runuser() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman_as_alice(&fake).image_exists("img").unwrap();
    fake.assert_call(
        0,
        &[
            "runuser", "-u", "alice", "--", "podman", "image", "exists", "img",
        ],
    );
}

/// Every method inherits the prefix, not just the one that was tested.
#[test]
fn the_prefix_reaches_every_method() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::ok("running\n"), Reply::status(0)]);
    let p = podman_as_alice(&fake);
    p.volume_exists("vol").unwrap();
    p.container_running("c").unwrap();
    p.secret_remove("c.KEY").unwrap();
    for argv in fake.argv_sequence() {
        assert_eq!(&argv[..4], &["runuser", "-u", "alice", "--"], "{argv:?}");
    }
}

// ---------------------------------------------------------------------
// image_exists  --  TestImageExists
// ---------------------------------------------------------------------

/// `TestImageExists::test_exists` (`cmd[-3:] == ["image", "exists",
/// "myimg:latest"]`) and `test_not_exists`.
#[test]
fn image_exists_reads_the_exit_status() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(1)]);
    let p = podman(&fake);
    assert!(p.image_exists("myimg:latest").unwrap());
    assert!(!p.image_exists("myimg:latest").unwrap());
    fake.assert_argv(&[
        &["podman", "image", "exists", "myimg:latest"],
        &["podman", "image", "exists", "myimg:latest"],
    ]);
    // Not captured: the Python passes no `capture_output`, and the
    // answer is the status.
    assert_eq!(fake.call(0).command.stdout_spec(), &Sink::Inherit);
    fake.assert_drained();
}

// ---------------------------------------------------------------------
// build_image  --  TestBuildImage
// ---------------------------------------------------------------------

/// `TestBuildImage::test_basic_build`: `-t`, the tag, `-f`, the
/// Containerfile, and the context directory last.
#[test]
fn build_basic() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake)
        .build_image(
            "myimg:latest",
            "/ctx",
            &BuildOptions {
                containerfile: Some("/path/Containerfile".into()),
                ..BuildOptions::default()
            },
        )
        .unwrap();
    fake.assert_call(
        0,
        &[
            "podman",
            "build",
            "-t",
            "myimg:latest",
            "-f",
            "/path/Containerfile",
            "/ctx",
        ],
    );
}

/// `TestBuildImage::test_no_cache`: `--no-cache` present, `-f` absent.
#[test]
fn build_no_cache_without_a_containerfile() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake)
        .build_image(
            "img",
            "/ctx",
            &BuildOptions {
                no_cache: true,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    fake.assert_call(0, &["podman", "build", "-t", "img", "--no-cache", "/ctx"]);
    assert!(!fake.argv(0).iter().any(|a| a == "-f"));
}

/// Not in `test_podman.py`, and the reason it should be: `no_cache` and
/// `pull` are independent, and the Python's docstring spends a paragraph
/// saying so. Each alone, and both together.
#[test]
fn build_no_cache_and_pull_are_independent() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(0), Reply::status(0)]);
    let p = podman(&fake);
    for (no_cache, pull) in [(false, true), (true, false), (true, true)] {
        p.build_image(
            "img",
            "/ctx",
            &BuildOptions {
                no_cache,
                pull,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    }
    fake.assert_argv(&[
        &["podman", "build", "-t", "img", "--pull=always", "/ctx"],
        &["podman", "build", "-t", "img", "--no-cache", "/ctx"],
        &[
            "podman",
            "build",
            "-t",
            "img",
            "--no-cache",
            "--pull=always",
            "/ctx",
        ],
    ]);
}

/// `TestBuildImage::test_cap_add`: one `--cap-add` per capability, in
/// order, and the context directory still last.
#[test]
fn build_cap_add() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake)
        .build_image(
            "img",
            "/ctx",
            &BuildOptions {
                cap_add: vec!["CAP_CHOWN".into(), "CAP_FOWNER".into()],
                ..BuildOptions::default()
            },
        )
        .unwrap();
    fake.assert_call(
        0,
        &[
            "podman",
            "build",
            "-t",
            "img",
            "--cap-add",
            "CAP_CHOWN",
            "--cap-add",
            "CAP_FOWNER",
            "/ctx",
        ],
    );
}

/// `TestBuildImage::test_build_args`, strengthened: the Python asserts
/// `"--build-arg" in cmd` and `"FOO=bar" in cmd` separately, which would
/// pass even if they were not adjacent. Declaration order is pinned too,
/// because the Python iterates a `dict` and `cage update`'s diff of the
/// rendered build args is order-sensitive.
#[test]
fn build_args_keep_their_order_and_stay_adjacent() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake)
        .build_image(
            "img",
            "/ctx",
            &BuildOptions {
                build_args: vec![
                    ("FOO".into(), "bar".into()),
                    ("BASE".into(), "docker.io/library/ubuntu:24.04".into()),
                ],
                ..BuildOptions::default()
            },
        )
        .unwrap();
    fake.assert_call(
        0,
        &[
            "podman",
            "build",
            "-t",
            "img",
            "--build-arg",
            "FOO=bar",
            "--build-arg",
            "BASE=docker.io/library/ubuntu:24.04",
            "/ctx",
        ],
    );
}

/// Every flag at once, in the Python's order: `-f`, `--no-cache`,
/// `--pull=always`, caps, build args, context.
#[test]
fn build_flag_order_matches_podman_py() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake)
        .build_image(
            "img",
            "/ctx",
            &BuildOptions {
                containerfile: Some("/Containerfile".into()),
                no_cache: true,
                pull: true,
                cap_add: vec!["CAP_CHOWN".into()],
                build_args: vec![("K".into(), "v".into())],
                quiet: false,
            },
        )
        .unwrap();
    fake.assert_call(
        0,
        &[
            "podman",
            "build",
            "-t",
            "img",
            "-f",
            "/Containerfile",
            "--no-cache",
            "--pull=always",
            "--cap-add",
            "CAP_CHOWN",
            "--build-arg",
            "K=v",
            "/ctx",
        ],
    );
}

/// `TestBuildImage::test_raises_on_failure`.
///
/// And the thing the Python cannot see, because it patches the function:
/// `quiet` decides whether the build streams or is captured, and the
/// captured failure carries the output. Same argv, different stdio.
#[test]
fn build_raises_on_failure_and_quiet_changes_the_stdio() {
    let fake = FakeRunner::new();
    fake.push_all([
        Reply::failed(1, "Error: no FROM"),
        Reply::failed(1, "Error: no FROM"),
    ]);
    let p = podman(&fake);

    p.build_image("img", "/ctx", &BuildOptions::default())
        .unwrap_err();
    assert_eq!(p.base().stdout_spec(), &Sink::Inherit);
    assert_eq!(fake.call(0).command.stdout_spec(), &Sink::Inherit);

    let err = p
        .build_image(
            "img",
            "/ctx",
            &BuildOptions {
                quiet: true,
                ..BuildOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(fake.call(1).command.stdout_spec(), &Sink::Capture);
    assert!(err.to_string().contains("no FROM"), "{err}");
    // Same argv either way.
    assert_eq!(fake.argv(0), fake.argv(1));
}

// ---------------------------------------------------------------------
// run_and_remove  --  not covered by test_podman.py
// ---------------------------------------------------------------------

/// `podman run --rm [-v host:bind[:mode]]... <image> <command...>`.
#[test]
fn run_and_remove_builds_its_mounts_in_order() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake)
        .run_and_remove(
            "alpine",
            &["sh".to_string(), "-c".to_string(), "true".to_string()],
            &[
                VolumeMount::new("/host/a"),
                VolumeMount::new("/host/b").bind("/in/b").mode("ro"),
            ],
        )
        .unwrap();
    fake.assert_call(
        0,
        &[
            "podman",
            "run",
            "--rm",
            "-v",
            "/host/a:/host/a",
            "-v",
            "/host/b:/in/b:ro",
            "alpine",
            "sh",
            "-c",
            "true",
        ],
    );
}

// ---------------------------------------------------------------------
// container_running / container_inspect  --  TestContainerRunning,
// TestContainerInspect
// ---------------------------------------------------------------------

/// `TestContainerRunning::{test_running,test_not_running,test_container_missing}`.
#[test]
fn container_running_compares_the_status_format() {
    let fake = FakeRunner::new();
    fake.push_all([
        Reply::ok("running\n"),
        Reply::ok("exited\n"),
        Reply::status(1),
    ]);
    let p = podman(&fake);
    assert!(p.container_running("mycontainer").unwrap());
    assert!(!p.container_running("mycontainer").unwrap());
    assert!(!p.container_running("mycontainer").unwrap());
    fake.assert_call(
        0,
        &[
            "podman",
            "inspect",
            "--format",
            "{{.State.Status}}",
            "mycontainer",
        ],
    );
    assert_eq!(fake.call(0).command.stdout_spec(), &Sink::Capture);
}

/// `TestContainerInspect::test_returns_first_item` and
/// `test_raises_on_missing`.
#[test]
fn container_inspect_takes_the_first_array_element() {
    let fake = FakeRunner::new();
    fake.push_all([
        Reply::ok(r#"[{"Id": "abc123", "State": {"Status": "running"}}]"#),
        Reply::failed(125, "no such container"),
    ]);
    let p = podman(&fake);
    assert_eq!(p.container_inspect("mycontainer").unwrap()["Id"], "abc123");
    p.container_inspect("missing").unwrap_err();
    fake.assert_call(0, &["podman", "inspect", "mycontainer"]);
}

/// Not covered by `test_podman.py`: `podman exec <name> <cmd...>`,
/// reporting the exit code rather than raising -- `cage verify` runs
/// probes whose failure is the answer.
#[test]
fn container_exec_returns_the_code_and_stdout() {
    let fake = FakeRunner::new();
    fake.push(Reply::Ran(agentcage_exec::Output {
        status: agentcage_exec::ExitStatus::exited(7),
        stdout: b"probe output\n".to_vec(),
        stderr: Vec::new(),
    }));
    let (code, stdout) = podman(&fake)
        .container_exec(
            "cage-workload",
            &["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
        )
        .unwrap();
    assert_eq!(code, 7);
    assert_eq!(stdout, "probe output\n");
    fake.assert_call(
        0,
        &["podman", "exec", "cage-workload", "sh", "-c", "exit 7"],
    );
}

// ---------------------------------------------------------------------
// network_remove / volume_*  --  TestNetworkRemove, TestVolumeRemove,
// TestVolumeExists
// ---------------------------------------------------------------------

/// `TestNetworkRemove::{test_success,test_failure}`,
/// `TestVolumeRemove::{test_success,test_failure}`,
/// `TestVolumeExists::{test_exists,test_not_exists}`.
#[test]
fn removals_and_existence_checks_report_the_status() {
    let fake = FakeRunner::new();
    fake.push_all([
        Reply::status(0),
        Reply::status(1),
        Reply::status(0),
        Reply::status(1),
        Reply::status(0),
        Reply::status(1),
    ]);
    let p = podman(&fake);
    assert!(p.network_remove("mynet").unwrap());
    assert!(!p.network_remove("mynet").unwrap());
    assert!(p.volume_remove("myvol").unwrap());
    assert!(!p.volume_remove("myvol").unwrap());
    assert!(p.volume_exists("myvol").unwrap());
    assert!(!p.volume_exists("myvol").unwrap());
    fake.assert_argv(&[
        &["podman", "network", "rm", "mynet"],
        &["podman", "network", "rm", "mynet"],
        &["podman", "volume", "rm", "myvol"],
        &["podman", "volume", "rm", "myvol"],
        &["podman", "volume", "exists", "myvol"],
        &["podman", "volume", "exists", "myvol"],
    ]);
    // `network rm` and `volume rm` capture (so podman's complaint does
    // not reach the operator's terminal); `volume exists` does not.
    assert_eq!(fake.call(0).command.stdout_spec(), &Sink::Capture);
    assert_eq!(fake.call(4).command.stdout_spec(), &Sink::Inherit);
    fake.assert_drained();
}

/// Not covered by `test_podman.py`. `volume create` captures and checks;
/// `volume export` redirects stdout to the backup file; `volume import`
/// feeds the archive in on stdin with a trailing `-`.
#[test]
fn volume_backup_and_restore_wire_their_streams_to_files() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(0), Reply::status(0)]);
    let p = podman(&fake);
    p.volume_create("myvol").unwrap();
    p.volume_export("myvol", "/backup/myvol.tar").unwrap();
    p.volume_import("myvol", "/backup/myvol.tar").unwrap();

    fake.assert_argv(&[
        &["podman", "volume", "create", "myvol"],
        &["podman", "volume", "export", "myvol"],
        &["podman", "volume", "import", "myvol", "-"],
    ]);
    assert_eq!(
        fake.call(1).command.stdout_spec(),
        &Sink::Write("/backup/myvol.tar".into()),
        "the tar stream must not pass through agentcage"
    );
    assert_eq!(
        fake.call(2).command.stdin_spec(),
        &Stdin::File("/backup/myvol.tar".into())
    );
}

// ---------------------------------------------------------------------
// pull / info / image_inspect  --  TestInfo
// ---------------------------------------------------------------------

/// Not covered by `test_podman.py`: `podman pull` streams to the
/// terminal and reports success as a bool, because a local-only image or
/// a missing network is a normal outcome.
#[test]
fn pull_streams_and_reports_a_bool() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(125)]);
    let p = podman(&fake);
    assert!(p.pull("docker.io/library/alpine:3").unwrap());
    assert!(!p.pull("docker.io/library/alpine:3").unwrap());
    fake.assert_call(0, &["podman", "pull", "docker.io/library/alpine:3"]);
    assert_eq!(fake.call(0).command.stdout_spec(), &Sink::Inherit);
}

/// `TestInfo::test_returns_parsed_json`.
#[test]
fn info_asks_for_json_and_parses_it() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok(r#"{"host": {"security": {"rootless": true}}}"#));
    let info = podman(&fake).info().unwrap();
    assert_eq!(info["host"]["security"]["rootless"], true);
    fake.assert_call(0, &["podman", "info", "--format", "json"]);
}

/// Not covered by `test_podman.py`: `podman image inspect` also takes
/// the first array element.
#[test]
fn image_inspect_takes_the_first_array_element() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok(r#"[{"Id": "sha256:deadbeef"}]"#));
    let data = podman(&fake).image_inspect("myimg:latest").unwrap();
    assert_eq!(data["Id"], "sha256:deadbeef");
    fake.assert_call(0, &["podman", "image", "inspect", "myimg:latest"]);
}

/// An empty array is a parse failure, not a panic -- the Python's `[0]`
/// would raise `IndexError`.
#[test]
fn an_empty_inspect_array_is_an_error() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok("[]"));
    let err = podman(&fake).container_inspect("c").unwrap_err();
    assert!(err.to_string().contains("non-empty"), "{err}");
}

// ---------------------------------------------------------------------
// secrets  --  TestSecretExists, TestSecretCreate, TestSecretRemove,
// TestSecretList, TestSecretRead
// ---------------------------------------------------------------------

/// `TestSecretExists::{test_exists,test_not_exists}`.
#[test]
fn secret_exists_reads_the_exit_status() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(1)]);
    let p = podman(&fake);
    assert!(p.secret_exists("mysecret").unwrap());
    assert!(!p.secret_exists("mysecret").unwrap());
    fake.assert_call(0, &["podman", "secret", "inspect", "mysecret"]);
}

/// `TestSecretCreate::test_creates_with_stdin`, which is the most
/// important assertion in the Python file: it checks
/// `kwargs["input"] == "supersecretvalue"`. Here that is the *whole*
/// claim -- the value is on stdin and the argv ends in `-`.
#[test]
fn secret_create_puts_the_value_on_stdin_and_never_in_argv() {
    let fake = FakeRunner::new();
    fake.push(Reply::status(0));
    podman(&fake)
        .secret_create("mysecret", "supersecretvalue")
        .unwrap();

    fake.assert_call(0, &["podman", "secret", "create", "mysecret", "-"]);
    assert_eq!(
        fake.call(0).stdin_text().as_deref(),
        Some("supersecretvalue")
    );
    assert!(
        !fake.argv(0).iter().any(|a| a.contains("supersecretvalue")),
        "the value must never reach /proc/<pid>/cmdline"
    );
    // And it must not reach a test failure message either.
    assert!(!format!("{:?}", fake.calls()).contains("supersecretvalue"));
    // podman echoes the new secret's ID; nothing reads it.
    assert_eq!(fake.call(0).command.stdout_spec(), &Sink::Null);
}

/// `TestSecretCreate::test_raises_on_failure`.
#[test]
fn secret_create_raises_on_failure() {
    let fake = FakeRunner::new();
    fake.push(Reply::failed(125, "secret already exists"));
    podman(&fake).secret_create("mysecret", "val").unwrap_err();
}

/// `TestSecretRemove::{test_success,test_failure}`.
#[test]
fn secret_remove_reports_a_bool() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::status(0), Reply::status(1)]);
    let p = podman(&fake);
    assert!(p.secret_remove("mysecret").unwrap());
    assert!(!p.secret_remove("mysecret").unwrap());
    fake.assert_call(0, &["podman", "secret", "rm", "mysecret"]);
}

/// `TestSecretList::{test_returns_all,test_filters_by_prefix,test_empty_output}`.
#[test]
fn secret_list_parses_and_filters() {
    let fake = FakeRunner::new();
    fake.on(
        ["podman", "secret", "ls"],
        Reply::ok("myapp.KEY1\nmyapp.KEY2\nother.KEY3\n"),
    );
    let p = podman(&fake);
    assert_eq!(p.secret_list("").unwrap().len(), 3);
    let filtered = p.secret_list("myapp.").unwrap();
    assert_eq!(filtered, ["myapp.KEY1", "myapp.KEY2"]);
    fake.assert_call(
        0,
        &[
            "podman",
            "secret",
            "ls",
            "--noheading",
            "--format",
            "{{.Name}}",
        ],
    );
}

/// `TestSecretList::test_empty_output`.
#[test]
fn secret_list_is_empty_for_empty_output() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok(""));
    assert!(podman(&fake).secret_list("").unwrap().is_empty());
}

/// `TestSecretList::test_command_failure_lenient` -- the behaviour
/// `cage show`, `secret list` and `destroy_resources` rely on.
#[test]
fn secret_list_is_lenient_about_failure() {
    let fake = FakeRunner::new();
    fake.push(Reply::failed(1, "daemon unavailable"));
    assert!(podman(&fake).secret_list("").unwrap().is_empty());
}

/// `TestSecretList::test_strict_raises_on_failure` and
/// `test_strict_empty_on_success` -- issue #262. Identical argv,
/// opposite behaviour, and the difference decides whether a cage gets
/// its `Secret=` directives.
#[test]
fn secret_list_strict_raises_where_the_lenient_one_shrugs() {
    let fake = FakeRunner::new();
    fake.push_all([Reply::failed(1, "daemon unavailable"), Reply::ok("")]);
    let p = podman(&fake);

    let err = p.secret_list_strict("").unwrap_err();
    assert!(err.to_string().contains("podman secret ls"), "{err}");
    assert!(err.to_string().contains("daemon unavailable"), "{err}");

    assert!(p.secret_list_strict("").unwrap().is_empty());

    assert_eq!(fake.argv(0), fake.argv(1), "same command, different policy");
}

/// The strict lister falls back to stdout when stderr is empty, as
/// `(r.stderr or r.stdout or '')` does.
#[test]
fn strict_failure_falls_back_to_stdout_for_its_message() {
    let fake = FakeRunner::new();
    fake.push(Reply::Ran(agentcage_exec::Output {
        status: agentcage_exec::ExitStatus::exited(1),
        stdout: b"cannot connect\n".to_vec(),
        stderr: Vec::new(),
    }));
    let err = podman(&fake).secret_list_strict("").unwrap_err();
    assert!(err.to_string().contains("cannot connect"), "{err}");
}

/// `TestSecretRead::{test_reads_value,test_raises_on_missing}`.
#[test]
fn secret_read_uses_showsecret_and_strips() {
    let fake = FakeRunner::new();
    fake.push_all([
        Reply::ok("secretval\n"),
        Reply::failed(125, "no such secret"),
    ]);
    let p = podman(&fake);
    assert_eq!(p.secret_read("mysecret").unwrap(), "secretval");
    p.secret_read("missing").unwrap_err();
    fake.assert_call(
        0,
        &[
            "podman",
            "secret",
            "inspect",
            "--showsecret",
            "--format",
            "{{.SecretData}}",
            "mysecret",
        ],
    );
}

// ---------------------------------------------------------------------
// secret_env_names  --  not covered by test_podman.py
// ---------------------------------------------------------------------

/// `podman.py::secret_env_names` strips the deploy prefix, and uses the
/// *strict* lister so that a transient failure reaches the caller's
/// fallback instead of arriving as an empty set.
#[test]
fn secret_env_names_strips_the_deploy_prefix() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok("myapp.KEY1\nmyapp.KEY2\n"));
    let p = podman(&fake);
    assert_eq!(secret_env_names(&p, "myapp").unwrap(), ["KEY1", "KEY2"]);
}

/// With no deploy name the entries are bare and nothing is stripped.
#[test]
fn secret_env_names_without_a_deploy_name_lists_bare_keys() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok("KEY1\nKEY2\n"));
    let p = podman(&fake);
    assert_eq!(secret_env_names(&p, "").unwrap(), ["KEY1", "KEY2"]);
}

/// The whole point of routing through the strict lister: a failure is a
/// failure, not an empty store.
#[test]
fn secret_env_names_propagates_a_listing_failure() {
    let fake = FakeRunner::new();
    fake.push(Reply::failed(1, "daemon unavailable"));
    let p = podman(&fake);
    secret_env_names(&p, "myapp").unwrap_err();
}

// ---------------------------------------------------------------------
// The fake's own contract
// ---------------------------------------------------------------------

/// An unstubbed call is a loud failure, not a silent exit 0.
#[test]
#[should_panic(expected = "unexpected call")]
fn an_unanticipated_podman_call_panics() {
    let fake = FakeRunner::new();
    let _ = podman(&fake).info();
}

/// A sequence of calls with nothing stubbed in between is asserted as
/// one unit -- the property `assert "-f" in cmd` cannot express.
#[test]
fn a_whole_teardown_sequence_is_one_assertion() {
    let fake = FakeRunner::new();
    fake.push_all([
        Reply::status(0), // secret rm
        Reply::status(0), // volume rm
        Reply::status(0), // network rm
    ]);
    let p = podman(&fake);
    p.secret_remove("myapp.KEY").unwrap();
    p.volume_remove("myapp-workspace").unwrap();
    p.network_remove("myapp-net").unwrap();
    fake.assert_argv(&[
        &["podman", "secret", "rm", "myapp.KEY"],
        &["podman", "volume", "rm", "myapp-workspace"],
        &["podman", "network", "rm", "myapp-net"],
    ]);
    fake.assert_drained();
}

/// The fake is a [`CommandRunner`], so anything that takes one takes it
/// -- including code that has nothing to do with podman.
#[test]
fn the_fake_is_a_drop_in_runner() {
    let fake = FakeRunner::new();
    fake.push(Reply::ok("hello"));
    let runner: &dyn agentcage_exec::CommandRunner = &fake;
    let out = runner
        .run(&Command::new("echo").arg("hello").captured())
        .unwrap();
    assert_eq!(out.stdout_text(), "hello");
}
