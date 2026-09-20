//! The argv `cage exec` hands to podman, and where the `--env` flags in
//! it come from.
//!
//! `cage exec`'s acceptance check is e2e phase 6, which runs it against
//! a real cage. That check cannot see the two things most likely to
//! break silently:
//!
//! * the **`-u` spec**, whose absence puts a session at the image's
//!   `USER` — root, on the ubuntu scaffold — while the cage still looks
//!   healthy; and
//! * the **`--env` placeholders**, which are read from the *stored*
//!   `cage.yaml` at call time rather than from the container's
//!   environment, so that a secret declared after the cage started is
//!   usable without a restart. A regression here is invisible until
//!   someone adds a secret and their agent reads an empty variable.
//!
//! Both are argv, so both are checked here with no podman in sight.

use agentcage_cli::backend::ContainerBackend;
use agentcage_cli::services::current_placeholders;
use agentcage_exec::{Elevation, FakeRunner};
use agentcage_state::{Paths, TestDir};

/// Write a stored `cage.yaml` for `name`, verbatim.
fn store(paths: &Paths, name: &str, yaml: &str) {
    std::fs::create_dir_all(paths.deployment_dir(name)).expect("state dir");
    std::fs::write(paths.stored_config_path(name), yaml).expect("cage.yaml");
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

const WITH_SECRETS: &str = "\
name: acme
container:
  image: node:22-slim
secret_injection:
  rules:
    - env: ANTHROPIC_API_KEY
      placeholder: sk-ant-placeholder-0001
      secret: anthropic
    - env: OPENAI_API_KEY
      placeholder: sk-openai-placeholder-0002
      secret: openai
domains:
  allow:
    - example.com
";

/// The shape, for a cage that declares no secrets.
#[test]
fn the_default_session_runs_as_uid_1000_with_its_group_pinned() {
    let dir = TestDir::new("exec-argv-plain");
    let paths = Paths::under(dir.path());
    store(
        &paths,
        "acme",
        "name: acme\ncontainer:\n  image: node:22-slim\ndomains:\n  allow:\n    - example.com\n",
    );
    let fake = FakeRunner::new();
    let backend = ContainerBackend::with_elevation(&paths, &fake, "9.9.9", Elevation::none());

    assert_eq!(
        backend.exec_argv("acme", "cage", &argv(&["ls", "-la"]), false, false),
        [
            "podman",
            "exec",
            "-u",
            "1000:1000",
            "acme-cage",
            "ls",
            "-la"
        ]
    );
    assert_eq!(
        fake.call_count(),
        0,
        "building an argv must not run anything"
    );
}

/// `--as-root` is the operator debug path, and `-it` only appears when
/// there is a terminal to allocate one for.
#[test]
fn as_root_and_interactive_are_the_only_two_variables() {
    let dir = TestDir::new("exec-argv-flags");
    let paths = Paths::under(dir.path());
    store(
        &paths,
        "acme",
        "name: acme\ncontainer:\n  image: node:22-slim\ndomains:\n  allow:\n    - example.com\n",
    );
    let fake = FakeRunner::new();
    let backend = ContainerBackend::with_elevation(&paths, &fake, "9.9.9", Elevation::none());

    assert_eq!(
        backend.exec_argv("acme", "cage", &argv(&["sh"]), true, true),
        ["podman", "exec", "-u", "0:0", "-it", "acme-cage", "sh"]
    );
    // `-it` sits between the `-u` spec and the container name, which is
    // the Python's order and the only one `--env` flags can follow.
    assert_eq!(
        backend.exec_argv("acme", "egress", &argv(&["sh"]), true, false),
        [
            "podman",
            "exec",
            "-u",
            "1000:1000",
            "-it",
            "acme-egress",
            "sh"
        ]
    );
}

/// The placeholders come from the stored config, and only the `cage`
/// service gets them.
#[test]
fn a_cage_session_carries_the_current_placeholders() {
    let dir = TestDir::new("exec-argv-secrets");
    let paths = Paths::under(dir.path());
    store(&paths, "acme", WITH_SECRETS);
    let fake = FakeRunner::new();
    let backend = ContainerBackend::with_elevation(&paths, &fake, "9.9.9", Elevation::none());

    assert_eq!(
        backend.exec_argv("acme", "cage", &argv(&["env"]), false, false),
        [
            "podman",
            "exec",
            "-u",
            "1000:1000",
            "--env",
            "ANTHROPIC_API_KEY=sk-ant-placeholder-0001",
            "--env",
            "OPENAI_API_KEY=sk-openai-placeholder-0002",
            "acme-cage",
            "env"
        ]
    );

    // The egress container runs the proxy, which holds the *real*
    // secrets; handing it the decoys would be noise at best.
    assert_eq!(
        backend.exec_argv("acme", "egress", &argv(&["env"]), false, false),
        ["podman", "exec", "-u", "1000:1000", "acme-egress", "env"]
    );
}

/// The point of reading the stored file at call time: a rule added
/// while the cage is running reaches the next session.
#[test]
fn a_secret_declared_after_the_cage_started_is_picked_up() {
    let dir = TestDir::new("exec-argv-live");
    let paths = Paths::under(dir.path());
    store(
        &paths,
        "acme",
        "name: acme\ncontainer:\n  image: node:22-slim\ndomains:\n  allow:\n    - example.com\n",
    );
    assert!(current_placeholders(&paths, "acme").is_empty());

    store(&paths, "acme", WITH_SECRETS);
    assert_eq!(
        current_placeholders(&paths, "acme"),
        [
            (
                "ANTHROPIC_API_KEY".to_owned(),
                "sk-ant-placeholder-0001".to_owned()
            ),
            (
                "OPENAI_API_KEY".to_owned(),
                "sk-openai-placeholder-0002".to_owned()
            ),
        ]
    );
}

/// Every shape that means "no placeholders", none of which may throw.
#[test]
fn an_unreadable_or_unfilled_config_yields_nothing() {
    let dir = TestDir::new("exec-argv-empty");
    let paths = Paths::under(dir.path());

    // No cage at all.
    assert!(current_placeholders(&paths, "ghost").is_empty());

    // A rule whose placeholder was never minted. The Python's `and`
    // chain treats an empty string as absent, so this is contract, not
    // defensiveness.
    store(
        &paths,
        "half",
        "name: half\nsecret_injection:\n  rules:\n    - env: KEY\n      placeholder: ''\n",
    );
    assert!(current_placeholders(&paths, "half").is_empty());

    // `secret_injection:` written as a bare list rather than a mapping
    // with `rules:` — the older spelling, which the Python still reads.
    store(
        &paths,
        "bare",
        "name: bare\nsecret_injection:\n  - env: KEY\n    placeholder: ph-1\n",
    );
    assert_eq!(
        current_placeholders(&paths, "bare"),
        [("KEY".to_owned(), "ph-1".to_owned())]
    );
}
