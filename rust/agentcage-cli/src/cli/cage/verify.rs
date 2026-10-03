//! `cage verify` — the health probe.
//!
//! `cli.py:1494` and all three of its backend branches. PR D6 landed
//! the `_verify_container` half, because e2e phase 1 needed it; D12
//! finishes the command with `_verify_apple_container` and
//! `_verify_vm`.
//!
//! # Why the two new branches do not wait for Track E
//!
//! They probe, they do not deploy. Every question they ask is one
//! `container exec` or one `limactl shell` away — the wrappers for both
//! already exist (PR D1) — so the branches are written against those
//! directly rather than against the vm / apple-container *backends*,
//! which really are Track E's and really do need a Mac and a Lima host
//! to write. The `-- Services --` block dispatches the same way, for
//! the same reason: asking podman whether a Lima VM's units are up
//! answers "no" on a perfectly healthy cage.
//!
//! Neither branch can be exercised on this PR's hardware. What they are
//! held to is the Python, line by line, and the argv assertions at the
//! bottom of this file under a recording fake.

use std::process::ExitCode;

use agentcage_exec::tools::apple::{AppleContainer, container_state};
use agentcage_exec::tools::limactl::LimaInstance;
use agentcage_exec::tools::podman::Podman;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};
use agentcage_cli::backend::SERVICE_NAMES;

/// Tallies the three result kinds, so the summary line can be printed
/// once at the end rather than counted twice.
#[derive(Default)]
struct Results {
    passed: u32,
    failed: u32,
    warned: u32,
}

impl Results {
    fn pass(&mut self, message: &str) {
        println!("  [PASS] {message}");
        self.passed += 1;
    }

    fn fail(&mut self, message: &str) {
        println!("  [FAIL] {message}");
        self.failed += 1;
    }

    fn warn(&mut self, message: &str) {
        println!("  [WARN] {message}");
        self.warned += 1;
    }
}

/// The body.
pub(crate) fn main(ctx: &Ctx, name: &str) -> ExitCode {
    match run(ctx, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    let Ok(config) = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
    else {
        eprintln!("error: cage '{name}' does not exist or has invalid config");
        return Err(ExitCode::from(EXIT_FAILURE));
    };
    ensure_v022_cage(&ctx.paths, name)?;

    let backend = ctx.backend_for(&config.isolation);
    let mut results = Results::default();

    println!("=== agentcage verify: {name} ({}) ===", config.isolation);
    println!();

    println!("-- Services --");
    for (service, running) in service_status(ctx, &backend, name, &config.isolation) {
        if running {
            results.pass(&format!("{name}-{service} is running"));
        } else {
            results.fail(&format!("{name}-{service} is NOT running"));
        }
    }

    match config.isolation.as_str() {
        "container" => verify_container(ctx, name, &config, &mut results),
        "apple-container" => verify_apple_container(ctx, name, &mut results),
        _ => verify_vm(ctx, name, &mut results),
    }

    println!();
    println!(
        "=== Results: {} passed, {} failed, {} warnings ===",
        results.passed, results.failed, results.warned
    );
    if results.failed > 0 {
        println!("    Review failures above.");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    Ok(())
}

/// `_verify_container` — four probe groups, all through `podman exec`.
/// `podman.container_exec` takes an owned argv; these are all literals.
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn verify_container(
    ctx: &Ctx,
    name: &str,
    config: &agentcage_core::config::Config,
    results: &mut Results,
) {
    let podman = Podman::new(ctx.runner.as_ref());
    let cage = format!("{name}-cage");

    println!();
    println!("-- CA Certificate --");
    match podman.container_exec(
        &cage,
        &argv(&["test", "-f", "/certs/mitmproxy-ca-cert.pem"]),
    ) {
        Ok((0, _)) => results.pass("mitmproxy CA cert exists in shared volume"),
        _ => results.fail("mitmproxy CA cert NOT found at /certs/mitmproxy-ca-cert.pem"),
    }

    println!();
    println!("-- Proxy Configuration --");
    let env_names: Vec<String> = podman
        .container_inspect(&cage)
        .ok()
        .and_then(|info| {
            Some(
                info.get("Config")?
                    .get("Env")?
                    .as_array()?
                    .iter()
                    .filter_map(|entry| entry.as_str())
                    .filter_map(|entry| entry.split_once('=').map(|(key, _)| key.to_owned()))
                    .collect(),
            )
        })
        .unwrap_or_default();
    for variable in ["HTTP_PROXY", "HTTPS_PROXY"] {
        if env_names.iter().any(|name| name == variable) {
            results.pass(&format!("{variable} is set"));
        } else {
            results.fail(&format!("{variable} is NOT set"));
        }
    }

    println!();
    println!("-- Egress Filtering --");
    match blocked_domain_status(&podman, &cage) {
        None => results
            .warn("No HTTP client (curl/node/python3) in cage — cannot verify egress filtering"),
        Some(status) if status == "403" || status == "000" => results.pass(&format!(
            "Blocked domain (evil-exfil-server.io) is denied (HTTP {status})"
        )),
        Some(status) => results.fail(&format!(
            "Blocked domain returned HTTP {status} — egress filtering may be broken"
        )),
    }

    if config.container.nested_containers {
        println!();
        println!("-- Nested Containers --");
        match podman.container_exec(&cage, &argv(&["podman", "--version"])) {
            Ok((0, output)) => {
                results.pass(&format!("Inner podman available ({})", output.trim()));
            }
            _ => results.fail("Inner podman is NOT available"),
        }
        match podman.container_exec(&cage, &argv(&["docker", "--version"])) {
            Ok((0, _)) => results.pass("Docker shim available"),
            _ => results.fail("Docker shim is NOT available"),
        }
    }

    println!();
    println!("-- Podman --");
    let rootless = podman
        .info()
        .ok()
        .and_then(|info| {
            info.get("host")?
                .get("security")?
                .get("rootless")?
                .as_bool()
        })
        .unwrap_or(false);
    if rootless {
        results.pass("Podman is running rootless");
    } else {
        results.fail("Podman is NOT rootless");
    }
}

/// The HTTP status the cage gets for a domain it must not reach.
///
/// Three clients, in the Python's order, because a cage image is the
/// operator's business and may have none of them: `curl` if it is on
/// `PATH`, then node's `fetch`, then python3's `urllib`. `None` means
/// no client answered at all, which is a warning rather than a failure.
fn blocked_domain_status(podman: &Podman<'_>, cage: &str) -> Option<String> {
    if matches!(
        podman.container_exec(cage, &argv(&["which", "curl"])),
        Ok((0, _))
    ) {
        let (_, output) = podman
            .container_exec(
                cage,
                &argv(&[
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--max-time",
                    "5",
                    "https://evil-exfil-server.io",
                ]),
            )
            .ok()?;
        return non_empty(output.trim());
    }

    if let Ok((0, output)) = podman.container_exec(
        cage,
        &argv(&[
            "node",
            "-e",
            "fetch('http://evil-exfil-server.io')\
             .then(r=>console.log(r.status))\
             .catch(()=>console.log('000'))",
        ]),
    ) {
        if let Some(status) = non_empty(output.trim()) {
            return Some(status);
        }
    }

    if let Ok((0, output)) = podman.container_exec(
        cage,
        &argv(&[
            "python3",
            "-c",
            "import urllib.request, urllib.error\n\
             try:\n\
             \x20   urllib.request.urlopen('https://evil-exfil-server.io', timeout=5)\n\
             \x20   print('200')\n\
             except urllib.error.HTTPError as e:\n\
             \x20   print(e.code)\n\
             except Exception:\n\
             \x20   print('000')",
        ]),
    ) {
        return non_empty(output.trim());
    }
    None
}

fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

/// Is each of the cage's two services up, on the backend the cage
/// actually runs on?
///
/// `backend.is_running(name, svc)` in `cli.py:1528`, dispatched. The
/// container answer is [`crate::cli::cage::lifecycle::service_status`];
/// the other two are `VMBackend.is_running` and
/// `AppleContainerBackend.is_running`, both of which are short enough
/// to live here rather than to wait for their backends.
fn service_status(
    ctx: &Ctx,
    backend: &agentcage_cli::backends::AnyBackend<'_>,
    name: &str,
    isolation: &str,
) -> Vec<(String, bool)> {
    match isolation {
        "container" => crate::cli::cage::lifecycle::service_status(backend, name),
        "apple-container" => {
            let apple = AppleContainer::new(ctx.runner.as_ref());
            SERVICE_NAMES
                .iter()
                .map(|service| {
                    // `cage` is the workload microVM, named after the
                    // cage itself; `egress` is its sibling. An unknown
                    // service reads as `cage`, which is the Python's
                    // parity rule for the legacy single-VM model.
                    let target = if *service == "egress" {
                        format!("{name}-egress")
                    } else {
                        name.to_owned()
                    };
                    let running = apple.inspect(&target).ok().flatten().is_some_and(|data| {
                        container_state(Some(&data)).as_deref() == Some("running")
                    });
                    ((*service).to_owned(), running)
                })
                .collect()
        }
        _ => {
            let instance = LimaInstance::new(ctx.runner.as_ref(), name);
            // A VM that is not up cannot answer for its units, and
            // `systemctl --user` inside it would fail in a way that
            // reads like a service fault rather than a stopped VM.
            let up = instance.is_running().unwrap_or(false);
            SERVICE_NAMES
                .iter()
                .map(|service| {
                    let running = up && unit_is_active(&instance, name, service);
                    ((*service).to_owned(), running)
                })
                .collect()
        }
    }
}

/// `systemctl --user is-active <cage>-<service>.service`, inside the VM.
fn unit_is_active(instance: &LimaInstance<'_>, name: &str, service: &str) -> bool {
    instance
        .exec(
            &argv(&[
                "systemctl",
                "--user",
                "is-active",
                &format!("{name}-{service}.service"),
            ]),
            false,
        )
        .is_ok_and(|out| out.stdout_trimmed() == "active")
}

/// `_verify_apple_container` — the inside-the-microVM invariants that
/// mean the supervisor wired itself up correctly.
///
/// Service status was already checked by the backend-agnostic block
/// above, so this only adds the three probes Apple's runtime can
/// answer. No failure aborts the run: every check reports its own
/// PASS / FAIL / WARN, which is what makes the summary line a count
/// rather than a first-failure.
fn verify_apple_container(ctx: &Ctx, name: &str, results: &mut Results) {
    let apple = AppleContainer::new(ctx.runner.as_ref());
    if apple.binary().is_none() {
        results.warn(
            "Apple `container` CLI not found; install from \
             https://github.com/apple/container/releases",
        );
        return;
    }

    // `container exec <name> …`, captured. Not the `execvp` hand-off
    // `cage exec` uses: verify is a query, not a hand-off.
    let exec = |command: &[&str]| -> (bool, String) {
        let mut args = vec!["exec".to_owned(), name.to_owned()];
        args.extend(argv(command));
        apple
            .run(args, false)
            .map_or((false, String::new()), |out| {
                let combined = format!("{}{}", out.stdout_text(), out.stderr_text());
                (out.success(), combined.trim().to_owned())
            })
    };

    println!();
    println!("-- CA Certificate --");
    if exec(&["test", "-f", "/certs/mitmproxy-ca-cert.pem"]).0 {
        results.pass("mitmproxy CA cert exists at /certs/mitmproxy-ca-cert.pem");
    } else {
        results.fail("mitmproxy CA cert NOT found at /certs/mitmproxy-ca-cert.pem");
    }

    println!();
    println!("-- DNS routing --");
    let (ok, resolv) = exec(&["cat", "/etc/resolv.conf"]);
    if ok && resolv.contains("nameserver 127.0.0.1") {
        results.pass("/etc/resolv.conf points to local dnsmasq (127.0.0.1)");
    } else {
        results.fail(&format!(
            "/etc/resolv.conf does NOT route to local dnsmasq (got: {})",
            python_repr(&resolv)
        ));
    }

    println!();
    println!("-- Egress Filtering --");
    if !exec(&["which", "curl"]).0 {
        results.warn(
            "curl not in cage image — cannot probe egress filtering (consider \
             installing curl in the user image to enable this check)",
        );
        return;
    }
    let (_, status) = exec(&[
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        "5",
        "https://evil-exfil-server.io",
    ]);
    if status == "403" {
        results.pass("Blocked domain (evil-exfil-server.io) is denied (HTTP 403 from mitmproxy)");
    } else if status.is_empty() || status == "000" {
        // Connection refused or timed out — the proxy or iptables
        // dropped it, which is also a pass, just less informative.
        results.pass("Blocked domain (evil-exfil-server.io) is denied (HTTP 000)");
    } else {
        results.fail(&format!(
            "Blocked domain returned HTTP {status} — egress filtering may be broken"
        ));
    }
}

/// `_verify_vm` — the Lima instance, then its units from inside.
///
/// The early return is the Python's: with the VM down, `systemctl`
/// inside it cannot be reached at all, and reporting two more failures
/// would say the services are broken when the truth is that nothing was
/// asked.
fn verify_vm(ctx: &Ctx, name: &str, results: &mut Results) {
    let instance = LimaInstance::new(ctx.runner.as_ref(), name);

    println!();
    println!("-- Lima VM --");
    if instance.is_running().unwrap_or(false) {
        results.pass("Lima VM instance is running");
    } else {
        results.fail("Lima VM instance is not running");
        return;
    }

    println!();
    println!("-- VM Services --");
    for service in SERVICE_NAMES {
        match instance.exec(
            &argv(&[
                "systemctl",
                "--user",
                "is-active",
                &format!("{name}-{service}.service"),
            ]),
            false,
        ) {
            Ok(out) if out.stdout_trimmed() == "active" => {
                results.pass(&format!("{service} service is active"));
            }
            Ok(out) => results.fail(&format!(
                "{service} service is not active ({})",
                out.stdout_trimmed()
            )),
            Err(error) => results.fail(&format!("Cannot check {service} service: {error}")),
        }
    }
}

/// `repr(s)` for a `str` — Python's own quoting, because the string
/// lands in an operator-facing message that the Python formats with
/// `{out!r}`.
///
/// Only the two escapes `repr` uses for the content this can carry: a
/// backslash and the quote character. A resolv.conf is ASCII, so the
/// non-printable branch of `repr` is not reachable here.
fn python_repr(text: &str) -> String {
    let escaped = text.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::{Results, python_repr, verify_apple_container, verify_vm};
    use crate::cli::context::Ctx;
    use agentcage_exec::{FakeRunner, Reply};
    use agentcage_state::{Paths, TestDir};

    /// A [`Ctx`] whose subprocesses are the fake's.
    ///
    /// `Ctx::runner` is a `Box<dyn CommandRunner>`, so the fake has to
    /// be handed over; `calls` are read back through the clone the
    /// caller keeps, which `FakeRunner` shares.
    fn ctx(dir: &TestDir, fake: FakeRunner) -> Ctx {
        Ctx {
            paths: Paths::under(dir.path()),
            runner: Box::new(fake),
            version: "9.9.9".to_owned(),
        }
    }

    /// `limactl shell … -- systemctl --user is-active <unit>`, once per
    /// service, and only after the instance answered "running".
    #[test]
    fn a_vm_cage_is_probed_through_limactl() {
        let dir = TestDir::new("verify-vm");
        let fake = FakeRunner::new();
        fake.assume_installed();
        // `limactl list --json <name>` — the readiness answer.
        fake.push(Reply::ok(r#"{"name": "acme", "status": "Running"}"#));
        fake.push(Reply::ok("active\n"));
        fake.push(Reply::ok("failed\n"));

        let mut results = Results::default();
        verify_vm(&ctx(&dir, fake.clone()), "acme", &mut results);

        assert_eq!((results.passed, results.failed), (2, 1));
        let calls = fake.argv_sequence();
        // The Lima instance is `agentcage-<cage>`; `LimaInstance::new`
        // owns that prefix, and reading it back here is what keeps the
        // probe pointed at the same VM the backend deploys.
        assert_eq!(calls[0], ["limactl", "list", "--json", "agentcage-acme"]);
        assert_eq!(
            calls[1],
            [
                "limactl",
                "shell",
                "--workdir",
                "/",
                "--tty=false",
                "agentcage-acme",
                "--",
                "systemctl",
                "--user",
                "is-active",
                "acme-cage.service"
            ]
        );
        assert_eq!(calls[2][10], "acme-egress.service");
    }

    /// A VM that is down is one failure and no further questions —
    /// `systemctl` inside it cannot be reached, and two more failures
    /// would report broken services where nothing was asked.
    #[test]
    fn a_stopped_vm_stops_the_probe() {
        let dir = TestDir::new("verify-vm-down");
        let fake = FakeRunner::new();
        fake.assume_installed();
        fake.push(Reply::ok(r#"{"name": "acme", "status": "Stopped"}"#));

        let mut results = Results::default();
        verify_vm(&ctx(&dir, fake.clone()), "acme", &mut results);

        assert_eq!((results.passed, results.failed), (0, 1));
        assert_eq!(fake.call_count(), 1, "nothing is asked of a stopped VM");
    }

    /// Without Apple's CLI there is nothing to ask, and that is a
    /// warning rather than a failure: the cage may be perfectly
    /// healthy on a host that simply has no `container` binary.
    #[test]
    fn a_missing_apple_cli_warns_once_and_probes_nothing() {
        let dir = TestDir::new("verify-apple-missing");
        let fake = FakeRunner::new();
        fake.assume_missing();

        let mut results = Results::default();
        verify_apple_container(&ctx(&dir, fake.clone()), "acme", &mut results);

        assert_eq!((results.passed, results.failed, results.warned), (0, 0, 1));
        assert_eq!(fake.call_count(), 0);
    }

    /// The three probes, in order, each as `container exec <name> …`.
    #[test]
    fn an_apple_cage_is_probed_through_container_exec() {
        let dir = TestDir::new("verify-apple");
        let fake = FakeRunner::new();
        fake.stub_which("container", "/usr/local/bin/container");
        // CA cert present, resolv.conf right, curl present, 403.
        fake.push(Reply::success());
        fake.push(Reply::ok("nameserver 127.0.0.1\n"));
        fake.push(Reply::success());
        fake.push(Reply::ok("403"));

        let mut results = Results::default();
        verify_apple_container(&ctx(&dir, fake.clone()), "acme", &mut results);

        assert_eq!((results.passed, results.failed, results.warned), (3, 0, 0));
        let calls = fake.argv_sequence();
        assert_eq!(
            calls[0],
            [
                "/usr/local/bin/container",
                "exec",
                "acme",
                "test",
                "-f",
                "/certs/mitmproxy-ca-cert.pem"
            ]
        );
        assert_eq!(calls[1][3..], ["cat", "/etc/resolv.conf"]);
        assert_eq!(calls[2][3..], ["which", "curl"]);
        assert_eq!(calls[3][3], "curl");
        assert_eq!(calls[3][calls[3].len() - 1], "https://evil-exfil-server.io");
    }

    /// A cage image with no `curl` cannot answer the egress question,
    /// and the Python says so rather than guessing.
    #[test]
    fn no_curl_in_the_image_is_a_warning_not_a_failure() {
        let dir = TestDir::new("verify-apple-nocurl");
        let fake = FakeRunner::new();
        fake.stub_which("container", "/usr/local/bin/container");
        fake.push(Reply::success());
        fake.push(Reply::ok("nameserver 127.0.0.1\n"));
        fake.push(Reply::status(1));

        let mut results = Results::default();
        verify_apple_container(&ctx(&dir, fake.clone()), "acme", &mut results);

        assert_eq!((results.passed, results.failed, results.warned), (2, 0, 1));
    }

    /// A connection that never completed is still a denial — the
    /// proxy or iptables dropped it — and reads as a pass.
    #[test]
    fn a_dropped_connection_counts_as_denied() {
        for status in ["000", ""] {
            let dir = TestDir::new("verify-apple-drop");
            let fake = FakeRunner::new();
            fake.stub_which("container", "/usr/local/bin/container");
            fake.push(Reply::success());
            fake.push(Reply::ok("nameserver 127.0.0.1\n"));
            fake.push(Reply::success());
            fake.push(Reply::ok(status));

            let mut results = Results::default();
            verify_apple_container(&ctx(&dir, fake.clone()), "acme", &mut results);
            assert_eq!(results.failed, 0, "status {status:?}");
            assert_eq!(results.passed, 3, "status {status:?}");
        }
    }

    /// A 200 from a domain no cage allows means the filter is not
    /// filtering, and that is the one outcome that has to fail.
    #[test]
    fn a_reachable_blocked_domain_fails() {
        let dir = TestDir::new("verify-apple-open");
        let fake = FakeRunner::new();
        fake.stub_which("container", "/usr/local/bin/container");
        fake.push(Reply::success());
        fake.push(Reply::ok("nameserver 127.0.0.1\n"));
        fake.push(Reply::success());
        fake.push(Reply::ok("200"));

        let mut results = Results::default();
        verify_apple_container(&ctx(&dir, fake.clone()), "acme", &mut results);
        assert_eq!((results.passed, results.failed), (2, 1));
    }

    /// The message quotes what it read, the way `{out!r}` does.
    #[test]
    fn the_resolv_conf_failure_quotes_python_style() {
        assert_eq!(python_repr("nameserver 1.1.1.1"), "'nameserver 1.1.1.1'");
        assert_eq!(python_repr("it's"), r"'it\'s'");
        assert_eq!(python_repr(""), "''");
    }
}
