//! `cage verify` — the health probe.
//!
//! `cli.py:1494` plus `_verify_container`. Only the container backend's
//! probes are here; `_verify_vm` and `_verify_apple_container` are
//! Track E's, and the dispatch below says so rather than silently
//! reporting a vm cage as healthy.

use std::process::ExitCode;

use agentcage_exec::tools::podman::Podman;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};

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

    let backend = ctx.backend();
    let mut results = Results::default();

    println!("=== agentcage verify: {name} ({}) ===", config.isolation);
    println!();

    println!("-- Services --");
    for (service, running) in crate::cli::cage::lifecycle::service_status(&backend, name) {
        if running {
            results.pass(&format!("{name}-{service} is running"));
        } else {
            results.fail(&format!("{name}-{service} is NOT running"));
        }
    }

    if config.isolation == "container" {
        verify_container(ctx, name, &config, &mut results);
    } else {
        results.warn(&format!(
            "the '{}' backend's probes are not ported yet (RUST-PORT-PLAN.md Track E)",
            config.isolation
        ));
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
