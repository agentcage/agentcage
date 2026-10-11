//! The nested-virt skip guard in `tests/e2e/phase_apple.sh`.
//!
//! GitHub's hosted `macos-26` runner is itself a VM, so Apple's
//! Virtualization.framework refuses to boot nested VMs with
//! `VZErrorDomain Code=2 "Virtualization is not available on this
//! hardware."` (issue #215). Rather than erroring mid-run, the phase
//! probes for nested virt and SKIPS (exit 0, clear reason) on a
//! no-nested-virt host, while still running the real e2e when nested
//! virt IS available.
//!
//! These tests run the script under a temp `PATH` of fake `uname` /
//! `container` / `sysctl` / `security` / `podman` / `agentcage` shims and
//! a sandboxed `HOME`, so the macOS-only guards can be exercised from any
//! CI without the phase reaching anything real. The "still runs the real
//! e2e when nested virt IS available" path is not asserted here: it is
//! documented in the phase header and verified manually on bare-metal
//! Apple Silicon.
//!
//! "Not asserted" does not mean inert: the force-override case below
//! still ENTERS that path, and on a Mac it would create a cage and write
//! to the login keychain. The shims and the sandbox are what keep it
//! contained on every host, not just on Linux CI.

mod common;

use std::fs;
use std::time::Duration;

use common::{Run, TempDir, e2e_dir, run_bash, write_shim};

fn run_phase(env: &[(&str, &str)]) -> Run {
    let tmp = TempDir::new("apple");
    let bindir = tmp.path().join("fakebin");
    fs::create_dir(&bindir).unwrap();
    // `uname` reports Darwin so the phase passes its macOS guard.
    write_shim(&bindir, "uname", "echo Darwin");
    // `container` is present so the phase passes the CLI-installed guard.
    write_shim(&bindir, "container", "exit 0");
    // `sysctl` for kern.hv.supported: 0, i.e. no hypervisor.
    write_shim(&bindir, "sysctl", "echo 0");
    // `security` so the macOS keychain is never reached: the apple
    // backend's secret store is the login keychain, which no HOME
    // sandbox can contain.
    write_shim(&bindir, "security", "exit 0");
    // The phase's own cleanup calls podman (stop_mock); the CLI under test
    // is a stub that refuses everything, so the force-override path stops
    // at its first `cage create`.
    write_shim(&bindir, "podman", "exit 0");
    let agentcage = write_shim(&bindir, "agentcage", "exit 1");
    // A sandboxed HOME and XDG dirs: the force-override case reaches the
    // phase body, which drives the CLI against $HOME/.config/agentcage/.
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".config")).unwrap();
    fs::create_dir_all(home.join(".local/share")).unwrap();
    let mut vars: Vec<(&str, String)> = vec![
        ("HOME", home.display().to_string()),
        (
            "XDG_CONFIG_HOME",
            home.join(".config").display().to_string(),
        ),
        (
            "XDG_DATA_HOME",
            home.join(".local/share").display().to_string(),
        ),
        ("AGENTCAGE", agentcage.display().to_string()),
        // An inherited CI marker must not decide the outcome.
        ("ImageOS", String::new()),
        ("AGENTCAGE_APPLE_E2E_FORCE", String::new()),
    ];
    for (k, v) in env {
        vars.push((k, (*v).to_owned()));
    }
    let phase = e2e_dir().join("phase_apple.sh");
    run_bash(
        &[phase.to_str().unwrap()],
        &bindir,
        &vars,
        Duration::from_secs(30),
    )
}

#[test]
fn skips_on_github_hosted_macos_runner() {
    // ImageOS=macos* means a hosted VM: no nested virt, SKIP, exit 0.
    let r = run_phase(&[("ImageOS", "macos26")]);
    assert_eq!(r.code, 0, "{}", r.both());
    for want in [
        "SKIP",
        "nested virtualization unavailable",
        "ImageOS=macos26",
        "#215",
    ] {
        assert!(r.stdout.contains(want), "missing {want:?}\n{}", r.both());
    }
}

#[test]
fn skips_when_kern_hv_supported_is_zero() {
    // ImageOS unset, so only the sysctl probe fires.
    let r = run_phase(&[]);
    assert_eq!(r.code, 0, "{}", r.both());
    for want in [
        "SKIP",
        "nested virtualization unavailable",
        "kern.hv.supported=0",
        "#215",
    ] {
        assert!(r.stdout.contains(want), "missing {want:?}\n{}", r.both());
    }
}

#[test]
fn force_override_bypasses_probe() {
    // With nested virt nominally unavailable, AGENTCAGE_APPLE_E2E_FORCE=1
    // must NOT take the skip. The phase then fails at the stubbed CLI;
    // only the absence of the skip is the point.
    let r = run_phase(&[("ImageOS", "macos26"), ("AGENTCAGE_APPLE_E2E_FORCE", "1")]);
    assert!(
        !r.stdout.contains("nested virtualization unavailable"),
        "{}",
        r.both()
    );
    assert!(
        !r.stderr.contains("nested virtualization unavailable"),
        "{}",
        r.both()
    );
}

#[test]
fn guard_logic_present_in_script() {
    let text = fs::read_to_string(e2e_dir().join("phase_apple.sh")).unwrap();
    for want in [
        "AGENTCAGE_APPLE_E2E_FORCE",
        "ImageOS",
        "kern.hv.supported",
        "#215",
        "nested virtualization unavailable",
    ] {
        assert!(text.contains(want), "missing {want:?}");
    }
}
