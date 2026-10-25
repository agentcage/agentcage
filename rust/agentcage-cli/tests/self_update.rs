//! `agentcage update`, end to end against a [`FakeRunner`]: every
//! `curl` and the new binary's `--version` are stubbed, and the files
//! the real runner would write come from the stubs' stdout.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use agentcage_cli::archive::{self, Member};
use agentcage_cli::self_update::{Outcome, Request, Version, managed_install, release_target, run};
use agentcage_exec::{FakeRunner, Reply};
use agentcage_state::TestDir;

const OLD: &[u8] = b"old agentcage";
const NEW: &[u8] = b"new agentcage";

fn v(text: &str) -> Version {
    Version::parse(text).expect("a version")
}

/// An installed `agentcage` holding [`OLD`].
fn installed(dir: &TestDir) -> PathBuf {
    let exe = dir.path().join("bin/agentcage");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, OLD).unwrap();
    exe
}

/// The release tarball for `version`, as the release workflow lays it
/// out, holding `binary`.
fn release_tarball(dir: &TestDir, version: &str, target: &str, binary: &[u8]) -> Vec<u8> {
    let stage = format!("agentcage-{version}-{target}");
    let path = dir.path().join("fixture.tar.gz");
    archive::write_targz(
        &path,
        &[
            Member::Dir(stage.clone()),
            Member::File(format!("{stage}/agentcage"), binary.to_vec()),
        ],
    )
    .unwrap();
    std::fs::read(path).unwrap()
}

fn latest_reply(version: &str) -> Reply {
    Reply::ok(format!(
        "https://github.com/agentcage/agentcage/releases/tag/v{version}"
    ))
}

fn checksum_reply(tarball: &[u8], target: &str, version: &str) -> Reply {
    Reply::ok(format!(
        "{}  agentcage-{version}-{target}.tar.gz\n",
        agentcage_core::fingerprint::sha256_hex(tarball)
    ))
}

fn request(exe: &Path, version: Option<Version>, check: bool) -> Request<'_> {
    Request {
        repo: "agentcage/agentcage",
        version,
        check,
        exe,
        current: v("0.53.1"),
    }
}

fn no_stray_new_file(exe: &Path) {
    assert!(
        !exe.with_file_name(".agentcage.new").exists(),
        "the staged binary was left behind"
    );
}

#[test]
fn versions_parse_strictly() {
    assert_eq!(Version::parse("0.53.1"), Some(v("v0.53.1")));
    assert_eq!(v("0.53.1").to_string(), "0.53.1");
    assert!(v("0.53.10") > v("0.53.9"));
    assert!(v("1.0.0") > v("0.99.99"));
    for not_a_version in [
        "my-agent",
        "0.53",
        "0.53.1.2",
        "0.53.x",
        "",
        "v",
        "0.53.1-rc1",
        "1..2",
    ] {
        assert_eq!(Version::parse(not_a_version), None, "{not_a_version:?}");
    }
}

/// The latest release is downloaded, checked and swapped in, in that
/// order, and the argv is the whole contract with GitHub.
#[test]
fn an_update_replaces_the_binary_with_the_latest_release() {
    let Some(target) = release_target() else {
        return;
    };
    let dir = TestDir::new("self-update");
    let exe = installed(&dir);
    let tarball = release_tarball(&dir, "0.54.0", target, NEW);
    let fake = FakeRunner::new();
    fake.push(latest_reply("0.54.0"));
    fake.push(Reply::ok(tarball.clone()));
    fake.push(checksum_reply(&tarball, target, "0.54.0"));
    fake.push(Reply::ok("agentcage, version 0.54.0\n"));

    let outcome = run(&fake, &request(&exe, None, false)).expect("updates");

    assert_eq!(
        outcome,
        Outcome::Updated {
            from: v("0.53.1"),
            to: v("0.54.0")
        }
    );
    assert_eq!(std::fs::read(&exe).unwrap(), NEW);
    assert_eq!(
        std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
        0o755
    );
    no_stray_new_file(&exe);

    let base = "https://github.com/agentcage/agentcage/releases/download/v0.54.0";
    let staged = exe.with_file_name(".agentcage.new").display().to_string();
    let tar = format!("{base}/agentcage-0.54.0-{target}.tar.gz");
    let sha = format!("{tar}.sha256");
    fake.assert_argv(&[
        &[
            "curl",
            "--proto",
            "=https",
            "--tlsv1.2",
            "-fsSLI",
            "-o",
            "/dev/null",
            "-w",
            "%{url_effective}",
            "https://github.com/agentcage/agentcage/releases/latest",
        ],
        &["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", &tar],
        &["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", &sha],
        &[&staged, "--version"],
    ]);
}

/// A named release skips the lookup, and may be older: that is how a
/// bad release is rolled back.
#[test]
fn a_named_release_is_installed_even_when_older() {
    let Some(target) = release_target() else {
        return;
    };
    let dir = TestDir::new("self-update-pinned");
    let exe = installed(&dir);
    let tarball = release_tarball(&dir, "0.52.3", target, NEW);
    let fake = FakeRunner::new();
    fake.push(Reply::ok(tarball.clone()));
    fake.push(checksum_reply(&tarball, target, "0.52.3"));
    fake.push(Reply::ok("agentcage, version 0.52.3\n"));

    let outcome = run(&fake, &request(&exe, Some(v("0.52.3")), false)).expect("installs");

    assert_eq!(
        outcome,
        Outcome::Updated {
            from: v("0.53.1"),
            to: v("0.52.3")
        }
    );
    assert_eq!(std::fs::read(&exe).unwrap(), NEW);
    assert_eq!(fake.call_count(), 3, "{:?}", fake.argv_sequence());
}

#[test]
fn a_bad_checksum_installs_nothing() {
    let Some(target) = release_target() else {
        return;
    };
    let dir = TestDir::new("self-update-checksum");
    let exe = installed(&dir);
    let tarball = release_tarball(&dir, "0.54.0", target, NEW);
    let fake = FakeRunner::new();
    fake.push(latest_reply("0.54.0"));
    fake.push(Reply::ok(tarball));
    fake.push(Reply::ok(format!("{}  x.tar.gz\n", "0".repeat(64))));

    let error = run(&fake, &request(&exe, None, false)).expect_err("refuses");

    assert!(error.contains("checksum mismatch"), "{error}");
    assert_eq!(std::fs::read(&exe).unwrap(), OLD);
    no_stray_new_file(&exe);
    assert_eq!(fake.call_count(), 3, "the new binary was run");
}

/// A binary that does not call itself the release it was downloaded
/// as — the wrong tarball, or one built from the wrong commit — never
/// replaces the old one.
#[test]
fn a_binary_reporting_another_version_installs_nothing() {
    let Some(target) = release_target() else {
        return;
    };
    let dir = TestDir::new("self-update-wrong-version");
    let exe = installed(&dir);
    let tarball = release_tarball(&dir, "0.54.0", target, NEW);
    let fake = FakeRunner::new();
    fake.push(latest_reply("0.54.0"));
    fake.push(Reply::ok(tarball.clone()));
    fake.push(checksum_reply(&tarball, target, "0.54.0"));
    fake.push(Reply::ok("agentcage, version 0.53.1\n"));

    let error = run(&fake, &request(&exe, None, false)).expect_err("refuses");

    assert!(error.contains("refusing to install"), "{error}");
    assert_eq!(std::fs::read(&exe).unwrap(), OLD);
    no_stray_new_file(&exe);
}

#[test]
fn a_binary_that_does_not_run_installs_nothing() {
    let Some(target) = release_target() else {
        return;
    };
    let dir = TestDir::new("self-update-no-run");
    let exe = installed(&dir);
    let tarball = release_tarball(&dir, "0.54.0", target, NEW);
    let fake = FakeRunner::new();
    fake.push(latest_reply("0.54.0"));
    fake.push(Reply::ok(tarball.clone()));
    fake.push(checksum_reply(&tarball, target, "0.54.0"));
    fake.push(Reply::failed(126, "exec format error"));

    let error = run(&fake, &request(&exe, None, false)).expect_err("refuses");

    assert!(error.contains("does not run"), "{error}");
    assert_eq!(std::fs::read(&exe).unwrap(), OLD);
    no_stray_new_file(&exe);
}

#[test]
fn a_tarball_without_the_binary_installs_nothing() {
    let Some(target) = release_target() else {
        return;
    };
    let dir = TestDir::new("self-update-empty-tarball");
    let exe = installed(&dir);
    let path = dir.path().join("empty.tar.gz");
    archive::write_targz(&path, &[Member::Dir("something-else".into())]).unwrap();
    let tarball = std::fs::read(&path).unwrap();
    let fake = FakeRunner::new();
    fake.push(latest_reply("0.54.0"));
    fake.push(Reply::ok(tarball.clone()));
    fake.push(checksum_reply(&tarball, target, "0.54.0"));

    let error = run(&fake, &request(&exe, None, false)).expect_err("refuses");

    assert!(error.contains("has no"), "{error}");
    assert_eq!(std::fs::read(&exe).unwrap(), OLD);
}

#[test]
fn a_failed_download_installs_nothing() {
    if release_target().is_none() {
        return;
    }
    let dir = TestDir::new("self-update-404");
    let exe = installed(&dir);
    let fake = FakeRunner::new();
    fake.push(latest_reply("0.54.0"));
    fake.push(Reply::failed(
        22,
        "curl: (22) The requested URL returned error: 404",
    ));

    let error = run(&fake, &request(&exe, None, false)).expect_err("refuses");

    assert!(error.contains("could not download"), "{error}");
    assert_eq!(std::fs::read(&exe).unwrap(), OLD);
}

/// Up to date, `--check`, and a build newer than the latest release all
/// stop after the one lookup.
#[test]
fn nothing_is_downloaded_unless_an_update_is_installed() {
    let dir = TestDir::new("self-update-noop");
    let exe = installed(&dir);
    for (latest, check, expected) in [
        ("0.53.1", false, Outcome::UpToDate(v("0.53.1"))),
        (
            "0.54.0",
            true,
            Outcome::Available {
                from: v("0.53.1"),
                to: v("0.54.0"),
            },
        ),
        (
            "0.53.0",
            false,
            Outcome::AheadOfLatest {
                current: v("0.53.1"),
                latest: v("0.53.0"),
            },
        ),
    ] {
        if release_target().is_none() {
            return;
        }
        let fake = FakeRunner::new();
        fake.push(latest_reply(latest));
        assert_eq!(
            run(&fake, &request(&exe, None, check)).expect("answers"),
            expected
        );
        assert_eq!(fake.call_count(), 1, "{latest} {check}");
        assert_eq!(std::fs::read(&exe).unwrap(), OLD);
    }
}

#[test]
fn an_unreadable_latest_redirect_is_an_error() {
    if release_target().is_none() {
        return;
    }
    let dir = TestDir::new("self-update-bad-redirect");
    let exe = installed(&dir);
    let fake = FakeRunner::new();
    fake.push(Reply::ok("https://github.com/agentcage/agentcage/releases"));

    let error = run(&fake, &request(&exe, None, false)).expect_err("refuses");

    assert!(
        error.contains("could not read the latest release"),
        "{error}"
    );
}

/// A package manager's binary is refused before anything is
/// downloaded, with the command that upgrades it instead.
#[test]
fn a_managed_install_is_refused() {
    for (path, hint) in [
        (
            "/opt/homebrew/Cellar/agentcage/0.53.1/bin/agentcage",
            "brew upgrade",
        ),
        (
            "/usr/local/Cellar/agentcage/0.53.1/bin/agentcage",
            "brew upgrade",
        ),
        ("/home/linuxbrew/.linuxbrew/bin/agentcage", "brew upgrade"),
        ("/usr/bin/agentcage", "package manager"),
    ] {
        let refusal = managed_install(Path::new(path)).unwrap_or_else(|| panic!("{path}"));
        assert!(refusal.contains(hint), "{path}: {refusal}");
    }
    // A cargo target directory under any name, found by the
    // `.rustc_info.json` cargo writes at its root.
    let dir = TestDir::new("self-update-cargo-target");
    let target_dir = dir.path().join("my-target-dir");
    std::fs::create_dir_all(target_dir.join("release")).unwrap();
    std::fs::create_dir_all(target_dir.join("x86_64-unknown-linux-musl/release")).unwrap();
    std::fs::write(target_dir.join(".rustc_info.json"), "{}").unwrap();
    for exe in [
        target_dir.join("release/agentcage"),
        target_dir.join("x86_64-unknown-linux-musl/release/agentcage"),
    ] {
        let refusal = managed_install(&exe).unwrap_or_else(|| panic!("{}", exe.display()));
        assert!(refusal.contains("cargo build"), "{refusal}");
    }
    assert_eq!(managed_install(&installed(&dir)), None);

    for path in [
        "/home/me/.local/bin/agentcage",
        "/usr/local/bin/agentcage",
        "/home/me/.cargo/bin/agentcage",
    ] {
        assert_eq!(managed_install(Path::new(path)), None, "{path}");
    }

    if release_target().is_none() {
        return;
    }
    let fake = FakeRunner::new();
    let error = run(
        &fake,
        &request(Path::new("/usr/bin/agentcage"), None, false),
    )
    .expect_err("refuses");
    assert!(error.contains("package manager"), "{error}");
    assert_eq!(fake.call_count(), 0, "the network was asked anyway");

    // `--check` only reports, so it still answers for a managed binary.
    fake.push(latest_reply("0.54.0"));
    assert_eq!(
        run(&fake, &request(Path::new("/usr/bin/agentcage"), None, true)).expect("answers"),
        Outcome::Available {
            from: v("0.53.1"),
            to: v("0.54.0")
        }
    );
}
