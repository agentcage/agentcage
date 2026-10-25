//! `agentcage update`: replace this binary with a released one.
//!
//! The same steps `install.sh` takes for a prebuilt install, from the
//! binary itself:
//!
//! 1. **Resolve the release.** The one asked for, or the latest, read
//!    from the redirect on `/releases/latest` rather than the JSON API,
//!    which is rate-limited per IP.
//! 2. **Download** `agentcage-<version>-<target>.tar.gz` and its
//!    `.sha256` with `curl`, the tarball streamed straight to a file.
//! 3. **Verify** the sha256. It sits on the same release page as the
//!    tarball, so it guards against a corrupt or truncated download,
//!    not against a compromised release — the same guarantee
//!    `install.sh` gives, and it says so too.
//! 4. **Check the new binary runs** and reports the version it was
//!    downloaded as, before it goes anywhere near the old one.
//! 5. **Install by rename** next to the running binary, so the path is
//!    never a half-written file: the rename is atomic within one
//!    filesystem, which is why the new file is written in the same
//!    directory rather than in `$TMPDIR`.
//!
//! # What it refuses
//!
//! A binary a package manager owns is not this command's to replace:
//! Homebrew and pacman would each go on believing they installed the
//! old version, and the next `brew upgrade` or `pacman -Syu` would
//! quietly put it back. A binary inside a cargo `target/` directory is
//! a build, not an install. Each refusal names the command that does
//! the job instead ([`managed_install`](crate::self_update::managed_install)).
//!
//! Everything runs through [`CommandRunner`](agentcage_exec::CommandRunner), so the whole sequence is
//! tested against a [`agentcage_exec::FakeRunner`] with no network.

use std::fmt;
use std::path::{Path, PathBuf};

use agentcage_exec::{Command, CommandRunner, ExecError, Sink};

/// Where releases come from, unless `AGENTCAGE_REPO` says otherwise —
/// the variable `install.sh` reads too.
pub const DEFAULT_REPO: &str = "agentcage/agentcage";

/// The release target this binary was built for, as the release assets
/// name it: `agentcage-<version>-<target>.tar.gz`.
///
/// `None` on a platform the release workflow does not build for, where
/// there is nothing to download.
#[must_use]
pub const fn release_target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-musl")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-musl")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else {
        None
    }
}

/// A release version: `MAJOR.MINOR.PATCH`, compared numerically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    /// `0.53.1` or `v0.53.1`. Nothing else: releases carry no
    /// pre-release or build suffix, and a string that is not a version
    /// is how `update` tells a cage name apart from one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.strip_prefix('v').unwrap_or(text);
        let mut parts = text.split('.');
        let mut next = || -> Option<u64> {
            let part = parts.next()?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let version = Self(next()?, next()?, next()?);
        parts.next().is_none().then_some(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// What `agentcage update` was asked to do.
#[derive(Debug)]
pub struct Request<'a> {
    /// `owner/name` on github.com.
    pub repo: &'a str,
    /// A specific release, or `None` for the latest.
    pub version: Option<Version>,
    /// Report only; download and install nothing.
    pub check: bool,
    /// The binary to replace: the running one, resolved.
    pub exe: &'a Path,
    /// The version this binary reports.
    pub current: Version,
}

/// How a request ended, for the caller to report.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Already on the requested (or latest) version.
    UpToDate(Version),
    /// `--check`: a different version is available.
    Available {
        /// The installed version.
        from: Version,
        /// The one that would be installed.
        to: Version,
    },
    /// This binary is newer than the latest release (a build from
    /// master, or a release not yet published), so nothing was done.
    AheadOfLatest {
        /// The installed version.
        current: Version,
        /// The latest release.
        latest: Version,
    },
    /// The binary was replaced.
    Updated {
        /// The version that was replaced.
        from: Version,
        /// The version now installed.
        to: Version,
    },
}

/// Run a request to completion.
///
/// # Errors
///
/// A message for the operator: an unsupported platform, a managed
/// install, a network or checksum failure, or a binary that would not
/// run. Nothing is replaced on any error.
pub fn run(runner: &dyn CommandRunner, request: &Request<'_>) -> Result<Outcome, String> {
    let Some(target) = release_target() else {
        return Err(format!(
            "there is no prebuilt agentcage for this platform ({} {}); \
             build it from source with install.sh --build",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
    };

    // Before the network: a binary this command cannot replace gets the
    // command that can, not a lookup it has no use for. `--check` only
    // reports, so it still answers.
    if !request.check
        && let Some(refusal) = managed_install(request.exe)
    {
        return Err(refusal);
    }

    let wanted = match request.version {
        Some(version) => version,
        None => latest(runner, request.repo)?,
    };
    if wanted == request.current {
        return Ok(Outcome::UpToDate(wanted));
    }
    if request.version.is_none() && wanted < request.current {
        return Ok(Outcome::AheadOfLatest {
            current: request.current,
            latest: wanted,
        });
    }
    if request.check {
        return Ok(Outcome::Available {
            from: request.current,
            to: wanted,
        });
    }

    let dir = request
        .exe
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", request.exe.display()))?;

    let staging = crate::scaffold::TempDir::new("agentcage-update-")
        .map_err(|error| format!("could not create a staging directory: {error}"))?;
    let stage = format!("agentcage-{wanted}-{target}");
    let base = format!(
        "https://github.com/{}/releases/download/v{wanted}",
        request.repo
    );
    let tarball = staging.path().join(format!("{stage}.tar.gz"));
    let checksum = staging.path().join(format!("{stage}.tar.gz.sha256"));
    println!("Downloading {stage}.tar.gz...");
    download(runner, &format!("{base}/{stage}.tar.gz"), &tarball)?;
    download(runner, &format!("{base}/{stage}.tar.gz.sha256"), &checksum)?;
    verify(&tarball, &checksum)?;

    let binary = crate::archive::read_member(&tarball, &format!("{stage}/agentcage"))
        .map_err(|error| format!("could not read {stage}.tar.gz: {error}"))?
        .ok_or_else(|| format!("{stage}.tar.gz has no {stage}/agentcage"))?;

    // In the target's directory, so the final rename cannot cross a
    // filesystem. The leading dot keeps it out of a `ls` and out of
    // `PATH` lookups that glob.
    let new = dir.join(".agentcage.new");
    write_executable(&new, &binary).map_err(|error| {
        let _ = std::fs::remove_file(&new);
        format!(
            "could not write {}: {error}. Is {} writable? Re-run with the permissions \
             that installed it, or reinstall with install.sh",
            new.display(),
            dir.display()
        )
    })?;
    if let Err(error) = check_runs(runner, &new, wanted) {
        let _ = std::fs::remove_file(&new);
        return Err(error);
    }
    std::fs::rename(&new, request.exe).map_err(|error| {
        let _ = std::fs::remove_file(&new);
        format!("could not replace {}: {error}", request.exe.display())
    })?;
    Ok(Outcome::Updated {
        from: request.current,
        to: wanted,
    })
}

/// The latest release's version, from where `/releases/latest`
/// redirects to (`…/releases/tag/v0.53.1`).
fn latest(runner: &dyn CommandRunner, repo: &str) -> Result<Version, String> {
    let url = format!("https://github.com/{repo}/releases/latest");
    let out = runner
        .run(
            &Command::new("curl")
                .args([
                    "--proto",
                    "=https",
                    "--tlsv1.2",
                    "-fsSLI",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{url_effective}",
                    &url,
                ])
                .captured(),
        )
        .and_then(|out| out.check("curl"))
        .map_err(|error| unreachable_github(&error))?;
    let location = out.stdout_trimmed();
    location
        .rsplit_once("/tag/")
        .and_then(|(_, tag)| Version::parse(tag))
        .ok_or_else(|| format!("could not read the latest release from {location:?}"))
}

/// `curl` the URL to `path`, stdout straight to the file.
fn download(runner: &dyn CommandRunner, url: &str, path: &Path) -> Result<(), String> {
    runner
        .run(
            &Command::new("curl")
                .args(["--proto", "=https", "--tlsv1.2", "-fsSL", url])
                .stdout(Sink::Write(path.to_path_buf()))
                .stderr(Sink::Capture),
        )
        .and_then(|out| out.check("curl"))
        .map(drop)
        .map_err(|error| format!("could not download {url}: {error}"))
}

fn unreachable_github(error: &ExecError) -> String {
    if error.is_not_found() {
        "agentcage update needs curl, which is not installed".to_owned()
    } else {
        format!("could not reach github.com to resolve the latest release: {error}")
    }
}

/// The tarball's sha256 against the first field of its `.sha256`.
fn verify(tarball: &Path, checksum: &Path) -> Result<(), String> {
    let name = tarball
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let expected = std::fs::read_to_string(checksum)
        .map_err(|error| format!("could not read the checksum for {name}: {error}"))?;
    let expected = expected.split_whitespace().next().unwrap_or_default();
    let data = std::fs::read(tarball).map_err(|error| format!("could not read {name}: {error}"))?;
    let actual = agentcage_core::fingerprint::sha256_hex(&data);
    if expected.is_empty() || !expected.eq_ignore_ascii_case(&actual) {
        return Err(format!(
            "checksum mismatch for {name} (expected '{expected}', got '{actual}'); \
             refusing to install"
        ));
    }
    Ok(())
}

fn write_executable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, data)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

/// The new binary has to run here and call itself `wanted`. A binary
/// for the wrong architecture, or a tarball with the wrong thing in it,
/// stops here with the old one untouched.
fn check_runs(runner: &dyn CommandRunner, binary: &Path, wanted: Version) -> Result<(), String> {
    let expected = format!("agentcage, version {wanted}");
    let out = runner
        .run(
            &Command::new(binary.display().to_string())
                .arg("--version")
                .captured(),
        )
        .and_then(|out| out.check("agentcage"))
        .map_err(|error| format!("the downloaded agentcage does not run: {error}"))?;
    let reported = out.stdout_trimmed();
    if reported == expected {
        Ok(())
    } else {
        Err(format!(
            "the downloaded agentcage reports {reported:?}, not {expected:?}; \
             refusing to install it"
        ))
    }
}

/// Why `exe` is not this command's to replace, if it is not.
///
/// Decided on the resolved path, so Homebrew's `bin/agentcage` symlink
/// is seen as the `Cellar` file it points at. The cargo-build check
/// looks at the filesystem around `exe`; the rest is the path alone.
#[must_use]
pub fn managed_install(exe: &Path) -> Option<String> {
    let path = exe.to_string_lossy();
    let homebrew = path.contains("/Cellar/")
        || path.starts_with("/opt/homebrew/")
        || path.starts_with("/home/linuxbrew/");
    if homebrew {
        return Some(format!(
            "{} is managed by Homebrew; upgrade it with: brew upgrade agentcage",
            exe.display()
        ));
    }
    let system = ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"]
        .iter()
        .any(|prefix| path.starts_with(prefix));
    if system {
        return Some(format!(
            "{} is managed by your system package manager; upgrade it there \
             (on Arch: paru -Syu agentcage-bin)",
            exe.display()
        ));
    }
    // A cargo target directory, whatever it is called
    // (`CARGO_TARGET_DIR` need not be `target`): cargo writes
    // `.rustc_info.json` at its root, and the binary sits one level
    // down (`release/`) or two (`<triple>/release/`).
    let build = exe
        .ancestors()
        .skip(2)
        .take(2)
        .any(|dir| dir.join(".rustc_info.json").is_file());
    if build {
        return Some(format!(
            "{} is a cargo build, not an install; rebuild it, or install a release \
             with install.sh",
            exe.display()
        ));
    }
    None
}

/// The running binary, symlinks resolved.
///
/// # Errors
///
/// When the OS cannot say where it is.
pub fn current_exe() -> std::io::Result<PathBuf> {
    std::fs::canonicalize(std::env::current_exe()?)
}
