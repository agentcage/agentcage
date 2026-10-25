//! `agentcage doctor`.
//!
//! # What this is
//!
//! Fourteen questions of the form "is this installed, and does it work",
//! grouped into four sections, each answered with a mark, a message and
//! an optional hint. It is the first thing an operator runs when a cage
//! will not start, so its value is entirely in whether it says the right
//! thing on a host that is broken in a particular way.
//!
//! # Why it is written against two traits
//!
//! That last sentence is also the testing problem: the output is a
//! function of the machine. Recording what the doctor prints on the CI
//! runner would pin the runner, not the code, and the interesting hosts
//! — no podman, no systemd, an unusable `systemd-creds`, a Mac — are
//! precisely the ones CI is not.
//!
//! So nothing here touches the world directly. Subprocesses go through
//! [`CommandRunner`](agentcage_exec::CommandRunner), which is why [`CommandRunner::which`](agentcage_exec::CommandRunner::which) is on the
//! trait at all (PR D1's docs make the same argument), and everything
//! else — `/etc/os-release`, the cgroup marker, free disk, DNS, a TCP
//! bind, `$USER`, the euid, macOS-ness and the apple-container
//! prerequisites — goes through [`DoctorHost`](crate::doctor::DoctorHost). A faked pair of those
//! reproduces any host exactly, which is what
//! `tests/golden_doctor.rs` does for 38 of them against output
//! recorded from an earlier release.
//!
//! # The recorded output has one line this does not print
//!
//! Earlier releases needed a Python interpreter on the host and checked
//! for one, so every recorded case carries a passing interpreter-version
//! line under "Prerequisites". The host has no such dependency any more,
//! so that check is gone and the golden test drops the line before
//! comparing. Nothing depended on its result: the exit code counts
//! `error`s, and the line was always a `pass`. The fixture proves that
//! rather than asserting it — no recorded case has summary counts that
//! dropping the line would move.
//!
//! # Faithfulness, and the two places it stops
//!
//! Everything else matches the recorded output as-is, including
//! behaviour that is arguably wrong (see
//! `tests/fixtures/doctor/README.md`). The two exceptions are
//! structural:
//!
//! * Earlier releases caught any exception a check raised and reported
//!   it as a warning. The functions here are total — every path returns
//!   a [`CheckResult`](crate::doctor::CheckResult) — so there is nothing to catch. Two fixture cases
//!   record a check raising; both are marked unported, and the golden
//!   test asserts that the unported set is exactly those two.
//! * A probe that is not installed or times out reads as a failed
//!   probe, as it always has. [`ExecError`](agentcage_exec::ExecError)'s other variants (spawn
//!   failures, I/O errors) take the same branch here, because the
//!   alternative is a diagnostic tool that crashes while diagnosing.
//!
//! # `--json` is the same run, not a second one
//!
//! `Report::to_json` renders the checks `run` already produced, so
//! the human report and the JSON document cannot disagree about what a
//! host answered: both are views of one `Report`. Every check is a
//! flat entry carrying its `section`, its `name` (the message it
//! prints), its `level` and its `hint`, under a stable
//! `JSON_SCHEMA_VERSION`. The exit code is the same in both modes.

use std::fmt;
use std::time::Duration;

use agentcage_core::har::json::{self, DumpOptions, Json};
use agentcage_exec::tools::creds::Scope;
use agentcage_exec::tools::systemctl::Systemctl;
use agentcage_exec::{Command, CommandRunner};

use crate::secrets::resolver::{Backend, SecretHost, SystemEnv};

// ── the world outside the subprocess seam ────────────────────

/// What the doctor reads that is not a subprocess.
///
/// One method per thing the doctor reads directly. They are
/// gathered into a trait rather than called inline for the reason in the
/// module docs: the host is the input, so it has to be substitutable.
pub trait DoctorHost: fmt::Debug {
    /// `sys.platform == "darwin"`, i.e. `doctor._IS_MACOS`.
    fn is_macos(&self) -> bool;

    /// `platform.machine()`, i.e. `doctor._host_machine()`: which QEMU
    /// system emulator `check_qemu` probes and which package it names.
    fn machine(&self) -> String;

    /// `Path("/etc/os-release").read_text()`, or `None` if it raised.
    fn os_release(&self) -> Option<String>;

    /// `Path(p).exists()`.
    ///
    /// # Errors
    ///
    /// The `except OSError` branch of `check_cgroup_v2`, carrying the
    /// message that check prints. See
    /// [`SystemDoctorHost::path_exists`] for why a real host never
    /// takes it.
    fn path_exists(&self, path: &str) -> Result<bool, String>;

    /// `shutil.disk_usage(os.path.expanduser("~")).free`.
    ///
    /// # Errors
    ///
    /// The `except OSError` branch, carrying the exception's message,
    /// which `check_disk_space` prints verbatim.
    fn disk_free_bytes(&self) -> Result<u64, String>;

    /// `socket.getaddrinfo("example.com", 80)`, reduced to its outcome.
    fn resolve_dns(&self) -> DnsOutcome;

    /// Whether a `bind(("127.0.0.1", port))` would succeed.
    fn port_is_free(&self, port: u16) -> bool;

    /// `os.environ.get(name)`.
    fn env_var(&self, name: &str) -> Option<String>;

    /// `os.geteuid() != 0`, for the secret-scope probe.
    fn non_root(&self) -> bool;

    /// `apple_container.prerequisites.check_prerequisites()`.
    ///
    /// Empty means every prerequisite is met. Asked at most once per
    /// run, because Apple's `container system status` is slow: the
    /// result is passed into both consumers.
    ///
    /// On Linux the answer is the "requires macOS" issue.
    fn apple_container_issues(&self) -> Vec<String>;
}

/// How `socket.getaddrinfo` finished.
///
/// The three `except` clauses of `check_dns`, as a type. They print
/// different messages, and the third prints the exception text, so
/// collapsing them would lose output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOutcome {
    /// It resolved.
    Resolved,
    /// `socket.gaierror` — the name did not resolve.
    NameError,
    /// `socket.timeout`. See the fixture README: reachable in a test,
    /// not on a real host.
    TimedOut,
    /// Any other `OSError`, with its message.
    Failed(String),
}

// ── results ──────────────────────────────────────────────────

/// `pass`, `warn` or `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Nothing to do.
    Pass,
    /// Worth knowing; does not stop `doctor` exiting 0.
    Warn,
    /// `doctor` exits 1.
    Error,
}

impl Level {
    /// The level's name, as the report spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// The styled mark this level prints.
    fn mark(self) -> String {
        match self {
            Self::Pass => crate::output::green("\u{2713}"),
            Self::Warn => yellow("\u{26a0}"),
            Self::Error => crate::output::red("\u{2717}"),
        }
    }
}

/// One check's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// Which mark it prints.
    pub level: Level,
    /// The line itself.
    pub message: String,
    /// The indented remediation line, or empty for none.
    pub hint: String,
}

impl CheckResult {
    fn new(level: Level, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            hint: hint.into(),
        }
    }

    fn pass(message: impl Into<String>) -> Self {
        Self::new(Level::Pass, message, "")
    }

    fn warn(message: impl Into<String>) -> Self {
        Self::new(Level::Warn, message, "")
    }
}

/// A heading and the checks under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The bold heading.
    pub title: &'static str,
    /// Its checks, in print order.
    pub results: Vec<CheckResult>,
}

/// The schema version of the `--json` document.
///
/// Bumping it is the promise that a consumer can key on the number rather
/// than sniff the fields: within one version, a field never changes
/// meaning and a key never disappears.
pub const JSON_SCHEMA_VERSION: i64 = 1;

/// What `main` was asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Print the `--json` document instead of the human report.
    pub json: bool,
}

/// A whole `doctor` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The four sections, in print order.
    pub sections: Vec<Section>,
}

impl Report {
    /// Every result, in print order.
    pub fn results(&self) -> impl Iterator<Item = &CheckResult> {
        self.sections.iter().flat_map(|s| s.results.iter())
    }

    /// `1` if any check errored, else `0`.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        u8::from(self.results().any(|r| r.level == Level::Error))
    }

    /// How many checks ended at `level`.
    #[must_use]
    pub fn count(&self, level: Level) -> usize {
        self.results().filter(|r| r.level == level).count()
    }

    /// The `--json` document, as a value.
    ///
    /// The checks are flat rather than nested under their sections: a
    /// consumer looking for "which check failed" should not have to
    /// walk two arrays, so each entry carries its own `section`. `name`
    /// is the check's message — the doctor has no separate identifier,
    /// and its message is what it prints.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let checks: Vec<Json> = self
            .sections
            .iter()
            .flat_map(|section| {
                section.results.iter().map(|result| {
                    Json::Object(vec![
                        ("section".to_owned(), Json::string(section.title)),
                        ("name".to_owned(), Json::string(&result.message)),
                        ("level".to_owned(), Json::string(result.level.as_str())),
                        ("hint".to_owned(), Json::string(&result.hint)),
                    ])
                })
            })
            .collect();
        let passed = self.count(Level::Pass);
        let warnings = self.count(Level::Warn);
        let errors = self.count(Level::Error);
        let exit_code = self.exit_code();
        Json::Object(vec![
            ("schema_version".to_owned(), Json::Int(JSON_SCHEMA_VERSION)),
            ("command".to_owned(), Json::string("doctor")),
            ("ok".to_owned(), Json::Bool(exit_code == 0)),
            ("exit_code".to_owned(), Json::Int(i64::from(exit_code))),
            (
                "summary".to_owned(),
                Json::Object(vec![
                    (
                        "passed".to_owned(),
                        Json::Int(i64::try_from(passed).unwrap_or(i64::MAX)),
                    ),
                    (
                        "warnings".to_owned(),
                        Json::Int(i64::try_from(warnings).unwrap_or(i64::MAX)),
                    ),
                    (
                        "errors".to_owned(),
                        Json::Int(i64::try_from(errors).unwrap_or(i64::MAX)),
                    ),
                ]),
            ),
            ("checks".to_owned(), Json::Array(checks)),
        ])
    }

    /// The `--json` document, rendered with the two-space indent
    /// `cage har` already uses for the same reason: a diff of two runs
    /// is readable.
    #[must_use]
    pub fn render_json(&self) -> String {
        json::dumps(&self.to_json(), DumpOptions::indented())
    }
}

// ── distro detection ─────────────────────────────────────────

/// The distribution family, which selects a remediation hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    /// Arch and derivatives.
    Arch,
    /// Debian, Ubuntu and derivatives.
    Debian,
    /// Fedora.
    Fedora,
    /// RHEL, `CentOS`, Rocky, Alma, Oracle.
    ///
    /// Reached only when `ID_LIKE` does **not** also name `fedora`;
    /// `_detect_distro` tests fedora first.
    Rhel,
    /// openSUSE and SLES.
    OpenSuse,
    /// Anything else, including an unreadable `/etc/os-release`.
    Unknown,
}

/// `_detect_distro`, over the text of `/etc/os-release`.
///
/// Split on the first `=`, strip whitespace,
/// then strip one layer of double quotes. Lines without an `=` are
/// ignored; a repeated key keeps the last value.
#[must_use]
pub fn detect_distro(os_release: Option<&str>) -> Distro {
    let Some(text) = os_release else {
        return Distro::Unknown;
    };

    let mut id = String::new();
    let mut id_like = String::new();
    for line in text.lines() {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let val = val.trim().trim_matches('"').to_owned();
        match key.trim() {
            "ID" => id = val,
            "ID_LIKE" => id_like = val,
            _ => {}
        }
    }

    if matches!(id.as_str(), "arch" | "archarm") || id_like.contains("arch") {
        return Distro::Arch;
    }
    if matches!(
        id.as_str(),
        "debian" | "ubuntu" | "pop" | "mint" | "elementary" | "zorin" | "kali" | "raspbian"
    ) || id_like.contains("debian")
        || id_like.contains("ubuntu")
    {
        return Distro::Debian;
    }
    if id == "fedora" || id_like.contains("fedora") {
        return Distro::Fedora;
    }
    if matches!(id.as_str(), "rhel" | "centos" | "rocky" | "alma" | "ol")
        || id_like.contains("rhel")
    {
        return Distro::Rhel;
    }
    if id.starts_with("opensuse") || id == "sles" || id_like.contains("suse") {
        return Distro::OpenSuse;
    }
    Distro::Unknown
}

impl Distro {
    /// `_INSTALL_PODMAN[distro]`.
    fn install_podman(self) -> &'static str {
        match self {
            Self::Arch => "sudo pacman -S podman",
            Self::Debian => "sudo apt-get install -y podman",
            Self::Fedora | Self::Rhel => "sudo dnf install -y podman",
            Self::OpenSuse => "sudo zypper install -y podman",
            Self::Unknown => "install podman for your distribution",
        }
    }

    /// `_INSTALL_LIMA[distro]`.
    fn install_lima(self) -> &'static str {
        match self {
            Self::Arch => "install lima from AUR or via 'brew install lima'",
            Self::Debian => "sudo apt-get install -y lima",
            Self::Fedora | Self::Rhel => "sudo dnf install -y lima",
            Self::OpenSuse => "sudo zypper install -y lima",
            Self::Unknown => "install lima from https://lima-vm.io",
        }
    }

    /// `_INSTALL_QEMU[distro]`, or `_INSTALL_QEMU_AARCH64[distro]` on an
    /// arm64 host.
    ///
    /// Note that this table is the one that is *not* uniform across the
    /// dnf pair: Fedora wants `qemu-system-x86-core` and RHEL wants
    /// `qemu-kvm`.
    fn install_qemu(self, arm64: bool) -> &'static str {
        match (self, arm64) {
            (Self::Arch, _) => "sudo pacman -S qemu-full",
            (Self::Debian, false) => "sudo apt-get install -y qemu-system-x86",
            (Self::Debian, true) => "sudo apt-get install -y qemu-system-arm",
            (Self::Fedora, false) => "sudo dnf install -y qemu-system-x86-core",
            (Self::Fedora, true) => "sudo dnf install -y qemu-system-aarch64-core",
            (Self::Rhel, _) => "sudo dnf install -y qemu-kvm",
            (Self::OpenSuse, false) => "sudo zypper install -y qemu-x86",
            (Self::OpenSuse, true) => "sudo zypper install -y qemu-arm",
            (Self::Unknown, _) => "install qemu for your distribution",
        }
    }
}

/// `_ENABLE_LINGER`.
const ENABLE_LINGER: &str = "sudo loginctl enable-linger $USER";

/// The ports `check_port` probes, in order — `_COMMON_PORTS`.
pub const COMMON_PORTS: [u16; 3] = [8080, 3000, 18789];

// ── prerequisite checks ──────────────────────────────────────

/// The 5s the version probes allow themselves.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// The 10s `podman info` and `podman network ls` allow themselves.
const PODMAN_TIMEOUT: Duration = Duration::from_secs(10);

/// Run a captured probe, flattening every failure into `None`.
///
/// A binary that is not installed, a timeout, a non-zero exit and every
/// other [`ExecError`](agentcage_exec::ExecError) all read as a failed probe.
fn probe(runner: &dyn CommandRunner, cmd: &Command) -> Option<String> {
    let out = runner.run(cmd).ok()?;
    out.success().then(|| out.stdout_text())
}

/// `check_podman` — installed, and what version.
#[must_use]
pub fn check_podman(runner: &dyn CommandRunner, distro: Distro, is_macos: bool) -> CheckResult {
    let cmd = Command::new("podman")
        .arg("--version")
        .captured()
        .timeout(PROBE_TIMEOUT);
    if let Some(stdout) = probe(runner, &cmd) {
        // `str.replace` in both languages replaces every occurrence, not
        // just a prefix. Kept rather than tidied into `strip_prefix`.
        let ver = stdout.trim().replace("podman version ", "");
        return CheckResult::pass(format!("Podman {ver}"));
    }
    if is_macos {
        return CheckResult::pass(
            "Podman not installed (optional on macOS — containers run inside the VM)",
        );
    }
    CheckResult::new(Level::Error, "Podman not found", distro.install_podman())
}

/// `check_podman_rootless` — rootless, rootful, or unanswerable.
#[must_use]
pub fn check_podman_rootless(runner: &dyn CommandRunner) -> CheckResult {
    let cmd = Command::new("podman")
        .args(["info", "--format", "{{.Host.Security.Rootless}}"])
        .captured()
        .timeout(PODMAN_TIMEOUT);
    if let Ok(out) = runner.run(&cmd)
        && out.success()
    {
        if out.stdout_text().trim().to_lowercase() == "true" {
            return CheckResult::pass("Podman rootless mode");
        }
        return CheckResult::new(
            Level::Warn,
            "Podman running as root (rootless recommended)",
            "run podman as a regular user, not root",
        );
    }
    CheckResult::warn("Could not verify Podman rootless mode")
}

/// `check_lima` — and, on macOS, whether its absence is fatal.
///
/// `apple_ok` is `run_doctor`'s precomputed answer, `None` on Linux
/// where it is never consulted.
#[must_use]
pub fn check_lima(
    runner: &dyn CommandRunner,
    distro: Distro,
    is_macos: bool,
    apple_ok: Option<bool>,
) -> CheckResult {
    let cmd = Command::new("limactl")
        .arg("--version")
        .captured()
        .timeout(PROBE_TIMEOUT);
    if let Some(stdout) = probe(runner, &cmd) {
        let ver = stdout.trim().replace("limactl version ", "");
        return CheckResult::pass(format!("Lima {ver}"));
    }
    if is_macos {
        // Issue #215: an apple-container-only Mac has a usable isolation
        // backend, so a missing Lima costs it `vm` isolation and nothing
        // else. Only a host with neither backend gets the hard error.
        if apple_ok.unwrap_or(false) {
            return CheckResult::new(
                Level::Warn,
                "Lima not found (optional — apple-container is available and is \
                 the chosen backend on this host; install Lima to also enable \
                 vm isolation)",
                "brew install lima",
            );
        }
        return CheckResult::new(
            Level::Error,
            "Lima not found (required on macOS — no usable isolation backend)",
            "brew install lima",
        );
    }
    CheckResult::new(
        Level::Warn,
        "Lima not found (needed for VM mode)",
        distro.install_lima(),
    )
}

/// `_check_apple_container`, over an already-computed prerequisite list.
///
/// Only the *first* unmet prerequisite becomes the hint, which is why
/// the fixture's no-backend case declares two.
#[must_use]
pub fn check_apple_container(issues: &[String]) -> CheckResult {
    match issues.first() {
        None => CheckResult::new(
            Level::Pass,
            "Apple container available (apple-container isolation enabled)",
            "Faster cage create than Lima, but no egress filter yet (v1). \
             Use Lima for untrusted workloads.",
        ),
        Some(first) => CheckResult::new(
            Level::Warn,
            "Apple container unavailable; apple-container isolation will not work",
            first.clone(),
        ),
    }
}

/// `_is_arm64` — Linux says `aarch64`, macOS and some BSDs `arm64`.
fn is_arm64(machine: &str) -> bool {
    machine.eq_ignore_ascii_case("aarch64") || machine.eq_ignore_ascii_case("arm64")
}

/// `check_qemu` — optional, Linux VM mode only.
///
/// Probes the system emulator for the host's own architecture: Lima on
/// an arm64 host runs aarch64 guests, so `qemu-system-x86_64` there is
/// neither needed nor, usually, installed.
#[must_use]
pub fn check_qemu(runner: &dyn CommandRunner, distro: Distro, machine: &str) -> CheckResult {
    let arm64 = is_arm64(machine);
    let binary = if arm64 {
        "qemu-system-aarch64"
    } else {
        "qemu-system-x86_64"
    };
    let cmd = Command::new(binary)
        .arg("--version")
        .captured()
        .timeout(PROBE_TIMEOUT);
    if let Some(stdout) = probe(runner, &cmd) {
        let first = stdout.lines().next().unwrap_or_default();
        return CheckResult::pass(format!("QEMU ({})", first.trim()));
    }
    CheckResult::new(
        Level::Warn,
        "QEMU not found (needed for VM mode on Linux)",
        distro.install_qemu(arm64),
    )
}

/// `check_systemd_linger` — user units survive logout, or they do not.
#[must_use]
pub fn check_systemd_linger(runner: &dyn CommandRunner, host: &dyn DoctorHost) -> CheckResult {
    // `os.environ.get("USER", "")` and then `if not user`, so an unset
    // variable and an empty one are the same thing.
    let user = host.env_var("USER").unwrap_or_default();
    if user.is_empty() {
        return CheckResult::warn("Could not determine current user for linger check");
    }
    let cmd = Command::new("loginctl")
        .args(["show-user", &user, "-p", "Linger"])
        .captured()
        .timeout(PROBE_TIMEOUT);
    match runner.run(&cmd) {
        Ok(out) => {
            if out.success() && out.stdout_text().to_lowercase().contains("yes") {
                CheckResult::pass("systemd user linger enabled")
            } else {
                CheckResult::new(
                    Level::Warn,
                    "systemd user linger not enabled",
                    ENABLE_LINGER,
                )
            }
        }
        Err(_) => CheckResult::warn("loginctl not available (no systemd?)"),
    }
}

// ── system checks ────────────────────────────────────────────

/// `check_disk_space` — 2GB in `$HOME`.
#[must_use]
pub fn check_disk_space(host: &dyn DoctorHost) -> CheckResult {
    let free = match host.disk_free_bytes() {
        Ok(bytes) => bytes,
        Err(msg) => return CheckResult::warn(format!("Could not check disk space: {msg}")),
    };
    #[allow(clippy::cast_precision_loss)]
    let free_gb = free as f64 / 1024_f64.powi(3);
    if free_gb >= 2.0 {
        // Both languages round half to even here, so 2.5 prints as `2`
        // on either side.
        return CheckResult::pass(format!("{free_gb:.0}GB disk available"));
    }
    CheckResult::new(
        Level::Error,
        format!("Only {free_gb:.1}GB disk free (need >= 2GB)"),
        "free up disk space in your home directory",
    )
}

/// `_check_secret_backend` — what `agentcage secret set` would use.
#[must_use]
pub fn check_secret_backend(runner: &dyn CommandRunner, host: &dyn DoctorHost) -> CheckResult {
    if host.is_macos() {
        // systemd-creds does not exist here, so this branch answers the
        // same question the Linux one does: which store would
        // `secrets::store::resolve_store` pick for a default (`auto`)
        // cage? On a Mac that is `KeychainStore` for every isolation an
        // operator can run — `host_keychain` covers apple-container, and
        // "fix(secret): use the host keychain for vm cages on macOS"
        // extended it to vm. The podman-backed store this used to name is
        // `PlaintextStore`, now reachable only by an explicit
        // `backend: plaintext` / `source: podman:` opt-in to cleartext,
        // so `runner.has("podman")` decides nothing here and the probe is
        // gone.
        //
        // Reports the store without proving it usable, unlike the Linux
        // branch: `KeychainStore::available` establishes write-ability by
        // adding and deleting a real keychain item, which a read-only
        // diagnostic must not do to the operator's login keychain.
        // `systemd-creds encrypt` writes nothing, which is why Linux can
        // probe. The ladder `KeychainStore::target` walks is in the hint.
        return CheckResult::new(
            Level::Pass,
            "macOS keychain (secrets encrypted at rest)",
            "Secrets go to the login keychain when a GUI session has it unlocked, \
             else the System keychain when passwordless sudo for /usr/bin/security \
             is configured. agentcage reads them back and materializes them at \
             cage start.",
        );
    }

    let env = SystemEnv;
    let secrets = SecretHost::new(runner, &env, host.non_root());
    let systemctl = Systemctl::new(runner);

    if secrets.default_backend() == Backend::SystemdCreds {
        let ver = systemctl.systemd_version();
        // `detect_default_scope() or "system"`. The backend being
        // systemd-creds already implies a scope, so the fallback is
        // unreachable — kept because it is what decides the message.
        let scope = secrets.default_scope().unwrap_or(Scope::System);
        if scope == Scope::User {
            return CheckResult::new(
                Level::Pass,
                format!("systemd-creds --user (systemd {ver}, per-user key)"),
                "Secrets encrypted with the per-user key — bound to this user, \
                 not the host. No polkit prompt at encrypt or decrypt time, so \
                 service users can set secrets unattended.",
            );
        }
        return CheckResult::new(
            Level::Pass,
            format!("systemd-creds (systemd {ver}, secrets encrypted at rest)"),
            "Secrets encrypted with TPM2 or host key. Note: encrypted blobs are \
             bound to this machine's hardware.",
        );
    }

    let ver = systemctl.systemd_version();
    if ver >= 250 && runner.has("systemd-creds") {
        return CheckResult::new(
            Level::Warn,
            format!("podman (systemd-creds installed but not usable, systemd {ver})"),
            "Run 'sudo systemd-creds setup' to initialize the host key, or use \
             'source: cmd:...' in cage.yaml for external secret managers.",
        );
    }
    CheckResult::new(
        Level::Warn,
        "podman (secrets stored unencrypted)",
        "Install systemd 250+ for encrypted secret storage, or use \
         'source: cmd:...' in cage.yaml for external secret managers.",
    )
}

/// `check_cgroup_v2` — rootless podman needs it.
#[must_use]
pub fn check_cgroup_v2(host: &dyn DoctorHost) -> CheckResult {
    match host.path_exists("/sys/fs/cgroup/cgroup.controllers") {
        Ok(true) => CheckResult::pass("cgroup v2 enabled"),
        Ok(false) => CheckResult::new(
            Level::Warn,
            "cgroup v2 not detected",
            "cgroup v2 is required for rootless containers; check your kernel \
             boot parameters",
        ),
        Err(msg) => CheckResult::warn(format!("Could not check cgroup version: {msg}")),
    }
}

// ── network checks ───────────────────────────────────────────

/// `check_dns`.
#[must_use]
pub fn check_dns(host: &dyn DoctorHost) -> CheckResult {
    const HINT: &str = "check /etc/resolv.conf and network connectivity";
    match host.resolve_dns() {
        DnsOutcome::Resolved => CheckResult::pass("DNS resolution working"),
        DnsOutcome::NameError => CheckResult::new(Level::Error, "DNS resolution failed", HINT),
        DnsOutcome::TimedOut => CheckResult::new(Level::Error, "DNS resolution timed out", HINT),
        DnsOutcome::Failed(msg) => {
            CheckResult::new(Level::Error, format!("DNS check failed: {msg}"), HINT)
        }
    }
}

/// `check_subnet_conflicts` — podman networks already in `10.89.0.0/16`.
#[must_use]
pub fn check_subnet_conflicts(runner: &dyn CommandRunner) -> CheckResult {
    let cmd = Command::new("podman")
        .args(["network", "ls", "--format", "json"])
        .captured()
        .timeout(PODMAN_TIMEOUT);
    let Ok(out) = runner.run(&cmd) else {
        return CheckResult::pass("No subnet conflicts (podman not available)");
    };
    if !out.success() {
        return CheckResult::pass("No subnet conflicts (could not query networks)");
    }

    let stdout = out.stdout_text();
    let networks: Vec<serde_json::Value> = if stdout.trim().is_empty() {
        Vec::new()
    } else {
        // Earlier releases reported unparseable output as a `warn`.
        // There is no exception to catch here, so unparseable output is
        // read as "no networks" — the
        // same answer the non-zero-exit branch already gives, and the
        // one fixture case that covers it is marked unported.
        serde_json::from_str(&stdout).unwrap_or_default()
    };

    let mut conflicts = Vec::new();
    for net in &networks {
        let Some(subnets) = net.get("subnets").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for sub in subnets {
            let gw = sub.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
            let subnet = sub.get("subnet").and_then(|v| v.as_str()).unwrap_or("");
            if gw.contains("10.89.") || subnet.contains("10.89.") {
                let name = net
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                conflicts.push(format!("{name} ({subnet})"));
            }
        }
    }

    if conflicts.is_empty() {
        return CheckResult::pass("No subnet conflicts");
    }
    CheckResult::new(
        Level::Warn,
        format!("Existing 10.89.x.0/24 subnets: {}", conflicts.join(", ")),
        "these may conflict with new cages; destroy unused cages to free subnets",
    )
}

/// `check_port` — and, when it is taken, who has it.
#[must_use]
pub fn check_port(runner: &dyn CommandRunner, host: &dyn DoctorHost, port: u16) -> CheckResult {
    if host.port_is_free(port) {
        return CheckResult::pass(format!("Port {port} available"));
    }
    let cmd = Command::new("ss")
        .args(["-tlnp", &format!("sport = :{port}")])
        .captured()
        .timeout(PROBE_TIMEOUT);
    let mut pid_info = String::new();
    if let Some(stdout) = probe(runner, &cmd) {
        // `for line in r.stdout.splitlines()[1:]` — the header is
        // skipped, and the FIRST line mentioning the port wins whether
        // or not it names a pid.
        for line in stdout.lines().skip(1) {
            if line.contains(&format!(":{port}")) {
                if let Some(pid) = first_pid(line) {
                    pid_info = format!(" (PID {pid})");
                }
                break;
            }
        }
    }
    CheckResult::warn(format!("Port {port} in use{pid_info}"))
}

/// `re.search(r"pid=(\d+)", line)`, group 1.
fn first_pid(line: &str) -> Option<&str> {
    let mut rest = line;
    while let Some(at) = rest.find("pid=") {
        let digits = &rest[at + 4..];
        let end = digits
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(digits.len());
        if end > 0 {
            return Some(&digits[..end]);
        }
        rest = &rest[at + 4..];
    }
    None
}

// ── the run ──────────────────────────────────────────────────

/// `run_doctor`, minus the printing.
///
/// Splitting the decisions from the rendering is what lets the golden
/// test assert both the structured results and the bytes, and it is the
/// same shape `output.rs` settled on for the same reason.
#[must_use]
pub fn run(runner: &dyn CommandRunner, host: &dyn DoctorHost) -> Report {
    let is_macos = host.is_macos();
    let distro = detect_distro(host.os_release().as_deref());

    // Apple's `container system status` is slow, so `run_doctor` probes
    // once and feeds the answer to both consumers. Reproduced, because
    // otherwise `doctor` on a Mac pays for it twice.
    let apple_issues = is_macos.then(|| DoctorHost::apple_container_issues(host));
    let apple_ok = apple_issues.as_ref().map(Vec::is_empty);

    let mut prereqs = Section {
        title: "Prerequisites",
        results: Vec::new(),
    };
    prereqs.results.push(check_podman(runner, distro, is_macos));
    // Gated on the previous result, which on macOS is a `pass` even when
    // podman is absent — hence the second condition, not just the first.
    if prereqs.results[0].level == Level::Pass && !is_macos {
        prereqs.results.push(check_podman_rootless(runner));
    }
    prereqs
        .results
        .push(check_lima(runner, distro, is_macos, apple_ok));
    if let Some(issues) = &apple_issues {
        prereqs.results.push(check_apple_container(issues));
    }
    if !is_macos {
        prereqs
            .results
            .push(check_qemu(runner, distro, &host.machine()));
        prereqs.results.push(check_systemd_linger(runner, host));
    }

    let mut system = Section {
        title: "System",
        results: Vec::new(),
    };
    if !is_macos {
        system.results.push(check_cgroup_v2(host));
    }
    system.results.push(check_disk_space(host));

    let secrets = Section {
        title: "Secrets",
        results: vec![check_secret_backend(runner, host)],
    };

    let mut network = Section {
        title: "Network",
        results: vec![check_dns(host), check_subnet_conflicts(runner)],
    };
    for port in COMMON_PORTS {
        network.results.push(check_port(runner, host, port));
    }

    Report {
        sections: vec![prereqs, system, secrets, network],
    }
}

// ── rendering ────────────────────────────────────────────────

/// `click.style(text, bold=True)`.
///
/// Local rather than in `output.rs` because the styling module never
/// learned about bold headings or the yellow mark.
fn bold(text: &str) -> String {
    format!("\u{1b}[1m{text}\u{1b}[0m")
}

/// `doctor._warn` — `click.style(text, fg="yellow")`.
fn yellow(text: &str) -> String {
    format!("\u{1b}[33m{text}\u{1b}[0m")
}

/// Everything `run_doctor` writes, as one string.
///
/// `styled` is whether stdout is a terminal. Colour only ever *adds*
/// escapes (PR D4's invariant), so the plain form is the styled form
/// with them stripped — which is exactly what `click.echo` does on its
/// way to a pipe, and what the fixture asserts on both sides.
#[must_use]
pub fn render(report: &Report, styled: bool) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    out.push('\n');
    out.push_str(&bold("agentcage doctor"));
    out.push('\n');

    for section in &report.sections {
        out.push('\n');
        let _ = writeln!(out, "  {}", bold(section.title));
        for r in &section.results {
            let _ = writeln!(out, "    {} {}", r.level.mark(), r.message);
            if !r.hint.is_empty() {
                let _ = writeln!(
                    out,
                    "      {} {}",
                    crate::output::dim("\u{2192}"),
                    crate::output::dim(&r.hint)
                );
            }
        }
    }

    let errors = report.results().filter(|r| r.level == Level::Error).count();
    let warnings = report.results().filter(|r| r.level == Level::Warn).count();
    let mut parts = Vec::new();
    if errors > 0 {
        parts.push(crate::output::red(&format!(
            "{errors} {}",
            plural("error", errors)
        )));
    }
    if warnings > 0 {
        parts.push(yellow(&format!(
            "{warnings} {}",
            plural("warning", warnings)
        )));
    }
    if parts.is_empty() {
        parts.push(crate::output::green("all checks passed"));
    }

    out.push('\n');
    let _ = writeln!(out, "  {} {}", bold("Summary:"), parts.join(", "));
    out.push('\n');

    if styled {
        out
    } else {
        crate::output::strip_ansi(&out)
    }
}

/// `f"{word}{'s' if n != 1 else ''}"`.
fn plural(word: &str, n: usize) -> String {
    if n == 1 {
        word.to_owned()
    } else {
        format!("{word}s")
    }
}

#[cfg(test)]
mod tests {
    use agentcage_exec::FakeRunner;

    use super::{
        Distro, DnsOutcome, DoctorHost, Level, check_secret_backend, detect_distro, first_pid,
        plural,
    };

    #[test]
    fn the_distro_parser_reads_id_and_id_like() {
        assert_eq!(detect_distro(Some("ID=arch\n")), Distro::Arch);
        assert_eq!(
            detect_distro(Some("ID=ubuntu\nID_LIKE=debian\n")),
            Distro::Debian
        );
        assert_eq!(detect_distro(Some("ID=rocky\n")), Distro::Rhel);
        assert_eq!(detect_distro(Some("ID=opensuse-leap\n")), Distro::OpenSuse);
        assert_eq!(detect_distro(Some("PRETTY_NAME=x\n")), Distro::Unknown);
        assert_eq!(detect_distro(None), Distro::Unknown);
    }

    /// A Rocky box whose `ID_LIKE` mentions fedora resolves to
    /// **fedora**, not rhel, because the fedora test comes first in the
    /// chain -- and the two differ in the QEMU package they
    /// name. The fixture pins it as its own environment.
    #[test]
    fn the_order_of_the_family_tests_is_load_bearing() {
        assert_eq!(
            detect_distro(Some("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n")),
            Distro::Fedora
        );
        assert_eq!(
            detect_distro(Some("ID=rocky\nID_LIKE=\"rhel\"\n")),
            Distro::Rhel
        );
    }

    #[test]
    fn a_pid_is_found_anywhere_in_the_line() {
        assert_eq!(first_pid("users:((\"node\",pid=4242,fd=23))"), Some("4242"));
        assert_eq!(first_pid("no process here"), None);
        assert_eq!(first_pid("pid=,pid=7"), Some("7"));
    }

    #[test]
    fn only_one_is_singular() {
        assert_eq!(plural("error", 1), "error");
        assert_eq!(plural("error", 0), "errors");
        assert_eq!(plural("warning", 3), "warnings");
    }

    /// A [`DoctorHost`] that is a Mac and answers everything else the
    /// way the trait's cheapest total implementation can. The macOS arm
    /// of `check_secret_backend` reads `is_macos` and nothing else,
    /// which is the point.
    #[derive(Debug)]
    struct MacHost;

    impl DoctorHost for MacHost {
        fn is_macos(&self) -> bool {
            true
        }
        fn machine(&self) -> String {
            "arm64".to_owned()
        }
        fn os_release(&self) -> Option<String> {
            None
        }
        fn path_exists(&self, _path: &str) -> Result<bool, String> {
            Ok(false)
        }
        fn disk_free_bytes(&self) -> Result<u64, String> {
            Ok(50 * 1024 * 1024 * 1024)
        }
        fn resolve_dns(&self) -> DnsOutcome {
            DnsOutcome::Resolved
        }
        fn port_is_free(&self, _port: u16) -> bool {
            true
        }
        fn env_var(&self, _name: &str) -> Option<String> {
            None
        }
        fn non_root(&self) -> bool {
            true
        }
        fn apple_container_issues(&self) -> Vec<String> {
            Vec::new()
        }
    }

    /// The bug: a Mac with host podman was told its secrets were in a
    /// podman store, and a Mac without it was told `secret set` did not
    /// work. Since #247 the store is the keychain either way, so podman
    /// must not appear in the verdict and must not be probed for it.
    #[test]
    fn a_macs_secret_store_is_the_keychain_whatever_podman_does() {
        let installed = FakeRunner::new();
        installed.assume_installed();
        let with_podman = check_secret_backend(&installed, &MacHost);

        let missing = FakeRunner::new();
        missing.assume_missing();
        let without_podman = check_secret_backend(&missing, &MacHost);

        assert_eq!(with_podman.level, Level::Pass);
        assert!(with_podman.message.contains("keychain"));
        assert!(!with_podman.message.to_lowercase().contains("podman"));
        assert!(!with_podman.hint.to_lowercase().contains("podman"));
        // Byte-identical: podman decides nothing here.
        assert_eq!(with_podman.message, without_podman.message);
        assert_eq!(with_podman.hint, without_podman.hint);
        assert_eq!(with_podman.level, without_podman.level);
        // And nothing at all is run or looked up -- the keychain is not
        // probed, deliberately (see `check_secret_backend`).
        assert_eq!(installed.call_count(), 0);
        assert!(installed.which_lookups().is_empty());
        assert!(missing.which_lookups().is_empty());
    }
}

// ── the real host ────────────────────────────────────────────

/// [`DoctorHost`] answered by the machine this is running on.
///
/// The two places the answer is coarser than the recorded behaviour are
/// called out on the method.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDoctorHost;

impl SystemDoctorHost {
    /// The real host.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// The OS name as the report spells it (`Linux`, `Darwin`).
    fn platform_system() -> &'static str {
        match std::env::consts::OS {
            "macos" => "Darwin",
            "linux" => "Linux",
            "freebsd" => "FreeBSD",
            "netbsd" => "NetBSD",
            "openbsd" => "OpenBSD",
            "windows" => "Windows",
            other => other,
        }
    }

    /// `platform.machine()`, ditto: macOS reports `arm64`, not
    /// `aarch64`, which is the spelling the prerequisite message tests.
    fn platform_machine() -> &'static str {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => "arm64",
            (_, arch) => arch,
        }
    }
}

impl DoctorHost for SystemDoctorHost {
    fn is_macos(&self) -> bool {
        cfg!(target_os = "macos")
    }

    /// The target the binary was built for, which on a native build is
    /// the host: `x86_64` or `aarch64`, the spellings Linux's
    /// `platform.machine()` uses for the same machines.
    fn machine(&self) -> String {
        std::env::consts::ARCH.to_owned()
    }

    fn os_release(&self) -> Option<String> {
        std::fs::read_to_string("/etc/os-release").ok()
    }

    /// Always `Ok`.
    ///
    /// `Path.exists()` swallows `OSError` and answers `False`, so
    /// `check_cgroup_v2`'s `except OSError` never fires on a real host
    /// either. `std::path::Path::exists` behaves the same way; the `Err`
    /// arm exists for the fixture case that drives the branch.
    fn path_exists(&self, path: &str) -> Result<bool, String> {
        Ok(std::path::Path::new(path).exists())
    }

    /// `shutil.disk_usage(...).free`, which on POSIX is
    /// `f_bavail * f_frsize` — the space available to an unprivileged
    /// writer, not `f_bfree`.
    fn disk_free_bytes(&self) -> Result<u64, String> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_owned());
        let stat = nix::sys::statvfs::statvfs(home.as_str()).map_err(|e| e.to_string())?;
        // `blocks_available()` is `u32` on Darwin and `u64` on Linux, so the
        // bare multiplication only compiles on Linux — which is why CI never
        // caught this. The conversion is what makes the expression portable;
        // it is genuinely redundant on Linux, hence the allow, which is
        // narrower than a `cfg` split for one arithmetic expression.
        #[allow(clippy::useless_conversion)]
        let available = u64::from(stat.blocks_available());
        #[allow(clippy::useless_conversion)]
        let fragment = u64::from(stat.fragment_size());
        Ok(available * fragment)
    }

    /// `socket.getaddrinfo("example.com", 80)`.
    ///
    /// The one place the outcome is coarser than the recorded one: the
    /// resolver reports a lookup failure as an uncategorized `io::Error`
    /// rather than as a distinct class, so anything that is not an
    /// explicit timeout is read as the `gaierror` branch. Both print an
    /// error with the same hint, and the message differs only in wording.
    ///
    /// Note there is no timeout here, and no way to ask for one. Earlier
    /// releases had none either in practice: their socket timeout did
    /// not apply to name resolution, so their timeout branch was
    /// unreachable on a real host. See the fixture README.
    fn resolve_dns(&self) -> DnsOutcome {
        use std::net::ToSocketAddrs;
        match ("example.com", 80u16).to_socket_addrs() {
            Ok(_) => DnsOutcome::Resolved,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => DnsOutcome::TimedOut,
            Err(_) => DnsOutcome::NameError,
        }
    }

    /// `socket.socket(AF_INET, SOCK_STREAM)` then `bind`, and closed on
    /// the spot.
    ///
    /// Deliberately **not** `std::net::TcpListener::bind`, which sets
    /// `SO_REUSEADDR` on Unix. A plain socket does not, so a port
    /// left in `TIME_WAIT` by a cage that just stopped reads as busy
    /// there and as free through `TcpListener` — a diagnostic that
    /// disagrees with itself depending on which of the two you asked.
    fn port_is_free(&self, port: u16) -> bool {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, SockaddrIn, bind, socket};
        use std::os::fd::AsRawFd;

        let Ok(fd) = socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        ) else {
            // A socket() failure reads the same as a failed bind(): the
            // port is reported as in use.
            return false;
        };
        bind(fd.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 1, port)).is_ok()
    }

    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn non_root(&self) -> bool {
        !nix::unistd::Uid::effective().is_root()
    }

    /// `apple_container.prerequisites.check_prerequisites()`.
    ///
    /// The non-Darwin branch — the only one a
    /// Linux host or CI runner ever reaches — is pinned by the fixture.
    /// The Darwin branch runs the arch and binary tests and reads the
    /// macOS major version from `sw_vers`; nothing in CI can check it.
    fn apple_container_issues(&self) -> Vec<String> {
        const MIN_MACOS_MAJOR: u32 = 26;

        let system = Self::platform_system();
        if system != "Darwin" {
            return vec![format!(
                "apple-container isolation requires macOS; current platform is {system}"
            )];
        }

        let runner = agentcage_exec::SystemRunner::new();
        let mut issues = Vec::new();

        let machine = Self::platform_machine();
        if machine != "arm64" {
            issues.push(format!(
                "apple-container isolation requires Apple Silicon (arm64); \
                 current arch is {machine}"
            ));
        }

        let major = macos_major(&runner);
        if major.is_none_or(|m| m < MIN_MACOS_MAJOR) {
            issues.push(format!(
                "apple-container isolation requires macOS {MIN_MACOS_MAJOR}+; \
                 detected major version {}",
                major.map_or_else(|| "None".to_owned(), |m| m.to_string())
            ));
        }

        let apple = agentcage_exec::tools::apple::AppleContainer::new(&runner);
        if apple.binary().is_none() {
            issues.push(
                "'container' CLI not found — install from \
                 https://github.com/apple/container/releases (the .pkg installer)"
                    .to_owned(),
            );
            return issues;
        }
        if !apple.system_running().unwrap_or(false) {
            issues.push(
                "Apple container apiserver is not running — run \
                 'container system start --enable-kernel-install'"
                    .to_owned(),
            );
        }
        issues
    }
}

/// `platform.mac_ver()[0].split(".")[0]`, by way of `sw_vers`.
///
/// A subprocess because the standard library has no call for the macOS
/// version.
pub(crate) fn macos_major(runner: &dyn CommandRunner) -> Option<u32> {
    let cmd = Command::new("sw_vers")
        .arg("-productVersion")
        .captured()
        .timeout(PROBE_TIMEOUT);
    let out = runner.run(&cmd).ok()?;
    out.success()
        .then(|| out.stdout_trimmed())?
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// `agentcage doctor`: run every check, print the report, pick the exit
/// code.
///
/// The exit code is `1` if any check errored, else `0`, in both output
/// modes — `--json` changes what is printed, not what the command
/// means. The human report is byte-identical whether or not `--json`
/// exists.
#[must_use]
pub fn main(options: Options) -> u8 {
    use std::io::IsTerminal;

    let runner = agentcage_exec::SystemRunner::new();
    let host = SystemDoctorHost::new();
    let report = run(&runner, &host);
    if options.json {
        println!("{}", report.render_json());
    } else {
        print!("{}", render(&report, std::io::stdout().is_terminal()));
    }
    report.exit_code()
}
