//! The cage lifecycle: `list`, `show`, `status`, `start`, `stop`,
//! `restart`, `destroy`, `prune`.
//!
//! # Why they are all in one file
//!
//! They were not, at first. D6 landed `list` / `show` / `status` /
//! `destroy` because e2e phase 1 could not clean up after itself
//! without them, D12 added `stop` for phase 6's tmpfs teardown and D9
//! added `restart` because the live-secret path falls back to it. Each
//! took only the slice its own phase needed.
//!
//! PR D7 owns the group, so the slices are one module now. That is not
//! tidiness: `start` and `restart` regenerate the same two derived
//! files, `prune` runs `destroy`'s teardown in a loop, and five of the
//! eight open with the identical existence-then-version gate. Spread
//! across three files those would have drifted — the `cage stop` that
//! refuses a `vm` cage and the `cage start` that quietly mis-starts one
//! is exactly the kind of pair this collapses.
//!
//! # The shape every command here shares
//!
//! 1. Does the cage exist? No → `error: cage '<name>' does not exist`,
//!    exit 1.
//! 2. Is it a v0.22 cage? No → the migration procedure, exit 2. See
//!    [`ensure_v022_cage`]; `destroy` and `list` are exempt, and
//!    deliberately so.
//! 3. Is its backend ported? No → refuse rather than address the wrong
//!    containers (docs/history/rust-port-plan.md Track E).

use std::fmt::Write as _;
use std::io::{Read as _, Seek as _};
use std::process::ExitCode;

use agentcage_core::config::{Config, PLACEHOLDER_PREFIX};
use agentcage_core::har::json::{self, DumpOptions, Json};
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage, parse_version};
use agentcage_cli::backend::SERVICE_NAMES;
use agentcage_cli::backends::AnyBackend;
use agentcage_state::Paths;

/// `cage list` — one row per cage, with live status.
pub(crate) fn list(ctx: &Ctx, as_json: bool) -> ExitCode {
    let rows: Vec<ListRow> = ctx
        .paths
        .list_deployments()
        .unwrap_or_default()
        .into_iter()
        .map(|name| list_row(ctx, &name))
        .collect();

    if as_json {
        print_json(&envelope(
            "cage list",
            Json::Object(vec![(
                "cages".to_owned(),
                Json::Array(rows.iter().map(ListRow::to_json).collect()),
            )]),
            Vec::new(),
        ));
        return ExitCode::SUCCESS;
    }

    if rows.is_empty() {
        println!("No cages found.");
        return ExitCode::SUCCESS;
    }

    println!(
        "{:<25} {:<14} {:<12} {:<15} STATUS",
        "NAME", "LIFECYCLE", "ISOLATION", "SCAFFOLD"
    );
    for row in &rows {
        println!(
            "{:<25} {:<14} {:<12} {:<15} {}",
            row.name, row.lifecycle, row.isolation, row.scaffold, row.status
        );
    }
    ExitCode::SUCCESS
}

/// One `cage list` row, gathered before anything is rendered.
struct ListRow {
    name: String,
    lifecycle: String,
    isolation: String,
    scaffold: String,
    /// `running (n/m)`, `stopped (0/m)`, `degraded (n/m)`, `exited`, the
    /// v0.21 annotation, or `unknown (config error)`.
    status: String,
    /// The status word without its counts: what a JSON consumer keys on.
    state: &'static str,
    running: Option<usize>,
    total: Option<usize>,
    legacy: bool,
}

impl ListRow {
    fn to_json(&self) -> Json {
        let count = |value: Option<usize>| {
            value.map_or(Json::Null, |n| {
                Json::Int(i64::try_from(n).unwrap_or(i64::MAX))
            })
        };
        Json::Object(vec![
            ("name".to_owned(), Json::string(&self.name)),
            ("lifecycle".to_owned(), Json::string(&self.lifecycle)),
            ("isolation".to_owned(), Json::string(&self.isolation)),
            ("scaffold".to_owned(), Json::string(&self.scaffold)),
            ("status".to_owned(), Json::string(&self.status)),
            ("state".to_owned(), Json::string(self.state)),
            ("running".to_owned(), count(self.running)),
            ("total".to_owned(), count(self.total)),
            ("legacy".to_owned(), Json::Bool(self.legacy)),
        ])
    }
}

/// Gather one row, with the same fallbacks the table has always used.
fn list_row(ctx: &Ctx, name: &str) -> ListRow {
    let Ok(config) = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
    else {
        return ListRow {
            name: name.to_owned(),
            lifecycle: "?".to_owned(),
            isolation: "?".to_owned(),
            scaffold: "-".to_owned(),
            status: "unknown (config error)".to_owned(),
            state: "unknown",
            running: None,
            total: None,
            legacy: false,
        };
    };
    let metadata = ctx
        .paths
        .load_metadata(name)
        .unwrap_or_else(|_| Json::Object(Vec::new()));
    let lifecycle = string_or(&metadata, "lifecycle", &config.lifecycle);
    let scaffold = {
        let value = string_or(&metadata, "scaffold", &config.scaffold);
        if value.is_empty() {
            "-".to_owned()
        } else {
            value
        }
    };

    // A v0.21 cage's containers are named `<name>-proxy` /
    // `<name>-dns`, which `service_names()` no longer knows about,
    // so probing would mislabel a running legacy cage as stopped.
    let version = string_or(&metadata, "agentcage_version", "0.0.0");
    let version = if version.is_empty() {
        "0.0.0".to_owned()
    } else {
        version
    };
    if parse_version(&version) < (0, 22) {
        return ListRow {
            name: name.to_owned(),
            isolation: config.isolation,
            lifecycle,
            scaffold,
            status: "(legacy v0.21 — destroy + recreate)".to_owned(),
            state: "legacy",
            running: None,
            total: None,
            legacy: true,
        };
    }

    let (running, total) = ctx.backend_for(&config.isolation).running_count(name);
    let (status, state) = if running == total {
        (format!("running ({running}/{total})"), "running")
    } else if running == 0 {
        if lifecycle == "interactive" || lifecycle == "ephemeral" {
            ("exited".to_owned(), "exited")
        } else {
            (format!("stopped (0/{total})"), "stopped")
        }
    } else {
        (format!("degraded ({running}/{total})"), "degraded")
    };
    ListRow {
        name: name.to_owned(),
        lifecycle,
        isolation: config.isolation,
        scaffold,
        status,
        state,
        running: Some(running),
        total: Some(total),
        legacy: false,
    }
}

/// `cage show` — one cage's configuration and status.
pub(crate) fn show(ctx: &Ctx, name: &str, as_json: bool) -> ExitCode {
    match show_inner(ctx, name, as_json) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// `cage status` — `show` with a NAME, `list` without one.
pub(crate) fn status(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let as_json = matches.get_flag("json");
    match matches.get_one::<String>("name") {
        Some(name) => show(ctx, name, as_json),
        None => list(ctx, as_json),
    }
}

fn show_inner(ctx: &Ctx, name: &str, as_json: bool) -> Result<(), ExitCode> {
    if !ctx.paths.deployment_exists(name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, name)?;

    let report = gather_show(ctx, name)?;
    if as_json {
        print_json(&envelope(
            "cage show",
            report.to_json(),
            report.warnings.clone(),
        ));
    } else {
        print!("{}", render_show(&report));
    }
    Ok(())
}

/// Everything `cage show` prints, gathered before anything is rendered.
///
/// The split exists for the same reason `doctor` has one: `--json` must
/// carry the same facts as the human report, and the only way to keep
/// the two honest is for one collection pass to feed both.
struct ShowReport {
    name: String,
    isolation: String,
    lifecycle: String,
    image: String,
    build: Option<String>,
    version: String,
    scaffold: String,
    running: usize,
    total: usize,
    network: Option<Network>,
    data_dir: String,
    ports: Vec<String>,
    volumes: Vec<String>,
    named_volumes: Vec<(String, String)>,
    tmpfs: Vec<String>,
    domains: Option<DomainReport>,
    secrets: Option<SecretReport>,
    watcher: WatcherReport,
    recent_blocked: Option<(usize, usize)>,
    warnings: Vec<String>,
}

/// The two static addresses and the subnet a cage's units are pinned to.
struct Network {
    subnet: String,
    cage: String,
    egress: String,
}

/// `domains:` read from the raw document, names and all.
struct DomainReport {
    mode: String,
    names: Vec<String>,
    passthrough: Vec<String>,
}

/// The secret names the cage expects, which are present, and the decoy
/// token that stands in for each one inside the cage.
struct SecretReport {
    expected: usize,
    present: usize,
    entries: Vec<SecretEntry>,
}

struct SecretEntry {
    name: String,
    present: bool,
    placeholder: String,
}

/// What `agents.watcher` says, and what its state file adds.
enum WatcherReport {
    Disabled,
    NoScanYet,
    Unreachable,
    Unreadable,
    Scanned {
        last_scan: String,
        failed: bool,
        findings: i64,
    },
}

fn gather_show(ctx: &Ctx, name: &str) -> Result<ShowReport, ExitCode> {
    let config = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    let metadata = ctx
        .paths
        .load_metadata(name)
        .unwrap_or_else(|_| Json::Object(Vec::new()));
    let backend = ctx.backend_for(&config.isolation);
    let (running, total) = backend.running_count(name);

    // The *staged* Containerfile, which is the copy `cage update`
    // actually builds. Editing the one they authored has no effect.
    let build = if config.container.build.containerfile.is_empty() {
        None
    } else {
        let staged = ctx
            .paths
            .deployment_dir(name)
            .join(&config.container.build.containerfile);
        staged.is_file().then(|| staged.display().to_string())
    };

    let version = string_or(&metadata, "agentcage_version", "-");
    let scaffold = string_or(&metadata, "scaffold", &config.scaffold);

    // Domain info comes from the *raw* document, not the parsed config:
    // `_read_domain_config` reports what is written, and it differs from
    // the dataclass in one visible way — a `domains:` block with neither
    // `allow` nor `block` reads as `allowlist` here and as `""` there.
    let domains = ctx
        .paths
        .load_raw_config(name, agentcage_state::AgentSchema::Check)
        .ok()
        .map(|raw| read_domain_config(&raw));

    let mut warnings = Vec::new();
    let secrets = secret_report(ctx, &config, name);
    let watcher = watcher_report(ctx, name, &config, &mut warnings);

    let capture = if config.isolation == "apple-container" {
        ctx.paths.apple_capture_file(name)
    } else {
        ctx.paths.capture_file(name)
    };
    let recent_blocked = recent_blocked(&capture);

    Ok(ShowReport {
        name: config.name.clone(),
        isolation: config.isolation.clone(),
        lifecycle: string_or(&metadata, "lifecycle", &config.lifecycle),
        image: config.container.image.clone(),
        build,
        version,
        scaffold,
        running,
        total,
        network: network(&config, &metadata),
        data_dir: ctx.paths.cage_data_dir(name).display().to_string(),
        ports: config.container.ports.clone(),
        volumes: config.container.volumes.clone(),
        named_volumes: config
            .container
            .named_volumes
            .iter()
            .map(|(volume, mount)| (volume.clone(), mount.clone()))
            .collect(),
        tmpfs: config.container.tmpfs.clone(),
        domains,
        secrets,
        watcher,
        recent_blocked,
        warnings,
    })
}

/// The cage's derived static addresses, when it has any.
///
/// The octet is persisted in `metadata.json` at deploy time; a legacy
/// deployment without one falls back to the same hash the renderer uses.
/// `apple-container` has no `10.89.x` pool — Apple allocates each cage's
/// subnet — so it reports none rather than inventing an address.
fn network(config: &Config, metadata: &Json) -> Option<Network> {
    if config.isolation == "apple-container" {
        return None;
    }
    let octet = match metadata.get("network_octet") {
        Some(Json::Int(value)) => u32::try_from(*value).ok(),
        _ => None,
    };
    let addrs = agentcage_core::quadlets::cage_network_addrs(&config.name, None, octet).ok()?;
    Some(Network {
        subnet: addrs.subnet,
        cage: addrs.ip_cage,
        egress: addrs.ip_egress,
    })
}

/// Which secret names are stored, through the backend's own store.
fn secret_report(ctx: &Ctx, config: &Config, name: &str) -> Option<SecretReport> {
    let expected = agentcage_cli::services::expected_secrets(config);
    if expected.is_empty() {
        return None;
    }
    // Host podman is the secret store — except on apple-container,
    // which has no host podman and keeps its secrets in the macOS
    // keychain (or, under `backend: plaintext`, in the cage's own
    // state directory). Asking podman about one of those cages is
    // the failure mode this backend keeps producing: podman does
    // not error, it answers *nothing found*, so every secret was
    // reported missing on a cage that had all of them. Observed
    // against a real cage — `Secrets: 0/3 (3 missing)` where earlier
    // releases said `3/3`.
    //
    // The source here is the one `secret list` uses, which is what
    // makes the two agree.
    let present: Vec<String> = if crate::cli::secret::apple::is_apple_container(config) {
        crate::cli::secret::apple::secret_names(ctx, config, name)
    } else {
        let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
        let prefix = format!("{name}.");
        podman
            .secret_list(&prefix)
            .unwrap_or_default()
            .into_iter()
            .map(|full| full[prefix.len().min(full.len())..].to_owned())
            .collect()
    };
    let entries: Vec<SecretEntry> = expected
        .iter()
        .map(|key| SecretEntry {
            name: key.clone(),
            present: present.contains(key),
            placeholder: config
                .secret_injection
                .iter()
                .find(|rule| rule.env == *key)
                .map_or_else(String::new, |rule| mask_placeholder(&rule.placeholder)),
        })
        .collect();
    let provided = entries.iter().filter(|entry| entry.present).count();
    Some(SecretReport {
        expected: expected.len(),
        present: provided,
        entries,
    })
}

/// The placeholder with its random suffix hidden.
///
/// A placeholder is a decoy, not a credential — `secret list` prints it
/// in full — but the token is 128 bits of entropy that identifies a
/// *generation*, and `cage show` is a status command, not a debugging
/// one. Masking it keeps a screenshot of `show` from being mistaken
/// for a leaked secret while still naming the rule.
fn mask_placeholder(placeholder: &str) -> String {
    if placeholder.is_empty() {
        return String::new();
    }
    match placeholder.strip_prefix(PLACEHOLDER_PREFIX) {
        Some(rest) => match rest.split_once(':') {
            Some((env, _token)) => format!("{PLACEHOLDER_PREFIX}{env}:****"),
            None => format!("{PLACEHOLDER_PREFIX}****"),
        },
        // A hand-written token with no canonical prefix: show that one
        // exists, without printing it.
        None => "****".to_owned(),
    }
}

/// The watcher's configured state, and its last scan when the state file
/// is readable. A read failure is a warning, not a diagnostic failure.
fn watcher_report(
    ctx: &Ctx,
    name: &str,
    config: &Config,
    warnings: &mut Vec<String>,
) -> WatcherReport {
    let watcher = &config.agents.watcher;
    if !watcher.enable {
        return WatcherReport::Disabled;
    }
    let Some(text) = crate::cli::watcher_cmd::load_output(ctx, name, config, "state.json") else {
        warnings.push(format!(
            "could not read the traffic watcher's scan state for '{name}'"
        ));
        return WatcherReport::Unreachable;
    };
    if text.trim().is_empty() {
        return WatcherReport::NoScanYet;
    }
    let Ok(state) = json::parse(&text) else {
        warnings.push(format!(
            "could not parse the traffic watcher's scan state for '{name}'"
        ));
        return WatcherReport::Unreadable;
    };
    WatcherReport::Scanned {
        last_scan: json_field(&state, "last_scan"),
        failed: state.get("last_scan_failed").is_some_and(Json::is_truthy),
        findings: match state.get("findings_total") {
            Some(Json::Int(n)) => *n,
            _ => 0,
        },
    }
}

/// How many entries `recent_blocked` reports on.
const BLOCKED_WINDOW: usize = 500;
/// The first chunk the backward read asks for. It doubles until the
/// chunk holds `BLOCKED_WINDOW` complete lines or reaches the start of
/// the file.
const BLOCKED_TAIL_BYTES: u64 = 256 * 1024;
/// A capture entry can carry a request or response body
/// (`capture.max_body_size` defaults to 10 MiB), so a fixed-size tail
/// silently loses entries. The cap keeps a pathological file from being
/// read whole to answer a status line.
const BLOCKED_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The last `BLOCKED_WINDOW` capture entries, and how many were
/// blocked.
///
/// The capture file rotates at 128 MB per file, so reading all of it to
/// answer a status line would not be "cheap". The read starts at the
/// end and grows backwards until it holds `BLOCKED_WINDOW` complete
/// lines or reaches the start of the file: one 256 KiB chunk is not
/// enough when an entry carries a body, and a single such entry used to
/// make the whole window read as empty. A torn first line from starting
/// mid-entry is discarded — but only when the byte before the read
/// really is not a newline, since `start > 0` also holds when the chunk
/// happens to begin exactly on a line boundary.
fn recent_blocked(path: &std::path::Path) -> Option<(usize, usize)> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }

    let mut tail = BLOCKED_TAIL_BYTES;
    loop {
        let start = len.saturating_sub(tail);
        let bytes = read_range(&mut file, start, len)?;
        let text = String::from_utf8_lossy(&bytes);
        let mut lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        // `start > 0` is not the test: a chunk that begins exactly at a
        // newline starts on a whole line. The byte before `start` is.
        if start > 0 && !lines.is_empty() && byte_before(&mut file, start)? != b'\n' {
            lines.remove(0);
        }
        // Enough for the window, the whole file (EOF), or the cap.
        if lines.len() >= BLOCKED_WINDOW || start == 0 || tail >= BLOCKED_MAX_BYTES {
            return count_blocked(&lines);
        }
        tail = tail.saturating_mul(2).min(BLOCKED_MAX_BYTES);
    }
}

/// The bytes of `file` from `start` up to `len`.
fn read_range(file: &mut std::fs::File, start: u64, len: u64) -> Option<Vec<u8>> {
    file.seek(std::io::SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(file)
        .take(len.saturating_sub(start))
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// The byte at `offset - 1`, i.e. the one that decides whether `offset`
/// is the start of a line. Only called with `offset > 0`.
fn byte_before(file: &mut std::fs::File, offset: u64) -> Option<u8> {
    file.seek(std::io::SeekFrom::Start(offset.checked_sub(1)?))
        .ok()?;
    let mut byte = [0u8; 1];
    std::io::Read::read_exact(file, &mut byte).ok()?;
    Some(byte[0])
}

/// How many of the last `BLOCKED_WINDOW` complete lines are capture
/// entries, and how many of those say `blocked`.
///
/// A line that does not parse as an object is not an entry. Counting it
/// in the denominator was the other half of `Blocked: 0 of the last N`:
/// a torn or corrupt line inflated `N` without ever being a request.
fn count_blocked(lines: &[&str]) -> Option<(usize, usize)> {
    let mut scanned = 0;
    let mut blocked = 0;
    for line in lines.iter().rev().take(BLOCKED_WINDOW) {
        let Ok(entry @ Json::Object(_)) = json::parse(line.trim()) else {
            continue;
        };
        scanned += 1;
        if entry.get("decision").and_then(Json::as_str) == Some("blocked") {
            blocked += 1;
        }
    }
    // Nothing parseable is not "0 of the last 0 requests".
    (scanned > 0).then_some((blocked, scanned))
}

/// A string field of a parsed JSON object, or `""`.
fn json_field(value: &Json, key: &str) -> String {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned()
}

impl ShowReport {
    /// `running`, `stopped`, `exited` or `degraded`.
    ///
    /// The same vocabulary `cage list` uses, so the two `--json`
    /// documents agree: an interactive or ephemeral cage whose containers
    /// are all gone has *exited* — that is what its lifecycle means —
    /// while a service that is down is *stopped*. The printed `status`
    /// line is a separate concern ([`Self::status_text`]) and keeps the
    /// wording earlier releases used.
    fn state(&self) -> &'static str {
        if self.running == self.total {
            "running"
        } else if self.running == 0 {
            if self.lifecycle == "interactive" || self.lifecycle == "ephemeral" {
                "exited"
            } else {
                "stopped"
            }
        } else {
            "degraded"
        }
    }

    /// The `status` line's value, unchanged from earlier releases.
    fn status_text(&self) -> String {
        if self.running == self.total {
            format!("running ({}/{})", self.running, self.total)
        } else if self.running == 0 {
            format!("stopped (0/{})", self.total)
        } else {
            format!("degraded ({}/{})", self.running, self.total)
        }
    }

    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("name".to_owned(), Json::string(&self.name)),
            ("isolation".to_owned(), Json::string(&self.isolation)),
            ("lifecycle".to_owned(), Json::string(&self.lifecycle)),
            ("image".to_owned(), Json::string(&self.image)),
            (
                "build".to_owned(),
                self.build.as_ref().map_or(Json::Null, Json::string),
            ),
            ("version".to_owned(), Json::string(&self.version)),
            ("scaffold".to_owned(), Json::string(&self.scaffold)),
            ("status".to_owned(), self.status_json()),
            (
                "network".to_owned(),
                self.network.as_ref().map_or(Json::Null, Network::to_json),
            ),
            ("data_dir".to_owned(), Json::string(&self.data_dir)),
            ("ports".to_owned(), string_array(&self.ports)),
            ("volumes".to_owned(), string_array(&self.volumes)),
            (
                "named_volumes".to_owned(),
                Json::Array(
                    self.named_volumes
                        .iter()
                        .map(|(volume, mount)| {
                            Json::Object(vec![
                                ("name".to_owned(), Json::string(volume)),
                                ("mount".to_owned(), Json::string(mount)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("tmpfs".to_owned(), string_array(&self.tmpfs)),
            (
                "domains".to_owned(),
                self.domains
                    .as_ref()
                    .map_or(Json::Null, DomainReport::to_json),
            ),
            (
                "passthrough".to_owned(),
                self.domains.as_ref().map_or_else(
                    || Json::Array(Vec::new()),
                    |domains| string_array(&domains.passthrough),
                ),
            ),
            (
                "secrets".to_owned(),
                self.secrets
                    .as_ref()
                    .map_or(Json::Null, SecretReport::to_json),
            ),
            ("watcher".to_owned(), self.watcher.to_json()),
            (
                "recent_blocked".to_owned(),
                self.recent_blocked
                    .map_or(Json::Null, |(blocked, scanned)| {
                        Json::Object(vec![
                            ("blocked".to_owned(), integer(blocked)),
                            ("scanned".to_owned(), integer(scanned)),
                        ])
                    }),
            ),
        ])
    }

    /// The `status` object: the word, the printed line and the counts.
    fn status_json(&self) -> Json {
        Json::Object(vec![
            ("state".to_owned(), Json::string(self.state())),
            ("text".to_owned(), Json::string(self.status_text())),
            ("running".to_owned(), integer(self.running)),
            ("total".to_owned(), integer(self.total)),
        ])
    }
}

/// A `usize` as a JSON integer.
fn integer(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// A list of strings as a JSON array.
fn string_array(values: &[String]) -> Json {
    Json::Array(values.iter().map(Json::string).collect())
}

impl Network {
    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("subnet".to_owned(), Json::string(&self.subnet)),
            ("cage".to_owned(), Json::string(&self.cage)),
            ("egress".to_owned(), Json::string(&self.egress)),
        ])
    }
}

impl DomainReport {
    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("mode".to_owned(), Json::string(&self.mode)),
            ("count".to_owned(), integer(self.names.len())),
            ("names".to_owned(), string_array(&self.names)),
        ])
    }
}

impl SecretReport {
    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("expected".to_owned(), integer(self.expected)),
            ("present".to_owned(), integer(self.present)),
            (
                "missing".to_owned(),
                integer(self.expected.saturating_sub(self.present)),
            ),
            (
                "entries".to_owned(),
                Json::Array(self.entries.iter().map(SecretEntry::to_json).collect()),
            ),
        ])
    }
}

impl SecretEntry {
    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("name".to_owned(), Json::string(&self.name)),
            ("present".to_owned(), Json::Bool(self.present)),
            (
                "placeholder".to_owned(),
                if self.placeholder.is_empty() {
                    Json::Null
                } else {
                    Json::string(&self.placeholder)
                },
            ),
        ])
    }
}

impl WatcherReport {
    fn to_json(&self) -> Json {
        let mut pairs = vec![("enabled".to_owned(), Json::Bool(!self.is_disabled()))];
        match self {
            WatcherReport::Disabled => pairs.push(("state".to_owned(), Json::string("disabled"))),
            WatcherReport::NoScanYet => {
                pairs.push(("state".to_owned(), Json::string("no-scan-yet")));
            }
            WatcherReport::Unreachable => {
                pairs.push(("state".to_owned(), Json::string("unreachable")));
            }
            WatcherReport::Unreadable => {
                pairs.push(("state".to_owned(), Json::string("unreadable")));
            }
            WatcherReport::Scanned {
                last_scan,
                failed,
                findings,
            } => {
                pairs.push(("state".to_owned(), Json::string("scanned")));
                pairs.push(("last_scan".to_owned(), Json::string(last_scan)));
                pairs.push(("last_scan_failed".to_owned(), Json::Bool(*failed)));
                pairs.push(("findings_total".to_owned(), Json::Int(*findings)));
            }
        }
        Json::Object(pairs)
    }

    fn is_disabled(&self) -> bool {
        matches!(self, WatcherReport::Disabled)
    }
}

/// The human report, byte-identical to earlier releases on the lines they
/// printed, with the detail the CLI reference promises appended under
/// them as indented continuation lines.
fn render_show(report: &ShowReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Name:       {}", report.name);
    let _ = writeln!(out, "Isolation:  {}", report.isolation);
    let _ = writeln!(out, "Lifecycle:  {}", report.lifecycle);
    let _ = writeln!(out, "Image:      {}", report.image);
    if let Some(build) = &report.build {
        let _ = writeln!(out, "Build:      {build}");
    }
    let _ = writeln!(
        out,
        "Version:    {}",
        if report.version.is_empty() {
            "-"
        } else {
            &report.version
        }
    );
    let _ = writeln!(
        out,
        "Scaffold:   {}",
        if report.scaffold.is_empty() {
            "-"
        } else {
            &report.scaffold
        }
    );
    let _ = writeln!(out, "Status:     {}", report.status_text());
    if let Some(network) = &report.network {
        let _ = writeln!(
            out,
            "Network:    {} (cage {}, egress {})",
            network.subnet, network.cage, network.egress
        );
    }
    let _ = writeln!(out, "Data:       {}", report.data_dir);
    if !report.ports.is_empty() {
        let _ = writeln!(out, "Ports:      {}", report.ports.join(", "));
    }
    render_mounts(report, &mut out);
    render_domains(report.domains.as_ref(), &mut out);
    render_secrets(report.secrets.as_ref(), &mut out);
    render_watcher(&report.watcher, report.recent_blocked, &mut out);
    out
}

/// Every mount, one per line, with its flags left in the spec and its
/// kind named: `volumes` carry `:ro`/`:rw`, `named_volumes` are podman
/// volumes rather than host paths, and `tmpfs` is neither.
fn render_mounts(report: &ShowReport, out: &mut String) {
    let mut mounts: Vec<String> = report.volumes.clone();
    mounts.extend(
        report
            .named_volumes
            .iter()
            .map(|(volume, mount)| format!("{volume}:{mount} (named volume)")),
    );
    mounts.extend(report.tmpfs.iter().map(|entry| format!("{entry} (tmpfs)")));
    for (index, mount) in mounts.iter().enumerate() {
        if index == 0 {
            let _ = writeln!(out, "Volumes:    {mount}");
        } else {
            let _ = writeln!(out, "            {mount}");
        }
    }
}

/// The mode, its count, and — the part that used to be missing — the
/// names themselves.
fn render_domains(domains: Option<&DomainReport>, out: &mut String) {
    let Some(domains) = domains else {
        return;
    };
    let _ = writeln!(
        out,
        "Domains:    {} ({} domains)",
        domains.mode,
        domains.names.len()
    );
    if !domains.names.is_empty() {
        let _ = writeln!(out, "            {}", domains.names.join(", "));
    }
    if !domains.passthrough.is_empty() {
        let _ = writeln!(out, "Passthrough: {} domains", domains.passthrough.len());
        let _ = writeln!(out, "            {}", domains.passthrough.join(", "));
    }
}

/// The count line earlier releases printed, then one line per secret.
fn render_secrets(secrets: Option<&SecretReport>, out: &mut String) {
    let Some(secrets) = secrets else {
        return;
    };
    let missing = secrets.expected.saturating_sub(secrets.present);
    if missing > 0 {
        let _ = writeln!(
            out,
            "Secrets:    {}/{} ({missing} missing)",
            secrets.present, secrets.expected
        );
    } else {
        let _ = writeln!(out, "Secrets:    {}/{}", secrets.expected, secrets.expected);
    }
    for entry in &secrets.entries {
        let suffix = if entry.present {
            if entry.placeholder.is_empty() {
                String::new()
            } else {
                format!(" {}", entry.placeholder)
            }
        } else {
            " (missing)".to_owned()
        };
        let _ = writeln!(out, "            {}{suffix}", entry.name);
    }
}

/// The watcher's state and, when the capture log is readable, how many
/// of its most recent entries were blocked.
fn render_watcher(
    watcher: &WatcherReport,
    recent_blocked: Option<(usize, usize)>,
    out: &mut String,
) {
    let watcher = match watcher {
        WatcherReport::Disabled => "not enabled".to_owned(),
        WatcherReport::NoScanYet => "enabled (no scan yet)".to_owned(),
        WatcherReport::Unreachable => "enabled (scan state unavailable)".to_owned(),
        WatcherReport::Unreadable => "enabled (scan state unreadable)".to_owned(),
        WatcherReport::Scanned {
            last_scan,
            failed,
            findings,
        } => format!(
            "enabled (last scan {last_scan}, {findings} findings{})",
            if *failed { ", last scan FAILED" } else { "" }
        ),
    };
    let _ = writeln!(out, "Watcher:    {watcher}");
    if let Some((blocked, scanned)) = recent_blocked {
        let _ = writeln!(
            out,
            "Blocked:    {blocked} of the last {scanned} captured requests"
        );
    }
}

/// The `schema_version` shared by this port's read-command JSON
/// envelopes.
const READ_SCHEMA_VERSION: i64 = 1;

/// `{schema_version, command, ok, data, warnings}` — the envelope every
/// read command's `--json` uses.
fn envelope(command: &str, data: Json, warnings: Vec<String>) -> Json {
    Json::Object(vec![
        ("schema_version".to_owned(), Json::Int(READ_SCHEMA_VERSION)),
        ("command".to_owned(), Json::string(command)),
        ("ok".to_owned(), Json::Bool(true)),
        ("data".to_owned(), data),
        (
            "warnings".to_owned(),
            Json::Array(warnings.into_iter().map(Json::string).collect()),
        ),
    ])
}

/// Write one JSON document and a newline, with the two-space indent the
/// other JSON writers in this port use.
fn print_json(document: &Json) {
    println!("{}", json::dumps(document, DumpOptions::indented()));
}

/// `cage stop` — stop both units without destroying anything.
///
/// Here rather than in PR D7 for the same reason the four above are
/// here: **e2e phase 6** tears the `e2e-mask` cage down with it, and
/// that teardown is what makes the `/workspace/.git/hooks` tmpfs
/// vanish — the exact thing 6.11 is measuring. A `cage stop` that
/// exits `EX_SOFTWARE` leaves the mask standing and the assertion
/// meaningless.
pub(crate) fn stop(ctx: &Ctx, name: &str) -> ExitCode {
    match stop_inner(ctx, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn stop_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    // A legacy cage is refused here and *not* in `destroy` — stopping
    // one would address units that no longer exist under these names,
    // while destroy is the documented way out.
    let config = addressable(ctx, name, "cage stop")?;
    ctx.backend_for(&config.isolation).stop(name);
    println!("Stopped cage '{name}'");
    Ok(())
}

/// `cage start` — bring a stopped cage back up.
///
/// `cli.py:2107`. It is not `backend.start` with a gate in front of it:
/// four things are refreshed first, and each one exists because the
/// cage was editable while it was down.
///
/// 1. **The nested-podman patch tree** is re-copied from the embedded
///    assets, overwriting whatever is in the work directory. `cage
///    create` and `cage restart` both do it; a `start` that did not
///    would be the one way to boot a cage against a tampered shim.
/// 2. **`env:` and `cmd:` secrets are re-resolved** into the podman
///    store. The value behind `env:GITHUB_TOKEN` is whatever the
///    operator's environment says *now*, and the quadlet's `Secret=`
///    directives resolve at container creation — so a stale store
///    boots the cage with last week's token. Strict, as at create: a
///    resolution failure aborts the start rather than launching a
///    container whose `Secret=` names nothing.
/// 3. **`proxy-config.yaml`** (and, through it,
///    `cage-env/placeholders.env`) and **`dns-allowlist.conf`** are
///    regenerated from `cage.yaml`, so an edit made while the cage was
///    stopped applies on this boot. Neither is baked into a unit file,
///    which is why no quadlet regeneration and no `daemon-reload` is
///    needed here.
/// 4. **The backend's prerequisites** are checked, which is
///    `_ensure_backend_ready` — the diagnostics that turn a downed
///    podman into a named prerequisite rather than an "image not
///    found" three steps later.
pub(crate) fn start(ctx: &Ctx, name: &str) -> ExitCode {
    match start_inner(ctx, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn start_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    let config = addressable(ctx, name, "cage start")?;

    if let Err(error) = agentcage_cli::services::ensure_patches(&ctx.paths) {
        eprintln!("error: {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    // Container mode only, as in `cage create` and `run`: the vm and
    // apple-container backends materialize their own secrets at start,
    // and on a macOS host there is no podman store to populate.
    if config.isolation == "container" {
        let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
        let env = agentcage_cli::secrets::SystemEnv;
        let host = agentcage_cli::secrets::SecretHost::detect(ctx.runner.as_ref(), &env);
        if let Err(error) = host.resolve_and_populate(
            &podman,
            &config,
            name,
            &ctx.paths.deployment_dir(name),
            &std::collections::BTreeSet::new(),
            true,
        ) {
            eprintln!("error: {}", error.message());
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }

    ctx.paths
        .save_proxy_config(name, &ctx.version)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    ctx.paths
        .save_dns_allowlist(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;

    let backend = ctx.ensure_backend_ready(&config)?;
    backend.start(name, false).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    println!("Started cage '{name}'");
    Ok(())
}

/// Steps 1–3 of the preamble every command in this module shares: the
/// cage exists, it is not a v0.21 cage, and its backend is one this
/// port can address. Returns the stored config, which every caller
/// wants next anyway.
///
/// `verb` names the command in the Track E refusal, so `cage start` on
/// an `apple-container` cage says `cage start` and not the name of
/// whichever helper happened to notice.
fn addressable(
    ctx: &Ctx,
    name: &str,
    verb: &str,
) -> Result<agentcage_core::config::Config, ExitCode> {
    if !ctx.paths.deployment_exists(name) {
        eprintln!("error: cage '{name}' does not exist");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ensure_v022_cage(&ctx.paths, name)?;
    let config = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    if let Some(refusal) = AnyBackend::refusal(&config.isolation, verb) {
        eprintln!("{refusal}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    Ok(config)
}
/// `cage restart` — restart the services without rebuilding anything.
///
/// `cli.py:1803`. PR D7's command; it is here because **e2e phase 3**
/// needs it (3.3b proves a placeholder edit applies on a plain restart,
/// with no `cage update`; 3.5c proves the cage still boots after a
/// `secret rm`) and because the same `_restart_cage` is already the
/// fallback half of this PR's live-apply path.
///
/// The patch files are re-copied from the embedded assets first, which
/// overwrites any tampering — the same thing `cage create` does.
pub(crate) fn restart(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    match restart_inner(ctx, &name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn restart_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    let _config = addressable(ctx, name, "cage restart")?;
    if let Err(error) = agentcage_cli::services::ensure_patches(&ctx.paths) {
        eprintln!("error: {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    crate::cli::secret::live::restart(ctx, name);
    println!("Restarted cage '{name}'");
    Ok(())
}

/// `cage destroy` — stop, remove quadlets, podman resources and state.
pub(crate) fn destroy(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let yes = matches.get_flag("yes");
    let keep_secrets = matches.get_flag("keep_secrets");

    if !yes {
        let mut detail = "This will stop containers, remove quadlets, and state.".to_owned();
        detail.push_str(if keep_secrets {
            " Scoped secrets will be kept."
        } else {
            " Scoped secrets will also be removed."
        });
        if !confirm(&format!("Destroy cage \"{name}\"? {detail}")) {
            // `click.confirm(..., abort=True)` raises `Abort`, which
            // click renders as this line and exit 1.
            eprintln!("Aborted!");
            return ExitCode::from(EXIT_FAILURE);
        }
    }

    // Remove a pre-rework grants watcher BEFORE stopping the cage, so a
    // vm cage's in-guest cleanup can still run.
    if ctx.paths.deployment_exists(&name)
        && let Ok(config) = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
    {
        agentcage_cli::legacy_watcher::remove_legacy_grants_watcher(
            ctx.runner.as_ref(),
            &config.name,
            &config.isolation,
        );
    }

    let removed = destroy_cage(ctx, &name, keep_secrets, true);

    println!();
    if removed.is_empty() {
        println!("Nothing to remove (cage \"{name}\" not found).");
    } else {
        println!("Removed:");
        for item in &removed {
            println!("  {item}");
        }
    }
    print_kept(&ctx.paths, &name);
    ExitCode::SUCCESS
}

/// Print the `Kept:` block: the per-cage data directory `destroy` does
/// not remove, and what is still in it (#423).
///
/// The deployment and the data directory are different things. The
/// former is what `destroy` removes; the latter holds the grants
/// overlay, the capture log, the policy audit trail and the timing
/// ledger, and outliving the cage is the point — deleting the audit
/// trail on `destroy` would make it erasable by the command that
/// removes the evidence of why it mattered. That decision stands;
/// what was wrong is that the command did not say so, and that the
/// list it said it with was hard-coded.
///
/// **The inventory is read off the directory and not asserted.** It is
/// taken *after* the teardown, so what it names is what actually
/// survived it, and there is no block at all when the directory is not
/// there. Two things that were wrong when this was a fixed sentence:
///
/// * `capture/` is the container and vm backend's log. An
///   `apple-container` cage writes `capture.jsonl` under
///   `~/.config/agentcage/apple-container/<name>/logs/`, which is the
///   apple state tree `destroy` removes (see
///   `agentcage_state::Paths::apple_capture_file` and
///   `har::capture_path`), so naming `capture/` there claimed to keep
///   a log that had just been deleted. The deploy still creates the
///   host `capture/` directory for every backend, but on apple it is
///   empty; empty directories are skipped, see below.
/// * `inspectors/` is staged deployment content, removed by
///   `remove_deployment`, so it must not be named as data that stayed.
///   Reading the directory after the teardown covers it without a
///   special case, and also covers the one path that does leave it
///   behind: destroy on a name with neither a stored config nor
///   backend resources.
///
/// A directory that holds nothing is skipped: `grants/` created at
/// deploy time but never written, or apple's empty `capture/`, keeps
/// no data and naming it would only suggest it did. The path line is
/// still printed either way — it is what the operator has to remove by
/// hand — and a `Kept:` heading over an otherwise empty directory is
/// the truth, not noise.
fn print_kept(paths: &Paths, name: &str) {
    let data = paths.cage_data_dir(name);
    if !data.is_dir() {
        return;
    }
    println!("Kept:");
    println!("  data:{}", data.display());
    let entries = kept_entries(&data);
    if !entries.is_empty() {
        println!("  left in place: {}", entries.join(", "));
    }
}

/// The top-level entries of the data directory that hold something,
/// as names to print: a directory gets a trailing `/`, a file does
/// not.
///
/// Sorted, because the order of a `read_dir` is the filesystem's and
/// this output is pinned by a test. An entry whose metadata or
/// directory cannot be read is skipped rather than reported: the
/// block's whole point is not to name anything the operator cannot
/// find.
fn kept_entries(data: &std::path::Path) -> Vec<String> {
    let mut entries: Vec<String> = std::fs::read_dir(data)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| holds_data(path))
        .filter_map(|path| {
            let name = path.file_name()?.to_string_lossy().into_owned();
            Some(if path.is_dir() {
                format!("{name}/")
            } else {
                name
            })
        })
        .collect();
    entries.sort();
    entries
}

/// Whether `path` keeps anything: a file always does, a directory only
/// when it has an entry of its own.
///
/// A directory that cannot be read answers *no* — see
/// [`kept_entries`].
fn holds_data(path: &std::path::Path) -> bool {
    !path.is_dir() || std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
}

/// Stop, destroy, forget.
///
/// When the stored config cannot be loaded the fallback is simply the
/// container backend: its `has_resources` is a filesystem check and
/// its podman calls already tolerate a podman that cannot be run.
fn destroy_cage(ctx: &Ctx, name: &str, keep_secrets: bool, echo: bool) -> Vec<String> {
    let backend = ctx.backend_of(name);
    let known = ctx.paths.deployment_exists(name);
    if !known && !backend.has_resources(name) {
        if echo {
            println!("Nothing to remove for '{name}' (no stored config and no backend resources).");
        }
        return Vec::new();
    }

    if echo {
        println!("Stopping services...");
    }
    backend.stop(name);

    if echo {
        println!("Removing resources...");
    }
    let mut removed = backend
        .destroy_resources(name, keep_secrets)
        .unwrap_or_else(|error| {
            eprintln!("warning: {error}");
            Vec::new()
        });

    if ctx.paths.deployment_exists(name) {
        let removal = if keep_secrets {
            ctx.paths.remove_deployment_keeping_secrets(name)
        } else {
            ctx.paths.remove_deployment(name)
        };
        if let Err(error) = removal {
            eprintln!("warning: {error}");
        } else {
            removed.push(format!("state:{name}"));
        }
    }
    removed
}

/// `cage prune` — remove every *exited* interactive or ephemeral cage.
///
/// `cli.py:1445`. Three filters decide the candidate list, and all
/// three matter:
///
/// * **Lifecycle.** Only `interactive` and `ephemeral` cages are
///   prunable. A `service` cage that happens to be down is down on
///   purpose — `cage stop` is a thing operators do — and removing it
///   would be indistinguishable from data loss. The lifecycle is read
///   from metadata first, falling back to `cage.yaml`, because `cage
///   run` records the lifecycle it actually deployed with.
/// * **Version.** A v0.21 cage is skipped, not refused: its containers
///   are named `<name>-proxy` / `<name>-dns`, so probing the v0.22
///   shape would answer "not running" for a *live* legacy cage and
///   prune it out from under its workload. The operator destroys those
///   by name. This is the third exemption from the v0.21 gate and the
///   only one that is silent — `list` annotates, `destroy` proceeds,
///   `prune` walks past.
/// * **Running.** Zero of the cage's services up.
///
/// The teardown itself is `destroy`'s, run with its narration
/// suppressed, so a ten-cage prune
/// prints ten `Removing <name>...` lines rather than thirty. A failure
/// on one cage warns and continues — a prune that stops at the first
/// stuck cage leaves the rest of the list uncollected.
pub(crate) fn prune(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let yes = matches.get_flag("yes");
    let mut candidates: Vec<String> = Vec::new();

    for name in ctx.paths.list_deployments().unwrap_or_default() {
        let Ok(config) = ctx
            .paths
            .load_deployment_config(&name, &agentcage_cli::hostenv::RealHost)
        else {
            continue;
        };
        // Track E. Only a backend this port can probe: an
        // apple-container cage answered by the container backend would
        // read as exited while it is up, and prune acts on that answer.
        if AnyBackend::refusal(&config.isolation, "cage prune").is_some() {
            continue;
        }
        let metadata = ctx
            .paths
            .load_metadata(&name)
            .unwrap_or_else(|_| Json::Object(Vec::new()));
        let lifecycle = string_or(&metadata, "lifecycle", &config.lifecycle);
        if lifecycle != "interactive" && lifecycle != "ephemeral" {
            continue;
        }
        let version = string_or(&metadata, "agentcage_version", "0.0.0");
        let version = if version.is_empty() {
            "0.0.0".to_owned()
        } else {
            version
        };
        if parse_version(&version) < (0, 22) {
            continue;
        }
        if ctx.backend_for(&config.isolation).running_count(&name).0 == 0 {
            candidates.push(name);
        }
    }

    if candidates.is_empty() {
        println!("Nothing to prune.");
        return ExitCode::SUCCESS;
    }

    println!("The following exited cages will be removed:");
    for name in &candidates {
        println!("  {name}");
    }

    if !yes && !confirm(&format!("\nRemove {} cage(s)?", candidates.len())) {
        eprintln!("Aborted!");
        return ExitCode::from(EXIT_FAILURE);
    }

    for name in &candidates {
        println!("Removing {name}...");
        destroy_cage(ctx, name, false, false);
        // The teardown is destroy's, so the retention notice is too.
        // Silent here would leave a prune of ten cages claiming to have
        // removed ten data directories it did not touch (#423).
        print_kept(&ctx.paths, name);
    }
    println!("Pruned {} cage(s).", candidates.len());
    ExitCode::SUCCESS
}

/// `click.confirm` — `[y/N]`, default no, EOF is no.
fn confirm(prompt: &str) -> bool {
    use std::io::{BufRead as _, Write as _};

    let mut out = std::io::stdout();
    let _ = write!(out, "{prompt} [y/N]: ");
    let _ = out.flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// `cli._read_domain_config`, reduced to what `cage show` prints: the
/// mode, the active domain names, and the passthrough names.
///
/// Both the current `allow`/`block` shape and the legacy `mode` +
/// `list` one, because a cage deployed by an older agentcage still has
/// the legacy keys on disk and §2.7 forbids a migration step.
fn read_domain_config(raw: &agentcage_core::yaml::Value) -> DomainReport {
    let domains = raw.get("domains");
    let sequence = |key: &str| -> Vec<String> {
        domains
            .and_then(|d| d.get(key))
            .and_then(|v| v.as_sequence())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let has = |key: &str| domains.is_some_and(|d| d.get(key).is_some());
    let passthrough = sequence("passthrough");
    if has("allow") {
        return DomainReport {
            mode: "allowlist".to_owned(),
            names: sequence("allow"),
            passthrough,
        };
    }
    if has("block") {
        return DomainReport {
            mode: "blocklist".to_owned(),
            names: sequence("block"),
            passthrough,
        };
    }
    let mode = domains
        .and_then(|d| d.get("mode"))
        .and_then(agentcage_core::yaml::Value::as_str)
        .unwrap_or("allowlist")
        .to_owned();
    DomainReport {
        mode,
        names: sequence("list"),
        passthrough,
    }
}

/// `meta.get(key, fallback)` for a string-valued metadata entry.
fn string_or(metadata: &Json, key: &str, fallback: &str) -> String {
    metadata
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

/// The count `cage list` and `cage show` both print, exposed so
/// `cage verify` can agree with them.
#[must_use]
pub(crate) fn service_status(backend: &AnyBackend<'_>, name: &str) -> Vec<(String, bool)> {
    SERVICE_NAMES
        .iter()
        .map(|service| ((*service).to_owned(), backend.is_running(name, service)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{
        ListRow, envelope, gather_show, list_row, mask_placeholder, read_domain_config,
        recent_blocked, render_show,
    };
    use crate::cli::context::Ctx;
    use agentcage_core::har::json::{self, Json};
    use agentcage_exec::{FakeRunner, Reply};
    use agentcage_state::{Paths, TestDir};

    /// A deployed container cage with every detail `show` now reports.
    const CAGE_YAML: &str = "\
name: acme
isolation: container
lifecycle: service
container:
  image: node:22-slim
  ports:
    - \"127.0.0.1:8080:8080\"
  volumes:
    - \"/host/workspace:/workspace:ro\"
  named_volumes:
    acme-data: /var/lib/acme
  tmpfs:
    - \"/tmp:size=64m\"
domains:
  allow:
    - api.example.com
    - github.com
  passthrough:
    - telemetry.example.com
secret_injection:
  - env: API_KEY
    placeholder: \"agentcage:secret:API_KEY:0123456789abcdef0123456789abcdef\"
    source: \"env:API_KEY\"
";

    fn ctx(dir: &TestDir, fake: FakeRunner) -> Ctx {
        Ctx {
            paths: Paths::under(dir.path()),
            runner: Box::new(fake),
            version: "9.9.9".to_owned(),
        }
    }

    /// Write the stored config and the v0.22 metadata stamp `show` reads.
    fn deploy(ctx: &Ctx, name: &str, octet: u32) {
        let dir = ctx.paths.deployment_dir(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(ctx.paths.stored_config_path(name), CAGE_YAML).unwrap();
        std::fs::write(
            dir.join("metadata.json"),
            format!(
                "{{\"agentcage_version\": \"0.53.1\", \"lifecycle\": \"service\", \
                 \"scaffold\": \"openclaw\", \"network_octet\": {octet}}}"
            ),
        )
        .unwrap();
    }

    /// A fake that answers nothing, then the secret store's one query.
    fn fake() -> FakeRunner {
        let fake = FakeRunner::new();
        fake.assume_missing();
        fake.default_reply(Reply::NotFound);
        fake.on(
            ["podman", "secret", "ls"],
            Reply::ok("acme.API_KEY\nacme.ORPHAN\n"),
        );
        fake
    }

    /// The lines the CLI reference promises, without losing the ones
    /// earlier releases printed.
    #[test]
    fn show_names_the_network_volumes_domains_and_secrets() {
        let dir = TestDir::new("show-enriched");
        let ctx = ctx(&dir, fake());
        deploy(&ctx, "acme", 42);

        let report = gather_show(&ctx, "acme").unwrap();
        let text = render_show(&report);

        assert!(text.contains("Name:       acme\n"), "{text}");
        assert!(text.contains("Lifecycle:  service\n"), "{text}");
        assert!(text.contains("Scaffold:   openclaw\n"), "{text}");
        // The persisted octet, not a re-derivation.
        assert!(
            text.contains("Network:    10.89.42.0/24 (cage 10.89.42.2, egress 10.89.42.10)\n"),
            "{text}"
        );
        assert!(text.contains("Data:       "), "{text}");
        assert!(text.contains("Ports:      127.0.0.1:8080:8080\n"), "{text}");
        // The mount flags survive in the spec, and each kind is named.
        assert!(
            text.contains("Volumes:    /host/workspace:/workspace:ro\n"),
            "{text}"
        );
        assert!(
            text.contains("            acme-data:/var/lib/acme (named volume)\n"),
            "{text}"
        );
        assert!(
            text.contains("            /tmp:size=64m (tmpfs)\n"),
            "{text}"
        );
        assert!(
            text.contains("Domains:    allowlist (2 domains)\n"),
            "{text}"
        );
        assert!(
            text.contains("            api.example.com, github.com\n"),
            "{text}"
        );
        assert!(text.contains("Passthrough: 1 domains\n"), "{text}");
        assert!(
            text.contains("            telemetry.example.com\n"),
            "{text}"
        );
        assert!(text.contains("Secrets:    1/1\n"), "{text}");
        assert!(
            text.contains("            API_KEY agentcage:secret:API_KEY:****\n"),
            "{text}"
        );
        assert!(text.contains("Watcher:    not enabled\n"), "{text}");
    }

    /// The placeholder is a decoy, but its random suffix is a generation
    /// identifier: `show` names the rule without printing the token.
    #[test]
    fn placeholders_are_masked_and_real_values_never_appear() {
        assert_eq!(
            mask_placeholder("agentcage:secret:API_KEY:0123456789abcdef"),
            "agentcage:secret:API_KEY:****"
        );
        assert_eq!(mask_placeholder("{{API_KEY}}"), "****");
        assert_eq!(mask_placeholder(""), "");
        assert!(
            !mask_placeholder("agentcage:secret:API_KEY:0123456789abcdef")
                .contains("0123456789abcdef")
        );
    }

    /// `cage list` calls a stopped interactive or ephemeral cage
    /// `exited`, and `show` must agree: both `--json` documents use one
    /// vocabulary. The printed `status.text` keeps the old wording.
    #[test]
    fn show_json_state_matches_list_for_an_interactive_cage() {
        let dir = TestDir::new("show-json-exited");
        let ctx = ctx(&dir, fake());
        deploy(&ctx, "acme", 3);
        // Same cage, interactive lifecycle: metadata is what both
        // commands read it from.
        std::fs::write(
            ctx.paths.deployment_dir("acme").join("metadata.json"),
            "{\"agentcage_version\": \"0.53.1\", \"lifecycle\": \"interactive\", \
             \"scaffold\": \"openclaw\", \"network_octet\": 3}",
        )
        .unwrap();

        let report = gather_show(&ctx, "acme").unwrap();
        let json = report.to_json();
        let status = json.get("status").expect("status");
        assert_eq!(status.get("state").and_then(Json::as_str), Some("exited"));
        // Byte-identical to the line earlier releases printed.
        assert_eq!(
            status.get("text").and_then(Json::as_str),
            Some("stopped (0/2)")
        );
        assert_eq!(status.get("running"), Some(&Json::Int(0)));
        assert_eq!(status.get("total"), Some(&Json::Int(2)));

        // And the same word `cage list --json` uses for the same cage.
        assert_eq!(list_row(&ctx, "acme").state, "exited");
    }

    /// The JSON envelope is the same one every read command uses, and its
    /// data carries the same facts as the text.
    #[test]
    fn show_json_uses_the_read_envelope() {
        let dir = TestDir::new("show-json");
        let ctx = ctx(&dir, fake());
        deploy(&ctx, "acme", 7);

        let report = gather_show(&ctx, "acme").unwrap();
        let document = envelope("cage show", report.to_json(), report.warnings.clone());
        let rendered = json::dumps(&document, json::DumpOptions::indented());
        let parsed = json::parse(&rendered).expect("valid JSON");

        assert_eq!(parsed.get("schema_version"), Some(&Json::Int(1)));
        assert_eq!(
            parsed.get("command").and_then(Json::as_str),
            Some("cage show")
        );
        assert_eq!(parsed.get("ok"), Some(&Json::Bool(true)));
        assert_eq!(
            parsed.get("warnings"),
            Some(&Json::Array(Vec::new())),
            "a healthy fixture must not warn"
        );

        let data = parsed.get("data").expect("data");
        assert_eq!(data.get("name").and_then(Json::as_str), Some("acme"));
        assert_eq!(
            data.get("status")
                .and_then(|s| s.get("state"))
                .and_then(Json::as_str),
            Some("stopped")
        );
        let network = data.get("network").expect("network");
        assert_eq!(
            network.get("subnet").and_then(Json::as_str),
            Some("10.89.7.0/24")
        );
        let domains = data.get("domains").expect("domains");
        assert_eq!(
            domains.get("names"),
            Some(&Json::Array(vec![
                Json::string("api.example.com"),
                Json::string("github.com"),
            ]))
        );
        let secrets = data.get("secrets").expect("secrets");
        assert_eq!(secrets.get("present"), Some(&Json::Int(1)));
        let Json::Array(entries) = secrets.get("entries").expect("entries") else {
            panic!("entries is not an array");
        };
        let entry = &entries[0];
        assert_eq!(
            entry.get("placeholder").and_then(Json::as_str),
            Some("agentcage:secret:API_KEY:****")
        );
        assert!(
            !rendered.contains("0123456789abcdef"),
            "the token leaked into JSON"
        );
    }

    /// A cage with no `network_octet` in metadata still reports the
    /// hash-derived addresses the renderer would use.
    #[test]
    fn a_legacy_metadata_octet_falls_back_to_the_hash() {
        let dir = TestDir::new("show-legacy-octet");
        let ctx = ctx(&dir, fake());
        let cage_dir = ctx.paths.deployment_dir("acme");
        std::fs::create_dir_all(&cage_dir).unwrap();
        std::fs::write(ctx.paths.stored_config_path("acme"), CAGE_YAML).unwrap();
        std::fs::write(
            cage_dir.join("metadata.json"),
            "{\"agentcage_version\": \"0.53.1\"}",
        )
        .unwrap();

        let report = gather_show(&ctx, "acme").unwrap();
        let expected = agentcage_core::quadlets::cage_network_addrs("acme", None, None).unwrap();
        assert_eq!(report.network.expect("network").subnet, expected.subnet);
    }

    /// `cage list --json` rows carry the same status the table prints.
    #[test]
    fn list_rows_render_both_ways() {
        let dir = TestDir::new("list-json");
        let ctx = ctx(&dir, fake());
        deploy(&ctx, "acme", 3);

        let row = list_row(&ctx, "acme");
        assert_eq!(row.name, "acme");
        assert_eq!(row.scaffold, "openclaw");
        assert_eq!(row.status, "stopped (0/2)");
        assert_eq!(row.state, "stopped");
        assert_eq!(row.running, Some(0));

        let json = row.to_json();
        assert_eq!(json.get("name").and_then(Json::as_str), Some("acme"));
        assert_eq!(json.get("state").and_then(Json::as_str), Some("stopped"));
        assert_eq!(json.get("total"), Some(&Json::Int(2)));
        assert_eq!(json.get("legacy"), Some(&Json::Bool(false)));

        // A cage whose config will not parse is a row, not an error —
        // and it says so in both forms.
        let broken = ListRow {
            name: "broken".to_owned(),
            lifecycle: "?".to_owned(),
            isolation: "?".to_owned(),
            scaffold: "-".to_owned(),
            status: "unknown (config error)".to_owned(),
            state: "unknown",
            running: None,
            total: None,
            legacy: false,
        };
        assert_eq!(broken.to_json().get("running"), Some(&Json::Null));
    }

    /// The legacy `mode` + `list` document still names its entries.
    #[test]
    fn the_legacy_domain_shape_still_lists_its_domains() {
        let raw =
            agentcage_core::yaml::load("domains:\n  mode: allowlist\n  list: [a.example.com]\n")
                .unwrap();
        let domains = read_domain_config(&raw);
        assert_eq!(domains.mode, "allowlist");
        assert_eq!(domains.names, ["a.example.com"]);
        assert!(domains.passthrough.is_empty());
    }

    /// An unreadable watcher state is a warning, not a silent state
    /// word: `show --json`'s `warnings` is where a consumer learns the
    /// command could not read something.
    #[test]
    fn an_unreadable_watcher_state_warns() {
        let dir = TestDir::new("show-watcher-unreadable");
        let ctx = ctx(&dir, fake());
        let cage_dir = ctx.paths.deployment_dir("acme");
        std::fs::create_dir_all(&cage_dir).unwrap();
        std::fs::write(
            ctx.paths.stored_config_path("acme"),
            "name: acme\nisolation: container\nlifecycle: service\n\
             container:\n  image: node:22-slim\n\
             agents:\n  watcher:\n    enable: true\n",
        )
        .unwrap();
        std::fs::write(
            cage_dir.join("metadata.json"),
            "{\"agentcage_version\": \"0.53.1\"}",
        )
        .unwrap();
        let watcher_dir = ctx.paths.grants_dir("acme").join("watcher");
        std::fs::create_dir_all(&watcher_dir).unwrap();
        std::fs::write(watcher_dir.join("state.json"), "not json").unwrap();

        let report = gather_show(&ctx, "acme").unwrap();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(
            report.warnings[0].contains("scan state"),
            "{:?}",
            report.warnings
        );
        let text = render_show(&report);
        assert!(
            text.contains("Watcher:    enabled (scan state unreadable)\n"),
            "{text}"
        );
    }

    /// A capture tail is counted, not read whole, and the torn first line
    /// of a partial read is not mistaken for an entry.
    #[test]
    fn recent_blocked_counts_the_tail_of_the_capture() {
        let dir = TestDir::new("show-blocked");
        let path = dir.path().join("capture.jsonl");
        let mut text = String::new();
        for decision in ["allowed", "blocked", "allowed", "blocked"] {
            let _ = writeln!(text, "{{\"decision\": \"{decision}\"}}");
        }
        std::fs::write(&path, text).unwrap();

        assert_eq!(recent_blocked(&path), Some((2, 4)));
        assert_eq!(recent_blocked(&dir.path().join("absent.jsonl")), None);
    }

    /// An entry larger than the first chunk must not hide itself.
    ///
    /// Capture entries carry request and response bodies
    /// (`capture.max_body_size` defaults to 10 MiB), so a fixed 256 KiB
    /// tail read started *inside* the newest entry, discarded it as
    /// torn, and answered `recent_blocked: null` — or `Blocked: 0 of
    /// the last N` — for a log whose last request was blocked.
    #[test]
    fn a_blocked_entry_larger_than_the_first_chunk_is_counted() {
        let dir = TestDir::new("show-blocked-big-entry");
        let path = dir.path().join("capture.jsonl");
        let mut text = String::new();
        let _ = writeln!(
            text,
            "{{\"decision\": \"blocked\", \"body\": \"{}\"}}",
            "x".repeat(300 * 1024)
        );
        let _ = writeln!(text, "{{\"decision\": \"allowed\"}}");
        assert!(text.len() > 256 * 1024, "the fixture must exceed the tail");
        std::fs::write(&path, text).unwrap();

        // The one-shot 256 KiB read answered `(0, 1)` here: the giant
        // entry was the torn first line, and only the following entry
        // was left.
        assert_eq!(recent_blocked(&path), Some((1, 2)));
    }

    /// A chunk that begins exactly on a line boundary keeps its first
    /// line. The old code dropped it whenever the read started past
    /// zero, which is not the same thing.
    #[test]
    fn a_chunk_starting_on_a_line_boundary_keeps_its_first_line() {
        let dir = TestDir::new("show-blocked-boundary");
        let path = dir.path().join("capture.jsonl");

        // The last 256 KiB of the file must begin right after a newline,
        // and hold one whole (parseable) entry.
        let prefix = "{\"decision\": \"blocked\"}\n";
        let entry = "{\"decision\": \"allowed\", \"body\": \"\"}";
        let padding = 256 * 1024 - 1 - entry.len();
        let text = format!(
            "{prefix}{{\"decision\": \"allowed\", \"body\": \"{}\"}}\n",
            "x".repeat(padding)
        );
        assert_eq!(text.len(), prefix.len() + 256 * 1024);
        std::fs::write(&path, text).unwrap();

        assert_eq!(recent_blocked(&path), Some((1, 2)));
    }

    /// A line that does not parse is not a request: the denominator is
    /// the number of entries looked at, not the number of lines.
    #[test]
    fn unparseable_lines_are_not_counted_as_requests() {
        let dir = TestDir::new("show-blocked-garbage");
        let path = dir.path().join("capture.jsonl");
        std::fs::write(
            &path,
            "{\"decision\": \"blocked\"}\nnot json\n{\"decision\": \"allowed\"}\n",
        )
        .unwrap();

        assert_eq!(recent_blocked(&path), Some((1, 2)));
    }
}
