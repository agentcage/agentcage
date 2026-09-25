//! `agentcage domain <command>` — the cage's DNS/L7 filter list.

use clap::Command;

use clap::Arg;

use crate::cli::args::{TEXT, aliases_section, cage_name, flag, group, leaf, value_opt};

/// `domain add`'s docstring, verbatim from `cli.py`.
const ADD_LONG: &str = "\
Add one or more domains to a cage's filter list.

Multiple domains may be passed; the cage is reloaded at most once.
With ``--expires-in`` the entry is time-limited (allowlist mode only):
it works until its TTL elapses, then the proxy blocks it at L7 and the
next reconcile (``cage grants <name> sync``, which also runs implicitly
from the CLI paths that read a cage) prunes it from the allowlist +
dnsmasq. Permanent by default.";

/// The `domain` group.
pub(crate) fn command() -> Command {
    group("domain")
        .about("Manage cage domain filters.")
        .after_help(aliases_section(&[("ls", "list")]))
        .subcommand(add_command())
        .subcommand(
            leaf("list")
                .alias("ls")
                .about("List domains for a cage.")
                .arg(cage_name()),
        )
        .subcommand(rm_command())
}

/// `domain add NAME DOMAIN_NAMES...` — the only variadic that is both
/// required and not a passthrough.
fn add_command() -> Command {
    leaf("add")
        .about("Add one or more domains to a cage's filter list.")
        .long_about(ADD_LONG)
        .arg(cage_name())
        .arg(
            Arg::new("domain_names")
                .required(true)
                .num_args(1..)
                .value_name("DOMAIN_NAMES"),
        )
        .arg(flag(
            "passthrough",
            "passthrough",
            "Also add to TLS passthrough list (no MITM interception).",
        ))
        .arg(value_opt(
            "expires_in",
            "expires-in",
            TEXT,
            "Time-limit the entry: e.g. 30m, 1h, 2d (or a bare number of seconds). After it expires the domain is blocked at the proxy and pruned from the allowlist. Useful for a one-off task like `npm install`. Only valid in allowlist mode.",
        ))
}

/// `domain rm NAME DOMAIN_NAME` — singular, unlike `add`.
fn rm_command() -> Command {
    leaf("rm")
        .about("Remove a domain from a cage's filter list.")
        .arg(cage_name())
        .arg(
            Arg::new("domain_name")
                .required(true)
                .value_name("DOMAIN_NAME"),
        )
        .arg(flag(
            "passthrough",
            "passthrough",
            "Remove only from passthrough list (keep in allow/block).",
        ))
}

// ── bodies ───────────────────────────────────────────────────
//
// PR D10. `cli.py:4129-4614`: the three commands, the raw-document
// helpers they share with the grants reconcile, and the live-reload
// chain both ends of that pair run.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::process::ExitCode;

use agentcage_core::config::{LabelPolicy, valid_domain};
use agentcage_core::har::datetime::DateTime;
use agentcage_core::har::json::Json;
use agentcage_core::yaml::{Mapping, Sequence, Value};
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};

/// `cli._read_domain_config` — `(mode, list, passthrough)` from the
/// raw document.
///
/// Both the current `allow`/`block` shape and the legacy `mode` +
/// `list` one; §2.7 forbids a migration step, so a cage deployed by an
/// older agentcage still has the legacy keys on disk and this is where
/// they are understood.
pub(crate) fn read_domain_config(raw: &Value) -> (String, Vec<String>, Vec<String>) {
    let domains = raw.get("domains");
    let strings = |key: &str| -> Vec<String> {
        domains
            .and_then(|d| d.get(key))
            .and_then(Value::as_sequence)
            .map(|items| items.iter().map(scalar_str).collect())
            .unwrap_or_default()
    };
    let has = |key: &str| domains.is_some_and(|d| d.get(key).is_some());
    let passthrough = strings("passthrough");
    if has("allow") {
        return ("allowlist".to_owned(), strings("allow"), passthrough);
    }
    if has("block") {
        return ("blocklist".to_owned(), strings("block"), passthrough);
    }
    let mode = domains
        .and_then(|d| d.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("allowlist")
        .to_owned();
    (mode, strings("list"), passthrough)
}

/// `str(value)` for the scalars a `domains:` list can hold.
///
/// Python interpolates whatever is in the list straight into its
/// messages, so a `domains.allow` entry written as a bare number is
/// printed as a number rather than dropped. Nothing downstream accepts
/// one — `valid_domain` rejects it — but `domain list` still has to
/// show the operator what is in their file.
pub(crate) fn scalar_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        _ => String::new(),
    }
}

/// The top-level mapping of a raw `cage.yaml`, mutable.
///
/// `load_raw_config` already folds a falsy document to `{}`, so the
/// only way this is not a mapping is a `cage.yaml` whose top level is a
/// list or a scalar. The Python would raise `TypeError` deep inside
/// `_ensure_domain_section`; replacing it with an empty mapping reaches
/// the same place through a message the operator can act on, and the
/// state corpus has no such file for the difference to be visible in.
fn top_mut(raw: &mut Value) -> &mut Mapping {
    if raw.as_mapping().is_none() {
        *raw = Value::Mapping(Mapping::new());
    }
    raw.as_mapping_mut().expect("just made one")
}

/// `cli._ensure_domain_section` — a `domains:` block with an `allow`
/// or `block` key, migrating the legacy `mode` + `list` pair.
///
/// The migration is in-place and key order matters: Python pops `mode`
/// and `list` and *then* assigns `allow`, so the new key lands at the
/// end of the block. `save_raw_config` emits with `sort_keys=False`, so
/// that order is what the operator sees after the write.
pub(crate) fn ensure_domain_section(raw: &mut Value) {
    let top = top_mut(raw);
    let needs_default = match top.get("domains") {
        None => true,
        // `raw["domains"]` present but not a mapping (`domains:` with
        // nothing under it is the common way to get here). The Python
        // raises; a fresh block is the same outcome minus the crash.
        Some(value) => value.as_mapping().is_none(),
    };
    if needs_default {
        let mut dom = Mapping::new();
        dom.insert(Value::from("allow"), Value::Sequence(Sequence::new()));
        top.insert(Value::from("domains"), Value::Mapping(dom));
        return;
    }
    let dom = top
        .get_mut("domains")
        .and_then(Value::as_mapping_mut)
        .expect("checked above");
    if dom.contains_key("allow") || dom.contains_key("block") {
        return;
    }
    let mode = dom
        .shift_remove("mode")
        .as_ref()
        .and_then(Value::as_str)
        .unwrap_or("allowlist")
        .to_owned();
    let entries = dom
        .shift_remove("list")
        .and_then(|v| v.as_sequence().cloned())
        .unwrap_or_default();
    // `else: dom["allow"] = list(entries)` — an unrecognised mode is an
    // allowlist, not an error.
    let key = if mode == "blocklist" {
        "block"
    } else {
        "allow"
    };
    dom.insert(Value::from(key), Value::Sequence(entries));
}

/// The active list key: `allow`, or `block` when that is the only one
/// present.
///
/// `"allow" if "allow" in dom else "block" if "block" in dom else
/// "allow"` — `allow` wins when a hand-edited file carries both.
pub(crate) fn list_key(raw: &Value) -> &'static str {
    let Some(dom) = raw.get("domains") else {
        return "allow";
    };
    if dom.get("allow").is_some() {
        "allow"
    } else if dom.get("block").is_some() {
        "block"
    } else {
        "allow"
    }
}

/// True for a cage whose `domains:` block is blocklist-only.
///
/// The gate both `grants promote` and the reconcile's promotion step
/// apply: a grant only ever *widens* the allow set, so appending one to
/// a block list would be the exact opposite of granting it.
pub(crate) fn is_blocklist_mode(raw: &Value) -> bool {
    raw.get("domains")
        .is_some_and(|dom| dom.get("block").is_some() && dom.get("allow").is_none())
}

/// The active list, mutable. Creates it when absent, as the Python's
/// `dom.setdefault(list_key, [])` does.
pub(crate) fn list_mut<'a>(raw: &'a mut Value, key: &str) -> &'a mut Sequence {
    let top = top_mut(raw);
    let dom = top
        .entry(Value::from("domains"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if dom.as_mapping().is_none() {
        *dom = Value::Mapping(Mapping::new());
    }
    let dom = dom.as_mapping_mut().expect("just made one");
    let entry = dom
        .entry(Value::from(key.to_owned()))
        .or_insert_with(|| Value::Sequence(Sequence::new()));
    if entry.as_sequence().is_none() {
        *entry = Value::Sequence(Sequence::new());
    }
    entry.as_sequence_mut().expect("just made one")
}

/// The list at `domains.<key>`, mutable, **only when it is already
/// there**.
///
/// `dom.get("allow") or []` in the Python: a blocklist-mode cage has no
/// `allow` key, and the prune steps that walk it must not create one.
/// [`list_mut`] is the `setdefault` version, for the paths that are
/// about to append.
pub(crate) fn existing_list_mut<'a>(raw: &'a mut Value, key: &str) -> Option<&'a mut Sequence> {
    raw.as_mapping_mut()?
        .get_mut("domains")?
        .as_mapping_mut()?
        .get_mut(key)?
        .as_sequence_mut()
}

/// `cli._parse_duration` — `30s` / `10m` / `1h` / `2d` / a bare number
/// of seconds.
///
/// # Errors
///
/// The Python's own `ValueError` message, which `domain add` prints
/// after `error: invalid --expires-in: `.
pub(crate) fn parse_duration(duration: &str) -> Result<i64, String> {
    let s = duration.trim().to_lowercase();
    if s.is_empty() {
        return Err("empty duration".to_owned());
    }
    // `s[:-1].isdigit()` is true only for a non-empty run of digits, and
    // `str.isdigit` accepts no sign, so a bare `-` or `+` is rejected
    // here exactly as it is there.
    let (head, last) = s.split_at(s.len() - s.chars().next_back().map_or(0, char::len_utf8));
    let multiplier = match last {
        "s" => Some(1_i64),
        "m" => Some(60),
        "h" => Some(3600),
        "d" => Some(86400),
        _ => None,
    };
    if let Some(multiplier) = multiplier
        && is_ascii_digits(head)
        && let Ok(value) = head.parse::<i64>()
    {
        return Ok(value.saturating_mul(multiplier));
    }
    if is_ascii_digits(&s)
        && let Ok(value) = s.parse::<i64>()
    {
        return Ok(value);
    }
    // `f"invalid duration {duration!r}: ..."` — Python's `repr` of a
    // plain string is single-quoted.
    Err(format!(
        "invalid duration {}: use a number with a unit suffix \
         (e.g. 30s, 10m, 1h, 2d) or a bare number of seconds",
        agentcage_core::python::repr_str(duration)
    ))
}

/// `str.isdigit()`, narrowed to ASCII.
///
/// Python's accepts superscripts and other Unicode digit characters,
/// which `int()` then rejects — so the pair behaves as this does, and
/// the difference is only in which of the two error paths is taken.
fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `cli._expires_at_from_now`.
pub(crate) fn expires_at_from_now(seconds: i64) -> String {
    DateTime::now_utc()
        .checked_sub_seconds(-seconds)
        .unwrap_or_else(DateTime::now_utc)
        .isoformat()
}

/// `datetime.now(timezone.utc).isoformat()`.
pub(crate) fn now_iso() -> String {
    DateTime::now_utc().isoformat()
}

/// `cli._read_domain_expires` — the `domains.expires` map, keys
/// lowercased and trailing-dot-stripped.
///
/// Both shapes are accepted because both have been written: a mapping
/// of `domain: expires_at`, and a list of `{domain, expires_at}`
/// records. A [`BTreeMap`] rather than an insertion-ordered one because
/// the only writer, [`write_domain_expires`], sorts.
pub(crate) fn read_domain_expires(raw: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(expires) = raw.get("domains").and_then(|d| d.get("expires")) else {
        return out;
    };
    match expires {
        Value::Mapping(map) => {
            for (key, value) in map {
                let (key, value) = (scalar_str(key), scalar_str(value));
                if !key.is_empty() && !value.is_empty() {
                    out.insert(canonical(&key), value);
                }
            }
        }
        Value::Sequence(items) => {
            for item in items {
                let Some(entry) = item.as_mapping() else {
                    continue;
                };
                let domain = entry.get("domain").map_or_else(String::new, scalar_str);
                let at = entry.get("expires_at").map_or_else(String::new, scalar_str);
                if !domain.is_empty() && !at.is_empty() {
                    out.insert(canonical(&domain), at);
                }
            }
        }
        _ => {}
    }
    out
}

/// `cli._write_domain_expires` — the map back into the document,
/// sorted, or the key removed when it is empty.
pub(crate) fn write_domain_expires(raw: &mut Value, expires: &BTreeMap<String, String>) {
    let top = top_mut(raw);
    let dom = top
        .entry(Value::from("domains"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if dom.as_mapping().is_none() {
        *dom = Value::Mapping(Mapping::new());
    }
    let dom = dom.as_mapping_mut().expect("just made one");
    if expires.is_empty() {
        dom.shift_remove("expires");
        return;
    }
    let mut map = Mapping::new();
    for (domain, at) in expires {
        map.insert(Value::from(domain.clone()), Value::from(at.clone()));
    }
    dom.insert(Value::from("expires"), Value::Mapping(map));
}

/// `domain.rstrip(".").lower()` — the form that lands in `cage.yaml`.
///
/// Every comparison and every stored value goes through this. An
/// uppercase entry in `domains.allow` is rejected by `validate_config`
/// on the next load (its regex is lowercase-only), which makes the
/// cage's own config unparseable — so canonicalising is not tidiness,
/// it is what keeps a `domain add FOO.COM` from bricking the cage.
pub(crate) fn canonical(domain: &str) -> String {
    domain.trim_end_matches('.').to_lowercase()
}

/// `cli._apply_baseline_change` — persist a raw `cage.yaml` edit and
/// live-reload the egress.
///
/// The shared tail of `domain add`, `domain rm` and the grants
/// reconcile. Reusing one function is what makes every grant path apply
/// domains the *exact* same way a manual `agentcage domain add` does.
///
/// # Errors
///
/// [`EXIT_FAILURE`], after printing, if the write or the reload fails.
pub(crate) fn apply_baseline_change(ctx: &Ctx, name: &str, raw: &Value) -> Result<(), ExitCode> {
    ctx.paths.save_raw_config(name, raw).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;
    ctx.paths
        .save_proxy_config(name, &ctx.version)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    let config = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;
    update_dns_quadlet(ctx, &config)
}

/// `cli._update_dns_quadlet` — apply an allowlist change to the running
/// egress without restarting the cage.
///
/// # The three steps, and why the middle one exists
///
/// 1. Rewrite `dns-allowlist.conf` from `cage.yaml`, keeping the old
///    contents in hand.
/// 2. `dnsmasq --test --servers-file=…` **inside the egress**, against
///    the mounted path. dnsmasq's SIGHUP re-read is best-effort: a
///    parse error leaves the daemon silently serving the previous
///    config, so a malformed allowlist would look like it applied and
///    then quietly not have. On a non-zero exit the file is reverted
///    and the parse error is the command's output.
/// 3. Signal. See [`RELOAD_SCRIPT`] for the two shapes that takes.
///
/// A stopped egress skips 2 and 3: the file rewrite is the whole job,
/// and the next start reads it.
///
/// # Errors
///
/// [`EXIT_FAILURE`] when dnsmasq rejects the new allowlist, after the
/// previous contents have been restored.
pub(crate) fn update_dns_quadlet(
    ctx: &Ctx,
    config: &agentcage_core::config::Config,
) -> Result<(), ExitCode> {
    let name = config.name.as_str();
    if config.isolation != "container" && config.isolation != "vm" {
        // apple-container's `reload_domains` is Track E (PR E5). The
        // caller has already written `cage.yaml` and
        // `proxy-config.yaml` by the time this is reached, so the
        // refusal is what tells the operator the change is durable but
        // not yet live — better than silently writing only the host
        // file and reporting success.
        eprintln!(
            "error: the DNS live reload on the '{}' backend is not ported yet \
             (RUST-PORT-PLAN.md Track E)",
            config.isolation
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    let allow_path = ctx.paths.dns_allowlist_path(name);
    let previous = std::fs::read_to_string(&allow_path).unwrap_or_default();
    if let Err(error) = ctx
        .paths
        .save_dns_allowlist(name, &agentcage_cli::hostenv::RealHost)
    {
        eprintln!("error: {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let backend = ctx.backend_for(&config.isolation);
    let vm_backend = backend.as_vm();

    // The guest reads a VM-LOCAL copy of the allowlist, not the host
    // file the quadlets would otherwise bind-mount: Lima's reverse-sshfs
    // mount caches host writes, so dnsmasq's SIGHUP and mitmproxy's
    // mtime poll would re-read the same stale bytes forever after a
    // `domain add`. The host file above stays authoritative; this is the
    // copy the running egress actually sees, and it has to be pushed
    // BEFORE the validation below, which reads the mounted path.
    if let Some(vm_backend) = vm_backend {
        // A guest that is down needs nothing: the next start pushes it.
        if !vm_backend.instance(name).is_running().unwrap_or(false) {
            return Ok(());
        }
        if let Err(error) = vm_backend.push_config_files(name) {
            eprintln!("error: {error}");
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }

    if !backend.is_running(name, "egress") {
        // The file rewrite is enough — the next start picks it up.
        return Ok(());
    }

    let container = format!("{name}-egress");
    let podman = agentcage_exec::tools::podman::Podman::new(ctx.runner.as_ref());
    // `_runtime_exec` — `podman exec` on the host, or the same argv
    // wrapped in a `limactl shell` for a vm cage.
    let runtime_exec =
        |argv: &[String]| -> Result<agentcage_exec::Output, agentcage_exec::ExecError> {
            let mut command = vec!["podman".to_owned(), "exec".to_owned(), container.clone()];
            command.extend(argv.iter().cloned());
            if let Some(vm_backend) = vm_backend {
                return vm_backend.instance(name).exec(&command, false);
            }
            let mut podman_argv = podman.base().arg("exec").arg(container.clone());
            podman_argv = podman_argv.args(argv.iter().cloned());
            ctx.runner.run(&podman_argv.captured())
        };

    // A podman that cannot be run at all is the Python's
    // `subprocess.run` raising, which propagates. Here it is the same
    // refusal the non-zero exit takes, because the allowlist has
    // already been rewritten and leaving it unvalidated is the one
    // outcome this check exists to prevent.
    let outcome = runtime_exec(&[
        "dnsmasq".to_owned(),
        "--test".to_owned(),
        "--servers-file=/etc/agentcage/dns-allowlist.conf".to_owned(),
    ]);
    let (ok, complaint) = match &outcome {
        Ok(output) => (
            output.success(),
            if output.stderr_text().is_empty() {
                output.stdout_text()
            } else {
                output.stderr_text()
            },
        ),
        Err(error) => (false, error.to_string()),
    };
    if !ok {
        // Revert and surface the parse error.
        let _ = std::fs::write(&allow_path, &previous);
        if let Some(vm_backend) = vm_backend {
            // The guest-local copy is pushed from the host file, so
            // re-pushing is what aligns it with the reverted contents.
            let _ = vm_backend.push_config_files(name);
        }
        eprintln!(
            "error: dnsmasq rejected the updated allowlist for cage \
             '{name}'; the previous configuration has been restored:"
        );
        let complaint = complaint.trim_end();
        if !complaint.is_empty() {
            eprintln!("{complaint}");
        }
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let _ = runtime_exec(&["sh".to_owned(), "-c".to_owned(), RELOAD_SCRIPT.to_owned()]);
    Ok(())
}

/// The reload signal, byte for byte from `cli.py:4398`.
///
/// # Why the host raises a flag instead of signalling directly
///
/// When the egress derived a default-route gateway at start it serves a
/// *rendered* runtime servers-file, and `supervisor-egress.sh`'s
/// `_render_servers_file` is the single implementation of that render:
/// per-zone forwarders, then every in-flight policy-API granted zone
/// appended. Re-rendering it here from the static baseline alone would
/// strip every granted zone out of dnsmasq on each `domain add` /
/// `domain rm` / `cage update` / lazy reconcile. So the host writes an
/// empty file to `/home/acproxy/dns/reload` and the supervisor's 1s
/// liveness loop re-renders BASELINE + GRANTED and SIGHUPs within ~1s.
///
/// When that runtime file is absent — fallback mode, no gateway was
/// derived, dnsmasq reads the bind-mounted allowlist directly — there
/// is nothing to re-render and a plain SIGHUP is enough. It goes
/// through the pidfile the supervisor writes, not `pkill`: the
/// supervisor runs dnsmasq under `setpriv --reuid=acdns`, so a `pkill`
/// from the supervisor's process tree finds nothing. The `[ -n "$pid" ]`
/// guard keeps a future path drift loud rather than a silent
/// `kill -HUP ""` no-op.
pub(crate) const RELOAD_SCRIPT: &str = "rt=/run/agentcage/dns-allowlist.egress.conf; \
if [ -f \"$rt\" ]; then : > /home/acproxy/dns/reload; \
else pid=\"$(cat /home/acdns/dnsmasq.pid)\" && [ -n \"$pid\" ] && kill -HUP \"$pid\"; fi";

/// The raw stored document, or the `cage '<name>' does not exist`
/// refusal every command in this group opens with.
fn raw_or_refuse(ctx: &Ctx, name: &str) -> Result<Value, ExitCode> {
    ctx.paths
        .load_raw_config(name, agentcage_state::AgentSchema::Check)
        .map_err(|error| {
            if error.is_missing() {
                eprintln!("error: cage '{name}' does not exist");
            } else {
                eprintln!("error: {error}");
            }
            ExitCode::from(EXIT_FAILURE)
        })
}

/// `domain list` — the filter list as it is on disk, after a reconcile.
///
/// The implicit `grants sync` is the point of the ordering: grants are
/// applied live inside the egress and written into `cage.yaml` lazily,
/// and this is the one command where that lag would be visible. A
/// no-op when there is nothing pending.
pub(crate) fn list(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    // The implicit `grants sync`. A non-success answer is the v0.22
    // refusal, which aborts the command in the Python too — its
    // `SystemExit(2)` is a `BaseException` and escapes the reconcile's
    // per-tick `except Exception`.
    let reconciled = crate::cli::cage::grants::reconcile(ctx, &name, true);
    if reconciled != ExitCode::SUCCESS {
        return reconciled;
    }
    match list_inner(ctx, &name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn list_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    let raw = raw_or_refuse(ctx, name)?;
    ensure_v022_cage(&ctx.paths, name)?;

    let (mode, mut entries, mut passthrough) = read_domain_config(&raw);
    let expires = read_domain_expires(&raw);
    let in_passthrough: std::collections::BTreeSet<&String> = passthrough.iter().collect();

    println!("Mode: {mode}");
    let listed = entries.clone();
    entries.sort();
    for domain in &entries {
        let mut tags = String::new();
        if in_passthrough.contains(domain) {
            tags.push_str(" [passthrough]");
        }
        if let Some(at) = expires.get(&canonical(domain)) {
            let _ = write!(tags, " (expires {at})");
        }
        println!("{domain}{tags}");
    }
    // Passthrough-only domains: in `passthrough` but not in the main
    // list. Compared against the *unsorted* list, as the Python does —
    // the comparison is by membership, so the order is immaterial, but
    // the values are the raw ones either way.
    passthrough.sort();
    for domain in &passthrough {
        if !listed.contains(domain) {
            println!("{domain} [passthrough only]");
        }
    }
    Ok(())
}

/// `domain add` — one or more domains, one reload.
pub(crate) fn add(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match add_inner(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

#[allow(clippy::too_many_lines)]
fn add_inner(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let domain_names: Vec<String> = matches
        .get_many::<String>("domain_names")
        .expect("required by the parser")
        .cloned()
        .collect();
    let passthrough = matches.get_flag("passthrough");
    let expires_in = matches.get_one::<String>("expires_in");

    let mut raw = raw_or_refuse(ctx, &name)?;
    ensure_v022_cage(&ctx.paths, &name)?;
    ensure_domain_section(&mut raw);
    let key = list_key(&raw);

    // `--expires-in` only makes sense in allowlist mode: a blocklist
    // denies by membership, not by time.
    let mut expires_iso = String::new();
    if let Some(expires_in) = expires_in {
        if key != "allow" {
            eprintln!(
                "error: --expires-in is only valid in allowlist mode \
                 (a blocklist entry can't be time-limited)"
            );
            return Err(ExitCode::from(EXIT_FAILURE));
        }
        match parse_duration(expires_in) {
            Ok(seconds) => expires_iso = expires_at_from_now(seconds),
            Err(message) => {
                eprintln!("error: invalid --expires-in: {message}");
                return Err(ExitCode::from(EXIT_FAILURE));
            }
        }
    }

    // Validate UP FRONT, before any append. `dom[list_key].append(dn)`
    // used to write first and validate never, so `domain add "foo.com/x"`
    // produced a `cage.yaml` that `validate_config` rejects on the next
    // load — a bricked cage. `allow_single_label` because this is the
    // operator speaking, at the same trust as editing `cage.yaml` by
    // hand, where a bare LAN hostname is valid; the runtime-grant paths
    // stay strict-dotted.
    for domain in &domain_names {
        if !valid_domain(&canonical(domain), LabelPolicy::AllowSingleLabel) {
            eprintln!(
                "error: invalid domain: {}",
                agentcage_core::python::repr_str(domain)
            );
            return Err(ExitCode::from(EXIT_FAILURE));
        }
    }

    let pt_note = if passthrough { " (passthrough)" } else { "" };
    let exp_note = if expires_iso.is_empty() {
        String::new()
    } else {
        format!(" (expires {expires_iso})")
    };
    let mut changed = false;
    let mut messages: Vec<String> = Vec::new();
    let mut expires = read_domain_expires(&raw);

    for domain in &domain_names {
        let canonical_name = canonical(domain);
        let already_in_list = read_domain_config(&raw)
            .1
            .iter()
            .any(|x| canonical(x) == canonical_name);
        let already_passthrough = read_domain_config(&raw)
            .2
            .iter()
            .any(|x| canonical(x) == canonical_name);

        if already_in_list && (!passthrough || already_passthrough) && expires_iso.is_empty() {
            messages.push(format!("'{domain}' is already in cage '{name}'."));
            continue;
        }

        if !already_in_list {
            list_mut(&mut raw, key).push(Value::from(canonical_name.clone()));
        }
        if passthrough && !already_passthrough {
            list_mut(&mut raw, "passthrough").push(Value::from(canonical_name.clone()));
        }
        if !expires_iso.is_empty() {
            expires.insert(canonical_name, expires_iso.clone());
        }

        changed = true;
        messages.push(format!(
            "Added '{domain}'{pt_note}{exp_note} to cage '{name}'."
        ));
    }

    write_domain_expires(&mut raw, &expires);

    if changed {
        apply_baseline_change(ctx, &name, &raw)?;
        // Nothing to schedule: an expired entry is blocked by the L7
        // inspector immediately and unconditionally, and the baseline is
        // tidied by the next reconcile.
        if ctx.backend_of(&name).is_running(&name, "cage") {
            messages.push("DNS and proxy updated.".to_owned());
        }
    }

    for line in messages {
        println!("{line}");
    }
    Ok(())
}

/// `domain rm` — one domain, and the audit record for it.
pub(crate) fn rm(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match rm_inner(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn rm_inner(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let domain = matches
        .get_one::<String>("domain_name")
        .expect("required by the parser")
        .clone();
    let passthrough_only = matches.get_flag("passthrough");

    let mut raw = raw_or_refuse(ctx, &name)?;
    ensure_v022_cage(&ctx.paths, &name)?;
    ensure_domain_section(&mut raw);
    let key = list_key(&raw);

    // Exact-match removal, deliberately: `domain rm` is `list.remove(x)`
    // in the Python, so `rm FOO.COM` against a stored `foo.com` is a
    // refusal rather than a silent case-folded hit. Reproduced because
    // the message is what tells the operator the entry is spelled
    // differently from what they typed.
    let (_, entries, pt_entries) = read_domain_config(&raw);
    if passthrough_only {
        if !pt_entries.contains(&domain) {
            eprintln!("error: '{domain}' is not in passthrough for cage '{name}'");
            return Err(ExitCode::from(EXIT_FAILURE));
        }
        remove_first(list_mut(&mut raw, "passthrough"), &domain);
    } else {
        if !entries.contains(&domain) {
            eprintln!("error: '{domain}' is not in cage '{name}'");
            return Err(ExitCode::from(EXIT_FAILURE));
        }
        remove_first(list_mut(&mut raw, key), &domain);
        if pt_entries.contains(&domain) {
            remove_first(list_mut(&mut raw, "passthrough"), &domain);
        }
        let mut expires = read_domain_expires(&raw);
        if expires.remove(&canonical(&domain)).is_some() {
            write_domain_expires(&mut raw, &expires);
        }
    }

    apply_baseline_change(ctx, &name, &raw)?;

    // The forensic record of egress widenings has to include the
    // narrowings an operator makes by hand, or a revoked decider grant
    // leaves no trace at all. Best-effort, as every audit write is.
    ctx.paths.append_policy_audit(
        &name,
        &now_iso(),
        &Json::Object(vec![
            ("kind".to_owned(), Json::string("policy_grant_removed")),
            ("domain".to_owned(), Json::string(&domain)),
            (
                "reason".to_owned(),
                Json::string("removed by operator via 'domain rm'"),
            ),
            ("source".to_owned(), Json::string("operator")),
            (
                "action".to_owned(),
                Json::string(if passthrough_only {
                    "removed_from_passthrough"
                } else {
                    "removed_from_baseline"
                }),
            ),
        ]),
    );

    let mut message = format!("Removed '{domain}' from cage '{name}'.");
    if ctx.backend_of(&name).is_running(&name, "cage") {
        message.push_str(" DNS and proxy updated.");
    }
    println!("{message}");
    Ok(())
}

/// `list.remove(x)` — the **first** match only, and by exact value.
fn remove_first(items: &mut Sequence, value: &str) {
    if let Some(index) = items.iter().position(|item| scalar_str(item) == value) {
        items.remove(index);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RELOAD_SCRIPT, canonical, ensure_domain_section, is_blocklist_mode, list_key, list_mut,
        parse_duration, read_domain_config, read_domain_expires, write_domain_expires,
    };
    use agentcage_core::yaml::{self, Value};
    use std::collections::BTreeMap;

    fn doc(text: &str) -> Value {
        yaml::load(text).unwrap()
    }

    #[test]
    fn durations_parse_the_way_python_parses_them() {
        assert_eq!(parse_duration("30s"), Ok(30));
        assert_eq!(parse_duration("10m"), Ok(600));
        assert_eq!(parse_duration("1h"), Ok(3600));
        assert_eq!(parse_duration("2d"), Ok(172_800));
        // A bare number is seconds.
        assert_eq!(parse_duration("3600"), Ok(3600));
        // Case and surrounding space are stripped first.
        assert_eq!(parse_duration("  1H "), Ok(3600));
        assert_eq!(parse_duration("0"), Ok(0));
    }

    #[test]
    fn a_bad_duration_carries_pythons_own_message() {
        assert_eq!(parse_duration(""), Err("empty duration".to_owned()));
        assert_eq!(parse_duration("   "), Err("empty duration".to_owned()));
        for bad in ["1w", "-5", "h", "1.5h", "abc", "1 h", "+3"] {
            let message = parse_duration(bad).unwrap_err();
            assert!(
                message.starts_with(&format!("invalid duration '{bad}'"))
                    || message.starts_with("invalid duration"),
                "{bad}: {message}"
            );
            assert!(message.contains("30s, 10m, 1h, 2d"), "{bad}: {message}");
        }
        // `repr` of the *original* argument, not the lowercased one.
        assert!(parse_duration("1W").unwrap_err().contains("'1W'"));
    }

    #[test]
    fn the_legacy_mode_and_list_pair_migrates_in_place() {
        let mut raw = doc("domains:\n  mode: allowlist\n  list: [a.example.com]\n");
        ensure_domain_section(&mut raw);
        assert_eq!(
            yaml::dump(&raw).unwrap(),
            "domains:\n  allow:\n  - a.example.com\n"
        );

        let mut raw = doc("domains:\n  mode: blocklist\n  list: [bad.example.com]\n");
        ensure_domain_section(&mut raw);
        assert!(is_blocklist_mode(&raw));
        assert_eq!(list_key(&raw), "block");

        // An unrecognised mode is an allowlist, not an error.
        let mut raw = doc("domains:\n  mode: sideways\n  list: [a.example.com]\n");
        ensure_domain_section(&mut raw);
        assert_eq!(list_key(&raw), "allow");
    }

    #[test]
    fn a_document_with_no_domains_block_gets_an_empty_allow_list() {
        let mut raw = doc("name: acme\n");
        ensure_domain_section(&mut raw);
        assert_eq!(
            yaml::dump(&raw).unwrap(),
            "name: acme\ndomains:\n  allow: []\n"
        );
        // And `domains:` with nothing under it, which the Python
        // crashes on with a `TypeError`.
        let mut raw = doc("domains:\n");
        ensure_domain_section(&mut raw);
        assert_eq!(list_key(&raw), "allow");
    }

    #[test]
    fn an_existing_block_is_left_alone() {
        let mut raw = doc("domains:\n  allow: [a.example.com]\n  passthrough: [b.example.com]\n");
        let before = yaml::dump(&raw).unwrap();
        ensure_domain_section(&mut raw);
        assert_eq!(yaml::dump(&raw).unwrap(), before);
    }

    #[test]
    fn allow_wins_over_block_when_a_hand_edited_file_has_both() {
        let raw = doc("domains:\n  block: [x.example.com]\n  allow: [a.example.com]\n");
        assert_eq!(list_key(&raw), "allow");
        assert!(!is_blocklist_mode(&raw));
    }

    #[test]
    fn both_expires_shapes_are_read_and_one_is_written() {
        let mapping =
            doc("domains:\n  expires:\n    B.Example.COM.: '2026-01-01T00:00:00+00:00'\n");
        assert_eq!(
            read_domain_expires(&mapping)
                .get("b.example.com")
                .map(String::as_str),
            Some("2026-01-01T00:00:00+00:00")
        );

        let list = doc(
            "domains:\n  expires:\n  - domain: b.example.com\n    expires_at: '2026-01-01T00:00:00+00:00'\n  - domain: ''\n    expires_at: x\n",
        );
        let read = read_domain_expires(&list);
        assert_eq!(read.len(), 1);

        // Written back sorted, and as a mapping either way.
        let mut raw = doc("domains:\n  allow: []\n");
        let mut expires = BTreeMap::new();
        expires.insert(
            "z.example.com".to_owned(),
            "2026-01-01T00:00:00+00:00".to_owned(),
        );
        expires.insert(
            "a.example.com".to_owned(),
            "2026-02-01T00:00:00+00:00".to_owned(),
        );
        write_domain_expires(&mut raw, &expires);
        assert_eq!(
            yaml::dump(&raw).unwrap(),
            "domains:\n  allow: []\n  expires:\n    a.example.com: '2026-02-01T00:00:00+00:00'\n    z.example.com: '2026-01-01T00:00:00+00:00'\n"
        );

        // An empty map removes the key rather than writing `{}`.
        write_domain_expires(&mut raw, &BTreeMap::new());
        assert_eq!(yaml::dump(&raw).unwrap(), "domains:\n  allow: []\n");
    }

    #[test]
    fn the_three_shapes_of_a_domains_block_read_back() {
        let (mode, entries, passthrough) = read_domain_config(&doc(
            "domains:\n  allow: [a.example.com]\n  passthrough: [p.example.com]\n",
        ));
        assert_eq!(mode, "allowlist");
        assert_eq!(entries, ["a.example.com"]);
        assert_eq!(passthrough, ["p.example.com"]);

        let (mode, entries, _) = read_domain_config(&doc("domains:\n  block: [x.example.com]\n"));
        assert_eq!(mode, "blocklist");
        assert_eq!(entries, ["x.example.com"]);

        // Legacy, unmigrated: `mode` is reported as written.
        let (mode, entries, _) = read_domain_config(&doc(
            "domains:\n  mode: blocklist\n  list: [x.example.com]\n",
        ));
        assert_eq!(mode, "blocklist");
        assert_eq!(entries, ["x.example.com"]);

        // A `domains:` block with neither key reads as an allowlist.
        let (mode, entries, _) = read_domain_config(&doc("domains:\n  passthrough: []\n"));
        assert_eq!(mode, "allowlist");
        assert!(entries.is_empty());
    }

    #[test]
    fn appending_creates_the_list_it_appends_to() {
        let mut raw = doc("domains:\n  allow: [a.example.com]\n");
        list_mut(&mut raw, "passthrough").push(Value::from("p.example.com"));
        assert_eq!(
            yaml::dump(&raw).unwrap(),
            "domains:\n  allow:\n  - a.example.com\n  passthrough:\n  - p.example.com\n"
        );
    }

    #[test]
    fn the_canonical_form_is_what_validate_config_will_accept() {
        assert_eq!(canonical("Example.COM."), "example.com");
        assert_eq!(canonical("example.com"), "example.com");
        assert_eq!(canonical("example.com..."), "example.com");
    }

    /// The reload contract with `supervisor-egress.sh`, pinned.
    ///
    /// Both halves matter and both are easy to "simplify" away: the
    /// flag file is what keeps in-flight granted zones in dnsmasq's
    /// servers-file, and the pidfile is what makes the fallback SIGHUP
    /// reach a daemon running under a different uid.
    #[test]
    fn the_reload_script_keeps_both_branches() {
        assert!(RELOAD_SCRIPT.contains("rt=/run/agentcage/dns-allowlist.egress.conf"));
        assert!(RELOAD_SCRIPT.contains(": > /home/acproxy/dns/reload"));
        assert!(RELOAD_SCRIPT.contains("cat /home/acdns/dnsmasq.pid"));
        assert!(RELOAD_SCRIPT.contains(r#"[ -n "$pid" ]"#));
        assert!(RELOAD_SCRIPT.contains(r#"kill -HUP "$pid""#));
        // Never `pkill`: the supervisor runs dnsmasq under
        // `setpriv --reuid=acdns`, so a pkill from its process tree
        // finds nothing.
        assert!(!RELOAD_SCRIPT.contains("pkill"));
    }
}
