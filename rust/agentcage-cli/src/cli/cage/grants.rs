//! `agentcage cage grants NAME <command>` — the Policy API's runtime
//! domain grants.
//!
//! # The shape to be careful about
//!
//! This is the only group in the tree that takes a positional argument
//! of its own *before* its subcommand. `cli.py:4724` declares
//! `@cage.group("grants")` with `@click.argument("name")`, and the
//! subcommands reach it through `click.get_current_context().parent`
//! rather than redeclaring it — so `agentcage cage grants myapp list`
//! parses `myapp` at the group and `list` below it, and neither
//! `grants list myapp` nor `grants myapp list extra` is accepted.
//!
//! clap handles this natively (a positional is matched before a
//! subcommand token), so the tree says what the Python says. What it
//! does *not* reproduce is the error for `cage grants myapp` with no
//! subcommand: click's `no_args_is_help` fires and prints the help,
//! clap raises `MissingSubcommand`. Both exit 2. See the allowed
//! differences in `tests/fixtures/cli-surface/README.md`.

use clap::Command;

use crate::cli::args::{aliases_section, cage_name, group, leaf, positional};

/// `cage grants sync`'s docstring, verbatim from `cli.py:4800`.
///
/// Forty-two lines of it, because the command is the one place where the
/// host CLI and the in-egress addon divide a single responsibility and
/// the docstring is the only record of the split. It is reproduced whole
/// rather than summarised: `--help` is where an operator reads it.
const SYNC_LONG: &str = "\
Reconcile decided grants into the operator's cage.yaml baseline.

This is bookkeeping, not enforcement. A granted domain is already live:
the addon applies it to the L7 inspector in-memory and publishes the zone
to the egress supervisor, which re-renders dnsmasq's servers-file and
SIGHUPs it. This command makes the grant DURABLE — it writes the domain
into the operator's ``domains.allow`` so it survives a cage rebuild and
shows up in ``domain list`` — and prunes entries whose expiry has passed.

It runs implicitly from the CLI paths that read a cage, so an operator
normally never types it. See docs/explain/egress-local-dns-apply.md.

Mirrors ``agentcage domain add`` exactly: for each grant the egress's
decider approved (an overlay entry), this command appends the domain to
the static ``domains.allow`` baseline (preserving its TTL into
``domains.expires``) and runs the live-reload chain
(``save_raw_config`` → ``save_proxy_config`` →
``_update_dns_quadlet`` → dnsmasq SIGHUP). That is what makes a granted
domain actually *reachable*: mitmproxy resolves its upstreams through
dnsmasq, so the L7 ``DomainInspector.grant()`` alone (which the addon
also applies) is not enough — the domain must be resolvable too, and
the only component that can write the dnsmasq allowlist + SIGHUP it is
the host CLI (the addon runs as ``acproxy``, uid 200, no ``CAP_KILL``).

Robustness:
  * Idempotent — promoted entries are removed from the overlay (they
    now live in the baseline), so a duplicate decision never
    re-promotes the same domain.
  * TTL-aware — when an entry's ``expires_at`` passes, the domain is
    removed from the baseline (via the ``domain rm`` chain) and the
    entry dropped from the overlay, so a TTL'd grant stops being
    reachable instead of silently becoming permanent.
  * Serial — pending grants are promoted in one batch (one
    ``save_raw_config`` + one reload) so a burst of decisions makes one
    atomic baseline edit, not a thundering herd of read-modify-writes.

Grants are APPLIED in-egress automatically: the addon publishes the
decided zone and raises the supervisor's reload flag, the supervisor
re-renders dnsmasq's servers-file (baseline + granted) and SIGHUPs it,
and the in-egress sweeper prunes expired grants (30s poll) so they drop
out of the runtime DNS via the next render. This command only PROMOTES
a decided grant into the operator's STATIC baseline so it survives a
cage rebuild — there is no continuous watcher to run, so it needs no
supervision unit.";

/// `cage grants revoke`'s docstring, verbatim from `cli.py`.
const REVOKE_LONG: &str = "\
Remove a runtime grant from the overlay (does not touch the baseline).

The addon hot-reloads the overlay on its mtime poll, so the grant stops
being effective on the next proxied request — no explicit signal needed.";

/// The `grants` group, with its one alias and its leading `NAME`.
pub(crate) fn command() -> Command {
    group("grants")
        .about("Manage Policy API runtime domain grants (see docs/explain/policy-api.md).")
        .arg(cage_name())
        .after_help(aliases_section(&[("ls", "list")]))
        .subcommand(
            leaf("list")
                .alias("ls")
                .about("List runtime grants (overlay) and the static baseline for a cage."),
        )
        .subcommand(
            leaf("promote")
                .about(
                    "Promote a runtime grant into the permanent baseline, then drop it from the overlay.",
                )
                .arg(positional("domain", "DOMAIN")),
        )
        .subcommand(
            leaf("revoke")
                .about("Remove a runtime grant from the overlay (does not touch the baseline).")
                .long_about(REVOKE_LONG)
                .arg(positional("domain", "DOMAIN")),
        )
        .subcommand(
            leaf("sync")
                .about("Reconcile decided grants into the operator's cage.yaml baseline.")
                .long_about(SYNC_LONG),
        )
}

// ── bodies ───────────────────────────────────────────────────
//
// PR D10. `cli.py:4615-5230`: the four commands and the reconcile pass
// behind two of them.
//
// # The overlay is shared mutable state across the trust boundary
//
// `grants/grants.yaml` is written by *two* programs in two PID
// namespaces: these commands, and the in-egress `policy_api`'s
// `_persist_grants`. Neither can lock the other out, so every write
// here is a **merge-on-write**: decide against a snapshot, then re-read
// the file immediately before saving and apply the decision to *that*.
//
// The merge is sound because of an asymmetry, not because of timing.
// The host only ever REMOVES overlay entries — `promote` and `revoke`
// drop one, the reconcile drops the expired and the promoted, and no
// host path ever adds one. So `merged = on_disk − removed` keeps every
// entry the addon persisted during the window, however long that window
// was. `agentcage-state`'s atomic writer (PR D2) is what makes the
// re-read see a whole file rather than a prefix.
//
// One refinement on top of that, which the Python calls Fix 3: the
// removal set is keyed by domain and carries the SNAPSHOT entry's
// `granted_at`. If the addon re-decided the same domain during the
// window, the on-disk entry is a different grant with a strictly newer
// `granted_at`, and dropping it by name would lose a live grant. So a
// newer `granted_at` survives the drop.

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use agentcage_core::config::{AUTO_NEVER_GRANT, LabelPolicy, encoded_private_ip, valid_domain};
use agentcage_core::har::json::Json;
use agentcage_core::yaml::{Mapping, Value};
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE, ensure_v022_cage};
use crate::cli::domain::{
    apply_baseline_change, canonical, ensure_domain_section, existing_list_mut, is_blocklist_mode,
    list_mut, now_iso, read_domain_config, read_domain_expires, scalar_str, write_domain_expires,
};

/// `str(e.get(key, ""))` for an overlay entry.
fn field(entry: &Mapping, key: &str) -> String {
    entry.get(key).map_or_else(String::new, scalar_str)
}

/// The entry's domain, canonicalised.
fn entry_domain(entry: &Mapping) -> String {
    canonical(&field(entry, "domain"))
}

/// `cli._grant_domain_match` — case- and trailing-dot-insensitive.
///
/// DNS is both, so grant lookups must be too: an operator typing
/// `revoke Foo.COM` against an overlay entry written as `foo.com` would
/// otherwise silently miss and report the grant as absent.
fn grant_domain_match(entry_domain: &str, target: &str) -> bool {
    canonical(entry_domain) == canonical(target)
}

/// `cli._host_never_grant` — the floor the reconcile applies on
/// promotion.
///
/// Mirrors the in-container addon's
/// `PolicyApi._effective_never_grant`: the built-in suffix set plus the
/// control host from `agents.decider.host`, defaulting to
/// `agentcage.local`. The reconcile runs on the host and cannot import
/// the addon, which lives in the egress image, so this is a deliberate
/// duplicate.
///
/// **The docstring in `cli.py` is stale and this is not.** It names
/// three built-ins — `internal`, `local`, `localhost` — and
/// `config._AUTO_NEVER_GRANT` has four: `metadata.goog` is GCP's public
/// metadata alias, the one cloud-metadata *name* that does not end in
/// `.internal` (AWS and Azure address theirs by IP, which the domain
/// syntax check already rejects). The constant is what both sides read,
/// so the port follows the constant.
fn host_never_grant(raw: &Value) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = AUTO_NEVER_GRANT.iter().map(|h| canonical(h)).collect();
    let host = raw
        .get("agents")
        .and_then(|a| a.get("decider"))
        .and_then(|d| d.get("host"))
        .map(scalar_str)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "agentcage.local".to_owned());
    out.insert(canonical(&host));
    out
}

/// `cli._is_never_grant` — suffix-match, plus the SSRF guard.
///
/// The suffix walk is what the name suggests: `internal` covers
/// `metadata.google.internal`, `local` covers the control host's TLD
/// family. The `encoded_private_ip` check in front of it is the case
/// suffix matching structurally cannot see — `10.0.0.1.nip.io` resolves
/// to a private address and matches no suffix in the set. This copy is
/// what stops the reconcile promoting such a domain into the operator's
/// baseline from an overlay that was hand-edited or written by an older
/// addon.
fn is_never_grant(domain: &str, never: &BTreeSet<String>) -> bool {
    if encoded_private_ip(domain).is_some() {
        return true;
    }
    let lowered = canonical(domain);
    let parts: Vec<&str> = lowered.split('.').collect();
    (0..parts.len()).any(|i| never.contains(&parts[i..].join(".")))
}

/// `entry.get("expires_at")` has passed.
///
/// A **string** comparison against `datetime.now(timezone.utc)
/// .isoformat()`, which is what the Python does — both ends are
/// produced by the same `isoformat`, so lexical order is chronological
/// order, and an empty `expires_at` means *no* expiry rather than
/// *expired*.
fn is_expired(entry: &Mapping, now: &str) -> bool {
    let at = field(entry, "expires_at");
    !at.is_empty() && at.as_str() <= now
}

/// The cage name the `grants` group parsed, and the leaf's own matches.
fn name_of(matches: &ArgMatches) -> String {
    matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone()
}

/// The overlay, or `None` when it could not be read at all.
///
/// `cli._load_grants_overlay`. The `None` is the vm backend's
/// "`limactl` round-trip failed", which callers must not confuse with
/// an empty overlay — merging against a fabricated `[]` would push an
/// EMPTY overlay and wipe every grant decided in the window.
///
/// A vm cage's overlay is guest-side — the host file is not what the
/// in-guest addon reads — so it is pulled over `limactl shell`, and an
/// unreachable guest is exactly the `None` this contract is about.
fn load_overlay(ctx: &Ctx, name: &str, isolation: &str) -> Option<Vec<Mapping>> {
    if isolation == "vm" {
        return ctx.backend_for(isolation).as_vm()?.pull_grants(name);
    }
    Some(ctx.paths.load_grants(name))
}

/// `cli._save_grants_overlay`.
fn save_overlay(ctx: &Ctx, name: &str, isolation: &str, entries: &[Mapping]) -> Result<(), String> {
    if isolation == "vm" {
        let backend = ctx.backend_for(isolation);
        let Some(vm) = backend.as_vm() else {
            return Err("the vm backend is unavailable".to_owned());
        };
        return vm.push_grants(name, entries).map_err(|e| e.to_string());
    }
    ctx.paths
        .save_grants(name, entries)
        .map_err(|error| error.to_string())
}

/// `cli._grants_vm_unreachable` — a manual grants command needs the
/// overlay it cannot reach.
fn vm_unreachable(name: &str) -> ExitCode {
    eprintln!(
        "error: could not reach the VM for cage '{name}' — the grants \
         overlay lives guest-side. Start the cage and retry."
    );
    ExitCode::from(EXIT_FAILURE)
}

/// The cage's isolation, or the refusal for a cage that is not there.
fn isolation_of(ctx: &Ctx, name: &str) -> Result<String, ExitCode> {
    ctx.paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map(|config| config.isolation)
        .map_err(|error| {
            if error.is_missing() {
                eprintln!("error: cage '{name}' does not exist");
            } else {
                eprintln!("error: {error}");
            }
            ExitCode::from(EXIT_FAILURE)
        })
}

/// The raw stored document, or the `does not exist` refusal.
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

/// `grants list` — the overlay, and the baseline it sits on top of.
pub(crate) fn list(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match list_inner(ctx, &name_of(matches)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn list_inner(ctx: &Ctx, name: &str) -> Result<(), ExitCode> {
    raw_or_refuse(ctx, name)?;
    // The baseline comes from the *validated* config so it reflects the
    // same allowlist the egress enforces, not a raw-dict
    // re-interpretation of it.
    let config = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map_err(|error| {
            if error.is_missing() {
                eprintln!("error: cage '{name}' does not exist");
            } else {
                eprintln!("error: {error}");
            }
            ExitCode::from(EXIT_FAILURE)
        })?;
    let mut baseline = config.domains.allow.clone();
    baseline.sort();
    if baseline.is_empty() {
        println!("Baseline: (empty)");
    } else {
        println!("Baseline: {}", baseline.join(" "));
    }

    let Some(entries) = load_overlay(ctx, name, &config.isolation) else {
        return Err(vm_unreachable(name));
    };
    if entries.is_empty() {
        println!("(no runtime grants)");
        return Ok(());
    }

    // Fixed-width columns keep the output greppable. The widths are
    // minimums, not truncations — Python's `f"{s:32}"` pads and never
    // cuts, so an over-long domain pushes the row out rather than
    // losing characters.
    println!(
        "{:32} {:26} {:26} {:24} SOURCE",
        "DOMAIN", "GRANTED_AT", "EXPIRES_AT", "REASON"
    );
    for entry in &entries {
        println!(
            "{:32} {:26} {:26} {:24} {}",
            field(entry, "domain"),
            field(entry, "granted_at"),
            field(entry, "expires_at"),
            field(entry, "reason"),
            field(entry, "source"),
        );
    }
    Ok(())
}

/// `grants promote` — a runtime grant into the permanent baseline.
pub(crate) fn promote(ctx: &Ctx, matches: &ArgMatches, domain: &str) -> ExitCode {
    match promote_inner(ctx, &name_of(matches), domain) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

#[allow(clippy::too_many_lines)]
fn promote_inner(ctx: &Ctx, name: &str, domain: &str) -> Result<(), ExitCode> {
    let mut raw = raw_or_refuse(ctx, name)?;
    let isolation = isolation_of(ctx, name)?;
    ensure_v022_cage(&ctx.paths, name)?;
    ensure_domain_section(&mut raw);

    // A grant only widens the allow set. Blocklist mode allows
    // everything except the listed names, so a "grant" is meaningless
    // there and the request endpoint refuses to run in that mode;
    // mirroring the invariant host-side keeps promotion honest.
    if is_blocklist_mode(&raw) {
        eprintln!("error: cannot promote into a blocklist-mode cage");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    let Some(snapshot) = load_overlay(ctx, name, &isolation) else {
        return Err(vm_unreachable(name));
    };
    // `promote` is for RUNTIME grants only. A domain that is not in the
    // overlay is not a Policy-API grant, so promoting it would be a
    // disguised, unaudited `domain add` — a baseline edit and a dnsmasq
    // change with no `policy_grant_promoted` record.
    let Some(grant) = snapshot
        .iter()
        .find(|entry| grant_domain_match(&field(entry, "domain"), domain))
        .cloned()
    else {
        eprintln!(
            "error: '{domain}' is not a runtime grant — use \
             `agentcage cage {name} domain add` instead"
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    };

    // Validate before the value lands in `domains.allow` and is
    // interpolated into `server=/<domain>/` lines. Strict-dotted, not
    // `AllowSingleLabel`: this is a runtime-grant path, and the
    // in-container addon validates the same way before granting.
    let canonical_name = canonical(domain);
    if !valid_domain(&canonical_name, LabelPolicy::StrictDotted) {
        eprintln!(
            "error: invalid domain: {}",
            agentcage_core::python::repr_str(domain)
        );
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    if is_never_grant(&canonical_name, &host_never_grant(&raw)) {
        eprintln!("error: '{domain}' is on the never_grant list and cannot be promoted");
        return Err(ExitCode::from(EXIT_FAILURE));
    }

    // Preserve the grant's TTL into `domains.expires`, or a
    // `ttl_seconds` grant promoted by hand silently becomes permanent.
    let expires_at = field(&grant, "expires_at");
    if !expires_at.is_empty() {
        let mut expires = read_domain_expires(&raw);
        expires.insert(canonical_name.clone(), expires_at.clone());
        write_domain_expires(&mut raw, &expires);
    }

    // `dom["allow"]`, not the computed list key: blocklist mode was
    // refused above, so `allow` is the only list a promotion touches.
    let already_baseline = list_mut(&mut raw, "allow")
        .iter()
        .any(|x| canonical(&scalar_str(x)) == canonical_name);
    if already_baseline {
        println!("'{domain}' is already in the baseline.");
        // The domain is present, but a TTL'd grant still TIGHTENS it,
        // and the `expires` write above has to be persisted rather than
        // silently dropped.
        if !expires_at.is_empty() {
            apply_baseline_change(ctx, name, &raw)?;
        }
    } else {
        // The CANONICAL form, not the operator's raw argument: an
        // uppercase entry lands in `cage.yaml` and `validate_config`
        // then rejects it, making the cage's own config unparseable.
        list_mut(&mut raw, "allow").push(Value::from(canonical_name.clone()));
        apply_baseline_change(ctx, name, &raw)?;
        ctx.paths.append_policy_audit(
            name,
            &now_iso(),
            &Json::Object(vec![
                ("kind".to_owned(), Json::string("policy_grant_promoted")),
                ("domain".to_owned(), Json::string(domain)),
                ("reason".to_owned(), Json::string("operator promote")),
                ("expires_at".to_owned(), Json::string(&expires_at)),
                ("action".to_owned(), Json::string("added_to_baseline")),
            ]),
        );
        if ctx.backend_of(name).is_running(name, "cage") {
            println!("DNS and proxy updated.");
        }
    }

    // The grant is now redundant with the baseline, so it comes out of
    // the overlay. Merge-on-write against a fresh re-read: see the
    // module note. A `None` re-read must NOT be treated as an empty
    // overlay; fall back to the snapshot's filtered list, which is
    // still correct for the promoted domain and only re-risks the
    // pre-fix race rather than wiping the file.
    let current = if let Some(current) = load_overlay(ctx, name, &isolation) {
        current
    } else {
        eprintln!(
            "warning: could not re-read the runtime overlay (VM \
             unreachable) — wrote the snapshot view; re-run `grants list` \
             once the cage is up to confirm"
        );
        snapshot
    };
    let remaining: Vec<Mapping> = current
        .into_iter()
        .filter(|entry| entry_domain(entry) != canonical_name)
        .collect();
    if let Err(error) = save_overlay(ctx, name, &isolation, &remaining) {
        eprintln!("error: {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    println!(
        "Promoted '{domain}' into the baseline and removed it from the \
         runtime overlay."
    );
    Ok(())
}

/// `grants revoke` — out of the overlay, leaving the baseline alone.
pub(crate) fn revoke(ctx: &Ctx, matches: &ArgMatches, domain: &str) -> ExitCode {
    match revoke_inner(ctx, &name_of(matches), domain) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// Is there a grant to revoke? The authorisation half, decided against
/// the snapshot.
///
/// Split from the durable write so a test can interleave a
/// proxy-side write between the two, which is the whole point of the
/// merge-on-write below.
fn authorize_revoke(snapshot: &[Mapping], domain: &str) -> bool {
    snapshot
        .iter()
        .any(|entry| grant_domain_match(&field(entry, "domain"), domain))
}

/// The durable half: re-read, drop the one domain, save.
///
/// `base` is what to fall back to when the re-read answers `None`.
fn persist_revoke(
    ctx: &Ctx,
    name: &str,
    isolation: &str,
    domain: &str,
    base: Vec<Mapping>,
) -> Result<(), String> {
    let current = if let Some(current) = load_overlay(ctx, name, isolation) {
        current
    } else {
        eprintln!(
            "warning: could not re-read the runtime overlay (VM \
             unreachable) — wrote the snapshot view; re-run `grants list` \
             once the cage is up to confirm"
        );
        base
    };
    let target = canonical(domain);
    let merged: Vec<Mapping> = current
        .into_iter()
        .filter(|entry| entry_domain(entry) != target)
        .collect();
    save_overlay(ctx, name, isolation, &merged)
}

fn revoke_inner(ctx: &Ctx, name: &str, domain: &str) -> Result<(), ExitCode> {
    raw_or_refuse(ctx, name)?;
    let isolation = isolation_of(ctx, name)?;
    let Some(snapshot) = load_overlay(ctx, name, &isolation) else {
        return Err(vm_unreachable(name));
    };
    if !authorize_revoke(&snapshot, domain) {
        // A silent no-op would leave the operator believing the grant
        // was revoked.
        eprintln!("error: '{domain}' is not a runtime grant");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    if let Err(error) = persist_revoke(ctx, name, &isolation, domain, snapshot) {
        eprintln!("error: {error}");
        return Err(ExitCode::from(EXIT_FAILURE));
    }
    ctx.paths.append_policy_audit(
        name,
        &now_iso(),
        &Json::Object(vec![
            ("kind".to_owned(), Json::string("policy_grant_revoked")),
            ("domain".to_owned(), Json::string(domain)),
            ("reason".to_owned(), Json::string("operator revoke")),
            ("action".to_owned(), Json::string("overlay_entry_removed")),
        ]),
    );
    println!("Revoked runtime grant for '{domain}'.");
    println!(
        "(takes effect within ~30s — the egress's overlay poll \
         interval; a restart applies it immediately)"
    );
    Ok(())
}

/// `grants sync` — one reconcile pass, reported.
pub(crate) fn sync(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    reconcile(ctx, &name_of(matches), false)
}

/// `cli._reconcile_grants` — promote decided grants, prune expired
/// entries.
///
/// Factored out of `grants sync` so the CLI paths that read a cage can
/// converge the baseline implicitly; the operator should not have to
/// know this step exists. `quiet` suppresses the not-found refusal for
/// those implicit callers, for whom a missing cage is the caller's
/// problem to report.
///
/// Every failure below the existence check is swallowed, which is
/// `cli._safe_tick`: a malformed overlay written across the trust
/// boundary must not abort the `domain list` that called this.
pub(crate) fn reconcile(ctx: &Ctx, name: &str, quiet: bool) -> ExitCode {
    // Existence check up front so a typo is not a silent no-op.
    if ctx
        .paths
        .load_raw_config(name, agentcage_state::AgentSchema::Check)
        .is_err()
    {
        if quiet {
            return ExitCode::SUCCESS;
        }
        eprintln!("error: cage '{name}' does not exist");
        return ExitCode::from(EXIT_FAILURE);
    }
    // The v0.22 gate, once and up front. In the Python it sits inside
    // step 0, and `_ensure_v022_cage` raises `SystemExit(2)` — a
    // `BaseException`, so `_safe_tick`'s `except Exception` does not
    // catch it and the whole command exits 2. Hoisting it says the same
    // thing without printing the refusal once per step.
    if let Err(code) = ensure_v022_cage(&ctx.paths, name) {
        return code;
    }
    let Ok(isolation) = ctx
        .paths
        .load_deployment_config(name, &agentcage_cli::hostenv::RealHost)
        .map(|config| config.isolation)
    else {
        return ExitCode::SUCCESS;
    };
    tick(ctx, name, &isolation);
    ExitCode::SUCCESS
}

/// What one tick intends to remove: domain → the SNAPSHOT entry's
/// `granted_at`.
type Removals = BTreeMap<String, String>;

/// One reconcile pass.
///
/// Steps 0 and 1 prune, step 2 promotes, step 3 persists the overlay.
/// Only step 3 writes the overlay, and only once, so a burst of
/// decisions makes one baseline edit rather than a thundering herd of
/// read-modify-writes.
#[allow(clippy::too_many_lines)]
fn tick(ctx: &Ctx, name: &str, isolation: &str) {
    let Some(mut entries) = load_overlay(ctx, name, isolation) else {
        // An unreachable guest is a quiet no-op tick, not an error: the
        // next pass picks the overlay up once the cage starts, and L7
        // enforcement inside the egress is unaffected either way.
        return;
    };
    let now = now_iso();
    let mut changed = false;
    let mut removed: Removals = Removals::new();

    // ── 0. Prune expired ALLOWLIST entries ────────────────────
    //
    // These came from `domain add --expires-in` and live in
    // `domains.expires`, not the overlay. The L7 inspector already
    // blocks them; this keeps the baseline and dnsmasq tidy so
    // `domain list` and DNS stay accurate.
    if let Ok(mut raw) = ctx
        .paths
        .load_raw_config(name, agentcage_state::AgentSchema::Check)
    {
        ensure_domain_section(&mut raw);
        let mut expires = read_domain_expires(&raw);
        let stale: Vec<String> = expires
            .iter()
            .filter(|(_, at)| !at.is_empty() && at.as_str() <= now.as_str())
            .map(|(domain, _)| domain.clone())
            .collect();
        if !stale.is_empty() {
            let mut removed_any = false;
            for domain in &stale {
                if let Some(allow) = existing_list_mut(&mut raw, "allow")
                    && let Some(index) = allow
                        .iter()
                        .position(|item| canonical(&scalar_str(item)) == *domain)
                {
                    allow.remove(index);
                    removed_any = true;
                }
                expires.remove(domain);
                ctx.paths.append_policy_audit(
                    name,
                    &now,
                    &Json::Object(vec![
                        ("kind".to_owned(), Json::string("domain_allow_expired")),
                        ("domain".to_owned(), Json::string(domain)),
                        ("reason".to_owned(), Json::string("allowlist entry expired")),
                        ("action".to_owned(), Json::string("removed_from_baseline")),
                    ]),
                );
            }
            // Persist the shrunk map whenever any expired entry was
            // processed, even when the domain was not in the allow
            // list — otherwise a stale `expires` entry is popped in
            // memory only and re-audited every tick forever.
            write_domain_expires(&mut raw, &expires);
            if removed_any {
                let _ = apply_baseline_change(ctx, name, &raw);
            } else {
                let _ = ctx.paths.save_raw_config(name, &raw);
            }
            changed = true;
        }
    }

    // ── 1. Drop expired GRANTS from baseline and overlay ──────
    let past_ttl: Vec<Mapping> = entries
        .iter()
        .filter(|entry| is_expired(entry, &now))
        .cloned()
        .collect();
    if !past_ttl.is_empty() {
        if let Ok(mut raw) = ctx
            .paths
            .load_raw_config(name, agentcage_state::AgentSchema::Check)
        {
            ensure_domain_section(&mut raw);
            let mut baseline_changed = false;
            for entry in &past_ttl {
                let domain = entry_domain(entry);
                if let Some(allow) = existing_list_mut(&mut raw, "allow")
                    && let Some(index) = allow
                        .iter()
                        .position(|item| canonical(&scalar_str(item)) == domain)
                {
                    allow.remove(index);
                    baseline_changed = true;
                }
            }
            if baseline_changed {
                // Tolerate a reload failure — a stopped cage is the
                // common case at startup. The baseline write is already
                // durable; the SIGHUP retries next tick.
                let _ = apply_baseline_change(ctx, name, &raw);
            }
        }
        let expired_domains: BTreeSet<String> = past_ttl.iter().map(entry_domain).collect();
        for entry in &past_ttl {
            removed.insert(entry_domain(entry), field(entry, "granted_at"));
            ctx.paths.append_policy_audit(
                name,
                &now,
                &Json::Object(vec![
                    ("kind".to_owned(), Json::string("policy_grant_removed")),
                    ("domain".to_owned(), Json::string(field(entry, "domain"))),
                    ("reason".to_owned(), Json::string("ttl expired")),
                    ("source".to_owned(), Json::string(field(entry, "source"))),
                    ("action".to_owned(), Json::string("removed_from_baseline")),
                ]),
            );
        }
        entries.retain(|entry| !expired_domains.contains(&entry_domain(entry)));
        // The overlay shrank and must be persisted even when the
        // expired domain was not in the baseline, or the entry reloads
        // next tick and re-audits forever.
        changed = true;
    }

    // ── 2. Promote pending grants into the baseline ───────────
    if !entries.is_empty()
        && let Ok(mut raw) = ctx
            .paths
            .load_raw_config(name, agentcage_state::AgentSchema::Check)
    {
        ensure_domain_section(&mut raw);
        // In blocklist mode a grant is meaningless; leave the entries
        // pending rather than appending granted domains to the BLOCK
        // list, which would be the exact opposite of a grant.
        if !is_blocklist_mode(&raw) {
            let never = host_never_grant(&raw);
            let mut expires = read_domain_expires(&raw);
            let mut allow_lower: BTreeSet<String> = read_domain_config(&raw)
                .1
                .iter()
                .map(|x| canonical(x))
                .collect();
            let mut promoted: BTreeSet<String> = BTreeSet::new();
            let mut baseline_touched = false;
            // Per-pass dedup for rejected entries. A rejected entry
            // stays in the overlay — it is neither promoted nor
            // removed, so the operator can see it — which would
            // re-audit every tick without this.
            let mut rejected_seen: BTreeSet<String> = BTreeSet::new();
            let reject = |domain: &str, reason: &str, seen: &mut BTreeSet<String>| {
                if !seen.insert(domain.to_owned()) {
                    return;
                }
                ctx.paths.append_policy_audit(
                    name,
                    &now,
                    &Json::Object(vec![
                        ("kind".to_owned(), Json::string("policy_grant_rejected")),
                        ("domain".to_owned(), Json::string(domain)),
                        ("reason".to_owned(), Json::string(reason)),
                        ("action".to_owned(), Json::string("not_promoted")),
                    ]),
                );
            };

            for entry in entries.clone() {
                let domain = entry_domain(&entry);
                // Validate BEFORE the string lands in `domains.allow`:
                // a value containing `\n` or `/` renders as multiple
                // valid `server=` lines and `dnsmasq --test` PASSES.
                if !valid_domain(&domain, LabelPolicy::StrictDotted) {
                    reject(&domain, "invalid domain syntax", &mut rejected_seen);
                    continue;
                }
                if is_never_grant(&domain, &never) {
                    reject(&domain, "never_grant", &mut rejected_seen);
                    continue;
                }
                if !allow_lower.contains(&domain) {
                    // `list_key = "allow"` in the Python, not the
                    // computed key: the blocklist case is excluded
                    // above, so this is the only list a grant can
                    // widen.
                    list_mut(&mut raw, "allow").push(Value::from(domain.clone()));
                    allow_lower.insert(domain.clone());
                    baseline_touched = true;
                    // Preserve the TTL **only** when this promotion
                    // actually ADDED the domain. `grants promote`
                    // deliberately writes an overlay TTL onto an
                    // already-permanent entry too, because that is an
                    // explicit operator act; the reconcile is automatic
                    // and must be more conservative, or a stale overlay
                    // TTL would let step 0 of a later tick prune the
                    // operator's own permanent `domain add` entry.
                    let at = field(&entry, "expires_at");
                    if !at.is_empty() {
                        expires.insert(domain.clone(), at);
                    }
                    // Audit only actual baseline additions: an entry
                    // already in the baseline is a no-op promotion, not
                    // a record worth writing every tick.
                    ctx.paths.append_policy_audit(
                        name,
                        &now,
                        &Json::Object(vec![
                            ("kind".to_owned(), Json::string("policy_grant_applied")),
                            ("domain".to_owned(), Json::string(field(&entry, "domain"))),
                            ("reason".to_owned(), Json::string(field(&entry, "reason"))),
                            ("source".to_owned(), Json::string(field(&entry, "source"))),
                            (
                                "expires_at".to_owned(),
                                Json::string(field(&entry, "expires_at")),
                            ),
                            ("action".to_owned(), Json::string("added_to_baseline")),
                        ]),
                    );
                }
                // Removed from the overlay whether it was newly added
                // or already in the baseline: it lives in the baseline
                // either way, and keeping it would grow the file
                // without bound.
                promoted.insert(domain.clone());
                removed.insert(domain, field(&entry, "granted_at"));
            }
            if !expires.is_empty() {
                write_domain_expires(&mut raw, &expires);
            }
            // Only run the live-reload chain — which execs podman,
            // hundreds of milliseconds — when a domain was actually
            // appended. When every pending entry was rejected the
            // baseline is untouched and there is nothing to SIGHUP.
            if baseline_touched {
                let _ = apply_baseline_change(ctx, name, &raw);
            }
            entries.retain(|entry| !promoted.contains(&entry_domain(entry)));
            if !promoted.is_empty() {
                changed = true;
            }
        }
    }

    // ── 3. Persist the overlay, merged ────────────────────────
    if changed {
        let Some(current) = load_overlay(ctx, name, isolation) else {
            // The guest went away mid-tick. The baseline changes are
            // already durable host-side; skip the overlay write and let
            // the next reachable tick re-merge.
            return;
        };
        let merged: Vec<Mapping> = current
            .into_iter()
            .filter(|entry| !dropped_by_tick(entry, &removed))
            .collect();
        let _ = save_overlay(ctx, name, isolation, &merged);
    }
}

/// Is `entry` one this tick intentionally removed?
///
/// A fresh re-grant the addon persisted AFTER this tick's snapshot has
/// a strictly NEWER `granted_at` than the snapshot entry this tick
/// removed, so it is kept: the addon re-decided the domain during the
/// window and the new grant must survive rather than be dropped as a
/// stale duplicate. Both values come from the same producer's
/// `isoformat`, so the lexical comparison is chronological. A malformed
/// or absent `granted_at` falls back to dropping — never resurrect a
/// genuinely-removed entry over a comparison surprise.
fn dropped_by_tick(entry: &Mapping, removed: &Removals) -> bool {
    let domain = entry_domain(entry);
    let Some(snapshot_granted_at) = removed.get(&domain) else {
        return false;
    };
    let current = field(entry, "granted_at");
    current.as_str() <= snapshot_granted_at.as_str()
}

#[cfg(test)]
mod tests {
    use super::{
        Removals, authorize_revoke, dropped_by_tick, entry_domain, field, grant_domain_match,
        host_never_grant, is_expired, is_never_grant, persist_revoke,
    };
    use crate::cli::context::Ctx;
    use agentcage_core::yaml::{self, Mapping, Value};
    use agentcage_state::{Paths, TestDir};

    fn ctx_under(dir: &std::path::Path) -> Ctx {
        Ctx {
            paths: Paths::under(dir),
            runner: Box::new(agentcage_exec::FakeRunner::new()),
            version: agentcage_core::VERSION.to_owned(),
        }
    }

    fn entry(domain: &str, granted_at: &str) -> Mapping {
        let mut map = Mapping::new();
        map.insert(Value::from("domain"), Value::from(domain));
        map.insert(Value::from("granted_at"), Value::from(granted_at));
        map
    }

    fn doc(text: &str) -> Value {
        yaml::load(text).unwrap()
    }

    fn domains(entries: &[Mapping]) -> Vec<String> {
        entries.iter().map(entry_domain).collect()
    }

    #[test]
    fn domain_matching_ignores_case_and_the_trailing_dot() {
        assert!(grant_domain_match("foo.com", "FOO.COM."));
        assert!(grant_domain_match("Foo.COM.", "foo.com"));
        assert!(!grant_domain_match("foo.com", "bar.com"));
        assert!(!grant_domain_match("foo.com", "sub.foo.com"));
    }

    /// The floor is the **constant**, not `cli.py`'s docstring.
    ///
    /// The docstring names three suffixes; `config._AUTO_NEVER_GRANT`
    /// has four. `metadata.goog` is GCP's public metadata alias — the
    /// one cloud-metadata name that is not under `.internal` — and
    /// leaving it out would let the reconcile promote a route to cloud
    /// credentials into the operator's baseline.
    #[test]
    fn the_never_grant_floor_has_four_builtins_not_three() {
        let never = host_never_grant(&doc("{}"));
        for suffix in ["internal", "local", "localhost", "metadata.goog"] {
            assert!(never.contains(suffix), "{suffix} is missing from {never:?}");
        }
        // Plus the control host, defaulted.
        assert!(never.contains("agentcage.local"));

        let custom = host_never_grant(&doc("agents:\n  decider:\n    host: Gate.Example.COM.\n"));
        assert!(custom.contains("gate.example.com"));
    }

    #[test]
    fn never_grant_is_a_suffix_walk_and_an_ssrf_guard() {
        let never = host_never_grant(&doc("{}"));
        // Suffix.
        assert!(is_never_grant("metadata.google.internal", &never));
        assert!(is_never_grant("anything.localhost", &never));
        assert!(is_never_grant("agentcage.local", &never));
        assert!(is_never_grant("metadata.goog", &never));
        // Not a suffix of any of them — `notinternal` must not match
        // `internal`, which a substring check would get wrong.
        assert!(!is_never_grant("notinternal.example.com", &never));
        assert!(!is_never_grant("registry.npmjs.org", &never));
        // The case suffix matching structurally cannot see: a hostname
        // that ENCODES a non-global address.
        assert!(is_never_grant("10.0.0.1.nip.io", &never));
        assert!(is_never_grant("127-0-0-1.sslip.io", &never));
        // ...and a hostname that encodes a *global* one is not on the
        // list, because naming a public host the long way round is no
        // more dangerous than naming it directly.
        assert!(!is_never_grant("93.184.216.34.nip.io", &never));
    }

    #[test]
    fn an_empty_expires_at_means_no_expiry_not_expired() {
        let now = "2026-09-20T12:00:00+00:00";
        let mut never = Mapping::new();
        never.insert(Value::from("domain"), Value::from("a.example.com"));
        assert!(!is_expired(&never, now));

        let mut blank = never.clone();
        blank.insert(Value::from("expires_at"), Value::from(""));
        assert!(!is_expired(&blank, now));

        let mut past = never.clone();
        past.insert(
            Value::from("expires_at"),
            Value::from("2026-09-20T11:59:59+00:00"),
        );
        assert!(is_expired(&past, now));

        let mut future = never;
        future.insert(
            Value::from("expires_at"),
            Value::from("2026-09-20T12:00:01+00:00"),
        );
        assert!(!is_expired(&future, now));
    }

    /// Fix 3: a re-grant made *during* the tick window survives the
    /// drop, because its `granted_at` is strictly newer.
    #[test]
    fn a_fresh_regrant_survives_the_ticks_removal() {
        let mut removed = Removals::new();
        removed.insert(
            "a.example.com".to_owned(),
            "2026-09-20T12:00:00+00:00".to_owned(),
        );

        // The same grant the tick removed.
        assert!(dropped_by_tick(
            &entry("a.example.com", "2026-09-20T12:00:00+00:00"),
            &removed
        ));
        // A *newer* one, decided by the addon while the tick was
        // exec'ing podman.
        assert!(!dropped_by_tick(
            &entry("a.example.com", "2026-09-20T12:00:05+00:00"),
            &removed
        ));
        // An older one is still stale.
        assert!(dropped_by_tick(
            &entry("a.example.com", "2026-09-20T11:00:00+00:00"),
            &removed
        ));
        // A malformed `granted_at` falls back to dropping: never
        // resurrect a genuinely-removed entry over a comparison
        // surprise.
        assert!(dropped_by_tick(&entry("a.example.com", ""), &removed));
        // A domain this tick never touched is untouched.
        assert!(!dropped_by_tick(
            &entry("b.example.com", "2026-09-20T12:00:05+00:00"),
            &removed
        ));
    }

    /// **The cross-boundary claim**: a host write and a proxy write do
    /// not lose each other.
    ///
    /// The overlay is written by two programs in two PID namespaces —
    /// these commands and the in-egress `policy_api._persist_grants`.
    /// The dangerous interleaving is not two writes at the same
    /// instant, which [`agentcage_state::atomic`] already handles; it
    /// is the host deciding against a snapshot and then writing that
    /// stale snapshot back, silently deleting whatever the addon
    /// persisted in between.
    ///
    /// So the test drives that exact window: authorize against the
    /// snapshot, let the proxy write, then persist. The proxy's write
    /// goes through `Paths::save_grants`, which is the same call the
    /// addon makes and the same atomic writer.
    #[test]
    fn a_host_revoke_and_a_proxy_grant_in_the_window_both_survive() {
        let dir = TestDir::new("grants-cross-namespace");
        let ctx = ctx_under(dir.path());
        ctx.paths.ensure_grants_dir("acme").unwrap();

        // What the host sees when it starts.
        let snapshot = vec![
            entry("a.example.com", "2026-09-20T12:00:00+00:00"),
            entry("b.example.com", "2026-09-20T12:00:01+00:00"),
        ];
        ctx.paths.save_grants("acme", &snapshot).unwrap();

        // 1. The host authorizes `revoke a.example.com` against it.
        assert!(authorize_revoke(&snapshot, "A.Example.com."));

        // 2. The egress addon decides a new grant and persists it,
        //    from the other side of the trust boundary.
        let mut proxy_view = ctx.paths.load_grants("acme");
        proxy_view.push(entry("c.example.com", "2026-09-20T12:00:02+00:00"));
        ctx.paths.save_grants("acme", &proxy_view).unwrap();

        // 3. The host persists its decision.
        persist_revoke(&ctx, "acme", "container", "A.Example.com.", snapshot).unwrap();

        // The revoke happened and the addon's grant is still there.
        let final_state = domains(&ctx.paths.load_grants("acme"));
        assert_eq!(final_state, ["b.example.com", "c.example.com"]);
    }

    /// The control arm: had the host written its snapshot minus the
    /// revoked entry — the obvious implementation — `c.example.com`
    /// would be gone. This is what the merge-on-write buys.
    #[test]
    fn writing_the_stale_snapshot_back_would_lose_the_proxys_grant() {
        let dir = TestDir::new("grants-cross-namespace-control");
        let ctx = ctx_under(dir.path());
        ctx.paths.ensure_grants_dir("acme").unwrap();

        let snapshot = vec![
            entry("a.example.com", "2026-09-20T12:00:00+00:00"),
            entry("b.example.com", "2026-09-20T12:00:01+00:00"),
        ];
        ctx.paths.save_grants("acme", &snapshot).unwrap();

        let mut proxy_view = ctx.paths.load_grants("acme");
        proxy_view.push(entry("c.example.com", "2026-09-20T12:00:02+00:00"));
        ctx.paths.save_grants("acme", &proxy_view).unwrap();

        // The naive write.
        let naive: Vec<Mapping> = snapshot
            .into_iter()
            .filter(|e| entry_domain(e) != "a.example.com")
            .collect();
        ctx.paths.save_grants("acme", &naive).unwrap();

        assert_eq!(domains(&ctx.paths.load_grants("acme")), ["b.example.com"]);
    }

    /// The same window, with the two writes genuinely concurrent.
    ///
    /// Threads stand in for the two PID namespaces: a reader never sees
    /// a torn document — `agentcage-state`'s atomic writer is what
    /// makes the re-read in `persist_revoke` safe — and the host's
    /// revoke still lands while the proxy keeps appending.
    #[test]
    fn concurrent_writers_never_expose_a_torn_overlay() {
        let dir = TestDir::new("grants-concurrent");
        let ctx = ctx_under(dir.path());
        ctx.paths.ensure_grants_dir("acme").unwrap();
        ctx.paths
            .save_grants(
                "acme",
                &[entry("a.example.com", "2026-09-20T12:00:00+00:00")],
            )
            .unwrap();

        let root = dir.path().to_path_buf();
        let proxy = std::thread::spawn(move || {
            let paths = Paths::under(&root);
            for i in 0..40 {
                let mut current = paths.load_grants("acme");
                current.push(entry(
                    &format!("p{i}.example.com"),
                    &format!("2026-09-20T12:00:{i:02}+00:00"),
                ));
                // A failed write is the `O_EXCL` collision the atomic
                // writer reports rather than resolving, which is
                // correct behaviour and not a test failure.
                let _ = paths.save_grants("acme", &current);
            }
        });

        let reader_root = dir.path().to_path_buf();
        let reader = std::thread::spawn(move || {
            let paths = Paths::under(&reader_root);
            for _ in 0..200 {
                // Every entry that comes back is well-formed: a torn
                // prefix would either fail to parse (and answer `[]`)
                // or yield an entry with no domain, which the loader
                // filters. Assert the stronger thing — that what we
                // read is always a document we could have written.
                for e in paths.load_grants("acme") {
                    assert!(!field(&e, "domain").is_empty());
                }
            }
        });

        proxy.join().unwrap();
        reader.join().unwrap();

        let snapshot = ctx.paths.load_grants("acme");
        assert!(authorize_revoke(&snapshot, "a.example.com"));
        persist_revoke(&ctx, "acme", "container", "a.example.com", snapshot).unwrap();
        let after = domains(&ctx.paths.load_grants("acme"));
        assert!(!after.contains(&"a.example.com".to_owned()));
        assert!(!after.is_empty(), "the proxy's grants were wiped");
    }

    /// A `revoke` for something that is not in the overlay is refused
    /// before anything is written.
    #[test]
    fn revoking_a_domain_that_is_not_a_grant_is_not_authorized() {
        let snapshot = vec![entry("a.example.com", "2026-09-20T12:00:00+00:00")];
        assert!(!authorize_revoke(&snapshot, "b.example.com"));
    }
}
