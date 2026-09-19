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
