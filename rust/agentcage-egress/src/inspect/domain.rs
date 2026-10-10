//! The domain allowlist / blocklist inspector, and the live grants it holds.
//!
//! Two layers of allow state:
//!
//! * the **baseline**: the operator's static `domains.allow` (or
//!   `domains.block`), plus per-domain expiries from `domains.expires`.
//!   Rebuilt by [`DomainInspector::configure`] on every config reload;
//! * the **grants**: runtime overlay entries the Policy API adds when the
//!   decider approves a request, and the host's `grants.yaml` reconcile
//!   adds or drops. `configure` never touches them, so a reload reapplies
//!   the baseline on top of live grants without dropping any.
//!
//! Grants only widen the allow set. They never weaken the SNI/Host check,
//! the other inspectors or the rate limit, which still run on traffic to a
//! granted domain.
//!
//! One instance lives for the life of the process: the chain, the Policy
//! API and the traffic watcher all hold the same `Arc`, and reconfiguring
//! it in place is what keeps the grants across reloads. Hence `&self`
//! everywhere, with the state behind one lock.
//!
//! Matching is by suffix label: `example.com` covers the apex and every
//! subdomain, there is no wildcard syntax, and a request host's trailing
//! dot is *not* stripped for the inspector check (`example.com.` does not
//! match `example.com`), while grant lookups and the baseline/grant-only
//! helpers do strip it. Both quirks are the replaced implementation's and
//! are kept.

use std::collections::{BTreeSet, HashMap};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use agentcage_core::audit::Timestamp;
use agentcage_core::har::datetime::DateTime;
use agentcage_core::python::str_of;
use indexmap::IndexMap;

use super::{Action, Context, Inspector, Severity, Verdict};
use crate::config::{Mapping, Value, truthy};

/// The name verdicts and config sections use.
pub const NAME: &str = "domain";

/// The `source` a grant gets when the caller gives none.
pub const DEFAULT_GRANT_SOURCE: &str = "policy-hook";

/// The baseline half of the state, everything `configure` rebuilds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainConfig {
    /// `"allowlist"`, `"blocklist"`, or whatever the legacy `mode:` key
    /// held (`None` when absent). Anything but the first two default-denies.
    mode: Option<String>,
    /// Lowercased baseline entries (not trailing-dot-stripped).
    baseline: BTreeSet<String>,
    /// Lowercased, trailing-dot-stripped domain → raw `expires_at`.
    expires: HashMap<String, String>,
}

impl DomainConfig {
    /// Parse a `domains:` section (or an `inspectors:` entry's `config:`).
    ///
    /// * `allow:` present → allowlist mode with that baseline;
    /// * else `block:` present → blocklist mode;
    /// * else the legacy `mode:` + `list:` pair.
    ///
    /// `expires:` is a `{domain: iso}` map or a list of
    /// `{domain, expires_at}` objects; entries with a falsy key or value
    /// are skipped and anything else there is ignored.
    ///
    /// A null section reads as empty (no mode, so default-deny). The
    /// replaced implementation raised on it instead; the result here is
    /// the same deny-everything policy without failing the reload.
    ///
    /// # Errors
    ///
    /// The section is not a mapping, a list key holds something other
    /// than a list of strings, or `mode` is neither a string nor null.
    /// The replaced implementation raised on most of these (and iterated
    /// a string's characters on the rest); refusing all of them keeps a
    /// reload fail-closed (D1) instead of guessing.
    pub fn parse(section: &Value) -> Result<Self, String> {
        let empty = Mapping::new();
        let map = match section {
            Value::Null => &empty,
            Value::Mapping(m) => m,
            other => {
                return Err(format!(
                    "domain inspector config must be a mapping (got {})",
                    agentcage_core::python::type_name(other)
                ));
            }
        };
        let (mode, baseline) = if map.contains_key("allow") {
            (Some("allowlist".to_owned()), lowered_list(map, "allow")?)
        } else if map.contains_key("block") {
            (Some("blocklist".to_owned()), lowered_list(map, "block")?)
        } else {
            let mode = match map.get("mode") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(other) => {
                    return Err(format!(
                        "domains.mode must be a string (got {})",
                        agentcage_core::python::type_name(other)
                    ));
                }
            };
            let baseline = if map.contains_key("list") {
                lowered_list(map, "list")?
            } else {
                BTreeSet::new()
            };
            (mode, baseline)
        };

        let mut expires = HashMap::new();
        match map.get("expires") {
            Some(Value::Mapping(raw)) => {
                for (k, v) in raw {
                    if truthy(k) && truthy(v) {
                        expires.insert(normalise(&str_of(k)), str_of(v));
                    }
                }
            }
            Some(Value::Sequence(raw)) => {
                for e in raw {
                    let Value::Mapping(e) = e else { continue };
                    let (Some(d), Some(x)) = (e.get("domain"), e.get("expires_at")) else {
                        continue;
                    };
                    if truthy(d) && truthy(x) {
                        expires.insert(normalise(&str_of(d)), str_of(x));
                    }
                }
            }
            _ => {}
        }
        Ok(Self {
            mode,
            baseline,
            expires,
        })
    }
}

/// `{d.lower() for d in config[key]}`.
fn lowered_list(map: &Mapping, key: &str) -> Result<BTreeSet<String>, String> {
    let Some(Value::Sequence(items)) = map.get(key) else {
        return Err(format!("domains.{key} must be a list of domain names"));
    };
    items
        .iter()
        .map(|v| match v {
            Value::String(s) => Ok(s.to_lowercase()),
            _ => Err(format!("domains.{key} entries must be strings")),
        })
        .collect()
}

/// `domain.lower().rstrip(".")`, the grant-key normalisation.
fn normalise(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_owned()
}

/// Every suffix of `host` split on `.`, longest first:
/// `a.b.c` → `a.b.c`, `b.c`, `c`. The same walk as
/// `[".".join(parts[i:]) for i in range(len(parts))]`, including the
/// empty-label suffixes a leading, trailing or doubled dot produces.
fn suffixes(host: &str) -> impl Iterator<Item = &str> {
    std::iter::once(host).chain(host.match_indices('.').map(move |(i, _)| &host[i + 1..]))
}

/// A grant entry's `expires_at`: `entry.get("expires_at") or ""`. A
/// non-string value reads as its Python `str()`.
fn entry_expiry(entry: &Mapping) -> String {
    match entry.get("expires_at") {
        Some(v) if truthy(v) => str_of(v),
        _ => String::new(),
    }
}

/// Whether `exp` is still in the future at `now`, or `None` when it
/// cannot be compared: unparseable, or naive (Python's `TypeError`
/// comparing it with an aware "now"). Callers treat `None` as "no
/// expiry" — fail open on a malformed timestamp, never closed.
fn expiry_in_future(exp: &str, now: Timestamp) -> Option<bool> {
    match Timestamp::parse_iso_aware(exp) {
        Some((ts, true)) => Some(ts > now),
        _ => None,
    }
}

/// The current instant as a [`Timestamp`].
fn now_ts() -> Timestamp {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0);
    Timestamp::from_unix_micros(micros)
}

#[derive(Debug, Default)]
struct State {
    config: DomainConfig,
    /// Normalised domain → overlay entry, in insertion order. The order
    /// is observable: [`DomainInspector::drop_expired`] reports in it,
    /// and that is the order `policy_grant_expired` records are written.
    /// Entries stay raw mappings so keys the host (or a newer egress)
    /// wrote survive a load → persist round trip.
    granted: IndexMap<String, Mapping>,
}

impl State {
    fn in_domain_set(&self, suffix: &str) -> bool {
        self.config.baseline.contains(suffix)
            || (self.config.mode.as_deref() == Some("allowlist")
                && self.granted.contains_key(suffix))
    }

    fn matches(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        suffixes(&host).any(|s| self.in_domain_set(s))
    }

    fn matched_expired(&self, host: &str, now: Timestamp) -> Option<String> {
        let host = host.to_lowercase();
        let mut expired_longest = None;
        for suffix in suffixes(&host) {
            if !self.in_domain_set(suffix) {
                continue;
            }
            let mut exp = self.config.expires.get(suffix).cloned().unwrap_or_default();
            if exp.is_empty() {
                if let Some(entry) = self.granted.get(suffix) {
                    exp = entry_expiry(entry);
                }
            }
            if exp.is_empty() {
                // A permanent entry allows the host whatever else expired.
                return None;
            }
            match expiry_in_future(&exp, now) {
                Some(false) => {}
                // Future, or uncomparable (fail open).
                Some(true) | None => return None,
            }
            // Expired. Walking longest first, the first one is the most
            // specific, which is the one the block reason names.
            if expired_longest.is_none() {
                expired_longest = Some(suffix.to_owned());
            }
        }
        expired_longest
    }

    fn matches_baseline(&self, host: &str) -> bool {
        let host = normalise(host);
        suffixes(&host).any(|s| self.config.baseline.contains(s))
    }
}

/// The domain inspector. See the module docs.
#[derive(Debug, Default)]
pub struct DomainInspector {
    state: RwLock<State>,
}

impl DomainInspector {
    /// An unconfigured inspector: no mode, so it default-denies.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An inspector configured from `section`.
    ///
    /// # Errors
    ///
    /// As [`DomainConfig::parse`].
    pub fn from_config(section: &Value) -> Result<Self, String> {
        let inspector = Self::new();
        inspector.apply_config(DomainConfig::parse(section)?);
        Ok(inspector)
    }

    // A poisoned lock means a panic mid-update of plain data; the state
    // is still a valid value, and refusing every request forever over it
    // would turn one bug into an outage.
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Parse and apply `section`; the grants are left alone.
    ///
    /// # Errors
    ///
    /// As [`DomainConfig::parse`]; the running config is unchanged then.
    pub fn configure(&self, section: &Value) -> Result<(), String> {
        self.apply_config(DomainConfig::parse(section)?);
        Ok(())
    }

    /// Swap in an already-parsed baseline. Infallible, so a reload can
    /// parse everything first and commit only once nothing failed.
    pub fn apply_config(&self, config: DomainConfig) {
        self.write().config = config;
    }

    /// The configured mode, raw: `Some("allowlist")`, `Some("blocklist")`,
    /// or whatever else the legacy `mode:` key held (`None` when absent).
    /// The Policy API's introspection reports it as is.
    #[must_use]
    pub fn mode(&self) -> Option<String> {
        self.read().config.mode.clone()
    }

    /// True in allowlist mode, the only mode grants apply in.
    #[must_use]
    pub fn is_allowlist(&self) -> bool {
        self.read().config.mode.as_deref() == Some("allowlist")
    }

    /// `_matches`: whether any suffix of `host` is in the effective set —
    /// baseline ∪ grants in allowlist mode, the baseline otherwise.
    /// Expiry is not consulted.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        self.read().matches(host)
    }

    /// `_matched_expired` at the current time.
    #[must_use]
    pub fn matched_expired(&self, host: &str) -> Option<String> {
        self.matched_expired_at(host, now_ts())
    }

    /// If `host` would be blocked by expiry at `now`, the longest
    /// matching expired suffix (for the block reason); else `None`.
    ///
    /// Expiry removes an allow entry rather than adding a deny rule: if
    /// *any* matching suffix is permanent, future-dated, or carries an
    /// expiry that cannot be compared (unparseable or naive — fail open),
    /// the host is allowed. The expiry is the baseline's `expires` entry,
    /// falling back to the matching grant's own `expires_at`, so a TTL'd
    /// grant stops working the moment it lapses rather than at the next
    /// sweep. Timestamps are compared as instants (offsets normalised),
    /// not as strings.
    #[must_use]
    pub fn matched_expired_at(&self, host: &str, now: Timestamp) -> Option<String> {
        self.read().matched_expired(host, now)
    }

    /// The request-side check at `now`; `inspect_request` is this at the
    /// current time.
    #[must_use]
    pub fn inspect_host_at(&self, host: &str, now: Timestamp) -> Option<Verdict> {
        let state = self.read();
        let block =
            |reason: String| Some(Verdict::new(NAME, Action::Block, reason, Severity::Error));
        match state.config.mode.as_deref() {
            Some("allowlist") => {
                if !state.matches(host) {
                    return block(format!("domain not in allowlist: {host}"));
                }
                if let Some(expired) = state.matched_expired(host, now) {
                    return block(format!(
                        "domain allowlist entry expired: {expired} (was allowed until its TTL elapsed)"
                    ));
                }
                None
            }
            Some("blocklist") => {
                if state.matches(host) {
                    return block(format!("domain in blocklist: {host}"));
                }
                None
            }
            // No recognisable policy (an omitted or empty `domains:`
            // section) fails closed rather than allowing every host.
            _ => block(format!(
                "no domain allowlist configured (default-deny): {host}"
            )),
        }
    }

    // ── Grants ───────────────────────────────────────────────

    /// Add `domain` to the live overlay, stamped with the current time.
    /// See [`Self::grant_at`].
    pub fn grant(&self, domain: &str, expires_at: &str, reason: &str, source: &str) -> bool {
        self.grant_at(
            domain,
            expires_at,
            reason,
            source,
            &DateTime::now_utc().isoformat(),
        )
    }

    /// Add (or replace) the grant for `domain` with `granted_at` as its
    /// timestamp. Effective for the very next request, including its own
    /// `expires_at`. An empty `source` becomes
    /// [`DEFAULT_GRANT_SOURCE`].
    ///
    /// A no-op outside allowlist mode (grants mean nothing there) and for
    /// a domain that normalises to empty; returns whether it was recorded.
    /// A replaced grant keeps its position in the overlay order.
    pub fn grant_at(
        &self,
        domain: &str,
        expires_at: &str,
        reason: &str,
        source: &str,
        granted_at: &str,
    ) -> bool {
        let mut state = self.write();
        if state.config.mode.as_deref() != Some("allowlist") {
            return false;
        }
        let d = normalise(domain);
        if d.is_empty() {
            return false;
        }
        let source = if source.is_empty() {
            DEFAULT_GRANT_SOURCE
        } else {
            source
        };
        let mut entry = Mapping::new();
        for (k, v) in [
            ("domain", d.as_str()),
            ("granted_at", granted_at),
            ("expires_at", expires_at),
            ("reason", reason),
            ("source", source),
        ] {
            entry.insert(Value::from(k), Value::from(v));
        }
        state.granted.insert(d, entry);
        true
    }

    /// Insert an overlay entry as loaded from `grants.yaml`, under the
    /// already-normalised key `domain`, without touching it. The reconcile
    /// path: it adds entries the overlay has and memory lacks, and never
    /// overwrites one memory already holds (see [`Self::reconcile`]).
    pub fn insert_raw_grant(&self, domain: String, entry: Mapping) {
        self.write().granted.insert(domain, entry);
    }

    /// Remove `domain` from the overlay; true if it was there.
    pub fn revoke(&self, domain: &str) -> bool {
        self.write()
            .granted
            .shift_remove(&normalise(domain))
            .is_some()
    }

    /// Whether `domain` itself (not a parent) has a live grant entry.
    #[must_use]
    pub fn is_granted(&self, domain: &str) -> bool {
        self.read().granted.contains_key(&normalise(domain))
    }

    /// How many grant entries are held (the `max_grants` gate).
    #[must_use]
    pub fn grant_count(&self) -> usize {
        self.read().granted.len()
    }

    /// True if `host` is reachable *only* because of a grant: some suffix
    /// is granted and no suffix is in the operator's baseline. A grant for
    /// `example.com` covers `sub.example.com`. Grant-only hosts get the
    /// extra restrictions keyed on "the cage asked for this" (the private
    /// peer guard); what the operator vetted does not.
    #[must_use]
    pub fn is_grant_only(&self, host: &str) -> bool {
        let state = self.read();
        let host = normalise(host);
        if suffixes(&host).any(|s| state.config.baseline.contains(s)) {
            return false;
        }
        suffixes(&host).any(|s| state.granted.contains_key(s))
    }

    /// True if a baseline suffix covers `host`, ignoring grants and
    /// expiry. The removal endpoint's 403-vs-404 decision: an expired
    /// baseline entry is still the operator's, not the egress's to retract.
    #[must_use]
    pub fn matches_baseline(&self, host: &str) -> bool {
        self.read().matches_baseline(host)
    }

    /// Whether `suffix` is literally a baseline entry.
    #[must_use]
    pub fn baseline_contains(&self, suffix: &str) -> bool {
        self.read().config.baseline.contains(suffix)
    }

    /// The baseline `domains.expires` value for `suffix` (the normalised
    /// key), or `""` when it has none.
    #[must_use]
    pub fn baseline_expiry(&self, suffix: &str) -> String {
        self.read()
            .config
            .expires
            .get(suffix)
            .cloned()
            .unwrap_or_default()
    }

    /// [`Self::baseline_active_covers_at`] at the current time.
    #[must_use]
    pub fn baseline_active_covers(&self, domain: &str) -> bool {
        self.baseline_active_covers_at(domain, now_ts())
    }

    /// True when an *active* (unexpired) baseline suffix still allows
    /// `domain` — the removal endpoint's `still_allowed_by_baseline` flag
    /// and the watcher's post-revoke check, which the replaced
    /// implementation wrote out twice.
    ///
    /// [`Self::matches_baseline`] first, then a walk of `domain`'s
    /// suffixes as given (callers pass a normalised domain): a baseline
    /// suffix with no expiry, a future one, or one that cannot be compared
    /// (fail open) counts. Grants are never consulted — a sibling grant
    /// keeping the domain reachable is not the baseline doing so.
    #[must_use]
    pub fn baseline_active_covers_at(&self, domain: &str, now: Timestamp) -> bool {
        let state = self.read();
        if !state.matches_baseline(domain) {
            return false;
        }
        suffixes(domain).any(|s| {
            if !state.config.baseline.contains(s) {
                return false;
            }
            // Stored expiries are never empty (falsy ones are skipped at
            // parse), so absence is the only "permanent".
            state
                .config
                .expires
                .get(s)
                .is_none_or(|exp| expiry_in_future(exp, now).unwrap_or(true))
        })
    }

    /// [`Self::drop_expired_at`] at the current time.
    pub fn drop_expired(&self) -> Vec<String> {
        self.drop_expired_at(&DateTime::now_utc().isoformat())
    }

    /// Remove and return the granted domains whose `expires_at` is at or
    /// before `now_iso`, in overlay order.
    ///
    /// The comparison is **lexical** on the ISO strings, unlike the
    /// inspector's parsed check. That is the replaced implementation's
    /// behaviour and part of the overlay contract: every producer of a
    /// grant's `expires_at` writes `datetime.now(timezone.utc).isoformat()`
    /// form, where the two orders agree.
    pub fn drop_expired_at(&self, now_iso: &str) -> Vec<String> {
        let mut state = self.write();
        let mut expired = Vec::new();
        state.granted.retain(|d, entry| {
            let exp = entry_expiry(entry);
            if !exp.is_empty() && exp.as_str() <= now_iso {
                expired.push(d.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    /// The overlay entries as `(domain, entry)`, sorted by domain: what is
    /// persisted to `grants.yaml` and reported by introspection.
    #[must_use]
    pub fn granted_entries(&self) -> Vec<(String, Mapping)> {
        let state = self.read();
        let mut out: Vec<_> = state
            .granted
            .iter()
            .map(|(d, e)| (d.clone(), e.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The granted domain keys, in overlay (insertion) order.
    #[must_use]
    pub fn granted_domains(&self) -> Vec<String> {
        self.read().granted.keys().cloned().collect()
    }

    /// The baseline, sorted.
    #[must_use]
    pub fn baseline_list(&self) -> Vec<String> {
        self.read().config.baseline.iter().cloned().collect()
    }

    /// Sync the overlay from `entries` (as loaded from `grants.yaml`):
    /// drop in-memory grants the overlay no longer has, add the ones it
    /// has that memory lacks, and never overwrite one memory already
    /// holds. Expired entries are left to the sweeper, so a reconcile
    /// alone never widens then narrows. Entries without a usable
    /// `domain` are skipped; for duplicates the last one wins, as a
    /// dict comprehension would have it.
    pub fn reconcile(&self, entries: &[Mapping]) {
        let mut new: IndexMap<String, &Mapping> = IndexMap::new();
        for e in entries {
            let Some(d) = e.get("domain").filter(|d| truthy(d)) else {
                continue;
            };
            new.insert(normalise(&str_of(d)), e);
        }
        let mut state = self.write();
        state.granted.retain(|d, _| new.contains_key(d));
        for (d, e) in new {
            if !state.granted.contains_key(&d) {
                state.granted.insert(d, e.clone());
            }
        }
    }
}

impl Inspector for DomainInspector {
    fn name(&self) -> &str {
        NAME
    }

    fn inspect_request(&self, ctx: &Context) -> Option<Verdict> {
        self.inspect_host_at(&ctx.host, now_ts())
    }
}

/// Parse a `grants.yaml` overlay document, lossily: unreadable or
/// malformed text, or a document that is not a list, is an empty
/// overlay, and only mapping entries with a truthy `domain` are kept —
/// the gate that stops a malformed entry reaching the DNS renderer. The
/// host's `cage grants` reads the file with the same rule.
#[must_use]
pub fn parse_overlay(text: &str) -> Vec<Mapping> {
    let Ok(Value::Sequence(entries)) = agentcage_core::yaml::load(text) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|e| match e {
            Value::Mapping(m) if m.get("domain").is_some_and(truthy) => Some(m),
            _ => None,
        })
        .collect()
}

/// Render overlay entries as the `grants.yaml` document, block style,
/// keys in entry order — the same emitter the host uses for the file.
///
/// # Errors
///
/// An entry the emitter cannot write safely.
pub fn render_overlay(entries: &[Mapping]) -> Result<String, agentcage_core::yaml::Error> {
    agentcage_core::yaml::dump(&Value::Sequence(
        entries.iter().cloned().map(Value::Mapping).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Value {
        agentcage_core::yaml::load(text).unwrap()
    }

    fn ctx(host: &str) -> Context {
        Context {
            host: host.to_owned(),
            ..Context::default()
        }
    }

    #[test]
    fn a_null_section_default_denies_and_a_bad_one_is_refused() {
        let d = DomainInspector::from_config(&Value::Null).unwrap();
        let v = d.inspect_request(&ctx("a.com")).unwrap();
        assert_eq!(
            v.reason,
            "no domain allowlist configured (default-deny): a.com"
        );
        assert_eq!(v.action, Action::Block);
        assert_eq!(v.severity, Severity::Error);

        for bad in [
            "- a.com\n",
            "allow: a.com\n",
            "allow:\n",
            "allow: [1]\n",
            "mode: 5\n",
            "block: {a: 1}\n",
        ] {
            assert!(
                DomainConfig::parse(&yaml(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_failed_configure_keeps_the_running_config() {
        let d = DomainInspector::from_config(&yaml("allow: [a.com]\n")).unwrap();
        assert!(d.configure(&yaml("allow: [7]\n")).is_err());
        assert!(d.inspect_request(&ctx("a.com")).is_none());
    }

    #[test]
    fn grants_survive_reconfigure_and_the_live_clock_is_used() {
        let d = DomainInspector::from_config(&yaml("allow: [a.com]\n")).unwrap();
        assert!(d.grant("g.com", "", "why", ""));
        assert!(d.grant("old.com", "2000-01-01T00:00:00+00:00", "", "x"));
        d.configure(&yaml("allow: [b.com]\n")).unwrap();
        assert!(d.inspect_request(&ctx("g.com")).is_none());
        assert!(d.inspect_request(&ctx("old.com")).is_some());
        assert_eq!(d.matched_expired("old.com").as_deref(), Some("old.com"));
        assert_eq!(d.drop_expired(), ["old.com"]);
        let entries = d.granted_entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0].1;
        assert_eq!(
            entry.get("source"),
            Some(&Value::from(DEFAULT_GRANT_SOURCE))
        );
        let granted_at = entry.get("granted_at").and_then(Value::as_str).unwrap();
        assert!(granted_at.ends_with("+00:00"), "{granted_at}");
        assert_eq!(d.grant_count(), 1);
        assert_eq!(d.granted_domains(), ["g.com"]);
        assert!(d.baseline_contains("b.com"));
        assert_eq!(d.baseline_expiry("b.com"), "");
    }

    #[test]
    fn the_overlay_round_trips_through_the_host_emitter() {
        let d = DomainInspector::from_config(&yaml("allow: []\n")).unwrap();
        d.grant_at(
            "b.com",
            "",
            "r: colon",
            "decider",
            "2026-08-30T14:20:00+00:00",
        );
        d.reconcile(&parse_overlay(
            "- domain: b.com\n- domain: a.com\n  granted_at: '2026-01-01'\n  extra: [1, 2]\n",
        ));
        let entries: Vec<Mapping> = d.granted_entries().into_iter().map(|(_, e)| e).collect();
        let text = render_overlay(&entries).unwrap();
        assert_eq!(parse_overlay(&text), entries);
        assert!(text.starts_with("- domain: a.com\n"), "{text}");
        // The quoted date stays a string across the crossing.
        assert!(text.contains("granted_at: '2026-01-01'"), "{text}");
    }

    #[test]
    fn suffix_walk_matches_python_split() {
        let got: Vec<_> = suffixes("a..b.").collect();
        assert_eq!(got, ["a..b.", ".b.", "b.", ""]);
        assert_eq!(suffixes("").collect::<Vec<_>>(), [""]);
    }
}
