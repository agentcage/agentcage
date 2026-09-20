//! `validate_config`'s in-egress agent rules — `agents.decider` and
//! `agents.watcher`.
//!
//! PR C3 of RUST-PORT-PLAN.md's Track C, and the last three blocks of
//! `config.py`'s `validate_config` (the "Policy API validation",
//! "agents.decider validation" and "agents.watcher validation"
//! sections, `config.py:2224` onward).
//!
//! # Why they are a block of their own
//!
//! Every rule here is a no-op when the feature is off, which is the
//! default: an omitted `decider:` block yields `enable=False` and adds
//! zero new surface — the control host is not even resolved. So the
//! whole area reads as "if this agent is on, it must be *completely*
//! configured", and a half-configured agent is refused at
//! `cage create` rather than discovered as a fail-closed 500 in the
//! egress at runtime.
//!
//! The two roster entries mirror each other field for field on
//! purpose: one grammar and one credential shape across the roster.
//! Where they differ — the decider's allowlist requirement versus the
//! watcher's blocklist refusal, the watcher's loop-hygiene bounds —
//! the reason is at the site.
//!
//! # Ordering
//!
//! `validate_config` runs these last, after the identity, image,
//! isolation, logging, port and domain checks that PR C2 owns. Within
//! the block the order is `config.py`'s, because a config with two
//! faults reports the first one reached and the golden corpus records
//! which.
//!
//! # No `validate_config` here
//!
//! This module is the C3 *half* of `validate_config`; PR C2 holds the
//! domain, port, secret and placeholder half. The single ordered
//! driver that calls both is deliberately not in either PR — the two
//! land in parallel, and a function whose body is half one branch and
//! half another is a merge conflict with a security-relevant ordering
//! inside it. [`validate_agents`] is a self-contained step that driver
//! will call last.

use std::collections::BTreeSet;

use crate::har::json::format_float;

use super::ConfigError;
use super::types::{Config, DeciderAgentConfig, LlmAgentConfig, WatcherAgentConfig};

type Checked<T> = Result<T, ConfigError>;

/// `_AGENT_MAX_TOKENS_FLOOR` — the completion budget's floor.
pub const AGENT_MAX_TOKENS_FLOOR: i64 = 1024;

/// The providers either roster entry may name.
///
/// NOT lowercased before the comparison, in `config.py` or here: a
/// `provider: Anthropic` is refused rather than accepted, because the
/// value is a dispatch key in the egress and a near-miss that silently
/// worked on one side would be worse than a refusal.
pub const VALID_AGENT_PROVIDERS: [&str; 3] = ["anthropic", "openai", "openrouter"];

/// The `source:` schemes an agent API key may use.
///
/// Narrower than `secret_resolver`'s set on purpose — see
/// [`validate_agent_api_key`].
pub const VALID_AGENT_KEY_SCHEMES: [&str; 2] = ["env", "systemd-creds"];

/// The whole `agents.*` half of `validate_config`.
///
/// Returns the warnings it accumulates, in the order `config.py`
/// appends them.
///
/// # Errors
///
/// [`ConfigError::Value`] for every fatal rule below, with
/// `config.py`'s wording byte for byte.
pub fn validate_agents(config: &Config) -> Checked<Vec<String>> {
    let mut warnings = Vec::new();

    // ── Policy API validation ───────────────────────────
    //
    // One loop over both roles, ahead of either block, so that a
    // nonsensical timeout is reported the same way whichever agent
    // carries it. `math.isfinite` catches the `.inf` and `nan` a YAML
    // float can be; `<= 0` catches the rest. A non-positive timeout
    // would make every call to the provider fail instantly, which
    // fails closed but reads like an outage.
    for (role, enable, timeout) in [
        (
            "decider",
            config.agents.decider.enable,
            config.agents.decider.llm.timeout_seconds,
        ),
        (
            "watcher",
            config.agents.watcher.enable,
            config.agents.watcher.llm.timeout_seconds,
        ),
    ] {
        if enable && (!timeout.is_finite() || timeout <= 0.0) {
            return Err(ConfigError::value(format!(
                "agents.{role}.timeout_seconds must be finite and > 0"
            )));
        }
    }

    validate_decider(config)?;
    validate_watcher(config, &mut warnings)?;
    Ok(warnings)
}

/// `agents.decider` — the policy decider that adjudicates grant
/// requests.
fn validate_decider(config: &Config) -> Checked<()> {
    let decider: &DeciderAgentConfig = &config.agents.decider;
    if !decider.enable {
        return Ok(());
    }

    // Control host: a dotted hostname, not an IP literal, not colliding
    // with a domain the operator already allow/passthrough'd (that would
    // make the synthetic control host also a real egress target).
    let host = decider.host.to_lowercase().trim_end_matches('.').to_owned();
    if !matches_control_host_shape(&host) || !host.contains('.') {
        return Err(ConfigError::value(format!(
            "agents.decider.host {} must be a dotted hostname (e.g. 'agentcage.local'), \
             not an IP literal or single label",
            crate::python::repr_str(&decider.host)
        )));
    }
    let all_named: BTreeSet<String> = config
        .domains
        .allow
        .iter()
        .chain(&config.domains.block)
        .chain(&config.domains.passthrough)
        .map(|domain| domain.to_lowercase())
        .collect();
    if all_named.contains(&host) {
        return Err(ConfigError::value(format!(
            "agents.decider.host {} must not appear in domains.allow/block/passthrough — \
             the control host is a synthetic, non-forwardable endpoint",
            crate::python::repr_str(&decider.host)
        )));
    }

    // The decider requires allowlist mode (a grant is meaningless in
    // blocklist mode — blocklist already allows everything not listed).
    // Fixed default; the operator can't turn this off in v1.
    if config.domains.mode != "allowlist" {
        return Err(ConfigError::value(
            "agents.decider requires domains allowlist mode (a grant only widens an \
             allowlist; in blocklist mode everything not blocked is already reachable).",
        ));
    }

    // Flat LLM client checks (same rules as agents.watcher — one
    // credential shape across the roster).
    validate_llm_client(
        &decider.llm,
        "agents.decider",
        // The decider agent's API key is a REQUIRED, egress-only credential
        // using the same source: scheme as secret_injection.source.
        "agents.decider.api_key is required — the decider agent needs its own API key, \
         an egress-only secret using the source: scheme (e.g. \
         'systemd-creds:POLICY_LLM_KEY' or 'env:OPENROUTER_API_KEY').",
        // https-only: the decider API key travels as a bearer header on
        // every call — an http:// base_url would leak it in cleartext.
        "agents.decider.base_url must be an https:// URL (the decider API key is sent on \
         every call; http:// would leak it in cleartext — got {})",
    )?;

    if !decider.rate_limit_rps.is_finite()
        || decider.rate_limit_rps < 0.0
        || decider.rate_limit_burst < 0
    {
        return Err(ConfigError::value(
            "agents.decider.rate_limit requests_per_second/burst must be >= 0",
        ));
    }

    validate_context(&decider.context, "agents.decider.context")?;

    // Control host is always in never_grant (operator can't remove it).
    //
    // An assertion, not a user-facing error: `effective_never_grant()`
    // inserts the host by construction, so no config can reach it
    // (`RAISE-COVERAGE.md` §3 lists it as structurally unreachable).
    // Kept anyway — it is the invariant that makes the control host
    // non-grantable, and the day someone lets the operator edit
    // `never_grant` it stops being free.
    if !decider.effective_never_grant().contains(&host) {
        return Err(ConfigError::value(
            "agents.decider.host must always be in never_grant (internal invariant violated)",
        ));
    }
    Ok(())
}

/// `agents.watcher` — the after-the-fact traffic auditor.
#[allow(clippy::too_many_lines)]
fn validate_watcher(config: &Config, warnings: &mut Vec<String>) -> Checked<()> {
    let watcher: &WatcherAgentConfig = &config.agents.watcher;
    if !watcher.enable {
        return Ok(());
    }

    // Allowlist mode, for the reason the decider requires it and one
    // more. ``DomainInspector._baseline`` IS the BLOCK list in
    // blocklist mode, so the digest would hand the model a set of
    // BLOCKED domains under the key ``current_baseline`` while the
    // system prompt describes a default-deny allowlist — and a
    // resulting baseline recommendation would tell the operator to run
    // `agentcage domain rm <domain>`, removing a BLOCK and WIDENING
    // egress. A narrowing-only auditor must never be able to produce a
    // widening recommendation.
    //
    // Refuse BLOCKLIST mode specifically, not "anything that isn't
    // allowlist": a cage with no domains section has mode "" and an
    // EMPTY baseline, so nothing inverts and nothing is recommended.
    if config.domains.mode == "blocklist" {
        return Err(ConfigError::value(
            "agents.watcher does not support domains blocklist mode (there the static \
             baseline IS the block list, so the watcher's digest and its baseline \
             recommendations invert — a recommended removal would widen egress, not \
             narrow it).",
        ));
    }

    validate_llm_client(
        &watcher.llm,
        "agents.watcher",
        // Same egress-only credential rules as the decider key.
        "agents.watcher.api_key is required — the watcher agent needs its own API key, \
         an egress-only secret using the source: scheme (e.g. \
         'systemd-creds:WATCHER_LLM_KEY' or 'env:WATCHER_LLM_KEY'). Reusing the \
         decider's key is fine: name the same env var.",
        // https-only — the watcher key travels as a bearer header on
        // every call, exactly like the decider key.
        "agents.watcher.base_url must be an https:// URL (the watcher API key is sent on \
         every call; http:// would leak it in cleartext — got {})",
    )?;

    // Loop hygiene: a 60s floor on the scan cadence so a mis-typed
    // interval cannot turn the watcher into a hot loop (one LLM call
    // per tick); a 24h cap on the post-restart lookback window (it is
    // re-read from capture.jsonl every egress start); a sane flow cap
    // (the digest prompt is bounded by max_flows, floor 10 so a typo'd 0
    // doesn't produce an empty digest every tick forever).
    if !watcher.interval_seconds.is_finite() || watcher.interval_seconds < 60.0 {
        return Err(ConfigError::value(format!(
            "agents.watcher.interval_seconds must be >= 60 (got {}) — one LLM scan per \
             interval, and a faster cadence would be a hot loop",
            format_float(watcher.interval_seconds)
        )));
    }
    if !(watcher.window_seconds > 0.0 && watcher.window_seconds <= 86_400.0) {
        return Err(ConfigError::value(format!(
            "agents.watcher.window_seconds must be in (0, 86400] (got {})",
            format_float(watcher.window_seconds)
        )));
    }
    if !(10..=2000).contains(&watcher.max_flows) {
        return Err(ConfigError::value(format!(
            "agents.watcher.max_flows must be in [10, 2000] (got {})",
            watcher.max_flows
        )));
    }
    if watcher.max_digest_tokens != 0 && !(2000..=500_000).contains(&watcher.max_digest_tokens) {
        return Err(ConfigError::value(format!(
            "agents.watcher.max_digest_tokens must be 0 (unbounded) or in [2000, 500000] \
             (got {})",
            watcher.max_digest_tokens
        )));
    }

    // Spend guardrail. Nothing here knows provider prices, so the
    // warning is denominated in TOKENS PER DAY, which the operator can
    // multiply by their own rate. The combination that motivated this
    // (a 60s cadence with max_flows at its 2000 ceiling and no digest
    // bound) reaches ~1.2 BILLION input tokens a day — a five-figure
    // monthly bill from a config the validator used to accept in
    // silence.
    let scans_per_day = 86400.0 / watcher.interval_seconds.max(1.0);
    if watcher.max_digest_tokens == 0 {
        warnings.push(format!(
            "agents.watcher.max_digest_tokens is 0, so the digest is unbounded: at \
             {scans_per_day:.0} scans/day this cage's model spend has no ceiling. Set a \
             token budget unless you are deliberately uncapping it."
        ));
    } else {
        // x1.15: 5% of scans run at 4x the budget (random
        // full-fidelity audits — see watcher._FULL_SCAN_PROB).
        #[allow(clippy::cast_precision_loss)]
        let per_day = watcher.max_digest_tokens as f64 * scans_per_day * 1.15;
        if per_day > 5_000_000.0 {
            let millions = per_day / 1e6;
            let budget = thousands(watcher.max_digest_tokens);
            warnings.push(format!(
                "agents.watcher may send up to {millions:.0}M input tokens/day ({budget} \
                 tokens x {scans_per_day:.0} scans). Raise interval_seconds or lower \
                 max_digest_tokens if that is more than intended."
            ));
        }
    }

    // Same trusted-context cap as agents.decider.context — it rides the
    // watcher's system prompt through proxy-config.yaml.
    validate_context(&watcher.context, "agents.watcher.context")
}

/// The flat LLM client rules both roster entries share.
///
/// `required_key` and `base_url_template` are the two messages that
/// name the role in their own words; everything else interpolates
/// `label`.
fn validate_llm_client(
    client: &LlmAgentConfig,
    label: &str,
    required_key: &str,
    base_url_template: &str,
) -> Checked<()> {
    if !VALID_AGENT_PROVIDERS.contains(&client.provider.as_str()) {
        return Err(ConfigError::value(format!(
            "{label}.provider must be 'anthropic', 'openai', or 'openrouter' (got {})",
            crate::python::repr_str(&client.provider)
        )));
    }
    if client.model.is_empty() {
        return Err(ConfigError::value(format!("{label}.model is required")));
    }
    validate_agent_max_tokens(client.max_tokens, &format!("{label}.max_tokens"))?;
    if client.api_key.is_empty() {
        return Err(ConfigError::value(required_key));
    }
    validate_agent_api_key(&client.api_key, label)?;
    if !client.base_url.is_empty() {
        let (scheme, hostname) = urlsplit(&client.base_url);
        if scheme != "https" || hostname.is_empty() {
            return Err(ConfigError::value(
                base_url_template.replace("{}", &crate::python::repr_str(&client.base_url)),
            ));
        }
    }
    Ok(())
}

/// `_validate_agent_max_tokens` — reject a completion budget that would
/// starve the forced tool call.
///
/// `config.py`'s first branch ("must be an integer") is structurally
/// unreachable — `_llm_client` coerces with `int()` before validation
/// and a bool is caught by the earlier "must be a number, not a
/// boolean" guard — and the type is an `i64` here for the same reason,
/// so only the floor survives the port. `RAISE-COVERAGE.md` §3.
///
/// # Errors
///
/// [`ConfigError::Value`] below [`AGENT_MAX_TOKENS_FLOOR`].
pub fn validate_agent_max_tokens(value: i64, path: &str) -> Checked<()> {
    if value >= AGENT_MAX_TOKENS_FLOOR {
        return Ok(());
    }
    Err(ConfigError::value(format!(
        "{path} must be at least {AGENT_MAX_TOKENS_FLOOR} (got {value}) — a reasoning \
         model spends thinking tokens inside this budget before emitting the forced tool \
         call, so a smaller ceiling returns finish_reason=length with no tool call at \
         all, which fails closed on every request. It is a ceiling, not a reservation: \
         providers bill only the tokens actually generated."
    )))
}

/// The `source:NAME` shape an agent API key must have.
///
/// Narrower than `secret_resolver.validate_source`'s four schemes, and
/// the narrowing is the point. The egress addon's `_read_secret`
/// resolves only `env:` and `systemd-creds:` (the egress container has
/// no shell), so a `cmd:` source silently materializes as an empty key
/// at runtime — fail-closed but confusing. `cmd:` gets its own message
/// saying so; `podman:` and anything else get the generic one.
///
/// # Errors
///
/// [`ConfigError::Value`] for a key with no scheme, a `cmd:` key, or an
/// unknown scheme.
pub fn validate_agent_api_key(api_key: &str, label: &str) -> Checked<()> {
    let (scheme, _) = require_api_key_shape(api_key, label)?;
    if scheme == "cmd" {
        return Err(ConfigError::value(format!(
            "{label}.api_key does not support cmd: sources (the egress container has no \
             shell); use env:NAME or systemd-creds:NAME"
        )));
    }
    if !VALID_AGENT_KEY_SCHEMES.contains(&scheme) {
        return Err(ConfigError::value(format!(
            "{label}.api_key unknown source scheme: '{scheme}'. Valid schemes: env, \
             systemd-creds"
        )));
    }
    Ok(())
}

/// The `source:NAME` split alone, without the scheme rules.
///
/// Separate because `config.py` makes this half of the check **twice
/// and in two places**: `load_config` runs it as soon as the roster
/// entry is built (`config.py:1316`, `:1408`), and `validate_config`
/// runs the whole of [`validate_agent_api_key`] later. The wording is
/// identical, so which one fires is invisible — until the config has a
/// *second* fault that one of C2's `validate_config` rules would catch
/// in between, and then the order decides what the user is told.
///
/// Returns the scheme and the name, which `load_config` needs: an
/// `env:` key names a host variable that must be stripped from the
/// cage's environment.
///
/// # Errors
///
/// [`ConfigError::Value`] when the key has no colon, an empty scheme
/// or an empty name.
pub fn require_api_key_shape<'a>(api_key: &'a str, label: &str) -> Checked<(&'a str, &'a str)> {
    // `str.partition(":")` — the FIRST colon, and an empty separator
    // when there is none. A `systemd-creds:NAME` has one colon; a
    // `cmd:op read op://vault/item` has several and only the first
    // splits.
    let (scheme, argument) = api_key.split_once(':').unwrap_or(("", ""));
    if scheme.is_empty() || argument.is_empty() {
        return Err(ConfigError::value(format!(
            "{label}.api_key must use the 'source:NAME' scheme (e.g. 'env:NAME' or \
             'systemd-creds:NAME') — got {}",
            crate::python::repr_str(api_key)
        )));
    }
    Ok((scheme, argument))
}

/// The 4096-character cap both `context` fields share.
///
/// The context rides in every call's system prompt and through
/// `proxy-config.yaml`, so a huge blob is a prompt-bloat/abuse surface.
/// Empty/whitespace-only is fine (feature off). 4096 is an explicit
/// boundary: a value that long is still accepted, anything longer is
/// rejected with the length in the message so the operator knows how
/// much to trim.
fn validate_context(context: &str, path: &str) -> Checked<()> {
    let length = python_strip(context).chars().count();
    if length > 4096 {
        return Err(ConfigError::value(format!(
            "{path} is too long ({length} chars, max 4096) — trim it or move details \
             into a shorter summary"
        )));
    }
    Ok(())
}

// ── small helpers ───────────────────────────────────────

/// `re.match(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z", host)`.
///
/// Hand-written rather than a regex crate, because the *anchor* is the
/// whole subtlety and a crate would hide it. Python's `$` matches at
/// end of string **or immediately before one trailing newline**, so
/// `agentcage.local\n` satisfied this pattern until 0.41.0.
///
/// That was a real hole — the control host rides into
/// `proxy-config.yaml`, and a host carrying a newline is the same shape
/// of injection `valid_domain`'s `\Z` anchor has always existed to
/// refuse on the domain lists. The anchor sweep closed it on both sides
/// of the boundary at once, `policy_api` included.
fn matches_control_host_shape(host: &str) -> bool {
    let body = host;
    let mut characters = body.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    let label = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !label(first) {
        return false;
    }
    let Some(last) = body.chars().next_back() else {
        return false;
    };
    if body.chars().count() == 1 {
        return true;
    }
    label(last)
        && body
            .chars()
            .skip(1)
            .take(body.chars().count() - 2)
            .all(|c| label(c) || c == '.' || c == '-')
}

/// `urllib.parse.urlsplit(url)`, reduced to the two fields the
/// base-url rule reads: the scheme and the hostname.
///
/// Both are lowercased, as `urlsplit` lowercases them. The hostname is
/// the authority with any `user:pass@` prefix and any `:port` suffix
/// removed, and an IPv6 literal unwrapped from its brackets — so
/// `https://` alone yields an empty hostname and is refused, which is
/// the case the `not parts.hostname` half of the check exists for.
fn urlsplit(url: &str) -> (String, String) {
    let (scheme, rest) = match url.split_once(':') {
        // A scheme is a letter followed by letters, digits, `+`, `-`
        // or `.`. Anything else means the colon belonged to the path,
        // and `urlsplit` leaves the scheme empty.
        Some((candidate, rest))
            if candidate.starts_with(|c: char| c.is_ascii_alphabetic())
                && candidate
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            (candidate.to_lowercase(), rest)
        }
        _ => (String::new(), url),
    };
    let Some(authority) = rest.strip_prefix("//") else {
        return (scheme, String::new());
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let hostname = if let Some(literal) = host_port.strip_prefix('[') {
        literal.split(']').next().unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    (scheme, hostname.to_lowercase())
}

/// Python's `str.strip()`.
///
/// Rust's `trim` uses the Unicode `White_Space` property; CPython's
/// `str.isspace` adds the four C0 file/group/record/unit separators on
/// top of it. The difference only shows up in a context blob written
/// with a stray `\x1c`, and reproducing it costs one predicate — the
/// length is in the error message, so a one-character disagreement is
/// a visible one.
fn python_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Python's `format(n, ",")` — thousands separators.
fn thousands(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if value < 0 {
        out.push('-');
    }
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        matches_control_host_shape, python_strip, thousands, urlsplit, validate_agent_api_key,
        validate_agent_max_tokens, validate_agents,
    };
    use crate::config::{FixedHost, load};

    /// The `$` anchor's trailing-newline hole, closed.
    ///
    /// `valid_domain` has always used `\Z` for exactly this reason and
    /// the A4 fixture has a case for it. `agents.decider.host` used `$`
    /// until 0.41.0, so `agentcage.local\n` passed; both sides now
    /// refuse it, and the A4 fixture was regenerated to match.
    #[test]
    fn the_control_host_pattern_refuses_a_trailing_newline() {
        assert!(matches_control_host_shape("agentcage.local"));
        assert!(!matches_control_host_shape("agentcage.local\n"));
        assert!(!matches_control_host_shape("agentcage.local\n\n"));
        assert!(!matches_control_host_shape("agentcage.local\nx"));
        assert!(!matches_control_host_shape(""));
        assert!(!matches_control_host_shape("-leading"));
        assert!(!matches_control_host_shape("trailing-"));
        assert!(!matches_control_host_shape("UPPER.local"));
        assert!(!matches_control_host_shape("has_underscore.local"));
        // A single label matches the pattern; the `"." not in host`
        // half of the check is what refuses it.
        assert!(matches_control_host_shape("a"));
    }

    /// End to end, against a config `config.py` now refuses.
    ///
    /// Measured, not reasoned about: `load_config` + `validate_config`
    /// on CPython 3.13 raise this exact `ValueError` for this document.
    /// So must this, or the host CLI and the egress `policy_api` —
    /// which resolves the same control host out of `proxy-config.yaml`
    /// — disagree about what the control host is.
    ///
    /// The document parses; only validation refuses it. That split
    /// matters: `load` still carries the newline through, so a config
    /// written before 0.41.0 is readable, and it is the validator that
    /// reports why it will not deploy.
    #[test]
    fn a_control_host_with_a_trailing_newline_is_refused_exactly_as_python_refuses_it() {
        let host = FixedHost::linux(&["192.0.2.53"]);
        let document = "name: c\ncontainer:\n  image: alpine\ndomains:\n  allow: [example.com]\n\
                        agents:\n  decider:\n    enable: true\n    host: \"agentcage.local\\n\"\n    \
                        provider: anthropic\n    model: m\n    api_key: env:K\n";
        let config = load("<test>", document, &host).expect("parse");
        assert_eq!(config.agents.decider.host, "agentcage.local\n");
        assert_eq!(
            validate_agents(&config)
                .expect_err("python raises")
                .message(),
            "agents.decider.host 'agentcage.local\\n' must be a dotted hostname \
             (e.g. 'agentcage.local'), not an IP literal or single label"
        );
    }

    #[test]
    fn the_api_key_schemes_are_narrower_than_the_secret_resolvers() {
        assert!(validate_agent_api_key("env:K", "agents.decider").is_ok());
        assert!(validate_agent_api_key("systemd-creds:K", "agents.decider").is_ok());
        assert_eq!(
            validate_agent_api_key("cmd:pass show k", "agents.decider")
                .expect_err("cmd is refused")
                .message(),
            "agents.decider.api_key does not support cmd: sources (the egress container \
             has no shell); use env:NAME or systemd-creds:NAME"
        );
        assert_eq!(
            validate_agent_api_key("podman:K", "agents.watcher")
                .expect_err("podman is refused")
                .message(),
            "agents.watcher.api_key unknown source scheme: 'podman'. Valid schemes: env, \
             systemd-creds"
        );
        // No colon, an empty scheme and an empty name all take the
        // shape message.
        for key in ["BARE", ":NAME", "env:"] {
            assert!(
                validate_agent_api_key(key, "agents.decider")
                    .expect_err("shape")
                    .message()
                    .contains("must use the 'source:NAME' scheme")
            );
        }
    }

    #[test]
    fn the_max_tokens_floor_is_inclusive() {
        assert!(validate_agent_max_tokens(1024, "agents.decider.max_tokens").is_ok());
        assert!(
            validate_agent_max_tokens(1023, "agents.decider.max_tokens")
                .expect_err("below the floor")
                .message()
                .starts_with("agents.decider.max_tokens must be at least 1024 (got 1023) —")
        );
    }

    #[test]
    fn urlsplit_reads_the_two_fields_the_rule_needs() {
        assert_eq!(
            urlsplit("https://llm.example.com/v1"),
            ("https".to_owned(), "llm.example.com".to_owned())
        );
        assert_eq!(
            urlsplit("HTTPS://LLM.Example.COM:8443/v1"),
            ("https".to_owned(), "llm.example.com".to_owned())
        );
        assert_eq!(
            urlsplit("https://user:pw@llm.example.com/v1"),
            ("https".to_owned(), "llm.example.com".to_owned())
        );
        assert_eq!(
            urlsplit("https://[2001:db8::1]:443/v1"),
            ("https".to_owned(), "2001:db8::1".to_owned())
        );
        // No authority at all -- the case `not parts.hostname` exists
        // for.
        assert_eq!(urlsplit("https://"), ("https".to_owned(), String::new()));
        assert_eq!(
            urlsplit("llm.example.com/v1"),
            (String::new(), String::new())
        );
    }

    #[test]
    fn thousands_matches_pythons_comma_format() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(100_000), "100,000");
        assert_eq!(thousands(500_000), "500,000");
        assert_eq!(thousands(-12_345), "-12,345");
    }

    #[test]
    fn strip_covers_pythons_extra_separators() {
        assert_eq!(python_strip("  hi \t\n"), "hi");
        assert_eq!(python_strip("\u{1c}hi\u{1f}"), "hi");
        assert_eq!(python_strip("\u{85}hi"), "hi");
    }
}
