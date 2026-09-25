//! The `agentcage:secret:NAME:<hex>` placeholder grammar.
//!
//! A placeholder is the token that stands in for a real credential
//! *inside the cage*. The workload sees only the placeholder; the egress
//! proxy swaps it for the real value on the way out and redacts the real
//! value back to the placeholder on the way in.
//!
//! # The cross-boundary contract
//!
//! RUST-PORT-PLAN.md §2.2 lists this as a format contract between
//! `config.PLACEHOLDER_PREFIX` and the proxy's `secret_injector`. Reading
//! the proxy side settles what that contract actually requires, and it is
//! less than the name suggests: `secret_injector.SecretInjector.load`
//! takes `entry["placeholder"]` and does nothing but **literal substring
//! matching** with it (`ph in text`, `rule.placeholder.encode() not in
//! content`). It never parses the token, never checks the prefix, and
//! refuses only the empty string — because `"" in text` is always true
//! and would match everything.
//!
//! So the contract is *byte identity*, not syntax: whatever the host
//! writes into `placeholders.env` and `proxy-config.yaml` is what the
//! proxy looks for. `config.py` says so in as many words — "the proxy
//! matches placeholders as literal strings, so the token can be any
//! stable string — no delimiters required".
//!
//! The grammar exists for two host-side reasons instead:
//!
//! - **Entropy.** A guessable placeholder like `{{GH_TOKEN}}` is an
//!   accidental-substitution hazard: any file the agent sends outbound
//!   that happens to contain that literal text — a template, a doc, this
//!   very paragraph — gets the real secret injected into it. 128 bits of
//!   random suffix makes a collision with legitimate content vanishingly
//!   unlikely.
//! - **Self-identification.** The `agentcage:secret:` prefix lets tooling
//!   recognise a placeholder on sight, which is what
//!   [`is_canonical`] is for: `validate_config` warns (never errors) when
//!   a rule carries a token in some other shape, and `agentcage secret
//!   rotate-placeholders` mints a conforming one.
//!
//! # Where the randomness comes from
//!
//! Not from here. `agentcage-core` does no I/O (see the crate docs) and
//! `secrets.token_hex` is a read from the OS entropy pool, so the token
//! is a *parameter*: [`placeholder_for`] formats one, and
//! [`fill_raw_placeholders`] takes a minting closure. That is also what
//! makes the golden corpus reproducible — its harness pins
//! `secrets.token_hex` to a per-case counter.

use std::collections::HashMap;

use crate::python::str_of;
use crate::yaml::{Mapping, Value};

use super::types::PLACEHOLDER_PREFIX;

/// `generate_placeholder(env)`, with the entropy supplied.
///
/// Format: `agentcage:secret:<ENV>:<token>`, where `config.py` passes
/// `secrets.token_hex(16)` — 32 hex characters, 128 bits.
#[must_use]
pub fn placeholder_for(env: &str, token: &str) -> String {
    format!("{PLACEHOLDER_PREFIX}{env}:{token}")
}

/// Whether `placeholder` is in the canonical, self-identifying form.
///
/// This is exactly the test `validate_config` makes —
/// `placeholder.startswith(PLACEHOLDER_PREFIX)` — and deliberately no
/// stricter. A token minted by an older agentcage, or one an operator
/// wrote by hand with the right prefix, keeps working: the check drives a
/// warning, not a refusal, because tightening it would break every cage
/// already running with an older token.
#[must_use]
pub fn is_canonical(placeholder: &str) -> bool {
    placeholder.starts_with(PLACEHOLDER_PREFIX)
}

/// `fill_raw_placeholders` — mint a placeholder for every rule that omits
/// one.
///
/// Mutates `raw` (a parsed `cage.yaml` document) in place and returns
/// whether any rule was filled. When `previous` is given (`cage update
/// -c`, `cage edit`), a placeholder already persisted for the same env is
/// carried over so the token stays **stable across updates** —
/// regenerating would desynchronize processes still holding the old token
/// in their environment.
///
/// The filled document is what gets persisted as the stored `cage.yaml`,
/// the single source of truth, so every consumer — quadlet rendering,
/// proxy config, `secret list` — sees the same value.
///
/// `mint` is called once per rule that needs a token, with that rule's env
/// name, and should return a full placeholder (see [`placeholder_for`]).
pub fn fill_raw_placeholders(
    raw: &mut Value,
    previous: Option<&Value>,
    mint: &mut dyn FnMut(&str) -> String,
) -> bool {
    // `prev = {e.get("env"): e.get("placeholder", "") for e in _rules(prev_raw)}`.
    // Keyed on the raw value rather than on a string: `env:` is whatever
    // the document said, and Python's dict lookup compares the same way.
    let mut carried: HashMap<Value, Value> = HashMap::new();
    if let Some(previous) = previous {
        for rule in injection_rules(previous) {
            if let Value::Mapping(rule) = rule {
                carried.insert(
                    rule.get("env").cloned().unwrap_or(Value::Null),
                    rule.get("placeholder")
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new())),
                );
            }
        }
    }

    let mut changed = false;
    for rule in injection_rules_mut(raw) {
        // `if not isinstance(entry, dict): continue`.
        let Value::Mapping(rule) = rule else {
            continue;
        };
        // `env = entry.get("env", "")` — falsy env means the rule is
        // skipped entirely, the same guard `load_config` applies.
        let Some(env) = rule.get("env").cloned() else {
            continue;
        };
        if !crate::yaml::python_bool(&env) {
            continue;
        }
        // `or entry.get("placeholder")` — an existing truthy placeholder
        // is left alone.
        if rule
            .get("placeholder")
            .is_some_and(crate::yaml::python_bool)
        {
            continue;
        }
        // `prev.get(env) or generate_placeholder(env)`: a carried-over
        // token only wins when it is truthy.
        let filled = match carried.get(&env) {
            Some(token) if crate::yaml::python_bool(token) => token.clone(),
            // `"%s%s:%s" % (...)` stringifies a non-string env the way
            // `str()` would, so a numeric `env: 1` behaves identically.
            _ => Value::String(mint(&str_of(&env))),
        };
        rule.insert(Value::String("placeholder".to_owned()), filled);
        changed = true;
    }
    changed
}

/// `_rules(d)` — `secret_injection` as a list, however it was written.
///
/// The section accepts a bare list or `{"rules": [...]}`, and anything
/// else — a scalar, a mapping without `rules` — is no rules at all rather
/// than an error. That leniency is the *raw* readers' alone:
/// `load_config` is stricter about the same section, and runs later.
///
/// Public because three raw readers want it and had grown three copies:
/// this one, `state::derived`'s `placeholders.env` writer, and
/// `cli.py::_injection_rules` (the `secret rotate-placeholders` /
/// `secret set --declare` pair, PR D9).
#[must_use]
pub fn injection_rules(document: &Value) -> &[Value] {
    const NONE: &[Value] = &[];
    let Some(section) = document.get("secret_injection") else {
        return NONE;
    };
    let candidate = match section {
        Value::Mapping(mapping) => match mapping.get("rules") {
            Some(rules) => rules,
            None => return NONE,
        },
        other => other,
    };
    match candidate {
        Value::Sequence(items) => items.as_slice(),
        _ => NONE,
    }
}

/// [`injection_rules`], for mutation.
///
/// Written out rather than shared with [`injection_rules`] because the
/// borrow checker will not let one function return both, and the
/// alternative — an index path — reads worse than the duplication.
#[must_use]
pub fn injection_rules_mut(document: &mut Value) -> &mut [Value] {
    let Some(section) = document.get_mut("secret_injection") else {
        return &mut [];
    };
    let candidate = match section {
        Value::Mapping(mapping) => {
            let key = Value::String("rules".to_owned());
            match mapping.get_mut(&key) {
                Some(rules) => rules,
                None => return &mut [],
            }
        }
        other => other,
    };
    match candidate {
        Value::Sequence(items) => items.as_mut_slice(),
        _ => &mut [],
    }
}

/// The `placeholder:` a rule carries, or `""`.
///
/// Small enough to inline, kept as a function because both the validator
/// and the CLI's `secret rotate-placeholders` ask the same question of a
/// raw rule.
#[must_use]
pub fn placeholder_of(rule: &Mapping) -> String {
    rule.get("placeholder").map_or_else(String::new, str_of)
}

#[cfg(test)]
mod tests {
    use super::{fill_raw_placeholders, is_canonical, placeholder_for};
    use crate::yaml::load;

    fn counter() -> impl FnMut(&str) -> String {
        let mut n = 0;
        move |env: &str| {
            n += 1;
            placeholder_for(env, &format!("{n:032x}"))
        }
    }

    #[test]
    fn an_omitted_placeholder_is_minted_and_a_present_one_is_not() {
        let mut raw = load("secret_injection:\n- env: A\n- env: B\n  placeholder: kept\n").unwrap();
        assert!(fill_raw_placeholders(&mut raw, None, &mut counter()));
        let rules = raw["secret_injection"].as_sequence().unwrap();
        assert_eq!(
            rules[0]["placeholder"].as_str(),
            Some("agentcage:secret:A:00000000000000000000000000000001")
        );
        assert_eq!(rules[1]["placeholder"].as_str(), Some("kept"));
    }

    /// The reason `previous` exists: a regenerated token desynchronizes
    /// every process still holding the old one in its environment.
    #[test]
    fn a_previous_token_is_carried_over_rather_than_regenerated() {
        let previous = load("secret_injection:\n- env: A\n  placeholder: old-token\n").unwrap();
        let mut raw = load("secret_injection:\n- env: A\n").unwrap();
        assert!(fill_raw_placeholders(
            &mut raw,
            Some(&previous),
            &mut counter()
        ));
        assert_eq!(
            raw["secret_injection"][0]["placeholder"].as_str(),
            Some("old-token")
        );
    }

    #[test]
    fn the_rules_mapping_spelling_is_accepted_too() {
        let mut raw = load("secret_injection:\n  rules:\n  - env: A\n").unwrap();
        assert!(fill_raw_placeholders(&mut raw, None, &mut counter()));
        assert!(
            raw["secret_injection"]["rules"][0]["placeholder"]
                .as_str()
                .is_some_and(is_canonical)
        );
    }

    #[test]
    fn a_rule_without_an_env_is_left_alone() {
        let mut raw = load("secret_injection:\n- placeholder: ''\n- notarule\n").unwrap();
        assert!(!fill_raw_placeholders(&mut raw, None, &mut counter()));
    }
}
