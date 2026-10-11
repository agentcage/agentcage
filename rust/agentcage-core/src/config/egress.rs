//! `egress:` — the egress process's own memory limits.
//!
//! ```yaml
//! egress:
//!   max_body_bytes: 268435456      # one buffered body (256 MiB)
//!   body_budget_bytes: 1073741824  # all buffered bodies at once (1 GiB)
//! ```
//!
//! Not policy (that is `max_request_body`, the `body-size` inspector's
//! limit) but how much memory the egress may spend holding bodies: a
//! request body is buffered whole for the inspectors and the injector,
//! and so is a response that cannot stream. `max_body_bytes` refuses one
//! larger body (a `413`, or a `502` for a response); `body_budget_bytes`
//! bounds the sum over every flow in flight (a `503` past it).
//!
//! The host and the egress parse the section with the same
//! [`EgressConfig::from_yaml`]: the host when it loads `cage.yaml`, the
//! egress on every (re)load of the `proxy-config.yaml` it is handed (the
//! section is one of the forwarded keys). A section one side accepts the
//! other cannot refuse.
//!
//! The supervisor starts the egress under an address-space limit
//! (`prlimit --as`), which counts reservations rather than resident
//! memory. [`EgressConfig::address_space_bytes`] is that limit: the
//! historical 2 GiB, or the budget plus [`ADDRESS_SPACE_HEADROOM`] when
//! that is larger, so raising the budget raises the ceiling with it
//! instead of trading a `503` for an allocation failure that would take
//! the whole egress down. The supervisor asks the egress binary for the
//! value at start (`agentcage-egress address-space`), so it is read from
//! the same config on every backend.

use crate::yaml::Value;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Default `egress.max_body_bytes`: 256 MiB.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 256 * MIB;

/// Default `egress.body_budget_bytes`: 1 GiB.
pub const DEFAULT_BODY_BUDGET_BYTES: u64 = GIB;

/// The smallest value either key accepts: 1 MiB. The budget never
/// refuses the first MiB of a body anyway, and a smaller per-body cap
/// would refuse ordinary API responses that cannot stream.
pub const MIN_BYTES: u64 = MIB;

/// The largest `egress.body_budget_bytes` accepted: 64 GiB. Far beyond
/// any agent's working set; a larger number is a typo.
pub const MAX_BODY_BUDGET_BYTES: u64 = 64 * GIB;

/// The address-space limit the egress has always run under, and the
/// floor of [`EgressConfig::address_space_bytes`]: 2 GiB.
pub const BASE_ADDRESS_SPACE: u64 = 2 * GIB;

/// What the egress reserves besides buffered bodies (thread stacks, the
/// plugin engine and instances, TLS state, the runtime): 1 GiB on top of
/// the budget.
pub const ADDRESS_SPACE_HEADROOM: u64 = GIB;

/// The memory of the microVM the apple-container backend runs the egress
/// in (`--memory 512M`; `agentcage-cli`'s `apple::run_argv` pins the two
/// together). Only the config warnings read it.
pub const APPLE_EGRESS_MEMORY_BYTES: u64 = 512 * MIB;

/// The two keys, in the order the docs list them.
const KEYS: [&str; 2] = ["max_body_bytes", "body_budget_bytes"];

/// The parsed `egress:` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressConfig {
    /// The largest single body the egress buffers, in bytes.
    pub max_body_bytes: u64,
    /// The most body bytes buffered at once across every flow.
    pub body_budget_bytes: u64,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            body_budget_bytes: DEFAULT_BODY_BUDGET_BYTES,
        }
    }
}

impl EgressConfig {
    /// Parse and validate the `egress:` value; absent or `null` is the
    /// defaults.
    ///
    /// # Errors
    ///
    /// An operator-facing message: the section is not a mapping, has a
    /// key other than the two, a value that is not an integer (a quoted
    /// number, a float and a boolean are all refused) or is out of range,
    /// or a budget smaller than the per-body cap.
    pub fn from_yaml(value: Option<&Value>) -> Result<Self, String> {
        let mapping = match value {
            None | Some(Value::Null) => return Ok(Self::default()),
            Some(Value::Mapping(mapping)) => mapping,
            Some(other) => {
                return Err(format!("egress must be a mapping (got {})", kind(other)));
            }
        };
        for key in mapping.keys() {
            let name = key.as_str().unwrap_or_default();
            if !KEYS.contains(&name) {
                return Err(format!(
                    "egress: unknown key {} (known: {})",
                    describe_key(key),
                    KEYS.join(", ")
                ));
            }
        }
        let read = |key: &str, default: u64, max: u64| -> Result<u64, String> {
            let Some(value) = mapping.get(key) else {
                return Ok(default);
            };
            let n = match value {
                Value::Number(n) => n.as_u64(),
                _ => None,
            }
            .ok_or_else(|| {
                format!(
                    "egress.{key} must be a whole number of bytes (got {})",
                    shown(value)
                )
            })?;
            if !(MIN_BYTES..=max).contains(&n) {
                return Err(format!(
                    "egress.{key} must be between {MIN_BYTES} (1 MiB) and {max} bytes (got {n})"
                ));
            }
            Ok(n)
        };
        let max_body_bytes = read(KEYS[0], DEFAULT_MAX_BODY_BYTES, MAX_BODY_BUDGET_BYTES)?;
        let body_budget_bytes = read(KEYS[1], DEFAULT_BODY_BUDGET_BYTES, MAX_BODY_BUDGET_BYTES)?;
        if body_budget_bytes < max_body_bytes {
            return Err(format!(
                "egress.body_budget_bytes ({body_budget_bytes}) must be at least \
                 egress.max_body_bytes ({max_body_bytes}): one body as large as the \
                 cap would never fit in the budget"
            ));
        }
        Ok(Self {
            max_body_bytes,
            body_budget_bytes,
        })
    }

    /// The address-space limit (`prlimit --as`) the supervisor starts
    /// the egress under: [`BASE_ADDRESS_SPACE`], or the budget plus
    /// [`ADDRESS_SPACE_HEADROOM`] when that is larger.
    #[must_use]
    pub fn address_space_bytes(&self) -> u64 {
        BASE_ADDRESS_SPACE.max(
            self.body_budget_bytes
                .saturating_add(ADDRESS_SPACE_HEADROOM),
        )
    }
}

/// A YAML value's kind, as the messages name it.
fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Sequence(_) => "list",
        Value::Mapping(_) => "mapping",
        Value::Tagged(_) => "tagged value",
    }
}

fn describe_key(key: &Value) -> String {
    match key {
        Value::String(s) => format!("{s:?}"),
        other => shown(other),
    }
}

/// A scalar as the operator wrote it, else its kind.
fn shown(value: &Value) -> String {
    match value {
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("{s:?}"),
        other => kind(other).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<EgressConfig, String> {
        let doc: Value = crate::yaml::load(text).unwrap();
        EgressConfig::from_yaml(doc.get("egress"))
    }

    #[test]
    fn an_absent_or_null_section_is_the_defaults() {
        assert_eq!(parse("name: c\n"), Ok(EgressConfig::default()));
        assert_eq!(parse("egress:\n"), Ok(EgressConfig::default()));
        assert_eq!(parse("egress: {}\n"), Ok(EgressConfig::default()));
        assert_eq!(EgressConfig::default().address_space_bytes(), 2 << 30);
    }

    #[test]
    fn both_keys_are_read_and_either_may_be_left_out() {
        let c =
            parse("egress:\n  max_body_bytes: 1048576\n  body_budget_bytes: 4194304\n").unwrap();
        assert_eq!((c.max_body_bytes, c.body_budget_bytes), (1 << 20, 4 << 20));
        let c = parse("egress:\n  body_budget_bytes: 4294967296\n").unwrap();
        assert_eq!(c.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(c.body_budget_bytes, 4 << 30);
        let c = parse("egress:\n  max_body_bytes: 67108864\n").unwrap();
        assert_eq!(c.body_budget_bytes, DEFAULT_BODY_BUDGET_BYTES);
    }

    #[test]
    fn the_address_space_grows_with_the_budget() {
        let c = parse("egress:\n  body_budget_bytes: 4294967296\n").unwrap();
        assert_eq!(c.address_space_bytes(), 5 << 30);
        let c =
            parse("egress:\n  body_budget_bytes: 536870912\n  max_body_bytes: 1048576\n").unwrap();
        assert_eq!(c.address_space_bytes(), BASE_ADDRESS_SPACE);
    }

    #[test]
    fn bad_values_are_refused_with_the_key_named() {
        let cases = [
            ("egress: [1]\n", "egress must be a mapping (got list)"),
            ("egress: 5\n", "egress must be a mapping (got number)"),
            (
                "egress:\n  max_body: 1048576\n",
                "egress: unknown key \"max_body\" (known: max_body_bytes, body_budget_bytes)",
            ),
            (
                "egress:\n  max_body_bytes: '1048576'\n",
                "egress.max_body_bytes must be a whole number of bytes (got \"1048576\")",
            ),
            (
                "egress:\n  max_body_bytes: true\n",
                "egress.max_body_bytes must be a whole number of bytes (got true)",
            ),
            (
                "egress:\n  body_budget_bytes: 1.5e9\n",
                "egress.body_budget_bytes must be a whole number of bytes (got 1500000000.0)",
            ),
            (
                "egress:\n  max_body_bytes: -1\n",
                "egress.max_body_bytes must be a whole number of bytes (got -1)",
            ),
            (
                "egress:\n  max_body_bytes: 1024\n",
                "egress.max_body_bytes must be between 1048576 (1 MiB) and 68719476736 bytes (got 1024)",
            ),
            (
                "egress:\n  body_budget_bytes: 137438953472\n",
                "egress.body_budget_bytes must be between 1048576 (1 MiB) and 68719476736 bytes (got 137438953472)",
            ),
            (
                "egress:\n  max_body_bytes: 2147483648\n",
                "egress.body_budget_bytes (1073741824) must be at least egress.max_body_bytes \
                 (2147483648): one body as large as the cap would never fit in the budget",
            ),
        ];
        for (yaml, want) in cases {
            assert_eq!(parse(yaml).unwrap_err(), want, "{yaml}");
        }
    }
}
