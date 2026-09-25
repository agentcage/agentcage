//! `<<` merge keys, and the two scalars PyYAML refuses outright.
//!
//! # Why this is not `Value::apply_merge`
//!
//! `serde_norway` parses `<<: *anchor` into a literal `"<<"` key and
//! leaves merging to an opt-in `Value::apply_merge()` call. PyYAML has
//! no such switch: `SafeLoader` resolves a plain `<<` to
//! `tag:yaml.org,2002:merge` and `construct_mapping` flattens it before
//! the caller ever sees the dict. So the two readers disagree about
//! what a file *means*, not about how to render it, and the
//! disagreement is silent — a config that shares a block between two
//! sections would come back with an untouched `<<` key and every
//! merged setting missing, which reads exactly like "the operator
//! never wrote them".
//!
//! That is the failure mode agentcage cannot have. `domains.allow`
//! assembled from a shared anchor would quietly become an empty
//! allowlist; a relay's `upstream` merged from a template would lose
//! its `tls: true`. Neither raises. So [`apply`] runs on every
//! document [`super::load`] reads, and the port keeps PyYAML's
//! semantics rather than the crate's default.
//!
//! `apply_merge()` is not used even as the engine, for two reasons
//! that both show up in a `cage edit` diff:
//!
//! * **Key order.** It appends the merged keys after the explicit ones.
//!   PyYAML *prepends* them (`node.value = merge + node.value`), so a
//!   key that appears in both keeps the merged position. `cage.yaml` is
//!   written back with `sort_keys=False` and the user reads that file,
//!   so the order is part of the output.
//! * **Sequence precedence.** For `<<: [*a, *b]` PyYAML reverses the
//!   list before merging, which makes the *earlier* alias win — the
//!   YAML spec's rule. Getting that backwards silently picks the wrong
//!   value whenever two merged blocks overlap.
//!
//! # The two scalars
//!
//! `<<` and `=` resolve to tags `SafeConstructor` has no constructor
//! for, so PyYAML raises `ConstructorError` on either one wherever it
//! is not being used as a merge key. Measured against PyYAML 6.0.3:
//!
//! | Document | `yaml.safe_load` |
//! | :-- | :-- |
//! | `child:\n  <<: *base` | the anchor's keys, merged in |
//! | `<<: [{a: 1}]` | `{'a': 1}` |
//! | `k: <<`, `- <<` | **raises** — merge tag, no constructor |
//! | `x:\n  <<: 5` | **raises** — not a mapping or list of mappings |
//! | `=: 1` | `{'=': 1}` — a key is retagged to `str` |
//! | `k: =`, `- =` | **raises** — value tag, no constructor |
//! | `k: "<<"` | `'<<'` — a quoted scalar is just a string |
//!
//! The last row is why this pass needs [`Shape`] and cannot work on the
//! value tree alone: `serde_norway` gives `Value::String("<<")` for the
//! quoted and the plain spelling alike, and only the plain one is a
//! merge key. It is the same distinction [`super::style`] exists for,
//! so it reuses the same shape tree rather than parsing a third time.
//!
//! Where PyYAML raises, so does this — the wording is agentcage's, but
//! the set of accepted documents is the same one the egress proxy
//! accepts.

use serde_norway::{Mapping, Value};

use super::style::{Shape, display_key, display_path};
use super::{Error, custom_error};

/// The `tag:yaml.org,2002:merge` scalar.
const MERGE: &str = "<<";

/// The `tag:yaml.org,2002:value` scalar.
const VALUE: &str = "=";

/// Flatten every `<<` merge key in `value`, the way PyYAML does.
///
/// `shape` must be the tree [`super::style::shape_of`] produced for the
/// same text, already checked for alignment by
/// [`super::style::resolve_1_1_booleans`] — this runs after it, so a
/// mismatch here means the value tree was rewritten in between.
///
/// # Errors
///
/// A `<<` whose value is not a mapping or a list of mappings, a plain
/// `<<` or `=` used anywhere but as a mapping key, or a shape that no
/// longer lines up with the value tree.
pub(super) fn apply(source: &str, value: &mut Value, shape: &Shape) -> Result<(), Error> {
    let mut path = Vec::new();
    reject_special(source, value, shape, &path)?;
    walk(source, value, shape, &mut path)
}

/// Flatten `value` in place, depth first.
///
/// Depth first is not an implementation detail: PyYAML calls
/// `flatten_mapping` on the merge *source* before splicing its pairs
/// in, so a chain of anchors that each merge the one below resolves
/// fully. Doing the children first gets the same answer without
/// tracking which nodes have been visited, because `serde_norway`
/// already expanded every alias into its own copy.
fn walk(
    source: &str,
    value: &mut Value,
    shape: &Shape,
    path: &mut Vec<String>,
) -> Result<(), Error> {
    match (&mut *value, shape) {
        // A custom tag survives into `Value::Tagged` while the shape
        // holds only the node under it — the same step-through
        // `style::overlay` does.
        (Value::Tagged(tagged), _) => walk(source, &mut tagged.value, shape, path),

        (Value::Sequence(items), Shape::Sequence(item_shapes)) => {
            expect_len(
                source,
                path,
                items.len(),
                item_shapes.len(),
                "sequence items",
            )?;
            for (index, (item, item_shape)) in items.iter_mut().zip(item_shapes).enumerate() {
                path.push(format!("[{index}]"));
                reject_special(source, item, item_shape, path)?;
                walk(source, item, item_shape, path)?;
                path.pop();
            }
            Ok(())
        }

        (Value::Mapping(mapping), Shape::Mapping(pairs)) => {
            expect_len(source, path, mapping.len(), pairs.len(), "mapping entries")?;
            let taken = std::mem::replace(mapping, Mapping::new());

            // PyYAML collects the merged pairs in document order and
            // then puts the whole lot *in front of* the explicit ones,
            // so both lists are built before either is inserted.
            let mut merged: Vec<(Value, Value)> = Vec::new();
            let mut explicit: Vec<(Value, Value)> = Vec::new();

            for ((mut key, mut entry), (key_shape, value_shape)) in taken.into_iter().zip(pairs) {
                if is_merge_key(&key, key_shape) {
                    path.push(MERGE.to_owned());
                    walk(source, &mut entry, value_shape, path)?;
                    collect_merge(source, entry, path, &mut merged)?;
                    path.pop();
                    continue;
                }

                // A composite key can hide a `<<` or `=` of its own.
                // Nothing in agentcage's own schema uses one, but the
                // reader is PyYAML-equivalent or it is nothing.
                reject_special_in_key(source, &key, key_shape, path)?;
                walk(source, &mut key, key_shape, path)?;

                path.push(display_key(&key));
                reject_special(source, &entry, value_shape, path)?;
                walk(source, &mut entry, value_shape, path)?;
                path.pop();

                explicit.push((key, entry));
            }

            // `Mapping` is an `IndexMap`: re-inserting an existing key
            // replaces the value and keeps the key where it first
            // landed. That is Python's `dict` rule, which is what makes
            // the merged-first ordering above come out like PyYAML's —
            // an explicit override wins on value, and the merged entry
            // wins on position.
            let mut rebuilt = Mapping::new();
            for (key, entry) in merged.into_iter().chain(explicit) {
                rebuilt.insert(key, entry);
            }
            *mapping = rebuilt;
            Ok(())
        }

        // Scalars, and a shape that agrees. `reject_special` has
        // already run on this node from its parent (or from `apply`,
        // for the document root).
        (_, Shape::Scalar { .. }) => Ok(()),

        (value, shape) => Err(misaligned(
            source,
            path,
            &format!(
                "the value tree has {} and the style pass saw {}",
                describe(value),
                describe_shape(shape)
            ),
        )),
    }
}

/// Splice one `<<` value's pairs into `merged`.
///
/// `entry` has already been walked, so a merge source that itself
/// merges is fully resolved by the time its pairs are read.
fn collect_merge(
    source: &str,
    entry: Value,
    path: &[String],
    merged: &mut Vec<(Value, Value)>,
) -> Result<(), Error> {
    match entry {
        Value::Mapping(mapping) => {
            merged.extend(mapping);
            Ok(())
        }
        Value::Sequence(items) => {
            // PyYAML reverses the list and then extends, so the
            // *first* alias in the sequence is inserted last and wins.
            // That is the spec's precedence rule and the opposite of
            // what a straight left-to-right merge gives.
            let mut blocks = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Mapping(mapping) => blocks.push(mapping),
                    other => {
                        return Err(custom_error(format!(
                            "{source}: the `<<` merge key at {} lists {}, but every item \
                             in a merge list has to be a mapping to merge from.",
                            display_path(path),
                            describe(&other)
                        )));
                    }
                }
            }
            blocks.reverse();
            for block in blocks {
                merged.extend(block);
            }
            Ok(())
        }
        other => Err(custom_error(format!(
            "{source}: the `<<` merge key at {} is {}, but a merge key takes a mapping \
             (`<<: *anchor`) or a list of mappings (`<<: [*a, *b]`).",
            display_path(path),
            describe(&other)
        ))),
    }
}

/// Is this key the merge key, rather than the two-character string?
fn is_merge_key(key: &Value, shape: &Shape) -> bool {
    matches!(key, Value::String(text) if text == MERGE)
        && matches!(shape, Shape::Scalar { plain: true })
}

/// Reject a plain `<<` or `=` outside a mapping key.
fn reject_special(
    source: &str,
    value: &Value,
    shape: &Shape,
    path: &[String],
) -> Result<(), Error> {
    let Value::String(text) = value else {
        return Ok(());
    };
    if !matches!(shape, Shape::Scalar { plain: true }) {
        return Ok(());
    }
    match text.as_str() {
        MERGE => Err(custom_error(format!(
            "{source}: a plain `<<` at {} is YAML's merge indicator, not a string. The \
             egress proxy's PyYAML refuses to load a file that uses it anywhere but as a \
             mapping key. Write it as `'<<'` if you meant the two characters.",
            display_path(path)
        ))),
        VALUE => Err(custom_error(format!(
            "{source}: a plain `=` at {} is YAML's value indicator, not a string. The \
             egress proxy's PyYAML refuses to load a file that uses it anywhere but as a \
             mapping key. Write it as `'='` if you meant the one character.",
            display_path(path)
        ))),
        _ => Ok(()),
    }
}

/// Reject a plain `<<` in key position.
///
/// `=` is fine here: `flatten_mapping` retags a `value`-tagged key to
/// `str`, so `=: 1` is the ordinary dict `{'=': 1}`. Only `<<` is left,
/// and by the time this runs it has already failed [`is_merge_key`] —
/// which can only mean the shape pass and the value tree disagree about
/// it.
fn reject_special_in_key(
    source: &str,
    key: &Value,
    shape: &Shape,
    path: &[String],
) -> Result<(), Error> {
    if matches!(key, Value::String(text) if text == MERGE)
        && matches!(shape, Shape::Scalar { plain: true })
    {
        return Err(misaligned(
            source,
            path,
            "a plain `<<` key was not recognised as a merge key",
        ));
    }
    Ok(())
}

/// Two trees that must have the same arity at this node.
fn expect_len(
    source: &str,
    path: &[String],
    value_len: usize,
    shape_len: usize,
    what: &str,
) -> Result<(), Error> {
    if value_len == shape_len {
        return Ok(());
    }
    Err(misaligned(
        source,
        path,
        &format!("the value tree has {value_len} {what} and the style pass saw {shape_len}"),
    ))
}

/// The error a value/shape disagreement produces.
///
/// Worded like [`super::style`]'s: by the time this module runs the two
/// trees have already been lined up once, so a failure here is an
/// agentcage bug rather than anything the operator wrote.
fn misaligned(source: &str, path: &[String], detail: &str) -> Error {
    custom_error(format!(
        "{source}: agentcage could not line up the YAML structure with its scalar styles \
         at {} ({detail}) while applying `<<` merge keys. This is a bug in agentcage's \
         YAML layer, not in your file. Please report it, with the file attached.",
        display_path(path)
    ))
}

/// A value's kind, for an error message.
fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a sequence",
        Value::Mapping(_) => "a mapping",
        Value::Tagged(_) => "a tagged node",
    }
}

/// A shape's kind, for an error message.
fn describe_shape(shape: &Shape) -> &'static str {
    match shape {
        Shape::Scalar { .. } => "a scalar",
        Shape::Sequence(_) => "a sequence",
        Shape::Mapping(_) => "a mapping",
    }
}

#[cfg(test)]
mod tests {
    use crate::yaml::{Value, load};

    /// `child` gets the anchor's keys, and its own `b` wins.
    ///
    /// The expected value is `yaml.safe_load`'s, measured: PyYAML
    /// returns `{'a': 1, 'b': 3, 'c': 4}` — `b` overridden but still in
    /// the position the merge gave it.
    #[test]
    fn a_merge_key_brings_the_anchor_in() {
        let value =
            load("base: &b\n  a: 1\n  b: 2\nchild:\n  <<: *b\n  b: 3\n  c: 4\n").expect("load");
        let child = &value["child"];
        assert_eq!(child["a"], Value::Number(1.into()));
        assert_eq!(child["b"], Value::Number(3.into()));
        assert_eq!(child["c"], Value::Number(4.into()));
        assert!(child.get("<<").is_none(), "the merge key must be gone");
    }

    /// Merged keys come first, explicit keys after — PyYAML's
    /// `merge + node.value`. `cage edit` shows this order to the user.
    #[test]
    fn merged_keys_keep_pyyaml_s_position() {
        let value = load("base: &b\n  a: 1\nchild:\n  c: 9\n  <<: *b\n  b: 3\n").expect("load");
        let keys: Vec<&str> = value["child"]
            .as_mapping()
            .expect("mapping")
            .keys()
            .map(|key| key.as_str().expect("string key"))
            .collect();
        assert_eq!(keys, ["a", "c", "b"]);
    }

    /// An override keeps the merged key's position, not its own.
    #[test]
    fn an_override_does_not_move_the_key() {
        let value = load("base: &b\n  a: 1\n  b: 2\nchild:\n  b: 3\n  <<: *b\n").expect("load");
        let child = value["child"].as_mapping().expect("mapping").clone();
        let keys: Vec<&str> = child.keys().map(|key| key.as_str().expect("str")).collect();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(child["b"], Value::Number(3.into()));
    }

    /// `<<: [*a, *b]` — the earlier alias wins, per the spec and per
    /// PyYAML's `submerge.reverse()`.
    #[test]
    fn the_first_alias_in_a_merge_list_wins() {
        let value =
            load("a: &a\n  x: 1\nb: &b\n  x: 2\n  y: 3\nc:\n  <<: [*a, *b]\n").expect("load");
        assert_eq!(value["c"]["x"], Value::Number(1.into()));
        assert_eq!(value["c"]["y"], Value::Number(3.into()));
    }

    /// A merge source that merges resolves all the way down.
    #[test]
    fn merges_chain() {
        let value =
            load("one: &one\n  a: 1\ntwo: &two\n  <<: *one\n  b: 2\nthree:\n  <<: *two\n  c: 3\n")
                .expect("load");
        assert_eq!(value["three"]["a"], Value::Number(1.into()));
        assert_eq!(value["three"]["b"], Value::Number(2.into()));
        assert_eq!(value["three"]["c"], Value::Number(3.into()));
    }

    /// A quoted `'<<'` is a string, exactly as PyYAML reads it. This is
    /// the row that makes the shape pass load-bearing here.
    #[test]
    fn a_quoted_merge_key_stays_a_key() {
        let value = load("child:\n  '<<': 1\n").expect("load");
        assert_eq!(value["child"]["<<"], Value::Number(1.into()));
    }

    /// `=` is a legal key and an illegal value, both like PyYAML.
    #[test]
    fn the_value_indicator_follows_pyyaml() {
        assert_eq!(load("=: 1\n").expect("load")["="], Value::Number(1.into()));
        assert!(load("k: =\n").is_err());
        assert!(load("- =\n").is_err());
        // Quoted, it is just a string again.
        assert_eq!(
            load("k: '='\n").expect("load")["k"],
            Value::String("=".into())
        );
    }

    /// A plain `<<` outside key position is an error, not a string.
    #[test]
    fn a_stray_merge_scalar_is_an_error() {
        assert!(load("k: <<\n").is_err());
        assert!(load("- <<\n").is_err());
        assert_eq!(
            load("k: '<<'\n").expect("load")["k"],
            Value::String("<<".into())
        );
    }

    /// A merge key needs something to merge.
    #[test]
    fn a_merge_key_that_is_not_a_mapping_is_an_error() {
        let error = load("x:\n  <<: 5\n").expect_err("not a mapping");
        assert!(
            error.to_string().contains("merge key"),
            "unexpected message: {error}"
        );
        assert!(load("x:\n  <<: [1]\n").is_err());
    }

    /// Nothing without a `<<` changes, which is what keeps this pass
    /// free for every config in the repo.
    #[test]
    fn documents_without_merge_keys_are_untouched() {
        let source = "zebra: 1\nnested:\n  apple: [1, 2]\n  mango: {x: 'y'}\n";
        let value = load(source).expect("load");
        assert_eq!(crate::yaml::dump(&value).expect("dump"), {
            let reparsed = load(source).expect("load");
            crate::yaml::dump(&reparsed).expect("dump")
        });
        assert_eq!(value["nested"]["mango"]["x"], Value::String("y".into()));
    }
}
