//! Scalar style, recovered from a second parse, and the YAML 1.1
//! boolean resolution that needs it.
//!
//! # The problem this solves
//!
//! `yaml.safe_load` resolves a **plain** `no` to `False` and a
//! **quoted** `'no'` to the string `"no"`. `relays/_validate.py:76` then
//! does `tls = bool(upstream.get("tls", True))`, so today:
//!
//! ```text
//! tls: no     ->  False  ->  bool(False) = False  ->  TLS off
//! tls: 'no'   ->  'no'   ->  bool('no')  = True   ->  TLS on
//! ```
//!
//! The second line is a bug in the Python — `bool()` of a non-empty
//! string is always `True` — but it is a bug that fails *safe*, on a
//! relay that carries real credentials upstream. A port that resolved
//! both spellings to `false` would turn it into a silent TLS
//! **downgrade**, and that is not a trade a port gets to make, however
//! rare the spelling.
//!
//! So agentcage has to tell `no` from `'no'`. Every serde YAML crate
//! throws scalar style away: `serde_norway` hands back
//! `Value::String("no")` for both, and its `libyaml` module — which does
//! know — is private. Even the explicit `!!str no` comes back
//! indistinguishable from a bare `no`.
//!
//! # How
//!
//! The document is parsed twice.
//!
//! 1. `serde_norway` produces the value tree. It stays **authoritative**:
//!    nothing here builds a value from the second parser, and a scalar's
//!    text, number parsing and `Tagged` handling are all left alone.
//! 2. [`saphyr_parser`] — a pure-Rust YAML event parser, no `libyaml`,
//!    no `unsafe` in its own source — produces a [`Shape`]: the same
//!    tree with nothing in it but "was this scalar plain?".
//! 3. [`resolve_1_1_booleans`] walks the two together and rewrites
//!    exactly one thing: a `Value::String` whose text is one of the
//!    twelve YAML 1.1-only boolean spellings, **and** whose scalar was
//!    written plain and untagged, becomes a `Value::Bool`.
//!
//! After that, [`super::load`] hands Track C's validators the same thing
//! `yaml.safe_load` hands `config.py`, and `bool()`-shaped coercions
//! port across literally.
//!
//! Why `saphyr-parser` and not `yaml-rust2`: both are pure Rust with the
//! same `arraydeque` dependency, and both expose scalar style. Only the
//! style is wanted, and `saphyr-parser` is the event parser on its own,
//! where `yaml-rust2` is a document model (`Yaml`, plus `hashlink`) with
//! a parser inside it. The narrower crate is the one whose whole surface
//! is the part being used. Its `0.1.0` is recent, which is worth saying
//! out loud — but see the fail-closed note below for why a bug in it
//! cannot produce a wrong value here, only an error.
//!
//! # Fail closed
//!
//! Two parsers can only be overlaid if they agree about the shape of the
//! document. Every disagreement — a different number of mapping entries,
//! a sequence where the other saw a scalar, an alias to an anchor that
//! was never defined, more than one document — is an [`Err`], never a
//! fallback to "leave it as a string".
//!
//! That is what makes the second parser's freshness a bounded risk. The
//! only thing it contributes is a boolean per scalar, and it is
//! contributed *against* a tree the first parser built. A
//! `saphyr-parser` bug can therefore make agentcage refuse a file it
//! should have accepted. It cannot make agentcage accept a file and get
//! the value wrong, which is the failure that matters.

use std::collections::HashMap;

use saphyr_parser::{Event, Parser, ScalarStyle};
use serde_norway::{Mapping, Value};

use super::{Error, custom_error, pyyaml};

/// A document's shape, carrying scalar style and nothing else.
///
/// Deliberately not a value: there is no scalar text in here, no
/// numbers, no tags. It cannot be mistaken for a second opinion about
/// what the document *means*, only about how it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Shape {
    /// A scalar, and whether it was written plain (unquoted, no block
    /// style) **and** carried no explicit tag.
    ///
    /// The tag matters: `!!str no` is a plain scalar as far as the
    /// scanner is concerned, but PyYAML honours the tag and gives back
    /// the string. Folding the tag into `plain` here keeps the one
    /// question this type answers a single boolean.
    Scalar { plain: bool },
    /// A sequence, and the shape of each item.
    Sequence(Vec<Shape>),
    /// A mapping, and the shape of each key and value, in order.
    Mapping(Vec<(Shape, Shape)>),
}

/// Parse `text` for shape alone.
///
/// `Ok(None)` means the stream held no document at all — an empty file,
/// or nothing but comments — which is `yaml.safe_load`'s `None` and
/// `serde_norway`'s [`Value::Null`].
///
/// # Errors
///
/// Malformed YAML, or more than one document. Both are reported by
/// `serde_norway` first in practice, since [`super::load`] calls it
/// before this; these exist so that a disagreement between the two
/// parsers about *whether* the text is valid is still an error and never
/// a silent skip.
pub(super) fn shape_of(source: &str, text: &str) -> Result<Option<Shape>, Error> {
    let events: Vec<Event<'_>> = Parser::new_from_str(text)
        .map(|event| event.map(|(event, _span)| event))
        .collect::<Result<_, _>>()
        .map_err(|error| {
            custom_error(format!(
                "{source}: could not re-read the file for scalar styles: {error}"
            ))
        })?;

    let mut reader = Reader {
        events: &events,
        position: 0,
        anchors: HashMap::new(),
        source,
    };
    reader.document()
}

/// A cursor over the event stream, plus the anchor table.
struct Reader<'a> {
    events: &'a [Event<'a>],
    position: usize,
    /// Anchor id to the shape of the node it labelled.
    ///
    /// `serde_norway` expands an alias into a copy of the anchored
    /// node's value, so the shape has to be expanded the same way or the
    /// two trees stop lining up at the first `*ref`.
    anchors: HashMap<usize, Shape>,
    source: &'a str,
}

impl<'a> Reader<'a> {
    /// The next event, or an "ended early" error.
    fn next(&mut self) -> Result<&'a Event<'a>, Error> {
        let event = self.events.get(self.position).ok_or_else(|| {
            custom_error(format!(
                "{}: the YAML event stream ended early",
                self.source
            ))
        })?;
        self.position += 1;
        Ok(event)
    }

    /// Read the stream's single document.
    fn document(&mut self) -> Result<Option<Shape>, Error> {
        match self.next()? {
            Event::StreamStart => {}
            other => return Err(self.unexpected("StreamStart", other)),
        }
        match self.next()? {
            Event::StreamEnd => return Ok(None),
            Event::DocumentStart(_) => {}
            other => return Err(self.unexpected("DocumentStart or StreamEnd", other)),
        }

        let shape = self.node()?;

        match self.next()? {
            Event::DocumentEnd => {}
            other => return Err(self.unexpected("DocumentEnd", other)),
        }
        match self.next()? {
            Event::StreamEnd => {}
            Event::DocumentStart(_) => {
                return Err(custom_error(format!(
                    "{}: more than one YAML document. agentcage reads one document \
                     per file; remove the `---` separator and the documents after it.",
                    self.source
                )));
            }
            other => return Err(self.unexpected("StreamEnd", other)),
        }

        Ok(Some(shape))
    }

    /// Read one node and everything under it.
    fn node(&mut self) -> Result<Shape, Error> {
        let shape = match self.next()? {
            Event::Scalar(_text, style, anchor, tag) => {
                let shape = Shape::Scalar {
                    plain: *style == ScalarStyle::Plain && tag.is_none(),
                };
                self.remember(*anchor, &shape);
                shape
            }
            Event::SequenceStart(anchor, _tag) => {
                let anchor = *anchor;
                let mut items = Vec::new();
                while !matches!(self.peek(), Some(Event::SequenceEnd)) {
                    items.push(self.node()?);
                }
                self.position += 1; // the SequenceEnd
                let shape = Shape::Sequence(items);
                self.remember(anchor, &shape);
                shape
            }
            Event::MappingStart(anchor, _tag) => {
                let anchor = *anchor;
                let mut pairs = Vec::new();
                while !matches!(self.peek(), Some(Event::MappingEnd)) {
                    let key = self.node()?;
                    let value = self.node()?;
                    pairs.push((key, value));
                }
                self.position += 1; // the MappingEnd
                let shape = Shape::Mapping(pairs);
                self.remember(anchor, &shape);
                shape
            }
            Event::Alias(anchor) => self.anchors.get(anchor).cloned().ok_or_else(|| {
                custom_error(format!(
                    "{}: alias to anchor {anchor}, which was never defined",
                    self.source
                ))
            })?,
            other => return Err(self.unexpected("a node", other)),
        };
        Ok(shape)
    }

    /// The event the cursor is on, without consuming it.
    fn peek(&self) -> Option<&'a Event<'a>> {
        self.events.get(self.position)
    }

    /// Record a node's shape under its anchor id, if it has one.
    ///
    /// Anchor id `0` means "no anchor" in `saphyr-parser`'s encoding.
    fn remember(&mut self, anchor: usize, shape: &Shape) {
        if anchor != 0 {
            self.anchors.insert(anchor, shape.clone());
        }
    }

    /// "Expected X, found Y", with the source named.
    fn unexpected(&self, expected: &str, found: &Event<'_>) -> Error {
        custom_error(format!(
            "{}: expected {expected} in the YAML event stream, found {found:?}",
            self.source
        ))
    }
}

/// Rewrite plain YAML 1.1 boolean scalars into real booleans.
///
/// `value` comes from `serde_norway`; `shape` comes from [`shape_of`] on
/// the same text. Every string whose text is one of the twelve
/// 1.1-only spellings and whose scalar was written plain and untagged
/// becomes a [`Value::Bool`] — in value position and in **key** position
/// alike, because `yaml.safe_load` of `no: 1` is `{False: 1}`.
///
/// # Errors
///
/// Any disagreement between the two parses, and any pair of mapping keys
/// that collide once resolved. Both name the path they happened at and
/// say what to do; neither falls back to leaving the value alone.
pub(super) fn resolve_1_1_booleans(
    source: &str,
    value: &mut Value,
    shape: &Shape,
) -> Result<(), Error> {
    let mut path = Vec::new();
    overlay(source, value, shape, &mut path)
}

/// The recursive half of [`resolve_1_1_booleans`].
fn overlay(
    source: &str,
    value: &mut Value,
    shape: &Shape,
    path: &mut Vec<String>,
) -> Result<(), Error> {
    match (&mut *value, shape) {
        // A custom tag survives into `Value::Tagged`, while the shape
        // has only the node under it. Step through the tag.
        (Value::Tagged(tagged), _) => overlay(source, &mut tagged.value, shape, path),

        (Value::Mapping(mapping), Shape::Mapping(pairs)) => {
            if mapping.len() != pairs.len() {
                return Err(misaligned(
                    source,
                    path,
                    &format!(
                        "the value tree has {} mapping entries and the style pass saw {}",
                        mapping.len(),
                        pairs.len()
                    ),
                ));
            }

            let taken = std::mem::replace(mapping, Mapping::new());
            let mut rebuilt = Mapping::new();
            for ((mut key, mut entry), (key_shape, value_shape)) in taken.into_iter().zip(pairs) {
                let before = key.clone();
                overlay(source, &mut key, key_shape, path)?;

                path.push(display_key(&key));
                overlay(source, &mut entry, value_shape, path)?;
                path.pop();

                if rebuilt.contains_key(&key) {
                    return Err(custom_error(format!(
                        "{source}: the key {} at {} resolves to {}, which another key in \
                         the same mapping already resolves to. YAML 1.1 — which the \
                         egress proxy's PyYAML speaks — reads `no`, `No`, `off` and \
                         `false` as the same value, so agentcage cannot tell which entry \
                         you meant. Keep one of them.",
                        display_key(&before),
                        display_path(path),
                        display_key(&key),
                    )));
                }
                rebuilt.insert(key, entry);
            }
            *mapping = rebuilt;
            Ok(())
        }

        (Value::Sequence(sequence), Shape::Sequence(items)) => {
            if sequence.len() != items.len() {
                return Err(misaligned(
                    source,
                    path,
                    &format!(
                        "the value tree has {} sequence items and the style pass saw {}",
                        sequence.len(),
                        items.len()
                    ),
                ));
            }
            for (index, (item, item_shape)) in sequence.iter_mut().zip(items).enumerate() {
                path.push(format!("[{index}]"));
                overlay(source, item, item_shape, path)?;
                path.pop();
            }
            Ok(())
        }

        // The one rewrite this module exists for.
        (Value::String(text), Shape::Scalar { plain: true }) => {
            if let Some(flag) = pyyaml::is_bool_1_1_only(text) {
                *value = Value::Bool(flag);
            }
            Ok(())
        }

        // Every other scalar: the shape agrees it is a scalar, and there
        // is nothing to rewrite.
        (
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_),
            Shape::Scalar { .. },
        ) => Ok(()),

        (value, shape) => Err(misaligned(
            source,
            path,
            &format!(
                "the value tree has {} and the style pass saw {}",
                describe_value(value),
                describe_shape(shape)
            ),
        )),
    }
}

/// The error every alignment failure produces.
fn misaligned(source: &str, path: &[String], detail: &str) -> Error {
    custom_error(format!(
        "{source}: agentcage could not line up the YAML structure with its scalar \
         styles at {} ({detail}). This is a bug in agentcage's YAML layer, not in \
         your file. agentcage refuses to guess here, because guessing is how \
         `tls: no` and `tls: 'no'` — which mean opposite things — get confused. \
         Please report it, with the file attached.",
        display_path(path)
    ))
}

/// `a.b[0].c`, or `the document root`.
pub(super) fn display_path(path: &[String]) -> String {
    if path.is_empty() {
        return "the document root".to_owned();
    }
    let mut out = String::new();
    for segment in path {
        if segment.starts_with('[') {
            out.push_str(segment);
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(segment);
        }
    }
    out
}

/// A mapping key, for an error message.
pub(super) fn display_key(key: &Value) -> String {
    match key {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "null".to_owned(),
        other => format!("{other:?}"),
    }
}

/// What kind of node this value is, in words.
fn describe_value(value: &Value) -> &'static str {
    match value {
        Value::Null => "a null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a sequence",
        Value::Mapping(_) => "a mapping",
        Value::Tagged(_) => "a tagged node",
    }
}

/// What kind of node this shape is, in words.
fn describe_shape(shape: &Shape) -> &'static str {
    match shape {
        Shape::Scalar { .. } => "a scalar",
        Shape::Sequence(_) => "a sequence",
        Shape::Mapping(_) => "a mapping",
    }
}

#[cfg(test)]
mod tests {
    use serde_norway::Value;

    use super::{Shape, resolve_1_1_booleans, shape_of};
    use crate::yaml::load;

    /// Shape a document and hand back what it saw.
    fn shape(text: &str) -> Shape {
        shape_of("<test>", text)
            .expect("shape")
            .expect("a document")
    }

    #[test]
    fn plain_and_quoted_scalars_are_told_apart() {
        let Shape::Mapping(pairs) = shape("a: no\nb: 'no'\nc: \"no\"\nd: |-\n  no\n") else {
            panic!("expected a mapping");
        };
        let plainness: Vec<bool> = pairs
            .iter()
            .map(|(_, value)| matches!(value, Shape::Scalar { plain: true }))
            .collect();
        assert_eq!(plainness, [true, false, false, false]);
    }

    #[test]
    fn an_explicit_tag_is_not_plain() {
        // `!!str no` is a plain scalar to the scanner but a string to
        // PyYAML, which honours the tag. Folding the tag into `plain`
        // is what keeps those two facts from fighting.
        let Shape::Mapping(pairs) = shape("k: !!str no\n") else {
            panic!("expected a mapping");
        };
        assert_eq!(pairs[0].1, Shape::Scalar { plain: false });
    }

    #[test]
    fn aliases_expand_the_way_the_value_tree_does() {
        // `serde_norway` copies the anchored node into every alias, so
        // the shape has to as well or the trees stop lining up.
        let value = load("a: &x {p: no}\nb: *x\n").expect("load");
        assert_eq!(value["a"]["p"], Value::Bool(false));
        assert_eq!(value["b"]["p"], Value::Bool(false));
    }

    #[test]
    fn an_undefined_alias_is_an_error() {
        // `saphyr-parser` rejects this one before the walk ever sees
        // it ("unknown anchor"), so what this pins is that the error
        // names the source and does not become a silent skip. The
        // `Alias` arm's own error stays as the belt to that braces.
        let error = shape_of("<test>", "a: *nope\n").expect_err("undefined alias");
        let message = error.to_string();
        assert!(message.starts_with("<test>: "), "{error}");
        assert!(
            message.contains("unknown anchor") || message.contains("never defined"),
            "{error}"
        );
    }

    #[test]
    fn a_second_document_is_an_error() {
        let error = shape_of("<test>", "a: 1\n---\nb: 2\n").expect_err("two documents");
        assert!(
            error.to_string().contains("more than one YAML document"),
            "{error}"
        );
    }

    #[test]
    fn an_empty_stream_has_no_document() {
        assert_eq!(shape_of("<test>", "").expect("shape"), None);
        assert_eq!(shape_of("<test>", "# nothing\n").expect("shape"), None);
    }

    /// The fail-closed contract, forced.
    ///
    /// The two parsers agree on every input this crate has seen, so the
    /// only way to prove the misalignment path is an error rather than a
    /// shrug is to hand it a shape that does not fit.
    #[test]
    fn a_shape_that_does_not_fit_is_refused() {
        let mut value = load("a: no\nb: no\n").expect("load");

        // One entry short.
        let short = Shape::Mapping(vec![(
            Shape::Scalar { plain: true },
            Shape::Scalar { plain: true },
        )]);
        let error =
            resolve_1_1_booleans("cage.yaml", &mut value.clone(), &short).expect_err("short");
        assert!(error.to_string().contains("cage.yaml"), "{error}");
        assert!(error.to_string().contains("2 mapping entries"), "{error}");
        assert!(error.to_string().contains("report it"), "{error}");

        // Right size, wrong kind.
        let wrong = Shape::Sequence(vec![Shape::Scalar { plain: true }]);
        let error = resolve_1_1_booleans("cage.yaml", &mut value, &wrong).expect_err("wrong");
        assert!(
            error.to_string().contains("has a mapping")
                && error.to_string().contains("saw a sequence"),
            "{error}"
        );
    }

    #[test]
    fn a_mismatch_deep_in_the_tree_names_its_path() {
        let mut value = load("outer:\n  inner:\n  - x\n  - y\n").expect("load");
        let shape = Shape::Mapping(vec![(
            Shape::Scalar { plain: true },
            Shape::Mapping(vec![(
                Shape::Scalar { plain: true },
                Shape::Sequence(vec![Shape::Scalar { plain: true }]),
            )]),
        )]);
        let error = resolve_1_1_booleans("cage.yaml", &mut value, &shape).expect_err("deep");
        assert!(
            error.to_string().contains("at outer.inner"),
            "path missing: {error}"
        );
    }

    #[test]
    fn keys_that_collide_once_resolved_are_refused() {
        // `no` and `No` are both `False` to PyYAML, which takes the last
        // silently. agentcage would rather say so.
        let error = load("no: 1\nNo: 2\n").expect_err("colliding keys");
        assert!(error.to_string().contains("Keep one of them"), "{error}");
    }
}
