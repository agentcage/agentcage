//! The block-style YAML emitter, and the only place quoting is decided.
//!
//! # Why this is hand-written and not `serde_norway::to_string`
//!
//! `serde_norway` emits perfectly good YAML 1.2. That is the problem:
//! `no`, `on`, `1:30` and `2024-01-02` are plain strings in YAML 1.2, so
//! it writes them bare, and PyYAML on the far side of the trust boundary
//! reads them as `False`, `True`, `90` and a `datetime.date`. The crate
//! gives no hook for "quote this scalar anyway" — the style decision is
//! taken inside `Serializer::serialize_str` and handed to libyaml.
//!
//! So the *structure* is written here (mappings, sequences, indentation)
//! and each *scalar* is still handed to `serde_norway`, whose answer is
//! then overridden in exactly one case: the crate chose plain and
//! [`super::pyyaml::resolves_to_non_string`] says PyYAML would not read
//! it back as a string. That keeps libyaml's scalar analysis — which
//! knows about indicator characters, control characters, `: ` inside a
//! value, trailing spaces and non-printable code points — and adds the
//! one rule it is missing.
//!
//! The alternative, post-processing the crate's finished output, would
//! mean finding the hazardous scalars again in emitted text. That is a
//! second parser written in string operations, and it fails silently.
//!
//! # The self-check
//!
//! `dump` re-parses its own output with [`super::load`] and compares it,
//! **key order included**, against the value it was given. It is cheap,
//! and this emitter writes `proxy-config.yaml`, which is the file the
//! egress proxy's whole policy comes from. An emitter bug that mangles a
//! domain list should stop the write, not reach the security boundary.
//!
//! Going through `load` rather than `serde_norway` is deliberate: `load`
//! resolves plain YAML 1.1 booleans the way PyYAML does, so a hazardous
//! scalar this emitter failed to quote comes back as a `Bool` where the
//! value held a `String`, and the write fails. That makes the quoting
//! rule enforced at run time on the security-critical path, not only by
//! the test suite.
//!
//! # What it deliberately does not reproduce
//!
//! PyYAML's formatting. PyYAML wraps at 80 columns and has its own
//! quoting heuristics; RUST-PORT-PLAN.md section 2.8 accepts that the
//! port changes YAML formatting (comments are already dropped today,
//! `state.py:195`) and requires the golden corpus to compare YAML
//! by parsed value rather than by bytes. Sequence indentation *does*
//! match PyYAML's `default_flow_style=False` output — items sit at their
//! parent key's indentation — because that is what every config in the
//! repo already looks like and `cage edit` shows it to the user.

use serde_norway::{Mapping, Sequence, Value};

use super::{Error, custom_error, pyyaml};

/// Two spaces, like `yaml.safe_dump` and like every config in the repo.
const INDENT_STEP: usize = 2;

/// Render `value` as a block-style YAML document.
///
/// # Errors
///
/// - the value contains a non-scalar mapping key (`? [a, b] : c`), which
///   this emitter does not write and `yaml.safe_load` would hand back as
///   an unhashable list anyway;
/// - the value contains a tagged node (`!custom x`), which `safe_load`
///   refuses to construct;
/// - the self-check fails, meaning re-parsing the emitted text did not
///   give the value back. That is an emitter bug, and the error says so.
pub(super) fn dump(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_node(value, 0, &mut out)?;

    // Through `super::load`, not the bare crate, and that is the whole
    // point of the check. `load` resolves plain 1.1 booleans exactly as
    // PyYAML does, so a scalar this emitter forgot to quote comes back
    // as a `Bool` where the value held a `String` and the comparison
    // below fails. Re-parsing with `serde_norway` alone would hand back
    // the string either way and agree with itself while the egress
    // proxy read something else.
    let reparsed: Value = super::load(&out).map_err(|source| {
        custom_error(format!(
            "emitted YAML does not parse back (this is a bug in agentcage's \
             YAML emitter, not in your config): {source}\n--- emitted ---\n{out}"
        ))
    })?;
    if !super::eq_with_key_order(&reparsed, value) {
        return Err(custom_error(format!(
            "emitted YAML does not round-trip (this is a bug in agentcage's \
             YAML emitter, not in your config)\n--- emitted ---\n{out}"
        )));
    }

    Ok(out)
}

/// Write a node that owns whole lines, starting at column `indent`.
fn write_node(value: &Value, indent: usize, out: &mut String) -> Result<(), Error> {
    match value {
        Value::Mapping(mapping) if !mapping.is_empty() => write_mapping(mapping, indent, out),
        Value::Sequence(sequence) if !sequence.is_empty() => write_sequence(sequence, indent, out),
        scalar => {
            push_indent(out, indent);
            out.push_str(&scalar_repr(scalar, indent + INDENT_STEP)?);
            out.push('\n');
            Ok(())
        }
    }
}

/// Write a non-empty block mapping.
fn write_mapping(mapping: &Mapping, indent: usize, out: &mut String) -> Result<(), Error> {
    for (key, value) in mapping {
        push_indent(out, indent);
        out.push_str(&key_repr(key)?);
        out.push(':');
        match value {
            Value::Mapping(nested) if !nested.is_empty() => {
                out.push('\n');
                write_mapping(nested, indent + INDENT_STEP, out)?;
            }
            // Sequences sit at the key's own indentation, which is what
            // `yaml.safe_dump(default_flow_style=False)` does and what
            // every committed cage.yaml looks like.
            Value::Sequence(nested) if !nested.is_empty() => {
                out.push('\n');
                write_sequence(nested, indent, out)?;
            }
            scalar => {
                out.push(' ');
                out.push_str(&scalar_repr(scalar, indent + INDENT_STEP)?);
                out.push('\n');
            }
        }
    }
    Ok(())
}

/// Write a non-empty block sequence.
///
/// Each item is rendered as if it were a node at `indent + 2`, and the
/// `- ` is then spliced into the two columns the item left blank. That
/// puts a nested mapping's first key on the dash's line without a
/// special case for every shape an item can have.
fn write_sequence(sequence: &Sequence, indent: usize, out: &mut String) -> Result<(), Error> {
    for item in sequence {
        let mut rendered = String::new();
        write_node(item, indent + INDENT_STEP, &mut rendered)?;
        debug_assert!(
            rendered.is_char_boundary(indent + INDENT_STEP)
                && rendered[..indent + INDENT_STEP].bytes().all(|b| b == b' '),
            "write_node must open with its own indentation"
        );
        rendered.replace_range(indent..indent + INDENT_STEP, "- ");
        out.push_str(&rendered);
    }
    Ok(())
}

/// Render a mapping key.
///
/// # Errors
///
/// Non-scalar keys, and scalars that would need more than one line.
fn key_repr(key: &Value) -> Result<String, Error> {
    match key {
        Value::Mapping(mapping) if !mapping.is_empty() => Err(custom_error(
            "YAML mapping keys must be scalars; agentcage does not emit complex keys",
        )),
        Value::Sequence(sequence) if !sequence.is_empty() => Err(custom_error(
            "YAML mapping keys must be scalars; agentcage does not emit complex keys",
        )),
        // A key has to fit on its line, so the block-scalar style is
        // not available here. Double quotes carry a newline as `\n` and
        // PyYAML reads the key back intact.
        Value::String(text) if text.contains('\n') => Ok(double_quoted(text)),
        scalar => {
            let rendered = scalar_repr(scalar, 0)?;
            debug_assert!(
                !rendered.contains('\n'),
                "only strings can need more than one line"
            );
            Ok(rendered)
        }
    }
}

/// Render a scalar (or an empty collection) on the current line.
///
/// `continuation_indent` is where the second and later lines of a block
/// scalar go; it is ignored for everything that fits on one line.
fn scalar_repr(value: &Value, continuation_indent: usize) -> Result<String, Error> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(flag) => Ok(if *flag { "true" } else { "false" }.to_owned()),
        // Numbers cannot be misread: every spelling `serde_norway` emits
        // (`1`, `-1`, `1.5`, `.inf`, `.nan`) is a number in YAML 1.1 too.
        // Delegating keeps `-0.0`, integer/float distinction and the
        // infinities exactly as the crate spells them.
        Value::Number(_) => delegate(value),
        Value::String(text) => string_repr(text, continuation_indent),
        Value::Mapping(mapping) if mapping.is_empty() => Ok("{}".to_owned()),
        Value::Sequence(sequence) if sequence.is_empty() => Ok("[]".to_owned()),
        Value::Tagged(tagged) => Err(custom_error(format!(
            "cannot emit the YAML tag {} — `yaml.safe_load` in the egress \
             proxy has no constructor for it and would refuse the file",
            tagged.tag
        ))),
        Value::Mapping(_) | Value::Sequence(_) => Err(custom_error(
            "internal error: write_node should have handled a non-empty collection",
        )),
    }
}

/// Render a string scalar, quoting it when PyYAML would not read it back.
fn string_repr(text: &str, continuation_indent: usize) -> Result<String, Error> {
    if text.contains('\n') {
        return Ok(literal_block(text, continuation_indent).unwrap_or_else(|| double_quoted(text)));
    }

    let rendered = delegate(&Value::String(text.to_owned()))?;

    // libyaml already quoted it: nothing plain, nothing to fix.
    if rendered.starts_with('\'') || rendered.starts_with('"') {
        return Ok(rendered);
    }

    // libyaml chose plain. That is correct for YAML 1.2 and is exactly
    // where the 1.1 hazard lives.
    if pyyaml::resolves_to_non_string(text) {
        return Ok(single_quoted(text));
    }
    Ok(rendered)
}

/// Ask `serde_norway` to render one scalar, and take its answer.
///
/// The crate emits with libyaml's width limit disabled
/// (`yaml_emitter_set_width(-1)`), so a single-line scalar always comes
/// back as a single line however long it is.
fn delegate(value: &Value) -> Result<String, Error> {
    let rendered = serde_norway::to_string(value)?;
    Ok(rendered.trim_end_matches('\n').to_owned())
}

/// `'…'` with the one escape single-quoted YAML has.
///
/// Only reached for text libyaml already judged plain-safe, so it has no
/// newlines and no control characters.
fn single_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for character in text.chars() {
        if character == '\'' {
            out.push('\'');
        }
        out.push(character);
    }
    out.push('\'');
    out
}

/// `"…"` with YAML's double-quoted escapes.
///
/// The fallback for text no other style can carry: control characters,
/// `\r`, lines with trailing whitespace. PyYAML reads all of these back
/// verbatim.
fn double_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0}' => out.push_str("\\0"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `|` / `|-` block scalar, when the text is shaped for one.
///
/// Returns `None` when a block scalar would not round-trip: trailing
/// whitespace on a line (a block scalar eats it), a leading space on the
/// first line (which would need an explicit indentation indicator), a
/// control character, or more than one trailing newline (which would
/// need the `+` chomping indicator). Those fall back to double quotes.
fn literal_block(text: &str, indent: usize) -> Option<String> {
    let (body, header) = match text.strip_suffix('\n') {
        Some(stripped) if stripped.ends_with('\n') => return None,
        Some(stripped) => (stripped, "|"),
        None => (text, "|-"),
    };
    if body.is_empty() {
        return None;
    }

    for (position, line) in body.split('\n').enumerate() {
        if line.chars().any(char::is_control) {
            return None;
        }
        if line.ends_with(' ') {
            return None;
        }
        if position == 0 && (line.is_empty() || line.starts_with(' ')) {
            return None;
        }
    }

    let mut out = String::from(header);
    for line in body.split('\n') {
        out.push('\n');
        if !line.is_empty() {
            push_indent(&mut out, indent);
            out.push_str(line);
        }
    }
    Some(out)
}

/// Push `indent` spaces.
fn push_indent(out: &mut String, indent: usize) {
    out.extend(std::iter::repeat_n(' ', indent));
}

#[cfg(test)]
mod tests {
    use serde_norway::Value;

    use super::super::{dump, load};

    /// Emit a one-key mapping and give back what came after `k: `.
    fn emitted_value(text: &str) -> String {
        let mut mapping = serde_norway::Mapping::new();
        mapping.insert(
            Value::String("k".to_owned()),
            Value::String(text.to_owned()),
        );
        let rendered = dump(&Value::Mapping(mapping)).expect("dump");
        rendered
            .strip_prefix("k: ")
            .unwrap_or(&rendered)
            .trim_end_matches('\n')
            .to_owned()
    }

    #[test]
    fn the_1_1_booleans_are_quoted() {
        for text in [
            "yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF",
        ] {
            assert_eq!(emitted_value(text), format!("'{text}'"), "{text:?}");
        }
    }

    #[test]
    fn sexagesimals_timestamps_and_underscores_are_quoted() {
        for text in [
            "1:30",
            "12:00:00",
            "1:30.5",
            "-1:30",
            "1_000",
            "1_000.5",
            "2024-01-02",
            "2024-01-02T03:04:05",
            "=",
            "<<",
        ] {
            assert_eq!(emitted_value(text), format!("'{text}'"), "{text:?}");
        }
    }

    #[test]
    fn the_1_2_specials_are_still_quoted_by_the_crate() {
        for text in [
            "true", "false", "null", "~", "0755", "0x1F", ".inf", ".nan", "",
        ] {
            let rendered = emitted_value(text);
            assert!(
                rendered.starts_with('\'') || rendered.starts_with('"'),
                "{text:?} emitted as {rendered:?}"
            );
        }
    }

    #[test]
    fn ordinary_strings_stay_plain() {
        for text in [
            "api.anthropic.com",
            "claude-code",
            "ANTHROPIC_API_KEY",
            "/workspace/src",
            "read-only",
            "yes-man",
            "no-cache",
        ] {
            assert_eq!(emitted_value(text), text, "{text:?}");
        }
    }

    #[test]
    fn awkward_strings_survive() {
        for text in [
            "a: b",
            "# not a comment",
            "- not an item",
            "tail  ",
            "  lead",
            "quote'inside",
            "tab\tinside",
            "*anchor",
            "&amp",
            "@at",
            "`tick",
            "emoji \u{1f600}",
            "\u{7f}del",
            "cr\rlf",
        ] {
            let mut mapping = serde_norway::Mapping::new();
            mapping.insert(
                Value::String("k".to_owned()),
                Value::String(text.to_owned()),
            );
            let original = Value::Mapping(mapping);
            let rendered = dump(&original).expect("dump");
            assert_eq!(load(&rendered).expect("reload"), original, "{text:?}");
        }
    }

    #[test]
    fn multiline_strings_survive() {
        for text in [
            "line one\nline two",
            "trailing newline\n",
            "two blank\n\nlines\n",
            "trailing space \nhere",
            " leading space\nhere",
            "double\n\n\nnewline at end\n\n",
            "tab\there\nand here",
        ] {
            let mut mapping = serde_norway::Mapping::new();
            mapping.insert(
                Value::String("k".to_owned()),
                Value::String(text.to_owned()),
            );
            let original = Value::Mapping(mapping);
            let rendered = dump(&original).expect("dump");
            assert_eq!(load(&rendered).expect("reload"), original, "{text:?}");
        }
    }

    #[test]
    fn nested_shapes_render_the_way_pyyaml_does() {
        let source = "\
a: 1
b:
- x
- k: v
  l:
  - deep
c:
  d: {}
  e: []
f: null
";
        let value = load(source).expect("load");
        assert_eq!(dump(&value).expect("dump"), source);
    }

    /// The self-check is not decorative: show it would fire.
    ///
    /// There is no way to ask this emitter for a deliberately broken
    /// emission, so this asserts the mechanism instead — that the text
    /// an unquoted emission *would* produce does not read back as the
    /// value that produced it, which is exactly what `dump` compares.
    #[test]
    fn an_unquoted_hazard_would_fail_the_self_check() {
        let mut mapping = serde_norway::Mapping::new();
        mapping.insert(
            Value::String("domain".to_owned()),
            Value::String("no".to_owned()),
        );
        let value = Value::Mapping(mapping);

        // What this emitter writes, and what it reads back.
        assert_eq!(dump(&value).expect("dump"), "domain: 'no'\n");
        assert_eq!(load("domain: 'no'\n").expect("load"), value);

        // What the bare crate writes, and what the self-check would
        // make of it.
        assert_eq!(
            serde_norway::to_string(&value).expect("naive"),
            "domain: no\n"
        );
        assert_ne!(
            load("domain: no\n").expect("load"),
            value,
            "the self-check must be able to tell these apart"
        );
    }

    #[test]
    fn hazardous_keys_are_quoted_too() {
        let mut mapping = serde_norway::Mapping::new();
        mapping.insert(Value::String("no".to_owned()), Value::Bool(true));
        let rendered = dump(&Value::Mapping(mapping)).expect("dump");
        assert_eq!(rendered, "'no': true\n");
    }

    #[test]
    fn empty_documents() {
        assert_eq!(dump(&Value::Null).expect("dump"), "null\n");
        assert_eq!(
            dump(&Value::Mapping(serde_norway::Mapping::new())).expect("dump"),
            "{}\n"
        );
        assert_eq!(dump(&Value::Sequence(Vec::new())).expect("dump"), "[]\n");
    }

    #[test]
    fn tagged_nodes_are_refused_rather_than_emitted_plain() {
        // `!!str no` loads as the plain string "no" (the tag is resolved
        // away), so the tag that survives into `Value` is a custom one —
        // and `yaml.safe_load` cannot construct those. Refusing beats
        // writing a file the proxy will reject at load.
        let value = load("k: !custom 1").expect("load");
        let error = dump(&value).expect_err("custom tags must be refused");
        assert!(
            error.to_string().contains("!custom"),
            "unhelpful error: {error}"
        );
    }
}
