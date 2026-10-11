//! The handful of Python value semantics the watcher's record handling
//! leans on.
//!
//! The watcher reads records it did not write — capture lines, ring
//! entries, a model's tool arguments — and the implementation it replaces
//! coerced every field with `str(x)`, `x or default`, `int(x)` and
//! `s[:n]`. Those coercions decide what reaches the digest, so they are
//! reproduced here rather than approximated at each call site.

use agentcage_core::python::repr_str;

use crate::json::{Json, format_float};

/// Python `str(value)` for a value `json.loads` produced.
pub(crate) fn py_str(value: &Json) -> String {
    match value {
        Json::Str(s) => s.clone(),
        other => py_repr(other),
    }
}

/// Python `repr(value)` for a value `json.loads` produced.
///
/// Containers repr their items, so `str(["a"])` is `['a']`. Strings go
/// through the host's `repr_str` (CPython quoting; C0/C1 controls
/// escaped), which only matters for a malformed record whose field was a
/// container instead of a string.
pub(crate) fn py_repr(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Int(i) => i.to_string(),
        Json::BigInt(digits) => digits.clone(),
        Json::Float(f) => float_str(*f),
        Json::Str(s) => repr_str(s),
        Json::Array(items) => {
            let inner: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Json::Object(pairs) => {
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", repr_str(k), py_repr(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// `str(float)`: `repr` digits, but `nan`/`inf` rather than JSON's spelling.
pub(crate) fn float_str(value: f64) -> String {
    if value.is_nan() {
        "nan".to_owned()
    } else if value.is_infinite() {
        if value > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else {
        format_float(value)
    }
}

/// `x or default` on an optional value: `None` when absent or falsy.
pub(crate) fn truthy(value: Option<&Json>) -> Option<&Json> {
    value.filter(|v| v.is_truthy())
}

/// `str(x or default)`.
pub(crate) fn str_or(value: Option<&Json>, default: &str) -> String {
    truthy(value).map_or_else(|| default.to_owned(), py_str)
}

/// `str(d.get(key, default))`: absent → `default`, present (even null or
/// falsy) → `str()` of it.
pub(crate) fn str_get(obj: &Json, key: &str, default: &str) -> String {
    obj.get(key).map_or_else(|| default.to_owned(), py_str)
}

/// `d.get(key) or {}` when the result is used as a mapping: a falsy or
/// non-object value reads as an empty object.
///
/// The replaced implementation called `.get` on whatever was there and so
/// crashed the scan on a truthy non-mapping (a list where an object
/// belongs) — and since the capture offset only advances on success, it
/// re-read and re-crashed on that line forever. Treating it as empty is
/// the fail-safe reading.
pub(crate) fn obj(value: Option<&Json>) -> &Json {
    static EMPTY: Json = Json::Object(Vec::new());
    match value {
        Some(v @ Json::Object(_)) => v,
        _ => &EMPTY,
    }
}

/// `s[:n]`, by code points.
pub(crate) fn prefix(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((at, _)) => s[..at].to_owned(),
        None => s.to_owned(),
    }
}

/// `int(x)` for a value `json.loads` produced; `None` where Python raises.
///
/// The replaced implementation let the `ValueError` escape and fail the
/// scan; the callers here substitute the field's default instead.
pub(crate) fn py_int(value: &Json) -> Option<i64> {
    match value {
        Json::Int(i) => Some(*i),
        Json::Bool(b) => Some(i64::from(*b)),
        #[allow(clippy::cast_possible_truncation)]
        Json::Float(f) if f.is_finite() => Some(f.trunc() as i64),
        Json::Str(s) => {
            let t = s.trim();
            let digits: String = t.chars().filter(|c| *c != '_').collect();
            if t.starts_with('_') || t.ends_with('_') || t.contains("__") {
                return None;
            }
            digits.parse().ok()
        }
        _ => None,
    }
}

/// `items[-n:]`, including Python's `x[-0:] == x` quirk and a negative `n`
/// meaning "drop the first `|n|`".
pub(crate) fn tail<T>(items: &[T], n: i64) -> &[T] {
    let len = items.len();
    let skip = match n {
        0 => 0,
        n if n > 0 => len.saturating_sub(usize::try_from(n).unwrap_or(usize::MAX)),
        n => usize::try_from(n.unsigned_abs())
            .unwrap_or(usize::MAX)
            .min(len),
    };
    &items[skip..]
}

/// A key that is equal for exactly the values Python's `==` (and so a
/// dict key) treats as equal: `200`, `200.0` and `True`/`1` collapse.
pub(crate) fn eq_key(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => "n".to_owned(),
        Some(Json::Bool(b)) => format!("i{}", i64::from(*b)),
        Some(Json::Int(i)) => format!("i{i}"),
        Some(Json::BigInt(d)) => format!("i{d}"),
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        Some(Json::Float(f)) if f.fract() == 0.0 && f.abs() < 9.0e15 => {
            format!("i{}", *f as i64)
        }
        Some(Json::Float(f)) => format!("f{}", float_str(*f)),
        Some(Json::Str(s)) => format!("s{s}"),
        Some(other) => format!("j{}", crate::json::to_compact_string(other)),
    }
}

/// `d.pop(key, None)` on an object.
pub(crate) fn remove(value: &mut Json, key: &str) {
    if let Json::Object(pairs) = value {
        pairs.retain(|(k, _)| k != key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_and_repr_follow_python() {
        assert_eq!(py_str(&Json::Null), "None");
        assert_eq!(py_str(&Json::Float(1.0)), "1.0");
        assert_eq!(py_str(&Json::Float(f64::NAN)), "nan");
        let v = crate::json::parse(r#"{"a": [1, "it's", "q\"", null, true]}"#).unwrap();
        assert_eq!(py_str(&v), r#"{'a': [1, "it's", 'q"', None, True]}"#);
    }

    #[test]
    fn tail_reproduces_negative_slices() {
        let v = [1, 2, 3, 4];
        assert_eq!(tail(&v, 2), &[3, 4]);
        assert_eq!(tail(&v, 0), &v);
        assert_eq!(tail(&v, 9), &v);
        assert_eq!(tail(&v, -1), &[2, 3, 4]);
        assert_eq!(tail(&v, -9), &[] as &[i32]);
    }

    #[test]
    fn int_coerces_like_python() {
        assert_eq!(py_int(&Json::string(" 1_000 ")), Some(1000));
        assert_eq!(py_int(&Json::string("1.5")), None);
        assert_eq!(py_int(&Json::Float(-2.9)), Some(-2));
        assert_eq!(py_int(&Json::Bool(true)), Some(1));
    }
}
