//! HAR 1.2 builder and capture JSONL filtering.
//!
//! Runs on the host — reads capture JSONL entries and produces standard
//! HAR JSON loadable in Chrome `DevTools`.
//!
//! This is the port of `src/agentcage/har.py`. The Python is a handful
//! of small functions over untyped `dict`s, and the shape of the output
//! is the whole contract: `tests/fixtures/golden/shared/har/` holds what
//! the Python produced from `_inputs/capture.jsonl`, in both views and
//! across eight filters, and `tests/golden_har.rs` reproduces those five
//! files byte for byte.
//!
//! # Where the port is deliberately not literal
//!
//! The Python reads capture entries with `dict.get` and never checks a
//! type, so a malformed entry can reach an `AttributeError` or a
//! `TypeError` that nothing catches — `_build_headers` on a header that
//! is not a pair, `_build_response_entry` on a `response` that is a
//! string. Rust has no equivalent to a traceback out of a pure function,
//! and the value of `cage har` is that it exports what it can, so this
//! port treats a wrongly-typed field the way it treats a missing one.
//! Each site says so where it happens. The capture writer only ever
//! emits well-formed entries, so this is about hostile or corrupt files,
//! not about normal operation.
//!
//! One behaviour that is *not* a simplification and is preserved
//! exactly: comparing a naive timestamp against an aware `--since`
//! cutoff raises `TypeError` in Python and
//! [`CaptureFilter::matches`] keeps the entry. See [`datetime`].

pub mod datetime;
pub mod json;
pub mod query;

use datetime::DateTime;
use json::{DumpOptions, Json};

/// How severe a decision is, for `--min-action`.
///
/// `har.py`'s `_ACTION_ORDER`, spelled as a function so an unknown name
/// lands on 0 the way `dict.get(name, 0)` does.
fn action_order(name: &str) -> u8 {
    match name {
        "flag" => 1,
        "block" => 2,
        // "all", and anything else.
        _ => 0,
    }
}

/// Filter capture entries (mirrors `AuditFilter`'s pattern).
///
/// An empty list means "no constraint on this field", as in the Python.
#[derive(Clone, Debug, Default)]
pub struct CaptureFilter {
    /// Keep only these `decision` values.
    pub decisions: Vec<String>,
    /// Keep only these `direction` values.
    pub directions: Vec<String>,
    /// Keep an entry whose `host` *contains* any of these.
    pub hosts: Vec<String>,
    /// Keep only these methods, compared case-insensitively.
    pub methods: Vec<String>,
    /// Keep entries at or above this action level: `all`, `flag` or
    /// `block`.
    pub min_action: Option<String>,
    /// Keep entries at or after this instant.
    pub since: Option<DateTime>,
}

impl CaptureFilter {
    /// Whether `entry` survives every constraint.
    #[must_use]
    pub fn matches(&self, entry: &Json) -> bool {
        if !self.decisions.is_empty() && !field_in(entry, "decision", &self.decisions) {
            return false;
        }
        if !self.directions.is_empty() && !field_in(entry, "direction", &self.directions) {
            return false;
        }
        if !self.hosts.is_empty() {
            // `entry.get("host", "")`, then a substring test per host.
            let host = entry.get("host").and_then(Json::as_str).unwrap_or("");
            if !self.hosts.iter().any(|needle| host.contains(needle)) {
                return false;
            }
        }
        if !self.methods.is_empty() {
            let method = entry
                .get("method")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_uppercase();
            if !self.methods.iter().any(|m| m.to_uppercase() == method) {
                return false;
            }
        }
        if let Some(min_action) = &self.min_action {
            let decision = entry
                .get("decision")
                .and_then(Json::as_str)
                .unwrap_or("allowed");
            let level = action_order(match decision {
                "flagged" => "flag",
                "blocked" => "block",
                // "allowed", and anything unrecognized: Python's
                // `dict.get(decision, "all")` gives both the same
                // answer, so neither trips `--min-action`.
                _ => "all",
            });
            if level < action_order(min_action) {
                return false;
            }
        }
        if let Some(since) = &self.since {
            // A timestamp that is missing, empty, not a string, not
            // parseable, or naive against an aware cutoff leaves the
            // entry in: Python either skips the `if ts` branch or
            // swallows the ValueError/TypeError and falls through.
            let keep = entry
                .get("ts")
                .filter(|ts| ts.is_truthy())
                .and_then(Json::as_str)
                .and_then(DateTime::from_isoformat)
                .and_then(|entry_dt| entry_dt.lt(since))
                .is_none_or(|before_cutoff| !before_cutoff);
            if !keep {
                return false;
            }
        }
        true
    }
}

/// `entry.get(field) in allowed`, where a missing or non-string field
/// can never be in a list of strings.
fn field_in(entry: &Json, field: &str, allowed: &[String]) -> bool {
    entry
        .get(field)
        .and_then(Json::as_str)
        .is_some_and(|value| allowed.iter().any(|a| a == value))
}

/// An object literal, in the order it is written.
fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

/// `dict.get(key, default)` over a value that may not be an object.
fn get_or(value: &Json, key: &str, default: Json) -> Json {
    value.get(key).cloned().unwrap_or(default)
}

/// Convert `[[name, value], …]` to HAR headers format.
fn build_headers(headers: &Json) -> Json {
    let Json::Array(items) = headers else {
        // Python iterates whatever this is; a dict would yield its keys
        // and anything else would raise. Treat it as absent.
        return Json::Array(Vec::new());
    };
    Json::Array(
        items
            .iter()
            .filter_map(|header| match header {
                Json::Array(pair) if pair.len() >= 2 => Some(object(vec![
                    ("name", pair[0].clone()),
                    ("value", pair[1].clone()),
                ])),
                _ => None,
            })
            .collect(),
    )
}

/// Extract query parameters from URL.
fn build_query_string(url: &Json) -> Json {
    let Some(url) = url.as_str() else {
        return Json::Array(Vec::new());
    };
    Json::Array(
        query::query_pairs(url)
            .into_iter()
            .map(|(name, value)| {
                object(vec![("name", Json::Str(name)), ("value", Json::Str(value))])
            })
            .collect(),
    )
}

/// The value of the first `content-type` header, or `""`.
fn content_type(headers: &Json) -> Json {
    let Json::Array(items) = headers else {
        return Json::string("");
    };
    for header in items {
        if let Json::Array(pair) = header
            && pair.len() >= 2
            && pair[0]
                .as_str()
                .is_some_and(|name| name.to_lowercase() == "content-type")
        {
            return pair[1].clone();
        }
    }
    Json::string("")
}

/// Convert a capture request snapshot to a HAR request object.
fn build_request_entry(req: &Json) -> Json {
    let headers = get_or(req, "headers", Json::Array(Vec::new()));
    let url = get_or(req, "url", Json::string(""));
    let body = get_or(req, "body", Json::string(""));
    let body_size = get_or(req, "bodySize", Json::Int(0));

    let mut har_req = object(vec![
        ("method", get_or(req, "method", Json::string(""))),
        ("url", url.clone()),
        (
            "httpVersion",
            get_or(req, "httpVersion", Json::string("HTTP/1.1")),
        ),
        ("cookies", Json::Array(Vec::new())),
        ("headers", build_headers(&headers)),
        ("queryString", build_query_string(&url)),
        ("headersSize", Json::Int(-1)),
        ("bodySize", body_size),
    ]);

    if body.is_truthy() {
        // Determine MIME type from headers
        let mut post_data = object(vec![("mimeType", content_type(&headers)), ("text", body)]);
        if get_or(req, "bodyEncoding", Json::Null) == Json::string("base64") {
            post_data.set("encoding", Json::string("base64"));
        }
        har_req.set("postData", post_data);
    }

    har_req
}

/// Convert a capture response snapshot to a HAR response object.
fn build_response_entry(resp: &Json) -> Json {
    // `if not resp` — a missing, null or empty response, and also a
    // response that is not an object at all, which Python would reach an
    // AttributeError on a line later.
    if !resp.is_truthy() || !matches!(resp, Json::Object(_)) {
        return object(vec![
            ("status", Json::Int(0)),
            ("statusText", Json::string("")),
            ("httpVersion", Json::string("HTTP/1.1")),
            ("cookies", Json::Array(Vec::new())),
            ("headers", Json::Array(Vec::new())),
            (
                "content",
                object(vec![("size", Json::Int(0)), ("mimeType", Json::string(""))]),
            ),
            ("redirectURL", Json::string("")),
            ("headersSize", Json::Int(-1)),
            ("bodySize", Json::Int(-1)),
        ]);
    }

    let body = get_or(resp, "body", Json::string(""));
    let mut content = object(vec![
        // Note the two different defaults for the same field: `content`
        // falls back to 0, the response's own `bodySize` to -1.
        ("size", get_or(resp, "bodySize", Json::Int(0))),
        ("mimeType", get_or(resp, "mimeType", Json::string(""))),
    ]);
    if body.is_truthy() {
        content.set("text", body);
        if get_or(resp, "bodyEncoding", Json::Null) == Json::string("base64") {
            content.set("encoding", Json::string("base64"));
        }
    }

    object(vec![
        ("status", get_or(resp, "status", Json::Int(0))),
        ("statusText", get_or(resp, "statusText", Json::string(""))),
        (
            "httpVersion",
            get_or(resp, "httpVersion", Json::string("HTTP/1.1")),
        ),
        ("cookies", Json::Array(Vec::new())),
        (
            "headers",
            build_headers(&get_or(resp, "headers", Json::Array(Vec::new()))),
        ),
        ("content", content),
        ("redirectURL", Json::string("")),
        ("headersSize", Json::Int(-1)),
        ("bodySize", get_or(resp, "bodySize", Json::Int(-1))),
    ])
}

/// Convert capture JSONL entries to HAR 1.2 JSON.
///
/// `view` selects which perspective to render: `"inbound"` or
/// `"outbound"`. The result is ready for [`dumps`].
///
/// The creator version is this binary's [`crate::VERSION`], where the
/// Python reads `importlib.metadata.version("agentcage")` and falls back
/// to `"0.0.0"` if the package is not installed — a fallback a compiled
/// constant cannot need. Use [`capture_to_har_with`] to pin it, which is
/// what the golden corpus does.
#[must_use]
pub fn capture_to_har(entries: &[Json], view: &str) -> Json {
    capture_to_har_with(entries, view, crate::VERSION, DateTime::now_utc())
}

/// [`capture_to_har`] with the two ambient values passed in: the
/// creator version, and the "now" that stands in for an entry with no
/// timestamp of its own.
#[must_use]
pub fn capture_to_har_with(
    entries: &[Json],
    view: &str,
    creator_version: &str,
    now: DateTime,
) -> Json {
    let har_entries: Vec<Json> = entries
        .iter()
        .map(|entry| build_har_entry(entry, view, &now))
        .collect();

    object(vec![(
        "log",
        object(vec![
            ("version", Json::string("1.2")),
            (
                "creator",
                object(vec![
                    ("name", Json::string("agentcage")),
                    ("version", Json::string(creator_version)),
                ]),
            ),
            ("entries", Json::Array(har_entries)),
        ]),
    )])
}

fn build_har_entry(entry: &Json, view: &str, now: &DateTime) -> Json {
    let perspective = get_or(entry, view, Json::Object(Vec::new()));
    let req_data = get_or(&perspective, "request", Json::Object(Vec::new()));
    let resp_data = get_or(&perspective, "response", Json::Object(Vec::new()));

    let ts = get_or(entry, "ts", Json::Str(now.isoformat()));

    let mut har_entry = object(vec![
        ("startedDateTime", ts),
        ("time", Json::Int(0)),
        ("request", build_request_entry(&req_data)),
        ("response", build_response_entry(&resp_data)),
        ("cache", Json::Object(Vec::new())),
        (
            "timings",
            object(vec![
                ("send", Json::Int(-1)),
                ("wait", Json::Int(-1)),
                ("receive", Json::Int(-1)),
            ]),
        ),
    ]);

    // Add agentcage metadata as a comment. This is a JSON *string*
    // inside the HAR, written with `json.dumps` defaults — one line,
    // `", "` and `": "` separators, `ensure_ascii=True` — and it carries
    // the entry's own `inspectors` list, whose key order comes from the
    // capture file rather than from this code.
    let metadata = object(vec![
        ("flow_id", get_or(entry, "flow_id", Json::string(""))),
        ("direction", get_or(entry, "direction", Json::string(""))),
        ("decision", get_or(entry, "decision", Json::string(""))),
        (
            "inspectors",
            get_or(entry, "inspectors", Json::Array(Vec::new())),
        ),
        ("view", Json::string(view)),
    ]);
    har_entry.set(
        "comment",
        Json::Str(json::dumps(&metadata, DumpOptions::default())),
    );

    har_entry
}

/// Render a HAR document the way `cage har` writes it:
/// `json.dumps(har, indent=2)`.
#[must_use]
pub fn dumps(har: &Json) -> String {
    json::dumps(har, DumpOptions::indented())
}

/// Parse a `--since` value into a datetime.
///
/// Accepts: `1h`, `30m`, `7d`, or ISO date strings. Returns `None` if
/// parsing fails.
///
/// Two edges of the Python that this does not reproduce, both
/// unreachable from a well-formed `--since`:
///
/// * Python's `\d` matches every Unicode decimal digit and `int()`
///   accepts them, so `١h` is a valid relative offset there. Here the
///   digits are ASCII.
/// * A relative offset so large that `timedelta` overflows raises
///   `OverflowError` out of the Python, uncaught. Here it returns
///   `None`, i.e. "no cutoff", which is the same path an unparseable
///   value takes.
#[must_use]
pub fn parse_since(since: &str) -> Option<DateTime> {
    if let Some((value, unit)) = split_relative(since) {
        let seconds = match unit {
            'h' => value.checked_mul(3_600),
            'm' => value.checked_mul(60),
            'd' => value.checked_mul(86_400),
            _ => None,
        };
        // A relative form never falls through to the ISO branch: once
        // the regex has matched, Python has already returned or raised.
        return seconds.and_then(|s| DateTime::now_utc().checked_sub_seconds(s));
    }

    // Try ISO date. A naive value is read as UTC.
    DateTime::from_isoformat(since).map(DateTime::assume_utc)
}

/// `re.match(r"^(\d+)([hHmMdD])$", since)`, lowercased unit.
///
/// Python's `$` also matches immediately before a trailing newline, so
/// `"1h\n"` is a valid relative offset there. That is faithfully
/// reproduced rather than tidied away: it is the difference between
/// `--since "$(cat file)"` working and silently exporting everything.
fn split_relative(since: &str) -> Option<(i64, char)> {
    let since = since.strip_suffix('\n').unwrap_or(since);
    let mut chars = since.chars();
    let unit = chars.next_back()?;
    if !matches!(unit, 'h' | 'H' | 'm' | 'M' | 'd' | 'D') {
        return None;
    }
    let digits = chars.as_str();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // A value too long for an i64 cannot fit a timedelta either.
    let value = digits.parse::<i64>().ok()?;
    Some((value, unit.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::{CaptureFilter, capture_to_har_with, dumps, parse_since};
    use crate::har::datetime::DateTime;
    use crate::har::json::{self, Json};

    /// One capture entry, holding everything the golden corpus's
    /// fixture does not: a repeated query parameter, a request with no
    /// response at all, and non-ASCII text in both the metadata and an
    /// inspector finding.
    const ENTRY: &str = "{\"ts\": \"2024-05-05T01:02:03+00:00\", \"flow_id\": \"flow-\\u00e9\", \"direction\": \"outbound\", \"decision\": \"flagged\", \"inspectors\": [{\"name\": \"secrets\", \"severity\": \"warning\", \"reason\": \"caf\\u00e9\"}], \"outbound\": {\"request\": {\"method\": \"POST\", \"url\": \"https://h/p?b=2&a=1&b=3\", \"headers\": [[\"Content-Type\", \"text/plain\"], [\"X\", \"1\"]], \"body\": \"hi\", \"bodySize\": 2}}}";

    /// The Python `json.dumps(har, indent=2)` output for [`ENTRY`].
    const PRODUCTION_HAR: &str = concat!(
        "{
",
        "  \"log\": {
",
        "    \"version\": \"1.2\",
",
        "    \"creator\": {
",
        "      \"name\": \"agentcage\",
",
        "      \"version\": \"0.0.0-golden\"
",
        "    },
",
        "    \"entries\": [
",
        "      {
",
        "        \"startedDateTime\": \"2024-05-05T01:02:03+00:00\",
",
        "        \"time\": 0,
",
        "        \"request\": {
",
        "          \"method\": \"POST\",
",
        "          \"url\": \"https://h/p?b=2&a=1&b=3\",
",
        "          \"httpVersion\": \"HTTP/1.1\",
",
        "          \"cookies\": [],
",
        "          \"headers\": [
",
        "            {
",
        "              \"name\": \"Content-Type\",
",
        "              \"value\": \"text/plain\"
",
        "            },
",
        "            {
",
        "              \"name\": \"X\",
",
        "              \"value\": \"1\"
",
        "            }
",
        "          ],
",
        "          \"queryString\": [
",
        "            {
",
        "              \"name\": \"b\",
",
        "              \"value\": \"2\"
",
        "            },
",
        "            {
",
        "              \"name\": \"b\",
",
        "              \"value\": \"3\"
",
        "            },
",
        "            {
",
        "              \"name\": \"a\",
",
        "              \"value\": \"1\"
",
        "            }
",
        "          ],
",
        "          \"headersSize\": -1,
",
        "          \"bodySize\": 2,
",
        "          \"postData\": {
",
        "            \"mimeType\": \"text/plain\",
",
        "            \"text\": \"hi\"
",
        "          }
",
        "        },
",
        "        \"response\": {
",
        "          \"status\": 0,
",
        "          \"statusText\": \"\",
",
        "          \"httpVersion\": \"HTTP/1.1\",
",
        "          \"cookies\": [],
",
        "          \"headers\": [],
",
        "          \"content\": {
",
        "            \"size\": 0,
",
        "            \"mimeType\": \"\"
",
        "          },
",
        "          \"redirectURL\": \"\",
",
        "          \"headersSize\": -1,
",
        "          \"bodySize\": -1
",
        "        },
",
        "        \"cache\": {},
",
        "        \"timings\": {
",
        "          \"send\": -1,
",
        "          \"wait\": -1,
",
        "          \"receive\": -1
",
        "        },
",
        "        \"comment\": \"{\\\"flow_id\\\": \\\"flow-\\\\u00e9\\\", \\\"direction\\\": \\\"outbound\\\", \\\"decision\\\": \\\"flagged\\\", \\\"inspectors\\\": [{\\\"name\\\": \\\"secrets\\\", \\\"severity\\\": \\\"warning\\\", \\\"reason\\\": \\\"caf\\\\u00e9\\\"}], \\\"view\\\": \\\"outbound\\\"}\"
",
        "      }
",
        "    ]
",
        "  }
",
        "}"
    );

    /// The format `cage har` actually writes — `json.dumps(har,
    /// indent=2)`, so Python dict order and `ensure_ascii=True`, not the
    /// sorted `ensure_ascii=False` text the corpus stores.
    ///
    /// This expectation was produced by the Python `har.py`, with
    /// `pkg_version` pinned the way the corpus harness pins it.
    #[test]
    fn production_output_matches_python_byte_for_byte() {
        let entries = [json::parse(ENTRY).unwrap()];
        let har = capture_to_har_with(&entries, "outbound", "0.0.0-golden", DateTime::now_utc());
        assert_eq!(dumps(&har), PRODUCTION_HAR);
    }

    fn entry_of(pairs: &[(&str, Json)]) -> Json {
        Json::Object(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone()))
                .collect(),
        )
    }

    /// Filter behaviour the corpus does not reach, each expectation read
    /// off `CaptureFilter.matches` in Python.
    #[test]
    fn filter_edges_match_python() {
        let cutoff = CaptureFilter {
            since: DateTime::from_isoformat("2024-03-01T00:00:00+00:00"),
            ..CaptureFilter::default()
        };
        // A naive timestamp against an aware cutoff is a TypeError in
        // Python, caught, and the entry stays. So does a timestamp that
        // is missing, empty, unparseable or not a string at all.
        assert!(cutoff.matches(&entry_of(&[("ts", Json::string("2024-01-01T00:00:00"))])));
        assert!(cutoff.matches(&entry_of(&[("ts", Json::string("nonsense"))])));
        assert!(cutoff.matches(&entry_of(&[("ts", Json::string(""))])));
        assert!(cutoff.matches(&entry_of(&[("ts", Json::Int(17))])));
        assert!(cutoff.matches(&entry_of(&[])));
        // An aware timestamp before the cutoff is the one that goes.
        assert!(!cutoff.matches(&entry_of(&[(
            "ts",
            Json::string("2024-01-01T00:00:00+00:00")
        )])));

        // An unrecognized decision counts as "all", so it is below every
        // threshold above "all" and never above one.
        let block = CaptureFilter {
            min_action: Some("block".to_string()),
            ..CaptureFilter::default()
        };
        assert!(!block.matches(&entry_of(&[("decision", Json::string("weird"))])));
        // An unrecognized *threshold* is 0, which nothing is below.
        let nonsense = CaptureFilter {
            min_action: Some("nope".to_string()),
            ..CaptureFilter::default()
        };
        assert!(nonsense.matches(&entry_of(&[("decision", Json::string("allowed"))])));

        // A missing field can never be in a list of wanted values.
        for filter in [
            CaptureFilter {
                hosts: vec!["x".to_string()],
                ..CaptureFilter::default()
            },
            CaptureFilter {
                methods: vec!["GET".to_string()],
                ..CaptureFilter::default()
            },
            CaptureFilter {
                decisions: vec!["allowed".to_string()],
                ..CaptureFilter::default()
            },
            CaptureFilter {
                directions: vec!["outbound".to_string()],
                ..CaptureFilter::default()
            },
        ] {
            assert!(!filter.matches(&entry_of(&[])));
        }
    }

    /// An entry with no `ts` is stamped with the current time, which is
    /// the one value `capture_to_har` invents.
    #[test]
    fn a_missing_timestamp_falls_back_to_now() {
        let now = DateTime::from_isoformat("2026-09-19T10:11:12+00:00").unwrap();
        let har = capture_to_har_with(&[Json::Object(Vec::new())], "inbound", "9.9.9", now);
        let started = har
            .get("log")
            .and_then(|log| log.get("entries"))
            .and_then(|entries| match entries {
                Json::Array(items) => items.first(),
                _ => None,
            })
            .and_then(|entry| entry.get("startedDateTime"))
            .and_then(Json::as_str);
        assert_eq!(started, Some("2026-09-19T10:11:12+00:00"));
    }

    /// The relative forms, the units' case-insensitivity, and the two
    /// ways a value can fail to parse.
    #[test]
    fn parse_since_handles_both_forms() {
        let now = DateTime::now_utc();
        for (spec, seconds) in [("1h", 3_600), ("30m", 1_800), ("7d", 604_800), ("0h", 0)] {
            let parsed = parse_since(spec).expect("a relative offset parses");
            assert_eq!(now.seconds_since(&parsed), Some(seconds), "for {spec}");
        }
        // `[hHmMdD]` — the unit is case-insensitive, the digits are not
        // optional.
        assert_eq!(
            parse_since("2H").map(|d| now.seconds_since(&d)),
            Some(Some(7_200))
        );
        // Python's `$` matches before a trailing newline, so this is a
        // valid relative offset there too.
        assert_eq!(
            parse_since("1h\n").map(|d| now.seconds_since(&d)),
            Some(Some(3_600))
        );

        // An ISO value is absolute, and a naive one is read as UTC.
        assert_eq!(
            parse_since("2024-01-01").map(|d| d.isoformat()),
            Some("2024-01-01T00:00:00+00:00".to_string())
        );
        assert_eq!(
            parse_since("2024-01-01T00:00:00").map(|d| d.isoformat()),
            Some("2024-01-01T00:00:00+00:00".to_string())
        );
        assert_eq!(
            parse_since("2024-06-01T12:00:00+02:00").map(|d| d.isoformat()),
            Some("2024-06-01T12:00:00+02:00".to_string())
        );

        for bad in ["", "5x", "not-a-since", "h", "-1h", "1 h", "1hh"] {
            assert!(parse_since(bad).is_none(), "{bad:?} should not parse");
        }
    }
}
