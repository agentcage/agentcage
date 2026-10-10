//! HTTP messages as the pipeline sees them.
//!
//! Headers are an ordered list of raw `(name, value)` byte pairs: case,
//! order and duplicates survive from the wire to the upstream, to audit
//! and to capture (plan D10). The string views decode UTF-8 and replace
//! invalid sequences, which differs from the replaced implementation's
//! `surrogateescape` only for bytes no placeholder or secret contains.
//!
//! Mutation follows the multidict semantics the pipeline was written
//! against: [`Headers::set`] keeps the position and name spelling of the
//! first occurrence, replaces its value and drops the other occurrences;
//! a name not present is appended.

/// An ordered, case-preserving, duplicate-preserving header list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers(pub Vec<(Vec<u8>, Vec<u8>)>);

impl Headers {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Every value for `name` (case-insensitive), in wire order, as text.
    #[must_use]
    pub fn get_all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect()
    }

    /// The values for `name` folded with `", "`, or `None` when absent.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<String> {
        let all = self.get_all(name);
        if all.is_empty() {
            None
        } else {
            Some(all.join(", "))
        }
    }

    /// Whether `name` is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.0
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
    }

    /// Replace every value of `name` with the one `value` (see the module
    /// docs for where it lands).
    pub fn set(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.set_all(name, vec![value.into()]);
    }

    /// Replace the values of `name` with `values`, one per existing
    /// occurrence in place, extra occurrences dropped, extra values
    /// appended.
    pub fn set_all(&mut self, name: &str, values: Vec<Vec<u8>>) {
        let mut values = values.into_iter();
        let mut out = Vec::with_capacity(self.0.len());
        for (k, v) in self.0.drain(..) {
            if k.eq_ignore_ascii_case(name.as_bytes()) {
                if let Some(new) = values.next() {
                    out.push((k, new));
                }
            } else {
                out.push((k, v));
            }
        }
        for new in values {
            out.push((name.as_bytes().to_vec(), new));
        }
        self.0 = out;
    }

    /// Append one more `(name, value)`.
    pub fn add(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.0.push((name.into(), value.into()));
    }

    /// Remove every occurrence of `name`.
    pub fn remove(&mut self, name: &str) {
        self.0
            .retain(|(k, _)| !k.eq_ignore_ascii_case(name.as_bytes()));
    }

    /// The pairs as text, in wire order.
    #[must_use]
    pub fn to_strings(&self) -> Vec<(String, String)> {
        self.0
            .iter()
            .map(|(k, v)| {
                (
                    String::from_utf8_lossy(k).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect()
    }
}

/// An HTTP request after framing, before or after injection.
///
/// `body` is the raw body as received (still Content-Encoded); the decoded
/// view is [`crate::text::decoded_body`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// The method, as sent.
    pub method: String,
    /// `http` or `https`.
    pub scheme: String,
    /// The upstream host name (or address literal, without brackets).
    pub host: String,
    /// The upstream port.
    pub port: u16,
    /// The request target's path and query, as sent (`/a?b=c`).
    pub path: String,
    /// `HTTP/1.1`, `HTTP/2.0`, …
    pub http_version: String,
    /// Header pairs, in wire order.
    pub headers: Headers,
    /// The body bytes as received.
    pub body: Vec<u8>,
}

impl Request {
    /// The URL the pipeline reports: `scheme://host[:port]path`, the port
    /// omitted when it is the scheme's default; an IPv6 literal is
    /// bracketed.
    #[must_use]
    pub fn url(&self) -> String {
        let default = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if default {
            format!("{}://{}{}", self.scheme, host, self.path)
        } else {
            format!("{}://{}:{}{}", self.scheme, host, self.port, self.path)
        }
    }

    /// The `Host` header (HTTP/1) or `:authority` (HTTP/2, stored as a
    /// `Host` header by the codec), if any.
    #[must_use]
    pub fn host_header(&self) -> Option<String> {
        self.headers.get("host")
    }
}

/// An HTTP response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The reason phrase (empty for HTTP/2).
    pub reason: String,
    /// `HTTP/1.1`, `HTTP/2.0`, …
    pub http_version: String,
    /// Header pairs, in wire order.
    pub headers: Headers,
    /// The body bytes as received.
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Headers {
        Headers(
            pairs
                .iter()
                .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
        )
    }

    #[test]
    fn get_folds_duplicates_case_insensitively() {
        let headers = h(&[("Accept", "a"), ("X", "1"), ("accept", "b")]);
        assert_eq!(headers.get("ACCEPT").as_deref(), Some("a, b"));
        assert_eq!(headers.get("missing"), None);
    }

    #[test]
    fn set_keeps_the_first_position_and_spelling_and_drops_the_rest() {
        let mut headers = h(&[("Authorization", "a"), ("X", "1"), ("authorization", "b")]);
        headers.set("AUTHORIZATION", "c");
        assert_eq!(headers, h(&[("Authorization", "c"), ("X", "1")]));
        headers.set("New", "v");
        assert_eq!(headers.0.last().unwrap().0, b"New");
    }

    #[test]
    fn urls_omit_default_ports_and_bracket_ipv6() {
        let mut r = Request {
            scheme: "https".into(),
            host: "example.com".into(),
            port: 443,
            path: "/x?y=1".into(),
            ..Request::default()
        };
        assert_eq!(r.url(), "https://example.com/x?y=1");
        r.port = 8443;
        assert_eq!(r.url(), "https://example.com:8443/x?y=1");
        r.host = "::1".into();
        assert_eq!(r.url(), "https://[::1]:8443/x?y=1");
    }
}
