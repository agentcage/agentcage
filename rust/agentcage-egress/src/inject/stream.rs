//! Redaction of a body that is relayed chunk by chunk, byte-for-byte what
//! [`Injector::redact_response`](super::Injector::redact_response) makes of
//! the whole body.
//!
//! The buffered redactor runs one pass per secret form over the body —
//! the literal, the escaped-form pattern, then each base64 core, for each
//! secret in turn, each pass over the output of the one before. A pass
//! only ever rewrites a contiguous region made of the bytes its form can
//! be spelled with: a literal match holds only the value's bytes, an
//! escaped match only the bytes of the escapes (`%`, hex digits, `+`,
//! `\`, `u`, the short-escape letters) and the value's own, and a base64
//! rewrite only covers a run of base64 characters and the up-to-two `=`
//! after it. So a byte none of the configured forms can contain — a
//! *separator*: a newline, a space, most punctuation, any byte past ASCII
//! for an ASCII secret — is never part of any match of any pass, is never
//! rewritten by one, and stays where it is between passes. Cutting the
//! body just after a separator therefore splits every pass's work into
//! two independent halves: each match lies wholly on one side, each scan
//! restarts on the other side exactly where the whole-body scan would
//! have, and a base64 run never extends across the cut. Redacting the two
//! halves separately and concatenating them is the redaction of the
//! whole, and by induction so is redacting every separator-delimited
//! segment on its own.
//!
//! [`StreamRedactor`] is that: it holds back only the bytes after the last
//! separator seen (the tail that may still grow into a match), and hands
//! every completed segment to the very function the buffered path uses.
//! A segment in which no form can occur (the same substring prefilter as
//! [`SecretForms::may_occur`], run as one multi-pattern scan) is passed on
//! as the chunk it came in, without a copy. An SSE event ends in `\n\n`,
//! so a token stream is relayed with no hold-back at all; a binary body has
//! a separator every few bytes. The one shape that is held is a long run
//! with no separator in it — a base64 blob, a hex string — which is kept
//! until it ends, up to [`MAX_HOLD`]: past that the exchange is aborted
//! rather than either buffered without bound or relayed unredacted.

use std::sync::Arc;

use aho_corasick::AhoCorasick;
use bytes::Bytes;

use super::SecretForms;

/// The longest run without a separator held back before the exchange is
/// aborted.
pub const MAX_HOLD: usize = 16 * 1024 * 1024;

/// Why a streamed body could not be redacted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamRedactError {
    /// A run of bytes with no separator in it outgrew [`MAX_HOLD`].
    UnboundedRun,
}

impl std::fmt::Display for StreamRedactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnboundedRun => f.write_str("unbounded base64 run during redaction"),
        }
    }
}

impl std::error::Error for StreamRedactError {}

/// The bytes any match of `forms` can contain (a superset is fine: it
/// only makes segments longer).
fn alphabet(forms: &[Arc<SecretForms>]) -> [bool; 256] {
    let mut used = [false; 256];
    let mut add = |bytes: &[u8]| {
        for &b in bytes {
            used[usize::from(b)] = true;
        }
    };
    for f in forms {
        add(f.raw());
        if f.pattern.is_some() {
            // Every escape the pattern accepts: `%XX` (either hex case),
            // `+` for a space, `\uXXXX` and the JSON short escapes.
            add(b"%0123456789ABCDEFabcdef+\\u\"/bfnrt");
        }
        if !f.b64_cores.is_empty() {
            // A base64 rewrite covers the whole run around a core in
            // either alphabet, and the padding after it.
            add(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=");
        }
    }
    used
}

/// One multi-pattern scan for every substring [`SecretForms::may_occur`]
/// looks for; `None` when some form has an escaped pattern with no anchor
/// (it may occur anywhere, so every segment goes through redaction).
fn triggers(forms: &[Arc<SecretForms>]) -> Option<AhoCorasick> {
    let mut needles: Vec<&[u8]> = Vec::new();
    let mut any_pattern = false;
    for f in forms {
        needles.push(f.raw());
        if f.pattern.is_some() {
            // A `%XX`-encoded spelling has no literal anchor, so the
            // prefilter must fire on any `%` (mirrors `may_occur`).
            any_pattern = true;
            needles.push(f.anchor.as_deref()?);
        }
        needles.extend(f.b64_cores.iter().map(Vec::as_slice));
    }
    if any_pattern {
        needles.push(b"%");
    }
    // Building only fails past the automaton's size limits, far beyond a
    // handful of secrets; redacting every segment is the safe fallback.
    AhoCorasick::new(needles).ok()
}

/// Redacts a body handed over in chunks; see the module docs.
pub struct StreamRedactor {
    forms: Vec<Arc<SecretForms>>,
    separator: [bool; 256],
    triggers: Option<AhoCorasick>,
    held: Vec<u8>,
    found: Vec<bool>,
    max_hold: usize,
}

impl std::fmt::Debug for StreamRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamRedactor")
            .field("forms", &self.forms.len())
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

impl StreamRedactor {
    /// A redactor for `forms`, in the order the buffered redactor applies
    /// them (longest value first, as `Injector::redaction_forms` sorts).
    #[must_use]
    pub fn new(forms: Vec<Arc<SecretForms>>) -> Self {
        let used = alphabet(&forms);
        let mut separator = [false; 256];
        for (sep, used) in separator.iter_mut().zip(used) {
            *sep = !used;
        }
        Self {
            triggers: triggers(&forms),
            found: vec![false; forms.len()],
            forms,
            separator,
            held: Vec::new(),
            max_hold: MAX_HOLD,
        }
    }

    /// The same redactor with a different hold bound (tests).
    #[must_use]
    pub fn with_max_hold(mut self, max_hold: usize) -> Self {
        self.max_hold = max_hold;
        self
    }

    /// Bytes currently held back.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// The forms, in order.
    #[must_use]
    pub fn forms(&self) -> &[Arc<SecretForms>] {
        &self.forms
    }

    /// Which forms were found in the body so far, by index into
    /// [`StreamRedactor::forms`].
    #[must_use]
    pub fn found(&self) -> &[bool] {
        &self.found
    }

    /// Redact one segment (it ends at a separator, or is the body's last).
    fn segment(&mut self, data: Bytes, out: &mut Vec<Bytes>) {
        if data.is_empty() {
            return;
        }
        if let Some(ac) = &self.triggers
            && !ac.is_match(&data[..])
        {
            out.push(data);
            return;
        }
        // Exactly the body half of `Injector::redact_response_body`.
        let mut content: Option<Vec<u8>> = None;
        for (forms, found) in self.forms.iter().zip(self.found.iter_mut()) {
            let current = content.as_deref().unwrap_or(&data);
            if let Some(new) = forms.redact(current) {
                content = Some(new);
                *found = true;
            }
        }
        out.push(content.map_or(data, Bytes::from));
    }

    fn is_sep(&self, b: u8) -> bool {
        self.separator[usize::from(b)]
    }

    /// Take the next chunk of the body; whatever can be released goes to
    /// `out` (possibly several pieces, possibly none).
    ///
    /// # Errors
    ///
    /// The held run outgrew the bound; the exchange must be aborted.
    pub fn push(&mut self, chunk: Bytes, out: &mut Vec<Bytes>) -> Result<(), StreamRedactError> {
        if chunk.is_empty() {
            return Ok(());
        }
        let Some(last) = chunk.iter().rposition(|&b| self.is_sep(b)) else {
            if self.held.len() + chunk.len() > self.max_hold {
                return Err(StreamRedactError::UnboundedRun);
            }
            self.held.extend_from_slice(&chunk);
            return Ok(());
        };
        let mut rest = chunk;
        if self.held.is_empty() {
            let tail = rest.split_off(last + 1);
            self.segment(rest, out);
            self.held = tail.to_vec();
        } else {
            // The held tail and the chunk up to its first separator form
            // one (small) segment; the rest of the chunk stays uncopied.
            let first = rest.iter().position(|&b| self.is_sep(b)).unwrap_or(last);
            let head = rest.split_to(first + 1);
            let mut joined = std::mem::take(&mut self.held);
            joined.extend_from_slice(&head);
            self.segment(Bytes::from(joined), out);
            let tail = rest.split_off(last - first);
            self.segment(rest, out);
            self.held = tail.to_vec();
        }
        Ok(())
    }

    /// The body ended: release what was held.
    pub fn finish(&mut self, out: &mut Vec<Bytes>) {
        let held = std::mem::take(&mut self.held);
        self.segment(Bytes::from(held), out);
    }

    /// The names of the rules whose values were found, given which forms
    /// the headers held (`header_found`, by form index), in the order the
    /// buffered redactor reports them.
    #[must_use]
    pub fn names(&self, header_found: &[bool]) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for (i, forms) in self.forms.iter().enumerate() {
            let hit = self.found[i] || header_found.get(i).copied().unwrap_or(false);
            if hit && !names.iter().any(|n| n == forms.name()) {
                names.push(forms.name().to_owned());
            }
        }
        names
    }
}
