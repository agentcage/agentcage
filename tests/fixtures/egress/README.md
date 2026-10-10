# Egress oracle corpora

Language-neutral `(input, expected)` cases for the Rust egress
(`rust/agentcage-egress`), recorded from the Python egress it replaces
(`src/agentcage/data/proxy/`) while that still exists. Plan:
`EGRESS-PORT-PLAN.md` §8, Layer 0.

Conventions:

- One JSON file per corpus: `{"_comment": "...", "cases": [...]}`.
  Byte strings are stored as `{"b64": "..."}` when they are not valid
  UTF-8, otherwise as plain strings.
- Each corpus has a generator, `gen/<corpus>.py`, that imports the
  Python modules and writes the file:
  `uv run python tests/fixtures/egress/gen/<corpus>.py`.
  Generators are deleted at cutover; the JSON files stay as golden files.
- `tests/test_egress_corpus_<corpus>.py` re-runs every case against the
  Python, so a corpus can never disagree with the implementation it was
  recorded from while that implementation exists.
- The Rust module that ports the behaviour asserts the same file from its
  own tests. A deliberate change is re-recorded with
  `AGENTCAGE_BLESS=1 cargo test -p agentcage-egress <test>` (and the
  generator updated to match until cutover).
