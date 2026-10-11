# Egress oracle corpora

Language-neutral `(input, expected)` cases for the egress
(`rust/agentcage-egress`). They were recorded from the previous egress
implementation while it still existed, so the Rust port started from that
behaviour; they are now golden files, asserted only by the Rust tests.

Conventions:

- One JSON file per corpus: `{"_comment": "...", "cases": [...]}`.
  Byte strings are stored as `{"b64": "..."}` when they are not valid
  UTF-8, otherwise as plain strings.
- The Rust module that implements the behaviour replays every case from
  its own tests:

  | Corpus | Asserted by |
  | :-- | :-- |
  | `audit_lines.json` | `src/audit/corpus.rs` |
  | `capture.json` | `src/capture/tests.rs` |
  | `get_text.json` | `src/text.rs` |
  | `imap.json` | `src/relays/imap_tests.rs` |
  | `injection.json` | `src/inject/tests.rs`, `src/transforms.rs` |
  | `inspectors.json`, `secrets.json` | `src/inspect/corpus.rs` |
  | `llm_wire.json` | `src/llm/tests.rs` |
  | `policy_api.json` | `src/policy/tests.rs` |
  | `smtp.json` | `src/relays/smtp_tests.rs` |
  | `watcher.json` | `src/watcher/corpus.rs` |

- A deliberate behaviour change is a changed expectation, reviewed as
  such. Where the test supports it, re-record with
  `AGENTCAGE_BLESS=1 cargo test -p agentcage-egress <test>` and read the
  diff; elsewhere edit the case by hand. A case that starts failing for
  any other reason is a regression, not a reason to re-bless.
