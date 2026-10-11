# Host/egress conformance fixtures

These JSON files are the **oracle** for every piece of logic that agentcage
implements on *both* sides of its trust boundary: the host CLI and the
per-cage egress proxy (`rust/agentcage-egress`).

- Originally generated from the host CLI of v0.50.0 and earlier by
  `scripts/gen-contract-fixtures.py`, cross-checked against the previous
  egress implementation; both are gone, and the files are now maintained
  by hand (see [Adding a case](#adding-a-case)).
- Asserted by the Rust test suite, host half and egress half separately
  (see [Where each contract is asserted](#where-each-contract-is-asserted)).

## Why these files exist

agentcage runs a host CLI and an in-cage egress proxy, and the boundary
between them is a security boundary. These have to give the same answer on
both sides of it:

| Contract | What crosses the boundary |
| :-- | :-- |
| `validate_relay_entry` | a `protocol_relays` entry, and the error string `cage create` prints verbatim |
| `valid_domain` | a domain the host renders into `dns-allowlist.conf` and the egress gates runtime grants with |
| `encoded_private_ip` | the structural half of the SSRF guard (`169-254-169-254.nip.io`) |
| `is_never_grant` | the floor under the decider: domains that can never be granted |
| `shared_constants` | the capture size cap, the never-grant floor, the built-in inspector names, the relay type/mode sets |
| `scaffold_inspectors` | the rendered `cage.yaml` the egress builds its inspector chain from |
| `agents_config` | the canonical `agents` block both sides accept |
| `agents_defaults` | what an omitted `agents.*` key resolves to |
| `logging_defaults` | `logging.allowed_requests` / legacy `log_allowed` resolution |

Several of these are one implementation shared through `agentcage-core`
(`valid_domain`, `encoded_private_ip`, the relay validator, the shared
constants). Others are deliberately duplicated because each side reads them
in a different place: the host's never-grant copy stops `grants reconcile`
promoting a domain from an overlay that was hand-edited or written by an
older egress, and the host validates and budgets an `agents` block whose
omitted keys the egress resolves on its own.

What a drift costs:

- **`valid_domain`**: a domain one side accepts and the other refuses is a
  split-brain allowlist, and in the injection-shaped cases (a trailing
  newline, a `/`) per-cage dnsmasq config corruption.
- **`encoded_private_ip`**: `169-254-169-254.nip.io` is a syntactically
  valid public hostname carrying none of the never-grant suffixes, and it
  resolves to the cloud metadata endpoint. If one side stops decoding it,
  the only thing left between the cage and `169.254.169.254` is the
  decider LLM's judgement.
- **`is_never_grant`**: the worst of the four. The egress refuses the
  grant; the host refuses to promote it.
- **`validate_relay_entry`**: two implementations rejecting the same config
  with different wording, or reporting a different one of two problems
  first, send an operator round in circles.

## The fixture is the oracle

Each side is asserted against the recorded, reviewed corpus rather than
against the other side. That also catches the two sides drifting
*together*, which a shared-module refactor does. **Neither implementation
is the oracle**: if a change makes one side disagree with these files, look
at the diff and decide whether the contract changed.

## What is in a file

Each file has a `contract` name, a `summary`, an `implementations` block
naming both sides, a `fields` block describing each case key, optional
`notes`, and a `cases` array. Every case has a stable `id` (the anchor a
diff is read against) and a `why` (the reason that input is in the corpus).
`rust/agentcage-core/tests/contract_fixture_integrity.rs` enforces that
shape, unique ids, and ASCII-escaped JSON. (The `implementations` strings
name the modules of the implementations the corpus was first
recorded against; they are provenance, not a map of the current code.)

| File | Case key | Expectation |
| :-- | :-- | :-- |
| `valid_domain.json` | `input` | `expected` (strict, both sides) plus `expected_allow_single_label` (**host only**, see below) |
| `encoded_private_ip.json` | `input` | `expected`: the decoded dotted quad, or `null` |
| `is_never_grant.json` | `input`, `never_grant` | `expected`: boolean |
| `validate_relay_entry.json` | `entry` | `ok`, `error` (the message **verbatim**), `source_validator_calls` |
| `shared_constants.json` | — | `value`, plus `host` / `proxy` naming where each side reads it |
| `scaffold_inspectors.json` | `scaffold` | `inspector_config` (what the host renders) and `loaded_inspectors` (the chain the egress builds from it) |
| `agents_config.json` | `config` | a cage.yaml both sides accept |
| `agents_defaults.json` | `id` (the omitted key) | `value`: what both sides resolve it to from the top-level minimal `config` |
| `logging_defaults.json` | `cage` (the logging keys of a cage.yaml) | `proxy_config` (what the host writes for the egress) and `allowed_requests` (what both sides resolve) |

`scaffold_inspectors.json` is split down the middle rather than asserted
twice. The artifact crossing the boundary is a *file*, so the two halves
meet there: the host side proves the renderer emits the recorded config,
the egress side proves that config builds the recorded inspector chain, in
order (a reordering is a behaviour change even when the set is identical).

`expected_allow_single_label` has no egress counterpart on purpose.
`valid_domain` with single labels allowed additionally accepts a bare
LAN/mDNS label (`nas`, `fcos-vm-home-01`) and is reachable only from
operator-owned paths: `domains.allow`, `domain add`. Every runtime grant
path stays strict-dotted, because a single-label name is exactly what an
internal service looks like.

## Where each contract is asserted

| Contract | Host | Egress |
| :-- | :-- | :-- |
| `valid_domain`, `encoded_private_ip` | `agentcage-core/src/config/domain.rs`, `tests/contract_domain.rs` | the same `agentcage-core` functions, imported |
| `validate_relay_entry` | `agentcage-core/src/relays.rs`, `tests/contract_relay_entry.rs` | the same `agentcage_core::relays`, imported |
| `is_never_grant` | `agentcage-cli/src/cli/cage/grants_never_grant_corpus.rs` | the decider's floor, `agentcage-egress/src/policy` (`policy_api.json` corpus) |
| `shared_constants` | `agentcage-core/tests/contract_relay_entry.rs` | `agentcage-egress/tests/contract_fixtures.rs` |
| `scaffold_inspectors` | `agentcage-core/tests/contract_relay_entry.rs` | `agentcage-egress/tests/contract_fixtures.rs` |
| `agents_config` | `agentcage-core/tests/contract_agents_config.rs` | `agentcage-egress/tests/contract_fixtures.rs` |
| `agents_defaults` | `agentcage-core/tests/contract_agents_defaults.rs` | `agentcage-egress/src/watcher/config.rs`, `src/watcher/corpus.rs` |
| `logging_defaults` | `agentcage-state/tests/contract_logging_defaults.rs` | `agentcage-egress/src/audit/records.rs` |

## Notes on the semantics

- **Pure JSON, ASCII-escaped.** Several cases carry zero-width and
  non-breaking characters that are invisible (or misleading) raw in a diff.
- **Error messages interpolate values and kind names in a fixed literal
  notation** (`agentcage_core::value_fmt`), because the messages were
  defined by earlier releases and operators see them verbatim. The
  JSON-to-kind-name mapping the messages use:

  | JSON | type name |
  | :-- | :-- |
  | `null` | `NoneType` |
  | `true` / `false` | `bool` |
  | integer | `int` |
  | fractional number | `float` |
  | string | `str` |
  | array | `list` |
  | object | `dict` |

  And `repr`: a string is single-quoted (`'imap'`); a number, boolean or
  null is bare (`123`, `True`, `None`).
- **Check order is part of the contract.** The `order-*` cases pin which
  of two problems is reported when an entry has both.
- **"Non-global" in `encoded_private_ip` is the IANA special-purpose
  registry**, implemented explicitly, not a crate's `is_private()`: the two
  are different predicates. 100.64.0.0/10 is the proof (not global, and
  not private either), so `!is_private` would let carrier-grade NAT
  through. The `cgnat-*` and `test-net-*` cases make that substitution
  fail loudly.
- **Never-grant matching is on label boundaries**, not string suffixes:
  `notinternal.com` is not blocked by `internal`. The `near-*` cases pin
  it, and `grants_never_grant_corpus.rs` checks that a string-suffix
  predicate would be caught.
- **Type coercion is part of the contract too.** `int(port)` truncating a
  float, `bool(tls)` making the *string* `"false"` truthy, `x or ""`
  turning `null` into an empty string: the `ok-`/`err-` cases say which
  answer is the current one.

## Adding a case

1. Add the case to the relevant JSON file, with a unique `id` and a `why`
   that says what the case is *for*. Keep the file ASCII (escape anything
   else as `\uXXXX`).
2. Run `cargo test --workspace`.
3. If one side disagrees with the expectation, decide which is right. A
   disagreement is a bug in one implementation, not a reason to weaken the
   case.

Changing an *existing* expectation is a changed security contract and
should be called out as such in the commit message.
