# Cross-language conformance fixtures

These JSON files are the **oracle** for every piece of logic that agentcage
implements on *both* sides of its trust boundary.

- Asserted on the proxy side by [`tests/test_contract_fixtures.py`](../../test_contract_fixtures.py)
- Asserted on the host side by the Rust test suite via `serde_json`
- Originally generated from the Python host CLI by
  `scripts/gen-contract-fixtures.py`; both were removed after v0.50.0, and
  the files are now maintained by hand (see [Adding a case](#adding-a-case))

## Why these files exist

agentcage runs a host CLI and an in-cage egress proxy, and the boundary
between them is a security boundary. These have to give the same answer on
both sides of it:

| Contract | Host | Proxy |
| :-- | :-- | :-- |
| `validate_relay_entry` | `agentcage.data.proxy.relays._validate` (imported by `config.py`) | `relays._validate` (bare import, no CLI package on the path) |
| `valid_domain` | `config.valid_domain` / `config.DOMAIN_RE` | `policy_api.PolicyApi._valid_domain` / `_DOMAIN_RE` |
| `encoded_private_ip` | `config.encoded_private_ip` | `policy_api._encoded_private_ip` |
| `is_never_grant` | `cli._is_never_grant` | `policy_api.PolicyApi._is_never_grant` |
| `shared_constants` | `config.MAX_CAPTURE_FILE_BYTES`, `config._AUTO_NEVER_GRANT`, `config._BUILTIN_INSPECTOR_NAMES`, the relay type/mode sets | `capture.CaptureWriter`'s default, `PolicyApi._effective_never_grant`, `addon._BUILTIN_INSPECTORS`, the same relay sets |
| `scaffold_inspectors` | `init.render_config` → cage.yaml | `addon._load_builtin_inspectors` reading it back |
| `agents_defaults` | `config::parse`'s fallbacks for an omitted `agents.*` key | `PolicyApi.__init__` / `Watcher.__init__` fallbacks for the same key |
| `logging_defaults` | `config::parse`'s `logging.allowed_requests` / legacy `log_allowed` resolution, and `save_proxy_config`'s copy of those keys | `addon._log_allowed` reading them back |

The first four are the docs/history/rust-port-plan.md §2.2 list. The last two came out of
PR A6's audit of the boundary: a duplicated constant and a *format*
contract, where the shared artifact is a file rather than a predicate.

`agents_defaults` is a duplicated constant table too. The host writes the
operator's `agents` block into `proxy-config.yaml` without filling in
defaults, so a key the operator left out runs at the egress's fallback
while the host validates and budgets against its own. The watcher's scan
interval drifted that way (300 in the egress, 900 on the host).

Today they agree for a reason that is about to stop being true. The first
is *literally one module*, imported from two paths — its own docstring says
it lives under `data/proxy/relays/` "so both sides of the trust boundary
import the same code". The other three are duplicated deliberately (the
addon cannot import `agentcage`; the egress image ships without it) and
kept honest by a pytest that imports *both* copies and asserts they match.

The Rust port of the host CLI deletes both mechanisms. Rust cannot import a
Python module, and pytest cannot import the Rust side. The proxy stays
Python forever — that is the whole point of the scope — so the duplication
is permanent while the thing that *enforced* agreement disappears.

What a drift costs:

- **`valid_domain`** — a domain one side accepts and the other refuses.
  The host renders accepted domains into `dns-allowlist.conf`; the proxy
  gates runtime grant requests with its copy. Disagreement is a
  split-brain allowlist, and in the injection-shaped cases (a trailing
  newline, a `/`) it is per-cage dnsmasq config corruption.
- **`encoded_private_ip`** — the structural half of the SSRF guard.
  `169-254-169-254.nip.io` is a syntactically valid *public* hostname
  carrying none of the never-grant suffixes, and it resolves to the cloud
  metadata endpoint. If one side stops decoding it, the only thing left
  between the cage and `169.254.169.254` is the decider LLM's judgement —
  which is exactly the dependency this guard was written to remove.
- **`is_never_grant`** — the floor under the decider: the domains that can
  never be granted whatever it says. The proxy copy refuses the grant; the
  host copy stops the reconcile promoting such a domain into the
  operator's baseline from an overlay that was hand-edited or written by
  an older addon. A drift here is the worst of the four.
- **`validate_relay_entry`** — 160 lines of validation whose *error
  strings* `agentcage cage create` surfaces to the user verbatim. Two
  implementations that reject the same configs with different wording, or
  report a different one of two problems first, send an operator round in
  circles.

## The fixture is the oracle

Before: `host == proxy`.
After: `host == fixture` **and** `proxy == fixture`.

That is not a cosmetic restatement. `host == proxy` cannot be written once
the two are in different languages, and it also passes when both sides
drift *together* — which is precisely what a shared-module refactor does.
Asserting each side against a recorded, reviewed corpus survives the
language split and catches the joint drift.

So: **neither implementation is the oracle.** If a future change makes
Python disagree with these files, the right response is to look at the
diff and decide whether the contract changed, not to regenerate on
autopilot.

## What is in a file

Each file has a `contract` name, a `summary`, an `implementations` block
naming both sides, a `fields` block describing each case key, optional
`notes`, and a `cases` array. Every case has a stable `id` (the anchor a
diff is read against) and a `why` (the reason that input is in the corpus,
so a later reader can tell a deliberate adversarial case from noise).

| File | Case key | Expectation |
| :-- | :-- | :-- |
| `valid_domain.json` | `input` | `expected` (strict, both sides) plus `expected_allow_single_label` (**host only** — see below) |
| `encoded_private_ip.json` | `input` | `expected`: the decoded dotted quad, or `null` |
| `is_never_grant.json` | `input`, `never_grant` | `expected`: boolean |
| `validate_relay_entry.json` | `entry` | `ok`, `error` (the `ValueError` message **verbatim**), `source_validator_calls` |
| `shared_constants.json` | — | `value`, plus `host` / `proxy` naming where each side reads it |
| `scaffold_inspectors.json` | `scaffold` | `inspector_config` (what the host renders) and `loaded_inspectors` (what the proxy loads from it) |
| `agents_defaults.json` | `id` (the omitted key) | `value`: what both sides resolve it to from the top-level minimal `config` |
| `logging_defaults.json` | `cage` (the logging keys of a cage.yaml) | `proxy_config` (what the host writes for the egress) and `allowed_requests` (what both sides resolve) |

`scaffold_inspectors.json` is the one contract split down the middle rather
than asserted twice. The artifact crossing the boundary is a *file*, so the
two halves meet there: the host side proves `render_config` emits the
recorded config, the proxy side proves that config loads the recorded
inspector chain, in order. Neither half needs the other — which is exactly
what lets the first half become a Rust test and the second stay a pytest.

`expected_allow_single_label` has no proxy counterpart on purpose.
`config.valid_domain(d, allow_single_label=True)` additionally accepts a
bare LAN/mDNS label (`nas`, `fcos-vm-home-01`) and is reachable only from
operator-owned paths — `domains.allow`, `domain add`. Every *runtime grant*
path stays strict-dotted, because a single-label name is exactly what an
internal service looks like. The fixture carries both columns so the Rust
port cannot quietly collapse them into one mode.

## Relationship to `tests/vectors.py`

The SSRF corpus the proxy tests assert directly lives in `tests/vectors.py`
(it used to be `tests/cross_language/vectors.py`, which held the
host-vs-proxy comparison tests these fixtures replaced; that directory was
deleted with the Python CLI). `TestFixtureIntegrity::
test_superset_of_the_shared_vectors` fails if `encoded_private_ip.json` or
`is_never_grant.json` ever stops covering a vector that file lists, so a
vector added on the proxy side is also checked against the Rust host.

The two contracts that comparison suite had found beyond the original list
— the `CaptureWriter` size-cap default and the scaffold-renderer → `addon`
inspector handshake — are `shared_constants.json` and
`scaffold_inspectors.json` here.

## Notes for the Rust port

- **Pure JSON, ASCII-escaped.** No Python-specific encoding; `serde_json`
  reads them directly. The escaping matters: several cases carry
  zero-width and non-breaking characters that are invisible (or
  misleading) raw in a diff.
- **Error messages interpolate Python type names and reprs.** A Rust port
  of `validate_relay_entry` must reproduce these exactly. The JSON→Python
  type-name mapping the messages use:

  | JSON | `type(x).__name__` |
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
- **`encoded_private_ip` "non-global" is CPython's
  `ipaddress.IPv4Address.is_global`**, and it does *not* vary by
  interpreter version. Every case in `encoded_private_ip.json` and
  `valid_domain.json` was run on CPython 3.12.0, 3.12.3, 3.12.4, 3.13.0
  and 3.14.7 and produced identical answers on all five (`is_global` is
  the same expression on each: `addr not in 100.64.0.0/10 and not
  addr.is_private`).

  A Rust port should nonetheless implement the IANA special-purpose
  registry explicitly rather than reach for a crate's `is_private()` —
  not because of version drift, but because **the two are different
  predicates**. 100.64.0.0/10 is the proof: `is_global` is `False` and
  `is_private` is *also* `False`, so `not is_private` would let
  carrier-grade NAT straight through. The `cgnat-*` and `test-net-*`
  cases exist to make that substitution fail loudly, and the mutation
  test `test_host_encoded_private_ip_mutation_is_caught` shows it doing
  exactly that.
- **`scaffold_inspectors.json` records `inspectors` chain ORDER.** The
  inspectors run as a chain, so a reordering is a behaviour change even
  when the set is identical.
- **Type coercion is part of the contract too.** `int(port)` truncating a
  float, `bool(tls)` making the *string* `"false"` truthy, `x or ""`
  turning `null` into an empty string — a Rust port working from typed
  YAML has to decide what to do with each, and the `ok-`/`err-` cases say
  which answer is the current one.

## Adding a case

The generator that used to compute these expectations ran the Python host
CLI, which no longer exists, so cases are now added by hand. That makes
the two suites the check: an expectation typed by a human can be wrong,
but it has to satisfy *both* the Rust implementation and the proxy.

1. Add the case to the relevant JSON file, with a unique `id` and a `why`
   that says what the case is *for*. Keep the file ASCII (escape anything
   else as `\uXXXX`); a pytest check enforces it.
2. Run both suites:

   ```
   uv run pytest tests/test_contract_fixtures.py -q
   cargo test --workspace
   ```

3. If one side disagrees with the expectation, decide which is right. A
   disagreement is a bug in one implementation, not a reason to weaken
   the case.

Changing an *existing* expectation is a changed security contract and
should be called out as such in the commit message.

## Proving the fixtures bite

A conformance corpus that passes against a broken implementation is worse
than no corpus, because it reads like coverage. `TestFixturesBite` in
`tests/test_contract_fixtures.py` applies real source-level mutations —
the module's own source, read from disk, edited, and executed — to the
proxy implementation, and requires the conformance check
to fail, naming the specific case ids that catch each one. There is a
control arm (`test_unmutated_modules_still_conform`) so a mutation test
cannot pass because the mutation harness itself is broken, and `_mutate`
refuses a pattern that does not match exactly once, so a mutation cannot
silently become a no-op when the implementation moves.
