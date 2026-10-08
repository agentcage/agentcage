# Golden corpus

Everything in this directory except this file is **generated**. Do not hand-edit it.

```sh
uv run python scripts/gen-golden-corpus.py
```

Then verify it across interpreters before committing — see
[Regenerating](#regenerating). "I generated it twice on my machine" is not the
check; the corpus has to be identical on every Python the CI matrix runs.

## What it is

A characterization net over the host's config handling. For a large set of
`cage.yaml` inputs, the harness records *everything the host deterministically
produces* from each one:

| Artifact | Produced by |
| :-- | :-- |
| `quadlets/*.container`, `*.network`, `*.volume` | `quadlets.generate_quadlets` + `templates/*.j2` |
| `quadlets/<cage>.json` (apple-container only) | `AppleContainerBackend.generate_units` |
| `launchd/io.agentcage.<cage>.plist` (apple-container only) | `AppleContainerBackend._install_launchd_plist` |
| `proxy-config.yaml` | `state.save_proxy_config` (the 12 keys in `state._PROXY_KEYS`) |
| `dns-allowlist.conf` | `state.save_dns_allowlist` |
| `placeholders.env` | `state.save_placeholders_env` |
| `stored-cage.yaml` | the cage.yaml as persisted into state, placeholders filled |
| `resolved-config.json` | the parsed `config.Config`, as JSON |
| `fingerprint.json` | `fingerprint.compute_fingerprint` |
| `volume-mounts.json` | `volume_mounts.py` parsing of this config's mounts |
| `warnings.txt` | `config.validate_config`'s return value, one per line |
| `render-warnings.txt` | what `generate_quadlets` wrote to stderr |
| `error.txt` | the exception from a config that does not validate |
| `shared/har/*` | `har.py`, over the committed `_inputs/capture.jsonl` |
| `shared/audit/*` | `audit.py`, over the committed `_inputs/audit.jsonl` |
| `shared/volume-mounts.json` | `volume_mounts.py`, over a standalone spec table |
| `shared/domain-validation.json` | `config.valid_domain` / `config.encoded_private_ip` |
| `shared/egress-content-hash.txt` | `egress_hash._egress_content_hash` (still re-exported from `backends/apple_container` before PR A5 lands) |

The most valuable part is the last column of that first group: **every
validation error message and every warning string**, captured verbatim. Those
strings are UX. `tests/test_config.py` already asserts a handful of them by
hand; this captures the rest.

## Why it exists

`src/agentcage/config.py` is ~2,500 lines, roughly 90% of it validation logic
and human-facing error strings, and it is being rewritten in Rust (see
`RUST-PORT-PLAN.md`, §4 "Layer 1"). "Did I port 2,500 lines of validation
correctly?" is not a reviewable question. With this corpus it becomes a diff:
the Rust implementation reads these files directly and must reproduce them.

The corpus is also useful on `master` on its own — it is a regression net over
config handling that did not exist before.

## Layout

```
_inputs/                 hand-written fixture inputs (capture.jsonl, audit.jsonl)
manifest.json            every case, its kind, and the corpus statistics
RAISE-COVERAGE.md        which `raise` sites in config.py the corpus reaches
raise-coverage.json      the same, machine-readable
shared/                  artifacts that do not depend on any one cage.yaml
valid/<case>/            a config that loads and validates
  input/cage.yaml        the exact input
  ...                    the artifacts listed above
invalid/<case>/          a config that does not
  input/cage.yaml        the exact input (or `invocation.txt`, see below)
  error.txt              "<ExceptionType>: <message>"
```

A handful of `invalid/` cases carry `invocation.txt` instead of
`input/cage.yaml`: they pin error paths that no file on disk can reach (a
missing config file, the host-DNS-detection failures).

Everything is a plain file in a predictable place, readable by a non-Python
process. No pickle, no Python module.

## Byte-exact vs. semantic comparison

`tests/test_golden_corpus.py` compares two ways, and the split is deliberate —
`RUST-PORT-PLAN.md` §2.8 is the source:

* **YAML artifacts** (`*.yaml`) are compared **by parsed value**. PyYAML's
  emitter is not reproducible from Rust: it wraps at 80 columns, does not
  indent sequences under a mapping key, and has its own quoting heuristics.
  Demanding byte equality there would force the port to reimplement PyYAML's
  line-breaking, which nothing depends on — the egress *parses*
  `proxy-config.yaml`, it does not diff it.
* **Everything else** is compared **byte-for-byte**: quadlet units, env files,
  `dns-allowlist.conf`, hashes, JSON, error strings, warning strings. These
  either feed a byte-sensitive consumer (systemd, dnsmasq, sha256) or are UX
  that users read.

**The launchd plist is XML, and it is on the byte-exact side.** That looks
like it should need the same argument YAML got, and it does not, for one
reason: `_install_launchd_plist` **never calls `plistlib`**. It builds the
document with an f-string, so the indentation, the key order, the `<true/>`
spelling and the trailing newline are agentcage's own source text rather than
a serializer's opinion. There is no emitter to reimplement and no
cross-version drift to absorb — reproducing these bytes is reproducing a
format string. The port keeps the f-string for the same reason: a plist crate
would produce *valid* output that differs byte for byte, which would turn a
settled comparison into a semantic one for no gain.

One exception inside the YAML rule: a case whose input is *deliberately
malformed* YAML falls back to a byte comparison, because unparseable text has
no value to compare.

The fingerprint sits safely on either side of this line: `fingerprint.py`
hashes the *parsed* cage.yaml, not its text.

### apple-container: units and a plist, not quadlets

The rest of what this backend derives — the volume and tmpfs
resolutions, and the three egress-config files it renders for the
microVM to bind-mount — is recorded separately in
`tests/fixtures/apple-container/` (PR E2), keyed `corpus:<case>`.

Cases with `isolation: apple-container` used to carry a
`quadlets/NOT-APPLICABLE.txt` where the units would be. They no longer do (PR
E3). That backend has no quadlets, but it does have units: `generate_units`
returns one `<cage>.json` metadata blob that `start()` rebuilds the
`container run` argv from, and it is recorded in the same `quadlets/`
directory because that is the directory `fingerprint-inputs.json` names as
"the units".

Which matters more than it sounds. `cli.py::_update_fingerprint` feeds
`backend.generate_units` to `compute_fingerprint` on **every** backend, so
recording no units for those cases meant recording a fingerprint no real
deploy could produce. Filling them in moved five `fingerprint.json` files and
nothing else.

The `launchd/` directory holds what `_install_launchd_plist` writes. The
harness calls the **real** installer — with `_gui_domain_reachable` pinned to
`False`, so it writes the file and returns before touching `launchctl`; a
corpus generator must not install a launch agent on the machine that runs it.
It is recorded for every apple-container case, not only the autostart one:
the document is a pure function of the cage name, the resolved `container`
path and the state dir, so `apple_container_autostart` decides whether it is
*installed*, not what it says. The flag itself is `autostart` in the unit
JSON.

## Determinism

The harness must produce an identical tree on any machine, on any run. It does
that by pinning, before `agentcage` is imported:

* a hermetic `HOME` / `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_RUNTIME_DIR`
  under a throwaway work directory (`state.py` honours these, so the real `~`
  is never touched);
* `platform.system()` / `platform.machine()` to Linux/x86_64, flipped to
  Darwin/arm64 only for the apple-container cases;
* `importlib.metadata.version("agentcage")` to `0.0.0-golden`, so a release
  does not churn the corpus;
* `shutil.which("agentcage")` to a fixed path;
* `config._host_dns_servers()` to fixed upstreams;
* `secrets.token_hex` to a per-case counter, so generated placeholders are
  stable (and restarted for each case, so inserting a case does not renumber
  every later one);
* `secret_resolver.detect_default_scope()`, which otherwise shells out to
  `systemd-creds`;
* `apple_container.cli.container_binary()` to `/usr/local/bin/container` — it
  is a `shutil.which`, so without the pin it is `None` on every machine that
  is not a Mac with the `.pkg` installed and no plist would be rendered at
  all;
* `backends.apple_container._gui_domain_reachable()` to `False`. That one is
  a safety interlock rather than a determinism pin: it shells out to
  `launchctl print gui/<uid>`, which is a `FileNotFoundError` on Linux but
  would answer `True` on a contributor's Mac — and `_install_launchd_plist`
  would then run `launchctl bootstrap` against their live session. A corpus
  generator must not install a launch agent on the machine that runs it.

Whatever absolute paths survive that are scrubbed on the way out to `{{HOME}}`,
`{{XDG_CONFIG_HOME}}`, `{{XDG_DATA_HOME}}`, `{{XDG_RUNTIME_DIR}}`, `{{WORK}}`
and `{{REPO}}`. The scrubber also looks **inside base64 blobs**: `quadlets.py`
base64-encodes host paths before embedding them in a systemd `Exec=` line, so
the corpus stores `base64("{{HOME}}/project")` and a reimplementation must
apply the same scrub before comparing.

Two consequences worth knowing:

* `fingerprint.json` is computed over the **scrubbed** unit text, so the
  recorded digest is a property of the corpus rather than of the machine that
  generated it. The rest of the fingerprint chain (`stable_json`, the component
  layout, the sha256-of-sha256s) is exercised unchanged.
* `fingerprint-inputs.json` is a *recipe*, not a copy: it names the files that
  were hashed rather than duplicating megabytes of quadlet text.

### Interpreter independence

Determinism across *runs* is not enough: the corpus must also be byte-identical
across every CPython the CI matrix runs (3.12, 3.13, 3.14). That rules out a
whole class of generator code — **anything whose output text is produced by a
pretty-printer that ships with the interpreter must never reach a committed
byte.**

The concrete trap, because it already bit once: `ast.unparse`. PEP 701 changed
its quote selection for f-strings containing nested quotes, so

```python
raise ValueError(f"unknown agents: {', '.join(sorted(unknown))}")
```

unparses with an outer `"` on 3.12/3.13 and an outer `'` on 3.14. A corpus
generated on 3.14 then failed on two thirds of the matrix over pure quote
style. `RAISE-COVERAGE.md` is now rendered from node *types* and *constant
values* (`_message_template` in the harness), which are fixed by the grammar,
so a raise site reads as `ValueError: unknown agents: {…}` — the message
template, with every interpolation collapsed — rather than as round-tripped
source. That is both stable and closer to what the Rust port actually has to
reproduce.

`tests/test_golden_corpus.py::test_harness_emits_nothing_interpreter_dependent`
is the cheap tripwire: it fails if the harness ever calls `ast.unparse` or
`ast.dump` again. It is not a substitute for the cross-interpreter run below.

### Regenerating

```sh
# 1. regenerate in place
uv run python scripts/gen-golden-corpus.py

# 2. prove it is deterministic AND interpreter-independent
for v in 3.12 3.13 3.14; do
    uv run --python $v python scripts/gen-golden-corpus.py --out /tmp/corpus-$v
done
diff -r /tmp/corpus-3.12 /tmp/corpus-3.13
diff -r /tmp/corpus-3.13 /tmp/corpus-3.14

# 3. run the suite on the ends of the matrix
uv run --python 3.12 pytest -q
uv run --python 3.14 pytest -q
```

Step 2 is the one that matters. Two runs on a single interpreter will happily
agree with each other and still fail CI.

## No real secrets

Every credential-shaped value in here is obviously fake (`FAKE_*`,
`example.com`, `RkFLRQ==`). Keep it that way.

## Re-blessing

Re-blessing is **deliberate**, never reflexive. A failure in
`tests/test_golden_corpus.py` means one of two things:

1. **A regression.** Fix the code.
2. **An intended behaviour change.** Regenerate, then *read the diff*. Every
   changed line is something a user sees, or something the Rust port will be
   held to. A one-line change to an error message should produce a one-line
   diff; if it produces four hundred, something else moved too.

`shared/egress-content-hash.txt` is the one artifact that changes for reasons
unrelated to config handling: it hashes the egress image's build inputs, so any
edit under `src/agentcage/data/proxy/` moves it. That is the intended
behaviour (§2.1 of the port plan — the tag must not drift between the Python
and Rust builds); `shared/egress-build-inputs.txt` lists the hashed files and
their sizes so the diff says *which* file moved.

Moving the hash *code* must not move the hash *value*. The harness imports
`agentcage.egress_hash` and falls back to the pre-A5 home in
`backends/apple_container`, so it is correct on either side of that
refactor — and this corpus records `25cff145d1e6` over 24 build inputs from
both import paths, which is the same value PR A5 measured independently.

## Known gaps

* **The apple-container plist cannot distinguish the state root from an XDG
  one.** The harness's sandbox sets `XDG_CONFIG_HOME` to `$HOME/.config`, and
  the scrubber prefers the longer rule, so the recorded plist says
  `{{XDG_CONFIG_HOME}}/agentcage/apple-container/<cage>` where the code in
  fact wrote `expanduser("~/.config/agentcage/apple-container/<cage>")` with
  no XDG lookup anywhere near it. The distinction is real — an
  `XDG_CONFIG_HOME` sandbox does **not** redirect this root — and it is
  pinned where it can be: in `agentcage-state`'s `Paths` tests, and in
  `tests/fixtures/apple-container/argv.json`, whose generator deliberately
  points `XDG_CONFIG_HOME` somewhere else. Same shape as
  `_stage_vm_file_volume`'s literal `~/.local/share`, and the same reason the
  corpus cannot see it.
* **11 of `config.py`'s 91 raise sites are unreachable** from any cage.yaml —
  see `RAISE-COVERAGE.md` for the list. They fall into three groups, and the
  middle one matters for the port:

  1. *Shadowed, identical wording.* `load_config#4`, `load_config#5`,
     `validate_config#29`, `validate_config#40`. An earlier guard raises the
     exact same string first (`validate_agents_raw` → `_agent_mapping`, or
     `load_config`'s own `api_key` scheme check). The message is in the corpus;
     it just comes from the other site.

  2. *Shadowed, **different** wording — dead strings.* `load_config#6`, `#9`,
     `#10`, `#12`, `#13`. These are the `agents.decider.enable`,
     `agents.watcher.enable`, `auto_revoke` and `dedup_samples` boolean
     guards, each of which appends a `— got <type>` suffix. `validate_agents_raw`
     runs first and rejects the same input with the *suffix-free* wording, so
     **the `— got <type>` variants can never be produced by any input.**
     Reproducing them in Rust would be reproducing dead code. If you want
     those messages to be the ones users see, the fix is to delete or relax
     the earlier guard, not to port both.

  3. *Structurally unreachable.* `_validate_agent_max_tokens#0` (`must be an
     integer`) — `_llm_client` coerces with `int()` before validation and a
     bool is caught by the earlier "must be a number, not a boolean" guard.
     `validate_config#35` (`host must always be in never_grant (internal
     invariant violated)`) — `effective_never_grant()` adds the host by
     construction; it is an assertion, not a user-facing error.
