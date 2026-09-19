# Golden corpus

Everything in this directory except this file is **generated**. Do not hand-edit it.

```sh
uv run python scripts/gen-golden-corpus.py
```

## What it is

A characterization net over the host's config handling. For a large set of
`cage.yaml` inputs, the harness records *everything the host deterministically
produces* from each one:

| Artifact | Produced by |
| :-- | :-- |
| `quadlets/*.container`, `*.network`, `*.volume` | `quadlets.generate_quadlets` + `templates/*.j2` |
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
| `shared/egress-content-hash.txt` | `backends/apple_container._egress_content_hash` |

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

One exception inside the YAML rule: a case whose input is *deliberately
malformed* YAML falls back to a byte comparison, because unparseable text has
no value to compare.

The fingerprint sits safely on either side of this line: `fingerprint.py`
hashes the *parsed* cage.yaml, not its text.

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
  `systemd-creds`.

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

To verify determinism: generate twice into two directories and `diff -r` them.

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

## Known gaps

* **apple-container units are not captured.** Cases with
  `isolation: apple-container` record their cage.yaml-derived artifacts
  (warnings — which is where most of that backend's config logic lives —
  resolved config, proxy-config, DNS allowlist, placeholders), but not units:
  that backend builds `container run` argv and a launchd plist in
  `backends/apple_container.py`, not quadlets. Those directories carry a
  `quadlets/NOT-APPLICABLE.txt` saying so.
* **11 of `config.py`'s 91 raise sites are unreachable** from any cage.yaml —
  see `RAISE-COVERAGE.md`. Most are shadowed by an earlier guard that raises
  the same or a near-identical message; one is an explicit internal-invariant
  assertion. The Rust port does not need to reproduce dead code, but it should
  not be surprised by its absence either.
