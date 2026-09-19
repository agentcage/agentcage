# agentcage: Python → Rust port plan (host CLI + tooling only)

Against `461c99b` (v0.40.1).

**Scope decision (2026-09-19):** port the host CLI and tooling to Rust **on
every platform — Linux and macOS alike**. The in-egress proxy — mitmproxy, the
addon, inspectors, protocol relays, the Policy API, the traffic watcher, and the
custom-inspector extension point — **stays in Python, unchanged**.

The target invariant: **Python is not an agentcage runtime dependency anywhere
except inside the egress container image.** Not on the host, not in the Lima
guest, not as an installable package. It ships as data embedded in the Rust
binary and baked into the egress image at build time.

Two things are deliberately outside that sentence. Workload images are the
user's business: the `claude-code`, `codex`, and `pi` scaffold Containerfiles
all install `python3` because the agents need it, and that is fine. And
dev/test tooling keeps Python: pytest for the proxy suite, `scripts/update-deps.py`,
and the e2e harness itself, which shells to host `python3` in phases 2, 7, and 8
to parse JSON. The invariant is about what a user must have installed to run
agentcage, not about what a contributor needs to hack on it.

That invariant is already almost true. The only host-side `python3` reference in
shipped code is `cli.py:1618`, and it runs *inside the cage container* as a
last-resort HTTP client during `cage verify` — a probe of the workload image,
not a host dependency. The Lima guest installs podman and its network stack and
no Python at all (`templates/lima/provision.sh.j2`). The port closes the
remaining gap, which is the CLI itself.

---

## 1. What this scope buys

The two halves of agentcage never call each other. They communicate only through
files on a bind mount:

| Direction | Artifact | Producer | Consumer |
| :-- | :-- | :-- | :-- |
| host → egress | `proxy-config.yaml` (12 whitelisted keys, `state._PROXY_KEYS`) | `state.save_proxy_config` | `addon.Agentcage.load` |
| host → egress | `dns-allowlist.conf` | `state.save_dns_allowlist` | dnsmasq (SIGHUP) |
| host → cage | `cage-env/placeholders.env`, tmpfs secret files | `state.save_placeholders_env` | workload env / `secret_injector` |
| both ways | `grants/grants.json` + reload flag | CLI `grants promote/revoke`, `policy_api._persist_grants` | both, atomically (`state._atomic_write_text`) |
| egress → host | `audit.jsonl`, `capture.jsonl`, watcher state/findings | addon | `cage audit` / `cage har` / `watcher findings` |

Because that seam is files-only, the host can be rewritten without touching a
line of proxy code.

**Two problems from the earlier full-port plan are deleted outright:**

- **Replacing mitmproxy.** No Rust equivalent exists for transparent
  `SO_ORIGINAL_DST` mode + reverse-mode listeners + on-the-fly leaf certs +
  h2 + WebSocket framing + the `flow.server_conn.error` abort seam. Gone.
- **Custom inspectors.** `inspectors/util.py:load_inspector_from_file`
  `exec_module`s user-authored `.py` files from `/etc/agentcage/inspectors` —
  a documented public API with no Rust story. Gone.

Those two carried essentially all the schedule variance. What remains is a
~21k-line subprocess orchestrator with excellent test coverage.

**LOC in scope**

| | LOC | Disposition |
| :-- | --: | :-- |
| Host (`src/agentcage/**` minus `data/proxy`) | 20,822 | **Port to Rust** |
| Egress proxy (`src/agentcage/data/proxy/**`) | 9,949 | Stays Python |
| Shell + Jinja + Containerfiles | 3,824 | Unchanged |
| Host-side pytest (63 files) | 30,468 | Replace with Rust tests |
| Proxy-side pytest (20 files) | 14,815 | **Stays pytest** |

---

## 2. The problems this scope *creates*

Splitting the languages at the trust boundary introduces work that a full port
would not have had. These are the real content of this plan.

### 2.1 The Rust binary must carry and materialize the Python package data

`backends/container.py:70` does:

```python
data_dir = Path(__file__).resolve().parent.parent / "data"
build_context = str(data_dir)      # ← the package's own data/ IS the podman build context
```

`Containerfile.egress` then `COPY`s `proxy/addon.py`, `proxy/inspectors/`,
`proxy/relays/`, `proxy/transforms/`, `containers/supervisor-egress.sh`, etc.
out of it. The vm backend pushes the same tree into the Lima guest
(`vm.py:593`); the apple-container backend builds from it too.

So the Rust binary must embed the full `data/`, `templates/`, and `scaffolds/`
trees (`include_dir!` or `rust-embed`) and extract them to a cache directory to
serve as a build context. Requirements:

- **Byte-exact extraction.** File *modes* matter (`chmod 0755` on the supervisor
  is done in the Containerfile, so that one is fine, but check each).
- **`_egress_content_hash` must reproduce exactly.** `apple_container.py:210`
  hashes sorted `(relpath, len, content)` triples over the transitive COPY
  sources to build the image tag `localhost/agentcage-egress:<version>-<hash>`.
  A different hash means every Mac rebuilds its egress image once, and
  thereafter drifts from the Python build. Port `_egress_copy_sources` (which
  parses logical Containerfile lines, handling continuations) verbatim.
- **Extraction cache invalidation** keyed on binary version + content hash.

This is new work with no Python counterpart — today the files are just *there*
on disk in the installed package.

### 2.2 Four shared-logic sites become cross-language contracts

Today, host and proxy either import the same module or are held in sync by tests
that import both. Neither survives the language split.

| Host | Proxy | Today |
| :-- | :-- | :-- |
| `config.py:15` imports `agentcage.data.proxy.relays._validate.validate_relay_entry` | `relays/_validate.py` imported as `relays._validate` | **Literally the same code.** The module's docstring says it lives there so "both sides of the trust boundary import the same code." |
| `config.encoded_private_ip` | `policy_api._encoded_private_ip` | Duplicated; `test_policy_api_ssrf_guard.py` imports both and asserts agreement |
| `cli._is_never_grant` | `policy_api._is_never_grant` | Duplicated; same test file |
| `config.valid_domain` / `DOMAIN_RE` | `policy_api._valid_domain` / `_DOMAIN_RE` | Duplicated by design (comment at `config.py:44`) |

Plus format contracts: `state._PROXY_KEYS`, the `agentcage:secret:NAME:<hex>`
placeholder grammar (`config.PLACEHOLDER_PREFIX` ↔ `secret_injector`), the
grants-overlay JSON shape, and `audit.jsonl` / `capture.jsonl` schemas.

Two more surfaced during the A6 import scan and were not in the list above:

- `CaptureWriter`'s default `max_file_size` ↔ `config.MAX_CAPTURE_FILE_BYTES`
- `init.render_config("openclaw")` output ↔ `addon._load_builtin_inspectors`,
  a host→proxy handshake: the host renders a config the proxy must be able to load

Expect the list to keep growing as the scan widens. That is an argument for
generating the fixtures from the Python implementation (below) rather than
curating them by hand.

**Mitigation:** a language-neutral conformance fixture. A JSON file of
`(input, expected)` cases per contract, checked by both a Rust test and a pytest
test. `relays/_validate.py` is the sharpest case — 161 lines of validation with
specific error strings that `agentcage cage create` surfaces to the user, which
must now exist twice. Consider generating the fixture from the Python
implementation so it cannot drift silently.

**This is the single largest new risk in this scope** and deserves to be built
first, in Phase 0, not discovered in Phase 2.

### 2.3 Version ownership (simpler than it first appears)

`importlib.metadata.version("agentcage")` is read at ~10 host call sites and
determines the egress image tag, the `Image=` pin in `egress.container.j2`,
`agentcage_version` in `cage.container.j2`, `metadata.json` stamps, and
`proxy_cfg["agentcage_version"]`.

The good news: **the Python side never reads its own package metadata.**
`policy_api._version()` (line 1557) takes `AGENTCAGE_VERSION` from the
environment — set by every backend — and falls back to the `proxy-config.yaml`
stamp the host writes. So once the CLI is Rust, the Rust binary owns the version
outright as a compile-time constant, and nothing needs to keep two package
versions in lockstep.

A root `VERSION` file is still worth having so the Containerfiles, docs, and the
dev-only `pyproject.toml` agree, but it is bookkeeping, not a correctness
constraint.

### 2.4 Python stops being a distributable package

Today `pyproject.toml` builds a wheel published to PyPI, and `uv tool install
agentcage` is the documented install path. After the port:

- `pyproject.toml` remains **dev/test-only**: no `[project.scripts]`, no publish.
  Its job is to let `pytest` run the 20 proxy test files, which it already does
  via `pythonpath = ["src", "src/agentcage/data/proxy"]` — no install required.
- The proxy's runtime dependencies (`pyyaml`, `cryptography`) are declared where
  they are actually installed: `Containerfile.egress`'s `pip install`.
- One final PyPI release ships a shim that prints a migration notice, then the
  package is yanked from the install path.

**Enforce the invariant in CI**, or it will rot:

- Fail the build if Rust source shells out to `python`/`python3` (one
  allowlisted exception: the in-cage `cage verify` probe).
- Fail the build if `data/proxy/**` imports anything outside stdlib + `yaml` +
  `cryptography`, since those are the only packages the egress image installs.
- Fail the build if any Containerfile under `data/containers/` other than
  `Containerfile.egress` installs Python. Scaffold Containerfiles are exempt
  (they build workload images, see above). `Containerfile.helper` — alpine plus
  `python3` and `py3-yaml` — is shipped today but referenced by nothing except
  `scripts/update-deps.py` and one test fixture. Delete it in F4 rather than
  allowlist it.

**Nine test files straddle the language boundary** and must be split, with the
cross-language half moving to the §2.2 fixture. Measured by an AST import scan
(PR A6, `scripts/classify-tests.py`), not by inspection — an earlier draft of
this plan guessed two, and guessed one of them wrong:

| Class | Files |
| :-- | --: |
| host | 63 |
| proxy | 26 |
| **both (split by A6)** | **9** |
| neutral | 9 |

`test_policy_api_ssrf_guard.py` was a genuine straddler. **`test_addon_reload_inspector_config.py`
is not** — it imports only proxy modules. `test_policy_api_config.py`,
`test_policy_api_ttl.py` and `test_dns_live_reload.py` are cleanly host-side
despite proxy-sounding names.

Two files resist classification and are worth knowing about: `test_egress_image.py`
and `test_egress_image_contents.py` assert *about* proxy source by reading it as
text without importing it, so no import edge exists to catch them. They will have
to become Rust-side or shell-side checks. And `tests/conftest.py` classifies as
host but must survive the deletion of host tests, because it is what stubs
mitmproxy for the proxy suite.

### 2.5 The image-size argument does not apply

`Containerfile.egress` stays `FROM docker.io/mitmproxy/mitmproxy@sha256:…` plus
`pip install pyyaml cryptography` plus eight apt packages. **The egress image
does not shrink, and Python remains inside the security boundary.** Any pitch
for this port should not claim otherwise. The real wins are host-side:

- No Python ≥3.12 requirement on the host; `install.sh` sheds its
  Python-detection and uv-bootstrap sections (though it still installs podman,
  Lima, Homebrew as today).
- Startup drops from interpreter + click import to ~1ms — noticeable on
  `cage list`, `domain list`, and shell completions.
- A single static binary to distribute.
- The host stops needing a Python toolchain entirely, on Linux *and* macOS.

### 2.6 macOS becomes a first-class build and release target

Porting the Mac path is less risky than it sounds, because of what CI already
does — see §4 — but it does add two genuinely new costs.

**Code signing and notarization.** A Python tool installed via `uv`/`pip` never
meets Gatekeeper. A downloaded Rust binary does. `install.sh` piping from curl
avoids the quarantine xattr, and Homebrew installs generally do too, but a
direct download from a GitHub release does not. Budget for an Apple Developer ID
plus `codesign` and `notarytool` steps in the release workflow, and decide
between a universal binary (`lipo`) and separate `aarch64-apple-darwin` /
`x86_64-apple-darwin` artifacts. Note `apple-container` is Apple-Silicon-only
while the `vm` (Lima) backend runs on both, so the x86_64 build is not dead
weight.

**Three cross-compilation targets, not one.** `x86_64`/`aarch64-unknown-linux-musl`
for Linux hosts, plus the two Darwin targets. macOS builds need a macOS runner;
cross-compiling Darwin from Linux is not worth attempting.

### 2.7 The Rust binary inherits Python's on-disk state, unversioned

At cutover every existing user has cages that Python deployed. The Rust binary
must read all of it in place, on its first invocation, with no migration step:

This table is corrected against the source as of PR A7. An earlier draft got
four of these wrong, and each error is a way a Rust reader would have failed:

| Location | Files |
| :-- | :-- |
| `~/.config/agentcage/**cages**/<name>/` | `cage.yaml`, `metadata.json`, `fingerprint.json`, `creds/<key>.cred`, `secret_keys.json`, `pending_secrets.json` |
| `~/.config/agentcage/apple-container/<name>/` | **a third root, and it uses `~` directly, not `XDG_CONFIG_HOME`** — `logs/{audit,capture}.jsonl`, `dnsmasq.log`, `ready`, `mask-mountpoints.json` |
| `~/.local/share/agentcage/<name>/` | `grants/grants.**yaml**` (a top-level YAML **list**), `capture/`, `policy-audit.jsonl` |
| `~/.local/share/agentcage/patches/` | **shared, not per-cage**: `resolv-<name>.conf`, `resolv-egress-<name>.conf`, the `nested/` podman shim |
| `~/.config/containers/systemd/` | quadlets Python rendered, still running |
| user-chosen paths | backup tarballs: gzipped tar with a `manifest.json` (`cli.py:3209`) |

Three traps worth stating outright:

- **`audit.jsonl` does not exist host-side for `container` or `vm` cages.** The
  addon writes its audit trail to stderr and the host reads it back out of
  `journalctl`. Only apple-container has a file. A Rust `cage audit` that looks
  for a file on Linux finds nothing.
- **`pending_secrets.json` is a JSON array of `[key, value]` pairs, not an
  object.** Both writers agree on this. A Rust reader assuming a map fails on
  every cage that used either path.
- **The apple-container state root ignores `XDG_CONFIG_HOME`.** That is both a
  portability wart and a testing hazard: an XDG sandbox does not redirect it.

**None of this carries a schema version.** `metadata.json` is a bare
`json.dumps(dict)`; there is no `state_version` field anywhere in `state.py`.
So there is nothing to branch on — the Rust readers simply have to accept
exactly what the Python writers produced, and the first `cage update` under
Rust on an untouched cage must be a fingerprint no-op. `fingerprint.json` is
what makes that checkable, which is why it belongs in the table.

**Mitigation:** PR A7 commits a generated state tree and backup tarball for
three cages, produced by driving the real code paths rather than by writing
JSON by hand. Every Rust reader is tested against it, and F2's acceptance check
includes upgrading a live Python-deployed cage in place.

**Known gap:** the staged Containerfile and build context that
`fingerprint.scaffold_context_version` hashes is not captured, because it needs
a real scaffold build. If the Rust `cage update` no-op path depends on it, that
needs a follow-up fixture. C4 confirmed this is still open: it ported the
digest itself but the directory walk is owed to Track D, and nothing verifies
it end to end.

**A second corpus recipe gap, found by C4.** For the three cases with a
generated `agentcage:secret:NAME:<hex>` placeholder, `gen-golden-corpus.py`
writes `resolved-config.json` from the config as *first loaded*, then calls
`fill_placeholders`, reloads, and fingerprints *that*. So the committed
resolved config cannot rebuild the fingerprint's `resolved_config` component
for those three. Their other four components reproduce, and `stored-cage.yaml`
(which is post-fill) reproduces exactly. Worth fixing the recipe so the corpus
is whole.

### 2.8 YAML: PyYAML speaks 1.1, every Rust crate speaks 1.2

This is the one place where a *correct* Rust port silently disagrees with the
Python it replaces. PyYAML's `safe_load` follows YAML 1.1: `yes`, `no`, `on`,
`off` are booleans, `0755` is octal 493, `1:30` is sexagesimal 90. Every Rust
YAML crate implements 1.2, where those are the strings `"yes"`, `"0755"`, and
`"1:30"`. It bites in both directions:

- **Rust reading cage.yaml.** A user with `tls: no` in a relay entry today gets
  `False`; after F2 they get the string `"no"`, which `bool("no")` semantics in
  the port could turn into `True`. No shipped config or doc uses these spellings
  (checked), but user configs can.
- **Rust writing proxy-config.yaml.** If the Rust emitter writes the string
  `no` unquoted — as a domain, a header value, anything — PyYAML inside the
  egress reads it as `False`. The emitter must quote every 1.1-ambiguous scalar.

**Measured, not assumed** (2026-09-19): emit each hazardous scalar from Rust
*as a string*, read it back with `yaml.safe_load`. A first pass over a
hand-written token list found 14 leaks. PR B2 then re-derived the set from
**PyYAML's own implicit-resolver table** rather than from a word list and found
**31 of 56**. The table below is the corrected one; the lesson is that this
hazard is a set of *patterns*, so enumerating spellings undercounts it.

| Corrupted | PyYAML reads |
| :-- | :-- |
| `yes` `Yes` `YES` `on` `On` `ON` | `True` |
| `no` `No` `NO` `off` `Off` `OFF` | `False` |
| `12:00:00` `1:30:15` `-1:30` `1:30.5` | sexagesimal int/float |
| `1_000` `1_000.5` `0x_1f` | underscored numerics |
| `2024-01-02` | `datetime.date` |
| `2024-01-02T03:04:05`, and the space-separated form | `datetime.datetime` |

The **timestamps are the ones a token list misses**, and they are not exotic: a
relay field, header value or domain shaped like a date silently stops being a
string inside the security boundary.

Two scalars do not corrupt — they **raise**. `<<` and `=` resolve to tags
SafeLoader has no constructor for, so an unquoted one stops the proxy loading
its config at all. Loud, but still a host-side emitter bug.

The crates already quote the YAML-1.2 specials — `true`, `null`, `~`, `0755`,
`0x1F`, `.inf`, `.nan` — so those are safe. It is precisely the **1.1-only**
patterns that leak, which is why this cannot be left to the crate's default
quoting. Both crates behave identically here, so the choice between them does
not affect it.

**Known reader gap, tracked (found by C4, verified 2026-09-19).** B2's reader
resolves 1.1 **booleans** only. The full resolver table exists in the crate but
is wired to the *emitter* predicate, so on load:

| YAML | PyYAML | Rust reader |
| :-- | :-- | :-- |
| `no` | `False` | `Bool(false)` ✓ |
| `0755` | `493` | `String("0755")` |
| `1:30` | `90` | `String("1:30")` |
| `1_000` | `1000` | `String("1_000")` |
| `2024-01-02` | `datetime.date` | `String("2024-01-02")` |

Booleans were the right place to stop: they map cleanly onto a `Value` variant
and carried the TLS impact above, whereas PyYAML's timestamps have no variant
to land in, so full parity is not a small change. The consequences are mild —
a numeric field receiving a string is a **loud** type error from C2/C3, and a
fingerprint over an unquoted octal drifts once, costing one spurious rebuild.
No shipped config, doc or corpus case hits it. Close the integer families
before Track D; timestamps need a decision about `Value` first.

**The read side has a sharper edge than the write side.** PyYAML reads bare
`no` as `False` but quoted `'no'` as the *string* `"no"`, and
`relays/_validate.py:76` does `tls = bool(upstream.get("tls", True))` — so
`upstream.tls: 'no'` runs today **with TLS on**. Every serde YAML crate
discards scalar style, so a naive port reads both spellings the same and turns
that relay's TLS **off**. Python's behaviour is itself a bug, but it fails
safe and the naive port fails unsafe, which is why B2 recovers scalar style
from a second, style-only parse rather than accepting the divergence.

Note the asymmetry: PyYAML *does* quote `'no'` on output, so Python→Rust and
Python→Python are both safe. **Only Rust→Python corrupts.** A round-trip test
that runs Rust→Rust will not catch this; the fixture has to cross the language
boundary in that one direction.

`serde_norway` preserves mapping key order on round-trip (verified), which
satisfies the other hard requirement.

Separately, **PyYAML's output formatting is not reproducible** from Rust: it
wraps at 80 columns, does not indent sequences under mapping keys, and has its
own quoting heuristics. `cage edit`, `domain add`, and `save_proxy_config` all
rewrite YAML, and the port will change that formatting. That is acceptable
(comments are already dropped today, `state.py:195`), but it means the golden
corpus must assert **semantic equality for YAML artifacts** — parse both, compare
values — and byte equality only for everything else. The fingerprint is safe:
`fingerprint.py:40` hashes the parsed value, not the text.

### 2.9 Python bugs the port found, and what to do about them

Porting reads every line of the original against a fixture, which turns out to
be an unusually good bug detector. These are **reproduced faithfully** in Rust
rather than fixed there, because a port that quietly diverges is worse than one
that carries a known wart. Each needs a product decision, and a fix has to land
on the Python, the corpus and the port together — as the audit one did.

| Found by | Bug | Status |
| :-- | :-- | :-- |
| C5 | The coloured `cage audit` table padded DIRECTION to 4 where the header and the plain branch used 10, shifting every column from METHOD onward by a different amount per row. Colour is the default. | **Fixed**, with the invariant "colour only adds escapes" now asserted on both sides |
| C3 | `agents.decider.host` is matched with `$`, not `\Z`. Python's `$` matches before one trailing newline, so `host: "agentcage.local\n"` validates — while `valid_domain` uses `\Z` specifically to refuse that shape. Verified end to end. | Open; reproduced and pinned |
| C3 | `_validate.py` coercion gaps in front of its branches: `port: true` becomes port 1; `host: [1]` becomes the string `"[1]"` and so looks present; a non-mapping `policy:` **silently skips the whole policy block**, `write_mode` included, because the guard is `isinstance(policy, dict)` rather than a refusal | Open; reproduced and pinned |
| C1 | `container.timeout_start_sec` defaults to 600 in the dataclass and 120 in `load_config`. Since `load_config` is the only way a `Config` is built from a file, **600 is unreachable** | Open; both reproduced, each pinned |
| C4 | The corpus recipe writes `resolved-config.json` pre-placeholder-fill and fingerprints post-fill, so three cases cannot rebuild one component | Open; corpus gap, not a product bug |
| C7 | The corpus recorded only the keys of the mask-mountpoint map, leaving the paths the cleanup chain consumes unverified | **Fixed** in C7 |

The decider-host anchor is the one worth attention. It is narrow — only a
*trailing* newline passes, so a newline followed by content is still refused —
and the practical effect is a control host that silently never matches rather
than an injection. But `valid_domain` and `policy_api` both treat the same
value, and one of the three is deliberately stricter than the others.

---

## 3. Module-by-module disposition

### Ports cleanly

| Python | LOC | Rust approach |
| :-- | --: | :-- |
| `config.py` | 2,473 | `serde` structs + hand-written validator. ~90% is validation and error strings asserted verbatim by `test_config.py`. Must now also reimplement `validate_relay_entry` (§2.2). |
| `quadlets.py` + `templates/*.j2` | 1,177 | `minijinja` 2.24 is Jinja2-compatible; templates should need no edits. The built-in filters used (`indent`, `default`, `join`, `lower`) all exist; register the two custom ones (`systemd_exec` filter in `quadlets.py:267`, `placeholder` global in `init.py:132`). Preserve `SandboxedEnvironment` semantics. |
| `state.py` | 580 | Port `_atomic_write_text`'s O_EXCL + PID-suffix + single-retry logic line for line — the in-container addon writes the same files from a different PID namespace, and the comment explains exactly why each branch exists. |
| `audit.py`, `har.py`, `fingerprint.py` | 685 | Pure functions. `fingerprint.stable_json` must be byte-identical or every `cage update` no-op detection breaks. |
| `volume_mounts.py`, `registry.py`, `secret_resolver.py` | 693 | Mechanical. |
| `podman.py`, `systemd.py`, `lima/*`, `apple_container/cli.py` | 1,073 | `std::process::Command` behind traits (§4). |
| `output.py`, `terminal.py`, `_timing.py` | 493 | `terminal.py`'s raw-mode / Kitty-protocol / bracketed-paste restoration is fiddly; `nix` covers the termios work. |
| `doctor.py`, `legacy_watcher.py` | 719 | Mechanical. `check_python_version` is dropped, not ported. |

### Needs care

| Python | LOC | Why |
| :-- | --: | :-- |
| `cli.py` | 5,632 | `clap` 4.6 vs click. `AliasGroup` (`ls`→`list`, `rm`→`destroy`, `ps`→`list`, `reload`→`restart`, `config`→`edit`, …), `_BannerGroup` help override, hidden back-compat options (`--lines`, `--json`, `--no-follow`), and `ignore_unknown_options` passthrough for `run`/`exec`. Split one module per command group — 5.6k lines in one file is already this codebase's worst seam. |
| `backends/apple_container.py` | 2,591 | Largest backend, but **most of it is fixture-testable on Linux** (§4): image naming + `_egress_content_hash`, `generate_units`, launchd plist rendering, `_user_volume_argv` / `_tmpfs_targets` / `_tmpfs_copyup_seeds`, `exec_argv` / `logs_argv` / `audit_argv`. Only `start`/`stop`/`_stage_secrets`/`_cleanup_mask_mountpoints` need real hardware. |
| `backends/vm.py` | 1,297 | Same split: `generate_units`, `push_config_files`, argv builders and the secret-bridging logic are fixture-testable; `_deploy_cage` and the readiness waits need a live Lima guest. |
| `secret_store.py` | 410 | Four stores (systemd-creds, Keychain, plaintext ×2). The Keychain `security(1)` interaction-blocked detection and the `sudo -n` System-keychain probe are macOS-only but argv-testable on Linux with a fake runner (PR E2b). |
| `run.py`, `init.py`, `scaffold_cli.py`, `scaffold_brief.py` | 1,460 | Ephemeral-cage flow + scaffold rendering + embedded-asset extraction (§2.1). |
| `services.py`, `backends/container.py` | 975 | Core deploy path; straightforward but load-bearing. |

### Untouched

All of `data/proxy/**`, `data/containers/*.sh`, `data/apple-container/*`,
`scaffolds/**`, `templates/**` (rendered by minijinja, not rewritten),
`tests/e2e/*.sh`, `scripts/update-deps.py`.

---

## 4. Testing strategy

30,468 lines of host-side pytest do not port — it is `monkeypatch`-heavy
(`test_apple_container.py` alone has 217 calls), patching module attributes to
fake subprocess results. Replacement has four layers.

**Layer 1 — golden corpus (Phase 0, before any Rust).**
A Python harness walks `tests/configs/**` plus a generated config matrix and
dumps, per case: rendered quadlets, `proxy-config.yaml`, `dns-allowlist.conf`,
`placeholders.env`, the fingerprint hash, `_egress_content_hash`, HAR output for
a fixed capture, and **every validation error message**. Committed as fixtures;
Rust reproduces them under `insta` — byte-for-byte for quadlets, env files,
hashes, and error strings, and by parsed-value comparison for YAML (§2.8). This
converts "did I port 2,473 lines of validation correctly?" from judgement into a
diff, and it is useful on `master` whether or not the port proceeds.

**Layer 2 — cross-language contract fixtures (Phase 0).** §2.2. Generated from
Python, asserted by both suites. Non-negotiable.

**Layer 3 — seam traits.** `trait CommandRunner` for podman, systemctl,
limactl, container(1), skopeo, security(1), systemd-creds. Tests inject a
recording fake and assert on argv — strictly better than monkeypatching, since
argv *is* the contract with those tools.

**Layer 4 — e2e shell suite, unchanged.** `tests/e2e/phase1..8` + `phase_apple`
drive the real CLI against real podman and are the conformance oracle. Run them
against Python and Rust builds side by side throughout the transition;
`.github/workflows/e2e.yml` needs only a build-step swap. Critically, **these
also exercise the unmodified Python egress**, so they directly validate that the
Rust host still drives it correctly — which is the whole bet of this scope.

### 4.1 What CI covers today, and why macOS is less scary than it looks

Every workflow — `test.yml`, `e2e.yml`, `supervisor.yml` — runs on
`ubuntu-latest` / `ubuntu-24.04`. **There is no macOS runner anywhere in CI.**

`test_apple_container.py` nonetheless exercises the Mac backend on Linux, by
patching `platform.system()` to return `"Darwin"` (line 44) and asserting on
generated argv, units, and plists. `phase_apple.sh` is never run in CI at all —
it is a manual, run-it-on-a-Mac gate.

Two consequences for this port:

1. **The fixture-testable majority of `apple_container.py` and `vm.py` can be
   ported and verified on Linux CI**, exactly as the Python is today. That is
   roughly two thirds of `apple_container.py`.
2. **The port does not regress Mac coverage, because there is none to regress.**
   The hardware-gated remainder stays a manual pre-release gate on Luca's Mac,
   the same arrangement as now.

If automated Mac coverage is wanted, it is a separate decision with its own
cost: GitHub-hosted macOS runners are VMs on Apple Silicon, and both Apple's
`container` CLI and Lima's `vz` driver want the Virtualization framework, which
is not reliably available nested. A self-hosted Mac runner is the realistic
option. **Do not put this on the port's critical path** — it is an improvement
over the status quo, not a prerequisite for matching it.

---

## 5. Phasing

**Phase 0 — Foundations and contracts (2 weeks)**
Cargo workspace (`agentcage-core`, `agentcage-cli`, `agentcage-assets`). CI
matrix. Build the Layer-1 golden corpus and the Layer-2 contract fixtures from
the Python implementation and freeze them. Move `VERSION` to the repo root and
wire both build systems to it. Settle the YAML crate: `serde_yaml` is deprecated
(last release 2024-03); evaluate `serde_norway` (maintained fork) or
`serde_yaml_ng`; `saphyr` only reached 0.1.0 on 2026-09-19 and is likely too
fresh. Hard requirements: **order-preserving mappings** — `save_raw_config` uses
`sort_keys=False` and cage.yaml key order is user-visible after `cage edit` —
and **quoting of YAML-1.1-ambiguous scalars on output** (§2.8).

**Phase 1 — Pure core (3–4 weeks)**
`agentcage-core`: config parse + validate (including the reimplemented
`validate_relay_entry`), domain matching + `encoded_private_ip`, placeholder
generation, fingerprint, audit parse/filter/summary, HAR builder, volume-mount
parsing, quadlet rendering. Asset embedding + extraction + `_egress_content_hash`.
No I/O beyond asset extraction, no subprocess, no CLI.
**Exit: 100% byte-identical on the golden corpus and all contract fixtures.**

**Phase 2 — CLI + container backend, Linux (5–7 weeks)**
`clap` command tree, `CommandRunner` seam, podman/systemd/quadlet lifecycle,
secret store (systemd-creds + plaintext), doctor, audit/har/logs/exec/shell,
backup/restore, `run` + scaffolds, `domain` and `grants` groups.
**Exit: e2e phases 1–6 green, driving the unmodified Python egress image.**
This is a shippable Linux release.

**Phase 3 — Remaining backends (4–5 weeks)**
`vm` (Lima) and `apple-container`, each split into a Linux-CI-verified
generation half and a hardware-gated execution half (§4.1). The generation half
can start as soon as Phase 1 lands and run in parallel with Phase 2 — worth
doing, because it front-loads the parts that need scarce hardware to *discover*
problems, even if the fixes wait.

**Phase 4 — Cutover (2–3 weeks)**
Rewrite `install.sh`. Set up macOS signing + notarization (§2.6). Publish
release binaries for four targets, a Homebrew tap, and an AUR package. Reduce
`pyproject.toml` to dev/test-only and add the §2.4 CI invariant guards. Final
PyPI shim release with a migration notice. Docs pass over the 39 files in
`docs/`.

**Rough total: 4–5 months solo.** Phases 0–2 are high-confidence. Phase 3's
hardware-gated remainder and Phase 4's macOS release engineering carry the
variance, and neither blocks a Linux-only release.

---

## 6. Risks

| Risk | Mitigation |
| :-- | :-- |
| **Cross-language contract drift** (§2.2) — `valid_domain` or `_is_never_grant` diverging silently lets a domain through on one side and not the other | Layer-2 fixtures generated from Python, asserted by both suites, checked in CI. Highest priority in Phase 0. |
| **`_egress_content_hash` mismatch** silently forces rebuilds and tag drift on macOS | Golden-corpus case; port `_egress_copy_sources` verbatim including continuation handling. |
| **Asset extraction bugs** — wrong modes or missing files break the podman build context in ways that surface as opaque build errors | e2e phases 1–6 catch this immediately; they build the real egress image. |
| **Validation error-message drift** changes UX and breaks the suite | Corpus captures every message; treat a diff as a build failure. |
| **YAML 1.1/1.2 divergence** (§2.8) — a user's `tls: no` changes meaning, or Rust writes an unquoted `no` that the proxy reads as `False` | B2 ambiguity fixture; emitter quotes 1.1-ambiguous scalars; corpus compares YAML by value. |
| **Rust cannot read Python-written state** (§2.7) — no schema version to branch on; a bad reader bricks every existing cage at F2 | A7 fixtures from a real Python deployment + backup; F2 acceptance is an in-place upgrade of a live cage. |
| **macOS release engineering** — signing, notarization, four build targets | §2.6. Front-load a signed pre-release spike in Phase 0 so the Apple Developer ID and `notarytool` flow are proven before they are on the critical path. |
| **apple-container execution paths untestable in CI** | Unchanged from today (§4.1) — `phase_apple.sh` is already a manual Mac gate. Port the fixture-testable two thirds on Linux CI; keep the manual gate. A self-hosted Mac runner is an upgrade, not a prerequisite. |
| **Python creeps back onto the host** after the invariant is established | §2.4 CI guards: no `python3` in Rust code paths, no non-stdlib imports in `data/proxy/**` beyond pyyaml/cryptography, no Python installed by any Containerfile but the egress one. |
| **Losing the rationale comments** — this codebase's comments are unusually good and load-bearing | Port comments with the code. Where one explains a Python-specific workaround, rewrite rather than delete: the reason usually outlives the language. |
| **Bilingual repo friction** — contributors now need both toolchains | Document in `CONTRIBUTING.md`; keep the pytest job fast so proxy work doesn't require Rust. |

---

## 7. Immediate next steps

1. Build the Layer-1 golden corpus harness (Python, lands on `master`, useful
   regardless of whether the port proceeds).
2. Build the Layer-2 cross-language contract fixtures — start with
   `relays/_validate.py`, since that is the one place the two sides share
   literal code today.
3. Move `VERSION` to the repo root; wire `pyproject.toml` to read it.
4. Settle the YAML crate with a round-trip test over every `tests/configs/**`
   file, asserting key-order preservation and quoting of `yes`/`no`/`on`/`off`/
   octal-looking scalars on output.
5. Stand up the Cargo workspace + asset embedding, and prove
   `_egress_content_hash` parity as the first Rust test that matters.
6. Spike macOS signing + notarization (§2.6) on a throwaway binary. Apple
   Developer enrollment has lead time; find out now, not in the final week.

---

## 8. PR breakdown

**Delivery model (decided 2026-09-19): one linear stack, merged at the end.**
Every PR branches off the one below it and targets it as its base, so each
GitHub diff shows only its own work. Nothing merges to `master` until the port
is complete. This replaces an earlier draft of this section which said `master`
stays shippable at every merge.

The reason is practical rather than stylistic: later PRs are *verified against*
earlier ones. Track C is checked against the golden corpus (A3) and the contract
fixtures (A4); if every branch sat independently off `master`, a Track C PR
could not see the thing it has to match. The stack is what makes each PR's
acceptance check runnable at the time it is opened.

Two rules still hold for every PR below:

1. **The stack stays green at every level.** The Python CLI is in production
   use, and the merge at the end must be a non-event. A red PR blocks everything
   above it, so a break gets fixed where it was introduced rather than papered
   over higher up.
2. **Every PR has a mechanical acceptance check** — a fixture diff, an argv
   assertion, or an e2e phase — not "looks right on review".

Track A is Python work that is useful whether or not the port proceeds. Tracks
B–D are Rust; the binary is built and tested in CI from B1 onward but ships to
nobody until F.

**Operational notes.** Rebase the chain upward when a lower branch changes, then
`push --force-with-lease`. Never rebase a branch while an agent is still working
in its worktree. Because the stack is long-lived, expect to re-run the full suite
at the stack top whenever the order changes — that is the only place the
combined state is actually exercised.

### Track A — Preparation (Python only, no Rust in the repo yet)

| # | PR | Acceptance check | Size |
| :-- | :-- | :-- | :-- |
| A1 | Root `VERSION` file; `pyproject.toml` reads it; CI fails on disagreement | Existing suite green; `agentcage --version` unchanged | XS |
| A2 | Parameterize the e2e harness on `${AGENTCAGE:-agentcage}` (140 call sites across `phase*.sh` + `lib.sh`) | `bash tests/e2e/run.sh container` green with the default; green again with `AGENTCAGE=$(which agentcage)` | S |
| A3 | Golden-corpus harness: walk `tests/configs/**` + a generated matrix, dump quadlets, `proxy-config.yaml`, `dns-allowlist.conf`, `placeholders.env`, fingerprints, HAR, and every validation error string | Harness is deterministic (run twice, empty diff); a deliberate one-char mutation in `config.py` fails the corpus check | M |
| A4 | Cross-language contract fixtures for `relays/_validate.validate_relay_entry`, `valid_domain`, `encoded_private_ip`, `_is_never_grant` (§2.2) | pytest asserts Python matches each fixture; mutation of either implementation fails | M |
| A5 | Extract `_egress_copy_sources` / `_egress_build_inputs` / `_egress_content_hash` into a standalone module + fixture | Hash for the current tree is pinned in a fixture; `test_apple_container.py` still green | S |
| A6 | Split the boundary-straddling test files into host-side and proxy-side halves. Find them by import scan (`tests/` holds 86 files; the 63/20 split above is approximate), not by the two named in §2.4 | Same assertion count, both halves green; the scan is committed as the §2.4 guard's seed | S |
| A7 | State-compatibility fixtures (§2.7): a Python-deployed cage's `~/.config` and `~/.local/share` trees plus a `cage backup` tarball, committed with secrets replaced by fixed test values | pytest loads every file through the Python readers unchanged; fixture is regenerated by a script, not by hand | S |

A3, A4, and A7 are the load-bearing ones. Everything in Tracks C, D, and F is
verified against what they produce, so they must be right before Rust starts.

### Track B — Rust foundations

| # | PR | Acceptance check | Deps |
| :-- | :-- | :-- | :-- |
| B1 | Cargo workspace skeleton (`agentcage-core`, `agentcage-assets`, `agentcage-cli`) + CI job (build, clippy, fmt) | CI green; no behavior change anywhere | A1 |
| B2 | YAML crate decision + round-trip test over every `tests/configs/**` file + the 1.1-ambiguity fixture (§2.8) | Key order preserved on 100% of configs; **the 14 measured hazard scalars survive a Rust-emit → PyYAML-read round trip as strings**; written as an ADR in the PR body | B1 |
| B3 | `agentcage-assets`: embed `data/`, `templates/`, `scaffolds/`; extract to a cache dir; reproduce `_egress_content_hash` | Matches the A5 fixture exactly; extracted tree byte- and mode-identical to the source | A5, B1 |

B3 is deliberately early: it is the highest-risk piece of new (not ported) work,
and it fails loudly and cheaply.

### Track C — Core logic (one PR per module, each verified against the A3 corpus)

| # | PR | Acceptance check |
| :-- | :-- | :-- |
| C1 | Config types + parse, no validation | Parses every `tests/configs/**` and every rendered scaffold `cage.yaml.j2` |
| C2 | Validation: domains, ports, secrets, placeholders | Error strings byte-match the corpus subset |
| C3 | Validation: relays (the §2.2 reimplementation), agents, capture, inspectors | Matches both the corpus **and** the A4 contract fixture |
| C4 | `fingerprint` + `stable_json` | Byte-identical hashes across the corpus |
| C5 | `audit` parse / filter / summary | Corpus diff |
| C6 | `har` builder | Corpus diff on a fixed capture |
| C7 | `volume_mounts` (incl. tmpfs mask + copyup) | Corpus diff |
| C8 | `quadlets` + minijinja over the existing `.j2` templates, with the `systemd_exec` filter and `placeholder` global registered | Rendered quadlets byte-identical for every corpus case |

These are independent of each other and can land in any order, or in parallel.

### Track D — CLI and I/O

| # | PR | Acceptance check |
| :-- | :-- | :-- |
| D1 | `CommandRunner` trait + podman wrapper + recording fake | argv assertions against `test_podman.py`'s expectations |
| D2 | `state` (atomic writes, deployment dirs) + `systemd` | Concurrency test on `_atomic_write_text`; argv assertions; reads every file in the A7 fixture |
| D3 | `secret_resolver` + `secret_store` (systemd-creds, plaintext) | argv assertions; reads A7's `creds/` and `secret_keys.json`; round-trip against real `systemd-creds` behind the same availability probe e2e phase 3 uses (`phase3_secrets.sh:378`) |
| D4 | `output`, `terminal`, `_timing` | Golden help/banner text; termios restore test under a pty |
| D5 | clap skeleton: `--version`, `--help`, banner, `AliasGroup` equivalents, hidden back-compat flags, `clap_complete` shell completions (click provides these implicitly via `_AGENTCAGE_COMPLETE`; clap needs generated scripts) | Golden diff of `--help` for every subcommand vs the Python click output; completion scripts for bash/zsh/fish generated and smoke-loaded |
| D6 | `cage create` / `cage update` + `services.build_and_deploy` + container backend | **e2e phase 1** green under `AGENTCAGE=<rust binary>` |
| D7 | `cage list` / `show` / `status` / `start` / `stop` / `restart` / `destroy` / `prune` | e2e phase 1 (full) |
| D8 | `cage logs` / `cage audit` | **e2e phase 2** |
| D9 | `secret` group + live-apply path | **e2e phase 3** |
| D10 | `domain` group + `grants` group + DNS quadlet reload | **e2e phase 4** |
| D11 | `cage backup` / `cage restore` | **e2e phase 5**; restores the A7 Python-made tarball |
| D12 | `cage exec` / `cage shell` / `cage verify` | **e2e phase 6** |
| D13 | `cage har` | Corpus diff + manual DevTools load |
| D14 | `init` + `scaffold` + `run` (ephemeral flow) | Scaffold render diff vs Python; **e2e phase 8** (the openclaw scaffold regression canary) |
| D15 | `doctor` (minus `check_python_version`) | Golden output on the CI runner |
| D16 | `legacy_watcher` cleanup path | Unit test against a synthesized legacy cage (`test_v021_legacy_cage.py` port) |

D6–D12 map almost 1:1 onto the existing e2e phases, which is what makes them
individually verifiable. Each one ends with a CI job that runs its phase against
the Rust binary while the Python binary keeps running the full suite.

Once D6–D12 are in, add a **dual-run CI job**: run each phase against both
binaries and diff `audit.jsonl`, `capture.jsonl`, the generated quadlets, and
`proxy-config.yaml`. That is the strongest single signal that the Rust host
still drives the unmodified Python egress correctly.

### Track E — Backends

Split by what each PR can be *verified* against, not by backend. E1–E3 need no
Mac and can run in parallel with Track D as soon as Track C lands.

| # | PR | Acceptance check | Hardware |
| :-- | :-- | :-- | :-- |
| E1 | `vm` backend, generation half: `generate_units`, `push_config_files`, Lima YAML rendering, argv builders, secret-bridging logic | Corpus diff + argv assertions on Linux CI (mirrors `test_vm_backend.py` / `test_lima_*.py`) | none |
| E2 | `apple-container`, generation half A: image naming, `_egress_content_hash` wiring, `_render_egress_config`, `_user_volume_argv`, `_tmpfs_targets`, `_tmpfs_copyup_seeds` | Fixture diff; mirrors `test_apple_container*.py`, which runs on Linux by patching `platform.system()` | none |
| E2b | `KeychainStore`: `security(1)` argv, `_security_interaction_blocked` detection, the `sudo -n` System-keychain probe | argv assertions with the recording fake; stderr fixtures for the interaction-blocked case | none |
| E3 | `apple-container`, generation half B: `generate_units`, launchd plist rendering, `exec_argv` / `logs_argv` / `audit_argv` | Golden unit + plist diff vs Python | none |
| E4 | `vm` backend, execution half: `_deploy_cage`, readiness waits, in-guest build | **e2e phase 7** | Lima host |
| E5 | `apple-container`, execution half: `start`/`stop`, `_stage_secrets`, mask mountpoint record/cleanup, `_wait_supervisor_ready` | **`phase_apple.sh`**, manual — the same gate this code has today | Apple Silicon, macOS 26+ |

### Track F — Cutover

| # | PR | Acceptance check |
| :-- | :-- | :-- |
| F1 | macOS signing + notarization in the release workflow; four-target build matrix | A signed, notarized pre-release binary opens on a clean Mac with no Gatekeeper prompt |
| F2 | Flip the default: Rust binary becomes `agentcage`; Python CLI entry point removed | Full e2e suite green on the Rust binary; `phase_apple.sh` green manually; **a cage deployed by the last Python release is upgraded in place and `cage update` reports no changes** |
| F3 | `install.sh` rewrite; release binaries; Homebrew tap; AUR | Fresh-VM install test on Arch, Ubuntu, and macOS |
| F4 | Reduce `pyproject.toml` to dev/test-only; add the §2.4 CI invariant guards; delete `Containerfile.helper`; final PyPI shim release | Proxy pytest green without installing the package; guards fail on a deliberate violation |
| F5 | Docs pass over `docs/**`, `README.md`, `CONTRIBUTING.md` | Link check; manual read |

F1 is first in this track and should be attempted during Phase 0 as a throwaway
spike — Apple Developer enrollment has lead time, and discovering that in the
final week would be avoidable self-harm.

### Sequencing notes

- **Critical path:** A1 → A3/A4/A7 → B1/B2/B3 → C2/C3/C8 → D5 → D6 → D7–D12 → F2.
- **Parallelizable:** all of Track C after C1; D13–D16; E1–E3 (no hardware) can
  run alongside Track D; E4 and E5 are independent of each other.
- **First externally visible change is F2.** Everything before it is additive,
  so the effort can be abandoned at any point losing only the Rust tree.
- **Natural stopping point:** after D12 + E4, every Linux backend is complete
  and shippable as an opt-in `agentcage-rs`. E5 is the only PR that cannot be
  verified without a Mac in hand, and it is the last one.
- **Roughly 37 PRs.** Track A ~1 week, B ~1 week, C ~3 weeks, D ~7 weeks,
  E ~4 weeks, F ~2–3 weeks.
