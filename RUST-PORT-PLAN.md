# agentcage: Python → Rust port plan (host CLI + tooling only)

Against `461c99b` (v0.40.1).

**Scope decision (2026-09-19):** port the host CLI and tooling to Rust **on
every platform — Linux and macOS alike**. The in-egress proxy — mitmproxy, the
addon, inspectors, protocol relays, the Policy API, the traffic watcher, and the
custom-inspector extension point — **stays in Python, unchanged**.

The target invariant: **Python exists only inside the egress container image.**
Not on the host, not in the Lima guest, not as an installable package. It ships
as data embedded in the Rust binary and baked into the egress image at build
time.

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
- Fail the build if any Containerfile other than `Containerfile.egress` installs
  Python.

Two test files straddle the language boundary and must be **split**, with the
cross-language half moving to the §2.2 fixture:

- `test_addon_reload_inspector_config.py` — imports `agentcage.data.proxy.addon` *and* host config
- `test_policy_api_ssrf_guard.py` — imports `agentcage.cli._is_never_grant` *and* `policy_api`

Also check `test_policy_api_config.py` (reaches into `state._PROXY_KEYS`),
`test_policy_api_ttl.py` and `test_dns_live_reload.py` (host-side, but named for
proxy features).

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

---

## 3. Module-by-module disposition

### Ports cleanly

| Python | LOC | Rust approach |
| :-- | --: | :-- |
| `config.py` | 2,473 | `serde` structs + hand-written validator. ~90% is validation and error strings asserted verbatim by `test_config.py`. Must now also reimplement `validate_relay_entry` (§2.2). |
| `quadlets.py` + `templates/*.j2` | 1,177 | `minijinja` 2.24 is Jinja2-compatible; templates should need no edits. Preserve `SandboxedEnvironment` semantics. |
| `state.py` | 580 | Port `_atomic_write_text`'s O_EXCL + PID-suffix + single-retry logic line for line — the in-container addon writes the same files from a different PID namespace, and the comment explains exactly why each branch exists. |
| `audit.py`, `har.py`, `fingerprint.py` | 685 | Pure functions. `fingerprint.stable_json` must be byte-identical or every `cage update` no-op detection breaks. |
| `volume_mounts.py`, `registry.py`, `secret_resolver.py` | 693 | Mechanical. |
| `podman.py`, `systemd.py`, `lima/*`, `apple_container/cli.py` | 1,073 | `std::process::Command` behind traits (§4). |
| `output.py`, `terminal.py`, `_timing.py` | 493 | `terminal.py`'s raw-mode / Kitty-protocol / bracketed-paste restoration is fiddly; `nix` covers the termios work. |
| `doctor.py`, `legacy_watcher.py` | 719 | Mechanical. |

### Needs care

| Python | LOC | Why |
| :-- | --: | :-- |
| `cli.py` | 5,632 | `clap` 4.6 vs click. `AliasGroup` (`ls`→`list`, `rm`→`destroy`, `ps`→`list`, `reload`→`restart`, `config`→`edit`, …), `_BannerGroup` help override, hidden back-compat options (`--lines`, `--json`, `--no-follow`), and `ignore_unknown_options` passthrough for `run`/`exec`. Split one module per command group — 5.6k lines in one file is already this codebase's worst seam. |
| `backends/apple_container.py` | 2,591 | Largest backend, but **most of it is fixture-testable on Linux** (§4): image naming + `_egress_content_hash`, `generate_units`, launchd plist rendering, `_user_volume_argv` / `_tmpfs_targets` / `_tmpfs_copyup_seeds`, `exec_argv` / `logs_argv` / `audit_argv`. Only `start`/`stop`/`_stage_secrets`/`_cleanup_mask_mountpoints` need real hardware. |
| `backends/vm.py` | 1,297 | Same split: `generate_units`, `push_config_files`, argv builders and the secret-bridging logic are fixture-testable; `_deploy_cage` and the readiness waits need a live Lima guest. |
| `secret_store.py` | 410 | Four stores (systemd-creds, Keychain, plaintext ×2). The Keychain `security(1)` interaction-blocked detection is macOS-only and fiddly. |
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
Rust reproduces them byte-for-byte under `insta`. This converts "did I port 2,473
lines of validation correctly?" from judgement into a diff, and it is useful on
`master` whether or not the port proceeds.

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
fresh. Hard requirement: **order-preserving mappings** — `save_raw_config` uses
`sort_keys=False` and cage.yaml key order is user-visible after `cage edit`.

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
   file, asserting key-order preservation.
5. Stand up the Cargo workspace + asset embedding, and prove
   `_egress_content_hash` parity as the first Rust test that matters.
6. Spike macOS signing + notarization (§2.6) on a throwaway binary. Apple
   Developer enrollment has lead time; find out now, not in the final week.

---

## 8. PR breakdown

Two rules hold for every PR below:

1. **`master` stays shippable at every merge.** The Python CLI is in production
   use; nothing here breaks it until the final cutover.
2. **Every PR has a mechanical acceptance check** — a fixture diff, an argv
   assertion, or an e2e phase — not "looks right on review".

Track A lands on `master` as Python work that is useful whether or not the port
proceeds. Tracks B–D are Rust; the binary is built and tested in CI from A6
onward but ships to nobody until E.

### Track A — Preparation (Python only, no Rust in the repo yet)

| # | PR | Acceptance check | Size |
| :-- | :-- | :-- | :-- |
| A1 | Root `VERSION` file; `pyproject.toml` reads it; CI fails on disagreement | Existing suite green; `agentcage --version` unchanged | XS |
| A2 | Parameterize the e2e harness on `${AGENTCAGE:-agentcage}` (140 call sites across `phase*.sh` + `lib.sh`) | `bash tests/e2e/run.sh container` green with the default; green again with `AGENTCAGE=$(which agentcage)` | S |
| A3 | Golden-corpus harness: walk `tests/configs/**` + a generated matrix, dump quadlets, `proxy-config.yaml`, `dns-allowlist.conf`, `placeholders.env`, fingerprints, HAR, and every validation error string | Harness is deterministic (run twice, empty diff); a deliberate one-char mutation in `config.py` fails the corpus check | M |
| A4 | Cross-language contract fixtures for `relays/_validate.validate_relay_entry`, `valid_domain`, `encoded_private_ip`, `_is_never_grant` (§2.2) | pytest asserts Python matches each fixture; mutation of either implementation fails | M |
| A5 | Extract `_egress_copy_sources` / `_egress_build_inputs` / `_egress_content_hash` into a standalone module + fixture | Hash for the current tree is pinned in a fixture; `test_apple_container.py` still green | S |
| A6 | Split the two boundary-straddling test files (`test_addon_reload_inspector_config.py`, `test_policy_api_ssrf_guard.py`) into host-side and proxy-side halves | Same assertion count, both halves green | S |

A3 and A4 are the load-bearing ones. Everything in Tracks C and D is verified
against what they produce, so they must be right before Rust starts.

### Track B — Rust foundations

| # | PR | Acceptance check | Deps |
| :-- | :-- | :-- | :-- |
| B1 | Cargo workspace skeleton (`agentcage-core`, `agentcage-assets`, `agentcage-cli`) + CI job (build, clippy, fmt) | CI green; no behavior change anywhere | A1 |
| B2 | YAML crate decision + round-trip test over every `tests/configs/**` file | Key order preserved on 100% of configs; written as an ADR in the PR body | B1 |
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
| C8 | `quadlets` + minijinja over the existing `.j2` templates | Rendered quadlets byte-identical for every corpus case |

These are independent of each other and can land in any order, or in parallel.

### Track D — CLI and I/O

| # | PR | Acceptance check |
| :-- | :-- | :-- |
| D1 | `CommandRunner` trait + podman wrapper + recording fake | argv assertions against `test_podman.py`'s expectations |
| D2 | `state` (atomic writes, deployment dirs) + `systemd` | Concurrency test on `_atomic_write_text`; argv assertions |
| D3 | `secret_resolver` + `secret_store` (systemd-creds, plaintext) | argv assertions; round-trip against a real `systemd-creds` on the CI runner |
| D4 | `output`, `terminal`, `_timing` | Golden help/banner text; termios restore test under a pty |
| D5 | clap skeleton: `--version`, `--help`, banner, `AliasGroup` equivalents, hidden back-compat flags | Golden diff of `--help` for every subcommand vs the Python click output |
| D6 | `cage create` / `cage update` + `services.build_and_deploy` + container backend | **e2e phase 1** green under `AGENTCAGE=<rust binary>` |
| D7 | `cage list` / `show` / `status` / `start` / `stop` / `restart` / `destroy` / `prune` | e2e phase 1 (full) |
| D8 | `cage logs` / `cage audit` | **e2e phase 2** |
| D9 | `secret` group + live-apply path | **e2e phase 3** |
| D10 | `domain` group + `grants` group + DNS quadlet reload | **e2e phase 4** |
| D11 | `cage backup` / `cage restore` | **e2e phase 5** |
| D12 | `cage exec` / `cage shell` / `cage verify` | **e2e phase 6** |
| D13 | `cage har` | Corpus diff + manual DevTools load |
| D14 | `init` + `scaffold` + `run` (ephemeral flow) | Scaffold render diff vs Python; `agentcage run busybox` smoke |
| D15 | `doctor` | Golden output on the CI runner |
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
| E3 | `apple-container`, generation half B: `generate_units`, launchd plist rendering, `exec_argv` / `logs_argv` / `audit_argv` | Golden unit + plist diff vs Python | none |
| E4 | `vm` backend, execution half: `_deploy_cage`, readiness waits, in-guest build | **e2e phase 7** | Lima host |
| E5 | `apple-container`, execution half: `start`/`stop`, `_stage_secrets`, mask mountpoint record/cleanup, `_wait_supervisor_ready` | **`phase_apple.sh`**, manual — the same gate this code has today | Apple Silicon, macOS 26+ |

### Track F — Cutover

| # | PR | Acceptance check |
| :-- | :-- | :-- |
| F1 | macOS signing + notarization in the release workflow; four-target build matrix | A signed, notarized pre-release binary opens on a clean Mac with no Gatekeeper prompt |
| F2 | Flip the default: Rust binary becomes `agentcage`; Python CLI entry point removed | Full e2e suite green on the Rust binary; `phase_apple.sh` green manually |
| F3 | `install.sh` rewrite; release binaries; Homebrew tap; AUR | Fresh-VM install test on Arch, Ubuntu, and macOS |
| F4 | Reduce `pyproject.toml` to dev/test-only; add the §2.4 CI invariant guards; final PyPI shim release | Proxy pytest green without installing the package; guards fail on a deliberate violation |
| F5 | Docs pass over `docs/**`, `README.md`, `CONTRIBUTING.md` | Link check; manual read |

F1 is first in this track and should be attempted during Phase 0 as a throwaway
spike — Apple Developer enrollment has lead time, and discovering that in the
final week would be avoidable self-harm.

### Sequencing notes

- **Critical path:** A1 → A3/A4 → B1/B3 → C2/C3/C8 → D5 → D6 → D7–D12 → F2.
- **Parallelizable:** all of Track C after C1; D13–D16; E1–E3 (no hardware) can
  run alongside Track D; E4 and E5 are independent of each other.
- **First externally visible change is F2.** Everything before it is additive,
  so the effort can be abandoned at any point losing only the Rust tree.
- **Natural stopping point:** after D12 + E4, every Linux backend is complete
  and shippable as an opt-in `agentcage-rs`. E5 is the only PR that cannot be
  verified without a Mac in hand, and it is the last one.
- **Roughly 35 PRs.** Track A ~1 week, B ~1 week, C ~3 weeks, D ~7 weeks,
  E ~4 weeks, F ~2–3 weeks.


- **Critical path:** A1 → A3/A4 → B1/B3 → C2/C3/C8 → D5 → D6 → D7–D12 → E4.
- **Parallelizable:** all of Track C after C1; D13–D16; E1 vs E2/E3.
- **First externally visible change is E4.** Everything before it is additive.
- **Natural stopping points:** after D12 (Linux container backend complete,
  could ship as an opt-in `agentcage-rs`), and after E1 (all Linux backends).
  If apple-container hardware access is thin, E2/E3 can lag indefinitely with
  the Python CLI retained for that backend only.
- **Roughly 30 PRs.** Track A ~1 week, B ~1 week, C ~3 weeks, D ~7 weeks,
  E ~4 weeks.
