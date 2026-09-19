# agentcage: Python → Rust port plan (host CLI + tooling only)

Against `461c99b` (v0.40.1).

**Scope decision (2026-09-19):** port the host CLI and tooling to Rust. The
in-egress proxy — mitmproxy, the addon, inspectors, protocol relays, the Policy
API, the traffic watcher, and the custom-inspector extension point — **stays in
Python, unchanged**. It ships as data assets inside the Rust binary and is built
into the egress container image exactly as today.

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

### 2.3 Version lockstep

`importlib.metadata.version("agentcage")` is read in at least 10 host call sites
and determines:

- the egress image tag (`agentcage-egress:<version>`) built by all three
  backends, **and** the `Image=` pin emitted into `egress.container.j2`
- `agentcage_version` rendered into `cage.container.j2`
- `metadata.json` stamps used by `cage list` and backup/restore
- `proxy_cfg["agentcage_version"]` in `save_proxy_config`, which the Policy API
  reports through introspection

With a Rust CLI and a Python proxy package these are two build systems. A single
`VERSION` file at the repo root, read by `build.rs` (into a compile-time
constant) and by `pyproject.toml`/hatchling, keeps them from drifting. A CI
check should fail the build if `Cargo.toml`, `VERSION`, and the Python package
metadata disagree.

### 2.4 The repo stays bilingual

`pyproject.toml` remains, but describes a *proxy-only* package: no
`[project.scripts]` entry point, dependencies drop to `pyyaml` (+ `cryptography`
for the JWT transform). `tests/conftest.py`'s mitmproxy stubbing and the 20
proxy test files stay exactly as they are. `.github/workflows/test.yml` grows a
Rust job beside the pytest job rather than replacing it.

Two test files straddle the boundary and must be **split**, with the
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
| `backends/apple_container.py` | 2,591 | Largest backend, macOS-only, untestable on this Arch VM. Carries `_egress_content_hash` (§2.1). Port last. |
| `backends/vm.py` | 1,297 | Lima orchestration + secret bridging (`_bridge_secrets`, `_resolve_source_secrets`) + the in-guest build-dir push. |
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

**Phase 3 — Remaining backends (3–4 weeks)**
`vm` (Lima), then `apple-container`. Needs Mac hardware; `apple_container.py` is
2.6k lines validated only by `phase_apple.sh` on a real machine. Reasonable to
leave apple-container on the Python CLI longest if hardware access is thin.

**Phase 4 — Cutover (1–2 weeks)**
Rewrite `install.sh`. Publish GitHub release binaries, Homebrew tap, AUR package.
Reduce `pyproject.toml` to the proxy-only package and drop `[project.scripts]`.
Final PyPI release of the Python CLI printing a migration notice. Docs pass over
the 39 files in `docs/` for changed install paths.

**Rough total: 3.5–4.5 months solo.** Phases 0–2 are high-confidence; Phase 3's
apple-container work is the main unknown, and it is bounded.

---

## 6. Risks

| Risk | Mitigation |
| :-- | :-- |
| **Cross-language contract drift** (§2.2) — `valid_domain` or `_is_never_grant` diverging silently lets a domain through on one side and not the other | Layer-2 fixtures generated from Python, asserted by both suites, checked in CI. Highest priority in Phase 0. |
| **`_egress_content_hash` mismatch** silently forces rebuilds and tag drift on macOS | Golden-corpus case; port `_egress_copy_sources` verbatim including continuation handling. |
| **Asset extraction bugs** — wrong modes or missing files break the podman build context in ways that surface as opaque build errors | e2e phases 1–6 catch this immediately; they build the real egress image. |
| **Validation error-message drift** changes UX and breaks the suite | Corpus captures every message; treat a diff as a build failure. |
| **Version desync** between Rust CLI and Python proxy package | Single root `VERSION` + CI consistency check. |
| **apple-container untestable** without a Mac | Port last; gate on `phase_apple.sh`; acceptable to ship Linux-first. |
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
