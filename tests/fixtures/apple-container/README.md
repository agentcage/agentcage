# apple-container fixtures

What `backends/apple_container.py` derives from a `cage.yaml`, recorded
by running the real Python.

## Why this directory exists

The golden corpus (`tests/fixtures/golden/`) records the rendered
quadlets for every case in the config matrix — except the
apple-container ones, which carry a `quadlets/NOT-APPLICABLE.txt`
instead. That backend does not go through the quadlet renderer at all:
it builds `container run` argv and a launchd plist inside itself, and
renders three config files onto disk for the egress microVM to
bind-mount. PR C8 flagged that those artifacts were recorded nowhere and
handed the gap to Track E. This is the generation-half-A part of it.
Half B (PR E3) closed the rest: the corpus now records the real
`container run` argv beside that note as `quadlets/<case>.json`, and
the launchd job under `launchd/`.

## Why it does not need a Mac

`scripts/gen-apple-container-fixtures.py` patches `platform.system()` to
`"Darwin"` before importing `agentcage`, which is exactly what
`tests/test_apple_container.py` has done since that backend existed.
There is no macOS runner in CI and there never has been, so this *is*
how this backend has always been tested. The execution half —
`start`/`stop`, `_stage_secrets`, mask-mountpoint record and cleanup —
genuinely needs Apple Silicon and stays behind the manual
`tests/e2e/phase_apple.sh` gate.

## Files

| File | What it pins |
| :-- | :-- |
| `image.json` | `_egress_image_name`, the egress content hash it embeds, and `_build_egress_image_if_missing`'s argv in its four flag shapes |
| `state-paths.json` | the per-cage state layout, and the fact that its root ignores `XDG_CONFIG_HOME` |
| `volumes.json` | `_user_volume_argv`, `_tmpfs_targets`, `_mask_mount_targets` and `_tmpfs_copyup_seeds` over a curated input table plus every apple cage in the golden corpus |
| `egress-config.json` + `egress-config/<case>/` | `_render_egress_config`'s three files, with the `cage.yaml` that produced them |

`rust/agentcage-cli/tests/golden_apple_container.rs` replays all of it.

## Tokens

Three placeholders keep the recording machine-independent:

* `{{ROOT}}` — the throwaway sandbox the generator built. A consumer
  materializes `volumes.json`'s `tree` somewhere of its own and
  substitutes its own root.
* `{{VERSION}}` — the package version. Substituted with
  `agentcage_core::VERSION` on the Rust side; `scripts/check-version.sh`
  is what holds the two equal.
* `{{CONTEXT}}` — the `container build` context. The Python's is the
  installed package's own `data/` directory; a single Rust binary has no
  such directory and materializes the embedded tree into a cache dir
  instead (RUST-PORT-PLAN.md §2.1). The argv *shape* is the contract,
  the path is not.

The egress content hash is deliberately **not** tokenized. It is a
frozen cross-language contract (`src/agentcage/egress_hash.py`, pinned
by `tests/fixtures/egress_hash.json`), and a diff in it is the point: a
Rust side that computes a different digest makes every Mac rebuild its
egress image once on upgrade and then drift from the Python-computed tag
forever.

## Adding a case

Edit `_volume_cases()` or `_egress_config_extra_cases()` in the
generator — inputs are curated, **expectations are always computed**. A
case cannot be added with a wrong expectation, and a behaviour change
shows up as a fixture diff in review rather than as silent drift between
the two implementations.

## Re-blessing

```
uv run python scripts/gen-apple-container-fixtures.py
```

`--check` fails if anything is stale, which is what CI runs
(`.github/workflows/rust.yml`). Review the diff before committing: this
backend has no CI on real hardware, so the fixture is the only thing
watching it.

---

# apple-container argv fixture

`argv.json` is **generated**. Do not hand-edit it.

```sh
uv run python scripts/gen-apple-argv-fixture.py          # write
uv run python scripts/gen-apple-argv-fixture.py --check  # fail if stale
```

## What it is

38 calls into the real `AppleContainerBackend.exec_argv`, `logs_argv`
and `audit_argv`, with the argv each one returned — or, for the two
refusal paths, the `BackendUnsupported` message it raised.

These three methods are what `cage exec` / `cage shell`, `cage logs` and
`cage audit` dispatch through on macOS, and they are the part of that
backend nothing else records: the golden corpus captures what a
`cage.yaml` turns into (units, plist, proxy-config, warnings), and this
captures what a *command invocation* turns into.

## Why it can be generated on Linux

`tests/test_apple_container.py` patches `platform.system()` to `"Darwin"`
(line 44) and asserts on generated argv, units and plists. There is no
macOS runner in CI and there never has been — that patch is how this
backend has always been tested. This generator does the same thing and
writes the answers down.

None of the three methods actually branches on the platform; the patch
is there so the recording is honest about where the code runs, not to
make it work.

## The three host facts, pinned

| Fact | Pinned to | Why |
| :-- | :-- | :-- |
| `apple_container.cli.container_binary()` | `/usr/local/bin/container`, or `None` | It is a `shutil.which`, so on a Linux runner it answers `None` for every case and the interesting argv would never be produced. `None` is kept as its own case. |
| `services.current_placeholders(name)` | declared per case | The real function reads the *stored* cage.yaml at call time — that is the point, so a secret declared after the cage started works in a new session without a restart — and it is already ported and tested on its own (PR D9/D12). Declaring the pairs keeps this fixture about argv, not about state layout. |
| `HOME` | a throwaway directory, scrubbed to `{{HOME}}` | `audit_argv` resolves a real path. |

`XDG_CONFIG_HOME` is set too, and **deliberately somewhere other than
`$HOME/.config`**. The apple state root is
`Path(os.path.expanduser("~/.config/agentcage/apple-container"))` — an
`expanduser` with no XDG lookup anywhere near it — so the recorded audit
path comes out under `{{HOME}}/.config` regardless. That is a testing
hazard as much as a portability wart (an XDG sandbox does not redirect
this root), and the fixture says so by construction rather than in a
comment.

## `audit_argv` is the odd one

There is **no host-side `audit.jsonl` for a `container` or `vm` cage**.
The egress addon writes its audit trail to stderr and the host reads it
back out of `journalctl`; only apple-container bind-mounts the file out
of its microVM. So this is agentcage's only file-reading audit path, and
nothing else in the port covers it.

Two things follow, and both are recorded:

* `since` is **ignored**. A JSONL file has no journalctl-style time
  index and `tail` cannot seek by time, so `cage audit --since` is
  applied after parsing, as `AuditFilter.since`.
* `follow` changes the whole shape rather than adding a flag:
  `tail -n 0 -F` — capital F, so a rotated or replaced file is reopened
  — against a `tail -n 10000` over-read, because not every line in the
  file is an audit record.

## Comparison

Byte-for-byte, element by element. `rust/agentcage-cli/tests/apple_argv.rs`
replays every case; it lives in that crate rather than in
`agentcage-core` because the audit path is derived through
`agentcage_state::Paths::apple_audit_file` and compared against the
recording, which needs both crates.

## No real secrets

The placeholders are decoy tokens in the shape `fill_placeholders`
generates, and the relay/agent credential names are all `FAKE_*`. Keep
it that way: a placeholder is what the cage's environment actually gets,
and the value never appears on a command line at all.
