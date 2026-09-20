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
