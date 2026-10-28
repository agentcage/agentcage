# README install instructions pin an old version and describe the old installer

| | |
| :--- | :--- |
| **Issue** | [#562](https://github.com/agentcage/agentcage/issues/562) |
| **Status** | Fixed — closed by #583 |
| **Priority** | P0 |
| **Area** | Documentation / release |
| **Affected** | v0.53.1 |
| **Fix** | Documentation update and a release checklist |

## Progress (2026-10-28)

Closed by [#583](https://github.com/agentcage/agentcage/pull/583): pins and the
installer description are corrected, and `cargo xtask check-docs` fails on a
stale `--tag` or `AGENTCAGE_VERSION=` pin. No release checklist was added.

## Summary

The root README and the install guide tell users to install the host with:

```console
cargo install --locked --git https://github.com/agentcage/agentcage --tag v0.50.0 agentcage-cli
```

The repository is at v0.53.1. The README also says the one-line installer
“builds agentcage from source with `cargo`”, while `install.sh` now downloads
the release’s prebuilt binary by default and uses `--build` for source builds.

## Evidence

- `README.md` — install snippet with `v0.50.0` and source-build description.
- `docs/get-started/install.md` — the same pinned tag in the cargo-install
  example.
- `install.sh` and the v0.53 changelog — prebuilt-by-default behaviour.
- `VERSION` / `Cargo.toml` — 0.53.1.

## Expected vs actual

**Expected:** the documented first command installs the current release with
the current supported method.

**Actual:** it installs a release that predates the Rust-only cutover and
missing features/fixes; the surrounding text also describes the wrong build
path.

## Impact

- New users start on an old binary, then hit bugs fixed several releases ago.
- Users without a Rust toolchain may think the standard installer requires
  one.
- The project’s own version references are inconsistent, which weakens trust.

## Proposed fix

- Update both snippets to the current release tag, or use a `<version>`
  placeholder consistently and link to the release page.
- Rewrite the installer paragraph to describe the prebuilt default and
  `--build` opt-in.
- Add “update version references” to the release checklist and, where
  possible, generate them from `VERSION` during the release.

## Acceptance criteria

- [x] No live documentation pins a release older than the current `VERSION`.
- [x] The README and install guide describe the same installer behaviour as
      `install.sh`.
- [ ] The release checklist includes README/install-guide version updates.
- [x] A docs test checks the pinned tag against `VERSION`.

## Tests

- Docs check: parse `cargo install ... --tag vX.Y.Z` and compare with
  `VERSION`.
- Manual fresh-install check on each release.

## Related

- [#578](https://github.com/agentcage/agentcage/issues/578)
- [#580](https://github.com/agentcage/agentcage/issues/580)
