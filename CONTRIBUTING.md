# Contributing to agentcage

## Development Setup

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
uv sync --dev          # the proxy suite, the fixture generators, the oracle
cargo build --workspace  # the CLI
```

The Python package here is **dev/test-only**. It installs no `agentcage`
command and is not published — `pip install agentcage` is not how anyone
gets the CLI any more. What it is for:

* the proxy test suite, which imports `agentcage.data.proxy.X` and bare
  `X`, the two spellings the egress image itself uses;
* the fixture generators under `scripts/`, which run the real Python to
  produce the recordings the Rust is asserted against;
* `tests/e2e/python-cli`, which runs the end-to-end suite against the
  Python so the two implementations can be compared phase by phase.

Run the Python CLI with `python -m agentcage`, or through that wrapper.

## Running Tests

```bash
uv run pytest                                    # Python
cargo test --workspace --all-targets             # Rust
python3 scripts/check-invariants.py              # Python stays out of the binary
```

## The Rust tree

**The host CLI is Rust.** The egress proxy under
`src/agentcage/data/proxy/` stays Python permanently. The two halves talk
only through files on a bind mount, which is what makes the split
possible.

You do not need Rust to work on the proxy, and you do not need Python to
work on the CLI. They have separate CI jobs and neither can fail the
other.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The workspace manifest is the root `Cargo.toml`; the crates live under
`rust/`:

| Crate | Rule |
| :-- | :-- |
| `agentcage-core` | pure logic. No subprocess, no I/O, no CLI. |
| `agentcage-assets` | embeds and extracts `data/`, `templates/`, `scaffolds/`. |
| `agentcage-cli` | the `agentcage` binary: argument parsing, subprocess, terminal, exit codes. |

Each crate's `//!` docs say what it will hold and which PR brings it.
The plan is `RUST-PORT-PLAN.md` on the `rust-port` branch.

The version lives in the root `VERSION` file and nowhere else. Cargo
cannot read it from there, so `[workspace.package] version` carries a
copy and `scripts/check-version.sh` fails when the two disagree. Bump
`VERSION`, then the copy.

## Making Changes

1. Fork the repository and create a feature branch.
2. Make your changes and add tests where appropriate.
3. Run `uv run pytest` and ensure all tests pass.
4. Submit a pull request with a clear description of what changed and why.

## Updating Dependencies

All dependencies are pinned (lock files, image digests, binary checksums). To check for updates:

```bash
./scripts/update-deps.py              # check all, report only
./scripts/update-deps.py --update     # check all, apply updates
./scripts/update-deps.py containers   # check a single category
```

Categories: `python`, `containers`, `node`, `pip`.

Requires `skopeo` for container image checks (`sudo pacman -S skopeo` on Arch).

## Changing the Egress Image

The shared `agentcage-egress` image is tagged by content
(`localhost/agentcage-egress:<version>-<12 hex>`), so an in-release fix to
`Containerfile.egress`, `supervisor-egress.sh`, or the `data/proxy/` tree
actually reaches hosts that already hold the previous tag (#312). The
digest is computed by `src/agentcage/egress_hash.py` and pinned, together
with the full list of files that feed it, in
`tests/fixtures/egress_hash.json`.

If you deliberately change what goes into the egress image, `uv run pytest
tests/test_egress_hash.py` will fail. Re-bless the fixture in the same
commit:

```bash
./scripts/bless-egress-hash.py          # rewrite the fixture
./scripts/bless-egress-hash.py --check  # exit 1 if it is stale
```

Re-bless deliberately: the digest is a cross-language contract that the
Rust port must reproduce byte-exactly, and the fixture's input list is
there so a review sees exactly which files entered or left the image.

## Code Style

- Follow existing patterns in the codebase.
- Keep changes focused — one concern per PR.

## Security Issues

Please **do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
