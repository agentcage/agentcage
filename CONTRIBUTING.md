# Contributing to agentcage

## Development Setup

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
uv sync --dev            # the egress proxy's test environment
cargo build --workspace  # the CLI
```

`pyproject.toml` is only the proxy's test environment. It is not a
package, installs no `agentcage` command and is not published —
`pip install agentcage` is not how anyone gets the CLI.

## Running Tests

```bash
uv run pytest                                    # the egress proxy
cargo test --workspace --all-targets             # the CLI
python3 scripts/check-invariants.py              # Python stays out of the binary
```

## The Rust tree

**The host CLI is Rust.** The egress proxy under
`src/agentcage/data/proxy/` is Python. The two halves talk
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

Each crate's `//!` docs say what it holds. Many comments cite
[`docs/history/rust-port-plan.md`](docs/history/rust-port-plan.md), the
plan the port from Python followed, for the reasoning behind a decision.

### Golden fixtures

Most Rust tests assert against committed files under `tests/fixtures/`
(the golden corpus, CLI surface, doctor, output, state-compat, contracts,
and so on). They were recorded from the Python CLI before it was removed,
and they are now maintained by hand: a deliberate behaviour change edits
the fixture in the same commit, and the failing assertion prints the
diff to copy from. A fixture that changes for any other reason is a
regression. `tests/fixtures/contracts/` is asserted by both the Rust
suite and the proxy's pytest suite, so a change there is a change to the
host/proxy contract.

The version lives in the root `VERSION` file and nowhere else. Cargo
cannot read it from there, so `[workspace.package] version` carries a
copy and `scripts/check-version.sh` fails when the two disagree. Bump
`VERSION`, then the copy.

## Making Changes

1. Fork the repository and create a feature branch.
2. Make your changes and add tests where appropriate.
3. Run the tests above and ensure they pass.
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
digest is computed by `rust/agentcage-assets/src/egress.rs` and pinned,
together with the full list of files that feed it, in
`tests/fixtures/egress_hash.json`.

If you deliberately change what goes into the egress image, `cargo test
-p agentcage-assets` will fail. Re-bless the fixture in the same commit:

```bash
AGENTCAGE_BLESS=1 cargo test -p agentcage-assets bless_the_egress_hash_fixture -- --ignored
```

Re-bless deliberately: the wire format is frozen so that hosts upgraded
from the Python CLI keep their existing image tags, and the fixture's
input list is there so a review sees exactly which files entered or left
the image.

### The Rust egress (transition)

While the Rust egress (`rust/agentcage-egress`) replaces the Python one,
the host can build either image. `AGENTCAGE_EGRESS_ENGINE=rust` selects
`Containerfile.egress-rust`, which ships the `agentcage-egress` binary and
no Python; unset (or `python`) keeps today's image. The Rust image's tag
is `<version>-rust-<hash>`, the hash covering the binary, so both images
coexist and a cage switches with `cage update`.

The host binary embeds a linux-musl egress for its own architecture
(`rust/agentcage-egress-embed`). Release builds get it from the publish
workflow; locally, build it first and then build `agentcage`, which picks
it up from `target/<arch>-unknown-linux-musl/release/` (or from
`AGENTCAGE_EGRESS_BIN=<path>`):

```bash
rustup target add x86_64-unknown-linux-musl   # needs musl-gcc (musl-tools / musl)
cargo build --release --target x86_64-unknown-linux-musl -p agentcage-egress
cargo build --release --bin agentcage
```

Rebuilding the egress means rebuilding `agentcage` too. Without an
embedded binary everything still builds and the Python engine works;
only `AGENTCAGE_EGRESS_ENGINE=rust` fails, at image-build time, saying how
to fix it. To run the container e2e against the Rust egress:

```bash
AGENTCAGE_EGRESS_ENGINE=rust AGENTCAGE=$PWD/target/release/agentcage \
  bash tests/e2e/run.sh container
```

## Code Style

- Follow existing patterns in the codebase.
- Keep changes focused — one concern per PR.

## Security Issues

Please **do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
