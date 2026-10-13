# Contributing to agentcage

agentcage is Rust end to end: the host CLI, the egress proxy that runs in every cage, the custom-inspector SDK and the e2e mock services are all crates in one Cargo workspace. You need a Rust toolchain and nothing else to build and test it.

## Development Setup

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
cargo build --workspace
```

## Running Tests

```bash
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo xtask check-invariants
```

`cargo xtask check-invariants` (`rust/xtask`) checks the repository-wide rules: no Rust code shells out to Python, no shipped Containerfile installs an interpreter, no Python is tracked outside `docs/history/`, and no tracked file names the proxy agentcage used before the Rust egress, except past `CHANGELOG.md` entries and `docs/history/`. CI runs all four commands.

## The Rust tree

The workspace manifest is the root `Cargo.toml`; the crates live under `rust/`:

| Crate | Rule |
| :-- | :-- |
| `agentcage-core` | pure logic: config, fingerprint, audit, HAR, quadlet rendering. No subprocess, no I/O, no CLI. |
| `agentcage-state` | the host's on-disk state: deployment dirs, atomic writes, the grants overlay, systemd unit lifecycle. |
| `agentcage-exec` | the subprocess seam: a `CommandRunner` trait, a recording fake, thin wrappers over the tools agentcage drives. |
| `agentcage-assets` | embeds and extracts `data/`, `templates/`, `scaffolds/`. |
| `agentcage-cli` | the `agentcage` binary: argument parsing, subprocess, terminal, exit codes. |
| `agentcage-egress` | the per-cage egress proxy (`agentcage-egress` binary): TLS interception, inspection, secret injection, audit and capture, the Policy API, the traffic watcher, the protocol relays. Linux-only at runtime; its pure modules build and test everywhere. |
| `agentcage-egress-embed` | carries the linux-musl `agentcage-egress` binary inside the host binary. |
| `agentcage-inspector-sdk` | the guest side of custom inspectors: Rust types and a macro over the WIT world `agentcage:inspector@1.1.0`, compiled to `wasm32-wasip2`. Examples are under `examples/inspectors/`. |
| `agentcage-e2e-mock` | the mock HTTP services and probes the e2e harness runs next to a cage. |
| `xtask` | repository tasks: `check-invariants`, `update-deps`, `gen-packaging`. |

Each crate's `//!` docs say what it holds. Many comments cite [`docs/history/rust-port-plan.md`](docs/history/rust-port-plan.md) (the host CLI's port) or [`docs/history/egress-port-plan.md`](docs/history/egress-port-plan.md) (the egress's) for the reasoning behind a decision.

### Golden fixtures

Most tests assert against committed files under `tests/fixtures/` (the golden corpus, CLI surface, doctor, output, state-compat, contracts, the egress corpora under `tests/fixtures/egress/`, and so on). They are plain golden files: a deliberate behaviour change updates the fixture in the same commit. Where a test has a re-record mode, run it with `AGENTCAGE_BLESS=1` and review the diff; elsewhere the failing assertion prints the diff to copy from. A fixture that changes for any other reason is a regression. `tests/fixtures/contracts/` pins the contracts between the host and the egress, so a change there is a change to both sides.

The version lives in the root `VERSION` file and nowhere else. Cargo cannot read it from there, so `[workspace.package] version` carries a copy and `scripts/check-version.sh` fails when the two disagree. Bump `VERSION`, then the copy.

## Making Changes

1. Fork the repository and create a feature branch.
2. Make your changes and add tests where appropriate.
3. Run the tests above and ensure they pass.
4. Submit a pull request with a clear description of what changed and why.

## Updating Dependencies

All dependencies are pinned (`Cargo.lock`, binary checksums) except the container base images, which deliberately float on a tag so that a rebuild can pick up their security fixes (`alpine:3` for the egress image, `debian:stable-slim` for `Containerfile.nested`). A base image that is pinned instead carries an `# update-from:` comment naming the tag it tracks; to check the pinned ones for newer digests:

```bash
cargo xtask update-deps            # report only
cargo xtask update-deps --update   # rewrite the pinned digests
```

This needs `skopeo` (`sudo pacman -S skopeo` on Arch). Rust dependencies are updated with `cargo update` as usual.

## The Egress Image

Every cage's egress runs `localhost/agentcage-egress:<version>-<hash>`, built on the host from one Containerfile, `src/agentcage/data/containers/Containerfile.egress`: `alpine:3` (a floating tag, not a digest pin), `dnsmasq`, `iptables`, `tini`, util-linux `setpriv`, iproute2's `ss`, `supervisor-egress.sh`, `dns-audit.sh`, and the static `agentcage-egress` binary. `<hash>` is the first 12 hex digits of a SHA-256 over the Containerfile and every file it copies, the binary included, so any change to the egress (code or image) produces a new tag that reaches hosts already holding the previous one. The digest is computed by `rust/agentcage-assets/src/egress.rs` and pinned, together with the full list of inputs, in `tests/fixtures/egress_hash.json`.

If you deliberately change what goes into the egress image, `cargo test -p agentcage-assets` will fail. Re-bless the fixture in the same commit:

```bash
AGENTCAGE_BLESS=1 cargo test -p agentcage-assets bless_the_egress_hash_fixture -- --ignored
```

### Building with the egress binary

The host binary embeds a linux-musl `agentcage-egress` for its own architecture (`rust/agentcage-egress-embed`); that is what goes into the image. `cargo build`, `cargo test` and `cargo clippy` work without it. A host built without it fails when it first has to build the egress image, with a message saying how to provide one. To build a complete host, build the egress first, then `agentcage`, which picks it up from `target/<arch>-unknown-linux-musl/release/` (or from `AGENTCAGE_EGRESS_BIN=<path>`):

```bash
rustup target add x86_64-unknown-linux-musl   # needs musl-gcc (musl-tools / musl)
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl -p agentcage-egress
cargo build --release --bin agentcage
```

Rebuilding the egress means rebuilding `agentcage` too. Release builds set `AGENTCAGE_REQUIRE_EGRESS_BIN=1`, which makes a missing binary a compile-time error.

### End-to-end tests

The e2e suite drives real cages through the `agentcage` binary under test. It needs rootless Podman, `jq`, and the musl target above: the harness runs its mock services from the `agentcage-e2e-mock` binary (built for `x86_64-unknown-linux-musl`, and built on demand when cargo is on `PATH`) inside a small container next to the cage.

```bash
AGENTCAGE=$PWD/target/release/agentcage bash tests/e2e/run.sh container   # phases 1-6 and 9
AGENTCAGE=$PWD/target/release/agentcage bash tests/e2e/run.sh 8           # one phase
```

Test 6.12 loads a custom inspector; build the example and point the harness at it:

```bash
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2 -p header-policy-inspector
export E2E_INSPECTOR_WASM=$PWD/target/wasm32-wasip2/release/header_policy_inspector.wasm
```

`E2E_MOCK_BIN` and `E2E_MOCK_IMAGE` override the mock binary and the image it runs in.

## Code Style

- Follow existing patterns in the codebase.
- Keep changes focused — one concern per PR.

## Security Issues

Please **do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
