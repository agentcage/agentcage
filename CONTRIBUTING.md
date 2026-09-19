# Contributing to agentcage

## Development Setup

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
uv sync --dev
```

## Running Tests

```bash
uv run pytest
```

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
