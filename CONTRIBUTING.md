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

## Code Style

- Follow existing patterns in the codebase.
- Keep changes focused — one concern per PR.

## Security Issues

Please **do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
